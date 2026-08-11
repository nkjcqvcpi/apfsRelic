//! `verify` — structural integrity checks before recovery (rewrite plan Phase 21).
//!
//! Validates: the image is readable, block 0 is an NXSB with a good checksum, the
//! checkpoint candidates and the selected checkpoint, the container and (when a
//! volume is selected) volume object maps and superblock, and the filesystem
//! B-tree root. Optionally scans the file extents of a `--path`.

use std::borrow::Cow;

use crate::cli::Options;
use apfsrelic_core::apfs::checksum;
use apfsrelic_core::apfs::vol::Volume;
use apfsrelic_core::error::Result;
use apfsrelic_core::json::{Envelope, Json};

struct Check {
    name: String,
    ok: bool,
    detail: Option<String>,
}

impl Check {
    fn to_json(&self) -> Json {
        let mut o = Json::obj()
            .set("check", self.name.as_str())
            .set("ok", self.ok);
        if let Some(d) = &self.detail {
            o.insert("detail", d.as_str());
        }
        o
    }
}

pub fn run(opts: &Options) -> Result<i32> {
    let mut checks: Vec<Check> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    let opened = super::open(opts)?;
    warnings.extend(opened.container.warnings.clone());
    checks.push(Check {
        name: "container_open".into(),
        ok: true,
        detail: Some(format!(
            "checkpoint xid {:#x}",
            opened.container.checkpoint_xid
        )),
    });

    // Block 0 checksum.
    let block0 = opened
        .container
        .dev
        .read_block(0, opened.container.block_size)?;
    checks.push(Check {
        name: "block0_checksum".into(),
        ok: checksum::is_valid(&block0),
        detail: None,
    });

    // Container omap tree root checksum.
    let omap_root = opened.container.dev.read_block(
        opened.container.nx_omap_tree_root,
        opened.container.block_size,
    )?;
    checks.push(Check {
        name: "container_omap_root".into(),
        ok: checksum::is_valid(&omap_root),
        detail: None,
    });

    // Volume-level checks if a volume is selected.
    if opts.volume.is_some() || opts.volume_name.is_some() {
        match super::open_volume_view(&opened, opts) {
            Ok((vol, _snap)) => {
                checks.push(Check {
                    name: "volume_superblock".into(),
                    ok: vol.apsb.magic == apfsrelic_core::apfs::volume::APFS_MAGIC,
                    detail: Some(vol.apsb.volname.clone()),
                });
                let root = vol.dev.read_block(vol.root_tree_root, vol.block_size)?;
                checks.push(Check {
                    name: "fs_root_tree_checksum".into(),
                    ok: checksum::is_valid(&root),
                    detail: None,
                });

                // Optional: scan extents for a path.
                if let Some(path) = &opts.path {
                    scan_path(&vol, path, &mut checks);
                }
                warnings.extend(vol.warnings.clone());
            }
            Err(e) => checks.push(Check {
                name: "volume_open".into(),
                ok: false,
                detail: Some(e.to_string()),
            }),
        }
    }

    let all_ok = checks.iter().all(|c| c.ok);

    if opts.json {
        let env = Envelope::new("verify")
            .image(super::image_json(&opened))
            .checkpoint_xid(opened.container.checkpoint_xid)
            .result(Json::obj().set("ok", all_ok).set(
                "checks",
                Json::Array(checks.iter().map(Check::to_json).collect()),
            ))
            .warnings(warnings);
        super::print_json(env.build());
    } else {
        for c in &checks {
            println!(
                "[{}] {}{}",
                if c.ok { "OK" } else { "FAIL" },
                c.name,
                c.detail
                    .as_deref()
                    .map(|d| format!(": {d}"))
                    .unwrap_or_default()
            );
        }
        println!(
            "{}",
            if all_ok {
                "verify: OK"
            } else {
                "verify: FAILED"
            }
        );
    }

    Ok(if all_ok {
        0
    } else {
        apfsrelic_core::error::ErrorKind::Corrupt.exit_code()
    })
}

/// Scan the file extents of `path`, checking each extent's first block reads.
fn scan_path(vol: &Volume, path: &str, checks: &mut Vec<Check>) {
    let bt = vol.btree();
    let resolved = match apfsrelic_core::apfs::path::resolve(vol, &bt, path) {
        Ok(r) => r,
        Err(e) => {
            checks.push(Check {
                name: "path_resolve".into(),
                ok: false,
                detail: Some(e.to_string()),
            });
            return;
        }
    };
    let inode_records = match vol.records(&bt, resolved.fsoid) {
        Ok(r) => r,
        Err(e) => {
            checks.push(Check {
                name: "path_records".into(),
                ok: false,
                detail: Some(e.to_string()),
            });
            return;
        }
    };
    let inode = match Volume::inode_from_records(&inode_records) {
        Ok(Some(inode)) => inode,
        Ok(None) => {
            checks.push(Check {
                name: "path_inode".into(),
                ok: false,
                detail: Some(format!("no inode for FSOID {:#x}", resolved.fsoid)),
            });
            return;
        }
        Err(e) => {
            checks.push(Check {
                name: "path_inode".into(),
                ok: false,
                detail: Some(e.to_string()),
            });
            return;
        }
    };
    let records = if inode.is_regular() {
        match vol.file_data_records(&bt, resolved.fsoid, &inode, &inode_records) {
            Ok(records) => records,
            Err(e) => {
                checks.push(Check {
                    name: "path_data_records".into(),
                    ok: false,
                    detail: Some(e.to_string()),
                });
                return;
            }
        }
    } else {
        Cow::Borrowed(inode_records.as_slice())
    };
    let mut extents = 0u64;
    let mut bad = 0u64;
    for rec in records.iter() {
        if let Ok(v) = raw_type(&rec.key) {
            if v == apfsrelic_core::apfs::jrec::APFS_TYPE_FILE_EXTENT {
                if let Ok(fe) = apfsrelic_core::apfs::jrec::FileExtent::parse(&rec.key, &rec.val) {
                    extents += 1;
                    if !fe.is_hole()
                        && vol
                            .dev
                            .read_block(fe.phys_block_num, vol.block_size)
                            .is_err()
                    {
                        bad += 1;
                    }
                }
            }
        }
    }
    checks.push(Check {
        name: "path_extents".into(),
        ok: bad == 0,
        detail: Some(format!("{extents} extent(s), {bad} unreadable")),
    });
}

fn raw_type(key: &[u8]) -> Result<u8> {
    let (_oid, ty) = apfsrelic_core::apfs::btree::split_obj_id_and_type(
        apfsrelic_core::apfs::raw::u64_at(key, 0)?,
    );
    Ok(ty)
}
