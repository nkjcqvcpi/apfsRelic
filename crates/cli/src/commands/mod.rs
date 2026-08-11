//! CLI subcommands. Each command has a text path and a `--json` path that never
//! interleaves diagnostics with stdout JSON (AGENTS.md rule 4).

pub mod history_union;
pub mod inspect;
pub mod ls;
pub mod partitions;
pub mod recover;
pub mod recover_manifest;
pub mod snapshots;
pub mod stat;
pub mod verify;
pub mod volumes;

use crate::cli::Options;
use apfsrelic_core::apfs::snapshot::{self, SnapshotInfo};
use apfsrelic_core::apfs::vol::Volume;
use apfsrelic_core::error::{Error, ErrorKind, Result};
use apfsrelic_core::json::Json;
use apfsrelic_core::source::{self, ImageKind, OpenOptions, OpenedImage};
use std::path::PathBuf;

/// Require `--container`.
pub fn require_container(opts: &Options) -> Result<PathBuf> {
    opts.container
        .clone()
        .ok_or_else(|| Error::new(ErrorKind::Usage, "`--container` is required"))
}

/// Build [`OpenOptions`] from parsed CLI options.
pub fn open_options(opts: &Options) -> Result<OpenOptions> {
    Ok(OpenOptions {
        container_path: require_container(opts)?,
        partition: opts.partition,
        offset: opts.offset,
        max_xid: opts.max_xid,
    })
}

/// Open the container described by `opts`.
pub fn open(opts: &Options) -> Result<OpenedImage> {
    source::open(&open_options(opts)?)
}

/// JSON description of the opened image (rewrite plan Phase 22 `image` field).
pub fn image_json(opened: &OpenedImage) -> Json {
    let kind = match opened.kind {
        ImageKind::SparseBundle => "sparsebundle",
        ImageKind::RawFile => "raw",
    };
    let mut o = Json::obj()
        .set("type", kind)
        .set("description", opened.image.description())
        .set("size", opened.image.size())
        .set("container_offset", opened.container_offset)
        .set("read_only", true);
    if let Some(idx) = opened.partition_index {
        o.insert("partition_index", idx);
    }
    o
}

/// Resolve the requested volume index, honoring `--volume-name`.
pub fn resolve_volume_index(opened: &OpenedImage, opts: &Options) -> Result<u32> {
    if let Some(idx) = opts.volume {
        if idx == 0 {
            return Err(Error::new(
                ErrorKind::Usage,
                "volume 0 is invalid for filesystem commands (volumes are 1-based)",
            ));
        }
        return Ok(idx);
    }
    if let Some(name) = &opts.volume_name {
        for slot in opened.container.list_volumes()? {
            if &slot.apsb.volname == name {
                return Ok(slot.index);
            }
        }
        return Err(Error::new(
            ErrorKind::Usage,
            format!("no volume named `{name}`"),
        ));
    }
    Err(Error::new(
        ErrorKind::Usage,
        "`--volume <index>` (or `--volume-name <name>`) is required",
    ))
}

/// Open a volume view: live, or a snapshot if `--snapshot`/`--snapshot-xid` set.
pub fn open_volume_view(
    opened: &OpenedImage,
    opts: &Options,
) -> Result<(Volume, Option<SnapshotInfo>)> {
    let index = resolve_volume_index(opened, opts)?;
    let live = Volume::open(&opened.container, index)?;

    if opts.snapshot.is_none() && opts.snapshot_xid.is_none() {
        return Ok((live, None));
    }

    let bt = live.btree();
    let snap = if let Some(xid) = opts.snapshot_xid {
        snapshot::find_by_xid(&live, &bt, xid)?
    } else {
        snapshot::find_by_name(&live, &bt, opts.snapshot.as_deref().unwrap())?
    };
    let view = snapshot::open_snapshot(&live, &bt, &snap)?;
    Ok((view, Some(snap)))
}

/// JSON description of the selected volume (rewrite plan Phase 22 `volume`).
pub fn volume_json(vol: &Volume, index: u32) -> Json {
    Json::obj()
        .set("index", index)
        .set("name", vol.apsb.volname.as_str())
        .set("role", vol.apsb.role_name())
        .set("uuid", vol.apsb.vol_uuid.as_str())
        .set("case_insensitive", vol.apsb.is_case_insensitive())
        .set("encrypted", vol.apsb.is_encrypted())
        .set("num_files", vol.apsb.num_files)
        .set("num_directories", vol.apsb.num_directories)
        .set("num_snapshots", vol.apsb.num_snapshots)
}

/// JSON description of the selected snapshot (rewrite plan Phase 22 `snapshot`).
pub fn snapshot_json(snap: &SnapshotInfo) -> Json {
    let mut o = Json::obj()
        .set("name", snap.name.as_str())
        .set("xid", snap.xid);
    if let Some(t) = apfsrelic_core::apfs::time::iso8601(snap.create_time) {
        o.insert("create_time", t);
    }
    o
}

/// Print `value` to stdout as compact JSON followed by a newline.
pub fn print_json(value: Json) {
    println!("{}", value.to_compact_string());
}
