//! `recover` — recover files and folders by logical extent layout (rewrite plan
//! Phases 16, 17, 19, 24).
//!
//! File data is reconstructed from `FILE_EXTENT` records sorted by logical
//! address and stops exactly at the logical file size. Sparse inodes retain
//! holes in seekable file outputs; streams and non-sparse files zero-fill gaps
//! for deterministic output and audit them in the recovery status. Output is
//! written to a temporary file and atomically renamed; the input image is never
//! modified. Encrypted volumes are refused unless `--raw-extents` is given.
//! Folder recovery walks the directory tree, recreates structure, preserves
//! symlinks and hard links, refuses path traversal, and reports per-file status.

use std::borrow::Cow;
use std::fs::{self, OpenOptions};
#[cfg(target_os = "macos")]
use std::io::Read;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::cli::Options;
use apfsrelic_core::apfs::btree::{BtreeReader, Record};
use apfsrelic_core::apfs::decmpfs::{self, Storage};
use apfsrelic_core::apfs::extract::Written;
use apfsrelic_core::apfs::jrec::Inode;
use apfsrelic_core::apfs::path as apath;
use apfsrelic_core::apfs::vol::Volume;
use apfsrelic_core::error::{Error, ErrorKind, Result};
use apfsrelic_core::json::{Envelope, Json};

const MAX_DIR_DEPTH: u32 = 256;

/// Per-file recovery outcome.
pub(crate) struct FileResult {
    pub(crate) path: String,
    pub(crate) fsoid: u64,
    pub(crate) status: &'static str,
    pub(crate) bytes: u64,
    pub(crate) note: Option<String>,
}

impl FileResult {
    fn to_json(&self) -> Json {
        let mut o = Json::obj()
            .set("path", self.path.as_str())
            .set("fsoid", format!("{:#x}", self.fsoid))
            .set("status", self.status)
            .set("bytes", self.bytes);
        if let Some(n) = &self.note {
            o.insert("note", n.as_str());
        }
        o
    }
}

pub fn run(opts: &Options) -> Result<i32> {
    let opened = super::open(opts)?;
    let (vol, snap) = super::open_volume_view(&opened, opts)?;
    let index = super::resolve_volume_index(&opened, opts)?;
    let bt = vol.btree();

    let fsoid = if let Some(path) = &opts.path {
        apath::resolve(&vol, &bt, path)?.fsoid
    } else if let Some(fsoid) = opts.fsoid {
        fsoid
    } else {
        return Err(Error::new(
            ErrorKind::Usage,
            "`recover` needs `--path <p>` or `--fsoid <id>`",
        ));
    };

    // Refuse plaintext recovery of encrypted data (Phase 19).
    if vol.apsb.is_encrypted() && !opts.raw_extents {
        return Err(Error::new(
            ErrorKind::EncryptedUnsupported,
            "volume is encrypted; refusing plaintext recovery (use --raw-extents for a forensic dump)",
        ));
    }

    let records = vol.records(&bt, fsoid)?;
    let inode = Volume::inode_from_records(&records)?.ok_or_else(|| {
        Error::new(
            ErrorKind::ObjectNotFound,
            format!("no inode for FSOID {fsoid:#x}"),
        )
    })?;

    let mut results: Vec<FileResult> = Vec::new();
    let mut state = HardlinkState::default();

    let recover_type;
    if inode.is_dir() {
        recover_type = "folder";
        let out_dir = opts.output.as_ref().ok_or_else(|| {
            Error::new(
                ErrorKind::Usage,
                "folder recovery requires `--output <dir>`",
            )
        })?;
        let out_dir = PathBuf::from(out_dir);
        recover_folder(
            &vol,
            &bt,
            fsoid,
            &inode,
            &out_dir,
            opts,
            0,
            &mut results,
            &mut state,
        )?;
    } else {
        recover_type = "file";
        match recover_single_file(&vol, &bt, fsoid, &inode, &records, opts) {
            Ok(result) => results.push(result),
            Err(error) => {
                let output = PathBuf::from(opts.output.as_deref().unwrap_or("-"));
                record_child_error_or_fail(opts, &mut results, &output, fsoid, error)?;
            }
        }
    }

    let mut warnings = opened.container.warnings.clone();
    warnings.extend(vol.warnings.clone());
    warnings.extend(bt.take_warnings());

    let partial = results
        .iter()
        .any(|r| r.status == "partial" || r.status == "error");
    let total_bytes: u64 = results.iter().map(|r| r.bytes).sum();

    if opts.json {
        let result = Json::obj()
            .set("type", recover_type)
            .set("dry_run", opts.dry_run)
            .set("files_total", results.len())
            .set("bytes_total", total_bytes)
            .set(
                "files",
                Json::Array(results.iter().map(FileResult::to_json).collect()),
            );
        let mut env = Envelope::new("recover")
            .image(super::image_json(&opened))
            .volume(super::volume_json(&vol, index))
            .checkpoint_xid(opened.container.checkpoint_xid)
            .result(result)
            .warnings(warnings);
        if let Some(s) = &snap {
            env = env.snapshot(super::snapshot_json(s));
        }
        if partial {
            env = env.error(
                "partial-recovery",
                "one or more files were not fully recovered",
            );
        }
        super::print_json(env.build());
    } else {
        for r in &results {
            eprintln!(
                "{}  {}  {} bytes{}",
                r.status,
                r.path,
                r.bytes,
                r.note
                    .as_deref()
                    .map(|n| format!("  ({n})"))
                    .unwrap_or_default()
            );
        }
    }

    Ok(if partial {
        ErrorKind::PartialRecovery.exit_code()
    } else {
        0
    })
}

/// Recover one regular file (or symlink) to `--output` (or stdout).
pub(crate) fn recover_single_file(
    vol: &Volume,
    bt: &BtreeReader,
    fsoid: u64,
    inode: &Inode,
    inode_records: &[Record],
    opts: &Options,
) -> Result<FileResult> {
    let size = inode.logical_size().unwrap_or(0);

    // Symlink: write the link target rather than extents.
    if inode.is_symlink() {
        if let Some(target) = Volume::symlink_target(inode_records)? {
            if let Some(out) = &opts.output {
                if opts.dry_run {
                    return Ok(FileResult {
                        path: out.clone(),
                        fsoid,
                        status: "dry-run",
                        bytes: target.len() as u64,
                        note: Some(format!("symlink -> {target}")),
                    });
                }
                let p = PathBuf::from(out);
                guard_overwrite(&p, opts)?;
                let _ = fs::remove_file(&p);
                std::os::unix::fs::symlink(&target, &p)?;
                return Ok(FileResult {
                    path: out.clone(),
                    fsoid,
                    status: "recovered",
                    bytes: target.len() as u64,
                    note: Some(format!("symlink -> {target}")),
                });
            }
        }
    }

    let out_desc = opts.output.clone().unwrap_or_else(|| "-".into());
    if opts.dry_run {
        return Ok(FileResult {
            path: out_desc,
            fsoid,
            status: "dry-run",
            bytes: size,
            note: None,
        });
    }

    if inode.is_regular() && inode.is_compressed() {
        let decmpfs_xattr =
            Volume::xattr(inode_records, decmpfs::DECMPFS_XATTR_NAME)?.ok_or_else(|| {
                Error::new(
                    ErrorKind::Corrupt,
                    format!(
                        "compressed FSOID {fsoid:#x} has no `{}` xattr",
                        decmpfs::DECMPFS_XATTR_NAME
                    ),
                )
            })?;
        let decmpfs_data = vol.read_xattr_data(bt, &decmpfs_xattr)?;
        let header = decmpfs::parse_header(&decmpfs_data)?;
        if header.uncompressed_size != size {
            return Err(Error::new(
                ErrorKind::Corrupt,
                format!(
                    "decmpfs size {} does not match inode logical size {size}",
                    header.uncompressed_size
                ),
            ));
        }
        let note = Some(format!(
            "decmpfs type {} {}",
            header.compression_type,
            header.storage().as_str()
        ));
        return match (&opts.output, header.storage()) {
            (None, Storage::Embedded) => {
                let stdout = io::stdout();
                let mut writer = stdout.lock();
                let bytes = decmpfs::write_embedded(&decmpfs_data, &mut writer)?;
                Ok(FileResult {
                    path: out_desc,
                    fsoid,
                    status: "recovered",
                    bytes,
                    note,
                })
            }
            (Some(out), Storage::Embedded) => {
                let final_path = PathBuf::from(out);
                guard_overwrite(&final_path, opts)?;
                #[cfg(target_os = "macos")]
                let (bytes, note) = {
                    write_kernel_compressed_atomic(&final_path, &decmpfs_data, None, size)?;
                    (
                        size,
                        Some(format!(
                            "decmpfs type {} kernel-verified",
                            header.compression_type
                        )),
                    )
                };
                #[cfg(not(target_os = "macos"))]
                let (bytes, note) = (
                    write_file_atomic_with(&final_path, |file| {
                        decmpfs::write_embedded(&decmpfs_data, file)
                    })?,
                    note,
                );
                Ok(FileResult {
                    path: out.clone(),
                    fsoid,
                    status: "recovered",
                    bytes,
                    note,
                })
            }
            (Some(out), Storage::ResourceFork) => {
                let resource_xattr =
                    Volume::xattr(inode_records, decmpfs::RESOURCE_FORK_XATTR_NAME)?.ok_or_else(
                        || {
                            Error::new(
                                ErrorKind::Corrupt,
                                format!(
                                    "decmpfs type {} has no `{}` xattr",
                                    header.compression_type,
                                    decmpfs::RESOURCE_FORK_XATTR_NAME
                                ),
                            )
                        },
                    )?;
                let resource_fork = vol.read_xattr_data(bt, &resource_xattr)?;
                let final_path = PathBuf::from(out);
                guard_overwrite(&final_path, opts)?;
                write_kernel_compressed_atomic(
                    &final_path,
                    &decmpfs_data,
                    Some(&resource_fork),
                    size,
                )?;
                Ok(FileResult {
                    path: out.clone(),
                    fsoid,
                    status: "recovered",
                    bytes: size,
                    note,
                })
            }
            (None, Storage::ResourceFork) => Err(Error::new(
                ErrorKind::UnsupportedFeature,
                "resource-fork decmpfs recovery requires --output on macOS",
            )),
            (Some(out), Storage::Kernel) => {
                let resource_fork =
                    match Volume::xattr(inode_records, decmpfs::RESOURCE_FORK_XATTR_NAME)? {
                        Some(xattr) => Some(vol.read_xattr_data(bt, &xattr)?),
                        None => None,
                    };
                let final_path = PathBuf::from(out);
                guard_overwrite(&final_path, opts)?;
                write_kernel_compressed_atomic(
                    &final_path,
                    &decmpfs_data,
                    resource_fork.as_deref(),
                    size,
                )?;
                Ok(FileResult {
                    path: out.clone(),
                    fsoid,
                    status: "recovered",
                    bytes: size,
                    note: Some(format!(
                        "decmpfs type {} kernel-verified",
                        header.compression_type
                    )),
                })
            }
            (None, Storage::Kernel) => Err(Error::new(
                ErrorKind::UnsupportedFeature,
                format!(
                    "decmpfs type {} requires --output on macOS",
                    header.compression_type
                ),
            )),
        };
    }

    // APFS keys a regular file's FILE_EXTENT records by the inode's private
    // data-stream id, which is not necessarily the inode's FSOID. Symlink
    // xattrs above deliberately continue to use the inode record set.
    let data_records = if inode.is_regular() {
        vol.file_data_records(bt, fsoid, inode, inode_records)?
    } else {
        Cow::Borrowed(inode_records)
    };

    match &opts.output {
        None => {
            // Stream to stdout.
            let stdout = io::stdout();
            let mut w = stdout.lock();
            let written = vol.write_file_data(data_records.as_ref(), size, &mut w)?;
            let status = recovery_status(size, inode.is_sparse(), inode.allocated_size(), &written);
            Ok(FileResult {
                path: out_desc,
                fsoid,
                status,
                bytes: written.bytes,
                note: written.note(),
            })
        }
        Some(out) => {
            let final_path = PathBuf::from(out);
            guard_overwrite(&final_path, opts)?;
            let written = write_file_atomic(
                vol,
                data_records.as_ref(),
                size,
                inode.is_sparse(),
                &final_path,
            )?;
            let status = recovery_status(size, inode.is_sparse(), inode.allocated_size(), &written);
            Ok(FileResult {
                path: out.clone(),
                fsoid,
                status,
                bytes: written.bytes,
                note: written.note(),
            })
        }
    }
}

/// Classify an extraction without treating zero-filled corruption as success.
/// Sparse inodes may legitimately contain holes, but overlaps and short writes
/// are always partial. A hole in a non-sparse, non-empty file includes the
/// no-extents case because the extractor zero-fills the entire logical size.
/// A sparse inode that declares allocated storage must also yield at least one
/// logical byte from a non-hole extent.
fn recovery_status(
    file_size: u64,
    is_sparse: bool,
    allocated_size: Option<u64>,
    written: &Written,
) -> &'static str {
    let incomplete = written.bytes != file_size || written.missing > 0;
    let suspect_layout =
        file_size > 0 && (written.overlaps > 0 || (!is_sparse && written.holes > 0));
    let missing_allocated_data = file_size > 0
        && is_sparse
        && allocated_size.is_some_and(|size| size > 0)
        && written.data_bytes == 0;
    if incomplete || suspect_layout || missing_allocated_data {
        "partial"
    } else {
        "recovered"
    }
}

/// Recursively recover a directory tree.
#[allow(clippy::too_many_arguments)]
fn recover_folder(
    vol: &Volume,
    bt: &BtreeReader,
    dir_fsoid: u64,
    _dir_inode: &Inode,
    out_dir: &Path,
    opts: &Options,
    depth: u32,
    results: &mut Vec<FileResult>,
    state: &mut HardlinkState,
) -> Result<()> {
    if depth > MAX_DIR_DEPTH {
        results.push(FileResult {
            path: out_dir.display().to_string(),
            fsoid: dir_fsoid,
            status: "error",
            bytes: 0,
            note: Some("max directory depth exceeded".into()),
        });
        return Ok(());
    }

    if !opts.dry_run {
        fs::create_dir_all(out_dir)?;
    }

    let entries = vol.list_dir(bt, dir_fsoid)?;
    for entry in entries {
        // Path-traversal guard: reject dangerous names outright.
        if !is_safe_name(&entry.name) {
            results.push(FileResult {
                path: format!("{}/{}", out_dir.display(), entry.name),
                fsoid: entry.file_id,
                status: "error",
                bytes: 0,
                note: Some("unsafe entry name; skipped".into()),
            });
            continue;
        }
        let child_path = out_dir.join(&entry.name);
        let child_records = match vol.records(bt, entry.file_id) {
            Ok(records) => records,
            Err(error) => {
                record_child_error_or_fail(opts, results, &child_path, entry.file_id, error)?;
                continue;
            }
        };
        let child_inode = match Volume::inode_from_records(&child_records) {
            Ok(Some(inode)) => inode,
            Ok(None) => {
                results.push(FileResult {
                    path: child_path.display().to_string(),
                    fsoid: entry.file_id,
                    status: "error",
                    bytes: 0,
                    note: Some("no inode".into()),
                });
                continue;
            }
            Err(error) => {
                record_child_error_or_fail(opts, results, &child_path, entry.file_id, error)?;
                continue;
            }
        };

        if child_inode.is_dir() {
            if let Err(error) = recover_folder(
                vol,
                bt,
                entry.file_id,
                &child_inode,
                &child_path,
                opts,
                depth + 1,
                results,
                state,
            ) {
                record_child_error_or_fail(opts, results, &child_path, entry.file_id, error)?;
            }
            continue;
        }

        // Resume support: skip an existing path unless --overwrite. This must
        // run before the hard-link branch so a secondary link never removes a
        // destination the user did not authorize us to replace.
        if !opts.overwrite && !opts.dry_run && child_path.exists() {
            results.push(FileResult {
                path: child_path.display().to_string(),
                fsoid: entry.file_id,
                status: "skipped-exists",
                bytes: 0,
                note: None,
            });
            continue;
        }

        // Hard link: if we've already recovered this inode, link instead.
        if child_inode.nchildren_or_nlink > 1 {
            if let Some(first) = state.get(entry.file_id) {
                if !opts.dry_run {
                    if opts.overwrite {
                        let _ = fs::remove_file(&child_path);
                    }
                    if let Err(e) = fs::hard_link(first, &child_path) {
                        results.push(FileResult {
                            path: child_path.display().to_string(),
                            fsoid: entry.file_id,
                            status: "error",
                            bytes: 0,
                            note: Some(format!("hardlink failed: {e}")),
                        });
                        continue;
                    }
                }
                results.push(FileResult {
                    path: child_path.display().to_string(),
                    fsoid: entry.file_id,
                    status: "recovered",
                    bytes: 0,
                    note: Some("hardlink".into()),
                });
                continue;
            }
        }

        let file_opts = Options {
            output: Some(child_path.display().to_string()),
            ..opts.clone()
        };
        match recover_single_file(
            vol,
            bt,
            entry.file_id,
            &child_inode,
            &child_records,
            &file_opts,
        ) {
            Ok(mut r) => {
                if child_inode.nchildren_or_nlink > 1 && !opts.dry_run {
                    state.insert(entry.file_id, child_path.clone());
                }
                r.path = child_path.display().to_string();
                results.push(r);
            }
            Err(e) => {
                if !opts.best_effort {
                    return Err(e);
                }
                results.push(FileResult {
                    path: child_path.display().to_string(),
                    fsoid: entry.file_id,
                    status: "error",
                    bytes: 0,
                    note: Some(e.to_string()),
                });
            }
        }
    }
    Ok(())
}

/// Record a child-local failure when best-effort recovery is enabled, or
/// preserve the command's fail-fast behavior otherwise.
fn record_child_error_or_fail(
    opts: &Options,
    results: &mut Vec<FileResult>,
    path: &Path,
    fsoid: u64,
    error: Error,
) -> Result<()> {
    if !opts.best_effort {
        return Err(error);
    }
    results.push(FileResult {
        path: path.display().to_string(),
        fsoid,
        status: "error",
        bytes: 0,
        note: Some(error.to_string()),
    });
    Ok(())
}

/// Tracks the first on-disk path recovered for each multi-linked inode.
#[derive(Default)]
struct HardlinkState {
    map: std::collections::HashMap<u64, PathBuf>,
}
impl HardlinkState {
    fn get(&self, oid: u64) -> Option<&PathBuf> {
        self.map.get(&oid)
    }
    fn insert(&mut self, oid: u64, path: PathBuf) {
        self.map.entry(oid).or_insert(path);
    }
}

/// Write `file_size` bytes to `final_path` via a temp file + atomic rename.
fn write_file_atomic(
    vol: &Volume,
    records: &[Record],
    file_size: u64,
    preserve_sparse: bool,
    final_path: &Path,
) -> Result<Written> {
    write_file_atomic_with(final_path, |file| {
        if preserve_sparse {
            vol.write_sparse_file_data(records, file_size, file)
        } else {
            vol.write_file_data(records, file_size, file)
        }
    })
}

/// Write a temporary file and atomically install it at `final_path`.
///
/// Keeping the write operation injectable makes the cleanup path testable. A
/// failed content write or flush removes the temporary file before returning.
fn write_file_atomic_with<T>(
    final_path: &Path,
    write: impl FnOnce(&mut fs::File) -> Result<T>,
) -> Result<T> {
    let (tmp, mut f) = create_temp_file(final_path)?;

    let written = (|| -> Result<T> {
        let written = write(&mut f)?;
        f.flush()?;
        Ok(written)
    })();

    let written = match written {
        Ok(written) => written,
        Err(error) => {
            let _ = fs::remove_file(&tmp);
            return Err(error);
        }
    };

    fs::rename(&tmp, final_path).inspect_err(|_| {
        let _ = fs::remove_file(&tmp);
    })?;
    Ok(written)
}

/// Atomically reserve a short temporary leaf beside the final destination.
/// `create_new` prevents a stale or adversarial symbolic link from redirecting
/// recovery writes outside the selected directory.
fn create_temp_file(final_path: &Path) -> Result<(PathBuf, fs::File)> {
    let dir = final_path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(dir)?;
    for collision in 0..1024u32 {
        let candidate = dir.join(format!(
            "_com.apfsrelic.recover_{}_{}",
            std::process::id(),
            collision
        ));
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => return Ok((candidate, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(Error::new(
        ErrorKind::Io,
        format!(
            "could not allocate a temporary file beside `{}`",
            final_path.display()
        ),
    ))
}

/// Recreate a transparent-compression file on macOS, then read its complete
/// logical stream before installing it atomically. This delegates private
/// AppleFSCompression formats to the kernel while still rejecting malformed or
/// incomplete output.
#[cfg(target_os = "macos")]
fn write_kernel_compressed_atomic(
    final_path: &Path,
    decmpfs_xattr: &[u8],
    resource_fork: Option<&[u8]>,
    logical_size: u64,
) -> Result<()> {
    use std::ffi::{c_char, c_int, c_void, CString};
    use std::os::unix::ffi::OsStrExt;

    extern "C" {
        fn setxattr(
            path: *const c_char,
            name: *const c_char,
            value: *const c_void,
            size: usize,
            position: u32,
            options: c_int,
        ) -> c_int;
        fn chflags(path: *const c_char, flags: u32) -> c_int;
    }

    fn c_path(path: &Path) -> Result<CString> {
        CString::new(path.as_os_str().as_bytes()).map_err(|_| {
            Error::new(
                ErrorKind::Usage,
                format!("output path contains NUL: `{}`", path.display()),
            )
        })
    }

    fn set_xattr(path: &CString, name: &str, value: &[u8]) -> Result<()> {
        let name = CString::new(name).expect("well-known xattr name has no NUL");
        // SAFETY: the C strings and value slice remain valid for the call; the
        // position/options pair requests a complete normal xattr replacement.
        let rc = unsafe {
            setxattr(
                path.as_ptr(),
                name.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                0,
                0,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error().into())
        }
    }

    let (tmp, reserved) = create_temp_file(final_path)?;
    drop(reserved);

    let installed = (|| -> Result<()> {
        let tmp_c = c_path(&tmp)?;
        if let Some(resource_fork) = resource_fork {
            set_xattr(&tmp_c, decmpfs::RESOURCE_FORK_XATTR_NAME, resource_fork)?;
        }
        set_xattr(&tmp_c, decmpfs::DECMPFS_XATTR_NAME, decmpfs_xattr)?;
        // SAFETY: `tmp_c` is a valid path C string. UF_COMPRESSED is the
        // documented BSD flag that activates the decmpfs xattr.
        if unsafe { chflags(tmp_c.as_ptr(), decmpfs::UF_COMPRESSED) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }

        let mut file = fs::File::open(&tmp)?;
        let mut sink = io::sink();
        let bytes = io::copy(&mut file, &mut sink)?;
        if bytes != logical_size {
            return Err(Error::new(
                ErrorKind::Corrupt,
                format!("kernel decoded decmpfs to {bytes} bytes, expected {logical_size}"),
            ));
        }
        let mut extra = [0u8; 1];
        if file.read(&mut extra)? != 0 {
            return Err(Error::new(
                ErrorKind::Corrupt,
                "kernel decoded decmpfs beyond its declared size",
            ));
        }
        Ok(())
    })();

    if let Err(error) = installed {
        let _ = fs::remove_file(&tmp);
        return Err(error);
    }
    fs::rename(&tmp, final_path).inspect_err(|_| {
        let _ = fs::remove_file(&tmp);
    })?;
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn write_kernel_compressed_atomic(
    _final_path: &Path,
    _decmpfs_xattr: &[u8],
    _resource_fork: Option<&[u8]>,
    _logical_size: u64,
) -> Result<()> {
    Err(Error::new(
        ErrorKind::UnsupportedFeature,
        "kernel-verified decmpfs recovery requires macOS",
    ))
}

/// Reject empty/`.`/`..` names and names containing a path separator or NUL.
fn is_safe_name(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains('/') && !name.contains('\0')
}

/// Refuse to overwrite an existing final path unless `--overwrite`.
fn guard_overwrite(path: &Path, opts: &Options) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) if !opts.overwrite => Err(Error::new(
            ErrorKind::Usage,
            format!(
                "`{}` already exists; pass --overwrite to replace it",
                path.display()
            ),
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TestDir(PathBuf);

    impl TestDir {
        fn new(label: &str) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock must be after Unix epoch")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "apfsrelic-recover-{label}-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir_all(&path).expect("create test directory");
            Self(path)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn safe_name_rejects_traversal() {
        assert!(is_safe_name("file.txt"));
        assert!(!is_safe_name(".."));
        assert!(!is_safe_name("a/b"));
        assert!(!is_safe_name(""));
    }

    #[test]
    fn child_error_is_recorded_only_in_best_effort_mode() {
        let mut results = Vec::new();
        let mut opts = Options {
            best_effort: true,
            ..Options::default()
        };
        record_child_error_or_fail(
            &opts,
            &mut results,
            Path::new("out/child"),
            0x2a,
            Error::new(ErrorKind::Corrupt, "bad child record"),
        )
        .expect("best-effort should continue");

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].path, "out/child");
        assert_eq!(results[0].fsoid, 0x2a);
        assert_eq!(results[0].status, "error");
        assert_eq!(results[0].note.as_deref(), Some("bad child record"));

        opts.best_effort = false;
        let error = record_child_error_or_fail(
            &opts,
            &mut results,
            Path::new("out/sibling"),
            0x2b,
            Error::new(ErrorKind::Io, "read failed"),
        )
        .expect_err("normal mode should fail fast");
        assert_eq!(error.kind(), ErrorKind::Io);
        assert_eq!(results.len(), 1, "fail-fast mode must not add a result");
    }

    #[test]
    fn atomic_write_removes_temp_file_when_writer_fails() {
        let dir = TestDir::new("atomic-cleanup");
        let final_path = dir.0.join("output.bin");

        let result: Result<()> = write_file_atomic_with(&final_path, |file| {
            file.write_all(b"partial")?;
            Err(Error::new(ErrorKind::Io, "injected write failure"))
        });

        assert!(result.is_err());
        assert!(!final_path.exists());
        assert_eq!(
            fs::read_dir(&dir.0).expect("read test directory").count(),
            0,
            "temporary file must be removed after a failed write"
        );
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_never_follows_a_stale_temp_symlink() {
        let dir = TestDir::new("atomic-symlink");
        let victim = dir.0.join("victim");
        let final_path = dir.0.join("output.bin");
        let stale = dir
            .0
            .join(format!("_com.apfsrelic.recover_{}_0", std::process::id()));
        fs::write(&victim, b"do not modify").expect("write victim");
        std::os::unix::fs::symlink(&victim, &stale).expect("create stale temp symlink");

        write_file_atomic_with(&final_path, |file| {
            file.write_all(b"recovered")?;
            Ok(())
        })
        .expect("use a create-new collision suffix");

        assert_eq!(fs::read(&victim).expect("read victim"), b"do not modify");
        assert_eq!(fs::read(&final_path).expect("read output"), b"recovered");
        assert!(stale.is_symlink());
    }

    #[cfg(unix)]
    #[test]
    fn no_overwrite_rejects_a_broken_symlink() {
        let dir = TestDir::new("broken-final-symlink");
        let final_path = dir.0.join("output.bin");
        std::os::unix::fs::symlink(dir.0.join("missing"), &final_path)
            .expect("create broken final symlink");

        let error = guard_overwrite(&final_path, &Options::default())
            .expect_err("broken symlink still occupies the destination name");
        assert_eq!(error.kind(), ErrorKind::Usage);
    }

    #[test]
    fn non_sparse_zero_fill_or_overlap_is_partial() {
        let no_extents = Written {
            bytes: 4096,
            data_bytes: 0,
            holes: 1,
            overlaps: 0,
            missing: 0,
        };
        assert_eq!(
            recovery_status(4096, false, Some(0), &no_extents),
            "partial"
        );

        let overlap = Written {
            bytes: 4096,
            data_bytes: 4096,
            holes: 0,
            overlaps: 1,
            missing: 0,
        };
        assert_eq!(
            recovery_status(4096, false, Some(4096), &overlap),
            "partial"
        );
    }

    #[test]
    fn sparse_hole_can_be_recovered() {
        let sparse = Written {
            bytes: 4096,
            data_bytes: 0,
            holes: 1,
            overlaps: 0,
            missing: 0,
        };
        assert_eq!(recovery_status(4096, true, Some(0), &sparse), "recovered");
    }

    #[test]
    fn allocated_sparse_without_data_is_partial() {
        let missing_data = Written {
            bytes: 4096,
            data_bytes: 0,
            holes: 1,
            overlaps: 0,
            missing: 0,
        };
        assert_eq!(
            recovery_status(4096, true, Some(4096), &missing_data),
            "partial"
        );

        let sparse_with_data = Written {
            data_bytes: 1,
            ..missing_data
        };
        assert_eq!(
            recovery_status(4096, true, Some(4096), &sparse_with_data),
            "recovered"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn kernel_validates_embedded_and_resource_fork_decmpfs() {
        fn header(compression_type: u32, size: u64, payload: &[u8]) -> Vec<u8> {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&decmpfs::DECMPFS_MAGIC.to_le_bytes());
            bytes.extend_from_slice(&compression_type.to_le_bytes());
            bytes.extend_from_slice(&size.to_le_bytes());
            bytes.extend_from_slice(payload);
            bytes
        }

        let dir = TestDir::new("decmpfs-kernel");
        let embedded = dir.0.join("embedded");
        let type1 = header(decmpfs::TYPE_UNCOMPRESSED_ATTR, 5, b"hello");
        write_kernel_compressed_atomic(&embedded, &type1, None, 5)
            .expect("kernel should accept type-1 decmpfs");
        assert_eq!(fs::read(&embedded).expect("read type-1 output"), b"hello");

        let resource = dir.0.join("resource");
        let lzvn_payload = [
            0x68, 0x01, 0x41, 0xf0, 0xe5, 0xe1, 0x41, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00,
        ];
        let mut resource_fork = Vec::new();
        resource_fork.extend_from_slice(&8u32.to_le_bytes());
        resource_fork.extend_from_slice(&(8u32 + lzvn_payload.len() as u32).to_le_bytes());
        resource_fork.extend_from_slice(&lzvn_payload);
        let type8 = header(decmpfs::TYPE_LZVN_RSRC, 255, b"");
        write_kernel_compressed_atomic(&resource, &type8, Some(&resource_fork), 255)
            .expect("kernel should accept type-8 resource-fork decmpfs");
        assert_eq!(
            fs::read(&resource).expect("read type-8 output"),
            vec![b'A'; 255]
        );
    }
}
