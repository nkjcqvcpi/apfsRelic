//! `recover-manifest` — recover many snapshot leaves without reopening the image.
//!
//! Input is JSON Lines. Every row names a snapshot XID, an absolute source
//! path in that snapshot, and a path relative to one fixed output root. Rows
//! are scheduled by descending snapshot XID so one [`Volume`] and one cached
//! [`BtreeReader`] serve every attempt against a snapshot. Failed or partial
//! attempts can be retried against older snapshots without ever installing the
//! partial staging file at its final name.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::{Component, Path, PathBuf};

use crate::cli::{parse_number, Options};
use apfsrelic_core::apfs::btree::BtreeReader;
use apfsrelic_core::apfs::path as apath;
use apfsrelic_core::apfs::snapshot::{self, SnapshotInfo};
use apfsrelic_core::apfs::vol::Volume;
use apfsrelic_core::error::{Error, ErrorKind, Result};
use apfsrelic_core::json::{Json, SCHEMA_VERSION};

const MAX_JSON_DEPTH: usize = 128;
const MAX_MANIFEST_LINE: usize = 64 * 1024 * 1024;

#[derive(Debug)]
struct ManifestRow {
    line: u64,
    snapshot_xid: u64,
    snapshot_name: Option<String>,
    source_path: String,
    output_relative_path: String,
    output_relative: PathBuf,
    relative_path: Option<String>,
    expected_fsoid: Option<u64>,
    expected_type: Option<String>,
}

#[derive(Debug)]
struct InvalidRow {
    line: u64,
    message: String,
}

struct WorkItem {
    row: ManifestRow,
    target: PathBuf,
    current_source_path: String,
    primary: bool,
    attempts: Vec<Attempt>,
}

#[derive(Debug)]
struct Attempt {
    snapshot_xid: u64,
    snapshot_name: Option<String>,
    source_path: String,
    fsoid: Option<u64>,
    status: &'static str,
    bytes: u64,
    note: Option<String>,
    error_code: Option<&'static str>,
    error_message: Option<String>,
    fallback_eligible: bool,
}

impl Attempt {
    fn error(
        snapshot_xid: u64,
        snapshot_name: Option<String>,
        source_path: String,
        error: Error,
        fallback_eligible: bool,
    ) -> Attempt {
        Attempt {
            snapshot_xid,
            snapshot_name,
            source_path,
            fsoid: None,
            status: "error",
            bytes: 0,
            note: None,
            error_code: Some(error.kind().code()),
            error_message: Some(error.to_string()),
            fallback_eligible,
        }
    }

    fn is_success(&self) -> bool {
        matches!(self.status, "recovered" | "dry-run")
    }

    fn to_json(&self) -> Json {
        let mut value = Json::obj()
            .set("snapshot_xid", self.snapshot_xid)
            .set("snapshot_name", self.snapshot_name.clone())
            .set("source_path", self.source_path.as_str())
            .set("fsoid", self.fsoid.map(|fsoid| format!("{fsoid:#x}")))
            .set("status", self.status)
            .set("bytes", self.bytes)
            .set("note", self.note.clone())
            .set("fallback_eligible", self.fallback_eligible);
        if let (Some(code), Some(message)) = (self.error_code, &self.error_message) {
            value.insert(
                "error",
                Json::obj()
                    .set("code", code)
                    .set("message", message.as_str()),
            );
        } else {
            value.insert("error", Json::Null);
        }
        value
    }
}

#[derive(Default)]
struct Summary {
    rows: u64,
    recovered: u64,
    dry_run: u64,
    skipped: u64,
    partial: u64,
    errors: u64,
}

impl Summary {
    fn observe(&mut self, status: &str) {
        self.rows += 1;
        match status {
            "recovered" => self.recovered += 1,
            "dry-run" => self.dry_run += 1,
            "skipped-exists" => self.skipped += 1,
            "partial" => self.partial += 1,
            _ => self.errors += 1,
        }
    }

    fn incomplete(&self) -> bool {
        self.partial > 0 || self.errors > 0
    }
}

pub fn run(opts: &Options) -> Result<i32> {
    validate_options(opts)?;
    let manifest_path = opts
        .manifest
        .as_deref()
        .ok_or_else(|| Error::new(ErrorKind::Usage, "`--manifest <jsonl>` is required"))?;
    let output_root_arg = opts
        .output_root
        .as_deref()
        .ok_or_else(|| Error::new(ErrorKind::Usage, "`--output-root <dir>` is required"))?;
    let (rows, invalid_rows) = read_manifest(manifest_path, opts.fallback_history)?;

    // Open the read-only source before creating anything in the destination.
    let opened = super::open(opts)?;
    let volume_index = super::resolve_volume_index(&opened, opts)?;
    let live = Volume::open(&opened.container, volume_index)?;
    if live.apsb.is_encrypted() && !opts.raw_extents {
        return Err(Error::new(
            ErrorKind::EncryptedUnsupported,
            "volume is encrypted; refusing plaintext recovery (use --raw-extents for a forensic dump)",
        ));
    }
    let live_bt = live.btree();
    let snapshots = snapshot::list_snapshots(&live, &live_bt)?;
    let snapshots_by_xid: BTreeMap<u64, SnapshotInfo> = snapshots
        .into_iter()
        .map(|snapshot| (snapshot.xid, snapshot))
        .collect();
    let output_root = prepare_output_root(output_root_arg, opts.dry_run)?;

    for warning in &opened.container.warnings {
        eprintln!("recover-manifest: source warning: {warning}");
    }
    for warning in &live.warnings {
        eprintln!("recover-manifest: volume warning: {warning}");
    }

    let stdout = io::stdout();
    let mut output = BufWriter::new(stdout.lock());
    let mut summary = Summary::default();
    for invalid in invalid_rows {
        emit_invalid(&mut output, invalid.line, &invalid.message)?;
        summary.observe("error");
    }

    let mut queue: BTreeMap<u64, Vec<WorkItem>> = BTreeMap::new();
    let mut claimed_targets = BTreeSet::new();
    for mut row in rows {
        let Some(snapshot) = snapshots_by_xid.get(&row.snapshot_xid) else {
            emit_row_error(
                &mut output,
                &row,
                ErrorKind::ObjectNotFound.code(),
                &format!(
                    "manifest references unknown snapshot xid {:#x}",
                    row.snapshot_xid
                ),
            )?;
            summary.observe("error");
            continue;
        };
        if let Some(name) = &row.snapshot_name {
            if name != &snapshot.name {
                emit_row_error(
                    &mut output,
                    &row,
                    "corrupt",
                    &format!(
                        "manifest snapshot_name `{name}` does not match xid {:#x} (`{}`)",
                        row.snapshot_xid, snapshot.name
                    ),
                )?;
                summary.observe("error");
                continue;
            }
        } else {
            row.snapshot_name = Some(snapshot.name.clone());
        }
        let target = match secure_target(&output_root, &row.output_relative, opts.dry_run) {
            Ok(target) => target,
            Err(error) => {
                emit_row_error(&mut output, &row, error.kind().code(), &error.to_string())?;
                summary.observe("error");
                continue;
            }
        };
        if !claimed_targets.insert(target.clone()) {
            emit_row_error(
                &mut output,
                &row,
                "usage",
                "duplicate output_relative_path resolves to the same target",
            )?;
            summary.observe("error");
            continue;
        }
        match fs::symlink_metadata(&target) {
            Ok(metadata) if !opts.overwrite => {
                emit_skipped(&mut output, &row, "destination already exists")?;
                summary.observe("skipped-exists");
                continue;
            }
            Ok(metadata) if metadata.is_dir() => {
                emit_row_error(
                    &mut output,
                    &row,
                    "usage",
                    "destination is a directory and cannot be replaced by a leaf",
                )?;
                summary.observe("error");
                continue;
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                emit_row_error(&mut output, &row, ErrorKind::Io.code(), &error.to_string())?;
                summary.observe("error");
                continue;
            }
        }
        let current_source_path = row.source_path.clone();
        queue.entry(row.snapshot_xid).or_default().push(WorkItem {
            row,
            target,
            current_source_path,
            primary: true,
            attempts: Vec::new(),
        });
    }

    // A hard-link key includes the source snapshot. The same FSOID in two
    // snapshots is not evidence that the byte streams are identical.
    let mut hardlinks: HashMap<(u64, u64), PathBuf> = HashMap::new();
    while let Some((&snapshot_xid, _)) = queue.last_key_value() {
        let mut work = queue
            .remove(&snapshot_xid)
            .expect("last_key_value key must remain present");
        eprintln!(
            "recover-manifest: snapshot xid={snapshot_xid:#x} attempts={}",
            work.len()
        );

        let view = snapshots_by_xid
            .get(&snapshot_xid)
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::ObjectNotFound,
                    format!("manifest references unknown snapshot xid {snapshot_xid:#x}"),
                )
            })
            .and_then(|snapshot| snapshot::open_snapshot(&live, &live_bt, snapshot));

        match view {
            Ok(view) => {
                for warning in &view.warnings {
                    eprintln!(
                        "recover-manifest: snapshot xid={snapshot_xid:#x} warning: {warning}"
                    );
                }
                let bt = view.btree();
                for mut item in work.drain(..) {
                    let attempt_number = item.attempts.len() + 1;
                    let attempt = recover_attempt(
                        &view,
                        &bt,
                        snapshot_xid,
                        snapshots_by_xid
                            .get(&snapshot_xid)
                            .map(|snapshot| snapshot.name.as_str()),
                        &item.current_source_path,
                        &item.target,
                        &item.row,
                        item.primary,
                        attempt_number,
                        opts,
                        &mut hardlinks,
                    );
                    item.attempts.push(attempt);
                    finish_or_reschedule(
                        item,
                        snapshot_xid,
                        &snapshots_by_xid,
                        opts,
                        &mut queue,
                        &mut output,
                        &mut summary,
                    )?;
                }
                for warning in bt.take_warnings() {
                    eprintln!(
                        "recover-manifest: snapshot xid={snapshot_xid:#x} btree warning: {warning}"
                    );
                }
            }
            Err(error) => {
                for mut item in work.drain(..) {
                    item.attempts.push(Attempt::error(
                        snapshot_xid,
                        snapshots_by_xid
                            .get(&snapshot_xid)
                            .map(|snapshot| snapshot.name.clone()),
                        item.current_source_path.clone(),
                        error.clone(),
                        true,
                    ));
                    finish_or_reschedule(
                        item,
                        snapshot_xid,
                        &snapshots_by_xid,
                        opts,
                        &mut queue,
                        &mut output,
                        &mut summary,
                    )?;
                }
            }
        }
    }
    output.flush()?;

    eprintln!(
        "recover-manifest: rows={} recovered={} dry_run={} skipped_exists={} partial={} errors={}",
        summary.rows,
        summary.recovered,
        summary.dry_run,
        summary.skipped,
        summary.partial,
        summary.errors
    );
    Ok(if summary.incomplete() {
        ErrorKind::PartialRecovery.exit_code()
    } else {
        0
    })
}

fn validate_options(opts: &Options) -> Result<()> {
    if opts.snapshot.is_some() || opts.snapshot_xid.is_some() {
        return Err(Error::new(
            ErrorKind::Usage,
            "`recover-manifest` reads snapshot_xid from each row; do not pass --snapshot or --snapshot-xid",
        ));
    }
    if opts.path.is_some() || opts.fsoid.is_some() || opts.output.is_some() {
        return Err(Error::new(
            ErrorKind::Usage,
            "use --manifest and --output-root, not --path, --fsoid, or --output",
        ));
    }
    if let Some(format) = &opts.format {
        if format != "jsonl" {
            return Err(Error::new(
                ErrorKind::Usage,
                "`recover-manifest` accepts JSONL only",
            ));
        }
    }
    if opts.fallback_history {
        let template = opts.path_template.as_deref().ok_or_else(|| {
            Error::new(
                ErrorKind::Usage,
                "--fallback-history requires --path-template <absolute-snapshot-root>",
            )
        })?;
        if !template.starts_with('/') || template.contains('\0') {
            return Err(Error::new(
                ErrorKind::Usage,
                "--path-template must be an absolute APFS path without NUL",
            ));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn recover_attempt(
    vol: &Volume,
    bt: &BtreeReader<'_>,
    snapshot_xid: u64,
    snapshot_name: Option<&str>,
    source_path: &str,
    target: &Path,
    row: &ManifestRow,
    primary: bool,
    attempt_number: usize,
    opts: &Options,
    hardlinks: &mut HashMap<(u64, u64), PathBuf>,
) -> Attempt {
    match recover_attempt_inner(
        vol,
        bt,
        snapshot_xid,
        snapshot_name,
        source_path,
        target,
        row,
        primary,
        attempt_number,
        opts,
        hardlinks,
    ) {
        Ok(attempt) => attempt,
        Err(error) => Attempt::error(
            snapshot_xid,
            snapshot_name.map(str::to_string),
            source_path.to_string(),
            error,
            true,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn recover_attempt_inner(
    vol: &Volume,
    bt: &BtreeReader<'_>,
    snapshot_xid: u64,
    snapshot_name: Option<&str>,
    source_path: &str,
    target: &Path,
    row: &ManifestRow,
    primary: bool,
    attempt_number: usize,
    opts: &Options,
    hardlinks: &mut HashMap<(u64, u64), PathBuf>,
) -> Result<Attempt> {
    let resolved = apath::resolve(vol, bt, source_path)?;
    if primary {
        if let Some(expected) = row.expected_fsoid {
            if resolved.fsoid != expected {
                return Err(Error::new(
                    ErrorKind::Corrupt,
                    format!(
                        "manifest FSOID {expected:#x} does not match resolved FSOID {:#x}",
                        resolved.fsoid
                    ),
                ));
            }
        }
    }
    let records = vol.records(bt, resolved.fsoid)?;
    let inode = Volume::inode_from_records(&records)?.ok_or_else(|| {
        Error::new(
            ErrorKind::ObjectNotFound,
            format!("no inode for FSOID {:#x}", resolved.fsoid),
        )
    })?;
    let actual_type = if inode.is_regular() {
        "file"
    } else if inode.is_symlink() {
        "symlink"
    } else {
        return Err(Error::new(
            ErrorKind::UnsupportedFeature,
            format!(
                "manifest leaf resolved to unsupported inode mode {:#o}",
                inode.mode
            ),
        ));
    };
    if let Some(expected_type) = &row.expected_type {
        if expected_type != actual_type {
            return Err(Error::new(
                ErrorKind::Corrupt,
                format!("manifest type `{expected_type}` resolved as `{actual_type}`"),
            ));
        }
    }

    if opts.dry_run {
        let file_opts = Options {
            output: Some(target.display().to_string()),
            overwrite: false,
            ..opts.clone()
        };
        let result = super::recover::recover_single_file(
            vol,
            bt,
            resolved.fsoid,
            &inode,
            &records,
            &file_opts,
        )?;
        return Ok(Attempt {
            snapshot_xid,
            snapshot_name: snapshot_name.map(str::to_string),
            source_path: source_path.to_string(),
            fsoid: Some(resolved.fsoid),
            status: result.status,
            bytes: result.bytes,
            note: result.note,
            error_code: None,
            error_message: None,
            fallback_eligible: false,
        });
    }

    let staging = match staging_path(target, row.line, attempt_number) {
        Ok(staging) => staging,
        Err(error) => {
            let mut attempt = Attempt::error(
                snapshot_xid,
                snapshot_name.map(str::to_string),
                source_path.to_string(),
                error,
                false,
            );
            attempt.fsoid = Some(resolved.fsoid);
            return Ok(attempt);
        }
    };
    let hardlink_key = (snapshot_xid, resolved.fsoid);
    if inode.nchildren_or_nlink > 1 {
        if let Some(first) = hardlinks.get(&hardlink_key).cloned() {
            if fs::symlink_metadata(&first).is_ok() && fs::hard_link(&first, &staging).is_ok() {
                if let Err(error) = install_staging(&staging, target, opts.overwrite) {
                    let _ = fs::remove_file(&staging);
                    let mut attempt = Attempt::error(
                        snapshot_xid,
                        snapshot_name.map(str::to_string),
                        source_path.to_string(),
                        error,
                        false,
                    );
                    attempt.fsoid = Some(resolved.fsoid);
                    return Ok(attempt);
                }
                return Ok(Attempt {
                    snapshot_xid,
                    snapshot_name: snapshot_name.map(str::to_string),
                    source_path: source_path.to_string(),
                    fsoid: Some(resolved.fsoid),
                    status: "recovered",
                    bytes: 0,
                    note: Some("hardlink to an earlier manifest output".to_string()),
                    error_code: None,
                    error_message: None,
                    fallback_eligible: false,
                });
            }
            let _ = fs::remove_file(&staging);
        }
    }

    let file_opts = Options {
        output: Some(staging.display().to_string()),
        overwrite: false,
        dry_run: false,
        ..opts.clone()
    };
    let result = match super::recover::recover_single_file(
        vol,
        bt,
        resolved.fsoid,
        &inode,
        &records,
        &file_opts,
    ) {
        Ok(result) => result,
        Err(error) => {
            let _ = fs::remove_file(&staging);
            let fallback_eligible =
                !matches!(error.kind(), ErrorKind::Usage | ErrorKind::PermissionDenied);
            let mut attempt = Attempt::error(
                snapshot_xid,
                snapshot_name.map(str::to_string),
                source_path.to_string(),
                error,
                fallback_eligible,
            );
            attempt.fsoid = Some(resolved.fsoid);
            return Ok(attempt);
        }
    };
    if result.status != "recovered" {
        let _ = fs::remove_file(&staging);
        let mut note = result.note;
        let removal_note = "partial staging output was removed";
        note = Some(match note {
            Some(note) => format!("{note}; {removal_note}"),
            None => removal_note.to_string(),
        });
        return Ok(Attempt {
            snapshot_xid,
            snapshot_name: snapshot_name.map(str::to_string),
            source_path: source_path.to_string(),
            fsoid: Some(resolved.fsoid),
            status: result.status,
            bytes: result.bytes,
            note,
            error_code: Some(ErrorKind::PartialRecovery.code()),
            error_message: Some("file content was not fully recoverable".to_string()),
            fallback_eligible: true,
        });
    }
    if inode.is_symlink()
        && !fs::symlink_metadata(&staging)
            .map(|metadata| metadata.file_type().is_symlink())
            .unwrap_or(false)
    {
        let _ = fs::remove_file(&staging);
        return Err(Error::new(
            ErrorKind::Corrupt,
            "symlink recovery produced a non-symlink output",
        ));
    }
    if let Err(error) = install_staging(&staging, target, opts.overwrite) {
        let _ = fs::remove_file(&staging);
        let mut attempt = Attempt::error(
            snapshot_xid,
            snapshot_name.map(str::to_string),
            source_path.to_string(),
            error,
            false,
        );
        attempt.fsoid = Some(resolved.fsoid);
        return Ok(attempt);
    }
    if inode.nchildren_or_nlink > 1 {
        hardlinks
            .entry(hardlink_key)
            .or_insert_with(|| target.to_path_buf());
    }
    Ok(Attempt {
        snapshot_xid,
        snapshot_name: snapshot_name.map(str::to_string),
        source_path: source_path.to_string(),
        fsoid: Some(resolved.fsoid),
        status: "recovered",
        bytes: result.bytes,
        note: result.note,
        error_code: None,
        error_message: None,
        fallback_eligible: false,
    })
}

#[allow(clippy::too_many_arguments)]
fn finish_or_reschedule(
    mut item: WorkItem,
    current_xid: u64,
    snapshots: &BTreeMap<u64, SnapshotInfo>,
    opts: &Options,
    queue: &mut BTreeMap<u64, Vec<WorkItem>>,
    output: &mut dyn Write,
    summary: &mut Summary,
) -> Result<()> {
    if item
        .attempts
        .last()
        .is_some_and(|attempt| attempt.is_success())
    {
        let status = item.attempts.last().unwrap().status;
        emit_work_item(output, &item, status)?;
        summary.observe(status);
        return Ok(());
    }

    if opts.fallback_history
        && item
            .attempts
            .last()
            .is_some_and(|attempt| attempt.fallback_eligible)
    {
        if let Some((older_xid, older)) = snapshots.range(..current_xid).next_back() {
            let relative_path = item
                .row
                .relative_path
                .as_deref()
                .expect("fallback rows are validated to contain relative_path");
            item.current_source_path = fallback_source_path(
                opts.path_template.as_deref().unwrap(),
                &older.name,
                relative_path,
            );
            item.primary = false;
            queue.entry(*older_xid).or_default().push(item);
            return Ok(());
        }
    }

    let status = if item
        .attempts
        .iter()
        .any(|attempt| attempt.status == "partial")
    {
        "partial"
    } else {
        "error"
    };
    emit_work_item(output, &item, status)?;
    summary.observe(status);
    Ok(())
}

fn fallback_source_path(template: &str, snapshot_name: &str, relative_path: &str) -> String {
    let snapshot_dir = snapshot_name
        .strip_prefix("com.apple.TimeMachine.")
        .unwrap_or(snapshot_name);
    let root = template
        .replace("{{snapshot-dir}}", snapshot_dir)
        .replace("{snapshot-dir}", snapshot_dir)
        .replace("{{snapshot}}", snapshot_name)
        .replace("{snapshot}", snapshot_name);
    let root = if root.len() > 1 {
        root.trim_end_matches('/')
    } else {
        root.as_str()
    };
    format!("{root}/{relative_path}")
}

fn staging_path(target: &Path, line: u64, attempt: usize) -> Result<PathBuf> {
    let parent = target.parent().ok_or_else(|| {
        Error::new(
            ErrorKind::Usage,
            format!("output target `{}` has no parent", target.display()),
        )
    })?;
    for collision in 0..1024u32 {
        let candidate = parent.join(format!(
            "_com.apfsrelic.recover_manifest_{}_{}_{}_{}",
            std::process::id(),
            line,
            attempt,
            collision
        ));
        match fs::symlink_metadata(&candidate) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(candidate),
            Ok(_) => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(Error::new(
        ErrorKind::Io,
        format!(
            "could not allocate a staging name beside `{}`",
            target.display()
        ),
    ))
}

/// Install a completely recovered staging leaf. Without `--overwrite`, link or
/// symlink creation supplies create-new semantics, so a destination that races
/// into existence is never silently replaced.
fn install_staging(staging: &Path, target: &Path, overwrite: bool) -> Result<()> {
    if overwrite {
        if fs::symlink_metadata(target)
            .map(|metadata| metadata.is_dir())
            .unwrap_or(false)
        {
            return Err(Error::new(
                ErrorKind::Usage,
                format!("refusing to replace directory `{}`", target.display()),
            ));
        }
        fs::rename(staging, target)?;
        return Ok(());
    }

    let metadata = fs::symlink_metadata(staging)?;
    if metadata.file_type().is_symlink() {
        let link_target = fs::read_link(staging)?;
        std::os::unix::fs::symlink(link_target, target)?;
    } else {
        fs::hard_link(staging, target)?;
    }
    if let Err(error) = fs::remove_file(staging) {
        let _ = fs::remove_file(target);
        return Err(error.into());
    }
    Ok(())
}

fn prepare_output_root(path: &Path, dry_run: bool) -> Result<PathBuf> {
    if path.as_os_str().is_empty() {
        return Err(Error::new(ErrorKind::Usage, "output root is empty"));
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    match fs::symlink_metadata(&absolute) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(Error::new(
                    ErrorKind::Usage,
                    "output root must not itself be a symbolic link",
                ));
            }
            if !metadata.is_dir() {
                return Err(Error::new(
                    ErrorKind::Usage,
                    "output root exists but is not a directory",
                ));
            }
            Ok(fs::canonicalize(absolute)?)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound && dry_run => Ok(absolute),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(&absolute)?;
            let metadata = fs::symlink_metadata(&absolute)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(Error::new(
                    ErrorKind::Usage,
                    "created output root is not a real directory",
                ));
            }
            Ok(fs::canonicalize(absolute)?)
        }
        Err(error) => Err(error.into()),
    }
}

fn secure_target(root: &Path, relative: &Path, dry_run: bool) -> Result<PathBuf> {
    let components: Vec<_> = relative.components().collect();
    if components.is_empty() {
        return Err(Error::new(
            ErrorKind::Usage,
            "output relative path is empty",
        ));
    }
    let mut target = root.to_path_buf();
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(name) = component else {
            return Err(Error::new(
                ErrorKind::Usage,
                "output path must be relative and contain no `.` or `..` components",
            ));
        };
        target.push(name);
        if index + 1 == components.len() {
            break;
        }
        match fs::symlink_metadata(&target) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(Error::new(
                    ErrorKind::Usage,
                    format!(
                        "output parent `{}` is a symbolic link; refusing boundary escape",
                        target.display()
                    ),
                ));
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err(Error::new(
                    ErrorKind::Usage,
                    format!("output parent `{}` is not a directory", target.display()),
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound && dry_run => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => fs::create_dir(&target)?,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(target)
}

fn emit_invalid(output: &mut dyn Write, line: u64, message: &str) -> Result<()> {
    let value = Json::obj()
        .set("schema_version", SCHEMA_VERSION as u64)
        .set("record", "recovery_result")
        .set("line", line)
        .set("status", "error")
        .set(
            "error",
            Json::obj().set("code", "usage").set("message", message),
        );
    emit_jsonl(output, value)
}

fn emit_row_error(
    output: &mut dyn Write,
    row: &ManifestRow,
    code: &str,
    message: &str,
) -> Result<()> {
    let value = base_result(row)
        .set("status", "error")
        .set("attempted_snapshot_xids", Json::Array(Vec::new()))
        .set("attempted_snapshot_names", Json::Array(Vec::new()))
        .set("actual_snapshot_xid", Json::Null)
        .set("actual_snapshot_name", Json::Null)
        .set("actual_source_path", Json::Null)
        .set("fallback_used", false)
        .set("fsoid", Json::Null)
        .set("bytes", 0u64)
        .set("note", Json::Null)
        .set("attempts", Json::Array(Vec::new()))
        .set(
            "error",
            Json::obj().set("code", code).set("message", message),
        );
    emit_jsonl(output, value)
}

fn emit_skipped(output: &mut dyn Write, row: &ManifestRow, note: &str) -> Result<()> {
    let value = base_result(row)
        .set("status", "skipped-exists")
        .set("attempted_snapshot_xids", Json::Array(Vec::new()))
        .set("attempted_snapshot_names", Json::Array(Vec::new()))
        .set("actual_snapshot_xid", Json::Null)
        .set("actual_snapshot_name", Json::Null)
        .set("actual_source_path", Json::Null)
        .set("fallback_used", false)
        .set("fsoid", Json::Null)
        .set("bytes", 0u64)
        .set("note", note)
        .set("attempts", Json::Array(Vec::new()))
        .set("error", Json::Null);
    emit_jsonl(output, value)
}

fn emit_work_item(output: &mut dyn Write, item: &WorkItem, status: &str) -> Result<()> {
    let success = item.attempts.iter().find(|attempt| attempt.is_success());
    let attempted_xids = item
        .attempts
        .iter()
        .map(|attempt| Json::UInt(attempt.snapshot_xid))
        .collect();
    let attempted_names = item
        .attempts
        .iter()
        .map(|attempt| Json::from(attempt.snapshot_name.clone()))
        .collect();
    let attempts = item.attempts.iter().map(Attempt::to_json).collect();
    let best_partial = item
        .attempts
        .iter()
        .rev()
        .find(|attempt| attempt.status == "partial");
    let representative = success.or(best_partial).or_else(|| item.attempts.last());
    let mut value = base_result(&item.row)
        .set("status", status)
        .set("attempted_snapshot_xids", Json::Array(attempted_xids))
        .set("attempted_snapshot_names", Json::Array(attempted_names))
        .set(
            "actual_snapshot_xid",
            success.map(|attempt| attempt.snapshot_xid),
        )
        .set(
            "actual_snapshot_name",
            success.and_then(|attempt| attempt.snapshot_name.clone()),
        )
        .set(
            "actual_source_path",
            success.map(|attempt| attempt.source_path.clone()),
        )
        .set(
            "fallback_used",
            success
                .map(|attempt| attempt.snapshot_xid != item.row.snapshot_xid)
                .unwrap_or(false),
        )
        .set(
            "fsoid",
            representative.and_then(|attempt| attempt.fsoid.map(|id| format!("{id:#x}"))),
        )
        .set(
            "bytes",
            representative.map(|attempt| attempt.bytes).unwrap_or(0),
        )
        .set(
            "note",
            representative.and_then(|attempt| attempt.note.clone()),
        )
        .set("attempts", Json::Array(attempts));
    if matches!(status, "recovered" | "dry-run") {
        value.insert("error", Json::Null);
    } else {
        let last = item.attempts.last();
        let code = if status == "partial" {
            ErrorKind::PartialRecovery.code()
        } else {
            last.and_then(|attempt| attempt.error_code)
                .unwrap_or(ErrorKind::ObjectNotFound.code())
        };
        let message = if status == "partial" {
            "no snapshot produced complete content"
        } else {
            last.and_then(|attempt| attempt.error_message.as_deref())
                .unwrap_or("no snapshot produced recoverable content")
        };
        value.insert(
            "error",
            Json::obj().set("code", code).set("message", message),
        );
    }
    emit_jsonl(output, value)
}

fn base_result(row: &ManifestRow) -> Json {
    Json::obj()
        .set("schema_version", SCHEMA_VERSION as u64)
        .set("record", "recovery_result")
        .set("line", row.line)
        .set("requested_snapshot_xid", row.snapshot_xid)
        .set("requested_snapshot_name", row.snapshot_name.clone())
        .set("requested_source_path", row.source_path.as_str())
        .set("output_relative_path", row.output_relative_path.as_str())
}

fn emit_jsonl(output: &mut dyn Write, value: Json) -> Result<()> {
    writeln!(output, "{}", value.to_compact_string())?;
    output.flush()?;
    Ok(())
}

fn read_manifest(path: &Path, fallback: bool) -> Result<(Vec<ManifestRow>, Vec<InvalidRow>)> {
    let reader: Box<dyn BufRead> = if path == Path::new("-") {
        Box::new(BufReader::new(io::stdin()))
    } else {
        Box::new(BufReader::new(File::open(path)?))
    };
    read_manifest_from(reader, fallback)
}

fn read_manifest_from(
    mut reader: Box<dyn BufRead>,
    fallback: bool,
) -> Result<(Vec<ManifestRow>, Vec<InvalidRow>)> {
    let mut rows = Vec::new();
    let mut invalid = Vec::new();
    let mut buffer = Vec::new();
    let mut line = 0u64;
    loop {
        buffer.clear();
        let bytes = reader.read_until(b'\n', &mut buffer)?;
        if bytes == 0 {
            break;
        }
        line = line.saturating_add(1);
        if buffer.len() > MAX_MANIFEST_LINE {
            invalid.push(InvalidRow {
                line,
                message: format!("JSONL row exceeds {MAX_MANIFEST_LINE} bytes"),
            });
            continue;
        }
        if buffer.last() == Some(&b'\n') {
            buffer.pop();
        }
        if buffer.last() == Some(&b'\r') {
            buffer.pop();
        }
        if buffer.iter().all(|byte| byte.is_ascii_whitespace()) {
            continue;
        }
        let text = match std::str::from_utf8(&buffer) {
            Ok(text) => text,
            Err(error) => {
                invalid.push(InvalidRow {
                    line,
                    message: format!("row is not UTF-8 JSON: {error}"),
                });
                continue;
            }
        };
        match parse_manifest_row(text, line, fallback) {
            Ok(row) => rows.push(row),
            Err(message) => invalid.push(InvalidRow { line, message }),
        }
    }
    Ok((rows, invalid))
}

fn parse_manifest_row(
    text: &str,
    line: u64,
    fallback: bool,
) -> std::result::Result<ManifestRow, String> {
    let value = JsonParser::new(text).parse()?;
    let ParsedJson::Object(fields) = value else {
        return Err("JSONL row must be an object".to_string());
    };
    let snapshot_xid = json_u64(required_field(&fields, "snapshot_xid")?, "snapshot_xid")?;
    let snapshot_name = optional_string(&fields, "snapshot_name")?;
    let source_path = json_string(required_field(&fields, "source_path")?, "source_path")?;
    if !source_path.starts_with('/') || source_path.contains('\0') {
        return Err("source_path must be an absolute APFS path without NUL".to_string());
    }
    let output_relative_path = json_string(
        required_field(&fields, "output_relative_path")?,
        "output_relative_path",
    )?;
    let output_relative = validated_relative_path(&output_relative_path, "output_relative_path")?;
    let relative_path = optional_string(&fields, "relative_path")?;
    if fallback && relative_path.is_none() {
        return Err("--fallback-history requires relative_path in every row".to_string());
    }
    if let Some(relative_path) = &relative_path {
        let _ = validated_relative_path(relative_path, "relative_path")?;
    }
    let expected_fsoid = optional_u64(&fields, "fsoid")?;
    let expected_type = optional_string(&fields, "type")?;
    if let Some(expected_type) = &expected_type {
        if expected_type != "file" && expected_type != "symlink" {
            return Err(format!(
                "type must be `file` or `symlink`, got `{expected_type}`"
            ));
        }
    }
    Ok(ManifestRow {
        line,
        snapshot_xid,
        snapshot_name,
        source_path,
        output_relative_path,
        output_relative,
        relative_path,
        expected_fsoid,
        expected_type,
    })
}

fn validated_relative_path(value: &str, field: &str) -> std::result::Result<PathBuf, String> {
    if value.is_empty() || value.contains('\0') || value.starts_with('/') || value.ends_with('/') {
        return Err(format!(
            "{field} must be a non-empty relative leaf path without NUL"
        ));
    }
    if value
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(format!(
            "{field} contains an empty, `.` or `..` path component"
        ));
    }
    let path = PathBuf::from(value);
    if path
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!(
            "{field} must contain only normal components, never `.` or `..`"
        ));
    }
    Ok(path)
}

fn required_field<'a>(
    fields: &'a [(String, ParsedJson)],
    name: &str,
) -> std::result::Result<&'a ParsedJson, String> {
    unique_field(fields, name)?.ok_or_else(|| format!("missing required field `{name}`"))
}

fn unique_field<'a>(
    fields: &'a [(String, ParsedJson)],
    name: &str,
) -> std::result::Result<Option<&'a ParsedJson>, String> {
    let mut matches = fields.iter().filter(|(key, _)| key == name);
    let value = matches.next().map(|(_, value)| value);
    if matches.next().is_some() {
        return Err(format!("duplicate field `{name}`"));
    }
    Ok(value)
}

fn json_string(value: &ParsedJson, field: &str) -> std::result::Result<String, String> {
    match value {
        ParsedJson::String(value) => Ok(value.clone()),
        _ => Err(format!("field `{field}` must be a JSON string")),
    }
}

fn optional_string(
    fields: &[(String, ParsedJson)],
    name: &str,
) -> std::result::Result<Option<String>, String> {
    match unique_field(fields, name)? {
        None | Some(ParsedJson::Null) => Ok(None),
        Some(value) => json_string(value, name).map(Some),
    }
}

fn json_u64(value: &ParsedJson, field: &str) -> std::result::Result<u64, String> {
    let text = match value {
        ParsedJson::Number(value) | ParsedJson::String(value) => value,
        _ => return Err(format!("field `{field}` must be an unsigned integer")),
    };
    parse_number(text).ok_or_else(|| format!("field `{field}` is not a valid u64: `{text}`"))
}

fn optional_u64(
    fields: &[(String, ParsedJson)],
    name: &str,
) -> std::result::Result<Option<u64>, String> {
    match unique_field(fields, name)? {
        None | Some(ParsedJson::Null) => Ok(None),
        Some(value) => json_u64(value, name).map(Some),
    }
}

#[derive(Debug, PartialEq)]
enum ParsedJson {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<ParsedJson>),
    Object(Vec<(String, ParsedJson)>),
}

struct JsonParser<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> JsonParser<'a> {
    fn new(input: &'a str) -> JsonParser<'a> {
        JsonParser {
            input: input.as_bytes(),
            offset: 0,
        }
    }

    fn parse(mut self) -> std::result::Result<ParsedJson, String> {
        let value = self.parse_value(0)?;
        self.whitespace();
        if self.offset != self.input.len() {
            return Err(format!("trailing JSON data at byte {}", self.offset));
        }
        Ok(value)
    }

    fn parse_value(&mut self, depth: usize) -> std::result::Result<ParsedJson, String> {
        if depth > MAX_JSON_DEPTH {
            return Err("JSON nesting is too deep".to_string());
        }
        self.whitespace();
        match self.peek() {
            Some(b'n') => {
                self.literal(b"null")?;
                Ok(ParsedJson::Null)
            }
            Some(b't') => {
                self.literal(b"true")?;
                Ok(ParsedJson::Bool(true))
            }
            Some(b'f') => {
                self.literal(b"false")?;
                Ok(ParsedJson::Bool(false))
            }
            Some(b'"') => self.parse_string().map(ParsedJson::String),
            Some(b'[') => self.parse_array(depth + 1),
            Some(b'{') => self.parse_object(depth + 1),
            Some(b'-' | b'0'..=b'9') => self.parse_number().map(ParsedJson::Number),
            Some(byte) => Err(format!(
                "unexpected byte {byte:#x} at JSON offset {}",
                self.offset
            )),
            None => Err("unexpected end of JSON".to_string()),
        }
    }

    fn parse_array(&mut self, depth: usize) -> std::result::Result<ParsedJson, String> {
        self.expect(b'[')?;
        self.whitespace();
        let mut values = Vec::new();
        if self.consume(b']') {
            return Ok(ParsedJson::Array(values));
        }
        loop {
            values.push(self.parse_value(depth)?);
            self.whitespace();
            if self.consume(b']') {
                break;
            }
            self.expect(b',')?;
        }
        Ok(ParsedJson::Array(values))
    }

    fn parse_object(&mut self, depth: usize) -> std::result::Result<ParsedJson, String> {
        self.expect(b'{')?;
        self.whitespace();
        let mut fields = Vec::new();
        if self.consume(b'}') {
            return Ok(ParsedJson::Object(fields));
        }
        loop {
            self.whitespace();
            let key = self.parse_string()?;
            self.whitespace();
            self.expect(b':')?;
            let value = self.parse_value(depth)?;
            fields.push((key, value));
            self.whitespace();
            if self.consume(b'}') {
                break;
            }
            self.expect(b',')?;
        }
        Ok(ParsedJson::Object(fields))
    }

    fn parse_string(&mut self) -> std::result::Result<String, String> {
        self.expect(b'"')?;
        let mut output = Vec::new();
        loop {
            let byte = self
                .next()
                .ok_or_else(|| "unterminated JSON string".to_string())?;
            match byte {
                b'"' => {
                    return String::from_utf8(output)
                        .map_err(|error| format!("JSON string is not UTF-8: {error}"));
                }
                b'\\' => {
                    let escaped = self
                        .next()
                        .ok_or_else(|| "unterminated JSON escape".to_string())?;
                    match escaped {
                        b'"' | b'\\' | b'/' => output.push(escaped),
                        b'b' => output.push(0x08),
                        b'f' => output.push(0x0c),
                        b'n' => output.push(b'\n'),
                        b'r' => output.push(b'\r'),
                        b't' => output.push(b'\t'),
                        b'u' => {
                            let first = self.hex4()?;
                            let scalar = if (0xd800..=0xdbff).contains(&first) {
                                self.expect(b'\\')?;
                                self.expect(b'u')?;
                                let second = self.hex4()?;
                                if !(0xdc00..=0xdfff).contains(&second) {
                                    return Err("invalid low surrogate in JSON string".to_string());
                                }
                                0x10000
                                    + (((first as u32 - 0xd800) << 10) | (second as u32 - 0xdc00))
                            } else if (0xdc00..=0xdfff).contains(&first) {
                                return Err("lone low surrogate in JSON string".to_string());
                            } else {
                                first as u32
                            };
                            let character = char::from_u32(scalar).ok_or_else(|| {
                                "invalid Unicode scalar in JSON string".to_string()
                            })?;
                            let mut encoded = [0u8; 4];
                            output
                                .extend_from_slice(character.encode_utf8(&mut encoded).as_bytes());
                        }
                        _ => return Err(format!("invalid JSON escape `\\{}`", escaped as char)),
                    }
                }
                0x00..=0x1f => return Err("unescaped control byte in JSON string".to_string()),
                _ => output.push(byte),
            }
        }
    }

    fn parse_number(&mut self) -> std::result::Result<String, String> {
        let start = self.offset;
        self.consume(b'-');
        match self.peek() {
            Some(b'0') => {
                self.offset += 1;
                if matches!(self.peek(), Some(b'0'..=b'9')) {
                    return Err("JSON number has a leading zero".to_string());
                }
            }
            Some(b'1'..=b'9') => {
                self.offset += 1;
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.offset += 1;
                }
            }
            _ => return Err("invalid JSON number".to_string()),
        }
        if self.consume(b'.') {
            let fraction_start = self.offset;
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.offset += 1;
            }
            if self.offset == fraction_start {
                return Err("JSON fraction has no digits".to_string());
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.offset += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.offset += 1;
            }
            let exponent_start = self.offset;
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.offset += 1;
            }
            if self.offset == exponent_start {
                return Err("JSON exponent has no digits".to_string());
            }
        }
        std::str::from_utf8(&self.input[start..self.offset])
            .map(str::to_string)
            .map_err(|error| error.to_string())
    }

    fn hex4(&mut self) -> std::result::Result<u16, String> {
        let mut value = 0u16;
        for _ in 0..4 {
            let byte = self
                .next()
                .ok_or_else(|| "short JSON Unicode escape".to_string())?;
            let digit = match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                _ => return Err("non-hex digit in JSON Unicode escape".to_string()),
            };
            value = (value << 4) | digit as u16;
        }
        Ok(value)
    }

    fn literal(&mut self, literal: &[u8]) -> std::result::Result<(), String> {
        if self.input.get(self.offset..self.offset + literal.len()) == Some(literal) {
            self.offset += literal.len();
            Ok(())
        } else {
            Err(format!("invalid JSON literal at byte {}", self.offset))
        }
    }

    fn whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            self.offset += 1;
        }
    }

    fn expect(&mut self, byte: u8) -> std::result::Result<(), String> {
        if self.consume(byte) {
            Ok(())
        } else {
            Err(format!(
                "expected byte {byte:#x} at JSON offset {}",
                self.offset
            ))
        }
    }

    fn consume(&mut self, byte: u8) -> bool {
        if self.peek() == Some(byte) {
            self.offset += 1;
            true
        } else {
            false
        }
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.offset).copied()
    }

    fn next(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.offset += 1;
        Some(byte)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TestDir(PathBuf);

    impl TestDir {
        fn new(label: &str) -> TestDir {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "apfsrelic-recover-manifest-{label}-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir_all(&path).expect("create test directory");
            TestDir(path)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn parser_round_trips_control_paths_and_nested_fields() {
        let row = parse_manifest_row(
            r#"{"snapshot_xid":"0x2a","source_path":"/a\tb\r\n\ud83d\ude00","output_relative_path":"x\ty\r\nz","relative_path":"a/b","fsoid":"0x99","type":"file","ignored":[true,{"x":null}]}"#,
            7,
            true,
        )
        .expect("parse row");
        assert_eq!(row.snapshot_xid, 42);
        assert_eq!(row.source_path, "/a\tb\r\n😀");
        assert_eq!(row.output_relative_path, "x\ty\r\nz");
        assert_eq!(row.expected_fsoid, Some(0x99));
    }

    #[test]
    fn output_path_rejects_absolute_parent_and_empty_components() {
        assert!(validated_relative_path("/absolute", "p").is_err());
        assert!(validated_relative_path("a/../b", "p").is_err());
        assert!(validated_relative_path("a//b", "p").is_err());
        assert!(validated_relative_path("a/./b", "p").is_err());
        assert!(validated_relative_path("normal/a\tb\r\n", "p").is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn secure_target_rejects_symlink_parent() {
        let dir = TestDir::new("symlink-boundary");
        let outside = TestDir::new("outside");
        std::os::unix::fs::symlink(&outside.0, dir.0.join("escape")).expect("create symlink");
        let error = secure_target(&dir.0, Path::new("escape/file"), false)
            .expect_err("symlink parent must be rejected");
        assert_eq!(error.kind(), ErrorKind::Usage);
        assert!(!outside.0.join("file").exists());
    }

    #[test]
    fn no_overwrite_install_preserves_existing_target() {
        let dir = TestDir::new("no-overwrite");
        let staging = dir.0.join("staging");
        let target = dir.0.join("target");
        fs::write(&staging, b"new").expect("write staging");
        fs::write(&target, b"old").expect("write target");
        assert!(install_staging(&staging, &target, false).is_err());
        assert_eq!(fs::read(&target).expect("read target"), b"old");
    }

    #[test]
    fn fallback_path_expands_snapshot_without_touching_relative_bytes() {
        assert_eq!(
            fallback_source_path("/{snapshot}/Data/Users/me", "snap-1", "a\tb\r\nc"),
            "/snap-1/Data/Users/me/a\tb\r\nc"
        );
        assert_eq!(
            fallback_source_path(
                "/{snapshot-dir}/Data/Users/me",
                "com.apple.TimeMachine.2023-01-02.backup",
                "doc"
            ),
            "/2023-01-02.backup/Data/Users/me/doc"
        );
    }

    #[test]
    fn duplicate_security_fields_are_rejected() {
        let error = parse_manifest_row(
            r#"{"snapshot_xid":1,"snapshot_xid":2,"source_path":"/a","output_relative_path":"b"}"#,
            1,
            false,
        )
        .expect_err("duplicate snapshot xid");
        assert!(error.contains("duplicate field"));
    }

    #[test]
    fn partial_attempt_is_rescheduled_and_never_counted_as_success() {
        let row = ManifestRow {
            line: 1,
            snapshot_xid: 20,
            snapshot_name: Some("com.apple.TimeMachine.new.backup".to_string()),
            source_path: "/new/Data/Users/me/doc".to_string(),
            output_relative_path: "doc".to_string(),
            output_relative: PathBuf::from("doc"),
            relative_path: Some("doc".to_string()),
            expected_fsoid: None,
            expected_type: Some("file".to_string()),
        };
        let attempt = Attempt {
            snapshot_xid: 20,
            snapshot_name: row.snapshot_name.clone(),
            source_path: row.source_path.clone(),
            fsoid: Some(42),
            status: "partial",
            bytes: 10,
            note: None,
            error_code: Some("partial-recovery"),
            error_message: Some("incomplete".to_string()),
            fallback_eligible: true,
        };
        assert!(!attempt.is_success());

        let item = WorkItem {
            row,
            target: PathBuf::from("/output/doc"),
            current_source_path: "/new/Data/Users/me/doc".to_string(),
            primary: true,
            attempts: vec![attempt],
        };
        let snapshots = BTreeMap::from([
            (
                10,
                SnapshotInfo {
                    xid: 10,
                    name: "com.apple.TimeMachine.old.backup".to_string(),
                    sblock_oid: 1,
                    extentref_tree_oid: 0,
                    create_time: 0,
                    change_time: 0,
                },
            ),
            (
                20,
                SnapshotInfo {
                    xid: 20,
                    name: "com.apple.TimeMachine.new.backup".to_string(),
                    sblock_oid: 2,
                    extentref_tree_oid: 0,
                    create_time: 0,
                    change_time: 0,
                },
            ),
        ]);
        let opts = Options {
            fallback_history: true,
            path_template: Some("/{snapshot-dir}/Data/Users/me".to_string()),
            ..Options::default()
        };
        let mut queue = BTreeMap::new();
        let mut output = Vec::new();
        let mut summary = Summary::default();
        finish_or_reschedule(
            item,
            20,
            &snapshots,
            &opts,
            &mut queue,
            &mut output,
            &mut summary,
        )
        .expect("schedule fallback");

        let queued = queue.get(&10).expect("older snapshot work");
        assert_eq!(queued.len(), 1);
        assert_eq!(
            queued[0].current_source_path,
            "/old.backup/Data/Users/me/doc"
        );
        assert!(!queued[0].primary);
        assert!(output.is_empty());
        assert_eq!(summary.rows, 0);
    }
}
