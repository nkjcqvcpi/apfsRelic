//! `history-union` — build one deterministic leaf manifest across snapshots.
//!
//! The container is opened once. Snapshots are visited oldest first and the
//! newest observation of each raw, relative path wins. Directories participate
//! in conflict and completeness analysis but are not emitted as recovery rows.

use std::collections::{BTreeMap, HashMap};
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};

use crate::cli::Options;
use apfsrelic_core::apfs::history::{
    portable_collision_key, EntryType, HistoryEntry, HistoryUnion, LatestPresence,
};
use apfsrelic_core::apfs::path as apath;
use apfsrelic_core::apfs::snapshot::{self, SnapshotInfo};
use apfsrelic_core::apfs::time;
use apfsrelic_core::apfs::vol::Volume;
use apfsrelic_core::error::{Error, ErrorKind, Result};
use apfsrelic_core::json::{Json, SCHEMA_VERSION};

const MAX_SCAN_DEPTH: u32 = 4096;

#[derive(Debug)]
struct ScanError {
    snapshot_xid: u64,
    snapshot_name: String,
    source_path: String,
    relative_prefix: String,
    error: Error,
}

struct ScanDir {
    fsoid: u64,
    source_path: String,
    relative_path: String,
    depth: u32,
    ancestors: Vec<u64>,
}

struct ManifestRow {
    entry: HistoryEntry,
    logical_bytes: Option<u64>,
    metadata_error: Option<String>,
}

pub fn run(opts: &Options) -> Result<i32> {
    if opts.path.is_some() && opts.path_template.is_some() {
        return Err(Error::new(
            ErrorKind::Usage,
            "use only one of `--path` and `--path-template`",
        ));
    }
    let root_template = opts
        .path_template
        .as_deref()
        .or(opts.path.as_deref())
        .ok_or_else(|| {
            Error::new(
                ErrorKind::Usage,
                "`history-union` requires `--path-template <absolute-path>` (or `--path`)",
            )
        })?;
    if !root_template.starts_with('/') {
        return Err(Error::new(
            ErrorKind::Usage,
            "history root path must be absolute",
        ));
    }

    let format = ManifestFormat::parse(opts.format.as_deref().unwrap_or("jsonl"))?;
    let opened = super::open(opts)?;
    let volume_index = super::resolve_volume_index(&opened, opts)?;
    let live = Volume::open(&opened.container, volume_index)?;
    let live_bt = live.btree();
    let all_snapshots = snapshot::list_snapshots(&live, &live_bt)?;
    let snapshots = select_snapshots(all_snapshots, opts)?;
    let latest = snapshots.last().cloned().ok_or_else(|| {
        Error::new(
            ErrorKind::ObjectNotFound,
            "volume has no snapshots at or before the requested boundary",
        )
    })?;

    if live.apsb.is_case_insensitive() || live.apsb.is_normalization_insensitive() {
        eprintln!(
            "history-union: warning: raw relative paths remain authoritative; collision_key is lowercase audit data, not exact APFS Unicode normalization"
        );
    }

    let mut union = HistoryUnion::new();
    let mut scan_errors = Vec::new();
    let mut latest_incomplete = Vec::new();
    for (position, snap) in snapshots.iter().enumerate() {
        let root = snapshot_root(root_template, &snap.name);
        eprintln!(
            "history-union: scanning {}/{} snapshot {:?} xid={:#x} root={:?}",
            position + 1,
            snapshots.len(),
            snap.name,
            snap.xid,
            root
        );

        let view = match snapshot::open_snapshot(&live, &live_bt, snap) {
            Ok(view) => view,
            Err(error) => {
                record_scan_error(
                    opts,
                    &mut scan_errors,
                    &mut latest_incomplete,
                    &latest,
                    snap,
                    &root,
                    "",
                    error,
                )?;
                continue;
            }
        };
        scan_snapshot(
            &view,
            snap,
            &latest,
            &root,
            opts,
            &mut union,
            &mut scan_errors,
            &mut latest_incomplete,
        )?;
    }

    let union_paths = union.len();
    let entries = union.finish(latest.xid, &latest_incomplete);
    let mut rows: Vec<ManifestRow> = entries
        .into_iter()
        .filter(|entry| entry.entry_type.is_leaf())
        .map(|entry| ManifestRow {
            entry,
            logical_bytes: None,
            metadata_error: None,
        })
        .collect();
    enrich_logical_sizes(&live, &live_bt, &snapshots, opts, &mut rows)?;

    let mut output = manifest_writer(opts)?;
    write_manifest(&mut output, format, &rows, &snapshots, &latest)?;
    output.flush()?;

    for failure in &scan_errors {
        eprintln!(
            "history-union: scan-error snapshot={:?} xid={:#x} source={:?} relative_prefix={:?} code={} message={}",
            failure.snapshot_name,
            failure.snapshot_xid,
            failure.source_path,
            failure.relative_prefix,
            failure.error.kind().code(),
            failure.error
        );
    }
    let historical_deleted = rows
        .iter()
        .filter(|row| decision(&row.entry).0 == "historical_deleted")
        .count();
    let unknown = rows
        .iter()
        .filter(|row| decision(&row.entry).0 == "unknown_latest_scan")
        .count();
    let conflicts = rows
        .iter()
        .filter(|row| decision(&row.entry).0 == "skip_path_conflict")
        .count();
    let metadata_errors = rows
        .iter()
        .filter(|row| row.metadata_error.is_some())
        .count();
    eprintln!(
        "history-union: snapshots={} union_paths={} leaf_rows={} historical_deleted={} unknown={} path_conflicts={} scan_errors={} metadata_errors={}",
        snapshots.len(),
        union_paths,
        rows.len(),
        historical_deleted,
        unknown,
        conflicts,
        scan_errors.len(),
        metadata_errors
    );

    if scan_errors.is_empty() && metadata_errors == 0 {
        Ok(0)
    } else {
        Ok(ErrorKind::PartialRecovery.exit_code())
    }
}

fn select_snapshots(mut snapshots: Vec<SnapshotInfo>, opts: &Options) -> Result<Vec<SnapshotInfo>> {
    if opts.snapshot.is_some() && opts.snapshot_xid.is_some() {
        return Err(Error::new(
            ErrorKind::Usage,
            "use only one of `--snapshot` and `--snapshot-xid` as the latest boundary",
        ));
    }
    snapshots.sort_by_key(|snapshot| snapshot.xid);
    let boundary = if let Some(xid) = opts.snapshot_xid {
        if !snapshots.iter().any(|snapshot| snapshot.xid == xid) {
            return Err(Error::new(
                ErrorKind::ObjectNotFound,
                format!("no snapshot with xid {xid:#x}"),
            ));
        }
        Some(xid)
    } else if let Some(name) = &opts.snapshot {
        Some(
            snapshots
                .iter()
                .find(|snapshot| &snapshot.name == name)
                .map(|snapshot| snapshot.xid)
                .ok_or_else(|| {
                    Error::new(
                        ErrorKind::ObjectNotFound,
                        format!("no snapshot named `{name}`"),
                    )
                })?,
        )
    } else {
        None
    };
    if let Some(boundary) = boundary {
        snapshots.retain(|snapshot| snapshot.xid <= boundary);
    }
    Ok(snapshots)
}

fn snapshot_root(template: &str, snapshot_name: &str) -> String {
    let directory_name = snapshot_name
        .strip_prefix("com.apple.TimeMachine.")
        .unwrap_or(snapshot_name);
    let expanded = template
        .replace("{snapshot-dir}", directory_name)
        .replace("{snapshot}", snapshot_name);
    if expanded.len() > 1 {
        expanded.trim_end_matches('/').to_string()
    } else {
        expanded
    }
}

#[allow(clippy::too_many_arguments)]
fn scan_snapshot(
    vol: &Volume,
    snap: &SnapshotInfo,
    latest: &SnapshotInfo,
    root: &str,
    opts: &Options,
    union: &mut HistoryUnion,
    scan_errors: &mut Vec<ScanError>,
    latest_incomplete: &mut Vec<String>,
) -> Result<()> {
    let bt = vol.btree();
    let resolved = match apath::resolve(vol, &bt, root) {
        Ok(resolved) => resolved,
        Err(error) if error.kind() == ErrorKind::PathNotFound => {
            let warnings = bt.take_warnings();
            // An absent root in an older snapshot is a valid empty observation.
            // An absent latest root, or a lookup with structural warnings, cannot
            // safely prove that every historical child was deleted.
            if snap.xid == latest.xid || !warnings.is_empty() {
                let mut message = error.to_string();
                if !warnings.is_empty() {
                    message.push_str(&format!("; B-tree warnings: {}", warnings.join("; ")));
                }
                record_scan_error(
                    opts,
                    scan_errors,
                    latest_incomplete,
                    latest,
                    snap,
                    root,
                    "",
                    Error::new(ErrorKind::PathNotFound, message),
                )?;
            }
            return Ok(());
        }
        Err(error) => {
            record_scan_error(
                opts,
                scan_errors,
                latest_incomplete,
                latest,
                snap,
                root,
                "",
                error,
            )?;
            return Ok(());
        }
    };
    if resolved.type_name != "dir" {
        return record_scan_error(
            opts,
            scan_errors,
            latest_incomplete,
            latest,
            snap,
            root,
            "",
            Error::new(
                ErrorKind::NotADirectory,
                format!("history root is a {}, not a directory", resolved.type_name),
            ),
        );
    }

    let mut stack = vec![ScanDir {
        fsoid: resolved.fsoid,
        source_path: root.to_string(),
        relative_path: String::new(),
        depth: 0,
        ancestors: vec![resolved.fsoid],
    }];
    while let Some(directory) = stack.pop() {
        let mut children = match vol.list_dir(&bt, directory.fsoid) {
            Ok(children) => children,
            Err(error) => {
                record_scan_error(
                    opts,
                    scan_errors,
                    latest_incomplete,
                    latest,
                    snap,
                    &directory.source_path,
                    &directory.relative_path,
                    error,
                )?;
                continue;
            }
        };
        for warning in bt.take_warnings() {
            record_scan_error(
                opts,
                scan_errors,
                latest_incomplete,
                latest,
                snap,
                &directory.source_path,
                &directory.relative_path,
                Error::new(ErrorKind::Corrupt, format!("B-tree warning: {warning}")),
            )?;
        }
        children.sort_by(|left, right| {
            (&left.name, left.file_id, left.flags).cmp(&(&right.name, right.file_id, right.flags))
        });
        for child in children.into_iter().rev() {
            let relative_path = join_relative(&directory.relative_path, &child.name);
            let source_path = join_absolute(&directory.source_path, &child.name);
            if !safe_component(&child.name) {
                record_scan_error(
                    opts,
                    scan_errors,
                    latest_incomplete,
                    latest,
                    snap,
                    &source_path,
                    &relative_path,
                    Error::new(ErrorKind::Corrupt, "unsafe directory-entry name"),
                )?;
                continue;
            }

            let entry_type = EntryType::from_name(child.type_name());
            union.observe(
                &relative_path,
                &source_path,
                entry_type,
                child.file_id,
                snap.xid,
            );
            if entry_type != EntryType::Dir {
                continue;
            }
            if directory.depth >= MAX_SCAN_DEPTH {
                record_scan_error(
                    opts,
                    scan_errors,
                    latest_incomplete,
                    latest,
                    snap,
                    &source_path,
                    &relative_path,
                    Error::new(
                        ErrorKind::Corrupt,
                        "history scan exceeded directory depth cap",
                    ),
                )?;
                continue;
            }
            if directory.ancestors.contains(&child.file_id) {
                record_scan_error(
                    opts,
                    scan_errors,
                    latest_incomplete,
                    latest,
                    snap,
                    &source_path,
                    &relative_path,
                    Error::new(ErrorKind::Corrupt, "directory cycle detected"),
                )?;
                continue;
            }
            let mut ancestors = directory.ancestors.clone();
            ancestors.push(child.file_id);
            stack.push(ScanDir {
                fsoid: child.file_id,
                source_path,
                relative_path,
                depth: directory.depth + 1,
                ancestors,
            });
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn record_scan_error(
    opts: &Options,
    scan_errors: &mut Vec<ScanError>,
    latest_incomplete: &mut Vec<String>,
    latest: &SnapshotInfo,
    snap: &SnapshotInfo,
    source_path: &str,
    relative_prefix: &str,
    error: Error,
) -> Result<()> {
    if !opts.best_effort {
        return Err(error.with_context(format!("snapshot {:?} path {:?}", snap.name, source_path)));
    }
    if snap.xid == latest.xid {
        latest_incomplete.push(relative_prefix.to_string());
    }
    scan_errors.push(ScanError {
        snapshot_xid: snap.xid,
        snapshot_name: snap.name.clone(),
        source_path: source_path.to_string(),
        relative_prefix: relative_prefix.to_string(),
        error,
    });
    Ok(())
}

fn safe_component(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains('/')
}

fn join_relative(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_string()
    } else {
        format!("{parent}/{name}")
    }
}

fn join_absolute(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{name}")
    } else {
        format!("{parent}/{name}")
    }
}

fn enrich_logical_sizes(
    live: &Volume,
    live_bt: &apfsrelic_core::apfs::btree::BtreeReader<'_>,
    snapshots: &[SnapshotInfo],
    opts: &Options,
    rows: &mut [ManifestRow],
) -> Result<()> {
    let snapshots_by_xid: BTreeMap<u64, &SnapshotInfo> =
        snapshots.iter().map(|snap| (snap.xid, snap)).collect();
    let mut rows_by_xid: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
    for (index, row) in rows.iter().enumerate() {
        rows_by_xid
            .entry(row.entry.snapshot_xid)
            .or_default()
            .push(index);
    }

    for (xid, indices) in rows_by_xid {
        let snap = snapshots_by_xid.get(&xid).ok_or_else(|| {
            Error::new(
                ErrorKind::Internal,
                format!("manifest winner references unselected snapshot {xid:#x}"),
            )
        })?;
        let view = match snapshot::open_snapshot(live, live_bt, snap) {
            Ok(view) => view,
            Err(error) if opts.best_effort => {
                let message = format!("cannot reopen winning snapshot: {error}");
                for index in indices {
                    rows[index].metadata_error = Some(message.clone());
                }
                continue;
            }
            Err(error) => return Err(error),
        };
        let bt = view.btree();
        let mut cache: HashMap<u64, std::result::Result<Option<u64>, String>> = HashMap::new();
        for index in indices {
            let row = &mut rows[index];
            let result = if let Some(cached) = cache.get(&row.entry.fsoid) {
                cached.clone()
            } else {
                let loaded = load_logical_size(&view, &bt, &row.entry);
                cache.insert(row.entry.fsoid, loaded.clone());
                loaded
            };
            match result {
                Ok(size) => row.logical_bytes = size,
                Err(message) if opts.best_effort => row.metadata_error = Some(message),
                Err(message) => {
                    return Err(
                        Error::new(ErrorKind::Corrupt, message).with_context(format!(
                            "snapshot {:?} source {:?}",
                            snap.name, row.entry.source_path
                        )),
                    );
                }
            }
        }
    }
    Ok(())
}

fn load_logical_size(
    vol: &Volume,
    bt: &apfsrelic_core::apfs::btree::BtreeReader<'_>,
    entry: &HistoryEntry,
) -> std::result::Result<Option<u64>, String> {
    let records = vol
        .records(bt, entry.fsoid)
        .map_err(|error| error.to_string())?;
    let inode = Volume::inode_from_records(&records)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| format!("no inode for FSOID {:#x}", entry.fsoid))?;
    if entry.entry_type == EntryType::Symlink {
        return Volume::symlink_target(&records)
            .map(|target| target.map(|target| target.len() as u64))
            .map_err(|error| error.to_string());
    }
    Ok(inode.logical_size())
}

enum ManifestFormat {
    Jsonl,
    Tsv,
}

impl ManifestFormat {
    fn parse(value: &str) -> Result<ManifestFormat> {
        match value {
            "jsonl" => Ok(ManifestFormat::Jsonl),
            "tsv" => Ok(ManifestFormat::Tsv),
            _ => Err(Error::new(
                ErrorKind::Usage,
                format!("unsupported --format `{value}` (expected jsonl or tsv)"),
            )),
        }
    }
}

fn manifest_writer(opts: &Options) -> Result<Box<dyn Write>> {
    let Some(path) = opts.output.as_deref() else {
        return Ok(Box::new(BufWriter::new(io::stdout())));
    };
    let file: File = if opts.overwrite {
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?
    } else {
        OpenOptions::new().write(true).create_new(true).open(path)?
    };
    Ok(Box::new(BufWriter::new(file)))
}

fn write_manifest(
    output: &mut dyn Write,
    format: ManifestFormat,
    rows: &[ManifestRow],
    snapshots: &[SnapshotInfo],
    latest: &SnapshotInfo,
) -> Result<()> {
    let snapshots_by_xid: BTreeMap<u64, &SnapshotInfo> =
        snapshots.iter().map(|snap| (snap.xid, snap)).collect();
    match format {
        ManifestFormat::Jsonl => {
            for row in rows {
                let snap = snapshots_by_xid
                    .get(&row.entry.snapshot_xid)
                    .ok_or_else(|| {
                        Error::new(ErrorKind::Internal, "manifest row has unknown snapshot")
                    })?;
                writeln!(
                    output,
                    "{}",
                    row_json(row, snap, latest).to_compact_string()
                )?;
            }
        }
        ManifestFormat::Tsv => {
            writeln!(output, "{}", TSV_HEADER.join("\t"))?;
            for row in rows {
                let snap = snapshots_by_xid
                    .get(&row.entry.snapshot_xid)
                    .ok_or_else(|| {
                        Error::new(ErrorKind::Internal, "manifest row has unknown snapshot")
                    })?;
                writeln!(output, "{}", row_tsv(row, snap, latest))?;
            }
        }
    }
    Ok(())
}

fn decision(entry: &HistoryEntry) -> (&'static str, String) {
    let (decision, mut reason) = if let Some(ancestor) = &entry.ancestor_conflict {
        (
            "skip_path_conflict",
            format!("newer non-directory ancestor `{ancestor}` blocks the selected leaf path"),
        )
    } else {
        match entry.latest_presence {
            LatestPresence::Present => (
                "latest_present",
                "raw relative path exists in the latest complete snapshot".to_string(),
            ),
            LatestPresence::Absent => (
                "historical_deleted",
                "latest complete snapshot scanned the relevant prefixes and the raw path is absent"
                    .to_string(),
            ),
            LatestPresence::Unknown => (
                "unknown_latest_scan",
                "latest complete snapshot has an unreadable ancestor prefix, so deletion is unproven"
                    .to_string(),
            ),
        }
    };
    if entry.type_conflict() {
        reason.push_str("; the same raw path changed type and the newest type won");
    }
    (decision, reason)
}

fn row_json(row: &ManifestRow, snap: &SnapshotInfo, latest: &SnapshotInfo) -> Json {
    let (selected_decision, reason) = decision(&row.entry);
    let observed_types = row
        .entry
        .observed_types
        .iter()
        .map(|ty| Json::Str(ty.as_str().to_string()))
        .collect();
    let mut value = Json::obj()
        .set("schema_version", SCHEMA_VERSION as u64)
        .set("record", "entry")
        .set("decision", selected_decision)
        .set("reason", reason)
        .set("relative_path", row.entry.relative_path.as_str())
        .set(
            "collision_key",
            portable_collision_key(&row.entry.relative_path),
        )
        .set("source_path", row.entry.source_path.as_str())
        .set("type", row.entry.entry_type.as_str())
        .set("logical_bytes", row.logical_bytes)
        .set("snapshot_name", snap.name.as_str())
        .set("snapshot_xid", snap.xid)
        .set("snapshot_create_time", time::iso8601(snap.create_time))
        .set("snapshot_create_time_raw", snap.create_time)
        .set("fsoid", format!("{:#x}", row.entry.fsoid))
        .set("latest_snapshot_name", latest.name.as_str())
        .set("latest_snapshot_xid", latest.xid)
        .set("latest_presence", row.entry.latest_presence.as_str())
        .set("snapshots_seen", row.entry.snapshots_seen)
        .set("first_snapshot_xid", row.entry.first_snapshot_xid)
        .set("type_conflict", row.entry.type_conflict())
        .set("observed_types", Json::Array(observed_types))
        .set("ancestor_conflict", row.entry.ancestor_conflict.clone())
        .set("metadata_error", row.metadata_error.clone());
    // The field is explicit so consumers do not mistake the portable audit key
    // for APFS normalization semantics.
    value.insert("collision_key_semantics", "unicode-lowercase-audit-only");
    value
}

const TSV_HEADER: [&str; 23] = [
    "schema_version",
    "decision",
    "reason",
    "relative_path",
    "collision_key",
    "collision_key_semantics",
    "source_path",
    "type",
    "logical_bytes",
    "snapshot_name",
    "snapshot_xid",
    "snapshot_create_time",
    "snapshot_create_time_raw",
    "fsoid",
    "latest_snapshot_name",
    "latest_snapshot_xid",
    "latest_presence",
    "snapshots_seen",
    "first_snapshot_xid",
    "type_conflict",
    "observed_types_json",
    "ancestor_conflict",
    "metadata_error",
];

fn row_tsv(row: &ManifestRow, snap: &SnapshotInfo, latest: &SnapshotInfo) -> String {
    let (selected_decision, reason) = decision(&row.entry);
    let observed_types = Json::Array(
        row.entry
            .observed_types
            .iter()
            .map(|ty| Json::Str(ty.as_str().to_string()))
            .collect(),
    )
    .to_compact_string();
    let fields = vec![
        SCHEMA_VERSION.to_string(),
        selected_decision.to_string(),
        reason,
        row.entry.relative_path.clone(),
        portable_collision_key(&row.entry.relative_path),
        "unicode-lowercase-audit-only".to_string(),
        row.entry.source_path.clone(),
        row.entry.entry_type.as_str().to_string(),
        row.logical_bytes
            .map(|value| value.to_string())
            .unwrap_or_default(),
        snap.name.clone(),
        snap.xid.to_string(),
        time::iso8601(snap.create_time).unwrap_or_default(),
        snap.create_time.to_string(),
        format!("{:#x}", row.entry.fsoid),
        latest.name.clone(),
        latest.xid.to_string(),
        row.entry.latest_presence.as_str().to_string(),
        row.entry.snapshots_seen.to_string(),
        row.entry.first_snapshot_xid.to_string(),
        row.entry.type_conflict().to_string(),
        observed_types,
        row.entry.ancestor_conflict.clone().unwrap_or_default(),
        row.metadata_error.clone().unwrap_or_default(),
    ];
    fields
        .into_iter()
        .map(|field| tsv_escape(&field))
        .collect::<Vec<_>>()
        .join("\t")
}

fn tsv_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\t', "\\t")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(xid: u64, name: &str) -> SnapshotInfo {
        SnapshotInfo {
            xid,
            name: name.into(),
            sblock_oid: 0,
            extentref_tree_oid: 0,
            create_time: 0,
            change_time: 0,
        }
    }

    fn entry(presence: LatestPresence) -> HistoryEntry {
        HistoryEntry {
            relative_path: "Documents/a\tb".into(),
            source_path: "/snap/home/Documents/a\tb".into(),
            entry_type: EntryType::File,
            fsoid: 42,
            snapshot_xid: 10,
            first_snapshot_xid: 5,
            snapshots_seen: 2,
            latest_presence: presence,
            observed_types: vec![EntryType::File],
            ancestor_conflict: None,
        }
    }

    #[test]
    fn template_expands_snapshot_tokens_and_trims_only_trailing_separator() {
        assert_eq!(
            snapshot_root("/{snapshot}/Data/Users/me/", "2023.backup"),
            "/2023.backup/Data/Users/me"
        );
        assert_eq!(
            snapshot_root(
                "/{snapshot-dir}/Macintosh HD - Data/Users/alice/",
                "com.apple.TimeMachine.2023-01-02-030405.backup"
            ),
            "/2023-01-02-030405.backup/Macintosh HD - Data/Users/alice"
        );
    }

    #[test]
    fn latest_scan_state_selects_recovery_decision() {
        assert_eq!(
            decision(&entry(LatestPresence::Present)).0,
            "latest_present"
        );
        assert_eq!(
            decision(&entry(LatestPresence::Absent)).0,
            "historical_deleted"
        );
        assert_eq!(
            decision(&entry(LatestPresence::Unknown)).0,
            "unknown_latest_scan"
        );
    }

    #[test]
    fn tsv_escapes_control_characters_and_backslashes() {
        assert_eq!(tsv_escape("a\tb\nc\\d\r"), "a\\tb\\nc\\\\d\\r");
    }

    #[test]
    fn tsv_header_and_row_have_the_same_column_count() {
        let row = ManifestRow {
            entry: entry(LatestPresence::Absent),
            logical_bytes: Some(123),
            metadata_error: None,
        };
        let snap = snapshot(10, "old");
        let latest = snapshot(20, "latest");
        assert_eq!(
            row_tsv(&row, &snap, &latest).split('\t').count(),
            TSV_HEADER.len()
        );
    }

    #[test]
    fn jsonl_row_has_recovery_source_and_stable_decision() {
        let row = ManifestRow {
            entry: entry(LatestPresence::Absent),
            logical_bytes: Some(123),
            metadata_error: None,
        };
        let snap = snapshot(10, "old");
        let latest = snapshot(20, "latest");
        let json = row_json(&row, &snap, &latest).to_compact_string();
        assert!(json.contains("\"decision\":\"historical_deleted\""));
        assert!(json.contains("\"source_path\":\"/snap/home/Documents/a\\tb\""));
        assert!(json.contains("\"logical_bytes\":123"));
    }
}
