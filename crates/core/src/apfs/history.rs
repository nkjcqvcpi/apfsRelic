//! Deterministic union of path observations from a sequence of APFS snapshots.
//!
//! The filesystem walker lives in the CLI because it owns image selection and
//! diagnostics.  This module contains the policy that must remain testable
//! without an image: snapshots are observed oldest first, the newest
//! observation of a raw relative path wins, and absence from the latest
//! complete view is distinguished from absence below an unreadable prefix.

use std::collections::{BTreeMap, BTreeSet};

/// Stable directory-entry types used by the history manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EntryType {
    File,
    Dir,
    Symlink,
    Fifo,
    Char,
    Block,
    Socket,
    Whiteout,
    Unknown,
}

impl EntryType {
    pub fn from_name(name: &str) -> EntryType {
        match name {
            "file" => EntryType::File,
            "dir" => EntryType::Dir,
            "symlink" => EntryType::Symlink,
            "fifo" => EntryType::Fifo,
            "char" => EntryType::Char,
            "block" => EntryType::Block,
            "socket" => EntryType::Socket,
            "whiteout" => EntryType::Whiteout,
            _ => EntryType::Unknown,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            EntryType::File => "file",
            EntryType::Dir => "dir",
            EntryType::Symlink => "symlink",
            EntryType::Fifo => "fifo",
            EntryType::Char => "char",
            EntryType::Block => "block",
            EntryType::Socket => "socket",
            EntryType::Whiteout => "whiteout",
            EntryType::Unknown => "unknown",
        }
    }

    pub fn is_leaf(self) -> bool {
        matches!(self, EntryType::File | EntryType::Symlink)
    }

    fn mask(self) -> u16 {
        1u16 << self as u8
    }
}

/// What the latest complete snapshot proves about a selected historical path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LatestPresence {
    Present,
    Absent,
    Unknown,
}

impl LatestPresence {
    pub fn as_str(self) -> &'static str {
        match self {
            LatestPresence::Present => "present",
            LatestPresence::Absent => "absent",
            LatestPresence::Unknown => "unknown",
        }
    }
}

/// The winning observation for one raw relative path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryEntry {
    /// Path relative to the per-snapshot root, retaining the newest spelling.
    pub relative_path: String,
    /// Absolute path inside the snapshot that supplied the winning observation.
    pub source_path: String,
    pub entry_type: EntryType,
    pub fsoid: u64,
    pub snapshot_xid: u64,
    pub first_snapshot_xid: u64,
    pub snapshots_seen: u32,
    pub latest_presence: LatestPresence,
    pub observed_types: Vec<EntryType>,
    /// Newer non-directory ancestor that makes this old leaf unplaceable at its
    /// original relative path.
    pub ancestor_conflict: Option<String>,
}

impl HistoryEntry {
    pub fn type_conflict(&self) -> bool {
        self.observed_types.len() > 1
    }
}

#[derive(Debug, Clone)]
struct PendingEntry {
    source_path: String,
    entry_type: EntryType,
    fsoid: u64,
    snapshot_xid: u64,
    first_snapshot_xid: u64,
    last_counted_snapshot_xid: u64,
    snapshots_seen: u32,
    type_mask: u16,
}

/// Incremental path union. Observations should be supplied oldest snapshot
/// first. Equal-XID duplicates are resolved by a deterministic tuple order.
pub struct HistoryUnion {
    entries: BTreeMap<String, PendingEntry>,
}

impl Default for HistoryUnion {
    fn default() -> Self {
        Self::new()
    }
}

impl HistoryUnion {
    pub fn new() -> HistoryUnion {
        HistoryUnion {
            entries: BTreeMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Observe one directory entry. `relative_path` is the cross-snapshot key;
    /// `source_path` is retained only for the winning snapshot.
    pub fn observe(
        &mut self,
        relative_path: impl Into<String>,
        source_path: impl Into<String>,
        entry_type: EntryType,
        fsoid: u64,
        snapshot_xid: u64,
    ) {
        let relative_path = clean_relative_path(&relative_path.into());
        let source_path = if entry_type.is_leaf() {
            source_path.into()
        } else {
            String::new()
        };
        // Raw, case-sensitive relative paths are authoritative. APFS Unicode
        // normalization is not approximated here; see `collision_key` below.
        let key = relative_path.clone();

        let Some(current) = self.entries.get_mut(&key) else {
            self.entries.insert(
                key,
                PendingEntry {
                    source_path,
                    entry_type,
                    fsoid,
                    snapshot_xid,
                    first_snapshot_xid: snapshot_xid,
                    last_counted_snapshot_xid: snapshot_xid,
                    snapshots_seen: 1,
                    type_mask: entry_type.mask(),
                },
            );
            return;
        };

        current.first_snapshot_xid = current.first_snapshot_xid.min(snapshot_xid);
        if current.last_counted_snapshot_xid != snapshot_xid {
            current.snapshots_seen = current.snapshots_seen.saturating_add(1);
            current.last_counted_snapshot_xid = snapshot_xid;
        }
        current.type_mask |= entry_type.mask();
        // A greater XID is newer. For an impossible duplicate within one XID,
        // choosing the lexicographically smaller tuple makes output independent
        // of B-tree visitation order.
        let replace = snapshot_xid > current.snapshot_xid
            || (snapshot_xid == current.snapshot_xid
                && (entry_type, fsoid) < (current.entry_type, current.fsoid));
        if replace {
            current.source_path = source_path;
            current.entry_type = entry_type;
            current.fsoid = fsoid;
            current.snapshot_xid = snapshot_xid;
        }
    }

    /// Finalize the union against the newest complete snapshot. An old path is
    /// `Unknown`, not `Absent`, when it lies below a directory prefix that the
    /// latest scan could not read.
    pub fn finish(
        self,
        latest_snapshot_xid: u64,
        latest_incomplete_prefixes: &[String],
    ) -> Vec<HistoryEntry> {
        let incomplete: BTreeSet<String> = latest_incomplete_prefixes
            .iter()
            .map(|path| clean_relative_path(path))
            .collect();

        let mut ancestor_conflicts: BTreeMap<String, String> = BTreeMap::new();
        for key in self.entries.keys() {
            let mut parent = parent_relative_path(key);
            while let Some(parent_key) = parent {
                if let Some(ancestor) = self.entries.get(parent_key) {
                    if ancestor.entry_type != EntryType::Dir {
                        ancestor_conflicts.insert(key.clone(), parent_key.to_string());
                        break;
                    }
                }
                parent = parent_relative_path(parent_key);
            }
        }

        self.entries
            .into_iter()
            .map(|(key, pending)| {
                let latest_presence = if pending.snapshot_xid == latest_snapshot_xid {
                    LatestPresence::Present
                } else if has_incomplete_ancestor(&key, &incomplete) {
                    LatestPresence::Unknown
                } else {
                    LatestPresence::Absent
                };
                let observed_types = ALL_ENTRY_TYPES
                    .iter()
                    .copied()
                    .filter(|ty| pending.type_mask & ty.mask() != 0)
                    .collect();
                let ancestor_conflict = ancestor_conflicts.remove(&key);
                HistoryEntry {
                    relative_path: key,
                    source_path: pending.source_path,
                    entry_type: pending.entry_type,
                    fsoid: pending.fsoid,
                    snapshot_xid: pending.snapshot_xid,
                    first_snapshot_xid: pending.first_snapshot_xid,
                    snapshots_seen: pending.snapshots_seen,
                    latest_presence,
                    observed_types,
                    ancestor_conflict,
                }
            })
            .collect()
    }
}

const ALL_ENTRY_TYPES: [EntryType; 9] = [
    EntryType::File,
    EntryType::Dir,
    EntryType::Symlink,
    EntryType::Fifo,
    EntryType::Char,
    EntryType::Block,
    EntryType::Socket,
    EntryType::Whiteout,
    EntryType::Unknown,
];

fn clean_relative_path(path: &str) -> String {
    path.trim_matches('/').to_string()
}

/// Portable audit key for finding paths that may collide on a differently
/// configured destination. This is Unicode lowercase only, not APFS NFD or
/// full case folding, and must never be used as the authoritative union key.
pub fn portable_collision_key(path: &str) -> String {
    clean_relative_path(path)
        .chars()
        .flat_map(char::to_lowercase)
        .collect()
}

fn parent_relative_path(path: &str) -> Option<&str> {
    path.rfind('/').map(|separator| &path[..separator])
}

fn has_incomplete_ancestor(path: &str, incomplete: &BTreeSet<String>) -> bool {
    if incomplete.contains("") {
        return true;
    }
    let mut candidate = Some(path);
    while let Some(current) = candidate {
        if incomplete.contains(current) {
            return true;
        }
        candidate = parent_relative_path(current);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn find<'a>(entries: &'a [HistoryEntry], path: &str) -> &'a HistoryEntry {
        entries
            .iter()
            .find(|entry| entry.relative_path == path)
            .unwrap()
    }

    #[test]
    fn newest_observation_wins_and_latest_absence_means_deleted() {
        let mut union = HistoryUnion::new();
        union.observe("Documents/a", "/old/Documents/a", EntryType::File, 1, 10);
        union.observe("Documents/a", "/new/Documents/a", EntryType::File, 2, 20);
        union.observe(
            "Documents/gone",
            "/old/Documents/gone",
            EntryType::File,
            3,
            10,
        );

        let entries = union.finish(20, &[]);
        let current = find(&entries, "Documents/a");
        assert_eq!(current.fsoid, 2);
        assert_eq!(current.source_path, "/new/Documents/a");
        assert_eq!(current.latest_presence, LatestPresence::Present);
        assert_eq!(current.snapshots_seen, 2);
        assert_eq!(
            find(&entries, "Documents/gone").latest_presence,
            LatestPresence::Absent
        );
    }

    #[test]
    fn unreadable_latest_prefix_does_not_create_false_deletion() {
        let mut union = HistoryUnion::new();
        union.observe(
            "Library/Mail/a",
            "/old/Library/Mail/a",
            EntryType::File,
            1,
            10,
        );
        union.observe("Documents/a", "/old/Documents/a", EntryType::File, 2, 10);

        let entries = union.finish(20, &["Library/Mail".into()]);
        assert_eq!(
            find(&entries, "Library/Mail/a").latest_presence,
            LatestPresence::Unknown
        );
        assert_eq!(
            find(&entries, "Documents/a").latest_presence,
            LatestPresence::Absent
        );
    }

    #[test]
    fn raw_case_variants_stay_distinct_with_equal_portable_audit_keys() {
        let mut union = HistoryUnion::new();
        union.observe("Foo", "/old/Foo", EntryType::Dir, 1, 10);
        union.observe("foo", "/new/foo", EntryType::File, 2, 20);

        let entries = union.finish(20, &[]);
        assert_eq!(entries.len(), 2);
        assert_eq!(portable_collision_key("Foo"), portable_collision_key("foo"));
    }

    #[test]
    fn same_raw_path_type_change_keeps_latest_type_and_flags_conflict() {
        let mut union = HistoryUnion::new();
        union.observe("item", "/old/item", EntryType::Dir, 1, 10);
        union.observe("item", "/new/item", EntryType::File, 2, 20);
        let entries = union.finish(20, &[]);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].entry_type, EntryType::File);
        assert!(entries[0].type_conflict());
    }

    #[test]
    fn newer_non_directory_ancestor_shadows_old_descendant() {
        let mut union = HistoryUnion::new();
        union.observe("a", "/old/a", EntryType::Dir, 1, 10);
        union.observe("a/b", "/old/a/b", EntryType::File, 2, 10);
        union.observe("a", "/new/a", EntryType::File, 3, 20);

        let entries = union.finish(20, &[]);
        assert_eq!(
            find(&entries, "a/b").ancestor_conflict.as_deref(),
            Some("a")
        );
    }

    #[test]
    fn output_order_is_raw_path_order() {
        let mut union = HistoryUnion::new();
        union.observe("z", "/s/z", EntryType::File, 1, 10);
        union.observe("a", "/s/a", EntryType::File, 2, 10);
        let entries = union.finish(10, &[]);
        assert_eq!(entries[0].relative_path, "a");
        assert_eq!(entries[1].relative_path, "z");
    }
}
