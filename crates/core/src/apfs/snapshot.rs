//! Snapshot support (rewrite plan Phase 13).
//!
//! Snapshots are listed from the volume's snapshot-metadata tree
//! (`apfs_snap_meta_tree_oid`). Each `SNAP_METADATA` record's key carries the
//! snapshot XID and its value names the snapshot and points at the volume
//! superblock captured for that snapshot. Opening a snapshot reads that captured
//! superblock and browses it with the omap resolved at the snapshot's XID, so
//! the live-volume view and the snapshot view stay cleanly separated.

use std::sync::Arc;

use super::btree::{split_obj_id_and_type, BtreeReader};
use super::jrec::{self, SnapMetadata};
use super::obj::{OBJ_PHYSICAL, OBJ_STORAGETYPE_MASK};
use super::vol::Volume;
use super::volume::ApfsSuperblock;
use crate::error::{not_found_obj, Result};

/// A snapshot of a volume.
#[derive(Debug, Clone)]
pub struct SnapshotInfo {
    pub xid: u64,
    pub name: String,
    pub sblock_oid: u64,
    pub extentref_tree_oid: u64,
    pub create_time: u64,
    pub change_time: u64,
}

/// List a volume's snapshots, oldest XID first.
pub fn list_snapshots(vol: &Volume, bt: &BtreeReader) -> Result<Vec<SnapshotInfo>> {
    let tree_oid = vol.apsb.snap_meta_tree_oid;
    if tree_oid == 0 {
        return Ok(Vec::new());
    }

    // The snapshot-metadata tree is typically a *physical* B-tree (its type bits
    // mark it physical), so its root OID is a block address and its child links
    // are physical too (`omap_root = None`). If a volume marks it virtual, resolve
    // the root through the volume omap and resolve child links the same way.
    let physical = vol.apsb.snap_meta_tree_type & OBJ_STORAGETYPE_MASK == OBJ_PHYSICAL;
    let (root_block, omap_root) = if physical {
        (tree_oid, None)
    } else {
        match super::resolver::readable_paddr(
            bt.omap_get(vol.omap_tree_root, tree_oid, vol.max_xid)?,
            &format!("snapshot metadata tree {tree_oid:#x}"),
        )? {
            Some(paddr) => (paddr, Some(vol.omap_tree_root)),
            None => return Ok(Vec::new()),
        }
    };

    let mut snaps: Vec<SnapshotInfo> = Vec::new();
    bt.fs_walk(omap_root, root_block, vol.max_xid, &mut |key, val| {
        let (obj_id, ty) = split_obj_id_and_type(crate::apfs::raw::u64_at(key, 0)?);
        if ty == jrec::APFS_TYPE_SNAP_METADATA {
            let meta = SnapMetadata::parse(val)?;
            snaps.push(SnapshotInfo {
                xid: obj_id, // the SNAP_METADATA key's obj_id is the snapshot XID
                name: meta.name,
                sblock_oid: meta.sblock_oid,
                extentref_tree_oid: meta.extentref_tree_oid,
                create_time: meta.create_time,
                change_time: meta.change_time,
            });
        }
        Ok(true)
    })?;
    snaps.sort_by_key(|s| s.xid);
    Ok(snaps)
}

/// Find a snapshot by exact name.
pub fn find_by_name(vol: &Volume, bt: &BtreeReader, name: &str) -> Result<SnapshotInfo> {
    list_snapshots(vol, bt)?
        .into_iter()
        .find(|s| s.name == name)
        .ok_or_else(|| not_found_obj(format!("no snapshot named `{name}`")))
}

/// Find a snapshot by XID.
pub fn find_by_xid(vol: &Volume, bt: &BtreeReader, xid: u64) -> Result<SnapshotInfo> {
    list_snapshots(vol, bt)?
        .into_iter()
        .find(|s| s.xid == xid)
        .ok_or_else(|| not_found_obj(format!("no snapshot with xid {xid:#x}")))
}

/// Open a snapshot as a [`Volume`] view.
///
/// A snapshot is browsed through the **live volume's** object map (which retains
/// every object version keyed by XID), resolving objects at the snapshot's XID.
/// The captured volume superblock at `sblock_oid` only provides the root-tree
/// OID that was current when the snapshot was taken; we resolve that virtual OID
/// through the live omap at `snap.xid`. This keeps the live and snapshot views
/// cleanly separated while reusing one object map.
pub fn open_snapshot(live: &Volume, bt: &BtreeReader, snap: &SnapshotInfo) -> Result<Volume> {
    let blk = live.dev.read_block(snap.sblock_oid, live.block_size)?;
    let apsb = ApfsSuperblock::parse(&blk)?;
    apsb.check_magic()?;

    let root_tree_root = super::resolver::readable_paddr(
        bt.omap_get(live.omap_tree_root, apsb.root_tree_oid, snap.xid)?,
        &format!("snapshot root tree {:#x}", apsb.root_tree_oid),
    )?
    .ok_or_else(|| {
        crate::error::not_found_obj(format!(
            "snapshot root tree (virtual OID {:#x}) not in volume omap at xid {:#x}",
            apsb.root_tree_oid, snap.xid
        ))
    })?;

    let mut warnings = Vec::new();
    if let Ok(report) = crate::apfs::feature::check_volume(&apsb) {
        warnings.extend(report.warnings);
    }

    Ok(Volume {
        dev: Arc::clone(&live.dev),
        block_size: live.block_size,
        apsb,
        omap_tree_root: live.omap_tree_root,
        root_tree_root,
        max_xid: snap.xid,
        warnings,
    })
}
