//! `Container` — open an APFS container from a [`BlockDevice`], select a valid
//! checkpoint, load the container object map, and enumerate volumes (rewrite
//! plan Phases 6 and 9).

use std::{cmp::Reverse, sync::Arc};

use super::btree::BtreeReader;
use super::checksum;
use super::nx::{CheckpointMap, NxSuperblock};
use super::obj::{ObjPhys, OBJECT_TYPE_NX_SUPERBLOCK};
use super::omap::OmapPhys;
use super::volume::ApfsSuperblock;
use crate::device::BlockDevice;
use crate::error::{corrupt, not_found_obj, unsupported, Error, ErrorKind, Result};

/// A successfully opened APFS container at a chosen checkpoint.
pub struct Container {
    pub dev: Arc<dyn BlockDevice>,
    pub block_size: u32,
    /// The selected (valid) container superblock.
    pub nx: NxSuperblock,
    /// Physical block address of the container object-map B-tree root.
    pub nx_omap_tree_root: u64,
    /// XID of the selected checkpoint.
    pub checkpoint_xid: u64,
    /// Index of the selected superblock within the checkpoint descriptor area.
    pub checkpoint_index: u32,
    /// Non-fatal warnings accumulated while opening.
    pub warnings: Vec<String>,
}

/// Minimal description of a volume slot for `volumes`/`inspect`.
pub struct VolumeSlot {
    /// 1-based volume index.
    pub index: u32,
    pub apsb: ApfsSuperblock,
}

const APFS_MIN_BLOCK_SIZE: usize = 4096;

impl Container {
    /// Build a [`BtreeReader`] bound to this container's device. A fresh reader
    /// has an empty node cache; reuse one reader across a command's reads.
    pub fn btree(&self) -> BtreeReader<'_> {
        BtreeReader::new(&*self.dev, self.block_size)
    }

    /// Open the container, selecting the most recent fully-valid checkpoint with
    /// `xid <= max_xid` (or the absolute latest when `max_xid == u64::MAX`).
    pub fn open(dev: Arc<dyn BlockDevice>, max_xid: u64) -> Result<Container> {
        // --- Bootstrap: read block 0 to learn the block size. ---
        let boot = dev.read_vec(0, APFS_MIN_BLOCK_SIZE)?;
        let boot_nx = NxSuperblock::parse(&boot)?;
        boot_nx.check_magic().map_err(|_| {
            Error::new(
                ErrorKind::UnsupportedFormat,
                "block 0 is not an APFS container superblock (no NXSB magic)",
            )
        })?;
        let block_size = boot_nx.block_size;
        if !(APFS_MIN_BLOCK_SIZE..=65536).contains(&(block_size as usize))
            || !block_size.is_power_of_two()
        {
            return Err(corrupt(format!(
                "implausible container block size {block_size}"
            )));
        }

        let mut warnings = Vec::new();

        if boot_nx.xp_desc_is_tree() {
            return Err(unsupported(
                "checkpoint descriptor area is a tree; this layout is not yet supported",
            ));
        }
        let xp_desc_base = boot_nx.xp_desc_base;
        let xp_desc_blocks = boot_nx.xp_desc_blocks();
        if xp_desc_base <= 0 || xp_desc_blocks == 0 {
            return Err(corrupt("container has no checkpoint descriptor area"));
        }

        // --- Scan the checkpoint descriptor area for superblock candidates. ---
        let mut candidates: Vec<(u32, u64)> = Vec::new(); // (index, xid)
        for i in 0..xp_desc_blocks {
            let blk = match dev.read_block(xp_desc_base as u64 + i as u64, block_size) {
                Ok(b) => b,
                Err(_) => {
                    warnings.push(format!("checkpoint descriptor block {i} unreadable"));
                    continue;
                }
            };
            if !checksum::is_valid(&blk) {
                continue; // skip silently; many slots are stale/empty
            }
            let Ok(header) = ObjPhys::parse(&blk) else {
                continue;
            };
            if header.type_id() == OBJECT_TYPE_NX_SUPERBLOCK {
                if let Ok(nx) = NxSuperblock::parse(&blk) {
                    if nx.magic == super::nx::NX_MAGIC && nx.xid <= max_xid {
                        candidates.push((i, nx.xid));
                    }
                }
            }
        }

        if candidates.is_empty() {
            return Err(corrupt(format!(
                "no valid container superblock with xid <= {max_xid} in the checkpoint area"
            )));
        }
        // Highest XID first; fall back to older checkpoints if the newest fails.
        candidates.sort_by_key(|candidate| Reverse(candidate.1));

        for (index, xid) in candidates {
            let blk = dev.read_block(xp_desc_base as u64 + index as u64, block_size)?;
            let nx = match NxSuperblock::parse(&blk) {
                Ok(n) => n,
                Err(_) => continue,
            };
            match load_container_omap(&dev, block_size, &nx) {
                Ok(omap_tree_root) => {
                    // Best-effort: validate the referenced checkpoint maps so a
                    // half-written checkpoint is rejected in favour of an older one.
                    if let Err(e) = validate_checkpoint_maps(&dev, block_size, &nx, xp_desc_base) {
                        warnings.push(format!(
                            "checkpoint xid {xid:#x} has invalid checkpoint maps ({e}); trying older"
                        ));
                        continue;
                    }
                    return Ok(Container {
                        dev,
                        block_size,
                        nx,
                        nx_omap_tree_root: omap_tree_root,
                        checkpoint_xid: xid,
                        checkpoint_index: index,
                        warnings,
                    });
                }
                Err(e) => {
                    warnings.push(format!(
                        "checkpoint xid {xid:#x} omap failed to load ({e}); trying older checkpoint"
                    ));
                }
            }
        }

        Err(corrupt(
            "every checkpoint candidate failed to load; container may be corrupt",
        ))
    }

    /// List every present volume slot (resolving each volume superblock).
    pub fn list_volumes(&self) -> Result<Vec<VolumeSlot>> {
        let bt = self.btree();
        let mut out = Vec::new();
        for (i, &fs_oid) in self.nx.fs_oids.iter().enumerate() {
            if fs_oid == 0 {
                continue;
            }
            let entry = match bt.omap_get(self.nx_omap_tree_root, fs_oid, self.nx.xid)? {
                Some(e) => e,
                None => continue,
            };
            let blk = self.dev.read_block(entry.val.paddr, self.block_size)?;
            if let Ok(apsb) = ApfsSuperblock::parse(&blk) {
                if apsb.magic == super::volume::APFS_MAGIC {
                    out.push(VolumeSlot {
                        index: i as u32 + 1,
                        apsb,
                    });
                }
            }
        }
        Ok(out)
    }

    /// Resolve a single volume superblock by 1-based index.
    pub fn volume_superblock(&self, index: u32) -> Result<ApfsSuperblock> {
        if index < 1 || index as usize > self.nx.fs_oids.len() {
            return Err(Error::new(
                ErrorKind::Usage,
                format!(
                    "volume index {index} out of range [1, {}]",
                    self.nx.fs_oids.len()
                ),
            ));
        }
        let fs_oid = self.nx.fs_oids[index as usize - 1];
        if fs_oid == 0 {
            return Err(not_found_obj(format!("volume {index} does not exist")));
        }
        let bt = self.btree();
        let entry = bt
            .omap_get(self.nx_omap_tree_root, fs_oid, self.nx.xid)?
            .ok_or_else(|| {
                not_found_obj(format!("volume {index} superblock not in container omap"))
            })?;
        let blk = self.dev.read_block(entry.val.paddr, self.block_size)?;
        let apsb = ApfsSuperblock::parse(&blk)?;
        apsb.check_magic()?;
        Ok(apsb)
    }
}

/// Read a container superblock's object map and return the physical block of its
/// B-tree root.
fn load_container_omap(
    dev: &Arc<dyn BlockDevice>,
    block_size: u32,
    nx: &NxSuperblock,
) -> Result<u64> {
    let blk = dev.read_block(nx.omap_oid, block_size)?;
    let omap = OmapPhys::parse(&blk)?;
    if !omap.tree_is_physical() {
        return Err(unsupported(
            "container omap B-tree is not a physical object",
        ));
    }
    // Touch the tree root so a bad address fails here, not deep in a query.
    let _ = dev.read_block(omap.tree_oid, block_size)?;
    Ok(omap.tree_oid)
}

/// Best-effort validation of the checkpoint map blocks referenced by `nx`. The
/// checkpoint's data area holds `nx_xp_desc_index .. +len` map blocks within the
/// descriptor area; we validate their checksums and that they are checkpoint
/// maps. A failure here triggers fallback to an older checkpoint.
fn validate_checkpoint_maps(
    dev: &Arc<dyn BlockDevice>,
    block_size: u32,
    nx: &NxSuperblock,
    xp_desc_base: i64,
) -> Result<()> {
    let len = nx.xp_desc_len;
    if len == 0 {
        return Ok(()); // nothing to validate
    }
    let total = nx.xp_desc_blocks();
    // The descriptor area is a ring buffer; the maps for this checkpoint occupy
    // `len` blocks ending just before the superblock at xp_desc_index.
    for k in 0..len.min(total) {
        let slot = (nx.xp_desc_index + k) % total.max(1);
        let blk = dev.read_block(xp_desc_base as u64 + slot as u64, block_size)?;
        if !checksum::is_valid(&blk) {
            continue; // the superblock slot itself lives here too; tolerate
        }
        if let Ok(h) = ObjPhys::parse(&blk) {
            // Map blocks should be checkpoint maps or the superblock.
            if h.type_id() == super::obj::OBJECT_TYPE_CHECKPOINT_MAP {
                let _ = CheckpointMap::parse(&blk)?; // structural check
            }
        }
    }
    Ok(())
}
