//! `Volume` — load a volume's object map and filesystem tree, and provide record
//! access used by every filesystem command (rewrite plan Phases 9, 11).

use std::borrow::Cow;
use std::fs::File;
use std::io::Write;
use std::sync::Arc;

use super::btree::{split_obj_id_and_type, BtreeReader, Record};
use super::container::Container;
use super::extract::{self, Written};
use super::feature;
use super::jrec::{self, DirRec, FileExtent, Inode, Xattr};
use super::omap::OmapPhys;
use super::volume::ApfsSuperblock;
use crate::device::BlockDevice;
use crate::error::{corrupt, not_found_obj, unsupported, Error, ErrorKind, Result};

/// xattr name that stores a symlink's target path (see `recover`).
const SYMLINK_XATTR: &str = "com.apple.fs.symlink";

/// An opened volume (live view or a snapshot view).
pub struct Volume {
    pub dev: Arc<dyn BlockDevice>,
    pub block_size: u32,
    pub apsb: ApfsSuperblock,
    /// Physical block of the volume object-map B-tree root.
    pub omap_tree_root: u64,
    /// Physical block of the filesystem root B-tree.
    pub root_tree_root: u64,
    /// XID context for resolving virtual OIDs through the volume omap.
    pub max_xid: u64,
    pub warnings: Vec<String>,
}

impl Volume {
    /// Open the live view of volume `index` within `container`.
    pub fn open(container: &Container, index: u32) -> Result<Volume> {
        let apsb = container.volume_superblock(index)?;
        Self::open_from_superblock(
            Arc::clone(&container.dev),
            container.block_size,
            apsb.clone(),
            apsb.xid,
            apsb.root_tree_oid,
        )
    }

    /// Open a view given an already-parsed volume superblock. `max_xid` is the
    /// omap-resolution context (the volume xid for the live view, or a snapshot
    /// xid); `root_tree_oid` is the virtual OID of the filesystem root tree to
    /// resolve (the volume's own, or a snapshot's).
    pub fn open_from_superblock(
        dev: Arc<dyn BlockDevice>,
        block_size: u32,
        apsb: ApfsSuperblock,
        max_xid: u64,
        root_tree_oid: u64,
    ) -> Result<Volume> {
        let mut warnings = Vec::new();

        // Feature gate: errors only on unknown incompatible bits.
        let report = feature::check_volume(&apsb)?;
        warnings.extend(report.warnings);

        // Volume object map (physical object -> physical B-tree root).
        let omap_blk = dev.read_block(apsb.omap_oid, block_size)?;
        let omap = OmapPhys::parse(&omap_blk)?;
        if !omap.tree_is_physical() {
            return Err(unsupported("volume omap B-tree is not a physical object"));
        }
        let omap_tree_root = omap.tree_oid;

        // Resolve the (virtual) filesystem root tree through the volume omap.
        let bt = BtreeReader::new(&*dev, block_size);
        let root_tree_root = super::resolver::readable_paddr(
            bt.omap_get(omap_tree_root, root_tree_oid, max_xid)?,
            &format!("filesystem root tree {root_tree_oid:#x}"),
        )?
        .ok_or_else(|| {
            not_found_obj(format!(
                "filesystem root tree (virtual OID {root_tree_oid:#x}) not in volume omap"
            ))
        })?;
        warnings.extend(bt.take_warnings());

        Ok(Volume {
            dev,
            block_size,
            apsb,
            omap_tree_root,
            root_tree_root,
            max_xid,
            warnings,
        })
    }

    /// A B-tree reader bound to this volume's device.
    pub fn btree(&self) -> BtreeReader<'_> {
        BtreeReader::new(&*self.dev, self.block_size)
    }

    /// All records for object `oid`, in key order. The volume root tree is
    /// virtual, so child links are resolved through the volume omap.
    pub fn records(&self, bt: &BtreeReader, oid: u64) -> Result<Vec<Record>> {
        bt.fs_collect(
            Some(self.omap_tree_root),
            self.root_tree_root,
            oid,
            self.max_xid,
        )
    }

    /// Parse the inode record (if any) from a record set for one object.
    pub fn inode_from_records(records: &[Record]) -> Result<Option<Inode>> {
        for rec in records {
            let (_oid, ty) = split_obj_id_and_type(crate::apfs::raw::u64_at(&rec.key, 0)?);
            if ty == jrec::APFS_TYPE_INODE {
                return Ok(Some(Inode::parse(&rec.val)?));
            }
        }
        Ok(None)
    }

    /// Look up an object's inode directly.
    pub fn inode(&self, bt: &BtreeReader, oid: u64) -> Result<Option<Inode>> {
        let records = self.records(bt, oid)?;
        Self::inode_from_records(&records)
    }

    /// Records that describe a regular file's data stream.
    ///
    /// APFS stores inode metadata under the file-system object id, while the
    /// `FILE_EXTENT` records are keyed by the inode's `private_id`. Older and
    /// simpler images may use the same id for both, in which case the already
    /// loaded inode records are borrowed instead of querying the tree again.
    pub fn file_data_records<'a>(
        &self,
        bt: &BtreeReader,
        fsoid: u64,
        inode: &Inode,
        inode_records: &'a [Record],
    ) -> Result<Cow<'a, [Record]>> {
        select_file_data_records(fsoid, inode.private_id, inode_records, |private_id| {
            self.records(bt, private_id).map_err(|error| {
                error.with_context(format!(
                    "data stream private_id {private_id:#x} for FSOID {fsoid:#x}"
                ))
            })
        })
    }

    /// List a directory's entries (the `DIR_REC` records of `dir_oid`).
    pub fn list_dir(&self, bt: &BtreeReader, dir_oid: u64) -> Result<Vec<DirRec>> {
        let records = self.records(bt, dir_oid)?;
        let mut out = Vec::new();
        for rec in &records {
            let (_oid, ty) = split_obj_id_and_type(crate::apfs::raw::u64_at(&rec.key, 0)?);
            if ty == jrec::APFS_TYPE_DIR_REC {
                out.push(DirRec::parse(&rec.key, &rec.val)?);
            }
        }
        Ok(out)
    }

    /// Reconstruct a regular file's logical data from its `FILE_EXTENT` records,
    /// writing exactly `file_size` bytes to `writer` (extents sorted by logical
    /// address, sparse holes and gaps zero-filled). Shared by the CLI `recover`
    /// command and the GUI recover action so there is a single implementation.
    pub fn write_file_data(
        &self,
        records: &[Record],
        file_size: u64,
        writer: &mut dyn Write,
    ) -> Result<Written> {
        let mut extents: Vec<FileExtent> = Vec::new();
        for rec in records {
            let (_oid, ty) = split_obj_id_and_type(crate::apfs::raw::u64_at(&rec.key, 0)?);
            if ty == jrec::APFS_TYPE_FILE_EXTENT {
                extents.push(FileExtent::parse(&rec.key, &rec.val)?);
            }
        }
        extract::write_extents(&*self.dev, self.block_size, &mut extents, file_size, writer)
    }

    /// Reconstruct a sparse regular file into a seekable destination while
    /// preserving source gaps and hole extents as unallocated ranges.
    pub fn write_sparse_file_data(
        &self,
        records: &[Record],
        file_size: u64,
        file: &mut File,
    ) -> Result<Written> {
        let mut extents: Vec<FileExtent> = Vec::new();
        for rec in records {
            let (_oid, ty) = split_obj_id_and_type(crate::apfs::raw::u64_at(&rec.key, 0)?);
            if ty == jrec::APFS_TYPE_FILE_EXTENT {
                extents.push(FileExtent::parse(&rec.key, &rec.val)?);
            }
        }
        extract::write_extents_sparse(&*self.dev, self.block_size, &mut extents, file_size, file)
    }

    /// Find and parse a named xattr in an inode's record set.
    pub fn xattr(records: &[Record], name: &str) -> Result<Option<Xattr>> {
        for rec in records {
            let (_oid, ty) = split_obj_id_and_type(crate::apfs::raw::u64_at(&rec.key, 0)?);
            if ty == jrec::APFS_TYPE_XATTR {
                let xattr = Xattr::parse(&rec.key, &rec.val)?;
                if xattr.name == name {
                    return Ok(Some(xattr));
                }
            }
        }
        Ok(None)
    }

    /// Read an embedded or stream-backed xattr into memory with strict extent
    /// validation. Compression resource forks must not silently inherit the
    /// regular-file extractor's zero-fill behavior when their stream is
    /// incomplete.
    pub fn read_xattr_data(&self, bt: &BtreeReader, xattr: &Xattr) -> Result<Vec<u8>> {
        match (xattr.is_embedded(), xattr.is_stream()) {
            (true, false) => Ok(xattr.data.clone()),
            (false, true) => {
                let dstream = xattr
                    .dstream()?
                    .expect("stream flag guarantees a descriptor");
                let size = usize::try_from(dstream.size).map_err(|_| {
                    Error::new(
                        ErrorKind::Io,
                        format!(
                            "xattr `{}` stream size {} does not fit this platform",
                            xattr.name, dstream.size
                        ),
                    )
                })?;
                let records = self.records(bt, dstream.xattr_obj_id).map_err(|error| {
                    error.with_context(format!(
                        "xattr `{}` data stream {:#x}",
                        xattr.name, dstream.xattr_obj_id
                    ))
                })?;
                let mut data = Vec::new();
                data.try_reserve_exact(size).map_err(|_| {
                    Error::new(
                        ErrorKind::Io,
                        format!(
                            "cannot allocate {} bytes for xattr `{}`",
                            dstream.size, xattr.name
                        ),
                    )
                })?;
                let written = self.write_file_data(&records, dstream.size, &mut data)?;
                if written.bytes != dstream.size
                    || written.holes > 0
                    || written.overlaps > 0
                    || written.missing > 0
                    || data.len() != size
                {
                    return Err(corrupt(format!(
                        "xattr `{}` stream is incomplete: {} bytes, {} hole(s), {} overlap(s), {} missing byte(s)",
                        xattr.name,
                        written.bytes,
                        written.holes,
                        written.overlaps,
                        written.missing
                    )));
                }
                Ok(data)
            }
            _ => Err(corrupt(format!(
                "xattr `{}` has invalid storage flags {:#x}",
                xattr.name, xattr.flags
            ))),
        }
    }

    /// Extract a symlink's target from its `com.apple.fs.symlink` xattr, if the
    /// records belong to a symlink and the target is stored inline.
    pub fn symlink_target(records: &[Record]) -> Result<Option<String>> {
        for rec in records {
            let (_oid, ty) = split_obj_id_and_type(crate::apfs::raw::u64_at(&rec.key, 0)?);
            if ty == jrec::APFS_TYPE_XATTR {
                let x = Xattr::parse(&rec.key, &rec.val)?;
                if x.name == SYMLINK_XATTR && x.is_embedded() {
                    return Ok(Some(crate::apfs::raw::cstr_utf8(&x.data)));
                }
            }
        }
        Ok(None)
    }
}

fn select_file_data_records<'a>(
    fsoid: u64,
    private_id: u64,
    inode_records: &'a [Record],
    load: impl FnOnce(u64) -> Result<Vec<Record>>,
) -> Result<Cow<'a, [Record]>> {
    if private_id == fsoid {
        Ok(Cow::Borrowed(inode_records))
    } else {
        load(private_id).map(Cow::Owned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(oid: u64, ty: u8) -> Record {
        Record {
            key: ((oid & 0x0fff_ffff_ffff_ffff) | ((ty as u64) << 60))
                .to_le_bytes()
                .to_vec(),
            val: Vec::new(),
        }
    }

    fn extent_record(oid: u64, logical_addr: u64, len: u64, phys_block_num: u64) -> Record {
        let mut record = record(oid, jrec::APFS_TYPE_FILE_EXTENT);
        record.key.extend_from_slice(&logical_addr.to_le_bytes());
        record.val.extend_from_slice(&len.to_le_bytes());
        record.val.extend_from_slice(&phys_block_num.to_le_bytes());
        record.val.extend_from_slice(&0u64.to_le_bytes());
        record
    }

    #[test]
    fn file_data_records_load_private_id_when_it_differs_from_fsoid() {
        let fsoid = 0x61e1e0;
        let private_id = 0x35748c;
        let inode_records = vec![record(fsoid, jrec::APFS_TYPE_INODE)];
        let private_extent = extent_record(private_id, 0, 4096, 0x1234);
        let mut loaded_oid = None;

        let selected =
            select_file_data_records(fsoid, private_id, &inode_records, |requested_oid| {
                loaded_oid = Some(requested_oid);
                Ok(vec![private_extent.clone()])
            })
            .expect("private-id records should load");

        assert_eq!(loaded_oid, Some(private_id));
        assert_eq!(selected.len(), 1);
        let (oid, ty) = split_obj_id_and_type(
            crate::apfs::raw::u64_at(&selected[0].key, 0).expect("record key"),
        );
        assert_eq!(oid, private_id);
        assert_eq!(ty, jrec::APFS_TYPE_FILE_EXTENT);
        let extent = FileExtent::parse(&selected[0].key, &selected[0].val)
            .expect("selected private-id record should be a valid extent");
        assert_eq!(extent.len, 4096);
        assert_eq!(extent.phys_block_num, 0x1234);
    }

    #[test]
    fn file_data_records_reuse_inode_records_when_ids_match() {
        let fsoid = 0x42;
        let inode_records = vec![record(fsoid, jrec::APFS_TYPE_FILE_EXTENT)];

        let selected = select_file_data_records(fsoid, fsoid, &inode_records, |_| {
            panic!("matching ids must not trigger another tree lookup")
        })
        .expect("matching ids should use existing records");

        assert!(matches!(selected, Cow::Borrowed(_)));
        assert_eq!(selected.len(), 1);
    }
}
