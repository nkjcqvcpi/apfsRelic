//! Filesystem record (`j_*`) key/value parsers (spec, "File-System Objects",
//! "Data Streams", "Snapshot Metadata"; rewrite plan Phase 11).
//!
//! Each record is a `(key, value)` byte pair pulled from a filesystem-tree leaf
//! by [`crate::apfs::btree`]. The key always begins with `j_key_t`
//! (`obj_id_and_type`); the value layout depends on the type nibble. Every
//! parser is bounds-checked and returns a typed error on a short/garbled value
//! rather than panicking. Unknown record types are preserved as
//! [`JRecord::Unknown`] for debug output.

use super::raw;
use super::xfield::{self, XField};
use crate::error::{corrupt, Result};

// ---- j_obj_types (the type nibble of obj_id_and_type) ----
pub const APFS_TYPE_SNAP_METADATA: u8 = 1;
pub const APFS_TYPE_EXTENT: u8 = 2;
pub const APFS_TYPE_INODE: u8 = 3;
pub const APFS_TYPE_XATTR: u8 = 4;
pub const APFS_TYPE_SIBLING_LINK: u8 = 5;
pub const APFS_TYPE_DSTREAM_ID: u8 = 6;
pub const APFS_TYPE_CRYPTO_STATE: u8 = 7;
pub const APFS_TYPE_FILE_EXTENT: u8 = 8;
pub const APFS_TYPE_DIR_REC: u8 = 9;
pub const APFS_TYPE_DIR_STATS: u8 = 10;
pub const APFS_TYPE_SNAP_NAME: u8 = 11;
pub const APFS_TYPE_SIBLING_MAP: u8 = 12;
pub const APFS_TYPE_FILE_INFO: u8 = 13;

// ---- Inode internal flags ----
pub const INODE_IS_SPARSE: u64 = 0x0000_0200;
pub const INODE_HAS_FINDER_INFO: u64 = 0x0000_0100;
pub const INODE_HAS_RSRC_FORK: u64 = 0x0000_4000;
pub const INODE_HAS_UNCOMPRESSED_SIZE: u64 = 0x0004_0000;
pub const UF_COMPRESSED: u32 = 0x0000_0020;

// ---- Directory-entry file-type nibble (DREC_TYPE_MASK = 0x000f) ----
pub const DREC_TYPE_MASK: u16 = 0x000f;
pub const DT_FIFO: u16 = 1;
pub const DT_CHR: u16 = 2;
pub const DT_DIR: u16 = 4;
pub const DT_BLK: u16 = 6;
pub const DT_REG: u16 = 8;
pub const DT_LNK: u16 = 10;
pub const DT_SOCK: u16 = 12;
pub const DT_WHT: u16 = 14;

// ---- Well-known inode numbers ----
pub const ROOT_DIR_INO_NUM: u64 = 2;
pub const PRIV_DIR_INO_NUM: u64 = 3;

const J_DREC_LEN_MASK: u32 = 0x0000_03ff;
const J_FILE_EXTENT_LEN_MASK: u64 = 0x00ff_ffff_ffff_ffff;

const INODE_FIXED_LEN: usize = 92;
// j_drec_val_t = file_id(8) + date_added(8) + flags(u16) = 18 bytes. The C
// prototype's header declares `flags` as u64 (24 bytes), but real records are
// consistently 18 bytes and the spec's `flags` is uint16_t; the C code only
// ever reads `flags & 0x000f`, so its over-wide read is masked away.
const DREC_VAL_FIXED_LEN: usize = 18;

/// Extract `(obj_id, type)` from the leading `obj_id_and_type` of a key.
pub fn key_obj_id_and_type(key: &[u8]) -> Result<(u64, u8)> {
    let v = raw::u64_at(key, 0)?;
    Ok(super::btree::split_obj_id_and_type(v))
}

/// A parsed inode record value.
#[derive(Debug, Clone)]
pub struct Inode {
    pub parent_id: u64,
    pub private_id: u64,
    pub create_time: u64,
    pub mod_time: u64,
    pub change_time: u64,
    pub access_time: u64,
    pub internal_flags: u64,
    /// `nchildren` (directories) or `nlink` (files) — same union slot.
    pub nchildren_or_nlink: i32,
    pub bsd_flags: u32,
    pub owner: u32,
    pub group: u32,
    pub mode: u16,
    pub uncompressed_size: u64,
    pub xfields: Vec<XField>,
}

impl Inode {
    pub fn parse(val: &[u8]) -> Result<Inode> {
        if val.len() < INODE_FIXED_LEN {
            return Err(corrupt(format!(
                "inode value too short ({} < {INODE_FIXED_LEN})",
                val.len()
            )));
        }
        let xfields = if val.len() > INODE_FIXED_LEN {
            xfield::parse_xfields(&val[INODE_FIXED_LEN..])?
        } else {
            Vec::new()
        };
        Ok(Inode {
            parent_id: raw::u64_at(val, 0)?,
            private_id: raw::u64_at(val, 8)?,
            create_time: raw::u64_at(val, 16)?,
            mod_time: raw::u64_at(val, 24)?,
            change_time: raw::u64_at(val, 32)?,
            access_time: raw::u64_at(val, 40)?,
            internal_flags: raw::u64_at(val, 48)?,
            nchildren_or_nlink: raw::i32_at(val, 56)?,
            bsd_flags: raw::u32_at(val, 68)?,
            owner: raw::u32_at(val, 72)?,
            group: raw::u32_at(val, 76)?,
            mode: raw::u16_at(val, 80)?,
            uncompressed_size: raw::u64_at(val, 84)?,
            xfields,
        })
    }

    /// Logical file size: prefer `uncompressed_size` when the inode advertises
    /// it, else the `DSTREAM` extended field's `size`, else `None`.
    pub fn logical_size(&self) -> Option<u64> {
        if self.internal_flags & INODE_HAS_UNCOMPRESSED_SIZE != 0 {
            return Some(self.uncompressed_size);
        }
        let f = xfield::find(&self.xfields, xfield::INO_EXT_TYPE_DSTREAM)?;
        // j_dstream_t starts with `size: u64`.
        raw::u64_at(&f.data, 0).ok()
    }

    /// Allocated (on-disk) size from the `DSTREAM` xfield, if present.
    pub fn allocated_size(&self) -> Option<u64> {
        let f = xfield::find(&self.xfields, xfield::INO_EXT_TYPE_DSTREAM)?;
        raw::u64_at(&f.data, 8).ok() // j_dstream_t.alloced_size
    }

    /// The inode's own name, from the `NAME` extended field (NUL-terminated).
    pub fn name(&self) -> Option<String> {
        let f = xfield::find(&self.xfields, xfield::INO_EXT_TYPE_NAME)?;
        Some(raw::cstr_utf8(&f.data))
    }

    pub fn is_dir(&self) -> bool {
        self.mode & 0o170000 == 0o040000
    }
    pub fn is_symlink(&self) -> bool {
        self.mode & 0o170000 == 0o120000
    }
    pub fn is_regular(&self) -> bool {
        self.mode & 0o170000 == 0o100000
    }
    pub fn is_sparse(&self) -> bool {
        self.internal_flags & INODE_IS_SPARSE != 0
    }
    pub fn has_rsrc_fork(&self) -> bool {
        self.internal_flags & INODE_HAS_RSRC_FORK != 0
    }
    pub fn has_finder_info(&self) -> bool {
        self.internal_flags & INODE_HAS_FINDER_INFO != 0
    }
    pub fn is_compressed(&self) -> bool {
        self.bsd_flags & UF_COMPRESSED != 0
    }
}

/// A parsed directory-entry record (`j_drec_hashed_key_t` + `j_drec_val_t`).
#[derive(Debug, Clone)]
pub struct DirRec {
    pub name: String,
    /// FSOID of the entry's target inode.
    pub file_id: u64,
    pub date_added: u64,
    pub flags: u16,
    pub xfields: Vec<XField>,
}

impl DirRec {
    /// Parse a directory record from its key and value bytes. The name lives in
    /// the key; we use the hashed-key form exclusively (see the C prototype's
    /// note on `j_drec_hashed_key_t`).
    pub fn parse(key: &[u8], val: &[u8]) -> Result<DirRec> {
        // key: j_key(8) | name_len_and_hash u32 | name[]
        let name_len_and_hash = raw::u32_at(key, 8)?;
        let name_len = (name_len_and_hash & J_DREC_LEN_MASK) as usize;
        let name_bytes = raw::slice(key, 12, name_len)?;
        // name_len includes the trailing NUL.
        let name = raw::cstr_utf8(name_bytes);

        if val.len() < DREC_VAL_FIXED_LEN {
            return Err(corrupt("directory record value too short"));
        }
        let xfields = if val.len() > DREC_VAL_FIXED_LEN {
            xfield::parse_xfields(&val[DREC_VAL_FIXED_LEN..])?
        } else {
            Vec::new()
        };
        Ok(DirRec {
            name,
            file_id: raw::u64_at(val, 0)?,
            date_added: raw::u64_at(val, 8)?,
            flags: raw::u16_at(val, 16)?,
            xfields,
        })
    }

    /// Stable lowercase type name for the entry's file type.
    pub fn type_name(&self) -> &'static str {
        dt_name(self.flags & DREC_TYPE_MASK)
    }
}

/// Map a directory-entry file-type nibble to a stable name.
pub fn dt_name(dt: u16) -> &'static str {
    match dt {
        DT_DIR => "dir",
        DT_REG => "file",
        DT_LNK => "symlink",
        DT_FIFO => "fifo",
        DT_CHR => "char",
        DT_BLK => "block",
        DT_SOCK => "socket",
        DT_WHT => "whiteout",
        _ => "unknown",
    }
}

/// A parsed file-extent record (`j_file_extent_key_t` + `j_file_extent_val_t`).
#[derive(Debug, Clone)]
pub struct FileExtent {
    /// Logical byte offset within the file.
    pub logical_addr: u64,
    /// Length of the extent in bytes (low 56 bits of `len_and_flags`).
    pub len: u64,
    /// First physical block of the extent (0 == sparse hole).
    pub phys_block_num: u64,
    pub crypto_id: u64,
}

impl FileExtent {
    pub fn parse(key: &[u8], val: &[u8]) -> Result<FileExtent> {
        let logical_addr = raw::u64_at(key, 8)?;
        let len_and_flags = raw::u64_at(val, 0)?;
        Ok(FileExtent {
            logical_addr,
            len: len_and_flags & J_FILE_EXTENT_LEN_MASK,
            phys_block_num: raw::u64_at(val, 8)?,
            crypto_id: raw::u64_at(val, 16)?,
        })
    }

    /// True if this extent is a sparse hole (no backing blocks).
    pub fn is_hole(&self) -> bool {
        self.phys_block_num == 0
    }
}

/// A parsed extended-attribute record (`j_xattr_key_t` + `j_xattr_val_t`).
#[derive(Debug, Clone)]
pub struct Xattr {
    pub name: String,
    pub flags: u16,
    /// Embedded data, or, for stream xattrs, the raw value bytes (a
    /// `j_xattr_dstream`). `flags` distinguishes the two.
    pub data: Vec<u8>,
}

pub const XATTR_DATA_STREAM: u16 = 0x1;
pub const XATTR_DATA_EMBEDDED: u16 = 0x2;

/// The data-stream descriptor stored in a stream-backed xattr value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XattrDstream {
    pub xattr_obj_id: u64,
    pub size: u64,
    pub allocated_size: u64,
    pub default_crypto_id: u64,
    pub total_bytes_written: u64,
    pub total_bytes_read: u64,
}

impl XattrDstream {
    pub const ENCODED_LEN: usize = 48;

    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::ENCODED_LEN {
            return Err(corrupt(format!(
                "xattr data-stream descriptor too short ({} < {})",
                data.len(),
                Self::ENCODED_LEN
            )));
        }
        Ok(Self {
            xattr_obj_id: raw::u64_at(data, 0)?,
            size: raw::u64_at(data, 8)?,
            allocated_size: raw::u64_at(data, 16)?,
            default_crypto_id: raw::u64_at(data, 24)?,
            total_bytes_written: raw::u64_at(data, 32)?,
            total_bytes_read: raw::u64_at(data, 40)?,
        })
    }
}

impl Xattr {
    pub fn parse(key: &[u8], val: &[u8]) -> Result<Xattr> {
        let name_len = raw::u16_at(key, 8)? as usize;
        let name = raw::cstr_utf8(raw::slice(key, 10, name_len)?);
        let flags = raw::u16_at(val, 0)?;
        let xdata_len = raw::u16_at(val, 2)? as usize;
        let data = raw::slice(val, 4, xdata_len.min(val.len().saturating_sub(4)))?.to_vec();
        Ok(Xattr { name, flags, data })
    }

    pub fn is_embedded(&self) -> bool {
        self.flags & XATTR_DATA_EMBEDDED != 0
    }
    pub fn is_stream(&self) -> bool {
        self.flags & XATTR_DATA_STREAM != 0
    }

    pub fn dstream(&self) -> Result<Option<XattrDstream>> {
        if self.is_stream() {
            Ok(Some(XattrDstream::parse(&self.data)?))
        } else {
            Ok(None)
        }
    }
}

/// A parsed snapshot-metadata record (`j_snap_metadata_val_t`).
#[derive(Debug, Clone)]
pub struct SnapMetadata {
    pub extentref_tree_oid: u64,
    pub sblock_oid: u64,
    pub create_time: u64,
    pub change_time: u64,
    pub inum: u64,
    pub flags: u32,
    pub name: String,
}

impl SnapMetadata {
    pub fn parse(val: &[u8]) -> Result<SnapMetadata> {
        // oid(8) oid(8) time(8) time(8) inum(8) type(4) flags(4) name_len(2) name[]
        let name_len = raw::u16_at(val, 48)? as usize;
        let name = raw::cstr_utf8(raw::slice(val, 50, name_len)?);
        Ok(SnapMetadata {
            extentref_tree_oid: raw::u64_at(val, 0)?,
            sblock_oid: raw::u64_at(val, 8)?,
            create_time: raw::u64_at(val, 16)?,
            change_time: raw::u64_at(val, 24)?,
            inum: raw::u64_at(val, 32)?,
            flags: raw::u32_at(val, 44)?,
            name,
        })
    }
}

/// A snapshot-name record key+value (`j_snap_name_key_t` + `j_snap_name_val_t`).
#[derive(Debug, Clone)]
pub struct SnapName {
    pub name: String,
    pub snap_xid: u64,
}

impl SnapName {
    pub fn parse(key: &[u8], val: &[u8]) -> Result<SnapName> {
        let name_len = raw::u16_at(key, 8)? as usize;
        let name = raw::cstr_utf8(raw::slice(key, 10, name_len)?);
        Ok(SnapName {
            name,
            snap_xid: raw::u64_at(val, 0)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_xattr_data_stream_descriptor() {
        let values = [0x1234u64, 99, 128, 7, 456, 321];
        let mut data = Vec::new();
        for value in values {
            data.extend_from_slice(&value.to_le_bytes());
        }
        let stream = XattrDstream::parse(&data).expect("valid descriptor");
        assert_eq!(stream.xattr_obj_id, 0x1234);
        assert_eq!(stream.size, 99);
        assert_eq!(stream.allocated_size, 128);
        assert_eq!(stream.default_crypto_id, 7);
        assert_eq!(stream.total_bytes_written, 456);
        assert_eq!(stream.total_bytes_read, 321);
        assert_eq!(
            XattrDstream::parse(&data[..47]).unwrap_err().kind(),
            crate::error::ErrorKind::Corrupt
        );
    }
}
