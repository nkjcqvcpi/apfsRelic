//! Object resolver status types (rewrite plan Phase 7).
//!
//! The actual traversal lives in [`crate::apfs::btree::BtreeReader`]; this module
//! adds the richer *status* vocabulary the rewrite plan calls for, so callers can
//! distinguish "deleted" from "missing" from "encrypted" without duplicating
//! object-map logic. `ls`, `stat`, `recover`, and `inspect` all resolve through
//! the same `BtreeReader`, then classify with [`classify`].

use super::btree::BtreeReader;
use super::omap::OmapEntry;
use crate::error::{Error, ErrorKind, Result};

/// The outcome of resolving a virtual object through an object map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveStatus {
    /// Found at the given physical block address.
    Found { paddr: u64, xid: u64 },
    /// No entry for this OID at or below the requested XID.
    NotFound,
    /// The entry is present but flagged deleted.
    Deleted,
    /// The entry is flagged encrypted (object-level).
    Encrypted,
}

/// Classify an optional omap entry into a [`ResolveStatus`].
pub fn classify(entry: Option<OmapEntry>) -> ResolveStatus {
    match entry {
        None => ResolveStatus::NotFound,
        Some(e) if e.val.is_deleted() => ResolveStatus::Deleted,
        Some(e) if e.val.is_encrypted() => ResolveStatus::Encrypted,
        Some(e) => ResolveStatus::Found {
            paddr: e.val.paddr,
            xid: e.key.xid,
        },
    }
}

/// Resolve a virtual OID through a physical omap tree and classify the result.
pub fn resolve_virtual(
    bt: &BtreeReader,
    omap_root: u64,
    oid: u64,
    max_xid: u64,
) -> Result<ResolveStatus> {
    Ok(classify(bt.omap_get(omap_root, oid, max_xid)?))
}

/// Return a readable physical address for an object-map lookup.
///
/// A deleted mapping is a placeholder, not an object location.  Treating its
/// `ov_paddr` as a block address can make unrelated bytes look like a malformed
/// B-tree node.  Encrypted object mappings are also not readable as plaintext.
pub fn readable_paddr(entry: Option<OmapEntry>, description: &str) -> Result<Option<u64>> {
    match classify(entry) {
        ResolveStatus::Found { paddr, .. } => Ok(Some(paddr)),
        ResolveStatus::NotFound | ResolveStatus::Deleted => Ok(None),
        ResolveStatus::Encrypted => Err(Error::new(
            ErrorKind::EncryptedUnsupported,
            format!("{description} is encrypted"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apfs::omap::{OmapKey, OmapVal, OMAP_VAL_DELETED, OMAP_VAL_ENCRYPTED};

    fn entry(flags: u32) -> OmapEntry {
        OmapEntry {
            key: OmapKey { oid: 5, xid: 9 },
            val: OmapVal {
                flags,
                size: 4096,
                paddr: 0x1234,
            },
        }
    }

    #[test]
    fn classifies_statuses() {
        assert_eq!(classify(None), ResolveStatus::NotFound);
        assert_eq!(
            classify(Some(entry(OMAP_VAL_DELETED))),
            ResolveStatus::Deleted
        );
        assert_eq!(
            classify(Some(entry(OMAP_VAL_ENCRYPTED))),
            ResolveStatus::Encrypted
        );
        assert_eq!(
            classify(Some(entry(0))),
            ResolveStatus::Found {
                paddr: 0x1234,
                xid: 9
            }
        );
    }

    #[test]
    fn deleted_mapping_never_yields_a_physical_address() {
        assert_eq!(
            readable_paddr(Some(entry(OMAP_VAL_DELETED)), "test object").unwrap(),
            None
        );
        assert_eq!(
            readable_paddr(Some(entry(0)), "test object").unwrap(),
            Some(0x1234)
        );
        assert_eq!(readable_paddr(None, "test object").unwrap(), None);
    }

    #[test]
    fn encrypted_mapping_is_not_exposed_as_plaintext() {
        let error = readable_paddr(Some(entry(OMAP_VAL_ENCRYPTED)), "test object").unwrap_err();
        assert_eq!(error.kind(), ErrorKind::EncryptedUnsupported);
    }
}
