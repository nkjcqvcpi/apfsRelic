//! Reusable APFS B-tree engine (rewrite plan Phase 8).
//!
//! Supports both shapes of APFS tree:
//!  * **Object-map trees** — fixed-size keys/values, child links are *physical*
//!    block addresses. Used for exact `(oid, xid)` lookups ([`BtreeReader::omap_get`]).
//!  * **Filesystem / snapshot-metadata trees** — variable-size keys/values keyed
//!    by `j_key_t` (`obj_id_and_type`); child links are *virtual* OIDs resolved
//!    through a volume object map. Used to collect all records for one object
//!    ([`BtreeReader::fs_collect`]) and to stream every record in order
//!    ([`BtreeReader::fs_walk`]).
//!
//! Every key/value/TOC access is bounds-checked against the node's geometry
//! before being dereferenced (mirroring the fuzz-hardened C traversal). Tree
//! depth and node-load counts are capped to defeat malformed loops, and a bad
//! checksum is recorded as a warning rather than aborting (best-effort reads).

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use super::checksum;
use super::obj::ObjPhys;
use super::omap::{OmapEntry, OmapKey, OmapVal};
use super::raw;
use crate::device::BlockDevice;
use crate::error::{corrupt, Result};

const MAX_NODE_DESCENT: u16 = 64; // cap on B-tree depth (real depth is tiny)
const MAX_NODE_LOADS: u64 = 1 << 20; // cap on total node reads per query
const MAX_FS_RECORDS: usize = 1 << 24; // cap on records collected per object
const BTREE_INFO_SIZE: usize = 40; // sizeof(btree_info_t), trailing on root nodes
const BTN_DATA_OFF: usize = 56; // offsetof(btree_node_phys_t, btn_data)

// Node flags.
const BTNODE_ROOT: u16 = 0x0001;
const BTNODE_LEAF: u16 = 0x0002;
const BTNODE_FIXED_KV_SIZE: u16 = 0x0004;

/// A raw filesystem record: the key and value bytes copied out of a leaf.
#[derive(Debug, Clone)]
pub struct Record {
    pub key: Vec<u8>,
    pub val: Vec<u8>,
}

/// A visitor invoked for each `(key, value)` leaf record during a tree walk.
/// Returns `Ok(false)` to stop the walk early.
pub type RecordVisitor<'f> = dyn FnMut(&[u8], &[u8]) -> Result<bool> + 'f;

#[derive(Clone, Copy)]
struct FsCollectQuery {
    omap_root: Option<u64>,
    oid: u64,
    max_xid: u64,
}

/// A validated view onto a B-tree node's geometry, borrowing the block bytes.
struct NodeView<'a> {
    block: &'a [u8],
    toc_off: usize,
    key_off: usize,
    val_end_off: usize,
    nkeys: u32,
    fixed: bool,
    leaf: bool,
    level: u16,
}

impl<'a> NodeView<'a> {
    /// Validate `block` as a B-tree node against `block_size`.
    fn parse(block: &'a [u8], block_size: usize) -> Result<NodeView<'a>> {
        if block.len() < BTN_DATA_OFF {
            return Err(corrupt("b-tree node shorter than its header"));
        }
        let flags = raw::u16_at(block, 32)?;
        let level = raw::u16_at(block, 34)?;
        let nkeys = raw::u32_at(block, 36)?;
        let ts_off = raw::u16_at(block, 40)? as usize;
        let ts_len = raw::u16_at(block, 42)? as usize;

        let root = flags & BTNODE_ROOT != 0;
        let fixed = flags & BTNODE_FIXED_KV_SIZE != 0;
        let leaf = flags & BTNODE_LEAF != 0;

        let val_end_off = if root {
            block_size
                .checked_sub(BTREE_INFO_SIZE)
                .ok_or_else(|| corrupt("block smaller than btree_info"))?
        } else {
            block_size
        };

        let toc_off = BTN_DATA_OFF
            .checked_add(ts_off)
            .ok_or_else(|| corrupt("toc offset overflow"))?;
        let key_off = toc_off
            .checked_add(ts_len)
            .ok_or_else(|| corrupt("key area offset overflow"))?;
        if key_off > val_end_off || val_end_off > block.len() {
            return Err(corrupt("b-tree node TOC/key/value areas out of range"));
        }

        // The TOC must be large enough to hold `nkeys` entries.
        let esize = if fixed { 4 } else { 8 };
        if (nkeys as usize)
            .checked_mul(esize)
            .ok_or_else(|| corrupt("toc size overflow"))?
            > ts_len
            || nkeys as usize > block_size / esize
        {
            return Err(corrupt(format!(
                "b-tree node claims {nkeys} keys that don't fit its {ts_len}-byte TOC"
            )));
        }

        Ok(NodeView {
            block,
            toc_off,
            key_off,
            val_end_off,
            nkeys,
            fixed,
            leaf,
            level,
        })
    }

    /// Fixed TOC entry `i` -> (key_off, val_off).
    fn fixed_toc(&self, i: u32) -> Result<(u16, u16)> {
        let p = self.toc_off + i as usize * 4;
        Ok((raw::u16_at(self.block, p)?, raw::u16_at(self.block, p + 2)?))
    }

    /// Variable TOC entry `i` -> (key_off, key_len, val_off, val_len).
    fn var_toc(&self, i: u32) -> Result<(u16, u16, u16, u16)> {
        let p = self.toc_off + i as usize * 8;
        Ok((
            raw::u16_at(self.block, p)?,
            raw::u16_at(self.block, p + 2)?,
            raw::u16_at(self.block, p + 4)?,
            raw::u16_at(self.block, p + 6)?,
        ))
    }

    /// Bounds-checked key bytes at key-area offset `off`, length `len`.
    fn key_ptr(&self, off: u16, len: usize) -> Result<&'a [u8]> {
        let p = self.key_off + off as usize;
        let end = p
            .checked_add(len)
            .ok_or_else(|| corrupt("key length overflow"))?;
        if end > self.val_end_off {
            return Err(corrupt("key extends past value area"));
        }
        raw::slice(self.block, p, len)
    }

    /// Bounds-checked value bytes at offset `off` counted back from value end.
    fn val_ptr(&self, off: u16, len: usize) -> Result<&'a [u8]> {
        if off as usize > self.val_end_off {
            return Err(corrupt("value offset past value area"));
        }
        let p = self.val_end_off - off as usize;
        let end = p
            .checked_add(len)
            .ok_or_else(|| corrupt("value length overflow"))?;
        if p < self.key_off || end > self.val_end_off {
            return Err(corrupt("value out of range"));
        }
        raw::slice(self.block, p, len)
    }
}

/// B-tree engine bound to a device + block size, with a node-block cache and a
/// running list of best-effort warnings (e.g. checksum mismatches).
pub struct BtreeReader<'a> {
    dev: &'a dyn BlockDevice,
    block_size: u32,
    cache: RefCell<HashMap<u64, Rc<Vec<u8>>>>,
    loads: RefCell<u64>,
    warnings: RefCell<Vec<String>>,
}

impl<'a> BtreeReader<'a> {
    pub fn new(dev: &'a dyn BlockDevice, block_size: u32) -> Self {
        BtreeReader {
            dev,
            block_size,
            cache: RefCell::new(HashMap::new()),
            loads: RefCell::new(0),
            warnings: RefCell::new(Vec::new()),
        }
    }

    /// Drain accumulated warnings.
    pub fn take_warnings(&self) -> Vec<String> {
        std::mem::take(&mut self.warnings.borrow_mut())
    }

    fn warn(&self, msg: String) {
        let mut w = self.warnings.borrow_mut();
        if w.len() < 256 {
            w.push(msg);
        }
    }

    /// Read and cache a node block at physical address `paddr`; warn (don't
    /// abort) on checksum mismatch.
    fn read_node(&self, paddr: u64) -> Result<Rc<Vec<u8>>> {
        if let Some(b) = self.cache.borrow().get(&paddr) {
            return Ok(Rc::clone(b));
        }
        {
            let mut loads = self.loads.borrow_mut();
            *loads += 1;
            if *loads > MAX_NODE_LOADS {
                return Err(corrupt("b-tree node-load budget exceeded (possible loop)"));
            }
        }
        let block = self.dev.read_block(paddr, self.block_size)?;
        if !checksum::is_valid(&block) {
            self.warn(format!(
                "checksum mismatch for node at block {paddr:#x}; continuing best-effort"
            ));
        }
        let rc = Rc::new(block);
        let mut cache = self.cache.borrow_mut();
        if cache.len() >= 4096 {
            cache.clear();
        }
        cache.insert(paddr, Rc::clone(&rc));
        Ok(rc)
    }

    fn node_view<'b>(&self, block: &'b [u8], paddr: u64) -> Result<NodeView<'b>> {
        NodeView::parse(block, self.block_size as usize)
            .map_err(|error| error.with_context(node_context(block, paddr)))
    }

    /// Exact `(oid, xid)` lookup in a physical object-map B-tree rooted at block
    /// `root_block`. Returns the entry with the given `oid` and the greatest
    /// `xid <= max_xid`, or `None` if absent.
    pub fn omap_get(&self, root_block: u64, oid: u64, max_xid: u64) -> Result<Option<OmapEntry>> {
        let mut paddr = root_block;
        let mut block = self.read_node(paddr)?;

        for _ in 0..MAX_NODE_DESCENT {
            let v = self.node_view(&block, paddr)?;
            if !v.fixed {
                return Err(corrupt("object-map node is not fixed-kv")
                    .with_context(node_context(&block, paddr)));
            }

            // Pick the last entry whose oid < target, or oid == target and
            // xid <= max_xid.
            let mut chosen: i64 = -1;
            for i in 0..v.nkeys {
                let (koff, _) = v.fixed_toc(i)?;
                let key = OmapKey::parse(v.key_ptr(koff, OmapKey::SIZE)?)?;
                if key.oid > oid || (key.oid == oid && key.xid > max_xid) {
                    break;
                }
                chosen = i as i64;
            }
            if chosen < 0 {
                return Ok(None);
            }
            let chosen = chosen as u32;
            let (koff, voff) = v.fixed_toc(chosen)?;

            if v.leaf {
                let key = OmapKey::parse(v.key_ptr(koff, OmapKey::SIZE)?)?;
                if key.oid != oid || key.xid > max_xid {
                    return Ok(None);
                }
                let val = OmapVal::parse(v.val_ptr(voff, OmapVal::SIZE)?)?;
                return Ok(Some(OmapEntry { key, val }));
            }

            // Nonleaf: child link is a physical block address (8 bytes).
            let child = raw::u64_at(v.val_ptr(voff, 8)?, 0)?;
            paddr = child;
            block = self.read_node(paddr)?;
        }
        Err(corrupt("object-map descent exceeded depth cap"))
    }

    /// Resolve a nonleaf child link to its physical block address. For a virtual
    /// tree (`omap_root = Some`) the link is a virtual OID resolved through the
    /// omap; for a physical tree (`omap_root = None`) the link is already a
    /// physical block address.
    fn resolve_child(
        &self,
        omap_root: Option<u64>,
        link: u64,
        max_xid: u64,
    ) -> Result<Option<u64>> {
        match omap_root {
            Some(root) => super::resolver::readable_paddr(
                self.omap_get(root, link, max_xid)?,
                &format!("virtual B-tree child {link:#x}"),
            ),
            None => Ok(Some(link)),
        }
    }

    /// Collect every record whose `obj_id` (low 60 bits of `obj_id_and_type`)
    /// equals `oid`, from the filesystem tree rooted at `fs_root_block`. When
    /// `omap_root` is `Some`, child links are virtual OIDs resolved through it;
    /// when `None`, the tree is physical and child links are block addresses.
    pub fn fs_collect(
        &self,
        omap_root: Option<u64>,
        fs_root_block: u64,
        oid: u64,
        max_xid: u64,
    ) -> Result<Vec<Record>> {
        let mut out = Vec::new();
        let root = self.read_node(fs_root_block)?;
        let query = FsCollectQuery {
            omap_root,
            oid,
            max_xid,
        };
        self.fs_collect_node(&root, fs_root_block, query, &mut out, 0)?;
        Ok(out)
    }

    fn fs_collect_node(
        &self,
        block: &[u8],
        paddr: u64,
        query: FsCollectQuery,
        out: &mut Vec<Record>,
        depth: u16,
    ) -> Result<()> {
        if depth > MAX_NODE_DESCENT {
            return Err(corrupt("fs-tree descent exceeded depth cap"));
        }
        let v = self.node_view(block, paddr)?;
        if v.fixed {
            return Err(corrupt("filesystem tree node has fixed-kv geometry")
                .with_context(node_context(block, paddr)));
        }

        if v.leaf {
            for i in 0..v.nkeys {
                let (koff, klen, voff, vlen) = v.var_toc(i)?;
                let key = v.key_ptr(koff, klen as usize)?;
                let obj_id = raw::u64_at(key, 0)? & OBJ_ID_MASK;
                if obj_id < query.oid {
                    continue;
                }
                if obj_id > query.oid {
                    break; // sorted: no more records for this oid
                }
                if out.len() >= MAX_FS_RECORDS {
                    return Err(corrupt("fs record cap exceeded"));
                }
                let val = v.val_ptr(voff, vlen as usize)?;
                out.push(Record {
                    key: key.to_vec(),
                    val: val.to_vec(),
                });
            }
            return Ok(());
        }

        // Nonleaf: descend into children whose key range may contain `oid`.
        for i in 0..v.nkeys {
            let (koff, klen, voff, _vlen) = v.var_toc(i)?;
            let key_i = raw::u64_at(v.key_ptr(koff, klen.max(8) as usize)?, 0)? & OBJ_ID_MASK;
            let next_oid = if i + 1 < v.nkeys {
                let (nk, nkl, _, _) = v.var_toc(i + 1)?;
                raw::u64_at(v.key_ptr(nk, nkl.max(8) as usize)?, 0)? & OBJ_ID_MASK
            } else {
                u64::MAX
            };
            if key_i > query.oid {
                break;
            }
            if key_i <= query.oid && query.oid <= next_oid {
                let child_link = raw::u64_at(v.val_ptr(voff, 8)?, 0)?;
                if let Some(child_paddr) =
                    self.resolve_child(query.omap_root, child_link, query.max_xid)?
                {
                    let child = self.read_node(child_paddr)?;
                    self.fs_collect_node(&child, child_paddr, query, out, depth + 1)?;
                } else {
                    self.warn(format!(
                        "volume omap has no object for virtual OID {child_link:#x}"
                    ));
                }
            }
        }
        Ok(())
    }

    /// Stream every record of the filesystem/snapshot tree in key order. `visit`
    /// returns `Ok(false)` to stop early. Child links are virtual OIDs resolved
    /// through `omap_root`.
    pub fn fs_walk(
        &self,
        omap_root: Option<u64>,
        fs_root_block: u64,
        max_xid: u64,
        visit: &mut RecordVisitor,
    ) -> Result<()> {
        let root = self.read_node(fs_root_block)?;
        self.fs_walk_node(&root, fs_root_block, omap_root, max_xid, visit, 0)?;
        Ok(())
    }

    fn fs_walk_node(
        &self,
        block: &[u8],
        paddr: u64,
        omap_root: Option<u64>,
        max_xid: u64,
        visit: &mut RecordVisitor,
        depth: u16,
    ) -> Result<bool> {
        if depth > MAX_NODE_DESCENT {
            return Err(corrupt("fs-tree walk exceeded depth cap"));
        }
        let v = self.node_view(block, paddr)?;
        if v.fixed {
            return Err(corrupt("filesystem tree node has fixed-kv geometry")
                .with_context(node_context(block, paddr)));
        }
        if v.leaf {
            for i in 0..v.nkeys {
                let (koff, klen, voff, vlen) = v.var_toc(i)?;
                let key = v.key_ptr(koff, klen as usize)?;
                let val = v.val_ptr(voff, vlen as usize)?;
                if !visit(key, val)? {
                    return Ok(false);
                }
            }
            return Ok(true);
        }
        for i in 0..v.nkeys {
            let (_koff, _klen, voff, _vlen) = v.var_toc(i)?;
            let child_link = raw::u64_at(v.val_ptr(voff, 8)?, 0)?;
            if let Some(child_paddr) = self.resolve_child(omap_root, child_link, max_xid)? {
                let child = self.read_node(child_paddr)?;
                if !self.fs_walk_node(&child, child_paddr, omap_root, max_xid, visit, depth + 1)? {
                    return Ok(false);
                }
            } else {
                self.warn(format!(
                    "volume omap has no object for virtual OID {child_link:#x}"
                ));
            }
        }
        Ok(true)
    }

    /// Read a physical object block, validating its checksum (warn on mismatch)
    /// and returning both the parsed header and the raw bytes. Used by the
    /// container/volume layers for non-tree objects.
    pub fn read_object(&self, paddr: u64) -> Result<(ObjPhys, Rc<Vec<u8>>)> {
        let block = self.read_node(paddr)?;
        let header = ObjPhys::parse(&block)?;
        Ok((header, block))
    }

    /// Access to the level field of a root node, for `inspect`/`verify`.
    pub fn root_level(&self, root_block: u64) -> Result<u16> {
        let block = self.read_node(root_block)?;
        let v = self.node_view(&block, root_block)?;
        Ok(v.level)
    }
}

fn node_context(block: &[u8], paddr: u64) -> String {
    let checksum = if checksum::is_valid(block) {
        "valid"
    } else {
        "invalid"
    };
    match ObjPhys::parse(block) {
        Ok(header) => format!(
            "B-tree block {paddr:#x}, checksum={checksum}, object_oid={:#x}, xid={:#x}, type={}({:#x}), subtype={}({:#x})",
            header.oid,
            header.xid,
            super::obj::type_name(header.type_id()),
            header.otype,
            super::obj::type_name(header.subtype & super::obj::OBJECT_TYPE_MASK),
            header.subtype
        ),
        Err(_) => format!("B-tree block {paddr:#x}, checksum={checksum}, object header unreadable"),
    }
}

/// Mask of the object-id portion of `j_key_t::obj_id_and_type`.
pub const OBJ_ID_MASK: u64 = 0x0fff_ffff_ffff_ffff;
/// Mask of the type portion.
pub const OBJ_TYPE_MASK: u64 = 0xf000_0000_0000_0000;
/// Shift to extract the type nibble.
pub const OBJ_TYPE_SHIFT: u64 = 60;

/// Extract `(obj_id, type)` from a `j_key_t` leading u64.
pub fn split_obj_id_and_type(v: u64) -> (u64, u8) {
    (
        (v & OBJ_ID_MASK),
        ((v & OBJ_TYPE_MASK) >> OBJ_TYPE_SHIFT) as u8,
    )
}
