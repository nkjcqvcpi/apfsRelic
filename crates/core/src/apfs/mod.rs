//! APFS on-disk parsing and the high-level container/volume engine.
//!
//! Lower layers (`raw`, `checksum`, `obj`, `nx`, `omap`, `btree`, `volume`,
//! `jrec`, `xfield`, `time`) are pure parsers with no I/O beyond a borrowed byte
//! slice. Higher layers (`container`, `vol`, `resolver`, `path`, `snapshot`,
//! `feature`) drive a [`crate::device::BlockDevice`] to open a container, pick a
//! checkpoint, and read filesystem records. Every layer is independent of the
//! CLI.

pub mod btree;
pub mod checksum;
pub mod container;
pub mod decmpfs;
pub mod extract;
pub mod feature;
pub mod history;
pub mod jrec;
pub mod nx;
pub mod obj;
pub mod omap;
pub mod path;
pub mod raw;
pub mod resolver;
pub mod snapshot;
pub mod time;
pub mod vol;
pub mod volume;
pub mod xfield;
