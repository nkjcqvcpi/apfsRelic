//! File-data extraction engine: turn a set of file extents into a dense byte
//! stream or a sparse seekable file following the logical layout (rewrite plan
//! Phase 16). Separated from the `recover` command so the byte-exact layout
//! logic is unit-testable without a CLI or a real container.

use std::fs::File;
use std::io::{Seek, SeekFrom, Write};

use super::jrec::FileExtent;
use crate::device::BlockDevice;
use crate::error::Result;

/// Outcome of writing file bytes.
#[derive(Debug, Default, Clone, Copy)]
pub struct Written {
    /// Total logical bytes reconstructed (should equal the file size on success).
    pub bytes: u64,
    /// Logical bytes supplied by non-hole extents.
    pub data_bytes: u64,
    /// Number of hole/gap regions, either zero-filled or retained as sparse.
    pub holes: u64,
    /// Number of overlapping extents skipped.
    pub overlaps: u64,
    /// Bytes that could not be written (file size minus bytes written).
    pub missing: u64,
}

impl Written {
    /// A short human note describing anomalies, or `None` if clean.
    pub fn note(&self) -> Option<String> {
        let mut parts = Vec::new();
        if self.holes > 0 {
            parts.push(format!("{} hole(s)", self.holes));
        }
        if self.overlaps > 0 {
            parts.push(format!("{} overlap(s)", self.overlaps));
        }
        if self.missing > 0 {
            parts.push(format!("{} missing byte(s)", self.missing));
        }
        if parts.is_empty() {
            None
        } else {
            Some(parts.join(", "))
        }
    }
}

/// Write `file_size` bytes to `writer` following the logical layout of
/// `extents`. Extents are sorted by logical address; gaps and zero-block extents
/// become zero-filled holes; overlapping extents keep the earlier data; output
/// stops exactly at `file_size`. Works sequentially so it is correct for both a
/// seekable file and a non-seekable stream (e.g. stdout).
pub fn write_extents(
    dev: &dyn BlockDevice,
    block_size: u32,
    extents: &mut [FileExtent],
    file_size: u64,
    writer: &mut dyn Write,
) -> Result<Written> {
    let mut output = ExtentOutput::Dense {
        writer,
        zero: vec![0u8; block_size as usize],
    };
    write_extents_to(dev, block_size, extents, file_size, &mut output)
}

/// Reconstruct a sparse file while retaining gaps and explicit hole extents as
/// unallocated ranges in `file`. The final logical length, including a trailing
/// hole, is established with [`File::set_len`].
pub fn write_extents_sparse(
    dev: &dyn BlockDevice,
    block_size: u32,
    extents: &mut [FileExtent],
    file_size: u64,
    file: &mut File,
) -> Result<Written> {
    let mut output = ExtentOutput::Sparse { file };
    write_extents_to(dev, block_size, extents, file_size, &mut output)
}

enum ExtentOutput<'a> {
    Dense {
        writer: &'a mut dyn Write,
        zero: Vec<u8>,
    },
    Sparse {
        file: &'a mut File,
    },
}

impl ExtentOutput<'_> {
    fn write_all(&mut self, data: &[u8]) -> Result<()> {
        match self {
            ExtentOutput::Dense { writer, .. } => writer.write_all(data)?,
            ExtentOutput::Sparse { file } => file.write_all(data)?,
        }
        Ok(())
    }

    fn hole(&mut self, len: u64, logical_end: u64) -> Result<()> {
        match self {
            ExtentOutput::Dense { writer, zero } => write_zeros(*writer, len, zero)?,
            ExtentOutput::Sparse { file } => {
                file.seek(SeekFrom::Start(logical_end))?;
            }
        }
        Ok(())
    }

    fn finish(&mut self, file_size: u64) -> Result<()> {
        if let ExtentOutput::Sparse { file } = self {
            file.set_len(file_size)?;
        }
        Ok(())
    }
}

fn write_extents_to(
    dev: &dyn BlockDevice,
    block_size: u32,
    extents: &mut [FileExtent],
    file_size: u64,
    output: &mut ExtentOutput<'_>,
) -> Result<Written> {
    extents.sort_by_key(|e| e.logical_addr);

    let bs = block_size as u64;
    let mut cursor = 0u64;
    let mut data_bytes = 0u64;
    let mut holes = 0u64;
    let mut overlaps = 0u64;

    for e in extents.iter() {
        if cursor >= file_size {
            break;
        }
        if e.logical_addr > cursor {
            // Gap before this extent => sparse hole.
            let gap = (e.logical_addr - cursor).min(file_size - cursor);
            cursor += gap;
            output.hole(gap, cursor)?;
            holes += 1;
        } else if e.logical_addr < cursor {
            // Overlapping extent: keep the earlier data already written.
            overlaps += 1;
            continue;
        }
        if cursor >= file_size {
            break;
        }

        let want = e.len.min(file_size - cursor);
        if e.is_hole() {
            cursor += want;
            output.hole(want, cursor)?;
            holes += 1;
            continue;
        }

        let mut block = e.phys_block_num;
        let mut remaining = want;
        while remaining > 0 {
            let data = dev.read_block(block, block_size)?;
            let n = remaining.min(bs);
            output.write_all(&data[..n as usize])?;
            remaining -= n;
            cursor += n;
            data_bytes += n;
            block += 1;
        }
    }

    if cursor < file_size {
        let tail = file_size - cursor;
        cursor = file_size;
        output.hole(tail, cursor)?;
        holes += 1;
    }
    output.finish(file_size)?;

    Ok(Written {
        bytes: cursor,
        data_bytes,
        holes,
        overlaps,
        missing: file_size.saturating_sub(cursor),
    })
}

fn write_zeros(writer: &mut dyn Write, mut n: u64, zero: &[u8]) -> Result<()> {
    while n > 0 {
        let chunk = (n as usize).min(zero.len());
        writer.write_all(&zero[..chunk])?;
        n -= chunk as u64;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Result as DResult;
    use std::fs::{self, OpenOptions};
    use std::io::Read;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TestPath(PathBuf);

    impl TestPath {
        fn file(label: &str) -> (Self, File) {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock must be after Unix epoch")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "apfsrelic-extract-{label}-{}-{nonce}",
                std::process::id()
            ));
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
                .expect("create sparse-output test file");
            (Self(path), file)
        }
    }

    impl Drop for TestPath {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    /// Minimal in-memory block device for tests.
    struct MemDevice {
        data: Vec<u8>,
    }
    impl BlockDevice for MemDevice {
        fn size(&self) -> u64 {
            self.data.len() as u64
        }
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> DResult<()> {
            let o = offset as usize;
            buf.copy_from_slice(&self.data[o..o + buf.len()]);
            Ok(())
        }
        fn description(&self) -> &str {
            "mem"
        }
    }

    fn extent(logical: u64, len: u64, phys: u64) -> FileExtent {
        FileExtent {
            logical_addr: logical,
            len,
            phys_block_num: phys,
            crypto_id: 0,
        }
    }

    #[test]
    fn writes_sparse_file_with_hole() {
        // 3 blocks of 4 bytes. Block 1 = "AAAA", block 2 = "BBBB".
        let bs = 4u32;
        let mut data = vec![0u8; 12];
        data[4..8].copy_from_slice(b"AAAA"); // block 1
        data[8..12].copy_from_slice(b"BBBB"); // block 2
        let dev = MemDevice { data };

        // File: [0,4) from block 1, [4,8) hole, [8,12) from block 2. size=12.
        let mut extents = vec![
            extent(0, 4, 1),
            // logical 8 from block 2; logical 4..8 is a gap (hole).
            extent(8, 4, 2),
        ];
        let mut out = Vec::new();
        let w = write_extents(&dev, bs, &mut extents, 12, &mut out).unwrap();
        assert_eq!(out, b"AAAA\0\0\0\0BBBB");
        assert_eq!(w.bytes, 12);
        assert_eq!(w.data_bytes, 8);
        assert!(w.holes >= 1);
        assert_eq!(w.missing, 0);
    }

    #[test]
    fn sparse_output_seeks_over_gaps_and_sets_trailing_length() {
        const BS: u32 = 4096;
        const FOUR_MIB: u64 = 4 * 1024 * 1024;
        const EIGHT_MIB: u64 = 8 * 1024 * 1024;
        const FILE_SIZE: u64 = 16 * 1024 * 1024;

        let mut data = vec![0u8; BS as usize * 3];
        data[BS as usize..BS as usize * 2].fill(b'A');
        data[BS as usize * 2..BS as usize * 3].fill(b'B');
        let dev = MemDevice { data };
        let mut extents = vec![
            extent(0, BS as u64, 1),
            extent(FOUR_MIB, FOUR_MIB, 0),
            extent(EIGHT_MIB, BS as u64, 2),
        ];
        let (_path, mut file) = TestPath::file("sparse-holes");

        let written = write_extents_sparse(&dev, BS, &mut extents, FILE_SIZE, &mut file).unwrap();

        assert_eq!(written.bytes, FILE_SIZE);
        assert_eq!(written.data_bytes, 2 * u64::from(BS));
        assert_eq!(written.holes, 3, "gap, explicit hole, and tail");
        assert_eq!(written.overlaps, 0);
        assert_eq!(written.missing, 0);
        let metadata = file.metadata().expect("sparse output metadata");
        assert_eq!(
            metadata.len(),
            FILE_SIZE,
            "set_len must retain the tail hole"
        );

        let mut sample = [0u8; 1];
        for (offset, expected) in [
            (0, b'A'),
            (2 * 1024 * 1024, 0),
            (6 * 1024 * 1024, 0),
            (EIGHT_MIB, b'B'),
            (FILE_SIZE - 1, 0),
        ] {
            file.seek(SeekFrom::Start(offset))
                .expect("seek test output");
            file.read_exact(&mut sample).expect("read test output");
            assert_eq!(sample[0], expected, "byte at logical offset {offset}");
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let allocated = metadata.blocks() * 512;
            assert!(
                allocated < FILE_SIZE / 4,
                "sparse output allocated {allocated} bytes for a {FILE_SIZE}-byte file"
            );
        }
    }

    #[test]
    fn explicit_hole_extent_zero_fills() {
        let bs = 4u32;
        let dev = MemDevice {
            data: b"WXYZ".to_vec(),
        };
        // phys_block_num 0 == hole.
        let mut extents = vec![extent(0, 4, 0)];
        let mut out = Vec::new();
        let w = write_extents(&dev, bs, &mut extents, 4, &mut out).unwrap();
        assert_eq!(out, b"\0\0\0\0");
        assert_eq!(w.bytes, 4);
        assert_eq!(w.data_bytes, 0);
    }

    #[test]
    fn stops_at_logical_size() {
        let bs = 4u32;
        let dev = MemDevice {
            data: b"ABCD".to_vec(),
        };
        // Extent maps 4 bytes from block 0, but the file size is only 2.
        let mut extents = vec![extent(0, 4, 0)];
        let mut out = Vec::new();
        let w = write_extents(&dev, bs, &mut extents, 2, &mut out).unwrap();
        assert_eq!(out, b"\0\0"); // block 0 is a hole (phys 0); truncated to 2
        assert_eq!(w.bytes, 2);
        assert_eq!(w.data_bytes, 0);
    }
}
