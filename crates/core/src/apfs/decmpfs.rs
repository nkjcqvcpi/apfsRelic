//! Apple `decmpfs` transparent-compression metadata and embedded-payload
//! decoding.
//!
//! The on-disk extended attribute starts with the 16-byte
//! `decmpfs_disk_header` documented by XNU. Types 1, 3, and 7 keep their
//! payload in that attribute. Types 4 and 8 keep a chunked payload in the
//! file's resource fork; callers can preserve those bytes and let the macOS
//! kernel validate and decode them when installing a recovered file.

use std::io::Write;

use super::raw;
use crate::error::{corrupt, unsupported, Error, ErrorKind, Result};

pub const DECMPFS_XATTR_NAME: &str = "com.apple.decmpfs";
pub const RESOURCE_FORK_XATTR_NAME: &str = "com.apple.ResourceFork";
pub const DECMPFS_MAGIC: u32 = 0x636d_7066;
pub const DECMPFS_HEADER_LEN: usize = 16;
pub const MAX_DECMPFS_XATTR_SIZE: usize = 3802;
pub const UF_COMPRESSED: u32 = 0x0000_0020;

pub const TYPE_UNCOMPRESSED_ATTR: u32 = 1;
pub const TYPE_ZLIB_ATTR: u32 = 3;
pub const TYPE_ZLIB_RSRC: u32 = 4;
pub const TYPE_LZVN_ATTR: u32 = 7;
pub const TYPE_LZVN_RSRC: u32 = 8;

const COMPRESSION_ZLIB: u32 = 0x205;
const COMPRESSION_LZFSE: u32 = 0x801;
const LZFSE_LZVN_BLOCK_MAGIC: u32 = 0x6e78_7662; // "bvxn"
const LZFSE_END_MAGIC: u32 = 0x2478_7662; // "bvx$"

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Storage {
    Embedded,
    ResourceFork,
    Kernel,
}

impl Storage {
    pub fn as_str(self) -> &'static str {
        match self {
            Storage::Embedded => "embedded",
            Storage::ResourceFork => "resource-fork",
            Storage::Kernel => "kernel",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub compression_type: u32,
    pub uncompressed_size: u64,
}

impl Header {
    pub fn storage(self) -> Storage {
        match self.compression_type {
            TYPE_UNCOMPRESSED_ATTR | TYPE_ZLIB_ATTR | TYPE_LZVN_ATTR => Storage::Embedded,
            TYPE_ZLIB_RSRC | TYPE_LZVN_RSRC => Storage::ResourceFork,
            _ => Storage::Kernel,
        }
    }

    pub fn codec(self) -> &'static str {
        match self.compression_type {
            TYPE_UNCOMPRESSED_ATTR => "none",
            TYPE_ZLIB_ATTR | TYPE_ZLIB_RSRC => "zlib",
            TYPE_LZVN_ATTR | TYPE_LZVN_RSRC => "lzvn",
            _ => "kernel",
        }
    }
}

/// Parse and validate the fixed `decmpfs_disk_header` from the raw xattr.
pub fn parse_header(data: &[u8]) -> Result<Header> {
    if data.len() < DECMPFS_HEADER_LEN {
        return Err(corrupt(format!(
            "decmpfs xattr is too short ({} < {DECMPFS_HEADER_LEN})",
            data.len()
        )));
    }
    if data.len() > MAX_DECMPFS_XATTR_SIZE {
        return Err(corrupt(format!(
            "decmpfs xattr is too large ({} > {MAX_DECMPFS_XATTR_SIZE})",
            data.len()
        )));
    }
    let magic = raw::u32_at(data, 0)?;
    if magic != DECMPFS_MAGIC {
        return Err(corrupt(format!(
            "invalid decmpfs magic {magic:#010x} (expected {DECMPFS_MAGIC:#010x})"
        )));
    }
    Ok(Header {
        compression_type: raw::u32_at(data, 4)?,
        uncompressed_size: raw::u64_at(data, 8)?,
    })
}

/// Decode an embedded type 1, 3, or 7 payload and write it only after all
/// structural, stream, output-length, and checksum checks have passed.
pub fn write_embedded(data: &[u8], writer: &mut dyn Write) -> Result<u64> {
    let header = parse_header(data)?;
    if header.storage() != Storage::Embedded {
        return Err(unsupported(format!(
            "decmpfs type {} is not an embedded compression type",
            header.compression_type
        )));
    }
    let payload = &data[DECMPFS_HEADER_LEN..];
    let decoded = match header.compression_type {
        TYPE_UNCOMPRESSED_ATTR => exact_raw(payload, header.uncompressed_size, None)?,
        TYPE_ZLIB_ATTR if payload.first().is_some_and(|byte| byte & 0x0f == 0x0f) => exact_raw(
            &payload[1..],
            header.uncompressed_size,
            Some("zlib raw marker"),
        )?,
        TYPE_ZLIB_ATTR => decode_zlib(payload, header.uncompressed_size)?,
        TYPE_LZVN_ATTR if payload.first() == Some(&0x06) => exact_raw(
            &payload[1..],
            header.uncompressed_size,
            Some("LZVN raw marker"),
        )?,
        TYPE_LZVN_ATTR => decode_lzvn(payload, header.uncompressed_size)?,
        _ => unreachable!("storage check limits this match to embedded types"),
    };
    writer.write_all(&decoded)?;
    Ok(decoded.len() as u64)
}

fn exact_raw(payload: &[u8], expected: u64, description: Option<&str>) -> Result<Vec<u8>> {
    let actual = payload.len() as u64;
    if actual != expected {
        let what = description.unwrap_or("type 1 payload");
        return Err(corrupt(format!(
            "decmpfs {what} length {actual} does not match uncompressed size {expected}"
        )));
    }
    Ok(payload.to_vec())
}

fn decode_zlib(payload: &[u8], expected: u64) -> Result<Vec<u8>> {
    // AppleFSCompression stores an RFC 1950 zlib stream. The public Compression
    // buffer API consumes its raw RFC 1951 DEFLATE payload, so validate and
    // remove the two-byte header and four-byte Adler-32 trailer first.
    if payload.len() < 6 {
        return Err(corrupt("decmpfs zlib payload is shorter than its wrapper"));
    }
    let cmf = payload[0];
    let flg = payload[1];
    if cmf & 0x0f != 8 || cmf >> 4 > 7 || (u16::from(cmf) << 8 | u16::from(flg)) % 31 != 0 {
        return Err(corrupt("invalid decmpfs zlib header"));
    }
    if flg & 0x20 != 0 {
        return Err(unsupported(
            "decmpfs zlib preset dictionaries are not supported",
        ));
    }
    let trailer = payload.len() - 4;
    let expected_adler = u32::from_be_bytes(payload[trailer..].try_into().expect("four bytes"));
    let decoded = decode_with_compression(&payload[2..trailer], expected, COMPRESSION_ZLIB)?;
    let actual_adler = adler32(&decoded);
    if actual_adler != expected_adler {
        return Err(corrupt(format!(
            "decmpfs zlib Adler-32 mismatch ({actual_adler:#010x} != {expected_adler:#010x})"
        )));
    }
    Ok(decoded)
}

fn decode_lzvn(payload: &[u8], expected: u64) -> Result<Vec<u8>> {
    let raw_size = u32::try_from(expected)
        .map_err(|_| corrupt("decmpfs LZVN uncompressed size exceeds 32-bit block format"))?;
    let payload_size = u32::try_from(payload.len())
        .map_err(|_| corrupt("decmpfs LZVN payload exceeds 32-bit block format"))?;
    let capacity = payload
        .len()
        .checked_add(16)
        .ok_or_else(|| corrupt("decmpfs LZVN wrapper size overflow"))?;
    let mut framed = Vec::new();
    framed
        .try_reserve_exact(capacity)
        .map_err(|_| Error::new(ErrorKind::Io, "cannot allocate decmpfs LZVN wrapper"))?;
    framed.extend_from_slice(&LZFSE_LZVN_BLOCK_MAGIC.to_le_bytes());
    framed.extend_from_slice(&raw_size.to_le_bytes());
    framed.extend_from_slice(&payload_size.to_le_bytes());
    framed.extend_from_slice(payload);
    framed.extend_from_slice(&LZFSE_END_MAGIC.to_le_bytes());
    decode_with_compression(&framed, expected, COMPRESSION_LZFSE)
}

fn adler32(data: &[u8]) -> u32 {
    const MOD_ADLER: u32 = 65_521;
    let mut a = 1u32;
    let mut b = 0u32;
    for chunk in data.chunks(5_552) {
        for byte in chunk {
            a += u32::from(*byte);
            b += a;
        }
        a %= MOD_ADLER;
        b %= MOD_ADLER;
    }
    b << 16 | a
}

#[cfg(target_os = "macos")]
fn decode_with_compression(source: &[u8], expected: u64, algorithm: u32) -> Result<Vec<u8>> {
    use std::ffi::c_void;
    use std::ptr;

    #[link(name = "compression")]
    extern "C" {
        fn compression_decode_buffer(
            dst_buffer: *mut u8,
            dst_size: usize,
            src_buffer: *const u8,
            src_size: usize,
            scratch_buffer: *mut c_void,
            algorithm: u32,
        ) -> usize;
    }

    let expected = usize::try_from(expected)
        .map_err(|_| corrupt("decmpfs uncompressed size does not fit this platform"))?;
    // An extra byte makes a stream that expands past the declared logical size
    // observable instead of accepting a truncated prefix as success.
    let capacity = expected
        .checked_add(1)
        .ok_or_else(|| corrupt("decmpfs output size overflow"))?;
    let mut output = Vec::new();
    output.try_reserve_exact(capacity).map_err(|_| {
        Error::new(
            ErrorKind::Io,
            format!("cannot allocate {capacity} bytes for decmpfs output"),
        )
    })?;
    output.resize(capacity, 0);
    // SAFETY: both vectors remain allocated for the call, their pointer/length
    // pairs are valid, and a null scratch pointer asks the framework to manage
    // its own decoder workspace.
    let decoded = unsafe {
        compression_decode_buffer(
            output.as_mut_ptr(),
            output.len(),
            source.as_ptr(),
            source.len(),
            ptr::null_mut(),
            algorithm,
        )
    };
    if decoded != expected {
        return Err(corrupt(format!(
            "decmpfs stream decoded to {decoded} bytes, expected {expected}"
        )));
    }
    output.truncate(decoded);
    Ok(output)
}

#[cfg(not(target_os = "macos"))]
fn decode_with_compression(_source: &[u8], _expected: u64, algorithm: u32) -> Result<Vec<u8>> {
    Err(unsupported(format!(
        "decmpfs algorithm {algorithm:#x} requires the macOS Compression framework"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xattr(compression_type: u32, size: u64, payload: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&DECMPFS_MAGIC.to_le_bytes());
        data.extend_from_slice(&compression_type.to_le_bytes());
        data.extend_from_slice(&size.to_le_bytes());
        data.extend_from_slice(payload);
        data
    }

    #[test]
    fn type1_is_copied_exactly() {
        let data = xattr(TYPE_UNCOMPRESSED_ATTR, 5, b"hello");
        let mut out = Vec::new();
        assert_eq!(write_embedded(&data, &mut out).unwrap(), 5);
        assert_eq!(out, b"hello");
    }

    #[test]
    fn raw_markers_are_removed_and_length_checked() {
        for (compression_type, marker) in [(TYPE_ZLIB_ATTR, 0xff), (TYPE_LZVN_ATTR, 0x06)] {
            let data = xattr(compression_type, 5, &[marker, b'h', b'e', b'l', b'l', b'o']);
            let mut out = Vec::new();
            write_embedded(&data, &mut out).unwrap();
            assert_eq!(out, b"hello");
        }

        let data = xattr(TYPE_LZVN_ATTR, 6, b"\x06hello");
        let error = write_embedded(&data, &mut Vec::new()).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Corrupt);
    }

    #[test]
    fn rejects_short_bad_magic_and_wrong_type1_length() {
        assert_eq!(
            parse_header(&[0u8; 15]).unwrap_err().kind(),
            ErrorKind::Corrupt
        );
        let mut bad_magic = xattr(TYPE_UNCOMPRESSED_ATTR, 0, b"");
        bad_magic[0] ^= 0xff;
        assert_eq!(
            parse_header(&bad_magic).unwrap_err().kind(),
            ErrorKind::Corrupt
        );
        let wrong_length = xattr(TYPE_UNCOMPRESSED_ATTR, 6, b"hello");
        assert_eq!(
            write_embedded(&wrong_length, &mut Vec::new())
                .unwrap_err()
                .kind(),
            ErrorKind::Corrupt
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn decodes_real_zlib_and_bare_lzvn_streams() {
        // RFC 1950 zlib stream for "hello" (including Adler-32 trailer).
        let zlib = xattr(
            TYPE_ZLIB_ATTR,
            5,
            &[
                0x78, 0x9c, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0x06, 0x2c, 0x02, 0x15,
            ],
        );
        let mut zlib_out = Vec::new();
        write_embedded(&zlib, &mut zlib_out).unwrap();
        assert_eq!(zlib_out, b"hello");

        // Bare LZVN produced on macOS by stripping the 12-byte `bvxn` header
        // and trailing `bvx$` word from a Compression-framework LZFSE stream.
        let lzvn_payload = [
            0x68, 0x01, 0x41, 0xf0, 0xe5, 0xe1, 0x41, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00,
        ];
        let lzvn = xattr(TYPE_LZVN_ATTR, 255, &lzvn_payload);
        let mut lzvn_out = Vec::new();
        write_embedded(&lzvn, &mut lzvn_out).unwrap();
        assert_eq!(lzvn_out, vec![b'A'; 255]);
    }
}
