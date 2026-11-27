//! zlib streams (ZFS `gzip-N`, btrfs `zlib`, APFS `decmpfs` zlib) and raw deflate.

use flate2::Decompress;

use crate::bad;
use crate::kept::Kept;
use fs_inspect_core::Result;

/// Inflaters reset between streams ([`crate::kept`]): making one per stream (its window and
/// tables, tens of KiB) for every compressed extent read would churn the heap.
static INFLATERS: Kept<Decompress> = Kept::new();

/// `f` with an inflater, at the start of a stream (`zlib_header`: a zlib stream, not raw
/// deflate).
fn with_inflater<T>(zlib_header: bool, f: impl FnOnce(&mut Decompress) -> T) -> T {
    INFLATERS.with(
        || Decompress::new(zlib_header),
        |d| {
            d.reset(zlib_header);
            f(d)
        },
    )
}

/// Decompress the zlib stream `src` (trailing bytes after its end ignored) into `out`; the
/// bytes produced (an error when the stream does not end within `src` and `out`).
pub fn decompress(src: &[u8], out: &mut [u8]) -> Result<usize> {
    inflate(src, out, true, "zlib stream")
}

/// Decompress the first `out.len()` bytes of the zlib stream `src` into `out` and stop there,
/// as btrfs reads an extent: the bytes produced, fewer when the stream ends first; an error
/// when `src` ends before either.
pub fn decompress_prefix(src: &[u8], out: &mut [u8]) -> Result<usize> {
    let (r, n) = with_inflater(true, |d| {
        let r = d.decompress(src, out, flate2::FlushDecompress::Finish);
        (r, usize::try_from(d.total_out()).unwrap_or(out.len()))
    });
    match r {
        Ok(flate2::Status::StreamEnd) => Ok(n),
        Ok(_) if n == out.len() => Ok(n),
        Ok(s) => Err(bad("zlib stream", format!("{s:?} after {n} bytes"))),
        Err(e) => Err(bad("zlib stream", e.to_string())),
    }
}

/// Decompress the raw deflate stream `src` into `out`, as [`decompress`].
pub fn inflate_raw(src: &[u8], out: &mut [u8]) -> Result<usize> {
    inflate(src, out, false, "deflate stream")
}

fn inflate(src: &[u8], out: &mut [u8], zlib_header: bool, what: &'static str) -> Result<usize> {
    with_inflater(zlib_header, |d| match d.decompress(src, out, flate2::FlushDecompress::Finish) {
        Ok(flate2::Status::StreamEnd) => Ok(usize::try_from(d.total_out()).unwrap_or(out.len())),
        Ok(s) => Err(bad(what, format!("{s:?} after {} bytes", d.total_out()))),
        Err(e) => Err(bad(what, e.to_string())),
    })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn zlib_and_raw() {
        let data: Vec<u8> = b"zlib stream ".iter().cycle().take(5000).copied().collect();
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        e.write_all(&data).unwrap();
        let mut z = e.finish().unwrap();
        z.resize(z.len().next_multiple_of(512), 0);
        let mut out = vec![0; data.len()];
        assert_eq!(decompress(&z, &mut out).unwrap(), data.len());
        assert_eq!(out, data);
        assert!(decompress(&z, &mut out[..100]).is_err());
        assert!(decompress(&z[..20], &mut out).is_err());

        let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::fast());
        e.write_all(&data).unwrap();
        let r = e.finish().unwrap();
        assert_eq!(inflate_raw(&r, &mut out).unwrap(), data.len());
        assert_eq!(out, data);
    }

    /// A prefix stops when the output is full, takes a stream that ends first, and fails on
    /// input that ends before either or is not zlib.
    #[test]
    fn prefixes() {
        let data: Vec<u8> = (0..5000u32).map(|i| (i * 31 % 251) as u8).collect();
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(&data).unwrap();
        let z = e.finish().unwrap();
        let mut out = vec![0u8; 100];
        assert_eq!(decompress_prefix(&z, &mut out).unwrap(), 100);
        assert_eq!(out, data[..100]);
        let mut out = vec![0u8; 8000];
        assert_eq!(decompress_prefix(&z, &mut out).unwrap(), 5000, "the stream ends first");
        assert_eq!(out[..5000], data);
        let e = decompress_prefix(&z[..z.len() / 2], &mut out).unwrap_err();
        assert_eq!(e.kind(), fs_inspect_core::ErrorKind::Corrupt, "{e}");
        assert!(decompress_prefix(b"not zlib at all", &mut out).is_err());
    }
}
