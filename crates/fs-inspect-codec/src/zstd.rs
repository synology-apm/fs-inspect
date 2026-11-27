//! zstd frames (ZFS `zstd`, btrfs `zstd`).

use ::zstd::zstd_safe::{DCtx, InBuffer, OutBuffer, ResetDirective, get_error_name};

use crate::bad;
use crate::kept::Kept;
use fs_inspect_core::Result;

/// Decoders reset between frames ([`crate::kept`]).
static DECODERS: Kept<DCtx<'static>> = Kept::new();

/// `f` with a decoder, at the start of a frame.
fn with_decoder<T>(f: impl FnOnce(&mut DCtx<'static>) -> Result<T>) -> Result<T> {
    DECODERS.with(DCtx::create, |d| {
        // What a frame left half read (an error, or a prefix) is dropped here.
        d.reset(ResetDirective::SessionOnly).map_err(|c| bad("zstd", get_error_name(c)))?;
        f(d)
    })
}

/// The zstd frame magic number.
pub const MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];

/// Decompress the zstd frame at the start of `src` (bytes after it ignored: btrfs pads its
/// extents to whole sectors) into `out`; the bytes produced (an error when the frame holds
/// more than `out`).
pub fn decompress(src: &[u8], out: &mut [u8]) -> Result<usize> {
    let n = ::zstd::zstd_safe::find_frame_compressed_size(src).map_err(|_| bad("zstd frame", "no complete frame"))?;
    with_decoder(|d| d.decompress(out, &src[..n]).map_err(|c| bad("zstd frame", get_error_name(c))))
}

/// Decompress the first `out.len()` bytes of the zstd frame at the start of `src` into `out`
/// and stop there, as btrfs reads an extent (a 6-byte inline extent can hold a frame of a whole
/// page): the bytes produced, fewer than `out.len()` when the frame ends first; an error when
/// `src` ends before either.
pub fn decompress_prefix(src: &[u8], out: &mut [u8]) -> Result<usize> {
    with_decoder(|d| {
        let mut input = InBuffer::around(src);
        let mut output = OutBuffer::around(out);
        while output.pos() < output.capacity() {
            let before = (input.pos(), output.pos());
            let r = d.decompress_stream(&mut output, &mut input).map_err(|c| bad("zstd frame", get_error_name(c)))?;
            if r == 0 {
                break;
            }
            if (input.pos(), output.pos()) == before {
                return Err(bad("zstd frame", "truncated"));
            }
        }
        Ok(output.pos())
    })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_corrupt() {
        let data: Vec<u8> = b"zstd frame ".iter().cycle().take(5000).copied().collect();
        let z = ::zstd::bulk::compress(&data, 3).unwrap();
        let mut out = vec![0; data.len()];
        assert_eq!(decompress(&z, &mut out).unwrap(), data.len());
        assert_eq!(out, data);
        assert!(decompress(&z, &mut out[..10]).is_err());
        let mut padded = z.clone();
        padded.resize(z.len() + 300, 0);
        assert_eq!(decompress(&padded, &mut out).unwrap(), data.len());
        assert!(decompress(&z[4..], &mut out).is_err());
    }

    #[test]
    fn prefix_stops_when_full() {
        let data: Vec<u8> = (0..20_000u32).map(|i| (i * 7 % 251) as u8).collect();
        let z = ::zstd::bulk::compress(&data, 3).unwrap();
        let mut out = vec![0; 6];
        assert_eq!(decompress_prefix(&z, &mut out).unwrap(), 6);
        assert_eq!(out, data[..6]);
        let mut all = vec![0; data.len() + 100];
        assert_eq!(decompress_prefix(&z, &mut all).unwrap(), data.len());
        assert_eq!(all[..data.len()], data[..]);
        assert!(decompress_prefix(&z[..z.len() / 2], &mut all).is_err());
        assert!(decompress_prefix(&z[4..], &mut out).is_err());
    }
}
