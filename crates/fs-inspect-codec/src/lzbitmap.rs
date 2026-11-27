//! LZBITMAP (APFS `decmpfs` types 13 and 14: one stream per block or 64 KiB chunk).
//!
//! A stream is `ZBM`, a flags byte, then chunks. Flags: bit 3 always set; bit 2: the tokens
//! are not run-length coded; bits 0–1: the largest decoded chunk, 0 = 16 KiB, 1 = 32 KiB
//! (2 and 3 are invalid). macOS writes `0x09`.
//!
//! Each chunk starts with its length (this header included) and its decoded length, u24 LE
//! each. Length = decoded length + 6: the chunk's bytes are stored as they are; decoded length
//! 0 (a stored chunk of nothing) ends the stream. Otherwise three more u24 offsets from the
//! chunk's start split it into areas:
//!
//! | bytes | holds |
//! |---|---|
//! | 15 .. `off1` | literals |
//! | `off1` .. `off2` | match distances (1 or 2 bytes LE each) |
//! | `off2` .. `off3` | bitmaps given in full |
//! | `off3` .. len − 17 | tokens, one nibble each (low nibble first) |
//! | the last 17 | the token table: 10-bit entries for tokens 3, 4, ...: an 8-bit bitmap, then how many distance bytes follow (0–2; 3 is invalid) |
//!
//! Every 8 output bytes take one token: 0–2 take the next full bitmap and that many distance
//! bytes; 3 and up take a table entry (12 of them, tokens 3–14; 13 when tokens are not
//! run-length coded, 3–15). A distance, when given, replaces the current one (8 at each
//! chunk's start). The bitmap's bit `k` (from the lowest) set: output byte `k` is the next
//! literal; clear: it is the byte that distance back (anywhere in the stream's output, which
//! earlier chunks are part of). Unless all 8 bytes are literals, the distance is at least 8
//! (macOS's encoder writes no shorter one, and its decoder reads shorter ones in ways that
//! depend on the tokens around them, so they are damage here) and reaches no further back
//! than the output's start.
//!
//! Run-length coded tokens: a nibble `0xF` after a token repeats that token, `4 + n1 + n2 + ...`
//! times in all, `n1, n2, ...` the nibbles that follow, as long as they are `0xF` (the first
//! one that is not ends the run and is not a token). Not run-length coded, the nibbles are at
//! least the chunk's tokens rounded up to a multiple of 8.
//!
//! As macOS's decoder: decoding stops when the output is full (no end chunk needed then) or at
//! the end chunk, and what follows is not looked at. A chunk decoded in full has used up its
//! literals and distances exactly.

use crate::bad;
use fs_inspect_core::Result;

const W: &str = "lzbitmap stream";
const HEADER: usize = 15;
const TABLE: usize = 17;

fn u24(b: &[u8], at: usize) -> usize {
    usize::from(b[at]) | usize::from(b[at + 1]) << 8 | usize::from(b[at + 2]) << 16
}

/// Decompress the LZBITMAP stream `src` into `out`: the bytes produced, `out.len()` unless the
/// stream ends first (at its end chunk). An error when it is damaged or cut short.
pub fn decompress(src: &[u8], out: &mut [u8]) -> Result<usize> {
    let flags = match src {
        [b'Z', b'B', b'M', f, ..] => *f,
        _ => return Err(bad(W, "no ZBM magic")),
    };
    if flags > 0x0F || flags & 8 == 0 || flags & 3 >= 2 {
        return Err(bad(W, format!("flags {flags:#04x}")));
    }
    let chunk_max = if flags & 3 == 1 { 0x8000 } else { 0x4000 };
    let rle = flags & 4 == 0;
    let (mut s, mut at) = (4usize, 0usize);
    while at < out.len() {
        let head = src.get(s..s + 6).ok_or_else(|| bad(W, "ends before the end chunk"))?;
        let (len, decoded) = (u24(head, 0), u24(head, 3));
        if decoded > chunk_max || len > decoded + 6 {
            return Err(bad(W, format!("chunk at {s}: length {len}, decoded {decoded}")));
        }
        let chunk = src.get(s..s + len).ok_or_else(|| bad(W, format!("chunk at {s} cut short")))?;
        let want = decoded.min(out.len() - at);
        if len == decoded + 6 {
            if decoded == 0 {
                return Ok(at);
            }
            out[at..at + want].copy_from_slice(&chunk[6..6 + want]);
        } else {
            compressed(chunk, rle, want, want == decoded, out, at).map_err(|e| e.context(format!("chunk at {s}")))?;
        }
        at += want;
        s += len;
    }
    Ok(at)
}

/// Decode `want` bytes of the compressed chunk `c` to `out[at..]`; `whole`: the chunk's whole
/// output (its areas must then be used up).
fn compressed(c: &[u8], rle: bool, want: usize, whole: bool, out: &mut [u8], at: usize) -> Result<()> {
    if c.len() < HEADER + 1 + TABLE {
        return Err(bad(W, format!("compressed chunk of {} bytes", c.len())));
    }
    let (off1, off2, off3, end) = (u24(c, 6), u24(c, 9), u24(c, 12), c.len() - TABLE);
    if !(HEADER <= off1 && off1 <= off2 && off2 <= off3 && off3 <= end) {
        return Err(bad(W, format!("areas at {off1}, {off2}, {off3} of {}", c.len())));
    }
    let mut table = [(0u8, 0u8); 13];
    for (i, e) in table.iter_mut().enumerate().take(if rle { 12 } else { 13 }) {
        let (byte, shift) = (end + 10 * i / 8, 10 * i % 8);
        let v = (usize::from(c[byte]) | usize::from(c[byte + 1]) << 8) >> shift & 0x3FF;
        if v >> 8 == 3 {
            return Err(bad(W, format!("token {} takes 3 distance bytes", i + 3)));
        }
        *e = ((v & 0xFF) as u8, (v >> 8) as u8);
    }
    let groups = want.div_ceil(8);
    let tokens = tokens(&c[off3..end], rle, groups)?;
    let (mut lit, mut dp, mut bp, mut dist) = (HEADER, off1, off2, 8usize);
    let mut pos = at;
    let stop = at + want;
    for &t in &tokens[..groups] {
        let (bitmap, n) = if t < 3 {
            let b = *c[..off3].get(bp).ok_or_else(|| bad(W, "runs out of bitmaps"))?;
            bp += 1;
            (b, t)
        } else {
            table[usize::from(t) - 3]
        };
        if n > 0 {
            let d = c[..off2].get(dp..dp + usize::from(n)).ok_or_else(|| bad(W, "runs out of distances"))?;
            dist = usize::from(d[0]) | if n == 2 { usize::from(d[1]) << 8 } else { 0 };
            dp += usize::from(n);
        }
        if bitmap != 0xFF && !(8..=pos).contains(&dist) {
            return Err(bad(W, format!("match distance {dist} at output offset {pos}")));
        }
        for k in 0..8.min(stop - pos) {
            out[pos] = if bitmap >> k & 1 == 1 {
                let b = *c[..off1].get(lit).ok_or_else(|| bad(W, "runs out of literals"))?;
                lit += 1;
                b
            } else {
                out[pos - dist]
            };
            pos += 1;
        }
    }
    if whole && (lit != off1 || dp != off2) {
        return Err(bad(W, "literals or distances left over"));
    }
    Ok(())
}

/// The first `groups` tokens of nibbles `b` (at least that many: a run may give more).
fn tokens(b: &[u8], rle: bool, groups: usize) -> Result<Vec<u8>> {
    if !rle && 2 * b.len() < groups.next_multiple_of(8) {
        return Err(bad(W, format!("{} bytes of tokens for {groups}", b.len())));
    }
    let mut nib = b.iter().flat_map(|&x| [x & 0xF, x >> 4]);
    let mut out = Vec::with_capacity(groups + 16);
    let short = || bad(W, "runs out of tokens");
    while out.len() < groups {
        let t = nib.next().ok_or_else(short)?;
        if !rle || t != 0xF {
            out.push(t);
            continue;
        }
        let &prev = out.last().ok_or_else(|| bad(W, "a token run before any token"))?;
        let mut n = 3;
        loop {
            let k = nib.next().ok_or_else(short)?;
            n += usize::from(k);
            if k != 0xF {
                break;
            }
        }
        out.extend(std::iter::repeat_n(prev, n.min(groups - out.len())));
    }
    Ok(out)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn le24(n: usize) -> [u8; 3] {
        [n as u8, (n >> 8) as u8, (n >> 16) as u8]
    }

    /// A stream (flags `flags`) of one compressed chunk decoding to `n` bytes, then the end.
    fn chunk(flags: u8, n: usize, lits: &[u8], dists: &[u8], bms: &[u8], toks: &[u8], table: &[(u8, u8)]) -> Vec<u8> {
        let mut nib = toks.to_vec();
        nib.resize(nib.len().next_multiple_of(2), 0);
        let nb: Vec<u8> = nib.chunks(2).map(|p| p[0] | p[1] << 4).collect();
        let mut bits = 0u128;
        for (i, &(bm, c)) in table.iter().enumerate() {
            bits |= u128::from(u16::from(bm) | u16::from(c) << 8) << (10 * i);
        }
        let mut tab = [0u8; TABLE];
        tab[..16].copy_from_slice(&bits.to_le_bytes());
        let off1 = HEADER + lits.len();
        let off2 = off1 + dists.len();
        let off3 = off2 + bms.len();
        let len = off3 + nb.len() + TABLE;
        let mut s = b"ZBM".to_vec();
        s.push(flags);
        for x in [len, n, off1, off2, off3] {
            s.extend(le24(x));
        }
        for part in [lits, dists, bms, &nb, &tab] {
            s.extend(part);
        }
        s.extend(le24(6));
        s.extend(le24(0));
        s
    }

    /// 8 literals, a group copying `dist` back, then `rest` tokens 3 (table entry: all match).
    fn with_distance(dist: u8, rest: usize) -> Vec<u8> {
        let mut toks = vec![0, 1];
        toks.extend(std::iter::repeat_n(3, rest));
        chunk(0x0D, 8 * toks.len(), b"ABCDEFGH", &[dist], &[0xFF, 0x00], &toks, &[(0x00, 0)])
    }

    #[test]
    fn hand_built() {
        let mut out = vec![0u8; 64];
        assert_eq!(decompress(&with_distance(8, 6), &mut out).unwrap(), 64);
        assert_eq!(out, b"ABCDEFGH".repeat(8));
        // Shorter than 8, or before the start: damage.
        assert!(decompress(&with_distance(7, 6), &mut out).is_err());
        assert!(decompress(&with_distance(9, 6), &mut out).is_err());
        // Not run-length coded: the tokens padded to a multiple of 8.
        assert!(decompress(&with_distance(8, 1), &mut [0u8; 24]).is_err());
        // Run-length coded: token 3, then 0xF 0x2: 4 + 2 of them in all.
        let s = chunk(0x09, 64, b"ABCDEFGH", &[8], &[0xFF, 0x00], &[0, 1, 3, 0xF, 2], &[(0x00, 0)]);
        assert_eq!(decompress(&s, &mut out).unwrap(), 64);
        assert_eq!(out, b"ABCDEFGH".repeat(8));
        // A literal left over in a chunk decoded in full.
        let s = chunk(0x0D, 8, b"ABCDEFGHI", b"", &[0xFF], &[0; 8], &[]);
        assert!(decompress(&s, &mut out[..8]).is_err());
        // A table entry taking 3 distance bytes.
        let s = chunk(0x0D, 8, b"ABCDEFGH", b"", &[], &[3; 8], &[(0xFF, 3)]);
        assert!(decompress(&s, &mut out[..8]).is_err());
    }

    #[test]
    fn framing() {
        let mut out = [0u8; 8];
        // A stored chunk, then the end before the output is full.
        let mut s = b"ZBM\x09".to_vec();
        s.extend(le24(9));
        s.extend(le24(3));
        s.extend(b"xyz");
        s.extend(le24(6));
        s.extend(le24(0));
        assert_eq!(decompress(&s, &mut out).unwrap(), 3);
        assert_eq!(&out[..3], b"xyz");
        // Full after the stored chunk: what follows is not looked at.
        assert_eq!(decompress(&s[..13], &mut out[..3]).unwrap(), 3);
        // Not full and no end chunk.
        assert!(decompress(&s[..13], &mut out).is_err());
        for flags in [0x01, 0x0A, 0x0B, 0x19] {
            s[3] = flags;
            assert!(decompress(&s, &mut out).is_err(), "{flags:#x}");
        }
        assert!(decompress(b"ZBX\x09", &mut out).is_err());
    }

    fn err(s: &[u8], n: usize) -> String {
        decompress(s, &mut vec![0u8; n]).unwrap_err().to_string()
    }

    /// Each way a compressed chunk can be damaged is an error saying which.
    #[test]
    fn damaged_chunks() {
        // Shorter than its header and table.
        let mut s = b"ZBM\x0D".to_vec();
        s.extend(le24(10));
        s.extend(le24(8));
        s.extend([0u8; 4]);
        assert!(err(&s, 8).contains("compressed chunk of 10 bytes"));
        // Decoding to more than a chunk holds.
        let mut s = b"ZBM\x0D".to_vec();
        s.extend(le24(40));
        s.extend(le24(0x9000));
        assert!(err(&s, 8).contains("decoded 36864"));
        // Areas out of order (each chunk below says it decodes to 64 bytes, of which 8 are
        // asked for).
        let mut s = chunk(0x0D, 64, b"ABCDEFGH", b"", &[0xFF], &[0; 8], &[]);
        s[10..13].copy_from_slice(&le24(3));
        assert!(err(&s, 8).contains("areas at 3"));
        // Too few literals, bitmaps or distances.
        assert!(err(&chunk(0x0D, 64, b"ABC", b"", &[0xFF], &[0; 8], &[]), 8).contains("runs out of literals"));
        assert!(err(&chunk(0x0D, 64, b"ABCDEFGH", b"", &[], &[0; 8], &[]), 8).contains("runs out of bitmaps"));
        let toks = [1, 0, 0, 0, 0, 0, 0, 0];
        assert!(err(&chunk(0x0D, 64, b"ABCDEFGH", b"", &[0xFF], &toks, &[]), 8).contains("runs out of distances"));
        // Run-length coded tokens: none at all, or a run first.
        assert!(err(&chunk(0x09, 64, b"ABCDEFGH", b"", &[0xFF], &[], &[]), 8).contains("runs out of tokens"));
        assert!(err(&chunk(0x09, 64, b"ABCDEFGH", b"", &[0xFF], &[0xF, 0], &[]), 8).contains("before any token"));
        // Not run-length coded: fewer than 8 tokens per 8 groups.
        assert!(err(&chunk(0x0D, 64, b"ABCDEFGH", b"", &[0xFF], &[0; 2], &[]), 8).contains("bytes of tokens for 1"));
    }
}
