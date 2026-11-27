//! XPRESS ([MS-XCA]): plain LZ77 (2.4) and LZ77 + Huffman (2.2), the latter what WOF's
//! XPRESS4K / 8K / 16K compress each chunk of a file with.
//!
//! **Plain**: 32-bit little-endian flag words, read from the most significant bit: a 0 bit is
//! a literal byte, a 1 bit a 16-bit match (distance minus 1 in the top 13 bits, length minus 3
//! in the low 3; 7 continues the length in a shared half byte, then a byte, then 16 and 32
//! bits). A match flag with no input left ends the stream.
//!
//! **Huffman**: blocks of up to 64 KiB of output, each starting with 256 bytes of 4-bit code
//! lengths for 512 symbols (symbol `2i` in the low half of byte `i`), then a bit stream read
//! 16 bits (little-endian) at a time, most significant bit first. Symbols below 256 are
//! literals; the others hold the length (low 4 bits, minus 3; 15 continues in a byte of the
//! input, then 16 and 32 bits) and how many extra bits the distance has (high 4 bits). A match
//! may run past the block's end; the next block starts where the output is.

use crate::{bad, copy_match};
use fs_inspect_core::Result;

/// Decompress plain LZ77 `src` into `out`; the bytes produced.
pub fn decompress_plain(src: &[u8], out: &mut [u8]) -> Result<usize> {
    const W: &str = "xpress stream";
    let mut s = 0usize;
    let mut at = 0usize;
    let mut flags = 0u32;
    let mut nflags = 0u32;
    // Where a half byte of a length is waiting for its other half.
    let mut half: Option<usize> = None;
    let byte = |s: &mut usize| -> Result<usize> {
        let b = *src.get(*s).ok_or_else(|| bad(W, "ends in a match length"))?;
        *s += 1;
        Ok(usize::from(b))
    };
    while at < out.len() {
        if nflags == 0 {
            let Some(w) = src.get(s..s + 4) else { break };
            flags = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
            s += 4;
            nflags = 32;
        }
        nflags -= 1;
        if flags & (1 << nflags) == 0 {
            let Some(&b) = src.get(s) else { break };
            out[at] = b;
            at += 1;
            s += 1;
            continue;
        }
        if s >= src.len() {
            break;
        }
        let m = src.get(s..s + 2).ok_or_else(|| bad(W, "ends in a match"))?;
        let m = usize::from(u16::from_le_bytes([m[0], m[1]]));
        s += 2;
        let dist = (m >> 3) + 1;
        let mut len = m & 7;
        if len == 7 {
            len = match half.take() {
                None => {
                    let b = *src.get(s).ok_or_else(|| bad(W, "ends in a match length"))?;
                    half = Some(s);
                    s += 1;
                    usize::from(b & 15)
                }
                Some(h) => usize::from(src[h] >> 4),
            };
            if len == 15 {
                len = byte(&mut s)?;
                if len == 255 {
                    len = byte(&mut s)? | (byte(&mut s)? << 8);
                    if len == 0 {
                        len = byte(&mut s)? | (byte(&mut s)? << 8) | (byte(&mut s)? << 16) | (byte(&mut s)? << 24);
                    }
                    len = len.checked_sub(15 + 7).ok_or_else(|| bad(W, format!("match length {len}")))?;
                }
                len += 15;
            }
            len += 7;
        }
        copy_match(out, &mut at, dist, len + 3, W)?;
    }
    Ok(at)
}

/// Longest Huffman code.
const MAX_LEN: u32 = 15;

/// Bits of the direct lookup: a block's table is built for every block (each WOF chunk is one),
/// so it is kept small; longer codes are found by length.
const FAST: u32 = 10;

/// A canonical Huffman decoding table: each `FAST`-bit prefix's symbol and code length (length
/// 0 when the code is longer), and per length the first code and where its symbols start in
/// `sorted` (the symbols by length, then value).
struct Table {
    fast: [(u16, u8); 1 << FAST],
    count: [u16; MAX_LEN as usize + 1],
    first_code: [u32; MAX_LEN as usize + 1],
    first_index: [u16; MAX_LEN as usize + 1],
    sorted: [u16; 512],
}

impl Table {
    fn new(lengths: &[u8; 512]) -> Result<Table> {
        let mut t = Table {
            fast: [(0, 0); 1 << FAST],
            count: [0; MAX_LEN as usize + 1],
            first_code: [0; MAX_LEN as usize + 1],
            first_index: [0; MAX_LEN as usize + 1],
            sorted: [0; 512],
        };
        for &l in lengths {
            t.count[usize::from(l)] += 1;
        }
        t.count[0] = 0;
        if t.count.iter().all(|&c| c == 0) {
            return Err(bad("xpress huffman table", "no symbols"));
        }
        let (mut code, mut index) = (0u32, 0u16);
        for len in 1..=MAX_LEN as usize {
            if code + u32::from(t.count[len]) > 1 << len {
                return Err(bad("xpress huffman table", "code lengths oversubscribed"));
            }
            t.first_code[len] = code;
            t.first_index[len] = index;
            code = (code + u32::from(t.count[len])) << 1;
            index += t.count[len];
        }
        let mut next = t.first_index;
        for (sym, &l) in lengths.iter().enumerate() {
            let l = usize::from(l);
            if l == 0 {
                continue;
            }
            let k = next[l];
            t.sorted[usize::from(k)] = sym as u16;
            next[l] += 1;
            if l as u32 <= FAST {
                let c = t.first_code[l] + u32::from(k - t.first_index[l]);
                let shift = FAST - l as u32;
                t.fast[(c << shift) as usize..((c + 1) << shift) as usize].fill((sym as u16, l as u8));
            }
        }
        Ok(t)
    }

    /// The symbol and code length of the `MAX_LEN` bits `p`; length 0 for no code.
    fn decode(&self, p: u32) -> (u16, u8) {
        let e = self.fast[(p >> (MAX_LEN - FAST)) as usize];
        if e.1 != 0 {
            return e;
        }
        for len in FAST as usize + 1..=MAX_LEN as usize {
            let k = (p >> (MAX_LEN as usize - len)).wrapping_sub(self.first_code[len]);
            if k < u32::from(self.count[len]) {
                return (self.sorted[usize::from(self.first_index[len]) + k as usize], len as u8);
            }
        }
        (0, 0)
    }
}

/// The bit stream of a Huffman block: 16-bit little-endian words into a 32-bit window, bytes
/// for long lengths read from the same input between them.
struct Bits<'a> {
    src: &'a [u8],
    s: usize,
    next: u32,
    extra: i32,
}

impl<'a> Bits<'a> {
    fn new(src: &'a [u8], s: usize) -> Result<Bits<'a>> {
        let w = |o: usize| -> Result<u32> {
            let b = src.get(o..o + 2).ok_or_else(|| bad("xpress huffman stream", "ends at a block start"))?;
            Ok(u32::from(u16::from_le_bytes([b[0], b[1]])))
        };
        Ok(Bits { src, s: s + 4, next: (w(s)? << 16) | w(s + 2)?, extra: 16 })
    }

    fn take(&mut self, n: u32) {
        if n == 0 {
            return;
        }
        self.next <<= n;
        self.extra -= n as i32;
        if self.extra < 0 {
            // Past the end reads as zeros: a stream may end with fewer bits than the window.
            let w = match self.src.get(self.s..self.s + 2) {
                Some(b) => u32::from(u16::from_le_bytes([b[0], b[1]])),
                None => 0,
            };
            self.s += 2;
            self.next |= w << (-self.extra) as u32;
            self.extra += 16;
        }
    }

    fn peek(&self, n: u32) -> u32 {
        if n == 0 { 0 } else { self.next >> (32 - n) }
    }

    fn byte(&mut self) -> Result<usize> {
        let b = *self.src.get(self.s).ok_or_else(|| bad("xpress huffman stream", "ends in a match length"))?;
        self.s += 1;
        Ok(usize::from(b))
    }
}

/// Decompress XPRESS Huffman `src` into `out`; the bytes produced.
pub fn decompress_huffman(src: &[u8], out: &mut [u8]) -> Result<usize> {
    const W: &str = "xpress huffman stream";
    let mut s = 0usize;
    let mut at = 0usize;
    while at < out.len() {
        let t = src.get(s..s + 256).ok_or_else(|| bad(W, format!("no code table at input offset {s}")))?;
        let mut lengths = [0u8; 512];
        for (i, b) in t.iter().enumerate() {
            lengths[2 * i] = b & 15;
            lengths[2 * i + 1] = b >> 4;
        }
        let table = Table::new(&lengths)?;
        let mut bits = Bits::new(src, s + 256)?;
        let block_end = (at + 65536).min(out.len());
        while at < block_end {
            let (sym, len) = table.decode(bits.peek(MAX_LEN));
            if len == 0 {
                return Err(bad(W, format!("no symbol for the bits at output offset {at}")));
            }
            bits.take(u32::from(len));
            let sym = usize::from(sym);
            if sym < 256 {
                out[at] = sym as u8;
                at += 1;
                continue;
            }
            let sym = sym - 256;
            let mut mlen = sym & 15;
            let dbits = (sym >> 4) as u32;
            if mlen == 15 {
                mlen = bits.byte()?;
                if mlen == 255 {
                    mlen = bits.byte()? | (bits.byte()? << 8);
                    if mlen == 0 {
                        mlen = bits.byte()? | (bits.byte()? << 8) | (bits.byte()? << 16) | (bits.byte()? << 24);
                    }
                    mlen = mlen.checked_sub(15).ok_or_else(|| bad(W, format!("match length {mlen}")))?;
                }
                mlen += 15;
            }
            let dist = (bits.peek(dbits) as usize) + (1 << dbits);
            bits.take(dbits);
            copy_match(out, &mut at, dist, mlen + 3, W)?;
        }
        s = bits.s;
        if s >= src.len() {
            break;
        }
    }
    Ok(at)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    /// The examples of [MS-XCA] 3.1.
    #[test]
    fn plain_examples() {
        let mut out = [0u8; 26];
        let mut src = vec![0x3f, 0, 0, 0];
        src.extend_from_slice(b"abcdefghijklmnopqrstuvwxyz");
        assert_eq!(decompress_plain(&src, &mut out).unwrap(), 26);
        assert_eq!(&out, b"abcdefghijklmnopqrstuvwxyz");

        let src = [0xff, 0xff, 0xff, 0x1f, 0x61, 0x62, 0x63, 0x17, 0x00, 0x0f, 0xff, 0x26, 0x01];
        let mut out = [0u8; 300];
        assert_eq!(decompress_plain(&src, &mut out).unwrap(), 300);
        assert_eq!(out.to_vec(), b"abc".repeat(100));
    }

    #[test]
    fn huffman_literals() {
        // Every literal 8 bits long (256 symbols of length 8): the bit stream is the bytes,
        // in 16-bit little-endian words.
        let mut src = vec![0x88u8; 128];
        src.extend_from_slice(&[0u8; 128]);
        let text = b"hello, world";
        for w in text.chunks(2) {
            src.extend_from_slice(&[w[1], w[0]]);
        }
        src.extend_from_slice(&[0, 0, 0, 0]);
        let mut out = [0u8; 12];
        assert_eq!(decompress_huffman(&src, &mut out).unwrap(), 12);
        assert_eq!(&out, text);
        // No table.
        assert!(decompress_huffman(&src[..100], &mut out).is_err());
    }

    /// A code table with no symbols or too many short codes, bits that match no code, and a
    /// block with no bit stream are errors.
    #[test]
    fn bad_huffman_blocks() {
        let mut out = [0u8; 8];
        let msg = |src: &[u8]| decompress_huffman(src, &mut [0u8; 8]).unwrap_err().to_string();
        let mut src = vec![0u8; 256 + 4];
        assert!(msg(&src).contains("no symbols"));
        src[..256].fill(0x11);
        assert!(msg(&src).contains("oversubscribed"));
        // One symbol, 15 bits long: only the all-zero code is one; ones match nothing.
        src[..256].fill(0);
        src[0] = 0x0F;
        src[256..].fill(0xFF);
        assert!(msg(&src).contains("no symbol for the bits at output offset 0"));
        src[256..].fill(0);
        assert_eq!(decompress_huffman(&src, &mut out).unwrap(), 8, "the zero code is symbol 0");
        assert_eq!(out, [0u8; 8]);
        assert!(msg(&src[..257]).contains("ends at a block start"));
    }
}
