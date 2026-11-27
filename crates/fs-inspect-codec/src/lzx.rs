//! LZX, written from the format's public description: the variant WOF (`compact /exe:lzx`)
//! compresses each 32 KiB chunk of a file with ([`Flavor::Wim`]), and the cabinet one
//! ([`Flavor::Cab`], `makecab`) the tests check it against.
//!
//! The bit stream is 16-bit little-endian words read from the most significant bit. It is a
//! sequence of blocks, each a 3-bit type (1 verbatim, 2 aligned offset, 3 uncompressed) and its
//! size: WIM gives one bit for the default 32768 or 16 bits; a cabinet always 24 bits (and,
//! once at the start, one bit for whether call instructions were translated, then the
//! translation size in 32 bits). A verbatim or aligned block carries Huffman code lengths
//! (aligned: eight 3-bit lengths first), the main code's in two parts (literals, then
//! matches) and the length code's, each as deltas from the previous block's through a
//! 20-symbol pretree. An uncompressed block is aligned to a word and starts with the three
//! repeated offsets. A main symbol below 256 is a literal; the others give a length header
//! (low 3 bits, 7 continued by the length code) and a position slot: slots 0–2 repeat a
//! recent offset, the others an offset of the slot's base plus extra bits (the low 3 through
//! the aligned code in an aligned block).
//!
//! Afterwards `E8` call instructions are translated back from absolute to relative targets:
//! always for WIM (translation size 12000000), as the header says for a cabinet.

use crate::{bad, copy_match};
use fs_inspect_core::Result;

const W: &str = "lzx stream";
/// Main code symbols: 256 literals, 8 length headers per position slot.
const NUM_CHARS: usize = 256;
const PRETREE: usize = 20;
const LENGTH: usize = 249;
const ALIGNED: usize = 8;
const MAX_CODE: u32 = 16;
const MIN_MATCH: usize = 2;
const WIM_TRANSLATION: i64 = 12_000_000;
/// Output of a cabinet frame.
const FRAME: usize = 32768;

/// Which LZX.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavor {
    /// WIM / WOF: each chunk on its own, call translation always on.
    Wim,
    /// Cabinet: a folder's frames (`CFDATA`, 32 KiB of output each) in a row; the bit stream
    /// starts a new word at each frame.
    Cab,
}

/// Position slots of a window of `window` bytes (a power of two, 2^15 to 2^21).
fn position_slots(window: usize) -> Result<usize> {
    if !window.is_power_of_two() {
        return Err(bad(W, format!("window of {window} bytes")));
    }
    Ok(match window.trailing_zeros() {
        15 => 30,
        16 => 32,
        17 => 34,
        18 => 36,
        19 => 38,
        20 => 42,
        21 => 50,
        _ => return Err(bad(W, format!("window of {window} bytes"))),
    })
}

/// Extra bits and base of each position slot.
fn slots() -> ([u32; 50], [u32; 50]) {
    let mut bits = [0u32; 50];
    let mut base = [0u32; 50];
    for i in 0..50 {
        bits[i] = if i < 4 { 0 } else { ((i as u32) / 2 - 1).min(17) };
        if i > 0 {
            base[i] = base[i - 1] + (1 << bits[i - 1]);
        }
    }
    (bits, base)
}

/// Decompress one LZX stream of `flavor` with a `window`-byte window into `out` (its known
/// size); the bytes produced.
pub fn decompress(src: &[u8], out: &mut [u8], window: usize, flavor: Flavor) -> Result<usize> {
    let nslots = position_slots(window)?;
    let main_len = NUM_CHARS + 8 * nslots;
    let (xbits, base) = slots();
    let mut b = Bits::new(src);
    let mut main_prev = vec![0u8; main_len];
    let mut len_prev = vec![0u8; LENGTH];
    let mut r = [1usize; 3];
    let translation = match flavor {
        Flavor::Wim => Some(WIM_TRANSLATION),
        Flavor::Cab => {
            if b.bit() {
                Some(i64::from((b.read(16) << 16) | b.read(16)))
            } else {
                None
            }
        }
    };
    let mut at = 0usize;
    while at < out.len() {
        let kind = b.read(3);
        let size = match flavor {
            Flavor::Wim if b.bit() => 32768,
            Flavor::Wim => b.read(16) as usize,
            Flavor::Cab => ((b.read(16) << 8) | b.read(8)) as usize,
        };
        if size == 0 {
            return Err(bad(W, format!("empty block at output offset {at}")));
        }
        let end = (at + size).min(out.len());
        match kind {
            1 | 2 => {
                let aligned = if kind == 2 {
                    let mut l = [0u8; ALIGNED];
                    for x in &mut l {
                        *x = b.read(3) as u8;
                    }
                    Some(Code::new(&l)?)
                } else {
                    None
                };
                read_lengths(&mut b, &mut main_prev[..NUM_CHARS])?;
                read_lengths(&mut b, &mut main_prev[NUM_CHARS..])?;
                read_lengths(&mut b, &mut len_prev)?;
                let main = Code::new(&main_prev)?;
                let lens = Code::new(&len_prev).ok();
                while at < end {
                    let sym = main.decode(&mut b)?;
                    if sym < NUM_CHARS {
                        out[at] = sym as u8;
                        at += 1;
                        if flavor == Flavor::Cab && at.is_multiple_of(FRAME) {
                            b.drop_partial();
                        }
                        continue;
                    }
                    let s = sym - NUM_CHARS;
                    let mut len = s & 7;
                    if len == 7 {
                        let l = lens.as_ref().ok_or_else(|| bad(W, "a long match without a length code"))?;
                        len += l.decode(&mut b)?;
                    }
                    len += MIN_MATCH;
                    let slot = s >> 3;
                    let dist = match slot {
                        0 => r[0],
                        1 => {
                            r.swap(0, 1);
                            r[0]
                        }
                        2 => {
                            r.swap(0, 2);
                            r[0]
                        }
                        _ => {
                            let n = xbits[slot];
                            let extra = match &aligned {
                                Some(a) if n >= 3 => (b.read(n - 3) << 3) as usize + a.decode(&mut b)?,
                                _ => b.read(n) as usize,
                            };
                            let d = base[slot] as usize + extra - 2;
                            r = [d, r[0], r[1]];
                            d
                        }
                    };
                    copy_match(out, &mut at, dist, len, W)?;
                    if flavor == Flavor::Cab && at.is_multiple_of(FRAME) {
                        b.drop_partial();
                    }
                }
            }
            3 => {
                b.align();
                for x in &mut r {
                    *x = b.raw_u32()? as usize;
                }
                let n = end - at;
                b.raw_bytes(&mut out[at..end])?;
                at += n;
                if !size.is_multiple_of(2) {
                    b.raw_skip(1);
                }
                b.restart();
            }
            k => return Err(bad(W, format!("block type {k} at output offset {at}"))),
        }
    }
    if let Some(t) = translation {
        untranslate(&mut out[..at], t);
    }
    Ok(at)
}

/// Read code lengths (deltas from `prev`, through a pretree) into `prev`.
fn read_lengths(b: &mut Bits, prev: &mut [u8]) -> Result<()> {
    let mut pl = [0u8; PRETREE];
    for x in &mut pl {
        *x = b.read(4) as u8;
    }
    let pre = Code::new(&pl)?;
    let mut i = 0usize;
    while i < prev.len() {
        let sym = pre.decode(b)?;
        let (n, value) = match sym {
            0..=16 => (1, None),
            17 => (4 + b.read(4) as usize, Some(0u8)),
            18 => (20 + b.read(5) as usize, Some(0u8)),
            19 => {
                let n = 4 + b.read(1) as usize;
                let s = pre.decode(b)?;
                if s > 16 {
                    return Err(bad(W, "pretree run of a run"));
                }
                (n, Some(((17 + u32::from(prev[i]) - s as u32) % 17) as u8))
            }
            _ => return Err(bad(W, format!("pretree symbol {sym}"))),
        };
        let n = n.min(prev.len() - i);
        for x in &mut prev[i..i + n] {
            *x = match value {
                Some(v) => v,
                None => ((17 + u32::from(*x) - sym as u32) % 17) as u8,
            };
        }
        i += n;
    }
    Ok(())
}

/// A canonical Huffman code: decoded one length at a time.
struct Code {
    /// Symbols ordered by code length, then value.
    symbols: Vec<u16>,
    /// Codes of each length.
    count: [u16; MAX_CODE as usize + 1],
}

impl Code {
    fn new(lengths: &[u8]) -> Result<Code> {
        let mut count = [0u16; MAX_CODE as usize + 1];
        for &l in lengths {
            if u32::from(l) > MAX_CODE {
                return Err(bad(W, format!("code length {l}")));
            }
            count[usize::from(l)] += 1;
        }
        count[0] = 0;
        // Over-subscribed codes are corruption; incomplete ones decode what they can.
        let mut left = 1i64;
        for &c in &count[1..] {
            left = left * 2 - i64::from(c);
            if left < 0 {
                return Err(bad(W, "Huffman code over-subscribed"));
            }
        }
        if count.iter().all(|&c| c == 0) {
            return Err(bad(W, "empty Huffman code"));
        }
        let mut symbols = Vec::with_capacity(lengths.len());
        for len in 1..=MAX_CODE {
            symbols.extend(lengths.iter().enumerate().filter(|(_, l)| u32::from(**l) == len).map(|(s, _)| s as u16));
        }
        Ok(Code { symbols, count })
    }

    fn decode(&self, b: &mut Bits) -> Result<usize> {
        let (mut code, mut first, mut index) = (0i64, 0i64, 0i64);
        for len in 1..=MAX_CODE as usize {
            code |= i64::from(b.read(1));
            let n = i64::from(self.count[len]);
            if code - first < n {
                return Ok(usize::from(self.symbols[(index + code - first) as usize]));
            }
            index += n;
            first = (first + n) << 1;
            code <<= 1;
        }
        Err(bad(W, "no Huffman symbol for the bits"))
    }
}

/// The bit stream: words most significant bit first, raw bytes for uncompressed blocks.
struct Bits<'a> {
    src: &'a [u8],
    /// Next word to load.
    s: usize,
    acc: u32,
    n: u32,
}

impl<'a> Bits<'a> {
    fn new(src: &'a [u8]) -> Bits<'a> {
        Bits { src, s: 0, acc: 0, n: 0 }
    }

    /// `n` (at most 17) bits; past the end of the input they read as zeros.
    fn read(&mut self, n: u32) -> u32 {
        if n == 0 {
            return 0;
        }
        while self.n < n {
            let w = match self.src.get(self.s..self.s + 2) {
                Some(w) => u32::from(u16::from_le_bytes([w[0], w[1]])),
                None => 0,
            };
            self.s += 2;
            self.acc |= w << (16 - self.n);
            self.n += 16;
        }
        let v = self.acc >> (32 - n);
        self.acc <<= n;
        self.n -= n;
        v
    }

    fn bit(&mut self) -> bool {
        self.read(1) == 1
    }

    /// Skip to the next word: the rest of the current one (a whole one when aligned).
    fn align(&mut self) {
        if self.n == 0 {
            self.s += 2;
        }
        self.acc = 0;
        self.n = 0;
    }

    fn raw_u32(&mut self) -> Result<u32> {
        let b = self.src.get(self.s..self.s + 4).ok_or_else(|| bad(W, "ends in an uncompressed block's header"))?;
        self.s += 4;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn raw_bytes(&mut self, out: &mut [u8]) -> Result<()> {
        let b = self.src.get(self.s..self.s + out.len()).ok_or_else(|| bad(W, "ends in an uncompressed block"))?;
        out.copy_from_slice(b);
        self.s += out.len();
        Ok(())
    }

    fn raw_skip(&mut self, n: usize) {
        self.s += n;
    }

    /// Drop what is left of the current word (a cabinet frame ends on a word).
    fn drop_partial(&mut self) {
        let k = self.n % 16;
        self.read(k);
    }

    /// Bits again after raw bytes.
    fn restart(&mut self) {
        self.acc = 0;
        self.n = 0;
    }
}

/// Undo the `E8` call translation of `data` (absolute targets back to relative ones).
fn untranslate(data: &mut [u8], size: i64) {
    if data.len() <= 10 {
        return;
    }
    let mut i = 0usize;
    while i < data.len() - 10 {
        if data[i] != 0xE8 {
            i += 1;
            continue;
        }
        let abs = i64::from(i32::from_le_bytes([data[i + 1], data[i + 2], data[i + 3], data[i + 4]]));
        let pos = i as i64;
        if abs >= -pos && abs < size {
            let rel = if abs >= 0 { abs - pos } else { abs + size };
            data[i + 1..i + 5].copy_from_slice(&(rel as i32).to_le_bytes());
        }
        i += 5;
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    /// Bits written most significant first into 16-bit little-endian words.
    #[derive(Default)]
    struct Writer {
        out: Vec<u8>,
        acc: u32,
        n: u32,
    }

    impl Writer {
        fn put(&mut self, v: u32, n: u32) {
            for k in (0..n).rev() {
                self.acc = (self.acc << 1) | ((v >> k) & 1);
                self.n += 1;
                if self.n == 16 {
                    self.out.extend_from_slice(&(self.acc as u16).to_le_bytes());
                    self.acc = 0;
                    self.n = 0;
                }
            }
        }
        fn finish(mut self) -> Vec<u8> {
            if self.n > 0 {
                let n = 16 - self.n;
                self.put(0, n);
            }
            self.out
        }
    }

    #[test]
    fn uncompressed_wim_block() {
        // Type 3, default size flag 0, size 5; aligned; R0..R2; "hello" and a pad byte.
        let mut w = Writer::default();
        w.put(3, 3);
        w.put(0, 1);
        w.put(5, 16);
        let mut s = w.finish();
        for _ in 0..3 {
            s.extend_from_slice(&1u32.to_le_bytes());
        }
        s.extend_from_slice(b"hello\0");
        let mut out = [0u8; 5];
        assert_eq!(decompress(&s, &mut out, 32768, Flavor::Wim).unwrap(), 5);
        assert_eq!(&out, b"hello");
    }

    /// A verbatim block whose codes give every literal and the first match symbols one
    /// length: lengths written as pretree deltas from 0.
    #[test]
    fn verbatim_wim_block() {
        let s = verbatim(30);
        let mut out = [0u8; 8];
        assert_eq!(decompress(&s, &mut out, 32768, Flavor::Wim).unwrap(), 8);
        assert_eq!(&out, b"abcdeeee");
    }

    /// A verbatim WIM block of "abcdeeee" whose main tree has the lengths of `nslots` position
    /// slots: decoded only with a window of that many slots.
    fn verbatim(nslots: usize) -> Vec<u8> {
        let main_len = NUM_CHARS + 8 * nslots;
        // Main code: the 256 literals and match symbol 256 + 8*3 + 1 (slot 3, length 3), all
        // length 9 would over-subscribe; use 256 literals at 9 bits (half the code space)
        // and the one match symbol at 1 bit.
        let mut main = vec![0u8; main_len];
        main[..256].fill(9);
        let msym = NUM_CHARS + (3 << 3) + 1;
        main[msym] = 1;
        let mut w = Writer::default();
        w.put(1, 3);
        w.put(0, 1);
        w.put(8, 16); // 8 bytes
        // Pretree: symbols 0..=16 all 5 bits would be 17 codes of 32: fine (incomplete).
        let write_lengths = |w: &mut Writer, lens: &[u8]| {
            for _ in 0..PRETREE {
                w.put(5, 4);
            }
            // Pretree symbol s (5-bit canonical code = s for s < 20): length (0 - s) mod 17.
            for &l in lens {
                let s = (17 - u32::from(l)) % 17;
                w.put(s, 5);
            }
        };
        write_lengths(&mut w, &main[..256]);
        write_lengths(&mut w, &main[256..]);
        write_lengths(&mut w, &[0u8; LENGTH]);
        // Canonical main code: the match symbol (1 bit) is 0; literals (9 bits) 256 + value
        // after it: code of literal c = 0b1_0000_0000 + c.
        for &c in b"abcde" {
            w.put(0x100 + u32::from(c), 9);
        }
        // Slot 3: offset 1 (base 3 - 2), no extra bits; length 3: "eee".
        w.put(0, 1);
        w.finish()
    }

    #[test]
    fn calls_are_translated_back() {
        let mut d = vec![0u8; 32];
        d[4] = 0xE8;
        d[5..9].copy_from_slice(&(4i32 + 100).to_le_bytes());
        untranslate(&mut d, WIM_TRANSLATION);
        assert_eq!(i32::from_le_bytes([d[5], d[6], d[7], d[8]]), 100);
    }

    #[test]
    fn slot_tables() {
        let (bits, base) = slots();
        assert_eq!(&bits[..8], &[0, 0, 0, 0, 1, 1, 2, 2]);
        assert_eq!(&base[..8], &[0, 1, 2, 3, 4, 6, 8, 12]);
        assert_eq!(bits[36], 17);
    }

    /// An uncompressed block of `data` (WIM: no default size), repeated offsets 1.
    fn stored(w: &mut Writer, data: &[u8]) -> Vec<u8> {
        w.put(3, 3);
        w.put(0, 1);
        w.put(data.len() as u32, 16);
        let mut s = std::mem::take(w).finish();
        for _ in 0..3 {
            s.extend_from_slice(&1u32.to_le_bytes());
        }
        s.extend_from_slice(data);
        if data.len() % 2 == 1 {
            s.push(0);
        }
        s
    }

    fn lzx_err(src: &[u8], n: usize, window: usize, flavor: Flavor) -> String {
        decompress(src, &mut vec![0u8; n], window, flavor).unwrap_err().to_string()
    }

    /// Every window from 2^15 to 2^21 decodes; others are refused. Blocks follow one another
    /// past an odd block's pad byte, call targets are translated back, and a cabinet's
    /// header comes first.
    #[test]
    fn windows_blocks_and_headers() {
        let mut s = stored(&mut Writer::default(), b"hello");
        s.extend(stored(&mut Writer::default(), b"world"));
        for k in 15..=21 {
            let mut out = [0u8; 10];
            assert_eq!(decompress(&s, &mut out, 1 << k, Flavor::Wim).unwrap(), 10, "window 2^{k}");
            assert_eq!(&out, b"helloworld");
        }
        for window in [1 << 14, 1 << 22, 3 << 15] {
            assert!(lzx_err(&s, 10, window, Flavor::Wim).contains(&format!("window of {window} bytes")));
        }
        // A compressed block's main tree has 8 lengths per position slot of the window: each
        // window reads exactly its own count, and a tree of another count does not decode.
        for (k, nslots) in (15..=21).zip([30, 32, 34, 36, 38, 42, 50]) {
            let mut out = [0u8; 8];
            let c = verbatim(nslots);
            assert_eq!(decompress(&c, &mut out, 1 << k, Flavor::Wim).unwrap(), 8, "window 2^{k}");
            assert_eq!(&out, b"abcdeeee", "window 2^{k}");
            let other = if k == 21 { 1 << 20 } else { 1 << (k + 1) };
            let mut out = [0u8; 8];
            let r = decompress(&c, &mut out, other, Flavor::Wim);
            assert!(r.is_err() || &out != b"abcdeeee", "the tree of 2^{k} read with a window of {other}");
        }

        // A call at 1 to absolute 20 is relative 19 again; one at 7 past the translation
        // size is left alone.
        let mut d = vec![0x90u8; 32];
        d[1] = 0xE8;
        d[2..6].copy_from_slice(&20i32.to_le_bytes());
        d[7] = 0xE8;
        d[8..12].copy_from_slice(&i32::MAX.to_le_bytes());
        let s = stored(&mut Writer::default(), &d);
        let mut out = [0u8; 32];
        decompress(&s, &mut out, 32768, Flavor::Wim).unwrap();
        assert_eq!(i32::from_le_bytes([out[2], out[3], out[4], out[5]]), 19);
        assert_eq!(out[8..12], i32::MAX.to_le_bytes());

        // A cabinet: translation on (size 1000) then a 24-bit block size.
        let mut w = Writer::default();
        w.put(1, 1);
        w.put(0, 16);
        w.put(1000, 16);
        w.put(3, 3);
        w.put(32, 24);
        let mut c = w.finish();
        for _ in 0..3 {
            c.extend_from_slice(&1u32.to_le_bytes());
        }
        let mut cd = d.clone();
        cd[2..6].copy_from_slice(&500i32.to_le_bytes());
        c.extend_from_slice(&cd);
        let mut out = [0u8; 32];
        assert_eq!(decompress(&c, &mut out, 32768, Flavor::Cab).unwrap(), 32);
        assert_eq!(i32::from_le_bytes([out[2], out[3], out[4], out[5]]), 499);
    }

    /// Bad block types, empty blocks and cut-short uncompressed blocks are errors.
    #[test]
    fn bad_blocks() {
        for kind in [0u32, 4, 7] {
            let mut w = Writer::default();
            w.put(kind, 3);
            w.put(1, 1);
            assert!(lzx_err(&w.finish(), 4, 32768, Flavor::Wim).contains(&format!("block type {kind}")));
        }
        let mut w = Writer::default();
        w.put(3, 3);
        w.put(0, 1);
        w.put(0, 16);
        assert!(lzx_err(&w.finish(), 4, 32768, Flavor::Wim).contains("empty block at output offset 0"));
        let s = stored(&mut Writer::default(), b"hello");
        assert!(lzx_err(&s[..8], 5, 32768, Flavor::Wim).contains("uncompressed block's header"));
        assert!(lzx_err(&s[..18], 5, 32768, Flavor::Wim).contains("ends in an uncompressed block"));
    }
}
