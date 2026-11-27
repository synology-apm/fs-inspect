//! Allocation bitmaps as NTFS, ReFS, ext, exFAT and APFS store them: bit `i` is bit `i % 8` of byte
//! `i / 8` (least significant first), set when the unit is in use.

use crate::cursor::push_range;
use crate::range::ByteRange;

/// Append the runs of set bits among the first `nbits` bits of `bits` as byte ranges: bit `i`
/// covers `[base + i * unit, base + (i + 1) * unit)`. Touching ranges merge with the last range
/// of `out`. Runs of clear or set bits are skipped 64 at a time.
pub fn push_bit_runs(out: &mut Vec<ByteRange>, bits: &[u8], nbits: u64, base: u64, unit: u64) {
    let nbits = nbits.min(bits.len() as u64 * 8);
    let mut i = 0u64;
    while let Some(start) = next_bit(bits, i, nbits, true) {
        let end = next_bit(bits, start, nbits, false).unwrap_or(nbits);
        push_range(out, base + start * unit, (end - start) * unit);
        i = end;
    }
}

/// The first bit at or after `from` and below `nbits` (within `bits`) that is `value`.
fn next_bit(bits: &[u8], from: u64, nbits: u64, value: bool) -> Option<u64> {
    // A clear bit is a set bit of the flipped word.
    let flip = if value { 0 } else { u64::MAX };
    let mut i = from;
    while i < nbits {
        let at = (i / 8) as usize;
        // A whole 64-bit word when aligned and inside the range.
        if i.is_multiple_of(64)
            && i + 64 <= nbits
            && let Some(w) = bits.get(at..at + 8)
        {
            let mut b = [0u8; 8];
            b.copy_from_slice(w);
            let w = u64::from_le_bytes(b) ^ flip;
            if w != 0 {
                return Some(i + u64::from(w.trailing_zeros()));
            }
            i += 64;
            continue;
        }
        if (bits[at] >> (i % 8)) & 1 == u8::from(value) {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Set (`value`) or clear bits `[a, b)` of `bits`, clipped to its length.
pub fn fill_bits(bits: &mut [u8], a: u64, b: u64, value: bool) {
    let b = b.min(bits.len() as u64 * 8);
    if a >= b {
        return;
    }
    let mask = |lo: u64, hi: u64| -> u8 { (((1u16 << (hi - lo)) - 1) << lo) as u8 };
    let apply = |byte: &mut u8, m: u8| if value { *byte |= m } else { *byte &= !m };
    let (first, last) = ((a / 8) as usize, ((b - 1) / 8) as usize);
    if first == last {
        apply(&mut bits[first], mask(a % 8, (b - 1) % 8 + 1));
        return;
    }
    apply(&mut bits[first], mask(a % 8, 8));
    bits[first + 1..last].fill(if value { 0xFF } else { 0 });
    apply(&mut bits[last], mask(0, (b - 1) % 8 + 1));
}

/// `dst |= src`, byte by byte over the shorter of the two.
pub fn or_into(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src) {
        *d |= s;
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn bit_runs() {
        let mut out = Vec::new();
        // bits 0,1 set; 8..16 set; 17 set; 30 set (beyond nbits=30 -> ignored)
        push_bit_runs(&mut out, &[0b0000_0011, 0xFF, 0b0000_0010, 0b0100_0000], 30, 100, 2);
        assert_eq!(out, [ByteRange::new(100, 4), ByteRange::new(116, 16), ByteRange::new(134, 2)]);
        let mut out = Vec::new();
        push_bit_runs(&mut out, &[0xFF, 0xFF, 0x0F], 20, 0, 1);
        assert_eq!(out, [ByteRange::new(0, 20)]);
        let mut out = vec![ByteRange::new(0, 10)];
        push_bit_runs(&mut out, &[0x01], 8, 10, 1);
        assert_eq!(out, [ByteRange::new(0, 11)]);
    }

    #[test]
    fn bit_runs_model() {
        let bits: Vec<u8> = (0..64u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
        for nbits in [0u64, 1, 7, 8, 9, 100, 511, 512] {
            let mut out = Vec::new();
            push_bit_runs(&mut out, &bits, nbits, 0, 1);
            let want: Vec<ByteRange> = crate::range::coalesce(
                (0..nbits).filter(|i| (bits[(i / 8) as usize] >> (i % 8)) & 1 == 1).map(|i| ByteRange::new(i, 1)),
            )
            .collect();
            assert_eq!(out, want, "nbits {nbits}");
        }
    }

    /// Long runs of clear and set bits, across 64-bit words, at any start and length.
    #[test]
    fn bit_runs_model_long_runs() {
        let mut bits = vec![0u8; 96];
        bits[9..30].fill(0xFF);
        bits[30] = 0x0F;
        bits[41] = 0x80;
        bits[42..64].fill(0xFF);
        bits[70..96].fill(0xFF);
        for nbits in [0u64, 63, 64, 65, 239, 240, 241, 335, 512, 600, 768] {
            for base in [0u64, 3] {
                let mut out = vec![ByteRange::new(0, 3)];
                push_bit_runs(&mut out, &bits, nbits, base, 1);
                let mut want = vec![ByteRange::new(0, 3)];
                for i in (0..nbits.min(768)).filter(|i| (bits[(i / 8) as usize] >> (i % 8)) & 1 == 1) {
                    crate::cursor::push_range(&mut want, base + i, 1);
                }
                assert_eq!(out, want, "nbits {nbits} base {base}");
            }
        }
    }

    #[test]
    fn fill_matches_bit_by_bit() {
        for a in 0..40u64 {
            for b in a..44 {
                for value in [false, true] {
                    let init: Vec<u8> = (0..5u8).map(|i| i.wrapping_mul(0x5B)).collect();
                    let mut got = init.clone();
                    fill_bits(&mut got, a, b, value);
                    let mut want = init.clone();
                    for i in a..b.min(40) {
                        let (byte, bit) = ((i / 8) as usize, i % 8);
                        if value { want[byte] |= 1 << bit } else { want[byte] &= !(1 << bit) }
                    }
                    assert_eq!(got, want, "[{a}, {b}) {value}");
                }
            }
        }
    }
}
