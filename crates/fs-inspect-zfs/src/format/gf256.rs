//! Arithmetic in GF(2^8) with the polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11d), the field of
//! the RAID-6 style parities raidz keeps: P is the XOR of the data columns, Q and R their sums
//! weighted by powers of 2 and of 4.

/// `EXP[i]` = 2^i (twice over, so a sum of two logs needs no reduction).
const EXP: [u8; 512] = {
    let mut t = [0u8; 512];
    let mut x: u16 = 1;
    let mut i = 0;
    while i < 255 {
        t[i] = x as u8;
        t[i + 255] = x as u8;
        x <<= 1;
        if x & 0x100 != 0 {
            x ^= 0x11d;
        }
        i += 1;
    }
    t[510] = t[0];
    t[511] = t[1];
    t
};

/// `LOG[x]`, the `n` with `2^n = x` (`LOG[0]` unused).
const LOG: [u8; 256] = {
    let mut t = [0u8; 256];
    let mut i = 0;
    while i < 255 {
        t[EXP[i] as usize] = i as u8;
        i += 1;
    }
    t
};

pub fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 { 0 } else { EXP[LOG[a as usize] as usize + LOG[b as usize] as usize] }
}

/// a^n of a non-zero element (the raidz generators 1, 2 and 4).
pub fn pow(a: u8, n: usize) -> u8 {
    EXP[(LOG[a as usize] as usize * n) % 255]
}

/// The inverse of a non-zero element.
pub fn inv(a: u8) -> u8 {
    debug_assert!(a != 0);
    EXP[(255 - LOG[a as usize] as usize) % 255]
}

/// `dst ^= c * src` over the common length.
pub fn mul_add(dst: &mut [u8], src: &[u8], c: u8) {
    match c {
        0 => {}
        1 => dst.iter_mut().zip(src).for_each(|(d, s)| *d ^= s),
        _ => {
            let lc = LOG[c as usize] as usize;
            for (d, &s) in dst.iter_mut().zip(src) {
                if s != 0 {
                    *d ^= EXP[lc + LOG[s as usize] as usize];
                }
            }
        }
    }
}

/// The inverse of the square matrix `m` (rows of `n` elements), `None` if it is singular.
pub fn invert(m: &[Vec<u8>]) -> Option<Vec<Vec<u8>>> {
    let n = m.len();
    let mut a: Vec<Vec<u8>> = m.to_vec();
    let mut out: Vec<Vec<u8>> = (0..n).map(|i| (0..n).map(|j| u8::from(i == j)).collect()).collect();
    for col in 0..n {
        let p = (col..n).find(|&r| a[r][col] != 0)?;
        a.swap(col, p);
        out.swap(col, p);
        let k = inv(a[col][col]);
        for j in 0..n {
            a[col][j] = mul(a[col][j], k);
            out[col][j] = mul(out[col][j], k);
        }
        for r in 0..n {
            let f = a[r][col];
            if r != col && f != 0 {
                for j in 0..n {
                    a[r][j] ^= mul(f, a[col][j]);
                    out[r][j] ^= mul(f, out[col][j]);
                }
            }
        }
    }
    Some(out)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    /// Multiplication the slow way: shift and add, reducing by the polynomial.
    fn slow_mul(mut a: u8, mut b: u8) -> u8 {
        let mut p = 0u8;
        while b != 0 {
            if b & 1 != 0 {
                p ^= a;
            }
            let carry = a & 0x80 != 0;
            a <<= 1;
            if carry {
                a ^= 0x1d;
            }
            b >>= 1;
        }
        p
    }

    #[test]
    fn tables_agree_with_shift_and_add() {
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                assert_eq!(mul(a, b), slow_mul(a, b), "{a} * {b}");
            }
            if a != 0 {
                assert_eq!(mul(a, inv(a)), 1, "{a}");
            }
        }
        assert_eq!(pow(2, 8), 0x1d);
        assert_eq!(pow(4, 3), mul(4, mul(4, 4)));
    }

    #[test]
    fn inverts_vandermonde_rows() {
        // Rows of generators 1, 2, 4 at column exponents 5, 2, 0.
        let m: Vec<Vec<u8>> = [1u8, 2, 4].iter().map(|&g| [5, 2, 0].iter().map(|&e| pow(g, e)).collect()).collect();
        let i = invert(&m).unwrap();
        for (r, row) in m.iter().enumerate() {
            for c in 0..3 {
                let v = row.iter().zip(&i).fold(0, |s, (a, irow)| s ^ mul(*a, irow[c]));
                assert_eq!(v, u8::from(r == c));
            }
        }
        assert!(invert(&[vec![1, 1], vec![1, 1]]).is_none());
    }
}
