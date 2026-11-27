//! Deterministic pseudo-random content.

/// xorshift64* stream.
#[derive(Clone)]
pub struct Prng(u64);

impl Prng {
    pub fn new(seed: u64) -> Self {
        Prng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next_u64() % n }
    }
    pub fn fill(&mut self, buf: &mut [u8]) {
        for c in buf.chunks_mut(8) {
            let v = self.next_u64().to_le_bytes();
            c.copy_from_slice(&v[..c.len()]);
        }
    }
}

pub fn bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut v = vec![0u8; len];
    Prng::new(seed).fill(&mut v);
    v
}
