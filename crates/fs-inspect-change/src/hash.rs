//! Canonical hashing. Every stored hash is xxh3-64 over a length-prefixed domain tag followed
//! by little-endian fields, so values are stable across platforms and releases; changing what
//! goes into one requires bumping [`HASH_SCHEMA_VERSION`].

use xxhash_rust::xxh3::Xxh3;

/// The version of everything hashed with [`CanonHasher`] (by trackers and by whoever stores
/// their results): a stored hash of another version is not compared.
pub const HASH_SCHEMA_VERSION: u16 = 1;

/// Streaming canonical hasher.
#[derive(Clone)]
pub struct CanonHasher {
    inner: Xxh3,
}

impl std::fmt::Debug for CanonHasher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CanonHasher")
    }
}

impl CanonHasher {
    /// A hasher for the domain `tag` (e.g. `b"ext.attr"`).
    pub fn new(tag: &[u8]) -> Self {
        let mut inner = Xxh3::new();
        inner.update(&(tag.len() as u32).to_le_bytes());
        inner.update(tag);
        CanonHasher { inner }
    }
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.inner.update(&[v]);
        self
    }
    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.inner.update(&v.to_le_bytes());
        self
    }
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.inner.update(&v.to_le_bytes());
        self
    }
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.inner.update(&v.to_le_bytes());
        self
    }
    pub fn i64(&mut self, v: i64) -> &mut Self {
        self.inner.update(&v.to_le_bytes());
        self
    }
    /// Length-prefixed bytes.
    pub fn bytes(&mut self, v: &[u8]) -> &mut Self {
        self.inner.update(&(v.len() as u64).to_le_bytes());
        self.inner.update(v);
        self
    }
    /// Raw bytes without a length prefix (for fixed-size blobs).
    pub fn raw(&mut self, v: &[u8]) -> &mut Self {
        self.inner.update(v);
        self
    }
    pub fn finish(&self) -> u64 {
        self.inner.digest()
    }
}

/// One-shot domain hash.
pub fn hash_bytes(tag: &[u8], data: &[u8]) -> u64 {
    CanonHasher::new(tag).bytes(data).finish()
}

/// A value that differs between calls, processes and runs (for per-scan tokens that must
/// never repeat, and preparation ids): time, a process-wide counter and the process id,
/// hashed under `label`. Never 0.
pub fn nonce(label: &[u8]) -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos() as u64);
    let c = COUNTER.fetch_add(1, Ordering::Relaxed);
    CanonHasher::new(label).u64(t).u64(c).u32(std::process::id()).finish().max(1)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn nonces_do_not_repeat() {
        let a = nonce(b"x");
        let b = nonce(b"x");
        assert_ne!(a, b);
        assert_ne!(a, 0);
    }

    /// The encoding: a u64 length prefix, domain separation, length separation.
    #[test]
    fn golden() {
        assert_eq!(hash_bytes(b"t", b""), CanonHasher::new(b"t").u64(0).finish());
        let a = CanonHasher::new(b"a").u64(1).finish();
        let b = CanonHasher::new(b"b").u64(1).finish();
        assert_ne!(a, b, "domain separates");
        assert_ne!(
            CanonHasher::new(b"x").bytes(b"ab").bytes(b"c").finish(),
            CanonHasher::new(b"x").bytes(b"a").bytes(b"bc").finish(),
            "length prefix separates"
        );
    }
}
