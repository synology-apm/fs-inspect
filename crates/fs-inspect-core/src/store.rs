//! Scratch storage for what a log replay keeps (patches, logged buffers, a logical overlay's
//! items): it grows with the log, never with the volume, and lives in a temporary file rather
//! than in memory.
//!
//! - [`Scratch`]: where a replay may keep it: a directory for temporary files (the system's by
//!   default) and a memory budget shared by every replay made with clones of it.
//! - [`Arena`]: append-only bytes, [`Scratch::arena`] makes one: a temporary file first (created
//!   by `tempfile`, deleted when closed); memory only when no file can be created, within the
//!   budget. A file arena that cannot be written (a full disk) fails with
//!   [`NoSpace`](crate::ErrorKind::NoSpace) and does not move to memory: what it holds is in the
//!   file.
//! - [`SortedTable`]: a table by `u64` key built from entries inserted in any order (the last
//!   one inserted for a key wins), kept sorted in an arena: a fixed buffer of entries in memory
//!   becomes a sorted run in the arena when full, and the runs are merged once. Looking up reads
//!   pages through a bounded [`Lru`]; what stays in memory is one key per page.
//!
//! No `mmap`: it needs `unsafe`, and a mapped file that cannot be read or written (truncated, a
//! full disk) faults instead of returning an error. Positioned reads of a file the OS caches
//! cost little more.

use crate::error::{Error, Result};
use crate::memo::Lru;
use std::fs::File;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};

/// Default memory budget of the arenas made when no temporary file can be created.
pub const DEFAULT_MAX_MEMORY: u64 = 256 << 20;

fs_inspect_io::named_enum! {
    /// Where an arena keeps its bytes.
    pub enum StoreKind ("replay store") {
        /// A temporary file.
        File = 1 => "file",
        /// Memory, within the [`Scratch`]'s budget.
        Memory = 2 => "memory",
    }
}

/// Where replays keep what they hold: temporary files in `dir` (the system's temporary
/// directory when `None`), or memory within a budget when no file can be created there (or
/// always, [`memory`](Self::memory)). Clones share the budget and what
/// [`fell_back`](Self::fell_back) tells.
#[derive(Debug, Clone)]
pub struct Scratch {
    dir: Option<PathBuf>,
    /// Arenas in memory only, no file tried.
    memory_only: bool,
    budget: Arc<Budget>,
    /// Why the first arena that should have been a file is in memory.
    fell_back: Arc<std::sync::OnceLock<String>>,
}

#[derive(Debug)]
struct Budget {
    max: u64,
    used: AtomicU64,
}

impl Budget {
    fn charge(&self, n: u64) -> Result<()> {
        let mut cur = self.used.load(Ordering::Relaxed);
        loop {
            let next = cur.checked_add(n).filter(|&v| v <= self.max).ok_or_else(|| {
                Error::limit(format!("replay memory ({} bytes; no scratch file could be created)", self.max))
            })?;
            match self.used.compare_exchange_weak(cur, next, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => return Ok(()),
                Err(v) => cur = v,
            }
        }
    }

    fn release(&self, n: u64) {
        self.used.fetch_sub(n, Ordering::Relaxed);
    }
}

impl Default for Scratch {
    fn default() -> Self {
        Scratch::new(None, DEFAULT_MAX_MEMORY)
    }
}

impl Scratch {
    /// Temporary files in `dir` (`None`: the system's temporary directory); `max_memory` bytes in
    /// all for the arenas kept in memory.
    pub fn new(dir: Option<PathBuf>, max_memory: u64) -> Self {
        Scratch {
            dir,
            memory_only: false,
            budget: Arc::new(Budget { max: max_memory, used: AtomicU64::new(0) }),
            fell_back: Arc::default(),
        }
    }

    /// Arenas in memory only, `max_memory` bytes in all (a caller that writes no file).
    pub fn memory(max_memory: u64) -> Self {
        Scratch { memory_only: true, ..Scratch::new(None, max_memory) }
    }

    /// Why arenas meant for temporary files were kept in memory (no file could be created), the
    /// first time it happened; `None` when it did not.
    pub fn fell_back(&self) -> Option<&str> {
        self.fell_back.get().map(String::as_str)
    }

    /// The directory temporary files are made in (`None`: the system's).
    pub fn dir(&self) -> Option<&std::path::Path> {
        self.dir.as_deref()
    }

    /// The memory budget, in bytes.
    pub fn max_memory(&self) -> u64 {
        self.budget.max
    }

    /// Bytes the memory arenas of this scratch hold now.
    pub fn memory_used(&self) -> u64 {
        self.budget.used.load(Ordering::Relaxed)
    }

    /// A new arena: a temporary file, or memory when none can be created (why is kept:
    /// [`fell_back`](Self::fell_back)) or the scratch is [`memory`](Self::memory) only.
    pub fn arena(&self) -> Arc<Arena> {
        if self.memory_only {
            return self.memory_arena();
        }
        let made = match &self.dir {
            Some(d) => tempfile::tempfile_in(d),
            None => tempfile::tempfile(),
        };
        match made {
            Ok(file) => Arc::new(Arena { backend: Backend::File { file, len: Mutex::new(0) } }),
            Err(e) => {
                let dir =
                    self.dir.as_ref().map_or_else(|| "the temporary directory".to_owned(), |d| d.display().to_string());
                let _ = self
                    .fell_back
                    .set(format!("no scratch file could be created in {dir} ({e}): replay data kept in memory"));
                self.memory_arena()
            }
        }
    }

    /// A new arena in memory (tests; [`arena`](Self::arena) when no file can be created).
    pub fn memory_arena(&self) -> Arc<Arena> {
        Arc::new(Arena { backend: Backend::Memory { data: RwLock::new(Vec::new()), budget: self.budget.clone() } })
    }
}

/// Append-only bytes in a temporary file or in memory (see the [module](self)).
#[derive(Debug)]
pub struct Arena {
    backend: Backend,
}

#[derive(Debug)]
enum Backend {
    File { file: File, len: Mutex<u64> },
    Memory { data: RwLock<Vec<u8>>, budget: Arc<Budget> },
}

impl Drop for Arena {
    fn drop(&mut self) {
        if let Backend::Memory { data, budget } = &self.backend {
            budget.release(data.read().unwrap_or_else(PoisonError::into_inner).len() as u64);
        }
    }
}

impl Arena {
    pub fn kind(&self) -> StoreKind {
        match self.backend {
            Backend::File { .. } => StoreKind::File,
            Backend::Memory { .. } => StoreKind::Memory,
        }
    }

    /// Bytes appended so far.
    pub fn len(&self) -> u64 {
        match &self.backend {
            Backend::File { len, .. } => *len.lock().unwrap_or_else(PoisonError::into_inner),
            Backend::Memory { data, .. } => data.read().unwrap_or_else(PoisonError::into_inner).len() as u64,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// `bytes` appended; where they start.
    pub fn append(&self, bytes: &[u8]) -> Result<u64> {
        match &self.backend {
            Backend::File { file, len } => {
                let mut len = len.lock().unwrap_or_else(PoisonError::into_inner);
                let at = *len;
                pwrite(file, at, bytes).map_err(|e| Error::file("replay scratch file", e))?;
                *len += bytes.len() as u64;
                Ok(at)
            }
            Backend::Memory { data, budget } => {
                budget.charge(bytes.len() as u64)?;
                let mut data = data.write().unwrap_or_else(PoisonError::into_inner);
                let at = data.len() as u64;
                data.try_reserve(bytes.len()).map_err(|_| Error::limit("replay memory (allocation failed)"))?;
                data.extend_from_slice(bytes);
                Ok(at)
            }
        }
    }

    /// `buf.len()` bytes at `at`, all appended before.
    pub fn read_at(&self, at: u64, buf: &mut [u8]) -> Result<()> {
        let end = at.checked_add(buf.len() as u64).filter(|&e| e <= self.len());
        if end.is_none() {
            return Err(Error::invalid_argument(format!(
                "replay scratch read of {} bytes at {at} past its {} bytes",
                buf.len(),
                self.len()
            )));
        }
        match &self.backend {
            Backend::File { file, .. } => pread(file, at, buf).map_err(|e| Error::file("replay scratch file", e)),
            Backend::Memory { data, .. } => {
                let data = data.read().unwrap_or_else(PoisonError::into_inner);
                buf.copy_from_slice(&data[at as usize..at as usize + buf.len()]);
                Ok(())
            }
        }
    }

    /// `len` bytes at `at`.
    pub fn read_vec(&self, at: u64, len: usize) -> Result<Vec<u8>> {
        let mut v = vec![0u8; len];
        self.read_at(at, &mut v)?;
        Ok(v)
    }
}

#[cfg(unix)]
fn pread(file: &File, at: u64, buf: &mut [u8]) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.read_exact_at(buf, at)
}

#[cfg(unix)]
fn pwrite(file: &File, at: u64, buf: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.write_all_at(buf, at)
}

#[cfg(windows)]
fn pread(file: &File, mut at: u64, mut buf: &mut [u8]) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        match file.seek_read(buf, at) {
            Ok(0) => return Err(std::io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => {
                buf = &mut buf[n..];
                at += n as u64;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[cfg(windows)]
fn pwrite(file: &File, mut at: u64, mut buf: &[u8]) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        match file.seek_write(buf, at) {
            Ok(0) => return Err(std::io::ErrorKind::WriteZero.into()),
            Ok(n) => {
                buf = &buf[n..];
                at += n as u64;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// A fixed-size value a [`SortedTable`] keeps, encoded in [`SIZE`](Record::SIZE) bytes.
pub trait Record: Clone + Send + Sync + 'static {
    const SIZE: usize;
    /// Written into `out` ([`SIZE`](Record::SIZE) bytes).
    fn put(&self, out: &mut [u8]);
    /// Read back from `b` ([`SIZE`](Record::SIZE) bytes).
    fn get(b: &[u8]) -> Self;
}

impl Record for () {
    const SIZE: usize = 0;
    fn put(&self, _: &mut [u8]) {}
    fn get(_: &[u8]) -> Self {}
}

impl Record for u64 {
    const SIZE: usize = 8;
    fn put(&self, out: &mut [u8]) {
        out.copy_from_slice(&self.to_le_bytes());
    }
    fn get(b: &[u8]) -> Self {
        u64::from_le_bytes(b.try_into().unwrap_or_default())
    }
}

impl<A: Record, B: Record> Record for (A, B) {
    const SIZE: usize = A::SIZE + B::SIZE;
    fn put(&self, out: &mut [u8]) {
        self.0.put(&mut out[..A::SIZE]);
        self.1.put(&mut out[A::SIZE..]);
    }
    fn get(b: &[u8]) -> Self {
        (A::get(&b[..A::SIZE]), B::get(&b[A::SIZE..]))
    }
}

/// Bytes of entries a [`TableBuilder`] holds before writing them as a run.
const RUN_BYTES: usize = 1 << 20;
/// Bytes of a page of a finished table: the unit read and cached.
const PAGE_BYTES: usize = 16 << 10;
/// Bytes read at once from each run while merging.
const MERGE_READ: usize = 64 << 10;

fn entry_size<V: Record>() -> usize {
    8 + V::SIZE
}

/// Builds a [`SortedTable`] from entries in any order; for a key inserted more than once, the
/// last one inserted wins.
#[derive(Debug)]
pub struct TableBuilder<V: Record> {
    arena: Arc<Arena>,
    buf: Vec<(u64, V)>,
    /// Runs written, oldest first: `(start, entries)`.
    runs: Vec<(u64, u64)>,
    cache_bytes: usize,
}

impl<V: Record + std::fmt::Debug> TableBuilder<V> {
    /// A table in `arena`; its pages cached within `cache_bytes`.
    pub fn new(arena: Arc<Arena>, cache_bytes: usize) -> Self {
        TableBuilder { arena, buf: Vec::new(), runs: Vec::new(), cache_bytes }
    }

    pub fn insert(&mut self, key: u64, value: V) -> Result<()> {
        self.buf.push((key, value));
        if self.buf.len() * entry_size::<V>() >= RUN_BYTES {
            self.flush()?;
        }
        Ok(())
    }

    /// The entries held written as a sorted run (the last of each key kept).
    fn flush(&mut self) -> Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        // Stable: equal keys stay in insertion order, the last one wins.
        self.buf.sort_by_key(|e| e.0);
        let mut out = Vec::with_capacity(self.buf.len() * entry_size::<V>());
        let mut n = 0u64;
        for (i, (k, v)) in self.buf.iter().enumerate() {
            if self.buf.get(i + 1).is_some_and(|next| next.0 == *k) {
                continue;
            }
            put_entry(&mut out, *k, v);
            n += 1;
        }
        let at = self.arena.append(&out)?;
        self.runs.push((at, n));
        self.buf.clear();
        Ok(())
    }

    /// The table: the runs merged into one (later runs win a key).
    pub fn finish(mut self) -> Result<SortedTable<V>> {
        // One run in memory only: written as it is.
        self.flush()?;
        let (at, count) = match self.runs.len() {
            0 => (self.arena.len(), 0),
            1 => self.runs[0],
            _ => merge::<V>(&self.arena, &self.runs)?,
        };
        SortedTable::over(self.arena, at, count, self.cache_bytes)
    }
}

fn put_entry<V: Record>(out: &mut Vec<u8>, k: u64, v: &V) {
    let start = out.len();
    out.resize(start + entry_size::<V>(), 0);
    out[start..start + 8].copy_from_slice(&k.to_le_bytes());
    v.put(&mut out[start + 8..]);
}

fn get_entry<V: Record>(b: &[u8]) -> (u64, V) {
    (u64::from_le_bytes(b[..8].try_into().unwrap_or_default()), V::get(&b[8..]))
}

/// A run read in order, a window at a time.
struct RunReader<'a> {
    arena: &'a Arena,
    next: u64,
    left: u64,
    window: Vec<u8>,
    pos: usize,
    size: usize,
}

impl RunReader<'_> {
    fn peek_key(&mut self) -> Result<Option<u64>> {
        if self.pos == self.window.len() {
            if self.left == 0 {
                return Ok(None);
            }
            let n = (MERGE_READ / self.size).max(1).min(usize::try_from(self.left).unwrap_or(usize::MAX));
            self.window = self.arena.read_vec(self.next, n * self.size)?;
            self.next += (n * self.size) as u64;
            self.left -= n as u64;
            self.pos = 0;
        }
        Ok(Some(u64::from_le_bytes(self.window[self.pos..self.pos + 8].try_into().unwrap_or_default())))
    }

    fn take(&mut self) -> &[u8] {
        let e = &self.window[self.pos..self.pos + self.size];
        self.pos += self.size;
        e
    }
}

/// `runs` merged into one run appended to `arena`: `(start, entries)`.
fn merge<V: Record>(arena: &Arena, runs: &[(u64, u64)]) -> Result<(u64, u64)> {
    use std::cmp::Reverse;
    use std::collections::BinaryHeap;
    let size = entry_size::<V>();
    let mut readers: Vec<RunReader<'_>> =
        runs.iter().map(|&(at, n)| RunReader { arena, next: at, left: n, window: Vec::new(), pos: 0, size }).collect();
    // By key, then the latest run first.
    let mut heap = BinaryHeap::new();
    for (i, r) in readers.iter_mut().enumerate() {
        if let Some(k) = r.peek_key()? {
            heap.push((Reverse(k), i));
        }
    }
    let mut out = Vec::with_capacity(MERGE_READ);
    let (mut start, mut count) = (None, 0u64);
    let flush = |out: &mut Vec<u8>, start: &mut Option<u64>| -> Result<()> {
        if !out.is_empty() {
            let at = arena.append(out)?;
            start.get_or_insert(at);
            out.clear();
        }
        Ok(())
    };
    while let Some((Reverse(k), i)) = heap.pop() {
        // Every run holding `k`: the latest (highest index) wins; each run holds a key once.
        let mut winner = i;
        let mut same = vec![i];
        while let Some(&(Reverse(k2), j)) = heap.peek() {
            if k2 != k {
                break;
            }
            heap.pop();
            winner = winner.max(j);
            same.push(j);
        }
        for j in same {
            let e = readers[j].take();
            if j == winner {
                out.extend_from_slice(e);
                count += 1;
            }
            if let Some(next) = readers[j].peek_key()? {
                heap.push((Reverse(next), j));
            }
        }
        if out.len() >= MERGE_READ {
            flush(&mut out, &mut start)?;
        }
    }
    flush(&mut out, &mut start)?;
    Ok((start.unwrap_or(arena.len()), count))
}

/// A page of a [`SortedTable`]: its entries, in order.
type Page<V> = Arc<[(u64, V)]>;

/// Entries by `u64` key, sorted, in an [`Arena`] (see the [module](self)). Cheap to share
/// behind an `Arc`; lookups take `&self`.
pub struct SortedTable<V: Record> {
    arena: Arc<Arena>,
    at: u64,
    count: u64,
    per_page: u64,
    /// The first key of each page.
    fences: Vec<u64>,
    pages: Mutex<Lru<u64, Page<V>>>,
}

impl<V: Record> std::fmt::Debug for SortedTable<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SortedTable")
            .field("entries", &self.count)
            .field("store", &self.arena.kind())
            .finish_non_exhaustive()
    }
}

impl<V: Record> SortedTable<V> {
    /// An empty table (in memory: it holds nothing).
    pub fn empty() -> Self {
        let arena = Arc::new(Arena {
            backend: Backend::Memory {
                data: RwLock::new(Vec::new()),
                budget: Arc::new(Budget { max: 0, used: AtomicU64::new(0) }),
            },
        });
        SortedTable { arena, at: 0, count: 0, per_page: 1, fences: Vec::new(), pages: Mutex::new(Lru::new(0)) }
    }

    fn over(arena: Arc<Arena>, at: u64, count: u64, cache_bytes: usize) -> Result<Self> {
        let size = entry_size::<V>() as u64;
        let per_page = (PAGE_BYTES as u64 / size).max(1);
        let mut fences = Vec::with_capacity(usize::try_from(count.div_ceil(per_page)).unwrap_or(0));
        let mut k = [0u8; 8];
        for p in 0..count.div_ceil(per_page) {
            arena.read_at(at + p * per_page * size, &mut k)?;
            fences.push(u64::from_le_bytes(k));
        }
        Ok(SortedTable { arena, at, count, per_page, fences, pages: Mutex::new(Lru::new(cache_bytes)) })
    }

    /// How many entries.
    pub fn len(&self) -> u64 {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Where it is kept.
    pub fn store(&self) -> StoreKind {
        self.arena.kind()
    }

    /// The arena it is kept in (for payloads kept beside it).
    pub fn arena(&self) -> &Arc<Arena> {
        &self.arena
    }

    /// Page `p`, read once while it stays cached.
    fn page(&self, p: u64) -> Result<Page<V>> {
        if let Some(hit) = self.pages.lock().unwrap_or_else(PoisonError::into_inner).get(&p) {
            return Ok(hit);
        }
        let page = self.read_page(p)?;
        let cost = page.len() * (8 + size_of::<V>()).max(1);
        self.pages.lock().unwrap_or_else(PoisonError::into_inner).insert(p, page.clone(), cost);
        Ok(page)
    }

    fn read_page(&self, p: u64) -> Result<Page<V>> {
        let size = entry_size::<V>();
        let first = p * self.per_page;
        let n = self.per_page.min(self.count - first) as usize;
        let bytes = self.arena.read_vec(self.at + first * size as u64, n * size)?;
        Ok(bytes.chunks_exact(size).map(get_entry::<V>).collect())
    }

    /// The page that holds `key` if any does: the last whose first key is at most `key`.
    fn page_of(&self, key: u64) -> Option<u64> {
        self.fences.partition_point(|&f| f <= key).checked_sub(1).map(|p| p as u64)
    }

    /// The value of `key`.
    pub fn get(&self, key: u64) -> Result<Option<V>> {
        Ok(self.floor(key)?.filter(|(k, _)| *k == key).map(|(_, v)| v))
    }

    /// The entry of the greatest key at most `key`.
    pub fn floor(&self, key: u64) -> Result<Option<(u64, V)>> {
        let Some(p) = self.page_of(key) else { return Ok(None) };
        let page = self.page(p)?;
        let i = page.partition_point(|e| e.0 <= key);
        Ok(i.checked_sub(1).map(|i| page[i].clone()))
    }

    /// Whether some key is in `[lo, hi)`, from the page fences alone when they tell (no read).
    pub fn may_hold(&self, lo: u64, hi: u64) -> Result<bool> {
        if lo >= hi || self.count == 0 {
            return Ok(false);
        }
        // A page starting inside the range holds a key in it.
        let first_after = self.fences.partition_point(|&f| f < lo);
        if self.fences.get(first_after).is_some_and(|&f| f < hi) {
            return Ok(true);
        }
        // Otherwise only the page before can, past `lo`.
        let Some(p) = first_after.checked_sub(1) else { return Ok(false) };
        let page = self.page(p as u64)?;
        let i = page.partition_point(|e| e.0 < lo);
        Ok(page.get(i).is_some_and(|e| e.0 < hi))
    }

    /// The entries with a key in `[lo, hi)`, in order, to `f`.
    pub fn range(&self, lo: u64, hi: u64, mut f: impl FnMut(u64, &V) -> Result<()>) -> Result<()> {
        if lo >= hi {
            return Ok(());
        }
        let mut p = self.page_of(lo).unwrap_or(0);
        while p < self.fences.len() as u64 && self.fences[p as usize] < hi {
            let page = self.page(p)?;
            for (k, v) in page.iter() {
                if *k >= hi {
                    return Ok(());
                }
                if *k >= lo {
                    f(*k, v)?;
                }
            }
            p += 1;
        }
        Ok(())
    }

    /// Every entry, in order, to `f`: read page by page without filling the cache.
    pub fn for_each(&self, mut f: impl FnMut(u64, &V) -> Result<()>) -> Result<()> {
        for p in 0..self.fences.len() as u64 {
            for (k, v) in self.read_page(p)?.iter() {
                f(*k, v)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::BTreeMap;

    fn arenas() -> Vec<Arc<Arena>> {
        let s = Scratch::default();
        let file = s.arena();
        assert_eq!((file.kind(), s.fell_back()), (StoreKind::File, None));
        vec![file, s.memory_arena()]
    }

    #[test]
    fn arenas_append_and_read_back() {
        for a in arenas() {
            assert_eq!(a.append(b"hello").unwrap(), 0);
            assert_eq!(a.append(b" world").unwrap(), 5);
            assert_eq!((a.len(), a.read_vec(3, 5).unwrap()), (11, b"lo wo".to_vec()));
            let e = a.read_at(8, &mut [0u8; 4]).unwrap_err();
            assert_eq!(e.kind(), crate::ErrorKind::InvalidArgument, "{e}");
        }
    }

    #[test]
    fn memory_arenas_share_the_budget_and_release_it() {
        let s = Scratch::new(None, 10);
        let a = s.memory_arena();
        let b = s.memory_arena();
        a.append(&[1; 6]).unwrap();
        let e = b.append(&[1; 6]).unwrap_err();
        assert_eq!(e.kind(), crate::ErrorKind::Limit, "{e}");
        assert_eq!(s.memory_used(), 6);
        drop(a);
        b.append(&[1; 6]).unwrap();
        assert_eq!(s.memory_used(), 6);
    }

    #[test]
    fn no_scratch_file_falls_back_to_memory_with_the_reason() {
        let dir = tempfile::tempdir().unwrap();
        let s = Scratch::new(Some(dir.path().join("missing")), 1 << 20);
        let a = s.arena();
        assert_eq!(a.kind(), StoreKind::Memory);
        assert!(s.clone().fell_back().unwrap().contains("missing"));
    }

    /// A file arena over `file` (a scratch file that cannot be written).
    fn file_arena(file: File) -> Arena {
        Arena { backend: Backend::File { file, len: Mutex::new(0) } }
    }

    /// A scratch file that cannot be written fails the append (a full disk: `NoSpace`) and
    /// stays a file: nothing moves to memory.
    #[test]
    fn a_scratch_file_that_cannot_be_written_fails_and_stays_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("scratch");
        std::fs::write(&path, b"").unwrap();
        let a = file_arena(File::open(&path).unwrap()); // read only
        assert!(a.append(b"patch").is_err());
        assert_eq!((a.kind(), a.len()), (StoreKind::File, 0));
        #[cfg(target_os = "linux")]
        {
            let full = file_arena(std::fs::OpenOptions::new().read(true).write(true).open("/dev/full").unwrap());
            let e = full.append(b"patch").unwrap_err();
            assert_eq!(e.kind(), crate::ErrorKind::NoSpace, "{e}");
            assert_eq!(full.kind(), StoreKind::File);
        }
        let e = Error::file("replay scratch file", std::io::Error::from(std::io::ErrorKind::StorageFull));
        assert_eq!(e.kind(), crate::ErrorKind::NoSpace, "{e}");
    }

    #[test]
    fn a_memory_scratch_tries_no_file() {
        let s = Scratch::memory(1 << 20);
        assert_eq!((s.arena().kind(), s.fell_back()), (StoreKind::Memory, None));
    }

    fn check(entries: &[(u64, u64)], arena: Arc<Arena>) {
        let mut want = BTreeMap::new();
        let mut b = TableBuilder::new(arena, 1 << 16);
        for &(k, v) in entries {
            want.insert(k, v);
            b.insert(k, v).unwrap();
        }
        let t = b.finish().unwrap();
        assert_eq!(t.len(), want.len() as u64);
        let mut all = Vec::new();
        t.for_each(|k, v| {
            all.push((k, *v));
            Ok(())
        })
        .unwrap();
        assert_eq!(all, want.iter().map(|(k, v)| (*k, *v)).collect::<Vec<_>>());
        for probe in [0, 1, 5, 99, 1000, u64::MAX] {
            assert_eq!(t.get(probe).unwrap(), want.get(&probe).copied());
            assert_eq!(t.floor(probe).unwrap(), want.range(..=probe).next_back().map(|(k, v)| (*k, *v)));
        }
        for (lo, hi) in [(0, 10), (5, 6), (100, 5000), (3, 3)] {
            let mut got = Vec::new();
            t.range(lo, hi, |k, v| {
                got.push((k, *v));
                Ok(())
            })
            .unwrap();
            let w: Vec<_> = want.range(lo..hi.max(lo)).map(|(k, v)| (*k, *v)).collect();
            assert_eq!(got, w, "[{lo}, {hi})");
            assert_eq!(t.may_hold(lo, hi).unwrap(), !w.is_empty(), "[{lo}, {hi})");
        }
    }

    #[test]
    fn tables_merge_runs_and_the_last_insert_wins() {
        // Several runs (a run is 1 MiB of 16-byte entries), keys repeated across them.
        let n = 3 * (RUN_BYTES / 16) as u64 + 17;
        let entries: Vec<(u64, u64)> = (0..n).map(|i| ((i * 7919) % 100_003, i)).collect();
        for a in arenas() {
            check(&entries, a);
        }
        let empty: SortedTable<u64> = SortedTable::empty();
        assert_eq!((empty.len(), empty.get(3).unwrap(), empty.may_hold(0, 9).unwrap()), (0, None, false));
    }

    proptest! {
        #[test]
        fn tables_match_a_map(entries in proptest::collection::vec((0u64..2000, any::<u64>()), 0..600)) {
            check(&entries, Scratch::default().memory_arena());
        }
    }
}
