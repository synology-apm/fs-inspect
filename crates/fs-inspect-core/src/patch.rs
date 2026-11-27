//! What a log replay writes, as patches over the volume, and the volume read through them
//! ([`PatchSource`]): the volume itself is left as it is.
//!
//! A [`PatchTable`] is a [`SortedTable`] by start offset in a replay's [`Arena`]: a patch is a
//! range of the volume itself ([`Patch::Copy`]: a block a journal logged, read where the log
//! holds it) or bytes kept in the arena ([`Patch::Stored`]: a buffer replay made). Nothing of
//! it stays in memory but one key per page and the pages a read caches.

use crate::error::{Error, Result, SourceError};
use crate::range::ByteRange;
use crate::store::{Arena, Record, SortedTable, StoreKind, TableBuilder};
use fs_inspect_io::{BlockSource, DynSource};
use std::sync::Arc;

/// What a patched range reads as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Patch {
    /// `len` bytes of the source itself at `from` (a copy of a block kept in a journal), with
    /// the first four bytes replaced by `head` when given (jbd2 escapes a logged block that
    /// starts with its magic).
    Copy { from: u64, len: u32, head: Option<[u8; 4]> },
    /// `len` bytes kept in the table's arena at `at`.
    Stored { at: u64, len: u32 },
}

impl Patch {
    pub fn len(&self) -> u64 {
        match self {
            Patch::Copy { len, .. } | Patch::Stored { len, .. } => u64::from(*len),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Record for Patch {
    // Tag, offset, length, head, whether a head.
    const SIZE: usize = 1 + 8 + 4 + 4 + 1;
    fn put(&self, out: &mut [u8]) {
        let (tag, at, len, head) = match *self {
            Patch::Copy { from, len, head } => (0u8, from, len, head),
            Patch::Stored { at, len } => (1u8, at, len, None),
        };
        out[0] = tag;
        out[1..9].copy_from_slice(&at.to_le_bytes());
        out[9..13].copy_from_slice(&len.to_le_bytes());
        out[13..17].copy_from_slice(&head.unwrap_or_default());
        out[17] = u8::from(head.is_some());
    }
    fn get(b: &[u8]) -> Self {
        let at = u64::from_le_bytes(b[1..9].try_into().unwrap_or_default());
        let len = u32::from_le_bytes(b[9..13].try_into().unwrap_or_default());
        match b[0] {
            0 => {
                let head = (b[17] != 0).then(|| b[13..17].try_into().unwrap_or_default());
                Patch::Copy { from: at, len, head }
            }
            _ => Patch::Stored { at, len },
        }
    }
}

/// Builds a [`PatchTable`]: patches inserted in any order, the last one for a start offset
/// winning.
#[derive(Debug)]
pub struct PatchBuilder {
    table: TableBuilder<Patch>,
    arena: Arc<Arena>,
}

impl PatchBuilder {
    /// A table kept in `arena`, its pages cached within `cache_bytes`.
    pub fn new(arena: Arc<Arena>, cache_bytes: usize) -> Self {
        PatchBuilder { table: TableBuilder::new(arena.clone(), cache_bytes), arena }
    }

    /// `at` reads as the source's `len` bytes at `from`, the first four replaced by `head`.
    pub fn copy(&mut self, at: u64, from: u64, len: u32, head: Option<[u8; 4]>) -> Result<()> {
        self.table.insert(at, Patch::Copy { from, len, head })
    }

    /// `at` reads as `bytes`, kept in the arena.
    pub fn bytes(&mut self, at: u64, bytes: &[u8]) -> Result<()> {
        let len = u32::try_from(bytes.len()).map_err(|_| Error::limit("a replay patch of 4 GiB or more"))?;
        let stored = self.arena.append(bytes)?;
        self.table.insert(at, Patch::Stored { at: stored, len })
    }

    /// Every patch of `table` inserted (a table made over another one).
    pub fn extend(&mut self, table: &PatchTable) -> Result<()> {
        table.table.for_each(|at, p| match *p {
            Patch::Copy { from, len, head } => self.copy(at, from, len, head),
            Patch::Stored { at: stored, len } => {
                let bytes = table.table.arena().read_vec(stored, len as usize)?;
                self.bytes(at, &bytes)
            }
        })
    }

    /// The table, checked: patches that do not overlap and end within `source_size` bytes.
    pub fn finish(self, source_size: u64) -> Result<PatchTable> {
        let table = self.table.finish()?;
        let (mut end, mut bytes) = (0u64, 0u64);
        table.for_each(|at, p| {
            if at < end {
                return Err(Error::corrupt(format!("replay patch at {at} overlaps the one before")));
            }
            end = at.checked_add(p.len()).filter(|&e| e <= source_size).ok_or_else(|| {
                Error::corrupt(format!("replay patch of {} bytes at {at} past the volume ({source_size})", p.len()))
            })?;
            bytes += p.len();
            Ok(())
        })?;
        Ok(PatchTable { table, end, bytes })
    }
}

/// The patches of a replay, by start offset, not overlapping (see the [module](self)).
#[derive(Debug)]
pub struct PatchTable {
    table: SortedTable<Patch>,
    /// Where the last patch ends.
    end: u64,
    /// Bytes patched.
    bytes: u64,
}

impl Default for PatchTable {
    fn default() -> Self {
        PatchTable::empty()
    }
}

impl PatchTable {
    /// No patch.
    pub fn empty() -> Self {
        PatchTable { table: SortedTable::empty(), end: 0, bytes: 0 }
    }

    /// How many patches.
    pub fn len(&self) -> u64 {
        self.table.len()
    }

    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }

    /// Bytes of the volume patched.
    pub fn patched_bytes(&self) -> u64 {
        self.bytes
    }

    /// Where it is kept.
    pub fn store(&self) -> StoreKind {
        self.table.store()
    }

    /// Bytes its arena holds (the table and the stored patches).
    pub fn stored_bytes(&self) -> u64 {
        self.table.arena().len()
    }

    /// The patched ranges, sorted and coalesced.
    pub fn ranges(&self) -> Result<Vec<ByteRange>> {
        let mut out: Vec<ByteRange> = Vec::new();
        self.table.for_each(|at, p| {
            match out.last_mut() {
                Some(last) if last.end() == at => last.length += p.len(),
                _ => out.push(ByteRange::new(at, p.len())),
            }
            Ok(())
        })?;
        Ok(out)
    }

    /// Each patch over `[offset, offset + len)`, in order, to `f`.
    fn over(&self, offset: u64, len: u64, mut f: impl FnMut(u64, &Patch) -> Result<()>) -> Result<()> {
        let end = offset + len;
        if offset >= self.end || len == 0 {
            return Ok(());
        }
        // One that starts before and reaches in (they do not overlap: only the one before).
        if let Some((at, p)) = self.table.floor(offset)?
            && at < offset
            && at + p.len() > offset
        {
            f(at, &p)?;
        }
        if self.table.may_hold(offset, end)? {
            self.table.range(offset, end, |at, p| f(at, p))?;
        }
        Ok(())
    }
}

/// A source whose ranges in a [`PatchTable`] read as the patch says and everything else as the
/// source: a volume with its log replayed, the volume itself left as it is.
pub struct PatchSource {
    inner: DynSource,
    /// Shared: sources over the same replay (each instance opened over it) hold one.
    patches: Arc<PatchTable>,
}

impl PatchSource {
    /// `inner` read through `patches`; an error when one ends past it.
    pub fn new(inner: DynSource, patches: Arc<PatchTable>) -> Result<Self> {
        if patches.end > inner.size() {
            return Err(Error::corrupt(format!("replay patches past the volume ({} bytes)", inner.size())));
        }
        Ok(PatchSource { inner, patches })
    }

    pub fn patches(&self) -> &Arc<PatchTable> {
        &self.patches
    }

    /// The patches over `[offset, offset + buf.len())` written into `buf`. A failed read of
    /// the source is its error as it is; the table's own (its store) is told by what it is
    /// about ([`store_failed`]).
    fn apply(&self, offset: u64, buf: &mut [u8]) -> Result<(), SourceError> {
        let end = offset + buf.len() as u64;
        let mut source: Option<SourceError> = None;
        let done = self.patches.over(offset, buf.len() as u64, |at, p| {
            let (from, to) = (at.max(offset), (at + p.len()).min(end));
            let dst = &mut buf[(from - offset) as usize..(to - offset) as usize];
            let skip = from - at;
            match *p {
                Patch::Stored { at: stored, .. } => self.patches.table.arena().read_at(stored + skip, dst)?,
                Patch::Copy { from: src, head, .. } => {
                    if let Err(e) = self.inner.read_exact_at(src + skip, dst) {
                        source = Some(e.clone());
                        return Err(e.into());
                    }
                    if let Some(h) = head {
                        // The head bytes that fall in `dst`.
                        for (i, b) in h.iter().enumerate() {
                            let pos = i as u64;
                            if pos >= skip && pos < skip + dst.len() as u64 {
                                dst[(pos - skip) as usize] = *b;
                            }
                        }
                    }
                }
            }
            Ok(())
        });
        match (done, source) {
            (Ok(()), _) => Ok(()),
            (Err(_), Some(e)) => Err(e),
            (Err(e), None) => Err(store_failed(e)),
        }
    }
}

/// A failure of the store holding the patches (memory, or a scratch file) as a failed read
/// ([`SourceError::from_error`]).
fn store_failed(e: Error) -> SourceError {
    SourceError::from_error(e).context("reading the replay's patches")
}

impl BlockSource for PatchSource {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), SourceError> {
        self.inner.read_exact_at(offset, buf)?;
        self.apply(offset, buf)
    }
    fn size(&self) -> u64 {
        self.inner.size()
    }
    fn queue_depth(&self) -> Option<std::num::NonZeroUsize> {
        self.inner.queue_depth()
    }
    fn alignment(&self) -> u32 {
        self.inner.alignment()
    }
    fn sector_size(&self) -> Option<u32> {
        self.inner.sector_size()
    }
    // A patch reads as data even where the source holds none.
    fn allocated_in(&self, range: ByteRange) -> Result<Option<Vec<ByteRange>>, SourceError> {
        let Some(mut hint) = self.inner.allocated_in(range)? else {
            return Ok(None);
        };
        let found = self.patches.over(range.offset, range.length, |at, p| {
            hint.push(ByteRange::new(at, p.len()));
            Ok(())
        });
        found.map_err(SourceError::from_error)?;
        hint.sort_unstable_by_key(|r| r.offset);
        Ok(Some(fs_inspect_io::clip(crate::range::coalesce(hint).collect(), range)))
    }
    fn read_parts(&self, offset: u64, buf: &mut [u8], parts: &[std::ops::Range<usize>]) -> Result<(), SourceError> {
        self.inner.read_parts(offset, buf, parts)?;
        // Over the gaps too: their bytes are no one's.
        self.apply(offset, buf)
    }
}

impl std::fmt::Debug for PatchSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PatchSource").field("patches", &self.patches.len()).finish_non_exhaustive()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::store::Scratch;
    use fs_inspect_io::MemSource;

    fn source() -> DynSource {
        Arc::new(MemSource::new((0..64u8).collect::<Vec<_>>()))
    }

    fn table(f: impl FnOnce(&mut PatchBuilder), memory: bool) -> Result<PatchTable> {
        let s = Scratch::default();
        let arena = if memory { s.memory_arena() } else { s.arena() };
        let mut b = PatchBuilder::new(arena, 1 << 16);
        f(&mut b);
        b.finish(64)
    }

    #[test]
    fn patched_ranges_read_as_their_patch_and_the_rest_as_the_source() {
        for memory in [false, true] {
            let t = table(
                |b| {
                    b.bytes(8, &[1, 1, 1, 1]).unwrap();
                    // Replaced: the last insert wins.
                    b.bytes(8, &[200, 201, 202, 203]).unwrap();
                    // A copy of bytes 40..48 at 16, its head replaced.
                    b.copy(16, 40, 8, Some([9, 9, 9, 9])).unwrap();
                },
                memory,
            )
            .unwrap();
            assert_eq!((t.len(), t.patched_bytes()), (2, 12));
            assert_eq!(t.ranges().unwrap(), [ByteRange::new(8, 4), ByteRange::new(16, 8)]);
            let s = PatchSource::new(source(), Arc::new(t)).unwrap();
            let mut all = vec![0u8; 64];
            s.read_exact_at(0, &mut all).unwrap();
            let mut want: Vec<u8> = (0..64).collect();
            want[8..12].copy_from_slice(&[200, 201, 202, 203]);
            want[16..24].copy_from_slice(&[9, 9, 9, 9, 44, 45, 46, 47]);
            assert_eq!(all, want);
            // Reads that start or end inside a patch, or inside its head.
            for (at, n) in [(10, 6), (18, 6), (17, 2), (0, 9), (23, 1), (30, 4)] {
                let mut part = vec![0u8; n];
                s.read_exact_at(at, &mut part).unwrap();
                assert_eq!(part, want[at as usize..at as usize + n], "{at}+{n}");
            }
            let mut run = vec![0u8; 18];
            s.read_parts(6, &mut run, &[0..4, 14..18]).unwrap();
            assert_eq!((&run[..4], &run[14..]), (&want[6..10], &want[20..24]));
        }
    }

    #[test]
    fn overlapping_or_outside_patches_are_refused() {
        let e = table(
            |b| {
                b.bytes(0, &[1; 8]).unwrap();
                b.bytes(4, &[1; 8]).unwrap();
            },
            true,
        )
        .unwrap_err();
        assert!(e.to_string().contains("overlaps"), "{e}");
        let e = table(|b| b.bytes(60, &[1; 8]).unwrap(), true).unwrap_err();
        assert!(e.to_string().contains("past the volume"), "{e}");
    }
    /// A source over memory that says which ranges hold data.
    #[derive(Debug)]
    struct Holes(MemSource, Option<Vec<ByteRange>>);
    impl BlockSource for Holes {
        fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), SourceError> {
            self.0.read_exact_at(offset, buf)
        }
        fn size(&self) -> u64 {
            self.0.size()
        }
        fn allocated_in(&self, range: ByteRange) -> Result<Option<Vec<ByteRange>>, SourceError> {
            Ok(self.1.clone().map(|v| fs_inspect_io::clip(v, range)))
        }
    }

    fn two_patches() -> PatchTable {
        table(
            |b| {
                b.bytes(8, &[1, 2, 3, 4]).unwrap();
                b.copy(16, 40, 8, None).unwrap();
            },
            true,
        )
        .unwrap()
    }

    /// Patches read as data where the source holds none; a source that says nothing still
    /// says nothing.
    #[test]
    fn patches_count_as_allocated() {
        let mem = MemSource::new((0..64u8).collect::<Vec<_>>());
        let s =
            PatchSource::new(Arc::new(Holes(mem, Some(vec![ByteRange::new(0, 8)]))), Arc::new(two_patches())).unwrap();
        assert_eq!(
            s.allocated_in(ByteRange::new(0, 64)).unwrap(),
            Some(vec![ByteRange::new(0, 12), ByteRange::new(16, 8)])
        );
        assert_eq!(s.allocated_in(ByteRange::new(20, 2)).unwrap(), Some(vec![ByteRange::new(20, 2)]));
        assert_eq!(s.allocated_in(ByteRange::new(30, 10)).unwrap(), Some(vec![]));
        let mem = MemSource::new((0..64u8).collect::<Vec<_>>());
        let s = PatchSource::new(Arc::new(Holes(mem, None)), Arc::new(two_patches())).unwrap();
        assert_eq!(s.allocated_in(ByteRange::new(0, 64)).unwrap(), None);
        assert!(!s.patches().is_empty());
        // An empty read past every patch; patches past a shorter source are refused.
        s.read_exact_at(5, &mut []).unwrap();
        let short: DynSource = Arc::new(MemSource::new(vec![0u8; 20]));
        assert!(PatchSource::new(short, Arc::new(two_patches())).unwrap_err().to_string().contains("past the volume"));
        assert!(PatchTable::default().is_empty());
    }

    /// A table made over another reads the same: copies kept, stored bytes copied.
    #[test]
    fn a_table_extends_another() {
        let first = two_patches();
        let t = table(|b| b.extend(&first).unwrap(), false).unwrap();
        assert_eq!(t.ranges().unwrap(), first.ranges().unwrap());
        let (a, b) =
            (PatchSource::new(source(), Arc::new(first)).unwrap(), PatchSource::new(source(), Arc::new(t)).unwrap());
        let (mut x, mut y) = (vec![0u8; 64], vec![0u8; 64]);
        a.read_exact_at(0, &mut x).unwrap();
        b.read_exact_at(0, &mut y).unwrap();
        assert_eq!(x, y);
        assert_eq!(&y[8..12], &[1, 2, 3, 4]);
    }
}
