//! What the intents a log left unfinished do to files, as log recovery finishes them: the
//! mapping updates of `BUI`s and the range exchanges of `XMI`s, kept in log order by
//! [`recover`](crate::format::recover) ([`FileUpdates`]) and applied by the instance over the
//! replay to the mappings and sizes it reads ([`XfsFs::fork_extents`](crate::XfsFs),
//! [`XfsFs::parse_inode`](crate::XfsFs)).
//!
//! An exchange makes two files' mappings depend on each other: the mapping of an inode is the
//! result of every update of the inodes exchanges link it to, applied in log order to the
//! mappings those inodes have on disk ([`FileUpdates::mapping`]).
//!
//! Once recovery is done, a mount releases each inode it finished an intent of, and frees what
//! a regular file maps past its end of file (unless the file is preallocated or append-only),
//! the end being the size the inode had when recovery loaded it:
//! an exchange's new size (`SET_SIZES`) is only written to disk. A block an exchange moves past
//! that end is unmapped then (and freed), though the new size covers it: the file reads zeros
//! there. The mapping is read the same way ([`Eof`]).

use crate::format::geom::Geom;
use crate::format::inode::EXTENT_UNWRITTEN;
use fs_inspect_core::FileExtent as Extent;
use fs_inspect_core::{Error, ExtentBuilder, ExtentOrder, Result};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// A block mapping update (an `xfs_map_extent` of a `BUI`) of a fork of an inode. `map`:
/// `blocks` blocks from `startblock` (a file system block number) mapped at `startoff`,
/// unwritten or not; otherwise whatever the fork maps in that range unmapped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BmapUpdate {
    pub attr_fork: bool,
    pub map: bool,
    pub unwritten: bool,
    pub startoff: u64,
    pub startblock: u64,
    pub blocks: u64,
}

/// A range exchange left to finish (an `XMI`): `blocks` blocks of a fork of `ino1` from
/// `startoff1` and of `ino2` from `startoff2` exchange their mappings; with `ino1_written`,
/// only where `ino1` maps written blocks. `sizes`: the sizes the two files get once it is done.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Exchange {
    pub ino1: u64,
    pub ino2: u64,
    pub attr_fork: bool,
    pub startoff1: u64,
    pub startoff2: u64,
    pub blocks: u64,
    pub ino1_written: bool,
    pub sizes: Option<(u64, u64)>,
}

/// What a fork's mapping ends at once recovery releases the inode (see the [module](self)):
/// `Some(size)`, the size the inode had before the updates, for a regular file whose blocks
/// past its end of file are freed; `None` otherwise.
pub type Eof = Option<u64>;

/// One update of a file an intent left unfinished.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileUpdate {
    Bmap { ino: u64, update: BmapUpdate },
    Exchange(Exchange),
}

impl FileUpdate {
    fn inodes(&self) -> impl Iterator<Item = u64> {
        let (a, b) = match self {
            FileUpdate::Bmap { ino, .. } => (*ino, None),
            FileUpdate::Exchange(x) => (x.ino1, Some(x.ino2)),
        };
        std::iter::once(a).chain(b)
    }
}

/// The updates intents left unfinished make to files, in log order (see the [module](self)).
#[derive(Debug, Default)]
pub struct FileUpdates {
    list: Vec<FileUpdate>,
    /// The updates of each inode (indices into `list`, ascending).
    by_inode: BTreeMap<u64, Vec<usize>>,
    /// The size an exchange leaves an inode (the last one in log order).
    sizes: BTreeMap<u64, u64>,
}

impl FileUpdates {
    /// The updates `list`, in log order.
    pub fn new(list: Vec<FileUpdate>) -> Self {
        let mut by_inode = BTreeMap::<u64, Vec<usize>>::new();
        let mut sizes = BTreeMap::new();
        for (i, u) in list.iter().enumerate() {
            for ino in u.inodes() {
                let v = by_inode.entry(ino).or_default();
                if v.last() != Some(&i) {
                    v.push(i);
                }
            }
            if let FileUpdate::Exchange(Exchange { ino1, ino2, sizes: Some((s1, s2)), .. }) = u {
                sizes.insert(*ino1, *s1);
                sizes.insert(*ino2, *s2);
            }
        }
        FileUpdates { list, by_inode, sizes }
    }

    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    /// The inodes updated.
    pub fn len(&self) -> usize {
        self.by_inode.len()
    }

    /// Whether inode `ino` is updated.
    pub fn touches(&self, ino: u64) -> bool {
        self.by_inode.contains_key(&ino)
    }

    /// The size an exchange leaves inode `ino`, if one sets it.
    pub fn size(&self, ino: u64) -> Option<u64> {
        self.sizes.get(&ino).copied()
    }

    /// The mapping of a fork of inode `ino` (the attribute fork with `attr`) once the updates
    /// are applied and recovery has released the inode (`eof`, see [`Eof`]): `on_disk(ino,
    /// attr)` reads the mapping a fork of an inode has on disk, for `ino` and every inode
    /// exchanges link it to (see the [module](self)).
    pub fn mapping(
        &self,
        g: &Geom,
        ino: u64,
        attr: bool,
        eof: Eof,
        on_disk: &mut dyn FnMut(u64, bool) -> Result<Vec<Extent>>,
    ) -> Result<Vec<Extent>> {
        let mapped = self.updated(g, ino, attr, on_disk)?;
        match eof {
            Some(size) if !attr && self.touches(ino) => {
                let end = size.div_ceil(g.bs()).saturating_mul(g.bs());
                Ok(cut(mapped, end, u64::MAX).0)
            }
            _ => Ok(mapped),
        }
    }

    /// The mapping of a fork of inode `ino` with the updates applied (see [`Self::mapping`]).
    fn updated(
        &self,
        g: &Geom,
        ino: u64,
        attr: bool,
        on_disk: &mut dyn FnMut(u64, bool) -> Result<Vec<Extent>>,
    ) -> Result<Vec<Extent>> {
        if !self.touches(ino) {
            return on_disk(ino, attr);
        }
        // The inodes exchanges link to `ino`, and their updates in log order.
        let mut group = BTreeSet::from([ino]);
        let mut todo = vec![ino];
        let mut updates = BTreeSet::new();
        while let Some(i) = todo.pop() {
            for &k in self.by_inode.get(&i).into_iter().flatten() {
                updates.insert(k);
                for other in self.list[k].inodes() {
                    if group.insert(other) {
                        todo.push(other);
                    }
                }
            }
        }
        let mut forks: HashMap<(u64, bool), Vec<Extent>> = HashMap::new();
        let mut fork = |forks: &mut HashMap<(u64, bool), Vec<Extent>>, key: (u64, bool)| -> Result<Vec<Extent>> {
            match forks.remove(&key) {
                Some(v) => Ok(v),
                None => on_disk(key.0, key.1),
            }
        };
        for k in updates {
            match self.list[k] {
                FileUpdate::Bmap { ino, update } => {
                    let key = (ino, update.attr_fork);
                    let v = apply_bmap(g, fork(&mut forks, key)?, &update)?;
                    forks.insert(key, v);
                }
                FileUpdate::Exchange(x) => {
                    let (k1, k2) = ((x.ino1, x.attr_fork), (x.ino2, x.attr_fork));
                    if k1 == k2 {
                        return Err(Error::corrupt(format!("xfs XMI exchanging inode {} with itself", x.ino1)));
                    }
                    let (a, b) = (fork(&mut forks, k1)?, fork(&mut forks, k2)?);
                    let (a, b) = exchange(g, a, b, &x)?;
                    forks.insert(k1, a);
                    forks.insert(k2, b);
                }
            }
        }
        match forks.remove(&(ino, attr)) {
            Some(v) => Ok(v),
            None => on_disk(ino, attr),
        }
    }
}

/// The byte range `[lo, hi)` of blocks `startoff`, `blocks` long.
fn byte_range(g: &Geom, startoff: u64, blocks: u64) -> Result<(u64, u64)> {
    let bs = g.bs();
    let overflow = || Error::corrupt("xfs logged file range overflows");
    let lo = startoff.checked_mul(bs).ok_or_else(overflow)?;
    let hi = blocks.checked_mul(bs).and_then(|n| lo.checked_add(n)).ok_or_else(overflow)?;
    Ok((lo, hi))
}

/// `extents` split at `lo` and `hi`: what is outside `[lo, hi)`, and the pieces inside.
fn cut(extents: Vec<Extent>, lo: u64, hi: u64) -> (Vec<Extent>, Vec<Extent>) {
    let (mut out, mut inside) = (Vec::with_capacity(extents.len() + 2), Vec::new());
    for e in extents {
        let (start, end) = (e.logical, e.logical.saturating_add(e.length));
        if end <= lo || start >= hi {
            out.push(e);
            continue;
        }
        let piece = |from: u64, to: u64| Extent {
            logical: from,
            physical: e.physical.map(|p| p + (from - start)),
            length: to - from,
            flags: e.flags,
        };
        if start < lo {
            out.push(piece(start, lo));
        }
        inside.push(piece(start.max(lo), end.min(hi)));
        if end > hi {
            out.push(piece(hi, end));
        }
    }
    (out, inside)
}

/// `extents` with `more` added, sorted and joined where they continue each other; overlapping
/// pieces are damage.
fn join(mut extents: Vec<Extent>, more: Vec<Extent>) -> Result<Vec<Extent>> {
    extents.extend(more);
    extents.sort_by_key(|e| e.logical);
    let mut b = ExtentBuilder::new(ExtentOrder::Ascending, extents.len().max(1));
    for e in extents {
        b.push(e)?;
    }
    b.finish()
}

/// `extents` with mapping update `u` applied: its range unmapped, then mapped when it maps.
pub fn apply_bmap(g: &Geom, extents: Vec<Extent>, u: &BmapUpdate) -> Result<Vec<Extent>> {
    let (lo, hi) = byte_range(g, u.startoff, u.blocks)?;
    let (rest, _) = cut(extents, lo, hi);
    let mut added = Vec::new();
    if u.map {
        if u.blocks == 0 {
            return Err(Error::corrupt("xfs logged mapping of no blocks"));
        }
        let (physical, length) = g.fsb_range(u.startblock, u.blocks).ok_or_else(|| {
            Error::corrupt(format!("xfs logged mapping {:#x}+{} outside the file system", u.startblock, u.blocks))
        })?;
        let flags = if u.unwritten { EXTENT_UNWRITTEN } else { 0 };
        added.push(Extent { logical: lo, physical: Some(physical), length, flags });
    }
    join(rest, added)
}

/// The two mappings `a` (of `x.ino1`) and `b` (of `x.ino2`) once exchange `x` is done.
fn exchange(g: &Geom, a: Vec<Extent>, b: Vec<Extent>, x: &Exchange) -> Result<(Vec<Extent>, Vec<Extent>)> {
    let (lo1, hi1) = byte_range(g, x.startoff1, x.blocks)?;
    let (lo2, _) = byte_range(g, x.startoff2, x.blocks)?;
    // The parts of the range exchanged, as offsets into it: all of it, or (`ino1_written`)
    // where `ino1` maps written blocks.
    let parts: Vec<(u64, u64)> = if x.ino1_written {
        let (_, inside) = cut(a.clone(), lo1, hi1);
        inside
            .iter()
            .filter(|e| e.physical.is_some() && e.flags & EXTENT_UNWRITTEN == 0)
            .map(|e| (e.logical - lo1, e.logical - lo1 + e.length))
            .collect()
    } else {
        vec![(0, hi1 - lo1)]
    };
    let (mut a, mut b) = (a, b);
    for (from, to) in parts {
        let (rest_a, mut from_a) = cut(a, lo1 + from, lo1 + to);
        let (rest_b, mut from_b) = cut(b, lo2 + from, lo2 + to);
        for e in &mut from_a {
            e.logical = e.logical - lo1 + lo2;
        }
        for e in &mut from_b {
            e.logical = e.logical - lo2 + lo1;
        }
        a = join(rest_a, from_b)?;
        b = join(rest_b, from_a)?;
    }
    Ok((a, b))
}
