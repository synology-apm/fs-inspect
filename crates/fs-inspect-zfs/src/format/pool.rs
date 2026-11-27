//! The leaf vdevs of a pool at hand: the device being opened and the other volumes given with it
//! (its peers), by top-level vdev. A pool spreads its metadata over all of its top-level vdevs,
//! so a leaf is read with the others. The legs of a mirror are interchangeable copies; the
//! children of a raidz vdev each hold their own columns.

use crate::format::blkptr::{Dva, VDEV_DATA_OFFSET};
use crate::format::raidz::Raidz;
use fs_inspect_io::DynSource;
use std::collections::BTreeMap;
use std::fmt;

/// How a top-level vdev spreads its space over its children.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Geometry {
    /// A disk or a file, or a mirror of them: every leaf holds the whole vdev.
    #[default]
    Plain,
    Raidz(Raidz),
}

/// One leaf vdev.
#[derive(Clone)]
pub struct Leaf {
    pub guid: u64,
    /// Its place among its top-level vdev's children (0 for a disk or a file).
    pub child: usize,
    pub src: DynSource,
}

impl fmt::Debug for Leaf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Leaf")
            .field("guid", &self.guid)
            .field("child", &self.child)
            .field("len", &self.src.size())
            .finish()
    }
}

/// A top-level vdev's leaves at hand.
#[derive(Debug, Clone, Default)]
pub struct Top {
    pub geometry: Geometry,
    /// Allocatable bytes (from the label).
    pub asize: u64,
    pub leaves: Vec<Leaf>,
}

impl Top {
    /// The leaf holding child `child`.
    pub fn child(&self, child: usize) -> Option<&Leaf> {
        self.leaves.iter().find(|l| l.child == child)
    }
}

/// Leaves by top-level vdev id, the device being opened first among its own.
#[derive(Debug, Clone, Default)]
pub struct VdevMap {
    tops: BTreeMap<u64, Top>,
}

impl VdevMap {
    /// Add a leaf of top-level vdev `top` (the first leaf of a top sets its shape); `false` (and
    /// nothing added) when a leaf with that guid is already there.
    pub fn add(&mut self, top: u64, geometry: Geometry, asize: u64, leaf: Leaf) -> bool {
        if self.tops.values().flat_map(|t| &t.leaves).any(|l| l.guid == leaf.guid) {
            return false;
        }
        self.tops.entry(top).or_insert_with(|| Top { geometry, asize, leaves: Vec::new() }).leaves.push(leaf);
        true
    }

    pub fn top(&self, top: u64) -> Option<&Top> {
        self.tops.get(&top)
    }

    /// The top-level vdevs with a leaf, by id.
    pub fn iter(&self) -> impl Iterator<Item = (u64, &Top)> {
        self.tops.iter().map(|(id, t)| (*id, t))
    }

    /// The leaves of top-level vdev `top` (none: not given).
    pub fn leaves(&self, top: u64) -> &[Leaf] {
        self.tops.get(&top).map_or(&[], |t| t.leaves.as_slice())
    }

    /// Keep the leaves `keep` accepts (dropping the tops left without one).
    pub fn retain(&mut self, mut keep: impl FnMut(u64, &Leaf) -> bool) {
        for (t, v) in self.tops.iter_mut() {
            v.leaves.retain(|l| keep(*t, l));
        }
        self.tops.retain(|_, v| !v.leaves.is_empty());
    }

    /// Whether `dva` lies within its top-level vdev at hand: within its allocatable space for a
    /// raidz vdev, within every leaf otherwise.
    pub fn within(&self, d: &Dva) -> bool {
        let Some(t) = self.tops.get(&d.vdev) else { return false };
        let Some(end) = d.offset.checked_add(d.asize) else { return false };
        match t.geometry {
            Geometry::Raidz(_) => end <= t.asize,
            Geometry::Plain => t.leaves.iter().all(|l| end.saturating_add(VDEV_DATA_OFFSET) <= l.src.size()),
        }
    }

    /// Number of top-level vdevs with a leaf.
    pub fn tops(&self) -> usize {
        self.tops.len()
    }

    /// Number of leaves.
    pub fn count(&self) -> usize {
        self.tops.values().map(|t| t.leaves.len()).sum()
    }
}
