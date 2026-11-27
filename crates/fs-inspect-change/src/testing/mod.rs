//! Test tooling (feature `test-util`): running a tracker twice without a comparer. A
//! [`Recorded`] keeps what one scan left (its state, its sections, its files, the allocation)
//! and hands it to the next as its [`Baseline`], as a comparer that stores them would.

use fs_inspect_core::VolumeMapExt;
pub mod compare;

use crate::{
    Baseline, Continuity, DriverExtra, FileState, FsScanner, PrevFile, PrevState, Result, ScanContext, SnapshotHints,
};
use fs_inspect_core::range::list;
use fs_inspect_core::{ByteRange, Filesystem, VolumeMap};
use fs_inspect_io::DynSource;
use std::collections::BTreeMap;
use std::sync::Arc;

/// What `fs` allocates (the used ranges of its map, within the file system).
pub fn allocation(fs: &Arc<dyn Filesystem>) -> Result<Vec<ByteRange>> {
    Ok(space(fs)?.0)
}

/// What `fs` allocates, and what of it the map says reads as zeros.
fn space(fs: &Arc<dyn Filesystem>) -> Result<(Vec<ByteRange>, Vec<ByteRange>)> {
    let map = VolumeMap::of_filesystem(fs)?;
    let end = fs.info().size;
    Ok((list::clip(&map.used(), end), list::clip(&map.zero, end)))
}

/// What a scan left for the next one.
#[derive(Debug, Clone, Default)]
pub struct Recorded {
    pub state: Vec<u8>,
    pub sections: BTreeMap<u32, Vec<u8>>,
    pub files: BTreeMap<u64, PrevFile>,
    pub allocated: Vec<ByteRange>,
    /// What of `allocated` the volume map says reads as zeros (structures the file system relies
    /// on being zero).
    pub zero: Vec<ByteRange>,
    /// The scan's [`SnapshotHints::guest_offline`].
    pub offline: bool,
}

impl Baseline for Recorded {
    fn state(&self) -> Option<&[u8]> {
        (!self.state.is_empty()).then_some(self.state.as_slice())
    }
    fn section(&self, n: u32) -> Option<&[u8]> {
        self.sections.get(&n).map(Vec::as_slice)
    }
    fn file(&self, key: u64) -> Option<PrevFile> {
        self.files.get(&key).copied()
    }
    fn allocated(&self) -> Vec<ByteRange> {
        self.allocated.clone()
    }
}

/// One scan of a tracker.
#[derive(Debug)]
pub struct Scan {
    /// The files it reported, in order.
    pub files: Vec<FileState>,
    pub extra: DriverExtra,
    /// Its continuity with the previous scan (`Ok` without one).
    pub continuity: Continuity,
    /// What it leaves for the next scan.
    pub next: Recorded,
}

impl Scan {
    /// The file reported under `key`.
    pub fn file(&self, key: u64) -> Option<&FileState> {
        self.files.iter().find(|f| f.key == key)
    }
}

/// Scan `fs` (on `source`) with `sc` as a comparer would: continuity against `prev` first (a
/// broken one: the scan runs without it), then the files, then the state.
pub fn scan(
    sc: &dyn FsScanner,
    source: &DynSource,
    fs: &Arc<dyn Filesystem>,
    hints: &SnapshotHints,
    prev: Option<&Recorded>,
) -> Result<Scan> {
    let (allocated, zero) = space(fs)?;
    let mut session = sc.begin()?;
    let offline = hints.guest_offline && prev.is_some_and(|p| p.offline);
    let continuity = match prev {
        Some(p) => session.continuity(PrevState { state: &p.state, offline }),
        None => Continuity::Ok,
    };
    let usable = prev.filter(|_| continuity == Continuity::Ok);
    let cx = ScanContext {
        source,
        fs,
        hints,
        allocated: &allocated,
        prev: usable.map(|p| p as &dyn Baseline),
        offline: offline && usable.is_some(),
    };
    let mut files = Vec::new();
    let extra = session.scan_files(&cx, &mut |f| files.push(f))?;
    let state = session.state()?;
    let next = Recorded {
        state,
        sections: extra.sections.iter().cloned().collect(),
        files: files.iter().map(|f| (f.key, PrevFile { generation: f.generation, meta: f.meta, aux: f.aux })).collect(),
        allocated: allocated.clone(),
        zero,
        offline: hints.guest_offline,
    };
    Ok(Scan { files, extra, continuity, next })
}
