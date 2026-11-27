//! [`RecoveryAware`]: what a volume's map takes from its two readings, on disk and as recovery
//! leaves it ([`crate::recovery`]), combined by one rule wherever the map, a whole-disk map or
//! a change tracker asks:
//!
//! - used: what either reading uses (a block allocated only in the log, its data already in
//!   place, is copied; the log itself is used on disk);
//! - zero: what both read as zero (the file system's must-be-zero ranges, files' unwritten
//!   extents);
//! - exclusions: the recovered files (what a restore shows after the OS replays the log), but
//!   never a range recovery rewrites: the OS replay reads what is there;
//! - the file system's end: the larger (a resize only in the log).
//!
//! A volume not replayed reads the same both ways.

use crate::recovery::View;
use crate::volume::Volume;
use fs_inspect_core::range::{BoxRanges, Coalesce, MergeInput, MergeN, intersect, sort_coalesce, subtract};
use fs_inspect_core::{ByteRange, Checksums, CursorIter, Error, Filesystem, Result};
use std::sync::Arc;

pub(crate) struct RecoveryAware {
    on_disk: Arc<dyn Filesystem>,
    /// `None`: not replayed (the on-disk reading is the only one).
    recovered: Option<Arc<dyn Filesystem>>,
    /// The ranges recovery rewrites ([`Replayed::targets`](fs_inspect_core::Replayed::targets)).
    targets: Vec<ByteRange>,
}

impl RecoveryAware {
    pub(crate) fn of(vol: &Volume) -> Result<Self> {
        let on_disk = vol.on_disk().clone();
        let (recovered, targets) = match vol.recovery()?.replayed() {
            Some(r) => (Some(vol.instance(View::Recovered, Checksums::Verify)?), r.targets()?),
            None => (None, Vec::new()),
        };
        Ok(RecoveryAware { on_disk, recovered, targets })
    }

    /// The instance the files are read from: as recovery leaves the volume.
    pub(crate) fn files(&self) -> &Arc<dyn Filesystem> {
        self.recovered.as_ref().unwrap_or(&self.on_disk)
    }

    /// Bytes of the volume the file system occupies: the larger reading.
    pub(crate) fn volume_bytes(&self) -> u64 {
        let on_disk = self.on_disk.info().size;
        self.recovered.as_ref().map_or(on_disk, |r| on_disk.max(r.info().size))
    }

    /// The allocated ranges, sorted and coalesced: either reading's.
    pub(crate) fn allocated(&self) -> Result<BoxRanges<Error>> {
        let stream = |fs: &Arc<dyn Filesystem>| -> Result<BoxRanges<Error>> {
            Ok(Box::new(Coalesce::new(CursorIter::new(fs.clone().allocated()?))))
        };
        let Some(recovered) = &self.recovered else { return stream(&self.on_disk) };
        Ok(Box::new(MergeN::new([MergeInput::Open(stream(&self.on_disk)?), MergeInput::Open(stream(recovered)?)])))
    }

    /// The file system's must-be-zero ranges ([`Filesystem::zero_ranges`]): both readings'.
    pub(crate) fn zero_ranges(&self) -> Result<Vec<ByteRange>> {
        let on_disk = self.on_disk.zero_ranges()?;
        match &self.recovered {
            None => Ok(on_disk),
            Some(r) => Ok(intersect(on_disk, r.zero_ranges()?).collect()),
        }
    }

    /// Files' zero ranges within `limit` (unwritten or preallocated extents, past the valid data
    /// length), on file systems that list files. Not replayed: what is
    /// [settled](fs_inspect_core::FileInfo::settled) on disk. Replayed: what the metadata on
    /// disk says, settled or not, that the recovered files say too: a log that turns such a
    /// range into data changes the recovered reading, and a replay that missed it leaves the
    /// range zero in both only if both readings agree. `check` runs per file (a cancel).
    pub(crate) fn file_zero(&self, limit: u64, check: &dyn Fn() -> Result<()>) -> Result<Vec<ByteRange>> {
        let of = |fs: &Arc<dyn Filesystem>, as_read: bool| -> Result<Option<Vec<ByteRange>>> {
            let Some(files) = fs.file_map() else { return Ok(None) };
            let mut zc = fs_inspect_core::ZeroCollector::new();
            files.for_each(&mut |f| {
                check()?;
                zc.add(&f.extents, if as_read { &f.zero_as_read } else { f.zero() });
                Ok(())
            })?;
            Ok(Some(zc.finish(&[ByteRange::new(0, limit)]).0))
        };
        let Some(on_disk) = of(&self.on_disk, self.recovered.is_some())? else { return Ok(Vec::new()) };
        match &self.recovered {
            None => Ok(on_disk),
            Some(r) => Ok(of(r, false)?.map_or_else(Vec::new, |rz| intersect(on_disk, rz).collect())),
        }
    }

    /// `excluded` (sorted and coalesced, from the recovered files) less what recovery rewrites.
    pub(crate) fn keep_targets(&self, excluded: Vec<ByteRange>) -> Vec<ByteRange> {
        if self.targets.is_empty() {
            return excluded;
        }
        sort_coalesce(subtract(excluded, self.targets.iter().copied()).collect())
    }
}
