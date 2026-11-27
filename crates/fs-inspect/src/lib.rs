//! fs-inspect: reading disk images and snapshot devices: their containers, partition tables,
//! volume managers and file systems, without mounting anything.
//!
//! Supported: NTFS, FAT12/16/32, exFAT, ext2/3/4, XFS, btrfs, APFS, ReFS 3.x, ZFS (a leaf
//! vdev of a pool without dRAID, read with the pool's other leaves given in the same set).
//! File systems on volume managers (LVM2, md RAID, Windows dynamic disks), on one disk or
//! spanning several, are read through their members.
//!
//! One way in, three steps:
//!
//! 1. [`DiskSet::open`]: the disks to read together, each a [`DiskSpec`] (an image file: raw,
//!    split raw, VHD, VHDX; a device; or any caller-supplied [`BlockSource`], such as a
//!    network disk). A single disk is a set of one. [`DiskSet::volumes`] lists every volume (MBR
//!    / GPT partitions, bare volumes, the volumes on logical volumes, ZFS pools; never a
//!    container member) with where it is, its file system, whether it can be read and a stable
//!    [`key`](VolumeEntry::key). The structure under them (each device's partitions and their
//!    roles, the containers, what every byte is) is [`DiskSet::partitions`],
//!    [`DiskSet::containers`] and [`DiskSet::layout`].
//! 2. [`DiskSet::open_volume`]: one opened file system ([`Volume`]).
//! 3. Then:
//!    - [`Volume::map`] / [`DiskSet::map`]: what every byte of a volume or a whole disk
//!      is ([`Map`]: data, zero, unused, excluded), exact, in blocks, or as a [`Bitmap`];
//!    - [`Volume::browse`]: its file system's tree ([`fs`]): roots, directories, metadata and
//!      file content; [`export`] copies a tree out;
//!    - [`Volume::verify`] / [`DiskSet::verify`]: every checksum and copy checked.
//!
//! A volume's map is in volume coordinates: the volume's offset in its device plus
//! `range.offset` is the offset in the device ([`Map::moved_to`]). A device's map is in its
//! coordinates.
//!
//! What the library worked around (damaged structures it routed around, exclusions it could
//! not apply) is reported as [`Diagnostic`]s: [`DiskSet::diagnostics`],
//! [`Volume::diagnostics`].
//!
//! A partition without a recognized file system opens as a raw volume ([`FsKind::Raw`]): all
//! data.
//!
//! ```no_run
//! use fs_inspect::{BlockClass, DeviceMapOptions, DeviceRef, DiskIndex, DiskSet, DiskSpec, OpenOptions, VolumeMapOptions};
//! use fs_inspect::range::Granularity;
//! let set = DiskSet::open(&[DiskSpec::path("disk.vhdx")], &OpenOptions::default(), None)?;
//! for v in set.volumes(None)? {
//!     println!("{} {} {:?} {:?}", v.index, v.key, v.fs_kind, v.location);
//! }
//! let vol = set.open_volume(set.only_volume(None)?, None)?;
//! let map = vol.map(&VolumeMapOptions::default(), None)?;
//! for r in map.blocks(BlockClass::Used, None)?.iter() {
//!     println!("{} {}", r.offset, r.length);
//! }
//! let disk = DeviceRef::Disk(DiskIndex(0));
//! let used = set.map(disk, &DeviceMapOptions::default(), None)?.bitmap(BlockClass::Used, Some(Granularity::new(4096)?))?;
//! println!("{} of {} blocks used", used.count(), used.shape().blocks);
//! # Ok::<(), fs_inspect::Error>(())
//! ```
//!
//! # Threads
//!
//! [`DiskSet`] and [`Volume`] are `Send + Sync` and cheap to clone. Reads a caller lists go out
//! [`OpenOptions::queue_depth`] at a time. Every call that may read takes a [`CancelToken`]
//! last (`cancel`): cancelled from any thread, its reads fail with [`ErrorKind::Cancelled`].
//! The token of a call that makes a handle ([`DiskSet::open`], [`Volume::browse`], a
//! directory, a walk, a file, ...) is the handle's and covers every later read of it, beside
//! each call's own (the rule: docs/design/overview.md, "Cancelling").
//! Readers that read at a queue depth do so on helper threads; [`set_max_helper_threads`]
//! caps those of the whole process, and [`set_cache_budget`] the memory the drivers' caches of
//! every open volume hold together.
#![forbid(unsafe_code)]
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

mod ahead;
pub mod catalog;
#[cfg(feature = "change")]
pub mod change;
mod device;
mod disk;
mod drivers;
mod exclude;
pub mod export;
pub mod fs;
pub mod guest;
pub mod layout;
mod listing;
mod map;
mod pipeline;
mod recovery;
mod registry;
mod set;
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod testns;
pub mod verify;
mod volume;
pub(crate) mod walk;
mod walker;

pub use device::{
    DEFAULT_CACHE_BYTES, DEFAULT_QUEUE_DEPTH, Device, DeviceInfo, DiskSpec, OpenOptions, PartitionEntry,
    PartitionEntryKind, PartitionInfo, PartitionType, SourceOrigin,
};
pub use exclude::ExcludePattern;
pub use fs_inspect_core::memo::{cache_bytes, set_cache_budget};
pub use fs_inspect_core::names::Named;
pub use fs_inspect_core::{
    ByteRange, DiagCode, Diagnostic, Error, ErrorKind, FsFamily, FsInfo, FsKind, Limits, Location, MemberRole,
    MemberRoleKind, Result, Scope, Severity, Space,
};
pub use fs_inspect_disk::{ContainerFormat, DiskId, DiskIdKind, PartitionScheme, disk_id};
pub use fs_inspect_io::{BlockSource, CancelToken, DynSource, IoCounts, IoStats};
pub use map::{Bitmap, BitmapShape, BlockClass, Blocks, DeviceMapOptions, Map, VolumeMapOptions};
pub use recovery::{NotReplayed, NotReplayedKind, ReplaySummary, StoreKind, VolumeState, VolumeStateKind};
pub use set::{
    ContainerIndex, ContainerInfo, ContainerKind, ContainerStatus, DeviceRef, DeviceRefKind, DiskExtent, DiskIndex,
    DiskProblem, DiskSet, ExtentInfo, LogicalId, LogicalIndex, LogicalInfo, MAX_SET_DISKS, MemberIndex, MemberInfo,
    MemberLocation, Partition, PartitionRole, PartitionRoleKind, PartitionTable, PartitionTableKind, Readability,
    SetDisk, SetDiskKind, VolumeEntry, VolumeIndex, VolumeLocation, VolumeLocationKind, VolumeTail,
};
pub use volume::{Bound, FileContent, Reach, Volume, VolumeInfo};

/// Caps at `max` the helper threads that all readers of the process run at once.
///
/// The cap covers the threads that read ahead or keep reads in flight: a stream or a copied
/// range read ahead, the runs of a merged read at a queue depth, a listing's batches read
/// ahead. A call that finds no helper free does not wait: it reads on its own thread. This
/// keeps the threads of a server bounded however many callers read at once. Helpers are taken
/// as a call needs them, so a new cap applies to the helpers taken after it.
///
/// A walk ([`FsHandle::walker`](fs::FsHandle::walker), an export) runs on a thread of its own.
/// That thread counts against the cap while the walk runs, but it starts even when no helper
/// is free. [`DiskSet::catalog`] opens volumes on threads of its own, which the cap does not
/// count.
///
/// `Some(0)`: no helpers but a walk's thread. `None` (the default): no cap. May be called from
/// any thread at any time.
pub fn set_max_helper_threads(max: Option<usize>) {
    fs_inspect_io::ahead::set_max_helpers(max);
}

/// Byte ranges combined: [`RangeSet`](range::RangeSet), a set built by inserts in any order,
/// and streaming set operations on sorted range sequences, to combine a map's ranges with a
/// caller's own extents (e.g. an SDK's deduplicated file extents).
pub mod range {
    pub use fs_inspect_core::range::{
        BoxRanges, Granularity, RangeSet, coalesce, coarsen, complement, intersect, sort_coalesce, subtract, union,
    };
}

/// Sources of bytes: the read interface a caller implements to read what fs-inspect cannot
/// open itself, and the sources fs-inspect builds on.
pub mod io {
    pub use fs_inspect_io::error::OutOfRange;
    /// Sparse images (`.fsbs`: what `fs-inspect capture` writes, the test fixtures).
    pub use fs_inspect_io::sparse;
    pub use fs_inspect_io::{
        Caching, FileSource, MemSource, ReadEvent, SourceError, SourceErrorKind, checked, parts_of,
    };
}

/// Extension points for code that builds on fs-inspect's own layers: file system drivers,
/// sources that wrap other sources, the constructors of what drivers report. **No stability
/// promise**: anything here may change in any version (docs/api-stability.md).
pub mod unstable {
    pub use crate::volume::{filesystem, volume_source};
    pub use fs_inspect_core::{
        CloudInfoExt, DiagnosticExt, DirEntryExt, FindingExt, FsInfoExt, NodeInfoExt, ReplaySummaryExt, RootInfoExt,
        StatExt, StreamInfoExt, TimesExt, TimestampExt, UnixModeExt, VolumeMapExt, WantExt, WinAttrsExt, XattrExt,
    };

    /// APFS's own: the metadata of a container, in tiers, for a cache in front of a slow copy
    /// of it.
    pub mod apfs {
        use crate::{Error, Result, Volume};
        pub use fs_inspect_apfs::{MetaBlock, MetaClass, MetaList, MetaObj, MetaOptions, Tier};

        /// The metadata of the APFS container `v` (see [`fs_inspect_apfs::metadata`]): ranges
        /// relative to the container, `container_offset` set to the volume's offset.
        /// [`ErrorKind::InvalidArgument`](crate::ErrorKind) when `v` is not APFS.
        pub fn metadata(v: &Volume, opts: &MetaOptions, cancel: Option<&crate::CancelToken>) -> Result<MetaList> {
            let any: &dyn std::any::Any = &**v.on_disk();
            let fs = any
                .downcast_ref::<fs_inspect_apfs::ApfsFs>()
                .ok_or_else(|| Error::invalid_argument(format!("not an APFS container: {:?}", v.info().fs.kind)))?;
            let mut m = fs_inspect_io::cancel::with_bound(cancel, || fs_inspect_apfs::metadata(fs, opts))?;
            m.container_offset = v.info().offset;
            Ok(m)
        }
    }

    /// The file system drivers: probing, and the traits of what they open
    /// ([`Filesystem`](driver::Filesystem) is implemented only by fs-inspect's own drivers;
    /// [`Namespace`](driver::Namespace) is what [`FsHandle`](crate::fs::FsHandle) browses).
    pub mod driver {
        pub use crate::registry::{Probe, driver_for, drivers, probe_fs, probe_volume};
        pub use fs_inspect_core::{
            Confidence, Driver, DriverContext, Filesystem, Namespace, RangeCursor, SNIFF_BYTES, Sniff, VolumePath,
        };

        /// The change tracker of a file system opened through this layer (feature `change`):
        /// `None` when its kind has none. A [`Volume`](crate::Volume)'s is
        /// [`change::tracker`](crate::change::tracker).
        #[cfg(feature = "change")]
        pub fn tracker(
            fs: std::sync::Arc<dyn Filesystem>,
        ) -> Option<fs_inspect_change::Result<Box<dyn crate::change::FsScanner>>> {
            crate::change::driver_tracker(fs)
        }
    }

    /// Sources that wrap other sources, and the tools a source or a reader uses.
    pub mod io {
        pub use fs_inspect_io::cancel::check_call;
        pub use fs_inspect_io::{AlignedSource, CancelSource, CountingSource, OffsetSource, ReadEventExt, thread_slot};

        /// Reading many small ranges in merged runs: [`plan`](batch::plan) groups them,
        /// [`read_runs`](batch::read_runs) reads the runs with a bounded queue depth.
        pub mod batch {
            pub use fs_inspect_io::batch::{BATCH_BYTES, GAP_BYTES, Run, plan, read_runs};
        }
    }
}
