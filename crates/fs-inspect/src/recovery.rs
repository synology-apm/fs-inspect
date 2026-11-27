//! A volume's two readings: as it is on disk, and as its file system's recovery leaves it (a
//! crash-consistent snapshot's log replayed in memory, nothing written). See
//! [`Volume::state`](crate::Volume::state).
//!
//! The rule (docs/design/overview.md, "Recovery"): bytes as they are, meaning as recovered. What is
//! read and copied is the volume's bytes ([`volume_source`](crate::unstable::volume_source)); which
//! of them are used and which files exist is what recovery leaves: the map counts used what either
//! reading uses and zero what both read as zero, browsing reads the recovered files; change
//! tracking dates the bytes as they are on disk (principle 5).
//!
//! [`Instances`] keeps a volume's instances, opened the first time one is asked for: the one
//! opened on disk, the one that reads with fewer checksums ([`Checksums::Trust`]), and the same
//! two over the replay, which is made once.

use fs_inspect_core::{Checksums, Consistency, Driver, DriverContext, Error, Filesystem, Replayed, Result};
use fs_inspect_io::DynSource;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

pub use fs_inspect_core::ReplaySummary;
pub use fs_inspect_core::store::StoreKind;

fs_inspect_io::tagged_enum! {
    /// Whether a volume's metadata is final, and what was done when it was not
    /// ([`Volume::state`](crate::Volume::state)).
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum VolumeState ("volume state") kind VolumeStateKind {
        /// Consistent on disk: nothing to replay.
        Clean = 1 => "clean",
        /// Inconsistent on disk (a crash-consistent snapshot); its log was replayed in memory, and
        /// the map and browsing read what recovery leaves.
        Recovered(ReplaySummary) = 2 => "recovered",
        /// Inconsistent on disk (`why`) and read as it is, with the file system's conservative
        /// rules: `allocation_covered` tells whether the map still includes everything recovery
        /// would allocate (otherwise a block allocated only in the log may be reported unused).
        Inconsistent { why: String, allocation_covered: bool, not_replayed: NotReplayed } = 3 => "inconsistent",
        /// The file system keeps no clean / dirty state this library reads, or it could not be read
        /// (`why`).
        Unknown(String) = 4 => "unknown",
    }
}

impl VolumeState {
    /// Whether the volume is consistent on disk ([`Clean`](Self::Clean)).
    pub fn is_consistent(&self) -> bool {
        matches!(self, VolumeState::Clean)
    }
}

fs_inspect_io::tagged_enum! {
    /// Why an inconsistent volume's log was not replayed ([`VolumeState::Inconsistent`]).
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum NotReplayed ("not replayed reason") kind NotReplayedKind {
        /// The caller turned replay off ([`OpenOptions::replay`](crate::OpenOptions::replay)).
        Disabled = 1 => "disabled",
        /// This file system's log is not replayed by this library (FAT's dirty flag, ReFS).
        Unsupported = 2 => "unsupported",
        /// The replay failed with `error`: a log this library cannot replay exactly, damaged, or no
        /// room to keep it ([`NoSpace`](crate::ErrorKind::NoSpace),
        /// [`Limit`](crate::ErrorKind::Limit)).
        Failed { error: Error } = 3 => "failed",
    }
}

/// Which reading of a volume an instance gives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum View {
    OnDisk,
    Recovered,
}

/// The outcome of a volume's replay, kept once made (a cancel is not: it is tried again).
#[derive(Debug, Clone)]
pub(crate) enum Recovery {
    /// Consistent on disk, or a state not known: nothing to replay.
    NotNeeded,
    Done(Arc<dyn Replayed>),
    NotReplayed(NotReplayed),
}

impl Recovery {
    pub(crate) fn replayed(&self) -> Option<&Arc<dyn Replayed>> {
        match self {
            Recovery::Done(r) => Some(r),
            _ => None,
        }
    }
}

/// How a volume's file system was opened: to open it again with other checks or over a replay.
#[derive(Clone)]
pub(crate) struct Opener {
    pub(crate) driver: &'static Driver,
    pub(crate) ctx: DriverContext,
}

/// A volume's instances (see the [module](self)).
pub(crate) struct Instances {
    /// Opened on disk with every checksum computed ([`Checksums::Verify`]).
    on_disk: Arc<dyn Filesystem>,
    /// `None`: a raw volume (one instance for everything).
    opener: Option<Opener>,
    /// Whether to replay ([`OpenOptions::replay`](crate::OpenOptions::replay)).
    replay: bool,
    recovery: Mutex<Option<Recovery>>,
    opened: Mutex<HashMap<(View, Checksums), Arc<dyn Filesystem>>>,
}

impl std::fmt::Debug for Instances {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Instances").field("on_disk", &self.on_disk.info().kind).finish_non_exhaustive()
    }
}

impl Instances {
    pub(crate) fn new(on_disk: Arc<dyn Filesystem>, opener: Option<Opener>, replay: bool) -> Self {
        Instances { on_disk, opener, replay, recovery: Mutex::new(None), opened: Mutex::default() }
    }

    /// The instance opened on disk with every checksum.
    pub(crate) fn on_disk(&self) -> &Arc<dyn Filesystem> {
        &self.on_disk
    }

    /// The volume's replay, made the first time (see [`Recovery`]).
    pub(crate) fn recovery(&self) -> Result<Recovery> {
        let mut kept = self.recovery.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(r) = &*kept {
            return Ok(r.clone());
        }
        let r = match self.on_disk.consistency() {
            Consistency::Inconsistent { .. } if !self.replay => Recovery::NotReplayed(NotReplayed::Disabled),
            Consistency::Inconsistent { .. } => {
                let started = std::time::Instant::now();
                match tracing::debug_span!("fs.replay").in_scope(|| self.on_disk.replay()) {
                    None => Recovery::NotReplayed(NotReplayed::Unsupported),
                    Some(Ok(r)) => {
                        tracing::debug!(summary = ?r.summary(), elapsed = ?started.elapsed(), "log replayed in memory");
                        Recovery::Done(r)
                    }
                    Some(Err(e)) if e.is_cancelled() => return Err(e),
                    Some(Err(e)) => {
                        tracing::debug!(error = %e, "log not replayed; the volume is read as on disk");
                        Recovery::NotReplayed(NotReplayed::Failed { error: e })
                    }
                }
            }
            _ => Recovery::NotNeeded,
        };
        *kept = Some(r.clone());
        Ok(r)
    }

    /// Why replays were kept in memory rather than in scratch files, when they were.
    pub(crate) fn scratch_fell_back(&self) -> Option<String> {
        self.opener.as_ref()?.ctx.scratch.fell_back().map(str::to_owned)
    }

    /// The state [`Volume::state`](crate::Volume::state) reports.
    pub(crate) fn state(&self) -> Result<VolumeState> {
        Ok(match self.on_disk.consistency() {
            Consistency::Clean => VolumeState::Clean,
            Consistency::Inconsistent { why, allocation_covered, .. } => match self.recovery()? {
                Recovery::Done(r) => VolumeState::Recovered(r.summary()),
                Recovery::NotReplayed(not_replayed) => {
                    VolumeState::Inconsistent { why, allocation_covered, not_replayed }
                }
                Recovery::NotNeeded => {
                    VolumeState::Inconsistent { why, allocation_covered, not_replayed: NotReplayed::Unsupported }
                }
            },
            Consistency::Unknown(why) => VolumeState::Unknown(why),
            // A state added later reads as not known.
            other => VolumeState::Unknown(format!("{other:?}")),
        })
    }

    /// The instance that reads `view` with `checksums`, opened from `source` the first time:
    /// the recovered view of a volume not replayed is its on-disk one, and a driver without
    /// checksums to skip ([`Driver::validates`]) has one instance for both.
    pub(crate) fn get(&self, source: &DynSource, view: View, checksums: Checksums) -> Result<Arc<dyn Filesystem>> {
        let Some(o) = &self.opener else { return Ok(self.on_disk.clone()) };
        let checksums = if o.driver.validates { checksums } else { Checksums::Verify };
        let replayed = match view {
            View::Recovered => self.recovery()?.replayed().cloned(),
            View::OnDisk => None,
        };
        let view = if replayed.is_some() { View::Recovered } else { View::OnDisk };
        if view == View::OnDisk && checksums == Checksums::Verify {
            return Ok(self.on_disk.clone());
        }
        if let Some(fs) = self.opened.lock().unwrap_or_else(PoisonError::into_inner).get(&(view, checksums)) {
            return Ok(fs.clone());
        }
        let fs = tracing::debug_span!("fs.open.again", ?view, ?checksums)
            .in_scope(|| open(o, source, &DriverContext { checksums, ..o.ctx.clone() }, replayed))?;
        let mut opened = self.opened.lock().unwrap_or_else(PoisonError::into_inner);
        Ok(opened.entry((view, checksums)).or_insert(fs).clone())
    }

    /// An instance of `view` opened again from `source` with `checksums` and `findings` (a
    /// verification's: not kept). `None`: a raw volume.
    pub(crate) fn reopen(
        &self,
        source: &DynSource,
        view: View,
        checksums: Checksums,
        findings: Option<Arc<dyn fs_inspect_core::FindingSink>>,
    ) -> Result<Option<Arc<dyn Filesystem>>> {
        let Some(o) = &self.opener else { return Ok(None) };
        let replayed = match view {
            View::Recovered => self.recovery()?.replayed().cloned(),
            View::OnDisk => None,
        };
        open(o, source, &DriverContext { checksums, findings, ..o.ctx.clone() }, replayed).map(Some)
    }
}

fn open(
    o: &Opener,
    source: &DynSource,
    ctx: &DriverContext,
    replayed: Option<Arc<dyn Replayed>>,
) -> Result<Arc<dyn Filesystem>> {
    match replayed {
        Some(r) => fs_inspect_core::fs::open_recovered(o.driver.open, source.clone(), ctx, r),
        None => (o.driver.open)(source.clone(), ctx),
    }
}
