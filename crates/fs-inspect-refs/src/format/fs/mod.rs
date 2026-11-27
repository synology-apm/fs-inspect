//! The ReFS [`Filesystem`](fs_inspect_core::Filesystem): open (boot sector, superblock,
//! checkpoint, container table, sub-allocators), the used range stream of the Medium
//! allocator, the walk over every file and path lookup.

mod lookup;
mod ns;
mod open;
mod space;
mod tables;
mod verify;

use crate::format::container::ContainerMap;
use crate::format::files::{Directory, FileReader, Format};
use crate::format::layout::{BootSector, Checkpoint, Superblock, root, table};
use crate::format::log::LogState;
use crate::format::tree::{Addressing, PageReader, SeenPage, TreeWalk};
use fs_inspect_core::range::{Coalesce, Merge, Subtract};
use fs_inspect_core::{
    ByteRange, Confidence, Diagnostics, DriverContext, FsInfo, FsKind, IterCursor, Limits, RangeCursor, Result, Sniff,
};
use fs_inspect_io::DynSource;
use space::MediumIter;
use std::sync::Arc;
use tables::root_of;

/// An opened ReFS volume.
#[derive(Debug)]
pub struct RefsFs {
    info: FsInfo,
    boot: BootSector,
    sb: Superblock,
    cp: Checkpoint,
    reader: PageReader,
    map: Arc<ContainerMap>,
    clusters: u64,
    /// Used ranges besides the Medium allocator's (fixed structures, the pages of the tables
    /// read at open, the sub-allocators), sorted and coalesced.
    extra: Vec<ByteRange>,
    /// The clusters the sub-allocators' rows cover but do not allocate, sorted and coalesced:
    /// unused, though the Medium allocator hands their containers out whole.
    sub_free: Vec<ByteRange>,
    limits: Limits,
    diag: Diagnostics,
    /// The tables the Object ID table lists and the pages read for them, read once.
    objects: std::sync::OnceLock<(Vec<Directory>, Vec<SeenPage>)>,
    /// The security table's descriptors by key, read once.
    security: std::sync::OnceLock<Result<std::collections::HashMap<crate::format::files::SecurityKey, Vec<u8>>>>,
    /// [`RefsFs::log_state`], read once.
    log: std::sync::OnceLock<Result<Option<LogState>>>,
    /// The records the listings gave last, while a hold lives.
    listed: fs_inspect_core::Held<ns::Listed>,
}

/// The ReFS boot sector: `High` when its checksum is valid, `Medium` otherwise.
pub fn probe(s: &Sniff<'_>) -> Option<(FsKind, Confidence)> {
    if !crate::format::layout::has_magic(s.head) {
        return None;
    }
    let ok = BootSector::parse(s.head).is_ok_and(|b| b.checksum_ok);
    Some((FsKind::Refs, if ok { Confidence::High } else { Confidence::Medium }))
}

/// Open the ReFS volume starting at offset 0 of `src`.
pub fn open(src: DynSource, ctx: &DriverContext) -> Result<Arc<dyn fs_inspect_core::Filesystem>> {
    Ok(Arc::new(RefsFs::open(src, ctx)?))
}

impl RefsFs {
    /// Messages reported while opening and reading (tests).
    #[cfg(test)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub(crate) fn warnings(&self) -> Vec<String> {
        self.diag.own().into_iter().map(|d| d.message).collect()
    }

    pub fn boot_sector(&self) -> &BootSector {
        &self.boot
    }

    pub fn superblock(&self) -> &Superblock {
        &self.sb
    }

    /// The checkpoint in use.
    pub fn checkpoint(&self) -> &Checkpoint {
        &self.cp
    }

    /// Reads pages of the volume, translating virtual addresses.
    pub fn reader(&self) -> &PageReader {
        &self.reader
    }

    pub fn container_map(&self) -> &ContainerMap {
        &self.map
    }

    /// The clusters inside the sub-allocators' rows that they do not allocate.
    pub fn sub_allocator_free(&self) -> &[ByteRange] {
        &self.sub_free
    }

    /// Used ranges that do not come from the Medium allocator.
    pub fn extra_ranges(&self) -> &[ByteRange] {
        &self.extra
    }

    /// Reads the directories and files of the checkpoint in use.
    pub fn file_reader(&self) -> FileReader<'_> {
        FileReader {
            reader: &self.reader,
            map: &self.map,
            format: Format::of(self.boot.major, self.boot.minor),
            clusters: self.clusters,
            limits: &self.limits,
        }
    }
}

impl fs_inspect_core::sealed::Fs for RefsFs {}

impl fs_inspect_core::Filesystem for RefsFs {
    fn default_excludes(&self) -> &'static [fs_inspect_core::DefaultExclude] {
        fs_inspect_core::exclude::WINDOWS_DEFAULTS
    }

    fn info(&self) -> &FsInfo {
        &self.info
    }

    fn namespace(self: Arc<Self>) -> Option<Arc<dyn fs_inspect_core::Namespace>> {
        Some(self)
    }

    fn file_map(&self) -> Option<&dyn fs_inspect_core::FileMap> {
        Some(self)
    }

    /// From the log: no page at or past the checkpoint's position, clean. Pages there may hold
    /// changes the checkpoint does not (replayed at mount), but a clean dismount writes some
    /// too, and what they hold is not read: not known then.
    fn verify(&self, scope: &fs_inspect_core::VerifyScope) -> Result<()> {
        verify::verify(self, scope)
    }

    fn consistency(&self) -> fs_inspect_core::Consistency {
        use fs_inspect_core::Consistency;
        match self.log_state() {
            Ok(Some(l)) if l.last >= self.cp.log_lsn => {
                Consistency::Unknown("the log has pages at or past the checkpoint's position".into())
            }
            Ok(Some(_)) => Consistency::Clean,
            Ok(None) => Consistency::Unknown("the log could not be placed".into()),
            Err(e) => Consistency::Unknown(format!("the log could not be read: {e}")),
        }
    }

    fn implicit_exclusions(&self) -> Result<Vec<ByteRange>> {
        self.vss_storage()
    }

    fn allocated(self: Arc<Self>) -> Result<Box<dyn RangeCursor>> {
        let root = root_of(&self.cp, root::MEDIUM_ALLOCATOR)?;
        let walk = TreeWalk::new(self.reader.clone(), root, Addressing::Virtual, table::MEDIUM_ALLOCATOR, &self.limits);
        let extra = self.extra.clone();
        let sub_free = self.sub_free.clone();
        let medium = MediumIter::new(walk, u64::from(self.reader.cluster_bytes()), self.clusters, self.diag.clone());
        // The sub-allocators hand out the clusters of the containers the Medium allocator gives
        // them: the ones they do not allocate are unused.
        let medium = Subtract::new(Coalesce::new(medium), sub_free.into_iter());
        let it = Coalesce::new(Merge::new(medium, extra.into_iter()));
        Ok(Box::new(IterCursor::new(it)))
    }
}
