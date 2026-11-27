//! The tables of the checkpoint in use: the container table and the allocators read at open,
//! the tables the Object ID table lists (read once), the log's place.

use super::RefsFs;
use super::space::{SubAllocated, medium_pages, sub_allocator};
use crate::format::container::ContainerMap;
use crate::format::files::{Directory, object};
use crate::format::layout::{CONTAINER_BYTES, Checkpoint, PageHeader, PageRef, root, table};
use crate::format::log::{LogInfo, LogState};
use crate::format::tree::{Addressing, PageReader, TreeWalk};
use fs_inspect_core::Scope;
use fs_inspect_core::bytes::{u32_at, u64_at};
use fs_inspect_core::range::{sort_coalesce, subtract};
use fs_inspect_core::{ByteRange, DiagCode, Diagnostics, Error, Limits, Result};
use std::sync::Arc;

/// What the tables of one checkpoint give: the translating reader, the container map, and the
/// used ranges of the sub-allocators and of the pages read.
pub(super) struct Tables {
    pub(super) reader: PageReader,
    pub(super) map: Arc<ContainerMap>,
    pub(super) extra: Vec<ByteRange>,
    pub(super) sub_free: Vec<ByteRange>,
}

pub(super) fn root_of(cp: &Checkpoint, i: usize) -> Result<PageRef> {
    cp.roots.get(i).copied().ok_or_else(|| Error::corrupt(format!("checkpoint has no root {i}")))
}

/// Read the container table (falling back to its copy), the sub-allocators, and check that
/// the Medium allocator's root is readable.
pub(super) fn load_tables(
    reader: &PageReader,
    cp: &Checkpoint,
    clusters: u64,
    limits: &Limits,
    diag: &Diagnostics,
) -> Result<Tables> {
    let cluster = u64::from(reader.cluster_bytes());
    let cpc = CONTAINER_BYTES / cluster;
    let (map, pages) = match ContainerMap::load(reader, root_of(cp, root::CONTAINER)?, cpc, clusters, limits) {
        Ok(v) => v,
        Err(e) if e.scope() != Scope::Unit => return Err(e),
        Err(e) => {
            let v = ContainerMap::load(reader, root_of(cp, root::CONTAINER_COPY)?, cpc, clusters, limits)
                .map_err(|e2| Error::corrupt(format!("container table: {e}; its copy: {e2}")))?;
            diag.warn(DiagCode::BackupUsed, format!("container table unreadable ({e}); using its copy"));
            v
        }
    };
    let map = Arc::new(map);
    let reader = reader.with_map(map.clone());
    let mut lcns = pages;
    // Also fails early (and falls back to the other checkpoint) on an unreadable Medium root.
    medium_pages(&reader, root_of(cp, root::MEDIUM_ALLOCATOR)?, limits, &mut lcns)?;
    let mut extra = Vec::new();
    let mut covered = Vec::new();
    for (i, addr, t) in [
        (root::ALLOCATOR_20, Addressing::Virtual, table::ALLOCATOR_20),
        (root::ALLOCATOR_22, Addressing::Physical, table::ALLOCATOR_22),
    ] {
        let r = root_of(cp, i)?;
        match sub_allocator(
            &reader,
            r,
            addr,
            t,
            clusters,
            limits,
            SubAllocated { out: &mut extra, covered: &mut covered, pages: &mut lcns },
        ) {
            Ok(()) => {}
            Err(e) if e.scope() != Scope::Unit => return Err(e),
            Err(e) => {
                diag.warn(
                    DiagCode::CountedAsUsed,
                    format!("allocator {t:#x} is unreadable ({e}); the whole volume counts as used"),
                );
                extra.push(ByteRange::new(0, clusters * cluster));
            }
        }
        if extra.len() > limits.max_file_extents {
            return Err(Error::limit("sub-allocator ranges"));
        }
    }
    for l in lcns {
        extra.push(ByteRange::new(l * cluster, cluster));
    }
    let sub_free = subtract(sort_coalesce(covered), sort_coalesce(extra.clone())).collect();
    Ok(Tables { reader, map, extra, sub_free })
}

/// Read every node of `walk`; damage ends it.
fn walk_whole(mut walk: TreeWalk) -> Result<()> {
    loop {
        match walk.next_with(&mut |_| {}) {
            Ok(Some(_)) => {}
            Ok(None) => return Ok(()),
            Err(e) if e.scope() == Scope::Unit => return Ok(()),
            Err(e) => return Err(e),
        }
    }
}

const LOG_INFO_NAME: &[u8] = b"Logfile Information Table";

/// The log row of the Logfile Information Table `o`: row 0 holds the table's name, row 1
/// `{start, end, length, control, control, 0}` (u64 each).
fn log_row(reader: &PageReader, o: &Directory, clusters: u64, limits: &Limits) -> Result<Option<LogInfo>> {
    let mut walk = TreeWalk::new(reader.clone(), o.root, Addressing::Virtual, o.id, limits);
    let (mut named, mut info) = (false, None);
    while let Some((node, i)) = walk.next_with(&mut |_| {})? {
        let (k, v) = (node.key(i), node.value(i));
        match u32_at(k, 0)? {
            0 => named = v == LOG_INFO_NAME,
            1 if v.len() >= 0x30 => {
                let f = |n: usize| u64_at(v, 8 * n);
                let (start, end, len) = (f(0)?, f(1)?, f(2)?);
                let control = [f(3)?, f(4)?];
                let fits =
                    start < end && end <= clusters && end - start == len && control.iter().all(|&c| c < clusters);
                if fits {
                    info = Some(LogInfo { start, end, control });
                }
            }
            _ => {}
        }
    }
    Ok(info.filter(|_| named))
}

impl RefsFs {
    /// Read every node of every table the checkpoint lists and of the system tables the Object
    /// ID table lists (directories are [`walk_files`](Self::walk_files)'), for
    /// `PageReader::record`. Damage ends the walk of that table only.
    pub fn walk_tables(&self) -> Result<()> {
        let physical = [root::CONTAINER, root::CONTAINER_COPY, root::ALLOCATOR_22];
        for (i, r) in self.cp.roots.iter().enumerate() {
            let addr = if physical.contains(&i) { Addressing::Physical } else { Addressing::Virtual };
            let page = match self.reader.read_node_of(r, addr, 0, &|_| true) {
                Ok(p) => p,
                Err(e) if e.scope() == Scope::Unit => continue,
                Err(e) => return Err(e),
            };
            let table = PageHeader::parse(&page.data)?.table;
            walk_whole(TreeWalk::from_page(self.reader.clone(), *r, page, addr, table, &self.limits))?;
        }
        let objects = match self.objects() {
            Ok(o) => o,
            Err(e) if e.scope() == Scope::Unit => return Ok(()),
            Err(e) => return Err(e),
        };
        let system: Vec<Directory> =
            objects.iter().filter(|o| o.id < object::ROOT && o.id != object::FS_METADATA).copied().collect();
        // Their root pages read together.
        self.file_reader().roots(&system, &mut |o, root| match root {
            Ok(p) => {
                walk_whole(TreeWalk::from_page(self.reader.clone(), o.root, p, Addressing::Virtual, o.id, &self.limits))
            }
            Err(e) if e.scope() == Scope::Unit => Ok(()),
            Err(e) => Err(e),
        })
    }

    /// Every table the Object ID table lists, by id: walked the first time, its pages counted
    /// as read by every later call within a [`PageReader::record`].
    pub(super) fn objects(&self) -> Result<&[Directory]> {
        if let Some((o, seen)) = self.objects.get() {
            self.reader.seen_again(seen);
            return Ok(o);
        }
        let root = root_of(&self.cp, root::OBJECT_ID)?;
        let (o, seen) = self.reader.record(|| self.file_reader().objects(root, &|_| true));
        let o = o?;
        Ok(&self.objects.get_or_init(|| (o, seen)).0)
    }

    /// Where the log is, from the Logfile Information Table (object 9; its copy is object 0xA):
    /// `None` when neither reads as expected.
    pub fn log_info(&self) -> Result<Option<LogInfo>> {
        let objects = match self.objects() {
            Ok(o) => o,
            Err(e) if e.scope() == Scope::Unit => return Ok(None),
            Err(e) => return Err(e),
        };
        for o in objects.iter().filter(|o| o.id == object::LOG_INFO || o.id == object::LOG_INFO_COPY) {
            match log_row(&self.reader, o, self.clusters, &self.limits) {
                Ok(Some(l)) => return Ok(Some(l)),
                Ok(None) => {}
                Err(e) if e.scope() == Scope::Unit => {}
                Err(e) => return Err(e),
            }
        }
        Ok(None)
    }

    /// Where the log is and how far it was written (`None` when it cannot be placed), read
    /// once.
    pub fn log_state(&self) -> Result<Option<LogState>> {
        self.log.get_or_init(|| crate::format::log::log_state(self)).clone()
    }

    /// The log has pages at or past the checkpoint's position: what they may change is not on
    /// disk yet.
    pub fn log_pending(&self) -> bool {
        matches!(self.log_state(), Ok(Some(l)) if l.last >= self.checkpoint().log_lsn)
    }

    /// The security descriptor of `key` (the security table read the first time).
    pub fn descriptor(&self, key: crate::format::files::SecurityKey) -> Result<Option<Vec<u8>>> {
        let table = self.security.get_or_init(|| {
            let mut out = std::collections::HashMap::new();
            let Some(t) = self.objects()?.iter().find(|o| o.id == object::SECURITY).copied() else {
                return Ok(out);
            };
            self.file_reader().rows(&t, &mut |_, v| {
                let key = crate::format::files::SecurityKey { hash: u32_at(v, 0)?, index: u32_at(v, 4)? };
                let len = (u32_at(v, 8)? as usize).saturating_sub(12);
                out.insert(key, fs_inspect_core::bytes::slice(v, 12, len)?.to_vec());
                Ok(std::ops::ControlFlow::Continue(()))
            })?;
            Ok(out)
        });
        Ok(table.as_ref().map_err(Clone::clone)?.get(&key).cloned())
    }

    /// The directory tables of the Object ID table.
    pub fn directories(&self) -> Result<Vec<Directory>> {
        Ok(self.objects()?.iter().filter(|o| o.id >= object::ROOT || o.id == object::FS_METADATA).copied().collect())
    }
}
