//! The namespace of a ReFS volume: one root, nodes numbered by directory table and file id.
//!
//! - Node ids (root 0): a directory is its object id in the high 32 bits, 0 in the low
//!   (`object << 32`: the root is `0x600 << 32`); a file is the directory table keeping its
//!   record in the high 32 bits and its file id there (never 0) in the low (`dir << 32 | id`):
//!   the file's identity, kept across renames and moves (a moved file's record, and a hard
//!   link's, stays where it was created). Both fit in 32 bits on every volume seen (object ids
//!   from 0x600, file ids in the thousands); a record that does not is refused as unsupported.
//! - Names (UTF-16) compare without case: the upper case of each unit. A name kept as a link
//!   (a moved file, a hard link) names the record another directory keeps by id; a link to a
//!   record that is not there is damage.
//! - A listing reads the directory table's leaves in order, as far as its reader goes. A name
//!   is looked up by a descent of the table by its key ([`dirkey`]), a file's record by its id
//!   row and then the row of its name (or the one kept by id): a miss of a name is the answer.
//!   Where the order of the name against a key met cannot be told (units outside ASCII), the
//!   rows are scanned; so they are, with a diagnostic ([`DiagCode::Fallback`]), when the
//!   descent meets damage (keys out of order, a page that does not read). A record not found by
//!   its keys is looked for among all the rows (a node id names it: a miss is rare).
//! - A file or directory's kind follows its reparse tag (symbolic links and junctions are
//!   [`NodeKind::Symlink`]); a listing takes it from the name row, without the record. A
//!   directory's stat reads its own record (row 0x10).
//! - Streams: the unnamed one is [`StreamId::MAIN`], the named ones follow in record order
//!   (ids from 1); each is read resident or through its extents, as stored up to its size
//!   (past the valid data length too).
//! - `node_info` reads the node's record once; every facet comes from it. `node_infos` takes a
//!   batch's records from its tables' rows in one pass, or, under a hold, from the listing
//!   that just gave them (a walk reads each directory's rows once). Names: a record kept
//!   by id lists every name (its link attributes, ReFS 3.5 on); one kept under its name has
//!   that one; a directory's are not kept with it (unsupported). Security: the self-relative
//!   descriptor of the record's key in the security table. Link: the reparse buffer (ReFS 3.5
//!   on). ReFS has no extended attributes (unsupported).
//! - Leaving a file out frees its clusters but those another file shares (block cloning):
//!   finding them walks every file, and a file with streams this reader does not read refuses
//!   it (its clusters may be shared unseen).

use super::RefsFs;
use crate::format::dirkey::{self, Key, collate};
use crate::format::files::{
    self, Directory, FileEntry, FileReader as Rows, Stream, dir_entry, name_units, object, row,
};
use crate::format::tree::TreeWalk;
use fs_inspect_core::RootId;
use fs_inspect_core::Scope;
use fs_inspect_core::bytes::{slice, u16_at, u32_at, u64_at};
use fs_inspect_core::range::{intersect, sort_coalesce, subtract};
use fs_inspect_core::read::{ExtentReader, FileReader, MemReader};
use fs_inspect_core::windows::reparse::{self, Reparse, kind_of_tag};
use fs_inspect_core::{
    ByteRange, DiagCode, DirEntry, Error, FileExtent, Hold, LinkTarget, Name, Namespace, NodeFlags, NodeId, NodeInfo,
    NodeKind, Result, RootInfo, Security, Stat, StreamId, StreamInfo, Times, Timestamp, Want, WinAttrs,
};
use fs_inspect_core::{DirEntryExt, NodeInfoExt, RootInfoExt, StatExt, StreamInfoExt, TimestampExt, WantExt};
use fs_inspect_core::{TimesExt, WinAttrsExt};
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::ops::ControlFlow;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// Bits of a node id below the directory part.
const SHIFT: u32 = 32;
/// `FILE_ATTRIBUTE_*` mapped to node flags.
/// `FILE_ATTRIBUTE_DIRECTORY`: not kept in a directory's record.
const DIRECTORY: u32 = 0x10;
const ATTR_FLAGS: [(u32, NodeFlags); 3] =
    [(0x200, NodeFlags::SPARSE), (0x800, NodeFlags::COMPRESSED), (0x4000, NodeFlags::ENCRYPTED)];

/// Records [`Listed`] keeps at most: some batches of a walk (of 4096 entries).
const LISTED: usize = 16384;

/// What the listings read, kept while a hold lives ([`Namespace::hold`]).
///
/// The records of the files they gave last: a walk reads the infos of a batch of entries
/// right after listing them, and takes their records from here, not from the table again.
/// The oldest go first; a record two rows give is taken from neither (damage: the lookup by
/// its keys tells which).
///
/// And where the last listings stopped: a listing taken up after the entry it stopped at goes
/// on with the same walk: its path, its pages read ahead, and its read-ahead at the size it
/// grew to.
#[derive(Debug, Default)]
pub(crate) struct Listed(Mutex<ListedRecords>);

/// Listings stopped and kept for [`Listed`]: a few, so two listings taken up in turn each
/// find theirs.
const PAUSED: usize = 2;

#[derive(Debug, Default)]
struct ListedRecords {
    /// By (directory table, file id); `None`: two rows gave it, or it was taken.
    records: HashMap<(u64, u64), Option<FileEntry>>,
    /// Their keys, oldest first.
    order: VecDeque<(u64, u64)>,
    /// Walks of directory tables stopped after the entry named (directory table, name), the
    /// latest last.
    paused: VecDeque<(u64, Vec<u16>, TreeWalk)>,
}

impl Listed {
    fn lock(&self) -> MutexGuard<'_, ListedRecords> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn keep(&self, e: FileEntry) {
        let mut guard = self.lock();
        let l = &mut *guard;
        let key = (e.dir, e.id);
        if let Some(kept) = l.records.get_mut(&key) {
            *kept = None;
            return;
        }
        l.records.insert(key, Some(e));
        l.order.push_back(key);
        let excess = l.order.len().saturating_sub(LISTED);
        for old in l.order.drain(..excess) {
            l.records.remove(&old);
        }
    }

    fn take(&self, dir: u64, id: u64) -> Option<FileEntry> {
        self.lock().records.get_mut(&(dir, id))?.take()
    }

    /// Keep `walk` of directory table `dir`, stopped after the entry named `after`.
    fn pause(&self, dir: u64, after: Vec<u16>, walk: TreeWalk) {
        let mut l = self.lock();
        l.paused.push_back((dir, after, walk));
        if l.paused.len() > PAUSED {
            l.paused.pop_front();
        }
    }

    /// The walk of directory table `dir` stopped after the entry named `after`, if kept.
    fn resume(&self, dir: u64, after: &[u16]) -> Option<TreeWalk> {
        let mut l = self.lock();
        let at = l.paused.iter().position(|(d, a, _)| *d == dir && a == after)?;
        l.paused.remove(at).map(|(_, _, walk)| walk)
    }
}

/// What a node id names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Node {
    /// A directory: its object id.
    Dir(u64),
    /// A file: the directory table keeping its record and its file id there.
    File { dir: u64, id: u64 },
}

fn split(node: NodeId) -> Result<Node> {
    if node.root != RootId(0) {
        return Err(Error::not_found(format!("refs node {node}")));
    }
    let (hi, lo) = (node.id >> SHIFT, node.id & ((1 << SHIFT) - 1));
    Ok(if lo == 0 { Node::Dir(hi) } else { Node::File { dir: hi, id: lo } })
}

fn dir_node(id: u64) -> Result<NodeId> {
    if id == 0 || id >> SHIFT != 0 {
        return Err(Error::unsupported(format!("refs: directory id {id:#x} does not fit a node id")));
    }
    Ok(NodeId::new(0, id << SHIFT))
}

fn file_node(dir: u64, id: u64) -> Result<NodeId> {
    if dir >> SHIFT != 0 || id == 0 || id >> SHIFT != 0 {
        return Err(Error::unsupported(format!("refs: file {dir:#x}:{id:#x} does not fit a node id")));
    }
    Ok(NodeId::new(0, dir << SHIFT | id))
}

/// Names compared without case: the upper case of each UTF-16 unit (one to one, as Windows
/// keeps it).
fn same(a: &[u16], b: &[u16]) -> bool {
    let upper = |u: u16| match char::from_u32(u32::from(u)).map(char::to_uppercase) {
        Some(mut c) if c.len() == 1 => c.next().and_then(|c| u16::try_from(u32::from(c)).ok()).unwrap_or(u),
        _ => u,
    };
    a.len() == b.len() && a.iter().zip(b).all(|(&x, &y)| x == y || upper(x) == upper(y))
}

/// The UTF-16 units of `name` (`None`: neither UTF-8 nor UTF-16: no ReFS name).
fn units(name: &Name) -> Option<Vec<u16>> {
    match name {
        Name::Utf16(u) => Some(u.clone()),
        Name::Bytes(b) => std::str::from_utf8(b).ok().map(|s| s.encode_utf16().collect()),
    }
}

/// The rows a lookup of a name found: a file kept under the name is the answer, then a link,
/// then a directory.
#[derive(Default)]
struct Found {
    file: Option<DirEntry>,
    link: Option<DirEntry>,
    sub: Option<DirEntry>,
}

impl Found {
    /// Row `(k, v)` of directory `dir`, when it is named `want`.
    fn offer(&mut self, dir: u64, want: &[u16], k: &[u8], v: &[u8]) -> Result<()> {
        if u16_at(k, 0)? != row::NAME || !same(&name_units(k), want) {
            return Ok(());
        }
        let slot = match dir_entry(k, v)? {
            files::DirEntry::File { name: Some(_), .. } => &mut self.file,
            files::DirEntry::Link { .. } => &mut self.link,
            files::DirEntry::Directory { .. } => &mut self.sub,
            _ => return Ok(()),
        };
        *slot = RefsFs::entry(dir, k, v)?;
        Ok(())
    }
}

/// Go on with the rows.
const MORE: Result<ControlFlow<()>> = Ok(ControlFlow::Continue(()));

fn table(dirs: &[Directory], id: u64) -> Option<&Directory> {
    dirs.iter().find(|d| d.id == id)
}

fn no_table(id: u64) -> Error {
    Error::corrupt(format!("refs: no directory table {id:#x}"))
}

impl RefsFs {
    /// The record of file `id` that directory table `dir` keeps (under a name or by id),
    /// `None` when it keeps none: found by its keys, else among all the rows. Only that record
    /// is parsed: damage elsewhere does not matter.
    fn record(&self, dirs: &[Directory], dir: u64, id: u64) -> Result<Option<FileEntry>> {
        let r = self.file_reader();
        let d = table(dirs, dir).ok_or_else(|| no_table(dir))?;
        let by_keys = self.indexed(d, || Self::record_by_keys(&r, d, id))?;
        if let Some(Some(e)) = by_keys {
            return Ok(Some(e));
        }
        let found = Self::record_scan(&r, d, id)?;
        if found.is_some() && by_keys.is_some() {
            self.diag.warn(
                DiagCode::Fallback,
                format!("refs: directory {dir:#x}: record {id:#x} found among the rows, not by its keys"),
            );
        }
        Ok(found)
    }

    /// The record of file `id` in `d` by its keys: its id row, then the row of its name or the
    /// one kept by id. `None`: the keys cannot be told apart from the rows met.
    fn record_by_keys(r: &Rows<'_>, d: &Directory, id: u64) -> Result<Option<Option<FileEntry>>> {
        let mut id_row = None;
        let told = r.seek_rows(d, &Key::Id(id), &mut |_, v| {
            id_row = Some(v.to_vec());
            Ok(ControlFlow::Break(()))
        })?;
        if !told {
            return Ok(None);
        }
        let Some(v) = id_row else { return Ok(Some(None)) };
        // `{u32 0, .., u16 name offset @ 8, u16 its bytes}`, or `{u64 2, u64 id, u64 directory}`.
        let (key, name) = match u32_at(&v, 0)? {
            0 => {
                let name = slice(&v, usize::from(u16_at(&v, 8)?), usize::from(u16_at(&v, 0x0A)?))?;
                (Key::Name(name), Some(name))
            }
            2 => (Key::ById(id, u64_at(&v, 0x10)?), None),
            _ => return Ok(Some(None)),
        };
        let mut found = None;
        let told = r.seek_rows(d, &key, &mut |k, v| {
            if let files::DirEntry::File { name: n, record } = dir_entry(k, v)?
                && n.is_some() == name.is_some()
                && name.is_none_or(|name| k.get(4..) == Some(name))
                && u64_at(record, 0x80)? == id
            {
                found = Some(r.file(d.id, n, record)?);
                return Ok(ControlFlow::Break(()));
            }
            MORE
        })?;
        Ok(told.then_some(found))
    }

    /// The record of file `id` in `d`, among all its rows.
    fn record_scan(r: &Rows<'_>, d: &Directory, id: u64) -> Result<Option<FileEntry>> {
        let mut found = None;
        r.rows(d, &mut |k, v| {
            if let files::DirEntry::File { name, record } = dir_entry(k, v)?
                && u64_at(record, 0x80).ok() == Some(id)
            {
                found = Some(r.file(d.id, name, record)?);
                return Ok(ControlFlow::Break(()));
            }
            MORE
        })?;
        Ok(found)
    }

    /// What `seek` answers by the keys of `d` (`None`: they cannot tell, the rows are to be
    /// scanned); damage met on the way is reported and the rows are scanned too.
    fn indexed<T>(&self, d: &Directory, seek: impl FnOnce() -> Result<Option<T>>) -> Result<Option<T>> {
        match seek() {
            Err(e) if e.scope() == Scope::Unit => {
                self.diag.warn(
                    DiagCode::Fallback,
                    format!("refs: directory {:#x}: {e}; its rows are read instead of its keys", d.id),
                );
                Ok(None)
            }
            r => r,
        }
    }

    /// The entry `name` of directory `dir`: by its key (`indexed`) or among all the rows.
    fn find(&self, dir: NodeId, name: &Name, indexed: bool) -> Result<Option<DirEntry>> {
        let Node::Dir(id) = split(dir)? else {
            self.file_entry(dir)?;
            return Ok(None);
        };
        let dirs = self.directories()?;
        let d = table(&dirs, id).ok_or_else(|| Error::not_found(format!("refs node {dir}")))?;
        let Some(want) = units(name) else { return Ok(None) };
        let r = self.file_reader();
        let key = dirkey::name_bytes(&want);
        let by_key = if indexed {
            self.indexed(d, || {
                let mut found = Found::default();
                let told = r.seek_rows(d, &Key::Name(&key), &mut |k, v| {
                    found.offer(id, &want, k, v)?;
                    MORE
                })?;
                Ok(told.then_some(found))
            })?
        } else {
            None
        };
        let found = match by_key {
            Some(found) => found,
            None => {
                let mut found = Found::default();
                r.rows(d, &mut |k, v| {
                    found.offer(id, &want, k, v)?;
                    MORE
                })?;
                found
            }
        };
        if found.file.is_none()
            && let Some(l) = &found.link
            && let Node::File { dir: d, id: f } = split(l.node)?
            && self.record(&dirs, d, f)?.is_none()
        {
            let name = name.to_string_lossy();
            return Err(Error::corrupt(format!("refs: {name}: no record {f:#x} in directory {d:#x}")));
        }
        Ok(found.file.or(found.link).or(found.sub))
    }

    /// [`Namespace::lookup`] among all the rows (tests: what the keys must agree with).
    #[cfg(test)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub(crate) fn lookup_scan(&self, dir: NodeId, name: &Name) -> Result<Option<DirEntry>> {
        self.find(dir, name, false)
    }

    /// The record of file `node` by its keys and among all the rows (tests).
    #[cfg(test)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub(crate) fn records(&self, node: NodeId) -> Result<(Option<Option<FileEntry>>, Option<FileEntry>)> {
        let Node::File { dir, id } = split(node)? else { return Err(Error::invalid_argument("a directory")) };
        let dirs = self.directories()?;
        let d = table(&dirs, dir).ok_or_else(|| no_table(dir))?;
        let r = self.file_reader();
        Ok((Self::record_by_keys(&r, d, id)?, Self::record_scan(&r, d, id)?))
    }

    /// The records of the files among `nodes` kept under a name, taken from the rows as a
    /// listing walks them: per directory table, the id rows from the least id to the greatest
    /// give each file's name, then the name rows from the least of those names to the greatest
    /// give the records. A record is taken where [`record_by_keys`](Self::record_by_keys) takes
    /// it: the row of the name its id row gives, holding its id. Bounded (records far apart
    /// walk no more rows than about their own); the leaves read are kept for the batch running
    /// ([`PageReader::batch`](crate::format::tree::PageReader::batch)). What is not found so
    /// (kept by id, damage, past the bound) is left to the lookups, which meet its error
    /// themselves.
    fn batch_records(&self, nodes: &[NodeId]) -> HashMap<(u64, u64), FileEntry> {
        let mut found = HashMap::new();
        let mut wanted = BTreeMap::<u64, HashSet<u64>>::new();
        for &node in nodes {
            if let Ok(Node::File { dir, id }) = split(node) {
                wanted.entry(dir).or_default().insert(id);
            }
        }
        let Ok(dirs) = self.directories() else { return found };
        let r = self.file_reader();
        for (dir, ids) in wanted {
            let Some(d) = table(&dirs, dir) else { continue };
            let (Some(&lo), Some(&hi)) = (ids.iter().min(), ids.iter().max()) else { continue };
            // Rows walked at most: about the records' own, a margin for those between.
            let most = 2 * ids.len() + 256;
            // The name key of each file wanted, and the least and the greatest of them.
            let mut names = HashMap::<Vec<u8>, u64>::new();
            let (mut first, mut last): (Option<Vec<u8>>, Option<Vec<u8>>) = (None, None);
            let mut ordered = true;
            let mut seen = 0;
            let _ = r.seek(d, &Key::Id(lo), &mut |k, v| {
                seen += 1;
                let Some(Key::Id(id)) = Key::parse(k) else { return Ok(ControlFlow::Break(())) };
                if id > hi || seen > most {
                    return Ok(ControlFlow::Break(()));
                }
                // `{u32 0, .., u16 name offset @ 8, u16 its bytes}`: kept under a name.
                if ids.contains(&id) && u32_at(v, 0)? == 0 {
                    let name = slice(v, usize::from(u16_at(v, 8)?), usize::from(u16_at(v, 0x0A)?))?;
                    let below = |a: &Option<Vec<u8>>, o| match a {
                        None => Some(true),
                        Some(a) => collate(&Key::Name(name), &Key::Name(a)).map(|c| c == o),
                    };
                    match (below(&first, Ordering::Less), below(&last, Ordering::Greater)) {
                        (Some(lt), Some(gt)) => {
                            if lt {
                                first = Some(name.to_vec());
                            }
                            if gt {
                                last = Some(name.to_vec());
                            }
                        }
                        _ => ordered = false,
                    }
                    names.insert(name.to_vec(), id);
                }
                MORE
            });
            let (Some(first), Some(last)) = (first, last) else { continue };
            if !ordered {
                continue;
            }
            let mut seen = 0;
            let _ = r.seek(d, &Key::Name(&first), &mut |k, v| {
                seen += 1;
                let past = Key::parse(k).and_then(|k| collate(&k, &Key::Name(&last)));
                if seen > most || !matches!(past, Some(Ordering::Less | Ordering::Equal)) {
                    return Ok(ControlFlow::Break(()));
                }
                if let Some(&id) = k.get(4..).and_then(|n| names.get(n))
                    && let Ok(files::DirEntry::File { name: Some(n), record }) = dir_entry(k, v)
                    && u64_at(record, 0x80).ok() == Some(id)
                    && let Ok(e) = r.file(d.id, Some(n), record)
                {
                    found.insert((dir, id), e);
                }
                MORE
            });
        }
        found
    }

    /// The record of file `node`.
    pub fn file_entry(&self, node: NodeId) -> Result<FileEntry> {
        let Node::File { dir, id } = split(node)? else {
            return Err(Error::invalid_argument(format!("refs node {node} is a directory")));
        };
        let dirs = self.directories()?;
        if table(&dirs, dir).is_none() {
            return Err(Error::not_found(format!("refs node {node}")));
        }
        self.record(&dirs, dir, id)?.ok_or_else(|| Error::not_found(format!("refs node {node}")))
    }

    /// The entries of directory `dir` (its listing), from the first or after the one named
    /// `after` (UTF-16 units).
    fn list_names(
        &self,
        dir: NodeId,
        after: Option<&[u16]>,
        f: &mut dyn FnMut(DirEntry) -> ControlFlow<()>,
    ) -> Result<()> {
        let Node::Dir(id) = split(dir)? else {
            self.file_entry(dir)?;
            return Err(Error::invalid_argument(format!("refs node {dir} is not a directory")));
        };
        let dirs = self.directories()?;
        let d = table(&dirs, id).ok_or_else(|| Error::not_found(format!("refs node {dir}")))?;
        // The name rows, from the first or from `after` (its row skipped): the rows before
        // them (the directory's own record, ids) are not read past. Where the seek cannot lead
        // (its rows read instead), the rows up to `after` are skipped. While a hold lives, the
        // records of the files given are kept for their infos (before `f` gets them: it may
        // ask for them). Where the last listing stopped at `after`, its walk goes on.
        let given = std::cell::Cell::new(false);
        let seen = std::cell::Cell::new(after.is_none());
        let listed = self.listed.get();
        let r = self.file_reader();
        let probe = after.map(dirkey::name_bytes).unwrap_or_default();
        // The name of the entry `f` stopped at.
        let stopped = std::cell::RefCell::new(None);
        let mut names = |k: &[u8], v: &[u8]| {
            if u16_at(k, 0)? > row::NAME {
                return Ok(ControlFlow::Break(()));
            }
            if let Some(after) = after
                && u16_at(k, 0)? == row::NAME
                && name_units(k) == after
            {
                seen.set(true);
                return MORE;
            }
            if !seen.get() {
                return MORE;
            }
            match Self::entry(id, k, v)? {
                Some(e) => {
                    if let Some(l) = &listed
                        && let Ok(files::DirEntry::File { name: Some(n), record }) = dir_entry(k, v)
                        && let Ok(rec) = r.file(id, Some(n), record)
                    {
                        l.keep(rec);
                    }
                    given.set(true);
                    let flow = f(e);
                    if flow.is_break() {
                        *stopped.borrow_mut() = Some(name_units(k));
                    }
                    Ok(flow)
                }
                None => MORE,
            }
        };
        let paused = after.zip(listed.as_ref()).and_then(|(a, l)| l.resume(id, a));
        let walk = match paused {
            Some(walk) => Ok(Some(walk)),
            None => r.seek_walk(d, &Key::Name(&probe)),
        };
        let seek = walk.and_then(|walk| {
            let Some(mut walk) = walk else { return Ok(false) };
            // The walk is on `after` or past it: past it, nothing is skipped.
            let broke = r.rows_on(&mut walk, d, &mut |k, v| {
                seen.set(true);
                names(k, v)
            })?;
            if let (true, Some(l), Some(at)) = (broke, &listed, stopped.take()) {
                l.pause(id, at, walk);
            }
            Ok(true)
        });
        seen.set(after.is_none());
        match seek {
            Ok(true) => Ok(()),
            Err(e) if e.scope() != Scope::Unit || given.get() => Err(e),
            res => {
                if let Err(e) = res {
                    self.diag.warn(
                        DiagCode::Fallback,
                        format!("refs: directory {id:#x}: {e}; its rows are read instead of its keys"),
                    );
                }
                r.rows(d, &mut names)
            }
        }
    }

    /// The namespace entry of directory row `(k, v)` of directory `dir` (`None`: a row naming
    /// nothing, a record kept by id).
    fn entry(dir: u64, k: &[u8], v: &[u8]) -> Result<Option<DirEntry>> {
        let (node, is_dir) = match dir_entry(k, v)? {
            files::DirEntry::File { name: Some(_), record } => (file_node(dir, u64_at(record, 0x80)?)?, false),
            files::DirEntry::Directory { id, .. } => (dir_node(id)?, true),
            files::DirEntry::Link { dir, id, .. } => (file_node(dir, id)?, false),
            files::DirEntry::File { name: None, .. } | files::DirEntry::Other => return Ok(None),
        };
        let tag = files::row_attributes(k, v).map_or(0, |(_, t)| t);
        Ok(Some(
            DirEntry::new(Name::Utf16(name_units(k)), node, Some(kind(tag, is_dir))).with_cloud(reparse::is_cloud(tag)),
        ))
    }

    /// The record of `node`: a file's, or a directory's own (`None`: a directory without one).
    fn node_entry(&self, node: NodeId) -> Result<Option<FileEntry>> {
        let Node::Dir(id) = split(node)? else { return self.file_entry(node).map(Some) };
        let dirs = self.directories()?;
        let d = table(&dirs, id).ok_or_else(|| Error::not_found(format!("refs node {node}")))?;
        let r = self.file_reader();
        match r.first_row(d)? {
            Some((k, v)) if u16_at(&k, 0)? == row::SELF => Ok(Some(r.file(id, None, &v)?)),
            _ => Ok(None),
        }
    }

    /// What [`node_info`](Namespace::node_info) gives of `node` from its record `e` (`None`: a
    /// directory without one, nothing but its kind).
    fn info_of(&self, node: NodeId, e: Option<&FileEntry>, want: Want) -> Result<NodeInfo> {
        let is_dir = matches!(split(node)?, Node::Dir(_));
        let Some(e) = e else {
            let mut info = NodeInfo::new(Stat::new(node, NodeKind::Dir, 0));
            info.xattrs = want.then(Want::XATTRS, no_xattrs);
            info.security = want.then(Want::SECURITY, || Ok(None));
            info.link = want.then(Want::LINK, || Ok(None));
            info.streams = want.then(Want::STREAMS, || Ok(Vec::new()));
            info.names = want.then(Want::NAMES, || Err(dir_names(node)));
            return Ok(info);
        };
        let mut info = NodeInfo::new(stat(node, is_dir, e));
        info.xattrs = want.then(Want::XATTRS, no_xattrs);
        info.security = want.then(Want::SECURITY, || Ok(self.descriptor(e.security)?.map(Security::Ntfs)));
        info.link = want.then(Want::LINK, || link(node, e));
        info.streams = want.then(Want::STREAMS, || if is_dir { Ok(Vec::new()) } else { streams(node, e) });
        info.names = want.then(Want::NAMES, || if is_dir { Err(dir_names(node)) } else { names(node, e) });
        Ok(info)
    }

    /// A reader of stream `stream` of file `node` (not a directory: `open` refuses one, and
    /// a directory's info has no stream to open) from its record `e`.
    fn reader_of(&self, node: NodeId, e: &FileEntry, stream: StreamId) -> Result<Box<dyn FileReader>> {
        if stream != StreamId::MAIN {
            let (_, s) = Self::named(e)
                .find(|(id, _)| *id == stream)
                .ok_or_else(|| Error::not_found(format!("refs node {node} has no stream {}", stream.get())))?;
            return self.stream_reader(s);
        }
        match e.data() {
            Some(s) => self.stream_reader(s),
            None => Ok(Box::new(MemReader::new(Vec::new()))),
        }
    }

    /// The named streams of `e` with their ids.
    fn named(e: &FileEntry) -> impl Iterator<Item = (StreamId, &Stream)> {
        e.streams.iter().filter(|s| s.name.is_some()).zip(1..).map(|(s, i)| (StreamId::new(i), s))
    }

    /// A reader of stream `s`.
    fn stream_reader(&self, s: &Stream) -> Result<Box<dyn FileReader>> {
        if s.resident {
            return Ok(Box::new(MemReader::new(s.data.clone())));
        }
        let c = u64::from(self.reader.cluster_bytes());
        let extents: Vec<FileExtent> =
            s.extents.iter().map(|x| FileExtent::mapped(x.vcn * c, x.lcn * c, x.clusters * c)).collect();
        Ok(Box::new(ExtentReader::new(self.reader.source().clone(), s.size, &extents, 0)?))
    }
}

/// The kind of a file or directory (`is_dir`) of reparse tag `tag` (0: none).
fn kind(tag: u32, is_dir: bool) -> NodeKind {
    match (tag, is_dir) {
        (0, true) => NodeKind::Dir,
        (0, false) => NodeKind::File,
        (t, d) => kind_of_tag(t, d),
    }
}

/// The stat of `node` (a directory: `is_dir`) from its record `e`.
fn stat(node: NodeId, is_dir: bool, e: &FileEntry) -> Stat {
    // A directory's record keeps neither its directory attribute nor a size.
    let attributes = if is_dir { e.attributes | DIRECTORY } else { e.attributes };
    let mut st = Stat::new(node, kind(e.reparse_tag, is_dir), if is_dir { 0 } else { e.size });
    if !is_dir {
        st.allocated = Some(e.allocated);
        // Kept under its name: that one; kept by id: its links (ReFS 3.5 on; unknown before).
        st.nlink = if e.name.is_some() {
            Some(1)
        } else if !e.links.is_empty() {
            u32::try_from(e.links.len()).ok()
        } else {
            None
        };
    }
    st.times = Times::new(
        Timestamp::from_filetime(e.created),
        Timestamp::from_filetime(e.modified),
        Timestamp::from_filetime(e.changed),
        Timestamp::from_filetime(e.accessed),
    );
    st.windows = Some(WinAttrs::new(attributes, None, Some(e.reparse_tag).filter(|&t| t != 0)));
    for (a, f) in ATTR_FLAGS {
        if attributes & a != 0 {
            st.flags |= f;
        }
    }
    if e.data().is_some_and(|s| s.resident) {
        st.flags |= NodeFlags::INLINE;
    }
    st
}

/// ReFS keeps no extended attributes.
fn no_xattrs<T>() -> Result<T> {
    Err(Error::unsupported("refs: extended attributes"))
}

/// A directory's names: its parent is not kept with it.
fn dir_names(node: NodeId) -> Error {
    Error::unsupported(format!("refs node {node}: a directory's parent is not kept with it"))
}

/// Where record `e` of `node` links to (`None`: no reparse point).
fn link(node: NodeId, e: &FileEntry) -> Result<Option<LinkTarget>> {
    if e.reparse_tag == 0 {
        return Ok(None);
    }
    let Some(b) = &e.reparse else {
        return Err(Error::unsupported(format!("refs node {node}: a reparse point of ReFS 3.4 or older")));
    };
    let r = Reparse::parse(b)?;
    Ok(Some(r.link()?.unwrap_or(LinkTarget::Other { tag: r.tag, data: r.data })))
}

/// The streams of file record `e` of `node`, the main one first.
fn streams(node: NodeId, e: &FileEntry) -> Result<Vec<StreamInfo>> {
    if e.incomplete {
        return Err(Error::unsupported(format!("refs node {node}: a non-resident named stream (ReFS 3.4 and older)")));
    }
    let flags = |s: &Stream| if s.resident { NodeFlags::INLINE } else { NodeFlags::default() };
    let main = e.data().map(flags).unwrap_or_default();
    let mut out = vec![StreamInfo::new(StreamId::MAIN, None, e.size, main)];
    for (id, s) in RefsFs::named(e) {
        out.push(StreamInfo::new(id, s.name.as_deref().map(Name::new), s.size, flags(s)));
    }
    Ok(out)
}

/// The names of file record `e` of `node`: the one it is kept under, or its links.
fn names(node: NodeId, e: &FileEntry) -> Result<Vec<(NodeId, Name)>> {
    if let Some(n) = &e.name {
        return Ok(vec![(dir_node(e.dir)?, Name::new(n))]);
    }
    if e.links.is_empty() {
        return Err(Error::unsupported(format!(
            "refs node {node}: the names of a record kept by id (ReFS 3.4 and older)"
        )));
    }
    e.links.iter().map(|(dir, n)| Ok((dir_node(*dir)?, Name::Utf16(n.clone())))).collect()
}

impl fs_inspect_core::sealed::Ns for RefsFs {}

impl Namespace for RefsFs {
    fn roots(&self) -> Result<Vec<RootInfo>> {
        Ok(vec![RootInfo::main(dir_node(object::ROOT)?)])
    }

    fn node_info(&self, node: NodeId, want: Want) -> Result<NodeInfo> {
        let e = self.node_entry(node)?;
        self.info_of(node, e.as_ref(), want)
    }

    /// As [`node_info`](Self::node_info) node after node, the records of a batch's files not
    /// looked up one by one: those a listing just gave while a hold lives (`Listed`), the
    /// others taken from the rows of their tables as a listing walks them (`batch_records`);
    /// the readers built from them. The pages read are kept for the batch.
    fn node_infos(
        self: Arc<Self>,
        nodes: &[NodeId],
        want: Want,
        f: &mut dyn FnMut(usize, Result<NodeInfo>) -> ControlFlow<()>,
    ) -> Result<()> {
        let _batch = self.reader.batch();
        // The records the listing kept, then those of the others from their tables' rows.
        let listed = self.listed.get();
        let mut kept: Vec<Option<FileEntry>> = nodes
            .iter()
            .map(|&n| match (split(n), &listed) {
                (Ok(Node::File { dir, id }), Some(l)) => l.take(dir, id),
                _ => None,
            })
            .collect();
        let rest: Vec<NodeId> = nodes.iter().zip(&kept).filter(|(_, k)| k.is_none()).map(|(n, _)| *n).collect();
        let mut records = self.batch_records(&rest);
        for (i, &node) in nodes.iter().enumerate() {
            let kept = match (kept[i].take(), split(node)) {
                (Some(e), _) => Some(Some(e)),
                (None, Ok(Node::File { dir, id })) => records.remove(&(dir, id)).map(Some),
                _ => None,
            };
            let info = kept.map_or_else(|| self.node_entry(node), Ok).and_then(|e| {
                let mut info = self.info_of(node, e.as_ref(), want)?;
                if want.contains(Want::OPEN)
                    && let Some(e) = &e
                {
                    info.readers =
                        info.streams_to_open().into_iter().map(|s| (s, self.reader_of(node, e, s))).collect();
                }
                Ok(info)
            });
            if f(i, info).is_break() {
                break;
            }
        }
        Ok(())
    }

    /// The records listings give, kept for the infos of the entries while the hold lives
    /// (`Listed`): a walk's listing and infos read a directory's rows once.
    fn hold(&self) -> Hold {
        self.listed.hold()
    }

    fn read_dir(&self, dir: NodeId, f: &mut dyn FnMut(DirEntry) -> ControlFlow<()>) -> Result<()> {
        self.list_names(dir, None, f)
    }

    fn resumes_listing(&self) -> bool {
        true
    }

    fn read_dir_after(&self, dir: NodeId, after: &Name, f: &mut dyn FnMut(DirEntry) -> ControlFlow<()>) -> Result<()> {
        let Name::Utf16(units) = after else {
            return Err(Error::invalid_argument(format!("refs: {after:?} is not a name of a directory of node {dir}")));
        };
        self.list_names(dir, Some(units.as_slice()), f)
    }

    fn lookup(&self, dir: NodeId, name: &Name) -> Result<Option<DirEntry>> {
        self.find(dir, name, true)
    }

    fn open(self: Arc<Self>, node: NodeId, stream: StreamId) -> Result<Box<dyn FileReader>> {
        if let Node::Dir(_) = split(node)? {
            return Err(Error::invalid_argument(format!("refs node {node} is not a regular file")));
        }
        let e = self.file_entry(node)?;
        self.reader_of(node, &e, stream)
    }

    fn case_insensitive(&self, _: u64) -> bool {
        true
    }

    /// A file's clusters, less those another file shares (block cloning): excluding a shared
    /// cluster would lose the other file's data. Finding them walks every file.
    fn exclusion_ranges(&self, node: NodeId) -> Result<Vec<ByteRange>> {
        if let Node::Dir(_) = split(node)? {
            return Ok(Vec::new());
        }
        let e = self.file_entry(node)?;
        let mine = self.file_ranges(&e);
        let mut shared = Vec::new();
        if !mine.is_empty() {
            self.walk_files(&mut |f| {
                let f = f?;
                // Streams not read may share the file's clusters unseen: nothing is excluded.
                if f.incomplete && (f.dir, f.id) != (e.dir, e.id) {
                    return Err(Error::unsupported("refs: a file has streams this reader does not read"));
                }
                if (f.dir, f.id) != (e.dir, e.id) {
                    shared.extend(intersect(mine.iter().copied(), self.file_ranges(&f)));
                }
                Ok(())
            })?;
        }
        Ok(subtract(mine, sort_coalesce(shared)).collect())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[path = "ns_tests.rs"]
mod tests;
