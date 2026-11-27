//! The intent logs replayed in memory: what each file system dataset's log changes, as an
//! overlay its namespace reads over the datasets on disk ([`Overlay`]). Nothing is patched:
//! an import replays a log by writing new blocks (copy on write), so the blocks on disk stay as
//! they are and the map is the same either way.
//!
//! Each dataset's records are applied as the import does (`zil_replay`), in sequence order:
//!
//! - Only records an import replays: those after the header's replay sequence, from a txg the
//!   pool has not synced (the claim's first txg when the log was claimed), up to where a claim
//!   ended (see [`zil`](crate::format::zil)).
//! - Create, mkdir, symlink: the object made (its number, generation, mode, owner and creation
//!   time from the record; every time its creation time), its entry added. Remove, rmdir,
//!   link, rename: entries and link counts (a directory's `..` counted), an object without
//!   link left freed. Write: the bytes copied into the record, or the whole block it points to
//!   at the block's offset (the size grows to the write's end only). Truncate: a range freed
//!   (zeros), or the end moved. Setattr: mode, owner, size, access and modification times as
//!   the record has them. Write2: the size extended.
//! - A write, truncate, setattr or write2 of an object that is not there is dropped (they may
//!   be logged out of order with a remove). A namespace record that does not apply (no such
//!   entry, an entry already there, a slot in use) fails the replay, as it fails the import.
//! - The times an import stamps with its own clock (a write's and a truncate's modification
//!   and change times, a directory's when its entries change, a change time) are not known:
//!   they read as the latest time the dataset's records hold (creation and setattr times).
//! - Records this driver does not apply (extended attributes in the SA, ACLs, creates with
//!   attributes or ACLs, rename exchange and whiteout, block cloning, extended attribute
//!   directories): the objects they name are refused.
//!
//! Copied data is kept in the scratch (the replay's arena); written-in-place blocks are read
//! from the pool. Encrypted datasets (their records unreadable without keys) and volumes (no
//! namespace) are not replayed.

use crate::format::blkptr::BlkPtr;
use crate::format::dnode::ot;
use crate::format::fs::ZfsFs;
use crate::format::zil::{self, Lr, Record, tx};
use crate::format::zpl::{Extra, Znode, Zpl};
use fs_inspect_core::ReplaySummaryExt;
use fs_inspect_core::Scope;
use fs_inspect_core::patch::PatchTable;
use fs_inspect_core::store::{Arena, Scratch};
use fs_inspect_core::{Error, NameMatch, ReplaySummary, Replayed, Result};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

pub(crate) const S_IFMT: u64 = 0o170000;
pub(crate) const S_IFDIR: u64 = 0o040000;
pub(crate) const S_IFREG: u64 = 0o100000;
/// Linux `ATTR_*` bits of a setattr record's mask (the importing OS reads them as its own).
const ATTR_MODE: u64 = 1;
const ATTR_UID: u64 = 2;
const ATTR_GID: u64 = 4;
const ATTR_SIZE: u64 = 8;
const ATTR_ATIME: u64 = 16;
const ATTR_MTIME: u64 = 32;
/// `sizeof (lr_setattr_t)`: a longer record carries optional attributes (`lr_attr_t`).
const SETATTR_LEN: usize = 112;

/// The intent logs of a pool replayed in memory (see the [module](self)).
#[derive(Debug)]
pub struct ZfsReplayed {
    patches: Arc<PatchTable>,
    pub(crate) overlay: Arc<Overlay>,
    summary: ReplaySummary,
}

impl Replayed for ZfsReplayed {
    fn patches(&self) -> &Arc<PatchTable> {
        &self.patches
    }

    fn summary(&self) -> ReplaySummary {
        self.summary.clone()
    }
}

/// What the logs change, by dataset (DSL directory object).
#[derive(Debug)]
pub struct Overlay {
    sets: HashMap<u64, SetLog>,
    /// Copied data.
    arena: Arc<Arena>,
}

impl Overlay {
    /// What dataset `dir_obj`'s log changes (`None`: it has none).
    pub(crate) fn set(&self, dir_obj: u64) -> Option<&SetLog> {
        self.sets.get(&dir_obj)
    }

    /// `len` bytes of copied data at `at`.
    pub(crate) fn stored(&self, at: u64, len: usize) -> Result<Vec<u8>> {
        self.arena.read_vec(at, len)
    }
}

/// One dataset's log replayed.
/// A directory's entries a log adds or removes, by name key ([`key`]): the name as given and
/// the entry value (`None`: removed).
type Listing = BTreeMap<Vec<u8>, (Vec<u8>, Option<u64>)>;

#[derive(Debug, Default)]
pub struct SetLog {
    objects: HashMap<u64, Obj>,
    /// Entries added (`Some`: the entry value) or removed (`None`), by directory and name key
    /// ([`key`]): with the name as given.
    entries: HashMap<u64, Listing>,
    /// Objects records not replayed change, and why.
    refused: HashMap<u64, String>,
}

/// An object the log changes.
#[derive(Debug, Clone)]
pub(crate) enum Obj {
    Freed,
    Live(Box<State>),
}

/// An object's state once the log is replayed.
#[derive(Debug, Clone)]
pub(crate) struct State {
    /// Made by the log: nothing of it is read from disk (a slot freed then used again too).
    pub(crate) new: bool,
    pub(crate) znode: Znode,
    pub(crate) atime: (u64, u64),
    pub(crate) crtime: Option<(u64, u64)>,
    pub(crate) rdev: u64,
    /// A new symlink's target.
    pub(crate) target: Option<Vec<u8>>,
    /// The size of what is read from disk: past it the base content is zeros.
    pub(crate) base_size: u64,
    /// Changes of the content, in order.
    pub(crate) data: Vec<DataOp>,
}

/// A change of a file's content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DataOp {
    /// `len` bytes at `offset` from the copied data at `at`.
    Stored { offset: u64, len: u64, at: u64 },
    /// The block `bp` at `offset`, `len` bytes of it (zeros past its end; a hole: zeros).
    Block { offset: u64, len: u64, bp: Box<BlkPtr> },
    /// Zeros in `[start, end)`.
    Zero { start: u64, end: u64 },
}

impl SetLog {
    /// Why `obj` is refused (a record not replayed changes it).
    pub(crate) fn refused(&self, obj: u64) -> Option<&str> {
        self.refused.get(&obj).map(String::as_str)
    }

    /// What the log leaves of object `obj` (`None`: the log does not change it).
    pub(crate) fn object(&self, obj: u64) -> Option<&Obj> {
        self.objects.get(&obj)
    }

    /// The entries of directory `dir` the log adds or removes: name, value (`None`: removed).
    pub(crate) fn entries(&self, dir: u64) -> impl Iterator<Item = (&[u8], Option<u64>)> {
        self.entries.get(&dir).into_iter().flat_map(|m| m.values().map(|(n, v)| (n.as_slice(), *v)))
    }

    /// The log's word on entry `name` of `dir` (names compared `how`): `Some(Some(value))`
    /// added, `Some(None)` removed, `None` not changed.
    pub(crate) fn entry(&self, dir: u64, name: &[u8], how: NameMatch) -> Option<Option<u64>> {
        self.entries.get(&dir)?.get(&key(name, how)).map(|(_, v)| *v)
    }
}

/// The key of a name in a directory compared `how` (folded without case).
pub(crate) fn key(name: &[u8], how: NameMatch) -> Vec<u8> {
    match (how, std::str::from_utf8(name)) {
        (NameMatch::Exact, _) | (_, Err(_)) => name.to_vec(),
        (NameMatch::AsciiCaseless, _) => name.to_ascii_lowercase(),
        (NameMatch::Caseless, Ok(s)) => s.to_lowercase().into_bytes(),
    }
}

/// `IFTODT`: a directory entry's type from a mode.
fn dtype(mode: u64) -> u64 {
    (mode & S_IFMT) >> 12
}

/// Replay the intent logs of `sets` (the pool's readable file system datasets).
pub fn replay(fs: &ZfsFs, sets: &[Zpl], scratch: &Scratch) -> Result<ZfsReplayed> {
    let arena = scratch.arena();
    let mut overlay = Overlay { sets: HashMap::new(), arena: arena.clone() };
    let mut records = 0u64;
    for z in sets.iter().filter(|z| !z.dataset.is_snapshot() && !z.objset.zil.log.is_hole()) {
        let log = zil::read(fs.reader(), &z.objset.zil, fs.limits().max_tree_nodes, true)?;
        let todo = to_replay(fs, z, &log);
        if todo.is_empty() {
            continue;
        }
        let mut b =
            Builder { fs, z, log: &log, arena: &arena, set: SetLog::default(), stamp: stamp(fs, &todo), block: None };
        for r in &todo {
            b.apply(r).map_err(|e| e.context(format!("{} intent log record {}", z.name, r.seq)))?;
        }
        records += todo.len() as u64;
        overlay.sets.insert(z.dataset.dir_obj, b.set);
    }
    let summary = ReplaySummary::overlay("zfs intent log", records, &arena);
    Ok(ZfsReplayed { patches: Arc::new(PatchTable::empty()), overlay: Arc::new(overlay), summary })
}

/// The records of `log` (dataset `z`'s) an import replays: not those of a txg on disk (in the
/// dataset already), nor those an earlier replay did.
fn to_replay<'l>(fs: &ZfsFs, z: &Zpl, log: &'l zil::Log) -> Vec<&'l Record> {
    let zh = &z.objset.zil;
    let first = if zh.claim_txg != 0 { zh.claim_txg } else { fs.uberblock().txg.saturating_add(1) };
    log.records.iter().filter(|r| r.seq > zh.replay_seq && r.txg >= first).collect()
}

/// What the namespace read on disk refuses, by dataset (DSL directory object): the objects its
/// intent log changes (`None`: all of them, the log's records not read).
#[derive(Debug, Default)]
pub struct Touched {
    sets: HashMap<u64, Option<HashSet<u64>>>,
}

impl Touched {
    pub(crate) fn touched(&self, dir_obj: u64, obj: u64) -> bool {
        match self.sets.get(&dir_obj) {
            None => false,
            Some(None) => true,
            Some(Some(s)) => s.contains(&obj),
        }
    }
}

/// The objects the intent logs of `sets` change (see [`Touched`]): those records name, and
/// those the entries they name hold on disk.
pub fn touched(fs: &ZfsFs, sets: &[Zpl]) -> Result<Touched> {
    let mut out = Touched::default();
    let r = fs.reader();
    let max = fs.limits().max_dir_entries;
    for z in sets.iter().filter(|z| !z.dataset.is_snapshot() && !z.objset.zil.log.is_hole()) {
        let one = || -> Result<HashSet<u64>> {
            let log = zil::read(r, &z.objset.zil, fs.limits().max_tree_nodes, true)?;
            let mut objs = HashSet::new();
            let entry = |dir: u64, name: &[u8]| -> Result<Option<u64>> {
                let Some(d) = z.objset.dnode(r, dir)? else { return Ok(None) };
                if d.ty != ot::DIRECTORY_CONTENTS {
                    return Ok(None);
                }
                Ok(z.child(r, &d, name, max)?.map(|v| v & ((1 << 48) - 1)))
            };
            for rec in to_replay(fs, z, &log) {
                match &rec.lr {
                    Lr::Create { dir, obj, .. } | Lr::Link { dir, obj, .. } => objs.extend([*dir, *obj]),
                    Lr::Remove { dir, name } => {
                        objs.insert(*dir);
                        objs.extend(entry(*dir, name)?);
                    }
                    Lr::Rename { sdir, tdir, sname, tname } => {
                        objs.extend([*sdir, *tdir]);
                        objs.extend(entry(*sdir, sname)?);
                        objs.extend(entry(*tdir, tname)?);
                    }
                    Lr::Write { obj, .. }
                    | Lr::Truncate { obj, .. }
                    | Lr::SetAttr { obj, .. }
                    | Lr::Write2 { obj, .. } => {
                        objs.insert(*obj);
                    }
                    Lr::Other { objects } => objs.extend(objects.iter().copied()),
                }
            }
            Ok(objs)
        };
        match one() {
            Ok(objs) if objs.is_empty() => {}
            Ok(objs) => {
                out.sets.insert(z.dataset.dir_obj, Some(objs));
            }
            Err(e) if e.scope() == Scope::Unit => {
                out.sets.insert(z.dataset.dir_obj, None);
            }
            Err(e) => return Err(e),
        }
    }
    Ok(out)
}

/// The time an import stamps with its own clock, as far as it can be told: the latest the
/// records hold, not before the pool's last sync.
fn stamp(fs: &ZfsFs, records: &[&Record]) -> (u64, u64) {
    let mut t = (fs.uberblock().timestamp, 0);
    for r in records {
        match &r.lr {
            Lr::Create { crtime, .. } => t = t.max(*crtime),
            Lr::SetAttr { mask, atime, mtime, .. } => {
                if mask & ATTR_ATIME == 0 {
                    t = t.max(*atime);
                }
                if mask & ATTR_MTIME == 0 {
                    t = t.max(*mtime);
                }
            }
            _ => {}
        }
    }
    t
}

struct Builder<'a> {
    fs: &'a ZfsFs,
    z: &'a Zpl,
    log: &'a zil::Log,
    arena: &'a Arena,
    set: SetLog,
    stamp: (u64, u64),
    /// The log block last read for copied data (its index and bytes).
    block: Option<(usize, Vec<u8>)>,
}

impl Builder<'_> {
    fn how(&self) -> NameMatch {
        self.z.name_match()
    }

    /// Object `obj` as the records so far leave it, read from disk the first time (`None`: a
    /// free slot, freed, or no file or directory).
    fn state(&mut self, obj: u64) -> Result<Option<&mut State>> {
        if !self.set.objects.contains_key(&obj) {
            let r = self.fs.reader();
            let Some(d) = self.z.objset.dnode(r, obj)? else { return Ok(None) };
            if d.ty != ot::PLAIN_FILE_CONTENTS && d.ty != ot::DIRECTORY_CONTENTS {
                return Ok(None);
            }
            let (znode, x): (Znode, Extra) = self.z.record(r, &d)?;
            let state = State {
                new: false,
                base_size: znode.size,
                znode,
                atime: x.atime,
                crtime: x.crtime,
                rdev: x.rdev,
                target: None,
                data: Vec::new(),
            };
            self.set.objects.insert(obj, Obj::Live(Box::new(state)));
        }
        Ok(match self.set.objects.get_mut(&obj) {
            Some(Obj::Live(s)) => Some(s),
            _ => None,
        })
    }

    /// Whether slot `obj` holds an object (any type) once the records so far are applied.
    fn in_use(&mut self, obj: u64) -> Result<bool> {
        match self.set.objects.get(&obj) {
            Some(Obj::Freed) => Ok(false),
            Some(Obj::Live(_)) => Ok(true),
            None => Ok(self.z.objset.dnode(self.fs.reader(), obj)?.is_some()),
        }
    }

    /// The bytes `at` of log block `index` (read once for the records after it in the block).
    fn copied(&mut self, index: usize, at: &std::ops::Range<usize>) -> Result<&[u8]> {
        if self.block.as_ref().is_none_or(|(i, _)| *i != index) {
            let bp = self.log.blocks.get(index).ok_or_else(|| Error::corrupt("a record of no log block"))?;
            let b =
                zil::read_block(self.fs.reader(), bp)?.ok_or_else(|| Error::corrupt("a log block no longer reads"))?;
            self.block = Some((index, b.bytes));
        }
        let b = self.block.as_ref().map_or(&[][..], |(_, b)| b.as_slice());
        b.get(at.clone()).ok_or_else(|| Error::corrupt("copied data past its block"))
    }

    /// Directory `dir`, which must be there.
    fn dir(&mut self, dir: u64) -> Result<&mut State> {
        match self.state(dir)? {
            Some(s) if s.znode.mode & S_IFMT == S_IFDIR => Ok(s),
            _ => Err(Error::corrupt(format!("directory {dir} is not there"))),
        }
    }

    /// The value of entry `name` of `dir` as the records so far leave it.
    fn lookup(&mut self, dir: u64, name: &[u8]) -> Result<Option<u64>> {
        if let Some(v) = self.set.entry(dir, name, self.how()) {
            return Ok(v);
        }
        if self.dir(dir)?.new {
            return Ok(None);
        }
        let r = self.fs.reader();
        let Some(d) = self.z.objset.dnode(r, dir)? else { return Ok(None) };
        self.z.child(r, &d, name, self.fs.limits().max_dir_entries)
    }

    fn set_entry(&mut self, dir: u64, name: &[u8], value: Option<u64>) {
        let k = key(name, self.how());
        self.set.entries.entry(dir).or_default().insert(k, (name.to_vec(), value));
    }

    /// A directory's entries changed: its size by `delta`, its times stamped.
    fn changed(&mut self, dir: u64, delta: i64) -> Result<()> {
        let stamp = self.stamp;
        let d = self.dir(dir)?;
        d.znode.size = d.znode.size.saturating_add_signed(delta);
        (d.znode.mtime, d.znode.ctime) = (stamp, stamp);
        Ok(())
    }

    /// One link of `obj` gone: freed when it was the last one (a directory always).
    fn unlink(&mut self, obj: u64) -> Result<()> {
        let stamp = self.stamp;
        let Some(s) = self.state(obj)? else { return Err(Error::corrupt(format!("object {obj} is not there"))) };
        if s.znode.mode & S_IFMT == S_IFDIR {
            if s.znode.size > 2 {
                return Err(Error::corrupt(format!("directory {obj} removed while not empty")));
            }
            s.znode.links = 0;
        } else {
            s.znode.links = s.znode.links.saturating_sub(1);
        }
        s.znode.ctime = stamp;
        if s.znode.links == 0 {
            self.set.objects.insert(obj, Obj::Freed);
        }
        Ok(())
    }

    fn apply(&mut self, r: &Record) -> Result<()> {
        let stamp = self.stamp;
        match &r.lr {
            Lr::Create { dir, obj, mode, uid, gid, generation, crtime, rdev, name, target } => {
                self.dir(*dir)?;
                if self.lookup(*dir, name)?.is_some() {
                    return Err(Error::corrupt(format!(
                        "{} already in directory {dir}",
                        String::from_utf8_lossy(name)
                    )));
                }
                if self.in_use(*obj)? {
                    return Err(Error::corrupt(format!("object {obj} is in use")));
                }
                let is_dir = mode & S_IFMT == S_IFDIR;
                let size = match target {
                    Some(t) => t.len() as u64,
                    None if is_dir => 2,
                    None => 0,
                };
                let znode = Znode {
                    mode: *mode,
                    size,
                    generation: *generation,
                    links: if is_dir { 2 } else { 1 },
                    flags: 0,
                    uid: *uid,
                    gid: *gid,
                    mtime: *crtime,
                    ctime: *crtime,
                };
                let state = State {
                    new: true,
                    znode,
                    atime: *crtime,
                    crtime: Some(*crtime),
                    rdev: *rdev,
                    target: target.clone(),
                    base_size: 0,
                    data: Vec::new(),
                };
                self.set.objects.insert(*obj, Obj::Live(Box::new(state)));
                self.set_entry(*dir, name, Some(obj | (dtype(*mode) << 60)));
                self.changed(*dir, 1)?;
                if is_dir {
                    self.dir(*dir)?.znode.links += 1;
                }
            }
            Lr::Remove { dir, name } => {
                let v = self.lookup(*dir, name)?.ok_or_else(|| {
                    Error::corrupt(format!("no {} in directory {dir}", String::from_utf8_lossy(name)))
                })?;
                let obj = v & ((1 << 48) - 1);
                let is_dir = self.state(obj)?.is_some_and(|s| s.znode.mode & S_IFMT == S_IFDIR);
                if is_dir != (r.ty == tx::RMDIR) {
                    return Err(Error::corrupt(format!("object {obj} removed as what it is not")));
                }
                self.unlink(obj)?;
                self.set_entry(*dir, name, None);
                self.changed(*dir, -1)?;
                if is_dir {
                    let d = self.dir(*dir)?;
                    d.znode.links = d.znode.links.saturating_sub(1);
                }
            }
            Lr::Link { dir, obj, name } => {
                self.dir(*dir)?;
                if self.lookup(*dir, name)?.is_some() {
                    return Err(Error::corrupt(format!(
                        "{} already in directory {dir}",
                        String::from_utf8_lossy(name)
                    )));
                }
                let s = self.state(*obj)?.ok_or_else(|| Error::corrupt(format!("object {obj} is not there")))?;
                if s.znode.mode & S_IFMT == S_IFDIR {
                    return Err(Error::corrupt(format!("a link to directory {obj}")));
                }
                s.znode.links += 1;
                s.znode.ctime = stamp;
                let mode = s.znode.mode;
                self.set_entry(*dir, name, Some(obj | (dtype(mode) << 60)));
                self.changed(*dir, 1)?;
            }
            Lr::Rename { sdir, tdir, sname, tname } => {
                let v = self.lookup(*sdir, sname)?.ok_or_else(|| {
                    Error::corrupt(format!("no {} in directory {sdir}", String::from_utf8_lossy(sname)))
                })?;
                let obj = v & ((1 << 48) - 1);
                self.dir(*tdir)?;
                let is_dir = self.state(obj)?.is_some_and(|s| s.znode.mode & S_IFMT == S_IFDIR);
                if let Some(t) = self.lookup(*tdir, tname)? {
                    let target = t & ((1 << 48) - 1);
                    if target == obj {
                        return Ok(());
                    }
                    let t_dir = self.state(target)?.is_some_and(|s| s.znode.mode & S_IFMT == S_IFDIR);
                    if t_dir != is_dir {
                        return Err(Error::corrupt(format!("object {obj} renamed over {target}")));
                    }
                    self.unlink(target)?;
                    self.changed(*tdir, -1)?;
                    if t_dir {
                        let d = self.dir(*tdir)?;
                        d.znode.links = d.znode.links.saturating_sub(1);
                    }
                }
                self.set_entry(*sdir, sname, None);
                self.changed(*sdir, -1)?;
                self.set_entry(*tdir, tname, Some(v));
                self.changed(*tdir, 1)?;
                if is_dir && sdir != tdir {
                    let d = self.dir(*sdir)?;
                    d.znode.links = d.znode.links.saturating_sub(1);
                    self.dir(*tdir)?.znode.links += 1;
                }
                if let Some(s) = self.state(obj)? {
                    s.znode.ctime = stamp;
                }
            }
            Lr::Write { obj, offset, length, bp, data } => {
                if self.file(*obj)?.is_none() {
                    return Ok(());
                }
                let eod = offset.saturating_add(*length);
                let (op, end) = match data {
                    Some(at) => {
                        let stored = {
                            let bytes = self.copied(r.block, at)?.to_vec();
                            self.arena.append(&bytes)?
                        };
                        (DataOp::Stored { offset: *offset, len: *length, at: stored }, eod)
                    }
                    // Written in place: the whole block (a shorter write, from the block's
                    // start), the size grown to the write's end only.
                    None => {
                        let bs = bp.lsize;
                        let (start, len) = if *length < bs { (offset - offset % bs, bs) } else { (*offset, *length) };
                        (DataOp::Block { offset: start, len, bp: bp.clone() }, start.saturating_add(len))
                    }
                };
                let Some(s) = self.file(*obj)? else { return Ok(()) };
                s.znode.size =
                    if matches!(op, DataOp::Block { .. }) && s.znode.size < eod { eod } else { s.znode.size.max(end) };
                s.data.push(op);
                (s.znode.mtime, s.znode.ctime) = (stamp, stamp);
            }
            Lr::Truncate { obj, offset, length } => {
                let Some(s) = self.file(*obj)? else { return Ok(()) };
                let end = offset.saturating_add(*length);
                if *offset > s.znode.size {
                    s.znode.size = end;
                } else if *length == 0 {
                    s.data.push(DataOp::Zero { start: *offset, end: u64::MAX });
                    s.znode.size = *offset;
                } else {
                    s.data.push(DataOp::Zero { start: *offset, end: end.min(s.znode.size) });
                    s.znode.size = s.znode.size.max(end);
                }
                (s.znode.mtime, s.znode.ctime) = (stamp, stamp);
            }
            Lr::SetAttr { obj, mask, mode, uid, gid, size, atime, mtime } => {
                if r.at.len() > SETATTR_LEN {
                    self.refuse(*obj, "a setattr record with optional attributes");
                    return Ok(());
                }
                let Some(s) = self.state(*obj)? else { return Ok(()) };
                if mask & ATTR_SIZE != 0 {
                    if *size < s.znode.size {
                        s.data.push(DataOp::Zero { start: *size, end: u64::MAX });
                    }
                    s.znode.size = *size;
                }
                if mask & ATTR_MODE != 0 {
                    s.znode.mode = (s.znode.mode & S_IFMT) | (mode & 0o7777);
                }
                if mask & ATTR_UID != 0 {
                    s.znode.uid = *uid;
                }
                if mask & ATTR_GID != 0 {
                    s.znode.gid = *gid;
                }
                if mask & ATTR_ATIME != 0 {
                    s.atime = *atime;
                }
                if mask & (ATTR_MTIME | ATTR_SIZE) != 0 {
                    s.znode.mtime = *mtime;
                }
                s.znode.ctime = stamp;
            }
            Lr::Write2 { obj, offset, length } => {
                let Some(s) = self.file(*obj)? else { return Ok(()) };
                s.znode.size = s.znode.size.max(offset.saturating_add(*length));
            }
            Lr::Other { objects } => {
                let why = format!("an intent log record of type {} is not replayed", r.ty);
                for &o in objects.iter().filter(|&&o| o != 0) {
                    self.refuse(o, &why);
                }
            }
        }
        Ok(())
    }

    /// Regular file `obj` (`None`: not there; a record of it is dropped).
    fn file(&mut self, obj: u64) -> Result<Option<&mut State>> {
        match self.state(obj)? {
            Some(s) if s.znode.mode & S_IFMT == S_IFREG => Ok(Some(s)),
            Some(_) => Err(Error::corrupt(format!("object {obj} written is not a regular file"))),
            None => Ok(None),
        }
    }

    fn refuse(&mut self, obj: u64, why: &str) {
        self.set.refused.entry(obj).or_insert_with(|| why.to_owned());
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    //! The records applied as an import does, one by one, over the root file system of a real
    //! pool (`fixtures/zfs/linux/basic`): what each leaves, and the records that cannot apply.
    use super::*;
    use crate::format::zap;
    use fs_inspect_core::DriverContext;

    const FREE: u64 = 1 << 30;

    struct Pool {
        fs: ZfsFs,
        z: Zpl,
        /// The root directory's regular files and directories: name, object.
        files: Vec<(Vec<u8>, u64)>,
        dirs: Vec<(Vec<u8>, u64)>,
    }

    fn pool() -> Pool {
        let src = fs_inspect_testkit::SparseSource::open(fs_inspect_testkit::fixture("zfs/linux/basic.fsbs"));
        let fs = ZfsFs::open(src, &DriverContext::default()).unwrap();
        let z = fs.file_systems().unwrap().0.into_iter().find(|z| z.prefix.is_empty()).unwrap();
        let root = z.objset.dnode(fs.reader(), z.root).unwrap().unwrap();
        let (mut files, mut dirs) = (Vec::new(), Vec::new());
        for e in zap::entries(fs.reader(), &root, 1 << 16).unwrap() {
            let v = e.first().unwrap();
            let obj = v & ((1 << 48) - 1);
            match v >> 60 {
                8 if z.file(fs.reader(), obj).unwrap().is_some_and(|f| f.1.links == 1) => files.push((e.name, obj)),
                4 => dirs.push((e.name, obj)),
                _ => {}
            }
        }
        assert!(files.len() >= 2 && !dirs.is_empty());
        Pool { fs, z, files, dirs }
    }

    fn rec(ty: u64, lr: Lr) -> Record {
        Record { ty, ci: false, txg: 0, seq: 0, block: 0, at: 0..0, lr }
    }

    fn create(dir: u64, obj: u64, mode: u64, name: &[u8], target: Option<&str>) -> Record {
        let ty = if mode & S_IFMT == S_IFDIR { tx::MKDIR } else { tx::CREATE };
        rec(
            ty,
            Lr::Create {
                dir,
                obj,
                mode,
                uid: 1,
                gid: 2,
                generation: 3,
                crtime: (400, 5),
                rdev: 0,
                name: name.to_vec(),
                target: target.map(|t| t.as_bytes().to_vec()),
            },
        )
    }

    fn remove(dir: u64, name: &[u8], rmdir: bool) -> Record {
        rec(if rmdir { tx::RMDIR } else { tx::REMOVE }, Lr::Remove { dir, name: name.to_vec() })
    }

    fn rename(sdir: u64, sname: &[u8], tdir: u64, tname: &[u8]) -> Record {
        rec(tx::RENAME, Lr::Rename { sdir, tdir, sname: sname.to_vec(), tname: tname.to_vec() })
    }

    fn state<'s>(b: &'s Builder, obj: u64) -> &'s State {
        match b.set.objects.get(&obj) {
            Some(Obj::Live(s)) => s,
            other => panic!("object {obj}: {other:?}"),
        }
    }

    fn freed(b: &Builder, obj: u64) -> bool {
        matches!(b.set.objects.get(&obj), Some(Obj::Freed))
    }

    /// Creates, links, removes and renames: entries, link counts (a directory's `..`),
    /// sizes and times; every record that cannot apply fails as it fails the import.
    #[test]
    fn namespace_records_apply_as_an_import_does() {
        let p = pool();
        let log = zil::Log::default();
        let arena = Scratch::memory(1 << 20).arena();
        let mut b = Builder {
            fs: &p.fs,
            z: &p.z,
            log: &log,
            arena: &arena,
            set: SetLog::default(),
            stamp: (500, 0),
            block: None,
        };
        let root = p.z.root;
        let (f0, o0) = p.files[0].clone();
        let (f1, o1) = p.files[1].clone();
        let (d0, _) = p.dirs[0].clone();
        let root_size = b.dir(root).unwrap().znode.size;
        let root_links = b.dir(root).unwrap().znode.links;
        assert!(!b.in_use(FREE).unwrap());

        // A file, a directory and a symlink made.
        b.apply(&create(root, FREE, S_IFREG | 0o644, b"zz-new", None)).unwrap();
        b.apply(&create(root, FREE + 1, S_IFDIR | 0o755, b"zz-dir", None)).unwrap();
        b.apply(&create(root, FREE + 2, 0o120777, b"zz-link", Some("target"))).unwrap();
        let s = state(&b, FREE);
        assert!(s.new && s.znode.links == 1 && s.znode.size == 0 && s.crtime == Some((400, 5)));
        assert_eq!((state(&b, FREE + 1).znode.size, state(&b, FREE + 1).znode.links), (2, 2));
        assert_eq!(state(&b, FREE + 2).znode.size, 6);
        assert_eq!(b.set.entry(root, b"zz-new", NameMatch::Exact), Some(Some(FREE | (8 << 60))));
        let r = state(&b, root);
        assert_eq!((r.znode.size, r.znode.links, r.znode.mtime), (root_size + 3, root_links + 1, (500, 0)));
        assert!(b.in_use(FREE).unwrap());
        // A name already there (logged or on disk), a slot in use, a directory not there.
        assert!(b.apply(&create(root, FREE + 3, S_IFREG, b"zz-new", None)).is_err());
        assert!(b.apply(&create(root, FREE + 3, S_IFREG, &f0, None)).is_err());
        assert!(b.apply(&create(root, FREE, S_IFREG, b"zz-other", None)).unwrap_err().message().contains("in use"));
        assert!(b.apply(&create(o0, FREE + 3, S_IFREG, b"x", None)).unwrap_err().message().contains("not there"));
        // Inside the new directory: nothing on disk to look up.
        assert_eq!(b.lookup(FREE + 1, b"anything").unwrap(), None);

        // Links: a second name, not to a directory, not over a name, not of nothing.
        let link = |dir, obj, name: &[u8]| rec(tx::LINK, Lr::Link { dir, obj, name: name.to_vec() });
        b.apply(&link(FREE + 1, FREE, b"again")).unwrap();
        assert_eq!(state(&b, FREE).znode.links, 2);
        assert!(b.apply(&link(root, FREE + 1, b"zz-d")).unwrap_err().message().contains("a link to directory"));
        assert!(b.apply(&link(root, FREE, b"zz-link")).unwrap_err().message().contains("already"));
        assert!(b.apply(&link(root, FREE + 5, b"zz-z")).unwrap_err().message().contains("not there"));

        // A directory that is not empty is not removed; one removed with the wrong record
        // type fails; a missing name fails.
        assert!(b.apply(&remove(root, b"zz-dir", true)).unwrap_err().message().contains("not empty"));
        assert!(b.apply(&remove(root, b"zz-new", true)).unwrap_err().message().contains("what it is not"));
        assert!(b.apply(&remove(root, b"zz-nothing", false)).is_err());
        // Removed: one link of two, then the last one frees the file.
        b.apply(&remove(FREE + 1, b"again", false)).unwrap();
        assert_eq!(b.set.entry(FREE + 1, b"again", NameMatch::Exact), Some(None));
        assert_eq!(state(&b, FREE).znode.links, 1);
        b.apply(&remove(root, b"zz-dir", true)).unwrap();
        assert!(freed(&b, FREE + 1));
        assert_eq!(state(&b, root).znode.links, root_links);
        assert!(!b.in_use(FREE + 1).unwrap());

        // Renames: onto itself (nothing), over a file on disk (its last link: freed), a file
        // over a directory (fails), a missing source (fails).
        b.apply(&rename(root, b"zz-new", root, b"zz-new")).unwrap();
        b.apply(&link(root, FREE, b"zz-new-too")).unwrap();
        b.apply(&rename(root, b"zz-new", root, b"zz-new-too")).unwrap();
        assert_eq!(state(&b, FREE).znode.links, 2);
        b.apply(&rename(root, b"zz-new-too", root, &f1)).unwrap();
        assert!(freed(&b, o1));
        assert_eq!(b.set.entry(root, &f1, NameMatch::Exact), Some(Some(FREE | (8 << 60))));
        assert!(b.apply(&rename(root, &f1, root, &d0)).unwrap_err().message().contains("renamed over"));
        assert!(b.apply(&rename(root, b"zz-gone", root, b"x")).is_err());
        // A directory moved into another: the link counts of both follow; then over an
        // empty directory, which goes.
        b.apply(&create(root, FREE + 6, S_IFDIR | 0o755, b"zz-a", None)).unwrap();
        b.apply(&create(root, FREE + 7, S_IFDIR | 0o755, b"zz-b", None)).unwrap();
        b.apply(&rename(root, b"zz-a", FREE + 7, b"a")).unwrap();
        assert_eq!(state(&b, FREE + 7).znode.links, 3);
        b.apply(&create(root, FREE + 8, S_IFDIR | 0o755, b"zz-c", None)).unwrap();
        b.apply(&rename(FREE + 7, b"a", root, b"zz-c")).unwrap();
        assert!(freed(&b, FREE + 8));
        assert_eq!(state(&b, FREE + 7).znode.links, 2);
        // The file removed on disk: its record of a write later is dropped.
        b.apply(&remove(root, &f0, false)).unwrap();
        assert!(freed(&b, o0));
        let w2 = rec(tx::WRITE2, Lr::Write2 { obj: o0, offset: 0, length: 10 });
        b.apply(&w2).unwrap();
        assert!(freed(&b, o0));
    }

    /// Writes, truncates, setattrs and write2: the content changes and sizes they leave, the
    /// records of objects not there dropped, of directories refused, optional attributes and
    /// records not replayed refused.
    #[test]
    fn content_records_apply_as_an_import_does() {
        let p = pool();
        let log = zil::Log::default();
        let arena = Scratch::memory(1 << 20).arena();
        let mut b = Builder {
            fs: &p.fs,
            z: &p.z,
            log: &log,
            arena: &arena,
            set: SetLog::default(),
            stamp: (500, 0),
            block: None,
        };
        let root = p.z.root;
        let o = FREE;
        b.apply(&create(root, o, S_IFREG | 0o600, b"zz-f", None)).unwrap();
        let mut bp = BlkPtr::default();
        bp.lsize = 4096;
        let write = |obj, offset, length, data: Option<std::ops::Range<usize>>| {
            rec(tx::WRITE, Lr::Write { obj, offset, length, bp: Box::new(bp), data })
        };
        // In place, shorter than its block: the whole block from its start, the size to the
        // write's end.
        b.apply(&write(o, 4196, 10, None)).unwrap();
        assert_eq!(state(&b, o).znode.size, 4206);
        assert!(matches!(state(&b, o).data[0], DataOp::Block { offset: 4096, len: 4096, .. }));
        b.apply(&write(o, 8192, 8192, None)).unwrap();
        assert_eq!(state(&b, o).znode.size, 16384);
        // Copied into a log block that is not there: damage.
        assert!(b.apply(&write(o, 0, 3, Some(0..3))).unwrap_err().message().contains("no log block"));
        // Of nothing: dropped; of a directory: damage.
        b.apply(&write(FREE + 9, 0, 1, None)).unwrap();
        assert!(!b.set.objects.contains_key(&(FREE + 9)));
        assert!(b.apply(&write(root, 0, 1, None)).unwrap_err().message().contains("not a regular file"));

        // Truncate: past the end grows; length 0 cuts; a range inside zeros it.
        let trunc = |offset, length| rec(tx::TRUNCATE, Lr::Truncate { obj: o, offset, length });
        b.apply(&trunc(20000, 100)).unwrap();
        assert_eq!(state(&b, o).znode.size, 20100);
        b.apply(&trunc(100, 50)).unwrap();
        assert_eq!(state(&b, o).data.last(), Some(&DataOp::Zero { start: 100, end: 150 }));
        assert_eq!(state(&b, o).znode.size, 20100);
        b.apply(&trunc(1000, 0)).unwrap();
        assert_eq!(
            (state(&b, o).znode.size, state(&b, o).data.last()),
            (1000, Some(&DataOp::Zero { start: 1000, end: u64::MAX }))
        );
        b.apply(&rec(tx::TRUNCATE, Lr::Truncate { obj: FREE + 9, offset: 0, length: 0 })).unwrap();

        // Setattr: each field its mask bit sets; a smaller size zeros past it.
        let setattr = |obj, mask, size| {
            rec(
                tx::SETATTR,
                Lr::SetAttr { obj, mask, mode: 0o4755, uid: 7, gid: 8, size, atime: (600, 1), mtime: (700, 2) },
            )
        };
        b.apply(&setattr(o, ATTR_MODE | ATTR_UID | ATTR_GID | ATTR_ATIME | ATTR_MTIME, 0)).unwrap();
        let s = state(&b, o);
        assert_eq!(
            (s.znode.mode, s.znode.uid, s.znode.gid, s.atime, s.znode.mtime, s.znode.size),
            (S_IFREG | 0o4755, 7, 8, (600, 1), (700, 2), 1000)
        );
        b.apply(&setattr(o, ATTR_SIZE, 10)).unwrap();
        assert_eq!(
            (state(&b, o).znode.size, state(&b, o).data.last()),
            (10, Some(&DataOp::Zero { start: 10, end: u64::MAX }))
        );
        b.apply(&setattr(o, ATTR_SIZE, 50)).unwrap();
        assert_eq!(state(&b, o).znode.size, 50);
        b.apply(&setattr(FREE + 9, ATTR_MODE, 0)).unwrap();
        let mut long = setattr(o, ATTR_UID, 0);
        long.at = 0..SETATTR_LEN + 8;
        b.apply(&long).unwrap();
        assert!(b.set.refused(o).unwrap().contains("optional attributes"));
        assert_eq!(state(&b, o).znode.uid, 7);

        // Write2 extends the size only.
        b.apply(&rec(tx::WRITE2, Lr::Write2 { obj: o, offset: 100, length: 50 })).unwrap();
        assert_eq!(state(&b, o).znode.size, 150);
        b.apply(&rec(tx::WRITE2, Lr::Write2 { obj: o, offset: 0, length: 10 })).unwrap();
        assert_eq!(state(&b, o).znode.size, 150);
        b.apply(&rec(tx::WRITE2, Lr::Write2 { obj: FREE + 9, offset: 0, length: 10 })).unwrap();

        // A record not replayed: the objects it names refused (0 names none), the first reason
        // kept.
        b.apply(&rec(tx::CLONE_RANGE, Lr::Other { objects: vec![0, o, FREE + 10] })).unwrap();
        assert!(b.set.refused(o).unwrap().contains("optional attributes"));
        assert!(b.set.refused(FREE + 10).unwrap().contains("type 24"));
        assert!(b.set.refused(0).is_none());
    }

    /// Names keyed as they compare; the objects a log touches, all of them when its records
    /// could not be read.
    #[test]
    fn keys_and_touched_objects() {
        assert_eq!(key(b"AbC", NameMatch::Exact), b"AbC");
        assert_eq!(key("ÄbC".as_bytes(), NameMatch::AsciiCaseless), "Äbc".as_bytes());
        assert_eq!(key("ÄbC".as_bytes(), NameMatch::Caseless), "äbc".as_bytes());
        assert_eq!(key(&[0xff, b'A'], NameMatch::Caseless), [0xff, b'A']);
        let mut t = Touched::default();
        t.sets.insert(1, None);
        t.sets.insert(2, Some([5].into_iter().collect()));
        assert!(t.touched(1, 99) && t.touched(2, 5) && !t.touched(2, 6) && !t.touched(3, 5));
        assert_eq!(dtype(S_IFDIR | 0o755), 4);
    }
}
