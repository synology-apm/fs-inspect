//! The XFS [`Filesystem`]: used blocks are the gaps between the free extents of each AG's
//! by-block-number free space B+tree, streamed one leaf at a time.

use crate::format::ag::{self, Agf, NULLAGBLOCK};
use crate::format::geom::Geom;
use crate::format::inode;
use crate::format::log::{LogArea, LogState};
use crate::format::overlay::FileUpdates;
use crate::format::recover::XfsReplayed;
use crate::format::sb::{SB_CRC_OFF, SB_MIN_BYTES, Superblock, VERSION_DIRV2, crc_ok};
use fs_inspect_core::FsInfoExt;
use fs_inspect_core::Integrity;
use fs_inspect_core::Scope;
use fs_inspect_core::StructureKind;
use fs_inspect_core::{
    ByteRange, Confidence, DiagCode, Diagnostics, DriverContext, Error, Filesystem, FnCursor, FsInfo, FsKind, Limits,
    RangeCursor, Result, Sniff, push_range,
};
use fs_inspect_core::{Role, Site};
use fs_inspect_io::DynSource;
use fs_inspect_io::batch::{BATCH_BYTES, GAP_BYTES, plan, read_runs};
use std::sync::Arc;

/// Most levels of a free space btree followed (XFS itself allows far fewer).
const MAX_LEVELS: usize = 32;

/// `High` for a sane v4 superblock or a sane v5 one whose checksum matches, else `Medium`.
pub fn probe(s: &Sniff<'_>) -> Option<(FsKind, Confidence)> {
    if s.head.len() < 4 || &s.head[..4] != crate::format::sb::SB_MAGIC {
        return None;
    }
    let Ok(sb) = Superblock::parse(s.head) else { return Some((FsKind::Xfs, Confidence::Medium)) };
    let sane = sb.validate().is_ok()
        && match sb.version() {
            4 => true,
            5 => s.head.get(..sb.sectsize as usize).is_some_and(|sec| crc_ok(sec, SB_CRC_OFF)),
            _ => false,
        };
    Some((FsKind::Xfs, if sane { Confidence::High } else { Confidence::Medium }))
}

/// Open the XFS volume starting at offset 0 of `src`.
pub fn open(src: DynSource, ctx: &DriverContext) -> Result<Arc<dyn Filesystem>> {
    Ok(Arc::new(XfsFs::open(src, ctx)?))
}

/// An opened XFS volume.
#[derive(Debug)]
pub struct XfsFs {
    src: DynSource,
    /// The superblock, its inode geometry checked.
    pub(crate) geom: Geom,
    info: FsInfo,
    limits: Limits,
    /// Most bytes a replay keeps in memory.
    cache_bytes: u64,
    /// Where a replay keeps its patches.
    scratch: fs_inspect_core::store::Scratch,
    diag: Diagnostics,
    sb_crc_ok: bool,
    /// Where the log is (`Err`: why it cannot be read).
    log: std::result::Result<LogArea, LogState>,
    /// The log's state, read once (set at open over a replay: clean).
    log_state: std::sync::OnceLock<LogState>,
    /// Opened over a replay ([`DriverContext::replayed`]): the volume as recovery leaves it.
    recovered: bool,
    /// Over a replay, the updates of files intents left unfinished make (applied to what the
    /// inodes map and their sizes: [`XfsFs::fork_extents`], [`XfsFs::parse_inode`]) ...
    files: Arc<FileUpdates>,
    /// ... and the inodes they change otherwise: refused.
    unfinished: Arc<std::collections::BTreeSet<u64>>,
}

/// The superblock in use, and whether the primary holds (its CRC on v5): the primary, else (it
/// does not validate, or its CRC is wrong) the secondary at the start of AG 1 when that one
/// holds and sits where its own geometry puts AG 1. A primary that validates but whose CRC
/// is wrong is used, reported, when the secondary does not hold.
fn pick_superblock(src: &DynSource, primary: Superblock, integrity: &Integrity) -> Result<(Superblock, bool)> {
    let site = Site::new(StructureKind::XfsSuperblock);
    let crc_holds = |sb: &Superblock, at: u64| -> Result<bool> {
        if !sb.is_v5() {
            return Ok(true);
        }
        let sec = src.read_vec(at, usize::from(sb.sectsize).max(SB_MIN_BYTES))?;
        Ok(integrity.ok(Role::Select, site.at(at), || crc_ok(&sec[..usize::from(sb.sectsize)], SB_CRC_OFF).into()))
    };
    let valid = primary.validate();
    let why = match &valid {
        Ok(()) if crc_holds(&primary, 0)? => return Ok((primary, true)),
        Ok(()) => "checksum mismatch".to_string(),
        Err(e) => e.to_string(),
    };
    let diag = integrity.diagnostics();
    let at = u64::from(primary.agblocks).checked_mul(u64::from(primary.blocksize));
    if let Some(at) = at.filter(|&a| a > 0 && a.saturating_add(SB_MIN_BYTES as u64) <= src.size()) {
        let read = src.read_vec(at, SB_MIN_BYTES);
        let secondary = match read {
            Ok(b) => Superblock::parse(&b).ok(),
            Err(e) if e.scope() == Scope::Unit => None,
            Err(e) => return Err(e),
        };
        if let Some(sb) = secondary
            && sb.validate().is_ok()
            && u64::from(sb.agblocks) * u64::from(sb.blocksize) == at
            && crc_holds(&sb, at)?
        {
            diag.warn(
                DiagCode::BackupUsed,
                format!("xfs primary superblock damaged ({why}); using the secondary of AG 1"),
            );
            return Ok((sb, false));
        }
    }
    valid.map_err(|e| e.context("xfs superblock"))?;
    diag.warn(DiagCode::ChecksumMismatch, "superblock checksum mismatch");
    Ok((primary, false))
}

impl XfsFs {
    /// Open the XFS volume at offset 0 of `src`; an external log is looked for among
    /// `ctx.peers`. Over a replay ([`DriverContext::replayed`], `src` patched by it), as
    /// recovery leaves it: the superblock read through the patches (a `growfs` the log holds
    /// included), the log clean.
    pub fn open(src: DynSource, ctx: &DriverContext) -> Result<Self> {
        let replayed = match &ctx.replayed {
            Some(r) => Some(
                (r.clone() as Arc<dyn std::any::Any + Send + Sync>)
                    .downcast::<XfsReplayed>()
                    .map_err(|_| Error::invalid_argument("an xfs volume opened over another file system's replay"))?,
            ),
            None => None,
        };
        let mut head = vec![0u8; SB_MIN_BYTES.max(512)];
        src.read_exact_at(0, &mut head)?;
        let primary = Superblock::parse(&head).map_err(|e| Error::format(format!("xfs: {e}")))?;
        let integrity = ctx.integrity();
        let (sb, sb_crc_ok) = pick_superblock(&src, primary, &integrity)?;
        let geom = Geom::new(&sb, integrity)?;
        match sb.version() {
            // Without version 2 directories (IRIX era): not supported.
            4 if sb.versionnum & VERSION_DIRV2 == 0 => {
                return Err(Error::unsupported("xfs v4 without version 2 directories"));
            }
            4 | 5 => {}
            v => return Err(Error::unsupported(format!("xfs superblock version {v}"))),
        }
        if sb.rblocks > 0 || sb.rextents > 0 {
            return Err(Error::unsupported("xfs with a realtime device"));
        }
        let volume_bytes = sb.dblocks * sb.bs(); // validate() checked the product
        if src.size() < volume_bytes {
            ctx.diagnostics.warn(
                DiagCode::Inconsistent,
                format!("source ({} bytes) is shorter than the file system ({volume_bytes} bytes)", src.size()),
            );
        }
        // An external log is among the volumes given with this one.
        let devices = match (sb.logstart, &ctx.peers) {
            (0, Some(p)) => p.volumes(FsKind::XfsLog),
            _ => Vec::new(),
        };
        let (log, log_state) = match &replayed {
            Some(r) => {
                let clean = LogState::Clean { head_lsn: r.head_lsn, how: "replayed in memory" };
                (Err(clean.clone()), std::sync::OnceLock::from(clean))
            }
            None => (LogArea::find(&src, &sb, &devices), std::sync::OnceLock::new()),
        };
        let info = FsInfo::new(
            FsKind::Xfs,
            u64::from(sb.blocksize),
            volume_bytes,
            sb.label(),
            Some(fs_inspect_core::guid::format_uuid(&sb.uuid)),
        );
        Ok(XfsFs {
            src,
            geom,
            info,
            limits: ctx.limits.clone(),
            cache_bytes: ctx.max_cache_bytes,
            scratch: ctx.scratch.clone(),
            diag: ctx.diagnostics.clone(),
            sb_crc_ok,
            log,
            log_state,
            recovered: replayed.is_some(),
            files: replayed.as_ref().map(|r| r.files.clone()).unwrap_or_default(),
            unfinished: replayed.map(|r| r.unfinished.clone()).unwrap_or_default(),
        })
    }

    /// What a fork of inode `ino` (slot bytes `raw`, core `d`) maps: the data fork, or the
    /// attribute fork with `attr`; over a replay, with the updates intents the log left
    /// unfinished make to it and the inodes exchanges link it to ([`FileUpdates::mapping`]).
    pub(crate) fn fork_extents(
        &self,
        ino: u64,
        raw: &[u8],
        d: &inode::Dinode,
        attr: bool,
    ) -> Result<Vec<fs_inspect_core::FileExtent>> {
        let (src, g, lim) = (self.source(), self.geometry(), self.file_limits());
        let fork = |ino: u64, raw: &[u8], d: &inode::Dinode, attr: bool| {
            if attr { inode::attr_extents(src, g, ino, raw, d, lim) } else { inode::extents(src, g, ino, raw, d, lim) }
        };
        if !self.files.touches(ino) {
            return fork(ino, raw, d, attr);
        }
        // The end of file recovery trims a regular file's blocks at (the size the replayed
        // inode has, not the one an exchange sets), unless it is preallocated or append-only.
        let eof = match inode::parse(raw, g, ino)? {
            Some(on_disk)
                if on_disk.is_reg() && on_disk.flags & (inode::DIFLAG_PREALLOC | inode::DIFLAG_APPEND) == 0 =>
            {
                Some(on_disk.size)
            }
            _ => None,
        };
        self.files.mapping(g, ino, attr, eof, &mut |other, attr| {
            if other == ino {
                return fork(ino, raw, d, attr);
            }
            let raw = src.read_vec(self.inode_byte(other)?, self.inode_len())?;
            match inode::parse(&raw, g, other)? {
                Some(d) => fork(other, &raw, &d, attr),
                None => Err(Error::corrupt(format!("xfs XMI exchanging with inode {other}, not in use"))),
            }
        })
    }

    /// The size an exchange the log left unfinished sets for inode `ino` (over a replay).
    pub(crate) fn updated_size(&self, ino: u64) -> Option<u64> {
        self.files.size(ino)
    }

    /// Refused when the log left an `ATTRI` that changes inode `ino` unfinished (over a replay):
    /// its attributes are not as recovery leaves them.
    pub(crate) fn check_finished(&self, ino: u64) -> Result<()> {
        if self.unfinished.contains(&ino) {
            return Err(Error::unsupported(format!("xfs inode {ino}: an intent the log left unfinished changes it")));
        }
        Ok(())
    }

    /// The primary superblock.
    pub fn superblock(&self) -> &Superblock {
        self.geom.sb()
    }

    /// Whether the primary superblock holds: it validates and its checksum matches (v5).
    /// When it does not, the secondary of AG 1 may be in use.
    pub fn superblock_crc_ok(&self) -> bool {
        self.sb_crc_ok
    }

    /// The limits the volume was opened with.
    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// The volume it was opened on (offset 0 is the start of the volume).
    pub fn source(&self) -> &DynSource {
        &self.src
    }

    /// Where reading reports what it worked around.
    pub(crate) fn diag(&self) -> &Diagnostics {
        &self.diag
    }

    /// Messages reported while opening and reading (tests).
    #[cfg(test)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub(crate) fn warnings(&self) -> Vec<String> {
        self.diag.own().into_iter().map(|d| d.message).collect()
    }

    pub(crate) fn read_block(&self, agno: u32, agbno: u32) -> Result<Vec<u8>> {
        let off = self
            .geom
            .sb()
            .ag_byte(agno, agbno as u64)
            .ok_or_else(|| Error::corrupt(format!("xfs: AG {agno} block {agbno} offset overflows")))?;
        self.src.read_vec(off, self.geom.sb().blocksize as usize)
    }

    /// The AGF of `agno`, or `None` (after a diagnostic) when it cannot be trusted.
    fn read_agf(&self, agno: u32) -> Result<Option<Agf>> {
        let off = self
            .geom
            .sb()
            .ag_byte(agno, 0)
            .and_then(|o| o.checked_add(self.geom.sb().sectsize as u64))
            .ok_or_else(|| Error::corrupt("xfs: AGF offset overflows"))?;
        let why = match self.src.read_vec(off, self.geom.sb().sectsize as usize) {
            Ok(buf) => match Agf::parse(&buf, &self.geom, agno) {
                Ok(agf) => return Ok(Some(agf)),
                Err(e) => e.to_string(),
            },
            // Past the end of a truncated image: damage, like a bad AGF.
            Err(e) if e.scope() == Scope::Unit => e.to_string(),
            Err(e) => return Err(e),
        };
        self.diag
            .warn(DiagCode::CountedAsUsed, format!("AGF of AG {agno} is damaged ({why}); the whole AG counts as used"));
        Ok(None)
    }

    /// The bnobt leaves of `agno` in key order, from its interior levels (each read in
    /// batches, its nodes checked).
    fn leaves(&self, agno: u32, agf: &Agf) -> Result<Vec<u32>> {
        let levels = agf.bno_level as usize;
        if levels == 0 || levels > MAX_LEVELS.min(self.limits.max_tree_depth) {
            return Err(Error::corrupt(format!("xfs: AG {agno}: bnobt has {levels} levels")));
        }
        let mut nodes = vec![agf.bno_root];
        let mut budget = self.limits.max_tree_nodes;
        for want_level in (1..levels).rev() {
            let mut kids: Vec<Vec<u32>> = vec![Vec::new(); nodes.len()];
            let mut failed: Option<Error> = None;
            self.read_blocks(agno, &nodes, |i, b| {
                let bno = nodes[i];
                let b = match b {
                    Some(b) => std::borrow::Cow::Borrowed(b),
                    None => std::borrow::Cow::Owned(self.read_block(agno, bno)?),
                };
                let check = || -> Result<Vec<u32>> {
                    let h = ag::parse_hdr(&b, &self.geom, agno, bno)?;
                    if h.level as usize != want_level {
                        return Err(Error::corrupt(format!("level {} (expected {want_level})", h.level)));
                    }
                    if h.numrecs == 0 {
                        return Err(Error::corrupt("empty interior node"));
                    }
                    if i == 0 && h.leftsib != NULLAGBLOCK {
                        return Err(Error::corrupt("leftmost node has a left sibling"));
                    }
                    let mut v = Vec::with_capacity(h.numrecs as usize);
                    for k in 0..h.numrecs as usize {
                        let child = ag::ptr(&b, self.geom.sb(), k)?;
                        if child == 0 || child >= agf.length {
                            return Err(Error::corrupt(format!("child pointer {child} outside the AG")));
                        }
                        v.push(child);
                    }
                    Ok(v)
                };
                match check() {
                    Ok(v) => kids[i] = v,
                    Err(e) => {
                        failed.get_or_insert(in_block(agno, bno)(e));
                    }
                }
                Ok(())
            })?;
            if let Some(e) = failed {
                return Err(e);
            }
            nodes = kids.concat();
            budget = budget
                .checked_sub(nodes.len() as u64)
                .ok_or_else(|| Error::limit(format!("xfs: AG {agno}: bnobt has too many nodes")))?;
        }
        Ok(nodes)
    }

    /// Read blocks `bnos` of `agno`, close ones together: `f` gets each one's index and bytes
    /// (in the order read; `None`: not read with the others).
    pub(crate) fn read_blocks<F: FnMut(usize, Option<&[u8]>) -> Result<()>>(
        &self,
        agno: u32,
        bnos: &[u32],
        mut f: F,
    ) -> Result<()> {
        let bs = self.geom.sb().bs();
        let items = bnos
            .iter()
            .enumerate()
            .filter_map(|(i, &b)| Some((self.geom.sb().ag_byte(agno, u64::from(b))?, bs, i)))
            .collect();
        read_runs::<_, Error>(&*self.src, plan(items, BATCH_BYTES, GAP_BYTES), &mut f)
    }
}

fn corrupt(agno: u32, bno: u32, what: &str) -> Error {
    Error::corrupt(format!("xfs: AG {agno} bnobt block {bno}: {what}"))
}

/// An error found in bnobt block `bno` of AG `agno`.
fn in_block(agno: u32, bno: u32) -> impl Fn(Error) -> Error {
    move |e| e.context(format_args!("xfs: AG {agno} bnobt block {bno}"))
}

/// Free extents of one AG kept from the checking walk (32 MiB, and at most `max_alloc`
/// bytes); an AG with more is walked again to emit its ranges.
const MAX_BUFFERED_EXTENTS: usize = 1 << 22;

/// Where the walk of one AG stands.
#[derive(Debug)]
struct AgWalk {
    agno: u32,
    agf: Agf,
    /// Next leaf to read, or `NULLAGBLOCK` when done.
    next: u32,
    /// The leaf read before `next` (its expected left sibling).
    prev: u32,
    /// AG block after the last free extent seen: everything from here up to the next free
    /// extent is used.
    pos: u32,
    free_sum: u64,
    leaves: u64,
    /// The leaves in key order (from the interior levels) and the index of `next` in it.
    order: Vec<u32>,
    at: usize,
    /// Leaves read ahead along `order`.
    ahead: Vec<(u32, Vec<u8>)>,
}

impl AgWalk {
    fn new(agno: u32, agf: Agf, order: Vec<u32>) -> Self {
        let next = order.first().copied().unwrap_or(NULLAGBLOCK);
        AgWalk { agno, agf, next, prev: NULLAGBLOCK, pos: 0, free_sum: 0, leaves: 0, order, at: 0, ahead: Vec::new() }
    }
}

#[derive(Debug)]
enum State {
    /// Read the AGF of this AG next.
    Ag(u32),
    /// Second walk of an AG whose bnobt checked out but held too many extents to keep.
    Walk(Box<AgWalk>),
}

impl XfsFs {
    /// Push AG-relative blocks `[start, end)` of `agno` as a used byte range.
    fn push_blocks(&self, out: &mut Vec<ByteRange>, agno: u32, start: u32, end: u32) -> Result<()> {
        if end > start {
            let off =
                self.geom.sb().ag_byte(agno, start as u64).ok_or_else(|| Error::corrupt("xfs: offset overflows"))?;
            push_range(out, off, (end - start) as u64 * self.geom.sb().bs());
        }
        Ok(())
    }

    /// Blocks holding the four AG header sectors (superblock, AGF, AGI, AGFL).
    fn hdr_blocks(&self) -> u32 {
        (4 * self.geom.sb().sectsize as u32).div_ceil(self.geom.sb().blocksize)
    }

    fn step(&self, state: &mut State, out: &mut Vec<ByteRange>) -> Result<bool> {
        match state {
            State::Ag(agno) => {
                let agno = *agno;
                if agno >= self.geom.sb().agcount {
                    return Ok(false);
                }
                *state = State::Ag(agno + 1);
                let Some(agf) = self.read_agf(agno)? else {
                    self.push_blocks(out, agno, 0, self.geom.sb().ag_len(agno))?;
                    return Ok(true);
                };
                // The whole bnobt is checked before any range of the AG goes out: a damaged
                // tree (e.g. a crash-consistent snapshot whose log was not replayed, holding a
                // block XFS had only logged) cannot be trusted anywhere, so the AG counts as used.
                match self.check_ag(agno, &agf) {
                    Ok(Some(free)) => {
                        let mut pos = 0;
                        for (start, end) in free {
                            self.push_blocks(out, agno, pos, start)?;
                            pos = end;
                        }
                        self.push_blocks(out, agno, pos, agf.length)?;
                    }
                    Ok(None) => *state = State::Walk(Box::new(AgWalk::new(agno, agf, self.leaves(agno, &agf)?))),
                    Err(e) if e.scope() == Scope::Unit => {
                        self.diag.warn(
                            DiagCode::CountedAsUsed,
                            format!("free space btree of AG {agno} is damaged ({e}); the whole AG counts as used"),
                        );
                        self.push_blocks(out, agno, 0, agf.length)?;
                    }
                    Err(e) => return Err(e),
                }
                Ok(true)
            }
            State::Walk(w) => {
                if w.next == NULLAGBLOCK {
                    self.push_blocks(out, w.agno, w.pos, w.agf.length)?;
                    *state = State::Ag(w.agno + 1);
                    return Ok(true);
                }
                let agno = w.agno;
                self.walk_leaf(w, |pos, start, _| self.push_blocks(out, agno, pos, start))?;
                Ok(true)
            }
        }
    }

    /// Walk the whole bnobt of `agno`, checking every block. Returns its free extents
    /// (`[start, end)` AG blocks, ascending), or `None` when there are too many to keep.
    fn check_ag(&self, agno: u32, agf: &Agf) -> Result<Option<Vec<(u32, u32)>>> {
        let mut w = AgWalk::new(agno, *agf, self.leaves(agno, agf)?);
        let cap = MAX_BUFFERED_EXTENTS.min((self.limits.max_alloc / 8).try_into().unwrap_or(usize::MAX));
        let mut free = Some(Vec::new());
        while w.next != NULLAGBLOCK {
            self.walk_leaf(&mut w, |_, start, end| {
                match &mut free {
                    Some(v) if v.len() < cap => v.push((start, end)),
                    _ => free = None,
                }
                Ok(())
            })?;
        }
        if w.free_sum != agf.freeblks as u64 {
            self.diag.warn(
                DiagCode::Inconsistent,
                format!("AG {agno}: bnobt holds {} free blocks, AGF says {}", w.free_sum, agf.freeblks),
            );
        }
        Ok(free)
    }

    /// Read and check leaf `w.next`, call `on_free(pos, start, end)` for each of its free
    /// extents (`pos`: end of the previous one), move to the right sibling.
    fn walk_leaf(&self, w: &mut AgWalk, mut on_free: impl FnMut(u32, u32, u32) -> Result<()>) -> Result<()> {
        let (agno, bno) = (w.agno, w.next);
        w.leaves += 1;
        if w.leaves > w.agf.length as u64 || w.leaves > self.limits.max_tree_nodes {
            return Err(in_block(agno, bno)(Error::limit("bnobt leaves (a cycle?)")));
        }
        let b = self.leaf(w, bno)?;
        let h = ag::parse_hdr(&b, &self.geom, agno, bno).map_err(in_block(agno, bno))?;
        if h.level != 0 {
            return Err(corrupt(agno, bno, &format!("leaf at level {}", h.level)));
        }
        if h.leftsib != w.prev {
            return Err(corrupt(agno, bno, &format!("left sibling {:#x}, expected {:#x}", h.leftsib, w.prev)));
        }
        // Only a root leaf (no siblings) may be empty; otherwise every leaf moves `pos` on,
        // which (with the bound above) rules out cycles.
        if h.numrecs == 0 && (h.leftsib != NULLAGBLOCK || h.rightsib != NULLAGBLOCK) {
            return Err(corrupt(agno, bno, "empty leaf"));
        }
        for i in 0..h.numrecs as usize {
            let (start, count) = ag::rec(&b, self.geom.sb(), i).map_err(in_block(agno, bno))?;
            let end = start.checked_add(count).filter(|&e| e <= w.agf.length);
            let Some(end) = end.filter(|_| count > 0) else {
                return Err(corrupt(agno, bno, &format!("free extent {start}+{count} outside the AG")));
            };
            // Free extents never cover the AG header sectors and are sorted, non-overlapping.
            if start < w.pos || start < self.hdr_blocks() {
                return Err(corrupt(agno, bno, &format!("free extent {start}+{count} out of order")));
            }
            on_free(w.pos, start, end)?;
            w.pos = end;
            w.free_sum += count as u64;
        }
        if h.rightsib != NULLAGBLOCK && (h.rightsib == 0 || h.rightsib >= w.agf.length) {
            return Err(corrupt(agno, bno, &format!("right sibling {} outside the AG", h.rightsib)));
        }
        w.prev = bno;
        w.next = h.rightsib;
        Ok(())
    }
}

impl XfsFs {
    /// Leaf `bno` of the walk `w`: from the leaves read ahead, which are refilled with the next
    /// batch of `w.order` when it is next there; read alone otherwise.
    fn leaf(&self, w: &mut AgWalk, bno: u32) -> Result<Vec<u8>> {
        if let Some(i) = w.ahead.iter().position(|e| e.0 == bno) {
            return Ok(w.ahead.swap_remove(i).1);
        }
        // The sibling chain follows the key order (a walk that leaves it fails its checks).
        if w.order.get(w.at) == Some(&bno) {
            let n = (BATCH_BYTES / self.geom.sb().bs()).max(1) as usize;
            let next: Vec<u32> = w.order[w.at..(w.at + n).min(w.order.len())].to_vec();
            w.at += next.len();
            let mut ahead = Vec::new();
            self.read_blocks(w.agno, &next, |i, b| {
                if let Some(b) = b {
                    ahead.push((next[i], b.to_vec()));
                }
                Ok(())
            })?;
            w.ahead = ahead;
            if let Some(i) = w.ahead.iter().position(|e| e.0 == bno) {
                return Ok(w.ahead.swap_remove(i).1);
            }
        }
        self.read_block(w.agno, bno)
    }

    /// Where the log is: on this volume or on an external log device.
    pub fn log_area(&self) -> Option<&LogArea> {
        self.log.as_ref().ok()
    }

    /// Whether the log is clean (read once).
    pub fn log_state(&self) -> &LogState {
        self.log_state.get_or_init(|| match &self.log {
            Ok(a) => a.inspect(),
            Err(s) => s.clone(),
        })
    }
}

impl fs_inspect_core::sealed::Fs for XfsFs {}

impl Filesystem for XfsFs {
    fn default_excludes(&self) -> &'static [fs_inspect_core::DefaultExclude] {
        fs_inspect_core::exclude::LINUX_DEFAULTS
    }

    /// The AGFs' free block counts, with the log clean and every AGF read whole.
    fn free_bytes(&self) -> Option<u64> {
        if !matches!(self.log_state(), LogState::Clean { .. }) {
            return None;
        }
        let sb = self.geom.sb();
        let mut free = 0u64;
        for agno in 0..sb.agcount {
            let off = sb.ag_byte(agno, 0)?.checked_add(u64::from(sb.sectsize))?;
            let buf = self.src.read_vec(off, sb.sectsize as usize).ok()?;
            free += u64::from(Agf::parse(&buf, &self.geom, agno).ok()?.freeblks);
        }
        free.checked_mul(u64::from(sb.blocksize)).filter(|&b| b <= self.info.size)
    }

    fn info(&self) -> &FsInfo {
        &self.info
    }

    fn file_map(&self) -> Option<&dyn fs_inspect_core::FileMap> {
        Some(self)
    }

    /// With a dirty log, lookups that read what the log changes are refused: browse the
    /// instance opened over the replay ([`Filesystem::replay`]).
    fn namespace(self: Arc<Self>) -> Option<Arc<dyn fs_inspect_core::Namespace>> {
        Some(self)
    }

    /// The log replayed in memory (`XfsReplayed`), when it is dirty and readable.
    fn replay(&self) -> Option<Result<Arc<dyn fs_inspect_core::Replayed>>> {
        if self.recovered || !matches!(self.log_state(), LogState::Dirty { .. }) {
            return None;
        }
        let area = match &self.log {
            Ok(a) => a,
            Err(s) => return Some(Err(Error::unsupported(format!("xfs log: {s:?}")))),
        };
        Some(
            crate::format::recover::replay(area, &self.src, &self.geom, self.cache_bytes, &self.scratch)
                .map(|r| Arc::new(r) as Arc<dyn fs_inspect_core::Replayed>),
        )
    }

    /// The log: clean (unmount record, or only superblock transactions to replay), dirty, or
    /// on an external device not given.
    fn verify(&self, scope: &fs_inspect_core::VerifyScope) -> Result<()> {
        crate::format::verify::verify(self, scope)
    }

    fn consistency(&self) -> fs_inspect_core::Consistency {
        match self.log_state() {
            LogState::Clean { .. } => fs_inspect_core::Consistency::Clean,
            LogState::Dirty { why, .. } => fs_inspect_core::Consistency::Inconsistent {
                why: format!("the log holds changes to replay ({why})"),
                allocation_covered: false,
                notes: Vec::new(),
            },
            LogState::Missing => {
                fs_inspect_core::Consistency::Unknown("the log is on an external device that was not given".into())
            }
        }
    }

    fn allocated(self: Arc<Self>) -> Result<Box<dyn RangeCursor>> {
        let mut state = State::Ag(0);
        let fs = self;
        Ok(Box::new(FnCursor::new(move |out: &mut Vec<ByteRange>| fs.step(&mut state, out))))
    }
}
