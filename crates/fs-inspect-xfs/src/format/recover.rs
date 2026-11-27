//! Log recovery in memory ([`XfsReplayed`], what
//! [`Filesystem::replay`](fs_inspect_core::Filesystem::replay) makes from the on-disk
//! instance): what replaying the log writes to the data device, as patches the recovered
//! instance reads through, the volume itself left as it is. The result is what a mount's
//! recovery leaves: the XFS log has no other specification.
//!
//! The records from the tail to the head ([`LogArea::walk`]) are split into transactions
//! (operations by transaction id, regions split across records joined again); only those whose
//! commit operation is in the log are replayed, in commit order, in two passes:
//!
//! 1. every cancelled buffer (`XFS_BLF_CANCEL`) is counted;
//! 2. the items of each transaction (buffers first, then inodes, then inode buffers, then
//!    cancels) are applied: a buffer's logged 128-byte chunks (or, for an inode buffer, only
//!    its `di_next_unlinked` fields), an inode's core (logged in the host's byte order) and
//!    forks, an inode chunk created (`ICREATE`). A buffer or inode is left alone while a
//!    cancel record of its buffer is still to come, and on v5 when the metadata on disk is
//!    already as new as the transaction (its LSN).
//!
//! Buffers replayed get their CRC computed again, as writing them would, and inodes theirs.
//!
//! What the replay holds is kept in its scratch ([`Scratch`], a temporary file unless none can be
//! made): the transactions' items as they are read (memory holds one offset per item), the buffers
//! replayed past the cache budget (`DriverContext::max_cache_bytes`, the ones used last kept in
//! memory), and the buffers it writes, as a [`PatchTable`].
//!
//! Intents (`EFI`, `RUI`, `CUI`) change only free space and reverse mappings: left unfinished,
//! the space they would free stays used (never too few blocks counted used). A `BUI` (a file's
//! block mapping updated) or an `XMI` (ranges of two files exchanged, their sizes set) left
//! unfinished, its done item not logged, is kept, in log order ([`XfsReplayed::files`]): the
//! instance over the replay applies them to the mappings and sizes it reads, as recovery
//! finishes them ([`overlay`](crate::format::overlay); the blocks they map are used already,
//! the ones they unmap stay used). An `ATTRI` (an extended attribute; only debug kernels log
//! one) names its inode ([`XfsReplayed::unfinished`]): the instance refuses it. An item this
//! module does not know fails the replay.

use crate::format::geom::Geom;
use crate::format::inode::{CORE_V2, CORE_V3, DINODE_CRC_OFF};
use crate::format::log::LogArea;
use crate::format::overlay::{BmapUpdate, Exchange, FileUpdate, FileUpdates};
use fs_inspect_core::ReplaySummaryExt;
use fs_inspect_core::checksum::{crc_with_zeroed_field, crc32c};
use fs_inspect_core::patch::{PatchBuilder, PatchTable};
use fs_inspect_core::store::{Arena, Scratch};
use fs_inspect_core::{Error, ReplaySummary, Replayed, Result};
use fs_inspect_io::DynSource;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;

/// An XFS volume's log replayed in memory (see the [module](self)): the buffers it writes, as
/// patches; their ranges are the targets.
#[derive(Debug)]
pub struct XfsReplayed {
    patches: Arc<PatchTable>,
    /// The LSN of the log's last record.
    pub(crate) head_lsn: u64,
    /// The updates of files `BUI`s and `XMI`s left unfinished make (see the [module](self)).
    pub(crate) files: Arc<FileUpdates>,
    /// The inodes an `ATTRI` left unfinished changes (see the [module](self)).
    pub(crate) unfinished: Arc<BTreeSet<u64>>,
    summary: ReplaySummary,
}

impl Replayed for XfsReplayed {
    fn patches(&self) -> &Arc<PatchTable> {
        &self.patches
    }

    fn summary(&self) -> ReplaySummary {
        self.summary.clone()
    }
}

const BB: u64 = 512;
const OP_START: u8 = 0x01;
const OP_COMMIT: u8 = 0x02;
const OP_CONTINUE: u8 = 0x04;
const OP_WAS_CONT: u8 = 0x08;
const OP_END: u8 = 0x10;
const OP_UNMOUNT: u8 = 0x20;
const CLIENT_LOG: u8 = 0xaa;
const CLIENT_TRANSACTION: u8 = 0x69;
const TRANS_MAGIC: u32 = 0x5452_414e;
const TRANS_HEADER_LEN: usize = 16;
/// Most regions one item may have (`XLOG_MAX_REGIONS_IN_ITEM`).
const MAX_REGIONS: u16 = 257;

const LI_EFI: u16 = 0x1236;
const LI_EFD: u16 = 0x1237;
const LI_INODE: u16 = 0x123b;
const LI_BUF: u16 = 0x123c;
const LI_DQUOT: u16 = 0x123d;
const LI_QUOTAOFF: u16 = 0x123e;
const LI_ICREATE: u16 = 0x123f;
const LI_RUI: u16 = 0x1240;
const LI_RUD: u16 = 0x1241;
const LI_CUI: u16 = 0x1242;
const LI_CUD: u16 = 0x1243;
const LI_BUI: u16 = 0x1244;
const LI_BUD: u16 = 0x1245;
const LI_ATTRI: u16 = 0x1246;
const LI_ATTRD: u16 = 0x1247;
const LI_XMI: u16 = 0x1248;
const LI_XMD: u16 = 0x1249;

const BLF_INODE_BUF: u16 = 0x1;
const BLF_CANCEL: u16 = 0x2;
const BLF_DQUOT_BUF: u16 = 0x4 | 0x8 | 0x10;
/// Bytes per bit of a buffer item's data map.
const BLF_CHUNK: usize = 128;

const ILOG_DDATA: u32 = 0x002;
const ILOG_DEXT: u32 = 0x004;
const ILOG_DBROOT: u32 = 0x008;
const ILOG_DEV: u32 = 0x010;
const ILOG_ADATA: u32 = 0x040;
const ILOG_AEXT: u32 = 0x080;
const ILOG_ABROOT: u32 = 0x100;
const ILOG_DFORK: u32 = ILOG_DDATA | ILOG_DEXT | ILOG_DBROOT;
const ILOG_AFORK: u32 = ILOG_ADATA | ILOG_AEXT | ILOG_ABROOT;

const DINODE_MAGIC: u16 = 0x494e;
const DIFLAG2_BIGTIME: u64 = 1 << 3;
const DIFLAG2_NREXT64: u64 = 1 << 4;
const NULLAGINO: u32 = u32::MAX;
/// Header of a long-form (bmbt) block, v5 and v4.
const LBLOCK_CRC_LEN: usize = 72;
const LBLOCK_LEN: usize = 24;

/// Integers of a log item, in the byte order of the host that wrote it.
#[derive(Clone, Copy)]
struct Order {
    le: bool,
}

impl Order {
    /// The byte order of an item whose type is `region[..2]`; `None` for an unknown type.
    fn of(region: &[u8]) -> Option<(Order, u16)> {
        let b: [u8; 2] = region.get(..2)?.try_into().ok()?;
        let known = |t: u16| (LI_EFI..=0x124f).contains(&t);
        let (le, be) = (u16::from_le_bytes(b), u16::from_be_bytes(b));
        if known(le) {
            Some((Order { le: true }, le))
        } else if known(be) {
            Some((Order { le: false }, be))
        } else {
            None
        }
    }
    fn u16(self, b: &[u8], o: usize) -> Result<u16> {
        let a: [u8; 2] = field(b, o)?;
        Ok(if self.le { u16::from_le_bytes(a) } else { u16::from_be_bytes(a) })
    }
    fn u32(self, b: &[u8], o: usize) -> Result<u32> {
        let a: [u8; 4] = field(b, o)?;
        Ok(if self.le { u32::from_le_bytes(a) } else { u32::from_be_bytes(a) })
    }
    fn u64(self, b: &[u8], o: usize) -> Result<u64> {
        let a: [u8; 8] = field(b, o)?;
        Ok(if self.le { u64::from_le_bytes(a) } else { u64::from_be_bytes(a) })
    }
}

fn field<const N: usize>(b: &[u8], o: usize) -> Result<[u8; N]> {
    b.get(o..o + N)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| Error::corrupt(format!("xfs log item shorter than {}", o + N)))
}

fn be_u16(b: &[u8], o: usize) -> u16 {
    u16::from_be_bytes([b[o], b[o + 1]])
}
fn be_u32(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn be_u64(b: &[u8], o: usize) -> u64 {
    u64::from_be_bytes(b[o..o + 8].try_into().unwrap_or_default())
}

/// A log item: its regions, the first the format structure.
#[derive(Debug, Default)]
struct Item {
    regions: Vec<Vec<u8>>,
    /// Regions the format says it has (0: none read yet).
    total: u16,
}

impl Item {
    /// The item written to `arena` (its length, then each region's length and bytes, all
    /// little endian); where it is.
    fn store(&self, arena: &Arena) -> Result<u64> {
        let len: usize = self.regions.iter().map(|r| 4 + r.len()).sum();
        let mut rec = Vec::with_capacity(4 + len);
        rec.extend_from_slice(&len32(len)?.to_le_bytes());
        for r in &self.regions {
            rec.extend_from_slice(&len32(r.len())?.to_le_bytes());
            rec.extend_from_slice(r);
        }
        arena.append(&rec)
    }

    /// The item [`store`](Self::store) wrote at `at` of `arena`.
    fn load(arena: &Arena, at: u64) -> Result<Item> {
        let mut len = [0u8; 4];
        arena.read_at(at, &mut len)?;
        let rec = arena.read_vec(at + 4, u32::from_le_bytes(len) as usize)?;
        let mut regions = Vec::new();
        let mut o = 0usize;
        while o < rec.len() {
            let n = u32::from_le_bytes(field(&rec, o)?) as usize;
            let r = rec.get(o + 4..o + 4 + n).ok_or_else(|| Error::corrupt("xfs replay: a stored item"))?;
            regions.push(r.to_vec());
            o += 4 + n;
        }
        let total = u16::try_from(regions.len()).map_err(|_| Error::corrupt("xfs replay: a stored item"))?;
        Ok(Item { regions, total })
    }

    /// When it is replayed in its transaction ([`Class`]), and the buffer it cancels.
    fn class(&self) -> Result<(Class, Option<(u64, u32)>)> {
        let first = self.regions.first().ok_or_else(|| Error::corrupt("xfs log item"))?;
        let (order, ty) = Order::of(first).ok_or_else(|| Error::corrupt("xfs log item"))?;
        Ok(match ty {
            LI_BUF => {
                let flags = order.u16(first, 4)?;
                if flags & BLF_CANCEL != 0 {
                    (Class::Cancel, Some((order.u64(first, 8)?, u32::from(order.u16(first, 6)?))))
                } else if flags & BLF_INODE_BUF != 0 {
                    (Class::InodeBuffer, None)
                } else {
                    (Class::Buffer, None)
                }
            }
            LI_ICREATE => (Class::Buffer, None),
            _ => (Class::Other, None),
        })
    }
}

fn len32(n: usize) -> Result<u32> {
    u32::try_from(n).map_err(|_| Error::limit("an xfs log item of 4 GiB"))
}

/// The order items of a transaction are replayed in: buffers (and inode chunks created), then
/// the other items (inodes, intents), then inode buffers, then cancels.
#[derive(Clone, Copy)]
enum Class {
    Buffer = 0,
    Other = 1,
    InodeBuffer = 2,
    Cancel = 3,
}

/// A transaction being read.
#[derive(Debug)]
struct Trans {
    /// The LSN of the record where the transaction starts.
    lsn: u64,
    /// Bytes of the transaction header read so far.
    header: usize,
    /// The item being read (its last region may continue in the next record).
    item: Option<Item>,
    /// The items read whole, by [`Class`]: where each is in the work arena.
    items: [Vec<u64>; 4],
    /// The buffers its cancel items name.
    cancels: Vec<(u64, u32)>,
}

impl Trans {
    /// The item being read, stored: it is whole.
    fn finish_item(&mut self, arena: &Arena) -> Result<()> {
        let Some(item) = self.item.take() else { return Ok(()) };
        if item.regions.len() != usize::from(item.total) {
            return Err(Error::corrupt("xfs log item with regions missing"));
        }
        let (class, cancel) = item.class()?;
        self.items[class as usize].push(item.store(arena)?);
        self.cancels.extend(cancel);
        Ok(())
    }
}

/// A transaction committed: where it starts and its items, by [`Class`].
struct Committed {
    lsn: u64,
    items: [Vec<u64>; 4],
}

/// The transactions committed in the log, in commit order, their items in the work arena (in
/// memory: one offset per item, and the item being read of each open transaction); and every
/// cancel record they hold.
struct Parser<'a> {
    open: HashMap<u32, Trans>,
    committed: Vec<Committed>,
    cancels: Cancels,
    arena: &'a Arena,
}

impl Parser<'_> {
    fn record(&mut self, lsn: u64, data: &[u8], ops: u32) -> Result<()> {
        let mut off = 0usize;
        for _ in 0..ops {
            let hdr = data.get(off..off + 12).ok_or_else(|| Error::corrupt("xfs log: operation past the record"))?;
            let tid = be_u32(hdr, 0);
            let len = be_u32(hdr, 4) as usize;
            let (client, flags) = (hdr[8], hdr[9]);
            let region = data
                .get(off + 12..off + 12 + len)
                .ok_or_else(|| Error::corrupt("xfs log: operation past the record"))?;
            off += 12 + len;
            if client != CLIENT_TRANSACTION && client != CLIENT_LOG {
                return Err(Error::corrupt(format!("xfs log: operation of client {client:#x}")));
            }
            let Some(trans) = self.open.get_mut(&tid) else {
                // A transaction starts with an operation of its own; others before it began
                // before the tail.
                if flags & OP_START != 0 {
                    let t = Trans { lsn, header: 0, item: None, items: Default::default(), cancels: Vec::new() };
                    self.open.insert(tid, t);
                }
                continue;
            };
            let mut flags = flags & !OP_END;
            if flags & OP_WAS_CONT != 0 {
                flags &= !OP_CONTINUE;
            }
            match flags {
                0 | OP_CONTINUE => add(trans, region, self.arena)?,
                OP_WAS_CONT => add_continued(trans, region)?,
                OP_COMMIT => {
                    if let Some(mut t) = self.open.remove(&tid) {
                        t.finish_item(self.arena)?;
                        for key in t.cancels {
                            *self.cancels.entry(key).or_default() += 1;
                        }
                        self.committed.push(Committed { lsn: t.lsn, items: t.items });
                    }
                }
                OP_UNMOUNT => {
                    self.open.remove(&tid);
                }
                f => return Err(Error::corrupt(format!("xfs log: operation flags {f:#x}"))),
            }
        }
        Ok(())
    }
}

/// A new region of `t`: the transaction header, or a region of the item being read, or the
/// first of a new one (the one before stored in `arena`).
fn add(t: &mut Trans, region: &[u8], arena: &Arena) -> Result<()> {
    if region.is_empty() {
        return Ok(());
    }
    if t.header < TRANS_HEADER_LEN {
        let magic = region.get(..4).map(|m| u32::from_le_bytes(m.try_into().unwrap_or_default()));
        if t.header != 0 || !(magic == Some(TRANS_MAGIC) || magic == Some(TRANS_MAGIC.swap_bytes())) {
            return Err(Error::corrupt("xfs log: transaction without its header"));
        }
        if region.len() > TRANS_HEADER_LEN {
            return Err(Error::corrupt("xfs log: transaction header too long"));
        }
        t.header = region.len();
        return Ok(());
    }
    if t.item.as_ref().is_some_and(|i| i.total != 0 && i.regions.len() == usize::from(i.total)) {
        t.finish_item(arena)?;
    }
    let item = t.item.get_or_insert_with(Item::default);
    if item.total == 0 {
        let (order, _) = Order::of(region)
            .ok_or_else(|| Error::unsupported(format!("xfs log item {:02x?}", &region[..2.min(region.len())])))?;
        let total = order.u16(region, 2)?;
        if total == 0 || total > MAX_REGIONS {
            return Err(Error::corrupt(format!("xfs log item of {total} regions")));
        }
        item.total = total;
    }
    if item.regions.len() >= usize::from(item.total) {
        return Err(Error::corrupt("xfs log item with more regions than it says"));
    }
    item.regions.push(region.to_vec());
    Ok(())
}

/// The rest of a region split across records.
fn add_continued(t: &mut Trans, region: &[u8]) -> Result<()> {
    if t.header < TRANS_HEADER_LEN {
        t.header += region.len();
        if t.header != TRANS_HEADER_LEN {
            return Err(Error::corrupt("xfs log: transaction header of a wrong length"));
        }
        return Ok(());
    }
    let last = t.item.as_mut().and_then(|i| i.regions.last_mut());
    let last = last.ok_or_else(|| Error::corrupt("xfs log: a continued region without its start"))?;
    last.extend_from_slice(region);
    Ok(())
}

/// A buffer held in memory: its bytes and when it was last used.
struct Held {
    bytes: Vec<u8>,
    used: u64,
}

/// Metadata buffers of the data device as replay leaves them: the ones used last in memory
/// (within a budget), the others written out to the work arena.
struct Buffers<'a> {
    src: &'a DynSource,
    /// In memory: non-overlapping byte ranges by start (none overlaps one written out).
    held: BTreeMap<u64, Held>,
    /// Bytes `held` holds, at most `budget` but for the buffer in use.
    held_bytes: usize,
    budget: usize,
    /// `held` by when each was last used.
    lru: BTreeMap<u64, u64>,
    tick: u64,
    /// Written out: start → where in `arena`, and the length.
    out: BTreeMap<u64, (u64, usize)>,
    arena: &'a Arena,
    /// Buffers changed whose CRC is to be computed again, `(start, len)`.
    changed: HashSet<(u64, usize)>,
}

impl<'a> Buffers<'a> {
    fn new(src: &'a DynSource, arena: &'a Arena, budget: usize) -> Self {
        Buffers {
            src,
            held: BTreeMap::new(),
            held_bytes: 0,
            budget,
            lru: BTreeMap::new(),
            tick: 0,
            out: BTreeMap::new(),
            arena,
            changed: HashSet::new(),
        }
    }

    fn hold(&mut self, start: u64, bytes: Vec<u8>) {
        self.held_bytes += bytes.len();
        self.tick += 1;
        self.lru.insert(self.tick, start);
        self.held.insert(start, Held { bytes, used: self.tick });
    }

    fn release(&mut self, start: u64) -> Option<Vec<u8>> {
        let h = self.held.remove(&start)?;
        self.held_bytes -= h.bytes.len();
        self.lru.remove(&h.used);
        Some(h.bytes)
    }

    /// `len` bytes at `at`, as replayed so far: read from the source the first time.
    fn get(&mut self, at: u64, len: usize) -> Result<&mut [u8]> {
        let end = at + len as u64;
        // What was written out and overlaps comes back first.
        let back: Vec<(u64, (u64, usize))> =
            self.out.range(..end).rev().take_while(|(s, (_, n))| *s + *n as u64 > at).map(|(s, v)| (*s, *v)).collect();
        for (s, (stored, n)) in back {
            self.out.remove(&s);
            let bytes = self.arena.read_vec(stored, n)?;
            self.hold(s, bytes);
        }
        let overlapping: Vec<(u64, usize)> = self
            .held
            .range(..end)
            .rev()
            .take_while(|(s, h)| *s + h.bytes.len() as u64 > at)
            .map(|(s, h)| (*s, h.bytes.len()))
            .collect();
        let (start, stop) = overlapping.iter().fold((at, end), |(lo, hi), &(s, n)| (lo.min(s), hi.max(s + n as u64)));
        if !(overlapping.len() == 1 && start == overlapping[0].0 && stop == start + overlapping[0].1 as u64) {
            let mut buf = self.src.read_vec(start, (stop - start) as usize)?;
            for (s, _) in overlapping {
                let old = self.release(s).unwrap_or_default();
                let o = (s - start) as usize;
                buf[o..o + old.len()].copy_from_slice(&old);
            }
            self.hold(start, buf);
        } else if let Some(bytes) = self.release(start) {
            self.hold(start, bytes); // used now
        }
        self.write_out_past_budget(start)?;
        let buf = self.held.get_mut(&start).ok_or_else(|| Error::corrupt("xfs replay buffer"))?;
        let o = (at - start) as usize;
        Ok(&mut buf.bytes[o..o + len])
    }

    /// The buffers used least recently written out while `held` is over its budget, but for
    /// the one at `keep`.
    fn write_out_past_budget(&mut self, keep: u64) -> Result<()> {
        while self.held_bytes > self.budget {
            let Some((_, &s)) = self.lru.iter().find(|(_, s)| **s != keep) else { break };
            let bytes = self.release(s).unwrap_or_default();
            let stored = self.arena.append(&bytes)?;
            self.out.insert(s, (stored, bytes.len()));
        }
        Ok(())
    }

    /// Every buffer, as patches.
    fn into_patches(self, patches: &mut PatchBuilder) -> Result<()> {
        for (at, h) in &self.held {
            patches.bytes(*at, &h.bytes)?;
        }
        for (at, (stored, n)) in &self.out {
            patches.bytes(*at, &self.arena.read_vec(*stored, *n)?)?;
        }
        Ok(())
    }
}

/// What an intent that changes a file does.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Intent {
    /// A `BUI` or an `XMI`: what it does to files.
    Files(Vec<FileUpdate>),
    /// An `ATTRI`: the inode it changes.
    Inodes(Vec<u64>),
}

/// Intents that change a file not done yet, by type and id, each with its place in the log
/// (the order recovery finishes them in).
#[derive(Debug, Default)]
struct Intents {
    left: HashMap<(u16, u64), (usize, Intent)>,
    logged: usize,
}

impl Intents {
    fn logged(&mut self, key: (u16, u64), intent: Intent) {
        self.left.insert(key, (self.logged, intent));
        self.logged += 1;
    }

    fn done(&mut self, key: (u16, u64)) {
        self.left.remove(&key);
    }
}

/// `xfs_xmi_log_format` flags: the attribute fork, sizes set when done, only where inode 1 maps
/// written blocks, the reflink flag of either inode cleared (nothing this reads).
const XMI_ATTR_FORK: u64 = 1 << 0;
const XMI_SET_SIZES: u64 = 1 << 1;
const XMI_INO1_WRITTEN: u64 = 1 << 2;
const XMI_KNOWN: u64 = (1 << 5) - 1;

/// `xfs_map_extent` flags: the operation (`XFS_BMAP_MAP`, `XFS_BMAP_UNMAP`) in the low byte, then
/// the fork, unwritten and realtime bits.
const BMAP_MAP: u32 = 1;
const BMAP_UNMAP: u32 = 2;
const BMAP_TYPE_MASK: u32 = 0xff;
const BMAP_ATTR_FORK: u32 = 1 << 31;
const BMAP_UNWRITTEN: u32 = 1 << 30;
const BMAP_REALTIME: u32 = 1 << 29;
/// Most extents one `BUI` holds (the kernel logs one).
const MAX_BUI_EXTENTS: u32 = 64;

/// What intent `f` (type `ty`) does.
fn intent(f: &[u8], order: Order, ty: u16) -> Result<Intent> {
    Ok(match ty {
        // xfs_bui_log_format: 16 bytes, then extents of 32: owner, startblock, startoff (u64),
        // length, flags (u32).
        LI_BUI => {
            let n = order.u32(f, 4)?;
            if n == 0 || n > MAX_BUI_EXTENTS {
                return Err(Error::corrupt(format!("xfs BUI of {n} extents")));
            }
            let mut out = Vec::with_capacity(n as usize);
            for i in 0..n as usize {
                let at = 16 + 32 * i;
                let flags = order.u32(f, at + 28)?;
                let map = match flags & BMAP_TYPE_MASK {
                    BMAP_MAP => true,
                    BMAP_UNMAP => false,
                    t => return Err(Error::corrupt(format!("xfs BUI operation {t}"))),
                };
                if flags & BMAP_REALTIME != 0 {
                    return Err(Error::unsupported("xfs BUI of a realtime file"));
                }
                let update = BmapUpdate {
                    attr_fork: flags & BMAP_ATTR_FORK != 0,
                    map,
                    unwritten: flags & BMAP_UNWRITTEN != 0,
                    startblock: order.u64(f, at + 8)?,
                    startoff: order.u64(f, at + 16)?,
                    blocks: u64::from(order.u32(f, at + 24)?),
                };
                out.push(FileUpdate::Bmap { ino: order.u64(f, at)?, update });
            }
            Intent::Files(out)
        }
        // xfs_attri_log_format: the inode at 16.
        LI_ATTRI => Intent::Inodes(vec![order.u64(f, 16)?]),
        // xfs_xmi_log_format: the inodes (16, 24), their generations (32, 36), the start in
        // each (40, 48), the blocks (56), flags (64), the sizes set when done (72, 80).
        _ => {
            let flags = order.u64(f, 64)?;
            if flags & !XMI_KNOWN != 0 {
                return Err(Error::unsupported(format!("xfs XMI flags {flags:#x}")));
            }
            let size = |at| -> Result<u64> {
                let s = order.u64(f, at)?;
                i64::try_from(s).map(|_| s).map_err(|_| Error::corrupt(format!("xfs XMI size {s:#x}")))
            };
            let sizes = if flags & XMI_SET_SIZES != 0 { Some((size(72)?, size(80)?)) } else { None };
            Intent::Files(vec![FileUpdate::Exchange(Exchange {
                ino1: order.u64(f, 16)?,
                ino2: order.u64(f, 24)?,
                attr_fork: flags & XMI_ATTR_FORK != 0,
                startoff1: order.u64(f, 40)?,
                startoff2: order.u64(f, 48)?,
                blocks: order.u64(f, 56)?,
                ino1_written: flags & XMI_INO1_WRITTEN != 0,
                sizes,
            })])
        }
    })
}

/// The intents left unfinished: what they do to files, in log order, and the inodes changed
/// otherwise.
fn unfinished(intents: Intents) -> (FileUpdates, BTreeSet<u64>) {
    let mut left: Vec<(usize, Intent)> = intents.left.into_values().collect();
    left.sort_by_key(|(seq, _)| *seq);
    let (mut files, mut inodes) = (Vec::new(), BTreeSet::new());
    for (_, i) in left {
        match i {
            Intent::Files(v) => files.extend(v),
            Intent::Inodes(v) => inodes.extend(v),
        }
    }
    (FileUpdates::new(files), inodes)
}

/// Cancel records still to come, by buffer (`blkno`, `len` in basic blocks).
type Cancels = HashMap<(u64, u32), u32>;

/// What replaying the log `area` writes to the data device `src` of the file system `g`
/// describes, as patches kept in `scratch`. The transactions' items and the buffers past the
/// cache budget are kept in a work arena of `scratch` meanwhile.
pub(crate) fn replay(
    area: &LogArea,
    src: &DynSource,
    g: &Geom,
    cache_bytes: u64,
    scratch: &Scratch,
) -> Result<XfsReplayed> {
    let work = scratch.arena();
    let mut p = Parser { open: HashMap::new(), committed: Vec::new(), cancels: Cancels::new(), arena: &work };
    let head = area.walk(&mut |lsn, _, data, ops| p.record(lsn, data, ops))?;
    let (committed, mut cancels) = (p.committed, p.cancels);
    let cache = usize::try_from(cache_bytes).unwrap_or(usize::MAX);
    let mut bufs = Buffers::new(src, &work, cache);
    let mut intents = Intents::default();
    for t in &committed {
        for &at in t.items.iter().flatten() {
            apply(&Item::load(&work, at)?, t.lsn, g, &mut bufs, &mut cancels, &mut intents)?;
        }
    }
    let (files, unfinished) = unfinished(intents);
    if !files.is_empty() || !unfinished.is_empty() {
        tracing::debug!(
            updated = files.len(),
            refused = unfinished.len(),
            "xfs log: intents left unfinished change files"
        );
    }
    set_crcs(&mut bufs, g)?;
    let mut patches = PatchBuilder::new(scratch.arena(), cache);
    bufs.into_patches(&mut patches)?;
    let patches = patches.finish(src.size())?;
    let summary = ReplaySummary::new("xfs log", committed.len() as u64, &patches);
    Ok(XfsReplayed {
        patches: Arc::new(patches),
        head_lsn: head,
        files: Arc::new(files),
        unfinished: Arc::new(unfinished),
        summary,
    })
}

/// The CRC of every buffer changed computed again (v5).
fn set_crcs(bufs: &mut Buffers<'_>, g: &Geom) -> Result<()> {
    if !g.v5() {
        return Ok(());
    }
    let bs = g.sb().blocksize as usize;
    let changed: Vec<(u64, usize)> = bufs.changed.iter().copied().collect();
    for (at, len) in changed {
        set_crc(bufs.get(at, len)?, bs);
    }
    Ok(())
}

fn apply(
    item: &Item,
    lsn: u64,
    g: &Geom,
    bufs: &mut Buffers<'_>,
    cancels: &mut Cancels,
    intents: &mut Intents,
) -> Result<()> {
    let f = &item.regions[0];
    let (order, ty) = Order::of(f).ok_or_else(|| Error::corrupt("xfs log item"))?;
    match ty {
        LI_BUF => buffer(item, order, lsn, g, bufs, cancels),
        LI_INODE => inode(item, order, lsn, g, bufs, cancels),
        LI_ICREATE => icreate(f, g, bufs, cancels),
        LI_BUI | LI_ATTRI | LI_XMI => {
            intents.logged((ty, order.u64(f, 8)?), intent(f, order, ty)?);
            Ok(())
        }
        LI_BUD | LI_ATTRD | LI_XMD => {
            intents.done((ty - 1, order.u64(f, 8)?));
            Ok(())
        }
        LI_EFI | LI_EFD | LI_RUI | LI_RUD | LI_CUI | LI_CUD | LI_DQUOT | LI_QUOTAOFF => Ok(()),
        // Realtime intents (0x124a..): a realtime device is refused at open.
        0x124a..=0x124f => Ok(()),
        t => Err(Error::unsupported(format!("xfs log item {t:#06x}"))),
    }
}

/// Whether a cancel record of buffer `key` is still to come.
fn cancelled(cancels: &Cancels, key: (u64, u32)) -> bool {
    cancels.get(&key).is_some_and(|&n| n > 0)
}

/// The data map bits of a buffer item: `(first chunk, chunks)` per run of set bits.
fn runs(order: Order, f: &[u8]) -> Result<Vec<(usize, usize)>> {
    let words = order.u32(f, 16)? as usize;
    let bits = (0..words * 32)
        .map(|i| Ok(order.u32(f, 20 + 4 * (i / 32))? >> (i % 32) & 1 == 1))
        .collect::<Result<Vec<bool>>>()?;
    let mut out = Vec::new();
    let mut i = 0;
    while i < bits.len() {
        if bits[i] {
            let start = i;
            while i < bits.len() && bits[i] {
                i += 1;
            }
            out.push((start, i - start));
        } else {
            i += 1;
        }
    }
    Ok(out)
}

/// A buffer item.
fn buffer(item: &Item, order: Order, lsn: u64, g: &Geom, bufs: &mut Buffers<'_>, cancels: &mut Cancels) -> Result<()> {
    let f = &item.regions[0];
    let flags = order.u16(f, 4)?;
    let len = order.u16(f, 6)?;
    let blkno = order.u64(f, 8)?;
    let key = (blkno, u32::from(len));
    if flags & BLF_CANCEL != 0 {
        if let Some(n) = cancels.get_mut(&key) {
            *n = n.saturating_sub(1);
        }
        return Ok(());
    }
    if cancelled(cancels, key) || flags & BLF_DQUOT_BUF != 0 {
        return Ok(());
    }
    let (at, bytes) = (blkno * BB, usize::from(len) * BB as usize);
    let b = bufs.get(at, bytes)?;
    if g.v5() && buffer_lsn(b).is_some_and(|l| l >= lsn) {
        return Ok(());
    }
    let runs = runs(order, f)?;
    if flags & BLF_INODE_BUF != 0 {
        return inode_buffer(item, &runs, g, b);
    }
    for (i, &(first, n)) in runs.iter().enumerate() {
        let region = item.regions.get(i + 1).ok_or_else(|| Error::corrupt("xfs log buffer item regions"))?;
        let o = first * BLF_CHUNK;
        let len = (n * BLF_CHUNK).min(region.len()).min(b.len().saturating_sub(o));
        b[o..o + len].copy_from_slice(&region[..len]);
    }
    if !is_inode_block(b) {
        bufs.changed.insert((at, bytes));
    }
    Ok(())
}

fn is_inode_block(b: &[u8]) -> bool {
    b.len() >= 2 && be_u16(b, 0) == DINODE_MAGIC
}

/// An inode buffer item: only the `di_next_unlinked` fields its regions hold, each inode's
/// CRC computed again.
fn inode_buffer(item: &Item, runs: &[(usize, usize)], g: &Geom, b: &mut [u8]) -> Result<()> {
    let isize = usize::from(g.sb().inodesize);
    for (i, &(first, n)) in runs.iter().enumerate() {
        let region = item.regions.get(i + 1).ok_or_else(|| Error::corrupt("xfs log buffer item regions"))?;
        let (start, end) = (first * BLF_CHUNK, (first + n) * BLF_CHUNK);
        for ino in 0..b.len() / isize {
            let at = ino * isize + 96;
            if at >= start && at + 4 <= end && at - start + 4 <= region.len() {
                b[at..at + 4].copy_from_slice(&region[at - start..at - start + 4]);
                if g.v5() {
                    inode_crc(&mut b[ino * isize..(ino + 1) * isize]);
                }
            }
        }
    }
    Ok(())
}

/// The LSN of the metadata block `b` (v5), by its magic; `None` when it has none or the magic
/// is not known (then the buffer is replayed).
fn buffer_lsn(b: &[u8]) -> Option<u64> {
    if b.len() < 16 {
        return None;
    }
    let at = match &b[..4] {
        b"XFSB" => 240,
        b"XAGF" => 208,
        b"XAGI" => 320,
        b"XAFL" => 24,
        b"AB3B" | b"AB3C" | b"IAB3" | b"FIB3" | b"RMB3" | b"R3FC" => 24,
        b"BMA3" => 32,
        b"XDB3" | b"XDD3" | b"XDF3" => 16,
        b"XARM" | b"XSLM" => 32,
        _ if be_u16(b, 0) == DINODE_MAGIC && b.get(4) == Some(&3) => 112,
        _ if matches!(be_u16(b, 8), 0x3ebe | 0x3df1 | 0x3dff | 0x3bee) => 24,
        _ => return None,
    };
    let lsn = b.get(at..at + 8).map(|_| be_u64(b, at))?;
    (lsn != 0 && lsn != u64::MAX).then_some(lsn)
}

/// The CRC of the v5 metadata buffer `b` (`bs`-byte file system blocks) computed again, at
/// the place its magic sets.
fn set_crc(b: &mut [u8], bs: usize) {
    if b.len() < 16 {
        return;
    }
    let at = match &b[..4] {
        b"XFSB" => 224,
        b"XAGF" => 216,
        b"XAGI" => 312,
        b"XAFL" => 32,
        b"AB3B" | b"AB3C" | b"IAB3" | b"FIB3" | b"RMB3" | b"R3FC" => 52,
        b"BMA3" => 64,
        b"XDB3" | b"XDD3" | b"XDF3" => 4,
        // A header in each file system block.
        b"XARM" | b"XSLM" => {
            for blk in b.chunks_mut(bs) {
                if matches!(blk.get(..4), Some(b"XARM" | b"XSLM")) {
                    put_crc(blk, 12);
                }
            }
            return;
        }
        _ if matches!(be_u16(b, 8), 0x3ebe | 0x3df1 | 0x3dff | 0x3bee) => 12,
        _ => return,
    };
    put_crc(b, at);
}

fn put_crc(b: &mut [u8], at: usize) {
    if let Some(c) = crc_with_zeroed_field(crc32c, b, at) {
        b[at..at + 4].copy_from_slice(&c.to_le_bytes());
    }
}

fn inode_crc(dip: &mut [u8]) {
    put_crc(dip, DINODE_CRC_OFF);
}

/// An inode item: the log dinode, in the host's byte order, written over the inode in its
/// cluster buffer, then the forks logged.
fn inode(item: &Item, order: Order, lsn: u64, g: &Geom, bufs: &mut Buffers<'_>, cancels: &Cancels) -> Result<()> {
    let f = &item.regions[0];
    // The 64-bit layout (56 bytes) or the packed 32-bit one (52).
    let (fields, ino_u, blk_at) = match f.len() {
        56 => (order.u32(f, 4)?, 24, 40),
        52 => (order.u32(f, 4)?, 20, 36),
        n => return Err(Error::corrupt(format!("xfs log inode item format of {n} bytes"))),
    };
    let blkno = order.u64(f, blk_at)?;
    let len = order.u32(f, blk_at + 8)?;
    let boffset = order.u32(f, blk_at + 12)? as usize;
    if cancelled(cancels, (blkno, len)) {
        return Ok(());
    }
    let isize = usize::from(g.sb().inodesize);
    let buf = bufs.get(blkno * BB, len as usize * BB as usize)?;
    let dip =
        buf.get_mut(boffset..boffset + isize).ok_or_else(|| Error::corrupt("xfs log inode item outside its buffer"))?;
    let ld = item.regions.get(1).ok_or_else(|| Error::corrupt("xfs log inode item without its core"))?;
    if be_u16(dip, 0) != DINODE_MAGIC || order.u16(ld, 0)? != DINODE_MAGIC {
        return Err(Error::corrupt("xfs log inode item over a block that holds no inode"));
    }
    let v3 = dip[4] >= 3;
    if v3 {
        let disk_lsn = be_u64(dip, 112);
        if disk_lsn != 0 && disk_lsn != u64::MAX && disk_lsn > lsn {
            return Ok(());
        }
    } else {
        let (logged, ondisk) = (order.u16(ld, 30)?, be_u16(dip, 30));
        if logged < ondisk && !(ondisk == u16::MAX && logged < u16::MAX >> 1) {
            return Ok(());
        }
    }
    to_disk(ld, order, dip, lsn)?;
    let core = if dip[4] >= 3 { CORE_V3 } else { CORE_V2 };
    let forkoff = usize::from(dip[82]) * 8;
    let dsize = if forkoff != 0 { forkoff } else { isize - core };
    if fields & ILOG_DEV != 0 {
        let rdev = order.u32(f, ino_u)?;
        dip[core..core + 4].copy_from_slice(&rdev.to_be_bytes());
    }
    let mut next = 2;
    if fields & ILOG_DFORK != 0 {
        let src = item.regions.get(next).ok_or_else(|| Error::corrupt("xfs log inode item without its data fork"))?;
        next += 1;
        let to = &mut dip[core..core + dsize];
        if fields & ILOG_DBROOT != 0 {
            bmbt_to_bmdr(src, to, g.v5())?;
        } else {
            let n = src.len().min(to.len());
            to[..n].copy_from_slice(&src[..n]);
        }
    }
    if fields & ILOG_AFORK != 0 {
        let src = item.regions.get(next).ok_or_else(|| Error::corrupt("xfs log inode item without its attr fork"))?;
        let to = dip
            .get_mut(core + forkoff..isize)
            .filter(|_| forkoff != 0)
            .ok_or_else(|| Error::corrupt("xfs log inode item: an attr fork logged where the inode has none"))?;
        if fields & ILOG_ABROOT != 0 {
            bmbt_to_bmdr(src, to, g.v5())?;
        } else {
            let n = src.len().min(to.len());
            to[..n].copy_from_slice(&src[..n]);
        }
    }
    if dip[4] >= 3 {
        inode_crc(dip);
    }
    Ok(())
}

/// The log dinode `ld` (host byte order) written over the on-disk inode core `dip` (big
/// endian): `di_next_unlinked` is not logged and stays.
fn to_disk(ld: &[u8], o: Order, dip: &mut [u8], lsn: u64) -> Result<()> {
    let version = *ld.get(4).ok_or_else(|| Error::corrupt("xfs log dinode"))?;
    let need = if version >= 3 { CORE_V3 } else { CORE_V2 - 4 };
    if ld.len() < need {
        return Err(Error::corrupt(format!("xfs log dinode of {} bytes", ld.len())));
    }
    let put16 = |d: &mut [u8], at: usize| -> Result<()> {
        d[at..at + 2].copy_from_slice(&o.u16(ld, at)?.to_be_bytes());
        Ok(())
    };
    let put32 = |d: &mut [u8], at: usize| -> Result<()> {
        d[at..at + 4].copy_from_slice(&o.u32(ld, at)?.to_be_bytes());
        Ok(())
    };
    let put64 = |d: &mut [u8], at: usize| -> Result<()> {
        d[at..at + 8].copy_from_slice(&o.u64(ld, at)?.to_be_bytes());
        Ok(())
    };
    let flags2 = if version >= 3 { o.u64(ld, 120)? } else { 0 };
    let ts = |d: &mut [u8], at: usize| -> Result<()> {
        if flags2 & DIFLAG2_BIGTIME != 0 { put64(d, at) } else { put32(d, at).and_then(|()| put32(d, at + 4)) }
    };
    put16(dip, 0)?; // magic
    put16(dip, 2)?; // mode
    dip[4] = version;
    dip[5] = ld[5]; // format
    put16(dip, 6)?; // metatype (v5), onlink (v1)
    put32(dip, 8)?; // uid
    put32(dip, 12)?; // gid
    put32(dip, 16)?; // nlink
    put16(dip, 20)?; // projid_lo
    put16(dip, 22)?; // projid_hi
    ts(dip, 32)?;
    ts(dip, 40)?;
    ts(dip, 48)?;
    put64(dip, 56)?; // size
    put64(dip, 64)?; // nblocks
    put32(dip, 72)?; // extsize
    dip[82] = ld[82]; // forkoff
    dip[83] = ld[83]; // aformat
    put32(dip, 84)?; // dmevmask
    put16(dip, 88)?; // dmstate
    put16(dip, 90)?; // flags
    put32(dip, 92)?; // gen
    if version >= 3 {
        put64(dip, 104)?; // changecount
        ts(dip, 144)?; // crtime
        put64(dip, 120)?; // flags2
        put32(dip, 128)?; // cowextsize
        put64(dip, 152)?; // ino
        dip[112..120].copy_from_slice(&lsn.to_be_bytes());
        dip[132..144].fill(0);
        dip[160..176].copy_from_slice(&ld[160..176]);
        if flags2 & DIFLAG2_NREXT64 == 0 {
            dip[24..32].fill(0);
        }
    } else {
        dip[24..30].fill(0);
        // The flush count starts again from zero.
        dip[30..32].fill(0);
    }
    if flags2 & DIFLAG2_NREXT64 != 0 {
        put64(dip, 24)?; // big_nextents
        put32(dip, 76)?; // big_anextents
        dip[80..82].fill(0);
    } else {
        put32(dip, 76)?; // nextents
        put16(dip, 80)?; // anextents
    }
    Ok(())
}

/// A bmbt root logged as an in-core btree block (`src`) written as the on-disk root `to`:
/// level and count, then the keys and the pointers, each at its place for the size of `to`.
fn bmbt_to_bmdr(src: &[u8], to: &mut [u8], v5: bool) -> Result<()> {
    let hdr = if v5 { LBLOCK_CRC_LEN } else { LBLOCK_LEN };
    if src.len() < hdr || to.len() < 4 {
        return Err(Error::corrupt("xfs log: a bmbt root too short"));
    }
    let numrecs = usize::from(be_u16(src, 6));
    let rmax = (src.len() - hdr) / 16;
    let dmax = (to.len() - 4) / 16;
    if numrecs > rmax || numrecs > dmax {
        return Err(Error::corrupt(format!("xfs log: a bmbt root of {numrecs} records")));
    }
    to.fill(0);
    to[0..2].copy_from_slice(&src[4..6]);
    to[2..4].copy_from_slice(&src[6..8]);
    to[4..4 + numrecs * 8].copy_from_slice(&src[hdr..hdr + numrecs * 8]);
    let (fp, tp) = (hdr + rmax * 8, 4 + dmax * 8);
    to[tp..tp + numrecs * 8].copy_from_slice(&src[fp..fp + numrecs * 8]);
    Ok(())
}

/// An inode chunk created: every inode of its blocks free, its number and generation set;
/// left alone when any of its buffers is cancelled later.
fn icreate(f: &[u8], g: &Geom, bufs: &mut Buffers<'_>, cancels: &Cancels) -> Result<()> {
    if f.len() < 28 {
        return Err(Error::corrupt("xfs log icreate item too short"));
    }
    let sb = g.sb();
    let (agno, agbno, length, generation) = (be_u32(f, 4), be_u32(f, 8), be_u32(f, 20), be_u32(f, 24));
    if agno >= sb.agcount || u64::from(agbno) + u64::from(length) > u64::from(sb.ag_len(agno)) {
        return Err(Error::corrupt(format!("xfs log icreate of AG {agno} blocks {agbno}+{length}")));
    }
    let at = sb.ag_byte(agno, u64::from(agbno)).ok_or_else(|| Error::corrupt("xfs log icreate"))?;
    let bytes = u64::from(length) * sb.bs();
    let (first_bb, end_bb) = (at / BB, (at + bytes) / BB);
    if cancels.iter().any(|(&(b, l), &n)| n > 0 && b < end_bb && b + u64::from(l) > first_bb) {
        return Ok(());
    }
    let isize = usize::from(sb.inodesize);
    let v3 = g.v5();
    let first_ino =
        (u64::from(agno) << (u32::from(sb.agblklog) + u32::from(sb.inopblog))) | (u64::from(agbno) << sb.inopblog);
    let uuid = *sb.metadata_uuid();
    let b = bufs.get(at, bytes as usize)?;
    b.fill(0);
    for (i, dip) in b.chunks_mut(isize).enumerate() {
        dip[0..2].copy_from_slice(&DINODE_MAGIC.to_be_bytes());
        dip[4] = if v3 { 3 } else { 2 };
        dip[92..96].copy_from_slice(&generation.to_be_bytes());
        dip[96..100].copy_from_slice(&NULLAGINO.to_be_bytes());
        if v3 {
            dip[152..160].copy_from_slice(&(first_ino + i as u64).to_be_bytes());
            dip[160..176].copy_from_slice(&uuid);
            inode_crc(dip);
        }
    }
    Ok(())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn a_bmbt_root_moves_its_pointers_to_the_place_of_the_smaller_root() {
        // v4 header (24 bytes), room for 2 records in the logged block; 1 record.
        let mut src = vec![0u8; 24 + 2 * 16];
        src[4..6].copy_from_slice(&1u16.to_be_bytes());
        src[6..8].copy_from_slice(&1u16.to_be_bytes());
        src[24..32].copy_from_slice(&[1; 8]); // key
        src[24 + 16..24 + 24].copy_from_slice(&[2; 8]); // pointer, after 2 keys
        let mut to = vec![0xffu8; 4 + 3 * 16];
        bmbt_to_bmdr(&src, &mut to, false).unwrap();
        assert_eq!(&to[..4], &[0, 1, 0, 1]);
        assert_eq!(&to[4..12], &[1; 8]);
        assert_eq!(&to[4 + 3 * 8..4 + 4 * 8], &[2; 8]);
        assert!(to[12..28].iter().all(|&b| b == 0));
    }

    /// A little-endian BUI of `extents` (owner, startblock, startoff, length, flags).
    fn bui(extents: &[(u64, u64, u64, u32, u32)]) -> Vec<u8> {
        let mut f = vec![0u8; 16];
        f[4..8].copy_from_slice(&(extents.len() as u32).to_le_bytes());
        for &(owner, block, off, len, flags) in extents {
            f.extend_from_slice(&owner.to_le_bytes());
            f.extend_from_slice(&block.to_le_bytes());
            f.extend_from_slice(&off.to_le_bytes());
            f.extend_from_slice(&len.to_le_bytes());
            f.extend_from_slice(&flags.to_le_bytes());
        }
        f
    }

    #[test]
    fn unfinished_intents_say_what_they_change() {
        let o = Order { le: true };
        // A BUI of two extents (inodes 7 and 9): a map of the data fork, an unwritten unmap of
        // the attribute fork.
        let mut b = bui(&[(7, 0x56, 80, 1, BMAP_MAP), (9, 0x60, 3, 2, BMAP_UNMAP | BMAP_ATTR_FORK | BMAP_UNWRITTEN)]);
        let up = |attr_fork, map, unwritten, startoff, startblock, blocks| BmapUpdate {
            attr_fork,
            map,
            unwritten,
            startoff,
            startblock,
            blocks,
        };
        let bmap = |ino, update| FileUpdate::Bmap { ino, update };
        assert_eq!(
            intent(&b, o, LI_BUI).unwrap(),
            Intent::Files(vec![
                bmap(7, up(false, true, false, 80, 0x56, 1)),
                bmap(9, up(true, false, true, 3, 0x60, 2))
            ])
        );
        let mut attri = vec![0u8; 24];
        attri[16..24].copy_from_slice(&5u64.to_le_bytes());
        assert_eq!(intent(&attri, o, LI_ATTRI).unwrap(), Intent::Inodes(vec![5]));
        // An XMI of inodes 3 and 4: blocks 10.. of 3 and 20.. of 4, 5 blocks, sizes set.
        let mut xmi = vec![0u8; 88];
        for (at, v) in [(16, 3u64), (24, 4), (40, 10), (48, 20), (56, 5), (64, XMI_SET_SIZES), (72, 4096), (80, 8192)] {
            xmi[at..at + 8].copy_from_slice(&v.to_le_bytes());
        }
        let exchange = Exchange {
            ino1: 3,
            ino2: 4,
            attr_fork: false,
            startoff1: 10,
            startoff2: 20,
            blocks: 5,
            ino1_written: false,
            sizes: Some((4096, 8192)),
        };
        assert_eq!(intent(&xmi, o, LI_XMI).unwrap(), Intent::Files(vec![FileUpdate::Exchange(exchange)]));
        // Left unfinished: the updates in log order (a BUI done is dropped), the ATTRI's inode
        // refused.
        let mut intents = Intents::default();
        intents.logged((LI_BUI, 1), intent(&b, o, LI_BUI).unwrap());
        intents.logged((LI_XMI, 3), intent(&xmi, o, LI_XMI).unwrap());
        intents.logged((LI_BUI, 2), intent(&bui(&[(7, 0x70, 81, 1, BMAP_MAP)]), o, LI_BUI).unwrap());
        intents.logged((LI_BUI, 4), intent(&bui(&[(8, 0x70, 81, 1, BMAP_MAP)]), o, LI_BUI).unwrap());
        intents.done((LI_BUI, 4));
        intents.logged((LI_ATTRI, 5), intent(&attri, o, LI_ATTRI).unwrap());
        let (files, inodes) = unfinished(intents);
        assert!(files.touches(7) && files.touches(9) && files.touches(3) && files.touches(4) && !files.touches(8));
        assert_eq!((files.size(3), files.size(4), files.size(7)), (Some(4096), Some(8192), None));
        assert_eq!(inodes.into_iter().collect::<Vec<_>>(), [5]);
        // An extent count past the item, an unknown operation, a realtime file, unknown XMI
        // flags, a size past i64: refused, no panic.
        b[4..8].copy_from_slice(&3u32.to_le_bytes());
        assert!(intent(&b, o, LI_BUI).is_err());
        assert!(intent(&bui(&[(7, 1, 1, 1, 3)]), o, LI_BUI).unwrap_err().scope() == fs_inspect_core::Scope::Unit);
        assert!(intent(&bui(&[(7, 1, 1, 1, BMAP_MAP | BMAP_REALTIME)]), o, LI_BUI).is_err());
        let mut bad = xmi.clone();
        bad[64..72].copy_from_slice(&(1u64 << 9).to_le_bytes());
        assert!(intent(&bad, o, LI_XMI).is_err());
        let mut bad = xmi.clone();
        bad[72..80].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(intent(&bad, o, LI_XMI).unwrap_err().scope() == fs_inspect_core::Scope::Unit);
        assert!(intent(&xmi[..80], o, LI_XMI).is_err());
    }

    #[test]
    fn items_round_trip_through_the_arena() {
        let arena = Scratch::memory(1 << 20).arena();
        let item = Item { regions: vec![vec![1, 2, 3], vec![], vec![9; 300]], total: 3 };
        let at = item.store(&arena).unwrap();
        let back = Item::load(&arena, at).unwrap();
        assert_eq!((back.regions, back.total), (item.regions, 3));
    }

    #[test]
    fn data_map_runs() {
        let mut f = vec![0u8; 28];
        f[16..20].copy_from_slice(&2u32.to_le_bytes());
        f[20..24].copy_from_slice(&0b1011_0000_0000_0000_0000_0000_0000_0110u32.to_le_bytes());
        f[24..28].copy_from_slice(&1u32.to_le_bytes());
        let runs = runs(Order { le: true }, &f).unwrap();
        assert_eq!(runs, [(1, 2), (28, 2), (31, 2)]);
    }
    use crate::synth::{Fork, Geo, Ino, World, rec};
    use fs_inspect_io::MemSource;

    const T: u8 = CLIENT_TRANSACTION;

    /// The transaction header region (little endian).
    fn th() -> Vec<u8> {
        let mut t = vec![0u8; TRANS_HEADER_LEN];
        t[..4].copy_from_slice(&TRANS_MAGIC.to_le_bytes());
        t
    }

    /// A little-endian buffer item format: `total` regions, flags, length, block, map words.
    fn buf_fmt(total: u16, flags: u16, len: u16, blkno: u64, map: &[u32]) -> Vec<u8> {
        let mut f = vec![0u8; 20];
        f[..2].copy_from_slice(&LI_BUF.to_le_bytes());
        f[2..4].copy_from_slice(&total.to_le_bytes());
        f[4..6].copy_from_slice(&flags.to_le_bytes());
        f[6..8].copy_from_slice(&len.to_le_bytes());
        f[8..16].copy_from_slice(&blkno.to_le_bytes());
        f[16..20].copy_from_slice(&(map.len() as u32).to_le_bytes());
        for w in map {
            f.extend_from_slice(&w.to_le_bytes());
        }
        f
    }

    /// Operations as a record's data.
    fn ops(list: &[(u32, u8, u8, &[u8])]) -> Vec<u8> {
        let mut v = Vec::new();
        for &(tid, client, flags, region) in list {
            v.extend_from_slice(&tid.to_be_bytes());
            v.extend_from_slice(&(region.len() as u32).to_be_bytes());
            v.extend_from_slice(&[client, flags, 0, 0]);
            v.extend_from_slice(region);
        }
        v
    }

    fn feed(p: &mut Parser<'_>, lsn: u64, list: &[(u32, u8, u8, &[u8])]) -> Result<()> {
        p.record(lsn, &ops(list), list.len() as u32)
    }

    #[test]
    fn transactions_are_joined_across_records() {
        let arena = Scratch::memory(1 << 20).arena();
        let mut p = Parser { open: HashMap::new(), committed: Vec::new(), cancels: Cancels::new(), arena: &arena };
        let (h, fmt, data) = (th(), buf_fmt(2, 0, 8, 0x10, &[1]), vec![0x5a; 128]);
        let cancel = buf_fmt(1, BLF_CANCEL, 8, 0x40, &[]);
        // The header and a data region split across records; an empty region; a cancel item;
        // operations of a transaction that began before the tail; one ended by an unmount.
        feed(&mut p, 100, &[(7, T, OP_START, &[]), (7, T, OP_CONTINUE, &h[..8])]).unwrap();
        feed(&mut p, 101, &[(7, T, OP_WAS_CONT, &h[8..]), (7, T, 0, &fmt), (7, T, OP_CONTINUE, &data[..64])]).unwrap();
        feed(
            &mut p,
            102,
            &[
                (7, T, OP_WAS_CONT | OP_END, &data[64..]),
                (7, T, 0, &[]),
                (7, T, 0, &cancel),
                (7, T, OP_COMMIT, &[]),
                (9, T, 0, &[1, 2]),
                (8, CLIENT_LOG, OP_START, &[]),
                (8, CLIENT_LOG, OP_UNMOUNT, &[]),
            ],
        )
        .unwrap();
        assert!(p.open.is_empty());
        assert_eq!(p.committed.len(), 1);
        let t = &p.committed[0];
        assert_eq!((t.lsn, t.items.each_ref().map(Vec::len)), (100, [1, 0, 0, 1]));
        let item = Item::load(&arena, t.items[Class::Buffer as usize][0]).unwrap();
        assert_eq!(item.regions, [fmt.clone(), data.clone()]);
        assert_eq!(p.cancels.get(&(0x40, 8)), Some(&1));

        let fails = |list: &[(u32, u8, u8, &[u8])]| {
            let mut p = Parser { open: HashMap::new(), committed: Vec::new(), cancels: Cancels::new(), arena: &arena };
            let mut all = vec![(1, T, OP_START, &[][..])];
            all.extend_from_slice(list);
            feed(&mut p, 1, &all).unwrap_err().message().to_string()
        };
        assert!(fails(&[(1, 0x11, 0, &[])]).contains("client 0x11"));
        assert!(fails(&[(1, T, 0x40, &[])]).contains("flags 0x40"));
        assert!(fails(&[(1, T, 0, &[0; 16])]).contains("without its header"));
        let mut long = th();
        long.push(0);
        assert!(fails(&[(1, T, 0, &long)]).contains("too long"));
        assert!(fails(&[(1, T, OP_CONTINUE, &h[..8]), (1, T, OP_WAS_CONT, &h[8..12])]).contains("wrong length"));
        assert!(fails(&[(1, T, 0, &h), (1, T, OP_WAS_CONT, &[1])]).contains("without its start"));
        assert!(fails(&[(1, T, 0, &h), (1, T, 0, &[0xff; 20])]).contains("xfs log item [ff, ff]"));
        assert!(fails(&[(1, T, 0, &h), (1, T, 0, &buf_fmt(0, 0, 8, 0, &[]))]).contains("of 0 regions"));
        assert!(fails(&[(1, T, 0, &h), (1, T, 0, &buf_fmt(300, 0, 8, 0, &[]))]).contains("of 300 regions"));
        assert!(fails(&[(1, T, 0, &h), (1, T, 0, &fmt), (1, T, OP_COMMIT, &[])]).contains("regions missing"));
        // Operations past the end of the record.
        let mut p = Parser { open: HashMap::new(), committed: Vec::new(), cancels: Cancels::new(), arena: &arena };
        assert!(p.record(1, &ops(&[(1, T, OP_START, &[])]), 2).is_err());
        let mut d = ops(&[(1, T, 0, &[0; 8])]);
        d.truncate(16);
        assert!(p.record(1, &d, 1).is_err());
    }

    #[test]
    fn items_are_classed_by_type_and_flags() {
        let class = |regions: Vec<Vec<u8>>| {
            let item = Item { total: regions.len() as u16, regions };
            item.class().map(|(c, k)| (c as usize, k))
        };
        assert_eq!(class(vec![buf_fmt(1, 0, 8, 1, &[])]).unwrap(), (Class::Buffer as usize, None));
        assert_eq!(class(vec![buf_fmt(1, BLF_INODE_BUF, 8, 1, &[])]).unwrap(), (Class::InodeBuffer as usize, None));
        assert_eq!(class(vec![buf_fmt(1, BLF_CANCEL, 8, 3, &[])]).unwrap(), (Class::Cancel as usize, Some((3, 8))));
        assert_eq!(class(vec![LI_ICREATE.to_be_bytes().to_vec()]).unwrap(), (Class::Buffer as usize, None));
        assert_eq!(class(vec![LI_INODE.to_le_bytes().to_vec()]).unwrap(), (Class::Other as usize, None));
        assert!(class(vec![]).is_err());
        assert!(class(vec![vec![0xff, 0xff]]).is_err());
        // Byte order by the type: big-endian items read big endian.
        let (o, ty) = Order::of(&[0x12, 0x3c, 0, 1, 0, 0, 0, 2]).unwrap();
        assert_eq!((o.le, ty, o.u16(&[0x12, 0x3c, 0, 1], 2).unwrap()), (false, LI_BUF, 1));
        assert_eq!(o.u32(&[0, 0, 0, 2], 0).unwrap(), 2);
        assert!(Order::of(&[0x12]).is_none());
        assert!(o.u64(&[0; 4], 0).unwrap_err().message().contains("shorter than 8"));
    }

    #[test]
    fn buffers_merge_overlaps_and_spill_past_their_budget() {
        let bytes: Vec<u8> = (0..64 << 10).map(|i| (i % 251) as u8).collect();
        let src: DynSource = Arc::new(MemSource::new(bytes.clone()));
        let arena = Scratch::memory(1 << 20).arena();
        let mut bufs = Buffers::new(&src, &arena, 4096);
        bufs.get(0, 1024).unwrap()[0] = 0xaa;
        // Overlapping the one held: one buffer over both, the change kept.
        assert_eq!(bufs.get(512, 1024).unwrap(), &bytes[512..1536]);
        assert_eq!(bufs.held.keys().collect::<Vec<_>>(), [&0]);
        assert_eq!(bufs.get(0, 1).unwrap()[0], 0xaa);
        // Over the budget: the one used least recently goes out to the arena, and comes back.
        bufs.get(8192, 4096).unwrap()[1] = 0xbb;
        assert_eq!(bufs.out.keys().collect::<Vec<_>>(), [&0]);
        assert_eq!(bufs.get(0, 2).unwrap(), &[0xaa, bytes[1]]);
        assert!(bufs.out.contains_key(&8192));
        // Every buffer as patches: what was changed reads back.
        let scratch = Scratch::memory(1 << 20);
        let mut patches = PatchBuilder::new(scratch.arena(), 1 << 20);
        bufs.into_patches(&mut patches).unwrap();
        let table = patches.finish(src.size()).unwrap();
        let ranges = table.ranges().unwrap();
        assert_eq!(ranges, [fs_inspect_core::ByteRange::new(0, 1536), fs_inspect_core::ByteRange::new(8192, 4096)]);
    }

    #[test]
    fn buffer_lsns_and_checksums_follow_the_magic() {
        let block = |magic: &[u8], at: usize| {
            let mut b = vec![0u8; 512];
            b[..magic.len()].copy_from_slice(magic);
            if at > 0 {
                b[at..at + 8].copy_from_slice(&77u64.to_be_bytes());
            }
            b
        };
        for (m, at) in [
            (&b"XFSB"[..], 240),
            (b"XAGF", 208),
            (b"XAGI", 320),
            (b"XAFL", 24),
            (b"AB3B", 24),
            (b"R3FC", 24),
            (b"BMA3", 32),
            (b"XDD3", 16),
            (b"XARM", 32),
            (b"XSLM", 32),
            (&[0x49, 0x4e, 0, 0, 3], 112),
        ] {
            assert_eq!(buffer_lsn(&block(m, at)), Some(77), "{m:?}");
        }
        let mut da = vec![0u8; 512];
        da[8..10].copy_from_slice(&0x3ebeu16.to_be_bytes());
        da[24..32].copy_from_slice(&5u64.to_be_bytes());
        assert_eq!(buffer_lsn(&da), Some(5));
        // An unknown magic, a v2 inode, LSN 0 or -1, a short buffer: none.
        assert_eq!(buffer_lsn(&block(b"ABCD", 0)), None);
        assert_eq!(buffer_lsn(&block(&[0x49, 0x4e, 0, 0, 2], 0)), None);
        assert_eq!(buffer_lsn(&block(b"XAGF", 0)), None);
        let mut max = block(b"XAGF", 0);
        max[208..216].fill(0xff);
        assert_eq!(buffer_lsn(&max), None);
        assert_eq!(buffer_lsn(b"XAGF"), None);

        // Checksums at the place of each magic; remote blocks in each file system block.
        let crc_at = |mut b: Vec<u8>, at: usize| {
            set_crc(&mut b, 256);
            crate::format::sb::crc_ok(&b, at)
        };
        assert!(crc_at(block(b"XFSB", 0), 224));
        assert!(crc_at(block(b"XAGI", 0), 312));
        assert!(crc_at(da.clone(), 12));
        let mut remote = block(b"XARM", 0);
        remote[256..260].copy_from_slice(b"XSLM");
        set_crc(&mut remote, 256);
        assert!(crate::format::sb::crc_ok(&remote[..256], 12) && crate::format::sb::crc_ok(&remote[256..], 12));
        let mut other = block(b"ABCD", 0);
        set_crc(&mut other, 256);
        assert_eq!(other, block(b"ABCD", 0));
        let mut short = b"XFSB".to_vec();
        set_crc(&mut short, 256);
        assert_eq!(short, b"XFSB");
    }

    /// A synthetic volume (root, file 1 at inode 1 of chunk 0), its geometry, the byte of
    /// inode 1 and the basic block of its cluster.
    fn volume(v5: bool) -> (Geom, DynSource, usize, u64) {
        let mut w = World::new(Geo::new(v5));
        let mut root = Ino::file(0, 0, 0, Vec::new());
        root.mode = 0o040755;
        root.fork = Fork::Local;
        w.files.push(root);
        w.files.push(Ino::file(0, 0, 1, vec![rec(0, 0, 300, 4)]));
        let src: DynSource = Arc::new(MemSource::new(w.render()));
        let fs = crate::XfsFs::open(src.clone(), &fs_inspect_core::DriverContext::default()).unwrap();
        let g = Geom::new(fs.superblock(), Default::default()).unwrap();
        let at = g.agino_byte(0, w.g.chunk_agino(0) + 1).unwrap();
        (g, src, (at % 4096) as usize, at / 4096 * 8)
    }

    /// A little-endian inode item format (56 bytes): `fields`, rdev, the cluster at `blkno`
    /// (8 basic blocks), the inode at `boffset`.
    fn ino_fmt(fields: u32, blkno: u64, boffset: u32) -> Vec<u8> {
        let mut f = vec![0u8; 56];
        f[..2].copy_from_slice(&LI_INODE.to_le_bytes());
        f[4..8].copy_from_slice(&fields.to_le_bytes());
        f[24..28].copy_from_slice(&0x0801u32.to_le_bytes());
        f[40..48].copy_from_slice(&blkno.to_le_bytes());
        f[48..52].copy_from_slice(&8u32.to_le_bytes());
        f[52..56].copy_from_slice(&boffset.to_le_bytes());
        f
    }

    /// A little-endian log dinode of `version`: size 12345, flush count `flush`, `flags2`.
    fn log_dinode(version: u8, flush: u16, flags2: u64) -> Vec<u8> {
        let mut d = vec![0u8; CORE_V3];
        d[..2].copy_from_slice(&DINODE_MAGIC.to_le_bytes());
        d[2..4].copy_from_slice(&0o100644u16.to_le_bytes());
        d[4] = version;
        d[5] = 2;
        d[30..32].copy_from_slice(&flush.to_le_bytes());
        d[32..40].copy_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
        d[56..64].copy_from_slice(&12345u64.to_le_bytes());
        d[120..128].copy_from_slice(&flags2.to_le_bytes());
        d[24..32].copy_from_slice(&if flags2 & DIFLAG2_NREXT64 != 0 { 9u64 } else { 0 }.to_le_bytes());
        d
    }

    /// Apply an inode item of `regions` at `lsn` to `src`; the inode's bytes after.
    fn apply_inode(
        g: &Geom,
        src: &DynSource,
        regions: Vec<Vec<u8>>,
        lsn: u64,
        cancels: &Cancels,
        at: (usize, u64),
    ) -> Result<Vec<u8>> {
        let arena = Scratch::memory(1 << 20).arena();
        let mut bufs = Buffers::new(src, &arena, 1 << 20);
        let item = Item { total: regions.len() as u16, regions };
        inode(&item, Order { le: true }, lsn, g, &mut bufs, cancels)?;
        let isize = usize::from(g.sb().inodesize);
        Ok(bufs.get(at.1 * BB, 4096)?[at.0..at.0 + isize].to_vec())
    }

    #[test]
    fn inode_items_on_v4() {
        let (g, src, off, blk) = volume(false);
        let none = Cancels::new();
        let fmt = |fields| ino_fmt(fields, blk, off as u32);
        let size = |d: &[u8]| u64::from_be_bytes(d[56..64].try_into().unwrap());
        // The core in place, the device number; the data fork logged (local).
        let d = apply_inode(&g, &src, vec![fmt(ILOG_DEV), log_dinode(2, 0, 0)], 5, &none, (off, blk)).unwrap();
        assert_eq!((size(&d), d[4], &d[CORE_V2..CORE_V2 + 4]), (12345, 2, &0x0801u32.to_be_bytes()[..]));
        let d = apply_inode(&g, &src, vec![fmt(ILOG_DDATA), log_dinode(2, 0, 0), vec![9; 8]], 5, &none, (off, blk))
            .unwrap();
        assert_eq!(&d[CORE_V2..CORE_V2 + 8], &[9; 8]);
        // The packed 32-bit format reads the same.
        let mut f52 = vec![0u8; 52];
        f52[..36].copy_from_slice(&fmt(0)[..36]);
        f52[36..52].copy_from_slice(&fmt(0)[40..56]);
        assert_eq!(size(&apply_inode(&g, &src, vec![f52, log_dinode(2, 0, 0)], 5, &none, (off, blk)).unwrap()), 12345);
        // A flush count older than the one on disk: left alone (unless it wrapped).
        let mut img = vec![0u8; src.size() as usize];
        src.read_exact_at(0, &mut img).unwrap();
        let at = (blk * BB) as usize + off;
        img[at + 30..at + 32].copy_from_slice(&5u16.to_be_bytes());
        let src5: DynSource = Arc::new(MemSource::new(img.clone()));
        let d = apply_inode(&g, &src5, vec![fmt(0), log_dinode(2, 3, 0)], 5, &none, (off, blk)).unwrap();
        assert_ne!(size(&d), 12345);
        img[at + 30..at + 32].copy_from_slice(&u16::MAX.to_be_bytes());
        let wrapped: DynSource = Arc::new(MemSource::new(img));
        assert_eq!(
            size(&apply_inode(&g, &wrapped, vec![fmt(0), log_dinode(2, 3, 0)], 5, &none, (off, blk)).unwrap()),
            12345
        );
        // A cancelled cluster: left alone.
        let cancels: Cancels = [((blk, 8), 1)].into();
        assert_ne!(
            size(&apply_inode(&g, &src, vec![fmt(0), log_dinode(2, 0, 0)], 5, &cancels, (off, blk)).unwrap()),
            12345
        );
        let err = |regions, at: u32| {
            let mut r: Vec<Vec<u8>> = regions;
            if at != u32::MAX {
                r[0][52..56].copy_from_slice(&at.to_le_bytes());
            }
            apply_inode(&g, &src, r, 5, &none, (off, blk)).unwrap_err().message().to_string()
        };
        // A format of another size; no core; a fork missing; an attr fork where there is none;
        // over a block of no inode; outside its buffer; a log dinode too short.
        let mut f40 = fmt(0);
        f40.truncate(40);
        assert!(err(vec![f40], u32::MAX).contains("format of 40 bytes"));
        assert!(err(vec![fmt(0)], u32::MAX).contains("without its core"));
        assert!(err(vec![fmt(ILOG_DDATA), log_dinode(2, 0, 0)], u32::MAX).contains("without its data fork"));
        assert!(err(vec![fmt(ILOG_ADATA), log_dinode(2, 0, 0)], u32::MAX).contains("attr fork"));
        assert!(err(vec![fmt(ILOG_ADATA), log_dinode(2, 0, 0), vec![1]], u32::MAX).contains("has none"));
        let mut bad = log_dinode(2, 0, 0);
        bad[0] = 0;
        assert!(err(vec![fmt(0), bad], u32::MAX).contains("holds no inode"));
        assert!(err(vec![fmt(0), log_dinode(2, 0, 0)], 4000).contains("outside its buffer"));
        let mut short = log_dinode(2, 0, 0);
        short.truncate(50);
        assert!(err(vec![fmt(0), short], u32::MAX).contains("dinode of 50 bytes"));
        assert!(err(vec![fmt(0), vec![0x4e, 0x49]], u32::MAX).contains("shorter than 32"));
    }

    #[test]
    fn inode_items_on_v5() {
        let (g, src, off, blk) = volume(true);
        let none = Cancels::new();
        let fmt = |fields| ino_fmt(fields, blk, off as u32);
        let size = |d: &[u8]| u64::from_be_bytes(d[56..64].try_into().unwrap());
        let lsn_of = |d: &[u8]| u64::from_be_bytes(d[112..120].try_into().unwrap());
        // Newer on disk than the transaction: left alone.
        let d = apply_inode(&g, &src, vec![fmt(0), log_dinode(3, 0, 0)], 1, &none, (off, blk)).unwrap();
        assert_ne!(size(&d), 12345);
        // Applied: the transaction's LSN, the CRC computed again, big timestamps and extent
        // counts as logged.
        let lsn = crate::synth::NEW_LSN;
        let d = apply_inode(
            &g,
            &src,
            vec![fmt(0), log_dinode(3, 0, DIFLAG2_BIGTIME | DIFLAG2_NREXT64)],
            lsn,
            &none,
            (off, blk),
        )
        .unwrap();
        assert_eq!((size(&d), lsn_of(&d)), (12345, lsn));
        assert_eq!(&d[32..40], &0x1122_3344_5566_7788u64.to_be_bytes());
        assert_eq!(u64::from_be_bytes(d[24..32].try_into().unwrap()), 9);
        assert!(crate::format::sb::crc_ok(&d, DINODE_CRC_OFF));
        // Small timestamps: two 32-bit halves.
        let d = apply_inode(&g, &src, vec![fmt(0), log_dinode(3, 0, 0)], lsn, &none, (off, blk)).unwrap();
        assert_eq!(&d[32..36], &0x5566_7788u32.to_be_bytes());
        // A bmbt root logged as a v5 btree block.
        let mut root = vec![0u8; LBLOCK_CRC_LEN + 2 * 16];
        root[6..8].copy_from_slice(&1u16.to_be_bytes());
        let d =
            apply_inode(&g, &src, vec![fmt(ILOG_DBROOT), log_dinode(3, 0, 0), root], lsn, &none, (off, blk)).unwrap();
        assert_eq!(&d[CORE_V3..CORE_V3 + 4], &[0, 0, 0, 1]);
        // A log dinode shorter than the v3 core.
        let mut short = log_dinode(3, 0, 0);
        short.truncate(120);
        assert!(apply_inode(&g, &src, vec![fmt(0), short], lsn, &none, (off, blk)).is_err());
    }

    #[test]
    fn bmbt_roots_that_do_not_fit_fail() {
        let src = vec![0u8; LBLOCK_LEN + 16];
        assert!(bmbt_to_bmdr(&src[..10], &mut [0; 20], false).is_err());
        assert!(bmbt_to_bmdr(&src, &mut [0; 3], false).is_err());
        let mut many = src.clone();
        many[6..8].copy_from_slice(&2u16.to_be_bytes());
        assert!(bmbt_to_bmdr(&many, &mut [0; 100], false).unwrap_err().message().contains("2 records"));
        let mut one = src;
        one[6..8].copy_from_slice(&1u16.to_be_bytes());
        assert!(bmbt_to_bmdr(&one, &mut [0; 8], false).unwrap_err().message().contains("1 records"));
    }

    /// An icreate item (big endian): AG, AG block, blocks, generation.
    fn icreate_item(agno: u32, agbno: u32, length: u32, generation: u32) -> Vec<u8> {
        let mut f = vec![0u8; 28];
        f[..2].copy_from_slice(&LI_ICREATE.to_be_bytes());
        f[4..8].copy_from_slice(&agno.to_be_bytes());
        f[8..12].copy_from_slice(&agbno.to_be_bytes());
        f[20..24].copy_from_slice(&length.to_be_bytes());
        f[24..28].copy_from_slice(&generation.to_be_bytes());
        f
    }

    #[test]
    fn inode_chunks_created() {
        for v5 in [true, false] {
            let (g, src, _, _) = volume(v5);
            let arena = Scratch::memory(1 << 20).arena();
            let isize = usize::from(g.sb().inodesize);
            let at = g.sb().ag_byte(1, 900).unwrap();
            let mut bufs = Buffers::new(&src, &arena, 1 << 20);
            icreate(&icreate_item(1, 900, 1, 42), &g, &mut bufs, &Cancels::new()).unwrap();
            let b = bufs.get(at, 4096).unwrap().to_vec();
            for (i, d) in b.chunks(isize).enumerate() {
                assert_eq!(
                    (be_u16(d, 0), d[4], be_u32(d, 92), be_u32(d, 96)),
                    (DINODE_MAGIC, if v5 { 3 } else { 2 }, 42, NULLAGINO)
                );
                if v5 {
                    assert_eq!(be_u64(d, 152), g.ino(1, (900 << g.sb().inopblog) + i as u32));
                    assert!(crate::format::sb::crc_ok(d, DINODE_CRC_OFF));
                }
            }
            // A cancel of one of its buffers to come: left alone.
            let mut bufs = Buffers::new(&src, &arena, 1 << 20);
            let cancels: Cancels = [(((at + 2 * 4096) / BB + 2, 1), 1)].into();
            icreate(&icreate_item(1, 902, 1, 42), &g, &mut bufs, &cancels).unwrap();
            assert!(bufs.held.is_empty());
            // Too short, another AG, past the end of its AG.
            let mut bufs = Buffers::new(&src, &arena, 1 << 20);
            assert!(icreate(&icreate_item(1, 900, 1, 42)[..20], &g, &mut bufs, &Cancels::new()).is_err());
            assert!(icreate(&icreate_item(2, 0, 1, 42), &g, &mut bufs, &Cancels::new()).is_err());
            assert!(icreate(&icreate_item(1, 999, 2, 42), &g, &mut bufs, &Cancels::new()).is_err());
        }
    }

    #[test]
    fn items_applied_by_type() {
        let (g, src, _, _) = volume(true);
        let arena = Scratch::memory(1 << 20).arena();
        let mut bufs = Buffers::new(&src, &arena, 1 << 20);
        let (mut cancels, mut intents) = (Cancels::new(), Intents::default());
        let mut run =
            |f: Vec<u8>| apply(&Item { regions: vec![f], total: 1 }, 1, &g, &mut bufs, &mut cancels, &mut intents);
        // Free space and quota items change nothing read; realtime intents are not read.
        for ty in [LI_EFI, LI_EFD, LI_RUI, LI_CUD, LI_DQUOT, LI_QUOTAOFF, 0x124a] {
            run(ty.to_le_bytes().to_vec()).unwrap();
        }
        // A type in the range that is not known.
        assert!(run(0x1238u16.to_le_bytes().to_vec()).unwrap_err().message().contains("0x1238"));
        // An ATTRI, then its ATTRD: done.
        let mut attri = vec![0u8; 24];
        attri[..2].copy_from_slice(&LI_ATTRI.to_le_bytes());
        attri[8..16].copy_from_slice(&3u64.to_le_bytes());
        attri[16..24].copy_from_slice(&5u64.to_le_bytes());
        run(attri).unwrap();
        let mut attrd = vec![0u8; 16];
        attrd[..2].copy_from_slice(&LI_ATTRD.to_le_bytes());
        attrd[8..16].copy_from_slice(&3u64.to_le_bytes());
        run(attrd).unwrap();
        assert!(intents.left.is_empty());
        // A BUI of no extents, or too many.
        let mut bui = vec![0u8; 16];
        bui[..2].copy_from_slice(&LI_BUI.to_le_bytes());
        assert!(intent(&bui, Order { le: true }, LI_BUI).is_err());
        bui[4..8].copy_from_slice(&(MAX_BUI_EXTENTS + 1).to_le_bytes());
        assert!(intent(&bui, Order { le: true }, LI_BUI).unwrap_err().message().contains("65 extents"));
    }

    #[test]
    fn buffer_items_replay_their_chunks() {
        let (g, src, off, blk) = volume(true);
        let arena = Scratch::memory(1 << 20).arena();
        let mut bufs = Buffers::new(&src, &arena, 1 << 20);
        let mut cancels = Cancels::new();
        let free = g.sb().ag_byte(1, 950).unwrap() / BB;
        // Chunks 0 and 2 of a block of no known magic: both written, marked changed.
        let item = Item { regions: vec![buf_fmt(3, 0, 8, free, &[0b101]), vec![1; 128], vec![2; 64]], total: 3 };
        buffer(&item, Order { le: true }, 9, &g, &mut bufs, &mut cancels).unwrap();
        let b = bufs.get(free * BB, 4096).unwrap();
        assert!(b[..128].iter().all(|&x| x == 1) && b[256..320].iter().all(|&x| x == 2) && b[128] == 0);
        assert!(bufs.changed.contains(&(free * BB, 4096)));
        // A region missing.
        let short = Item { regions: vec![buf_fmt(2, 0, 8, free, &[0b101]), vec![1; 128]], total: 2 };
        assert!(buffer(&short, Order { le: true }, 9, &g, &mut bufs, &mut cancels).is_err());
        // Quota buffers are not replayed; a buffer with a cancel to come neither, the cancel
        // record counting down.
        let dq = Item { regions: vec![buf_fmt(2, 0x4, 8, free + 8, &[1]), vec![3; 128]], total: 2 };
        buffer(&dq, Order { le: true }, 9, &g, &mut bufs, &mut cancels).unwrap();
        assert!(!bufs.held.contains_key(&((free + 8) * BB)));
        cancels.insert((free + 16, 8), 1);
        let c = Item { regions: vec![buf_fmt(2, 0, 8, free + 16, &[1]), vec![3; 128]], total: 2 };
        buffer(&c, Order { le: true }, 9, &g, &mut bufs, &mut cancels).unwrap();
        assert!(!bufs.held.contains_key(&((free + 16) * BB)));
        let cancel = Item { regions: vec![buf_fmt(1, BLF_CANCEL, 8, free + 16, &[])], total: 1 };
        buffer(&cancel, Order { le: true }, 9, &g, &mut bufs, &mut cancels).unwrap();
        assert_eq!(cancels[&(free + 16, 8)], 0);
        // An inode buffer: only the next-unlinked fields, the inodes' CRCs again.
        let isize = usize::from(g.sb().inodesize);
        let first = (off / isize) * isize;
        let chunk = (first + 96) / 128;
        let mut region = vec![0u8; 128];
        let at = first + 96 - chunk * 128;
        region[at..at + 4].copy_from_slice(&77u32.to_be_bytes());
        let ib = Item { regions: vec![buf_fmt(2, BLF_INODE_BUF, 8, blk, &[1 << chunk]), region], total: 2 };
        buffer(&ib, Order { le: true }, u64::MAX - 1, &g, &mut bufs, &mut cancels).unwrap();
        let b = bufs.get(blk * BB, 4096).unwrap();
        assert_eq!(be_u32(b, first + 96), 77);
        assert!(crate::format::sb::crc_ok(&b[first..first + isize], DINODE_CRC_OFF));
        assert!(!bufs.changed.contains(&(blk * BB, 4096)));
    }
}
