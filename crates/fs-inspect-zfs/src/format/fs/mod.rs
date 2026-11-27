//! The ZFS [`Filesystem`](fs_inspect_core::Filesystem): open one leaf vdev (labels, uberblock, MOS,
//! pool configuration, features, metaslabs, intent logs) and stream its allocated ranges. The
//! pool's other leaves come from the volumes given with it ([`DriverContext::peers`]): its
//! metadata is spread over every top-level vdev.

mod assemble;
mod metaslab;

pub(crate) use assemble::vdev_layout;
pub use assemble::{KNOWN_FEATURES, Member, Pool, PoolStatus};

use crate::format::blkptr::{BlkPtr, Dva, VDEV_DATA_OFFSET};
use crate::format::dnode::Dnode;
use crate::format::dsl::{self, Dataset, mos_object};
use crate::format::label::{LABEL_SIZE, Leaf, Uberblock};
use crate::format::objset::Objset;
use crate::format::reader::BlockReader;
use crate::format::replay::{Overlay, Touched, ZfsReplayed};
use crate::format::zil;
use fs_inspect_core::Scope;
use fs_inspect_core::range::{Coalesce, Merge, coalesce};
use fs_inspect_core::store::Scratch;
use fs_inspect_core::{
    ByteRange, Consistency, DiagCode, Diagnostics, DriverContext, Error, FsInfo, IterCursor, Limits, RangeCursor,
    Replayed, Result,
};
use fs_inspect_io::DynSource;
use metaslab::{Metaslab, MetaslabIter};
use std::collections::BTreeMap;
use std::sync::Arc;

/// An opened ZFS leaf vdev.
#[derive(Debug)]
pub struct ZfsFs {
    info: FsInfo,
    reader: BlockReader,
    ub: Uberblock,
    pool: Pool,
    mos: Objset,
    dir: BTreeMap<String, Vec<u64>>,
    features: BTreeMap<String, u64>,
    metaslabs: Vec<Metaslab>,
    /// Device ranges of intent log blocks and the data of their indirect writes.
    zil: Vec<ByteRange>,
    /// The block each chain ends at (allocated for the next log write).
    zil_pending: Vec<BlkPtr>,
    /// Datasets with a non-empty intent log.
    zil_datasets: Vec<u64>,
    limits: Limits,
    diag: Diagnostics,
    /// The namespace's datasets and mounts (read once).
    pub(crate) ns: std::sync::OnceLock<Result<Arc<crate::format::ns::Mounts>>>,
    /// Opened over a replay ([`DriverContext::replayed`]): what the intent logs change.
    pub(crate) overlay: Option<Arc<Overlay>>,
    /// Read on disk: the objects the intent logs change, which its namespace refuses (read
    /// once).
    pub(crate) touched: std::sync::OnceLock<Result<Arc<Touched>>>,
    scratch: Scratch,
}

impl ZfsFs {
    /// Open the leaf vdev starting at offset 0 of `src` (its pool's other leaves among
    /// `ctx.peers`). A cache or spare device is refused: [`crate::open`] opens those.
    pub fn open(src: DynSource, ctx: &DriverContext) -> Result<Self> {
        Self::open_leaf(Leaf::read(src)?, ctx)
    }

    /// Open the leaf vdev whose labels `own` holds; over a replay ([`DriverContext::replayed`]),
    /// its namespace as the intent logs leave it.
    pub(crate) fn open_leaf(own: Leaf, ctx: &DriverContext) -> Result<Self> {
        let mut fs = Self::open_pool(own, ctx)?;
        if let Some(r) = &ctx.replayed {
            let r = (r.clone() as Arc<dyn std::any::Any + Send + Sync>)
                .downcast::<ZfsReplayed>()
                .map_err(|_| Error::invalid_argument("a zfs pool opened over another file system's replay"))?;
            fs.overlay = Some(r.overlay.clone());
        }
        fs.metaslabs = fs.load_metaslabs()?;
        fs.load_intent_logs()?;
        Ok(fs)
    }

    /// The pool and this device's place in it, as [`open`](Self::open) checks them (labels,
    /// MOS, topology, features), without reading the space maps or intent logs.
    pub fn read_pool(src: DynSource, ctx: &DriverContext) -> Result<Pool> {
        Ok(Self::open_pool(Leaf::read(src)?, ctx)?.pool)
    }

    /// Intent logs of the head datasets: their blocks count as allocated.
    fn load_intent_logs(&mut self) -> Result<()> {
        let mut budget = self.limits.max_tree_nodes;
        let datasets = dsl::all_datasets(&self.reader, &self.mos, &mut budget)?;
        let mut ranges = Vec::new();
        for ds in datasets.iter().filter(|d| !d.is_snapshot()) {
            if ds.bp.is_hole() {
                continue;
            }
            let os = match Objset::read(&self.reader, &ds.bp) {
                Ok(o) => o,
                Err(e) if e.scope() == Scope::Unit => {
                    self.diag.warn(DiagCode::CountedAsUsed, format!("dataset {} unreadable ({e})", ds.obj));
                    continue;
                }
                Err(e) => return Err(e),
            };
            let log = zil::read(&self.reader, &os.zil, self.limits.max_tree_nodes, false)?;
            // The block allocated for the next log write: also with an empty log.
            self.zil_pending.extend(log.pending);
            if log.is_empty() {
                continue;
            }
            self.zil_datasets.push(ds.obj);
            for bp in log.blocks.iter().chain(&log.writes) {
                self.bp_ranges(bp, &mut ranges);
            }
        }
        ranges.sort();
        self.zil = coalesce(ranges).collect();
        Ok(())
    }

    /// Device ranges of every copy of `bp` on this device (a gang block: its header and its
    /// members' copies).
    pub fn bp_ranges(&self, bp: &BlkPtr, out: &mut Vec<ByteRange>) {
        for d in bp.copies() {
            self.dva_ranges(bp, d, out, 0);
        }
    }

    /// The range of this device that holds `[offset, offset + len)` of its top-level vdev (a
    /// raidz child: the rows of its column there).
    pub fn on_device(&self, offset: u64, len: u64) -> Option<ByteRange> {
        let (s, e) = match self.pool.raidz {
            Some(g) => g.child_range(self.pool.child, offset, len)?,
            None => (offset, offset.checked_add(len)?),
        };
        let (s, e) = (s.checked_add(VDEV_DATA_OFFSET)?, e.checked_add(VDEV_DATA_OFFSET)?);
        (e > s).then(|| ByteRange::from_bounds(s, e))
    }

    /// Device range of one copy that is not a gang block (none on another top-level vdev).
    pub fn dva_range(&self, d: &Dva, out: &mut Vec<ByteRange>) {
        if d.vdev == self.pool.top_id
            && let Some(r) = self.on_device(d.offset, d.asize)
        {
            out.push(r);
        }
    }

    fn dva_ranges(&self, bp: &BlkPtr, d: &Dva, out: &mut Vec<ByteRange>, depth: u32) {
        if d.vdev != self.pool.top_id {
            return;
        }
        if !d.gang {
            out.extend(self.on_device(d.offset, d.asize));
            return;
        }
        let hdr = match self.pool.raidz {
            Some(g) => g.asize(self.reader.gang_header_size()),
            None => self.reader.gang_header_size().next_multiple_of(1 << self.pool.ashift),
        };
        out.extend(self.on_device(d.offset, hdr));
        match (depth < 8).then(|| self.reader.gang_members(bp, d)) {
            Some(Ok(members)) => {
                for m in members {
                    for md in m.copies() {
                        self.dva_ranges(&m, md, out, depth + 1);
                    }
                }
            }
            // The whole allocation the gang DVA covers.
            _ => out.extend(self.on_device(d.offset, d.asize)),
        }
    }

    pub fn reader(&self) -> &BlockReader {
        &self.reader
    }

    pub fn uberblock(&self) -> &Uberblock {
        &self.ub
    }

    pub fn pool(&self) -> &Pool {
        &self.pool
    }

    pub fn mos(&self) -> &Objset {
        &self.mos
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    pub fn diagnostics(&self) -> &Diagnostics {
        &self.diag
    }

    pub fn features(&self) -> &BTreeMap<String, u64> {
        &self.features
    }

    /// The first value of a MOS object directory entry.
    pub fn dir_value(&self, key: &str) -> Option<u64> {
        self.dir.get(key).and_then(|v| v.first().copied())
    }

    /// The values of a MOS object directory entry.
    pub fn dir_values(&self, key: &str) -> Option<&[u64]> {
        self.dir.get(key).map(|v| v.as_slice())
    }

    /// Every MOS object directory entry.
    pub fn dir_entries(&self) -> impl Iterator<Item = (&str, &[u64])> {
        self.dir.iter().map(|(k, v)| (k.as_str(), v.as_slice()))
    }

    /// A MOS object.
    pub fn mos_object(&self, obj: u64) -> Result<Dnode> {
        mos_object(&self.reader, &self.mos, obj)
    }

    /// Every dataset of the pool (heads, snapshots, clones).
    pub fn datasets(&self) -> Result<Vec<Dataset>> {
        let mut budget = self.limits.max_tree_nodes;
        dsl::all_datasets(&self.reader, &self.mos, &mut budget)
    }

    /// Device ranges of the intent logs.
    pub fn intent_log_ranges(&self) -> &[ByteRange] {
        &self.zil
    }

    /// Device ranges of the blocks the intent log chains end at, of those born after txg
    /// `after` (`0`: all of them). No tree pointer reaches them, so the walk of new blocks
    /// does not either.
    pub fn pending_log_ranges(&self, after: u64) -> Vec<ByteRange> {
        let mut out = Vec::new();
        for bp in self.zil_pending.iter().filter(|bp| bp.phys_birth() > after) {
            self.bp_ranges(bp, &mut out);
        }
        out.sort();
        out
    }

    /// Ranges always counted as used: the front labels and boot area, the back labels.
    pub fn fixed_ranges(&self) -> Vec<ByteRange> {
        let len = self.info.size;
        vec![ByteRange::new(0, VDEV_DATA_OFFSET.min(len)), ByteRange::new(len - 2 * LABEL_SIZE, 2 * LABEL_SIZE)]
    }
}

impl fs_inspect_core::sealed::Fs for ZfsFs {}

impl fs_inspect_core::Filesystem for ZfsFs {
    fn verify(&self, scope: &fs_inspect_core::VerifyScope) -> Result<()> {
        crate::format::verify::verify(self, scope)
    }

    fn info(&self) -> &FsInfo {
        &self.info
    }

    /// Every transaction group is consistent; an intent log holds synchronous writes the next
    /// import replays (its blocks are in the allocation map). Over a replay: clean.
    fn consistency(&self) -> Consistency {
        if self.zil_datasets.is_empty() || self.overlay.is_some() {
            Consistency::Clean
        } else {
            Consistency::Inconsistent {
                why: format!("{} datasets have intent log records the next import replays", self.zil_datasets.len()),
                allocation_covered: true,
                notes: Vec::new(),
            }
        }
    }

    /// The intent logs of the file system datasets replayed in memory (`format::replay`).
    fn replay(&self) -> Option<Result<Arc<dyn Replayed>>> {
        if self.overlay.is_some() || self.zil_datasets.is_empty() {
            return None;
        }
        let replayed = || {
            let sets = self.head_sets()?.sets;
            crate::format::replay::replay(self, &sets, &self.scratch).map(|r| Arc::new(r) as Arc<dyn Replayed>)
        };
        Some(replayed())
    }

    fn file_map(&self) -> Option<&dyn fs_inspect_core::FileMap> {
        Some(self)
    }

    fn namespace(self: Arc<Self>) -> Option<Arc<dyn fs_inspect_core::Namespace>> {
        Some(self)
    }

    /// The swap volumes' blocks (see `format::zvol`).
    fn default_ranges(&self) -> Result<Vec<ByteRange>> {
        self.swap_zvols()
    }

    /// The metaslabs' allocated ranges merged with the fixed ranges, the intent log blocks and
    /// the blocks the log chains end at.
    fn allocated(self: Arc<Self>) -> Result<Box<dyn RangeCursor>> {
        let mut extra = self.fixed_ranges();
        extra.extend_from_slice(&self.zil);
        extra.extend(self.pending_log_ranges(0));
        extra.sort();
        let extra: Vec<ByteRange> = coalesce(extra).collect();
        let ms = MetaslabIter::new(self);
        let it = Coalesce::new(Merge::new(ms, extra.into_iter()));
        Ok(Box::new(IterCursor::new(it)))
    }
}
