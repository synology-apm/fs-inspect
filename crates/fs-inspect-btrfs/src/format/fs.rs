//! The btrfs [`Filesystem`](fs_inspect_core::Filesystem): open (superblock, chunk map, extent
//! tree root, tree log), the used range stream, the consistency verdict and the default
//! exclusions.
//!
//! Opening refuses (`Unsupported`) more than one device, a chunk tree that lists another
//! device, a RAID profile, the zoned, extent_tree_v2 and raid_stripe_tree features, unknown
//! incompat bits and unknown checksum types.

use crate::format::chunk::{CHUNK_ITEM_KEY, ChunkMap, PhysStripe, parse_chunk_item, parse_sys_chunk_array};
use crate::format::csum::CsumType;
use crate::format::log::{self, LogState};
use crate::format::replay::{BtrfsReplayed, Overlay};
use crate::format::superblock::{SUPER_OFFSETS, SUPER_SIZE, Superblock, check_copy, incompat};
use crate::format::tree::{Key, Root, TreePath, TreeReader};
use fs_inspect_core::FsInfoExt;
use fs_inspect_core::Scope;
use fs_inspect_core::bytes::{u8_at, u64_at};
use fs_inspect_core::exclude::{self, DefaultExclude};
use fs_inspect_core::range::{Coalesce, Merge, coalesce};
use fs_inspect_core::store::Scratch;
use fs_inspect_core::{
    ByteRange, DiagCode, Diagnostics, DriverContext, Error, FsInfo, FsKind, Integrity, IterCursor, Limits, RangeCursor,
    Result,
};
use fs_inspect_core::{Consistency, Replayed};
use fs_inspect_io::DynSource;
use std::collections::HashMap;
use std::sync::Arc;

/// Key types and object ids (the tests use some the driver does not).
#[allow(dead_code)]
pub mod keys {
    pub const INODE_ITEM: u8 = 1;
    pub const INODE_REF: u8 = 12;
    pub const INODE_EXTREF: u8 = 13;
    pub const EXTENT_DATA: u8 = 108;
    pub const ROOT_ITEM: u8 = 132;
    pub const EXTENT_ITEM: u8 = 168;
    pub const METADATA_ITEM: u8 = 169;
    pub const BLOCK_GROUP_ITEM: u8 = 192;
    pub const DEV_ITEM: u8 = 216;
    pub const ROOT_TREE_OBJECTID: u64 = 1;
    pub const EXTENT_TREE_OBJECTID: u64 = 2;
    pub const FS_TREE_OBJECTID: u64 = 5;
    /// The range of subvolume (and inode) object ids.
    pub const FIRST_FREE_OBJECTID: u64 = 256;
    pub const LAST_FREE_OBJECTID: u64 = -256i64 as u64;
    pub const TREE_LOG_OBJECTID: u64 = -6i64 as u64;
    pub const DATA_RELOC_TREE_OBJECTID: u64 = -9i64 as u64;
    pub const EXTENT_CSUM_OBJECTID: u64 = -10i64 as u64;
    pub const CSUM_TREE_OBJECTID: u64 = 7;
    pub const EXTENT_CSUM: u8 = 128;
}

/// The device area btrfs never allocates (boot loaders, partitioning tools).
pub const RESERVED_HEAD: u64 = 1 << 20;
/// Most chunks accepted.
const MAX_CHUNKS: usize = 1 << 22;

/// An opened btrfs volume.
#[derive(Debug)]
pub struct BtrfsFs {
    info: FsInfo,
    sb: Superblock,
    reader: TreeReader,
    stripes: Vec<PhysStripe>,
    extent_root: Root,
    /// Physical ranges of an unreplayed log tree (its nodes and the data it references), or
    /// the whole device when it cannot be read.
    log: Vec<ByteRange>,
    /// Physical ranges of the data extents the log references.
    log_data: Vec<ByteRange>,
    log_state: LogState,
    limits: Limits,
    pub(crate) diag: Diagnostics,
    /// The subvolumes path lookups cross (read once).
    pub(crate) subvolumes: std::sync::OnceLock<Result<crate::format::lookup::Subvolumes>>,
    /// Opened over a replay ([`DriverContext::replayed`]): what the tree logs change.
    pub(crate) overlay: Option<Arc<Overlay>>,
    scratch: Scratch,
}

/// A superblock copy, or why it is unusable.
type CopyCheck = Result<Superblock>;

/// Read every superblock copy the source holds and pick the valid one with the highest
/// generation (copies of another file system, or past the device size they record, are
/// ignored).
fn pick_superblock(src: &DynSource, diag: &Diagnostics, integrity: &Integrity) -> Result<Superblock> {
    let len = src.size();
    let mut copies: Vec<(u64, CopyCheck)> = Vec::new();
    let mut primary_magic = false;
    for &off in &SUPER_OFFSETS {
        if off.checked_add(SUPER_SIZE as u64).is_none_or(|e| e > len) {
            continue;
        }
        let raw = src.read_vec(off, SUPER_SIZE)?;
        if off == SUPER_OFFSETS[0] {
            primary_magic = raw.get(0x40..0x48) == Some(&crate::format::superblock::MAGIC[..]);
        }
        copies.push((off, check_copy(&raw, off, integrity)));
    }
    let primary = copies.iter().find(|(o, _)| *o == SUPER_OFFSETS[0]).and_then(|(_, r)| r.as_ref().ok());
    let fsid = primary.map(|sb| sb.fsid);
    let mut best: Option<(u64, &Superblock)> = None;
    for (off, r) in &copies {
        let Ok(sb) = r else { continue };
        if fsid.is_some_and(|f| f != sb.fsid) {
            continue;
        }
        if off.saturating_add(SUPER_SIZE as u64) > sb.dev_item.total_bytes {
            continue;
        }
        if best.is_none_or(|(_, b)| sb.generation > b.generation) {
            best = Some((*off, sb));
        }
    }
    let Some((off, best)) = best else {
        if !primary_magic {
            return Err(Error::format("no btrfs superblock"));
        }
        let why = copies.first().and_then(|(_, r)| r.as_ref().err()).map(ToString::to_string).unwrap_or_default();
        return Err(Error::corrupt(format!("no valid btrfs superblock (primary: {why})")));
    };
    for (o, r) in &copies {
        if let Err(e) = r
            && *o < best.dev_item.total_bytes
        {
            diag.warn(DiagCode::ChecksumMismatch, format!("superblock copy at {o:#x} is damaged ({e})"));
        }
    }
    if off != SUPER_OFFSETS[0] {
        diag.warn(
            DiagCode::BackupUsed,
            format!("using the superblock copy at {off:#x} (generation {})", best.generation),
        );
    }
    Ok(best.clone())
}

impl BtrfsFs {
    /// Messages reported while opening and reading (tests).
    #[cfg(test)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub(crate) fn warnings(&self) -> Vec<String> {
        self.diag.own().into_iter().map(|d| d.message).collect()
    }

    /// Open the volume at offset 0 of `src`; damage worked around goes to `ctx.diagnostics`.
    /// Over a replay ([`DriverContext::replayed`]), its trees as the logs leave them.
    pub fn open(src: DynSource, ctx: &DriverContext) -> Result<Self> {
        let limits = ctx.limits.clone();
        let diag = ctx.diagnostics.clone();
        let integrity = ctx.integrity();
        let sb = pick_superblock(&src, &diag, &integrity)?;
        let csum = check_superblock(&sb, src.size(), &diag)?;
        let (ss, ns) = (sb.sectorsize, sb.nodesize);
        let dev = &sb.dev_item;
        let (devid, dev_bytes) = (dev.devid, dev.total_bytes);

        // Bootstrap from sys_chunk_array, then read the whole chunk tree.
        let sys = parse_sys_chunk_array(&sb.sys_chunk_array, devid, dev_bytes)?;
        let fsid = sb.header_fsid();
        let map = read_chunk_tree(&src, &sb, &sys, csum, &diag, &integrity, &limits)?;
        let stripes = map.stripes_by_physical()?;
        let reader = TreeReader::new(src, map, ns, csum, fsid, diag.clone(), integrity)
            .with_max_cache_bytes(ctx.max_cache_bytes);

        // The extent tree's root item in the root tree.
        let tree_root = Root { bytenr: sb.root, level: sb.root_level, generation: Some(sb.generation) };
        let extent_root = find_root(&reader, tree_root, keys::EXTENT_TREE_OBJECTID, limits.max_tree_nodes)?
            .ok_or_else(|| Error::corrupt("the root tree has no extent tree"))?;
        // Fail early on an unreadable extent tree root.
        reader.read(extent_root.bytenr, extent_root.level, extent_root.generation)?;

        let mut fs = BtrfsFs {
            info: FsInfo::new(
                FsKind::Btrfs,
                u64::from(ss),
                dev_bytes,
                Some(sb.label.clone()).filter(|l| !l.is_empty()),
                Some(fs_inspect_core::guid::format_uuid(&sb.fsid)),
            ),
            sb,
            reader,
            stripes,
            extent_root,
            log: Vec::new(),
            log_data: Vec::new(),
            log_state: LogState::Clean(Default::default()),
            limits,
            diag,
            subvolumes: std::sync::OnceLock::new(),
            overlay: None,
            scratch: ctx.scratch.clone(),
        };
        if let Some(r) = &ctx.replayed {
            let r = (r.clone() as Arc<dyn std::any::Any + Send + Sync>)
                .downcast::<BtrfsReplayed>()
                .map_err(|_| Error::invalid_argument("a btrfs volume opened over another file system's replay"))?;
            fs.overlay = Some(r.overlay.clone());
        }
        if fs.sb.log_root != 0 {
            fs.load_log()?;
        }
        Ok(fs)
    }

    /// The superblock copy in use.
    pub fn superblock(&self) -> &Superblock {
        &self.sb
    }

    /// The tree node reader (chunk map, checksum, cache).
    pub fn reader(&self) -> &TreeReader {
        &self.reader
    }

    /// The extent tree's root.
    pub fn extent_root(&self) -> Root {
        self.extent_root
    }

    /// The tree log: the inodes it logs, or that it cannot be read.
    pub fn log_state(&self) -> &LogState {
        &self.log_state
    }

    /// Physical ranges (every copy) of the data extents an unreplayed log references.
    pub fn log_data(&self) -> &[ByteRange] {
        &self.log_data
    }

    /// Physical ranges of an unreplayed log tree (its nodes and data), or the whole device when
    /// it cannot be read.
    pub fn log_ranges(&self) -> &[ByteRange] {
        &self.log
    }

    /// The limits the volume was opened with (walk bounds for further reads).
    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// Ranges always counted as used: the first MiB and the superblock copies.
    pub fn fixed_ranges(&self) -> Vec<ByteRange> {
        let dev = self.info.size;
        let mut v = vec![ByteRange::new(0, RESERVED_HEAD.min(dev))];
        for &o in &SUPER_OFFSETS {
            if o.saturating_add(SUPER_SIZE as u64) <= dev {
                v.push(ByteRange::new(o, SUPER_SIZE as u64));
            }
        }
        v.sort();
        coalesce(v).collect()
    }

    /// The log tree's ranges (an unreadable one: the whole device, which a replay could touch
    /// anywhere).
    fn load_log(&mut self) -> Result<()> {
        match self.read_log() {
            Ok((all, data, inodes)) => {
                self.log = all;
                self.log_data = data;
                self.log_state = LogState::Clean(inodes);
            }
            Err(e) if e.scope() != Scope::Unit => return Err(e),
            // A replay would add what the log holds, anywhere in the device: keep it all.
            Err(e) => {
                self.diag.warn(
                    DiagCode::CountedAsUsed,
                    format!("the log tree is unreadable ({e}); the whole device counts as used"),
                );
                self.log = vec![ByteRange::new(0, self.info.size)];
                self.log_state = LogState::Unreadable(e.to_string());
            }
        }
        Ok(())
    }

    /// Read the log tree: the physical ranges of its nodes and data, of its data alone, and the
    /// inodes it logs.
    #[allow(clippy::type_complexity)]
    fn read_log(&self) -> Result<(Vec<ByteRange>, Vec<ByteRange>, std::collections::HashSet<(u64, u64)>)> {
        let ns = u64::from(self.reader.nodesize());
        let t = log::read(&self.reader, &self.sb, self.limits.max_tree_nodes, self.limits.max_file_extents)?;
        let map = self.reader.map();
        let mut data = Vec::with_capacity(t.data.len());
        for &(l, n) in &t.data {
            map.map_all(l, n, &mut data)?;
        }
        let mut all = data.clone();
        for &l in &t.nodes {
            map.map_all(l, ns, &mut all)?;
        }
        data.sort();
        all.sort();
        Ok((coalesce(all).collect(), coalesce(data).collect(), t.inodes))
    }
}

/// The superblock's checks before anything else is read: one device, known features, a
/// supported checksum, sane sizes. Its checksum algorithm.
fn check_superblock(sb: &Superblock, readable: u64, diag: &Diagnostics) -> Result<CsumType> {
    if sb.num_devices != 1 {
        return Err(Error::unsupported(format!("btrfs with {} devices", sb.num_devices)));
    }
    let unsupported = [
        (incompat::EXTENT_TREE_V2, "extent_tree_v2"),
        (incompat::RAID_STRIPE_TREE, "raid_stripe_tree"),
        (incompat::ZONED, "zoned"),
    ];
    for (bit, name) in unsupported {
        if sb.incompat_flags & bit != 0 {
            return Err(Error::unsupported(format!("btrfs feature {name}")));
        }
    }
    if sb.incompat_flags & !incompat::KNOWN != 0 {
        return Err(Error::unsupported(format!("unknown btrfs incompat features {:#x}", sb.incompat_flags)));
    }
    let csum = sb.csum_type().ok_or_else(|| Error::unsupported(format!("checksum type {}", sb.csum_type_raw)))?;

    let ss = sb.sectorsize;
    if !ss.is_power_of_two() || !(4096..=65536).contains(&ss) {
        return Err(Error::corrupt(format!("sector size {ss}")));
    }
    let ns = sb.nodesize;
    if !ns.is_power_of_two() || ns < ss || ns > 65536 {
        return Err(Error::corrupt(format!("node size {ns}")));
    }
    let dev = &sb.dev_item;
    if dev.total_bytes == 0 || dev.total_bytes < SUPER_OFFSETS[0] + SUPER_SIZE as u64 {
        return Err(Error::corrupt(format!("device size {}", dev.total_bytes)));
    }
    if dev.total_bytes > readable {
        diag.warn(
            DiagCode::Inconsistent,
            format!("the device is {} bytes, the volume only {}", dev.total_bytes, readable),
        );
    }
    Ok(csum)
}

/// The chunk map: bootstrapped from the superblock's system chunks (`sys`), then the whole
/// chunk tree.
fn read_chunk_tree(
    src: &DynSource,
    sb: &Superblock,
    sys: &ChunkMap,
    csum: CsumType,
    diag: &Diagnostics,
    integrity: &Integrity,
    limits: &Limits,
) -> Result<ChunkMap> {
    let (devid, dev_bytes) = (sb.dev_item.devid, sb.dev_item.total_bytes);
    let boot =
        TreeReader::new(src.clone(), sys.clone(), sb.nodesize, csum, sb.header_fsid(), diag.clone(), integrity.clone());
    let chunk_root =
        Root { bytenr: sb.chunk_root, level: sb.chunk_root_level, generation: Some(sb.chunk_root_generation) };
    let mut map = ChunkMap::default();
    let mut path = TreePath::first(&boot, chunk_root, limits.max_tree_nodes)?;
    while let Some((key, leaf, slot)) = path.next(&boot)? {
        match key.ty {
            CHUNK_ITEM_KEY => {
                let data = leaf.item_data(slot)?;
                let (c, size) = parse_chunk_item(data, key.offset, devid, dev_bytes)?;
                if size != data.len() {
                    return Err(Error::corrupt(format!("chunk item {:#x}: size {}", key.offset, data.len())));
                }
                if map.len() >= MAX_CHUNKS {
                    return Err(Error::limit("too many chunks"));
                }
                map.insert(c)?;
            }
            keys::DEV_ITEM if key.offset != devid => {
                return Err(Error::unsupported(format!("chunk tree lists device {}", key.offset)));
            }
            _ => {}
        }
    }
    for c in sys.chunks() {
        if map.lookup(c.logical).is_none() {
            map.insert(c.clone())?;
        }
    }
    Ok(map)
}

/// The root (node, level, generation) of `ROOT_ITEM` `objectid` in the root tree.
pub(crate) fn find_root(r: &TreeReader, tree_root: Root, objectid: u64, max_nodes: u64) -> Result<Option<Root>> {
    let mut p = TreePath::search(r, tree_root, Key::new(objectid, keys::ROOT_ITEM, 0), max_nodes)?;
    match p.next(r)? {
        Some((k, leaf, slot)) if k.objectid == objectid && k.ty == keys::ROOT_ITEM => {
            Ok(Some(parse_root_item(leaf.item_data(slot)?)?))
        }
        _ => Ok(None),
    }
}

/// A root item's tree root.
pub fn parse_root_item(d: &[u8]) -> Result<Root> {
    Ok(Root { bytenr: u64_at(d, 176)?, level: u8_at(d, 238)?, generation: Some(u64_at(d, 160)?) })
}

/// The extents of a chunk: offset in the chunk and length.
type ChunkExtents = Arc<Vec<(u64, u64)>>;

/// Extents of the extent tree, chunk stripe by chunk stripe in device order, as device
/// ranges. The extents of a chunk with several stripes (DUP) are walked once and kept until
/// its last stripe.
#[derive(Debug)]
struct ExtentIter {
    fs: Arc<BtrfsFs>,
    stripe: usize,
    path: Option<TreePath>,
    done: bool,
    /// Stripes per chunk, by chunk logical start.
    copies: HashMap<u64, usize>,
    /// Extents of chunks with stripes still to come, and how many.
    kept: HashMap<u64, (usize, ChunkExtents)>,
    /// The current stripe's extents, taken from `kept`, and the next one.
    from_kept: Option<(ChunkExtents, usize)>,
}

impl ExtentIter {
    fn new(fs: Arc<BtrfsFs>) -> Self {
        let mut copies = HashMap::new();
        for s in &fs.stripes {
            *copies.entry(s.logical).or_insert(0) += 1;
        }
        ExtentIter { fs, stripe: 0, path: None, done: false, copies, kept: HashMap::new(), from_kept: None }
    }

    /// The next extent of chunk stripe `s` (logical, clipped to the chunk), from `self.path`.
    fn next_in(&mut self, s: PhysStripe) -> Result<Option<(u64, u64)>> {
        let fs = self.fs.clone();
        let chunk_end = s.logical.saturating_add(s.length);
        loop {
            let path = match &mut self.path {
                Some(p) => p,
                None => self.path.insert(TreePath::search(
                    &fs.reader,
                    fs.extent_root,
                    Key::new(s.logical, 0, 0),
                    fs.limits.max_tree_nodes,
                )?),
            };
            let Some((key, _, _)) = path.next(&fs.reader)?.filter(|(k, _, _)| k.objectid < chunk_end) else {
                self.path = None;
                return Ok(None);
            };
            let len = match key.ty {
                keys::EXTENT_ITEM => key.offset,
                keys::METADATA_ITEM => u64::from(fs.reader.nodesize()),
                _ => continue,
            };
            let start = key.objectid.max(s.logical);
            let end = key.objectid.saturating_add(len).min(chunk_end);
            if end > start {
                return Ok(Some((start, end)));
            }
        }
    }

    fn step(&mut self) -> Result<Option<ByteRange>> {
        loop {
            let Some(s) = self.fs.stripes.get(self.stripe).copied() else { return Ok(None) };
            if let Some((list, i)) = &mut self.from_kept {
                if let Some(&(o, l)) = list.get(*i) {
                    *i += 1;
                    return Ok(Some(ByteRange::new(s.physical + o, l)));
                }
                self.from_kept = None;
                self.stripe += 1;
                continue;
            }
            let n = self.copies.get(&s.logical).copied().unwrap_or(1);
            if n > 1 {
                let list = match self.kept.remove(&s.logical) {
                    Some((left, list)) => {
                        if left > 1 {
                            self.kept.insert(s.logical, (left - 1, list.clone()));
                        }
                        list
                    }
                    None => {
                        let mut list = Vec::new();
                        while let Some((start, end)) = self.next_in(s)? {
                            list.push((start - s.logical, end - start));
                        }
                        let list = Arc::new(list);
                        self.kept.insert(s.logical, (n - 1, list.clone()));
                        list
                    }
                };
                self.from_kept = Some((list, 0));
                continue;
            }
            match self.next_in(s)? {
                Some((start, end)) => return Ok(Some(ByteRange::new(s.physical + (start - s.logical), end - start))),
                None => self.stripe += 1,
            }
        }
    }
}

impl Iterator for ExtentIter {
    type Item = Result<ByteRange>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let r = self.step().transpose();
        if !matches!(r, Some(Ok(_))) {
            self.done = true;
        }
        r
    }
}

/// [`LINUX_DEFAULTS`](exclude::LINUX_DEFAULTS) and the same files under the usual btrfs
/// subvolume layouts, paths from the top-level subvolume: `@` (Ubuntu), `@swap`, and Fedora's
/// `root`.
const DEFAULT_EXCLUDES: &[DefaultExclude] = &[
    DefaultExclude::checked("/swapfile", exclude::SWAP_HEAD, exclude::swap_file),
    DefaultExclude::checked("/swap.img", exclude::SWAP_HEAD, exclude::swap_file),
    DefaultExclude::checked("/var/swap", exclude::SWAP_HEAD, exclude::swap_file),
    DefaultExclude::checked("/swap/swapfile", exclude::SWAP_HEAD, exclude::swap_file),
    DefaultExclude::checked("/var/swap/swapfile", exclude::SWAP_HEAD, exclude::swap_file),
    DefaultExclude::checked("/@/swapfile", exclude::SWAP_HEAD, exclude::swap_file),
    DefaultExclude::checked("/@/swap.img", exclude::SWAP_HEAD, exclude::swap_file),
    DefaultExclude::checked("/@/swap/swapfile", exclude::SWAP_HEAD, exclude::swap_file),
    DefaultExclude::checked("/@swap/swapfile", exclude::SWAP_HEAD, exclude::swap_file),
    DefaultExclude::checked("/root/var/swap/swapfile", exclude::SWAP_HEAD, exclude::swap_file),
];

impl fs_inspect_core::sealed::Fs for BtrfsFs {}

impl fs_inspect_core::Filesystem for BtrfsFs {
    fn verify(&self, scope: &fs_inspect_core::VerifyScope) -> Result<()> {
        crate::format::verify::verify(self, scope)
    }

    fn default_excludes(&self) -> &'static [fs_inspect_core::DefaultExclude] {
        DEFAULT_EXCLUDES
    }

    fn info(&self) -> &FsInfo {
        &self.info
    }

    /// The trees are consistent at every commit; a tree log holds what was fsync'ed after it,
    /// replayed at the next mount. Its extents are read into the allocation map. Over a
    /// replay: clean.
    fn consistency(&self) -> Consistency {
        if self.sb.log_root == 0 || self.overlay.is_some() {
            Consistency::Clean
        } else {
            Consistency::Inconsistent {
                why: "a tree log holds fsync'ed changes the next mount replays".into(),
                allocation_covered: true,
                notes: Vec::new(),
            }
        }
    }

    /// The tree logs replayed in memory (`format::replay`).
    fn replay(&self) -> Option<Result<Arc<dyn Replayed>>> {
        if self.sb.log_root == 0 || self.overlay.is_some() {
            return None;
        }
        Some(crate::format::replay::replay(self, &self.scratch).map(|r| Arc::new(r) as Arc<dyn Replayed>))
    }

    fn file_map(&self) -> Option<&dyn fs_inspect_core::FileMap> {
        Some(self)
    }

    fn namespace(self: Arc<Self>) -> Option<Arc<dyn fs_inspect_core::Namespace>> {
        Some(self)
    }

    fn allocated(self: Arc<Self>) -> Result<Box<dyn RangeCursor>> {
        let mut extra = self.fixed_ranges();
        extra.extend_from_slice(&self.log);
        extra.sort();
        let extra: Vec<ByteRange> = coalesce(extra).collect();
        let extents = ExtentIter::new(self);
        let it = Coalesce::new(Merge::new(extents, extra.into_iter()));
        Ok(Box::new(IterCursor::new(it)))
    }
}
