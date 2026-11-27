//! Finding the newest usable checkpoint, its space manager, and walking the space manager's
//! chunk-info blocks in ascending block order.
//!
//! Every valid container superblock in the checkpoint descriptor area (and block 0's) is a
//! candidate; the newest one whose checkpoint map, space manager and chunk-info chain
//! (CAB → CIB → `chunk_info_t`) check out is used. Damage in a newer one falls back to an
//! older one ([`DiagCode::BackupUsed`]); a bad block-0 checksum is reported as
//! [`DiagCode::ChecksumMismatch`]. Fusion containers and descriptor areas stored as a B-tree
//! are `Unsupported`.

use crate::format::btree::MetaObj;
use crate::format::checksum;
use crate::format::layout::{
    ARRAY_HEADER, CHECKPOINT_MAP_LAST, CHUNK_INFO, CheckpointMapping, ChunkInfo, MIN_BLOCK_SIZE, NxSuperblock,
    OBJECT_TYPE_CHECKPOINT_MAP, OBJECT_TYPE_NX_SUPERBLOCK, OBJECT_TYPE_SPACEMAN, OBJECT_TYPE_SPACEMAN_CAB,
    OBJECT_TYPE_SPACEMAN_CIB, ObjHeader, Spaceman, XP_TREE_FLAG, parse_checkpoint_map,
};
use fs_inspect_core::DiagCode;
use fs_inspect_core::Diagnostic;
use fs_inspect_core::DiagnosticExt;
use fs_inspect_core::Scope;
use fs_inspect_core::block::BlockReader;
use fs_inspect_core::bytes::{u32_at, u64_at};
use fs_inspect_core::{Error, Integrity, Limits, Named, Result, Role, Site, StructureKind};
use fs_inspect_io::DynSource;
use fs_inspect_io::batch::{BATCH_BYTES, ItemWindow};
use std::sync::Arc;

/// Most checkpoint-descriptor blocks scanned.
const MAX_DESC_BLOCKS: u64 = 1 << 24;

/// Container geometry: block size and block count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Geometry {
    pub block_size: u32,
    pub block_count: u64,
}

impl Geometry {
    fn new(block_size: u32, block_count: u64) -> Result<Self> {
        if block_count == 0 {
            return Err(Error::corrupt("container has no blocks"));
        }
        block_count
            .checked_mul(block_size as u64)
            .ok_or_else(|| Error::corrupt(format!("container size overflows ({block_count} blocks)")))?;
        Ok(Geometry { block_size, block_count })
    }

    pub fn volume_bytes(&self) -> u64 {
        self.block_count * self.block_size as u64
    }

    /// A reader of this container's blocks from `src`.
    pub fn reader(&self, src: &DynSource) -> Result<BlockReader> {
        BlockReader::new(src.clone(), self.block_size, self.block_count)
    }
}

/// Read the one-block object at `paddr` and check its checksum, type (`kind`, flags masked)
/// and object id (`oid`; the block address for a physical object).
pub fn read_obj(
    blocks: &BlockReader,
    paddr: u64,
    oid: u64,
    kind: u32,
    what: StructureKind,
    check: (&Integrity, Role),
) -> Result<(ObjHeader, Vec<u8>)> {
    let b = blocks.read(paddr, what.as_str())?;
    Ok((check_obj(&b, paddr, oid, kind, what, check)?, b))
}

/// Whether the object `b` at `paddr` (`what`) has a right checksum, or none computed (the
/// policy skips `role`).
pub fn sum_ok(b: &[u8], paddr: u64, what: StructureKind, (integrity, role): (&Integrity, Role)) -> bool {
    integrity.ok(role, Site::new(what).id(paddr), || checksum::verify(b).into())
}

/// Check the one-block object `b` read from `paddr` as [`read_obj`] does; its header.
pub fn check_obj(
    b: &[u8],
    paddr: u64,
    oid: u64,
    kind: u32,
    what: StructureKind,
    check: (&Integrity, Role),
) -> Result<ObjHeader> {
    let h = ObjHeader::parse(b)?;
    // The type and id first: a block of another object is no checksum finding.
    let sum_ok = h.kind != kind || h.oid != oid || sum_ok(b, paddr, what, check);
    if h.kind != kind || h.oid != oid || !sum_ok {
        return Err(Error::corrupt(format!(
            "{what} at block {paddr} is invalid (type {:#x}, oid {:#x}, checksum {}; expected type {kind:#x}, \
             oid {oid:#x})",
            h.kind,
            h.oid,
            if sum_ok { "ok" } else { "bad" }
        )));
    }
    Ok(h)
}

/// The checkpoint the driver uses: its superblock and validated space manager.
#[derive(Debug, Clone)]
pub struct Checkpoint {
    pub sb: NxSuperblock,
    pub geometry: Geometry,
    pub spaceman: Arc<Spaceman>,
    /// Its space manager's chunks.
    pub chunks: Arc<Chunks>,
    /// Its checkpoint map: every ephemeral object of the checkpoint (space manager, free
    /// queues, reaper, ...), in the checkpoint data area.
    pub ephemeral: Vec<CheckpointMapping>,
    /// Damage worked around (older checkpoint used, bad block-0 checksum, ...); `ApfsFs::open`
    /// reports these to the diagnostics.
    pub warnings: Vec<Diagnostic>,
}

/// The blocks of a checkpoint descriptor area, read a batch at a time.
struct DescArea {
    blocks: BlockReader,
    base: u64,
    count: u64,
    window: ItemWindow,
}

impl DescArea {
    fn new(blocks: BlockReader, base: u64, count: u64) -> Self {
        let window = ItemWindow::new(u64::from(blocks.block_size()));
        DescArea { blocks, base, count, window }
    }

    /// Block `blk` (from the area's batches when it lies in it); `None` when it cannot be read
    /// (damage).
    fn block(&mut self, blk: u64, what: &'static str) -> Result<Option<Vec<u8>>> {
        if (self.base..self.base + self.count).contains(&blk) {
            let n = (BATCH_BYTES / u64::from(self.blocks.block_size())).min(self.base + self.count - blk);
            let run = |i, k| self.blocks.run_bytes(i, k).map(|r| vec![r]);
            if let Some(b) = self.window.fetch(&**self.blocks.source(), blk, n, run)? {
                return Ok(Some(b.to_vec()));
            }
        }
        match self.blocks.read(blk, what) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.scope() == Scope::Unit => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/// Find the newest checkpoint whose checkpoint map and space manager are usable, falling back
/// to older ones (noted as [`DiagCode::BackupUsed`]) when the newest is damaged.
pub fn load(src: &DynSource, limits: &Limits, integrity: &Integrity) -> Result<Checkpoint> {
    let select = (integrity, Role::Select);
    if src.size() < MIN_BLOCK_SIZE as u64 {
        return Err(Error::format("too small for an APFS container"));
    }
    let head = src.read_vec(0, MIN_BLOCK_SIZE as usize)?;
    let bs = NxSuperblock::parse(&head).map_err(|e| Error::format(format!("not an APFS container: {e}")))?.block_size;
    let block0 = src.read_vec(0, bs as usize)?;
    let sb0 = NxSuperblock::parse(&block0).map_err(|e| Error::format(format!("not an APFS container: {e}")))?;
    if sb0.is_fusion() {
        return Err(Error::unsupported("APFS Fusion container"));
    }
    if sb0.xp_desc_blocks & XP_TREE_FLAG != 0 {
        return Err(Error::unsupported("APFS checkpoint descriptor area stored as a B-tree"));
    }
    let mut warnings = Vec::new();
    let sb0_ok =
        sb0.hdr.kind == OBJECT_TYPE_NX_SUPERBLOCK && sum_ok(&block0, 0, StructureKind::ApfsContainerSuperblock, select);
    if !sb0_ok {
        warnings.push(Diagnostic::warning(
            DiagCode::ChecksumMismatch,
            "block 0 container superblock has a bad checksum".to_string(),
        ));
    }
    let geo0 = Geometry::new(bs, sb0.block_count)?;

    // Every valid container superblock of the descriptor area is a checkpoint candidate.
    let desc_blocks = sb0.xp_desc_blocks as u64;
    let desc_end = sb0.xp_desc_base.checked_add(desc_blocks);
    if desc_blocks == 0 || desc_end.is_none_or(|e| e > geo0.block_count) {
        return Err(Error::corrupt(format!(
            "checkpoint descriptor area ({} blocks at {}) outside the container",
            desc_blocks, sb0.xp_desc_base
        )));
    }
    if desc_blocks > MAX_DESC_BLOCKS {
        return Err(Error::limit(format!("{desc_blocks} checkpoint descriptor blocks")));
    }
    // A descriptor block that cannot be read is no candidate.
    let mut area = DescArea::new(geo0.reader(src)?, sb0.xp_desc_base, desc_blocks);
    let mut candidates: Vec<NxSuperblock> = Vec::new();
    let mut unreadable = Vec::new();
    for i in 0..desc_blocks {
        let blk = sb0.xp_desc_base + i;
        let Some(b) = area.block(blk, "checkpoint descriptor")? else {
            unreadable.push(blk);
            continue;
        };
        if let Ok(sb) = NxSuperblock::parse(&b)
            && sb.hdr.kind == OBJECT_TYPE_NX_SUPERBLOCK
            && sb.block_size == bs
            && sum_ok(&b, blk, StructureKind::ApfsContainerSuperblock, select)
        {
            candidates.push(sb);
        }
    }
    if let Some(first) = unreadable.first() {
        warnings.push(Diagnostic::warning(
            DiagCode::BackupUsed,
            format!(
                "{} checkpoint descriptor blocks cannot be read (the first at block {first}); the newest \
                 checkpoint among the rest is used",
                unreadable.len()
            ),
        ));
    }
    if sb0_ok {
        candidates.push(sb0);
    }
    candidates.sort_by_key(|s| std::cmp::Reverse(s.hdr.xid));
    candidates.dedup_by_key(|s| s.hdr.xid);
    if candidates.is_empty() {
        return Err(Error::corrupt("no valid container superblock in the checkpoint descriptor area"));
    }

    let mut first_err: Option<Error> = None;
    let mut skipped = Vec::new();
    for sb in candidates {
        match load_checkpoint(src, &sb, &mut area, limits, integrity) {
            Ok(mut cp) => {
                for (xid, e) in &skipped {
                    warnings.push(Diagnostic::warning(
                        DiagCode::BackupUsed,
                        format!("checkpoint {xid} is unusable ({e}); using older checkpoint {}", sb.hdr.xid),
                    ));
                }
                warnings.append(&mut cp.warnings);
                cp.warnings = warnings;
                return Ok(cp);
            }
            // Only damage makes an older checkpoint worth trying.
            Err(e) if e.scope() != Scope::Unit => return Err(e),
            Err(e) => {
                tracing::debug!(xid = sb.hdr.xid, "checkpoint unusable: {e}");
                skipped.push((sb.hdr.xid, e.to_string()));
                first_err.get_or_insert(e);
            }
        }
    }
    Err(first_err.unwrap_or_else(|| Error::corrupt("no usable checkpoint")))
}

/// Load the space manager of the checkpoint `sb` describes and walk its chunk-info blocks, once:
/// a damaged chain makes the caller fall back to an older checkpoint.
fn load_checkpoint(
    src: &DynSource,
    sb: &NxSuperblock,
    area: &mut DescArea,
    limits: &Limits,
    integrity: &Integrity,
) -> Result<Checkpoint> {
    if sb.is_fusion() {
        return Err(Error::unsupported("APFS Fusion container"));
    }
    if sb.xp_desc_blocks & XP_TREE_FLAG != 0 {
        return Err(Error::unsupported("APFS checkpoint descriptor area stored as a B-tree"));
    }
    let geo = Geometry::new(sb.block_size, sb.block_count)?;
    check_descriptor_area(sb, &geo)?;
    let ephemeral = checkpoint_map(sb, area, integrity)?;
    let m = spaceman_mapping(sb, &ephemeral)?;
    let obj = read_spaceman(src, sb, &geo, &m, limits, integrity)?;
    let sm = Arc::new(Spaceman::parse(&obj, geo.block_size, geo.block_count)?);
    let chunks = Chunks::walk(geo.reader(src)?, sm.clone(), integrity)?;
    let warnings = coverage_warnings(&chunks, &sm, &geo);
    Ok(Checkpoint { sb: sb.clone(), geometry: geo, spaceman: sm, chunks: Arc::new(chunks), ephemeral, warnings })
}

/// The checkpoint's place in the descriptor ring must lie inside the ring, and the ring inside
/// the container.
fn check_descriptor_area(sb: &NxSuperblock, geo: &Geometry) -> Result<()> {
    let xid = sb.hdr.xid;
    let desc_blocks = sb.xp_desc_blocks as u64;
    let (desc_index, desc_len) = (sb.xp_desc_index as u64, sb.xp_desc_len as u64);
    if desc_blocks == 0 || desc_index >= desc_blocks || desc_len == 0 || desc_len > desc_blocks {
        return Err(Error::corrupt(format!(
            "checkpoint {xid}: descriptor index {desc_index} length {desc_len} in a {desc_blocks}-block area"
        )));
    }
    if sb.xp_desc_base.checked_add(desc_blocks).is_none_or(|e| e > geo.block_count) {
        return Err(Error::corrupt(format!("checkpoint {xid}: descriptor area outside the container")));
    }
    Ok(())
}

/// The checkpoint map's entries: every ephemeral object of the checkpoint (space manager, free
/// queues, reaper, ...), from the checkpoint-map blocks, which precede the superblock in the
/// descriptor ring.
fn checkpoint_map(sb: &NxSuperblock, area: &mut DescArea, integrity: &Integrity) -> Result<Vec<CheckpointMapping>> {
    let xid = sb.hdr.xid;
    let desc_blocks = sb.xp_desc_blocks as u64;
    let mut ephemeral = Vec::new();
    for k in 0..sb.xp_desc_len as u64 {
        let blk = sb.xp_desc_base + (sb.xp_desc_index as u64 + k) % desc_blocks;
        let b = area
            .block(blk, "checkpoint map")?
            .ok_or_else(|| Error::corrupt(format!("checkpoint {xid}: checkpoint map block {blk} cannot be read")))?;
        let h = ObjHeader::parse(&b)?;
        if k > 0 && h.kind == OBJECT_TYPE_NX_SUPERBLOCK {
            break;
        }
        if h.kind != OBJECT_TYPE_CHECKPOINT_MAP
            || h.xid != xid
            || !sum_ok(&b, blk, StructureKind::ApfsCheckpointMap, (integrity, Role::Select))
        {
            return Err(Error::corrupt(format!(
                "checkpoint {xid}: block {blk} is not a valid checkpoint map (type {:#x}, xid {})",
                h.kind, h.xid
            )));
        }
        let (flags, maps) = parse_checkpoint_map(&b)?;
        ephemeral.extend(maps);
        if flags & CHECKPOINT_MAP_LAST != 0 {
            break;
        }
    }
    Ok(ephemeral)
}

/// The space manager's entry in the checkpoint map.
fn spaceman_mapping(sb: &NxSuperblock, ephemeral: &[CheckpointMapping]) -> Result<CheckpointMapping> {
    let xid = sb.hdr.xid;
    let m = ephemeral.iter().copied().find(|m| m.oid == sb.spaceman_oid).ok_or_else(|| {
        Error::corrupt(format!("checkpoint {xid}: space manager {:#x} not in the checkpoint map", sb.spaceman_oid))
    })?;
    if m.kind != OBJECT_TYPE_SPACEMAN {
        return Err(Error::corrupt(format!("checkpoint {xid}: space manager mapping has type {:#x}", m.kind)));
    }
    Ok(m)
}

/// The space manager object `m` maps, checked. It may span several blocks of the checkpoint
/// data ring, and wrap around it.
fn read_spaceman(
    src: &DynSource,
    sb: &NxSuperblock,
    geo: &Geometry,
    m: &CheckpointMapping,
    limits: &Limits,
    integrity: &Integrity,
) -> Result<Vec<u8>> {
    let xid = sb.hdr.xid;
    let bs = geo.block_size as u64;
    let size = m.size as u64;
    if size == 0 || !size.is_multiple_of(bs) {
        return Err(Error::corrupt(format!("checkpoint {xid}: space manager size {size}")));
    }
    if size > limits.max_alloc {
        return Err(Error::limit(format!("space manager of {size} bytes")));
    }
    let nblocks = size / bs;
    let data_blocks = (sb.xp_data_blocks & !XP_TREE_FLAG) as u64;
    let in_ring =
        sb.xp_data_blocks & XP_TREE_FLAG == 0 && m.paddr >= sb.xp_data_base && m.paddr - sb.xp_data_base < data_blocks;
    if in_ring && nblocks > data_blocks {
        return Err(Error::corrupt(format!("checkpoint {xid}: space manager larger than the data area")));
    }
    // In runs of consecutive blocks: one, or two where it wraps around the ring.
    let first = if in_ring { m.paddr - sb.xp_data_base } else { 0 };
    let runs = if in_ring && first + nblocks > data_blocks {
        vec![(m.paddr, data_blocks - first), (sb.xp_data_base, nblocks - (data_blocks - first))]
    } else {
        vec![(m.paddr, nblocks)]
    };
    let reader = geo.reader(src)?;
    let mut obj = Vec::with_capacity(size as usize);
    let mut buf = Vec::new();
    for (at, n) in runs {
        let n = u32::try_from(n).map_err(|_| Error::corrupt("space manager size overflows"))?;
        reader.read_run(at, n, &mut buf, "apfs space manager")?;
        obj.extend_from_slice(&buf);
    }
    let h = ObjHeader::parse(&obj)?;
    let fits = h.kind == OBJECT_TYPE_SPACEMAN && h.oid == sb.spaceman_oid;
    let sum = !fits || sum_ok(&obj, m.paddr, StructureKind::ApfsSpaceManager, (integrity, Role::Select));
    if !fits || !sum {
        return Err(Error::corrupt(format!(
            "checkpoint {xid}: space manager at block {} is invalid (type {:#x}, oid {:#x}, checksum {})",
            m.paddr,
            h.kind,
            h.oid,
            if sum { "ok" } else { "bad" }
        )));
    }
    Ok(obj)
}

/// Warnings for blocks no chunk or the space manager covers (they count as used).
fn coverage_warnings(chunks: &Chunks, sm: &Spaceman, geo: &Geometry) -> Vec<Diagnostic> {
    let mut warnings = Vec::new();
    let (mut gaps, mut free, mut end) = (0u64, 0u64, 0u64);
    for ci in &chunks.list {
        gaps += ci.addr - end;
        free += ci.free_count as u64;
        end = ci.addr + ci.block_count as u64;
    }
    if gaps > 0 {
        warnings.push(Diagnostic::warning(
            DiagCode::CountedAsUsed,
            format!("{gaps} blocks are not covered by any chunk; they count as used"),
        ));
    }
    if sm.main.block_count < geo.block_count {
        warnings.push(Diagnostic::warning(
            DiagCode::CountedAsUsed,
            format!(
                "space manager covers {} of {} blocks; the rest counts as used",
                sm.main.block_count, geo.block_count
            ),
        ));
    }
    if free != sm.main.free_count {
        tracing::debug!(chunks = free, device = sm.main.free_count, "free block counts differ");
    }
    warnings
}

/// The chunks of a space manager, from one walk of its chunk-info blocks (the bitmaps are not
/// read): at most `chunk_count` entries.
#[derive(Debug, Clone, Default)]
pub struct Chunks {
    /// In ascending block order, each checked against the space manager and the one before.
    pub list: Vec<ChunkInfo>,
    /// The chunk-info and chunk-info address blocks.
    pub objects: Vec<MetaObj>,
}

impl Chunks {
    /// Walk the chunk-info blocks of `sm`.
    pub fn walk(blocks: BlockReader, sm: Arc<Spaceman>, integrity: &Integrity) -> Result<Chunks> {
        let mut w = ChunkWalker::new(blocks, sm, integrity.clone());
        let mut list = Vec::new();
        while let Some(ci) = w.next_chunk()? {
            list.push(ci);
        }
        Ok(Chunks { list, objects: w.objects })
    }
}

/// Walks the chunk-info entries of the main device in ascending block order, one chunk-info
/// block (and at most one CIB-address block) in memory at a time, checking checksums, types,
/// indexes, counts and ordering.
#[derive(Debug)]
struct ChunkWalker {
    blocks: BlockReader,
    integrity: Integrity,
    sm: Arc<Spaceman>,
    /// Next index into `sm.addrs`.
    top: usize,
    cab: Option<Vec<u8>>,
    cab_count: u32,
    cab_pos: u32,
    cib: Option<Vec<u8>>,
    cib_count: u32,
    cib_pos: u32,
    cibs_seen: u64,
    chunks_seen: u64,
    /// The block after the last chunk returned.
    pos: u64,
    /// The CIBs and CABs read.
    objects: Vec<MetaObj>,
}

impl ChunkWalker {
    fn new(blocks: BlockReader, sm: Arc<Spaceman>, integrity: Integrity) -> Self {
        ChunkWalker {
            blocks,
            integrity,
            sm,
            top: 0,
            cab: None,
            cab_count: 0,
            cab_pos: 0,
            cib: None,
            cib_count: 0,
            cib_pos: 0,
            cibs_seen: 0,
            chunks_seen: 0,
            pos: 0,
            objects: Vec::new(),
        }
    }

    /// Read the physical object at `paddr` and check checksum, type and object id.
    fn read_obj(&mut self, paddr: u64, kind: u32, what: StructureKind) -> Result<Vec<u8>> {
        let (h, b) = read_obj(&self.blocks, paddr, paddr, kind, what, (&self.integrity, Role::Select))?;
        self.objects.push(MetaObj::of(paddr, &h, &b));
        Ok(b)
    }

    fn next_cib_addr(&mut self) -> Result<Option<u64>> {
        if self.sm.main.cab_count == 0 {
            let a = self.sm.addrs.get(self.top).copied();
            self.top += a.is_some() as usize;
            return Ok(a);
        }
        loop {
            if let Some(cab) = &self.cab
                && self.cab_pos < self.cab_count
            {
                let a = u64_at(cab, ARRAY_HEADER + self.cab_pos as usize * 8)?;
                self.cab_pos += 1;
                return Ok(Some(a));
            }
            let Some(&a) = self.sm.addrs.get(self.top) else { return Ok(None) };
            let b = self.read_obj(a, OBJECT_TYPE_SPACEMAN_CAB, StructureKind::ApfsChunkInfoAddressBlock)?;
            let (index, count) = (u32_at(&b, 0x20)?, u32_at(&b, 0x24)?);
            if index as usize != self.top || count == 0 || count > self.sm.cibs_per_cab {
                return Err(Error::corrupt(format!(
                    "chunk-info address block at {a}: index {index} (want {}), {count} entries",
                    self.top
                )));
            }
            self.top += 1;
            self.cab = Some(b);
            self.cab_count = count;
            self.cab_pos = 0;
        }
    }

    /// The next chunk, in ascending block order; `None` after the last one (then not called
    /// again).
    fn next_chunk(&mut self) -> Result<Option<ChunkInfo>> {
        loop {
            if let Some(cib) = &self.cib
                && self.cib_pos < self.cib_count
            {
                let ci = ChunkInfo::parse(cib, ARRAY_HEADER + self.cib_pos as usize * CHUNK_INFO)?;
                self.cib_pos += 1;
                self.check_chunk(&ci)?;
                return Ok(Some(ci));
            }
            let sm = self.sm.clone();
            let main = &sm.main;
            let Some(a) = self.next_cib_addr()? else {
                if self.cibs_seen != main.cib_count as u64 || self.chunks_seen != main.chunk_count {
                    return Err(Error::corrupt(format!(
                        "space manager lists {} chunk-info blocks with {} chunks, expected {} with {}",
                        self.cibs_seen, self.chunks_seen, main.cib_count, main.chunk_count
                    )));
                }
                return Ok(None);
            };
            if self.cibs_seen >= main.cib_count as u64 {
                return Err(Error::corrupt(format!("more than {} chunk-info blocks", main.cib_count)));
            }
            let b = self.read_obj(a, OBJECT_TYPE_SPACEMAN_CIB, StructureKind::ApfsChunkInfoBlock)?;
            let (index, count) = (u32_at(&b, 0x20)? as u64, u32_at(&b, 0x24)?);
            // The index is global; accept one counted within its address block too.
            let local = if main.cab_count > 0 { Some(self.cab_pos.saturating_sub(1) as u64) } else { None };
            if (index != self.cibs_seen && Some(index) != local) || count == 0 || count > self.sm.chunks_per_cib {
                return Err(Error::corrupt(format!(
                    "chunk-info block at {a}: index {index} (want {}), {count} chunks",
                    self.cibs_seen
                )));
            }
            self.cibs_seen += 1;
            self.cib = Some(b);
            self.cib_count = count;
            self.cib_pos = 0;
        }
    }

    fn check_chunk(&mut self, ci: &ChunkInfo) -> Result<()> {
        let main = &self.sm.main;
        let end = ci.addr.checked_add(ci.block_count as u64);
        let bad = if self.chunks_seen >= main.chunk_count {
            Some(format!("more than {} chunks", main.chunk_count))
        } else if ci.addr < self.pos {
            Some(format!("chunk at block {} overlaps or precedes the previous one (ending at {})", ci.addr, self.pos))
        } else if ci.block_count == 0 || ci.block_count > self.sm.blocks_per_chunk {
            Some(format!("chunk at block {} has {} blocks", ci.addr, ci.block_count))
        } else if ci.free_count > ci.block_count {
            Some(format!("chunk at block {} has {} free of {} blocks", ci.addr, ci.free_count, ci.block_count))
        } else if end.is_none_or(|e| e > main.block_count) {
            Some(format!("chunk at block {} extends past the device ({} blocks)", ci.addr, main.block_count))
        } else {
            None
        };
        if let Some(msg) = bad {
            return Err(Error::corrupt(format!("space manager: {msg}")));
        }
        self.pos = end.unwrap_or(self.pos);
        self.chunks_seen += 1;
        Ok(())
    }
}
