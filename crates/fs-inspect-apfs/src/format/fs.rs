//! The APFS [`Filesystem`](fs_inspect_core::Filesystem): used blocks of the whole container from
//! the chunk bitmaps of the space manager, streamed one chunk (one chunk-info entry, at most
//! one bitmap block) per step.
//!
//! - A chunk whose bitmap cannot be read, blocks no chunk covers and the tail the space manager
//!   does not describe count as used (`counted_as_used`).
//! - Blocks in the free queues are still set in the bitmaps, so they count as used.
//! - APFS has no unwritten extents (unwritten space is a hole), so nothing reads as zeros.

use crate::format::checksum;
use crate::format::container::{self, Chunks, Geometry};
use crate::format::layout::{
    CheckpointMapping, ChunkInfo, NxSuperblock, OBJECT_TYPE_NX_SUPERBLOCK, Spaceman, sane_block_size,
};
use fs_inspect_core::FsInfoExt;
use fs_inspect_core::Integrity;
use fs_inspect_core::Scope;
use fs_inspect_core::block::BlockReader;
use fs_inspect_core::bytes::{bytes_at, u32_at};
use fs_inspect_core::{
    ByteRange, Confidence, DiagCode, Diagnostics, DriverContext, FnCursor, FsInfo, FsKind, Limits, RangeCursor, Result,
    Sniff, push_bit_runs, push_range,
};
use fs_inspect_io::DynSource;
use fs_inspect_io::batch::{BATCH_BYTES, ItemWindow};
use std::sync::Arc;

/// An opened APFS container.
#[derive(Debug)]
pub struct ApfsFs {
    blocks: BlockReader,
    info: FsInfo,
    geo: Geometry,
    /// Container superblock of the checkpoint in use.
    sb: NxSuperblock,
    spaceman: Arc<Spaceman>,
    chunks: Arc<Chunks>,
    /// The checkpoint's ephemeral objects.
    ephemeral: Vec<CheckpointMapping>,
    limits: Limits,
    pub(crate) diag: Diagnostics,
    pub(crate) integrity: Integrity,
    /// The object maps read, loaded once.
    pub(crate) omaps: Arc<crate::format::omap::OmapCache>,
    /// The volumes path lookups read, found once.
    pub(crate) lookups: std::sync::OnceLock<Result<crate::format::lookup::Lookups>>,
    /// The node cache the batches of a walk share while it holds it ([`Namespace::hold`]).
    ///
    /// [`Namespace::hold`]: fs_inspect_core::Namespace::hold
    pub(crate) held: fs_inspect_core::Held<crate::format::btree::NodeCache>,
}

/// `NXSB` at offset 32 of block 0 with a sane block size: `High` when the object checksum is
/// valid, `Medium` otherwise.
pub fn probe(s: &Sniff<'_>) -> Option<(FsKind, Confidence)> {
    if bytes_at::<4>(s.head, 0x20).ok()? != *crate::format::layout::NX_MAGIC {
        return None;
    }
    let bs = u32_at(s.head, 0x24).ok()?;
    if !sane_block_size(bs) {
        return None;
    }
    let block = s.head.get(..bs as usize);
    let ok = block.is_some_and(|b| {
        checksum::verify(b) && NxSuperblock::parse(b).is_ok_and(|sb| sb.hdr.kind == OBJECT_TYPE_NX_SUPERBLOCK)
    });
    Some((FsKind::Apfs, if ok { Confidence::High } else { Confidence::Medium }))
}

/// Open the APFS container starting at offset 0 of `src`.
pub fn open(src: DynSource, ctx: &DriverContext) -> Result<Arc<dyn fs_inspect_core::Filesystem>> {
    Ok(Arc::new(ApfsFs::open(src, ctx)?))
}

impl ApfsFs {
    /// Messages reported while opening (tests).
    #[cfg(test)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub(crate) fn warnings(&self) -> Vec<String> {
        self.diag.own().into_iter().map(|d| d.message).collect()
    }

    /// Open the container at offset 0 of `src`; damage worked around goes to `ctx.diagnostics`.
    pub fn open(src: DynSource, ctx: &DriverContext) -> Result<Self> {
        let integrity = ctx.integrity();
        let cp = container::load(&src, &ctx.limits, &integrity)?;
        for d in &cp.warnings {
            ctx.diagnostics.report(d.severity, d.code, d.message.clone());
        }
        let info = FsInfo::new(
            FsKind::Apfs,
            u64::from(cp.geometry.block_size),
            cp.geometry.volume_bytes(),
            None,
            Some(fs_inspect_core::guid::format_uuid(&cp.sb.uuid).to_uppercase()),
        );
        Ok(ApfsFs {
            blocks: cp.geometry.reader(&src)?,
            info,
            geo: cp.geometry,
            sb: cp.sb,
            spaceman: cp.spaceman,
            chunks: cp.chunks,
            ephemeral: cp.ephemeral,
            limits: ctx.limits.clone(),
            diag: ctx.diagnostics.clone(),
            integrity,
            omaps: Arc::default(),
            lookups: std::sync::OnceLock::new(),
            held: Default::default(),
        })
    }

    /// Transaction id of the checkpoint in use.
    pub fn checkpoint_xid(&self) -> u64 {
        self.sb.hdr.xid
    }

    /// Block size and block count of the container.
    /// The container's blocks.
    pub(crate) fn blocks(&self) -> &BlockReader {
        &self.blocks
    }

    pub fn geometry(&self) -> Geometry {
        self.geo
    }

    /// The container superblock of the checkpoint in use (checksum and type checked).
    pub fn superblock(&self) -> &NxSuperblock {
        &self.sb
    }

    /// The container it was opened on (offset 0 is the start of the container).
    pub fn source(&self) -> &DynSource {
        self.blocks.source()
    }

    /// The limits the container was opened with.
    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// The space manager of the checkpoint in use.
    pub fn spaceman(&self) -> &Spaceman {
        &self.spaceman
    }

    /// The chunks of the space manager in use.
    pub fn chunks(&self) -> &Chunks {
        &self.chunks
    }

    /// The checkpoint map of the checkpoint in use: its ephemeral objects.
    pub fn ephemeral(&self) -> &[CheckpointMapping] {
        &self.ephemeral
    }

    /// The bitmap at block `addr`, from `batch` (blocks): past it, `batch` is refilled with
    /// that bitmap and those of the `upcoming` chunks at the blocks after it, in one read.
    fn bitmap(&self, addr: u64, upcoming: impl Iterator<Item = ChunkInfo>, batch: &mut ItemWindow) -> Result<Vec<u8>> {
        let max = (BATCH_BYTES / u64::from(self.geo.block_size)).max(1);
        let mut n = 1u64;
        // Chunks without a bitmap to read leave the run going.
        for c in upcoming.filter(|c| c.free_count != 0 && c.bitmap_addr != 0) {
            if n >= max || Some(c.bitmap_addr) != addr.checked_add(n) {
                break;
            }
            n += 1;
        }
        let run = |i, k| self.blocks.run_bytes(i, k).map(|r| vec![r]);
        match batch.fetch(&**self.blocks.source(), addr, n, run)? {
            Some(bm) => Ok(bm.to_vec()),
            None => self.blocks.read(addr, "apfs chunk bitmap"),
        }
    }

    /// One step of the walk of the used blocks: chunk `*i` (and the blocks between the previous
    /// chunk, ending at `*end`, and it) appended to `out`, or past the last chunk the blocks the
    /// space manager does not describe. `false` when done.
    fn used_step(
        &self,
        i: &mut usize,
        end: &mut u64,
        batch: &mut ItemWindow,
        out: &mut Vec<ByteRange>,
    ) -> Result<bool> {
        let bs = self.geo.block_size as u64;
        let total = self.geo.block_count;
        let list = &self.chunks.list;
        let Some(ci) = list.get(*i) else {
            // Blocks the space manager does not describe count as used.
            let e = (*end).min(total);
            push_range(out, e * bs, (total - e) * bs);
            return Ok(false);
        };
        if ci.addr > *end {
            push_range(out, *end * bs, (ci.addr.min(total) - (*end).min(total)) * bs);
        }
        self.emit_chunk(ci, list[*i + 1..].iter().copied(), batch, out)?;
        (*i, *end) = (*i + 1, ci.addr + ci.block_count as u64);
        Ok(true)
    }

    /// The used blocks of the container, as byte ranges (sorted, coalesced).
    pub fn used_ranges(&self) -> Result<Vec<ByteRange>> {
        let mut batch = ItemWindow::new(u64::from(self.geo.block_size));
        let (mut i, mut end, mut out) = (0usize, 0u64, Vec::new());
        while self.used_step(&mut i, &mut end, &mut batch, &mut out)? {}
        fs_inspect_core::range::list::normalize(&mut out);
        Ok(out)
    }

    /// Append the used blocks of chunk `ci` to `out`; its bitmap from `batch` (see
    /// [`bitmap`](Self::bitmap)).
    fn emit_chunk(
        &self,
        ci: &ChunkInfo,
        upcoming: impl Iterator<Item = ChunkInfo>,
        batch: &mut ItemWindow,
        out: &mut Vec<ByteRange>,
    ) -> Result<()> {
        let bs = self.geo.block_size as u64;
        // The walker keeps each chunk non-empty and inside the device, which is inside the
        // container.
        let count = ci.block_count as u64;
        let base = ci.addr * bs;
        if ci.free_count == 0 {
            push_range(out, base, count * bs);
        } else if ci.bitmap_addr == 0 {
            if ci.free_count != ci.block_count {
                self.diag.warn(
                    DiagCode::CountedAsUsed,
                    format!(
                        "chunk at block {} has {} used blocks but no bitmap; the chunk counts as used",
                        ci.addr,
                        ci.block_count - ci.free_count
                    ),
                );
                push_range(out, base, count * bs);
            }
        } else {
            let bm = match self.bitmap(ci.bitmap_addr, upcoming, batch) {
                Ok(bm) => bm,
                Err(e) if e.scope() != Scope::Unit => return Err(e),
                Err(e) => {
                    self.diag.warn(
                        DiagCode::CountedAsUsed,
                        format!("bitmap of the chunk at block {} unreadable ({e}); the chunk counts as used", ci.addr),
                    );
                    push_range(out, base, count * bs);
                    return Ok(());
                }
            };
            push_bit_runs(out, &bm, count, base, bs);
            if tracing::enabled!(tracing::Level::DEBUG) {
                let set: u64 = (0..count)
                    .filter(|i| bm.get((i / 8) as usize).is_some_and(|b| (b >> (i % 8)) & 1 == 1))
                    .count() as u64;
                let want = (ci.block_count - ci.free_count) as u64;
                if set != want {
                    tracing::debug!(chunk = ci.addr, bitmap = set, info = want, "chunk used counts differ");
                }
            }
        }
        Ok(())
    }
}

impl fs_inspect_core::sealed::Fs for ApfsFs {}

impl fs_inspect_core::Filesystem for ApfsFs {
    fn default_excludes(&self) -> &'static [fs_inspect_core::DefaultExclude] {
        super::exclude::DEFAULT_EXCLUDES
    }

    fn info(&self) -> &FsInfo {
        &self.info
    }

    /// Copy-on-write with checkpoints: the newest valid checkpoint (the one read) is
    /// consistent; there is nothing to replay.
    fn verify(&self, scope: &fs_inspect_core::VerifyScope) -> Result<()> {
        crate::format::verify::verify(self, scope)
    }

    fn consistency(&self) -> fs_inspect_core::Consistency {
        fs_inspect_core::Consistency::Clean
    }

    /// The chunks' free block counts (the container's, as every volume's map is); a chunk
    /// partly used without a bitmap counts as used, as in the map. The walker keeps the chunks
    /// apart, inside the container, each with at most its own blocks free: the sum fits the
    /// container's size.
    fn free_bytes(&self) -> Option<u64> {
        let free: u64 = self
            .chunks
            .list
            .iter()
            .filter(|ci| ci.bitmap_addr != 0 || ci.free_count == ci.block_count)
            .map(|ci| u64::from(ci.free_count))
            .sum();
        Some(free * u64::from(self.geo.block_size))
    }

    fn namespace(self: Arc<Self>) -> Option<Arc<dyn fs_inspect_core::Namespace>> {
        Some(self)
    }

    fn allocated(self: Arc<Self>) -> Result<Box<dyn RangeCursor>> {
        let mut batch = ItemWindow::new(u64::from(self.geo.block_size));
        let fs = self;
        // The next chunk, and the block after the previous one.
        let (mut i, mut end) = (0usize, 0u64);
        Ok(Box::new(FnCursor::new(move |out: &mut Vec<ByteRange>| fs.used_step(&mut i, &mut end, &mut batch, out))))
    }
}
