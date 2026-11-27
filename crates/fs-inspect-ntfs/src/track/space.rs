//! Dating the used space outside the reported files by its content, read with the MFT or for
//! this, against digests the previous signature keeps (driver sections), or by the structures
//! it is written with.
//!
//! Every digest is of the bytes as read (before the fixups) and where they lie: stamps (LSNs,
//! the update sequence number NTFS writes into every 512-byte sector of a record) repeat on
//! another branch of the volume's history (a snapshot written to after it was taken, such as
//! for VSS writers' recovery, and the live volume after it), content does not.
//!
//! Each kind of structure keeps [`ChunkDigests`] (a driver section): per chunk, the digest of
//! what was read in it with where each piece lies.
//!
//! - MFT: a chunk of `$MFT:$DATA` ([`MFT_CHUNK`] bytes, or one record when records are larger)
//!   is unchanged when its digest is the previous signature's; the system records
//!   (`$MFTMirr`, `$Secure`, `$UpCase`, ...) also one by one.
//! - Index blocks of every `$INDEX_ALLOCATION` (directories, `$Secure`, `$Extend` indexes),
//!   checked against their VCN: a digest per block, grouped by [`MFT_CHUNK`] of the volume.
//! - `$LogFile`: its record pages read, a digest per [`LOG_CHUNK`] of the log.
//! - The data of the files under `$Extend` but the journal's `$J` (`$RmMetadata`'s
//!   `$Repair` streams and transaction logs: NTFS writes them, no file reports them): read, a
//!   digest per [`EXTEND_CHUNK`] of the volume.
//! - `$Bitmap`: a cluster of it is unchanged when the allocation of the clusters it describes
//!   is.
//! - `$UpCase`, `$AttrDef`: unchanged while their records are (written when formatted).
//! - Streams written with the structures they are dated by, written back in any order until
//!   the log is clean: dated only when the previous and the current log are clean, or nothing
//!   was in flight at either snapshot nor written in between ([`Prev::settled`]).
//!   - `$MFT:$BITMAP`: a cluster of it is unchanged when every record it describes is (a
//!     record allocated or freed is changed) and so is `$MFT`'s own record (its size and the
//!     bitmap's runlist: the clusters past the last record are unchanged with it).
//!   - `$MFTMirr`: unchanged when the records it mirrors are.
//!   - `$Secure:$SDS`: descriptors are only appended, each with new `$SII` / `$SDH` entries:
//!     unchanged when the `$Secure` records (base and extension) and index blocks are.
//! - The runlists of these system streams are put together from the fragments in the base
//!   record and its extension records ([`assemble`]).
//! - Fixed (compared by content): `$Boot`, the backup boot sector past the last cluster, the
//!   two `$LogFile` restart pages (rewritten on every mount).
//! - The rest is the residual (dirty): index `$BITMAP`s, files that are not reported (damaged,
//!   `$BadClus`), blocks that do not check out. (The attribute lists and other
//!   non-`$DATA` attributes of reported files are owned by them: `scan`.)

use crate::format::attr::RawAttrBody;
use crate::format::fixup::check_fixup;
use crate::format::index::parse_index_root;
use crate::format::record::ParsedRecord;
use crate::format::volume::MFT_CHUNK;
use crate::format::volume::map_stream_bytes;
use crate::{AttrType, Frn, NtfsVolume, Run, system_records};
use fs_inspect_change::chunks::{ChunkDigests, ChunkHasher};
use fs_inspect_change::hash::CanonHasher;
use fs_inspect_core::ByteRange;
use fs_inspect_core::Scope;
use fs_inspect_core::bytes::u64_at;
use fs_inspect_core::range::list::normalize;
use fs_inspect_io::batch::{BATCH_BYTES, GAP_BYTES, plan, read_runs};
use std::collections::BTreeMap;

/// Bytes of `$LogFile` per digest: a quarter of a 1 MiB batch read, like the node page chunks of
/// ReFS.
pub const LOG_CHUNK: u64 = 256 << 10;
/// Bytes of the volume per digest of the data under `$Extend`.
pub const EXTEND_CHUNK: u64 = 256 << 10;
/// Index block size assumed when the index root is not in the base record.
const DEFAULT_INDEX_BLOCK: u32 = 4096;
/// Most index blocks read together (planned at once).
const INDEX_GROUP: usize = 1 << 16;

/// What [`Dater`] found.
#[derive(Debug, Default)]
pub struct Dated {
    pub tracked: Vec<ByteRange>,
    /// The digest of each system record (`0..FIRST_USER`) read, by record number.
    pub system: ChunkDigests,
    /// The digest of each [`MFT_CHUNK`] of `$MFT:$DATA` read.
    pub mft: ChunkDigests,
    /// The digest of the index blocks in each [`MFT_CHUNK`] of the volume.
    pub indexes: ChunkDigests,
    /// The digest of the record pages in each [`LOG_CHUNK`] of `$LogFile`.
    pub log: ChunkDigests,
    /// The digest of the data under `$Extend` in each [`EXTEND_CHUNK`] of the volume.
    pub extend: ChunkDigests,
}

/// What the previous signature dates against.
#[derive(Debug, Default, Clone, Copy)]
pub struct Prev<'a> {
    /// Its digests ([`Dated`]); `None`: nothing of that kind is unchanged.
    pub system: Option<&'a ChunkDigests>,
    pub mft: Option<&'a ChunkDigests>,
    pub indexes: Option<&'a ChunkDigests>,
    pub log: Option<&'a ChunkDigests>,
    pub extend: Option<&'a ChunkDigests>,
    /// Where the allocation may differ from its snapshot's (`None`: `$Bitmap` is not dated).
    pub alloc_changes: Option<&'a [ByteRange]>,
    /// Its log and the current one are clean (every structure of both snapshots was written
    /// back), or both snapshots are of a guest not running with nothing written in between
    /// (`false`: the streams dated by structures written with them are not dated).
    pub settled: bool,
}

/// Into `h`: `raw` as read (before the fixups) and where it lies (`pieces`).
fn placed(h: &mut CanonHasher, pieces: &[ByteRange], raw: &[u8]) {
    h.u64(pieces.len() as u64);
    for p in pieces {
        h.u64(p.offset).u64(p.length);
    }
    h.bytes(raw);
}

/// The digest of `raw` read from `pieces` under `domain`.
fn placed_digest(domain: &[u8], pieces: &[ByteRange], raw: &[u8]) -> u64 {
    let mut h = CanonHasher::new(domain);
    placed(&mut h, pieces, raw);
    h.finish()
}

/// Dates the used space of a volume outside the reported files against `prev`: the chunks of
/// `$MFT:$DATA` as they are read ([`Self::chunk`]), then the rest ([`Self::finish`]).
pub struct Dater<'a> {
    vol: &'a NtfsVolume,
    prev: Prev<'a>,
    out: Dated,
    roots: BTreeMap<(u64, Vec<u16>), u32>,
    indexes: Vec<(u64, Vec<u16>, Vec<Run>)>,
    /// The fragments of the system streams, from their base records and extension records.
    fragments: Vec<Fragment>,
    /// The sequence number of each system record in use.
    bases: BTreeMap<u64, u16>,
    /// The extension records of the system records in use: (base, record).
    holders: Vec<(Frn, u64)>,
    /// The system records with an attribute list.
    listed: Vec<u64>,
    /// Chunks handed to [`Self::chunk`] (read).
    read: u64,
    /// The clusters of the data under `$Extend` ([`Self::extend_data`]).
    extend: Vec<ByteRange>,
    /// Per chunk, per system record: unchanged since `prev`.
    unchanged: Vec<bool>,
    sys_unchanged: Vec<bool>,
}

impl<'a> Dater<'a> {
    pub fn new(vol: &'a NtfsVolume, prev: Prev<'a>) -> Self {
        let mft = vol.mft();
        let chunks = (mft.record_count * u64::from(mft.record_size)).div_ceil(vol.mft_chunk());
        // The system records one by one, then the chunks.
        let sys = system_records::FIRST_USER.min(mft.record_count);
        Dater {
            vol,
            prev,
            out: Dated::default(),
            roots: BTreeMap::new(),
            indexes: Vec::new(),
            fragments: Vec::new(),
            bases: BTreeMap::new(),
            holders: Vec::new(),
            listed: Vec::new(),
            read: 0,
            extend: Vec::new(),
            unchanged: vec![false; chunks as usize],
            sys_unchanged: vec![false; sys as usize],
        }
    }

    /// Chunk `c` of `$MFT:$DATA` ([`NtfsVolume::mft_chunks`]): `raw`, read from `pieces`, and
    /// its records parsed ([`NtfsVolume::parse_chunk`]).
    pub fn chunk(&mut self, c: u64, pieces: &[ByteRange], raw: &[u8], parsed: &[Option<ParsedRecord>]) {
        let (vol, prev) = (self.vol, self.prev);
        let g = vol.geometry();
        let mft = vol.mft();
        let rs = u64::from(mft.record_size);
        let sys = self.sys_unchanged.len() as u64;
        let logical = c * vol.mft_chunk();
        self.out.mft.insert(c, placed_digest(b"ntfs.mft-chunk", pieces, raw));
        self.read += 1;
        for (i, r) in raw.chunks_exact(rs as usize).enumerate() {
            let n = logical / rs + i as u64;
            if n < sys {
                let at = map_stream_bytes(&mft.runs, g.cluster_size, n * rs, rs).unwrap_or_default();
                self.out.system.insert(n, placed_digest(b"ntfs.system-record", &at, r));
                self.sys_unchanged[n as usize] = prev.system.is_some_and(|p| self.out.system.same(p, n));
            }
        }
        for (i, rec) in parsed.iter().enumerate() {
            let n = logical / rs + i as u64;
            let Some(rec) = rec else { continue };
            if !rec.header.in_use() {
                continue;
            }
            let ext = rec.header.is_extension();
            let frn = if ext { rec.header.base_record } else { rec.frn() };
            let base = frn.record;
            if SYSTEM_BASES.contains(&base) {
                if ext {
                    self.holders.push((frn, n));
                } else {
                    self.bases.insert(n, frn.seq);
                    if rec.has_attr_list() {
                        self.listed.push(n);
                    }
                }
            }
            for a in &rec.attributes {
                let name = a.name.units();
                match (&a.body, a.kind) {
                    (RawAttrBody::Resident { data, .. }, AttrType::INDEX_ROOT) => {
                        if let Ok((info, _)) = parse_index_root(data) {
                            self.roots.insert((base, name.to_vec()), info.block_size);
                        }
                    }
                    (RawAttrBody::NonResident(h), AttrType::INDEX_ALLOCATION) => {
                        if let Ok(runs) = &h.runs {
                            self.indexes.push((base, name.to_vec(), runs.clone()));
                        }
                    }
                    // In the base record or, with an attribute list, in extension records.
                    (RawAttrBody::NonResident(h), kind) => {
                        let stream = if kind == AttrType::DATA && name.is_empty() && SYSTEM_DATA.contains(&base) {
                            Sys::Data(base)
                        } else if kind == AttrType::DATA && base == system_records::SECURE && name == SDS {
                            Sys::Sds
                        } else if kind == AttrType::BITMAP && base == system_records::MFT && name.is_empty() {
                            Sys::MftBitmap
                        } else {
                            continue;
                        };
                        if let Ok(runs) = &h.runs {
                            self.fragments.push(Fragment {
                                stream,
                                base: frn,
                                lowest_vcn: h.lowest_vcn,
                                highest_vcn: h.highest_vcn,
                                allocated: h.allocated,
                                runs: runs.clone(),
                            });
                        }
                    }
                    _ => {}
                }
            }
        }
        if prev.mft.is_some_and(|p| self.out.mft.same(p, c)) {
            self.unchanged[c as usize] = true;
            self.out.tracked.extend(pieces.iter().copied());
        }
    }

    /// The clusters of the data under `$Extend` (the journal's `$J` left out), dated by
    /// [`Self::finish`].
    pub fn extend_data(&mut self, clusters: Vec<ByteRange>) {
        self.extend = clusters;
    }

    /// Date the rest: index blocks, the log, the data under `$Extend`, the system streams, the
    /// bitmaps.
    pub fn finish(self) -> fs_inspect_core::Result<Dated> {
        let Dater {
            vol,
            prev,
            mut out,
            roots,
            indexes,
            fragments,
            bases,
            holders,
            listed,
            read,
            extend,
            unchanged,
            sys_unchanged,
        } = self;
        let records =
            Records { vol, complete: read == unchanged.len() as u64, unchanged, sys_unchanged, bases, holders, listed };
        let system = assemble(fragments, &records.bases, u64::from(vol.geometry().cluster_size));
        let secure_indexes = {
            let _span = tracing::debug_span!("ntfs.indexes").entered();
            date_indexes(vol, &roots, &indexes, prev.indexes, &mut out)?
        };
        {
            let _span = tracing::debug_span!("ntfs.log").entered();
            date_log(vol, &system, prev.log, &mut out)?;
        }
        {
            let _span = tracing::debug_span!("ntfs.extend").entered();
            date_extend(vol, extend, prev.extend, &mut out)?;
        }
        date_system_streams(&records, &system, prev.settled, secure_indexes, &mut out);
        date_bitmap(vol, &system, prev.alloc_changes, &mut out);
        normalize(&mut out.tracked);
        Ok(out)
    }
}

/// The records of the MFT as [`Dater::chunk`] found them against the previous signature.
struct Records<'a> {
    vol: &'a NtfsVolume,
    /// Per chunk, per system record: unchanged since then.
    unchanged: Vec<bool>,
    sys_unchanged: Vec<bool>,
    /// Every chunk was read.
    complete: bool,
    /// The sequence number of each system record in use.
    bases: BTreeMap<u64, u16>,
    /// The extension records of the system records in use: (base, record).
    holders: Vec<(Frn, u64)>,
    /// The system records with an attribute list.
    listed: Vec<u64>,
}

impl Records<'_> {
    /// The records `[from, to)` are unchanged.
    fn unchanged(&self, from: u64, to: u64) -> bool {
        let mft = self.vol.mft();
        let (rs, chunk, sys) = (u64::from(mft.record_size), self.vol.mft_chunk(), self.sys_unchanged.len() as u64);
        let to = to.min(mft.record_count);
        if to <= sys {
            return (from..to).all(|n| self.sys_unchanged[n as usize]);
        }
        to <= from || (from * rs / chunk..=(to * rs - 1) / chunk).all(|c| self.unchanged.get(c as usize) == Some(&true))
    }

    /// System record `s` is unchanged, with every extension record it has (all of them seen:
    /// every chunk was read, when it has an attribute list).
    fn system_unchanged(&self, s: u64) -> bool {
        self.unchanged(s, s + 1)
            && (self.complete || !self.listed.contains(&s))
            && self
                .holders
                .iter()
                .all(|&(b, n)| b.record != s || self.bases.get(&s) != Some(&b.seq) || self.unchanged(n, n + 1))
    }
}

/// Index blocks: each one that checks out goes into the digest (an all-zero one too: never
/// written) of the [`MFT_CHUNK`] of the volume it starts in; those of chunks unchanged since
/// `prev` are tracked. The blocks of all indexes are read together, a group at a time. Returns
/// whether `$Secure`'s indexes are all there, check out and are unchanged.
///
/// Every block is read, not only those of directories the journal or the MFT says changed:
/// NTFS writes a child's duplicated information (times, size) into its parent's entry when the
/// file is closed, after its record already holds it (written when a snapshot was taken with
/// the file open, or a last access time updated). That write leaves no journal record, no log
/// record (the block's LSN stays) and no change to any record in the interval it falls in.
/// `track/tests/index_pairs.rs` measures this on pairs of snapshots.
fn date_indexes(
    vol: &NtfsVolume,
    roots: &BTreeMap<(u64, Vec<u16>), u32>,
    indexes: &[(u64, Vec<u16>, Vec<Run>)],
    prev: Option<&ChunkDigests>,
    out: &mut Dated,
) -> fs_inspect_core::Result<bool> {
    let g = vol.geometry();
    let cs = u64::from(g.cluster_size);
    let mut secure_ok = true;
    // (chunk, pieces, of $Secure)
    type Block = (u64, Vec<ByteRange>, bool);
    let mut blocks: Vec<Block> = Vec::new();
    // (first byte, digest) of each block that checks out.
    let mut digests: Vec<(u64, u64)> = Vec::new();
    // Per index: every block checks out, bytes of blocks read.
    let mut checked = vec![(true, 0u64); indexes.len()];
    // (pieces, (index, logical offset))
    let mut pending: Vec<(Pieces, (usize, u64))> = Vec::new();
    let mut flush = |pending: &mut Vec<(Pieces, (usize, u64))>| {
        read_blocks(vol, std::mem::take(pending), |pieces, (i, logical), raw| {
            let (base, _, _) = &indexes[i];
            let unit = vol.index_block_unit(raw.len() as u32);
            let zero = raw.iter().all(|&b| b == 0);
            let ok = zero
                || &raw[..4] == b"INDX"
                    && u64_at(raw, 0x10).ok() == Some(logical / unit)
                    && check_fixup(raw).is_ok_and(|f| !f.torn());
            checked[i].0 &= ok;
            checked[i].1 += raw.len() as u64;
            if ok && let Some(&ByteRange { offset: p0, .. }) = pieces.first() {
                blocks.push((p0 / MFT_CHUNK, pieces.to_vec(), *base == system_records::SECURE));
                digests.push((p0, placed_digest(b"ntfs.indx", pieces, raw)));
            }
        })
    };
    let mut spans = vec![None; indexes.len()];
    for (i, (base, name, runs)) in indexes.iter().enumerate() {
        let bs = roots.get(&(*base, name.clone())).copied().unwrap_or(DEFAULT_INDEX_BLOCK);
        if !bs.is_power_of_two() || !(512..=65536).contains(&bs) {
            secure_ok &= *base != system_records::SECURE;
            continue;
        }
        let (Some(first), Some(last)) = (runs.first(), runs.last()) else { continue };
        let bs = u64::from(bs);
        let (start, end) = ((first.vcn() * cs).next_multiple_of(bs), last.end_vcn() * cs);
        spans[i] = Some(end.saturating_sub(start) / bs * bs);
        for logical in (start..end.saturating_sub(bs - 1)).step_by(bs as usize) {
            // Unmapped (sparse, past the runs): not read.
            if let Some(pieces) = map_stream_bytes(runs, g.cluster_size, logical, bs) {
                pending.push((pieces, (i, logical)));
            }
            if pending.len() >= INDEX_GROUP {
                flush(&mut pending)?;
            }
        }
    }
    flush(&mut pending)?;
    for (i, (base, _, _)) in indexes.iter().enumerate() {
        if *base == system_records::SECURE
            && let Some(span) = spans[i]
        {
            secure_ok &= checked[i].0 && checked[i].1 == span;
        }
    }
    // In volume order, whatever order the indexes were read in.
    digests.sort_unstable();
    let mut chunks = ChunkHasher::new(b"ntfs.indx-chunk");
    for (p0, d) in digests {
        chunks.at(p0 / MFT_CHUNK).u64(d);
    }
    out.indexes = chunks.finish();
    for (chunk, pieces, secure) in &blocks {
        let same = prev.is_some_and(|p| out.indexes.same(p, *chunk));
        if same {
            out.tracked.extend(pieces.iter().copied());
        }
        secure_ok &= !secure || same;
    }
    Ok(secure_ok && (prev.is_some() || !indexes.iter().any(|i| i.0 == system_records::SECURE)))
}

/// `$LogFile` record pages, read every time: each [`LOG_CHUNK`]'s digest is of the pages read
/// in it (with their offsets in the log); those of chunks unchanged since `prev` are tracked.
fn date_log(
    vol: &NtfsVolume,
    system: &BTreeMap<Sys, Vec<Run>>,
    prev: Option<&ChunkDigests>,
    out: &mut Dated,
) -> fs_inspect_core::Result<()> {
    let Some(runs) = system.get(&Sys::Data(system_records::LOG_FILE)) else { return Ok(()) };
    let Some(r) = crate::format::lfs::restart::restart_info(vol)? else { return Ok(()) };
    let page = u64::from(r.log_page);
    let map = |p: u64| map_stream_bytes(runs, vol.geometry().cluster_size, p, page);
    let pages = (2 * u64::from(r.system_page)..r.file_size.saturating_sub(page - 1))
        .step_by(page as usize)
        .filter_map(|p| Some((map(p)?, p)))
        .collect();
    // (offset in the log, digest) of each page read.
    let mut read = Vec::new();
    read_blocks(vol, pages, |pieces, p, raw| read.push((p, placed_digest(b"ntfs.log-page", pieces, raw))))?;
    read.sort_unstable();
    let mut chunks = ChunkHasher::new(b"ntfs.log-chunk");
    for &(p, d) in &read {
        chunks.at(p / LOG_CHUNK).u64(p).u64(d);
    }
    out.log = chunks.finish();
    if let Some(prev) = prev {
        for &(p, _) in read.iter().filter(|&&(p, _)| out.log.same(prev, p / LOG_CHUNK)) {
            out.tracked.extend(map(p).into_iter().flatten());
        }
    }
    Ok(())
}

/// The data under `$Extend` (`clusters`), read every time in pieces that do not cross an
/// [`EXTEND_CHUNK`] of the volume: each chunk's digest is of the pieces read in it (with where
/// they lie); those of chunks unchanged since `prev` are tracked. NTFS writes these streams
/// with no journal record or stamp to date them by, but their content says it all.
fn date_extend(
    vol: &NtfsVolume,
    mut clusters: Vec<ByteRange>,
    prev: Option<&ChunkDigests>,
    out: &mut Dated,
) -> fs_inspect_core::Result<()> {
    normalize(&mut clusters);
    let mut blocks = Vec::new();
    for r in clusters {
        let mut at = r.offset;
        while at < r.end() {
            let end = r.end().min((at / EXTEND_CHUNK + 1) * EXTEND_CHUNK);
            blocks.push((vec![ByteRange::from_bounds(at, end)], ()));
            at = end;
        }
    }
    // (piece, digest) of each piece read.
    let mut read = Vec::new();
    read_blocks(vol, blocks, |pieces, (), raw| {
        read.push((pieces[0], placed_digest(b"ntfs.extend-piece", pieces, raw)))
    })?;
    read.sort_unstable_by_key(|(p, _)| p.offset);
    let mut chunks = ChunkHasher::new(b"ntfs.extend-chunk");
    for &(p, d) in &read {
        chunks.at(p.offset / EXTEND_CHUNK).u64(p.offset).u64(p.length).u64(d);
    }
    out.extend = chunks.finish();
    if let Some(prev) = prev {
        out.tracked
            .extend(read.iter().filter(|(p, _)| out.extend.same(prev, p.offset / EXTEND_CHUNK)).map(|(p, _)| *p));
    }
    Ok(())
}

/// The system streams dated by the records they go with: `$UpCase` and `$AttrDef` always;
/// `$MFTMirr`, `$MFT:$BITMAP` and `$Secure:$SDS` when `settled` ([`Prev::settled`]), the last
/// also when `$Secure`'s indexes are unchanged (`secure_indexes`).
fn date_system_streams(
    records: &Records<'_>,
    system: &BTreeMap<Sys, Vec<Run>>,
    settled: bool,
    secure_indexes: bool,
    out: &mut Dated,
) {
    let mft = records.vol.mft();
    let cs = u64::from(records.vol.geometry().cluster_size);
    let rs = u64::from(mft.record_size);
    // `$UpCase`, `$AttrDef`: with their record.
    for s in [system_records::UPCASE, system_records::ATTR_DEF] {
        if let Some(runs) = system.get(&Sys::Data(s))
            && records.system_unchanged(s)
        {
            out.tracked.extend(clusters(runs, cs));
        }
    }
    if !settled {
        return;
    }
    // `$MFTMirr`: with the records it mirrors.
    if let Some(runs) = system.get(&Sys::Data(system_records::MFT_MIRR)) {
        let n = runs.last().map_or(0, Run::end_vcn) * cs / rs;
        if n > 0 && records.unchanged(0, n) {
            out.tracked.extend(clusters(runs, cs));
        }
    }
    // `$MFT:$BITMAP`: each of its clusters describes `8 * cs` records (none past the last
    // record: those follow `$MFT`'s record alone).
    let in_use_unchanged = |s: u64| records.bases.contains_key(&s) && records.system_unchanged(s);
    if in_use_unchanged(system_records::MFT) {
        for r in system.get(&Sys::MftBitmap).map_or(&[][..], Vec::as_slice) {
            let Some(lcn) = r.lcn() else { continue };
            for v in r.vcn()..r.end_vcn() {
                if records.unchanged(v * 8 * cs, (v + 1) * 8 * cs) {
                    out.tracked.push(ByteRange::new((lcn + v - r.vcn()) * cs, cs));
                }
            }
        }
    }
    // `$Secure:$SDS`.
    if secure_indexes
        && in_use_unchanged(system_records::SECURE)
        && let Some(sds) = system.get(&Sys::Sds)
    {
        out.tracked.extend(clusters(sds, cs));
    }
}

/// `$Bitmap`: each of its clusters describes `8 * cs` clusters of the volume; unchanged when
/// none of their allocation changed (`changes`, `None`: not dated).
fn date_bitmap(vol: &NtfsVolume, system: &BTreeMap<Sys, Vec<Run>>, changes: Option<&[ByteRange]>, out: &mut Dated) {
    let (Some(runs), Some(diff)) = (system.get(&Sys::Data(system_records::BITMAP)), changes) else { return };
    let g = vol.geometry();
    let cs = u64::from(g.cluster_size);
    let span = 8 * cs * cs;
    let mut changed: Vec<u64> = diff.iter().flat_map(|d| d.offset / span..=(d.end() - 1) / span).collect();
    changed.dedup();
    let bitmap_vcns = runs.last().map(Run::end_vcn).unwrap_or(0);
    let need = g.cluster_count.div_ceil(8 * cs);
    for r in runs {
        let Some(lcn) = r.lcn() else { continue };
        for v in r.vcn()..r.end_vcn().min(bitmap_vcns).min(need) {
            if changed.binary_search(&v).is_err() {
                out.tracked.push(ByteRange::new((lcn + v - r.vcn()) * cs, cs));
            }
        }
    }
}

/// The fixed regions: `$Boot`, the sectors past the last whole cluster (the backup boot
/// sector) of a volume of `volume_bytes`, the `$LogFile` restart pages.
pub fn fixed(vol: &NtfsVolume, volume_bytes: u64) -> fs_inspect_core::Result<Vec<ByteRange>> {
    let g = vol.geometry();
    let cs = u64::from(g.cluster_size);
    // A record that cannot be read (damage): no runs.
    let data = |n: u64| -> fs_inspect_core::Result<Vec<Run>> {
        match vol.entry(n) {
            Ok(Some(e)) => Ok(e
                .streams
                .iter()
                .find(|s| s.kind == AttrType::DATA && s.name.is_empty())
                .map(|s| s.runs().to_vec())
                .unwrap_or_default()),
            Ok(None) => Ok(Vec::new()),
            Err(e) if e.scope() == Scope::Unit => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    };
    let mut v = clusters(&data(system_records::BOOT)?, cs);
    if v.is_empty() {
        v.push(ByteRange::new(0, cs.max(8192)));
    }
    let restart = crate::format::lfs::restart::restart_info(vol)?.map_or(8192, |r| 2 * u64::from(r.system_page));
    let pieces = crate::format::volume::map_stream_bytes(&data(system_records::LOG_FILE)?, g.cluster_size, 0, restart);
    v.extend(pieces.unwrap_or_default());
    let end = g.cluster_count * cs;
    if volume_bytes > end {
        v.push(ByteRange::new(end, volume_bytes - end));
    }
    normalize(&mut v);
    Ok(v)
}

/// Unnamed `$DATA` of these system files is dated as a whole.
const SYSTEM_DATA: [u64; 6] = [
    system_records::MFT_MIRR,
    system_records::LOG_FILE,
    system_records::ATTR_DEF,
    system_records::BITMAP,
    system_records::BOOT,
    system_records::UPCASE,
];
/// `$SDS` in UTF-16.
const SDS: &[u16] = &[0x24, 0x53, 0x44, 0x53];

/// The records whose fragments of [`Sys`] streams are kept.
const SYSTEM_BASES: [u64; 8] = [
    system_records::MFT,
    system_records::MFT_MIRR,
    system_records::LOG_FILE,
    system_records::ATTR_DEF,
    system_records::BITMAP,
    system_records::BOOT,
    system_records::SECURE,
    system_records::UPCASE,
];

/// A system stream the dater reads the runs of.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Sys {
    /// The unnamed `$DATA` of one of [`SYSTEM_DATA`].
    Data(u64),
    /// `$Secure:$SDS`.
    Sds,
    /// `$MFT:$BITMAP`.
    MftBitmap,
}

/// A fragment of a [`Sys`] stream, as one record (base or extension) holds it.
#[derive(Debug, Clone)]
struct Fragment {
    stream: Sys,
    /// The base record, as the record holding the fragment names it.
    base: Frn,
    lowest_vcn: u64,
    highest_vcn: i64,
    /// Meaningful in the first fragment only.
    allocated: u64,
    runs: Vec<Run>,
}

/// The runlist of each [`Sys`] stream whose fragments cover it exactly, from VCN 0 to its
/// allocated size, each from a record naming its base as it is in use (`bases`). A stream with a
/// gap, an overlap or a stray fragment is left out (dirty).
fn assemble(mut fragments: Vec<Fragment>, bases: &BTreeMap<u64, u16>, cs: u64) -> BTreeMap<Sys, Vec<Run>> {
    fragments.retain(|f| bases.get(&f.base.record) == Some(&f.base.seq));
    fragments.sort_by_key(|f| (f.stream, f.lowest_vcn));
    let mut out = BTreeMap::new();
    for fs in fragments.chunk_by(|a, b| a.stream == b.stream) {
        let mut next = 0u64;
        let mut runs = Vec::new();
        let mut ok = true;
        for f in fs {
            // `runs` covers `lowest_vcn..=highest_vcn` (checked when parsed).
            ok &= f.lowest_vcn == next && f.highest_vcn + 1 >= f.lowest_vcn as i64;
            if !ok {
                break;
            }
            next = (f.highest_vcn + 1) as u64;
            runs.extend_from_slice(&f.runs);
        }
        if ok && next * cs == fs[0].allocated {
            out.insert(fs[0].stream, runs);
        }
    }
    out
}

fn clusters(runs: &[Run], cs: u64) -> Vec<ByteRange> {
    runs.iter().filter_map(|r| r.lcn().map(|l| ByteRange::new(l * cs, r.len() * cs))).collect()
}

/// The physical pieces of a block of a stream.
type Pieces = Vec<ByteRange>;

/// Read `blocks` (the physical pieces of each, and a tag), close ones together, and hand `f`
/// each one read. A block that cannot be read (damage) is not handed: it is not dated. A
/// source failure or a cancel is an error.
fn read_blocks<T>(
    vol: &NtfsVolume,
    blocks: Vec<(Pieces, T)>,
    mut f: impl FnMut(&[ByteRange], T, &[u8]),
) -> fs_inspect_core::Result<()> {
    let src = &**vol.source();
    let mut alone = Vec::new();
    // Read a block by itself: `false` when it is damaged.
    let read_alone = |pieces: &[ByteRange], buf: &mut Vec<u8>| -> fs_inspect_core::Result<bool> {
        buf.clear();
        for p in pieces {
            let at = buf.len();
            buf.resize(at + p.length as usize, 0);
            match src.read_exact_at(p.offset, &mut buf[at..]) {
                Ok(()) => {}
                Err(e) if e.scope() == Scope::Unit => return Ok(false),
                Err(e) => return Err(e.into()),
            }
        }
        Ok(true)
    };
    let mut slots = Vec::with_capacity(blocks.len());
    let mut items = Vec::new();
    for (pieces, tag) in blocks {
        match pieces[..] {
            [p] => items.push((p.offset, p.length, slots.len())),
            // Fragmented: alone.
            _ => {
                if read_alone(&pieces, &mut alone)? {
                    f(&pieces, tag, &alone);
                }
                continue;
            }
        }
        slots.push(Some((pieces, tag)));
    }
    read_runs::<_, fs_inspect_core::Error>(src, plan(items, BATCH_BYTES, GAP_BYTES), &mut |i, raw| {
        let Some((pieces, tag)) = slots[i].take() else { return Ok(()) };
        match raw {
            Some(raw) => f(&pieces, tag, raw),
            None => {
                if read_alone(&pieces, &mut alone)? {
                    f(&pieces, tag, &alone);
                }
            }
        }
        Ok(())
    })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn frag(base: Frn, lowest_vcn: u64, lcn: u64, len: u64, allocated: u64) -> Fragment {
        Fragment {
            stream: Sys::Sds,
            base,
            lowest_vcn,
            highest_vcn: (lowest_vcn + len) as i64 - 1,
            allocated,
            runs: vec![Run::Mapped { vcn: lowest_vcn, lcn, len }],
        }
    }

    #[test]
    fn system_streams_are_put_together_from_extension_records() {
        let secure = Frn::new(system_records::SECURE, 9);
        let bases = BTreeMap::from([(system_records::SECURE, 9)]);
        let cs = 4096;
        // In the base record and one extension record, in any order.
        let split = vec![frag(secure, 4, 500, 6, 0), frag(secure, 0, 100, 4, 10 * cs)];
        let runs = &assemble(split, &bases, cs)[&Sys::Sds];
        assert_eq!(clusters(runs, cs), vec![ByteRange::new(100 * cs, 4 * cs), ByteRange::new(500 * cs, 6 * cs)]);
        // A gap, an overlap, a missing end, or a fragment naming the record by another sequence
        // number: not dated.
        for bad in [
            vec![frag(secure, 0, 100, 4, 10 * cs), frag(secure, 5, 500, 5, 0)],
            vec![frag(secure, 0, 100, 4, 10 * cs), frag(secure, 3, 500, 7, 0)],
            vec![frag(secure, 0, 100, 4, 10 * cs)],
            vec![frag(secure, 0, 100, 4, 10 * cs), frag(Frn::new(system_records::SECURE, 8), 4, 500, 6, 0)],
        ] {
            assert!(assemble(bad, &bases, cs).is_empty());
        }
        // A base record not seen in use: nothing.
        assert!(assemble(vec![frag(secure, 0, 100, 4, 4 * cs)], &BTreeMap::new(), cs).is_empty());
    }
}
