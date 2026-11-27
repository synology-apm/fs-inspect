//! Volume access: the volume opened, its file records parsed into entries (with their
//! extension records), stream reading. `mft` reads `$MFT` itself, `walk` walks its records,
//! `lookup` reads directories.

mod lookup;
mod mft;
mod walk;

use fs_inspect_core::Scope;
#[cfg(any(test, feature = "change"))]
pub use mft::MFT_CHUNK;
use mft::bootstrap_mft;
pub use mft::{MftChunk, MftLayout, map_stream_bytes};
pub use walk::ChunkFn;

use crate::format::attr::{AttrType, Frn, RawAttrBody, attr_flags};
use crate::format::entry::{FileEntry, Stream, StreamBody, build_entry};
use crate::format::error::{Error, Result};
use crate::format::geometry::Geometry;
use crate::format::lfs::restart::RestartPages;
use crate::format::record::{ParsedRecord, RecordParse, parse_record};
use crate::format::runlist::Run;
use crate::format::upcase::UpCase;
use fs_inspect_core::Diagnostics;
use fs_inspect_core::Limits;
use fs_inspect_io::batch::{self, BATCH_BYTES, GAP_BYTES};
use fs_inspect_io::{BlockSource, DynSource};
use std::collections::HashMap;
use std::sync::OnceLock;

pub mod system_records {
    pub const MFT: u64 = 0;
    pub const MFT_MIRR: u64 = 1;
    pub const LOG_FILE: u64 = 2;
    pub const VOLUME: u64 = 3;
    pub const ATTR_DEF: u64 = 4;
    pub const ROOT: u64 = 5;
    pub const BITMAP: u64 = 6;
    pub const BOOT: u64 = 7;
    pub const BAD_CLUS: u64 = 8;
    pub const SECURE: u64 = 9;
    pub const UPCASE: u64 = 10;
    pub const EXTEND: u64 = 11;
    /// Records `0..FIRST_USER` are reserved for the file system.
    pub const FIRST_USER: u64 = 24;
}

/// An opened NTFS volume: its geometry, where `$MFT` lies, and what is read once and kept
/// (`$UpCase`, the system records, the `$LogFile` restart pages).
#[derive(Debug)]
pub struct NtfsVolume {
    source: DynSource,
    geometry: Geometry,
    mft: MftLayout,
    limits: Limits,
    diag: Diagnostics,
    upcase: OnceLock<UpCase>,
    /// The raw system records (`0..FIRST_USER`), read together once.
    system: OnceLock<Vec<u8>>,
    /// The `$LogFile` restart pages, read once.
    restart: OnceLock<Option<RestartPages>>,
}

impl NtfsVolume {
    pub fn open(source: DynSource) -> Result<Self> {
        Self::open_with(source, Limits::default(), Diagnostics::default())
    }

    /// Open with `limits`, reporting what is worked around to `diag`.
    pub fn open_with(source: DynSource, limits: Limits, diag: Diagnostics) -> Result<Self> {
        let mut boot = vec![0u8; 512];
        if source.size() < boot.len() as u64 {
            return Err(crate::format::error::not_ntfs("source smaller than a boot sector"));
        }
        source.read_exact_at(0, &mut boot)?;
        let geometry = Geometry::parse(&boot)?;
        // Every structure sized from the boot sector (bitmaps of `cluster_count` bits) must be
        // backed by the source: a corrupt `total_sectors` must not drive huge allocations.
        if geometry.cluster_bytes() > source.size() {
            return Err(crate::format::error::bad_geometry(format!(
                "volume of {} clusters x {} bytes exceeds the source ({} bytes)",
                geometry.cluster_count,
                geometry.cluster_size,
                source.size()
            )));
        }
        let mft = bootstrap_mft(&*source, &geometry, &limits, &diag)?;
        Ok(NtfsVolume {
            source,
            geometry,
            mft,
            limits,
            diag,
            upcase: OnceLock::new(),
            system: OnceLock::new(),
            restart: OnceLock::new(),
        })
    }

    /// Where this volume reports what it works around.
    pub fn diagnostics(&self) -> &Diagnostics {
        &self.diag
    }

    pub fn geometry(&self) -> &Geometry {
        &self.geometry
    }

    pub fn mft(&self) -> &MftLayout {
        &self.mft
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    pub fn source(&self) -> &DynSource {
        &self.source
    }

    pub fn record_count(&self) -> u64 {
        self.mft.record_count
    }

    /// The `$LogFile` restart pages ([`crate::format::lfs::restart`]), read the first time.
    pub(crate) fn restart_pages(&self) -> Result<Option<&RestartPages>> {
        if let Some(p) = self.restart.get() {
            return Ok(p.as_ref());
        }
        let p = crate::format::lfs::restart::read_pages(self)?;
        Ok(self.restart.get_or_init(|| p).as_ref())
    }

    pub fn read_parsed(&self, n: u64) -> Result<RecordParse> {
        let mut buf = self.read_record_raw(n)?;
        Ok(parse_record(n, &mut buf, self.geometry.cluster_count, &self.limits))
    }

    fn fetch_extension(&self, n: u64) -> Result<Option<ParsedRecord>> {
        match self.read_parsed(n)? {
            RecordParse::Ok(r) => Ok(Some(r)),
            _ => Ok(None),
        }
    }

    /// The content of the non-resident attribute list of `base` (`None`: it has none, or a
    /// resident one); `Err` inside when it cannot be had (damage). A source failure or a cancel
    /// is an error.
    fn attr_list_data(&self, base: &ParsedRecord) -> Result<Option<std::result::Result<Vec<u8>, String>>> {
        let Some(al) = base.attributes.iter().find(|a| a.kind == AttrType::ATTRIBUTE_LIST) else { return Ok(None) };
        let RawAttrBody::NonResident(nr) = &al.body else { return Ok(None) };
        let runs = match &nr.runs {
            Ok(r) => r,
            Err(e) => return Ok(Some(Err(e.to_string()))),
        };
        if nr.size > self.limits.max_attr_list_bytes {
            return Ok(Some(Err(format!("attribute list size {} exceeds limit", nr.size))));
        }
        let mut out = Vec::new();
        match self.read_runs(NonResident { runs, size: nr.size, initialized: nr.initialized }, 0, nr.size, &mut out) {
            Ok(()) => Ok(Some(Ok(out))),
            Err(e) if e.scope() == Scope::Unit => Ok(Some(Err(e.to_string()))),
            Err(e) => Err(e),
        }
    }

    /// Merged entry for base record `n`. `None` for free, empty, bad or extension records.
    pub fn entry(&self, n: u64) -> Result<Option<FileEntry>> {
        let RecordParse::Ok(rec) = self.read_parsed(n)? else { return Ok(None) };
        if !rec.header.in_use() || rec.header.is_extension() {
            return Ok(None);
        }
        let al = self.attr_list_data(&rec)?;
        self.merge(&rec, al, &mut |x| self.fetch_extension(x))
    }

    /// The entries of records `records`, as [`Self::entry`] builds each: the records read
    /// together in disk order ([`batch::read_runs`]), then the extension records their
    /// attribute lists name, together. A record not read so (past the initialized size, not in
    /// one piece, in a merged read that failed) is read alone. Only a cancel is an error of
    /// them all.
    pub fn entries(&self, records: &[u64]) -> Result<Vec<Result<Option<FileEntry>>>> {
        let rs = u64::from(self.mft.record_size);
        let mut out: Vec<Option<Result<Option<FileEntry>>>> = records.iter().map(|_| None).collect();
        // Bases with extension records: index, record, attribute list, the records it names.
        let mut pending = Vec::new();
        let items = records.iter().enumerate().filter_map(|(i, &n)| Some((self.record_at(n)?, rs, i))).collect();
        batch::read_runs::<_, Error>(&*self.source, batch::plan(items, BATCH_BYTES, GAP_BYTES), &mut |i, b| {
            let Some(b) = b else { return Ok(()) };
            let n = records[i];
            let mut buf = self.cleared(n, b);
            let rec = match parse_record(n, &mut buf, self.geometry.cluster_count, &self.limits) {
                RecordParse::Ok(rec) if rec.header.in_use() && !rec.header.is_extension() => rec,
                _ => {
                    out[i] = Some(Ok(None));
                    return Ok(());
                }
            };
            let al = match self.attr_list_data(&rec) {
                Ok(al) => al,
                Err(e) => {
                    out[i] = Some(kept(Err(e))?);
                    return Ok(());
                }
            };
            let targets = self.attr_list_targets(&rec, al.as_ref());
            if targets.is_empty() {
                out[i] = Some(kept(self.merge(&rec, al, &mut |x| self.fetch_extension(x)))?);
            } else {
                pending.push((i, rec, al, targets));
            }
            Ok(())
        })?;
        let mut wanted: Vec<u64> = pending.iter().flat_map(|p| p.3.iter().copied()).collect();
        wanted.sort_unstable();
        wanted.dedup();
        let items = wanted.into_iter().filter_map(|n| Some((self.record_at(n)?, rs, n))).collect();
        let mut exts: HashMap<u64, Option<ParsedRecord>> = HashMap::new();
        batch::read_runs::<_, Error>(&*self.source, batch::plan(items, BATCH_BYTES, GAP_BYTES), &mut |n, b| {
            if let Some(b) = b {
                let mut buf = self.cleared(n, b);
                let rec = match parse_record(n, &mut buf, self.geometry.cluster_count, &self.limits) {
                    RecordParse::Ok(r) => Some(r),
                    _ => None,
                };
                exts.insert(n, rec);
            }
            Ok(())
        })?;
        for (i, rec, al, _) in pending {
            let e = self.merge(&rec, al, &mut |x| match exts.get(&x) {
                Some(r) => Ok(r.clone()),
                None => self.fetch_extension(x),
            });
            out[i] = Some(kept(e)?);
        }
        records
            .iter()
            .zip(out)
            .map(|(&n, e)| match e {
                Some(e) => Ok(e),
                None => kept(self.entry(n)),
            })
            .collect()
    }

    /// Where record `n` lies on the volume, when it is read there in one piece (not past the
    /// initialized size).
    fn record_at(&self, n: u64) -> Option<u64> {
        let rs = u64::from(self.mft.record_size);
        if n >= self.mft.record_count || n * rs >= self.mft.initialized_size {
            return None;
        }
        match self.mft.map_bytes(n * rs, rs)?.as_slice() {
            [p] => Some(p.offset),
            _ => None,
        }
    }

    /// The records of a chunk [`Self::mft_chunks`] read, `raw` holding records `first..`, each
    /// parsed once (past the initialized size cleared): `None` for one that does not parse.
    pub fn parse_chunk(&self, first: u64, raw: &[u8]) -> Vec<Option<ParsedRecord>> {
        let rs = u64::from(self.mft.record_size);
        let mut buf = Vec::with_capacity(rs as usize);
        raw.chunks_exact(rs as usize)
            .zip(first..)
            .map(|(r, n)| {
                buf.clear();
                buf.extend_from_slice(r);
                let init_end = self.mft.initialized_size.saturating_sub(n * rs).min(rs) as usize;
                buf[init_end..].fill(0);
                match parse_record(n, &mut buf, self.geometry.cluster_count, &self.limits) {
                    RecordParse::Ok(rec) => Some(rec),
                    _ => None,
                }
            })
            .collect()
    }

    /// Raw record `n` as [`Self::mft_chunks`] read it, past the initialized size cleared.
    fn cleared(&self, n: u64, raw: &[u8]) -> Vec<u8> {
        let rs = u64::from(self.mft.record_size);
        let mut buf = raw.to_vec();
        let init_end = self.mft.initialized_size.saturating_sub(n * rs).min(rs) as usize;
        buf[init_end..].fill(0);
        buf
    }

    /// The entry of base record `rec` (in use), with the content of its non-resident
    /// attribute list (`al`, [`Self::attr_list_data`]), its extension records fetched by
    /// `fetch`. An extension record or attribute list that cannot be read (damage) is left out
    /// of the entry (which says so); a source failure or a cancel is an error.
    fn merge(
        &self,
        rec: &ParsedRecord,
        al: Option<std::result::Result<Vec<u8>, String>>,
        fetch: &mut dyn FnMut(u64) -> Result<Option<ParsedRecord>>,
    ) -> Result<Option<FileEntry>> {
        let mut fatal = None;
        let e = build_entry(
            rec,
            al,
            &mut |x| match fetch(x) {
                Ok(r) => r,
                Err(e) if e.scope() == Scope::Unit => None,
                Err(e) => {
                    fatal.get_or_insert(e);
                    None
                }
            },
            &self.limits,
        );
        match fatal {
            Some(e) => Err(e),
            None => Ok(Some(e)),
        }
    }

    /// Entry by FRN; `None` if the sequence number does not match.
    pub fn entry_frn(&self, frn: Frn) -> Result<Option<FileEntry>> {
        Ok(self.entry(frn.record)?.filter(|e| e.frn.seq == frn.seq))
    }

    /// Read part of a stream (resident or non-resident).
    pub fn read_stream(&self, stream: &Stream, offset: u64, len: u64) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.read_stream_into(stream, offset, len, &mut out)?;
        Ok(out)
    }

    /// Read `[offset, offset + len)` of a stream (cut at its size) into `out`, replacing its
    /// content and reusing its allocation. Bytes at or beyond the initialized size read as
    /// zeros, as do sparse runs.
    pub fn read_stream_into(&self, stream: &Stream, offset: u64, len: u64, out: &mut Vec<u8>) -> Result<()> {
        out.clear();
        match &stream.body {
            StreamBody::Resident { data } => {
                let s = (offset.min(data.len() as u64)) as usize;
                let e = (offset.saturating_add(len).min(data.len() as u64)) as usize;
                out.extend_from_slice(&data[s..e]);
                Ok(())
            }
            StreamBody::NonResident { size, initialized, compression_unit, runs, .. } => {
                if *compression_unit != 0 && stream.flags & attr_flags::COMPRESSED != 0 {
                    return Err(Error::unsupported("reading compressed stream data"));
                }
                self.read_runs(NonResident { runs, size: *size, initialized: *initialized }, offset, len, out)
            }
        }
    }

    /// Read `[offset, offset+len)` of non-resident stream `s` into `out` (empty on entry).
    fn read_runs(&self, s: NonResident<'_>, offset: u64, len: u64, out: &mut Vec<u8>) -> Result<()> {
        let NonResident { runs, size, initialized } = s;
        let end = offset.saturating_add(len).min(size);
        if offset >= end {
            return Ok(());
        }
        if end - offset > self.limits.max_alloc {
            return Err(Error::limit(format!("ntfs stream read of {} bytes", end - offset)));
        }
        out.resize((end - offset) as usize, 0);
        let cs = self.geometry.cluster_size as u64;
        let readable_end = end.min(initialized);
        // Only the runs overlapping the request: the first one ending past `offset`, on.
        let first = runs.partition_point(|r| r.end_vcn().saturating_mul(cs) <= offset);
        for r in &runs[first..] {
            let (rs, re) = (r.vcn() * cs, r.end_vcn() * cs);
            if rs >= readable_end {
                break;
            }
            let s = offset.max(rs);
            let e = readable_end.min(re);
            if s >= e {
                continue;
            }
            if let Some(lcn) = r.lcn() {
                let dst = &mut out[(s - offset) as usize..(e - offset) as usize];
                self.source.read_exact_at(lcn * cs + (s - rs), dst)?;
            }
        }
        Ok(())
    }

    pub fn read_stream_all(&self, stream: &Stream) -> Result<Vec<u8>> {
        self.read_stream(stream, 0, stream.size())
    }
}

/// The entry of one record of [`NtfsVolume::entries`]; a cancel is the error of all.
fn kept(e: Result<Option<FileEntry>>) -> Result<Result<Option<FileEntry>>> {
    match e {
        Err(e) if e.is_cancelled() => Err(e),
        e => Ok(e),
    }
}

/// A non-resident stream: its runs (sorted by VCN), size and initialized size.
#[derive(Debug, Clone, Copy)]
struct NonResident<'a> {
    runs: &'a [Run],
    size: u64,
    initialized: u64,
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::format::geometry::{BootSpec, encode_boot_sector};
    use fs_inspect_io::MemSource;

    /// A boot sector claiming 2^36 sectors on an 8 MiB source must be
    /// rejected, not allocate a 4 GiB bitmap.
    #[test]
    fn total_sectors_beyond_source_is_rejected() {
        let mut img = vec![0u8; 8 << 20];
        img[..512].copy_from_slice(&encode_boot_sector(&BootSpec {
            bytes_per_sector: 512,
            sectors_per_cluster_raw: 8,
            total_sectors: 1 << 36,
            mft_lcn: 4,
            mftmirr_lcn: 8,
            clusters_per_record_raw: -10,
            clusters_per_index_raw: 1,
            serial: 7,
        }));
        let r = NtfsVolume::open(std::sync::Arc::new(MemSource::new(img)));
        assert!(matches!(&r, Err(e) if e.to_string().contains("invalid NTFS geometry")), "{:?}", r.err());
    }

    /// An `$MFT` data size far past its allocated size must not make walks
    /// visit 2^40 records.
    #[test]
    fn mft_data_size_is_capped_by_its_allocation() {
        use crate::synth::{SyntheticVolume, VolumeSpec};
        let synth = SyntheticVolume::format(VolumeSpec { clusters: 4096, ..Default::default() });
        let base = synth.open();
        let mut bad = synth.source().data().to_vec();
        let rs = base.mft.record_size as usize;
        let at = (base.geometry.mft_lcn * u64::from(base.geometry.cluster_size)) as usize;
        let rec = &mut bad[at..at + rs];
        // The unnamed $DATA attribute of record 0: patch its data size (offset 0x30 of a
        // non-resident attribute header).
        let mut off = usize::from(u16::from_le_bytes([rec[0x14], rec[0x15]]));
        loop {
            let ty = u32::from_le_bytes(rec[off..off + 4].try_into().unwrap());
            let len = u32::from_le_bytes(rec[off + 4..off + 8].try_into().unwrap()) as usize;
            if ty == AttrType::DATA.0 {
                rec[off + 0x30..off + 0x38].copy_from_slice(&(1u64 << 50).to_le_bytes());
                break;
            }
            off += len;
        }
        let v = NtfsVolume::open(std::sync::Arc::new(MemSource::new(bad))).unwrap();
        assert_eq!(v.record_count(), base.record_count());
    }

    use fs_inspect_io::test_util::{CountingSource, FaultySource};

    /// The entries of a walk over the chunks of `vol` from the first user record, in record
    /// order: each record handed once.
    fn walk(vol: &NtfsVolume) -> Vec<(u64, Result<Option<FileEntry>>)> {
        walk_with(vol, walk::Caps::DEFAULT)
    }

    fn walk_with(vol: &NtfsVolume, caps: walk::Caps) -> Vec<(u64, Result<Option<FileEntry>>)> {
        let mut out = Vec::new();
        vol.walk_entries_with(caps, system_records::FIRST_USER, &mut |_, _, _| {}, &mut |n, e| {
            out.push((n, e));
            Ok(())
        })
        .unwrap();
        out.sort_by_key(|e| e.0);
        let all: Vec<u64> = out.iter().map(|e| e.0).collect();
        assert_eq!(all, (system_records::FIRST_USER..vol.record_count()).collect::<Vec<_>>());
        out
    }

    /// A walk over the chunks sees the same entries as record by record, in a read per run of
    /// `$MFT` (the chunks of a batch read together).
    #[test]
    fn a_walk_reads_the_mft_in_large_pieces() {
        use crate::synth::{Placement, SyntheticVolume, VolumeSpec};
        let mut synth = SyntheticVolume::format(VolumeSpec { clusters: 16384, ..Default::default() });
        for i in 0..300 {
            synth.create_file(system_records::ROOT, &format!("f{i}"), 2000 + i * 7, i, Placement::FirstFit);
        }
        let open = || {
            let src = CountingSource::new(std::sync::Arc::new(synth.source()));
            (NtfsVolume::open(src.clone()).unwrap(), src)
        };
        let (single, single_src) = open();
        let (batched, batched_src) = open();
        let before = (single_src.stats(), batched_src.stats());
        let entries = walk(&batched);
        for (n, e) in entries {
            assert_eq!(e.unwrap(), single.entry(n).unwrap(), "record {n}");
        }
        let (one, many) = (single_src.stats().since(&before.0).reads, batched_src.stats().since(&before.1).reads);
        assert!(one >= 300, "{one} reads record by record");
        // One read per run of $MFT (the synthetic one grows in pieces): not one per chunk, nor
        // more where a chunk crosses a run.
        let runs = batched.mft.runs.len() as u64;
        assert!(runs > 1 && many <= runs, "{many} reads in batches, {runs} runs");
    }

    /// A damaged record is read over three times: by its batch, its chunk alone and itself
    /// alone. Every other record of the walk reads as on a clean volume.
    #[test]
    fn a_damaged_record_fails_one_batch() {
        use crate::synth::{Placement, SyntheticVolume, VolumeSpec};
        let mut synth = SyntheticVolume::format(VolumeSpec { clusters: 16384, ..Default::default() });
        for i in 0..300 {
            synth.create_file(system_records::ROOT, &format!("f{i}"), 0, i, Placement::FirstFit);
        }
        let clean = NtfsVolume::open(std::sync::Arc::new(synth.source())).unwrap();
        let rs = u64::from(clean.mft.record_size);
        let bad = 100;
        let at = clean.mft.map_bytes(bad * rs, rs).unwrap()[0].offset + 8;
        let src = std::sync::Arc::new(FaultySource::new(std::sync::Arc::new(synth.source()), at..at + 1));
        let vol = NtfsVolume::open(src.clone()).unwrap();
        let hits = src.hits();
        for (n, got) in walk(&vol) {
            if n == bad {
                assert!(got.is_err());
            } else {
                assert_eq!(got.unwrap(), clean.entry(n).unwrap(), "record {n}");
            }
        }
        let hits = src.hits() - hits;
        assert_eq!(hits, 3, "reads over the damage");
    }

    /// Extension records chunks away from their bases, before and after them, come from the
    /// walk's own read of `$MFT`: no read of their own. Kept nowhere (no room), they are read
    /// with the records that follow them, those allocated together in one read, and the
    /// entries are the same.
    #[test]
    fn extension_records_come_from_the_walk() {
        use crate::synth::{Placement, SyntheticVolume, VolumeSpec};
        let mut synth = SyntheticVolume::format(VolumeSpec { clusters: 16384, ..Default::default() });
        // Named streams spill the first files into extension records after the last file, and
        // (once files near the start are deleted) the last files into records near the start.
        let ads = |synth: &mut SyntheticVolume, f: u64, i: usize| {
            for j in 0..8 {
                synth.add_ads(f, &format!("s{j}"), 300, (i * 8 + j) as u64);
            }
        };
        // One image for the files and the first ones' streams, one for the deletes (records
        // are given out when the image is made: the slots freed must not be free before then).
        let files: Vec<u64> = synth.batch(|synth| {
            let files: Vec<u64> = (0..1100)
                .map(|i| synth.create_file(system_records::ROOT, &format!("f{i}"), 0, i, Placement::FirstFit))
                .collect();
            for (i, &f) in files[..10].iter().enumerate() {
                ads(synth, f, i);
            }
            files
        });
        synth.batch(|synth| {
            for &f in &files[20..40] {
                synth.delete(f);
            }
        });
        for (i, &f) in files[1090..].iter().enumerate() {
            ads(&mut synth, f, 10 + i);
        }
        let open = || {
            let src = CountingSource::new(std::sync::Arc::new(synth.source()));
            (NtfsVolume::open(src.clone()).unwrap(), src)
        };
        let (single, _) = open();
        let rs = u64::from(single.mft.record_size);
        let per = single.mft_chunk() / rs;
        let (mut ahead, mut behind) = (0, 0);
        for n in system_records::FIRST_USER..single.record_count() {
            if let Ok(RecordParse::Ok(r)) = single.read_parsed(n)
                && r.header.in_use()
                && r.header.is_extension()
            {
                let base = r.header.base_record.record;
                assert_ne!(n / per, base / per, "record {n}, base {base}");
                if n > base { ahead += 1 } else { behind += 1 }
            }
        }
        assert!(ahead >= 10 && behind >= 10, "{ahead} extension records ahead, {behind} behind");
        // What reading $MFT alone takes.
        let (vol, src) = open();
        let before = src.stats();
        vol.mft_chunks(&mut |_, _| Ok(())).unwrap();
        let mft = src.stats().since(&before).reads;
        let none = walk::Caps { bytes: 0 };
        for caps in [walk::Caps::DEFAULT, none] {
            let (vol, src) = open();
            let before = src.stats();
            for (n, e) in walk_with(&vol, caps) {
                assert_eq!(e.unwrap(), single.entry(n).unwrap(), "record {n}");
            }
            let reads = src.stats().since(&before).reads - mft;
            match caps.bytes {
                // Fewer reads than records (a window can take a few reads: `$MFT` grows in
                // pieces).
                0 => assert!(
                    reads > 0 && reads * 4 < ahead + behind,
                    "{reads} reads of {ahead} + {behind} extension records"
                ),
                _ => assert_eq!(reads, 0),
            }
        }
    }

    /// An extension record that cannot be read (damage) is left out of its file's entry, which
    /// says so; a source failure reading it is an error.
    #[test]
    fn an_unreadable_extension_record() {
        use crate::synth::{Placement, SyntheticVolume, VolumeSpec};
        use fs_inspect_io::test_util::Fault;
        let mut synth = SyntheticVolume::format(VolumeSpec { clusters: 16384, ..Default::default() });
        let f = synth.create_file(system_records::ROOT, "f", 0, 0, Placement::FirstFit);
        for j in 0..8 {
            synth.add_ads(f, &format!("s{j}"), 300, j);
        }
        let clean = NtfsVolume::open(std::sync::Arc::new(synth.source())).unwrap();
        let rs = u64::from(clean.mft.record_size);
        let ext = (f + 1..clean.record_count())
            .find(|&n| matches!(clean.read_parsed(n), Ok(RecordParse::Ok(r)) if r.header.is_extension()))
            .unwrap();
        assert!(!clean.entry(f).unwrap().unwrap().has_problem());
        let at = clean.mft.map_bytes(ext * rs, rs).unwrap()[0].offset + 8;
        let open = |fault| {
            let src = FaultySource::with_fault(std::sync::Arc::new(synth.source()), at..at + 1, fault);
            NtfsVolume::open(std::sync::Arc::new(src)).unwrap()
        };
        assert!(open(Fault::Damage).entry(f).unwrap().unwrap().has_problem());
        for fault in [Fault::Device, Fault::Cancel] {
            let e = open(fault).entry(f).unwrap_err();
            assert!(e.scope() != Scope::Unit, "{fault:?}: {e}");
        }
    }
}
