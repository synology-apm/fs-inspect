//! `$MFT`: where `$MFT:$DATA` lies (bootstrapped from record 0), and its records read raw,
//! one by one, the system records together, or a chunk at a time for a walk.

use super::{NtfsVolume, system_records};
use crate::format::attr::{AttrListEntry, AttrType, Frn, RawAttrBody, parse_attr_list};
use crate::format::error::{Error, Result};
use crate::format::geometry::Geometry;
use crate::format::record::{RecordParse, parse_record};
use crate::format::runlist::{self, Run};
use fs_inspect_core::Scope;
use fs_inspect_core::{ByteRange, Limits};
use fs_inspect_core::{DiagCode, Diagnostics};
use fs_inspect_io::BlockSource;
use fs_inspect_io::batch::{self, BATCH_BYTES, GAP_BYTES};
use std::collections::BTreeMap;

/// Location of `$MFT:$DATA`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MftLayout {
    pub runs: Vec<Run>,
    pub data_size: u64,
    pub initialized_size: u64,
    pub allocated_size: u64,
    pub record_size: u32,
    pub record_count: u64,
    pub cluster_size: u32,
}

impl MftLayout {
    /// Physical pieces `(offset, len)` holding logical bytes `[logical, logical+len)` of
    /// `$MFT:$DATA`; `None` if any part is unmapped.
    pub fn map_bytes(&self, logical: u64, len: u64) -> Option<Vec<ByteRange>> {
        map_stream_bytes(&self.runs, self.cluster_size, logical, len)
    }

    /// Clusters `(lcn, len)` holding record `n`.
    pub fn record_clusters(&self, n: u64) -> Vec<(u64, u64)> {
        let cs = self.cluster_size as u64;
        let start = n * self.record_size as u64;
        let first_vcn = start / cs;
        let last_vcn = (start + self.record_size as u64 - 1) / cs;
        runlist::map_vcn_range(&self.runs, first_vcn, last_vcn - first_vcn + 1)
    }
}

/// Bytes of `$MFT:$DATA` read at a time by [`NtfsVolume::mft_chunks`] (at least one record).
pub const MFT_CHUNK: u64 = 64 << 10;

/// A chunk of `$MFT:$DATA` as read: where it lies and its bytes.
pub type MftChunk<'a> = (&'a [ByteRange], &'a [u8]);

/// Piece `k` of `n` of a chunk of [`NtfsVolume::mft_chunks`] (`n` 0: the chunk is not mapped).
struct Piece {
    chunk: u64,
    k: usize,
    n: usize,
    range: ByteRange,
}

/// Map logical bytes of a non-resident stream to physical byte ranges.
pub fn map_stream_bytes(runs: &[Run], cluster_size: u32, logical: u64, len: u64) -> Option<Vec<ByteRange>> {
    let cs = cluster_size as u64;
    let mut out = Vec::new();
    let mut pos = logical;
    let end = logical.checked_add(len)?;
    let mut idx = runs.partition_point(|r| r.end_vcn() * cs <= pos);
    while pos < end {
        let r = runs.get(idx)?;
        let rs = r.vcn() * cs;
        let re = r.end_vcn() * cs;
        if pos < rs {
            return None;
        }
        let lcn = r.lcn()?;
        let n = re.min(end) - pos;
        out.push(ByteRange::new(lcn * cs + (pos - rs), n));
        pos += n;
        idx += 1;
    }
    Some(out)
}

impl NtfsVolume {
    /// The size of the chunks [`Self::mft_chunks`] reads.
    pub fn mft_chunk(&self) -> u64 {
        MFT_CHUNK.max(u64::from(self.mft.record_size))
    }

    /// Read `$MFT:$DATA` in [`Self::mft_chunk`] bytes at a time, straight from the volume:
    /// `f(index, chunk)`, the chunk `None` when it is not mapped or cannot be read (damage).
    /// Raw bytes: fixups not applied, nothing past the initialized size cleared. The chunks'
    /// pieces on the volume are read together in disk runs ([`batch::read_runs`], ahead of
    /// `f`); a chunk not read whole is read alone, so damage is that of the chunk it is in.
    pub fn mft_chunks(&self, f: &mut dyn FnMut(u64, Option<MftChunk<'_>>) -> Result<()>) -> Result<()> {
        let chunk = self.mft_chunk();
        let total = self.mft.record_count * u64::from(self.mft.record_size);
        let count = total.div_ceil(chunk);
        // Each chunk's pieces in order; a chunk not mapped is an empty item where the reading
        // is, so it is handed in its place.
        let mut at = 0u64;
        let items = (0..count).flat_map(move |i| {
            let len = ((i + 1) * chunk).min(total) - i * chunk;
            let pieces = self.mft.map_bytes(i * chunk, len);
            let n = pieces.as_ref().map_or(0, Vec::len);
            let items: Vec<(u64, u64, Piece)> = match pieces {
                None => vec![(at, 0, Piece { chunk: i, k: 0, n: 0, range: ByteRange::new(at, 0) })],
                Some(p) => p
                    .into_iter()
                    .enumerate()
                    .map(|(k, r)| (r.offset, r.length, Piece { chunk: i, k, n, range: r }))
                    .collect(),
            };
            if let Some(last) = items.last() {
                at = last.0 + last.1;
            }
            items
        });
        let (mut pieces, mut asm, mut whole) = (Vec::new(), Vec::new(), true);
        let mut each = |p: Piece, b: Option<&[u8]>| -> Result<()> {
            if p.n == 0 {
                return f(p.chunk, None);
            }
            if p.n == 1
                && let Some(b) = b
            {
                return f(p.chunk, Some((&[p.range], b)));
            }
            if p.k == 0 {
                (whole, pieces, asm) = (true, Vec::new(), Vec::new());
            }
            pieces.push(p.range);
            match b {
                Some(b) if whole => asm.extend_from_slice(b),
                _ => whole = false,
            }
            if p.k + 1 < p.n {
                return Ok(());
            }
            if !whole {
                asm.resize(pieces.iter().map(|r| r.length as usize).sum(), 0);
                match self.read_all(&pieces, &mut asm) {
                    Ok(()) => {}
                    Err(e) if e.scope() == Scope::Unit => return f(p.chunk, None),
                    Err(e) => return Err(e),
                }
            }
            f(p.chunk, Some((&pieces, &asm)))
        };
        batch::read_runs(&*self.source, batch::runs(items, BATCH_BYTES, GAP_BYTES), &mut each)
    }

    /// Read `pieces` (of the volume) into `buf` one after the other.
    fn read_all(&self, pieces: &[ByteRange], buf: &mut [u8]) -> Result<()> {
        let mut at = 0usize;
        for p in pieces {
            self.source.read_exact_at(p.offset, &mut buf[at..at + p.length as usize])?;
            at += p.length as usize;
        }
        Ok(())
    }

    /// Raw bytes of record `n` (fixups not applied). Records beyond the initialized size
    /// read as zeros.
    pub fn read_record_raw(&self, n: u64) -> Result<Vec<u8>> {
        let rs = self.mft.record_size as u64;
        if n >= self.mft.record_count {
            return Err(Error::not_found(format!("record {n} beyond MFT ({} records)", self.mft.record_count)));
        }
        let mut buf = vec![0u8; rs as usize];
        let logical = n * rs;
        if logical >= self.mft.initialized_size {
            return Ok(buf);
        }
        if let Some(sys) = self.system_records()? {
            let at = (n * rs) as usize;
            if let Some(r) = sys.get(at..at + rs as usize) {
                return Ok(self.cleared(n, r));
            }
        }
        let pieces = self
            .mft
            .map_bytes(logical, rs)
            .ok_or_else(|| Error::corrupt(format!("record {n} is not mapped by $MFT runlist")))?;
        self.read_all(&pieces, &mut buf)?;
        Ok(self.cleared(n, &buf))
    }

    /// The raw system records (`0..FIRST_USER`, those up to the initialized size), read in one
    /// go the first time; `None` when they cannot be (they are then read one by one).
    fn system_records(&self) -> Result<Option<&[u8]>> {
        if let Some(s) = self.system.get() {
            return Ok(Some(s));
        }
        let rs = u64::from(self.mft.record_size);
        let len = (system_records::FIRST_USER.min(self.mft.record_count) * rs).min(self.mft.initialized_size / rs * rs);
        let Some(pieces) = self.mft.map_bytes(0, len) else { return Ok(None) };
        let mut buf = vec![0u8; len as usize];
        if batch::read_pieces(&*self.source, &pieces, &mut buf)? < len {
            return Ok(None);
        }
        Ok(Some(self.system.get_or_init(|| buf)))
    }
}

/// Locate `$MFT:$DATA`, following record 0's attribute list if present.
pub(super) fn bootstrap_mft(
    src: &dyn BlockSource,
    g: &Geometry,
    limits: &Limits,
    diag: &Diagnostics,
) -> Result<MftLayout> {
    let rs = g.record_size as u64;
    let mut buf = vec![0u8; rs as usize];
    src.read_exact_at(g.mft_lcn * g.cluster_size as u64, &mut buf)?;
    let rec0 = match parse_record(0, &mut buf, g.cluster_count, limits) {
        RecordParse::Ok(r) if r.header.in_use() => r,
        RecordParse::Ok(_) => return Err(bad("record 0 is not in use")),
        RecordParse::Empty => return Err(bad("record 0 is empty")),
        RecordParse::Bad { reason } => return Err(bad(format!("record 0: {reason}"))),
    };
    let first = rec0
        .attributes
        .iter()
        .find(|a| a.kind == AttrType::DATA && a.name.is_empty() && a.lowest_vcn() == 0)
        .and_then(|a| a.non_resident().cloned())
        .ok_or_else(|| bad("record 0 has no non-resident $DATA starting at VCN 0"))?;
    let first_runs = first.runs.clone().map_err(|e| bad(format!("$MFT runlist: {e}")))?;
    let mut layout = MftLayout {
        runs: first_runs.clone(),
        data_size: first.size,
        initialized_size: first.initialized,
        allocated_size: first.allocated,
        record_size: g.record_size,
        record_count: first.size / rs,
        cluster_size: g.cluster_size,
    };
    if first.size % rs != 0 {
        diag.warn(
            DiagCode::Inconsistent,
            format!("$MFT data size {} is not a multiple of the record size", first.size),
        );
    }
    if let Some(al) = rec0.attributes.iter().find(|a| a.kind == AttrType::ATTRIBUTE_LIST) {
        let data = attribute_list_bytes(src, g, limits, &al.body)?;
        let entries = parse_attr_list(&data, limits.max_attr_list_entries)
            .map_err(|e| bad(format!("$MFT attribute list: {e}")))?;
        let todo = entries
            .into_iter()
            .filter(|e| e.kind == AttrType::DATA && e.name.is_empty() && e.segment.record != 0)
            .collect();
        let mut fragments = Fragments { src, g, limits, base: rec0.frn(), by_vcn: BTreeMap::from([(0, first_runs)]) };
        layout.runs = fragments.assemble(todo)?;
    }
    check_runs(&mut layout, g, diag)?;
    Ok(layout)
}

fn bad(msg: impl std::fmt::Display) -> Error {
    crate::format::error::mft_bootstrap(msg)
}

/// Bytes of `$MFT` mapped by `pieces`, read into `out` one after the other.
fn read_mapped(src: &dyn BlockSource, pieces: &[ByteRange], out: &mut [u8]) -> Result<()> {
    let mut pos = 0usize;
    for p in pieces {
        src.read_exact_at(p.offset, &mut out[pos..pos + p.length as usize])?;
        pos += p.length as usize;
    }
    Ok(())
}

/// The bytes of record 0's attribute list (`body`).
fn attribute_list_bytes(src: &dyn BlockSource, g: &Geometry, limits: &Limits, body: &RawAttrBody) -> Result<Vec<u8>> {
    match body {
        RawAttrBody::Resident { data, .. } => Ok(data.clone()),
        RawAttrBody::NonResident(nr) => {
            let runs = nr.runs.clone().map_err(|e| bad(format!("$MFT attribute list: {e}")))?;
            if nr.size > limits.max_attr_list_bytes {
                return Err(bad("$MFT attribute list too large"));
            }
            let mut out = vec![0u8; nr.size as usize];
            let pieces = map_stream_bytes(&runs, g.cluster_size, 0, nr.initialized.min(nr.size))
                .ok_or_else(|| bad("$MFT attribute list not mapped"))?;
            read_mapped(src, &pieces, &mut out)?;
            Ok(out)
        }
    }
}

/// The `$MFT:$DATA` runlist being assembled from the fragments in extension records.
struct Fragments<'a> {
    src: &'a dyn BlockSource,
    g: &'a Geometry,
    limits: &'a Limits,
    /// Record 0, which every extension record names as its base.
    base: Frn,
    /// Each fragment's runs, by its first VCN.
    by_vcn: BTreeMap<u64, Vec<Run>>,
}

impl Fragments<'_> {
    /// Read the fragments listed in `todo`, in rounds: an extension record may lie in a part
    /// of `$MFT` only another fragment maps. The runlist of every fragment.
    fn assemble(&mut self, mut todo: Vec<AttrListEntry>) -> Result<Vec<Run>> {
        let mut runs = self.runs();
        for _round in 0..16 {
            if todo.is_empty() {
                break;
            }
            let before = todo.len();
            let mut remaining = Vec::new();
            for e in todo {
                if !self.read(&e, &runs)? {
                    remaining.push(e);
                }
            }
            runs = self.runs();
            todo = remaining;
            if todo.len() == before {
                break;
            }
        }
        if !todo.is_empty() {
            return Err(bad(format!("{} $MFT fragments could not be located", todo.len())));
        }
        Ok(runs)
    }

    fn runs(&self) -> Vec<Run> {
        self.by_vcn.values().flatten().copied().collect()
    }

    /// The fragment `e` names, through `runs` (the runlist so far); `false` when its record
    /// is not mapped yet.
    fn read(&mut self, e: &AttrListEntry, runs: &[Run]) -> Result<bool> {
        let (g, rs) = (self.g, self.g.record_size as u64);
        let record = e.segment.record;
        let Some(pieces) = map_stream_bytes(runs, g.cluster_size, record * rs, rs) else { return Ok(false) };
        let mut b = vec![0u8; rs as usize];
        read_mapped(self.src, &pieces, &mut b)?;
        let RecordParse::Ok(r) = parse_record(record, &mut b, g.cluster_count, self.limits) else {
            return Err(bad(format!("$MFT extension record {record} unreadable")));
        };
        if r.header.base_record != self.base || r.header.seq != e.segment.seq {
            return Err(bad(format!("$MFT extension record {record} does not belong to $MFT")));
        }
        let a = r
            .find(AttrType::DATA, e.attr_id)
            .and_then(|a| a.non_resident().cloned())
            .ok_or_else(|| bad(format!("$MFT fragment missing in record {record}")))?;
        let runs = a.runs.map_err(|err| bad(format!("$MFT fragment runlist: {err}")))?;
        self.by_vcn.insert(a.lowest_vcn, runs);
        Ok(true)
    }
}

/// The assembled runlist must be continuous from VCN 0 and cover the data; the record count
/// is capped to what is allocated, mapped and fits on the volume (a larger data size would
/// have walks visit records that cannot exist).
fn check_runs(layout: &mut MftLayout, g: &Geometry, diag: &Diagnostics) -> Result<()> {
    let cs = g.cluster_size as u64;
    let mut vcn = 0;
    for r in &layout.runs {
        if r.vcn() != vcn {
            return Err(bad(format!("$MFT runlist gap at VCN {vcn}")));
        }
        vcn = r.end_vcn();
    }
    if vcn * cs < layout.data_size.min(layout.allocated_size) {
        return Err(bad(format!("$MFT runlist covers {} bytes, data size {}", vcn * cs, layout.data_size)));
    }
    let cap = layout.allocated_size.min(vcn * cs).min(g.cluster_count.saturating_mul(cs)) / g.record_size as u64;
    if layout.record_count > cap {
        diag.warn(
            DiagCode::Inconsistent,
            format!("$MFT data size {} exceeds its allocation; using {cap} records", layout.data_size),
        );
        layout.record_count = cap;
    }
    Ok(())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::synth::{Placement, ROOT, SyntheticVolume, VolumeSpec};
    use fs_inspect_io::MemSource;
    use std::sync::Arc;

    /// A volume whose `$MFT` grew one scattered cluster at a time, until its runlist no longer
    /// fits record 0: record 0 holds an attribute list naming the extension records that hold
    /// the rest of `$MFT:$DATA`.
    fn fragmented() -> SyntheticVolume {
        let mut synth = SyntheticVolume::format(VolumeSpec {
            cluster_size: 1024,
            record_size: 1024,
            clusters: 16384,
            initial_mft_records: 16,
            mft_grow_records: 1,
            mft_grow_placement: Placement::Scattered,
            ..Default::default()
        });
        synth.batch(|s| {
            for i in 0..300 {
                s.create_file(ROOT, &format!("f{i}"), 0, i, Placement::FirstFit);
            }
        });
        assert!(!synth.file(0).extensions.is_empty(), "the test needs $MFT in extension records");
        synth
    }

    /// Where record `n` of `vol`'s `$MFT` lies in the image.
    fn record_at(vol: &NtfsVolume, n: u64) -> usize {
        let rs = u64::from(vol.mft.record_size);
        let pieces = vol.mft.map_bytes(n * rs, rs).unwrap();
        assert_eq!(pieces.len(), 1);
        pieces[0].offset as usize
    }

    #[test]
    fn a_fragmented_mft_is_assembled_from_its_attribute_list() {
        let synth = fragmented();
        let vol = synth.open();
        let expected = runlist::normalize(synth.file(0).data().unwrap().runs());
        assert_eq!(runlist::normalize(&vol.mft.runs), expected, "the runlist of every fragment, in VCN order");
        assert!(vol.mft.runs.len() > 100, "{} runs", vol.mft.runs.len());
        // Every file, including those in the clusters only the extension records map, reads.
        for f in synth.user_files() {
            match vol.read_parsed(f).unwrap() {
                RecordParse::Ok(r) => assert!(r.header.in_use(), "record {f}"),
                other => panic!("record {f}: {other:?}"),
            }
        }
        // A record's clusters are where its bytes are.
        let last = vol.record_count() - 1;
        let cs = u64::from(vol.mft.cluster_size);
        let clusters = vol.mft.record_clusters(last);
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].0 * cs, record_at(&vol, last) as u64);
    }

    /// An extension record of `$MFT` whose base is another record, or that does not parse,
    /// fails the open: `$MFT` cannot be located.
    #[test]
    fn a_damaged_mft_extension_record_fails_the_open() {
        let synth = fragmented();
        let vol = synth.open();
        let ext = synth.file(0).extensions[0];
        let at = record_at(&vol, ext);
        let open = |img: Vec<u8>| NtfsVolume::open(Arc::new(MemSource::new(img))).map(|_| ()).unwrap_err().to_string();

        let mut other_base = synth.image.clone();
        // The base record reference (offset 0x20): record 5, not $MFT.
        other_base[at + 0x20..at + 0x28].copy_from_slice(&5u64.to_le_bytes());
        let e = open(other_base);
        assert!(e.contains(&format!("$MFT extension record {ext} does not belong to $MFT")), "{e}");

        let mut unreadable = synth.image.clone();
        unreadable[at..at + 4].copy_from_slice(b"BAAD");
        let e = open(unreadable);
        assert!(e.contains(&format!("$MFT extension record {ext} unreadable")), "{e}");
    }

    #[test]
    fn stream_bytes_map_across_runs_and_not_past_them() {
        let runs = [
            Run::Mapped { vcn: 0, lcn: 10, len: 2 },
            Run::Sparse { vcn: 2, len: 1 },
            Run::Mapped { vcn: 3, lcn: 50, len: 1 },
        ];
        // From the middle of the first run into the second cluster.
        assert_eq!(map_stream_bytes(&runs, 512, 100, 600), Some(vec![ByteRange::new(5220, 600)]));
        // A sparse run has no place on the volume.
        assert_eq!(map_stream_bytes(&runs, 512, 900, 400), None);
        assert_eq!(map_stream_bytes(&runs, 512, 1536, 512), Some(vec![ByteRange::new(50 * 512, 512)]));
        // Past the last run, and a length that overflows.
        assert_eq!(map_stream_bytes(&runs, 512, 2000, 100), None);
        assert_eq!(map_stream_bytes(&runs, 512, 1, u64::MAX), None);
        assert_eq!(map_stream_bytes(&runs, 512, 0, 0), Some(Vec::new()));
    }

    /// The offset in record `rec` of its first attribute of type `ty`.
    fn attr_at(rec: &[u8], ty: AttrType) -> usize {
        let mut off = usize::from(u16::from_le_bytes([rec[0x14], rec[0x15]]));
        loop {
            let t = u32::from_le_bytes(rec[off..off + 4].try_into().unwrap());
            assert_ne!(t, u32::MAX, "no attribute {ty:?}");
            if t == ty.0 {
                return off;
            }
            off += u32::from_le_bytes(rec[off + 4..off + 8].try_into().unwrap()) as usize;
        }
    }

    /// Record 0 not in use, its data size not a whole number of records, its data past what
    /// its runlist maps: the first fails the open, the second is said, the third fails.
    #[test]
    fn record_0_must_describe_the_mft() {
        let synth = SyntheticVolume::format(VolumeSpec { clusters: 4096, ..Default::default() });
        let vol = synth.open();
        let rs = vol.mft.record_size as usize;
        let at = (vol.geometry.mft_lcn * u64::from(vol.geometry.cluster_size)) as usize;
        let data = at + attr_at(&synth.image[at..at + rs], AttrType::DATA);
        let open = |img: Vec<u8>| NtfsVolume::open(Arc::new(MemSource::new(img)));
        let mut img = synth.image.clone();
        img[at + 0x16] &= !1;
        let e = open(img).unwrap_err().to_string();
        assert!(e.contains("record 0 is not in use"), "{e}");

        let size = u64::from_le_bytes(synth.image[data + 0x30..data + 0x38].try_into().unwrap());
        let mut img = synth.image.clone();
        img[data + 0x30..data + 0x38].copy_from_slice(&(size - 8).to_le_bytes());
        let v = open(img).unwrap();
        let w: Vec<String> = v.diagnostics().all().into_iter().map(|d| d.message).collect();
        assert!(w.iter().any(|m| m.contains("is not a multiple of the record size")), "{w:?}");

        let mut img = synth.image.clone();
        for f in [0x28, 0x30] {
            img[data + f..data + f + 8].copy_from_slice(&(size * 64).to_le_bytes());
        }
        let e = open(img).unwrap_err().to_string();
        assert!(e.contains("$MFT runlist covers"), "{e}");
    }

    /// An extension record of `$MFT` of another sequence number, or without the fragment its
    /// attribute list names, fails the open.
    #[test]
    fn an_mft_extension_record_must_hold_its_fragment() {
        let synth = fragmented();
        let vol = synth.open();
        let ext = synth.file(0).extensions[0];
        let at = record_at(&vol, ext);
        let open = |img: Vec<u8>| NtfsVolume::open(Arc::new(MemSource::new(img))).map(|_| ()).unwrap_err().to_string();
        let mut img = synth.image.clone();
        img[at + 0x10] ^= 0x40;
        let e = open(img);
        assert!(e.contains(&format!("$MFT extension record {ext} does not belong to $MFT")), "{e}");
        let mut img = synth.image.clone();
        let rs = vol.mft.record_size as usize;
        let d = at + attr_at(&synth.image[at..at + rs], AttrType::DATA);
        img[d..d + 4].copy_from_slice(&AttrType::BITMAP.0.to_le_bytes());
        let e = open(img);
        assert!(e.contains(&format!("$MFT fragment missing in record {ext}")), "{e}");
    }
}
