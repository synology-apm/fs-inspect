//! A synthetic NTFS volume (`crate::synth`) with a USN journal model (`$Max`, `$Info`,
//! sparse `$J`). Operations update the model like NTFS would: journal records, `$SI.Usn`,
//! LastWriteTime.

use crate::synth::{EXTEND, Placement, ROOT, SyntheticVolume, VolumeSpec};
use crate::synth::{FileNode, NameNode, StreamData, StreamNode};
use crate::track::usn::encode::{encode_info, encode_max, encode_usn_record};
use crate::track::usn::{MaxInfo, PAGE, UsnRecord, reason};
use crate::{AttrType, Frn, Namespace, Run, attr_flags};
use fs_inspect_change::testing::{self, Recorded, Scan};
use fs_inspect_change::{Baseline, Continuity, DegradeCode, Evidence, FileState, PrevFile};
use fs_inspect_change::{SnapshotHints, TaggedRange};
use fs_inspect_core::range::list;
use fs_inspect_core::{ByteRange, DriverContext, Filesystem, files};
use fs_inspect_io::DynSource;
use std::sync::Arc;

pub const CS: u64 = 4096;

#[derive(Debug, Clone)]
pub struct Journal {
    pub id: u64,
    pub record: u64,
    pub max_size: u64,
    pub delta: u64,
    /// First valid byte (cluster aligned); everything before is sparse.
    pub start: u64,
    /// Next USN (= data size of `$J`).
    pub next: u64,
    /// Bytes `[start, next)`.
    pub data: Vec<u8>,
    /// Mapped runs from VCN `start / cs` to the end of the allocation.
    pub runs: Vec<Run>,
    pub lowest_valid: i64,
    /// Range tracking `(chunk, threshold)`.
    pub range: Option<(u64, u64)>,
}

pub struct World {
    pub v: SyntheticVolume,
    pub j: Option<Journal>,
    seed: u64,
    /// The `$LogFile` restart pages say the volume is clean (as after a VSS snapshot or a
    /// clean dismount).
    pub log_clean: bool,
}

pub fn opts() -> SnapshotHints {
    SnapshotHints::default()
}

impl World {
    pub fn new(journal: bool, range: Option<(u64, u64)>) -> Self {
        Self::with_spec(VolumeSpec { clusters: 16384, ..Default::default() }, journal, range)
    }

    pub fn with_spec(spec: VolumeSpec, journal: bool, range: Option<(u64, u64)>) -> Self {
        let v = SyntheticVolume::format(spec);
        let mut w = World { v, j: None, seed: 1, log_clean: true };
        if journal {
            w.enable_journal(1, range, 1 << 20, 64 << 10);
        }
        w
    }

    /// Create `$Extend\$UsnJrnl` (or replace its streams with a new journal).
    pub fn enable_journal(&mut self, id: u64, range: Option<(u64, u64)>, max_size: u64, delta: u64) {
        let record = match self.j.take() {
            Some(old) => {
                self.v.alloc.free_runs(&old.runs);
                old.record
            }
            None => {
                let r = (24..self.v.mft_records)
                    .find(|r| !self.v.files.contains_key(r) && !self.v.ext_owner.contains_key(r))
                    .expect("free record");
                let seq = *self.v.slot_seq.get(&r).unwrap_or(&1);
                self.v.stale.remove(&r);
                let si = self.v.files[&ROOT].si.clone();
                self.v.files.insert(
                    r,
                    FileNode {
                        record: r,
                        seq,
                        is_dir: false,
                        extra_header_flags: 0,
                        names: vec![NameNode { parent: EXTEND, ns: Namespace::Win32AndDos, name: "$UsnJrnl".into() }],
                        si,
                        streams: Vec::new(),
                        extra: Vec::new(),
                        index_runs: Vec::new(),
                        extensions: Vec::new(),
                        attr_list_runs: Vec::new(),
                    },
                );
                r
            }
        };
        let runs = self.v.alloc.alloc(delta / CS, 0, Placement::FirstFit);
        self.j = Some(Journal {
            id,
            record,
            max_size,
            delta,
            start: 0,
            next: 0,
            data: Vec::new(),
            runs,
            lowest_valid: 0,
            range,
        });
        self.sync();
    }

    /// Remove the journal (`fsutil usn deleteJournal`).
    pub fn delete_journal(&mut self) {
        if let Some(j) = self.j.take() {
            self.v.alloc.free_runs(&j.runs);
            self.v.files.remove(&j.record);
            let seq = *self.v.slot_seq.get(&j.record).unwrap_or(&1);
            self.v.slot_seq.insert(j.record, seq + 1);
        }
        self.v.materialize();
    }

    /// Write the journal model into its file node and re-materialise the image.
    pub fn sync(&mut self) {
        if let Some(j) = &self.j {
            let mut runs = Vec::new();
            let first_vcn = j.runs.first().map(|r| r.vcn()).unwrap_or(j.start / CS);
            if first_vcn > 0 {
                runs.push(Run::Sparse { vcn: 0, len: first_vcn });
            }
            runs.extend(j.runs.iter().copied());
            let mut streams = vec![
                StreamNode {
                    kind: AttrType::DATA,
                    name: "$J".encode_utf16().collect(),
                    flags: attr_flags::SPARSE,
                    data: StreamData::NonResident { runs: runs.clone(), size: j.next, initialized: j.next },
                },
                StreamNode {
                    kind: AttrType::DATA,
                    name: "$Max".encode_utf16().collect(),
                    flags: 0,
                    data: StreamData::Resident(encode_max(&MaxInfo {
                        maximum_size: j.max_size,
                        allocation_delta: j.delta,
                        journal_id: j.id,
                        lowest_valid_usn: j.lowest_valid,
                    })),
                },
            ];
            if let Some((chunk, threshold)) = j.range {
                streams.push(StreamNode {
                    kind: AttrType::DATA,
                    name: "$Info".encode_utf16().collect(),
                    flags: 0,
                    data: StreamData::Resident(encode_info(chunk, threshold)),
                });
            }
            let (start, data, record) = (j.start, j.data.clone(), j.record);
            self.v.write_stream(&runs, start, &data);
            self.v.files.get_mut(&record).expect("journal node").streams = streams;
        }
        self.v.materialize();
    }

    fn alloc_end(j: &Journal) -> u64 {
        j.runs.last().map(|r| r.end_vcn() * CS).unwrap_or(j.start)
    }

    /// Append `rec` (padded so it does not cross a page; its `usn` is assigned), growing and
    /// wrapping `$J` like NTFS; returns the USN, `None` without a journal.
    pub fn append(&mut self, mut rec: UsnRecord) -> Option<i64> {
        let j = self.j.as_mut()?;
        let len = encode_usn_record(&rec).len() as u64;
        if (j.next % PAGE) + len > PAGE {
            let pad = PAGE - j.next % PAGE;
            j.data.resize(j.data.len() + pad as usize, 0);
            j.next += pad;
        }
        rec.usn = j.next as i64;
        let bytes = encode_usn_record(&rec);
        j.data.extend_from_slice(&bytes);
        j.next += bytes.len() as u64;
        let usn = rec.usn;
        loop {
            let j = self.j.as_ref().expect("journal");
            if j.next <= Self::alloc_end(j) {
                break;
            }
            let vcn0 = Self::alloc_end(j) / CS;
            let runs = self.v.alloc.alloc(j.delta / CS, vcn0, Placement::FirstFit);
            self.j.as_mut().expect("journal").runs.extend(runs);
        }
        // wrap: keep at most max_size bytes
        loop {
            let j = self.j.as_ref().expect("journal");
            if j.next - j.start <= j.max_size {
                break;
            }
            let new_start = (j.start + j.delta).div_ceil(CS) * CS;
            let drop_vcn = new_start / CS;
            let mut keep = Vec::new();
            let mut freed = Vec::new();
            for r in &j.runs {
                if r.end_vcn() <= drop_vcn {
                    freed.push(*r);
                } else if r.vcn() < drop_vcn {
                    let cut = drop_vcn - r.vcn();
                    let lcn = r.lcn().expect("mapped");
                    freed.push(Run::Mapped { vcn: r.vcn(), lcn, len: cut });
                    keep.push(Run::Mapped { vcn: drop_vcn, lcn: lcn + cut, len: r.len() - cut });
                } else {
                    keep.push(*r);
                }
            }
            self.v.alloc.free_runs(&freed);
            let j = self.j.as_mut().expect("journal");
            let drop = (new_start - j.start) as usize;
            j.data.drain(..drop.min(j.data.len()));
            j.start = new_start;
            j.lowest_valid = new_start as i64;
            j.runs = keep;
        }
        Some(usn)
    }

    fn frn(&self, record: u64) -> Frn {
        Frn::new(record, self.v.files[&record].seq)
    }

    /// A V2 record for `record` with `reasons`, stamping `$SI.Usn`.
    pub fn journal(&mut self, record: u64, reasons: u32) {
        let f = &self.v.files[&record];
        let rec = UsnRecord {
            usn: 0,
            major_version: 2,
            minor_version: 0,
            frn: f.frn(),
            parent: Frn::new(ROOT, 5),
            frn_high: 0,
            timestamp: Some(self.v.clock),
            reason: reasons,
            source_info: 0,
            security_id: f.si.security_id,
            attributes: Some(f.si.attributes),
            name: f.names.first().map(|n| n.name.encode_utf16().collect()).unwrap_or_default(),
            remaining_extents: 0,
            extents: vec![],
        };
        if let Some(usn) = self.append(rec) {
            self.v.files.get_mut(&record).expect("file").si.usn = Some(usn as u64);
        }
    }

    /// A V4 range-tracking record, when range tracking is on and the file is large enough.
    pub fn journal_ranges(&mut self, record: u64, extents: Vec<(i64, i64)>) {
        let Some((_, threshold)) = self.j.as_ref().and_then(|j| j.range) else { return };
        if self.data_size(record) < threshold {
            return;
        }
        let rec = UsnRecord {
            usn: 0,
            major_version: 4,
            minor_version: 0,
            frn: self.frn(record),
            parent: Frn::new(ROOT, 5),
            frn_high: 0,
            timestamp: None,
            reason: reason::DATA_OVERWRITE,
            source_info: 0,
            security_id: None,
            attributes: None,
            name: Vec::new(),
            remaining_extents: 0,
            extents,
        };
        if let Some(usn) = self.append(rec) {
            self.v.files.get_mut(&record).expect("file").si.usn = Some(usn as u64);
        }
    }

    pub fn data_size(&self, record: u64) -> u64 {
        self.v.files[&record].data().map(|s| s.size()).unwrap_or(0)
    }

    fn next_seed(&mut self) -> u64 {
        self.seed += 1;
        self.seed
    }

    /// Create a file in the root directory.
    pub fn create(&mut self, name: &str, size: u64) -> u64 {
        let seed = self.next_seed();
        let r = self.v.create_file(ROOT, name, size, seed, Placement::FirstFit);
        self.journal(r, reason::FILE_CREATE);
        self.journal(r, reason::FILE_CREATE | reason::DATA_EXTEND | reason::CLOSE);
        self.sync();
        r
    }

    /// Overwrite/extend the unnamed `$DATA` like an application write: data, LastWriteTime,
    /// a V2 record, V4 ranges (if tracked), and the close record.
    pub fn write(&mut self, record: u64, offset: u64, len: u64) {
        let old = self.data_size(record);
        let seed = self.next_seed();
        self.v.write_data(record, offset, len, seed, Placement::FirstFit);
        let now = self.v.clock;
        let si = &mut self.v.files.get_mut(&record).expect("file").si;
        si.modified = now;
        si.mft_changed = now;
        let mut reasons = 0;
        if offset < old {
            reasons |= reason::DATA_OVERWRITE;
        }
        if offset + len > old {
            reasons |= reason::DATA_EXTEND;
        }
        self.journal(record, reasons);
        if offset < old {
            self.journal_ranges(record, vec![(offset as i64, len.min(old - offset) as i64)]);
        }
        self.journal(record, reasons | reason::CLOSE);
        self.sync();
    }

    /// A metadata-only change (attributes / timestamps other than LastWriteTime).
    pub fn touch_metadata(&mut self, record: u64) {
        self.v.clock += 10_000_000;
        let now = self.v.clock;
        self.v.files.get_mut(&record).expect("file").si.mft_changed = now;
        self.journal(record, reason::BASIC_INFO_CHANGE);
        self.journal(record, reason::BASIC_INFO_CHANGE | reason::CLOSE);
        self.sync();
    }

    pub fn delete(&mut self, record: u64) {
        self.journal(record, reason::FILE_DELETE | reason::CLOSE);
        self.v.delete(record);
        self.sync();
    }

    pub fn set_si(&mut self, record: u64, f: impl FnOnce(&mut crate::StdInfo)) {
        f(&mut self.v.files.get_mut(&record).expect("file").si);
        self.sync();
    }

    /// Byte ranges of the unnamed `$DATA` of `record`.
    pub fn data_ranges(&self, record: u64) -> Vec<ByteRange> {
        self.stream_ranges(self.v.files[&record].data().expect("data"))
    }

    /// Physical ranges holding logical bytes `[lo, hi)` of the unnamed `$DATA`.
    pub fn phys(&self, record: u64, lo: u64, hi: u64) -> Vec<ByteRange> {
        let mut out = Vec::new();
        for r in self.v.files[&record].data().expect("data").runs() {
            let (s, e) = ((r.vcn() * CS).max(lo), (r.end_vcn() * CS).min(hi));
            if let (Some(l), true) = (r.lcn(), s < e) {
                out.push(ByteRange::new(l * CS + s - r.vcn() * CS, e - s));
            }
        }
        list::normalize(&mut out);
        out
    }

    pub fn stream_ranges(&self, s: &StreamNode) -> Vec<ByteRange> {
        s.runs().iter().filter_map(|r| r.lcn().map(|l| ByteRange::new(l * CS, r.len() * CS))).collect()
    }

    /// Byte ranges of `$J`.
    pub fn j_ranges(&self) -> Vec<ByteRange> {
        self.j
            .as_ref()
            .map(|j| j.runs.iter().map(|r| ByteRange::new(r.lcn().unwrap() * CS, r.len() * CS)).collect())
            .unwrap_or_default()
    }

    pub fn source(&self) -> DynSource {
        Arc::new(fs_inspect_io::MemSource::new(self.image()))
    }

    /// The image, its `$LogFile` restart pages saying clean or not ([`World::log_clean`]).
    pub fn image(&self) -> Vec<u8> {
        let mut img = self.v.image.clone();
        let rp = self.v.restart_page(self.v.restart_lsn(), self.log_clean);
        for page in [0u64, 4096] {
            let r = self.v.logfile_runs.iter().find(|r| r.vcn() <= page / CS && page / CS < r.end_vcn()).unwrap();
            let at = ((r.lcn().unwrap() + page / CS - r.vcn()) * CS + page % CS) as usize;
            img[at..at + 512].copy_from_slice(&rp);
        }
        img
    }

    /// A scan of the tracker against `prev` (what a previous scan left), as a comparer runs it.
    pub fn scan_with(&self, prev: Option<&Recorded>, o: &SnapshotHints) -> Diff {
        let src = self.source();
        let fs: Arc<dyn Filesystem> = crate::open(src.clone(), &DriverContext::default()).expect("fs");
        let sc = crate::track::open(fs.clone()).expect("scanner");
        let scan = testing::scan(&*sc, &src, &fs, o, prev).expect("scan");
        let prev = prev.filter(|_| scan.continuity == Continuity::Ok).cloned();
        Diff { scan, prev }
    }

    pub fn scan(&self, prev: Option<&Recorded>) -> Diff {
        self.scan_with(prev, &opts())
    }

    /// What a scan of the current state leaves (as a backup would keep it).
    pub fn base(&self) -> Recorded {
        self.scan(None).scan.next
    }
}

/// A scan and the previous one it was compared with.
#[derive(Debug)]
pub struct Diff {
    pub scan: Scan,
    /// The previous scan, when the continuity held (the scan used it).
    pub prev: Option<Recorded>,
}

impl Diff {
    /// The file reported under `key`.
    pub fn file(&self, key: u64) -> &FileState {
        self.scan.file(key).expect("file reported")
    }

    /// What the previous scan recorded of the file reported under `key`.
    pub fn before(&self, key: u64) -> Option<PrevFile> {
        self.prev.as_ref()?.file(key)
    }

    /// The file under `key` compares unchanged: the same generation, `meta` and `aux` as the
    /// previous scan recorded, and no evidence of a write.
    pub fn unchanged(&self, key: u64) -> bool {
        let f = self.file(key);
        let now = PrevFile { generation: f.generation, meta: f.meta, aux: f.aux };
        self.before(key) == Some(now) && matches!(f.evidence, Evidence::None | Evidence::MetadataOnly)
    }

    /// The file under `key` is another file than the previous scan's (none there, or another
    /// generation).
    pub fn created(&self, key: u64) -> bool {
        self.before(key).is_none_or(|p| p.generation != self.file(key).generation)
    }

    pub fn degraded(&self) -> Vec<DegradeCode> {
        let mut v: Vec<DegradeCode> = self.scan.extra.degraded.iter().map(|d| d.code).collect();
        if let Continuity::Broken(d) = &self.scan.continuity {
            v.push(d.code);
        }
        v
    }

    /// What the file system allocates.
    pub fn used(&self) -> &[ByteRange] {
        &self.scan.next.allocated
    }

    /// The physical ranges of every reported file.
    pub fn data(&self) -> Vec<ByteRange> {
        let mut v = Vec::new();
        for f in &self.scan.files {
            files::all_physical(&f.extents, &mut v);
        }
        list::normalize(&mut v);
        v
    }

    /// The physical ranges of the files' zero ranges, and the driver's own.
    pub fn zero(&self) -> Vec<ByteRange> {
        let mut v = self.scan.extra.zero.clone();
        for f in &self.scan.files {
            for z in &f.zero {
                files::physical_in(&f.extents, z.offset, z.end(), &mut v);
            }
        }
        list::normalize(&mut v);
        v
    }

    /// The used space outside the files' data that the scan does not vouch for: its dirty
    /// ranges, and what it neither tracks, owns through an unchanged file, reads as zeros
    /// nor reports as fixed (those a comparer checks by their content).
    pub fn space(&self) -> Vec<ByteRange> {
        let x = &self.scan.extra;
        let mut vouched = x.tracked.clone();
        vouched.extend(x.owned.iter().filter(|(k, _)| self.scan.file(*k).is_some() && self.unchanged(*k)).map(|o| o.1));
        vouched.extend(x.fixed.iter().copied());
        vouched.extend(self.data());
        vouched.extend(self.zero());
        list::normalize(&mut vouched);
        let mut v = list::subtract(self.used(), &vouched);
        v.extend(x.dirty.iter().map(TaggedRange::range));
        list::normalize(&mut v);
        list::intersect(&v, self.used())
    }

    /// [`space`](Diff::space) inside `ranges`.
    pub fn space_in(&self, ranges: &[ByteRange]) -> Vec<ByteRange> {
        list::intersect(&self.space(), &norm(ranges))
    }

    /// The driver's dirty ranges inside `ranges`.
    pub fn dirty_in(&self, ranges: &[ByteRange]) -> Vec<TaggedRange> {
        let ranges = norm(ranges);
        let mut out = Vec::new();
        for t in &self.scan.extra.dirty {
            out.extend(TaggedRange::tag_all(list::intersect(&[t.range()], &ranges), t.reason));
        }
        out
    }

    /// The data of the files that do not compare unchanged.
    pub fn changed_data(&self) -> Vec<ByteRange> {
        let mut v = Vec::new();
        for f in self.scan.files.iter().filter(|f| !self.unchanged(f.key)) {
            files::all_physical(&f.extents, &mut v);
        }
        list::normalize(&mut v);
        v
    }

    /// What the scan reports at all as possibly changed: [`space`](Diff::space), the data of
    /// the files that changed, and the allocation that is new.
    pub fn all_changed(&self) -> Vec<ByteRange> {
        let mut v = self.space();
        v.extend(self.changed_data());
        match &self.prev {
            Some(p) => v.extend(list::subtract(self.used(), &norm(&p.allocated))),
            None => v.extend(self.used().iter().copied()),
        }
        list::normalize(&mut v);
        v
    }
}

/// `v` sorted and coalesced.
pub fn norm(v: &[ByteRange]) -> Vec<ByteRange> {
    let mut v = v.to_vec();
    list::normalize(&mut v);
    v
}

/// The physical bytes of `[from, to)` of a stream mapped by `runs` (unmapped parts left out).
pub fn phys_of(runs: &[Run], from: u64, to: u64) -> Vec<ByteRange> {
    let to = to.min(runs.last().map_or(0, |r| r.end_vcn()) * CS);
    (from / CS..to.div_ceil(CS))
        .filter_map(|v| crate::format::volume::map_stream_bytes(runs, CS as u32, v * CS, CS))
        .flatten()
        .collect()
}

impl World {
    /// Where MFT record `r` lies.
    pub fn record_range(&self, r: u64) -> Vec<ByteRange> {
        let rs = u64::from(self.v.spec.record_size);
        crate::format::volume::map_stream_bytes(&self.v.mft_runs, CS as u32, r * rs, rs).unwrap()
    }

    /// The structures dirty whenever the log moved or the journal grew, whatever else
    /// changed: the `$LogFile` restart pages (fixed), the allocation of `$J` past its data.
    pub fn always_dirty(&self) -> Vec<ByteRange> {
        let v = &self.v;
        let mut r = phys_of(&v.logfile_runs, 0, 8192);
        if let Some(j) = &self.j {
            let end = j.runs.last().map(|r| r.end_vcn()).unwrap_or(0) * CS;
            r.extend(phys_of(&j.runs, j.next.div_ceil(CS) * CS, end));
        }
        list::normalize(&mut r);
        r
    }
    /// What `d` reports as changed outside [`World::always_dirty`].
    pub fn changed(&self, d: &Diff) -> Vec<ByteRange> {
        list::subtract(&d.all_changed(), &self.always_dirty())
    }
}

pub fn total(v: &[TaggedRange]) -> u64 {
    v.iter().map(|t| t.length).sum()
}
