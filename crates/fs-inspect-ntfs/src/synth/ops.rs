//! File operations on a [`SyntheticVolume`]: each updates the model like NTFS would and
//! re-materialises the image (once at the end of a [`SyntheticVolume::batch`]).

use crate::attr_flags;
use crate::synth::alloc::Placement;
use crate::synth::content::bytes;
use crate::synth::*;
use crate::{AttrType, Run, StdInfo};

impl SyntheticVolume {
    fn begin(&mut self) {
        self.tick();
        self.touch_logfile();
    }

    fn parent_touched(&mut self, parent: u64) {
        let now = self.clock;
        if let Some(p) = self.files.get_mut(&parent) {
            p.si.modified = now;
            p.si.mft_changed = now;
        }
    }

    fn new_node(&mut self, parent: u64, name: &str, is_dir: bool) -> u64 {
        let record = self.alloc_slot(24);
        let seq = self.take_seq(record);
        let now = self.clock;
        let ns = self.spec.namespace;
        let si = StdInfo {
            created: now,
            modified: now,
            mft_changed: now,
            accessed: now,
            attributes: if is_dir { 0x10 } else { 0x20 },
            max_versions: 0,
            version: 0,
            class_id: 0,
            owner_id: Some(0),
            security_id: Some(0x100),
            quota: Some(0),
            usn: Some(0),
        };
        self.files.insert(
            record,
            FileNode {
                record,
                seq,
                is_dir,
                extra_header_flags: 0,
                names: vec![NameNode { parent, ns, name: name.into() }],
                si,
                streams: Vec::new(),
                extra: Vec::new(),
                index_runs: Vec::new(),
                extensions: Vec::new(),
                attr_list_runs: Vec::new(),
            },
        );
        record
    }

    /// Create a file with `size` bytes of content derived from `seed`; returns its record.
    pub fn create_file(&mut self, parent: u64, name: &str, size: u64, seed: u64, how: Placement) -> u64 {
        self.begin();
        let r = self.new_node(parent, name, false);
        let data = bytes(seed, size as usize);
        let stream = if size as usize <= RESIDENT_MAX {
            StreamNode { kind: AttrType::DATA, name: vec![], flags: 0, data: StreamData::Resident(data) }
        } else {
            let s = self.nr_stream("", size, how);
            self.write_stream(s.runs(), 0, &data);
            s
        };
        self.files.get_mut(&r).expect("just created").streams.push(stream);
        self.parent_touched(parent);
        self.changed();
        r
    }

    /// Create a directory; returns its record.
    pub fn create_dir(&mut self, parent: u64, name: &str) -> u64 {
        self.begin();
        let r = self.new_node(parent, name, true);
        self.parent_touched(parent);
        self.changed();
        r
    }

    /// Add a named `$DATA` stream (alternate data stream) to a file.
    pub fn add_ads(&mut self, record: u64, name: &str, size: u64, seed: u64) {
        self.begin();
        let data = bytes(seed, size as usize);
        let stream = if size as usize <= RESIDENT_MAX {
            StreamNode {
                kind: AttrType::DATA,
                name: name.encode_utf16().collect(),
                flags: 0,
                data: StreamData::Resident(data),
            }
        } else {
            let s = self.nr_stream(name, size, Placement::FirstFit);
            self.write_stream(s.runs(), 0, &data);
            s
        };
        self.files.get_mut(&record).expect("no such file").streams.push(stream);
        self.changed();
    }

    /// Give a file another name (a hard link) in directory `parent`.
    pub fn add_link(&mut self, record: u64, parent: u64, name: &str) {
        self.begin();
        let ns = self.spec.namespace;
        self.files.get_mut(&record).expect("no such file").names.push(NameNode { parent, ns, name: name.into() });
        self.parent_touched(parent);
        self.changed();
    }

    fn record_bytes(&self, r: u64) -> Vec<u8> {
        let rs = self.spec.record_size as u64;
        self.read_stream(&self.mft_runs.clone(), r * rs, rs as usize)
    }

    /// Delete a file (or an empty directory), freeing its clusters.
    pub fn delete(&mut self, record: u64) {
        self.begin();
        let f = self.files[&record].clone();
        assert!(
            !f.is_dir || !self.files.values().any(|c| c.names.iter().any(|n| n.parent == record)),
            "directory not empty"
        );
        let f = self.files.remove(&record).expect("checked above");
        self.alloc.free_runs(&f.all_runs());
        for e in &f.extensions {
            let seq = *self.slot_seq.get(e).unwrap_or(&1);
            self.ext_owner.remove(e);
            let b = self.record_bytes(*e);
            self.release_slot(*e, seq, Some(b));
        }
        let last = self.record_bytes(record);
        self.release_slot(record, f.seq, Some(last));
        for n in &f.names {
            self.parent_touched(n.parent);
        }
        self.changed();
    }
}

// ---- data-stream changes ------------------------------------------------------------------
//
// Each returns the clusters whose content it wrote, as `(lcn, len)` pairs: the changed-block
// list a CBT driver would report for the operation.

/// Split `runs` so that a run boundary falls at `vcn`.
fn split_at(runs: &mut Vec<Run>, vcn: u64) {
    if let Some(i) = runs.iter().position(|r| r.vcn() < vcn && vcn < r.end_vcn()) {
        let k = vcn - runs[i].vcn();
        let (a, b) = match runs[i] {
            Run::Mapped { vcn: v, lcn, len } => {
                (Run::Mapped { vcn: v, lcn, len: k }, Run::Mapped { vcn, lcn: lcn + k, len: len - k })
            }
            Run::Sparse { vcn: v, len } => (Run::Sparse { vcn: v, len: k }, Run::Sparse { vcn, len: len - k }),
        };
        runs[i] = a;
        runs.insert(i + 1, b);
    }
}

/// Merge neighbours that continue each other (as NTFS mapping pairs would).
fn normalize(runs: Vec<Run>) -> Vec<Run> {
    let mut out: Vec<Run> = Vec::new();
    for r in runs.into_iter().filter(|r| !r.is_empty()) {
        match (out.last_mut(), r) {
            (Some(Run::Mapped { lcn: pl, len: plen, .. }), Run::Mapped { lcn, len, .. }) if *pl + *plen == lcn => {
                *plen += len
            }
            (Some(Run::Sparse { len: plen, .. }), Run::Sparse { len, .. }) => *plen += len,
            _ => out.push(r),
        }
    }
    out
}

/// Physical clusters of `runs` between VCNs `lo` and `hi`.
fn mapped_between(runs: &[Run], lo: u64, hi: u64) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    for r in runs {
        let (s, e) = (r.vcn().max(lo), r.end_vcn().min(hi));
        if let (Some(l), true) = (r.lcn(), s < e) {
            out.push((l + s - r.vcn(), e - s));
        }
    }
    out
}

impl SyntheticVolume {
    fn data_parts(&self, record: u64) -> (Vec<Run>, u64, u64, bool) {
        let s = self.files[&record].data().expect("file has no $DATA");
        match &s.data {
            StreamData::NonResident { runs, size, initialized } => {
                (runs.clone(), *size, *initialized, s.flags & attr_flags::SPARSE != 0)
            }
            StreamData::Resident(_) => panic!("stream is resident"),
        }
    }

    fn set_data_parts(&mut self, record: u64, runs: Vec<Run>, size: u64, initialized: u64) {
        let s = self.files.get_mut(&record).and_then(|f| f.data_mut()).expect("file has no $DATA");
        s.data = StreamData::NonResident { runs: normalize(runs), size, initialized: initialized.min(size) };
    }

    /// Move resident `$DATA` out of the record (NTFS never moves it back).
    fn make_non_resident(&mut self, record: u64, how: Placement) -> Vec<(u64, u64)> {
        let s = self.files[&record].data().expect("file has no $DATA");
        let StreamData::Resident(d) = &s.data else { return Vec::new() };
        let (d, flags) = (d.clone(), s.flags);
        let mut ns = self.nr_stream("", d.len() as u64, how);
        ns.flags = flags;
        self.write_stream(ns.runs(), 0, &d);
        let written = mapped_between(ns.runs(), 0, u64::MAX);
        *self.files.get_mut(&record).and_then(|f| f.data_mut()).expect("checked above") = ns;
        written
    }

    /// Give every sparse cluster of VCNs `[lo, hi)` a real, zeroed cluster; returns them.
    fn map_vcns(&mut self, runs: &mut Vec<Run>, lo: u64, hi: u64, how: Placement) -> Vec<(u64, u64)> {
        let cs = self.cs();
        let end = runs.last().map(|r| r.end_vcn()).unwrap_or(0);
        if end < hi {
            runs.push(Run::Sparse { vcn: end, len: hi - end });
        }
        split_at(runs, lo);
        split_at(runs, hi);
        let mut out = Vec::new();
        let mut i = 0;
        while i < runs.len() {
            let r = runs[i];
            if r.lcn().is_none() && r.vcn() >= lo && r.end_vcn() <= hi {
                let new = self.alloc.alloc(r.len(), r.vcn(), how);
                for n in &new {
                    let l = n.lcn().expect("allocations are mapped");
                    let o = (l * cs) as usize;
                    self.image[o..o + (n.len() * cs) as usize].fill(0);
                    out.push((l, n.len()));
                }
                let k = new.len();
                runs.splice(i..i + 1, new);
                i += k;
            } else {
                i += 1;
            }
        }
        out
    }

    /// Write `len` bytes (content from `seed`) at `offset` of the unnamed `$DATA`, allocating
    /// clusters for holes and for growth (a non-sparse file is allocated up to its new end).
    pub fn write_data(&mut self, record: u64, offset: u64, len: u64, seed: u64, how: Placement) -> Vec<(u64, u64)> {
        self.begin();
        let cs = self.cs();
        let mut written = self.make_non_resident(record, how);
        let (mut runs, size, init, sparse) = self.data_parts(record);
        let end = offset + len;
        let lo = if sparse { offset / cs } else { size.min(offset) / cs };
        written.extend(self.map_vcns(&mut runs, lo, end.div_ceil(cs), how));
        // Bytes between the old valid data length and the write read as zero.
        if offset > init {
            self.write_mapped(&runs, init, offset - init, &mut written, None);
        }
        let data = bytes(seed, len as usize);
        self.write_mapped(&runs, offset, len, &mut written, Some(&data));
        self.set_data_parts(record, runs, size.max(end), init.max(end));
        self.changed();
        written
    }

    /// Write `data` (or zeros) over the mapped parts of `[offset, offset + len)`.
    fn write_mapped(
        &mut self,
        runs: &[Run],
        offset: u64,
        len: u64,
        written: &mut Vec<(u64, u64)>,
        data: Option<&[u8]>,
    ) {
        let cs = self.cs();
        for r in runs {
            let Some(l) = r.lcn() else { continue };
            let (s, e) = ((r.vcn() * cs).max(offset), (r.end_vcn() * cs).min(offset + len));
            if s >= e {
                continue;
            }
            let phys = l * cs + s - r.vcn() * cs;
            let dst = &mut self.image[phys as usize..(phys + e - s) as usize];
            match data {
                Some(d) => dst.copy_from_slice(&d[(s - offset) as usize..(e - offset) as usize]),
                None => dst.fill(0),
            }
            written.push((phys / cs, (phys + e - s).div_ceil(cs) - phys / cs));
        }
    }

    /// `SetEndOfFile`: shrinking frees the clusters past the new end; growing a non-sparse
    /// file allocates (unwritten) clusters, growing a sparse one adds a hole. Returns the
    /// newly allocated clusters.
    pub fn truncate(&mut self, record: u64, new_size: u64, how: Placement) -> Vec<(u64, u64)> {
        self.begin();
        let cs = self.cs();
        let mut out = self.make_non_resident(record, how);
        let (mut runs, _, init, sparse) = self.data_parts(record);
        let (old_end, new_end) = (runs.last().map(|r| r.end_vcn()).unwrap_or(0), new_size.div_ceil(cs));
        if new_end < old_end {
            split_at(&mut runs, new_end);
            let tail: Vec<Run> = runs.iter().copied().filter(|r| r.vcn() >= new_end).collect();
            self.alloc.free_runs(&tail);
            runs.retain(|r| r.vcn() < new_end);
        } else if new_end > old_end {
            if sparse {
                runs.push(Run::Sparse { vcn: old_end, len: new_end - old_end });
            } else {
                for n in self.alloc.alloc(new_end - old_end, old_end, how) {
                    out.push((n.lcn().expect("allocations are mapped"), n.len()));
                    runs.push(n);
                }
            }
        }
        self.set_data_parts(record, runs, new_size, init.min(new_size));
        self.changed();
        out
    }

    /// `FSCTL_SET_SPARSE` on the unnamed `$DATA`.
    pub fn set_sparse(&mut self, record: u64) {
        self.begin();
        self.make_non_resident(record, Placement::FirstFit);
        let s = self.files.get_mut(&record).and_then(|f| f.data_mut()).expect("file has no $DATA");
        s.flags |= attr_flags::SPARSE;
        self.changed();
    }

    /// `FSCTL_SET_ZERO_DATA`: on a sparse file, whole clusters in the range are deallocated
    /// and partial ones zeroed; on a non-sparse file the range is zeroed in place. Returns the
    /// zeroed clusters.
    pub fn zero_data(&mut self, record: u64, offset: u64, len: u64) -> Vec<(u64, u64)> {
        self.begin();
        let cs = self.cs();
        let mut written = self.make_non_resident(record, Placement::FirstFit);
        let (mut runs, size, init, sparse) = self.data_parts(record);
        let end = (offset + len).min(size);
        let zend = init.min(end);
        let (lo, hi) = if sparse && offset < end { (offset.div_ceil(cs), end / cs) } else { (0, 0) };
        if lo < hi {
            split_at(&mut runs, lo);
            split_at(&mut runs, hi);
            for r in runs.iter_mut() {
                if r.vcn() >= lo && r.end_vcn() <= hi && r.lcn().is_some() {
                    self.alloc.free_runs(&[*r]);
                    *r = Run::Sparse { vcn: r.vcn(), len: r.len() };
                }
            }
            if offset < (lo * cs).min(zend) {
                self.write_mapped(&runs, offset, (lo * cs).min(zend) - offset, &mut written, None);
            }
            if hi * cs < zend {
                self.write_mapped(&runs, hi * cs, zend - hi * cs, &mut written, None);
            }
        } else if offset < zend {
            self.write_mapped(&runs, offset, zend - offset, &mut written, None);
        }
        self.set_data_parts(record, runs, size, init);
        self.changed();
        written
    }
}
