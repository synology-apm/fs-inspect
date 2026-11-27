//! `SyntheticVolume`: an in-memory NTFS volume generated from a model.
//!
//! The model (files, names, streams, allocation, `$LogFile` counter) is the source of truth for
//! metadata; file *data* lives directly in the image. [`SyntheticVolume::materialize`]
//! deterministically re-encodes every metadata structure from the model, so unchanged
//! structures produce identical bytes and any real change shows up as a changed cluster.
//!
//! Test tooling (the `synth` feature, and this crate's own tests); [`ops`] has the file
//! operations, [`alloc`] the first-fit cluster allocator.

#![allow(clippy::comparison_chain, clippy::type_complexity, missing_debug_implementations)]
// Test tooling: a broken fixture should stop the test that builds it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub mod alloc;
pub mod bitmap;
pub mod content;
pub mod ops;

pub use crate::Run;
use crate::UpCase;
use crate::attr_flags;
use crate::encode::index as ienc;
use crate::encode::protect;
use crate::encode::{AttrListEntry, encode_attr_list};
use crate::encode::{BootSpec, encode_boot_sector};
use crate::encode::{NonResidentSpec, RecordBuilder, encode_non_resident, encode_resident, header_flags};
use crate::synth::alloc::Allocator;
pub use crate::synth::alloc::Placement;
pub use crate::synth::bitmap::Bitmap;
use crate::{AttrType, FileName, Frn, Namespace, NtfsName, StdInfo};
use fs_inspect_core::bytes::{put_u16, put_u32, put_u64};
use std::collections::{BTreeMap, BTreeSet};

pub const ROOT: u64 = 5;
pub const EXTEND: u64 = 11;
/// Data up to this size stays resident.
pub const RESIDENT_MAX: usize = 400;

#[derive(Debug, Clone)]
pub struct VolumeSpec {
    pub bytes_per_sector: u32,
    pub cluster_size: u32,
    pub record_size: u32,
    pub index_block_size: u32,
    pub clusters: u64,
    pub initial_mft_records: u64,
    pub mft_grow_records: u64,
    /// Placement for MFT growth (use `MaxRun(1)`/`Scattered` to fragment `$MFT`).
    pub mft_grow_placement: Placement,
    pub serial: u64,
    pub logfile_clusters: u64,
    /// Write an operation counter into `$LogFile` on every operation (like real NTFS).
    pub touch_logfile: bool,
    pub namespace: Namespace,
}

impl Default for VolumeSpec {
    fn default() -> Self {
        VolumeSpec {
            bytes_per_sector: 512,
            cluster_size: 4096,
            record_size: 1024,
            index_block_size: 4096,
            clusters: 8192,
            initial_mft_records: 64,
            mft_grow_records: 32,
            mft_grow_placement: Placement::FirstFit,
            serial: 0x1234_5678_9ABC_DEF0,
            logfile_clusters: 16,
            touch_logfile: true,
            namespace: Namespace::Posix,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamData {
    Resident(Vec<u8>),
    NonResident { runs: Vec<Run>, size: u64, initialized: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamNode {
    pub kind: AttrType,
    pub name: Vec<u16>,
    pub flags: u16,
    pub data: StreamData,
}

impl StreamNode {
    pub fn runs(&self) -> &[Run] {
        match &self.data {
            StreamData::NonResident { runs, .. } => runs,
            StreamData::Resident(_) => &[],
        }
    }
    pub fn size(&self) -> u64 {
        match &self.data {
            StreamData::NonResident { size, .. } => *size,
            StreamData::Resident(d) => d.len() as u64,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameNode {
    pub parent: u64,
    pub ns: Namespace,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct FileNode {
    pub record: u64,
    pub seq: u16,
    pub is_dir: bool,
    pub extra_header_flags: u16,
    pub names: Vec<NameNode>,
    pub si: StdInfo,
    /// `$DATA` streams and other non-index attributes.
    pub streams: Vec<StreamNode>,
    /// Additional resident attributes `(type, name, value)` (volume info, view indexes...).
    pub extra: Vec<(AttrType, Vec<u16>, Vec<u8>)>,
    /// `$I30` `$INDEX_ALLOCATION` clusters (directories).
    pub index_runs: Vec<Run>,
    pub extensions: Vec<u64>,
    pub attr_list_runs: Vec<Run>,
}

impl FileNode {
    pub fn frn(&self) -> Frn {
        Frn::new(self.record, self.seq)
    }
    pub fn data(&self) -> Option<&StreamNode> {
        self.streams.iter().find(|s| s.kind == AttrType::DATA && s.name.is_empty())
    }
    pub fn data_mut(&mut self) -> Option<&mut StreamNode> {
        self.streams.iter_mut().find(|s| s.kind == AttrType::DATA && s.name.is_empty())
    }
    pub fn stream(&self, name: &str) -> Option<&StreamNode> {
        let n: Vec<u16> = name.encode_utf16().collect();
        self.streams.iter().find(|s| s.kind == AttrType::DATA && s.name == n)
    }
    /// Every mapped cluster run of this file's streams and index.
    pub fn all_runs(&self) -> Vec<Run> {
        let mut v: Vec<Run> = self.streams.iter().flat_map(|s| s.runs().iter().copied()).collect();
        v.extend(self.index_runs.iter().copied());
        v.extend(self.attr_list_runs.iter().copied());
        v
    }
}

pub(crate) fn utf16(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

/// Attribute to be placed into records.
#[derive(Debug, Clone)]
struct AttrSpec {
    kind: AttrType,
    name: Vec<u16>,
    flags: u16,
    body: AttrBody,
}

#[derive(Debug, Clone)]
enum AttrBody {
    Resident { value: Vec<u8>, indexed: bool },
    NonResident { lowest_vcn: u64, highest_vcn: i64, allocated: u64, size: u64, initialized: u64, runs: Vec<Run> },
}

impl AttrSpec {
    fn encode(&self, id: u16) -> Vec<u8> {
        match &self.body {
            AttrBody::Resident { value, indexed } => {
                encode_resident(self.kind, &self.name, id, self.flags, value, *indexed)
            }
            AttrBody::NonResident { lowest_vcn, highest_vcn, allocated, size, initialized, runs } => {
                // A stream flagged compressed gets the compression unit NTFS uses (16 clusters);
                // its data is stored as written (the drivers never decompress).
                let compressed = self.flags & attr_flags::COMPRESSED != 0;
                let sized = self.flags & attr_flags::SPARSE != 0 || compressed;
                encode_non_resident(&NonResidentSpec {
                    kind: self.kind,
                    name: &self.name,
                    id,
                    flags: self.flags,
                    lowest_vcn: *lowest_vcn,
                    highest_vcn: *highest_vcn,
                    compression_unit: if compressed { 4 } else { 0 },
                    allocated: if *lowest_vcn == 0 { *allocated } else { 0 },
                    size: if *lowest_vcn == 0 { *size } else { 0 },
                    initialized: if *lowest_vcn == 0 { *initialized } else { 0 },
                    compressed_size: (sized && *lowest_vcn == 0).then_some(*allocated).or(sized.then_some(0)),
                    runs,
                })
            }
        }
    }
    fn lowest_vcn(&self) -> u64 {
        match &self.body {
            AttrBody::NonResident { lowest_vcn, .. } => *lowest_vcn,
            _ => 0,
        }
    }
}

/// Result of laying out the directory index of one directory.
struct IndexPlan {
    root_value: Vec<u8>,
    blocks: Vec<Vec<u8>>,
    bitmap: Vec<u8>,
}

/// An in-memory NTFS volume: the model (files, allocation, `$MFT` and `$LogFile` layout) and
/// the image materialised from it.
pub struct SyntheticVolume {
    pub spec: VolumeSpec,
    pub image: Vec<u8>,
    pub files: BTreeMap<u64, FileNode>,
    pub alloc: Allocator,
    pub total_clusters: u64,
    pub mft_runs: Vec<Run>,
    pub mft_records: u64,
    pub mft_bitmap_runs: Vec<Run>,
    pub mirror_lcn: u64,
    pub bitmap_runs: Vec<Run>,
    pub logfile_runs: Vec<Run>,
    /// Next sequence number for free record slots.
    pub slot_seq: BTreeMap<u64, u16>,
    /// Bytes of freed records (stale content, not in use).
    pub stale: BTreeMap<u64, Vec<u8>>,
    /// extension record -> base record
    pub ext_owner: BTreeMap<u64, u64>,
    pub clock: u64,
    /// Bytes of log record pages written (the position of the next page).
    pub log_pos: u64,
    /// LSN of the last log page written: what changed records and index blocks are stamped
    /// with.
    pub last_lsn: u64,
    pub security_next: u32,
    /// Records whose parent index entries keep the duplicated information of this older
    /// state (NTFS refreshes index copies lazily).
    pub stale_index: BTreeMap<u64, FileNode>,
    /// Inside [`batch`](Self::batch): the lowest record slot a new record may take. Slots are
    /// handed out in increasing order and a slot freed during the batch is reused only after it.
    pub batching: Option<u64>,
    /// Every user slot (from 24) below this one is taken: where a new slot is looked for from
    /// (a volume of a million records allocates in time linear in them).
    pub taken_below: u64,
}

/// `seq_number_bits` of the synthetic log.
pub const LOG_SEQ_BITS: u32 = 30;

const T0: u64 = 133_000_000_000_000_000; // 2022-06-18

impl SyntheticVolume {
    pub fn cs(&self) -> u64 {
        self.spec.cluster_size as u64
    }
    fn rs(&self) -> usize {
        self.spec.record_size as usize
    }
    fn spc(&self) -> u64 {
        self.cs() / self.spec.bytes_per_sector as u64
    }
    pub fn total_sectors(&self) -> u64 {
        self.total_clusters * self.spc()
    }

    /// Create and format a volume.
    pub fn format(spec: VolumeSpec) -> Self {
        assert!(spec.cluster_size.is_power_of_two() && spec.cluster_size >= spec.bytes_per_sector);
        let cs = spec.cluster_size as u64;
        let total = spec.clusters;
        let img_len = (total * cs + spec.bytes_per_sector as u64) as usize;
        let mut v = SyntheticVolume {
            alloc: Allocator::new(total),
            image: vec![0u8; img_len],
            files: BTreeMap::new(),
            total_clusters: total,
            mft_runs: Vec::new(),
            mft_records: 0,
            mft_bitmap_runs: Vec::new(),
            mirror_lcn: 0,
            bitmap_runs: Vec::new(),
            logfile_runs: Vec::new(),
            slot_seq: BTreeMap::new(),
            stale: BTreeMap::new(),
            ext_owner: BTreeMap::new(),
            clock: T0,
            log_pos: 0,
            last_lsn: 0,
            security_next: 0x100,
            stale_index: BTreeMap::new(),
            batching: None,
            taken_below: 24,
            spec,
        };
        v.layout_system();
        v.materialize();
        v
    }

    pub(crate) fn tick(&mut self) -> u64 {
        self.clock += 10_000_000;
        self.clock
    }

    fn si(&self, attributes: u32) -> StdInfo {
        StdInfo {
            created: self.clock,
            modified: self.clock,
            mft_changed: self.clock,
            accessed: self.clock,
            attributes,
            max_versions: 0,
            version: 0,
            class_id: 0,
            owner_id: Some(0),
            security_id: Some(0x100),
            quota: Some(0),
            usn: Some(0),
        }
    }

    pub(crate) fn nr_stream(&mut self, name: &str, bytes: u64, how: Placement) -> StreamNode {
        let cs = self.cs();
        let n = bytes.div_ceil(cs);
        let runs = self.alloc.alloc(n, 0, how);
        StreamNode {
            kind: AttrType::DATA,
            name: utf16(name),
            flags: 0,
            data: StreamData::NonResident { runs, size: bytes, initialized: bytes },
        }
    }

    fn system_file(&mut self, record: u64, name: &str, streams: Vec<StreamNode>, is_dir: bool) {
        let seq = if record == 0 { 1 } else { record as u16 };
        let mut si = self.si(0x06);
        if is_dir {
            si.attributes = 0x06;
        }
        self.files.insert(
            record,
            FileNode {
                record,
                seq,
                is_dir,
                extra_header_flags: 0,
                names: vec![NameNode { parent: ROOT, ns: Namespace::Win32AndDos, name: name.into() }],
                si,
                streams,
                extra: Vec::new(),
                index_runs: Vec::new(),
                extensions: Vec::new(),
                attr_list_runs: Vec::new(),
            },
        );
    }

    fn layout_system(&mut self) {
        let cs = self.cs();
        let rs = self.rs() as u64;
        let total = self.total_clusters;
        // boot area
        let boot_clusters = 8192u64.div_ceil(cs);
        self.alloc.mark(0, boot_clusters);
        // $MFT
        let recs_per_cluster = (cs / rs).max(1);
        let mut records = self.spec.initial_mft_records.max(32);
        records = records.div_ceil(recs_per_cluster) * recs_per_cluster;
        let mft_clusters = (records * rs).div_ceil(cs);
        let mft_lcn = (16384 / cs).max(boot_clusters);
        self.alloc.mark(mft_lcn, mft_clusters);
        self.mft_runs = vec![Run::Mapped { vcn: 0, lcn: mft_lcn, len: mft_clusters }];
        self.mft_records = records;
        // $MFTMirr in the middle of the volume (after a $MFT that reaches past it)
        let mirror_clusters = (4 * rs).div_ceil(cs);
        self.mirror_lcn = (total / 2).max(mft_lcn + mft_clusters);
        self.alloc.mark(self.mirror_lcn, mirror_clusters);
        // $MFT:$BITMAP
        let bitmap_bytes = records.div_ceil(8).div_ceil(8) * 8;
        self.mft_bitmap_runs = self.alloc.alloc(bitmap_bytes.div_ceil(cs), 0, Placement::FirstFit);
        // $LogFile
        self.logfile_runs = self.alloc.alloc(self.spec.logfile_clusters, 0, Placement::FirstFit);
        let lf_lcn = self.logfile_runs[0].lcn().unwrap();
        let lf_off = (lf_lcn * cs) as usize;
        self.image[lf_off..lf_off + (self.spec.logfile_clusters * cs) as usize].fill(0xFF);
        // The two restart pages of a cleanly unmounted volume (what a VSS snapshot shows).
        let rp = self.restart_page(self.lsn_at(0), true);
        for page in [0usize, 4096] {
            self.image[lf_off + page..lf_off + page + 512].copy_from_slice(&rp);
        }
        // $Bitmap
        let bm_bytes = total.div_ceil(8).div_ceil(8) * 8;
        self.bitmap_runs = self.alloc.alloc(bm_bytes.div_ceil(cs), 0, Placement::FirstFit);
        // $AttrDef, $UpCase, $Secure:$SDS
        let attrdef = attrdef_table();
        let attrdef_s = self.nr_stream("", attrdef.len() as u64, Placement::FirstFit);
        self.write_stream(attrdef_s.runs(), 0, &attrdef);
        let upcase = UpCase::default_table().to_bytes();
        let upcase_s = self.nr_stream("", upcase.len() as u64, Placement::FirstFit);
        self.write_stream(upcase_s.runs(), 0, &upcase);
        let sds = self.nr_stream("$SDS", 4096, Placement::FirstFit);

        let mft_data = StreamNode {
            kind: AttrType::DATA,
            name: vec![],
            flags: 0,
            data: StreamData::NonResident {
                runs: self.mft_runs.clone(),
                size: records * rs,
                initialized: records * rs,
            },
        };
        let mft_bitmap = StreamNode {
            kind: AttrType::BITMAP,
            name: vec![],
            flags: 0,
            data: StreamData::NonResident { runs: self.mft_bitmap_runs.clone(), size: 8, initialized: 8 },
        };
        self.system_file(0, "$MFT", vec![mft_data, mft_bitmap], false);
        let mirr = StreamNode {
            kind: AttrType::DATA,
            name: vec![],
            flags: 0,
            data: StreamData::NonResident {
                runs: vec![Run::Mapped { vcn: 0, lcn: self.mirror_lcn, len: mirror_clusters }],
                size: 4 * rs,
                initialized: 4 * rs,
            },
        };
        self.system_file(1, "$MFTMirr", vec![mirr], false);
        let lf_bytes = self.spec.logfile_clusters * cs;
        let lf = StreamNode {
            kind: AttrType::DATA,
            name: vec![],
            flags: 0,
            data: StreamData::NonResident { runs: self.logfile_runs.clone(), size: lf_bytes, initialized: lf_bytes },
        };
        self.system_file(2, "$LogFile", vec![lf], false);
        self.system_file(
            3,
            "$Volume",
            vec![StreamNode { kind: AttrType::DATA, name: vec![], flags: 0, data: StreamData::Resident(vec![]) }],
            false,
        );
        let label: Vec<u8> = utf16("synthetic").iter().flat_map(|u| u.to_le_bytes()).collect();
        let mut volinfo = vec![0u8; 12];
        volinfo[8] = 3;
        volinfo[9] = 1;
        let vol = self.files.get_mut(&3).unwrap();
        vol.extra.push((AttrType::VOLUME_NAME, vec![], label));
        vol.extra.push((AttrType::VOLUME_INFORMATION, vec![], volinfo));
        self.system_file(4, "$AttrDef", vec![attrdef_s], false);
        self.system_file(ROOT, ".", vec![], true);
        let bitmap = StreamNode {
            kind: AttrType::DATA,
            name: vec![],
            flags: 0,
            data: StreamData::NonResident { runs: self.bitmap_runs.clone(), size: bm_bytes, initialized: bm_bytes },
        };
        self.system_file(6, "$Bitmap", vec![bitmap], false);
        let boot = StreamNode {
            kind: AttrType::DATA,
            name: vec![],
            flags: 0,
            data: StreamData::NonResident {
                runs: vec![Run::Mapped { vcn: 0, lcn: 0, len: boot_clusters }],
                size: 8192,
                initialized: 8192,
            },
        };
        self.system_file(7, "$Boot", vec![boot], false);
        let bad = StreamNode {
            kind: AttrType::DATA,
            name: utf16("$Bad"),
            flags: attr_flags::SPARSE,
            data: StreamData::NonResident {
                runs: vec![Run::Sparse { vcn: 0, len: total }],
                size: total * cs,
                initialized: 0,
            },
        };
        let empty = StreamNode { kind: AttrType::DATA, name: vec![], flags: 0, data: StreamData::Resident(vec![]) };
        self.system_file(8, "$BadClus", vec![empty, bad], false);
        self.system_file(9, "$Secure", vec![sds], false);
        let sec = self.files.get_mut(&9).unwrap();
        sec.extra_header_flags = header_flags::VIEW_INDEX;
        let empty_view = |collation: u32| {
            let node = ienc::node(&[ienc::entry(Frn::default(), &[], None, true)], false, None);
            ienc::root(0, collation, 4096, 1, &node)
        };
        sec.extra.push((AttrType::INDEX_ROOT, utf16("$SDH"), empty_view(0x12)));
        sec.extra.push((AttrType::INDEX_ROOT, utf16("$SII"), empty_view(0x10)));
        self.system_file(10, "$UpCase", vec![upcase_s], false);
        self.system_file(EXTEND, "$Extend", vec![], true);
        // Records 12..24 are reserved: never-used formatted slots.
    }

    // ---- record slots ----------------------------------------------------------------

    pub(crate) fn slot_free(&self, r: u64) -> bool {
        r >= 16 && !self.files.contains_key(&r) && !self.ext_owner.contains_key(&r)
    }

    /// Lowest free slot `>= min` (and, inside a batch, at or after the batch's next slot),
    /// growing the MFT if needed.
    pub(crate) fn alloc_slot(&mut self, min: u64) -> u64 {
        let asked = self.batching.map_or(min, |next| next.max(min));
        let hinted = (24..=self.taken_below).contains(&asked);
        let from = if asked >= 24 { asked.max(self.taken_below) } else { asked };
        loop {
            if let Some(r) = (from..self.mft_records).find(|&r| self.slot_free(r)) {
                if hinted {
                    self.taken_below = r;
                }
                if self.batching.is_some() {
                    self.batching = Some(r + 1);
                }
                return r;
            }
            self.grow_mft();
        }
    }

    /// Run the operations of `f` with one materialisation at the end instead of one per
    /// operation, so building a volume of many files costs time linear in their number.
    pub fn batch<R>(&mut self, f: impl FnOnce(&mut Self) -> R) -> R {
        self.batching = Some(24);
        let r = f(self);
        self.batching = None;
        self.materialize();
        r
    }

    /// After an operation: re-encode the image, unless inside [`batch`](Self::batch).
    pub(crate) fn changed(&mut self) {
        if self.batching.is_none() {
            self.materialize();
        }
    }

    pub(crate) fn take_seq(&mut self, r: u64) -> u16 {
        self.stale.remove(&r);
        *self.slot_seq.get(&r).unwrap_or(&1)
    }

    /// Free a slot: keep stale bytes and bump the sequence number.
    pub(crate) fn release_slot(&mut self, r: u64, seq: u16, last_bytes: Option<Vec<u8>>) {
        self.taken_below = self.taken_below.min(r.max(24));
        let next = if seq == u16::MAX { 1 } else { seq + 1 };
        self.slot_seq.insert(r, next);
        if let Some(mut b) = last_bytes {
            // apply fixup, clear in-use, set new seq, re-protect
            let _ = crate::encode::apply_fixup(&mut b);
            let flags = u16::from_le_bytes([b[0x16], b[0x17]]) & !header_flags::IN_USE;
            put_u16(&mut b, 0x16, flags);
            put_u16(&mut b, 0x10, next);
            protect(&mut b, 0x30, 1);
            self.stale.insert(r, b);
        }
    }

    pub(crate) fn grow_mft(&mut self) {
        let rs = self.rs() as u64;
        let cs = self.cs();
        let add = self.spec.mft_grow_records.max(cs / rs).div_ceil((cs / rs).max(1)) * (cs / rs).max(1);
        let clusters = (add * rs).div_ceil(cs);
        let vcn0 = self.mft_runs.last().map(|r| r.end_vcn()).unwrap_or(0);
        let runs = self.alloc.alloc(clusters, vcn0, self.spec.mft_grow_placement);
        self.mft_runs.extend(runs);
        self.mft_records += add;
        // grow $MFT:$BITMAP allocation if needed
        let need_bytes = self.mft_records.div_ceil(8).div_ceil(8) * 8;
        let have = crate::mapped_clusters(&self.mft_bitmap_runs) * cs;
        if need_bytes > have {
            let vcn = self.mft_bitmap_runs.last().map(|r| r.end_vcn()).unwrap_or(0);
            let more = self.alloc.alloc((need_bytes - have).div_ceil(cs), vcn, Placement::FirstFit);
            self.mft_bitmap_runs.extend(more);
        }
    }

    // ---- stream I/O -------------------------------------------------------------------

    /// Write bytes at logical offset of a stream described by `runs`.
    pub fn write_stream(&mut self, runs: &[Run], offset: u64, data: &[u8]) {
        let cs = self.cs();
        let mut pos = 0usize;
        while pos < data.len() {
            let logical = offset + pos as u64;
            let vcn = logical / cs;
            let r = runs.iter().find(|r| r.vcn() <= vcn && vcn < r.end_vcn()).expect("write outside stream runs");
            let lcn = r.lcn().expect("write into sparse run");
            let phys = (lcn + (vcn - r.vcn())) * cs + logical % cs;
            let run_end = (lcn + r.len()) * cs;
            let n = ((run_end - phys) as usize).min(data.len() - pos);
            self.image[phys as usize..phys as usize + n].copy_from_slice(&data[pos..pos + n]);
            pos += n;
        }
    }

    pub fn read_stream(&self, runs: &[Run], offset: u64, len: usize) -> Vec<u8> {
        let cs = self.cs();
        let mut out = vec![0u8; len];
        for (i, b) in out.iter_mut().enumerate() {
            let logical = offset + i as u64;
            let vcn = logical / cs;
            if let Some(r) = runs.iter().find(|r| r.vcn() <= vcn && vcn < r.end_vcn())
                && let Some(l) = r.lcn()
            {
                *b = self.image[((l + vcn - r.vcn()) * cs + logical % cs) as usize];
            }
        }
        out
    }

    // ---- materialisation ---------------------------------------------------------------

    fn record_capacity(&self) -> usize {
        let rs = self.rs();
        let first = (0x30 + 2 * (rs / 512 + 1)).div_ceil(8) * 8;
        rs - first - 8
    }

    fn file_name_value(&self, f: &FileNode, n: &NameNode) -> Vec<u8> {
        let parent_seq = self.files.get(&n.parent).map(|p| p.seq).unwrap_or(0);
        let (alloc, size) = match f.data() {
            Some(s) => match &s.data {
                StreamData::Resident(d) => ((d.len() as u64).div_ceil(8) * 8, d.len() as u64),
                StreamData::NonResident { runs, size, .. } => (crate::mapped_clusters(runs) * self.cs(), *size),
            },
            None => (0, 0),
        };
        FileName {
            parent: Frn::new(n.parent, parent_seq),
            created: f.si.created,
            modified: f.si.modified,
            mft_changed: f.si.mft_changed,
            accessed: f.si.accessed,
            allocated: if f.is_dir { 0 } else { alloc },
            size: if f.is_dir { 0 } else { size },
            attributes: f.si.attributes | if f.is_dir { 0x1000_0000 } else { 0 },
            reparse_or_ea: 0,
            namespace: n.ns,
            name: NtfsName::from(n.name.as_str()),
        }
        .encode()
    }

    /// Children index keys of directory `dir`, sorted by NTFS collation.
    fn index_keys(&self, dir: u64, children: &[(u64, usize)], up: &UpCase) -> Vec<(Vec<u8>, Frn)> {
        let mut keys: Vec<(Vec<u16>, Vec<u16>, Vec<u8>, Frn)> = Vec::new();
        for &(r, i) in children {
            let f = &self.files[&r];
            let n = &f.names[i];
            if f.record != dir {
                let units = utf16(&n.name);
                let upc: Vec<u16> = units.iter().map(|u| up.up(*u)).collect();
                let dup = self.stale_index.get(&r).unwrap_or(f);
                keys.push((upc, units, self.file_name_value(dup, n), f.frn()));
            }
        }
        keys.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
        keys.into_iter().map(|(_, _, k, f)| (k, f)).collect()
    }

    fn vcn_per_block(&self) -> u64 {
        // Index VCNs count clusters, or 512-byte units when blocks are smaller than a cluster.
        let ib = self.spec.index_block_size as u64;
        if ib >= self.cs() { ib / self.cs() } else { ib / 512 }
    }

    fn clusters_per_index_raw(&self) -> i8 {
        let ib = self.spec.index_block_size as u64;
        if ib >= self.cs() { (ib / self.cs()) as i8 } else { -(ib.trailing_zeros() as i8) }
    }

    /// Build the `$I30` B-tree for `dir` given the root capacity (bytes for the root
    /// node's entries). Allocates index clusters as needed.
    fn build_index(&mut self, dir: u64, children: &[(u64, usize)], root_cap: usize, up: &UpCase) -> IndexPlan {
        let keys = self.index_keys(dir, children, up);
        let ib = self.spec.index_block_size as usize;
        let vpb = self.vcn_per_block();
        // INDX: entries start at 0x18 + 0x28 (4 KiB block) — compute like the encoder
        let strides = ib / 512;
        let entries_start = (0x28 + 2 * (strides + 1)).div_ceil(8) * 8;
        let block_cap = ib - entries_start;
        let entry_len = |key: &[u8], child: bool| (0x10 + key.len()).div_ceil(8) * 8 + if child { 8 } else { 0 };
        let last_len = |child: bool| 0x10 + if child { 8 } else { 0 };

        type Item = (Vec<u8>, Frn, Option<u64>);
        let mut items: Vec<Item> = keys.into_iter().map(|(k, f)| (k, f, None)).collect();
        let mut tail: Option<u64> = None;
        let mut nodes: Vec<(Vec<Item>, Option<u64>)> = Vec::new();
        let encode_node = |items: &[Item], tail: Option<u64>| -> Vec<Vec<u8>> {
            let mut v: Vec<Vec<u8>> = items.iter().map(|(k, f, c)| ienc::entry(*f, k, *c, false)).collect();
            v.push(ienc::entry(Frn::default(), &[], tail, true));
            v
        };
        let root_entries;
        loop {
            let size: usize =
                items.iter().map(|(k, _, c)| entry_len(k, c.is_some())).sum::<usize>() + last_len(tail.is_some());
            if size <= root_cap {
                root_entries = encode_node(&items, tail);
                break;
            }
            // group into blocks
            let mut seps: Vec<Item> = Vec::new();
            let mut cur: Vec<Item> = Vec::new();
            let mut cur_size = 0usize;
            let base = nodes.len() as u64;
            let mut produced = 0u64;
            for it in items.drain(..) {
                let l = entry_len(&it.0, it.2.is_some());
                // reserve room for an END entry with a child pointer
                if cur_size + l + last_len(true) <= block_cap {
                    cur_size += l;
                    cur.push(it);
                } else {
                    nodes.push((std::mem::take(&mut cur), it.2));
                    seps.push((it.0, it.1, Some((base + produced) * vpb)));
                    produced += 1;
                    cur_size = 0;
                }
            }
            nodes.push((cur, tail));
            tail = Some((base + produced) * vpb);
            items = seps;
        }
        let has_children = !nodes.is_empty();
        let node = ienc::node(&root_entries, has_children, None);
        let root_value = ienc::root(0x30, 1, self.spec.index_block_size, self.clusters_per_index_raw(), &node);
        // allocation
        let cs = self.cs();
        let need_clusters = (nodes.len() as u64 * ib as u64).div_ceil(cs);
        let f = self.files.get(&dir).unwrap();
        let have = crate::mapped_clusters(&f.index_runs);
        if need_clusters > have {
            let vcn0 = f.index_runs.last().map(|r| r.end_vcn()).unwrap_or(0);
            let more = self.alloc.alloc(need_clusters - have, vcn0, Placement::FirstFit);
            self.files.get_mut(&dir).unwrap().index_runs.extend(more);
        }
        let blocks: Vec<Vec<u8>> = nodes
            .iter()
            .enumerate()
            .map(|(i, (items, tail))| {
                let n = ienc::node(&encode_node(items, *tail), tail.is_some(), None);
                ienc::block(i as u64 * vpb, &n, ib, 1).expect("index block overflow")
            })
            .collect();
        let alloc_clusters = crate::mapped_clusters(&self.files[&dir].index_runs);
        let alloc_blocks = (alloc_clusters * cs) / ib as u64;
        let mut bitmap = vec![0u8; (alloc_blocks.div_ceil(8).div_ceil(8) * 8).max(8) as usize];
        for i in 0..blocks.len() {
            bitmap[i / 8] |= 1 << (i % 8);
        }
        IndexPlan { root_value, blocks, bitmap }
    }

    /// Non-index attributes of a file (sorted).
    fn attr_specs(&self, f: &FileNode) -> Vec<AttrSpec> {
        let mut v = Vec::new();
        v.push(AttrSpec {
            kind: AttrType::STANDARD_INFORMATION,
            name: vec![],
            flags: 0,
            body: AttrBody::Resident { value: f.si.encode(), indexed: false },
        });
        for n in &f.names {
            v.push(AttrSpec {
                kind: AttrType::FILE_NAME,
                name: vec![],
                flags: 0,
                body: AttrBody::Resident { value: self.file_name_value(f, n), indexed: true },
            });
        }
        let streams = f.streams.clone();
        for s in &streams {
            let body = match &s.data {
                StreamData::Resident(d) => AttrBody::Resident { value: d.clone(), indexed: false },
                StreamData::NonResident { runs, size, initialized } => {
                    let end = runs.last().map(|r| r.end_vcn()).unwrap_or(0);
                    AttrBody::NonResident {
                        lowest_vcn: 0,
                        highest_vcn: end as i64 - 1,
                        allocated: end * self.cs(),
                        size: *size,
                        initialized: *initialized,
                        runs: runs.clone(),
                    }
                }
            };
            v.push(AttrSpec { kind: s.kind, name: s.name.clone(), flags: s.flags, body });
        }
        for (k, n, val) in &f.extra {
            v.push(AttrSpec {
                kind: *k,
                name: n.clone(),
                flags: 0,
                body: AttrBody::Resident { value: val.clone(), indexed: false },
            });
        }
        v
    }

    fn index_specs(&self, f: &FileNode, plan: &IndexPlan) -> Vec<AttrSpec> {
        let i30 = utf16("$I30");
        let mut v = vec![AttrSpec {
            kind: AttrType::INDEX_ROOT,
            name: i30.clone(),
            flags: 0,
            body: AttrBody::Resident { value: plan.root_value.clone(), indexed: false },
        }];
        if !f.index_runs.is_empty() {
            let end = f.index_runs.last().unwrap().end_vcn();
            let bytes = end * self.cs();
            v.push(AttrSpec {
                kind: AttrType::INDEX_ALLOCATION,
                name: i30.clone(),
                flags: 0,
                body: AttrBody::NonResident {
                    lowest_vcn: 0,
                    highest_vcn: end as i64 - 1,
                    allocated: bytes,
                    size: bytes,
                    initialized: bytes,
                    runs: f.index_runs.clone(),
                },
            });
            v.push(AttrSpec {
                kind: AttrType::BITMAP,
                name: i30,
                flags: 0,
                body: AttrBody::Resident { value: plan.bitmap.clone(), indexed: false },
            });
        }
        v
    }

    /// Split a non-resident attribute into fragments whose encodings fit `cap` bytes.
    fn fragments(a: &AttrSpec, cap: usize) -> Vec<AttrSpec> {
        let AttrBody::NonResident { allocated, size, initialized, runs, .. } = &a.body else { return vec![a.clone()] };
        if a.encode(0).len() <= cap {
            return vec![a.clone()];
        }
        let mut out = Vec::new();
        let mut start = 0usize;
        while start < runs.len() {
            let mut end = start + 1;
            loop {
                if end >= runs.len() {
                    break;
                }
                let trial = Self::frag(a, &runs[start..=end], *allocated, *size, *initialized);
                if trial.encode(0).len() > cap {
                    break;
                }
                end += 1;
            }
            out.push(Self::frag(a, &runs[start..end], *allocated, *size, *initialized));
            start = end;
        }
        out
    }

    fn frag(a: &AttrSpec, runs: &[Run], allocated: u64, size: u64, initialized: u64) -> AttrSpec {
        let lo = runs[0].vcn();
        let hi = runs.last().unwrap().end_vcn() as i64 - 1;
        AttrSpec {
            kind: a.kind,
            name: a.name.clone(),
            flags: a.flags,
            body: AttrBody::NonResident {
                lowest_vcn: lo,
                highest_vcn: hi,
                allocated,
                size,
                initialized,
                runs: runs.to_vec(),
            },
        }
    }

    fn header_flags(f: &FileNode) -> u16 {
        header_flags::IN_USE | if f.is_dir { header_flags::DIRECTORY } else { 0 } | f.extra_header_flags
    }

    fn encode_record(&self, number: u64, seq: u16, flags: u16, base: Frn, attrs: &[Vec<u8>]) -> Vec<u8> {
        RecordBuilder {
            seq,
            link_count: 0,
            flags,
            base_record: base,
            lsn: 0,
            usn: 1,
            attributes: attrs.to_vec(),
            next_attr_id: attrs.len() as u16,
        }
        .encode(number, self.rs())
        .unwrap_or_else(|| panic!("record {number} overflow"))
    }

    /// Encode one file into base (+ extension) records. May allocate extension records,
    /// attribute-list clusters and grow the MFT.
    fn encode_file(
        &mut self,
        record: u64,
        plan: Option<&IndexPlan>,
        out: &mut BTreeMap<u64, Vec<u8>>,
        al_data: &mut Vec<(Vec<Run>, Vec<u8>)>,
    ) {
        let f = self.files[&record].clone();
        let cap = self.record_capacity();
        let mut specs = self.attr_specs(&f);
        if let Some(p) = plan {
            specs.extend(self.index_specs(&f, p));
        }
        specs.sort_by(|a, b| (a.kind, &a.name, a.lowest_vcn()).cmp(&(b.kind, &b.name, b.lowest_vcn())));
        let link_count = f.names.iter().filter(|n| n.ns != Namespace::Dos).count() as u16;
        let total: usize = specs.iter().map(|s| s.encode(0).len()).sum();
        let mut base_flags = Self::header_flags(&f);
        if total <= cap {
            let enc: Vec<Vec<u8>> = specs.iter().enumerate().map(|(i, s)| s.encode(i as u16)).collect();
            let mut b = self.encode_record(record, f.seq, base_flags, Frn::default(), &enc);
            put_u16(&mut b, 0x12, link_count);
            reprotect(&mut b);
            out.insert(record, b);
            self.set_extensions(record, Vec::new());
            self.set_attr_list_runs(record, Vec::new());
            return;
        }
        // Attribute list needed.
        base_flags |= 0;
        let ext_cap = cap;
        let mut base_specs: Vec<AttrSpec> = Vec::new();
        let mut rest: Vec<AttrSpec> = Vec::new();
        for s in specs {
            match s.kind {
                AttrType::STANDARD_INFORMATION | AttrType::FILE_NAME | AttrType::INDEX_ROOT => base_specs.push(s),
                // $MFT: the fragment starting at VCN 0 must stay in record 0 (bootstrap).
                AttrType::DATA if record == 0 && s.name.is_empty() => {
                    let mut frags = Self::fragments(&s, ext_cap / 2).into_iter();
                    base_specs.extend(frags.next());
                    rest.extend(frags);
                }
                _ => rest.extend(Self::fragments(&s, ext_cap - 8)),
            }
        }
        // Pack the rest into extension records.
        let mut packs: Vec<Vec<AttrSpec>> = Vec::new();
        let mut cur: Vec<AttrSpec> = Vec::new();
        let mut cur_size = 0usize;
        for s in rest {
            let l = s.encode(0).len();
            if cur_size + l > ext_cap && !cur.is_empty() {
                packs.push(std::mem::take(&mut cur));
                cur_size = 0;
            }
            cur_size += l;
            cur.push(s);
        }
        if !cur.is_empty() {
            packs.push(cur);
        }
        let min_slot = if record < 24 { 16 } else { 24 };
        let mut exts = f.extensions.clone();
        while exts.len() < packs.len() {
            let r = self.alloc_slot(min_slot);
            let s = self.take_seq(r);
            self.slot_seq.insert(r, s);
            self.ext_owner.insert(r, record);
            exts.push(r);
        }
        for extra in exts.split_off(packs.len()) {
            let seq = *self.slot_seq.get(&extra).unwrap_or(&1);
            self.ext_owner.remove(&extra);
            let last = out.get(&extra).cloned();
            self.release_slot(extra, seq, last);
        }
        let base_frn = Frn::new(record, f.seq);
        // attribute list entries
        let mut entries: Vec<AttrListEntry> = Vec::new();
        for (i, s) in base_specs.iter().enumerate() {
            // ids: $SI 0, then others; the $ATTRIBUTE_LIST itself gets id = len
            entries.push(AttrListEntry {
                kind: s.kind,
                name: NtfsName(s.name.clone()),
                starting_vcn: s.lowest_vcn(),
                segment: base_frn,
                attr_id: i as u16,
            });
        }
        for (pi, pack) in packs.iter().enumerate() {
            let r = exts[pi];
            let seq = *self.slot_seq.get(&r).unwrap_or(&1);
            for (i, s) in pack.iter().enumerate() {
                entries.push(AttrListEntry {
                    kind: s.kind,
                    name: NtfsName(s.name.clone()),
                    starting_vcn: s.lowest_vcn(),
                    segment: Frn::new(r, seq),
                    attr_id: i as u16,
                });
            }
        }
        entries.sort_by(|a, b| (a.kind, &a.name, a.starting_vcn).cmp(&(b.kind, &b.name, b.starting_vcn)));
        let list = encode_attr_list(&entries);
        let base_size: usize = base_specs.iter().map(|s| s.encode(0).len()).sum();
        let al_id = base_specs.len() as u16;
        let resident_al = encode_resident(AttrType::ATTRIBUTE_LIST, &[], al_id, 0, &list, false);
        let al_attr = if base_size + resident_al.len() <= cap {
            self.set_attr_list_runs(record, Vec::new());
            resident_al
        } else {
            let cs = self.cs();
            let need = (list.len() as u64).div_ceil(cs);
            let mut runs = f.attr_list_runs.clone();
            let have = crate::mapped_clusters(&runs);
            if need > have {
                let vcn0 = runs.last().map(|r| r.end_vcn()).unwrap_or(0);
                runs.extend(self.alloc.alloc(need - have, vcn0, Placement::FirstFit));
            }
            self.set_attr_list_runs(record, runs.clone());
            let end = runs.last().unwrap().end_vcn();
            al_data.push((runs.clone(), list.clone()));
            encode_non_resident(&NonResidentSpec {
                kind: AttrType::ATTRIBUTE_LIST,
                name: &[],
                id: al_id,
                flags: 0,
                lowest_vcn: 0,
                highest_vcn: end as i64 - 1,
                compression_unit: 0,
                allocated: end * cs,
                size: list.len() as u64,
                initialized: list.len() as u64,
                compressed_size: None,
                runs: &runs,
            })
        };
        // base record: specs in type order with the list after $SI
        let mut base_enc: Vec<(AttrType, Vec<u8>)> =
            base_specs.iter().enumerate().map(|(i, s)| (s.kind, s.encode(i as u16))).collect();
        base_enc.push((AttrType::ATTRIBUTE_LIST, al_attr));
        base_enc.sort_by_key(|(k, _)| *k);
        let enc: Vec<Vec<u8>> = base_enc.into_iter().map(|(_, b)| b).collect();
        let mut b = self.encode_record(record, f.seq, base_flags, Frn::default(), &enc);
        put_u16(&mut b, 0x12, link_count);
        reprotect(&mut b);
        out.insert(record, b);
        for (pi, pack) in packs.iter().enumerate() {
            let r = exts[pi];
            let seq = *self.slot_seq.get(&r).unwrap_or(&1);
            let enc: Vec<Vec<u8>> = pack.iter().enumerate().map(|(i, s)| s.encode(i as u16)).collect();
            let e = self.encode_record(r, seq, header_flags::IN_USE, base_frn, &enc);
            out.insert(r, e);
        }
        self.set_extensions(record, exts);
    }

    fn set_extensions(&mut self, record: u64, exts: Vec<u64>) {
        let old = std::mem::take(&mut self.files.get_mut(&record).unwrap().extensions);
        for r in old.iter().filter(|r| !exts.contains(r)) {
            let seq = *self.slot_seq.get(r).unwrap_or(&1);
            self.ext_owner.remove(r);
            self.release_slot(*r, seq, None);
        }
        self.files.get_mut(&record).unwrap().extensions = exts;
    }

    fn set_attr_list_runs(&mut self, record: u64, runs: Vec<Run>) {
        let f = self.files.get_mut(&record).unwrap();
        if runs.is_empty() && !f.attr_list_runs.is_empty() {
            let old = std::mem::take(&mut f.attr_list_runs);
            self.alloc.free_runs(&old);
        } else if !runs.is_empty() {
            f.attr_list_runs = runs;
        }
    }

    /// Re-encode every metadata structure into the image.
    pub fn materialize(&mut self) {
        let up = UpCase::default_table();
        let (records, al_data, plans) = loop {
            // keep a margin of free slots so encoding does not need to grow the MFT
            while (24..self.mft_records).filter(|&r| self.slot_free(r)).count() < 8 {
                self.grow_mft();
            }
            let before = (self.mft_records, self.mft_runs.clone());
            // directory indexes
            let dirs: Vec<u64> = self.files.values().filter(|f| f.is_dir).map(|f| f.record).collect();
            let mut plans: BTreeMap<u64, IndexPlan> = BTreeMap::new();
            let mut children: BTreeMap<u64, Vec<(u64, usize)>> = BTreeMap::new();
            for f in self.files.values() {
                for (i, n) in f.names.iter().enumerate() {
                    children.entry(n.parent).or_default().push((f.record, i));
                }
            }
            for d in dirs {
                let f = self.files[&d].clone();
                let other: usize = self.attr_specs(&f).iter().map(|s| s.encode(0).len()).sum();
                // room for $INDEX_ALLOCATION (with a few runs) and $BITMAP
                let reserve = 0x80 + 0x28;
                let root_cap = self.record_capacity().saturating_sub(other + 0x20 + 0x20 + reserve);
                let kids = children.remove(&d).unwrap_or_default();
                plans.insert(d, self.build_index(d, &kids, root_cap, &up));
            }
            // update $MFT data stream from the current MFT layout
            self.sync_mft_streams();
            let mut out = BTreeMap::new();
            let mut al = Vec::new();
            let recs: Vec<u64> = self.files.keys().copied().collect();
            for r in recs {
                let plan = plans.get(&r);
                self.encode_file(r, plan, &mut out, &mut al);
            }
            if (self.mft_records, self.mft_runs.clone()) == before {
                break (out, al, plans);
            }
        };
        self.write_all(records, al_data, plans);
    }

    fn sync_mft_streams(&mut self) {
        let rs = self.rs() as u64;
        let runs = self.mft_runs.clone();
        let size = self.mft_records * rs;
        let bm_runs = self.mft_bitmap_runs.clone();
        let bm_size = self.mft_records.div_ceil(8).div_ceil(8) * 8;
        let f = self.files.get_mut(&0).unwrap();
        for s in f.streams.iter_mut() {
            if s.kind == AttrType::DATA && s.name.is_empty() {
                s.data = StreamData::NonResident { runs: runs.clone(), size, initialized: size };
            } else if s.kind == AttrType::BITMAP {
                s.data = StreamData::NonResident { runs: bm_runs.clone(), size: bm_size, initialized: bm_size };
            }
        }
    }

    fn empty_record(&self, number: u64) -> Vec<u8> {
        let seq = *self.slot_seq.get(&number).unwrap_or(&0);
        let mut b = self.encode_record(number, seq, 0, Frn::default(), &[]);
        reprotect(&mut b);
        b
    }

    fn write_all(
        &mut self,
        records: BTreeMap<u64, Vec<u8>>,
        al_data: Vec<(Vec<Run>, Vec<u8>)>,
        plans: BTreeMap<u64, IndexPlan>,
    ) {
        let cs = self.cs();
        let rs = self.rs();
        let bps = self.spec.bytes_per_sector;
        // boot sectors
        let spc_raw = self.spc() as u8;
        let rec_raw = -(self.spec.record_size.trailing_zeros() as i8);
        let mft_lcn = self.mft_runs[0].lcn().unwrap();
        let boot = encode_boot_sector(&BootSpec {
            bytes_per_sector: bps,
            sectors_per_cluster_raw: spc_raw,
            total_sectors: self.total_sectors(),
            mft_lcn,
            mftmirr_lcn: self.mirror_lcn,
            clusters_per_record_raw: if self.spec.record_size as u64 >= cs {
                (self.spec.record_size as u64 / cs) as i8
            } else {
                rec_raw
            },
            clusters_per_index_raw: self.clusters_per_index_raw(),
            serial: self.spec.serial,
        });
        self.image[..512].copy_from_slice(&boot);
        let backup = (self.total_sectors() * bps as u64) as usize;
        if self.image.len() < backup + bps as usize {
            self.image.resize(backup + bps as usize, 0);
        }
        self.image[backup..backup + 512].copy_from_slice(&boot);
        // records
        let mut mft = vec![0u8; self.mft_records as usize * rs];
        let mut in_use = vec![0u8; (self.mft_records.div_ceil(8).div_ceil(8) * 8) as usize];
        for r in 0..self.mft_records {
            let bytes = match records.get(&r) {
                Some(b) => {
                    in_use[(r / 8) as usize] |= 1 << (r % 8);
                    b.clone()
                }
                None => self.stale.get(&r).cloned().unwrap_or_else(|| self.empty_record(r)),
            };
            mft[r as usize * rs..(r as usize + 1) * rs].copy_from_slice(&bytes);
        }
        let mft_runs = self.mft_runs.clone();
        // Index blocks to write, then LSNs: a record or block whose content changed is
        // stamped with a new log page's LSN; the others keep theirs.
        let mut blocks = Vec::new();
        for (d, plan) in &plans {
            let runs = self.files[d].index_runs.clone();
            for (i, b) in plan.blocks.iter().enumerate() {
                let off = i as u64 * self.spec.index_block_size as u64;
                let old = self.read_stream(&runs, off, b.len());
                blocks.push((runs.clone(), off, b.clone(), old));
            }
        }
        let old_mft = self.read_stream(&mft_runs, 0, mft.len());
        let same = |new: &[u8], old: &[u8]| new[..8] == old[..8] && new[16..] == old[16..];
        let changed = mft.chunks(rs).zip(old_mft.chunks(rs)).any(|(n, o)| !same(n, o))
            || blocks.iter().any(|(_, _, n, o)| !same(n, o));
        if changed {
            self.touch_logfile();
        }
        let stamp = self.last_lsn;
        let restamp = |new: &mut [u8], old: &[u8]| {
            let lsn = if same(new, old) { old[8..16].to_vec() } else { stamp.to_le_bytes().to_vec() };
            new[8..16].copy_from_slice(&lsn);
        };
        for (n, o) in mft.chunks_mut(rs).zip(old_mft.chunks(rs)) {
            restamp(n, o);
        }
        for (_, _, n, o) in blocks.iter_mut() {
            restamp(n, o);
        }
        self.write_stream(&mft_runs, 0, &mft);
        let mirror = mft[..4 * rs].to_vec();
        let mirror_runs = vec![Run::Mapped { vcn: 0, lcn: self.mirror_lcn, len: (4 * rs as u64).div_ceil(cs) }];
        self.write_stream(&mirror_runs, 0, &mirror);
        let bm_runs = self.mft_bitmap_runs.clone();
        self.write_stream(&bm_runs, 0, &in_use);
        // directory index blocks
        for (runs, off, b, _) in blocks {
            self.write_stream(&runs, off, &b);
        }
        // non-resident attribute lists
        for (runs, data) in al_data {
            self.write_stream(&runs, 0, &data);
        }
        // $Bitmap last: it reflects every allocation made above
        let bm = self.alloc.bitmap.to_lsb_bytes();
        let mut padded = bm.clone();
        padded.resize((self.total_clusters.div_ceil(8).div_ceil(8) * 8) as usize, 0);
        let runs = self.bitmap_runs.clone();
        self.write_stream(&runs, 0, &padded);
        self.write_restart(true);
    }

    /// Bytes of the log past the two restart pages, in whole pages.
    fn log_span(&self) -> u64 {
        (self.spec.logfile_clusters * self.cs()).saturating_sub(8192) / 4096 * 4096
    }

    /// The LSN of log position `pos` (bytes of record pages written before it): the wrap
    /// count (from 1) above [`LOG_SEQ_BITS`], the byte offset in the log divided by 8 below.
    pub fn lsn_at(&self, pos: u64) -> u64 {
        let span = self.log_span().max(4096);
        let (seq, off) = (1 + pos / span, 8192 + pos % span);
        (seq << (64 - LOG_SEQ_BITS)) | (off >> 3)
    }

    /// The log position the restart pages give: past the last page written.
    pub fn restart_lsn(&self) -> u64 {
        self.lsn_at(self.log_pos)
    }

    /// Write both restart pages: the log at [`Self::restart_lsn`], `clean` or not.
    pub fn write_restart(&mut self, clean: bool) {
        if self.logfile_runs.is_empty() || self.spec.logfile_clusters * self.cs() < 8192 {
            return;
        }
        let rp = self.restart_page(self.restart_lsn(), clean);
        let runs = self.logfile_runs.clone();
        for page in [0u64, 4096] {
            self.write_stream(&runs, page, &rp);
        }
    }

    /// The first sector of a restart page saying the log is at `current_lsn`.
    pub fn restart_page(&self, current_lsn: u64, clean: bool) -> [u8; 512] {
        let mut p = [0u8; 512];
        p[0..4].copy_from_slice(b"RSTR");
        p[0x10..0x14].copy_from_slice(&4096u32.to_le_bytes());
        p[0x14..0x18].copy_from_slice(&4096u32.to_le_bytes());
        p[0x18..0x1A].copy_from_slice(&0x30u16.to_le_bytes());
        p[0x30..0x38].copy_from_slice(&current_lsn.to_le_bytes());
        p[0x3E..0x40].copy_from_slice(&(if clean { 0x0002u16 } else { 0 }).to_le_bytes());
        p[0x40..0x44].copy_from_slice(&LOG_SEQ_BITS.to_le_bytes());
        p[0x48..0x50].copy_from_slice(&(self.spec.logfile_clusters * self.cs()).to_le_bytes());
        p
    }

    /// Record an operation in `$LogFile` (real NTFS logs every metadata change): a record
    /// page at the next position, stamped with its LSN.
    pub(crate) fn touch_logfile(&mut self) {
        if !self.spec.touch_logfile {
            return;
        }
        let span = self.log_span();
        if span == 0 {
            return;
        }
        // The LSN of a record in the page, past its start.
        let lsn = self.lsn_at(self.log_pos) + 1;
        let mut page = vec![0u8; 4096];
        page[0..4].copy_from_slice(b"RCRD");
        page[4..6].copy_from_slice(&0x28u16.to_le_bytes());
        page[6..8].copy_from_slice(&9u16.to_le_bytes());
        page[0x08..0x10].copy_from_slice(&lsn.to_le_bytes());
        page[0x14..0x18].copy_from_slice(&0x0001_0001u32.to_le_bytes());
        page[0x20..0x28].copy_from_slice(&lsn.to_le_bytes());
        protect(&mut page, 0x28, (self.log_pos / span) as u16 + 1);
        let off = 8192 + self.log_pos % span;
        let runs = self.logfile_runs.clone();
        self.write_stream(&runs, off, &page);
        self.log_pos += 4096;
        self.last_lsn = lsn;
    }

    pub fn source(&self) -> fs_inspect_io::MemSource {
        fs_inspect_io::MemSource::new(self.image.clone())
    }

    pub fn open(&self) -> crate::NtfsVolume {
        crate::NtfsVolume::open(std::sync::Arc::new(self.source())).expect("synthetic volume must open")
    }

    pub fn used_bitmap(&self) -> crate::synth::bitmap::Bitmap {
        self.alloc.bitmap.clone()
    }

    /// Cluster runs `(lcn, count)` of the unnamed `$DATA` of the root files a backup always
    /// leaves out (pagefile.sys, hiberfil.sys, swapfile.sys, DumpStack.log.tmp; any case).
    pub fn windows_default_runs(&self) -> Vec<(u64, u64)> {
        const NAMES: [&str; 4] = ["pagefile.sys", "hiberfil.sys", "swapfile.sys", "dumpstack.log.tmp"];
        self.files
            .values()
            .filter(|f| {
                !f.is_dir && f.names.iter().any(|n| n.parent == ROOT && NAMES.contains(&n.name.to_lowercase().as_str()))
            })
            .filter_map(|f| f.data())
            .flat_map(|s| s.runs().iter().filter_map(|r| r.lcn().map(|l| (l, r.len()))))
            .collect()
    }

    pub fn file(&self, record: u64) -> &FileNode {
        &self.files[&record]
    }

    /// Records of user files (not system / `$Extend`).
    pub fn user_files(&self) -> Vec<u64> {
        let extend_children: BTreeSet<u64> =
            self.files.values().filter(|f| f.names.iter().any(|n| n.parent == EXTEND)).map(|f| f.record).collect();
        self.files.keys().copied().filter(|r| *r >= 24 && !extend_children.contains(r)).collect()
    }
}

fn reprotect(b: &mut [u8]) {
    let _ = crate::encode::apply_fixup(b);
    protect(b, 0x30, 1);
}

/// Standard `$AttrDef` table.
fn attrdef_table() -> Vec<u8> {
    let defs: &[(&str, u32, u32, u64, i64)] = &[
        ("$STANDARD_INFORMATION", 0x10, 0x40, 0x30, 0x48),
        ("$ATTRIBUTE_LIST", 0x20, 0x80, 0, -1),
        ("$FILE_NAME", 0x30, 0x42, 0x44, 0x242),
        ("$OBJECT_ID", 0x40, 0x40, 0, 0x100),
        ("$SECURITY_DESCRIPTOR", 0x50, 0x80, 0, -1),
        ("$VOLUME_NAME", 0x60, 0x40, 2, 0x100),
        ("$VOLUME_INFORMATION", 0x70, 0x40, 0xC, 0xC),
        ("$DATA", 0x80, 0x00, 0, -1),
        ("$INDEX_ROOT", 0x90, 0x40, 0, -1),
        ("$INDEX_ALLOCATION", 0xA0, 0x80, 0, -1),
        ("$BITMAP", 0xB0, 0x80, 0, -1),
        ("$REPARSE_POINT", 0xC0, 0x80, 0, 0x4000),
        ("$EA_INFORMATION", 0xD0, 0x40, 8, 8),
        ("$EA", 0xE0, 0x00, 0, 0x10000),
        ("$LOGGED_UTILITY_STREAM", 0x100, 0x80, 0, 0x10000),
    ];
    let mut out = vec![0u8; 0xA00];
    for (i, (name, ty, flags, min, max)) in defs.iter().enumerate() {
        let o = i * 0xA0;
        for (j, u) in name.encode_utf16().enumerate() {
            put_u16(&mut out, o + j * 2, u);
        }
        put_u32(&mut out, o + 0x80, *ty);
        put_u32(&mut out, o + 0x88, if *ty == 0x30 { 1 } else { 0 });
        put_u32(&mut out, o + 0x8C, *flags);
        put_u64(&mut out, o + 0x90, *min);
        put_u64(&mut out, o + 0x98, *max as u64);
    }
    out
}
