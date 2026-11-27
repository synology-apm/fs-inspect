//! Verifying a volume's file system (`fs_inspect_volume_verify`) and what holds the volumes
//! of a set of disks (`fs_inspect_disks_verify`).

use crate::cancel::FsInspectCancel;
use crate::support::*;
use crate::*;
use fs_inspect::verify::{FindingSite, MAX_FINDINGS, VerifyOptions, VerifyReport};
use std::ffi::{CString, c_char};

/// `fs_inspect_verify_options.flags`: read every file's content too (data checksums where the
/// file system keeps them, read errors elsewhere).
pub const FS_INSPECT_VERIFY_FLAG_DATA: u32 = 1 << 0;
const VERIFY_FLAGS: u32 = FS_INSPECT_VERIFY_FLAG_DATA;

/// How a volume is verified; all-zero is the default.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsInspectVerifyOptions {
    /// `sizeof` this struct in the caller's header (set it before the call).
    pub struct_size: usize,
    /// `FS_INSPECT_VERIFY_FLAG_*` bits.
    pub flags: u32,
    /// Set to 0.
    pub reserved: u32,
    /// The most findings kept (0: 10 000). Findings past it are only counted (`dropped`).
    pub max_findings: u64,
}

crate::sized_struct!(FsInspectVerifyOptions, max_findings);

impl Default for FsInspectVerifyOptions {
    fn default() -> Self {
        FsInspectVerifyOptions { struct_size: size_of::<Self>(), flags: 0, reserved: 0, max_findings: 0 }
    }
}

/// Opaque handle: what a verification found. Its strings stay valid until it is freed.
#[derive(Debug)]
pub struct FsInspectVerifyReport {
    report: VerifyReport,
    /// Each finding's structure and message, NUL terminated.
    findings: Vec<(CString, CString)>,
    /// The kinds of structure checked, with their counts.
    checked: Vec<(CString, fs_inspect::verify::Counts)>,
    /// Each kind of structure not covered, its name and which of them.
    not_covered: Vec<(fs_inspect::verify::StructureKind, CString, CString)>,
    stopped: CString,
}

impl FsInspectVerifyReport {
    fn new(report: VerifyReport) -> Self {
        FsInspectVerifyReport {
            findings: report
                .findings
                .iter()
                .map(|f| (cstring(&f.structure.to_string()), cstring(&f.message)))
                .collect(),
            checked: report.checked.iter().map(|(k, c)| (cstring(&k.to_string()), *c)).collect(),
            not_covered: report
                .not_covered
                .iter()
                .map(|(k, which)| (*k, cstring(&k.to_string()), cstring(which)))
                .collect(),
            stopped: cstring(&report.stopped.as_ref().map_or_else(String::new, |s| s.error.to_string())),
            report,
        }
    }
}

/// What a verification found, in all. Its lists: `fs_inspect_verify_report_finding_count`,
/// `_checked_count`, `_not_covered_count`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsInspectVerifySummary {
    /// `sizeof` this struct in the caller's header (set it before the call).
    pub struct_size: usize,
    /// Nothing is damaged. A wrong copy beside a right one counts as `recovered` and passes.
    pub passed: bool,
    pub reserved: [u8; 3],
    /// What stopped it part way (`FS_INSPECT_E_CANCELLED`, `_IO`, ...); `FS_INSPECT_OK` when it
    /// went to its end.
    pub stopped_status: FsInspectStatus,
    /// Why it stopped, UTF-8 ("" when it went to its end); valid until the report is freed.
    pub stopped_message: *const c_char,
    /// Structures (or data) without a right copy.
    pub damaged: u64,
    /// Wrong copies of structures that have a right copy.
    pub recovered: u64,
    /// Findings not kept (past `fs_inspect_verify_options.max_findings`).
    pub dropped: u64,
}

crate::sized_struct!(FsInspectVerifySummary, dropped);

/// One finding of a verification: a structure (or data) whose check failed.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsInspectFinding {
    /// `sizeof` this struct in the caller's header (set it before the call).
    pub struct_size: usize,
    /// `FS_INSPECT_FINDING_*`.
    pub kind: u32,
    /// `FS_INSPECT_OUTCOME_*`.
    pub outcome: u32,
    /// The kind of structure ("superblock", "inode", ...), UTF-8; valid until the report is freed.
    pub structure: *const c_char,
    /// `offset` is set: where the structure is, in bytes of the volume (or disk).
    pub has_offset: bool,
    /// `id` is set: the structure's own number (an inode, a group, an object id).
    pub has_id: bool,
    pub reserved: [u8; 6],
    pub offset: u64,
    pub id: u64,
    /// What is wrong, UTF-8; valid until the report is freed.
    pub message: *const c_char,
    /// What the structure is in, when it is not one of the verified volume's own structures:
    /// `FS_INSPECT_FINDING_SITE_*`, or 0 for none. The site's own field is set: `device`,
    /// `volume` (an index in the set's volume list) or `node`; the others are 0.
    pub site_kind: u32,
    pub volume: u32,
    pub device: crate::disks::FsInspectDeviceRef,
    pub node: FsInspectNode,
}

crate::sized_struct!(FsInspectFinding, node);

/// One kind of structure a verification checked and how much of it.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsInspectVerifyChecked {
    /// `sizeof` this struct in the caller's header (set it before the call).
    pub struct_size: usize,
    /// The kind of structure, UTF-8; valid until the report is freed.
    pub name: *const c_char,
    /// How many were checked, and their bytes.
    pub structures: u64,
    pub bytes: u64,
}

crate::sized_struct!(FsInspectVerifyChecked, bytes);

/// One kind of structure a verification does not cover, and which of them.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsInspectVerifyNotCovered {
    /// `sizeof` this struct in the caller's header (set it before the call).
    pub struct_size: usize,
    /// `FS_INSPECT_STRUCTURE_*`.
    pub structure: u32,
    pub reserved: u32,
    /// The kind of structure as text, UTF-8; valid until the report is freed.
    pub name: *const c_char,
    /// Which of them are not covered (`of encrypted volumes`), UTF-8; valid until the report is
    /// freed.
    pub which: *const c_char,
}

crate::sized_struct!(FsInspectVerifyNotCovered, which);

/// Verify the file system of `vol` as `opts` says (NULL: the default): compute every checksum
/// it keeps, check every copy of a structure, and read every node. Damage does not fail the
/// call: it is in the report. So is what stopped the verification part way, such as `cancel`
/// or the disks' token. `FS_INSPECT_E_UNSUPPORTED` for a volume without a file system or an
/// unknown flag. Free `*out` with `fs_inspect_verify_report_free`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_volume_verify(
    vol: *const FsInspectVolume,
    opts: *const FsInspectVerifyOptions,
    out: *mut *mut FsInspectVerifyReport,
    cancel: *const FsInspectCancel,
) -> FsInspectStatus {
    guard(|| {
        let v = handle(vol, "volume")?;
        let vo = verify_options(opts)?;
        out_arg(out, "out")?;
        let r = crate::cancel::under(cancel, |c| v.vol.verify(&vo, c))?;
        boxed(out, FsInspectVerifyReport::new(r))
    })
}

/// The caller's options as the library takes them; an unknown flag is
/// `FS_INSPECT_E_UNSUPPORTED`.
fn verify_options(opts: *const FsInspectVerifyOptions) -> FfiResult<VerifyOptions> {
    let o = if opts.is_null() { FsInspectVerifyOptions::default() } else { read_sized(opts, "opts")? };
    unknown_bits("fs_inspect_verify_options.flags", o.flags, VERIFY_FLAGS)?;
    let max = match o.max_findings {
        0 => MAX_FINDINGS,
        n => usize::try_from(n).unwrap_or(usize::MAX),
    };
    Ok(VerifyOptions::default().with_data(o.flags & FS_INSPECT_VERIFY_FLAG_DATA != 0).with_max_findings(max))
}

/// Verify what holds the volumes of `disks`:
///
/// - each disk's container: a VHD's footer and its copy, a VHDX's headers and region tables;
/// - each disk's GPT: both headers and partition arrays;
/// - each volume's LVM label and metadata areas, and its md superblock.
///
/// The file systems are not verified here; `fs_inspect_volume_verify` does each. `opts` is as
/// for `fs_inspect_volume_verify`; its flags are checked but have no effect here. Free `*out`
/// with `fs_inspect_verify_report_free`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_disks_verify(
    disks: *const FsInspectDisks,
    opts: *const FsInspectVerifyOptions,
    out: *mut *mut FsInspectVerifyReport,
    cancel: *const FsInspectCancel,
) -> FsInspectStatus {
    guard(|| {
        let d = handle(disks, "disks")?;
        let vo = verify_options(opts)?;
        out_arg(out, "out")?;
        let r = crate::cancel::under(cancel, |c| d.set.verify(&vo, c))?;
        boxed(out, FsInspectVerifyReport::new(r))
    })
}

fn report_ref<'a>(report: *const FsInspectVerifyReport) -> FfiResult<&'a FsInspectVerifyReport> {
    handle(report, "report")
}

/// What `report` found, in all.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_verify_report_get_summary(
    report: *const FsInspectVerifyReport,
    out: *mut FsInspectVerifySummary,
) -> FsInspectStatus {
    guard(|| {
        let h = report_ref(report)?;
        let r = &h.report;
        let s = FsInspectVerifySummary {
            struct_size: size_of::<FsInspectVerifySummary>(),
            passed: r.passed,
            reserved: [0; 3],
            stopped_status: r.stopped.as_ref().map_or(FS_INSPECT_OK, |s| support::status_of(s.error.kind())),
            stopped_message: h.stopped.as_ptr(),
            damaged: r.damaged,
            recovered: r.recovered,
            dropped: r.dropped,
        };
        put_sized(out, "out", s)
    })
}

/// How many findings `report` kept.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_verify_report_finding_count(
    report: *const FsInspectVerifyReport,
    out: *mut usize,
) -> FsInspectStatus {
    guard(|| put(out, "out", report_ref(report)?.findings.len()))
}

/// Finding `index` (0 .. count) of `report`; past the end `FS_INSPECT_E_NOT_FOUND`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_verify_report_finding_get(
    report: *const FsInspectVerifyReport,
    index: usize,
    out: *mut FsInspectFinding,
) -> FsInspectStatus {
    guard(|| {
        let h = report_ref(report)?;
        let all = &h.report.findings;
        let i = index;
        let (f, (structure, message)) =
            all.get(i).zip(h.findings.get(i)).ok_or_else(|| not_found("finding", index, all.len()))?;
        // Each site's own field; the others zero. Every kind named, so a new one is mapped here.
        let (none_device, none_node) = (crate::disks::FsInspectDeviceRef::default(), FsInspectNode::default());
        let (device, volume, node) = match f.site {
            Some(FindingSite::Device(d)) => (crate::disks::FsInspectDeviceRef::of(d), 0, none_node),
            Some(FindingSite::Volume(v)) => (none_device, v.0, none_node),
            Some(FindingSite::Node(n)) => (none_device, 0, n.into()),
            Some(_) | None => (none_device, 0, none_node),
        };
        let r = FsInspectFinding {
            struct_size: size_of::<FsInspectFinding>(),
            kind: code(f.kind),
            outcome: code(f.outcome),
            structure: structure.as_ptr(),
            has_offset: f.offset.is_some(),
            has_id: f.id.is_some(),
            reserved: [0; 6],
            site_kind: f.site.map_or(0, |s| code(s.kind())),
            offset: f.offset.unwrap_or(0),
            id: f.id.unwrap_or(0),
            device,
            volume,
            node,
            message: message.as_ptr(),
        };
        put_sized(out, "out", r)
    })
}

/// How many kinds of structure `report` checked.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_verify_report_checked_count(
    report: *const FsInspectVerifyReport,
    out: *mut usize,
) -> FsInspectStatus {
    guard(|| put(out, "out", report_ref(report)?.checked.len()))
}

/// Kind of structure `index` (0 .. count, by name) `report` checked; past the end
/// `FS_INSPECT_E_NOT_FOUND`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_verify_report_checked_get(
    report: *const FsInspectVerifyReport,
    index: usize,
    out: *mut FsInspectVerifyChecked,
) -> FsInspectStatus {
    guard(|| {
        let all = &report_ref(report)?.checked;
        let (name, c) = all.get(index).ok_or_else(|| not_found("checked kind", index, all.len()))?;
        let r = FsInspectVerifyChecked {
            struct_size: size_of::<FsInspectVerifyChecked>(),
            name: name.as_ptr(),
            structures: c.structures,
            bytes: c.bytes,
        };
        put_sized(out, "out", r)
    })
}

/// How many kinds of structure the verification of `report` does not cover.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_verify_report_not_covered_count(
    report: *const FsInspectVerifyReport,
    out: *mut usize,
) -> FsInspectStatus {
    guard(|| put(out, "out", report_ref(report)?.not_covered.len()))
}

/// Kind of structure `index` (0 .. count, by name) the verification of `report` does not
/// cover; past the end `FS_INSPECT_E_NOT_FOUND`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_verify_report_not_covered_get(
    report: *const FsInspectVerifyReport,
    index: usize,
    out: *mut FsInspectVerifyNotCovered,
) -> FsInspectStatus {
    guard(|| {
        let all = &report_ref(report)?.not_covered;
        let (k, name, which) = all.get(index).ok_or_else(|| not_found("part not covered", index, all.len()))?;
        let r = FsInspectVerifyNotCovered {
            struct_size: size_of::<FsInspectVerifyNotCovered>(),
            structure: code(*k),
            reserved: 0,
            name: name.as_ptr(),
            which: which.as_ptr(),
        };
        put_sized(out, "out", r)
    })
}

/// `report` as JSON: `passed`, `damaged`, `recovered`, `checked` (structures and bytes by
/// kind), `findings` (`structure`, `offset`, `id`, `site`, `kind`, `outcome`, `message`),
/// `dropped`, `not_covered`, and `stopped` (`kind`, `message`, `location`) when it stopped part
/// way.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_verify_report_json(
    report: *const FsInspectVerifyReport,
    out: *mut *mut FsInspectBuf,
) -> FsInspectStatus {
    guard(|| crate::browse::json_out(out, &report_ref(report)?.report))
}

/// Free a verification's report (NULL allowed).
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_verify_report_free(report: *mut FsInspectVerifyReport) {
    free(report);
}
