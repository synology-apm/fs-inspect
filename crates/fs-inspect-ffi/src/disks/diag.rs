//! What the library worked around while reading a set of disks or a volume.

use super::*;
use fs_inspect::Diagnostic;
use std::ffi::{CString, c_char};

/// Something the library worked around.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsInspectDiagnostic {
    /// `sizeof` this struct in the caller's header (set it before the call).
    pub struct_size: usize,
    /// `FS_INSPECT_SEVERITY_*`.
    pub severity: u32,
    /// `FS_INSPECT_DIAG_*`.
    pub code: u32,
    /// It concerns disk `disk`.
    pub has_disk: bool,
    /// It concerns volume `volume` of the set.
    pub has_volume: bool,
    pub reserved: [u8; 2],
    pub disk: u32,
    pub volume: u32,
    pub reserved2: u32,
    /// The logical volume or container (`lvm:vg/lv`, `md:name`, `ldm:group/volume`, `lvm:vg`)
    /// it concerns; "" when none. The strings are valid until the snapshot is freed.
    pub logical: *const c_char,
    /// What was worked around.
    pub message: *const c_char,
}

crate::sized_struct!(FsInspectDiagnostic, message);

/// A snapshot of diagnostics (`fs_inspect_disks_diagnostics`,
/// `fs_inspect_volume_diagnostics`): what was reported when it was taken.
#[derive(Debug)]
pub struct FsInspectDiagnostics {
    items: Vec<(Diagnostic, CString, CString)>,
    dropped: u64,
}

/// `*out` = a new snapshot of `all`, `dropped` more not kept.
fn snapshot(out: *mut *mut FsInspectDiagnostics, all: Vec<Diagnostic>, dropped: u64) -> FfiResult {
    let items = all
        .into_iter()
        .map(|d| {
            let (l, m) =
                (cstring(&d.logical.as_ref().map(ToString::to_string).unwrap_or_default()), cstring(&d.message));
            (d, l, m)
        })
        .collect();
    boxed(out, FsInspectDiagnostics { items, dropped })
}

/// The diagnostics that the disks, and what was opened from them, have reported so far. More
/// come as volumes are opened and read. Each disk's come first, then the set's own, each in the
/// order reported. Each is reported once. At most 256 are kept per volume and per disk, and
/// 4096 in all; later ones are dropped and counted in `fs_inspect_diagnostics_info.dropped`.
/// Free `*out` with `fs_inspect_diagnostics_free`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_disks_diagnostics(
    disks: *const FsInspectDisks,
    out: *mut *mut FsInspectDiagnostics,
) -> FsInspectStatus {
    guard(|| {
        let set = &disks_ref(disks)?.set;
        // The count first: a diagnostic dropped between the two calls is then counted, not lost.
        let dropped = set.diagnostics_dropped();
        snapshot(out, set.diagnostics(), dropped)
    })
}

/// What was worked around so far while opening and reading volume `vol`. For a volume on a
/// logical volume, it also holds what concerns that logical volume and its container. Its
/// `dropped` is 0: the set's snapshot counts what the caps dropped. Free `*out` with
/// `fs_inspect_diagnostics_free`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_volume_diagnostics(
    vol: *const FsInspectVolume,
    out: *mut *mut FsInspectDiagnostics,
) -> FsInspectStatus {
    guard(|| snapshot(out, volume_ref(vol)?.vol.diagnostics(), 0))
}

/// What a snapshot of diagnostics holds (`fs_inspect_diagnostics_get_info`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsInspectDiagnosticsInfo {
    /// `sizeof` this struct in the caller's header (set it before the call).
    pub struct_size: usize,
    /// How many distinct diagnostics were dropped because a cap was reached (0: the list is
    /// complete).
    pub dropped: u64,
}

crate::sized_struct!(FsInspectDiagnosticsInfo, dropped);

/// How many diagnostics were dropped. `fs_inspect_diagnostics_count` tells how many the
/// snapshot holds.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_diagnostics_get_info(
    diags: *const FsInspectDiagnostics,
    out: *mut FsInspectDiagnosticsInfo,
) -> FsInspectStatus {
    guard(|| {
        let d = handle(diags, "diags")?;
        let r = FsInspectDiagnosticsInfo { struct_size: size_of::<FsInspectDiagnosticsInfo>(), dropped: d.dropped };
        put_sized(out, "out", r)
    })
}

/// How many diagnostics the snapshot holds.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_diagnostics_count(diags: *const FsInspectDiagnostics, out: *mut usize) -> FsInspectStatus {
    guard(|| put(out, "out", handle(diags, "diags")?.items.len()))
}

/// The diagnostic at `index` of the snapshot.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_diagnostics_get(
    diags: *const FsInspectDiagnostics,
    index: usize,
    out: *mut FsInspectDiagnostic,
) -> FsInspectStatus {
    guard(|| {
        let all = &handle(diags, "diags")?.items;
        let (d, logical, message) = all.get(index).ok_or_else(|| not_found("diagnostic", index, all.len()))?;
        let r = FsInspectDiagnostic {
            struct_size: size_of::<FsInspectDiagnostic>(),
            severity: code(d.severity),
            code: code(d.code),
            has_disk: d.disk.is_some(),
            has_volume: d.volume.is_some(),
            reserved: [0; 2],
            disk: d.disk.map_or(0, |i| i.0),
            volume: d.volume.map_or(0, |i| i.0),
            reserved2: 0,
            logical: logical.as_ptr(),
            message: message.as_ptr(),
        };
        put_sized(out, "out", r)
    })
}

/// Free a snapshot of diagnostics (NULL allowed).
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_diagnostics_free(diags: *mut FsInspectDiagnostics) {
    free(diags);
}
