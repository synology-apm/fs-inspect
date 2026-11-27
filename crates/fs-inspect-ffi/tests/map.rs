//! The C ABI driven from Rust: disks opened through callbacks, paths and split segments, their
//! volumes and containers, their layouts, partitions and diagnostics, the maps and bitmaps of
//! volumes and whole disks, and the read counters and limits of a set.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code
#![allow(unsafe_code)]

use fs_inspect::Named;
use fs_inspect::io::MemSource;
use fs_inspect::{
    BlockClass, ByteRange, DeviceRef, DiskIndex, DiskSet, DiskSpec, OpenOptions, VolumeIndex, VolumeMapOptions,
};
use fs_inspect_ffi::*;
use fs_inspect_testkit::{Placement, ROOT, SyntheticVolume, VolumeSpec};
use std::ffi::{CStr, CString, c_char, c_void};
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// A callback source's context: the bytes, the ranges holding data (None: all), and how many
/// times this context was released (its own counter: tests run in parallel).
struct Ctx {
    data: Vec<u8>,
    holes_but: Option<Vec<ByteRange>>,
    released: Arc<AtomicUsize>,
}

extern "C" fn read_at(ctx: *mut c_void, offset: u64, buf: *mut u8, len: usize) -> i32 {
    // SAFETY: ctx is the Ctx leaked by the test; buf has room for len bytes.
    let data = &unsafe { &*(ctx as *const Ctx) }.data;
    let (s, e) = (offset as usize, offset as usize + len);
    if e > data.len() {
        return -1;
    }
    unsafe { ptr::copy_nonoverlapping(data[s..e].as_ptr(), buf, len) };
    0
}

extern "C" fn data_ranges(
    ctx: *mut c_void,
    offset: u64,
    length: u64,
    emit: FsInspectEmitRangeFn,
    emit_ctx: *mut c_void,
) -> i32 {
    // SAFETY: ctx is the Ctx leaked by the test.
    let c = unsafe { &*(ctx as *const Ctx) };
    let Some(d) = &c.holes_but else { return -1 };
    for r in fs_inspect::range::intersect(d.iter().copied(), [ByteRange::new(offset, length)]) {
        let Some(emit) = emit else { return -1 };
        // SAFETY: emit and emit_ctx are what the library handed this call.
        let st = unsafe { emit(emit_ctx, r.offset, r.length) };
        if st != FS_INSPECT_OK {
            return st;
        }
    }
    0
}

extern "C" fn release(ctx: *mut c_void) {
    // SAFETY: ctx came from Box::into_raw in the test.
    let ctx = unsafe { Box::from_raw(ctx as *mut Ctx) };
    ctx.released.fetch_add(1, Ordering::SeqCst);
}

/// Callbacks over `data` (no release counter kept).
fn ops(data: Vec<u8>) -> FsInspectSourceOps {
    counted(data).0
}

/// Callbacks over `data`, and the release counter of their context.
fn counted(data: Vec<u8>) -> (FsInspectSourceOps, Arc<AtomicUsize>) {
    with_data(data, None)
}

/// Callbacks over `data` that report only `data_at` as holding data (None: no `data_ranges`).
fn with_data(data: Vec<u8>, data_at: Option<Vec<ByteRange>>) -> (FsInspectSourceOps, Arc<AtomicUsize>) {
    let len = data.len() as u64;
    let released = Arc::new(AtomicUsize::new(0));
    let has_ranges = data_at.is_some();
    let ctx = Box::into_raw(Box::new(Ctx { data, holes_but: data_at, released: released.clone() })) as *mut c_void;
    let o = FsInspectSourceOps {
        ctx,
        read_at: Some(read_at),
        size: len,
        release: Some(release),
        data_ranges: if has_ranges { Some(data_ranges) } else { None },
        ..sized()
    };
    (o, released)
}

fn last_error() -> String {
    unsafe { CStr::from_ptr(fs_inspect_last_error_message()) }.to_string_lossy().into_owned()
}

/// A library string (NULL: "").
fn cstr(p: *const c_char) -> String {
    // SAFETY: NULL or the library's NUL-terminated string, alive with what holds it.
    if p.is_null() { String::new() } else { unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned() }
}

/// A source handle over the callbacks `o`.
fn source(o: &FsInspectSourceOps) -> *mut FsInspectSource {
    let mut s = ptr::null_mut();
    assert_eq!(fs_inspect_source_new(o, &mut s), FS_INSPECT_OK, "{}", last_error());
    s
}

/// A disk spec over a new source on the callbacks `o` (`raw`: the whole source is one volume
/// or partitioned disk, no container detected); [`open`] frees the source handle.
fn ops_spec(o: &FsInspectSourceOps, raw: bool) -> FsInspectDiskSpec {
    FsInspectDiskSpec { source: source(o), flags: if raw { FS_INSPECT_DISK_FLAG_RAW } else { 0 }, ..sized() }
}

/// Open `specs` with `opts` (NULL: defaults), then free their source handles: the set holds
/// its own.
fn open(specs: &[FsInspectDiskSpec], opts: *const FsInspectOpenOptions) -> Result<*mut FsInspectDisks, i32> {
    let mut d = ptr::null_mut();
    let rc = fs_inspect_disks_open(specs.as_ptr(), specs.len(), opts, &mut d, ptr::null());
    for spec in specs {
        fs_inspect_source_free(spec.source.cast_mut());
    }
    match rc {
        FS_INSPECT_OK => Ok(d),
        rc => {
            assert!(d.is_null());
            Err(rc)
        }
    }
}

/// One raw disk over callbacks on `data`.
fn open_raw(data: Vec<u8>) -> *mut FsInspectDisks {
    open(&[ops_spec(&FsInspectSourceOps { release: None, ..ops(data) }, true)], ptr::null()).unwrap()
}

fn volume(disks: *const FsInspectDisks, index: u32) -> *mut FsInspectVolume {
    let mut vol = ptr::null_mut();
    assert_eq!(fs_inspect_disks_open_volume(disks, index, &mut vol, ptr::null()), FS_INSPECT_OK, "{}", last_error());
    vol
}

fn map_volume(vol: *const FsInspectVolume, opts: *const FsInspectMapOptions) -> *mut FsInspectMap {
    let mut m = ptr::null_mut();
    assert_eq!(fs_inspect_volume_map(vol, opts, &mut m, ptr::null()), FS_INSPECT_OK, "{}", last_error());
    m
}

/// Disk `i` as a device.
fn disk_ref(i: u32) -> FsInspectDeviceRef {
    FsInspectDeviceRef::of(DeviceRef::Disk(DiskIndex(i)))
}

fn map_disk(disks: *const FsInspectDisks, disk: u32, opts: *const FsInspectMapOptions) -> *mut FsInspectMap {
    let mut m = ptr::null_mut();
    assert_eq!(
        fs_inspect_disks_map(disks, disk_ref(disk), opts, &mut m, ptr::null()),
        FS_INSPECT_OK,
        "{}",
        last_error()
    );
    m
}

/// Every range of `cls` in blocks of `unit`, read `cap` at a time.
fn ranges(map: *const FsInspectMap, cls: u32, unit: u64, cap: usize) -> Vec<ByteRange> {
    let mut blocks = ptr::null_mut();
    assert_eq!(fs_inspect_map_blocks(map, cls, unit, &mut blocks), FS_INSPECT_OK, "{}", last_error());
    let mut count = usize::MAX;
    assert_eq!(fs_inspect_ranges_count(blocks, &mut count), FS_INSPECT_OK);
    let mut info: FsInspectRangesInfo = sized();
    assert_eq!(fs_inspect_ranges_get_info(blocks, &mut info), FS_INSPECT_OK);
    assert_eq!(info.cls, cls);
    let mut out = Vec::new();
    let mut b = vec![ByteRange::default(); cap];
    loop {
        let mut k = usize::MAX;
        assert_eq!(
            fs_inspect_ranges_read(blocks, out.len(), b.as_mut_ptr(), b.len(), &mut k),
            FS_INSPECT_OK,
            "{}",
            last_error()
        );
        if k == 0 {
            break;
        }
        out.extend_from_slice(&b[..k]);
    }
    assert_eq!(out.len(), count);
    assert_eq!(out.iter().map(|x| x.length).sum::<u64>(), info.bytes);
    fs_inspect_ranges_free(blocks);
    out
}

/// Every range of a list of ranges, and what its info says.
fn all_ranges(r: *mut FsInspectRanges) -> (Vec<ByteRange>, FsInspectRangesInfo) {
    let mut info: FsInspectRangesInfo = sized();
    assert_eq!(fs_inspect_ranges_get_info(r, &mut info), FS_INSPECT_OK);
    let mut count = usize::MAX;
    assert_eq!(fs_inspect_ranges_count(r, &mut count), FS_INSPECT_OK);
    let mut out = vec![ByteRange::default(); count];
    let mut n = usize::MAX;
    assert_eq!(fs_inspect_ranges_read(r, 0, out.as_mut_ptr(), out.len(), &mut n), FS_INSPECT_OK);
    assert_eq!(n, out.len());
    assert_eq!(out.iter().map(|x| x.length).sum::<u64>(), info.bytes);
    fs_inspect_ranges_free(r);
    (out, info)
}

/// The bytes of `cls` in a map.
fn map_bytes(map: *const FsInspectMap, cls: u32) -> u64 {
    let mut b = u64::MAX;
    assert_eq!(fs_inspect_map_bytes(map, cls, &mut b), FS_INSPECT_OK, "{}", last_error());
    b
}

/// Where a map lies (offset, length).
fn extent(map: *const FsInspectMap) -> (u64, u64) {
    let mut e = ByteRange::default();
    assert_eq!(fs_inspect_map_get_extent(map, &mut e), FS_INSPECT_OK);
    (e.offset, e.length)
}

/// What a device of a set is.
fn device_info(disks: *const FsInspectDisks, disk: u32) -> FsInspectDeviceInfo {
    let mut info: FsInspectDeviceInfo = sized();
    assert_eq!(
        fs_inspect_disks_device_info(disks, disk_ref(disk), &mut info, ptr::null()),
        FS_INSPECT_OK,
        "{}",
        last_error()
    );
    info
}

/// A set's volumes (a snapshot, freed on drop).
struct Vols(*mut FsInspectVolumes);

impl Drop for Vols {
    fn drop(&mut self) {
        fs_inspect_volumes_free(self.0);
    }
}

impl Vols {
    fn of(disks: *const FsInspectDisks) -> Self {
        let mut v = ptr::null_mut();
        assert_eq!(fs_inspect_disks_volumes(disks, &mut v, ptr::null()), FS_INSPECT_OK, "{}", last_error());
        Vols(v)
    }

    fn count(&self) -> usize {
        let mut n = usize::MAX;
        assert_eq!(fs_inspect_volumes_count(self.0, &mut n), FS_INSPECT_OK);
        n
    }

    /// Volume `i`: its strings live as long as `self`.
    fn get(&self, i: usize) -> FsInspectVolumeEntry {
        let mut e: FsInspectVolumeEntry = sized();
        assert_eq!(fs_inspect_volumes_get(self.0, i, &mut e), FS_INSPECT_OK, "{}", last_error());
        e
    }

    /// The disk extents of volume `i`, read one at a time.
    fn extents(&self, i: usize) -> Vec<(u32, u64, u64)> {
        let mut out = Vec::new();
        loop {
            let mut x = [FsInspectDiskExtent::default()];
            let mut n = usize::MAX;
            assert_eq!(fs_inspect_volumes_extents_read(self.0, i, out.len(), x.as_mut_ptr(), 1, &mut n), FS_INSPECT_OK);
            if n == 0 {
                break;
            }
            out.push((x[0].disk, x[0].offset, x[0].length));
        }
        out
    }
}

/// A set's containers (a snapshot, freed on drop).
struct Containers(*mut FsInspectContainers);

impl Drop for Containers {
    fn drop(&mut self) {
        fs_inspect_containers_free(self.0);
    }
}

impl Containers {
    fn of(disks: *const FsInspectDisks) -> Self {
        let mut c = ptr::null_mut();
        assert_eq!(fs_inspect_disks_containers(disks, &mut c, ptr::null()), FS_INSPECT_OK, "{}", last_error());
        Containers(c)
    }

    fn count(&self) -> usize {
        let mut n = usize::MAX;
        assert_eq!(fs_inspect_containers_count(self.0, &mut n), FS_INSPECT_OK);
        n
    }

    /// Container `i`: its strings live as long as `self`.
    fn get(&self, i: usize) -> FsInspectContainer {
        let mut c: FsInspectContainer = sized();
        assert_eq!(fs_inspect_containers_get(self.0, i, &mut c), FS_INSPECT_OK, "{}", last_error());
        c
    }
}

/// Every extent of a list of disk extents (freed).
fn disk_extents(e: *mut FsInspectDiskExtents) -> Vec<(u32, u64, u64)> {
    let mut count = usize::MAX;
    assert_eq!(fs_inspect_disk_extents_count(e, &mut count), FS_INSPECT_OK);
    let mut buf = vec![FsInspectDiskExtent::default(); count];
    let mut n = usize::MAX;
    assert_eq!(fs_inspect_disk_extents_read(e, 0, buf.as_mut_ptr(), buf.len(), &mut n), FS_INSPECT_OK);
    assert_eq!(n, count);
    fs_inspect_disk_extents_free(e);
    buf.iter().map(|x| (x.disk, x.offset, x.length)).collect()
}

/// A diagnostic with its strings copied out of its snapshot.
#[derive(Debug, Clone)]
struct Diag {
    d: FsInspectDiagnostic,
    logical: String,
    message: String,
}

/// The diagnostics of a snapshot (freed), and how many it says were dropped.
fn diagnostics_dropped(snap: *mut FsInspectDiagnostics) -> (Vec<Diag>, u64) {
    let mut n = usize::MAX;
    assert_eq!(fs_inspect_diagnostics_count(snap, &mut n), FS_INSPECT_OK);
    let mut info: FsInspectDiagnosticsInfo = sized();
    assert_eq!(fs_inspect_diagnostics_get_info(snap, &mut info), FS_INSPECT_OK);
    let out = (0..n)
        .map(|i| {
            let mut d: FsInspectDiagnostic = sized();
            assert_eq!(fs_inspect_diagnostics_get(snap, i, &mut d), FS_INSPECT_OK, "{}", last_error());
            Diag { d, logical: cstr(d.logical), message: cstr(d.message) }
        })
        .collect();
    let mut d: FsInspectDiagnostic = sized();
    assert_eq!(fs_inspect_diagnostics_get(snap, n, &mut d), FS_INSPECT_E_NOT_FOUND);
    fs_inspect_diagnostics_free(snap);
    (out, info.dropped)
}

/// The diagnostics of a snapshot (freed).
fn diagnostics(snap: *mut FsInspectDiagnostics) -> Vec<Diag> {
    diagnostics_dropped(snap).0
}

/// The diagnostics of a set now, and how many it dropped.
fn set_diags_dropped(disks: *const FsInspectDisks) -> (Vec<Diag>, u64) {
    let mut snap = ptr::null_mut();
    assert_eq!(fs_inspect_disks_diagnostics(disks, &mut snap), FS_INSPECT_OK, "{}", last_error());
    diagnostics_dropped(snap)
}

/// The diagnostics of a set now.
fn set_diags(disks: *const FsInspectDisks) -> Vec<Diag> {
    set_diags_dropped(disks).0
}

/// The partitions of a device of a set: the table's info and each entry.
fn partitions(
    disks: *const FsInspectDisks,
    device: FsInspectDeviceRef,
) -> (FsInspectPartitionTableInfo, Vec<FsInspectPartition>) {
    // The partitions' strings are not kept: only their fixed fields are read after the free.
    let mut t = ptr::null_mut();
    assert_eq!(fs_inspect_disks_partitions(disks, device, &mut t, ptr::null()), FS_INSPECT_OK, "{}", last_error());
    let mut info: FsInspectPartitionTableInfo = sized();
    assert_eq!(fs_inspect_partition_table_get_info(t, &mut info), FS_INSPECT_OK);
    let mut count = usize::MAX;
    assert_eq!(fs_inspect_partition_table_count(t, &mut count), FS_INSPECT_OK);
    let parts = (0..count)
        .map(|i| {
            let mut p: FsInspectPartition = sized();
            assert_eq!(fs_inspect_partition_table_get(t, i, &mut p), FS_INSPECT_OK, "{}", last_error());
            p
        })
        .collect();
    let mut p: FsInspectPartition = sized();
    assert_eq!(fs_inspect_partition_table_get(t, count, &mut p), FS_INSPECT_E_NOT_FOUND);
    fs_inspect_partition_table_free(t);
    (info, parts)
}

/// What the Rust API gives for the volume `index` of a raw disk over `data`.
fn rust_volume(data: &[u8], index: u32, opts: &VolumeMapOptions, class: BlockClass, unit: u64) -> Vec<ByteRange> {
    let set = DiskSet::open(
        &[DiskSpec::source(Arc::new(MemSource::new(data.to_vec()))).raw()],
        &OpenOptions::default(),
        None,
    )
    .unwrap();
    set.open_volume(VolumeIndex(index), None)
        .unwrap()
        .map(opts, None)
        .unwrap()
        .blocks(class, fs_inspect::range::Granularity::new(unit).ok())
        .unwrap()
        .to_vec()
}

fn excluding(paths: &[*const c_char], flags: u32) -> FsInspectMapOptions {
    FsInspectMapOptions { excludes: paths.as_ptr(), excludes_count: paths.len(), flags, ..sized() }
}

#[test]
fn ntfs_through_callbacks() {
    let mut v = SyntheticVolume::format(VolumeSpec { clusters: 2048, ..Default::default() });
    v.create_file(ROOT, "pagefile.sys", 256 << 10, 1, Placement::FirstFit);
    v.create_file(ROOT, "keep.bin", 100_000, 2, Placement::FirstFit);
    let want = rust_volume(&v.image, 0, &VolumeMapOptions::default(), BlockClass::Used, 0);

    let (o, released) = counted(v.image.clone());
    let disks = open(&[ops_spec(&o, true)], ptr::null()).unwrap();

    let mut n = 0usize;
    assert_eq!(fs_inspect_disks_disk_count(disks, &mut n), FS_INSPECT_OK);
    assert_eq!(n, 1);
    let mut sd: FsInspectSetDisk = sized();
    assert_eq!(fs_inspect_disks_disk_get(disks, 0, &mut sd), FS_INSPECT_OK);
    assert_eq!((sd.kind, sd.problem), (FS_INSPECT_SET_DISK_PRESENT, 0));
    assert_eq!(fs_inspect_disks_disk_get(disks, 1, &mut sd), FS_INSPECT_E_NOT_FOUND);
    let info = device_info(disks, 0);
    assert_eq!((info.origin, info.format), (FS_INSPECT_ORIGIN_EXTERNAL, FS_INSPECT_CONTAINER_FORMAT_RAW));
    // No sector size given: 0, not known. A bare volume: no partition table, no disk id.
    assert_eq!((info.size, info.sector_size), (v.image.len() as u64, 0));
    assert_eq!((info.scheme, info.disk_id_kind), (FS_INSPECT_SCHEME_NONE, 0));
    let mut bad_info: FsInspectDeviceInfo = sized();
    assert_eq!(fs_inspect_disks_device_info(disks, disk_ref(1), &mut bad_info, ptr::null()), FS_INSPECT_E_NOT_FOUND);

    let vols = Vols::of(disks);
    assert_eq!(vols.count(), 1);
    let e = vols.get(0);
    assert_eq!(
        (e.index, e.fs_kind, e.location, e.device, e.offset, e.scheme, e.readable),
        (
            0,
            FS_INSPECT_FS_NTFS,
            FS_INSPECT_LOCATION_DEVICE,
            disk_ref(0),
            0,
            FS_INSPECT_SCHEME_NONE,
            FS_INSPECT_READABLE_FULL
        )
    );
    assert_eq!(e.disk_extent_count, 1);
    assert_eq!(vols.extents(0), [(0, 0, e.length)]);
    let mut bad: FsInspectVolumeEntry = sized();
    assert_eq!(fs_inspect_volumes_get(vols.0, 5, &mut bad), FS_INSPECT_E_NOT_FOUND);
    assert!(last_error().contains("no volume 5"), "{}", last_error());
    let mut only = 9u32;
    assert_eq!(fs_inspect_disks_only_volume(disks, &mut only, ptr::null()), FS_INSPECT_OK);
    assert_eq!(only, 0);
    // A bare volume of a disk that records nothing stable: keyed by place; "0" is the index.
    assert_eq!(cstr(e.key), "disk0-0");
    let mut found = 9u32;
    let zero = CString::new("0").unwrap();
    assert_eq!(
        fs_inspect_disks_find_volume(disks, zero.as_ptr(), &mut found, ptr::null()),
        FS_INSPECT_OK,
        "{}",
        last_error()
    );
    assert_eq!(found, 0);

    let vol = volume(disks, e.index);
    let mut vi: FsInspectVolumeInfo = sized();
    assert_eq!(fs_inspect_volume_get_info(vol, &mut vi), FS_INSPECT_OK);
    assert_eq!((vi.fs_kind, vi.unit, vi.has_index, vi.index), (FS_INSPECT_FS_NTFS, 4096, true, 0));
    assert_eq!(vi.coverage_bytes, v.image.len() as u64, "a bare volume: the whole image");
    assert_eq!(vi.logical_kind, 0, "not on a logical volume");
    assert!(!cstr(vi.uuid).is_empty());
    let mut vdi: FsInspectDeviceInfo = sized();
    assert_eq!(fs_inspect_volume_device_info(vol, &mut vdi, ptr::null()), FS_INSPECT_OK, "{}", last_error());
    assert_eq!((vdi.size, vdi.origin), (v.image.len() as u64, FS_INSPECT_ORIGIN_EXTERNAL));

    // The volume's own bytes; past its end refused.
    let mut head = [0u8; 16];
    assert_eq!(
        fs_inspect_volume_read_at(vol, 3, head.as_mut_ptr(), 16, ptr::null()),
        FS_INSPECT_OK,
        "{}",
        last_error()
    );
    assert_eq!(head, v.image[3..19]);
    let past = v.image.len() as u64 - 8;
    assert_ne!(fs_inspect_volume_read_at(vol, past, head.as_mut_ptr(), 16, ptr::null()), FS_INSPECT_OK);

    // Where a file's bytes are, and where every file's content is: as the library has them.
    let rust_set = DiskSet::open(
        &[DiskSpec::source(Arc::new(MemSource::new(v.image.clone()))).raw()],
        &OpenOptions::default(),
        None,
    )
    .unwrap();
    let rust_vol = rust_set.open_volume(VolumeIndex(0), None).unwrap();
    let keep = CString::new("/keep.bin").unwrap();
    let mut r = ptr::null_mut();
    assert_eq!(
        fs_inspect_volume_file_ranges(vol, keep.as_ptr(), &mut r, ptr::null()),
        FS_INSPECT_OK,
        "{}",
        last_error()
    );
    let (got, info) = all_ranges(r);
    assert_eq!(Some(got), rust_vol.file_ranges(&"/keep.bin".parse().unwrap(), None).unwrap());
    assert!(info.bytes >= 100_000, "{info:?}");
    let missing = CString::new("/no such file").unwrap();
    let mut r = ptr::null_mut();
    assert_eq!(fs_inspect_volume_file_ranges(vol, missing.as_ptr(), &mut r, ptr::null()), FS_INSPECT_E_NOT_FOUND);
    assert!(r.is_null());
    // A pattern that breaks the syntax: refused at the call, named, in both places.
    let bad = CString::new("keep.bin").unwrap();
    assert_eq!(fs_inspect_volume_file_ranges(vol, bad.as_ptr(), &mut r, ptr::null()), FS_INSPECT_E_INVALID_ARGUMENT);
    assert!(r.is_null() && last_error().contains("\"keep.bin\""), "{}", last_error());
    let (ok, bad) = (CString::new("/keep.bin").unwrap(), CString::new("/**/x").unwrap());
    let paths = [ok.as_ptr(), bad.as_ptr()];
    let o = excluding(&paths, 0);
    let mut m = ptr::null_mut();
    assert_eq!(fs_inspect_volume_map(vol, &o, &mut m, ptr::null()), FS_INSPECT_E_INVALID_ARGUMENT);
    assert!(m.is_null());
    assert!(last_error().contains("excludes[1]") && last_error().contains("\"/**/x\""), "{}", last_error());
    assert_eq!(fs_inspect_volume_file_content(vol, &mut r, ptr::null()), FS_INSPECT_OK, "{}", last_error());
    let (got, info) = all_ranges(r);
    let want_content = rust_vol.file_content(None).unwrap();
    assert_eq!(got, want_content.ranges);
    assert_eq!((info.items, info.unreadable), (want_content.files, want_content.unreadable));
    assert!(info.items >= 2, "{info:?}");

    // Defaults: the library's map, paged a few at a time; the info adds up.
    let m = map_volume(vol, ptr::null());
    assert_eq!(ranges(m, FS_INSPECT_BLOCK_CLASS_USED, FS_INSPECT_UNIT_DEFAULT, 3), want);
    let mut unit = 0u64;
    assert_eq!(fs_inspect_map_get_unit(m, &mut unit), FS_INSPECT_OK);
    let size = extent(m).1;
    assert_eq!((extent(m), unit), ((0, v.image.len() as u64), 4096));
    let data = map_bytes(m, FS_INSPECT_BLOCK_CLASS_DATA);
    assert_eq!(data + map_bytes(m, FS_INSPECT_BLOCK_CLASS_ZERO) + map_bytes(m, FS_INSPECT_BLOCK_CLASS_UNUSED), size);
    assert!(map_bytes(m, FS_INSPECT_BLOCK_CLASS_EXCLUDED) >= 256 << 10, "the paging file is left out");
    let exact = ranges(m, FS_INSPECT_BLOCK_CLASS_DATA, FS_INSPECT_UNIT_EXACT, 64);
    assert_eq!(exact.iter().map(|r| r.length).sum::<u64>(), data);
    // The exact ranges' info: byte-exact, their class and bytes.
    let mut r = ptr::null_mut();
    assert_eq!(fs_inspect_map_blocks(m, FS_INSPECT_BLOCK_CLASS_DATA, FS_INSPECT_UNIT_EXACT, &mut r), FS_INSPECT_OK);
    let (got, info) = all_ranges(r);
    assert_eq!((got, info.unit, info.cls, info.bytes), (exact, 1, FS_INSPECT_BLOCK_CLASS_DATA, data));
    // The default unit resolved; reading past the end: nothing, a NULL buffer is fine then.
    let mut blocks = ptr::null_mut();
    assert_eq!(fs_inspect_map_blocks(m, FS_INSPECT_BLOCK_CLASS_USED, 0, &mut blocks), FS_INSPECT_OK);
    let mut bi: FsInspectRangesInfo = sized();
    assert_eq!(fs_inspect_ranges_get_info(blocks, &mut bi), FS_INSPECT_OK);
    assert_eq!(bi.unit, 4096);
    let mut k = 7usize;
    assert_eq!(fs_inspect_ranges_read(blocks, 1 << 20, ptr::null_mut(), 4, &mut k), FS_INSPECT_OK);
    assert_eq!(k, 0);
    fs_inspect_ranges_free(blocks);

    // Exclusions through the options struct: what the library gives for the same path.
    let want_ex = rust_volume(
        &v.image,
        0,
        &VolumeMapOptions::default().with_excludes(vec!["/Keep.bin".parse().unwrap()]),
        BlockClass::Used,
        0,
    );
    assert_ne!(want_ex, want);
    let p = CString::new("/Keep.bin").unwrap();
    let paths = [p.as_ptr()];
    let opts = excluding(&paths, 0);
    let mx = map_volume(vol, &opts);
    assert_eq!(ranges(mx, FS_INSPECT_BLOCK_CLASS_USED, 0, 1 << 12), want_ex);
    fs_inspect_map_free(mx);

    // Bad arguments: a block size not a power of two, an unknown class or flag, NULLs.
    let mut bx = ptr::null_mut();
    assert_eq!(fs_inspect_map_blocks(m, FS_INSPECT_BLOCK_CLASS_USED, 1000, &mut bx), FS_INSPECT_E_INVALID_ARGUMENT);
    assert_eq!(fs_inspect_map_blocks(m, 99, 0, &mut bx), FS_INSPECT_E_INVALID_ARGUMENT);
    assert_eq!(fs_inspect_map_blocks(m, 0, 0, &mut bx), FS_INSPECT_E_INVALID_ARGUMENT);
    assert!(bx.is_null());
    let mut mx = ptr::null_mut();
    let unknown = FsInspectMapOptions { flags: 0x80 | FS_INSPECT_MAP_FLAG_FILE_ZERO, ..sized() };
    assert_eq!(fs_inspect_volume_map(vol, &unknown, &mut mx, ptr::null()), FS_INSPECT_E_UNSUPPORTED);
    // The message names the field, its value and only the bits it does not know.
    assert_eq!(last_error(), "fs_inspect_map_options.flags 0x81: unknown bits 0x80");
    assert_eq!(fs_inspect_volume_map(ptr::null(), ptr::null(), &mut mx, ptr::null()), FS_INSPECT_E_INVALID_ARGUMENT);
    assert!(last_error().contains("NULL"), "{}", last_error());
    assert!(mx.is_null());
    fs_inspect_map_free(m);
    fs_inspect_volume_free(vol);
    fs_inspect_disks_free(disks);
    assert_eq!(released.load(Ordering::SeqCst), 1, "ctx released once");

    // Unknown content: the whole image is a raw volume (all data); at an offset that starts
    // no partition it is a format error. The callback context is still released.
    let (o, released) = counted(vec![0u8; 1 << 16]);
    let disks = open(&[ops_spec(&o, true)], ptr::null()).unwrap();
    let vol = volume(disks, 0);
    let mut vi: FsInspectVolumeInfo = sized();
    assert_eq!(fs_inspect_volume_get_info(vol, &mut vi), FS_INSPECT_OK);
    assert_eq!(vi.fs_kind, FS_INSPECT_FS_RAW);
    fs_inspect_volume_free(vol);
    let mut vol = ptr::null_mut();
    let at = |disk, offset, length, has| {
        let mut vol = ptr::null_mut();
        let flags = if has { FS_INSPECT_OPEN_VOLUME_AT_FLAG_LENGTH } else { 0 };
        fs_inspect_disks_open_volume_at(disks, disk, offset, length, flags, &mut vol, ptr::null())
    };
    assert_eq!(at(0, 4096, 0, false), FS_INSPECT_E_FORMAT);
    assert_eq!(at(0, 4096, 8192, true), FS_INSPECT_E_FORMAT);
    assert_eq!(at(0, 1 << 20, 0, false), FS_INSPECT_E_NOT_FOUND);
    assert_eq!(at(1, 0, 0, false), FS_INSPECT_E_NOT_FOUND);
    assert_eq!(fs_inspect_disks_open_volume_at(disks, 0, 0, 0, 0, &mut vol, ptr::null()), FS_INSPECT_OK);
    fs_inspect_volume_free(vol);
    fs_inspect_disks_free(disks);
    assert_eq!(released.load(Ordering::SeqCst), 1);
    assert!(!unsafe { CStr::from_ptr(fs_inspect_version()) }.to_bytes().is_empty());
}

/// Bitmaps: the shape, the bits of used and unused (complements), a buffer too small.
#[test]
fn bitmaps() {
    let mut v = SyntheticVolume::format(VolumeSpec { clusters: 1000, ..Default::default() });
    v.create_file(ROOT, "a.bin", 300_000, 1, Placement::MaxRun(3));
    let disks = open_raw(v.image.clone());
    let vol = volume(disks, 0);
    let m = map_volume(vol, ptr::null());
    for unit in [FS_INSPECT_UNIT_DEFAULT, 4096, 64 << 10] {
        let mut bi: FsInspectBitmapShape = sized();
        assert_eq!(fs_inspect_map_bitmap_shape(m, unit, &mut bi), FS_INSPECT_OK, "{}", last_error());
        let u = if unit == 0 { 4096 } else { unit };
        assert_eq!((bi.unit, bi.start), (u, 0));
        assert_eq!(bi.blocks, (v.image.len() as u64).div_ceil(u));
        assert_eq!(bi.bytes, bi.blocks.div_ceil(8));
        let bits = |cls: u32| {
            // One spare byte: zeroed.
            let mut b = vec![0xA5u8; bi.bytes as usize + 1];
            let mut shape: FsInspectBitmapShape = sized();
            let rc = fs_inspect_map_bitmap_into(m, cls, unit, b.as_mut_ptr(), b.len(), &mut shape);
            assert_eq!(rc, FS_INSPECT_OK, "{}", last_error());
            assert_eq!((shape.unit, shape.start, shape.blocks, shape.bytes), (bi.unit, bi.start, bi.blocks, bi.bytes));
            assert_eq!(b.pop(), Some(0));
            b
        };
        let (used, unused) = (bits(FS_INSPECT_BLOCK_CLASS_USED), bits(FS_INSPECT_BLOCK_CLASS_UNUSED));
        for i in 0..bi.blocks {
            let (byte, bit) = ((i / 8) as usize, i % 8);
            let (a, b) = (used[byte] >> bit & 1, unused[byte] >> bit & 1);
            assert_eq!(a ^ b, 1, "block {i} at unit {u}: exactly one of used and unused");
        }
        // The bits are the blocks.
        let blocks = ranges(m, FS_INSPECT_BLOCK_CLASS_USED, unit, 16);
        let set: u64 = used.iter().map(|b| u64::from(b.count_ones())).sum();
        let want: u64 = blocks.iter().map(|r| r.length.div_ceil(u)).sum();
        assert_eq!(set, want);
        let mut short = vec![0u8; bi.bytes as usize - 1];
        assert_eq!(
            fs_inspect_map_bitmap_into(
                m,
                FS_INSPECT_BLOCK_CLASS_USED,
                unit,
                short.as_mut_ptr(),
                short.len(),
                ptr::null_mut()
            ),
            FS_INSPECT_E_INVALID_ARGUMENT
        );
        assert!(last_error().contains(&format!("needs {}", bi.bytes)), "{}", last_error());
    }
    let mut bi: FsInspectBitmapShape = sized();
    assert_eq!(fs_inspect_map_bitmap_shape(m, 3, &mut bi), FS_INSPECT_E_INVALID_ARGUMENT);
    assert_eq!(
        fs_inspect_map_bitmap_into(m, FS_INSPECT_BLOCK_CLASS_USED, 0, ptr::null_mut(), 1 << 20, ptr::null_mut()),
        FS_INSPECT_E_INVALID_ARGUMENT
    );

    // Moved to a disk offset: blocks on the disk's grid, the bitmap starting at the block
    // holding the volume's first byte.
    let mut moved = ptr::null_mut();
    assert_eq!(fs_inspect_map_moved_to(m, 32_256, &mut moved), FS_INSPECT_OK, "{}", last_error());
    assert_eq!(extent(moved), (32_256, v.image.len() as u64));
    assert_eq!(fs_inspect_map_bitmap_shape(moved, 4096, &mut bi), FS_INSPECT_OK);
    assert_eq!(bi.start, 28_672);
    let exact = |m| ranges(m, FS_INSPECT_BLOCK_CLASS_USED, FS_INSPECT_UNIT_EXACT, 64);
    let shifted: Vec<ByteRange> = exact(m).iter().map(|r| ByteRange::new(r.offset + 32_256, r.length)).collect();
    assert_eq!(exact(moved), shifted);
    assert_eq!(fs_inspect_map_moved_to(m, u64::MAX - 10, &mut moved), FS_INSPECT_E_INVALID_ARGUMENT);
    fs_inspect_map_free(moved);
    fs_inspect_map_free(m);
    fs_inspect_volume_free(vol);
    fs_inspect_disks_free(disks);
}

#[test]
fn whole_disk_and_raw_partition() {
    use fs_inspect_testkit::disk::{self, DiskPart};
    let mut v = SyntheticVolume::format(VolumeSpec { clusters: 1024, ..Default::default() });
    v.create_file(ROOT, "keep.bin", 50_000, 1, Placement::FirstFit);
    let raw = vec![0x5Au8; 64 << 10];
    let d = disk::disk_image(disk::TableKind::Gpt, 512, &[DiskPart::primary(&v.image), DiskPart::primary(&raw)]);
    let rust = DiskSet::open(
        &[DiskSpec::source(Arc::new(MemSource::new(d.image.clone()))).raw()],
        &OpenOptions::default(),
        None,
    )
    .unwrap();
    let rust_map = |o: &fs_inspect::DeviceMapOptions| rust.map(DiskIndex(0), o, None).unwrap();
    let want = rust_map(&fs_inspect::DeviceMapOptions::default()).blocks(BlockClass::Used, None).unwrap().to_vec();

    // No release callback: the context is left to the test process.
    let disks = open_raw(d.image.clone());
    let m = map_disk(disks, 0, ptr::null());
    assert_eq!(ranges(m, FS_INSPECT_BLOCK_CLASS_USED, 0, 64), want);
    assert_eq!(extent(m), (0, d.image.len() as u64));
    // No file system here needs zeros: data is used.
    assert!(ranges(m, FS_INSPECT_BLOCK_CLASS_ZERO, 0, 8).is_empty());
    assert_eq!(ranges(m, FS_INSPECT_BLOCK_CLASS_DATA, 0, 8), want);
    // A whole disk's finest block is its sector.
    let mut bl = ptr::null_mut();
    assert_eq!(fs_inspect_map_blocks(m, FS_INSPECT_BLOCK_CLASS_USED, 256, &mut bl), FS_INSPECT_OK);
    fs_inspect_ranges_free(bl);
    let mut bi: FsInspectBitmapShape = sized();
    assert_eq!(fs_inspect_map_bitmap_shape(m, 256, &mut bi), FS_INSPECT_OK);
    assert_eq!(bi.unit, 512);
    fs_inspect_map_free(m);

    // Exclusions apply to every volume: what the library gives for the same options.
    let want_ex = rust_map(
        &fs_inspect::DeviceMapOptions::default().with_map(
            fs_inspect::VolumeMapOptions::default()
                .with_default_excludes(false)
                .with_excludes(vec!["/Keep.bin".parse().unwrap()]),
        ),
    )
    .blocks(BlockClass::Used, None)
    .unwrap()
    .to_vec();
    assert_ne!(want_ex, want);
    let p = CString::new("/Keep.bin").unwrap();
    let paths = [p.as_ptr()];
    let m = map_disk(disks, 0, &excluding(&paths, FS_INSPECT_MAP_FLAG_NO_DEFAULT_EXCLUDES));
    assert_eq!(ranges(m, FS_INSPECT_BLOCK_CLASS_USED, 0, 64), want_ex);
    assert!(!ranges(m, FS_INSPECT_BLOCK_CLASS_EXCLUDED, 0, 8).is_empty());
    fs_inspect_map_free(m);
    let mut m = ptr::null_mut();
    assert_eq!(fs_inspect_disks_map(disks, disk_ref(1), ptr::null(), &mut m, ptr::null()), FS_INSPECT_E_NOT_FOUND);
    let bad_ref = FsInspectDeviceRef { lv: 1, ..disk_ref(0) };
    assert_eq!(fs_inspect_disks_map(disks, bad_ref, ptr::null(), &mut m, ptr::null()), FS_INSPECT_E_INVALID_ARGUMENT);
    let bad_kind = FsInspectDeviceRef { kind: 9, ..disk_ref(0) };
    assert_eq!(fs_inspect_disks_map(disks, bad_kind, ptr::null(), &mut m, ptr::null()), FS_INSPECT_E_INVALID_ARGUMENT);
    // The files' zeros of each volume: what the library gives for the same options.
    let fz = FsInspectMapOptions { flags: FS_INSPECT_MAP_FLAG_FILE_ZERO, ..sized() };
    assert_eq!(fs_inspect_disks_map(disks, disk_ref(0), &fz, &mut m, ptr::null()), FS_INSPECT_OK);
    fs_inspect_map_free(m);

    // A volume not read: all its bytes data, as the library has it; not a volume's option;
    // only volumes the set has.
    let want_un =
        rust_map(&fs_inspect::DeviceMapOptions::default().with_unread(vec![VolumeIndex(0)])).ranges(BlockClass::Data);
    let first = ByteRange::new(d.starts[0], v.image.len() as u64);
    assert_eq!(fs_inspect::range::subtract([first], want_un.clone()).count(), 0, "{want_un:?}");
    let un = [0u32];
    let opts = FsInspectMapOptions { unread: un.as_ptr(), unread_count: 1, ..sized() };
    let m = map_disk(disks, 0, &opts);
    assert_eq!(ranges(m, FS_INSPECT_BLOCK_CLASS_DATA, 1, 8), want_un);
    assert!(ranges(m, FS_INSPECT_BLOCK_CLASS_EXCLUDED, 1, 8).is_empty());
    fs_inspect_map_free(m);
    let vol = volume(disks, 0);
    let mut m = ptr::null_mut();
    assert_eq!(fs_inspect_volume_map(vol, &opts, &mut m, ptr::null()), FS_INSPECT_E_INVALID_ARGUMENT);
    fs_inspect_volume_free(vol);
    let bad = [7u32];
    let opts = FsInspectMapOptions { unread: bad.as_ptr(), unread_count: 1, ..sized() };
    assert_eq!(fs_inspect_disks_map(disks, disk_ref(0), &opts, &mut m, ptr::null()), FS_INSPECT_E_NOT_FOUND);
    let opts = FsInspectMapOptions { unread_count: 1, ..sized() };
    assert_eq!(fs_inspect_disks_map(disks, disk_ref(0), &opts, &mut m, ptr::null()), FS_INSPECT_E_INVALID_ARGUMENT);

    // The partitions: a GPT entry each; the unrecognized one opens as a raw volume.
    let vols = Vols::of(disks);
    let e = vols.get(1);
    assert_eq!((e.scheme, e.number, e.fs_kind, e.has_partition), (FS_INSPECT_SCHEME_GPT, 2, 0, true));
    assert_eq!(e.entry, FS_INSPECT_PARTITION_ENTRY_GPT);
    assert!(cstr(e.key).starts_with("part-"), "{}", cstr(e.key));
    drop(vols);
    let vol = volume(disks, 1);
    let mut vi: FsInspectVolumeInfo = sized();
    assert_eq!(fs_inspect_volume_get_info(vol, &mut vi), FS_INSPECT_OK);
    assert_eq!((vi.fs_kind, vi.offset), (FS_INSPECT_FS_RAW, e.offset));
    fs_inspect_volume_free(vol);
    // The only volume with a file system.
    let mut only = 9u32;
    assert_eq!(fs_inspect_disks_only_volume(disks, &mut only, ptr::null()), FS_INSPECT_OK);
    assert_eq!(only, 0);

    // The partition table: two GPT entries, each a volume of the set.
    let (info, parts) = partitions(disks, disk_ref(0));
    assert_eq!((info.kind, info.problem, parts.len()), (FS_INSPECT_PARTITION_TABLE_READ, 0, 2));
    for (i, p) in parts.iter().enumerate() {
        assert_eq!(
            (p.device, p.offset, p.scheme, p.entry),
            (disk_ref(0), d.starts[i], FS_INSPECT_SCHEME_GPT, FS_INSPECT_PARTITION_ENTRY_GPT)
        );
        assert_eq!((p.role, p.volume, p.number), (FS_INSPECT_PARTITION_ROLE_VOLUME, i as u32, i as u32 + 1));
        assert_ne!(p.partition_type, 0);
    }
    assert_eq!((parts[0].fs_kind, parts[1].fs_kind), (FS_INSPECT_FS_NTFS, 0));
    assert_eq!(cstr(parts[1].part_guid.as_ptr()).len(), 36);
    let mut t = ptr::null_mut();
    assert_eq!(fs_inspect_disks_partitions(disks, disk_ref(3), &mut t, ptr::null()), FS_INSPECT_E_NOT_FOUND);
    assert!(t.is_null());
    fs_inspect_disks_free(disks);
}

/// A disk's areas paged as the library's layout has them; a volume read from a caller's reader
/// in a new set (the old one unchanged), read back through the disk; where a volume's bytes
/// lie on the disk.
#[test]
fn layout_and_a_volume_from_elsewhere() {
    use fs_inspect_testkit::disk::{self, DiskPart};
    let raw = vec![0x5Au8; 64 << 10];
    let d = disk::disk_image(disk::TableKind::Gpt, 512, &[DiskPart::primary(&raw), DiskPart::primary(&raw)]);
    let rust = DiskSet::open(
        &[DiskSpec::source(Arc::new(MemSource::new(d.image.clone()))).raw()],
        &OpenOptions::default(),
        None,
    )
    .unwrap();
    let want: Vec<(u64, u64, u32, u32)> = rust
        .layout(DiskIndex(0), None)
        .unwrap()
        .areas()
        .iter()
        .map(|a| (a.range.offset, a.range.length, a.content.kind().code(), a.content.volume().map_or(0, |v| v.0)))
        .collect();
    let rust_layout = rust.layout(DiskIndex(0), None).unwrap();
    let disks = open_raw(d.image.clone());
    let mut layout = ptr::null_mut();
    assert_eq!(
        fs_inspect_disks_layout(disks, disk_ref(0), &mut layout, ptr::null()),
        FS_INSPECT_OK,
        "{}",
        last_error()
    );
    let mut li: FsInspectLayoutInfo = sized();
    assert_eq!(fs_inspect_layout_get_info(layout, &mut li), FS_INSPECT_OK);
    assert_eq!((li.device, li.size, li.problem), (disk_ref(0), d.image.len() as u64, 0));
    let mut count = usize::MAX;
    assert_eq!(fs_inspect_layout_areas_count(layout, &mut count), FS_INSPECT_OK);
    assert_eq!(count, want.len());
    // Two areas a read.
    let mut got = Vec::new();
    loop {
        let mut page = [FsInspectArea::default(); 2];
        let mut n = 0usize;
        assert_eq!(fs_inspect_layout_areas_read(layout, got.len(), page.as_mut_ptr(), 2, &mut n), FS_INSPECT_OK);
        if n == 0 {
            break;
        }
        got.extend(page[..n].iter().map(|a| (a.offset, a.length, a.content, a.volume)));
    }
    assert_eq!(got, want);
    assert!(got.iter().any(|a| a.2 == FS_INSPECT_AREA_VOLUME && a.3 == 1 && a.0 == d.starts[1]));
    // The area holding a byte; what a range crosses.
    let mut a = FsInspectArea::default();
    assert_eq!(fs_inspect_layout_area_at(layout, d.starts[1] + 5, &mut a), FS_INSPECT_OK);
    assert_eq!((a.offset, a.content, a.volume), (d.starts[1], FS_INSPECT_AREA_VOLUME, 1));
    assert_eq!(fs_inspect_layout_area_at(layout, d.image.len() as u64, &mut a), FS_INSPECT_E_NOT_FOUND);
    let (s, l) = (d.starts[1] - 512, 1024);
    let mut areas = ptr::null_mut();
    assert_eq!(fs_inspect_layout_split(layout, s, l, &mut areas), FS_INSPECT_OK, "{}", last_error());
    let mut n = usize::MAX;
    assert_eq!(fs_inspect_areas_count(areas, &mut n), FS_INSPECT_OK);
    let mut split = vec![FsInspectArea::default(); n];
    let mut got_n = usize::MAX;
    assert_eq!(fs_inspect_areas_read(areas, 0, split.as_mut_ptr(), n, &mut got_n), FS_INSPECT_OK);
    assert_eq!(got_n, n);
    fs_inspect_areas_free(areas);
    let want_split: Vec<_> =
        rust_layout.split(ByteRange::new(s, l)).iter().map(|a| (a.range.offset, a.range.length)).collect();
    assert_eq!(split[..n].iter().map(|a| (a.offset, a.length)).collect::<Vec<_>>(), want_split);
    assert_eq!(split[n - 1].content, FS_INSPECT_AREA_VOLUME);
    // Volume 1's bytes and areas; the other lists as the library has them.
    let mut vb = 0u64;
    assert_eq!(fs_inspect_layout_bytes(layout, FS_INSPECT_AREA_VOLUME, 1, &mut vb), FS_INSPECT_OK, "{}", last_error());
    assert_eq!(vb, raw.len() as u64);
    let mut r = ptr::null_mut();
    assert_eq!(fs_inspect_layout_ranges(layout, FS_INSPECT_AREA_VOLUME, 1, &mut r), FS_INSPECT_OK);
    assert_eq!(all_ranges(r).0, [ByteRange::new(d.starts[1], raw.len() as u64)]);
    assert_eq!(fs_inspect_layout_ranges(layout, FS_INSPECT_AREA_FREE, 1, &mut r), FS_INSPECT_E_INVALID_ARGUMENT);
    assert_eq!(fs_inspect_layout_ranges(layout, 99, 0, &mut r), FS_INSPECT_E_INVALID_ARGUMENT);
    assert_eq!(fs_inspect_layout_structures(layout, &mut r), FS_INSPECT_OK);
    assert_eq!(all_ranges(r).0, rust_layout.structures());
    assert_eq!(fs_inspect_layout_system(layout, &mut r), FS_INSPECT_OK);
    assert_eq!(all_ranges(r).0, rust_layout.system());
    assert_eq!(fs_inspect_layout_unsynced(layout, &mut r), FS_INSPECT_OK);
    assert!(all_ranges(r).0.is_empty());
    fs_inspect_layout_free(layout);
    let mut none = ptr::null_mut();
    assert_eq!(fs_inspect_disks_layout(disks, disk_ref(1), &mut none, ptr::null()), FS_INSPECT_E_NOT_FOUND);
    assert!(none.is_null());

    // Volume 1's bytes 16..48 on the disk.
    let r = [ByteRange::new(16, 32)];
    let mut ext = ptr::null_mut();
    let rc =
        fs_inspect_disks_volume_to_disks(disks, 1, r.as_ptr(), 1, FS_INSPECT_PROJECTION_WRITTEN, &mut ext, ptr::null());
    assert_eq!(rc, FS_INSPECT_OK, "{}", last_error());
    assert_eq!(disk_extents(ext), [(0, d.starts[1] + 16, 32)]);
    let rc = fs_inspect_disks_volume_to_disks(disks, 1, r.as_ptr(), 1, 7, &mut ext, ptr::null());
    assert_eq!(rc, FS_INSPECT_E_INVALID_ARGUMENT);

    // Volume 1 read from a reader whose first 4 KiB are 0xEE; one shorter than the volume is
    // refused, unless the rest of the volume is to be read from the disk; an unknown tail is
    // refused.
    let (short_ops, short_released) = counted(vec![0xEE; 4096]);
    let short = source(&short_ops);
    let mut swapped = ptr::null_mut();
    for tail in [0, 9, FS_INSPECT_VOLUME_TAIL_EXACT] {
        assert_eq!(
            fs_inspect_disks_replace_volume_source(disks, 1, short, tail, &mut swapped, ptr::null()),
            FS_INSPECT_E_INVALID_ARGUMENT,
            "tail {tail}"
        );
    }
    let mut tailed = ptr::null_mut();
    assert_eq!(
        fs_inspect_disks_replace_volume_source(
            disks,
            1,
            short,
            FS_INSPECT_VOLUME_TAIL_DEVICE,
            &mut tailed,
            ptr::null()
        ),
        FS_INSPECT_OK,
        "{}",
        last_error()
    );
    fs_inspect_source_free(short);
    let mut b = [0u8; 8];
    let at = d.starts[1] + 4096 - 4;
    assert_eq!(fs_inspect_disks_read_at(tailed, disk_ref(0), at, b.as_mut_ptr(), 8, ptr::null()), FS_INSPECT_OK);
    assert_eq!(b, [0xEE, 0xEE, 0xEE, 0xEE, 0x5A, 0x5A, 0x5A, 0x5A], "the reader's bytes, then the disk's");
    fs_inspect_disks_free(tailed);
    assert_eq!(short_released.load(Ordering::SeqCst), 1);
    let (long_ops, _) = counted(vec![0; raw.len() + 1]);
    let long = source(&long_ops);
    assert_eq!(
        fs_inspect_disks_replace_volume_source(
            disks,
            1,
            long,
            FS_INSPECT_VOLUME_TAIL_DEVICE,
            &mut swapped,
            ptr::null()
        ),
        FS_INSPECT_E_INVALID_ARGUMENT
    );
    fs_inspect_source_free(long);
    let mut copy = raw.clone();
    copy[..4096].fill(0xEE);
    let (o, released) = counted(copy);
    let src = source(&o);
    assert_eq!(
        fs_inspect_disks_replace_volume_source(disks, 1, src, FS_INSPECT_VOLUME_TAIL_EXACT, &mut swapped, ptr::null()),
        FS_INSPECT_OK,
        "{}",
        last_error()
    );
    fs_inspect_source_free(src);
    let mut b = [0u8; 8];
    let at = d.starts[1] + 4096 - 4;
    assert_eq!(fs_inspect_disks_read_at(swapped, disk_ref(0), at, b.as_mut_ptr(), 8, ptr::null()), FS_INSPECT_OK);
    assert_eq!(b, [0xEE, 0xEE, 0xEE, 0xEE, 0x5A, 0x5A, 0x5A, 0x5A]);
    assert_eq!(fs_inspect_disks_read_at(disks, disk_ref(0), at, b.as_mut_ptr(), 8, ptr::null()), FS_INSPECT_OK);
    assert_eq!(b, [0x5A; 8], "the set it came from is unchanged");
    let len = d.image.len() as u64;
    assert_eq!(
        fs_inspect_disks_read_at(swapped, disk_ref(0), len - 4, b.as_mut_ptr(), 8, ptr::null()),
        FS_INSPECT_E_NOT_FOUND
    );
    // A volume that is not there: the source stays the caller's.
    let (o2, released2) = counted(vec![0; 16]);
    let src2 = source(&o2);
    let mut none = ptr::null_mut();
    assert_eq!(
        fs_inspect_disks_replace_volume_source(disks, 9, src2, FS_INSPECT_VOLUME_TAIL_EXACT, &mut none, ptr::null()),
        FS_INSPECT_E_NOT_FOUND
    );
    assert_eq!(released2.load(Ordering::SeqCst), 0);
    // A disk read another way must be as long.
    assert_eq!(
        fs_inspect_disks_replace_disk_source(disks, 0, src2, &mut none, ptr::null()),
        FS_INSPECT_E_INVALID_ARGUMENT
    );
    assert_eq!(released2.load(Ordering::SeqCst), 0);
    fs_inspect_source_free(src2);
    assert_eq!(released2.load(Ordering::SeqCst), 1);
    fs_inspect_disks_free(disks);
    assert_eq!(released.load(Ordering::SeqCst), 0, "the new set still reads it");
    fs_inspect_disks_free(swapped);
    assert_eq!(released.load(Ordering::SeqCst), 1);
}

/// What a source reports holding no data reads as zeros: on a whole disk, allocated bytes there
/// are zero, not data. Its sector size is the disk's.
#[test]
fn source_data_ranges_and_sector_size() {
    let data_at = vec![ByteRange::new(0, 4096), ByteRange::new(32 << 10, 8192)];
    let (o, released) = with_data(vec![0x11u8; 1 << 16], Some(data_at.clone()));
    let o = FsInspectSourceOps { sector_size: 4096, ..o };
    let disks = open(&[ops_spec(&o, true)], ptr::null()).unwrap();
    assert_eq!(device_info(disks, 0).sector_size, 4096);
    let m = map_disk(disks, 0, ptr::null());
    assert_eq!(ranges(m, FS_INSPECT_BLOCK_CLASS_DATA, FS_INSPECT_UNIT_EXACT, 8), data_at);
    assert_eq!(
        ranges(m, FS_INSPECT_BLOCK_CLASS_ZERO, FS_INSPECT_UNIT_EXACT, 8),
        [ByteRange::new(4096, 28 << 10), ByteRange::new(40 << 10, 24 << 10)]
    );
    fs_inspect_map_free(m);
    fs_inspect_disks_free(disks);
    assert_eq!(released.load(Ordering::SeqCst), 1);

    // A sector size not a power of two of at least 512: refused, the context still the caller's.
    let (o, released) = counted(vec![0u8; 1 << 16]);
    let o = FsInspectSourceOps { sector_size: 1000, ..o };
    let mut s = ptr::null_mut();
    assert_eq!(fs_inspect_source_new(&o, &mut s), FS_INSPECT_E_INVALID_ARGUMENT);
    assert!(s.is_null());
    assert_eq!(released.load(Ordering::SeqCst), 0);
    release(o.ctx);
}

extern "C" fn ranges_fail(_: *mut c_void, _: u64, _: u64, _: FsInspectEmitRangeFn, _: *mut c_void) -> i32 {
    FS_INSPECT_E_DATA_MISSING
}

/// A `data_ranges` that fails fails the call asking with its status, not the next read.
#[test]
fn a_failing_data_ranges_fails_the_call() {
    let (o, released) = counted(vec![0u8; 1 << 16]);
    let o = FsInspectSourceOps { data_ranges: Some(ranges_fail), ..o };
    let disks = open(&[ops_spec(&o, true)], ptr::null()).unwrap();
    let mut m = ptr::null_mut();
    let rc = fs_inspect_disks_map(disks, disk_ref(0), ptr::null(), &mut m, ptr::null());
    assert_eq!(rc, FS_INSPECT_E_DATA_MISSING, "{}", last_error());
    assert!(m.is_null());
    assert!(last_error().contains("data_ranges"), "{}", last_error());
    fs_inspect_disks_free(disks);
    assert_eq!(released.load(Ordering::SeqCst), 1);
}

/// A set never takes its specs' source handles: whatever fails, each context is released once,
/// when the caller frees its handle; the first failing disk is named.
#[test]
fn open_failures_leave_the_sources_to_the_caller() {
    assert_eq!(fs_inspect_api_version(), FS_INSPECT_API_VERSION);
    let (a, ra) = counted(vec![0u8; 1 << 16]);
    let (b, rb) = counted(vec![0u8; 1 << 16]);
    let (c, rc) = counted(vec![0u8; 1 << 16]);
    let bad = FsInspectDiskSpec { flags: 0x40, ..ops_spec(&b, true) };
    let specs = [ops_spec(&a, true), bad, ops_spec(&c, true)];
    assert_eq!(open(&specs, ptr::null()).unwrap_err(), FS_INSPECT_E_UNSUPPORTED);
    assert!(last_error().starts_with("disk 1:"), "{}", last_error());
    for r in [&ra, &rb, &rc] {
        assert_eq!(r.load(Ordering::SeqCst), 1);
    }

    // Two sources in one spec: refused.
    let (a, ra) = counted(vec![0u8; 1 << 16]);
    let p = CString::new("x.img").unwrap();
    let paths = [p.as_ptr()];
    let both = FsInspectDiskSpec { paths: paths.as_ptr(), path_count: 1, ..ops_spec(&a, false) };
    assert_eq!(open(&[both], ptr::null()).unwrap_err(), FS_INSPECT_E_INVALID_ARGUMENT);
    assert_eq!(ra.load(Ordering::SeqCst), 1);

    // No out pointer: refused, the source untouched.
    let (a, ra) = counted(vec![0u8; 1 << 16]);
    let spec = ops_spec(&a, true);
    assert_eq!(
        fs_inspect_disks_open(&spec, 1, ptr::null(), ptr::null_mut(), ptr::null()),
        FS_INSPECT_E_INVALID_ARGUMENT
    );
    assert_eq!(ra.load(Ordering::SeqCst), 0);
    fs_inspect_source_free(spec.source.cast_mut());
    assert_eq!(ra.load(Ordering::SeqCst), 1);

    // A struct too small to hold `release`: refused, not released (the library cannot).
    let (a, ra) = counted(vec![0u8; 1 << 16]);
    let o = FsInspectSourceOps { struct_size: 8, ..a };
    let mut s = ptr::null_mut();
    assert_eq!(fs_inspect_source_new(&o, &mut s), FS_INSPECT_E_INVALID_ARGUMENT);
    assert_eq!(ra.load(Ordering::SeqCst), 0);
    release(a.ctx);

    // No specs, nothing given. A set of no disks is a set with nothing in it.
    let mut d = ptr::null_mut();
    assert_eq!(fs_inspect_disks_open(ptr::null(), 1, ptr::null(), &mut d, ptr::null()), FS_INSPECT_E_INVALID_ARGUMENT);
    assert_eq!(fs_inspect_disks_open(ptr::null(), 0, ptr::null(), &mut d, ptr::null()), FS_INSPECT_OK);
    assert_eq!(Vols::of(d).count(), 0);
    fs_inspect_disks_free(d);
    d = ptr::null_mut();
    let empty: FsInspectDiskSpec = sized();
    assert_eq!(fs_inspect_disks_open(&empty, 1, ptr::null(), &mut d, ptr::null()), FS_INSPECT_E_INVALID_ARGUMENT);
    assert!(d.is_null());
}

/// A cancel token on the set fails what runs after it is triggered; one given to a map fails
/// that map only; a child token is cancelled with its parent, not the other way round.
#[test]
fn cancel_tokens() {
    let mut v = SyntheticVolume::format(VolumeSpec { clusters: 4096, ..Default::default() });
    v.create_file(ROOT, "a.bin", 1 << 20, 1, Placement::MaxRun(1));
    let mut call = ptr::null_mut();
    assert_eq!(fs_inspect_cancel_new(&mut call), FS_INSPECT_OK);
    let disks = open_raw(v.image.clone());
    let vol = volume(disks, 0);
    let mut child = ptr::null_mut();
    assert_eq!(fs_inspect_cancel_child(call, &mut child), FS_INSPECT_OK);
    let mut grandchild = ptr::null_mut();
    assert_eq!(fs_inspect_cancel_child(child, &mut grandchild), FS_INSPECT_OK);
    fs_inspect_cancel_trigger(grandchild);
    assert!(fs_inspect_cancel_is_cancelled(grandchild));
    assert!(!fs_inspect_cancel_is_cancelled(child), "a child does not cancel its parent");
    assert_eq!(fs_inspect_cancel_check(call), FS_INSPECT_OK);
    fs_inspect_cancel_trigger(call);
    assert!(fs_inspect_cancel_is_cancelled(call));
    assert!(fs_inspect_cancel_is_cancelled(child), "a parent cancels its children");
    assert_eq!(fs_inspect_cancel_check(child), FS_INSPECT_E_CANCELLED);
    assert_eq!(fs_inspect_status_scope(FS_INSPECT_E_CANCELLED), FS_INSPECT_SCOPE_CANCELLED);
    assert!(!fs_inspect_cancel_is_cancelled(ptr::null()));
    assert_eq!(fs_inspect_cancel_check(ptr::null()), FS_INSPECT_OK);
    fs_inspect_cancel_trigger(ptr::null());
    let mut m = ptr::null_mut();
    assert_eq!(fs_inspect_volume_map(vol, ptr::null(), &mut m, child), FS_INSPECT_E_CANCELLED);
    assert!(m.is_null());
    fs_inspect_cancel_free(child);
    fs_inspect_cancel_free(grandchild);
    // The volume itself is not cancelled.
    let m = map_volume(vol, ptr::null());
    fs_inspect_map_free(m);
    fs_inspect_volume_free(vol);
    fs_inspect_disks_free(disks);
    fs_inspect_cancel_free(call);

    let mut whole = ptr::null_mut();
    assert_eq!(fs_inspect_cancel_new(&mut whole), FS_INSPECT_OK);
    let oo = FsInspectOpenOptions { queue_depth: 4, ..sized() };
    let src = FsInspectSourceOps { release: None, ..ops(v.image.clone()) };
    let spec = [ops_spec(&src, true)];
    let mut disks = ptr::null_mut();
    assert_eq!(fs_inspect_disks_open(spec.as_ptr(), 1, &oo, &mut disks, whole), FS_INSPECT_OK, "{}", last_error());
    fs_inspect_source_free(spec[0].source.cast_mut());
    // The set keeps its own reference to the token.
    fs_inspect_cancel_trigger(whole);
    fs_inspect_cancel_free(whole);
    let mut vol = ptr::null_mut();
    let mut rc = fs_inspect_disks_open_volume(disks, 0, &mut vol, ptr::null());
    if rc == FS_INSPECT_OK {
        let mut m = ptr::null_mut();
        rc = fs_inspect_volume_map(vol, ptr::null(), &mut m, ptr::null());
        fs_inspect_volume_free(vol);
    }
    assert_eq!(rc, FS_INSPECT_E_CANCELLED, "{}", last_error());
    fs_inspect_disks_free(disks);
}

/// What the library worked around is readable through the set, in the order reported, as a
/// snapshot (later diagnostics are not in it); a volume's are those at its offset.
#[test]
fn diagnostics_and_error_locations() {
    let mut v = SyntheticVolume::format(VolumeSpec { clusters: 2048, ..Default::default() });
    v.create_file(ROOT, "a.bin", 10_000, 1, Placement::FirstFit);
    let disks = open_raw(v.image.clone());
    let vol = volume(disks, 0);
    let mut before = ptr::null_mut();
    assert_eq!(fs_inspect_disks_diagnostics(disks, &mut before), FS_INSPECT_OK);

    // A path that does not exist is reported, not excluded.
    let p = CString::new("/no such file").unwrap();
    let paths = [p.as_ptr()];
    let m = map_volume(vol, &excluding(&paths, 0));
    fs_inspect_map_free(m);
    assert!(diagnostics(before).is_empty(), "a snapshot keeps what was there when taken");
    let (all, dropped) = set_diags_dropped(disks);
    assert_eq!((all.len(), dropped), (1, 0));
    let Diag { d, message: msg, .. } = all[0].clone();
    assert_eq!(
        (d.severity, d.code, d.has_volume, d.volume),
        (FS_INSPECT_SEVERITY_INFO, FS_INSPECT_DIAG_EXCLUSION_SKIPPED, true, 0)
    );
    assert!(msg.contains("/no such file"), "{msg}");
    let mut snap = ptr::null_mut();
    assert_eq!(fs_inspect_volume_diagnostics(vol, &mut snap), FS_INSPECT_OK, "{}", last_error());
    let of_vol = diagnostics(snap);
    assert_eq!(of_vol.len(), 1);
    assert_eq!(of_vol[0].message, msg);
    assert_eq!(fs_inspect_disks_diagnostics(disks, &mut snap), FS_INSPECT_OK);
    assert_eq!(fs_inspect_diagnostics_get(snap, 0, ptr::null_mut()), FS_INSPECT_E_INVALID_ARGUMENT);
    fs_inspect_diagnostics_free(snap);
    fs_inspect_diagnostics_free(ptr::null_mut());
    assert_eq!(fs_inspect_disks_diagnostics(ptr::null(), &mut snap), FS_INSPECT_E_INVALID_ARGUMENT);
    let mut n = 0usize;
    assert_eq!(fs_inspect_diagnostics_count(ptr::null(), &mut n), FS_INSPECT_E_INVALID_ARGUMENT);

    // An error without a location leaves the out struct unset.
    let mut other = ptr::null_mut();
    assert_eq!(fs_inspect_disks_open_volume_at(disks, 0, 4096, 0, 0, &mut other, ptr::null()), FS_INSPECT_E_FORMAT);
    let mut loc = FsInspectErrorLocation { offset: 7, ..sized() };
    assert!(!fs_inspect_last_error_location(&mut loc));
    assert_eq!((loc.offset, loc.space), (7, 0));
    assert!(loc.structure.is_null());
    // A NULL out pointer is allowed.
    assert!(!fs_inspect_last_error_location(ptr::null_mut()));
    // A success clears the last error.
    let mut disk_n = 0usize;
    assert_eq!(fs_inspect_disks_disk_count(disks, &mut disk_n), FS_INSPECT_OK);
    assert_eq!(last_error(), "");
    fs_inspect_volume_free(vol);
    fs_inspect_disks_free(disks);
}

/// Each status's scope: what it is about, as the library's error kinds have it.
#[test]
fn status_scopes() {
    for (status, scope) in [
        (FS_INSPECT_E_CORRUPT, FS_INSPECT_SCOPE_UNIT),
        (FS_INSPECT_E_FORMAT, FS_INSPECT_SCOPE_UNIT),
        (FS_INSPECT_E_IO, FS_INSPECT_SCOPE_SOURCE),
        (FS_INSPECT_E_PERMISSION_DENIED, FS_INSPECT_SCOPE_SOURCE),
        (FS_INSPECT_E_NOT_FOUND, FS_INSPECT_SCOPE_CALLER),
        (FS_INSPECT_E_INVALID_ARGUMENT, FS_INSPECT_SCOPE_CALLER),
        (FS_INSPECT_E_CANCELLED, FS_INSPECT_SCOPE_CANCELLED),
        (FS_INSPECT_E_CALLBACK, FS_INSPECT_SCOPE_CALLER),
    ] {
        assert_eq!(fs_inspect_status_scope(status), scope, "status {status}");
    }
    for kind in fs_inspect::ErrorKind::ALL {
        let status = -(kind.code() as i32);
        assert_eq!(fs_inspect_status_scope(status), kind.scope().code(), "{kind:?}");
    }
    // Not an error: no scope.
    for status in [FS_INSPECT_OK, FS_INSPECT_E_INTERNAL, -50, 3] {
        assert_eq!(fs_inspect_status_scope(status), 0, "status {status}");
    }
}

/// Read counters given in the open options count the reads of what is opened from the set; a
/// traced one records each read. Limits: each 0 field is the default, which fits a real volume.
#[test]
fn io_stats_and_limits() {
    let mut v = SyntheticVolume::format(VolumeSpec { clusters: 2048, ..Default::default() });
    v.create_file(ROOT, "a.bin", 100_000, 1, Placement::FirstFit);
    let mut d: FsInspectLimits = sized();
    assert_eq!(fs_inspect_limits_default(&mut d), FS_INSPECT_OK);
    let rust = fs_inspect::Limits::default();
    assert_eq!(
        (d.max_alloc, d.max_dir_entries, d.max_path_depth, d.max_tree_nodes),
        (rust.max_alloc, rust.max_dir_entries, rust.max_path_depth as u64, rust.max_tree_nodes)
    );
    assert!(d.max_attr_list_entries > 0 && d.max_file_extents > 0 && d.max_cache_bytes > 0);
    let zero: FsInspectLimits = sized();
    for traced in [false, true] {
        let mut stats = ptr::null_mut();
        assert_eq!(
            fs_inspect_io_stats_new(if traced { FS_INSPECT_IO_STATS_FLAG_TRACED } else { 0 }, &mut stats),
            FS_INSPECT_OK
        );
        let mut c: FsInspectIoCounts = sized();
        assert_eq!(fs_inspect_io_stats_get_counts(stats, &mut c), FS_INSPECT_OK);
        assert_eq!((c.reads, c.bytes, c.largest), (0, 0, 0));
        let limits = if traced { &d } else { &zero };
        let oo = FsInspectOpenOptions { io_stats: stats, limits, ..sized() };
        let src = FsInspectSourceOps { release: None, ..ops(v.image.clone()) };
        let disks = open(&[ops_spec(&src, true)], &oo).unwrap_or_else(|rc| panic!("{rc}: {}", last_error()));
        // The set keeps its own reference.
        let mut events = ptr::null_mut();
        assert_eq!(fs_inspect_io_stats_get_events(stats, &mut events), FS_INSPECT_OK);
        let vol = volume(disks, 0);
        let m = map_volume(vol, ptr::null());
        assert_eq!(fs_inspect_io_stats_get_counts(stats, &mut c), FS_INSPECT_OK);
        assert!(c.reads > 0 && c.bytes >= c.largest && c.largest > 0, "{c:?}");
        let mut n = usize::MAX;
        assert_eq!(fs_inspect_read_events_count(events, &mut n), FS_INSPECT_OK);
        let mut later = ptr::null_mut();
        assert_eq!(fs_inspect_io_stats_get_events(stats, &mut later), FS_INSPECT_OK);
        let mut now = 0usize;
        assert_eq!(fs_inspect_read_events_count(later, &mut now), FS_INSPECT_OK);
        if traced {
            assert!(now > n, "a snapshot holds the reads recorded when taken: {n} then {now}");
            let mut e: FsInspectReadEvent = sized();
            assert_eq!(fs_inspect_read_events_get(later, 0, &mut e), FS_INSPECT_OK);
            assert!(e.ok && e.length > 0 && !e.phase.is_null(), "{e:?}");
            assert_eq!(fs_inspect_read_events_get(later, now, &mut e), FS_INSPECT_E_NOT_FOUND);
        } else {
            assert_eq!((n, now), (0, 0), "not traced: no reads recorded");
        }
        fs_inspect_read_events_free(events);
        fs_inspect_read_events_free(later);
        fs_inspect_map_free(m);
        fs_inspect_volume_free(vol);
        fs_inspect_io_stats_free(stats);
        fs_inspect_disks_free(disks);
    }
    fs_inspect_io_stats_free(ptr::null_mut());
    let mut c: FsInspectIoCounts = sized();
    assert_eq!(fs_inspect_io_stats_get_counts(ptr::null(), &mut c), FS_INSPECT_E_INVALID_ARGUMENT);
    // A limits struct too short to be one is refused.
    let short = FsInspectLimits { struct_size: 4, ..sized() };
    let oo = FsInspectOpenOptions { limits: &short, ..sized() };
    let src = FsInspectSourceOps { release: None, ..ops(v.image.clone()) };
    assert_eq!(open(&[ops_spec(&src, true)], &oo).unwrap_err(), FS_INSPECT_E_INVALID_ARGUMENT);
}

/// A volume read from a shorter reader, the rest from its disk: each byte read once, counted
/// once.
#[test]
fn a_shorter_volume_reader_counts_each_byte_once() {
    let v = SyntheticVolume::format(VolumeSpec { clusters: 2048, ..Default::default() });
    let len = v.image.len();
    let mut stats = ptr::null_mut();
    assert_eq!(fs_inspect_io_stats_new(0, &mut stats), FS_INSPECT_OK);
    let oo = FsInspectOpenOptions { io_stats: stats, ..sized() };
    let src = FsInspectSourceOps { release: None, ..ops(v.image.clone()) };
    let disks = open(&[ops_spec(&src, true)], &oo).unwrap_or_else(|rc| panic!("{rc}: {}", last_error()));
    let (short_ops, _) = counted(vec![0xEE; len / 2]);
    let short = source(&short_ops);
    let mut tailed = ptr::null_mut();
    assert_eq!(
        fs_inspect_disks_replace_volume_source(
            disks,
            0,
            short,
            FS_INSPECT_VOLUME_TAIL_DEVICE,
            &mut tailed,
            ptr::null()
        ),
        FS_INSPECT_OK,
        "{}",
        last_error()
    );
    fs_inspect_source_free(short);
    let mut before: FsInspectIoCounts = sized();
    assert_eq!(fs_inspect_io_stats_get_counts(stats, &mut before), FS_INSPECT_OK);
    let mut b = vec![0u8; len];
    assert_eq!(
        fs_inspect_disks_read_at(tailed, disk_ref(0), 0, b.as_mut_ptr(), len, ptr::null()),
        FS_INSPECT_OK,
        "{}",
        last_error()
    );
    let mut after: FsInspectIoCounts = sized();
    assert_eq!(fs_inspect_io_stats_get_counts(stats, &mut after), FS_INSPECT_OK);
    assert!(b[..len / 2].iter().all(|&x| x == 0xEE));
    assert!(b[len / 2..] == v.image[len / 2..]);
    assert_eq!(after.bytes - before.bytes, len as u64);
    fs_inspect_disks_free(tailed);
    fs_inspect_disks_free(disks);
    fs_inspect_io_stats_free(stats);
}

#[test]
fn split_images_from_their_segments() {
    let mut v = SyntheticVolume::format(VolumeSpec { clusters: 1024, ..Default::default() });
    v.create_file(ROOT, "a.bin", 10_000, 1, Placement::FirstFit);
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let half = v.image.len() / 2;
    let names: Vec<CString> = [(0, half), (half, v.image.len())]
        .iter()
        .enumerate()
        .map(|(i, &(a, b))| {
            let p = dir.join(format!("vol.{:03}", i + 1));
            std::fs::write(&p, &v.image[a..b]).unwrap();
            CString::new(p.to_str().unwrap()).unwrap()
        })
        .collect();
    let ptrs: Vec<_> = names.iter().map(|c| c.as_ptr()).collect();
    let check = |paths: &[*const c_char]| {
        let spec = FsInspectDiskSpec { paths: paths.as_ptr(), path_count: paths.len(), ..sized() };
        let disks = open(&[spec], ptr::null()).unwrap_or_else(|rc| panic!("{rc}: {}", last_error()));
        let info = device_info(disks, 0);
        assert_eq!(
            (info.origin, info.format, info.size),
            (FS_INSPECT_ORIGIN_FILE, FS_INSPECT_CONTAINER_FORMAT_SPLIT, v.image.len() as u64)
        );
        fs_inspect_disks_free(disks);
    };
    // The segments, or the first alone (the rest found by name).
    check(&ptrs);
    check(&ptrs[..1]);
    let spec = FsInspectDiskSpec { paths: ptr::null(), path_count: 2, ..sized() };
    assert_eq!(open(&[spec], ptr::null()).unwrap_err(), FS_INSPECT_E_INVALID_ARGUMENT);
}

/// A disk set through the C API: an LVM volume group over two disks (testkit's writer), its
/// container, logical volume, member partitions and per-disk maps.
#[test]
fn disk_set_with_lvm() {
    use fs_inspect_testkit::disk::{self, DiskPart, GPT_LINUX_LVM};
    use fs_inspect_testkit::volmgr::{LvmLv, LvmPvDef, LvmSeg, LvmVg, write_lvm_pv};
    const MIB: usize = 1 << 20;
    let pv = |n: &str, u: char| LvmPvDef {
        name: n.into(),
        uuid: u.to_string().repeat(32),
        pe_start_sectors: 2048,
        pe_count: 7,
    };
    let vg = LvmVg {
        name: "vgc".into(),
        id: "C".repeat(32),
        seqno: 1,
        extent_sectors: 2048,
        pvs: vec![pv("pv0", 'A'), pv("pv1", 'B')],
        lvs: vec![LvmLv {
            name: "lv".into(),
            visible: true,
            segments: vec![LvmSeg::linear(0, 2, "pv0", 0), LvmSeg::linear(2, 2, "pv1", 3)],
        }],
    };
    let mut sources = Vec::new();
    for u in ['A', 'B'] {
        let mut b = vec![0u8; 8 * MIB];
        write_lvm_pv(&mut b, &u.to_string().repeat(32), &vg.text(), (MIB - 4096) as u64, None);
        let d = disk::disk_image(disk::TableKind::Gpt, 512, &[DiskPart::typed(&b, 0x8E, GPT_LINUX_LVM)]);
        sources.push(ops(d.image));
    }
    let specs: Vec<_> = sources.iter().map(|o| ops_spec(o, true)).collect();
    let set = open(&specs, ptr::null()).unwrap_or_else(|rc| panic!("{rc}: {}", last_error()));
    let cs = Containers::of(set);
    assert_eq!(cs.count(), 1);
    let c = cs.get(0);
    assert_eq!((c.kind, c.status), (FS_INSPECT_CONTAINER_KIND_LVM, FS_INSPECT_CONTAINER_STATUS_COMPLETE));
    assert_eq!(cstr(c.name), "vgc");
    assert!(!cstr(c.id).is_empty());
    let mut lvs = ptr::null_mut();
    assert_eq!(fs_inspect_containers_lvs(cs.0, 0, &mut lvs), FS_INSPECT_OK);
    let mut n_lv = usize::MAX;
    assert_eq!(fs_inspect_logical_volumes_count(lvs, &mut n_lv), FS_INSPECT_OK);
    assert_eq!(n_lv, 1);
    let mut lv: FsInspectLogicalVolume = sized();
    assert_eq!(fs_inspect_logical_volumes_get(lvs, 0, &mut lv), FS_INSPECT_OK);
    assert_eq!((lv.readable, lv.extent_count, lv.size), (FS_INSPECT_READABLE_FULL, 2, 4 * MIB as u64));
    let lv_ref = FsInspectDeviceRef { kind: FS_INSPECT_DEVICE_LOGICAL, disk: 0, container: 0, lv: 0 };
    assert_eq!((lv.has_device, lv.device), (true, lv_ref));
    assert!(cstr(lv.id).contains(&cstr(c.id)), "{} in {}", cstr(c.id), cstr(lv.id));
    let mut x = [FsInspectMemberArea::default(); 4];
    let mut got_x = usize::MAX;
    assert_eq!(fs_inspect_logical_volumes_extents_read(lvs, 0, 1, x.as_mut_ptr(), 4, &mut got_x), FS_INSPECT_OK);
    assert_eq!(got_x, 1);
    assert_eq!((x[0].member, x[0].offset, x[0].length), (1, (MIB + 3 * MIB) as u64, 2 * MIB as u64));
    let mut lv_vols = [u32::MAX; 2];
    assert_eq!(fs_inspect_logical_volumes_volumes_read(lvs, 0, 0, lv_vols.as_mut_ptr(), 2, &mut got_x), FS_INSPECT_OK);
    assert_eq!(lv_vols[..got_x], [0]);
    let mut ms = ptr::null_mut();
    assert_eq!(fs_inspect_containers_members(cs.0, 0, &mut ms), FS_INSPECT_OK);
    let mut n_m = usize::MAX;
    assert_eq!(fs_inspect_members_count(ms, &mut n_m), FS_INSPECT_OK);
    assert_eq!(n_m, 2);
    let mut m: FsInspectMember = sized();
    assert_eq!(fs_inspect_members_get(ms, 1, &mut m), FS_INSPECT_OK);
    assert_eq!((m.found, m.device, m.offset), (true, disk_ref(1), MIB as u64));
    assert_eq!((m.role, cstr(m.role_name).as_str()), (FS_INSPECT_MEMBER_ROLE_PV, "pv1"), "the role and the PV's name");
    // The member partitions are in the structure view, not the volume list.
    let (info, parts) = partitions(set, disk_ref(1));
    assert_eq!((info.kind, parts.len()), (FS_INSPECT_PARTITION_TABLE_READ, 1));
    let part = parts[0];
    assert_eq!(
        (part.role, part.container, part.member, part.offset),
        (FS_INSPECT_PARTITION_ROLE_MEMBER, 0, 1, MIB as u64)
    );
    assert_eq!(part.fs_kind, 0);
    // The one volume: the logical volume's (raw: no file system).
    let vols = Vols::of(set);
    assert_eq!(vols.count(), 1);
    let v = vols.get(0);
    assert_eq!((v.location, v.device, v.readable), (FS_INSPECT_LOCATION_DEVICE, lv_ref, FS_INSPECT_READABLE_FULL));
    // The logical volume has no partition table: one partition, the whole device.
    let (info, parts) = partitions(set, lv_ref);
    assert_eq!((info.kind, parts.len()), (FS_INSPECT_PARTITION_TABLE_READ, 1));
    assert_eq!(
        (parts[0].role, parts[0].volume, parts[0].scheme),
        (FS_INSPECT_PARTITION_ROLE_VOLUME, 0, FS_INSPECT_SCHEME_NONE)
    );
    // The logical volume as a device.
    let mut lvi: FsInspectDeviceInfo = sized();
    assert_eq!(fs_inspect_disks_device_info(set, lv_ref, &mut lvi, ptr::null()), FS_INSPECT_OK, "{}", last_error());
    assert_eq!((lvi.origin, lvi.size), (FS_INSPECT_ORIGIN_LOGICAL, 4 * MIB as u64));
    // The logical volume on the disks: its two extents.
    assert_eq!(v.disk_extent_count, 2);
    assert_eq!(vols.extents(0)[1], (1, (MIB + 4 * MIB) as u64, 2 * MIB as u64));
    let mut n = u32::MAX;
    let sel = CString::new("vgc/lv").unwrap();
    assert_eq!(fs_inspect_disks_find_volume(set, sel.as_ptr(), &mut n, ptr::null()), FS_INSPECT_OK);
    assert_eq!(n, 0);
    let key = CString::new(cstr(v.key)).unwrap();
    assert!(key.to_str().unwrap().starts_with("lv-"), "{key:?}");
    assert_eq!(fs_inspect_disks_find_volume(set, key.as_ptr(), &mut n, ptr::null()), FS_INSPECT_OK);
    assert_eq!(n, 0);
    let none = CString::new("vgc/none").unwrap();
    assert_eq!(fs_inspect_disks_find_volume(set, none.as_ptr(), &mut n, ptr::null()), FS_INSPECT_E_NOT_FOUND);
    // The volume on the logical volume says so.
    let lvol = volume(set, 0);
    let mut vi: FsInspectVolumeInfo = sized();
    assert_eq!(fs_inspect_volume_get_info(lvol, &mut vi), FS_INSPECT_OK);
    assert_eq!(
        (vi.logical_kind, cstr(vi.logical_container), cstr(vi.logical_volume)),
        (FS_INSPECT_CONTAINER_KIND_LVM, "vgc".to_string(), "lv".to_string())
    );
    fs_inspect_volume_free(lvol);
    // Disk 1's map: the PV's metadata (its first MiB) and the volume's 2 extents (raw: data).
    let map = map_disk(set, 1, ptr::null());
    let data = ranges(map, FS_INSPECT_BLOCK_CLASS_DATA, FS_INSPECT_UNIT_EXACT, 3);
    fs_inspect_map_free(map);
    let p = MIB as u64;
    assert_eq!(fs_inspect::range::subtract([ByteRange::new(p, MIB as u64)], data.clone()).count(), 0);
    assert_eq!(
        fs_inspect::range::subtract([ByteRange::new(p + 4 * MIB as u64, 2 * MIB as u64)], data.clone()).count(),
        0
    );
    let free = ByteRange::new(p + MIB as u64, 3 * MIB as u64);
    assert_eq!(fs_inspect::range::intersect(data, [free]).count(), 0, "free extents are not data");
    // The logical volume as a device (raw: all data), and where its last 2 MiB lie.
    assert_ne!(lv.mapping_digest, 0);
    assert_eq!(m.unsynced_count, 0);
    let mut lmap = ptr::null_mut();
    assert_eq!(
        fs_inspect_disks_map(set, lv_ref, ptr::null(), &mut lmap, ptr::null()),
        FS_INSPECT_OK,
        "{}",
        last_error()
    );
    assert_eq!(
        ranges(lmap, FS_INSPECT_BLOCK_CLASS_DATA, FS_INSPECT_UNIT_EXACT, 4),
        [ByteRange::new(0, 4 * MIB as u64)]
    );
    fs_inspect_map_free(lmap);
    let lv5 = FsInspectDeviceRef { lv: 5, ..lv_ref };
    assert_eq!(fs_inspect_disks_map(set, lv5, ptr::null(), &mut lmap, ptr::null()), FS_INSPECT_E_NOT_FOUND);
    let tail = [ByteRange::new(2 * MIB as u64, 2 * MIB as u64)];
    let mut ext = ptr::null_mut();
    let rc = fs_inspect_disks_device_to_disks(
        set,
        lv_ref,
        tail.as_ptr(),
        1,
        FS_INSPECT_PROJECTION_COPIES,
        &mut ext,
        ptr::null(),
    );
    assert_eq!(rc, FS_INSPECT_OK, "{}", last_error());
    assert_eq!(disk_extents(ext), [(1, p + 4 * MIB as u64, 2 * MIB as u64)]);
    let mut got = 0usize;
    let mut uns = [ByteRange::new(0, 0); 1];
    assert_eq!(fs_inspect_members_unsynced_read(ms, 1, 0, uns.as_mut_ptr(), 1, &mut got), FS_INSPECT_OK);
    assert_eq!(got, 0);
    fs_inspect_members_free(ms);
    fs_inspect_logical_volumes_free(lvs);
    drop((vols, cs));
    fs_inspect_disks_free(set);
}

/// One GPT disk whose only partition is an LVM PV of the 2-extent LV `vg1/lv` holding `fs`, or
/// with `half`, the first PV of a VG whose LV spans a second, missing, disk.
fn lvm_disk(fs: &[u8], half: bool) -> Vec<u8> {
    use fs_inspect_testkit::disk::{self, DiskPart, GPT_LINUX_LVM};
    use fs_inspect_testkit::volmgr::{LvmLv, LvmPvDef, LvmSeg, LvmVg, write_lvm_pv};
    const MIB: usize = 1 << 20;
    let pv = |n: &str, u: char| LvmPvDef {
        name: n.into(),
        uuid: u.to_string().repeat(32),
        pe_start_sectors: 2048,
        pe_count: 2,
    };
    let mut segments = vec![LvmSeg::linear(0, 2, "pv0", 0)];
    let mut pvs = vec![pv("pv0", 'A')];
    if half {
        pvs.push(pv("pv1", 'B'));
        segments.push(LvmSeg::linear(2, 2, "pv1", 0));
    }
    let vg = LvmVg {
        name: "vg1".into(),
        id: "D".repeat(32),
        seqno: 1,
        extent_sectors: 2048,
        pvs,
        lvs: vec![LvmLv { name: "lv".into(), visible: true, segments }],
    };
    let mut b = vec![0u8; 3 * MIB];
    write_lvm_pv(&mut b, &"A".repeat(32), &vg.text(), (MIB - 4096) as u64, None);
    b[MIB..MIB + fs.len()].copy_from_slice(fs);
    disk::disk_image(disk::TableKind::Gpt, 512, &[DiskPart::typed(&b, 0x8E, GPT_LINUX_LVM)]).image
}

/// A disk opened by path, its volume on the logical volume opened and mapped like the volume
/// alone; moved to disk coordinates it has no single place.
#[test]
fn disk_by_path_and_logical_volume() {
    let mut v = SyntheticVolume::format(VolumeSpec { clusters: 400, ..Default::default() });
    v.create_file(ROOT, "a.bin", 300_000, 1, Placement::FirstFit);
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let path = dir.join("d.img");
    std::fs::write(&path, lvm_disk(&v.image, false)).unwrap();
    let by_path = |p: &CString| {
        let paths = [p.as_ptr()];
        let spec = FsInspectDiskSpec { paths: paths.as_ptr(), path_count: 1, ..sized() };
        open(&[spec], ptr::null())
    };
    let p = CString::new(path.to_str().unwrap()).unwrap();
    let set = by_path(&p).unwrap_or_else(|rc| panic!("{rc}: {}", last_error()));
    // A missing file: not found (as the OS says).
    let missing = CString::new(dir.join("none.img").to_str().unwrap()).unwrap();
    assert_eq!(by_path(&missing).unwrap_err(), FS_INSPECT_E_NOT_FOUND, "{}", last_error());

    let sel = CString::new("vg1/lv").unwrap();
    let mut index = 0u32;
    assert_eq!(
        fs_inspect_disks_find_volume(set, sel.as_ptr(), &mut index, ptr::null()),
        FS_INSPECT_OK,
        "{}",
        last_error()
    );
    let vol = volume(set, index);
    let mut info: FsInspectVolumeInfo = sized();
    assert_eq!(fs_inspect_volume_get_info(vol, &mut info), FS_INSPECT_OK);
    assert_eq!((info.fs_kind, info.size), (FS_INSPECT_FS_NTFS, v.image.len() as u64), "NTFS on the LV");
    let map = map_volume(vol, ptr::null());
    let on_lv = ranges(map, FS_INSPECT_BLOCK_CLASS_DATA, FS_INSPECT_UNIT_EXACT, 4);
    fs_inspect_map_free(map);
    assert_eq!(on_lv, rust_volume(&v.image, 0, &VolumeMapOptions::default(), BlockClass::Data, 1));
    fs_inspect_volume_free(vol);
    let mut vol = ptr::null_mut();
    assert_eq!(fs_inspect_disks_open_volume(set, 99, &mut vol, ptr::null()), FS_INSPECT_E_NOT_FOUND);
    assert_eq!(fs_inspect_disks_open_volume(set, index, ptr::null_mut(), ptr::null()), FS_INSPECT_E_INVALID_ARGUMENT);

    // Complete: no diagnostics.
    let (diags, dropped) = set_diags_dropped(set);
    assert_eq!((diags.len(), dropped), (0, 0));
    fs_inspect_disks_free(set);
}

/// A set missing a disk: the incomplete volume group is reported, through each accessor.
#[test]
fn set_diagnostics() {
    let v = SyntheticVolume::format(VolumeSpec { clusters: 400, ..Default::default() });
    let set = open_raw(lvm_disk(&v.image, true));
    let cs = Containers::of(set);
    assert_eq!(cs.get(0).status, FS_INSPECT_CONTAINER_STATUS_INCOMPLETE);
    let mut ms = ptr::null_mut();
    assert_eq!(fs_inspect_containers_members(cs.0, 0, &mut ms), FS_INSPECT_OK);
    let mut m: FsInspectMember = sized();
    assert_eq!(fs_inspect_members_get(ms, 1, &mut m), FS_INSPECT_OK);
    assert!(!m.found);
    fs_inspect_members_free(ms);
    drop(cs);
    let all = set_diags(set);
    assert!(!all.is_empty(), "an incomplete container is reported");
    for d in &all {
        assert!(!d.message.is_empty());
        assert_ne!((d.d.severity, d.d.code), (0, 0));
    }
    assert!(all.iter().any(|d| d.logical.starts_with("lvm:vg1")), "a diagnostic names the volume group");
    assert!(all.iter().any(|d| d.d.code == FS_INSPECT_DIAG_CONTAINER_INCOMPLETE));
    let mut info: FsInspectDiagnosticsInfo = sized();
    assert_eq!(fs_inspect_diagnostics_get_info(ptr::null(), &mut info), FS_INSPECT_E_INVALID_ARGUMENT);
    fs_inspect_disks_free(set);
}

/// A volume's state: consistent; inconsistent and its replay failed (a synthetic volume's
/// `$LogFile` holds no restart area), or replay turned off; unknown open flags are refused.
#[test]
fn volume_state() {
    let state = |data: Vec<u8>, opts: *const FsInspectOpenOptions| {
        let o = FsInspectSourceOps { release: None, ..ops(data) };
        let disks = open(&[ops_spec(&o, true)], opts).unwrap();
        let vol = volume(disks, 0);
        let mut s: FsInspectVolumeStateInfo = sized();
        assert_eq!(fs_inspect_volume_state(vol, &mut s, ptr::null()), FS_INSPECT_OK, "{}", last_error());
        let why = cstr(s.why);
        fs_inspect_volume_free(vol);
        fs_inspect_disks_free(disks);
        (s, why)
    };
    let v = SyntheticVolume::format(VolumeSpec { clusters: 4096, ..Default::default() });
    let (s, why) = state(v.image.clone(), ptr::null());
    assert_eq!((s.kind, s.not_replayed, s.replay_status), (FS_INSPECT_VOLUME_STATE_CLEAN, 0, 0));
    assert_eq!(why, "");

    // Clear the clean flag of both $LogFile restart pages.
    let mut img = v.image.clone();
    let lcn = v.logfile_runs[0].lcn().unwrap();
    for page in [0, 4096] {
        img[(lcn * v.cs() + page) as usize + 0x3E] = 0;
    }
    let (s, why) = state(img.clone(), ptr::null());
    assert_eq!((s.kind, s.not_replayed), (FS_INSPECT_VOLUME_STATE_INCONSISTENT, FS_INSPECT_NOT_REPLAYED_FAILED));
    assert_eq!(s.replay_status, FS_INSPECT_E_CORRUPT, "{why}");
    assert!(!s.allocation_covered);
    assert!(why.contains("$LogFile"), "{why}");

    let no_replay = FsInspectOpenOptions { flags: FS_INSPECT_OPEN_FLAG_NO_REPLAY, ..sized() };
    let (s, _) = state(img, &no_replay);
    assert_eq!((s.kind, s.not_replayed), (FS_INSPECT_VOLUME_STATE_INCONSISTENT, FS_INSPECT_NOT_REPLAYED_DISABLED));

    let unknown = FsInspectOpenOptions { flags: 1 << 31, ..sized() };
    let o = FsInspectSourceOps { release: None, ..ops(v.image) };
    assert_eq!(open(&[ops_spec(&o, true)], &unknown).unwrap_err(), FS_INSPECT_E_UNSUPPORTED);
    assert!(last_error().contains("fs_inspect_open_options.flags 0x80000000: unknown bits"), "{}", last_error());
}

/// A Windows system whose SYSTEM hive is damaged: the catalog says which volume's system files
/// could not be read and why (`_GUEST_UNREAD`, damaged); a problem past the last is
/// `FS_INSPECT_E_NOT_FOUND`, a NULL catalog an invalid argument.
#[test]
fn a_catalog_names_the_system_volume_it_could_not_read() {
    use fs_inspect::BlockSource;
    let mut hive = fs_inspect_testkit::regf::HiveBuilder::new()
        .key("MountedDevices")
        .value_binary(r"\DosDevices\C:", &[0; 24])
        .build();
    hive[0x1000..0x1004].copy_from_slice(b"junk");
    let mut v = SyntheticVolume::format(VolumeSpec { clusters: 4096, ..Default::default() });
    let w = v.create_dir(ROOT, "Windows");
    let s = v.create_dir(w, "System32");
    let c = v.create_dir(s, "config");
    let f = v.create_file(c, "SYSTEM", hive.len() as u64, 2, Placement::FirstFit);
    let runs = v.file(f).data().expect("data").runs().to_vec();
    v.write_stream(&runs, 0, &hive);
    let src = v.source();
    let disks = open_raw(src.read_vec(0, src.size() as usize).unwrap());
    let mut cat = ptr::null_mut();
    assert_eq!(fs_inspect_disks_catalog(disks, &mut cat, ptr::null()), FS_INSPECT_OK, "{}", last_error());
    let mut n = 0usize;
    assert_eq!(fs_inspect_catalog_problem_count(cat, &mut n), FS_INSPECT_OK);
    assert_eq!(n, 1);
    let mut p: FsInspectCatalogProblem = sized();
    assert_eq!(fs_inspect_catalog_problem_get(cat, 0, &mut p), FS_INSPECT_OK, "{}", last_error());
    assert_eq!(
        (p.kind, p.unreadable, p.has_volume, p.volume),
        (FS_INSPECT_CATALOG_PROBLEM_GUEST_UNREAD, FS_INSPECT_DISK_PROBLEM_DAMAGED, true, 0)
    );
    assert_eq!(fs_inspect_catalog_problem_get(cat, 1, &mut p), FS_INSPECT_E_NOT_FOUND);
    assert_eq!(last_error(), "no problem 1 (1 in all)");
    assert_eq!(fs_inspect_catalog_problem_count(ptr::null(), &mut n), FS_INSPECT_E_INVALID_ARGUMENT);
    fs_inspect_catalog_free(cat);
    fs_inspect_disks_free(disks);
}
