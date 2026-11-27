//! The guest systems and the catalog through the C ABI, on Linux on LVM over two disks
//! (`fixtures/guest/linux`) read through callbacks with `read_parts`, a file's presence, and
//! what a caller's source handle owns and how many of its reads run at once.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code
#![allow(unsafe_code)]

use fs_inspect::BlockSource;
use fs_inspect::ByteRange;
use fs_inspect_ffi::*;
use fs_inspect_testkit::sparse::SparseSource;
use std::ffi::{CStr, c_void};
use std::ptr;
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};

fn last_error() -> String {
    // SAFETY: the library's thread-local message, NUL terminated.
    unsafe { CStr::from_ptr(fs_inspect_last_error_message()) }.to_string_lossy().into_owned()
}

fn text(p: *const std::ffi::c_char) -> Option<String> {
    // SAFETY: NULL or the library's NUL-terminated text, alive with its snapshot.
    (!p.is_null()).then(|| unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
}

/// A callback source's context: the fixture, how often each callback ran, and the code every
/// read fails with (0: none fails; a test may change it).
struct Ctx {
    src: std::sync::Arc<SparseSource>,
    whole: AtomicUsize,
    parts: AtomicUsize,
    fails: AtomicI32,
}

extern "C" fn read_at(ctx: *mut c_void, offset: u64, buf: *mut u8, len: usize) -> i32 {
    // SAFETY: ctx is the test's Ctx; buf has room for len bytes.
    let c = unsafe { &*(ctx as *const Ctx) };
    c.whole.fetch_add(1, Ordering::Relaxed);
    let fails = c.fails.load(Ordering::SeqCst);
    if fails != 0 {
        return fails;
    }
    let buf = unsafe { std::slice::from_raw_parts_mut(buf, len) };
    if c.src.read_exact_at(offset, buf).is_ok() { 0 } else { -1 }
}

/// Fills only the parts; the bytes between them get a pattern no one may see.
extern "C" fn read_parts(
    ctx: *mut c_void,
    offset: u64,
    buf: *mut u8,
    len: usize,
    parts: *const ByteRange,
    count: usize,
) -> i32 {
    // SAFETY: ctx is the test's Ctx; buf has room for len bytes, parts for count ranges.
    let c = unsafe { &*(ctx as *const Ctx) };
    c.parts.fetch_add(1, Ordering::Relaxed);
    let fails = c.fails.load(Ordering::SeqCst);
    if fails != 0 {
        return fails;
    }
    let buf = unsafe { std::slice::from_raw_parts_mut(buf, len) };
    let parts = unsafe { std::slice::from_raw_parts(parts, count) };
    buf.fill(0xEE);
    let mut end = 0;
    for p in parts {
        let (s, e) = (p.offset as usize, (p.offset + p.length) as usize);
        assert!(s >= end && e <= len, "parts sorted, apart, inside the buffer");
        end = e;
        if c.src.read_exact_at(offset + p.offset, &mut buf[s..e]).is_err() {
            return -1;
        }
    }
    0
}

extern "C" fn release(ctx: *mut c_void) {
    // SAFETY: ctx came from Box::into_raw below.
    drop(unsafe { Box::from_raw(ctx as *mut Ctx) });
}

struct Disks {
    disks: *mut FsInspectDisks,
    /// The contexts, alive until the set releases them.
    ctxs: Vec<*const Ctx>,
}

impl Drop for Disks {
    fn drop(&mut self) {
        fs_inspect_disks_free(self.disks);
    }
}

impl Disks {
    /// From now on every read of every disk fails with `status`.
    fn fail_with(&self, status: i32) {
        for &c in &self.ctxs {
            // SAFETY: the set holds the contexts until it is freed.
            unsafe { &*c }.fails.store(status, Ordering::SeqCst);
        }
    }

    fn calls(&self) -> (usize, usize) {
        self.ctxs.iter().fold((0, 0), |(w, p), &c| {
            // SAFETY: the set holds the contexts until it is freed.
            let c = unsafe { &*c };
            (w + c.whole.load(Ordering::Relaxed), p + c.parts.load(Ordering::Relaxed))
        })
    }
}

fn open(fixtures: &[&str]) -> Disks {
    open_failing(fixtures, &[])
}

/// [`open`], the reads of disk `i` failing with `fails[i]` (0 or past its end: none); a fixture
/// `""` is a place with no disk, its bytes missing.
fn open_failing(fixtures: &[&str], fails: &[i32]) -> Disks {
    let mut ctxs = Vec::new();
    let sources: Vec<*mut FsInspectSource> = fixtures
        .iter()
        .enumerate()
        .map(|(i, f)| {
            if f.is_empty() {
                return ptr::null_mut();
            }
            let src = SparseSource::open(fs_inspect_testkit::fixture(f));
            let len = src.size();
            let fails = fails.get(i).copied().unwrap_or(0);
            let ctx = Box::into_raw(Box::new(Ctx {
                src,
                whole: AtomicUsize::new(0),
                parts: AtomicUsize::new(0),
                fails: AtomicI32::new(fails),
            }));
            ctxs.push(ctx as *const Ctx);
            let ops = FsInspectSourceOps {
                ctx: ctx as *mut c_void,
                read_at: Some(read_at),
                size: len,
                release: Some(release),
                read_parts: Some(read_parts),
                ..sized()
            };
            let mut source = ptr::null_mut();
            assert_eq!(fs_inspect_source_new(&ops, &mut source), FS_INSPECT_OK, "{}", last_error());
            source
        })
        .collect();
    let specs: Vec<FsInspectDiskSpec> = sources
        .iter()
        .map(|&s| match s.is_null() {
            false => FsInspectDiskSpec { source: s, flags: FS_INSPECT_DISK_FLAG_RAW, ..sized() },
            true => FsInspectDiskSpec { absent: FS_INSPECT_DISK_PROBLEM_DATA_MISSING, ..sized() },
        })
        .collect();
    let mut disks = ptr::null_mut();
    assert_eq!(
        fs_inspect_disks_open(specs.as_ptr(), specs.len(), ptr::null(), &mut disks, ptr::null()),
        FS_INSPECT_OK,
        "{}",
        last_error()
    );
    // The set holds what it reads: the caller's handles go.
    sources.into_iter().for_each(|s| fs_inspect_source_free(s));
    Disks { disks, ctxs }
}

struct Catalog(*mut FsInspectCatalog);

impl Drop for Catalog {
    fn drop(&mut self) {
        fs_inspect_catalog_free(self.0);
    }
}

fn catalog(d: &Disks) -> Catalog {
    let mut c = ptr::null_mut();
    assert_eq!(fs_inspect_disks_catalog(d.disks, &mut c, ptr::null()), FS_INSPECT_OK, "{}", last_error());
    Catalog(c)
}

fn group(c: &Catalog, g: usize) -> FsInspectCatalogGroup {
    let mut out: FsInspectCatalogGroup = sized();
    assert_eq!(fs_inspect_catalog_group_get(c.0, g, &mut out), FS_INSPECT_OK, "{}", last_error());
    out
}

fn volume(c: &Catalog, v: usize) -> FsInspectCatalogVolume {
    let mut out: FsInspectCatalogVolume = sized();
    assert_eq!(fs_inspect_catalog_volume_get(c.0, v, &mut out), FS_INSPECT_OK, "{}", last_error());
    out
}

/// What a `fs_inspect_catalog_*_disks_read`/`_volumes_read` call copies out.
fn listed(f: impl Fn(usize, *mut u32, usize, *mut usize) -> i32) -> Vec<u32> {
    let (mut buf, mut got) = ([u32::MAX; 8], 0usize);
    assert_eq!(f(0, buf.as_mut_ptr(), buf.len(), &mut got), FS_INSPECT_OK, "{}", last_error());
    buf[..got].to_vec()
}

#[test]
fn a_catalog_lists_names_and_opens_the_volumes() {
    let d = open(&["guest/linux/lvm-disk1.fsbs", "guest/linux/lvm-disk2.fsbs"]);
    let c = catalog(&d);
    let mut n = 0;
    assert_eq!(fs_inspect_catalog_volume_count(c.0, &mut n), FS_INSPECT_OK);
    let names: Vec<String> = (0..n).map(|v| text(volume(&c, v).name).unwrap()).collect();
    assert_eq!(names, ["root (/)", "boot (/boot)", "home (/home)", "EFI (/boot/efi)", "data (/srv/my data)"]);

    assert_eq!(fs_inspect_catalog_group_count(c.0, &mut n), FS_INSPECT_OK);
    assert_eq!(n, 2);
    let (disk, vg) = (group(&c, 0), group(&c, 1));
    assert_eq!(text(disk.name).as_deref(), Some("Disk 1"));
    assert_eq!((disk.kind, disk.disk), (FS_INSPECT_CATALOG_GROUP_DISK, 0));
    assert_eq!((vg.kind, vg.container_kind), (FS_INSPECT_CATALOG_GROUP_CONTAINER, FS_INSPECT_CONTAINER_KIND_LVM));
    assert_eq!(text(disk.key).as_deref(), Some("disk-1"));
    let vg_key = text(vg.key).unwrap();
    assert!(vg_key.starts_with("lvm-") && vg_key.len() > "lvm-".len(), "{vg_key:?}");
    assert_eq!(vg_key, vg_key.to_lowercase());
    assert_eq!(listed(|f, b, cap, got| fs_inspect_catalog_group_disks_read(c.0, 1, f, b, cap, got)), [0, 1]);
    assert_eq!(listed(|f, b, cap, got| fs_inspect_catalog_group_volumes_read(c.0, 1, f, b, cap, got)), [0, 2, 4]);
    assert_eq!(vg.volume_count, 3);

    let root = volume(&c, 0);
    assert_eq!((root.group, root.fs_kind, root.unreadable), (1, FS_INSPECT_FS_EXT4, 0));
    assert_eq!((root.readable, root.state), (FS_INSPECT_READABLE_FULL, FS_INSPECT_CATALOG_STATE_READABLE));
    let mut problems = usize::MAX;
    assert_eq!(fs_inspect_catalog_problem_count(c.0, &mut problems), FS_INSPECT_OK);
    assert_eq!(problems, 0);
    assert_eq!((root.mount_by, root.mount_os), (FS_INSPECT_MOUNT_BY_SYSTEM, FS_INSPECT_GUEST_OS_LINUX));
    assert_eq!(text(root.mount_at).as_deref(), Some("/"));
    assert_eq!(text(root.name).as_deref(), Some("root (/)"));
    assert!(text(root.id).unwrap().starts_with("lv-"), "{:?}", text(root.id));
    // Each volume lives on its own disks, not its whole group's.
    let root_disks = listed(|f, b, cap, got| fs_inspect_catalog_volume_disks_read(c.0, 0, f, b, cap, got));
    assert_eq!((root.disk_count, root_disks.len()), (1, 1));
    let boot = listed(|f, b, cap, got| fs_inspect_catalog_volume_disks_read(c.0, 1, f, b, cap, got));
    assert_eq!(boot, [0]);

    // The disks: none says it cannot be read.
    assert_eq!(fs_inspect_catalog_disk_count(c.0, &mut n), FS_INSPECT_OK);
    assert_eq!(n, 2);
    let mut disk1: FsInspectCatalogDisk = sized();
    assert_eq!(fs_inspect_catalog_disk_get(c.0, 1, &mut disk1), FS_INSPECT_OK);
    assert_eq!(disk1.problem, 0);
    assert_eq!(fs_inspect_catalog_disk_get(c.0, 2, &mut disk1), FS_INSPECT_E_NOT_FOUND);

    // Its file system opens from the catalog, its root a plain directory.
    let mut fs = ptr::null_mut();
    assert_eq!(fs_inspect_catalog_volume_fs(c.0, 0, &mut fs), FS_INSPECT_OK, "{}", last_error());
    let mut st: FsInspectStat = sized();
    assert_eq!(fs_inspect_fs_stat(fs, root.root_node, &mut st, ptr::null()), FS_INSPECT_OK, "{}", last_error());
    assert_eq!((st.kind, st.presence), (FS_INSPECT_NODE_DIR, FS_INSPECT_PRESENCE_NORMAL));
    // The file system outlives the catalog.
    drop(c);
    assert_eq!(fs_inspect_fs_stat(fs, root.root_node, &mut st, ptr::null()), FS_INSPECT_OK, "{}", last_error());
    fs_inspect_fs_free(fs);

    let (whole, parts) = d.calls();
    assert!(whole > 0 && parts > 0, "read_at {whole} times, read_parts {parts} times");
}

#[test]
fn the_guest_systems_and_their_mounts() {
    let d = open(&["guest/linux/lvm-disk1.fsbs", "guest/linux/lvm-disk2.fsbs"]);
    let mut g = ptr::null_mut();
    assert_eq!(fs_inspect_disks_guest(d.disks, &mut g, ptr::null()), FS_INSPECT_OK, "{}", last_error());
    let (mut systems, mut mounts) = (0, 0);
    assert_eq!(fs_inspect_guest_system_count(g, &mut systems), FS_INSPECT_OK);
    assert_eq!(fs_inspect_guest_mount_count(g, &mut mounts), FS_INSPECT_OK);
    assert_eq!(systems, 1);
    let mut s: FsInspectGuestSystem = sized();
    assert_eq!(fs_inspect_guest_system_get(g, 0, &mut s), FS_INSPECT_OK);
    assert_eq!(s.os, FS_INSPECT_GUEST_OS_LINUX);
    let at: Vec<String> = (0..mounts)
        .map(|i| {
            let mut m: FsInspectGuestMount = sized();
            assert_eq!(fs_inspect_guest_mount_get(g, i, &mut m), FS_INSPECT_OK);
            assert!(m.has_system && m.system == 0 && m.letter == 0);
            assert_eq!(m.at_kind, FS_INSPECT_MOUNT_POINT_PATH);
            text(m.at).unwrap()
        })
        .collect();
    for p in ["/", "/boot", "/boot/efi", "/home", "/srv/my data"] {
        assert!(at.iter().any(|a| a == p), "{p} in {at:?}");
    }
    let mut m: FsInspectGuestMount = sized();
    assert_eq!(fs_inspect_guest_mount_get(g, mounts, &mut m), FS_INSPECT_E_NOT_FOUND);
    fs_inspect_guest_free(g);
}

/// A place with no disk keeps the disks after it at their numbers, and is listed with why.
#[test]
fn an_absent_disk_keeps_its_place() {
    let d = open(&["", "", "guest/btrfs/fedora.fsbs"]);
    let c = catalog(&d);
    let g = group(&c, 0);
    assert_eq!((text(g.name).as_deref(), g.disk), (Some("Disk 3"), 2));
    let mut disk: FsInspectCatalogDisk = sized();
    assert_eq!(fs_inspect_catalog_disk_get(c.0, 0, &mut disk), FS_INSPECT_OK);
    assert_eq!(disk.problem, FS_INSPECT_DISK_PROBLEM_DATA_MISSING);
    assert_eq!(fs_inspect_catalog_disk_get(c.0, 2, &mut disk), FS_INSPECT_OK);
    assert_eq!(disk.problem, 0);
    // The set says the same of its places; a place with no disk has no bytes to describe.
    let mut sd: FsInspectSetDisk = sized();
    assert_eq!(fs_inspect_disks_disk_get(d.disks, 0, &mut sd), FS_INSPECT_OK);
    assert_eq!((sd.kind, sd.problem), (FS_INSPECT_SET_DISK_UNREADABLE, FS_INSPECT_DISK_PROBLEM_DATA_MISSING));
    assert_eq!(fs_inspect_disks_disk_get(d.disks, 2, &mut sd), FS_INSPECT_OK);
    assert_eq!((sd.kind, sd.problem), (FS_INSPECT_SET_DISK_PRESENT, 0));
    let dev = |disk| FsInspectDeviceRef { kind: FS_INSPECT_DEVICE_DISK, disk, container: 0, lv: 0 };
    let mut info: FsInspectDeviceInfo = sized();
    assert_eq!(fs_inspect_disks_device_info(d.disks, dev(0), &mut info, ptr::null()), FS_INSPECT_E_UNAVAILABLE);
    assert_eq!(fs_inspect_disks_device_info(d.disks, dev(2), &mut info, ptr::null()), FS_INSPECT_OK);
    assert_eq!(info.origin, FS_INSPECT_ORIGIN_EXTERNAL);
    // A disk spec with bytes and a problem both is refused.
    let ops = FsInspectSourceOps { read_at: Some(read_at), ..sized() };
    let mut source = ptr::null_mut();
    assert_eq!(fs_inspect_source_new(&ops, &mut source), FS_INSPECT_OK, "{}", last_error());
    let spec = FsInspectDiskSpec { source, absent: FS_INSPECT_DISK_PROBLEM_DAMAGED, ..sized() };
    let mut out = ptr::null_mut();
    assert_eq!(fs_inspect_disks_open(&spec, 1, ptr::null(), &mut out, ptr::null()), FS_INSPECT_E_INVALID_ARGUMENT);
    fs_inspect_source_free(source);
    // A problem that is not one is refused.
    let spec = FsInspectDiskSpec { absent: 99, ..sized() };
    assert_eq!(fs_inspect_disks_open(&spec, 1, ptr::null(), &mut out, ptr::null()), FS_INSPECT_E_INVALID_ARGUMENT);
}

#[test]
fn a_volume_that_cannot_be_read_says_why() {
    let d = open(&["zfs/linux/multi-a.fsbs"]);
    let c = catalog(&d);
    let v = volume(&c, 0);
    assert_eq!(
        (v.readable, v.unreadable, v.fs_kind),
        (FS_INSPECT_READABLE_NO, FS_INSPECT_DISK_PROBLEM_MEMBERS_MISSING, FS_INSPECT_FS_ZFS)
    );
    assert_eq!(v.state, FS_INSPECT_CATALOG_STATE_UNREADABLE);
    assert!(!text(v.name).unwrap().contains("unavailable"));
    let mut fs = ptr::null_mut();
    assert_eq!(fs_inspect_catalog_volume_fs(c.0, 0, &mut fs), FS_INSPECT_E_UNAVAILABLE);
    assert!(fs.is_null());
}

/// A reader that does not have a disk's bytes (`FS_INSPECT_E_DATA_MISSING`) leaves out what is
/// on that disk only: the catalog is made, the volumes of the other disk read.
#[test]
fn bytes_a_reader_does_not_have_leave_out_only_what_they_belong_to() {
    let d =
        open_failing(&["guest/linux/lvm-disk1.fsbs", "guest/linux/lvm-disk2.fsbs"], &[0, FS_INSPECT_E_DATA_MISSING]);
    let c = catalog(&d);
    let mut n = 0;
    assert_eq!(fs_inspect_catalog_volume_count(c.0, &mut n), FS_INSPECT_OK);
    let got: Vec<(String, u32)> = (0..n)
        .map(|v| {
            let v = volume(&c, v);
            (text(v.name).unwrap(), v.unreadable)
        })
        .collect();
    let unreadable = FS_INSPECT_DISK_PROBLEM_MEMBERS_MISSING;
    let none = 0;
    let want = [
        ("root (/)", none),
        ("boot (/boot)", none),
        ("EFI (/boot/efi)", none),
        ("home", unreadable),
        ("data", unreadable),
    ];
    assert_eq!(got, want.map(|(n, u)| (n.to_string(), u)));
    let mut disk: FsInspectCatalogDisk = sized();
    assert_eq!(fs_inspect_catalog_disk_get(c.0, 1, &mut disk), FS_INSPECT_OK);
    assert_eq!(disk.problem, FS_INSPECT_DISK_PROBLEM_DATA_MISSING);
}

/// A reader that holds a disk's bytes in a form it does not read (`FS_INSPECT_E_UNSUPPORTED`)
/// leaves out only that disk, which says so.
#[test]
fn bytes_a_reader_does_not_read_leave_out_only_what_they_belong_to() {
    let d = open_failing(&["guest/linux/lvm-disk1.fsbs", "guest/linux/lvm-disk2.fsbs"], &[0, FS_INSPECT_E_UNSUPPORTED]);
    let c = catalog(&d);
    let mut disk: FsInspectCatalogDisk = sized();
    assert_eq!(fs_inspect_catalog_disk_get(c.0, 1, &mut disk), FS_INSPECT_OK);
    assert_eq!(disk.problem, FS_INSPECT_DISK_PROBLEM_UNSUPPORTED);
    assert_eq!(fs_inspect_catalog_disk_get(c.0, 0, &mut disk), FS_INSPECT_OK);
    assert_eq!(disk.problem, 0);
}

/// A code `read_at` may not return is a failed read, its message saying so.
#[test]
fn a_code_outside_the_contract_is_a_failed_read() {
    let d = open_failing(&["guest/linux/lvm-disk1.fsbs"], &[7]);
    let mut b = [0u8; 512];
    let dev = FsInspectDeviceRef { kind: FS_INSPECT_DEVICE_DISK, disk: 0, container: 0, lv: 0 };
    assert_eq!(fs_inspect_disks_read_at(d.disks, dev, 0, b.as_mut_ptr(), b.len(), ptr::null()), FS_INSPECT_E_IO);
    assert!(last_error().contains("broke its contract"), "{}", last_error());
    assert_eq!(fs_inspect_status_scope(FS_INSPECT_E_IO), FS_INSPECT_SCOPE_SOURCE);
    let d = open_failing(&["guest/linux/lvm-disk1.fsbs"], &[FS_INSPECT_E_PERMISSION_DENIED]);
    assert_eq!(
        fs_inspect_disks_read_at(d.disks, dev, 0, b.as_mut_ptr(), b.len(), ptr::null()),
        FS_INSPECT_E_PERMISSION_DENIED
    );
}

/// A context that counts its releases and the reads in flight.
#[derive(Default)]
struct Counted {
    released: AtomicUsize,
    in_flight: AtomicUsize,
    most: AtomicUsize,
}

extern "C" fn counted_release(ctx: *mut c_void) {
    // SAFETY: ctx is the test's Counted, alive for the test.
    unsafe { &*(ctx as *const Counted) }.released.fetch_add(1, Ordering::SeqCst);
}

/// Zeros, slowly enough that reads from several threads overlap.
extern "C" fn counted_read(ctx: *mut c_void, _offset: u64, buf: *mut u8, len: usize) -> i32 {
    // SAFETY: ctx is the test's Counted; buf has room for len bytes.
    let c = unsafe { &*(ctx as *const Counted) };
    let now = c.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
    c.most.fetch_max(now, Ordering::SeqCst);
    unsafe { std::ptr::write_bytes(buf, 0, len) };
    std::thread::sleep(std::time::Duration::from_millis(2));
    c.in_flight.fetch_sub(1, Ordering::SeqCst);
    0
}

fn counted_ops(c: &Counted, queue_depth: u32) -> FsInspectSourceOps {
    FsInspectSourceOps {
        ctx: c as *const Counted as *mut c_void,
        read_at: Some(counted_read),
        size: 1 << 20,
        release: Some(counted_release),
        queue_depth,
        ..sized()
    }
}

/// `fs_inspect_source_new` owns the context only when it succeeds: a failed call never
/// releases it; a made source releases it once, when its handle and every set using it are
/// freed.
#[test]
fn a_source_owns_its_context_only_once_made() {
    let c = Counted::default();
    let mut source = ptr::null_mut();
    // Refused: no read_at, a bad sector size, no out. The context is still the caller's.
    let no_read = FsInspectSourceOps { read_at: None, ..counted_ops(&c, 0) };
    assert_eq!(fs_inspect_source_new(&no_read, &mut source), FS_INSPECT_E_INVALID_ARGUMENT);
    let bad_sector = FsInspectSourceOps { sector_size: 1000, ..counted_ops(&c, 0) };
    assert_eq!(fs_inspect_source_new(&bad_sector, &mut source), FS_INSPECT_E_INVALID_ARGUMENT);
    assert_eq!(fs_inspect_source_new(&counted_ops(&c, 0), ptr::null_mut()), FS_INSPECT_E_INVALID_ARGUMENT);
    assert!(source.is_null());
    assert_eq!(c.released.load(Ordering::SeqCst), 0);

    // Made and freed: released once.
    assert_eq!(fs_inspect_source_new(&counted_ops(&c, 0), &mut source), FS_INSPECT_OK, "{}", last_error());
    fs_inspect_source_free(source);
    assert_eq!(c.released.load(Ordering::SeqCst), 1);

    // Given to a set: released once both are freed, in either order.
    assert_eq!(fs_inspect_source_new(&counted_ops(&c, 0), &mut source), FS_INSPECT_OK);
    let spec = FsInspectDiskSpec { source, flags: FS_INSPECT_DISK_FLAG_RAW, ..sized() };
    let mut disks = ptr::null_mut();
    assert_eq!(
        fs_inspect_disks_open(&spec, 1, ptr::null(), &mut disks, ptr::null()),
        FS_INSPECT_OK,
        "{}",
        last_error()
    );
    fs_inspect_source_free(source);
    assert_eq!(c.released.load(Ordering::SeqCst), 1);
    fs_inspect_disks_free(disks);
    assert_eq!(c.released.load(Ordering::SeqCst), 2);

    // A set that fails to open does not take the source: the caller's handle still releases it.
    assert_eq!(fs_inspect_source_new(&counted_ops(&c, 0), &mut source), FS_INSPECT_OK);
    let bad = FsInspectDiskSpec { source, absent: FS_INSPECT_DISK_PROBLEM_DAMAGED, ..sized() };
    assert_eq!(fs_inspect_disks_open(&bad, 1, ptr::null(), &mut disks, ptr::null()), FS_INSPECT_E_INVALID_ARGUMENT);
    assert_eq!(c.released.load(Ordering::SeqCst), 2);
    fs_inspect_source_free(source);
    assert_eq!(c.released.load(Ordering::SeqCst), 3);
    fs_inspect_source_free(ptr::null_mut());
}

/// `queue_depth` is a hard limit: reads from many threads at once never overlap more.
#[test]
fn queue_depth_bounds_the_reads_in_flight() {
    for depth in [1u32, 2] {
        let c = Counted::default();
        let mut source = ptr::null_mut();
        assert_eq!(fs_inspect_source_new(&counted_ops(&c, depth), &mut source), FS_INSPECT_OK);
        let spec = FsInspectDiskSpec { source, flags: FS_INSPECT_DISK_FLAG_RAW, ..sized() };
        let mut disks = ptr::null_mut();
        assert_eq!(fs_inspect_disks_open(&spec, 1, ptr::null(), &mut disks, ptr::null()), FS_INSPECT_OK);
        fs_inspect_source_free(source);
        let set = disks as usize;
        std::thread::scope(|s| {
            for t in 0..6u64 {
                s.spawn(move || {
                    let dev = FsInspectDeviceRef { kind: FS_INSPECT_DEVICE_DISK, disk: 0, container: 0, lv: 0 };
                    let mut b = [0u8; 4096];
                    for i in 0..4u64 {
                        let at = (t * 16 + i) * 4096;
                        let got = fs_inspect_disks_read_at(
                            set as *const FsInspectDisks,
                            dev,
                            at,
                            b.as_mut_ptr(),
                            b.len(),
                            ptr::null(),
                        );
                        assert_eq!(got, FS_INSPECT_OK);
                    }
                });
            }
        });
        let most = c.most.load(Ordering::SeqCst);
        assert!(most >= 1 && most <= depth as usize, "{most} reads in flight with queue_depth {depth}");
        fs_inspect_disks_free(disks);
        assert_eq!(c.released.load(Ordering::SeqCst), 1);
    }
}

/// Where a failure happened: a read failing inside a structure a file system was reading is
/// placed in the volume with the structure's name, as the thread's last error; it lasts until
/// the next call on the thread.
#[test]
fn an_error_s_location() {
    let d = open(&["guest/linux/lvm-disk1.fsbs", "guest/linux/lvm-disk2.fsbs"]);
    let c = catalog(&d);
    let root = volume(&c, 0);
    let mut fs = ptr::null_mut();
    assert_eq!(fs_inspect_catalog_volume_fs(c.0, 0, &mut fs), FS_INSPECT_OK, "{}", last_error());
    let resolve = |path: &str, n: &mut FsInspectNode| {
        let path = std::ffi::CString::new(path).unwrap();
        fs_inspect_fs_resolve(fs, root.root_node.root, path.as_ptr(), n, ptr::null())
    };
    let mut tool = FsInspectNode::default();
    assert_eq!(resolve("/usr/bin/tool", &mut tool), FS_INSPECT_OK, "{}", last_error());
    d.fail_with(FS_INSPECT_E_IO);
    let mut n = FsInspectNode::default();
    assert_eq!(resolve("/root/.profile", &mut n), FS_INSPECT_E_IO, "{}", last_error());
    let mut loc: FsInspectErrorLocation = sized();
    assert!(fs_inspect_last_error_location(&mut loc), "{}", last_error());
    assert_eq!(loc.space, FS_INSPECT_SPACE_VOLUME);
    assert_eq!(text(loc.structure).as_deref(), Some("ext block"));
    // A struct_size too small: refused.
    let mut short = FsInspectErrorLocation { struct_size: 8, ..sized() };
    assert!(!fs_inspect_last_error_location(&mut short));

    // The next call on the thread replaces it.
    d.fail_with(0);
    let mut sd: FsInspectSetDisk = sized();
    assert_eq!(fs_inspect_disks_disk_get(d.disks, 0, &mut sd), FS_INSPECT_OK);
    assert!(!fs_inspect_last_error_location(&mut loc));
    fs_inspect_fs_free(fs);
}

/// The first volume of `d` whose file system is `fs_kind`, opened.
fn open_volume_of(d: &Disks, fs_kind: u32) -> *mut FsInspectVolume {
    for i in 0..8 {
        let mut vol = ptr::null_mut();
        if fs_inspect_disks_open_volume(d.disks, i, &mut vol, ptr::null()) != FS_INSPECT_OK {
            continue;
        }
        let mut info: FsInspectVolumeInfo = sized();
        assert_eq!(fs_inspect_volume_get_info(vol, &mut info), FS_INSPECT_OK, "{}", last_error());
        if info.fs_kind == fs_kind {
            return vol;
        }
        fs_inspect_volume_free(vol);
    }
    panic!("no volume of kind {fs_kind}");
}

/// A ZFS pool's leaves (`fs_inspect_volume_members`): one per present member, each with its
/// member index, each opening as a volume of its own that reads its bytes and outlives the
/// snapshot; an index past the end is `FS_INSPECT_E_NOT_FOUND`, a NULL handle or out pointer
/// `FS_INSPECT_E_INVALID_ARGUMENT` naming the argument. Any other volume has no leaves.
#[test]
fn a_pool_s_leaves_open_as_volumes_of_their_own() {
    let d = open(&["zfs/linux/mirror-a.fsbs", "zfs/linux/mirror-b.fsbs"]);
    let pool = open_volume_of(&d, FS_INSPECT_FS_ZFS);
    let mut m = ptr::null_mut();
    assert_eq!(fs_inspect_volume_members(pool, &mut m, ptr::null()), FS_INSPECT_OK, "{}", last_error());
    let mut n = 0usize;
    assert_eq!(fs_inspect_pool_members_count(m, &mut n), FS_INSPECT_OK);
    assert_eq!(n, 2, "a two-way mirror, both members present");
    let mut indexes = Vec::new();
    for i in 0..n {
        let mut member = u32::MAX;
        assert_eq!(fs_inspect_pool_members_get(m, i, &mut member), FS_INSPECT_OK);
        indexes.push(member);
    }
    indexes.sort_unstable();
    assert_eq!(indexes, [0, 1]);

    let mut leaf = ptr::null_mut();
    assert_eq!(fs_inspect_pool_members_open(m, 0, &mut leaf), FS_INSPECT_OK, "{}", last_error());
    assert!(!leaf.is_null());
    // The snapshot goes; the leaf keeps its own reference.
    fs_inspect_pool_members_free(m);
    let mut info: FsInspectVolumeInfo = sized();
    assert_eq!(fs_inspect_volume_get_info(leaf, &mut info), FS_INSPECT_OK, "{}", last_error());
    assert!(info.size > 0);
    let mut head = [0u8; 16];
    assert_eq!(fs_inspect_volume_read_at(leaf, 0, head.as_mut_ptr(), head.len(), ptr::null()), FS_INSPECT_OK);
    // Past its end, and a NULL buffer: named.
    let end = info.reach_length.max(info.size);
    assert_eq!(
        fs_inspect_volume_read_at(leaf, end, head.as_mut_ptr(), head.len(), ptr::null()),
        FS_INSPECT_E_NOT_FOUND
    );
    assert!(last_error().contains("past the end of the volume"), "{}", last_error());
    assert_eq!(fs_inspect_volume_read_at(leaf, 0, ptr::null_mut(), 16, ptr::null()), FS_INSPECT_E_INVALID_ARGUMENT);
    assert!(last_error().contains("buf must not be NULL"), "{}", last_error());
    // Nothing to read: no buffer needed.
    assert_eq!(fs_inspect_volume_read_at(leaf, 0, ptr::null_mut(), 0, ptr::null()), FS_INSPECT_OK);
    fs_inspect_volume_free(leaf);

    let mut m = ptr::null_mut();
    assert_eq!(fs_inspect_volume_members(pool, &mut m, ptr::null()), FS_INSPECT_OK);
    let mut member = 0u32;
    assert_eq!(fs_inspect_pool_members_get(m, 2, &mut member), FS_INSPECT_E_NOT_FOUND);
    assert_eq!(last_error(), "no leaf 2 (2 in all)");
    let mut none = ptr::null_mut();
    assert_eq!(fs_inspect_pool_members_open(m, 2, &mut none), FS_INSPECT_E_NOT_FOUND);
    assert!(none.is_null());
    assert_eq!(fs_inspect_pool_members_open(m, 0, ptr::null_mut()), FS_INSPECT_E_INVALID_ARGUMENT);
    assert_eq!(fs_inspect_pool_members_count(ptr::null(), &mut n), FS_INSPECT_E_INVALID_ARGUMENT);
    assert!(last_error().contains("members must not be NULL"), "{}", last_error());
    assert_eq!(fs_inspect_pool_members_count(m, ptr::null_mut()), FS_INSPECT_E_INVALID_ARGUMENT);
    assert_eq!(fs_inspect_volume_members(pool, ptr::null_mut(), ptr::null()), FS_INSPECT_E_INVALID_ARGUMENT);
    fs_inspect_pool_members_free(m);
    fs_inspect_pool_members_free(ptr::null_mut());
    fs_inspect_volume_free(pool);

    // Not a pool: no leaves.
    let d = open(&["ntfs/browse/ntfs-browse.fsbs"]);
    let vol = open_volume_of(&d, FS_INSPECT_FS_NTFS);
    let mut m = ptr::null_mut();
    assert_eq!(fs_inspect_volume_members(vol, &mut m, ptr::null()), FS_INSPECT_OK, "{}", last_error());
    assert_eq!(fs_inspect_pool_members_count(m, &mut n), FS_INSPECT_OK);
    assert_eq!(n, 0);
    fs_inspect_pool_members_free(m);
    // Opening at an offset takes only the flags it knows.
    let mut other = ptr::null_mut();
    assert_eq!(
        fs_inspect_disks_open_volume_at(d.disks, 0, 0, 0, 1 << 7, &mut other, ptr::null()),
        FS_INSPECT_E_UNSUPPORTED
    );
    assert_eq!(last_error(), "fs_inspect_disks_open_volume_at flags 0x80: unknown bits 0x80");
    assert!(other.is_null());
    fs_inspect_volume_free(vol);
}
