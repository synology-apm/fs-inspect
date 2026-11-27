//! Browsing and exporting through the C ABI, driven from Rust, on the NTFS browse volume
//! (`fixtures/ntfs/browse`, made by Windows).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code
#![allow(unsafe_code)]

use fs_inspect_ffi::*;
use std::ffi::{CStr, CString, c_char, c_void};
use std::ptr;

fn last_error() -> String {
    // SAFETY: the library's thread-local message, NUL terminated.
    unsafe { CStr::from_ptr(fs_inspect_last_error_message()) }.to_string_lossy().into_owned()
}

/// The fixture written out as a raw image in `dir`.
fn image(dir: &std::path::Path) -> CString {
    use fs_inspect::BlockSource;
    let src = fs_inspect_testkit::sparse::SparseSource::open(
        fs_inspect_testkit::fixture("ntfs/browse").join("ntfs-browse.fsbs"),
    );
    let p = dir.join("ntfs.img");
    std::fs::write(&p, src.read_vec(0, src.size() as usize).unwrap()).unwrap();
    CString::new(p.to_str().unwrap()).unwrap()
}

struct Opened {
    disks: *mut FsInspectDisks,
    vol: *mut FsInspectVolume,
    fs: *mut FsInspectFs,
}

impl Drop for Opened {
    fn drop(&mut self) {
        fs_inspect_fs_free(self.fs);
        fs_inspect_volume_free(self.vol);
        fs_inspect_disks_free(self.disks);
    }
}

fn open(path: &CString) -> Opened {
    let mut o = Opened { disks: ptr::null_mut(), vol: ptr::null_mut(), fs: ptr::null_mut() };
    let paths = [path.as_ptr()];
    let spec = FsInspectDiskSpec { paths: paths.as_ptr(), path_count: 1, ..sized() };
    assert_eq!(
        fs_inspect_disks_open(&spec, 1, ptr::null(), &mut o.disks, ptr::null()),
        FS_INSPECT_OK,
        "{}",
        last_error()
    );
    assert_eq!(fs_inspect_disks_open_volume(o.disks, 0, &mut o.vol, ptr::null()), FS_INSPECT_OK, "{}", last_error());
    assert_eq!(fs_inspect_volume_browse(o.vol, ptr::null(), &mut o.fs, ptr::null()), FS_INSPECT_OK, "{}", last_error());
    o
}

fn buf(b: *mut FsInspectBuf) -> Vec<u8> {
    let (mut data, mut len) = (ptr::null(), 0usize);
    assert_eq!(fs_inspect_buf_get_bytes(b, &mut data, &mut len), FS_INSPECT_OK);
    // SAFETY: `len` bytes at `data`, alive until the buffer is freed.
    let v = unsafe { std::slice::from_raw_parts(data, len) }.to_vec();
    fs_inspect_buf_free(b);
    v
}

fn json(b: *mut FsInspectBuf) -> serde_json::Value {
    serde_json::from_slice(&buf(b)).unwrap()
}

/// A library string (NULL: "").
fn cstr(p: *const c_char) -> String {
    if p.is_null() {
        return String::new();
    }
    // SAFETY: a NUL-terminated string the library keeps alive for the test's use.
    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
}

/// `len` library bytes at `p` (NULL or 0: none).
fn bytes(p: *const u8, len: usize) -> Vec<u8> {
    if p.is_null() || len == 0 {
        return Vec::new();
    }
    // SAFETY: `len` bytes at `p`, alive while the handle they come from is.
    unsafe { std::slice::from_raw_parts(p, len) }.to_vec()
}

/// A root as a snapshot gave it, its strings copied out.
#[derive(Debug, Clone)]
struct Root {
    info: FsInspectRootInfo,
    name: String,
    path: String,
    mountpoint: String,
}

/// An all-zero entry for a batch call to fill.
fn zeroed<T: Copy>() -> T {
    // SAFETY: the entry structs are plain data (integers, bools, NULL pointers).
    unsafe { std::mem::zeroed() }
}

/// The item errors of a call (freed): (index, status, message, has a location).
fn item_errors(errors: *mut FsInspectItemErrors) -> Vec<(usize, FsInspectStatus, String, bool)> {
    if errors.is_null() {
        return Vec::new();
    }
    let mut n = usize::MAX;
    assert_eq!(fs_inspect_item_errors_count(errors, &mut n), FS_INSPECT_OK);
    let out = (0..n)
        .map(|i| {
            let mut e: FsInspectItemError = sized();
            assert_eq!(fs_inspect_item_errors_get(errors, i, &mut e), FS_INSPECT_OK);
            assert!(e.status < 0);
            (e.index, e.status, cstr(e.message), !cstr(e.structure).is_empty())
        })
        .collect();
    let mut e: FsInspectItemError = sized();
    assert_eq!(fs_inspect_item_errors_get(errors, n, &mut e), FS_INSPECT_E_NOT_FOUND);
    fs_inspect_item_errors_free(errors);
    out
}

/// A token already triggered.
fn triggered() -> *mut FsInspectCancel {
    let mut c = ptr::null_mut();
    assert_eq!(fs_inspect_cancel_new(&mut c), FS_INSPECT_OK);
    fs_inspect_cancel_trigger(c);
    c
}

/// The roots of `fs` (`visible`: those a user sees), through a snapshot.
fn roots(fs: *const FsInspectFs, visible: bool) -> Vec<Root> {
    let mut h = ptr::null_mut();
    let s = if visible {
        fs_inspect_fs_visible_roots(fs, &mut h, ptr::null())
    } else {
        fs_inspect_fs_roots(fs, &mut h, ptr::null())
    };
    assert_eq!(s, FS_INSPECT_OK, "{}", last_error());
    let mut n = 0usize;
    assert_eq!(fs_inspect_roots_count(h, &mut n), FS_INSPECT_OK);
    let all: Vec<Root> = (0..n)
        .map(|i| {
            let mut r: FsInspectRootInfo = sized();
            assert_eq!(fs_inspect_roots_get(h, i, &mut r), FS_INSPECT_OK);
            Root { info: r, name: cstr(r.name), path: cstr(r.path), mountpoint: cstr(r.mountpoint) }
        })
        .collect();
    let mut past: FsInspectRootInfo = sized();
    assert_eq!(fs_inspect_roots_get(h, n, &mut past), FS_INSPECT_E_NOT_FOUND);
    fs_inspect_roots_free(h);
    all
}

fn root(fs: *const FsInspectFs) -> FsInspectRootInfo {
    let all = roots(fs, false);
    assert_eq!(all.len(), 1);
    let Root { info: r, path, mountpoint, .. } = all[0].clone();
    assert_eq!(r.kind, FS_INSPECT_ROOT_MAIN);
    // The only root: the default, no path, none of the facts of APFS or ZFS.
    assert!(r.is_default);
    assert_eq!((r.role, path.as_str(), mountpoint.as_str(), r.volume_group[0]), (0, "", "", 0));
    // Visible to a user as well.
    let visible = roots(fs, true);
    assert_eq!(visible.len(), 1);
    assert_eq!((visible[0].info.root, visible[0].info.node), (r.root, r.node));
    r
}

/// A NUL-terminated field as text.
fn text(b: &[c_char]) -> String {
    // SAFETY: the library NUL-terminates every string field it fills.
    unsafe { CStr::from_ptr(b.as_ptr()) }.to_string_lossy().into_owned()
}

/// An APFS volume's role, volume group and path (a synthetic container).
#[test]
fn an_apfs_volume_s_role_and_group() {
    let mut m = fs_inspect_testkit::apfs::volume::Model::new();
    m.role = 0x40;
    m.volume_group = [0xAB; 16];
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("apfs.img");
    std::fs::write(&p, m.build()).unwrap();
    let o = open(&CString::new(p.to_str().unwrap()).unwrap());
    let all = roots(o.fs, false);
    let Root { info: r, name, path, mountpoint } = all[0].clone();
    assert_eq!((r.kind, r.is_default, r.role), (FS_INSPECT_ROOT_VOLUME, true, FS_INSPECT_VOLUME_ROLE_DATA));
    assert_eq!((name.as_str(), path.as_str()), ("vol0", "vol0"));
    assert_eq!(text(&r.volume_group), "ABABABAB-ABAB-ABAB-ABAB-ABABABABABAB");
    assert_eq!(mountpoint, "");
}

fn resolve(fs: *const FsInspectFs, root: u64, path: &str) -> FsInspectNode {
    let p = CString::new(path).unwrap();
    let mut n = FsInspectNode::default();
    assert_eq!(
        fs_inspect_fs_resolve(fs, root, p.as_ptr(), &mut n, ptr::null()),
        FS_INSPECT_OK,
        "{path}: {}",
        last_error()
    );
    n
}

fn stat(fs: *const FsInspectFs, node: FsInspectNode) -> FsInspectStat {
    let mut st: FsInspectStat = sized();
    assert_eq!(fs_inspect_fs_stat(fs, node, &mut st, ptr::null()), FS_INSPECT_OK, "{}", last_error());
    st
}

#[test]
fn browse_and_read() {
    let dir = tempfile::tempdir().unwrap();
    let o = open(&image(dir.path()));
    let r = root(o.fs);

    // The root lists plain.bin, with its kind, read three at a time.
    let mut found = None;
    for e in listing(o.fs, r.node, ptr::null(), 3) {
        assert_eq!(e.encoding, FS_INSPECT_NAME_UTF16);
        let units: Vec<u16> = e.raw.chunks(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        assert_eq!(String::from_utf16(&units).unwrap(), e.name);
        if e.name == "plain.bin" {
            assert_eq!(e.kind, FS_INSPECT_NODE_FILE);
            found = Some(e.node);
        }
        assert!(e.stat.is_none());
    }
    let plain = found.expect("plain.bin listed");
    assert_eq!(resolve(o.fs, r.root, "/plain.bin"), plain);

    let mut st = stat(o.fs, plain);
    assert_eq!((st.kind, st.size), (FS_INSPECT_NODE_FILE, 307_323));
    assert_ne!(st.has & FS_INSPECT_HAS_FLAG_MODIFIED, 0);
    assert_ne!(st.has & FS_INSPECT_HAS_FLAG_WINDOWS, 0);
    assert_eq!(st.presence, FS_INSPECT_PRESENCE_NORMAL);

    // Looked up in its directory: by its listed text, by its bytes (case as NTFS compares).
    let look = |name: &[u8], flags: u32| {
        let mut n = FsInspectNode::default();
        let s = fs_inspect_fs_lookup(o.fs, r.node, name.as_ptr(), name.len(), flags, &mut n, ptr::null());
        (s, n)
    };
    let (s, n) = look(b"plain.bin", 0);
    assert_eq!((s, n), (FS_INSPECT_OK, plain), "{}", last_error());
    same_stat(&stat(o.fs, n), &st);
    assert_eq!(look(b"PLAIN.BIN", FS_INSPECT_LOOKUP_FLAG_RAW).1, plain);
    assert_eq!(look(b"no such", 0).0, FS_INSPECT_E_NOT_FOUND);
    assert_eq!(look(b"bad\\q", 0).0, FS_INSPECT_E_INVALID_ARGUMENT);
    assert_eq!(look(b"plain.bin", 1 << 5).0, FS_INSPECT_E_UNSUPPORTED);

    // How full the volume is.
    let mut u: FsInspectUsage = sized();
    assert_eq!(fs_inspect_fs_usage(o.fs, &mut u, ptr::null()), FS_INSPECT_OK, "{}", last_error());
    assert!(u.unit >= 512 && u.free_bytes < u.total_bytes, "{u:?}");

    // The whole content, in pieces, from two threads.
    let mut f = ptr::null_mut();
    let mut st2: FsInspectStat = sized();
    assert_eq!(fs_inspect_fs_open(o.fs, plain, 0, &mut st2, &mut f, ptr::null()), FS_INSPECT_OK);
    assert_eq!((st2.size, st2.times.modified.secs, st2.has), (st.size, st.times.modified.secs, st.has));
    // The open file's stat is the node's.
    let mut st3: FsInspectStat = sized();
    assert_eq!(fs_inspect_file_get_stat(f, &mut st3), FS_INSPECT_OK, "{}", last_error());
    same_stat(&st3, &st);
    let mut len = 0u64;
    assert_eq!(fs_inspect_file_get_size(f, &mut len), FS_INSPECT_OK);
    assert_eq!(len, 307_323);
    let f_addr = f as usize;
    let read = move |off: u64, n: usize| {
        let mut b = vec![0u8; n];
        let mut got = 0usize;
        let s = fs_inspect_file_read_at(f_addr as *const FsInspectFile, off, b.as_mut_ptr(), n, &mut got, ptr::null());
        assert_eq!(s, FS_INSPECT_OK);
        b.truncate(got);
        b
    };
    let t = std::thread::spawn(move || read(0, 200_000));
    let tail = read(200_000, 200_000);
    let mut all = t.join().unwrap();
    all.extend(tail);
    assert_eq!(all.len(), 307_323);
    assert!(read(len, 10).is_empty());
    // Its extents, two a read: in order, covering it.
    let mut el = ptr::null_mut();
    assert_eq!(fs_inspect_file_extents_new(f, &mut el, ptr::null()), FS_INSPECT_OK, "{}", last_error());
    let mut count = usize::MAX;
    assert_eq!(fs_inspect_file_extents_count(el, &mut count), FS_INSPECT_OK);
    let mut ext = Vec::new();
    loop {
        let mut page = [FsInspectFileExtent::default(); 2];
        let mut n = 0usize;
        assert_eq!(fs_inspect_file_extents_read(el, ext.len(), page.as_mut_ptr(), 2, &mut n), FS_INSPECT_OK);
        if n == 0 {
            break;
        }
        ext.extend_from_slice(&page[..n]);
    }
    fs_inspect_file_extents_free(el);
    assert!(!ext.is_empty() && ext.len() == count);
    let mut at = 0;
    for e in &ext {
        assert_eq!(e.offset, at, "{ext:?}");
        assert!((FS_INSPECT_FILE_EXTENT_DATA..=FS_INSPECT_FILE_EXTENT_ABSENT).contains(&e.kind), "{ext:?}");
        at += e.length;
    }
    assert_eq!(at, len);

    // Served: available, then a range and the whole written through the callback in order;
    // a callback returning non-zero stops it, release runs once either way.
    let mut yes = false;
    assert_eq!(fs_inspect_file_available(f, 0, u64::MAX, &mut yes, ptr::null()), FS_INSPECT_OK);
    assert!(yes);
    struct Sink {
        got: Vec<u8>,
        stop_after: usize,
        released: u32,
    }
    unsafe extern "C" fn write(ctx: *mut c_void, data: *const u8, len: usize) -> i32 {
        // SAFETY: the test's Sink; `len` bytes at `data`.
        let s = unsafe { &mut *ctx.cast::<Sink>() };
        s.got.extend_from_slice(unsafe { std::slice::from_raw_parts(data, len) });
        i32::from(s.got.len() >= s.stop_after)
    }
    unsafe extern "C" fn release(ctx: *mut c_void) {
        // SAFETY: the test's Sink.
        unsafe { &mut *ctx.cast::<Sink>() }.released += 1;
    }
    let serve_with = |off: u64, n: u64, stop_after: usize, cancel: *const FsInspectCancel| {
        let mut s = Sink { got: Vec::new(), stop_after, released: 0 };
        let ops = FsInspectWriteOps {
            struct_size: size_of::<FsInspectWriteOps>(),
            ctx: (&raw mut s).cast(),
            write: Some(write),
            release: Some(release),
        };
        let mut copied = 0u64;
        let status = fs_inspect_file_copy_range(f, off, n, &ops, &mut copied, cancel);
        assert_eq!(s.released, 1);
        (status, copied, s.got)
    };
    let serve = |off: u64, n: u64, stop_after: usize| serve_with(off, n, stop_after, ptr::null());
    assert_eq!(serve(0, u64::MAX, usize::MAX), (FS_INSPECT_OK, 307_323, all.clone()));
    assert_eq!(serve(1000, 5000, usize::MAX), (FS_INSPECT_OK, 5000, all[1000..6000].to_vec()));
    assert_eq!(serve(len, 10, usize::MAX), (FS_INSPECT_OK, 0, Vec::new()));
    let (status, copied, _) = serve(0, u64::MAX, 1);
    assert_eq!((status, copied), (FS_INSPECT_E_CALLBACK, 0));
    let mut c = ptr::null_mut();
    assert_eq!(fs_inspect_cancel_new(&mut c), FS_INSPECT_OK);
    fs_inspect_cancel_trigger(c);
    assert_eq!(serve_with(0, u64::MAX, usize::MAX, c).0, FS_INSPECT_E_CANCELLED);
    // A triggered token cancels a read too.
    let mut one = [0u8; 16];
    let mut got = 0usize;
    assert_eq!(fs_inspect_file_read_at(f, 0, one.as_mut_ptr(), 16, &mut got, c), FS_INSPECT_E_CANCELLED);
    // The calls that may read what a file is take a token too: cancelled where they read (this
    // file's extents are in its record, read when it was opened).
    let mut el = ptr::null_mut();
    match fs_inspect_file_extents_new(f, &mut el, c) {
        FS_INSPECT_OK => fs_inspect_file_extents_free(el),
        st => assert_eq!((st, el.is_null()), (FS_INSPECT_E_CANCELLED, true)),
    }
    let av = fs_inspect_file_available(f, 0, u64::MAX, &mut yes, c);
    assert!(av == FS_INSPECT_OK || av == FS_INSPECT_E_CANCELLED, "{av}");
    fs_inspect_cancel_free(c);
    fs_inspect_file_free(f);

    // Not a file: no file handle.
    let mut f = ptr::null_mut();
    assert_eq!(fs_inspect_fs_open(o.fs, r.node, 0, ptr::null_mut(), &mut f, ptr::null()), FS_INSPECT_E_IS_A_DIRECTORY);

    // Streams, extended attributes, links, security, names.
    let ads = resolve(o.fs, r.root, "/ads.bin");
    let mut b = ptr::null_mut();
    let mut sl = ptr::null_mut();
    assert_eq!(fs_inspect_fs_streams(o.fs, ads, &mut sl, ptr::null()), FS_INSPECT_OK);
    let mut count = 0usize;
    assert_eq!(fs_inspect_streams_count(sl, &mut count), FS_INSPECT_OK);
    let streams: Vec<Stream> = (0..count)
        .map(|i| {
            let mut s: FsInspectStreamInfo = sized();
            assert_eq!(fs_inspect_streams_get(sl, i, &mut s), FS_INSPECT_OK);
            let name = cstr(s.name);
            let name = (!name.is_empty()).then_some(name);
            (name, s.id, s.size, bytes(s.raw, s.raw_len), s.encoding)
        })
        .collect();
    let mut s: FsInspectStreamInfo = sized();
    assert_eq!(fs_inspect_streams_get(sl, count, &mut s), FS_INSPECT_E_NOT_FOUND);
    fs_inspect_streams_free(sl);
    assert_eq!((streams[0].0.as_deref(), streams[0].4), (None, 0), "the main stream first, unnamed");
    let meta = streams.iter().find(|s| s.0.as_deref() == Some("meta")).expect("meta stream");
    assert_eq!(meta.2, 20000);
    assert_eq!(meta.3, "meta".encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<u8>>(), "UTF-16 as stored");
    assert_eq!(meta.4, FS_INSPECT_NAME_UTF16);
    let mut f = ptr::null_mut();
    assert_eq!(fs_inspect_fs_open(o.fs, ads, meta.1, ptr::null_mut(), &mut f, ptr::null()), FS_INSPECT_OK);
    let mut len = 0u64;
    assert_eq!(fs_inspect_file_get_size(f, &mut len), FS_INSPECT_OK);
    assert_eq!(len, 20000);
    fs_inspect_file_free(f);

    // Extended attributes: a snapshot of each with its name, namespace and size.
    let ea = resolve(o.fs, r.root, "/ea.txt");
    let mut xh = ptr::null_mut();
    assert_eq!(fs_inspect_fs_xattrs(o.fs, ea, &mut xh, ptr::null()), FS_INSPECT_OK, "{}", last_error());
    let mut count = 0usize;
    assert_eq!(fs_inspect_xattrs_count(xh, &mut count), FS_INSPECT_OK);
    assert_eq!(count, 2);
    let xattrs: Vec<(String, Vec<u8>, u64, u32)> = (0..count)
        .map(|i| {
            let mut x: FsInspectXattr = sized();
            assert_eq!(fs_inspect_xattrs_get(xh, i, &mut x), FS_INSPECT_OK);
            assert!(x.namespace == 0 || (FS_INSPECT_XATTR_NS_USER..=FS_INSPECT_XATTR_NS_OTHER).contains(&x.namespace));
            if x.has_value {
                assert_eq!(bytes(x.value, x.size as usize).len() as u64, x.size);
            }
            (cstr(x.name), bytes(x.raw, x.raw_len), x.size, x.encoding)
        })
        .collect();
    let mut x: FsInspectXattr = sized();
    assert_eq!(fs_inspect_xattrs_get(xh, count, &mut x), FS_INSPECT_E_NOT_FOUND);
    fs_inspect_xattrs_free(xh);
    let second = xattrs.iter().find(|x| x.0 == "SECOND").unwrap_or_else(|| panic!("SECOND listed: {xattrs:?}"));
    assert!(second.2 > 0);
    let name = second.0.as_bytes();
    assert_eq!(
        fs_inspect_fs_read_xattr(o.fs, ea, name.as_ptr(), name.len(), &mut b, ptr::null()),
        FS_INSPECT_OK,
        "{}",
        last_error()
    );
    assert_eq!(buf(b).len() as u64, second.2);
    let none = b"NO SUCH";
    assert_eq!(
        fs_inspect_fs_read_xattr(o.fs, ea, none.as_ptr(), none.len(), &mut b, ptr::null()),
        FS_INSPECT_E_NOT_FOUND
    );

    let link = resolve(o.fs, r.root, "/symlink-rel.txt");
    let mut lh = ptr::null_mut();
    assert_eq!(fs_inspect_fs_read_link(o.fs, link, &mut lh, ptr::null()), FS_INSPECT_OK);
    let mut li: FsInspectLinkInfo = sized();
    assert_eq!(fs_inspect_link_get_info(lh, &mut li), FS_INSPECT_OK);
    assert_eq!((li.kind, li.relative), (FS_INSPECT_LINK_WINDOWS_SYMLINK, true));
    assert_eq!(cstr(li.target), "resident.txt");
    assert_eq!(li.encoding, FS_INSPECT_NAME_UTF16);
    assert_eq!(li.target_len, 2 * "resident.txt".len());
    assert_eq!(
        bytes(li.target_raw, li.target_len),
        "resident.txt".encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<u8>>()
    );
    fs_inspect_link_free(lh);
    assert_eq!(fs_inspect_fs_read_link(o.fs, plain, &mut lh, ptr::null()), FS_INSPECT_E_NOT_FOUND);

    let mut sh = ptr::null_mut();
    assert_eq!(fs_inspect_fs_security(o.fs, plain, &mut sh, ptr::null()), FS_INSPECT_OK);
    let mut si: FsInspectSecurityInfo = sized();
    assert_eq!(fs_inspect_security_get_info(sh, &mut si), FS_INSPECT_OK);
    assert_eq!(si.kind, FS_INSPECT_SECURITY_NTFS);
    assert!(si.ntfs_len > 0 && !si.access.present && !si.default_acl.present);
    assert_eq!(bytes(si.ntfs, si.ntfs_len)[0], 1, "a self-relative descriptor starts with revision 1");
    fs_inspect_security_free(sh);

    let linked = resolve(o.fs, r.root, "/linked.bin");
    let mut nl = ptr::null_mut();
    assert_eq!(fs_inspect_fs_names(o.fs, linked, &mut nl, ptr::null()), FS_INSPECT_OK);
    let mut count = 0usize;
    assert_eq!(fs_inspect_names_count(nl, &mut count), FS_INSPECT_OK);
    assert_eq!(count, 2);
    let mut got = Vec::new();
    for i in 0..count {
        let mut n: FsInspectNodeName = sized();
        assert_eq!(fs_inspect_names_get(nl, i, &mut n), FS_INSPECT_OK);
        assert_eq!(n.dir.root, r.root);
        got.push(cstr(n.name));
    }
    fs_inspect_names_free(nl);
    assert!(got.iter().any(|n| n == "linked.bin"), "{got:?}");

    // Cloud state.
    let partial = resolve(o.fs, r.root, "/cloud/partial.bin");
    st = stat(o.fs, partial);
    assert_ne!(st.has & FS_INSPECT_HAS_FLAG_CLOUD, 0);
    assert_eq!(
        (st.cloud.provider, st.cloud.hydration),
        (FS_INSPECT_CLOUD_PROVIDER_WINDOWS_CLOUD_FILES, FS_INSPECT_HYDRATION_PARTIAL)
    );
    assert_eq!(fs_inspect_fs_read_cloud_data(o.fs, partial, &mut b, ptr::null()), FS_INSPECT_OK, "{}", last_error());
    assert!(!buf(b).is_empty());
    // A file with no cloud state has no cloud data.
    let mut nb = ptr::null_mut();
    assert_eq!(fs_inspect_fs_read_cloud_data(o.fs, plain, &mut nb, ptr::null()), FS_INSPECT_E_NOT_FOUND);
    assert!(nb.is_null());

    // Each of these calls stops on a triggered token, handing nothing.
    let c = triggered();
    let mut sl = ptr::null_mut();
    assert_eq!(fs_inspect_fs_streams(o.fs, ads, &mut sl, c), FS_INSPECT_E_CANCELLED);
    let mut xh = ptr::null_mut();
    assert_eq!(fs_inspect_fs_xattrs(o.fs, ea, &mut xh, c), FS_INSPECT_E_CANCELLED);
    let mut xb = ptr::null_mut();
    assert_eq!(fs_inspect_fs_read_xattr(o.fs, ea, name.as_ptr(), name.len(), &mut xb, c), FS_INSPECT_E_CANCELLED);
    let mut lh = ptr::null_mut();
    assert_eq!(fs_inspect_fs_read_link(o.fs, link, &mut lh, c), FS_INSPECT_E_CANCELLED);
    let mut sh = ptr::null_mut();
    assert_eq!(fs_inspect_fs_security(o.fs, plain, &mut sh, c), FS_INSPECT_E_CANCELLED);
    let mut nl = ptr::null_mut();
    assert_eq!(fs_inspect_fs_names(o.fs, linked, &mut nl, c), FS_INSPECT_E_CANCELLED);
    let mut cb = ptr::null_mut();
    assert_eq!(fs_inspect_fs_read_cloud_data(o.fs, partial, &mut cb, c), FS_INSPECT_E_CANCELLED);
    assert!(
        sl.is_null() && xh.is_null() && xb.is_null() && lh.is_null() && sh.is_null() && nl.is_null() && cb.is_null()
    );
    fs_inspect_cancel_free(c);

    // Errors.
    let missing = CString::new("/no such").unwrap();
    let mut n = FsInspectNode::default();
    assert_eq!(fs_inspect_fs_resolve(o.fs, r.root, missing.as_ptr(), &mut n, ptr::null()), FS_INSPECT_E_NOT_FOUND);
    assert_eq!(fs_inspect_fs_resolve(o.fs, r.root, ptr::null(), &mut n, ptr::null()), FS_INSPECT_E_INVALID_ARGUMENT);
    // A node id's text is a path like any other: the name `5:123` (none here), not node 123.
    for id in ["5:123".to_string(), format!("{}:{}", plain.root, plain.id)] {
        let p = CString::new(id.as_str()).unwrap();
        assert_eq!(
            fs_inspect_fs_resolve(o.fs, r.root, p.as_ptr(), &mut n, ptr::null()),
            FS_INSPECT_E_NOT_FOUND,
            "{id}"
        );
    }
    assert_eq!(fs_inspect_fs_stat(ptr::null(), plain, &mut st, ptr::null()), FS_INSPECT_E_INVALID_ARGUMENT);

    // Browse options: every checksum computed reads the same; an unknown policy is refused.
    let verify = FsInspectBrowseOptions { checksums: FS_INSPECT_CHECKSUMS_VERIFY, ..sized() };
    let mut fs2: *mut FsInspectFs = ptr::null_mut();
    assert_eq!(fs_inspect_volume_browse(o.vol, &verify, &mut fs2, ptr::null()), FS_INSPECT_OK, "{}", last_error());
    assert_eq!(roots(fs2, false)[0].info.root, r.root);
    fs_inspect_fs_free(fs2);
    let bad = FsInspectBrowseOptions { checksums: 7, ..sized() };
    assert_eq!(fs_inspect_volume_browse(o.vol, &bad, &mut fs2, ptr::null()), FS_INSPECT_E_INVALID_ARGUMENT);
    let unsized_opts = FsInspectBrowseOptions::default();
    assert_eq!(fs_inspect_volume_browse(o.vol, &unsized_opts, &mut fs2, ptr::null()), FS_INSPECT_E_INVALID_ARGUMENT);
}

extern "C" fn collect(ctx: *mut c_void, data: *const u8, len: usize) -> i32 {
    // SAFETY: ctx is the test's Vec; `len` bytes at `data`.
    unsafe { (*(ctx as *mut Vec<u8>)).extend_from_slice(std::slice::from_raw_parts(data, len)) };
    0
}

extern "C" fn released(ctx: *mut c_void) {
    // SAFETY: ctx is the test's Vec. The 0xEE byte pushed marks the release for the test.
    unsafe { (*(ctx as *mut Vec<u8>)).push(0xEE) };
}

/// Progress ticks: counted, each with a path and counts that never go down.
#[derive(Default)]
struct Ticks {
    n: u64,
    files: u64,
    paths: bool,
}

extern "C" fn count(ctx: *mut c_void, p: *const FsInspectProgress) -> i32 {
    // SAFETY: ctx is the test's Ticks; `p` valid for the call.
    let (t, p) = unsafe { (&mut *(ctx as *mut Ticks), &*p) };
    t.n += 1;
    assert!(p.files >= t.files);
    t.files = p.files;
    t.paths |= !cstr(p.path).is_empty();
    0
}

extern "C" fn stop(_ctx: *mut c_void, _p: *const FsInspectProgress) -> i32 {
    1
}

/// What an export's report counts.
#[derive(Debug)]
struct Report {
    files: u64,
    skipped: usize,
    cloud: usize,
    notes: usize,
}

/// The summary of an export's report and its list counts, its lists read through their getters.
fn report(rep: *const FsInspectExportReport) -> Report {
    let mut s = sized::<FsInspectExportSummary>();
    assert_eq!(fs_inspect_export_report_get_summary(rep, &mut s), FS_INSPECT_OK);
    let mut sum = Report { files: s.files, skipped: usize::MAX, cloud: usize::MAX, notes: usize::MAX };
    assert_eq!(fs_inspect_export_report_skipped_count(rep, &mut sum.skipped), FS_INSPECT_OK);
    assert_eq!(fs_inspect_export_report_cloud_count(rep, &mut sum.cloud), FS_INSPECT_OK);
    assert_eq!(fs_inspect_export_report_note_count(rep, &mut sum.notes), FS_INSPECT_OK);
    for i in 0..sum.skipped {
        let mut s: FsInspectSkipped = sized();
        assert_eq!(fs_inspect_export_report_skipped_get(rep, i, &mut s), FS_INSPECT_OK);
        assert!(!cstr(s.path).is_empty() && s.status < 0, "skipped {i}: {}", cstr(s.reason));
    }
    let mut s: FsInspectSkipped = sized();
    assert_eq!(fs_inspect_export_report_skipped_get(rep, sum.skipped, &mut s), FS_INSPECT_E_NOT_FOUND);
    for i in 0..sum.cloud {
        let mut c: FsInspectCloudFile = sized();
        assert_eq!(fs_inspect_export_report_cloud_get(rep, i, &mut c), FS_INSPECT_OK);
        assert!(!cstr(c.path).is_empty());
        assert!((FS_INSPECT_HYDRATION_FULL..=FS_INSPECT_HYDRATION_UNKNOWN).contains(&c.hydration), "{c:?}");
    }
    let mut c: FsInspectCloudFile = sized();
    assert_eq!(fs_inspect_export_report_cloud_get(rep, sum.cloud, &mut c), FS_INSPECT_E_NOT_FOUND);
    for i in 0..sum.notes {
        let mut n: FsInspectNote = sized();
        assert_eq!(fs_inspect_export_report_note_get(rep, i, &mut n), FS_INSPECT_OK);
        assert!(!cstr(n.note).is_empty());
    }
    let mut n: FsInspectNote = sized();
    assert_eq!(fs_inspect_export_report_note_get(rep, sum.notes, &mut n), FS_INSPECT_E_NOT_FOUND);
    sum
}

#[test]
fn export_archives_and_a_directory() {
    let dir = tempfile::tempdir().unwrap();
    let o = open(&image(dir.path()));
    let r = root(o.fs);

    for format in [FS_INSPECT_ARCHIVE_TAR, FS_INSPECT_ARCHIVE_ZIP] {
        let mut out = Vec::<u8>::new();
        let ops = FsInspectWriteOps {
            struct_size: size_of::<FsInspectWriteOps>(),
            ctx: &mut out as *mut Vec<u8> as *mut c_void,
            write: Some(collect),
            release: Some(released),
        };
        let mut ticks = Ticks::default();
        let mut rep = ptr::null_mut();
        let s = fs_inspect_fs_export_archive(
            o.fs,
            &r.node,
            1,
            format,
            &ops,
            ptr::null(),
            Some(count),
            &mut ticks as *mut Ticks as *mut c_void,
            &mut rep,
            ptr::null(),
        );
        assert_eq!(s, FS_INSPECT_OK, "{}", last_error());
        // Released once, after the last write.
        assert_eq!(out.pop(), Some(0xEE));
        let sum = report(rep);
        assert!(sum.files > 15 && ticks.n >= sum.files && ticks.paths, "{sum:?} {}", ticks.n);
        // Cloud files not on the volume are reported.
        assert!(sum.cloud >= 2, "{sum:?}");
        let mut b = ptr::null_mut();
        assert_eq!(fs_inspect_export_report_json(rep, &mut b), FS_INSPECT_OK);
        assert_eq!(json(b)["files"], sum.files);
        fs_inspect_export_report_free(rep);
        if format == FS_INSPECT_ARCHIVE_ZIP {
            let z = zip::ZipArchive::new(std::io::Cursor::new(out)).unwrap();
            assert!(z.file_names().any(|n| n.is_ok_and(|n| n == "plain.bin")));
        } else {
            assert_eq!(out.len() % 512, 0);
        }
    }

    // Into a directory, every stream, names escaped, sparse files filled.
    let to = dir.path().join("out");
    std::fs::create_dir(&to).unwrap();
    let dest = CString::new(to.to_str().unwrap()).unwrap();
    let plain = resolve(o.fs, r.root, "/plain.bin");
    let mut rep = ptr::null_mut();
    let opts = FsInspectExportOptions {
        streams: FS_INSPECT_EXPORT_STREAMS_ALL,
        names: FS_INSPECT_EXPORT_NAMES_ESCAPE,
        sparse: FS_INSPECT_EXPORT_SPARSE_FILL,
        on_error: FS_INSPECT_EXPORT_ON_ERROR_SKIP_AND_REPORT,
        ..sized()
    };
    let s =
        fs_inspect_fs_export_dir(o.fs, &plain, 1, dest.as_ptr(), &opts, None, ptr::null_mut(), &mut rep, ptr::null());
    assert_eq!(s, FS_INSPECT_OK, "{}", last_error());
    assert_eq!(report(rep).files, 1);
    fs_inspect_export_report_free(rep);
    assert_eq!(std::fs::metadata(to.join("plain.bin")).unwrap().len(), 307_323);

    // A cloud policy: only what is on the volume, the rest reported.
    let cloud_dir = resolve(o.fs, r.root, "/cloud");
    let to2 = dir.path().join("out2");
    std::fs::create_dir(&to2).unwrap();
    let dest2 = CString::new(to2.to_str().unwrap()).unwrap();
    let opts = FsInspectExportOptions { cloud: FS_INSPECT_EXPORT_CLOUD_SKIP_AND_REPORT, ..sized() };
    let s = fs_inspect_fs_export_dir(
        o.fs,
        &cloud_dir,
        1,
        dest2.as_ptr(),
        &opts,
        None,
        ptr::null_mut(),
        &mut rep,
        ptr::null(),
    );
    assert_eq!(s, FS_INSPECT_OK, "{}", last_error());
    assert!(report(rep).cloud >= 1);
    fs_inspect_export_report_free(rep);

    // Bad options: unknown flags, an unknown cloud policy or stream choice, no nodes.
    let bad = FsInspectExportOptions { flags: 1 << 30, ..sized() };
    assert_eq!(
        fs_inspect_fs_export_dir(o.fs, &plain, 1, dest.as_ptr(), &bad, None, ptr::null_mut(), &mut rep, ptr::null()),
        FS_INSPECT_E_UNSUPPORTED
    );
    for bad in [FsInspectExportOptions { cloud: 9, ..sized() }, FsInspectExportOptions { streams: 9, ..sized() }] {
        assert_eq!(
            fs_inspect_fs_export_dir(
                o.fs,
                &plain,
                1,
                dest.as_ptr(),
                &bad,
                None,
                ptr::null_mut(),
                &mut rep,
                ptr::null()
            ),
            FS_INSPECT_E_INVALID_ARGUMENT
        );
    }
    assert_eq!(
        fs_inspect_fs_export_dir(
            o.fs,
            &plain,
            0,
            dest.as_ptr(),
            ptr::null(),
            None,
            ptr::null_mut(),
            &mut rep,
            ptr::null()
        ),
        FS_INSPECT_E_INVALID_ARGUMENT
    );

    // A progress callback returning nonzero stops that export.
    let mut out = Vec::<u8>::new();
    let ops = FsInspectWriteOps {
        struct_size: size_of::<FsInspectWriteOps>(),
        ctx: &mut out as *mut Vec<u8> as *mut c_void,
        write: Some(collect),
        release: None,
    };
    let s = fs_inspect_fs_export_archive(
        o.fs,
        &r.node,
        1,
        FS_INSPECT_ARCHIVE_TAR,
        &ops,
        ptr::null(),
        Some(stop),
        ptr::null_mut(),
        &mut rep,
        ptr::null(),
    );
    assert_eq!(s, FS_INSPECT_E_CALLBACK);
    // Stopped by its callback, an export leaves the caller's token as it was: the token still
    // serves the next call.
    let mut c = ptr::null_mut();
    assert_eq!(fs_inspect_cancel_new(&mut c), FS_INSPECT_OK);
    let s = fs_inspect_fs_export_archive(
        o.fs,
        &r.node,
        1,
        FS_INSPECT_ARCHIVE_ZIP,
        &ops,
        ptr::null(),
        Some(stop),
        ptr::null_mut(),
        &mut rep,
        c,
    );
    assert_eq!(s, FS_INSPECT_E_CALLBACK);
    assert!(!fs_inspect_cancel_is_cancelled(c));
    let kept = dir.path().join("kept");
    std::fs::create_dir(&kept).unwrap();
    let kept = CString::new(kept.to_str().unwrap()).unwrap();
    let s =
        fs_inspect_fs_export_dir(o.fs, &plain, 1, kept.as_ptr(), ptr::null(), Some(stop), ptr::null_mut(), &mut rep, c);
    assert_eq!(s, FS_INSPECT_E_CALLBACK);
    assert!(!fs_inspect_cancel_is_cancelled(c));
    let fresh = dir.path().join("fresh");
    std::fs::create_dir(&fresh).unwrap();
    let fresh = CString::new(fresh.to_str().unwrap()).unwrap();
    let s = fs_inspect_fs_export_dir(o.fs, &plain, 1, fresh.as_ptr(), ptr::null(), None, ptr::null_mut(), &mut rep, c);
    assert_eq!(s, FS_INSPECT_OK, "{}", last_error());
    fs_inspect_export_report_free(rep);
    fs_inspect_cancel_free(c);
    // A triggered cancel token cancels it.
    let mut c = ptr::null_mut();
    assert_eq!(fs_inspect_cancel_new(&mut c), FS_INSPECT_OK);
    fs_inspect_cancel_trigger(c);
    let s = fs_inspect_fs_export_dir(o.fs, &plain, 1, dest.as_ptr(), ptr::null(), None, ptr::null_mut(), &mut rep, c);
    assert_eq!(s, FS_INSPECT_E_CANCELLED);
    fs_inspect_cancel_free(c);
    // That export only: the next one on the same file system runs.
    out.clear();
    let s = fs_inspect_fs_export_archive(
        o.fs,
        &r.node,
        1,
        FS_INSPECT_ARCHIVE_TAR,
        &ops,
        ptr::null(),
        None,
        ptr::null_mut(),
        &mut rep,
        ptr::null(),
    );
    assert_eq!(s, FS_INSPECT_OK);
    assert!(!out.is_empty());
    fs_inspect_export_report_free(rep);
}

#[test]
fn verify_a_volume() {
    let dir = tempfile::tempdir().unwrap();
    let o = open(&image(dir.path()));
    let mut rep: *mut FsInspectVerifyReport = ptr::null_mut();
    let opts = FsInspectVerifyOptions { flags: FS_INSPECT_VERIFY_FLAG_DATA, ..sized() };
    assert_eq!(fs_inspect_volume_verify(o.vol, &opts, &mut rep, ptr::null()), FS_INSPECT_OK, "{}", last_error());
    let mut s: FsInspectVerifySummary = sized();
    assert_eq!(fs_inspect_verify_report_get_summary(rep, &mut s), FS_INSPECT_OK);
    assert_eq!((s.passed, s.damaged, s.stopped_status), (true, 0, FS_INSPECT_OK));
    assert_eq!(cstr(s.stopped_message), "");
    // What was checked, by name; no finding.
    let (mut checked, mut findings, mut not_covered) = (0usize, usize::MAX, usize::MAX);
    assert_eq!(fs_inspect_verify_report_checked_count(rep, &mut checked), FS_INSPECT_OK);
    assert_eq!(fs_inspect_verify_report_finding_count(rep, &mut findings), FS_INSPECT_OK);
    assert_eq!(fs_inspect_verify_report_not_covered_count(rep, &mut not_covered), FS_INSPECT_OK);
    assert!(checked > 0);
    assert_eq!(findings, 0);
    let mut names = Vec::new();
    for i in 0..checked {
        let mut c: FsInspectVerifyChecked = sized();
        assert_eq!(fs_inspect_verify_report_checked_get(rep, i, &mut c), FS_INSPECT_OK);
        names.push((cstr(c.name), c.bytes));
    }
    assert!(names.iter().any(|(n, b)| n == "file_data" && *b > 0), "{names:?}");
    let mut c: FsInspectVerifyChecked = sized();
    assert_eq!(fs_inspect_verify_report_checked_get(rep, checked, &mut c), FS_INSPECT_E_NOT_FOUND);
    let mut fnd: FsInspectFinding = sized();
    assert_eq!(fs_inspect_verify_report_finding_get(rep, findings, &mut fnd), FS_INSPECT_E_NOT_FOUND);
    for i in 0..=not_covered {
        let mut nc: FsInspectVerifyNotCovered = sized();
        let st = fs_inspect_verify_report_not_covered_get(rep, i, &mut nc);
        if i == not_covered {
            assert_eq!(st, FS_INSPECT_E_NOT_FOUND);
        } else {
            assert_eq!(st, FS_INSPECT_OK);
            assert!(nc.structure != 0 && !cstr(nc.name).is_empty() && !cstr(nc.which).is_empty());
        }
    }
    let mut b = ptr::null_mut();
    assert_eq!(fs_inspect_verify_report_json(rep, &mut b), FS_INSPECT_OK);
    let j = json(b);
    assert_eq!(j["passed"], true);
    assert!(j["checked"]["file_data"]["bytes"].as_u64().unwrap() > 0, "{j}");
    fs_inspect_verify_report_free(rep);

    // NULL options; unknown flags.
    assert_eq!(fs_inspect_volume_verify(o.vol, ptr::null(), &mut rep, ptr::null()), FS_INSPECT_OK, "{}", last_error());
    fs_inspect_verify_report_free(rep);
    let bad = FsInspectVerifyOptions { flags: 1 << 9, ..sized() };
    assert_eq!(fs_inspect_volume_verify(o.vol, &bad, &mut rep, ptr::null()), FS_INSPECT_E_UNSUPPORTED);
    fs_inspect_verify_report_free(ptr::null_mut());

    // A triggered token stops it: the report says so.
    let mut c = ptr::null_mut();
    assert_eq!(fs_inspect_cancel_new(&mut c), FS_INSPECT_OK);
    fs_inspect_cancel_trigger(c);
    assert_eq!(fs_inspect_volume_verify(o.vol, &opts, &mut rep, c), FS_INSPECT_OK, "{}", last_error());
    let mut s: FsInspectVerifySummary = sized();
    assert_eq!(fs_inspect_verify_report_get_summary(rep, &mut s), FS_INSPECT_OK);
    assert_eq!(s.stopped_status, FS_INSPECT_E_CANCELLED);
    assert!(!cstr(s.stopped_message).is_empty());
    fs_inspect_verify_report_free(rep);
    fs_inspect_cancel_free(c);

    // What holds the volumes: a bare volume, nothing to check.
    assert_eq!(fs_inspect_disks_verify(o.disks, ptr::null(), &mut rep, ptr::null()), FS_INSPECT_OK, "{}", last_error());
    let mut s: FsInspectVerifySummary = sized();
    assert_eq!(fs_inspect_verify_report_get_summary(rep, &mut s), FS_INSPECT_OK);
    let mut findings = usize::MAX;
    assert_eq!(fs_inspect_verify_report_finding_count(rep, &mut findings), FS_INSPECT_OK);
    assert_eq!((s.passed, s.stopped_status, findings), (true, FS_INSPECT_OK, 0));
    fs_inspect_verify_report_free(rep);
}

/// A stream as listed: (name, id, size, name bytes, encoding).
type Stream = (Option<String>, u32, u64, Vec<u8>, u32);

/// An entry as a listing gave it, copied out.
#[derive(Debug, Clone)]
struct Got {
    name: String,
    raw: Vec<u8>,
    encoding: u32,
    kind: u32,
    node: FsInspectNode,
    stat: Option<FsInspectStat>,
}

/// `e` copied out (its pointers valid until the next call on what it came from).
fn got(e: &FsInspectDirEntry) -> Got {
    let name = cstr(e.name);
    assert_eq!(e.occurrence, 1, "{name}: a sound directory's names are each one");
    // SAFETY: NULL or the listing's stat, valid until the next call.
    let stat = unsafe { e.stat.as_ref() }.copied();
    Got { name, raw: bytes(e.raw, e.raw_len), encoding: e.encoding, kind: e.kind, node: e.node, stat }
}

/// The entries of `d` from where it is to the end, `page` at a time.
fn read_rest(d: *mut FsInspectDir, page: usize) -> Vec<Got> {
    let mut out = Vec::new();
    loop {
        let mut es: Vec<FsInspectDirEntry> = (0..page).map(|_| zeroed()).collect();
        let mut n = 0usize;
        let mut errors = ptr::null_mut();
        let s = fs_inspect_dir_read(
            d,
            es.as_mut_ptr(),
            page,
            size_of::<FsInspectDirEntry>(),
            &mut n,
            &mut errors,
            ptr::null(),
        );
        assert_eq!(s, FS_INSPECT_OK, "{}", last_error());
        assert_eq!(item_errors(errors), [], "a sound directory's stats all read");
        if n == 0 {
            return out;
        }
        out.extend(es[..n].iter().map(got));
    }
}

/// Every entry of directory `dir` listed with `opts` (NULL: names only), `page` at a time.
fn listing(fs: *const FsInspectFs, dir: FsInspectNode, opts: *const FsInspectDirOptions, page: usize) -> Vec<Got> {
    let mut d = ptr::null_mut();
    assert_eq!(fs_inspect_dir_open(fs, dir, opts, &mut d, ptr::null()), FS_INSPECT_OK, "{}", last_error());
    let out = read_rest(d, page);
    fs_inspect_dir_free(d);
    out
}

fn same_stat(a: &FsInspectStat, b: &FsInspectStat) {
    assert_eq!(
        (a.kind, a.size, a.has, a.times.modified.secs, a.times.modified.nanos, a.windows.attributes, a.node),
        (b.kind, b.size, b.has, b.times.modified.secs, b.times.modified.nanos, b.windows.attributes, b.node)
    );
}

#[test]
fn listings_with_stats_and_batched_stats() {
    let dir = tempfile::tempdir().unwrap();
    let o = open(&image(dir.path()));
    let r = root(o.fs);

    // Names only, then with stats (read a batch at a time): the same entries, each stat what
    // fs_inspect_fs_stat gives.
    let names = listing(o.fs, r.node, ptr::null(), 4096);
    let mut opts: FsInspectDirOptions = sized();
    opts.flags = FS_INSPECT_DIR_FLAG_STAT;
    let plus = listing(o.fs, r.node, &opts, 5);
    let names_of = |l: &[Got]| l.iter().map(|g| g.name.clone()).collect::<Vec<_>>();
    assert_eq!(names_of(&names), names_of(&plus));
    assert!(plus.len() > 3);
    for g in &plus {
        let st = g.stat.as_ref().unwrap_or_else(|| panic!("{}: no stat", g.name));
        same_stat(st, &stat(o.fs, g.node));
    }

    // Positions: position, seek back and forth on one handle; a handle started part way.
    let mut d = ptr::null_mut();
    assert_eq!(fs_inspect_dir_open(o.fs, r.node, &opts, &mut d, ptr::null()), FS_INSPECT_OK);
    let mut node = FsInspectNode::default();
    assert_eq!(fs_inspect_dir_get_node(d, &mut node), FS_INSPECT_OK);
    assert_eq!(node, r.node);
    let mut pos = 99u64;
    assert_eq!(fs_inspect_dir_get_position(d, &mut pos), FS_INSPECT_OK);
    assert_eq!(pos, 0);
    assert_eq!(names_of(&read_rest(d, 2)), names_of(&plus));
    assert_eq!(fs_inspect_dir_get_position(d, &mut pos), FS_INSPECT_OK);
    assert_eq!(pos, plus.len() as u64);
    assert_eq!(fs_inspect_dir_seek(d, 2), FS_INSPECT_OK);
    assert_eq!(names_of(&read_rest(d, 1)), names_of(&plus[2..]));
    assert_eq!(fs_inspect_dir_seek(d, 1 << 40), FS_INSPECT_OK);
    assert!(read_rest(d, 1).is_empty());
    let mut e: FsInspectDirEntry = zeroed();
    let esz = size_of::<FsInspectDirEntry>();
    let none = ptr::null_mut();
    // cap 0 reads none.
    let mut n = 9usize;
    assert_eq!(fs_inspect_dir_read(d, &mut e, 0, esz, &mut n, none, ptr::null()), FS_INSPECT_OK);
    assert_eq!(n, 0);
    assert_eq!(fs_inspect_dir_read(d, &mut e, 1, 8, &mut n, none, ptr::null()), FS_INSPECT_E_INVALID_ARGUMENT);
    // An entry's identity (its name, no repeat here) finds its position; the handle stays.
    let id = CString::new(plus[3].name.as_str()).unwrap();
    assert_eq!(fs_inspect_dir_find(d, id.as_ptr(), &mut pos, ptr::null()), FS_INSPECT_OK);
    assert_eq!(pos, 3);
    assert_eq!(fs_inspect_dir_get_position(d, &mut pos), FS_INSPECT_OK);
    assert_eq!(pos, plus.len() as u64);
    let repeat = CString::new(format!(r"{}\#2", plus[3].name)).unwrap();
    assert_eq!(fs_inspect_dir_find(d, repeat.as_ptr(), &mut pos, ptr::null()), FS_INSPECT_E_NOT_FOUND);
    assert_eq!(fs_inspect_dir_find(d, ptr::null(), &mut pos, ptr::null()), FS_INSPECT_E_INVALID_ARGUMENT);
    // A triggered token stops a first read, which reads the directory; the handle reads on
    // after.
    let c = triggered();
    let mut fresh = ptr::null_mut();
    assert_eq!(fs_inspect_dir_open(o.fs, r.node, &opts, &mut fresh, ptr::null()), FS_INSPECT_OK);
    assert_eq!(fs_inspect_dir_read(fresh, &mut e, 1, esz, &mut n, none, c), FS_INSPECT_E_CANCELLED);
    assert_eq!(names_of(&read_rest(fresh, 4)), names_of(&plus));
    fs_inspect_dir_free(fresh);
    fs_inspect_cancel_free(c);
    // Started part way: seek, then read.
    assert_eq!(fs_inspect_dir_seek(d, 3), FS_INSPECT_OK);
    assert_eq!(names_of(&read_rest(d, 2)), names_of(&plus[3..]));
    fs_inspect_dir_free(d);

    // Bits this version does not know are unsupported, as in every other options struct.
    let mut bad = opts;
    bad.flags = 1 << 7;
    let mut d = ptr::null_mut();
    assert_eq!(fs_inspect_dir_open(o.fs, r.node, &bad, &mut d, ptr::null()), FS_INSPECT_E_UNSUPPORTED);
}

/// A directory collected whole into a listing: the entries a handle reads, found by identity
/// and by node, in identity order, as read-ahead siblings.
#[test]
fn a_directory_collected_into_a_listing() {
    let dir = tempfile::tempdir().unwrap();
    let o = open(&image(dir.path()));
    let r = root(o.fs);
    let opts = FsInspectDirOptions { flags: FS_INSPECT_DIR_FLAG_STAT, ..sized() };
    let plus = listing(o.fs, r.node, &opts, 64);

    let mut d = ptr::null_mut();
    assert_eq!(fs_inspect_dir_open(o.fs, r.node, &opts, &mut d, ptr::null()), FS_INSPECT_OK);
    let mut l = ptr::null_mut();
    let mut errors = ptr::null_mut();
    assert_eq!(fs_inspect_dir_collect(d, &mut l, &mut errors, ptr::null()), FS_INSPECT_OK, "{}", last_error());
    assert_eq!(item_errors(errors), []);
    // The handle is at the end.
    let mut pos = 0u64;
    assert_eq!(fs_inspect_dir_get_position(d, &mut pos), FS_INSPECT_OK);
    assert_eq!(pos, plus.len() as u64);
    // Collecting again under a triggered token: cancelled, nothing handed.
    assert_eq!(fs_inspect_dir_seek(d, 0), FS_INSPECT_OK);
    let c = triggered();
    let mut l2 = ptr::null_mut();
    assert_eq!(fs_inspect_dir_collect(d, &mut l2, ptr::null_mut(), c), FS_INSPECT_E_CANCELLED);
    assert!(l2.is_null());
    fs_inspect_cancel_free(c);
    fs_inspect_dir_free(d);

    let mut info: FsInspectListingInfo = sized();
    assert_eq!(fs_inspect_listing_get_info(l, &mut info), FS_INSPECT_OK);
    assert_eq!(info.dir, r.node);
    assert!(info.whole && info.memory_bytes > 0);
    let mut len = 0usize;
    assert_eq!(fs_inspect_listing_count(l, &mut len), FS_INSPECT_OK);
    assert_eq!(len, plus.len());

    // Its entries, three a read: the ones the handle read, with their stats.
    let mut entries = Vec::new();
    loop {
        let mut es: Vec<FsInspectDirEntry> = (0..3).map(|_| zeroed()).collect();
        let mut n = 0usize;
        let s = fs_inspect_listing_read(
            l,
            entries.len() as u64,
            es.as_mut_ptr(),
            3,
            size_of::<FsInspectDirEntry>(),
            &mut n,
        );
        assert_eq!(s, FS_INSPECT_OK, "{}", last_error());
        if n == 0 {
            break;
        }
        entries.extend(es[..n].iter().map(got));
    }
    assert_eq!(entries.len(), plus.len());
    for (a, b) in entries.iter().zip(&plus) {
        assert_eq!((&a.name, a.node, a.kind), (&b.name, b.node, b.kind));
        same_stat(a.stat.as_ref().unwrap(), b.stat.as_ref().unwrap());
    }

    // Found by identity and by node.
    let id = CString::new(plus[2].name.as_str()).unwrap();
    let mut at = 99u64;
    assert_eq!(fs_inspect_listing_find(l, id.as_ptr(), &mut at), FS_INSPECT_OK);
    assert_eq!(at, 2);
    let none = CString::new("no such entry").unwrap();
    assert_eq!(fs_inspect_listing_find(l, none.as_ptr(), &mut at), FS_INSPECT_E_NOT_FOUND);
    assert_eq!(fs_inspect_listing_position(l, plus[4].node, &mut at), FS_INSPECT_OK);
    assert_eq!(at, 4);
    let stranger = FsInspectNode { root: r.root, id: 0xFFFF_FFF0 };
    assert_eq!(fs_inspect_listing_position(l, stranger, &mut at), FS_INSPECT_E_NOT_FOUND);

    // In identity order (directories first or not): a permutation of the positions, sorted.
    for by in [0, FS_INSPECT_DIR_ORDER_IDS, FS_INSPECT_DIR_ORDER_DIRS_FIRST] {
        let mut order = vec![0u64; len];
        let mut n = 0usize;
        assert_eq!(fs_inspect_listing_order_read(l, by, 0, order.as_mut_ptr(), len, &mut n), FS_INSPECT_OK);
        assert_eq!(n, len);
        let order: Vec<usize> = order.iter().map(|&i| i as usize).collect();
        let mut seen = order.clone();
        seen.sort_unstable();
        assert_eq!(seen, (0..len).collect::<Vec<_>>());
        if by == FS_INSPECT_DIR_ORDER_DIRS_FIRST {
            let dirs = order.iter().take_while(|&&i| plus[i].kind == FS_INSPECT_NODE_DIR).count();
            assert!(order[dirs..].iter().all(|&i| plus[i].kind != FS_INSPECT_NODE_DIR), "directories first");
        }
        let mut rest = [0u64; 1];
        assert_eq!(fs_inspect_listing_order_read(l, by, len, rest.as_mut_ptr(), 1, &mut n), FS_INSPECT_OK);
        assert_eq!(n, 0);
    }

    // As read-ahead siblings: each entry, a plain file on the volume readable.
    let mut sibs = vec![FsInspectSibling::default(); len];
    let mut n = 0usize;
    assert_eq!(fs_inspect_listing_siblings_read(l, 0, sibs.as_mut_ptr(), len, &mut n), FS_INSPECT_OK);
    assert_eq!(n, len);
    for (s, g) in sibs.iter().zip(&plus) {
        assert_eq!(s.node, g.node);
        let st = g.stat.as_ref().unwrap();
        if s.readable {
            assert_eq!((st.kind, s.size), (FS_INSPECT_NODE_FILE, st.size), "{}", g.name);
        }
    }
    assert!(sibs.iter().any(|s| s.readable));
    fs_inspect_listing_free(l);
    fs_inspect_listing_free(ptr::null_mut());
}

/// Every entry a walk hands: (depth, path, has a stat, node, kind, failed).
type Entry = (usize, String, bool, FsInspectNode, u32, bool);

/// Walk `dir` with `opts` (NULL: the defaults), `cap` entries a call; `skip` decides which
/// directories handed are not entered; `stop_after` entries, `cancel` is triggered.
fn walk(
    fs: *const FsInspectFs,
    dir: FsInspectNode,
    opts: *const FsInspectWalkOptions,
    cap: usize,
    skip: &dyn Fn(&str) -> bool,
    cancel: *const FsInspectCancel,
    stop_after: usize,
) -> (FsInspectStatus, Vec<Entry>) {
    let mut w = ptr::null_mut();
    let s = fs_inspect_fs_walk(fs, dir, opts, &mut w, cancel);
    if s != FS_INSPECT_OK {
        return (s, Vec::new());
    }
    let mut out: Vec<Entry> = Vec::new();
    let status = loop {
        let mut es: Vec<FsInspectWalkEntry> = (0..cap).map(|_| zeroed()).collect();
        let mut n = 0usize;
        let mut errors = ptr::null_mut();
        let sz = size_of::<FsInspectWalkEntry>();
        let s = fs_inspect_walk_next_batch(w, es.as_mut_ptr(), cap, sz, &mut n, &mut errors, ptr::null());
        if s != FS_INSPECT_OK {
            assert!(errors.is_null());
            break s;
        }
        // Each failed entry's error is in the batch's item errors.
        let failed = es[..n].iter().filter(|e| e.failed).count();
        assert!(item_errors(errors).len() >= failed);
        if n == 0 {
            break FS_INSPECT_OK;
        }
        for e in &es[..n] {
            let path = cstr(e.path);
            // The name is the path's last component.
            assert_eq!(path.rsplit('/').next().unwrap(), cstr(e.name), "{path}");
            if e.kind == FS_INSPECT_NODE_DIR && skip(&path) {
                assert_eq!(fs_inspect_walk_skip(w, e.node), FS_INSPECT_OK);
            }
            out.push((e.depth, path, !e.stat.is_null(), e.node, e.kind, e.failed));
        }
        if out.len() >= stop_after {
            fs_inspect_cancel_trigger(cancel);
        }
    };
    fs_inspect_walk_free(w);
    (status, out)
}

#[test]
fn a_walk_hands_every_entry_with_its_path() {
    let dir = tempfile::tempdir().unwrap();
    let o = open(&image(dir.path()));
    let r = root(o.fs);
    let never = |_: &str| false;

    let (s, all) = walk(o.fs, r.node, ptr::null(), 7, &never, ptr::null(), usize::MAX);
    assert_eq!(s, FS_INSPECT_OK, "{}", last_error());
    assert!(all.iter().any(|e| e.0 == 0 && e.1 == "/plain.bin"), "{all:?}");
    assert!(all.iter().all(|e| !e.2 && !e.5));
    let deeper: Vec<_> = all.iter().filter(|e| e.0 > 0).collect();
    assert!(!deeper.is_empty(), "the fixture has subdirectories");
    // One entry a call hands the same.
    let (_, ones) = walk(o.fs, r.node, ptr::null(), 1, &never, ptr::null(), usize::MAX);
    assert_eq!(ones.iter().map(|e| &e.1).collect::<Vec<_>>(), all.iter().map(|e| &e.1).collect::<Vec<_>>());

    // With stats, in preorder, one level, small batches: the top directory's entries, each
    // with its stat.
    let opts = FsInspectWalkOptions {
        flags: FS_INSPECT_DIR_FLAG_STAT,
        order: FS_INSPECT_WALK_PREORDER,
        max_depth: 1,
        batch: 2,
        ..sized()
    };
    let (s, top) = walk(o.fs, r.node, &opts, 3, &never, ptr::null(), usize::MAX);
    assert_eq!(s, FS_INSPECT_OK, "{}", last_error());
    assert!(top.iter().all(|e| e.0 == 0 && e.2));
    assert_eq!(top.len(), all.iter().filter(|e| e.0 == 0).count());

    // An unknown flag bit is unsupported; an unknown order is an invalid argument.
    let bad = FsInspectWalkOptions { flags: 1 << 7, ..opts };
    assert_eq!(walk(o.fs, r.node, &bad, 1, &never, ptr::null(), usize::MAX).0, FS_INSPECT_E_UNSUPPORTED);
    let bad = FsInspectWalkOptions { order: 9, ..opts };
    assert_eq!(walk(o.fs, r.node, &bad, 1, &never, ptr::null(), usize::MAX).0, FS_INSPECT_E_INVALID_ARGUMENT);
    // A stride too small for an entry is refused.
    let mut w = ptr::null_mut();
    assert_eq!(fs_inspect_fs_walk(o.fs, r.node, ptr::null(), &mut w, ptr::null()), FS_INSPECT_OK);
    let mut e: FsInspectWalkEntry = zeroed();
    let mut n = 0usize;
    let none = ptr::null_mut();
    assert_eq!(fs_inspect_walk_next_batch(w, &mut e, 1, 8, &mut n, none, ptr::null()), FS_INSPECT_E_INVALID_ARGUMENT);
    // A token given to one call stops that call.
    let c = triggered();
    let sz = size_of::<FsInspectWalkEntry>();
    assert_eq!(fs_inspect_walk_next_batch(w, &mut e, 1, sz, &mut n, none, c), FS_INSPECT_E_CANCELLED);
    fs_inspect_cancel_free(c);
    fs_inspect_walk_free(w);

    // A directory skipped is not entered.
    let parent = deeper[0].1.rsplit_once('/').unwrap().0.to_string();
    let skip_parent = |p: &str| p == parent;
    let (s, skipped) = walk(o.fs, r.node, ptr::null(), 1, &skip_parent, ptr::null(), usize::MAX);
    assert_eq!(s, FS_INSPECT_OK);
    assert!(skipped.iter().any(|e| e.1 == parent), "the skipped directory itself is handed");
    assert!(skipped.iter().all(|e| !e.1.starts_with(&format!("{parent}/"))), "{skipped:?}");

    // Cancelled through its token, from the caller's side, after two entries.
    let mut c = ptr::null_mut();
    assert_eq!(fs_inspect_cancel_new(&mut c), FS_INSPECT_OK);
    let (s, cancelled) = walk(o.fs, r.node, ptr::null(), 1, &never, c, 2);
    assert_eq!(s, FS_INSPECT_E_CANCELLED);
    assert!(cancelled.len() >= 2 && cancelled.len() < all.len());
    fs_inspect_cancel_free(c);
    // A walk started after runs.
    let (s, again) = walk(o.fs, r.node, ptr::null(), 4, &never, ptr::null(), usize::MAX);
    assert_eq!(s, FS_INSPECT_OK);
    assert_eq!(again.len(), all.len());
}

#[test]
fn small_files_read_ahead_of_their_opening() {
    let dir = tempfile::tempdir().unwrap();
    let o = open(&image(dir.path()));
    let r = root(o.fs);
    // The directory listed whole with its stats: what a read-ahead reads from.
    let opts = FsInspectDirOptions { flags: FS_INSPECT_DIR_FLAG_STAT, ..sized() };
    let mut d = ptr::null_mut();
    assert_eq!(fs_inspect_dir_open(o.fs, r.node, &opts, &mut d, ptr::null()), FS_INSPECT_OK);
    let mut s = ptr::null_mut();
    assert_eq!(fs_inspect_dir_collect(d, &mut s, ptr::null_mut(), ptr::null()), FS_INSPECT_OK, "{}", last_error());
    fs_inspect_dir_free(d);
    let mut len = 0usize;
    assert_eq!(fs_inspect_listing_count(s, &mut len), FS_INSPECT_OK);
    let mut sibs = vec![FsInspectSibling::default(); len];
    let mut n = 0usize;
    assert_eq!(fs_inspect_listing_siblings_read(s, 0, sibs.as_mut_ptr(), len, &mut n), FS_INSPECT_OK);
    assert_eq!(n, len);
    for e in &sibs {
        let st = stat(o.fs, e.node);
        let readable = st.kind == FS_INSPECT_NODE_FILE && st.presence == FS_INSPECT_PRESENCE_NORMAL;
        assert_eq!(e.readable, readable);
    }
    let small: Vec<usize> = (0..sibs.len()).filter(|&i| sibs[i].readable && sibs[i].size <= 256 << 10).collect();
    assert!(small.len() >= 3, "{} small files", small.len());

    let mut ra = ptr::null_mut();
    let opts = FsInspectReadAheadOptions { batch_files: 2, ..sized() };
    assert_eq!(fs_inspect_fs_read_ahead_new(o.fs, &opts, &mut ra, ptr::null()), FS_INSPECT_OK, "{}", last_error());

    // A buffer's bytes (freed), or None for NULL.
    let content = |b: *mut FsInspectBuf| (!b.is_null()).then(|| buf(b));
    let read = |i: usize| {
        let mut b = 9usize as *mut FsInspectBuf;
        let st = fs_inspect_read_ahead_read(ra, s, i, &mut b, ptr::null());
        assert_eq!(st, FS_INSPECT_OK, "{}", last_error());
        content(b)
    };
    let whole = |n: FsInspectNode| {
        let mut f = ptr::null_mut();
        assert_eq!(fs_inspect_fs_open(o.fs, n, 0, ptr::null_mut(), &mut f, ptr::null()), FS_INSPECT_OK);
        let mut v = vec![0u8; stat(o.fs, n).size as usize];
        let mut got = 0usize;
        assert_eq!(fs_inspect_file_read_at(f, 0, v.as_mut_ptr(), v.len(), &mut got, ptr::null()), FS_INSPECT_OK);
        assert_eq!(got, v.len());
        fs_inspect_file_free(f);
        v
    };
    let answer = |i: usize| {
        let mut a = 9;
        let mut kept = 9usize as *mut FsInspectBuf;
        let st = fs_inspect_read_ahead_try_open(ra, s, i, &mut a, &mut kept);
        assert_eq!(st, FS_INSPECT_OK, "{}", last_error());
        assert_eq!(a == FS_INSPECT_AHEAD_KEPT, !kept.is_null());
        (a, content(kept))
    };
    let kept = |n: FsInspectNode| {
        let mut yes = false;
        assert_eq!(fs_inspect_read_ahead_is_kept(ra, n, &mut yes), FS_INSPECT_OK, "{}", last_error());
        yes
    };
    assert!(!kept(sibs[small[2]].node), "nothing kept before a batch");
    assert_eq!(answer(small[0]), (FS_INSPECT_AHEAD_ALONE, None), "the first opened is read alone");
    assert_eq!(answer(small[1]), (FS_INSPECT_AHEAD_BATCH, None));
    assert_eq!(read(small[1]).unwrap(), whole(sibs[small[1]].node), "read with a batch");
    assert!(kept(sibs[small[2]].node), "the batch's other file is kept");
    assert_eq!(answer(small[2]), (FS_INSPECT_AHEAD_KEPT, Some(whole(sibs[small[2]].node))), "kept");
    let mut stats: FsInspectReadAheadStats = sized();
    assert_eq!(fs_inspect_read_ahead_get_stats(ra, &mut stats), FS_INSPECT_OK);
    assert_eq!((stats.hits, stats.misses, stats.batches, stats.files_read), (1, 2, 1, 2));
    let mut a = 0;
    let mut kb = ptr::null_mut();
    let st = fs_inspect_read_ahead_try_open(ra, s, sibs.len(), &mut a, &mut kb);
    assert_eq!(st, FS_INSPECT_E_NOT_FOUND);
    let st = fs_inspect_read_ahead_try_open(ra, s, 0, ptr::null_mut(), &mut kb);
    assert_eq!(st, FS_INSPECT_E_INVALID_ARGUMENT);
    let st = fs_inspect_read_ahead_try_open(ra, s, 0, &mut a, ptr::null_mut());
    assert_eq!(st, FS_INSPECT_E_INVALID_ARGUMENT);
    let mut yes = false;
    assert_eq!(fs_inspect_read_ahead_is_kept(ptr::null(), r.node, &mut yes), FS_INSPECT_E_INVALID_ARGUMENT);

    // An index past the entries, NULLs.
    let mut b = ptr::null_mut();
    let st = fs_inspect_read_ahead_read(ra, s, sibs.len(), &mut b, ptr::null());
    assert_eq!(st, FS_INSPECT_E_NOT_FOUND);
    let st = fs_inspect_read_ahead_read(ra, s, 0, ptr::null_mut(), ptr::null());
    assert_eq!(st, FS_INSPECT_E_INVALID_ARGUMENT);
    let st = fs_inspect_read_ahead_read(ra, ptr::null(), 0, &mut b, ptr::null());
    assert_eq!(st, FS_INSPECT_E_INVALID_ARGUMENT);
    assert!(b.is_null());

    // Clearing drops what is kept; forgetting makes the next opening a first one.
    assert_eq!(fs_inspect_read_ahead_clear(ra), FS_INSPECT_OK);
    assert_eq!(fs_inspect_read_ahead_forget(ra, r.node), FS_INSPECT_OK);
    assert_eq!(read(small[0]), None);
    assert_eq!(fs_inspect_read_ahead_get_stats(ra, &mut stats), FS_INSPECT_OK);
    assert_eq!(stats.kept_files, 0);
    let mut c = ptr::null_mut();
    assert_eq!(fs_inspect_cancel_new(&mut c), FS_INSPECT_OK);
    fs_inspect_cancel_trigger(c);
    let st = fs_inspect_read_ahead_read(ra, s, small[1], &mut b, c);
    assert!(st == FS_INSPECT_E_CANCELLED || st == FS_INSPECT_OK, "cancelled where it reads: {st}");
    content(b);
    fs_inspect_cancel_free(c);
    fs_inspect_read_ahead_free(ra);
    fs_inspect_listing_free(s);
    assert_eq!(
        fs_inspect_fs_read_ahead_new(ptr::null(), ptr::null(), &mut ra, ptr::null()),
        FS_INSPECT_E_INVALID_ARGUMENT
    );
}

/// Each string field of what a call hands out: set (never NULL), "" when it has no value.
macro_rules! strings_set {
    ($what:expr, $v:expr, $($f:ident),+) => {
        $(assert!(!$v.$f.is_null(), "{}.{} is NULL", $what, stringify!($f));)+
    };
}

extern "C" fn path_set(_ctx: *mut c_void, p: *const FsInspectProgress) -> i32 {
    // SAFETY: `p` is valid for the call.
    let p = unsafe { &*p };
    strings_set!("progress", p, path);
    0
}

#[test]
fn every_string_handed_out_is_set() {
    let dir = tempfile::tempdir().unwrap();
    let o = open(&image(dir.path()));
    let none = ptr::null();

    // The set: its volumes, partitions, catalog, guest mounts, diagnostics.
    let mut vols = ptr::null_mut();
    assert_eq!(fs_inspect_disks_volumes(o.disks, &mut vols, none), FS_INSPECT_OK);
    let mut n = 0usize;
    assert_eq!(fs_inspect_volumes_count(vols, &mut n), FS_INSPECT_OK);
    for i in 0..n {
        let mut v: FsInspectVolumeEntry = sized();
        assert_eq!(fs_inspect_volumes_get(vols, i, &mut v), FS_INSPECT_OK);
        strings_set!("volume_entry", v, name, key);
    }
    fs_inspect_volumes_free(vols);
    let mut table = ptr::null_mut();
    let disk0 = FsInspectDeviceRef { kind: FS_INSPECT_DEVICE_DISK, ..Default::default() };
    assert_eq!(fs_inspect_disks_partitions(o.disks, disk0, &mut table, none), FS_INSPECT_OK);
    assert_eq!(fs_inspect_partition_table_count(table, &mut n), FS_INSPECT_OK);
    for i in 0..n {
        let mut p: FsInspectPartition = sized();
        assert_eq!(fs_inspect_partition_table_get(table, i, &mut p), FS_INSPECT_OK);
        strings_set!("partition", p, name);
    }
    fs_inspect_partition_table_free(table);
    let mut info: FsInspectVolumeInfo = sized();
    assert_eq!(fs_inspect_volume_get_info(o.vol, &mut info), FS_INSPECT_OK);
    strings_set!("volume_info", info, label, uuid, logical_container, logical_volume);
    let mut state: FsInspectVolumeStateInfo = sized();
    assert_eq!(fs_inspect_volume_state(o.vol, &mut state, none), FS_INSPECT_OK);
    strings_set!("volume_state_info", state, log, why);
    let mut cat = ptr::null_mut();
    assert_eq!(fs_inspect_disks_catalog(o.disks, &mut cat, none), FS_INSPECT_OK, "{}", last_error());
    assert_eq!(fs_inspect_catalog_volume_count(cat, &mut n), FS_INSPECT_OK);
    assert!(n > 0);
    for i in 0..n {
        let mut v: FsInspectCatalogVolume = sized();
        assert_eq!(fs_inspect_catalog_volume_get(cat, i, &mut v), FS_INSPECT_OK);
        strings_set!("catalog_volume", v, name, id, label, mount_at);
    }
    assert_eq!(fs_inspect_catalog_group_count(cat, &mut n), FS_INSPECT_OK);
    for i in 0..n {
        let mut g: FsInspectCatalogGroup = sized();
        assert_eq!(fs_inspect_catalog_group_get(cat, i, &mut g), FS_INSPECT_OK);
        strings_set!("catalog_group", g, name, key);
    }
    fs_inspect_catalog_free(cat);
    let mut guest = ptr::null_mut();
    assert_eq!(fs_inspect_disks_guest(o.disks, &mut guest, none), FS_INSPECT_OK);
    assert_eq!(fs_inspect_guest_mount_count(guest, &mut n), FS_INSPECT_OK);
    for i in 0..n {
        let mut m: FsInspectGuestMount = sized();
        assert_eq!(fs_inspect_guest_mount_get(guest, i, &mut m), FS_INSPECT_OK);
        strings_set!("guest_mount", m, at);
    }
    fs_inspect_guest_free(guest);

    // The file system: roots, entries, a walk, each file's streams, attributes and names.
    for r in roots(o.fs, false) {
        let mut info: FsInspectRootInfo = sized();
        let mut rs = ptr::null_mut();
        assert_eq!(fs_inspect_fs_roots(o.fs, &mut rs, none), FS_INSPECT_OK);
        assert_eq!(fs_inspect_roots_get(rs, 0, &mut info), FS_INSPECT_OK);
        strings_set!("root_info", info, name, path, mountpoint);
        fs_inspect_roots_free(rs);
        let opts = FsInspectDirOptions { flags: FS_INSPECT_DIR_FLAG_STAT, ..sized() };
        let mut d = ptr::null_mut();
        assert_eq!(fs_inspect_dir_open(o.fs, r.info.node, &opts, &mut d, none), FS_INSPECT_OK);
        let mut es: Vec<FsInspectDirEntry> = (0..64).map(|_| zeroed()).collect();
        let mut errors = ptr::null_mut();
        let st = fs_inspect_dir_read(d, es.as_mut_ptr(), 64, size_of::<FsInspectDirEntry>(), &mut n, &mut errors, none);
        assert_eq!(st, FS_INSPECT_OK);
        fs_inspect_item_errors_free(errors);
        for e in &es[..n] {
            strings_set!("dir_entry", e, name);
        }
        fs_inspect_dir_free(d);

        let mut w = ptr::null_mut();
        assert_eq!(fs_inspect_fs_walk(o.fs, r.info.node, ptr::null(), &mut w, none), FS_INSPECT_OK);
        let mut nodes = Vec::new();
        loop {
            let mut es: Vec<FsInspectWalkEntry> = (0..64).map(|_| zeroed()).collect();
            let mut errors = ptr::null_mut();
            let st = fs_inspect_walk_next_batch(
                w,
                es.as_mut_ptr(),
                64,
                size_of::<FsInspectWalkEntry>(),
                &mut n,
                &mut errors,
                none,
            );
            assert_eq!(st, FS_INSPECT_OK);
            fs_inspect_item_errors_free(errors);
            if n == 0 {
                break;
            }
            for e in &es[..n] {
                strings_set!("walk_entry", e, path, name);
                nodes.push(e.node);
            }
        }
        fs_inspect_walk_free(w);
        assert!(nodes.len() > 15);
        for node in nodes {
            let mut s = ptr::null_mut();
            assert_eq!(fs_inspect_fs_streams(o.fs, node, &mut s, none), FS_INSPECT_OK);
            assert_eq!(fs_inspect_streams_count(s, &mut n), FS_INSPECT_OK);
            for i in 0..n {
                let mut si: FsInspectStreamInfo = sized();
                assert_eq!(fs_inspect_streams_get(s, i, &mut si), FS_INSPECT_OK);
                strings_set!("stream_info", si, name);
            }
            fs_inspect_streams_free(s);
            let mut x = ptr::null_mut();
            assert_eq!(fs_inspect_fs_xattrs(o.fs, node, &mut x, none), FS_INSPECT_OK);
            assert_eq!(fs_inspect_xattrs_count(x, &mut n), FS_INSPECT_OK);
            for i in 0..n {
                let mut xa: FsInspectXattr = sized();
                assert_eq!(fs_inspect_xattrs_get(x, i, &mut xa), FS_INSPECT_OK);
                strings_set!("xattr", xa, name);
            }
            fs_inspect_xattrs_free(x);
            let mut names = ptr::null_mut();
            assert_eq!(fs_inspect_fs_names(o.fs, node, &mut names, none), FS_INSPECT_OK);
            assert_eq!(fs_inspect_names_count(names, &mut n), FS_INSPECT_OK);
            for i in 0..n {
                let mut nn: FsInspectNodeName = sized();
                assert_eq!(fs_inspect_names_get(names, i, &mut nn), FS_INSPECT_OK);
                strings_set!("node_name", nn, name);
            }
            fs_inspect_names_free(names);
            let mut l = ptr::null_mut();
            if fs_inspect_fs_read_link(o.fs, node, &mut l, none) == FS_INSPECT_OK {
                let mut li: FsInspectLinkInfo = sized();
                assert_eq!(fs_inspect_link_get_info(l, &mut li), FS_INSPECT_OK);
                strings_set!("link_info", li, target, print);
                fs_inspect_link_free(l);
            }
        }

        // An export (its progress, its report's lists) and a verification.
        let mut out = Vec::<u8>::new();
        let ops = FsInspectWriteOps {
            struct_size: size_of::<FsInspectWriteOps>(),
            ctx: &mut out as *mut Vec<u8> as *mut c_void,
            write: Some(collect),
            release: Some(released),
        };
        let mut rep = ptr::null_mut();
        let st = fs_inspect_fs_export_archive(
            o.fs,
            &r.info.node,
            1,
            FS_INSPECT_ARCHIVE_TAR,
            &ops,
            ptr::null(),
            Some(path_set),
            ptr::null_mut(),
            &mut rep,
            none,
        );
        assert_eq!(st, FS_INSPECT_OK, "{}", last_error());
        assert_eq!(fs_inspect_export_report_skipped_count(rep, &mut n), FS_INSPECT_OK);
        for i in 0..n {
            let mut s: FsInspectSkipped = sized();
            assert_eq!(fs_inspect_export_report_skipped_get(rep, i, &mut s), FS_INSPECT_OK);
            strings_set!("skipped", s, path, reason);
        }
        assert_eq!(fs_inspect_export_report_cloud_count(rep, &mut n), FS_INSPECT_OK);
        assert!(n > 0);
        for i in 0..n {
            let mut c: FsInspectCloudFile = sized();
            assert_eq!(fs_inspect_export_report_cloud_get(rep, i, &mut c), FS_INSPECT_OK);
            strings_set!("cloud_file", c, path);
        }
        assert_eq!(fs_inspect_export_report_note_count(rep, &mut n), FS_INSPECT_OK);
        for i in 0..n {
            let mut nt: FsInspectNote = sized();
            assert_eq!(fs_inspect_export_report_note_get(rep, i, &mut nt), FS_INSPECT_OK);
            strings_set!("note", nt, path, note);
        }
        fs_inspect_export_report_free(rep);
    }
    let mut vrep = ptr::null_mut();
    assert_eq!(fs_inspect_volume_verify(o.vol, ptr::null(), &mut vrep, none), FS_INSPECT_OK);
    let mut s: FsInspectVerifySummary = sized();
    assert_eq!(fs_inspect_verify_report_get_summary(vrep, &mut s), FS_INSPECT_OK);
    strings_set!("verify_summary", s, stopped_message);
    assert_eq!(fs_inspect_verify_report_checked_count(vrep, &mut n), FS_INSPECT_OK);
    for i in 0..n {
        let mut c: FsInspectVerifyChecked = sized();
        assert_eq!(fs_inspect_verify_report_checked_get(vrep, i, &mut c), FS_INSPECT_OK);
        strings_set!("verify_checked", c, name);
    }
    assert_eq!(fs_inspect_verify_report_not_covered_count(vrep, &mut n), FS_INSPECT_OK);
    for i in 0..n {
        let mut c: FsInspectVerifyNotCovered = sized();
        assert_eq!(fs_inspect_verify_report_not_covered_get(vrep, i, &mut c), FS_INSPECT_OK);
        strings_set!("verify_not_covered", c, name, which);
    }
    assert_eq!(fs_inspect_verify_report_finding_count(vrep, &mut n), FS_INSPECT_OK);
    for i in 0..n {
        let mut f: FsInspectFinding = sized();
        assert_eq!(fs_inspect_verify_report_finding_get(vrep, i, &mut f), FS_INSPECT_OK);
        strings_set!("finding", f, structure, message);
    }
    fs_inspect_verify_report_free(vrep);

    // Diagnostics and an item error.
    let mut diags = ptr::null_mut();
    assert_eq!(fs_inspect_disks_diagnostics(o.disks, &mut diags), FS_INSPECT_OK);
    assert_eq!(fs_inspect_diagnostics_count(diags, &mut n), FS_INSPECT_OK);
    for i in 0..n {
        let mut d: FsInspectDiagnostic = sized();
        assert_eq!(fs_inspect_diagnostics_get(diags, i, &mut d), FS_INSPECT_OK);
        strings_set!("diagnostic", d, logical, message);
    }
    fs_inspect_diagnostics_free(diags);
}

/// `fs_inspect_fs_restore_metadata`: unknown facet bits are refused before anything is
/// written; each facet skipped has one bit, a status, a reason, and a stream name only for
/// `FS_INSPECT_META_FLAG_STREAMS`; past the end is `FS_INSPECT_E_NOT_FOUND`.
#[test]
fn restore_metadata_and_its_report() {
    let dir = tempfile::tempdir().unwrap();
    let o = open(&image(dir.path()));
    let r = root(o.fs);
    // A file with named streams (`meta`, `tiny`), a Windows owner and the archive attribute.
    let node = resolve(o.fs, r.root, "/ads.bin");
    let dest = dir.path().join("dest");
    std::fs::write(&dest, b"").unwrap();
    let path = CString::new(dest.to_str().unwrap()).unwrap();
    let mut rep = ptr::null_mut();

    let unknown = FS_INSPECT_META_FLAG_ALL | (1 << 20);
    assert_eq!(
        fs_inspect_fs_restore_metadata(o.fs, node, path.as_ptr(), unknown, &mut rep, ptr::null()),
        FS_INSPECT_E_UNSUPPORTED
    );
    assert!(rep.is_null());
    let missing = CString::new(dir.path().join("none").to_str().unwrap()).unwrap();
    assert_eq!(
        fs_inspect_fs_restore_metadata(o.fs, node, missing.as_ptr(), FS_INSPECT_META_FLAG_ALL, &mut rep, ptr::null()),
        FS_INSPECT_E_NOT_FOUND
    );

    let facets = FS_INSPECT_META_FLAG_ALL & !FS_INSPECT_META_FLAG_ACL;
    assert_eq!(
        fs_inspect_fs_restore_metadata(o.fs, node, path.as_ptr(), facets, &mut rep, ptr::null()),
        FS_INSPECT_OK,
        "{}",
        last_error()
    );
    let mut n = usize::MAX;
    assert_eq!(fs_inspect_metadata_report_skipped_count(rep, &mut n), FS_INSPECT_OK);
    let mut skipped = Vec::new();
    for i in 0..n {
        let mut s: FsInspectSkippedFacet = sized();
        assert_eq!(fs_inspect_metadata_report_skipped_get(rep, i, &mut s), FS_INSPECT_OK);
        assert!(s.facet.is_power_of_two() && s.facet & facets != 0, "{:#x}", s.facet);
        assert_eq!(s.stream.is_null(), s.facet != FS_INSPECT_META_FLAG_STREAMS, "{:#x}", s.facet);
        if !s.stream.is_null() {
            assert!(["meta", "tiny"].contains(&cstr(s.stream).as_str()), "{}", cstr(s.stream));
        }
        assert!(s.status < 0, "{:#x}: {}", s.facet, s.status);
        let reason = cstr(s.reason);
        assert!(!reason.is_empty() && !reason.contains(dest.to_str().unwrap()), "{reason}");
        skipped.push((s.facet, s.status));
    }
    let mut past: FsInspectSkippedFacet = sized();
    assert_eq!(fs_inspect_metadata_report_skipped_get(rep, n, &mut past), FS_INSPECT_E_NOT_FOUND);
    fs_inspect_metadata_report_free(rep);

    if cfg!(windows) {
        // The streams are written; another owner needs a privilege a test may not have.
        assert!(std::fs::metadata(format!("{}:meta", dest.display())).is_ok());
        for (facet, status) in &skipped {
            assert_eq!((*facet, *status), (FS_INSPECT_META_FLAG_OWNER, FS_INSPECT_E_PERMISSION_DENIED));
        }
    } else {
        // A Windows owner and Windows attributes cannot be represented on Unix.
        for facet in [FS_INSPECT_META_FLAG_OWNER, FS_INSPECT_META_FLAG_MODE] {
            assert!(skipped.contains(&(facet, FS_INSPECT_E_UNSUPPORTED)), "{facet:#x}: {skipped:?}");
        }
    }
}

/// An entry whose stat cannot be read (its MFT record's update sequence array out of the
/// record) is listed with the others: the call succeeds, its stat is left
/// out, and the failure is handed as an item error with the entry's index in the batch, its
/// status and a message naming the record.
#[test]
fn an_entry_whose_stat_fails_is_an_item_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = image(dir.path());
    let file = std::path::PathBuf::from(path.to_str().unwrap());
    let mut img = std::fs::read(&file).unwrap();
    let name: Vec<u8> = "resident.txt".encode_utf16().flat_map(u16::to_le_bytes).collect();
    // Its $FILE_NAME: the name after its length in characters and its namespace (the
    // symbolic link to it holds the name too, in its reparse data).
    let rec = img
        .windows(name.len())
        .enumerate()
        .filter(|&(i, w)| w == &name[..] && img[i - 2] == 12)
        .map(|(i, _)| i / 1024 * 1024)
        .find(|&r| &img[r..r + 4] == b"FILE")
        .expect("its MFT record");
    // Its update sequence array placed past the record's end: the record cannot be read.
    img[rec + 4..rec + 6].copy_from_slice(&0xFFF0u16.to_le_bytes());
    std::fs::write(&file, &img).unwrap();
    let o = open(&path);
    let r = root(o.fs);
    let mut opts: FsInspectDirOptions = sized();
    opts.flags = FS_INSPECT_DIR_FLAG_STAT;
    let mut d = ptr::null_mut();
    assert_eq!(fs_inspect_dir_open(o.fs, r.node, &opts, &mut d, ptr::null()), FS_INSPECT_OK, "{}", last_error());
    let mut es: Vec<FsInspectDirEntry> = (0..64).map(|_| zeroed()).collect();
    let (mut n, mut errors) = (0usize, ptr::null_mut());
    let s = fs_inspect_dir_read(
        d,
        es.as_mut_ptr(),
        es.len(),
        size_of::<FsInspectDirEntry>(),
        &mut n,
        &mut errors,
        ptr::null(),
    );
    assert_eq!(s, FS_INSPECT_OK, "{}", last_error());
    let names: Vec<String> = es[..n].iter().map(|e| cstr(e.name)).collect();
    let at = names.iter().position(|n| n == "resident.txt").expect("still listed");
    assert!(es[at].stat.is_null(), "no stat for the damaged record");
    assert!(es.iter().take(n).enumerate().all(|(i, e)| i == at || !e.stat.is_null()), "the others' stats read");
    let errs = item_errors(errors);
    assert_eq!(errs.len(), 1, "{errs:?}");
    let (index, status, message, _) = &errs[0];
    assert_eq!(*index, at);
    assert_eq!(*status, FS_INSPECT_E_CORRUPT, "{message}");
    assert!(message.contains("MFT record") && message.contains("update sequence array"), "{errs:?}");
    fs_inspect_dir_free(d);
}
