//! Containers macOS made (`fixtures/apfs/macos`, `fixtures/apfs/encrypted`,
//! `fixtures/apfs/macos-lookup`) and containers Linux's apfsprogs made (`fixtures/apfs/linux`);
//! each directory's README.md says what they hold.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use fs_inspect_apfs::ApfsFs;
use fs_inspect_core::ns::{self, Namespace, StreamId};
use fs_inspect_core::{ByteRange, Confidence, CursorIter, DriverContext, Filesystem, FsKind, Sniff, VolumePath};
use fs_inspect_io::{DynSource, OffsetSource};
use fs_inspect_testkit::SparseSource;
use fs_inspect_testkit::lookup::file;
use std::path::PathBuf;
use std::sync::Arc;

fn check(src: DynSource) -> (Arc<ApfsFs>, Vec<ByteRange>) {
    let head = src.read_vec(0, 65536.min(src.size() as usize)).unwrap();
    let p = fs_inspect_apfs::probe(&Sniff { head: &head, volume_size: src.size() });
    assert_eq!(p, Some((FsKind::Apfs, Confidence::High)));
    let ctx = DriverContext::default();
    let fs = Arc::new(ApfsFs::open(src, &ctx).unwrap());
    assert!(ctx.diagnostics.all().is_empty(), "{:?}", ctx.diagnostics.all());
    let used: Vec<ByteRange> = CursorIter::new(fs.clone().allocated().unwrap()).map(|r| r.unwrap()).collect();
    for w in used.windows(2) {
        assert!(w[0].end() <= w[1].offset, "{used:?}");
    }
    let bs = fs.info().unit;
    let total: u64 = used.iter().map(|r| r.length).sum();
    let sm = fs.spaceman();
    // The bitmaps agree with the space manager's free count, and nothing lies past the end.
    assert_eq!(total / bs, sm.main.block_count - sm.main.free_count);
    assert!(used.last().unwrap().end() <= fs.info().size);
    // Block 0 is in use.
    assert_eq!(used[0].offset, 0);
    (fs, used)
}

// --- Containers made on macOS by newfs_apfs / diskutil / asr (fixtures/apfs/macos/README.md) ---

/// (offset, block size, block count, free count) of every container of `image` in
/// `fixtures/apfs/<made_on>/expected.txt` (read there by an independent parser).
fn expected(made_on: &str, image: &str) -> Vec<(u64, u32, u64, u64)> {
    let text = std::fs::read_to_string(fixture_dir(made_on).join("expected.txt")).unwrap();
    text.lines()
        .filter(|l| l.starts_with(&format!("{image} container ")))
        .map(|l| {
            let w: Vec<&str> = l.split_whitespace().collect();
            let field = |k: &str| w[w.iter().position(|x| *x == k).unwrap() + 1].parse::<u64>().unwrap();
            (w[2].parse().unwrap(), field("block_size") as u32, field("block_count"), field("free"))
        })
        .collect()
}

fn fixture_dir(name: &str) -> PathBuf {
    fs_inspect_testkit::fixture("apfs").join(name)
}

fn check_macos(image: &str, containers: usize) {
    check_made_on("macos", image, containers);
}

/// Every container of fixture `image` (in `fixtures/apfs/<made_on>`) against `expected.txt`.
fn check_made_on(made_on: &str, image: &str, containers: usize) {
    let file: DynSource = SparseSource::open(fixture_dir(made_on).join(format!("{image}.fsbs")));
    let want = expected(made_on, image);
    assert_eq!(want.len(), containers);
    for (offset, bs, blocks, free) in want {
        let src: DynSource = Arc::new(OffsetSource::new(file.clone(), offset, blocks * bs as u64).unwrap());
        let (fs, used) = check(src);
        assert_eq!((fs.info().unit, fs.info().size), (u64::from(bs), blocks * bs as u64));
        let total: u64 = used.iter().map(|r| r.length).sum();
        assert_eq!(total, (blocks - free) * bs as u64, "{image} container at {offset}");
    }
}

#[test]
fn macos_asr_bare_container() {
    // Laid out like a Mac backup made with asr: no partition table, four volumes.
    check_macos("asr-mac", 1);
}

#[test]
fn macos_gpt_three_containers() {
    check_macos("gpt-mac", 3);
}

/// A GPT disk whose container holds one volume macOS encrypted (a keybag, encrypted FS-tree
/// nodes; see fixtures/apfs/encrypted/README.md): the container opens in its partition, its used
/// blocks match `expected.txt`, and the volume is listed as encrypted and not read.
#[test]
fn macos_encrypted_volume_on_gpt() {
    check_made_on("encrypted", "enc-gpt", 1);
    let file: DynSource = SparseSource::open(fixture_dir("encrypted").join("enc-gpt.fsbs"));
    let (offset, bs, blocks, _) = expected("encrypted", "enc-gpt")[0];
    let src: DynSource = Arc::new(OffsetSource::new(file, offset, blocks * u64::from(bs)).unwrap());
    let fs = Arc::new(ApfsFs::open(src, &DriverContext::default()).unwrap());
    let roots = fs.roots().unwrap();
    assert_eq!(roots.len(), 1);
    assert_eq!(roots[0].name, "Locked");
    assert_eq!(roots[0].access, fs_inspect_core::RootAccess::Encrypted);
    let e = ns::stat(&*fs, roots[0].node).unwrap_err();
    assert_eq!(e.kind(), fs_inspect_core::ErrorKind::Unsupported, "{e}");
}

// --- Containers made on Linux by apfsprogs' mkapfs (see fixtures/apfs/linux/README.md) --------

#[test]
fn linux_mkapfs_bare_container() {
    check_made_on("linux", "mkapfs-bare", 1);
}

#[test]
fn linux_mkapfs_on_gpt() {
    check_made_on("linux", "mkapfs-gpt", 1);
}

// --- Path lookup (see fixtures/apfs/macos-lookup/README.md) -----------------------------------

/// The namespace of `fs` and a path in it.
fn ns_of(fs: Arc<ApfsFs>) -> Arc<dyn Namespace> {
    fs.namespace().unwrap()
}

fn p(s: &str) -> VolumePath {
    VolumePath::parse(s, 16).unwrap()
}

#[test]
fn macos_lookup() {
    let src: DynSource = SparseSource::open(fixture_dir("macos-lookup").join("lookup.fsbs"));
    let (fs, _) = check(src);
    let ns = ns_of(fs);
    fs_inspect_testkit::lookup::check_in(&ns, "apfs", "macos-lookup", "lookup");
    let roots = ns::path_roots(&*ns).unwrap();
    assert!(roots.iter().any(|r| ns.case_insensitive(r.root.0)));
    // Data is case-insensitive, CS is not.
    let upper = file(&ns, &p("/CI/mixedcase.txt"), 0).unwrap().unwrap();
    assert_eq!(upper.0, file(&ns, &p("/ci/MixedCase.TXT"), 0).unwrap().unwrap().0);
    assert!(file(&ns, &p("/cs/NAME.txt"), 0).unwrap().is_none());
    // In two volumes: the union of both (an exclusion then keeps no single mapping).
    let sig = file(&ns, &p("/.sig"), 16).unwrap().unwrap();
    assert_eq!(sig.0.len(), 2);
    assert_eq!(ns::find_files(&*ns, &roots, &p("/.sig")).unwrap().len(), 2);
    let frag = ns::find_files(&*ns, &roots, &p("/dir/frag.bin")).unwrap();
    let segs = ns.clone().open(frag[0].node, StreamId::MAIN).unwrap().segments().unwrap();
    assert!(segs.iter().any(|s| s.physical().is_some()));
    // Names are not normalized: the name as stored (decomposed) is found, the composed one not.
    assert!(file(&ns, &p("/dir/sub/cafe\u{301}.txt"), 0).unwrap().is_some());
    assert!(file(&ns, &p("/dir/sub/caf\u{e9}.txt"), 0).unwrap().is_none());
    // VM has its role; no volume is in a group; with no System or Data volume the first is the
    // default.
    let roots = ns.roots().unwrap();
    let vm = roots.iter().find(|r| r.name == "VM").unwrap();
    assert_eq!(vm.role, Some(fs_inspect_core::VolumeRole::Vm));
    assert!(roots.iter().all(|r| r.volume_group.is_none() && r.path == r.name));
    assert_eq!(roots.iter().filter(|r| r.default).map(|r| r.root).collect::<Vec<_>>(), [roots[0].root]);
}

/// A volume with a snapshot (`snap`): a file leaves out the blocks only it and its own version in
/// the snapshot hold, whether written before the snapshot or since; nothing a clone shares, even
/// one the snapshot alone still holds, or one of another inode whose data stream it took over.
#[test]
fn macos_lookup_with_a_snapshot() {
    let src: DynSource = SparseSource::open(fixture_dir("macos-lookup").join("snap.fsbs"));
    let (fs, _) = check(src);
    let ns = ns_of(fs);
    fs_inspect_testkit::lookup::check_in(&ns, "apfs", "macos-lookup", "snap");
    let own = |s: &str| {
        let f = file(&ns, &p(s), 0).unwrap().unwrap();
        f.0.iter().map(|r| r.length).sum::<u64>()
    };
    for (path, len) in [("/keep.bin", 256 << 10), ("/part.bin", 256 << 10), ("/new.bin", 64 << 10)] {
        assert_eq!(own(path), len, "{path}");
    }
    for path in ["/pre.bin", "/preclone.bin", "/gone.bin", "/post.bin", "/postclone.bin", "/moved-copy.bin"] {
        assert_eq!(own(path), 0, "{path}");
    }
}

/// Volumes asr wrote (it leaves a snapshot in each): lookups read through the snapshots.
#[test]
fn macos_lookup_through_asr_snapshots() {
    let src: DynSource = SparseSource::open(fixture_dir("macos").join("asr-mac.fsbs"));
    let ns = ns_of(Arc::new(ApfsFs::open(src, &DriverContext::default()).unwrap()));
    let roots = ns::path_roots(&*ns).unwrap();
    let names: Vec<String> = roots
        .iter()
        .filter_map(|r| ns::resolve(&*ns, r.node, &p("/apfs")).unwrap())
        .flat_map(|d| ns::list(&*ns, d.node).unwrap())
        .map(|e| e.name.to_string_lossy())
        .collect();
    assert!(names.contains(&"clone0.bin".to_string()));
    // The roles asr set; snapshots carry their own names as paths and their volume's role.
    use fs_inspect_core::{RootKind, VolumeRole};
    let all = ns.roots().unwrap();
    let role = |name: &str| all.iter().find(|r| r.name == name).unwrap().role;
    assert_eq!(role("Data"), Some(VolumeRole::Data));
    assert_eq!(role("Macintosh HD"), Some(VolumeRole::System));
    assert_eq!(role("Preboot"), Some(VolumeRole::Preboot));
    assert_eq!(role("Recovery"), Some(VolumeRole::Recovery));
    let snaps: Vec<_> = all.iter().filter(|r| r.kind == RootKind::Snapshot).collect();
    assert!(!snaps.is_empty());
    for s in snaps {
        let vol = all.iter().find(|r| Some(r.root) == s.parent).unwrap();
        assert_eq!((s.name.clone(), s.role, s.default), (format!("{}@{}", vol.name, s.path), vol.role, false));
    }
    assert!(file(&ns, &p("/apfs/clone0.bin"), 0).unwrap().is_some());
    assert!(file(&ns, &p("/no such file"), 0).unwrap().is_none());
}
