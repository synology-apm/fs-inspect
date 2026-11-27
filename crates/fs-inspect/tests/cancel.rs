//! The cancel rule (docs/design/overview.md, "Cancelling") on a synthetic NTFS volume: each
//! call that reads stops at its own token; a handle's token covers every later read of it;
//! the two compose, so either one stops a read.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use fs_inspect::fs::{BrowseOptions, DirOptions, FsHandle, NodeId, ReadAheadOptions, StreamId, WalkOptions, Want};
use fs_inspect::{
    CancelToken, DeviceMapOptions, DeviceRef, DiskIndex, DiskSet, DiskSpec, ErrorKind, OpenOptions, Result, Volume,
    VolumeIndex, VolumeMapOptions,
};
use fs_inspect_testkit::{Placement, ROOT, SyntheticVolume, VolumeSpec};
use std::io::Read;
use std::sync::Arc;

fn volume() -> SyntheticVolume {
    let mut v = SyntheticVolume::format(VolumeSpec { clusters: 4096, ..Default::default() });
    let d = v.create_dir(ROOT, "dir");
    v.create_file(d, "a.bin", 100_000, 1, Placement::FirstFit);
    v.create_file(ROOT, "frag.bin", 300_000, 3, Placement::MaxRun(2));
    v.create_file(ROOT, "small.txt", 10, 6, Placement::FirstFit);
    v
}

/// The set of `v`, its caches keeping nothing across calls: every call reads.
fn set(v: &SyntheticVolume, cancel: Option<&CancelToken>) -> DiskSet {
    let opts = OpenOptions::default().with_max_cache_bytes(0);
    DiskSet::open(&[DiskSpec::source(Arc::new(v.source()))], &opts, cancel).unwrap()
}

fn cancelled() -> CancelToken {
    let t = CancelToken::new();
    t.cancel();
    t
}

fn is_cancelled<T: std::fmt::Debug>(what: &str, r: Result<T>) {
    match r {
        Err(e) => assert_eq!(e.kind(), ErrorKind::Cancelled, "{what}: {e}"),
        Ok(v) => panic!("{what}: not cancelled: {v:?}"),
    }
}

/// A file system just opened: the next call reads.
fn fresh(v: &SyntheticVolume, handle: Option<&CancelToken>) -> (Volume, FsHandle) {
    let vol = set(v, None).open_volume(VolumeIndex(0), None).unwrap();
    let fs = vol.browse(&BrowseOptions::default(), handle).unwrap();
    (vol, fs)
}

/// A call on a file system, its result dropped.
type Call<'a> = dyn Fn(&FsHandle) -> Result<()> + 'a;

fn node(fs: &FsHandle, path: &str) -> NodeId {
    fs.resolve(fs.roots(None).unwrap()[0].root, path, None).unwrap().node
}

#[test]
fn each_set_call_stops_at_its_own_token() {
    let v = volume();
    let t = cancelled();
    let c = Some(&t);
    let disk = DeviceRef::Disk(DiskIndex(0));
    is_cancelled("volumes", set(&v, None).volumes(c));
    is_cancelled("partitions", set(&v, None).partitions(disk, c));
    is_cancelled("containers", set(&v, None).containers(c));
    is_cancelled("open_volume", set(&v, None).open_volume(VolumeIndex(0), c));
    is_cancelled("only_volume", set(&v, None).only_volume(c));
    is_cancelled("layout", set(&v, None).layout(disk, c));
    is_cancelled("map", set(&v, None).map(disk, &DeviceMapOptions::default(), c));
    is_cancelled("catalog", set(&v, None).catalog(c));
    is_cancelled("guest", set(&v, None).guest(c));
    let s = set(&v, None);
    is_cancelled(
        "verify",
        s.verify(&Default::default(), c).map(|r| r.stopped.map(|s| s.error)).and_then(|s| match s {
            Some(e) => Err(e),
            None => Ok(()),
        }),
    );
}

#[test]
fn each_volume_call_stops_at_its_own_token() {
    let v = volume();
    let t = cancelled();
    let c = Some(&t);
    let vol = || set(&v, None).open_volume(VolumeIndex(0), None).unwrap();
    is_cancelled("map", vol().map(&VolumeMapOptions::default(), c));
    is_cancelled("file_ranges", vol().file_ranges(&"/frag.bin".parse().unwrap(), c));
    is_cancelled("browse", vol().browse(&BrowseOptions::default(), c));
}

#[test]
fn each_browsing_call_stops_at_its_own_token() {
    let v = volume();
    let t = cancelled();
    let c = Some(&t);
    let (_vol, fs) = fresh(&v, None);
    let dir = node(&fs, "/dir");
    let file = node(&fs, "/frag.bin");
    let root = fs.roots(None).unwrap()[0].root;
    let calls: Vec<(&str, Box<Call<'_>>)> = vec![
        ("stat", Box::new(|fs| fs.stat(file, c).map(drop))),
        ("info", Box::new(|fs| fs.info(file, Want::ALL, c).map(drop))),
        ("lookup", Box::new(|fs| fs.lookup(dir, &"a.bin".into(), c).map(drop))),
        ("resolve", Box::new(|fs| fs.resolve(root, "/dir/a.bin", c).map(drop))),
        ("open", Box::new(|fs| fs.open(file, StreamId::MAIN, c).map(drop))),
        ("info names", Box::new(|fs| fs.info(file, Want::NAMES, c).map(drop))),
        ("info link", Box::new(|fs| fs.info(file, Want::LINK, c).map(drop))),
        (
            "walker",
            Box::new(|fs| fs.walker(dir, &WalkOptions::default(), c)?.next_batch(&mut Vec::new(), None).map(drop)),
        ),
        ("dir", Box::new(|fs| fs.dir(dir, &DirOptions::default(), c).read(10, None).map(drop))),
    ];
    for (what, call) in &calls {
        let (_vol, fs) = fresh(&v, None);
        is_cancelled(what, call(&fs));
    }
    // Reading a file and a cursor, each call with its own token.
    let f = fs.open(file, StreamId::MAIN, None).unwrap();
    is_cancelled("read_at", f.read_at(0, &mut [0; 4096], c));
    let mut cursor = fs.dir(dir, &DirOptions::default(), None);
    is_cancelled("DirCursor::read", cursor.read(10, c));
}

#[test]
fn a_handle_token_covers_its_later_reads() {
    let v = volume();
    let t = CancelToken::new();
    let (_vol, fs) = fresh(&v, Some(&t));
    let file = node(&fs, "/frag.bin");
    let dir = node(&fs, "/dir");
    let f = fs.open(file, StreamId::MAIN, None).unwrap();
    let mut cursor = fs.dir(dir, &DirOptions::default(), None);
    t.cancel();
    is_cancelled("stat on a cancelled handle", fs.stat(file, None));
    is_cancelled("read_at on a cancelled handle", f.read_at(0, &mut [0; 4096], None));
    is_cancelled("a cursor of a cancelled handle", cursor.read(10, None));

    // A handle's own token: the file's, the cursor's, the walker's.
    let (_vol, fs) = fresh(&v, None);
    let file = node(&fs, "/frag.bin");
    let dir = node(&fs, "/dir");
    let ft = CancelToken::new();
    let mut f = fs.open(file, StreamId::MAIN, Some(&ft)).unwrap();
    let ct = CancelToken::new();
    let mut cursor = fs.dir(dir, &DirOptions::default(), Some(&ct));
    let wt = CancelToken::new();
    let walker = fs.walker(dir, &WalkOptions::default(), Some(&wt)).unwrap();
    for t in [&ft, &ct, &wt] {
        t.cancel();
    }
    is_cancelled("File::read_at", f.read_at(0, &mut [0; 4096], None));
    let e = f.read(&mut [0; 4096]).unwrap_err();
    let inner = e.get_ref().and_then(|x| x.downcast_ref::<fs_inspect::Error>()).map(fs_inspect::Error::kind);
    assert_eq!(inner, Some(ErrorKind::Cancelled), "io::Read: {e}");
    is_cancelled("DirCursor::read", cursor.read(10, None));
    is_cancelled("Walker::next_batch", walker.next_batch(&mut Vec::new(), None));
    // The handle and the others it made go on.
    fs.stat(file, None).unwrap();
}

#[test]
fn a_handle_token_and_a_call_token_compose() {
    let v = volume();
    let (_vol, fs) = fresh(&v, Some(&CancelToken::new()));
    let file = node(&fs, "/frag.bin");
    let ht = CancelToken::new();
    let f = fs.open(file, StreamId::MAIN, Some(&ht)).unwrap();
    let mut buf = [0; 4096];
    f.read_at(0, &mut buf, Some(&CancelToken::new())).unwrap();
    is_cancelled("the call's cancelled", f.read_at(0, &mut buf, Some(&cancelled())));
    f.read_at(0, &mut buf, None).unwrap();
    ht.cancel();
    is_cancelled("the handle's cancelled", f.read_at(0, &mut buf, Some(&CancelToken::new())));
}

#[test]
fn a_set_token_covers_everything_of_the_set() {
    let v = volume();
    let t = CancelToken::new();
    let s = set(&v, Some(&t));
    let vol = s.open_volume(VolumeIndex(0), None).unwrap();
    let fs = vol.browse(&BrowseOptions::default(), None).unwrap();
    let file = node(&fs, "/frag.bin");
    t.cancel();
    assert!(s.cancel_token().is_cancelled());
    is_cancelled("stat under a cancelled set", fs.stat(file, None));
    is_cancelled("a map under a cancelled set", vol.map(&VolumeMapOptions::default(), None));
}

/// A read-ahead's batch stops at the read-ahead's token or the call's, with
/// [`ErrorKind::Cancelled`](fs_inspect::ErrorKind): nothing is read ahead, and the next batch
/// starts where the cancelled one did.
#[test]
fn a_read_ahead_stops_at_its_token_or_the_call_s() {
    let v = volume();
    let (_vol, fs) = fresh(&v, None);
    let opts = DirOptions::default().with_want(Want::STAT);
    let listing = fs.dir(fs.roots(None).unwrap()[0].node, &opts, None).collect(None).unwrap();
    let find = |s: &str| listing.find(&s.parse().unwrap()).unwrap();
    let (first, small) = (find("frag.bin"), find("small.txt"));
    // Reading the folder's second file reads a batch: here one that reads it.
    let read = |handle: Option<&CancelToken>, call: Option<&CancelToken>| {
        let ahead = fs.read_ahead(&ReadAheadOptions::default(), handle);
        assert!(ahead.read(&listing, first, None).unwrap().is_none(), "the first opening reads alone");
        let got = ahead.read(&listing, small, call);
        (got, ahead)
    };
    let (got, ahead) = read(Some(&CancelToken::new()), Some(&CancelToken::new()));
    assert_eq!(got.unwrap().map(|d| d.len()), Some(10));
    assert!(ahead.stats().files_read > 0, "with the folder's other small files");
    let (got, ahead) = read(None, Some(&cancelled()));
    is_cancelled("the call's token", got);
    assert_eq!(ahead.stats().files_read, 0);
    // Not cancelled again, the same opening reads the batch the cancelled one did not.
    assert_eq!(ahead.read(&listing, small, None).unwrap().map(|d| d.len()), Some(10));
    let (got, ahead) = read(Some(&cancelled()), None);
    is_cancelled("the read-ahead's token", got);
    assert_eq!(ahead.stats().files_read, 0);
}
