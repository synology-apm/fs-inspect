//! The crash-consistency suite every file system that replays its log runs over its
//! crash-consistent fixtures (`fixtures/<fs>/replay*`: a volume copied while mounted, its
//! `manifest.txt` the files once the log is replayed).
//!
//! [`crash_suite!`](crate::crash_suite) makes one test per fixture: the volume opens as
//! inconsistent, its driver replays its log ([`Filesystem::replay`]), and the instance opened
//! over the replay ([`open_recovered`](fs_inspect_core::fs::open_recovered)) is consistent, its
//! namespace the manifest, whether the replay is kept in a scratch file or in memory (no
//! scratch file could be made), with its pages cached or not: the same patches every way.
//!
//! [`exercise_replay`] and [`with_bytes`] are for the robustness tests of a replay: a log
//! damaged, cut or failing to read must fail it (the volume then read as on disk), never panic
//! nor give another answer.

use crate::SparseSource;
use fs_inspect_core::patch::PatchSource;
use fs_inspect_core::store::{DEFAULT_MAX_MEMORY, Scratch, StoreKind};
use fs_inspect_core::{ByteRange, DriverContext, Filesystem, Result};
use fs_inspect_io::BlockSource;
use fs_inspect_io::DynSource;
use std::sync::Arc;

/// A driver's `open`, as [`Driver::open`](fs_inspect_core::Driver).
pub type Open = fn(DynSource, &DriverContext) -> Result<Arc<dyn Filesystem>>;

/// The ways a replay can keep what it holds, each a context to open with: a scratch file or
/// memory, its pages cached or not. The scratch directory (`None`: none) lives as long as the
/// context's use.
fn contexts() -> Vec<(&'static str, DriverContext, Option<tempfile::TempDir>)> {
    let missing = tempfile::tempdir().expect("a scratch directory");
    let in_memory = Scratch::new(Some(missing.path().join("missing")), DEFAULT_MAX_MEMORY);
    vec![
        ("a scratch file", DriverContext::default(), None),
        ("a scratch file, nothing cached", DriverContext { max_cache_bytes: 0, ..Default::default() }, None),
        ("memory", DriverContext { scratch: in_memory.clone(), ..Default::default() }, Some(missing)),
        (
            "memory, nothing cached",
            DriverContext { scratch: in_memory, max_cache_bytes: 0, ..Default::default() },
            None,
        ),
    ]
}

/// Fixture `dir` (`image` in it) opened with `open`: it needs recovery, its log replays, and
/// the namespace over the replay is its manifest, however the replay is kept. `fs` names the
/// file system in messages.
pub fn check_fixture(open: Open, fs: &str, dir: &str, image: &str) {
    let mut first: Option<(&str, Vec<(ByteRange, Vec<u8>)>)> = None;
    for (how, ctx, _dir) in contexts() {
        let src: DynSource = Arc::new(SparseSource::open(crate::fixture(dir).join(image)));
        let on_disk = open(src.clone(), &ctx).unwrap_or_else(|e| panic!("{dir}, kept in {how}: {e}"));
        assert!(!on_disk.consistency().is_clean(), "{dir}: a crash-consistent fixture reads as clean");
        let replayed = on_disk
            .replay()
            .unwrap_or_else(|| panic!("{dir}: {fs} does not replay"))
            .unwrap_or_else(|e| panic!("{dir}, kept in {how}: the replay failed: {e}"));
        let summary = replayed.summary();
        assert!(summary.records > 0, "{dir}: {summary:?}");
        let memory = how.starts_with("memory");
        assert_eq!(summary.store, if memory { StoreKind::Memory } else { StoreKind::File }, "{dir}: {how}");
        let targets = replayed.targets().unwrap();
        assert!(targets.windows(2).all(|w| w[0].end() < w[1].offset), "{dir}: targets not sorted and coalesced");
        for p in replayed.patches().ranges().unwrap() {
            assert!(
                targets.iter().any(|t| t.offset <= p.offset && p.end() <= t.end()),
                "{dir}: patched {p:?} is not a target"
            );
        }
        let patched = PatchSource::new(src.clone(), replayed.patches().clone()).unwrap();
        let bytes: Vec<(ByteRange, Vec<u8>)> = replayed
            .patches()
            .ranges()
            .unwrap()
            .into_iter()
            .map(|r| (r, patched.read_vec(r.offset, r.length as usize).unwrap()))
            .collect();
        match &first {
            None => first = Some((how, bytes)),
            Some((then, want)) => assert!(bytes == *want, "{dir}: the replay kept in {how} differs from in {then}"),
        }
        let recovered = fs_inspect_core::fs::open_recovered(open, src, &ctx, replayed)
            .unwrap_or_else(|e| panic!("{dir}, kept in {how}: opened over the replay: {e}"));
        assert!(recovered.consistency().is_clean(), "{dir}: inconsistent over its replay");
        let ns = recovered.namespace().unwrap_or_else(|| panic!("{dir}: no namespace"));
        crate::browse::check_fixture(&ns, &format!("{fs} ({how})"), dir);
    }
    check_faults(open, dir, image);
}

/// Fixture `dir` replayed with its reads failing from some point on (an I/O error, or the
/// same answer: never another), and cut short at points spread over it (no panic).
fn check_faults(open: Open, dir: &str, image: &str) {
    let src: DynSource = Arc::new(SparseSource::open(crate::fixture(dir).join(image)));
    let ctx = DriverContext::default();
    let go = |s: DynSource| exercise_replay(open, s, &ctx);
    let reads = crate::fault::check_read_failures(src.clone(), crate::cases(64) as u64, go);
    assert!(reads > 0, "{dir}");
    let len = src.size();
    let points = crate::cases(32) as u64;
    for k in 1..points {
        let cut: DynSource = Arc::new(fs_inspect_io::OffsetSource::new(src.clone(), 0, len / points * k).unwrap());
        let _ = go(cut);
    }
}

/// One test per crash-consistent fixture of a file system (see the [module](self)), its
/// faults included (reads failing, the image cut short):
///
/// ```ignore
/// fs_inspect_testkit::crash_suite!(fs_inspect_xfs::DRIVER.open, "xfs", {
///     replay => "xfs/replay", "xfs-replay.fsbs";
/// });
/// ```
#[macro_export]
macro_rules! crash_suite {
    ($open:expr, $fs:literal, { $($name:ident => $dir:literal, $image:literal;)+ }) => {
        mod crash_suite {
            $(
                #[test]
                fn $name() {
                    $crate::crash::check_fixture($open, $fs, $dir, $image);
                }
            )+
        }
    };
}

/// What a replay and the instance over it read, as a value two runs compare.
#[derive(Debug, PartialEq, Eq)]
pub struct ReplayDigest {
    /// Each patched range and a hash of its bytes.
    pub patches: Vec<(ByteRange, u64)>,
    /// The recovered instance's allocated ranges (coalesced) and zero ranges.
    pub allocated: Vec<ByteRange>,
    pub zero: Vec<ByteRange>,
    /// A hash of the tree read from the roots (at most 4 roots, 2048 nodes; each file's first
    /// 64 KiB), or the kind of error browsing ends with (a volume without a namespace, a damaged
    /// directory or file).
    pub entries: std::result::Result<u64, fs_inspect_core::ErrorKind>,
}

/// Open `src` with `open` and `ctx`, replay its log and read the instance over the replay:
/// its allocated and zero ranges, the tree from its roots. `Ok(None)`: the volume has nothing to
/// replay (or its driver does not replay). Every error is returned but those browsing ends
/// with that are not a failed read or a cancel (kept in [`ReplayDigest::entries`]).
pub fn exercise_replay(open: Open, src: DynSource, ctx: &DriverContext) -> Result<Option<ReplayDigest>> {
    use std::hash::{Hash, Hasher};
    let on_disk = open(src.clone(), ctx)?;
    let Some(replayed) = on_disk.replay() else { return Ok(None) };
    let replayed = replayed?;
    let _ = replayed.summary();
    let targets = replayed.targets()?;
    let ranges = replayed.patches().ranges()?;
    let patched = PatchSource::new(src.clone(), replayed.patches().clone())?;
    let mut patches = Vec::with_capacity(ranges.len());
    for r in ranges {
        assert!(targets.iter().any(|t| t.offset <= r.offset && r.end() <= t.end()), "patched {r:?} is not a target");
        let mut h = std::collections::hash_map::DefaultHasher::new();
        patched.read_vec(r.offset, r.length as usize)?.hash(&mut h);
        patches.push((r, h.finish()));
    }
    let recovered = fs_inspect_core::fs::open_recovered(open, src, ctx, replayed)?;
    let allocated =
        fs_inspect_core::CursorIter::new(recovered.clone().allocated()?).take(1 << 20).collect::<Result<Vec<_>>>()?;
    let allocated = fs_inspect_core::range::coalesce(allocated).collect();
    let zero = recovered.zero_ranges()?;
    let browse = || -> Result<u64> {
        use fs_inspect_core::{NodeKind, StreamId};
        let Some(ns) = recovered.namespace() else { return Err(fs_inspect_core::Error::unsupported("no namespace")) };
        let mut h = std::collections::hash_map::DefaultHasher::new();
        let mut todo: std::collections::VecDeque<_> = ns.roots()?.iter().take(4).map(|r| r.node).collect();
        let mut budget = 2048usize;
        while let Some(dir) = todo.pop_front() {
            let mut found = Vec::new();
            ns.read_dir(dir, &mut |e| {
                found.push(e);
                if found.len() < budget {
                    std::ops::ControlFlow::Continue(())
                } else {
                    std::ops::ControlFlow::Break(())
                }
            })?;
            budget = budget.saturating_sub(found.len());
            for e in found {
                e.name.as_bytes().hash(&mut h);
                let kind = match e.kind {
                    Some(k) => k,
                    None => fs_inspect_core::ns::stat(&*ns, e.node)?.kind,
                };
                match kind {
                    NodeKind::Dir if budget > 0 => todo.push_back(e.node),
                    NodeKind::File => {
                        let r = ns.clone().open(e.node, StreamId::MAIN)?;
                        let mut b = vec![0u8; r.len().min(64 << 10) as usize];
                        r.read_exact_at(0, &mut b)?;
                        b.hash(&mut h);
                    }
                    _ => {}
                }
            }
        }
        Ok(h.finish())
    };
    let entries = match browse() {
        Ok(n) => Ok(n),
        Err(e) if matches!(e.kind(), fs_inspect_core::ErrorKind::Io | fs_inspect_core::ErrorKind::Cancelled) => {
            return Err(e);
        }
        Err(e) => Err(e.kind()),
    };
    Ok(Some(ReplayDigest { patches, allocated, zero, entries }))
}

/// `src` with the bytes of `edits` (offset, value; the last edit of an offset wins) in place
/// of its own, read through patches kept in memory (a large image is not copied).
pub fn with_bytes(src: DynSource, edits: &[(u64, u8)]) -> DynSource {
    let edits: std::collections::BTreeMap<u64, u8> = edits.iter().copied().filter(|&(o, _)| o < src.size()).collect();
    let mut b = fs_inspect_core::patch::PatchBuilder::new(Scratch::memory(64 << 20).arena(), 1 << 16);
    for (o, v) in edits {
        b.bytes(o, &[v]).expect("a patch in memory");
    }
    let table = b.finish(src.size()).expect("patches within the source");
    Arc::new(PatchSource::new(src, Arc::new(table)).expect("a patched source"))
}
