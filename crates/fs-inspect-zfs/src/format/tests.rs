//! Robustness over real pools (`fixtures/zfs/linux`): read errors, truncation and hostile
//! metadata never panic and never give a different answer.

use crate::format::cksum::seal_embedded;
use crate::format::label::{LABEL_SIZE, PHYS_OFFSET, PHYS_SIZE, RING_OFFSET, RING_SIZE};
use crate::format::reader::hostile;
use fs_inspect_change::SnapshotHints;
use fs_inspect_change::testing::{self, Recorded};
use fs_inspect_core::{ByteRange, CursorIter, DriverContext, Sniff};
use fs_inspect_io::SourceError;
use fs_inspect_io::{BlockSource, DynSource, OffsetSource};
use proptest::prelude::*;
use std::collections::BTreeMap;
use std::sync::Arc;

fn fixture(name: &str) -> DynSource {
    fs_inspect_testkit::SparseSource::open(fs_inspect_testkit::fixture("zfs/linux").join(format!("{name}.fsbs")))
}

/// A source with some bytes replaced.
#[derive(Debug)]
struct Patched {
    inner: DynSource,
    bytes: BTreeMap<u64, u8>,
}

impl BlockSource for Patched {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), SourceError> {
        self.inner.read_exact_at(offset, buf)?;
        for (&at, &v) in self.bytes.range(offset..offset + buf.len() as u64) {
            buf[(at - offset) as usize] = v;
        }
        Ok(())
    }
    fn size(&self) -> u64 {
        self.inner.size()
    }
}

/// Open, map and scan (after `prev`): what a caller would do, all of it. The used ranges, and
/// the tracker's dirty ones (a first scan has none).
fn everything(src: &DynSource, prev: Option<&Recorded>) -> fs_inspect_change::Result<(Vec<ByteRange>, Vec<ByteRange>)> {
    let fs = crate::open(src.clone(), &DriverContext::default())?;
    let sc = crate::track::open(fs.clone())?;
    let out = testing::scan(sc.as_ref(), src, &fs, &SnapshotHints::default(), prev)?;
    let dirty = out.extra.dirty.iter().map(|t| ByteRange::new(t.offset, t.length)).collect();
    Ok((out.next.allocated, dirty))
}

/// What a scan of the pool on `src` leaves for the next.
fn recorded(src: &DynSource) -> Recorded {
    let fs = crate::open(src.clone(), &DriverContext::default()).unwrap();
    let sc = crate::track::open(fs.clone()).unwrap();
    testing::scan(sc.as_ref(), src, &fs, &SnapshotHints::default(), None).unwrap().next
}

/// A read error anywhere in opening or scanning fails the scan (never a different answer), and
/// a truncated image never panics.
#[test]
fn read_errors_and_truncation() {
    use fs_inspect_testkit::fault::check_read_failures;
    let prev = recorded(&fixture("pair-0"));
    let cur = fixture("pair-1");
    let reads = check_read_failures(cur.clone(), 300, |s| everything(&s, Some(&prev)));
    assert!(reads > 20, "{reads}");
    // Cut anywhere (the end labels go first, then the data).
    let len = cur.size();
    let mut ok = 0;
    for i in 0..120u64 {
        let n = len / 120 * i + (i * 4099) % 8192;
        let s: DynSource = Arc::new(OffsetSource::new(cur.clone(), 0, n.min(len)).unwrap());
        ok += usize::from(everything(&s, Some(&prev)).is_ok());
    }
    assert!(ok < 120);
}

/// Bytes to lay over `src`: label 0's name/value list (or, with `ring`, its uberblock ring)
/// with `edits`, resealed so the checksums pass, and labels 1-3 spoiled.
fn patch_label(src: &DynSource, ring: bool, edits: &[(usize, u8)]) -> BTreeMap<u64, u8> {
    let mut out = BTreeMap::new();
    let (start, size, slot) = if ring { (RING_OFFSET, RING_SIZE, 4096) } else { (PHYS_OFFSET, PHYS_SIZE, PHYS_SIZE) };
    let mut b = src.read_vec(start, size).unwrap();
    for &(at, v) in edits {
        b[at % size] = v;
    }
    for s in (0..size).step_by(slot) {
        seal_embedded(&mut b[s..s + slot], slot - 40, &[start + s as u64, 0, 0, 0]);
    }
    for (i, v) in b.iter().enumerate() {
        out.insert(start + i as u64, *v);
    }
    // Labels 1-3 hold nothing usable: only label 0 counts.
    for l in 1..4u64 {
        let at = if l < 2 { l * LABEL_SIZE } else { crate::format::label::label_offset(src.size(), l as usize) };
        out.insert(at + PHYS_OFFSET + 3, 0xa5);
        for s in (0..RING_SIZE as u64).step_by(1024) {
            out.insert(at + RING_OFFSET + s, 0);
        }
    }
    out
}

fn run_hostile(name: &str, block_edits: Vec<(u64, usize, u8)>, label: Option<(bool, Vec<(usize, u8)>)>) {
    let base = fixture(name);
    let src: DynSource = match label {
        Some((ring, edits)) => Arc::new(Patched { bytes: patch_label(&base, ring, &edits), inner: base.clone() }),
        None => base.clone(),
    };
    hostile::EDITS.with(|e| *e.borrow_mut() = block_edits);
    let head = src.read_vec(0, 1 << 17).unwrap();
    let _ = crate::probe(&Sniff { head: &head, volume_size: src.size() });
    if let Ok(fs) = crate::open(src.clone(), &DriverContext::default()) {
        if let Ok(c) = fs.clone().allocated() {
            let _ = CursorIter::new(c).take(1 << 16).count();
        }
        if let Some(m) = fs.file_map() {
            let _ = m.for_each(&mut |_| Ok(()));
        }
    }
    let _ = everything(&src, None);
    hostile::EDITS.with(|e| e.borrow_mut().clear());
}

proptest! {
    #![proptest_config(ProptestConfig { cases: fs_inspect_testkit::cases(64), ..ProptestConfig::default() })]

    /// Random bytes in decoded metadata blocks (past their checksums) never panic.
    #[test]
    fn mutated_images_never_panic(
        fixture in prop::sample::select(vec!["basic", "variety", "logsm", "pair-1", "zil"]),
        edits in prop::collection::vec((any::<u64>(), any::<usize>(), any::<u8>()), 1..6),
    ) {
        run_hostile(fixture, edits, None);
    }

    /// Random bytes in the label's name/value list or uberblocks, resealed, never panic.
    #[test]
    fn mutated_labels_never_panic(
        ring in any::<bool>(),
        edits in prop::collection::vec((any::<usize>(), any::<u8>()), 1..12),
    ) {
        run_hostile("basic", Vec::new(), Some((ring, edits)));
    }

    #[test]
    fn random_structures_never_panic(data in prop::collection::vec(any::<u8>(), 0..3000), at in 0usize..600) {
        use crate::format::{blkptr::BlkPtr, dnode::Dnode, dsl::Dataset, nvlist, objset::Objset, zpl};
        let _ = nvlist::decode(&data);
        let _ = BlkPtr::parse(&data, at);
        let _ = Dnode::parse(&data, at);
        let _ = Objset::parse(&data);
        let _ = Dataset::parse(0, &data);
        let _ = crate::format::label::parse_uberblock(&data, 0);
        let _ = zpl::znode_phys(&data);
        for c in [0u8, 1, 2, 3, 4, 10, 15, 16] {
            let _ = crate::format::codec::decompress(c, &data, at * 8);
        }
    }
}

/// The block a log chain ends at (allocated for the next log write, never verified) counts as
/// allocated, and as new after any txg before its birth, although no tree pointer reaches it.
#[test]
fn intent_log_includes_the_pending_block() {
    use crate::format::{dsl, objset::Objset, zil};
    let fs = Arc::new(crate::format::ZfsFs::open(fixture("zil"), &DriverContext::default()).unwrap());
    let mut budget = fs.limits().max_tree_nodes;
    let mut pending = Vec::new();
    for ds in dsl::all_datasets(fs.reader(), fs.mos(), &mut budget).unwrap() {
        if ds.is_snapshot() || ds.bp.is_hole() {
            continue;
        }
        let os = Objset::read(fs.reader(), &ds.bp).unwrap();
        let log = zil::read(fs.reader(), &os.zil, u64::MAX, false).unwrap();
        if let Some(bp) = log.pending {
            assert!(!log.blocks.contains(&bp));
            fs.bp_ranges(&bp, &mut pending);
        }
    }
    assert!(!pending.is_empty(), "no log ends at an allocated block");
    pending.sort();
    assert_eq!(fs.pending_log_ranges(0), pending);
    let used: Vec<ByteRange> = CursorIter::new(fs_inspect_core::Filesystem::allocated(fs.clone()).unwrap())
        .collect::<fs_inspect_core::Result<_>>()
        .unwrap();
    assert!(fs_inspect_core::range::list::subtract(&pending, &used).is_empty(), "pending blocks not allocated");
}

/// A log block's pointer, its copies on the device, its bytes and where its records are.
type LogCopy = (crate::format::blkptr::BlkPtr, Vec<ByteRange>, Vec<u8>, std::ops::Range<usize>);

/// The verified log blocks of the crash-consistent pool (`fixtures/zfs/replay`): each one's
/// pointer, its copies on the device, its bytes and where its records are (those with any).
fn replay_log_blocks(src: &DynSource) -> Vec<LogCopy> {
    use crate::format::{dsl, objset::Objset, zil};
    let fs = crate::format::ZfsFs::open(src.clone(), &DriverContext::default()).unwrap();
    let mut budget = fs.limits().max_tree_nodes;
    let mut out = Vec::new();
    for ds in dsl::all_datasets(fs.reader(), fs.mos(), &mut budget).unwrap() {
        if ds.is_snapshot() || ds.bp.is_hole() {
            continue;
        }
        let os = Objset::read(fs.reader(), &ds.bp).unwrap();
        for bp in zil::read(fs.reader(), &os.zil, u64::MAX, false).unwrap().blocks {
            assert_eq!(bp.cksum_alg, crate::format::cksum::alg::ZILOG2);
            let zil::LogBlock { bytes: b, records, .. } = zil::read_block(fs.reader(), &bp).unwrap().unwrap();
            let mut copies = Vec::new();
            fs.bp_ranges(&bp, &mut copies);
            if !records.is_empty() {
                out.push((bp, copies, b, records));
            }
        }
    }
    assert!(out.len() > 1, "{} log blocks", out.len());
    out
}

proptest! {
    #![proptest_config(ProptestConfig { cases: fs_inspect_testkit::cases(64), ..ProptestConfig::default() })]

    /// Random bytes in the intent log's records, their blocks sealed again (the records reach
    /// the parser and the replay) or not (the chain ends there): the replay fails or reads
    /// something, and browsing over it never panics.
    #[test]
    fn a_damaged_intent_log_never_panics(
        edits in prop::collection::vec((any::<usize>(), any::<usize>(), any::<u8>()), 1..24),
        reseal in any::<bool>(),
    ) {
        use crate::format::cksum::{ECK_SIZE, alg, seal_embedded_with};
        use crate::format::zil::CHAIN;
        let src: DynSource = fs_inspect_testkit::SparseSource::open(
            fs_inspect_testkit::fixture("zfs/replay").join("zfs-replay.fsbs"),
        );
        let mut blocks = replay_log_blocks(&src);
        let n = blocks.len();
        let mut touched = std::collections::BTreeSet::new();
        for (i, at, v) in edits {
            let (_, _, b, records) = &mut blocks[i % n];
            b[records.start + at % records.len()] = v;
            touched.insert(i % n);
        }
        let mut bytes = Vec::new();
        for i in touched {
            let (bp, copies, b, records) = &mut blocks[i];
            if reseal {
                let sealed = records.end.next_multiple_of(4096).min(b.len());
                seal_embedded_with(alg::ZILOG2, &mut b[..sealed], CHAIN - ECK_SIZE, &bp.cksum);
            }
            for c in copies.iter() {
                bytes.extend(b.iter().take(c.length as usize).enumerate().map(|(k, &v)| (c.offset + k as u64, v)));
            }
        }
        let damaged = fs_inspect_testkit::crash::with_bytes(src, &bytes);
        let _ = fs_inspect_testkit::crash::exercise_replay(crate::DRIVER.open, damaged, &DriverContext::default());
    }
}

/// Sealed again unchanged, the log replays as before (the test above reaches the records).
#[test]
fn a_resealed_intent_log_replays() {
    use crate::format::cksum::{ECK_SIZE, alg, seal_embedded_with};
    use crate::format::zil::CHAIN;
    let src: DynSource =
        fs_inspect_testkit::SparseSource::open(fs_inspect_testkit::fixture("zfs/replay").join("zfs-replay.fsbs"));
    let mut bytes = Vec::new();
    for (bp, copies, mut b, records) in replay_log_blocks(&src) {
        let sealed = records.end.next_multiple_of(4096).min(b.len());
        seal_embedded_with(alg::ZILOG2, &mut b[..sealed], CHAIN - ECK_SIZE, &bp.cksum);
        for c in copies {
            bytes.extend(b.iter().take(c.length as usize).enumerate().map(|(k, &v)| (c.offset + k as u64, v)));
        }
    }
    let open = crate::DRIVER.open;
    let ctx = DriverContext::default();
    let want = fs_inspect_testkit::crash::exercise_replay(open, src.clone(), &ctx).unwrap().unwrap();
    let got =
        fs_inspect_testkit::crash::exercise_replay(open, fs_inspect_testkit::crash::with_bytes(src, &bytes), &ctx);
    assert_eq!(got.unwrap().unwrap(), want);
    assert!(want.entries.is_ok(), "{:?}", want.entries);
}

/// The golden line of a file system's [`Consistency`](fs_inspect_core::Consistency).
fn consistency_line(fs: &dyn fs_inspect_core::Filesystem) -> String {
    match fs.consistency() {
        fs_inspect_core::Consistency::Clean => "  consistency: clean\n".into(),
        fs_inspect_core::Consistency::Inconsistent { why, .. } => format!("  consistency: inconsistent: {why}\n"),
        fs_inspect_core::Consistency::Unknown(why) => format!("  consistency: unknown: {why}\n"),
        other => format!("  consistency: {other:?}\n"),
    }
}

/// What the driver reports of single-device pools (`fs_inspect_testkit::golden::fs_report`) and
/// how much it reads opening and mapping them: pools of each ashift, log space maps left
/// unflushed, an encrypted dataset, an intent log, snapshots and clones, swap zvols; one leg of
/// a mirror alone; and `basic` with labels 1-3 spoiled, read from label 0 alone.
#[test]
fn golden_maps() {
    use fs_inspect_testkit::golden::{CountingSource, check, fs_report};
    let mut cases: Vec<(&str, DynSource, &[&str])> =
        ["logsm", "crypt", "zil", "snaps", "swap", "mirror-a"].into_iter().map(|n| (n, fixture(n), &[][..])).collect();
    cases.insert(0, ("basic", fixture("basic"), &["/dir0/noise.bin", "/sparse.bin", "/hardlink.txt"][..]));
    let base = fixture("basic");
    let label0: DynSource = Arc::new(Patched { bytes: patch_label(&base, false, &[]), inner: base });
    cases.push(("basic-label-0-only", label0, &["/dir0/noise.bin"][..]));
    let mut out = String::new();
    let mut reads = String::new();
    for (name, src, lookups) in cases {
        let counting = CountingSource::new(src);
        let ctx = DriverContext::default();
        out.push_str(&format!("== {name}\n"));
        match crate::open(counting.clone(), &ctx) {
            Ok(fs) => {
                out.push_str(&fs_report(fs.clone(), &ctx.diagnostics, lookups));
                out.push_str(&consistency_line(&*fs));
            }
            Err(e) => out.push_str(&format!("open error {:?}: {e}\n", e.kind())),
        }
        reads.push_str(&format!("{name}: {}\n", counting.summary()));
    }
    check(env!("CARGO_MANIFEST_DIR"), "zfs", &out);
    check(env!("CARGO_MANIFEST_DIR"), "zfs-reads", &reads);
}
