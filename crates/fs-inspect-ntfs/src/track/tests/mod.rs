//! Tracker tests on synthetic NTFS volumes: what the tracker reports of each file and of the
//! space, scanned as a comparer runs it (`fs_inspect_change::testing`).

mod harness;
mod index_pairs;

use crate::track::usn::reason;
use fs_inspect_change::testing::{self, Recorded};
use fs_inspect_change::{Evidence, Reason};
use fs_inspect_core::ByteRange;
use fs_inspect_core::range::list;
use harness::*;

const K: u64 = 1024;

fn ranges_of(v: &[fs_inspect_change::TaggedRange]) -> Vec<ByteRange> {
    let mut r: Vec<ByteRange> = v.iter().map(|t| t.range()).collect();
    list::normalize(&mut r);
    r
}

/// Whether the state `rec` left keeps a rewound journal position.
fn rewound_in(rec: &Recorded) -> bool {
    let v: serde_json::Value = serde_json::from_slice(&rec.state).expect("JSON");
    !v["state"]["journal"]["snapshot_next_usn"].is_null()
}

fn evidence_of(w: &World, prev: &Recorded, key: u64) -> Evidence {
    w.scan(Some(prev)).file(key).evidence.clone()
}

/// The file under `key` changed in its `meta` or `aux` (the same generation), and nothing
/// narrows the change: a comparer copies it whole ([`Reason::MetaChanged`]).
fn meta_whole(d: &Diff, key: u64) -> bool {
    let (f, p) = (d.file(key), d.before(key).expect("recorded before"));
    let narrowed = match &f.evidence {
        Evidence::None => false,
        Evidence::MetadataOnly => true,
        _ => !f.no_narrow,
    };
    p.generation == f.generation && (p.meta != f.meta || p.aux != f.aux) && !narrowed
}

/// The file under `key` is copied whole: another file than before, the tracker asks for all
/// of it, or [`meta_whole`].
fn whole(d: &Diff, key: u64) -> bool {
    d.created(key) || d.file(key).evidence == Evidence::WholeFile || meta_whole(d, key)
}

/// What reads as zeros inside `ranges`.
fn zero_in(d: &Diff, ranges: &[ByteRange]) -> Vec<ByteRange> {
    list::intersect(&d.zero(), &norm(ranges))
}

/// Bytes covered.
fn bytes(v: &[ByteRange]) -> u64 {
    list::total(v)
}

#[test]
fn unchanged_volume_is_clean() {
    let mut w = World::new(true, Some((16 * K, 64 * K)));
    let a = w.create("a.bin", 300 * K);
    w.create("b.bin", 100);
    w.write(a, 0, 4 * K);
    let sig = w.base();
    let d = w.scan(Some(&sig));
    assert_eq!(w.changed(&d), vec![]);
    let x = &d.scan.extra;
    assert!(x.dirty.iter().all(|t| t.reason == Reason::Unclaimed), "{:?}", x.dirty);
    assert!(x.degraded.is_empty(), "{:?}", x.degraded);
    assert!(x.known_misses.is_empty(), "{:?}", x.known_misses);
    assert!(x.warnings.is_empty(), "{:?}", x.warnings);
    assert_eq!(d.scan.files.len(), 1, "only the non-resident stream is reported");
}

#[test]
fn data_write_marks_whole_file() {
    let mut w = World::new(true, None);
    let a = w.create("a.bin", 200 * K);
    let b = w.create("b.bin", 200 * K);
    let sig = w.base();
    w.write(a, 8 * K, 4 * K);
    let d = w.scan(Some(&sig));
    assert!(meta_whole(&d, a), "{:?}", d.file(a));
    assert!(d.unchanged(b));
    assert!(d.degraded().is_empty());
}

#[test]
fn restored_mtime_is_caught_by_si_usn() {
    let mut w = World::new(true, None);
    let a = w.create("a.bin", 200 * K);
    let sig = w.base();
    let mtime = w.v.files[&a].si.modified;
    w.write(a, 0, 4 * K);
    w.set_si(a, |si| si.modified = mtime);
    assert!(meta_whole(&w.scan(Some(&sig)), a));
}

#[test]
fn v4_ranges_narrow_to_written_chunks() {
    let mut w = World::new(true, Some((16 * K, 64 * K)));
    let a = w.create("a.bin", 512 * K);
    let sig = w.base();
    w.write(a, 100 * K, 4 * K);
    let d = w.scan(Some(&sig));
    let f = d.file(a);
    assert_eq!(f.evidence, Evidence::Logical(vec![ByteRange::new(96 * K, 16 * K)]));
    assert!(!f.no_narrow);
    assert!(d.degraded().is_empty());
}

#[test]
fn v4_ranges_with_a_later_write_time_are_whole_file() {
    let mut w = World::new(true, Some((16 * K, 64 * K)));
    let a = w.create("a.bin", 512 * K);
    let sig = w.base();
    w.write(a, 100 * K, 4 * K);
    // A later write (e.g. mapped pages written back) moved LastWriteTime past the journal.
    w.set_si(a, |si| si.modified += 1);
    assert!(meta_whole(&w.scan(Some(&sig)), a));
}

#[test]
fn encrypted_file_is_not_narrowed() {
    let mut w = World::new(true, Some((16 * K, 64 * K)));
    let a = w.create("a.bin", 512 * K);
    w.set_si(a, |si| si.attributes |= 0x4000);
    let sig = w.base();
    w.write(a, 100 * K, 4 * K);
    assert!(meta_whole(&w.scan(Some(&sig)), a));
}

/// A compressed stream: its clusters do not map one to one to file bytes, so a change marks the
/// whole stream (not the written range, though the journal records one), it has no zero
/// ranges past the valid data length, and compressing a file marks it whole.
#[test]
fn compressed_file_is_not_narrowed() {
    let compress = |w: &mut World, r: u64| {
        w.v.files.get_mut(&r).unwrap().data_mut().unwrap().flags |= crate::attr_flags::COMPRESSED;
        w.sync();
    };
    let mut w = World::new(true, Some((16 * K, 64 * K)));
    let a = w.create("a.bin", 512 * K);
    let b = w.create("b.bin", 256 * K);
    compress(&mut w, a);
    // Valid data ends in the middle: an uncompressed stream would have zero clusters after it.
    w.v.files.get_mut(&a).unwrap().data_mut().unwrap().data = match w.v.files[&a].data().unwrap().data.clone() {
        crate::synth::StreamData::NonResident { runs, size, .. } => {
            crate::synth::StreamData::NonResident { runs, size, initialized: 200 * K }
        }
        d => d,
    };
    w.sync();
    let sig = w.base();
    w.write(a, 100 * K, 4 * K);
    compress(&mut w, b);
    let d = w.scan(Some(&sig));
    assert!(d.file(a).no_narrow);
    assert!(meta_whole(&d, a));
    assert!(zero_in(&d, &w.data_ranges(a)).is_empty());
    assert!(whole(&d, b), "compressing marks the whole file: {:?}", d.file(b));
}

#[test]
fn small_file_below_threshold_is_whole_file() {
    let mut w = World::new(true, Some((16 * K, 1024 * K)));
    let a = w.create("a.bin", 512 * K);
    let sig = w.base();
    w.write(a, 100 * K, 4 * K);
    assert!(meta_whole(&w.scan(Some(&sig)), a));
}

#[test]
fn append_only_is_extended() {
    let mut w = World::new(true, None);
    let a = w.create("a.bin", 2048 * K);
    let sig = w.base();
    let before = w.data_ranges(a);
    w.write(a, 2048 * K, 8 * K);
    let d = w.scan(Some(&sig));
    // Only the appended part: the old data is not marked.
    assert_eq!(d.file(a).evidence, Evidence::Extended(vec![ByteRange::new(2048 * K, 8 * K)]));
    assert!(!d.file(a).no_narrow);
    // Appended into new clusters: new allocations.
    let new = list::subtract(&w.data_ranges(a), &before);
    assert_eq!(bytes(&new), 8 * K);
    assert_eq!(list::subtract(&new, &list::subtract(d.used(), &norm(&sig.allocated))), vec![]);
}

#[test]
fn append_into_preallocated_space_marks_from_old_vdl() {
    let mut w = World::new(true, None);
    let a = w.create("a.bin", 1536 * K);
    // SetEndOfFile to 2 MiB: allocated, valid data length stays at 1.5 MiB.
    w.v.truncate(a, 2048 * K, crate::synth::Placement::FirstFit);
    w.journal(a, reason::DATA_EXTEND | reason::CLOSE);
    w.sync();
    let base = w.scan(None);
    let sig = base.scan.next.clone();
    // Write past the valid data length inside the allocation: NTFS zero-fills from the
    // old VDL; the journal shows only an extension of valid data (no overwrite).
    w.v.write_data(a, 1600 * K, 8 * K, 99, crate::synth::Placement::FirstFit);
    let now = w.v.clock;
    w.v.files.get_mut(&a).unwrap().si.modified = now;
    w.journal(a, reason::DATA_EXTEND | reason::CLOSE);
    w.sync();
    let d = w.scan(Some(&sig));
    let f = d.file(a);
    let Evidence::Extended(grown) = &f.evidence else { panic!("{:?}", f.evidence) };
    assert_eq!(list::subtract(&norm(grown), &f.zero), vec![ByteRange::new(1536 * K, 72 * K)], "{grown:?}");
    // The rest of the allocation, past the new valid data length, still reads as zeros (and
    // did before: not changed).
    assert_eq!(zero_in(&d, &w.data_ranges(a)), w.phys(a, 1608 * K, 2048 * K));
    assert_eq!(list::subtract(&zero_in(&d, &w.data_ranges(a)), &zero_in(&base, &w.data_ranges(a))), vec![]);
}

#[test]
fn past_valid_data_length_reads_as_zero_when_the_log_is_clean() {
    let mut w = World::new(true, None);
    let a = w.create("a.bin", 512 * K + 100);
    w.v.truncate(a, 1024 * K, crate::synth::Placement::FirstFit);
    w.journal(a, reason::DATA_EXTEND | reason::CLOSE);
    w.sync();
    // The cluster holding the valid data length is data.
    let d = w.scan(None);
    assert_eq!(zero_in(&d, &w.data_ranges(a)), w.phys(a, 516 * K, 1024 * K));
    assert_eq!(bytes(&d.zero()), 508 * K);
    let sig = d.scan.next;
    // A change of the file: the part past the valid data length still reads as zero.
    w.touch_metadata(a);
    w.set_si(a, |si| si.usn = Some(1 << 40));
    let d = w.scan(Some(&sig));
    assert!(meta_whole(&d, a));
    assert_eq!(zero_in(&d, &w.data_ranges(a)), w.phys(a, 516 * K, 1024 * K));
    // Without a clean $LogFile the length may not be final: nothing reads as zeros.
    w.log_clean = false;
    let d = w.scan(None);
    assert!(d.zero().is_empty());
    let warnings = &d.scan.extra.warnings;
    assert!(warnings.iter().any(|m| m.message.contains("$LogFile") && m.message.contains("1 stream")), "{warnings:?}");
    // Nothing past a valid data length: nothing to warn about.
    let mut w = World::new(true, None);
    w.create("b.bin", 300 * K);
    w.log_clean = false;
    let d = w.scan(None);
    assert!(d.scan.extra.warnings.is_empty(), "{:?}", d.scan.extra.warnings);
}

/// The format side's file map (what the bitmap uses for file-level zero) reports the data
/// streams of the user files with what a scan reads as zero, and no zero while the `$LogFile`
/// is not clean.
#[test]
fn file_map_reports_what_the_scan_sees() {
    let mut w = World::new(true, None);
    let a = w.create("a.bin", 512 * K + 100);
    w.v.truncate(a, 1024 * K, crate::synth::Placement::FirstFit);
    let p = w.create("pagefile.sys", 200 * K);
    w.v.truncate(p, 400 * K, crate::synth::Placement::FirstFit);
    let d = w.v.create_dir(crate::synth::ROOT, "dir");
    let b = w.v.create_file(d, "b.bin", 64 * K, 3, crate::synth::Placement::FirstFit);
    w.v.create_file(crate::synth::EXTEND, "$Sys", 64 * K, 4, crate::synth::Placement::FirstFit);
    w.sync();
    let files = |w: &World| {
        let fs = crate::open(w.source(), &fs_inspect_core::DriverContext::default()).unwrap();
        let mut out = Vec::new();
        fs.file_map()
            .unwrap()
            .for_each(&mut |f| {
                out.push(f);
                Ok(())
            })
            .unwrap();
        out
    };
    let got = files(&w);
    // The journal's $J lives under $Extend: left out with the other $Extend files.
    assert_eq!(got.iter().map(|f| f.key).collect::<Vec<_>>(), [a, p, b]);
    for f in &got {
        let mut phys = Vec::new();
        fs_inspect_core::files::all_physical(&f.extents, &mut phys);
        list::normalize(&mut phys);
        assert_eq!(phys, w.data_ranges(f.key));
    }
    let mut zero = Vec::new();
    for z in got[0].zero() {
        fs_inspect_core::files::physical_in(&got[0].extents, z.offset, z.end(), &mut zero);
    }
    assert_eq!(zero, w.phys(a, 516 * K, 1024 * K));
    assert_eq!(zero, zero_in(&w.scan(None), &w.data_ranges(a)));
    // A paging file's length past its valid data is not trusted.
    assert!(got[1].zero().is_empty());
    w.log_clean = false;
    assert!(files(&w).iter().all(|f| f.zero().is_empty()));
}

#[test]
fn metadata_only_change_is_clean() {
    let mut w = World::new(true, None);
    let a = w.create("a.bin", 200 * K);
    let sig = w.base();
    let data = w.data_ranges(a);
    w.touch_metadata(a);
    assert_eq!(data, w.data_ranges(a), "the same map");
    assert_eq!(evidence_of(&w, &sig, a), Evidence::MetadataOnly);
}

#[test]
fn transacted_hard_link_is_clean() {
    // Windows servicing links component files in and out of the store in TxF transactions:
    // `HARD_LINK_CHANGE | TRANSACTED_CHANGE` and nothing written.
    let mut w = World::new(true, None);
    let a = w.create("a.bin", 200 * K);
    let sig = w.base();
    w.journal(a, reason::HARD_LINK_CHANGE | reason::TRANSACTED_CHANGE | reason::CLOSE);
    w.sync();
    assert_eq!(evidence_of(&w, &sig, a), Evidence::MetadataOnly);
}

#[test]
fn si_usn_change_without_records_is_whole_file() {
    let mut w = World::new(true, None);
    let a = w.create("a.bin", 200 * K);
    let sig = w.base();
    w.touch_metadata(a);
    // $SI.Usn moved past the file's own records (no record explains it).
    w.set_si(a, |si| si.usn = Some(si.usn.unwrap() + 8));
    assert!(meta_whole(&w.scan(Some(&sig)), a));
}

#[test]
fn reused_record_is_created() {
    let mut w = World::new(true, None);
    let a = w.create("a.bin", 200 * K);
    let seq = w.v.files[&a].seq;
    let sig = w.base();
    w.delete(a);
    let c = w.create("c.bin", 200 * K);
    assert_eq!(c, a, "slot reused");
    assert_ne!(w.v.files[&c].seq, seq);
    let d = w.scan(Some(&sig));
    assert!(d.before(c).is_some());
    assert!(d.created(c));
}

#[test]
fn named_streams_are_tracked_separately() {
    let mut w = World::new(true, None);
    let a = w.create("a.bin", 200 * K);
    w.v.add_ads(a, "extra", 100 * K, 5);
    w.sync();
    let sig = w.base();
    let ads = w.stream_ranges(w.v.files[&a].stream("extra").unwrap());
    // Write the named stream in place without touching LastWriteTime.
    let off = ads[0].offset as usize;
    w.v.image[off] ^= 0xFF;
    w.journal(a, reason::NAMED_DATA_OVERWRITE | reason::CLOSE);
    w.sync();
    let d = w.scan(Some(&sig));
    let keys: Vec<u64> = d.scan.files.iter().map(|f| f.key).collect();
    assert_eq!(keys.len(), 2);
    let named = *keys.iter().find(|&&k| k & (1 << 63) != 0 && k & ((1 << 48) - 1) == a).expect("the named stream");
    assert!(keys.contains(&a));
    assert!(!d.created(a) && d.file(a).evidence == Evidence::MetadataOnly, "unnamed stream untouched");
    assert!(meta_whole(&d, named));
    let mut phys = Vec::new();
    fs_inspect_core::files::all_physical(&d.file(named).extents, &mut phys);
    assert_eq!(norm(&phys), norm(&ads));
}

/// A file with so many named streams that its attribute list is non-resident.
fn with_attribute_list(w: &mut World) -> (u64, Vec<ByteRange>) {
    let a = w.create("a.bin", 200 * K);
    for i in 0..48 {
        w.v.add_ads(a, &format!("s{i:02}"), 4 * K, i);
    }
    w.sync();
    let runs = w.v.files[&a].attr_list_runs.clone();
    assert!(!runs.is_empty(), "the attribute list is non-resident");
    (a, phys_of(&runs, 0, u64::MAX))
}

#[test]
fn attribute_list_follows_its_file() {
    let mut w = World::new(true, None);
    let (a, list) = with_attribute_list(&mut w);
    let sig = w.base();
    let d = w.scan(Some(&sig));
    assert!(d.space_in(&list).is_empty(), "unchanged file: its attribute list is not read");
    assert_eq!(w.changed(&d), vec![]);
    // Any change to the file stamps its `$SI.Usn`: the attribute list goes with it.
    w.touch_metadata(a);
    let d = w.scan(Some(&sig));
    assert_eq!(bytes(&d.space_in(&list)), bytes(&norm(&list)));
}

#[test]
fn attribute_list_without_a_journal_is_dirty() {
    let mut w = World::new(false, None);
    let (_, list) = with_attribute_list(&mut w);
    let sig = w.base();
    let d = w.scan(Some(&sig));
    assert_eq!(bytes(&d.space_in(&list)), bytes(&norm(&list)));
}

#[test]
fn journal_tail_is_tracked_by_the_driver() {
    let mut w = World::new(true, None);
    let a = w.create("a.bin", 200 * K);
    for _ in 0..40 {
        w.touch_metadata(a);
    }
    let sig = w.base();
    let prev_next = w.j.as_ref().unwrap().next;
    w.touch_metadata(a);
    let next = w.j.as_ref().unwrap().next;
    let d = w.scan(Some(&sig));
    let dj: Vec<_> = d.dirty_in(&w.j_ranges()).into_iter().filter(|t| t.reason == Reason::DriverMetadata).collect();
    assert!(!dj.is_empty());
    let j0 = w.j_ranges()[0].offset;
    assert_eq!(dj[0].offset - j0, prev_next / CS * CS);
    assert_eq!(total(&dj), next.div_ceil(CS) * CS - prev_next / CS * CS);
    // The allocated tail past the data is not dated (left to be copied).
    let end = j0 + next.div_ceil(CS) * CS;
    let tail = list::subtract(&d.space_in(&w.j_ranges()), &ranges_of(&dj));
    assert!(!tail.is_empty() && tail.iter().all(|t| t.offset >= end), "{tail:?}");
    assert!(prev_next > CS, "the journal spans several clusters");
}

#[test]
fn recreated_journal_removes_narrowing_but_stays_complete() {
    let mut w = World::new(true, Some((16 * K, 64 * K)));
    let a = w.create("a.bin", 512 * K);
    let b = w.create("b.bin", 200 * K);
    let sig = w.base();
    w.enable_journal(2, Some((16 * K, 64 * K)), 1 << 20, 64 << 10);
    w.write(a, 100 * K, 4 * K);
    w.touch_metadata(b);
    let d = w.scan(Some(&sig));
    assert!(d.degraded().contains(&super::codes::USN_RECREATED), "{:?}", d.degraded());
    assert!(!d.scan.extra.known_misses.is_empty());
    assert!(meta_whole(&d, a));
    // Without the journal a metadata change cannot be proven: whole file.
    assert!(meta_whole(&d, b));
    // All of the new $J is to be copied.
    assert_eq!(bytes(&d.space_in(&w.j_ranges())), bytes(&w.j_ranges()));
}

#[test]
fn wrapped_journal_removes_narrowing_but_stays_complete() {
    let mut w = World::new(false, None);
    w.enable_journal(7, Some((16 * K, 64 * K)), 16 * K, 8 * K);
    let a = w.create("a.bin", 512 * K);
    let sig = w.base();
    for _ in 0..200 {
        w.touch_metadata(a);
    }
    w.write(a, 100 * K, 4 * K);
    assert!(w.j.as_ref().unwrap().lowest_valid > 0, "the journal wrapped");
    let d = w.scan(Some(&sig));
    assert!(d.degraded().contains(&super::codes::USN_TRUNCATED), "{:?}", d.degraded());
    assert!(d.scan.extra.known_misses.is_empty(), "same journal: $SI.Usn stays sound");
    assert!(meta_whole(&d, a));
    assert_eq!(bytes(&d.space_in(&w.j_ranges())), bytes(&w.j_ranges()));
}

#[test]
fn diverged_journal_removes_narrowing() {
    let mut w = World::new(true, None);
    let a = w.create("a.bin", 200 * K);
    let sig = w.base();
    // The volume's journal differs from the previous snapshot's at its last record.
    let j = w.j.as_mut().unwrap();
    let last = j.data.len() - 8;
    j.data[last] ^= 0x55;
    w.touch_metadata(a);
    let d = w.scan(Some(&sig));
    assert!(d.degraded().contains(&super::codes::USN_DIVERGED), "{:?}", d.degraded());
    assert!(meta_whole(&d, a));
}

#[test]
fn unparsable_journal_interval_removes_narrowing() {
    let mut w = World::new(true, None);
    let a = w.create("a.bin", 200 * K);
    let sig = w.base();
    let from = w.j.as_ref().unwrap().next as usize;
    w.touch_metadata(a);
    let j = w.j.as_mut().unwrap();
    let rel = from - j.start as usize;
    j.data[rel + 4..rel + 6].copy_from_slice(&[9, 0]); // version 9
    w.sync();
    let d = w.scan(Some(&sig));
    assert!(d.degraded().contains(&super::codes::USN_UNREADABLE), "{:?}", d.degraded());
    assert!(meta_whole(&d, a));
    assert_eq!(bytes(&d.space_in(&w.j_ranges())), bytes(&w.j_ranges()));
}

#[test]
fn volume_without_journal_is_still_complete() {
    let mut w = World::new(false, None);
    let seed = 3;
    let a = w.v.create_file(crate::synth::ROOT, "a.bin", 200 * K, seed, crate::synth::Placement::FirstFit);
    let sig = w.base();
    w.v.write_data(a, 0, 4 * K, 4, crate::synth::Placement::FirstFit);
    let now = w.v.clock;
    w.set_si(a, |si| si.modified = now);
    let d = w.scan(Some(&sig));
    assert!(d.degraded().contains(&super::codes::USN_UNAVAILABLE));
    assert!(!d.scan.extra.known_misses.is_empty());
    assert!(meta_whole(&d, a));
}

#[test]
fn deleted_journal_is_a_known_miss() {
    let mut w = World::new(true, None);
    let a = w.create("a.bin", 200 * K);
    let sig = w.base();
    w.delete_journal();
    w.write(a, 0, 4 * K);
    let d = w.scan(Some(&sig));
    assert!(d.degraded().contains(&super::codes::USN_UNAVAILABLE));
    assert!(!d.scan.extra.known_misses.is_empty());
    assert!(meta_whole(&d, a));
}

#[test]
fn paging_files_are_always_whole_file() {
    let mut w = World::new(true, None);
    let p = w.create("PageFile.sys", 200 * K);
    let sig = w.base();
    let d = w.scan(Some(&sig));
    assert_eq!(d.file(p).evidence, Evidence::WholeFile);
}

#[test]
fn extend_files_and_directories_are_not_reported() {
    let mut w = World::new(true, None);
    let d = w.v.create_dir(crate::synth::ROOT, "dir");
    let inner = w.v.create_file(d, "inner.bin", 100 * K, 1, crate::synth::Placement::FirstFit);
    let sys = w.v.create_file(crate::synth::EXTEND, "$Sys", 100 * K, 2, crate::synth::Placement::FirstFit);
    w.sync();
    let sig = w.base();
    let keys: Vec<u64> = w.scan(Some(&sig)).scan.files.iter().map(|f| f.key).collect();
    assert_eq!(keys, vec![inner], "only the file in the subdirectory");
    // An $Extend file's data is dated by its content: unchanged, nothing of it is dirty.
    let r = w.data_ranges(sys);
    let s = w.scan(Some(&sig));
    assert!(s.space_in(&r).is_empty(), "{:?}", s.space_in(&r));
    // NTFS writes it with no journal record or stamp: the chunk written in is not dated.
    let runs = w.v.files[&sys].data().unwrap().runs().to_vec();
    w.v.write_stream(&runs, 8 * K, &[0x5A; 4096]);
    let s = w.scan(Some(&sig));
    assert!(s.dirty_in(&r).is_empty(), "not the driver's own dirty ranges");
    let undated = s.space_in(&r);
    let written = w.phys(sys, 8 * K, 12 * K);
    assert_eq!(list::subtract(&written, &undated), vec![], "{undated:?}");
    assert!(bytes(&undated) <= crate::track::space::EXTEND_CHUNK, "{undated:?}");
}

#[test]
fn identity_and_state() {
    let mut w = World::new(true, Some((16 * K, 64 * K)));
    w.create("a.bin", 200 * K);
    let src = w.source();
    let sc = crate::track::NtfsScanner::new(crate::open(src, &Default::default()).unwrap()).unwrap();
    use fs_inspect_change::TypedScanner;
    let id = sc.identity();
    assert_eq!((id.family, id.unit_bytes), (fs_inspect_core::FsFamily::Ntfs, 4096));
    assert_eq!(id.uuid.as_deref(), Some("123456789ABCDEF0"));
    assert_eq!(id.detail["record_bytes"], "1024");
    let st = sc.current().unwrap();
    let pos = st.journal.clone().unwrap();
    assert_eq!(pos.state.journal_id, 1);
    assert_eq!(pos.state.next_usn as u64, w.j.as_ref().unwrap().next);
    assert_eq!(
        pos.state.range_tracking,
        crate::track::usn::RangeTracking::Enabled { chunk_size: 16 * K, file_size_threshold: 64 * K as i64 }
    );
    assert!(pos.tail.len > 0 && (pos.tail.at + pos.tail.len) as i64 == pos.state.next_usn);
    // Journal problems never break continuity; an unusable state does.
    assert_eq!(TypedScanner::continuity(&sc, &st, &st, false), fs_inspect_change::Continuity::Ok);
    match fs_inspect_change::ScanOnce::continuity(&sc, fs_inspect_change::PrevState::new(b"garbage")) {
        fs_inspect_change::Continuity::Broken(d) => assert_eq!(d.code, super::codes::STATE),
        fs_inspect_change::Continuity::Ok => panic!("garbage state accepted"),
    }
}

fn hinted(usn: u64, journal_id: Option<u64>) -> fs_inspect_change::SnapshotHints {
    let next_usn = i64::try_from(usn).unwrap();
    let mut o = opts();
    o.usn_journal = Some(fs_inspect_change::UsnPosition { journal_id, next_usn });
    o
}

#[test]
fn journal_ahead_of_data_at_the_snapshot_is_read_again() {
    // VSS flushes the volume, then holds its writes: a write in between has its records (and
    // `$SI`) in the snapshot, its data only in the cache. The data reaches the disk after the
    // snapshot with no record; a comparison from the snapshot's journal end misses it.
    // Starting the next one at the USN read before the snapshot reads it again.
    let mut w = World::new(true, Some((16 * K, 512 * K)));
    let big = w.create("big.bin", 1024 * K);
    let small = w.create("small.bin", 200 * K);
    let quiet = w.create("quiet.bin", 200 * K);
    let u_pre = w.j.as_ref().unwrap().next;
    // Between the request and the snapshot: records and $SI land, the data stays cached.
    let before = w.v.image.clone();
    w.write(big, 300 * K, 8 * K);
    w.write(small, 4 * K, 100);
    let after = w.v.image.clone();
    let cached: Vec<ByteRange> = [w.data_ranges(big), w.data_ranges(small)].concat();
    for r in &cached {
        let (s, e) = (r.offset as usize, (r.offset + r.length) as usize);
        w.v.image[s..e].copy_from_slice(&before[s..e]);
    }
    let plain = w.base();
    let rewound = w.scan_with(None, &hinted(u_pre, Some(1))).scan.next;
    assert!(rewound_in(&rewound));
    // The cached data reaches the disk after the snapshot, without journal records.
    for r in &cached {
        let (s, e) = (r.offset as usize, (r.offset + r.length) as usize);
        w.v.image[s..e].copy_from_slice(&after[s..e]);
    }

    // From the snapshot's journal end: missed (the documented residual risk without the hint).
    let d = w.scan(Some(&plain));
    assert!(d.unchanged(big) && d.unchanged(small));

    // From the rewound position: found; the range-tracked file only in its ranges.
    let d = w.scan(Some(&rewound));
    let x = &d.scan.extra;
    assert!(x.degraded.is_empty() && x.warnings.is_empty(), "{:?} {:?}", x.degraded, x.warnings);
    assert_eq!(d.file(big).evidence, Evidence::Logical(vec![ByteRange::new(288 * K, 32 * K)]));
    assert_eq!(d.file(small).evidence, Evidence::WholeFile);
    assert!(d.unchanged(quiet));
    // $J from the rewound position.
    let dj = d.dirty_in(&w.j_ranges());
    assert_eq!(dj[0].offset - w.j_ranges()[0].offset, u_pre / CS * CS);

    // The next comparison, from what this run left without a rewind, is quiet.
    assert!(!rewound_in(&d.scan.next));
    let d = w.scan(Some(&d.scan.next));
    assert_eq!(w.changed(&d), vec![]);
}

#[test]
fn journal_start_hint_outside_the_snapshot_journal_is_ignored() {
    let mut w = World::new(true, None);
    let a = w.create("a.bin", 200 * K);
    let u_pre = w.j.as_ref().unwrap().next;
    w.touch_metadata(a);
    let sig = w.base();
    let next = w.j.as_ref().unwrap().next;
    for (o, what) in [(hinted(next + 8, None), "outside"), (hinted(u_pre, Some(2)), "recreated")] {
        let d = w.scan_with(Some(&sig), &o);
        assert!(!rewound_in(&d.scan.next));
        let warnings = &d.scan.extra.warnings;
        assert!(warnings.iter().any(|x| x.message.contains("ignored") && x.message.contains(what)), "{warnings:?}");
    }
    // The snapshot's own end: nothing to rewind.
    assert!(!rewound_in(&w.scan_with(None, &hinted(next, Some(1))).scan.next));
    // A position inside a record.
    let d = w.scan_with(Some(&sig), &hinted(u_pre + 8, None));
    assert!(!rewound_in(&d.scan.next));
    let warnings = &d.scan.extra.warnings;
    assert!(warnings.iter().any(|x| x.message.contains("not the end of a journal record")), "{warnings:?}");
}

/// At a power loss `$J` may keep its new size while its last pages were never written: they
/// hold what their clusters held before. The tail is the last record with those bytes after
/// it: the next run narrows as usual from the journal's size, and one where those bytes
/// changed (rewritten since) diverged.
#[test]
fn journal_ending_in_pages_never_written() {
    let mut w = World::new(true, None);
    let a = w.create("a.bin", 200 * K);
    let b = w.create("b.bin", 200 * K);
    for _ in 0..200 {
        w.journal(a, reason::BASIC_INFO_CHANGE);
    }
    // The last two and a half pages: other content.
    let overwrite = |w: &mut World, seed: u8| {
        let j = w.j.as_mut().unwrap();
        let n = j.data.len();
        for (i, x) in j.data[n - 10_000..].iter_mut().enumerate() {
            *x = (i as u8).wrapping_mul(97).wrapping_add(seed) | 0x80;
        }
        w.sync();
    };
    overwrite(&mut w, 1);
    let sig = w.base();
    let d = w.scan(Some(&sig));
    assert!(d.degraded().is_empty(), "{:?}", d.degraded());
    assert_eq!(w.changed(&d), vec![]);

    overwrite(&mut w, 2);
    assert!(w.scan(Some(&sig)).degraded().contains(&super::codes::USN_DIVERGED));
    // Only the pages before the last one rewritten.
    overwrite(&mut w, 1);
    let n = w.j.as_ref().unwrap().data.len();
    w.j.as_mut().unwrap().data[n - 10_000..n - 6_000].fill(0);
    w.sync();
    assert!(w.scan(Some(&sig)).degraded().contains(&super::codes::USN_DIVERGED));

    overwrite(&mut w, 1);
    let next = w.j.as_ref().unwrap().next;
    w.write(b, 0, 4 * K);
    let d = w.scan(Some(&sig));
    assert!(d.degraded().is_empty(), "{:?}", d.degraded());
    assert!(!d.unchanged(b));
    assert!(d.unchanged(a));
    // `$J` from the size it had.
    let dj = d.dirty_in(&w.j_ranges());
    assert_eq!(dj[0].offset - w.j_ranges()[0].offset, next / CS * CS);
}

/// What a tracker scan reports, comparable: each file's key, generation, `meta`, `aux`,
/// evidence and mapping, and the driver's dirty and tracked ranges.
type Report =
    (Vec<(u64, u64, u64, [u64; 2], Evidence, Vec<ByteRange>)>, Vec<fs_inspect_change::TaggedRange>, Vec<ByteRange>);

fn report(s: &testing::Scan) -> Report {
    let files = s
        .files
        .iter()
        .map(|f| {
            let mut phys = Vec::new();
            fs_inspect_core::files::all_physical(&f.extents, &mut phys);
            (f.key, f.generation, f.meta, f.aux, f.evidence.clone(), phys)
        })
        .collect();
    (files, s.extra.dirty.clone(), s.extra.tracked.clone())
}

/// A read error anywhere in opening or scanning fails the scan (never a different answer), and
/// a truncated image never panics.
#[test]
fn read_errors_and_truncation() {
    use fs_inspect_core::{DriverContext, Filesystem};
    use fs_inspect_io::DynSource;
    use fs_inspect_testkit::fault::{check_read_failures, check_truncations};
    use std::sync::Arc;
    let mut w = World::new(true, Some((16 * K, 64 * K)));
    let a = w.create("a.bin", 300 * K);
    w.create("b.bin", 100);
    let sig = w.base();
    w.write(a, 0, 4 * K);
    let go = |src: DynSource| {
        let fs: Arc<dyn Filesystem> = crate::open(src.clone(), &DriverContext::default())?;
        let sc = crate::track::open(fs.clone())?;
        Ok(report(&testing::scan(&*sc, &src, &fs, &opts(), Some(&sig))?))
    };
    let reads = check_read_failures(w.source(), 400, go);
    assert!(reads > 5, "{reads}");
    let mut img = vec![0u8; w.source().size() as usize];
    w.source().read_exact_at(0, &mut img).unwrap();
    check_truncations(&img, 200, go);
}

/// Byte edits, half of them in the first 256 KiB (where the structures are).
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
fn mutate(bytes: &mut [u8], muts: &[(u64, u8)]) {
    for (i, &(off, v)) in muts.iter().enumerate() {
        let n = if i % 2 == 0 { bytes.len().min(256 << 10) } else { bytes.len() } as u64;
        bytes[(off % n) as usize] = v;
    }
}

/// The undamaged image of `mutated_images_never_panic`, its journal ranges and what a scan of
/// the image before its last write left: made once, every case damages a copy.
fn mutation_base() -> &'static (Vec<u8>, Vec<ByteRange>, Recorded) {
    static BASE: std::sync::OnceLock<(Vec<u8>, Vec<ByteRange>, Recorded)> = std::sync::OnceLock::new();
    BASE.get_or_init(|| {
        let mut w = World::new(true, Some((16 * K, 64 * K)));
        let a = w.create("a.bin", 300 * K);
        w.create("b.bin", 100);
        let sig = w.base();
        w.write(a, 0, 4 * K);
        let src = w.source();
        let mut bytes = vec![0u8; src.size() as usize];
        src.read_exact_at(0, &mut bytes).unwrap();
        (bytes, w.j_ranges(), sig)
    })
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig { cases: fs_inspect_testkit::cases(96), ..Default::default() })]

    /// Damaged images never panic: open and scan (alone and against the undamaged image's)
    /// either fail or produce something.
    #[test]
    fn mutated_images_never_panic(muts in proptest::collection::vec((0u64..u64::MAX, proptest::prelude::any::<u8>()), 1..32)) {
        use fs_inspect_core::DriverContext;
        use fs_inspect_io::DynSource;
        use std::sync::Arc;
        let (base, j_ranges, sig) = mutation_base();
        let mut bytes = base.clone();
        // The MFT and the journal sit past the first 256 KiB too: aim at them as well.
        mutate(&mut bytes, &muts);
        for r in j_ranges.iter().take(1) {
            let o = (r.offset + muts[0].0 % r.length.max(1)) as usize;
            bytes[o] = muts[0].1;
        }
        let src: DynSource = Arc::new(fs_inspect_io::MemSource::new(bytes));
        if let Ok(fs) = crate::open(src.clone(), &DriverContext::default())
            && let Ok(sc) = crate::track::open(fs.clone())
        {
            let _ = testing::scan(&*sc, &src, &fs, &opts(), None);
            let _ = testing::scan(&*sc, &src, &fs, &opts(), Some(sig));
        }
    }
}

/// A recreated journal restarts the USN counter: a write it stamps with the value the file
/// already had (timestamps restored) is caught by the stamp lying in the new journal's span.
#[test]
fn recreated_journal_restamping_the_same_usn_is_whole_file() {
    let mut w = World::new(true, None);
    let a = w.create("a.bin", 200 * K);
    let b = w.create("b.bin", 200 * K);
    let old = w.v.files[&a].si.usn;
    let sig = w.base();
    w.delete_journal();
    w.enable_journal(2, None, 1 << 20, 64 << 10);
    for _ in 0..20 {
        w.touch_metadata(b);
    }
    let t = w.v.files[&a].si.modified;
    w.write(a, 8 * K, 4 * K);
    w.set_si(a, |si| {
        si.modified = t;
        si.usn = old;
    });
    assert!(old.unwrap() < w.j.as_ref().unwrap().next, "the old stamp lies in the new journal's span");
    let d = w.scan(Some(&sig));
    assert!(d.degraded().contains(&super::codes::USN_RECREATED));
    assert!(whole(&d, a), "{:?}", d.file(a));
}

/// After a recreation, the new journal may have stamped (and since purged) values below its
/// first valid USN too: the old stamp falls below it here and must still count.
#[test]
fn restamped_value_below_a_purged_new_journal_is_whole_file() {
    let mut w = World::new(true, None);
    let a = w.create("a.bin", 200 * K);
    let b = w.create("b.bin", 200 * K);
    let old = w.v.files[&a].si.usn;
    let sig = w.base();
    w.delete_journal();
    w.enable_journal(2, None, 64 * K, 16 * K);
    let t = w.v.files[&a].si.modified;
    w.write(a, 8 * K, 4 * K);
    w.set_si(a, |si| {
        si.modified = t;
        si.usn = old;
    });
    for _ in 0..3000 {
        w.journal(b, reason::BASIC_INFO_CHANGE);
    }
    w.sync();
    let j = w.j.as_ref().unwrap();
    assert!((old.unwrap() as i64) < j.lowest_valid, "the old stamp lies below the purged beginning");
    let d = w.scan(Some(&sig));
    assert!(whole(&d, a), "{:?}", d.file(a));
}

/// A journal enabled since the previous scan: files it never stamped keep `$SI.Usn` 0,
/// which is not taken for a stamp (only the file of its record at USN 0 is).
#[test]
fn never_stamped_files_stay_clean_when_a_journal_appears() {
    let mut w = World::new(false, None);
    let a = w.create("a.bin", 200 * K);
    let b = w.create("b.bin", 200 * K);
    let sig = w.base();
    w.enable_journal(1, None, 1 << 20, 64 << 10);
    w.touch_metadata(b);
    let d = w.scan(Some(&sig));
    assert!(d.degraded().contains(&super::codes::USN_UNAVAILABLE), "{:?}", d.degraded());
    assert!(d.unchanged(a), "never stamped: unchanged");
}

/// A snapshot whose `$LogFile` is not clean may hold MFT records whose data is still cached:
/// the next comparison misses it, so the run says so, unless a journal position from before
/// the snapshot is given.
#[test]
fn not_clean_snapshot_reports_its_boundary_miss() {
    let has =
        |d: &Diff| d.scan.extra.known_misses.iter().any(|m| m.message == crate::track::scan::KNOWN_MISS_NOT_CLEAN);
    let mut w = World::new(true, Some((16 * K, 64 * K)));
    w.create("a.bin", 300 * K);
    let u_pre = w.j.as_ref().unwrap().next;
    let sig = w.base();
    assert!(!has(&w.scan(Some(&sig))));
    w.log_clean = false;
    assert!(has(&w.scan(Some(&sig))));
    assert!(!has(&w.scan_with(Some(&sig), &hinted(u_pre, Some(1)))));
}

/// A changed MFT record makes its chunk undated, a changed index block carries a newer LSN; the
/// other chunks and blocks are dated, and nothing is read for comparison.
#[test]
fn records_and_index_blocks_follow_their_lsn() {
    let mut w = World::new(true, None);
    let a = w.create("a.bin", 64 * K);
    let b = w.create("b.bin", 64 * K);
    let d = w.v.create_dir(crate::synth::ROOT, "dir");
    for i in 0..40 {
        w.v.create_file(d, &format!("f{i:02}.bin"), 100, 1, crate::synth::Placement::FirstFit);
    }
    w.sync();
    let idx = phys_of(&w.v.files[&d].index_runs, 0, u64::MAX / 2);
    assert!(!idx.is_empty(), "the directory has index blocks");
    // MFT chunks are dated as a whole: `b` shares `a`'s, `far` does not.
    let per = crate::format::volume::MFT_CHUNK / u64::from(w.v.spec.record_size);
    assert_eq!(a / per, b / per);
    let far = *w.v.files.keys().find(|&&r| r / per != a / per && r >= 24).expect("a record in another chunk");
    let sig = w.base();
    assert_eq!(w.changed(&w.scan(Some(&sig))), vec![]);
    w.touch_metadata(a);
    let s = w.scan(Some(&sig));
    assert!(!s.space_in(&w.record_range(a)).is_empty());
    assert!(!s.space_in(&w.record_range(b)).is_empty());
    assert!(s.space_in(&w.record_range(far)).is_empty());
    assert!(s.space_in(&idx).is_empty());
    // `$MFTMirr` follows records 0-3, `$SDS` the `$Secure` record and index blocks (system
    // records are dated one by one); `$MFT:$BITMAP` the chunks of the records it describes.
    let sds = phys_of(w.v.files[&9].stream("$SDS").unwrap().runs(), 0, u64::MAX / 2);
    assert!(s.space_in(&[ByteRange::new(w.v.mirror_lcn * CS, CS)]).is_empty());
    assert!(s.space_in(&sds).is_empty());
    assert!(!s.space_in(&phys_of(&w.v.mft_bitmap_runs, 0, CS)).is_empty());
    // A new name in the directory rewrites an index block.
    w.v.create_file(d, "g.bin", 100, 1, crate::synth::Placement::FirstFit);
    w.sync();
    assert!(!w.scan(Some(&sig)).space_in(&idx).is_empty());
}

/// A record is dated by its content: one rewritten with nothing but a new update sequence
/// number (Windows rewrites whole pages of records so) is changed, and so is one rewritten
/// with neither a new LSN nor a new update sequence number (raw writes, or another branch of
/// the volume's history reusing them).
#[test]
fn records_follow_their_content() {
    let mut w = World::new(true, None);
    let a = w.create("a.bin", 64 * K);
    let sig = w.base();
    let r = w.record_range(a)[0];
    assert!(w.scan(Some(&sig)).space_in(&[r]).is_empty());
    w.v.image[(r.offset + 0x100) as usize] ^= 1;
    assert!(!w.scan(Some(&sig)).space_in(&[r]).is_empty());
    w.v.image[(r.offset + 0x100) as usize] ^= 1;
    // The update sequence number at 0x30 and in each sector's last two bytes.
    for o in [0x30, 0x1FE, 0x3FE] {
        w.v.image[(r.offset + o) as usize] += 1;
    }
    let d = w.scan(Some(&sig));
    assert!(!d.space_in(&[r]).is_empty());
    assert!(d.scan.extra.warnings.is_empty());
}

/// Log record pages are dated by their content, a [`space::LOG_CHUNK`] at a time: the chunk
/// of the new pages is not dated, the others are; a page with other content and the same LSN
/// (another branch) is not.
#[test]
fn log_pages_follow_their_content() {
    let spec = crate::synth::VolumeSpec { clusters: 16384, logfile_clusters: 256, ..Default::default() };
    let mut w = World::with_spec(spec, true, None);
    let a = w.create("a.bin", 64 * K);
    let sig = w.base();
    let pos = w.v.log_pos;
    let span = w.v.spec.logfile_clusters * CS - 8192;
    let page = |w: &World, p: u64| phys_of(&w.v.logfile_runs, 8192 + p % span, 8192 + p % span + 4096);
    let away = pos + 2 * crate::track::space::LOG_CHUNK;
    assert!(w.scan(Some(&sig)).space_in(&page(&w, pos)).is_empty());
    w.touch_metadata(a);
    let d = w.scan(Some(&sig));
    assert!(!d.space_in(&page(&w, pos)).is_empty());
    assert!(d.space_in(&page(&w, away)).is_empty());
    let at = page(&w, away)[0].offset as usize + 0x100;
    w.v.image[at] ^= 1;
    assert!(!w.scan(Some(&sig)).space_in(&page(&w, away)).is_empty());
}

/// `$MFT:$BITMAP` past the last record follows `$MFT`'s record: unchanged with it, changed
/// when the bitmap grows or moves (a new cluster held anything before).
#[test]
fn mft_bitmap_past_the_records_follows_the_mft_record() {
    let mut w = World::new(true, None);
    let a = w.create("a.bin", 64 * K);
    // A cluster of bitmap past the last record (allocated ahead).
    let vcn = w.v.mft_bitmap_runs.last().unwrap().end_vcn();
    let more = w.v.alloc.alloc(1, vcn, crate::synth::Placement::FirstFit);
    w.v.mft_bitmap_runs.extend(more);
    w.sync();
    let bitmap = |w: &World| phys_of(&w.v.mft_bitmap_runs, 0, u64::MAX / 2);
    let sig = w.base();
    w.touch_metadata(a);
    let d = w.scan(Some(&sig));
    assert!(d.space_in(&phys_of(&w.v.mft_bitmap_runs, CS, 2 * CS)).is_empty());

    // Grown by a cluster: `$MFT`'s record changes, the whole bitmap with it.
    let mut grown = w.v.mft_bitmap_runs.clone();
    grown.extend(w.v.alloc.alloc(1, vcn + 1, crate::synth::Placement::FirstFit));
    let before = std::mem::replace(&mut w.v.mft_bitmap_runs, grown);
    w.sync();
    let d = w.scan(Some(&sig));
    assert_eq!(bytes(&d.space_in(&bitmap(&w))), 3 * CS);

    // Moved: the cluster past the last record is somewhere else.
    w.v.mft_bitmap_runs = before;
    let last = w.v.mft_bitmap_runs.pop().unwrap();
    w.v.mft_bitmap_runs.extend(w.v.alloc.alloc(1, last.vcn(), crate::synth::Placement::FirstFit));
    w.sync();
    let d = w.scan(Some(&sig));
    assert!(!d.space_in(&phys_of(&w.v.mft_bitmap_runs, CS, 2 * CS)).is_empty());
}

/// `$MFT:$BITMAP`, `$MFTMirr` and `$SDS` are not dated when the previous or the current log
/// is not clean: they may have been written back before or after the structures they are
/// dated by.
#[test]
fn streams_dated_by_other_structures_need_clean_logs() {
    let mut w = World::new(true, None);
    let a = w.create("a.bin", 64 * K);
    let streams = [
        phys_of(&w.v.mft_bitmap_runs, 0, CS),
        vec![ByteRange::new(w.v.mirror_lcn * CS, CS)],
        phys_of(w.v.files[&9].stream("$SDS").unwrap().runs(), 0, u64::MAX / 2),
    ];
    let undated = |w: &World, sig| {
        let d = w.scan(Some(sig));
        streams.iter().map(|r| !d.space_in(r).is_empty()).collect::<Vec<_>>()
    };
    let sig = w.base();
    assert_eq!(undated(&w, &sig), [false; 3]);
    w.log_clean = false;
    assert_eq!(undated(&w, &sig), [true; 3]);
    let sig = w.base();
    w.log_clean = true;
    w.touch_metadata(a);
    assert_eq!(undated(&w, &sig), [true; 3]);
}

/// Both snapshots of a guest not running and the `$LogFile` restart area as it was: nothing
/// was mounted in between, so nothing changed, a log not clean as a clean one.
#[test]
fn unclean_log_offline_and_untouched_is_settled() {
    let mut w = World::new(true, None);
    w.create("a.bin", 64 * K);
    let streams = [
        phys_of(&w.v.mft_bitmap_runs, 0, CS),
        vec![ByteRange::new(w.v.mirror_lcn * CS, CS)],
        phys_of(w.v.files[&9].stream("$SDS").unwrap().runs(), 0, u64::MAX / 2),
        phys_of(&w.v.logfile_runs, 0, u64::MAX / 2),
    ];
    let offline = |on: bool| fs_inspect_change::SnapshotHints { guest_offline: on, ..Default::default() };
    let undated = |w: &World, sig, on| {
        let d = w.scan_with(Some(sig), &offline(on));
        streams.iter().map(|r| !d.space_in(r).is_empty()).collect::<Vec<_>>()
    };
    let base = |w: &World, on| w.scan_with(None, &offline(on)).scan.next;
    let clean = base(&w, true);
    let clean = undated(&w, &clean, true);
    w.log_clean = false;
    let (on, off) = (base(&w, false), base(&w, true));
    assert_eq!(undated(&w, &off, true), clean);
    let d = w.scan_with(Some(&off), &offline(true));
    assert!(!d.scan.extra.known_misses.iter().any(|m| m.message == crate::track::scan::KNOWN_MISS_NOT_CLEAN));
    // Nothing written since: `$Extend` data and the rest of the space neither.
    assert_eq!(d.all_changed(), vec![]);
    assert_eq!(undated(&w, &on, true)[..3], [true; 3]);
    assert_eq!(undated(&w, &off, false)[..3], [true; 3]);
}

/// `$Bitmap` follows the allocation of the clusters it describes.
#[test]
fn bitmap_follows_the_allocation() {
    let mut w = World::new(true, None);
    let a = w.create("a.bin", 64 * K);
    let bm = phys_of(&w.v.bitmap_runs, 0, CS);
    let sig = w.base();
    w.touch_metadata(a);
    assert!(w.scan(Some(&sig)).space_in(&bm).is_empty());
    w.create("b.bin", 64 * K);
    assert!(!w.scan(Some(&sig)).space_in(&bm).is_empty());
}

/// Index blocks, MFT chunks and log pages are dated by their content whatever the previous
/// log, and when the journal diverged from the previous snapshot's (it was written to after it
/// was taken).
#[test]
fn space_is_dated_whatever_the_journal() {
    let mut w = World::new(true, None);
    let a = w.create("a.bin", 64 * K);
    let d = w.v.create_dir(crate::synth::ROOT, "dir");
    for i in 0..40 {
        w.v.create_file(d, &format!("f{i:02}.bin"), 100, 1, crate::synth::Placement::FirstFit);
    }
    w.sync();
    let idx = phys_of(&w.v.files[&d].index_runs, 0, u64::MAX / 2);
    w.log_clean = false;
    let sig = w.base();
    w.log_clean = true;
    let s = w.scan(Some(&sig));
    assert!(s.space_in(&idx).is_empty());
    assert!(s.space_in(&w.record_range(a)).is_empty());

    let sig = w.base();
    assert!(w.scan(Some(&sig)).space_in(&idx).is_empty());
    // The journal differs from the previous snapshot's at its last record.
    let j = w.j.as_mut().unwrap();
    let last = j.data.len() - 8;
    j.data[last] ^= 0x55;
    w.sync();
    let s = w.scan(Some(&sig));
    assert!(s.degraded().contains(&super::codes::USN_DIVERGED), "{:?}", s.degraded());
    assert!(s.space_in(&idx).is_empty());
    assert!(s.space_in(&w.record_range(a)).is_empty());
    assert!(s.space_in(&phys_of(&w.v.logfile_runs, 8192, u64::MAX / 2)).is_empty());
}

/// An index block is dated by its content: one written with a new update sequence number but
/// its LSN unchanged (Windows updates the file names' duplicated sizes and times so) is
/// changed, and so is one rewritten with neither.
#[test]
fn index_blocks_follow_their_content() {
    let mut w = World::new(true, None);
    let d = w.v.create_dir(crate::synth::ROOT, "dir");
    for i in 0..40 {
        w.v.create_file(d, &format!("f{i:02}.bin"), 100, 1, crate::synth::Placement::FirstFit);
    }
    w.sync();
    let idx = phys_of(&w.v.files[&d].index_runs, 0, u64::MAX / 2);
    let sig = w.base();
    let at = idx[0].offset as usize;
    assert_eq!(&w.v.image[at..at + 4], b"INDX");
    assert!(w.scan(Some(&sig)).space_in(&idx).is_empty());
    w.v.image[at + 0x100] ^= 1;
    assert!(!w.scan(Some(&sig)).space_in(&idx).is_empty());
    w.v.image[at + 0x100] ^= 1;
    // The update sequence number at 0x28 and in each sector's last two bytes.
    let usa = u16::from_le_bytes([w.v.image[at + 4], w.v.image[at + 5]]) as usize;
    let sectors = u16::from_le_bytes([w.v.image[at + 6], w.v.image[at + 7]]) as usize - 1;
    assert_eq!(usa, 0x28);
    for o in std::iter::once(usa).chain((0..sectors).map(|k| 0x1FE + 0x200 * k)) {
        w.v.image[at + o] = w.v.image[at + o].wrapping_add(1);
    }
    let s = w.scan(Some(&sig));
    assert!(!s.space_in(&idx).is_empty());
    assert!(s.scan.extra.warnings.is_empty());
}

/// The index blocks of all directories are read together; one that cannot be read is not
/// dated, the others still are, and the scan goes on.
#[test]
fn an_unreadable_index_block_is_not_dated() {
    use fs_inspect_core::{DriverContext, Filesystem};
    use fs_inspect_io::DynSource;
    use fs_inspect_io::test_util::FaultySource;
    use std::sync::Arc;
    let mut w = World::new(true, None);
    let dirs: Vec<u64> = (0..2).map(|k| w.v.create_dir(crate::synth::ROOT, &format!("d{k}"))).collect();
    for &d in &dirs {
        for i in 0..40 {
            w.v.create_file(d, &format!("f{i:02}.bin"), 100, 1, crate::synth::Placement::FirstFit);
        }
    }
    w.sync();
    let idx: Vec<Vec<ByteRange>> = dirs.iter().map(|d| phys_of(&w.v.files[d].index_runs, 0, u64::MAX / 2)).collect();
    let sig = w.base();
    let bad = idx[0][0].offset;
    let src = Arc::new(FaultySource::new(w.source(), bad..bad + 1));
    let fs: Arc<dyn Filesystem> = crate::open(src.clone(), &DriverContext::default()).unwrap();
    let sc = crate::track::open(fs.clone()).unwrap();
    let dyn_src: DynSource = src.clone();
    let scan = testing::scan(&*sc, &dyn_src, &fs, &opts(), Some(&sig)).unwrap();
    let d = Diff { scan, prev: Some(sig) };
    assert!(!d.space_in(&[ByteRange::new(bad, 4096)]).is_empty());
    assert!(d.space_in(&idx[1]).is_empty());
    assert!(src.hits() <= 3, "{} reads over the damage", src.hits());
}

/// The warning of `d` whose message has `what`.
fn warning<'d>(d: &'d Diff, what: &str) -> &'d str {
    let w: Vec<&str> = d.scan.extra.warnings.iter().map(|w| w.message.as_str()).collect();
    w.iter().find(|m| m.contains(what)).unwrap_or_else(|| panic!("no warning with {what:?} in {w:?}"))
}

/// A torn record of a file with data is damaged: the scan warns, naming the record, and the
/// file's data counts as changed; the other files are not affected.
#[test]
fn a_damaged_record_counts_its_data_as_changed() {
    let mut w = World::new(true, None);
    let a = w.create("a.bin", 200 * K);
    let b = w.create("b.bin", 200 * K);
    let sig = w.base();
    // The last bytes of the record's first sector no longer match its update sequence.
    let at = w.record_range(a)[0].offset as usize;
    w.v.image[at + 510] ^= 0xFF;
    let d = w.scan(Some(&sig));
    let m = warning(&d, "are damaged");
    assert!(m.starts_with("1 record(s)") && m.ends_with(&format!("(records {a})")), "{m}");
    let data = norm(&w.data_ranges(a));
    assert_eq!(list::intersect(&d.all_changed(), &data), data);
    assert!(d.unchanged(b));
}

/// A file whose directory's record is gone has a parent that does not resolve: the scan
/// warns, naming the record.
#[test]
fn a_file_whose_directory_is_gone_is_reported() {
    let mut w = World::new(true, None);
    let dir = w.v.create_dir(crate::synth::ROOT, "d");
    let a = w.v.create_file(dir, "a.bin", 200 * K, 7, crate::synth::Placement::FirstFit);
    w.sync();
    let sig = w.base();
    let at = w.record_range(dir)[0].offset as usize;
    let rs = w.v.spec.record_size as usize;
    w.v.image[at..at + rs].fill(0);
    let d = w.scan(Some(&sig));
    let m = warning(&d, "parent directory that does not resolve");
    assert!(m.contains(&format!("record {a}")) || m.contains(&format!("records {a}")), "{m}");
}
