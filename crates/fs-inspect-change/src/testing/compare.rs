//! A model of a comparer over two scans of a tracker ([`scan`](super::scan)), for tests that
//! check what a tracker's report comes to. Simplified: a changed file is marked whole (no map
//! windows; evidence other than `WholeFile` is not narrowed), a key reported twice is not looked
//! for, and the fixed regions count as unchanged. As a comparer does: the residual, new
//! allocations, zero changes and the tracker's dirty ranges are marked; overlapping marks keep
//! the lower reason; a broken continuity marks everything used (`Fallback`), as does a first
//! scan (`Baseline`). What the volume map says reads as zeros
//! ([`Recorded::zero`](super::Recorded::zero)) counts as zeros.

use super::Scan;
use crate::{Continuity, Degrade, Evidence, FileState, Reason, TaggedRange};
use fs_inspect_core::ByteRange;
use fs_inspect_core::ZeroCollector;
use fs_inspect_core::files::all_physical;
use fs_inspect_core::range::list;
use std::collections::{BTreeMap, BTreeSet};

/// What a comparer makes of a scan against the previous one.
#[derive(Debug, Default)]
pub struct Cbt {
    /// Dirty ranges that do not read as zeros, sorted.
    pub dirty: Vec<TaggedRange>,
    /// Dirty ranges that read as zeros, sorted.
    pub zero: Vec<TaggedRange>,
    /// Every used range that reads as zeros.
    pub zero_all: Vec<ByteRange>,
    /// Used before, not now.
    pub freed: Vec<ByteRange>,
    /// The residual: used, but neither file data, zeros, tracked nor fixed.
    pub unclaimed: Vec<ByteRange>,
    /// What the tracker accounts for (its tracked ranges, the owned ranges of unchanged files).
    pub tracked: Vec<ByteRange>,
    /// The files' data.
    pub data: Vec<ByteRange>,
    pub used: Vec<ByteRange>,
    /// A broken continuity's degrade first, then the tracker's.
    pub degraded: Vec<Degrade>,
}

impl Cbt {
    pub fn dirty_bytes(&self) -> u64 {
        self.dirty.iter().map(|t| t.length).sum()
    }
    pub fn used_bytes(&self) -> u64 {
        list::total(&self.used)
    }
    pub fn file_data_bytes(&self) -> u64 {
        list::total(&self.data)
    }
    /// The degrade codes, as strings.
    pub fn codes(&self) -> Vec<String> {
        self.degraded.iter().map(|d| d.code.to_string()).collect()
    }
}

fn norm(mut v: Vec<ByteRange>) -> Vec<ByteRange> {
    list::normalize(&mut v);
    v
}

/// The used space of a scan: (used, file data, everything that reads as zeros).
fn space(s: &Scan) -> (Vec<ByteRange>, Vec<ByteRange>, Vec<ByteRange>) {
    let used = norm(s.next.allocated.clone());
    let mut zc = ZeroCollector::new();
    for f in &s.files {
        zc.add(&f.extents, &f.zero);
    }
    let (file_zero, data) = zc.finish(&used);
    let data = norm(data);
    let driver_zero = list::subtract(&list::intersect(&norm(s.extra.zero.clone()), &used), &data);
    let map_zero = list::subtract(&list::intersect(&s.next.zero, &used), &data);
    let zero_all = list::union(&list::union(&norm(file_zero), &driver_zero), &map_zero);
    (used.clone(), list::intersect(&data, &used), zero_all)
}

/// Whether `f` compares unchanged against `old`, else why it is marked.
fn verdict(f: &FileState, old: Option<&&FileState>) -> Option<Reason> {
    let Some(o) = old.filter(|o| o.generation == f.generation) else { return Some(Reason::Created) };
    let meta_ch = o.meta != f.meta || o.aux != f.aux;
    let map_ch = o.extents != f.extents;
    match f.evidence {
        Evidence::WholeFile => Some(Reason::DriverWholeFile),
        Evidence::None | Evidence::MetadataOnly if !meta_ch && !map_ch => None,
        _ if meta_ch => Some(Reason::MetaChanged),
        _ => Some(Reason::MapChanged),
    }
}

/// What a comparer makes of `now` against `prev` (the scan `now` was made against).
pub fn compare(prev: Option<&Scan>, now: &Scan) -> Cbt {
    let (used, data, zero_all) = space(now);
    let mut degraded: Vec<Degrade> = Vec::new();
    if let Continuity::Broken(d) = &now.continuity {
        degraded.push(d.clone());
    }
    degraded.extend(now.extra.degraded.iter().cloned());
    let freed = prev.map(|p| list::subtract(&space(p).0, &used)).unwrap_or_default();
    let mut marks: Vec<TaggedRange> = Vec::new();
    let mut tracked = norm(now.extra.tracked.clone());
    let mut unclaimed = Vec::new();
    match prev.filter(|_| now.continuity == Continuity::Ok) {
        None => {
            let reason = if prev.is_some() { Reason::Fallback } else { Reason::Baseline };
            marks.extend(TaggedRange::tag_all(used.clone(), reason));
        }
        Some(p) => {
            let (p_used, _, p_zero) = space(p);
            let old: BTreeMap<u64, &FileState> = p.files.iter().map(|f| (f.key, f)).collect();
            let mut unchanged = BTreeSet::new();
            for f in &now.files {
                match verdict(f, old.get(&f.key)) {
                    None => {
                        unchanged.insert(f.key);
                    }
                    Some(reason) => {
                        let mut v = Vec::new();
                        all_physical(&f.extents, &mut v);
                        marks.extend(TaggedRange::tag_all(v, reason));
                    }
                }
            }
            let (ok, bad): (Vec<&(u64, ByteRange)>, Vec<_>) =
                now.extra.owned.iter().partition(|o| unchanged.contains(&o.0));
            let owned = list::subtract(
                &norm(ok.into_iter().map(|o| o.1).collect()),
                &norm(bad.into_iter().map(|o| o.1).collect()),
            );
            tracked = list::intersect(&list::union(&tracked, &owned), &used);
            let accounted = list::union(&list::union(&data, &zero_all), &tracked);
            let fixed = norm(now.extra.fixed.clone());
            unclaimed = list::subtract(&list::subtract(&used, &accounted), &fixed);
            marks.extend(TaggedRange::tag_all(unclaimed.clone(), Reason::Unclaimed));
            marks.extend(now.extra.dirty.iter().copied());
            let unzeroed = list::subtract(&list::intersect(&p_zero, &used), &zero_all);
            let zeroed = list::subtract(&list::intersect(&zero_all, &p_used), &p_zero);
            marks.extend(TaggedRange::tag_all(list::union(&unzeroed, &zeroed), Reason::ZeroChanged));
            marks.extend(TaggedRange::tag_all(list::subtract(&used, &p_used), Reason::NewAlloc));
        }
    }
    let mut by: BTreeMap<Reason, Vec<ByteRange>> = BTreeMap::new();
    for t in sweep(&marks) {
        by.entry(t.reason).or_default().push(t.range());
    }
    let (mut dirty, mut zero) = (Vec::new(), Vec::new());
    for (reason, v) in by {
        let v = list::intersect(&norm(v), &used);
        dirty.extend(TaggedRange::tag_all(list::subtract(&v, &zero_all), reason));
        zero.extend(TaggedRange::tag_all(list::intersect(&v, &zero_all), reason));
    }
    dirty.sort_by_key(|t| t.offset);
    zero.sort_by_key(|t| t.offset);
    Cbt { dirty, zero, zero_all, freed, unclaimed, tracked, data, used, degraded }
}

/// `marks` without overlaps: where they overlap the lower reason wins; adjacent ones of the
/// same reason are merged.
fn sweep(marks: &[TaggedRange]) -> Vec<TaggedRange> {
    let mut ev: Vec<(u64, bool, Reason)> = marks
        .iter()
        .filter(|t| t.length > 0)
        .flat_map(|t| [(t.offset, true, t.reason), (t.end(), false, t.reason)])
        .collect();
    ev.sort_unstable_by_key(|e| e.0);
    let mut active: BTreeMap<Reason, usize> = BTreeMap::new();
    let mut out: Vec<TaggedRange> = Vec::new();
    let mut at = 0;
    for (pos, start, reason) in ev {
        if let Some((&r, _)) = active.first_key_value()
            && pos > at
        {
            match out.last_mut() {
                Some(l) if l.end() == at && l.reason == r => l.length += pos - at,
                _ => out.push(TaggedRange { offset: at, length: pos - at, reason: r }),
            }
        }
        at = pos;
        let n = active.entry(reason).or_default();
        if start {
            *n += 1;
        } else {
            *n -= 1;
            if *n == 0 {
                active.remove(&reason);
            }
        }
    }
    out
}
