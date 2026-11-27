//! Offline checker for reading only the index blocks that may have changed (research tool,
//! `#[ignore]`d): for pairs of snapshots (prev, cur) of a real NTFS volume, which index blocks
//! changed (every block of both read), which candidate sets of indexes hold all of them, and
//! what each set would read.
//!
//! ```sh
//! FSI_INDEX_PAIRS=pairs.txt cargo test -p fs-inspect-ntfs --release --lib index_pairs -- --ignored --nocapture
//! ```
//!
//! `pairs.txt`: one pair per line, `LABEL<TAB>PREV<TAB>CUR` (images or devices, such as a VSS
//! shadow copy device, `PATH@OFFSET` for the volume at that byte offset of a disk image: only
//! the volume's structures are read, never its last sector); `#` starts a comment. One JSON
//! line per pair goes to stdout (also to `FSI_INDEX_OUT`, appended, when set): the MFT and
//! index sizes, the index bytes per kind (`cost`: bytes, bytes
//! changed), the journal over the interval, and per candidate set the directories in it, the
//! bytes it reads and its misses (changed blocks outside it) and moved indexes (runlist not the
//! previous one, outside it). Then the first misses of each set with what changed in the block:
//! entries added (`+`), removed (`-`) or changed (`~`, with the child's `$SI` times in both),
//! `*` when the child's record changed. `FSI_INDEX_DUMP_USN` also prints the interval's USN
//! records.
//!
//! The candidate sets, each with the system indexes (`$Secure`, `$Extend` and the directories
//! under it, records below `FIRST_USER` but the root) always read:
//! - `usn`: directories whose records changed (base or extension), the parents (`$FILE_NAME` in
//!   cur) of every file whose record changed, and the parents of every USN record of the
//!   interval (with the parents of their files in cur); `None` when the journal is not
//!   continuous.
//! - `usn_only`: the USN records' parents and files alone.
//! - `mft`: by MFT chunk (what the driver knows from its digests): directories with a record in
//!   a changed chunk and the parents, in cur and in prev, of every file with a record in one.
//! - `mft_rec`: as `mft`, by record.
//! - `mft_cur`: as `mft`, the parents in cur only (no parents kept from prev).
//! - `stale`: the directories of prev with an entry whose duplicated information is not its
//!   child's record's ([`stale_dirs`]); `usn+stale`, `mft+stale`, `mft_rec+stale`: with it.

use crate::format::attr::{FileName, RawAttrBody};
use crate::format::index::{parse_index_block, parse_index_root};
use crate::format::volume::map_stream_bytes;
use crate::track::usn;
use crate::{AttrType, NtfsVolume, Run, system_records};
use fs_inspect_change::hash::hash_bytes;
use fs_inspect_core::ByteRange;
use fs_inspect_io::FileSource;
use fs_inspect_io::batch::{BATCH_BYTES, GAP_BYTES, plan, read_runs};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;
use std::sync::Arc;
use std::time::Instant;

#[derive(Debug, Clone, Default)]
struct Rec {
    hash: u64,
    in_use: bool,
    /// The base record (itself for a base record).
    base: u64,
    /// `$FILE_NAME` parents in this record.
    parents: Vec<u64>,
    /// `$STANDARD_INFORMATION` times (created, modified, changed, accessed) of a base record.
    si: Option<[u64; 4]>,
    /// The size of the unnamed `$DATA` when its first fragment is in this record (non-resident).
    size: Option<u64>,
}

#[derive(Debug, Clone)]
struct Index {
    base: u64,
    name: Vec<u16>,
    runs: Vec<Run>,
    bs: u64,
}

struct Image {
    vol: NtfsVolume,
    recs: Vec<Rec>,
    chunks: Vec<u64>,
    indexes: Vec<Index>,
    /// Parents of each file (base record), from every record of it.
    parents: HashMap<u64, BTreeSet<u64>>,
    journal: Option<(usn::UsnJournal, usn::UsnState)>,
    mft_bytes: u64,
}

fn open(path: &str) -> Image {
    // `PATH@OFFSET`: the volume at that byte offset of a disk image.
    let (file, offset) = match path.rsplit_once('@') {
        Some((f, o)) if o.parse::<u64>().is_ok() => (f, o.parse::<u64>().unwrap_or(0)),
        _ => (path, 0),
    };
    let f = FileSource::open(file).unwrap_or_else(|e| panic!("{path}: {e}"));
    let src: fs_inspect_io::DynSource = if offset == 0 {
        Arc::new(f)
    } else {
        let len = fs_inspect_io::BlockSource::size(&f) - offset;
        Arc::new(fs_inspect_io::OffsetSource::new(f, offset, len).unwrap())
    };
    let vol = NtfsVolume::open(src).unwrap_or_else(|e| panic!("{path}: {e}"));
    let mft = vol.mft();
    let rs = u64::from(mft.record_size);
    let mut recs = vec![Rec::default(); mft.record_count as usize];
    let mut chunks = vec![0u64; (mft.record_count * rs).div_ceil(vol.mft_chunk()) as usize];
    let mut roots: BTreeMap<(u64, Vec<u16>), u32> = BTreeMap::new();
    let mut found: Vec<(u64, Vec<u16>, Vec<Run>)> = Vec::new();
    let mut mft_bytes = 0u64;
    let chunk = vol.mft_chunk();
    vol.mft_chunks(&mut |c, data| {
        let Some((_, raw)) = data else { return Ok(()) };
        mft_bytes += raw.len() as u64;
        chunks[c as usize] = hash_bytes(b"chunk", raw);
        let first = c * chunk / rs;
        for (i, r) in raw.chunks_exact(rs as usize).enumerate() {
            if let Some(x) = recs.get_mut(first as usize + i) {
                x.hash = hash_bytes(b"rec", r);
            }
        }
        for (i, p) in vol.parse_chunk(first, raw).into_iter().enumerate() {
            let n = first + i as u64;
            let Some(p) = p else { continue };
            let Some(x) = recs.get_mut(n as usize) else { continue };
            x.in_use = p.header.in_use();
            x.base = if p.header.is_extension() { p.header.base_record.record } else { n };
            for a in &p.attributes {
                match (&a.body, a.kind) {
                    (RawAttrBody::Resident { data, .. }, AttrType::STANDARD_INFORMATION) => {
                        if let Ok(i) = crate::format::attr::StdInfo::parse(data) {
                            x.si = Some([i.created, i.modified, i.mft_changed, i.accessed]);
                        }
                    }
                    (RawAttrBody::NonResident(h), AttrType::DATA) if a.name.units().is_empty() && h.lowest_vcn == 0 => {
                        x.size = Some(h.size);
                    }
                    (RawAttrBody::Resident { data, .. }, AttrType::FILE_NAME) => {
                        if let Ok(f) = FileName::parse(data) {
                            x.parents.push(f.parent.record);
                        }
                    }
                    (RawAttrBody::Resident { data, .. }, AttrType::INDEX_ROOT) if x.in_use => {
                        if let Ok((info, _)) = parse_index_root(data) {
                            roots.insert((x.base, a.name.units().to_vec()), info.block_size);
                        }
                    }
                    (RawAttrBody::NonResident(h), AttrType::INDEX_ALLOCATION) if x.in_use => {
                        if let Ok(runs) = &h.runs {
                            found.push((x.base, a.name.units().to_vec(), runs.clone()));
                        }
                    }
                    _ => {}
                }
            }
            x.parents.sort_unstable();
            x.parents.dedup();
        }
        Ok(())
    })
    .unwrap();
    // An index split over records (attribute list): its fragments in VCN order.
    let mut by: BTreeMap<(u64, Vec<u16>), Vec<Run>> = BTreeMap::new();
    for (b, n, r) in found {
        by.entry((b, n)).or_default().extend(r);
    }
    let indexes = by
        .into_iter()
        .map(|((base, name), mut runs)| {
            runs.sort_by_key(Run::vcn);
            let bs = u64::from(roots.get(&(base, name.clone())).copied().unwrap_or(4096));
            Index { base, name, runs, bs }
        })
        .collect();
    let mut parents: HashMap<u64, BTreeSet<u64>> = HashMap::new();
    for r in &recs {
        if r.in_use {
            parents.entry(r.base).or_default().extend(&r.parents);
        }
    }
    let journal = usn::find_journal(&vol).ok().flatten().and_then(|j| {
        let s = usn::state_of(&vol, &j).ok()?;
        Some((j, s))
    });
    Image { vol, recs, chunks, indexes, parents, journal, mft_bytes }
}

impl Image {
    /// The parents of the file whose record is `n` here: of its base record as in use, or the
    /// stale names of a record no longer in use.
    fn parents_of(&self, n: u64, out: &mut BTreeSet<u64>) {
        let Some(r) = self.recs.get(n as usize) else { return };
        if let Some(p) = self.parents.get(&r.base) {
            out.extend(p);
        }
        out.extend(&r.parents);
    }

    fn base_of(&self, n: u64) -> Option<u64> {
        self.recs.get(n as usize).map(|r| r.base)
    }

    /// Whether `d` is a system index owner: below `FIRST_USER`, or `$Extend` or under it.
    fn system(&self, d: u64) -> bool {
        if d < system_records::FIRST_USER {
            return d != system_records::ROOT;
        }
        let mut x = d;
        for _ in 0..8 {
            let Some(&p) = self.parents.get(&x).and_then(|p| p.first()) else { return false };
            if p == system_records::EXTEND {
                return true;
            }
            if p == x || p < system_records::FIRST_USER {
                return false;
            }
            x = p;
        }
        false
    }

    fn category(&self, i: &Index) -> &'static str {
        let name = String::from_utf16_lossy(&i.name);
        match i.base {
            system_records::SECURE => "secure",
            system_records::ROOT => "dir",
            system_records::EXTEND => "extend-dir",
            b if b < system_records::FIRST_USER => "system-other",
            b if self.system(b) => match name.as_str() {
                "$I30" => "extend-dir",
                _ => "extend-index",
            },
            _ => "dir",
        }
    }
}

/// The directories of `img` with an entry in an index block whose duplicated information (times,
/// and the size of a file whose unnamed `$DATA` is non-resident in its base record) differs
/// from the child's record: NTFS writes those entries later (at the close of the file). Also
/// how many entries were compared and how many differ.
fn stale_dirs(img: &Image) -> (BTreeSet<u64>, u64, u64) {
    let g = img.vol.geometry();
    let cs = u64::from(g.cluster_size);
    let mut items: Vec<(usize, Vec<ByteRange>, u64)> = Vec::new();
    for (k, ix) in img.indexes.iter().enumerate() {
        if ix.name != [0x24u16, 0x49, 0x33, 0x30] || !ix.bs.is_power_of_two() || !(512..=65536).contains(&ix.bs) {
            continue;
        }
        let (Some(first), Some(last)) = (ix.runs.first(), ix.runs.last()) else { continue };
        let (start, end) = ((first.vcn() * cs).next_multiple_of(ix.bs), last.end_vcn() * cs);
        for logical in (start..end.saturating_sub(ix.bs - 1)).step_by(ix.bs as usize) {
            if let Some(p) = map_stream_bytes(&ix.runs, g.cluster_size, logical, ix.bs) {
                items.push((k, p, logical));
            }
        }
    }
    let (mut out, mut compared, mut differ) = (BTreeSet::new(), 0u64, 0u64);
    for (k, pieces, logical) in items {
        let ix = &img.indexes[k];
        let mut raw = read_raw(&img.vol, &pieces);
        let unit = img.vol.index_block_unit(ix.bs as u32);
        let Ok((entries, _)) = parse_index_block(&mut raw, logical / unit) else { continue };
        for e in entries {
            let Some(f) = e.file_name() else { continue };
            let Some(r) = img.recs.get(e.frn.record as usize) else { continue };
            if !r.in_use || r.base != e.frn.record {
                continue;
            }
            let Some(si) = r.si else { continue };
            compared += 1;
            let mut same = [f.created, f.modified, f.mft_changed, f.accessed] == si;
            if f.attributes & 0x1000_0000 == 0
                && let Some(size) = r.size
            {
                same &= f.size == size;
            }
            if !same {
                differ += 1;
                out.insert(ix.base);
            }
        }
    }
    (out, compared, differ)
}

/// A block of an index of cur, read in both images.
struct Block {
    index: usize,
    logical: u64,
    pieces: Vec<ByteRange>,
    cur: u64,
    prev: u64,
}

fn read_hashes(vol: &NtfsVolume, blocks: &[(usize, Vec<ByteRange>)], out: &mut [u64]) {
    let src = &**vol.source();
    let mut items = Vec::new();
    for (k, (_, pieces)) in blocks.iter().enumerate() {
        match pieces[..] {
            [p] => items.push((p.offset, p.length, k)),
            _ => {
                let mut buf = Vec::new();
                for p in pieces {
                    let at = buf.len();
                    buf.resize(at + p.length as usize, 0);
                    if src.read_exact_at(p.offset, &mut buf[at..]).is_err() {
                        buf.clear();
                        break;
                    }
                }
                out[k] = hash_bytes(b"blk", &buf);
            }
        }
    }
    read_runs::<_, fs_inspect_core::Error>(src, plan(items, BATCH_BYTES, GAP_BYTES), &mut |k, raw| {
        out[k] = raw.map_or(1, |r| hash_bytes(b"blk", r));
        Ok(())
    })
    .unwrap();
}

fn read_raw(vol: &NtfsVolume, pieces: &[ByteRange]) -> Vec<u8> {
    let mut buf = Vec::new();
    for p in pieces {
        let at = buf.len();
        buf.resize(at + p.length as usize, 0);
        let _ = vol.source().read_exact_at(p.offset, &mut buf[at..]);
    }
    buf
}

/// What differs between two versions of an index block: entries added, removed, changed.
fn block_diff(prev: &NtfsVolume, cur: &NtfsVolume, b: &Block, unit: u64, changed: &dyn Fn(u64) -> bool) -> String {
    let (mut p, mut c) = (read_raw(prev, &b.pieces), read_raw(cur, &b.pieces));
    let lsn = |x: &[u8]| x.get(8..16).map(|s| u64::from_le_bytes(s.try_into().unwrap())).unwrap_or(0);
    let mut s = format!("lsn {:#x} -> {:#x}; ", lsn(&p), lsn(&c));
    let vcn = b.logical / unit;
    let ents = |x: &mut [u8]| -> Option<BTreeMap<(u64, String), String>> {
        let (e, _) = parse_index_block(x, vcn).ok()?;
        Some(
            e.iter()
                .map(|e| match e.file_name() {
                    Some(f) => (
                        (e.frn.record, f.name.to_string_lossy()),
                        format!(
                            "seq {} sz {} alloc {} m {} a {} c {} attr {:#x}",
                            e.frn.seq, f.size, f.allocated, f.modified, f.accessed, f.mft_changed, f.attributes
                        ),
                    ),
                    None => ((e.frn.record, format!("key{:02x?}", &e.key[..e.key.len().min(16)])), String::new()),
                })
                .collect(),
        )
    };
    let star = |r: u64| if changed(r) { "*" } else { "" };
    match (ents(&mut p), ents(&mut c)) {
        (Some(a), Some(b)) => {
            for (k, v) in &a {
                match b.get(k) {
                    None => {
                        let _ = write!(s, "-{}{}:{} ", star(k.0), k.0, k.1);
                    }
                    Some(w) if w != v => {
                        let si = |vol: &NtfsVolume| {
                            vol.entry(k.0)
                                .ok()
                                .flatten()
                                .and_then(|e| e.std_info)
                                .map(|i| (i.modified, i.accessed, i.mft_changed))
                        };
                        let _ = write!(
                            s,
                            "~{}{}:{} [{v}] -> [{w}] $SI(m,a,c) prev {:?} cur {:?} ",
                            star(k.0),
                            k.0,
                            k.1,
                            si(prev),
                            si(cur)
                        );
                    }
                    _ => {}
                }
            }
            for k in b.keys().filter(|k| !a.contains_key(*k)) {
                let _ = write!(s, "+{}{}:{} ", star(k.0), k.0, k.1);
            }
        }
        (a, b) => {
            let _ = write!(s, "parse prev {} cur {}", a.is_some(), b.is_some());
        }
    }
    s
}

#[test]
#[ignore = "research tool: needs FSI_INDEX_PAIRS"]
fn index_pairs() {
    let list = std::env::var("FSI_INDEX_PAIRS").expect("FSI_INDEX_PAIRS");
    let text = std::fs::read_to_string(&list).unwrap();
    let mut cache: Option<(String, Image)> = None;
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let f: Vec<&str> = line.split('\t').collect();
        let (label, prev_path, cur_path) = (f[0], f[1], f[2]);
        let t0 = Instant::now();
        let prev = match cache.take() {
            Some((p, img)) if p == prev_path => img,
            _ => open(prev_path),
        };
        let cur = open(cur_path);
        let t_open = t0.elapsed().as_secs_f64();
        let out = check(label, &prev, &cur, t_open);
        println!("{out}");
        if let Ok(o) = std::env::var("FSI_INDEX_OUT") {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new().create(true).append(true).open(o).unwrap();
            writeln!(f, "{out}").unwrap();
        }
        cache = Some((cur_path.to_string(), cur));
    }
}

fn check(label: &str, prev: &Image, cur: &Image, t_open: f64) -> String {
    let t0 = Instant::now();
    let g = cur.vol.geometry();
    let cs = u64::from(g.cluster_size);
    let rs = u64::from(cur.vol.mft().record_size);
    let per_chunk = cur.vol.mft_chunk() / rs;
    let n = cur.recs.len().max(prev.recs.len()) as u64;
    let hash = |img: &Image, i: u64| img.recs.get(i as usize).map(|r| (r.hash, r.in_use));
    let changed_rec: Vec<u64> = (0..n).filter(|&i| hash(prev, i) != hash(cur, i)).collect();
    let nchunks = cur.chunks.len().max(prev.chunks.len());
    let changed_chunk: Vec<u64> =
        (0..nchunks as u64).filter(|&c| prev.chunks.get(c as usize) != cur.chunks.get(c as usize)).collect();
    let in_chunks: Vec<u64> = changed_chunk.iter().flat_map(|&c| c * per_chunk..((c + 1) * per_chunk).min(n)).collect();

    // Owners and parents of a set of changed records.
    let own_and_parents = |recs: &[u64], with_prev: bool| -> BTreeSet<u64> {
        let mut s = BTreeSet::new();
        for &r in recs {
            for b in [cur.base_of(r), prev.base_of(r)].into_iter().flatten() {
                s.insert(b);
                cur.parents_of(b, &mut s);
                if with_prev {
                    prev.parents_of(b, &mut s);
                }
            }
            cur.parents_of(r, &mut s);
            if with_prev {
                prev.parents_of(r, &mut s);
            }
        }
        s
    };
    // `usn` candidate: changed records with cur parents only, plus the journal.
    let mut journal = String::from("none");
    let mut usn_only = BTreeSet::new();
    let usn_set = match (&prev.journal, &cur.journal) {
        (Some((_, ps)), Some((cj, cst))) => {
            let status = usn::continuity(ps, cst);
            if status == usn::UsnStatus::Ok {
                let mut s = own_and_parents(&changed_rec, false);
                let mut count = 0u64;
                let stats = usn::read_usn_range(&cur.vol, cj, ps.next_usn, cst.next_usn, None, &mut |r| {
                    count += 1;
                    if std::env::var_os("FSI_INDEX_DUMP_USN").is_some() {
                        println!(
                            "  usn {} frn {} parent {} reason {:#x} {}",
                            r.usn,
                            r.frn.record,
                            r.parent.record,
                            r.reason,
                            String::from_utf16_lossy(&r.name)
                        );
                    }
                    usn_only.insert(r.parent.record);
                    usn_only.insert(r.frn.record);
                    s.insert(r.parent.record);
                    s.insert(r.frn.record);
                    cur.parents_of(r.frn.record, &mut s);
                    true
                });
                journal = format!(
                    "ok {} records {} bytes clean {}",
                    count,
                    cst.next_usn - ps.next_usn,
                    stats.as_ref().is_ok_and(|s| s.clean())
                );
                stats.is_ok().then_some(s)
            } else {
                journal = format!("{status:?}");
                None
            }
        }
        (p, c) => {
            let _ = write!(journal, " (prev {}, cur {})", p.is_some(), c.is_some());
            None
        }
    };
    let usn_only = usn_set.is_some().then_some(usn_only);
    let (stale, compared, differ) = stale_dirs(prev);
    let with_stale =
        |s: &Option<BTreeSet<u64>>| s.as_ref().map(|s| s.union(&stale).copied().collect::<BTreeSet<u64>>());
    let mft = Some(own_and_parents(&in_chunks, true));
    let mft_rec = Some(own_and_parents(&changed_rec, true));
    let sets: Vec<(&str, Option<BTreeSet<u64>>)> = vec![
        ("usn+stale", with_stale(&usn_set)),
        ("mft+stale", with_stale(&mft)),
        ("mft_rec+stale", with_stale(&mft_rec)),
        ("stale", Some(stale.clone())),
        ("usn", usn_set),
        ("usn_only", usn_only),
        ("mft", mft),
        ("mft_rec", mft_rec),
        ("mft_cur", Some(own_and_parents(&in_chunks, false))),
    ];

    // Every block of every index of cur, read in both.
    let mut list: Vec<(usize, Vec<ByteRange>)> = Vec::new();
    let mut logicals = Vec::new();
    for (k, ix) in cur.indexes.iter().enumerate() {
        if !ix.bs.is_power_of_two() || !(512..=65536).contains(&ix.bs) {
            continue;
        }
        let (Some(first), Some(last)) = (ix.runs.first(), ix.runs.last()) else { continue };
        let (start, end) = ((first.vcn() * cs).next_multiple_of(ix.bs), last.end_vcn() * cs);
        for logical in (start..end.saturating_sub(ix.bs - 1)).step_by(ix.bs as usize) {
            if let Some(p) = map_stream_bytes(&ix.runs, g.cluster_size, logical, ix.bs) {
                list.push((k, p));
                logicals.push(logical);
            }
        }
    }
    let mut hc = vec![0u64; list.len()];
    let mut hp = vec![0u64; list.len()];
    let t_read = Instant::now();
    read_hashes(&cur.vol, &list, &mut hc);
    let t_cur = t_read.elapsed().as_secs_f64();
    read_hashes(&prev.vol, &list, &mut hp);
    let blocks: Vec<Block> = list
        .into_iter()
        .zip(logicals)
        .zip(hc.into_iter().zip(hp))
        .map(|(((index, pieces), logical), (cur, prev))| Block { index, logical, pieces, cur, prev })
        .collect();

    // Cost per category, changed blocks.
    let mut cost: BTreeMap<&str, (u64, u64)> = BTreeMap::new();
    let mut index_bytes = vec![0u64; cur.indexes.len()];
    let (mut total, mut changed_bytes, mut changed_blocks) = (0u64, 0u64, 0u64);
    for b in &blocks {
        let ix = &cur.indexes[b.index];
        let e = cost.entry(cur.category(ix)).or_default();
        e.0 += ix.bs;
        index_bytes[b.index] += ix.bs;
        total += ix.bs;
        if b.cur != b.prev {
            e.1 += ix.bs;
            changed_bytes += ix.bs;
            changed_blocks += 1;
        }
    }
    let prev_runs: BTreeMap<(u64, &[u16]), &[Run]> =
        prev.indexes.iter().map(|i| ((i.base, &i.name[..]), &i.runs[..])).collect();
    let mut out = format!(
        "{{\"pair\":\"{label}\",\"records\":{n},\"changed_records\":{},\"mft_chunks\":{nchunks},\"changed_chunks\":{},\
         \"mft_bytes\":{},\"indexes\":{},\"index_bytes\":{total},\"blocks\":{},\"changed_blocks\":{changed_blocks},\
         \"changed_bytes\":{changed_bytes},\"journal\":\"{journal}\",\"stale_entries\":[{compared},{differ}],\"cost\":{{",
        changed_rec.len(),
        changed_chunk.len(),
        cur.mft_bytes,
        cur.indexes.len(),
        blocks.len()
    );
    for (i, (k, (b, c))) in cost.iter().enumerate() {
        let _ = write!(out, "{}\"{k}\":[{b},{c}]", if i > 0 { "," } else { "" });
    }
    out.push_str("},\"sets\":{");
    let mut details = String::new();
    for (si, (name, set)) in sets.iter().enumerate() {
        let _ = write!(out, "{}\"{name}\":", if si > 0 { "," } else { "" });
        let Some(set) = set else {
            out.push_str("null");
            continue;
        };
        let cand = |k: usize| {
            let ix = &cur.indexes[k];
            set.contains(&ix.base) || cur.system(ix.base)
        };
        let read: u64 = (0..cur.indexes.len()).filter(|&k| cand(k)).map(|k| index_bytes[k]).sum();
        let ndirs = (0..cur.indexes.len()).filter(|&k| cand(k)).count();
        let (mut misses, mut moved) = (0u64, 0u64);
        for k in (0..cur.indexes.len()).filter(|&k| !cand(k)) {
            let ix = &cur.indexes[k];
            if prev_runs.get(&(ix.base, &ix.name[..])) != Some(&&ix.runs[..]) {
                moved += 1;
                let _ = writeln!(details, "  {label} {name} MOVED index {} runs differ", ix.base);
            }
        }
        for b in blocks.iter().filter(|b| b.cur != b.prev && !cand(b.index)) {
            misses += 1;
            let ix = &cur.indexes[b.index];
            if misses <= 20 {
                let unit = cur.vol.index_block_unit(ix.bs as u32);
                let _ = writeln!(
                    details,
                    "  {label} {name} MISS index {} {} block {} at {:#x}: {}",
                    ix.base,
                    String::from_utf16_lossy(&ix.name),
                    b.logical / unit,
                    b.pieces[0].offset,
                    block_diff(&prev.vol, &cur.vol, b, unit, &|r| changed_rec.binary_search(&r).is_ok())
                );
            }
        }
        let _ = write!(
            out,
            "{{\"dirs\":{},\"indexes\":{ndirs},\"read\":{read},\"misses\":{misses},\"moved\":{moved}}}",
            set.len()
        );
    }
    let _ = write!(
        out,
        "}},\"secs\":{{\"open\":{t_open:.1},\"read_cur_indexes\":{t_cur:.1},\"check\":{:.1}}}}}",
        t0.elapsed().as_secs_f64()
    );
    if !details.is_empty() {
        out.push('\n');
        out.push_str(details.trim_end());
    }
    out
}
