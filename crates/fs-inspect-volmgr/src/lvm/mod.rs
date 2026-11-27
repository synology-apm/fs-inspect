//! LVM2: physical volume labels, metadata areas and the volume group text they hold.
//!
//! A PV has a label in one of its first four sectors (`LABELONE`, checksummed), then a PV
//! header with its UUID and the offsets of its data and metadata areas. Each metadata area
//! starts with a checksummed header whose first raw location points at the committed text of
//! the volume group, in a circular buffer after the header. Every PV with a metadata area
//! keeps a copy; the valid copy with the highest `seqno` wins.
//!
//! Mapped: logical volumes made of `striped` segments (linear when `stripe_count` is 1) and of
//! `mirror`, `raid0`, `raid1`, `raid4`, `raid5*`, `raid6*` and `raid10` (near copies) segments
//! whose images are linear LVs (`raid_segments`), unless being reshaped. Every other segment
//! type (thin*, cache*, snapshot, vdo, writecache, integrity) and every hidden LV (the images
//! and metadata sub-volumes) only mark the extents they use as data, unless a mapped volume
//! covers them. A PV UUID found on two slots (a cloned disk) is the first of them, as LVM
//! itself picks one; the other is not claimed (`DuplicateMember`).
//!
//! Sync state ([`Container::unsynced`]): a mirror or RAID volume is in sync when every dm-raid
//! metadata image (`*_rmeta_*`) has no device failed, no resync or recovery pending and a
//! current write-intent bitmap without a bit set, and every `mirror` segment's disk log marks
//! all its regions clean. Otherwise (a core log, a log or metadata image that cannot be read)
//! its whole footprint is out of sync.

use fs_inspect_core::DiagnosticExt;
mod label;
mod raid;
mod sync;
pub mod text;

pub(crate) use label::damaged;
use label::read_mda;
pub use label::{PvLabel, read_label};
use raid::{raid_name, raid_segments};
use sync::lv_in_sync;

use crate::map::{Area, Layout, LogicalMap, Segment};
use crate::{Container, LogicalDef, Member, MemberRole, Readability, Slot, VolumeManager, status_of};
use fs_inspect_core::{ByteRange, DiagCode, Diagnostic, Error, Limits, Result};
use std::collections::HashMap;
use std::sync::Arc;
use text::{Section, Value};

const SECTOR: u64 = 512;

fn strip_uuid(s: &str) -> String {
    s.chars().filter(|c| *c != '-').collect()
}

/// A parsed copy of a volume group's metadata.
struct VgCopy {
    name: String,
    id: String,
    seqno: u64,
    vg: Section,
}

fn parse_copy(text: &[u8], limits: &Limits) -> Result<VgCopy> {
    let top = text::parse(text, limits.max_tree_depth.min(32), limits.max_tree_nodes)?;
    let (name, vg) = top
        .sections()
        .next()
        .map(|(n, s)| (n.to_string(), s.clone()))
        .ok_or_else(|| Error::corrupt("LVM metadata without a volume group"))?;
    let id = vg.str("id").ok_or_else(|| Error::corrupt("LVM volume group without id"))?.to_string();
    Ok(VgCopy { name, id, seqno: vg.uint("seqno")?, vg })
}

/// Assemble the volume groups of the slots not in `taken`.
pub fn assemble(
    slots: &[Slot],
    taken: &[usize],
    limits: &Limits,
    unreadable: &mut Vec<(usize, Error)>,
) -> Vec<Container> {
    // PV labels, and every readable metadata copy.
    let mut labels: Vec<(usize, PvLabel)> = Vec::new();
    let mut copies: Vec<VgCopy> = Vec::new();
    let mut damaged: HashMap<usize, Vec<String>> = HashMap::new();
    for (i, s) in slots.iter().enumerate() {
        if taken.contains(&i) || s.has_fs {
            continue;
        }
        let label = match read_label(&*s.source) {
            Ok(Some(l)) => l,
            Ok(None) => continue,
            Err(e) => {
                unreadable.push((i, e.context("LVM label")));
                continue;
            }
        };
        for &(o, sz) in &label.mdas {
            match read_mda(&*s.source, o, sz).and_then(|t| t.map(|t| parse_copy(&t, limits)).transpose()) {
                Ok(Some(c)) => copies.push(c),
                Ok(None) => {}
                Err(e) => damaged.entry(i).or_default().push(format!("metadata area at {o}: {e}")),
            }
        }
        labels.push((i, label));
    }
    // A PV UUID on two slots (a cloned disk): neither is claimed.
    let mut by_uuid: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, l) in &labels {
        by_uuid.entry(l.uuid.clone()).or_default().push(*i);
    }
    // The newest copy of each volume group.
    let mut newest: HashMap<String, VgCopy> = HashMap::new();
    let mut older: HashMap<String, usize> = HashMap::new();
    for c in copies {
        match newest.get(&c.id) {
            Some(n) if n.seqno >= c.seqno => {
                if n.seqno > c.seqno {
                    *older.entry(c.id.clone()).or_default() += 1;
                }
            }
            _ => {
                if newest.contains_key(&c.id) {
                    *older.entry(c.id.clone()).or_default() += 1;
                }
                newest.insert(c.id.clone(), c);
            }
        }
    }
    let mut out = Vec::new();
    let mut ids: Vec<_> = newest.keys().cloned().collect();
    ids.sort();
    for id in ids {
        let c = &newest[&id];
        let mut notes = Vec::new();
        if let Some(n) = older.get(&id) {
            notes.push(Diagnostic::info(
                DiagCode::BackupUsed,
                format!("LVM volume group {}: {n} older metadata copies ignored (seqno {})", c.name, c.seqno),
            ));
        }
        match build_vg(c, slots, &labels, &by_uuid, limits, &mut notes) {
            Ok(mut cont) => {
                for m in &cont.members {
                    if let Some(errs) = m.slot.and_then(|s| damaged.get(&s)) {
                        for e in errs {
                            cont.notes.push(Diagnostic::warning(
                                DiagCode::ChecksumMismatch,
                                format!("LVM PV {}: {e}", m.role),
                            ));
                        }
                    }
                }
                cont.notes.splice(0..0, notes);
                out.push(cont);
            }
            Err(e) => tracing::warn!(vg = %c.name, error = %e, "LVM volume group not assembled"),
        }
    }
    out
}

fn build_vg(
    c: &VgCopy,
    slots: &[Slot],
    labels: &[(usize, PvLabel)],
    by_uuid: &HashMap<String, Vec<usize>>,
    limits: &Limits,
    notes: &mut Vec<Diagnostic>,
) -> Result<Container> {
    let vg = &c.vg;
    let ext = vg
        .uint("extent_size")?
        .checked_mul(SECTOR)
        .filter(|&e| e > 0)
        .ok_or_else(|| Error::corrupt("bad extent_size"))?;
    let pvs = Pvs::of(c, slots, labels, by_uuid, ext, notes)?;
    let lvs = vg.section("logical_volumes");
    let runs = linear_runs(lvs, &pvs);
    let mut b = VgBuild { vg: c, slots, pvs: &pvs, runs: &runs, limits, opaque: Vec::new(), unsynced: Vec::new() };
    let mut volumes = Vec::new();
    for (name, lv) in lvs.into_iter().flat_map(|s| s.sections()) {
        if let Some(v) = b.logical_volume(name, lv, notes)? {
            volumes.push(v);
        }
    }
    let VgBuild { opaque, unsynced, .. } = b;
    // Opaque: everything any LV uses, minus what readable mapped volumes cover (projected).
    let opaque = crate::uncovered(opaque, &volumes);
    let Pvs { members, metadata, .. } = pvs;
    let status = status_of(&members, &volumes);
    Ok(Container {
        kind: VolumeManager::Lvm,
        name: c.name.clone(),
        uuid: c.id.clone(),
        members,
        volumes,
        metadata,
        opaque,
        unsynced,
        status,
        notes: Vec::new(),
    })
}

/// The physical volumes of a volume group: its members, with where each one's extents start
/// and its label and metadata areas.
struct Pvs<'a> {
    members: Vec<Member>,
    /// Member index by PV name.
    index: HashMap<&'a str, usize>,
    pe_start: Vec<u64>,
    metadata: Vec<(usize, ByteRange)>,
    /// Extent size (bytes).
    ext: u64,
}

impl<'a> Pvs<'a> {
    fn of(
        c: &'a VgCopy,
        slots: &[Slot],
        labels: &[(usize, PvLabel)],
        by_uuid: &HashMap<String, Vec<usize>>,
        ext: u64,
        notes: &mut Vec<Diagnostic>,
    ) -> Result<Pvs<'a>> {
        let sec = c.vg.section("physical_volumes").ok_or_else(|| Error::corrupt("no physical_volumes"))?;
        let mut p = Pvs { members: Vec::new(), index: HashMap::new(), pe_start: Vec::new(), metadata: Vec::new(), ext };
        for (name, pv) in sec.sections() {
            if p.members.len() >= crate::MAX_MEMBERS {
                return Err(Error::limit("too many PVs"));
            }
            let uuid = strip_uuid(pv.str("id").unwrap_or(""));
            let found = by_uuid.get(&uuid).map(Vec::as_slice).unwrap_or(&[]);
            let slot = match found {
                [one] => Some(*one),
                [] => None,
                [first, ..] => {
                    notes.push(Diagnostic::warning(
                        DiagCode::DuplicateMember,
                        format!("LVM PV {name} ({uuid}) is on {} disks (a clone?); the first is used", found.len()),
                    ));
                    Some(*first)
                }
            };
            let start = pv.uint("pe_start")?.checked_mul(SECTOR).ok_or_else(|| Error::corrupt("bad pe_start"))?;
            let ix = p.members.len();
            if let Some(s) = slot {
                // The label and every metadata area are data (pe_start covers the first ones).
                p.metadata.push((ix, ByteRange::new(0, start.min(slots[s].source.size()))));
                if let Some((_, l)) = labels.iter().find(|(i, _)| *i == s) {
                    p.metadata.push((ix, ByteRange::new(l.label_sector * SECTOR, SECTOR)));
                    p.metadata.extend(l.mdas.iter().map(|&(o, sz)| (ix, ByteRange::new(o, sz))));
                }
            }
            p.index.insert(name, ix);
            p.pe_start.push(start);
            p.members.push(Member { id: uuid, slot, role: MemberRole::Pv(name.to_string()) });
        }
        let missing: Vec<String> = p.members.iter().filter(|m| m.slot.is_none()).map(|m| m.role.to_string()).collect();
        if !missing.is_empty() {
            notes.push(Diagnostic::warning(
                DiagCode::ContainerIncomplete,
                format!("LVM volume group {}: PVs not found: {}", c.name, missing.join(", ")),
            ));
        }
        Ok(p)
    }

    /// Where extent `pe` of PV `pv` is.
    fn area(&self, pv: &str, pe: u64) -> Result<Area> {
        let m = *self.index.get(pv).ok_or_else(|| Error::corrupt(format!("segment on unknown PV {pv}")))?;
        let off = pe
            .checked_mul(self.ext)
            .and_then(|o| o.checked_add(self.pe_start[m]))
            .ok_or_else(|| Error::corrupt("extent overflows"))?;
        Ok(Area { member: m, start: off })
    }
}

/// Each linear LV's PV runs, in LV offsets: the images RAID and mirror LVs are made of.
fn linear_runs<'s>(lvs: Option<&'s Section>, pvs: &Pvs<'_>) -> HashMap<&'s str, Vec<Run>> {
    let mut runs = HashMap::new();
    for (name, lv) in lvs.into_iter().flat_map(|s| s.sections()) {
        let mut r = Vec::new();
        let linear = lv.sections().all(|(_, seg)| {
            let pairs = pv_pairs(seg, &pvs.index);
            let (Ok(st), Ok(n)) = (seg.uint("start_extent"), seg.uint("extent_count")) else { return false };
            match (seg.str("type"), seg.uint("stripe_count").unwrap_or(1), pairs.as_slice()) {
                (Some("striped"), 1, [(pv, pe)]) => match pvs.area(pv, *pe) {
                    Ok(a) => {
                        r.push((st.saturating_mul(pvs.ext), n.saturating_mul(pvs.ext), a));
                        true
                    }
                    Err(_) => false,
                },
                _ => false,
            }
        });
        if linear {
            r.sort_by_key(|x| x.0);
            runs.insert(name, r);
        }
    }
    runs
}

/// A volume group's logical volumes being mapped, and what they use besides.
struct VgBuild<'a> {
    vg: &'a VgCopy,
    slots: &'a [Slot],
    pvs: &'a Pvs<'a>,
    runs: &'a HashMap<&'a str, Vec<Run>>,
    limits: &'a Limits,
    /// What the LVs use on the PVs, mapped or not.
    opaque: Vec<(usize, ByteRange)>,
    /// Member bytes of redundant LVs whose copies are not known to agree.
    unsynced: Vec<(usize, ByteRange)>,
}

impl VgBuild<'_> {
    /// LV `name`'s definition (`None`: a sub-volume, its extents opaque unless a mapped volume
    /// covers them).
    fn logical_volume(&mut self, name: &str, lv: &Section, notes: &mut Vec<Diagnostic>) -> Result<Option<LogicalDef>> {
        let ext = self.pvs.ext;
        let mut segs = Vec::new();
        let mut kinds = Vec::new();
        let mut why_not: Option<String> = None;
        // Where the next RAID segment's part of each image starts.
        let mut next: HashMap<String, u64> = HashMap::new();
        let reshaping = ["status", "flags"]
            .iter()
            .any(|k| lv.list(k).is_some_and(|l| l.iter().any(|v| matches!(v, Value::Str(s) if s.contains("RESHAPE")))));
        for (_, seg) in lv.sections() {
            if segs.len() >= self.limits.max_file_extents.min(1 << 20) {
                return Err(Error::limit(format!("LV {name} has too many segments")));
            }
            let kind = seg.str("type").unwrap_or("?").to_string();
            let (start, count) = (seg.uint("start_extent")?, seg.uint("extent_count")?);
            let pairs = pv_pairs(seg, &self.pvs.index);
            // What it uses on the PVs, mapped or not.
            let per_area = if kind == "striped" { count.div_ceil(pairs.len().max(1) as u64) } else { count };
            for (pv, pe) in &pairs {
                let a = self.pvs.area(pv, *pe)?;
                self.opaque.push((a.member, ByteRange::new(a.start, per_area.saturating_mul(ext))));
            }
            let (s0, n0) = (start.saturating_mul(ext), count.saturating_mul(ext));
            if kind == "striped" && !pairs.is_empty() {
                segs.push(self.striped(name, seg, &pairs, s0, n0)?);
            } else if reshaping {
                why_not.get_or_insert_with(|| "being reshaped".into());
            } else {
                match raid_segments(&kind, seg, s0, n0, ext, self.runs, &mut next) {
                    Ok(pieces) => segs.extend(pieces),
                    Err(why) => {
                        why_not.get_or_insert(why);
                    }
                }
            }
            let shown = raid_name(&kind).unwrap_or(&kind).to_string();
            if !kinds.contains(&shown) {
                kinds.push(shown);
            }
        }
        if !lv.has_flag("status", "VISIBLE") {
            return Ok(None);
        }
        segs.sort_by_key(|s| s.start);
        let uuid = lv.str("id").unwrap_or("").to_string();
        if let Some(why) = why_not {
            let layout = kinds.join("+");
            notes.push(Diagnostic::warning(
                DiagCode::UnsupportedLayout,
                format!("LVM volume {}/{name} is {layout} ({why}): the space it uses counts as data", self.vg.name),
            ));
            return Ok(Some(LogicalDef {
                name: name.to_string(),
                uuid,
                layout,
                map: Arc::default(),
                readable: Readability::No,
            }));
        }
        let len = segs.last().map_or(0, |s| s.start + s.len);
        let map = LogicalMap { len, segments: segs };
        let members = &self.pvs.members;
        // A map that does not fit its PVs makes this LV unreadable (counted as data), not the
        // whole volume group.
        if let Err(e) = map
            .validate(&|m: usize| members.get(m).and_then(|x| x.slot).map(|s| self.slots[s].source.size()), usize::MAX)
        {
            notes.push(Diagnostic::warning(
                DiagCode::Inconsistent,
                format!("LVM volume {}/{name}: {e}; it counts as data", self.vg.name),
            ));
            return Ok(Some(LogicalDef {
                name: name.to_string(),
                uuid,
                layout: kinds.join("+"),
                map: Arc::default(),
                readable: Readability::No,
            }));
        }
        let readable = map.readable(&|m: usize| members.get(m).is_some_and(|x| x.slot.is_some()));
        let redundant = map
            .segments
            .iter()
            .any(|s| matches!(s.layout, Layout::Mirror { .. } | Layout::Parity { .. } | Layout::Raid10 { .. }));
        let read = |m: usize, off: u64, len: usize| -> Option<Vec<u8>> {
            let s = members.get(m)?.slot?;
            self.slots[s].source.read_vec(off, len).ok()
        };
        if redundant && !lv_in_sync(lv, self.runs, &read) {
            self.unsynced.extend(map.footprint().into_iter().map(|(m, s, e)| (m, ByteRange::from_bounds(s, e.max(s)))));
        }
        let layout = if kinds.iter().all(|k| k == "striped") {
            if map.segments.iter().any(|s| matches!(s.layout, Layout::Striped { .. })) { "striped" } else { "linear" }
                .to_string()
        } else {
            kinds.into_iter().filter(|k| k != "striped").collect::<Vec<_>>().join("+")
        };
        Ok(Some(LogicalDef { name: name.to_string(), uuid, layout, map: Arc::new(map), readable }))
    }

    /// A striped (or, with one stripe, linear) segment of LV `name` at `[start, start + len)`.
    fn striped(&self, name: &str, seg: &Section, pairs: &[(String, u64)], start: u64, len: u64) -> Result<Segment> {
        let stripes = seg.uint("stripe_count").unwrap_or(1) as usize;
        let areas = pairs.iter().map(|(pv, pe)| self.pvs.area(pv, *pe)).collect::<Result<Vec<_>>>()?;
        if stripes != areas.len() {
            return Err(Error::corrupt(format!("LV {name}: stripe_count {stripes} but {} stripes", areas.len())));
        }
        let layout = if stripes == 1 {
            Layout::Linear(areas[0])
        } else {
            Layout::Striped { chunk: seg.uint("stripe_size")?.saturating_mul(SECTOR), areas }
        };
        Ok(Segment { start, len, layout })
    }
}

/// A linear LV's piece: (offset in the LV, length, where it is on a PV), bytes.
type Run = (u64, u64, Area);

/// The `("pvN", extent)` pairs of a segment's lists that name PVs (`stripes`, a pvmove's
/// `mirrors`, ...).
fn pv_pairs(seg: &Section, pvs: &HashMap<&str, usize>) -> Vec<(String, u64)> {
    let mut out = Vec::new();
    for (_, v) in &seg.entries {
        if let Value::List(l) = v {
            for w in l.chunks(2) {
                if let [Value::Str(pv), Value::Int(pe)] = w
                    && pvs.contains_key(pv.as_str())
                    && *pe >= 0
                {
                    out.push((pv.clone(), *pe as u64));
                }
            }
        }
    }
    out
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::sync::{BITMAP_MAGIC, DM_RAID_MAGIC, MIRROR_MAGIC};
    use super::*;
    use crate::{ContainerStatus, LogicalSource, SlotHint};
    use fs_inspect_io::{BlockSource, DynSource, MemSource};
    use fs_inspect_testkit::volmgr::{LvmLv, LvmPvDef, LvmSeg, LvmVg, write_lvm_pv};

    const MIB: u64 = 1 << 20;

    fn vg(seqno: u64) -> LvmVg {
        let pv = |n: &str, u: char| LvmPvDef {
            name: n.into(),
            uuid: u.to_string().repeat(32),
            pe_start_sectors: 2048,
            pe_count: 7,
        };
        LvmVg {
            name: "vg0".into(),
            id: "V".repeat(32),
            seqno,
            extent_sectors: 2048, // 1 MiB
            pvs: vec![pv("pv0", 'A'), pv("pv1", 'B')],
            lvs: vec![
                // root: 3 MiB on pv0 (extents 0-2), then 2 MiB on pv1 (extents 0-1).
                LvmLv {
                    name: "root".into(),
                    visible: true,
                    segments: vec![LvmSeg::linear(0, 3, "pv0", 0), LvmSeg::linear(3, 2, "pv1", 0)],
                },
                // data: 4 MiB striped over pv0 extents 3-4 and pv1 extents 2-3, 64 KiB stripes.
                LvmLv {
                    name: "data".into(),
                    visible: true,
                    segments: vec![LvmSeg {
                        start_extent: 0,
                        extent_count: 4,
                        kind: "striped",
                        stripes: vec![("pv0".into(), 3), ("pv1".into(), 2)],
                        stripe_size: 128,
                        ..LvmSeg::linear(0, 0, "", 0)
                    }],
                },
                // A hidden sub-volume (e.g. a thin pool's data) on pv1 extent 5.
                LvmLv { name: "pool_tdata".into(), visible: false, segments: vec![LvmSeg::linear(0, 1, "pv1", 5)] },
                LvmLv {
                    name: "thin1".into(),
                    visible: true,
                    segments: vec![LvmSeg {
                        start_extent: 0,
                        extent_count: 9,
                        kind: "thin",
                        stripes: vec![],
                        stripe_size: 0,
                        ..LvmSeg::linear(0, 0, "", 0)
                    }],
                },
            ],
        }
    }

    fn pvs() -> Vec<Vec<u8>> {
        let mut a = vec![0u8; 8 * MIB as usize];
        let mut b = vec![0u8; 8 * MIB as usize];
        write_lvm_pv(&mut a, &"A".repeat(32), &vg(5).text(), MIB - 4096, None);
        // pv1's copy is newer and wraps around the end of its circular area.
        write_lvm_pv(&mut b, &"B".repeat(32), &vg(6).text(), MIB - 4096, Some(700));
        // Recognizable data in every extent: byte = (pv, extent) mixed with the offset.
        for (n, pv) in [&mut a, &mut b].into_iter().enumerate() {
            for e in 0..7u64 {
                for i in 0..MIB {
                    let off = (MIB + e * MIB + i) as usize;
                    pv[off] = (n as u64 * 31 + e * 7 + i * 13 % 251) as u8;
                }
            }
        }
        vec![a, b]
    }

    fn slots(pvs: &[Vec<u8>]) -> Vec<Slot> {
        pvs.iter()
            .map(|b| Slot {
                source: Arc::new(MemSource::new(b.clone())) as DynSource,
                hint: SlotHint::Unknown,
                has_fs: false,
                parent: None,
            })
            .collect()
    }

    #[test]
    fn assembles_two_pvs() {
        let pvs = pvs();
        let s = slots(&pvs);
        let all = crate::assemble(&s, &[], &Limits::default());
        assert_eq!(all.len(), 1);
        let c = &all[0];
        assert_eq!((c.name.as_str(), c.status), ("vg0", ContainerStatus::Complete));
        assert!(c.notes.iter().any(|n| n.code == DiagCode::BackupUsed), "{:?}", c.notes);
        let names: Vec<_> = c.volumes.iter().map(|v| (v.name.as_str(), v.layout.as_str(), v.readable)).collect();
        assert_eq!(
            names,
            [
                ("root", "linear", Readability::Full),
                ("data", "striped", Readability::Full),
                ("thin1", "thin", Readability::No)
            ]
        );
        // The hidden volume's extent stays data; nothing of root or data does.
        assert_eq!(c.opaque, [(1, ByteRange::new(MIB + 5 * MIB, MIB))]);

        // Read through the maps: root's 4th MiB is pv1 extent 0; data's 2nd 64 KiB is pv1 extent 2.
        let members: Vec<Option<DynSource>> = s.iter().map(|x| Some(x.source.clone())).collect();
        let root = LogicalSource::new(c.volumes[0].map.clone(), members.clone());
        assert_eq!(root.size(), 5 * MIB);
        let mut got = vec![0u8; 4096];
        root.read_exact_at(3 * MIB, &mut got).unwrap();
        assert_eq!(got, pvs[1][(MIB) as usize..(MIB + 4096) as usize]);
        let data = LogicalSource::new(c.volumes[1].map.clone(), members);
        data.read_exact_at(64 << 10, &mut got).unwrap();
        assert_eq!(got, pvs[1][(3 * MIB) as usize..(3 * MIB + 4096) as usize]);
    }

    #[test]
    fn a_missing_pv() {
        let pvs = pvs();
        let s = slots(&pvs[..1]);
        let c = &crate::assemble(&s, &[], &Limits::default())[0];
        assert_eq!(c.status, ContainerStatus::Incomplete);
        assert!(c.volumes.iter().all(|v| v.readable == Readability::No));
        // Everything the volume group uses on pv0 counts as data: root's 3 extents, data's 2.
        let mut op: Vec<ByteRange> = c.opaque.iter().filter(|(m, _)| *m == 0).map(|(_, r)| *r).collect();
        op = fs_inspect_core::range::sort_coalesce(op);
        assert_eq!(op, [ByteRange::new(MIB, 5 * MIB)]);
    }

    #[test]
    fn damage() {
        let mut pvs = pvs();
        // A broken label checksum: not a PV.
        pvs[0][512 + 100] ^= 1;
        assert!(read_label(&MemSource::new(pvs[0].clone())).unwrap().is_none());
        // A cloned disk: two slots with pv1's UUID; the first is used, the clone is not
        // claimed.
        let s = slots(&[pvs[1].clone(), pvs[1].clone()]);
        let c = &crate::assemble(&s, &[], &Limits::default())[0];
        let claimed: Vec<usize> = c.members.iter().filter_map(|m| m.slot).collect();
        assert_eq!(claimed, [0]);
        assert!(c.notes.iter().any(|n| n.code == DiagCode::DuplicateMember && n.message.contains("clone")));
    }

    /// RAID and mirror LVs, on 4 PVs of 16 extents of 64 KiB (PV `i` at extent 0 holds
    /// `{lv}_rmeta_i`). `images`: each image's runs (PV, first extent, extents); `fill`: the
    /// image contents for logical `data`.
    struct RaidCase {
        seg: LvmSeg,
        images: Vec<Vec<(usize, u64, u64)>>,
        extra: Vec<LvmLv>,
        fill: fn(&mut [Vec<u8>], &[u8]),
    }

    const EXT: u64 = 64 << 10;
    const CHUNK: u64 = 8 << 10;

    fn raid_pvs(c: &RaidCase, data: &[u8], text_fix: impl Fn(String) -> String) -> Vec<Vec<u8>> {
        let lv = c.seg.subs[0].split('_').next().unwrap().to_string();
        let image_ext: u64 = c.images[0].iter().map(|r| r.2).sum();
        let mut lvs = vec![LvmLv { name: lv.clone(), visible: true, segments: vec![c.seg.clone()] }];
        let sub = if c.seg.kind == "mirror" { "mimage" } else { "rimage" };
        for (i, runs) in c.images.iter().enumerate() {
            let mut le = 0;
            let segments = runs
                .iter()
                .map(|&(pv, pe, n)| {
                    le += n;
                    LvmSeg::linear(le - n, n, &format!("pv{pv}"), pe)
                })
                .collect();
            lvs.push(LvmLv { name: format!("{lv}_{sub}_{i}"), visible: false, segments });
            if sub == "rimage" && c.seg.kind != "raid0" {
                lvs.push(LvmLv {
                    name: format!("{lv}_rmeta_{i}"),
                    visible: false,
                    segments: vec![LvmSeg::linear(0, 1, &format!("pv{i}"), 0)],
                });
            }
        }
        lvs.extend(c.extra.iter().cloned());
        let vg = LvmVg {
            name: "vg".into(),
            id: "V".repeat(32),
            seqno: 1,
            extent_sectors: EXT / 512,
            pvs: (0..4)
                .map(|i| LvmPvDef {
                    name: format!("pv{i}"),
                    uuid: char::from(b'A' + i as u8).to_string().repeat(32),
                    pe_start_sectors: 2048,
                    pe_count: 16,
                })
                .collect(),
            lvs,
        };
        let text = text_fix(vg.text());
        let mut images = vec![vec![0u8; (image_ext * EXT) as usize]; c.images.len()];
        (c.fill)(&mut images, data);
        let mut pvs: Vec<Vec<u8>> = (0..4u8)
            .map(|i| {
                // Recognizable leftovers everywhere, so nothing reads as zeros by chance.
                let mut b: Vec<u8> = (0..MIB + 16 * EXT).map(|x| (x * 7 + i as u64) as u8).collect();
                write_lvm_pv(&mut b, &char::from(b'A' + i).to_string().repeat(32), &text, MIB - 4096, None);
                b
            })
            .collect();
        for (img, runs) in images.iter().zip(&c.images) {
            let mut at = 0usize;
            for &(pv, pe, n) in runs {
                let len = (n * EXT) as usize;
                let to = (MIB + pe * EXT) as usize;
                pvs[pv][to..to + len].copy_from_slice(&img[at..at + len]);
                at += len;
            }
        }
        pvs
    }

    fn logical(c: &Container, s: &[Slot], v: usize) -> LogicalSource {
        let members = c.members.iter().map(|m| m.slot.map(|i| s[i].source.clone())).collect();
        LogicalSource::new(c.volumes[v].map.clone(), members)
    }

    fn data(len: u64) -> Vec<u8> {
        (0..len).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect()
    }

    fn copy_all(images: &mut [Vec<u8>], data: &[u8]) {
        for i in images {
            i[..data.len()].copy_from_slice(data);
        }
    }

    /// Check layout, opaque (only what is not image: rmeta and `extra`), full and degraded reads.
    fn check(c: RaidCase, layout: &str, len: u64, opaque: &[(usize, u64)], missing: usize) {
        let d = data(len);
        let pvs = raid_pvs(&c, &d, |t| t);
        for gone in [None, Some(missing)] {
            let s: Vec<Slot> =
                slots(&pvs).into_iter().enumerate().filter(|(i, _)| Some(*i) != gone).map(|x| x.1).collect();
            let all = crate::assemble(&s, &[], &Limits::default());
            let ct = &all[0];
            let v = &ct.volumes[0];
            assert_eq!(v.layout, layout, "{:?}", ct.notes);
            assert_eq!(v.map.len, len);
            let want = if gone.is_some() { Readability::Degraded } else { Readability::Full };
            assert_eq!(v.readable, want, "missing {gone:?}");
            let mut got = vec![0u8; len as usize];
            logical(ct, &s, 0).read_exact_at(0, &mut got).unwrap();
            assert!(got == d, "{layout} reads back (missing {gone:?})");
            if gone.is_none() {
                let mut op = ct.opaque.clone();
                op.sort();
                let want: Vec<_> = opaque.iter().map(|&(m, e)| (m, ByteRange::new(MIB + e * EXT, EXT))).collect();
                assert_eq!(op, want);
            }
        }
    }

    fn rmeta(n: usize) -> Vec<(usize, u64)> {
        (0..n).map(|i| (i, 0)).collect()
    }

    #[test]
    fn raid5_with_a_split_image() {
        // rimage_0 is on pv0 extents 1-2 and pv3 extents 0-1: two pieces, parity rotating on.
        let seg = LvmSeg::raid("raid5", "r", 0, 8, 3, CHUNK / 512);
        let images = vec![vec![(0, 1, 2), (3, 0, 2)], vec![(1, 1, 4)], vec![(2, 1, 4)]];
        let fill = |i: &mut [Vec<u8>], d: &[u8]| fs_inspect_testkit::volmgr::raid5_ls_write(i, 0, CHUNK, d);
        let c = RaidCase { seg, images, extra: vec![], fill };
        let pvs = raid_pvs(&c, &[], |t| t);
        let ct = &crate::assemble(&slots(&pvs), &[], &Limits::default())[0];
        let rows: Vec<_> = ct.volumes[0]
            .map
            .segments
            .iter()
            .map(|s| match s.layout {
                Layout::Parity { first_row, .. } => (s.start, first_row),
                _ => panic!("{:?}", s.layout),
            })
            .collect();
        assert_eq!(rows, [(0, 0), (4 * EXT, 2 * EXT / CHUNK)]);
        check(c, "raid5", 8 * EXT, &rmeta(3), 3);
    }

    #[test]
    fn raid6_zr() {
        let seg = LvmSeg::raid("raid6", "r", 0, 8, 4, CHUNK / 512);
        let fill = |i: &mut [Vec<u8>], d: &[u8]| fs_inspect_testkit::volmgr::raid6_zr_write(i, 0, CHUNK, d);
        // Any one image missing: rebuilt from P, never Q.
        for missing in 0..4 {
            let seg = seg.clone();
            let images: Vec<_> = (0..4).map(|i| vec![(i, 1, 4)]).collect();
            check(RaidCase { seg, images, extra: vec![], fill }, "raid6", 8 * EXT, &rmeta(4), missing);
        }
    }

    #[test]
    fn raid1_raid0_raid10() {
        let images = |n: usize, e: u64| (0..n).map(|i| vec![(i, 1, e)]).collect::<Vec<_>>();
        let seg = LvmSeg::raid("raid1", "r", 0, 4, 2, 0);
        check(RaidCase { seg, images: images(2, 4), extra: vec![], fill: copy_all }, "raid1", 4 * EXT, &rmeta(2), 0);

        // raid0 has no redundancy: just check the map.
        let seg = LvmSeg::raid("raid0", "r", 0, 8, 2, CHUNK / 512);
        let c = RaidCase {
            seg,
            images: images(2, 4),
            extra: vec![],
            fill: |i, d| {
                for (k, ch) in d.chunks(CHUNK as usize).enumerate() {
                    let at = k / 2 * CHUNK as usize;
                    i[k % 2][at..at + ch.len()].copy_from_slice(ch);
                }
            },
        };
        let d = data(8 * EXT);
        let pvs = raid_pvs(&c, &d, |t| t);
        let s = slots(&pvs);
        let ct = &crate::assemble(&s, &[], &Limits::default())[0];
        assert_eq!((ct.volumes[0].layout.as_str(), ct.volumes[0].readable), ("raid0", Readability::Full));
        let mut got = vec![0u8; d.len()];
        logical(ct, &s, 0).read_exact_at(0, &mut got).unwrap();
        assert!(got == d);
        assert!(ct.opaque.is_empty());

        // raid10, two copies over four images: chunk k on images 2k % 4 and 2k % 4 + 1.
        let mut seg = LvmSeg::raid("raid10", "r", 0, 8, 4, CHUNK / 512);
        seg.data_copies = 2;
        let fill = |i: &mut [Vec<u8>], d: &[u8]| {
            for (k, ch) in d.chunks(CHUNK as usize).enumerate() {
                let at = k * 2 / 4 * CHUNK as usize;
                for dev in [k * 2 % 4, k * 2 % 4 + 1] {
                    i[dev][at..at + ch.len()].copy_from_slice(ch);
                }
            }
        };
        check(RaidCase { seg, images: images(4, 4), extra: vec![], fill }, "raid10", 8 * EXT, &rmeta(4), 2);
    }

    #[test]
    fn old_mirror_with_a_log() {
        let seg = LvmSeg::mirror("m", 0, 4, 2, true);
        let images = vec![vec![(0, 1, 4)], vec![(1, 1, 4)]];
        let log = LvmLv { name: "m_mlog".into(), visible: false, segments: vec![LvmSeg::linear(0, 1, "pv2", 0)] };
        check(RaidCase { seg, images, extra: vec![log], fill: copy_all }, "mirror", 4 * EXT, &[(2, 0)], 1);
    }

    /// A dm-raid metadata image at PV byte `at`, in sync: its superblock and a clean bitmap.
    fn write_rmeta(pv: &mut [u8], at: usize) {
        let b = &mut pv[at..at + 8192];
        b.fill(0);
        b[0..4].copy_from_slice(&DM_RAID_MAGIC.to_le_bytes());
        b[16..24].copy_from_slice(&7u64.to_le_bytes());
        b[32..48].fill(0xFF);
        let h = &mut b[4096..];
        h[0..4].copy_from_slice(&BITMAP_MAGIC.to_le_bytes());
        h[24..32].copy_from_slice(&7u64.to_le_bytes());
        h[40..48].copy_from_slice(&(4 * EXT / 512).to_le_bytes());
        h[52..56].copy_from_slice(&(EXT as u32).to_le_bytes());
    }

    #[test]
    fn redundant_volumes_are_unsynced_unless_their_metadata_says_otherwise() {
        let unsynced = |pvs: &[Vec<u8>]| {
            let mut u = crate::assemble(&slots(pvs), &[], &Limits::default()).remove(0).unsynced;
            u.sort();
            u
        };
        let images = |e: u64| vec![(0, ByteRange::new(MIB + EXT, e * EXT)), (1, ByteRange::new(MIB + EXT, e * EXT))];
        let seg = LvmSeg::raid("raid1", "r", 0, 4, 2, 0);
        let c = RaidCase { seg, images: vec![vec![(0, 1, 4)], vec![(1, 1, 4)]], extra: vec![], fill: copy_all };
        let mut pvs = raid_pvs(&c, &data(4 * EXT), |t| t);
        // No dm-raid superblock in the metadata images: not known.
        assert_eq!(unsynced(&pvs), images(4));
        for pv in &mut pvs[..2] {
            write_rmeta(pv, MIB as usize);
        }
        assert!(unsynced(&pvs).is_empty());
        // A write-intent bit set, a resync pending, a stale bitmap.
        let at = MIB as usize;
        for (off, v) in [(4096 + 256, 2u8), (40, 0), (4096 + 24, 6)] {
            let keep = pvs[1][at + off];
            pvs[1][at + off] = v;
            assert_eq!(unsynced(&pvs), images(4), "byte {off}");
            pvs[1][at + off] = keep;
        }
        assert!(unsynced(&pvs).is_empty());

        // An old mirror: in sync when its disk log has every region clean.
        let seg = LvmSeg::mirror("m", 0, 4, 2, true);
        let log = LvmLv { name: "m_mlog".into(), visible: false, segments: vec![LvmSeg::linear(0, 1, "pv2", 0)] };
        let c = RaidCase { seg, images: vec![vec![(0, 1, 4)], vec![(1, 1, 4)]], extra: vec![log], fill: copy_all };
        let mut pvs = raid_pvs(&c, &data(4 * EXT), |t| t);
        assert_eq!(unsynced(&pvs), images(4));
        let l = &mut pvs[2][MIB as usize..(MIB + EXT) as usize];
        l.fill(0);
        l[0..4].copy_from_slice(&MIRROR_MAGIC.to_le_bytes());
        l[8..16].copy_from_slice(&11u64.to_le_bytes());
        l[1024] = 0xFF;
        l[1025] = 0b111;
        assert!(unsynced(&pvs).is_empty());
        pvs[2][MIB as usize + 1025] = 0b011;
        assert_eq!(unsynced(&pvs), images(4));
    }

    #[test]
    fn a_reshaping_raid_stays_opaque() {
        let seg = LvmSeg::raid("raid5", "r", 0, 8, 3, CHUNK / 512);
        let images = (0..3).map(|i| vec![(i, 1, 4)]).collect();
        let c = RaidCase { seg, images, extra: vec![], fill: |_, _| {} };
        let pvs =
            raid_pvs(&c, &[], |t| t.replace("id = \"lvid-r\"\nstatus = [", "id = \"lvid-r\"\nstatus = [\"RESHAPE\", "));
        let s = slots(&pvs);
        let ct = &crate::assemble(&s, &[], &Limits::default())[0];
        assert_eq!((ct.volumes[0].layout.as_str(), ct.volumes[0].readable), ("raid5", Readability::No));
        assert!(ct.notes.iter().any(|n| n.code == DiagCode::UnsupportedLayout && n.message.contains("reshaped")));
        // Every image and rmeta extent counts as data.
        let op = fs_inspect_core::range::sort_coalesce(ct.opaque.iter().filter(|x| x.0 == 1).map(|x| x.1).collect());
        assert_eq!(op, [ByteRange::new(MIB, 5 * EXT)]);
    }

    /// Both PVs of `vg`, with each's metadata text (seqnos `a` and `b`) edited by `fix`.
    fn pvs_with(a: u64, b: u64, fix: impl Fn(String) -> String) -> Vec<Vec<u8>> {
        [('A', a), ('B', b)]
            .into_iter()
            .map(|(u, seqno)| {
                let mut p = vec![0u8; 8 * MIB as usize];
                write_lvm_pv(&mut p, &u.to_string().repeat(32), &fix(vg(seqno).text()), MIB - 4096, None);
                p
            })
            .collect()
    }

    #[test]
    fn copies_without_a_volume_group() {
        let l = Limits::default();
        for (text, why) in [
            (&b"contents = \"Text Format Volume Group\"\nversion = 1\n"[..], "without a volume group"),
            (b"vg { seqno = 1 }", "volume group without id"),
            (b"vg { id = \"x\" }", "no integer seqno"),
            (b"vg { id = \"x\" seqno = -1 }", "negative seqno"),
        ] {
            let e = parse_copy(text, &l).err().unwrap();
            assert_eq!(e.kind(), fs_inspect_core::ErrorKind::Corrupt, "{e}");
            assert!(e.to_string().contains(why), "{e}");
        }
    }

    #[test]
    fn a_damaged_copy_is_noted_on_its_pv() {
        // Same seqno on both: no older copies noted.
        let pvs = pvs_with(5, 5, |t| t);
        let c = &crate::assemble(&slots(&pvs), &[], &Limits::default())[0];
        assert!(!c.notes.iter().any(|n| n.code == DiagCode::BackupUsed), "{:?}", c.notes);
        assert!(!c.notes.iter().any(|n| n.code == DiagCode::ChecksumMismatch), "{:?}", c.notes);
        // pv0's text fails its checksum: pv1's copy is used, the damage noted against pv0.
        let mut pvs = pvs;
        pvs[0][4096 + 512 + 10] ^= 1;
        let got = crate::assemble(&slots(&pvs), &[], &Limits::default());
        assert_eq!(got.len(), 1);
        let c = &got[0];
        assert_eq!(c.members.iter().filter_map(|m| m.slot).collect::<Vec<_>>(), [0, 1]);
        let n: Vec<_> = c.notes.iter().filter(|n| n.code == DiagCode::ChecksumMismatch).collect();
        assert_eq!(n.len(), 1, "{:?}", c.notes);
        assert!(
            n[0].message.contains("metadata area at 4096") && n[0].message.contains("fails its checksum"),
            "{}",
            n[0].message
        );
        assert!(!c.notes.iter().any(|n| n.code == DiagCode::BackupUsed), "{:?}", c.notes);
    }

    #[test]
    fn volume_groups_that_are_not_assembled() {
        // No extent size, or a striped segment whose stripe count disagrees with its list.
        for fix in [
            (|t: String| t.replace("extent_size = 2048\n", "extent_size = 0\n")) as fn(String) -> String,
            |t: String| t.replace("stripe_count = 2\n", "stripe_count = 3\n"),
            |t: String| t.replace("physical_volumes {", "physical_volumez {"),
        ] {
            let pvs = pvs_with(5, 5, fix);
            assert_ne!(fix(vg(5).text()), vg(5).text());
            assert!(crate::assemble(&slots(&pvs), &[], &Limits::default()).is_empty());
        }
    }
}
