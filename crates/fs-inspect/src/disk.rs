//! Whole-disk map: the data / zero / unused bytes of a whole device, in its coordinates.
//!
//! Data: what the disk needs outside the partitions (below), partitions without a recognized
//! file system, the allocated ranges of every recognized file system, and the rest of a
//! partition whose file system fails to open or to list its allocation (from where it failed).
//! Space past the end of a file system that is smaller than its partition is unused, like its
//! free space (unless the partition keeps RAID metadata there). Each file system's must-be-zero
//! ranges are zero. Where partitions overlap (a damaged table), the overlap is all data: either
//! file system may own it.
//!
//! A partition that is a member of a volume manager container (an LVM physical volume, an md
//! array member, a Windows dynamic disk's data area: see [`DiskSet`]) holds the container's
//! metadata (data), the bytes of each of its logical volumes that hold that volume's data and
//! zero ranges (every copy; for RAID 4/5/6 every chunk of each row in use, parity included, so
//! a restore needs no resync), and unused space (free extents, rows no volume uses). What
//! cannot be mapped (a layout not supported, a volume missing members) is data where it lies.
//!
//! Space outside every partition is unused except what the disk needs there, as
//! [`DiskSet::layout`] has it: the partition table's areas (its structures, MBR, EBRs, both GPT
//! headers and arrays, and everything before the first partition: GRUB's core.img on MBR
//! disks, the LDM private header of Windows dynamic disks at sector 6, VeraCrypt and vendor
//! loaders) and the reserved last MiB (the LDM database of Windows dynamic disks, BIOS RAID
//! metadata: Intel IMSM, SNIA DDF, nVidia, Promise, SiI keep it in the last sectors).
//!
//! The same rules apply inside a logical volume (a partitioned md array), whose map is then
//! projected onto its members.

use crate::CancelToken;
use crate::device::{Device, Part as DevicePart};
use crate::layout::{device_needs, footprint, member_fixed};
use crate::map::{DeviceMapOptions, Map};
use crate::pipeline::{Allocation, ExcludeOptions, Ranges, ZeroDetail, allocation, shifted};
use crate::set::Ix;
use crate::set::{DeviceRef, DiskSet, Layout, VolumeIndex, Wired};
use crate::volume::Volume;
use fs_inspect_core::range::{
    Coalesce, Intersect, Merge, MergeInput, MergeN, intersect, sort_coalesce, subtract, union,
};
use fs_inspect_core::{ByteRange, ErrorKind, Result};
use fs_inspect_core::{DiagCode, Diagnostics};
use fs_inspect_volmgr::{LogicalMap, MemberIx, RangesFactory, project, project_zero};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// One partition of the map.
struct Part {
    /// Where the volume starts in the device (its own coordinates may start elsewhere: a volume
    /// the caller read from a snapshot device starts at 0 there).
    at: u64,
    /// Bytes `[start, end)` of the device it contributes.
    start: u64,
    end: u64,
    /// What its file system allocates; None when it cannot be opened at all or cannot list its
    /// exclusions and zero ranges (then the part is all data).
    alloc: Option<Arc<Allocation>>,
}

impl Part {
    /// The part's allocated ranges in device coordinates: those of its file system, or all of it
    /// when the file system cannot list them (no volume, or the listing failed on the way: then
    /// from where it failed).
    fn stream(&self) -> Ranges {
        let part = ByteRange::from_bounds(self.start, self.end);
        let Some(a) = &self.alloc else { return Box::new(std::iter::once(Ok(part))) };
        let mut v: Vec<ByteRange> = intersect(a.alloc.iter().map(|r| r.shifted(self.at)), [part]).collect();
        if a.failed.is_some() {
            // Listed up to the last range: the rest counts as data (reported when listed).
            let from = a.alloc.last().map_or(self.start, |r| r.end().saturating_add(self.at)).max(self.start);
            if from < self.end {
                v.push(ByteRange::from_bounds(from, self.end));
            }
        }
        Box::new(v.into_iter().map(Ok))
    }
}

/// A partition that is a container member: what the container needs of it.
struct MemberPart {
    index: u32,
    start: u64,
    end: u64,
    /// Where the member's slot starts in the device.
    slot_offset: u64,
    /// Slot bytes that are data whatever the volumes hold (metadata, what is not mapped),
    /// sorted and coalesced.
    fixed: Vec<ByteRange>,
    /// Each readable logical volume with a part on this member: its map, this member's index
    /// in it, and the volume's own map.
    lvs: Vec<(Arc<LogicalMap>, MemberIx, Arc<DeviceMap>)>,
    diag: Diagnostics,
}

impl MemberPart {
    fn stream(&self) -> Ranges {
        let mut inputs: Vec<MergeInput<fs_inspect_core::Error>> =
            vec![MergeInput::Open(Box::new(self.fixed.clone().into_iter().map(Ok)))];
        for (map, m, child) in &self.lvs {
            let c = child.clone();
            let content: RangesFactory = Arc::new(move || Ok(c.alloc()));
            inputs.push(MergeInput::Open(project(map, *m, content)));
        }
        let merged: Ranges = Box::new(MergeN::new(inputs));
        let cut = Intersect::new(
            shifted(merged, self.slot_offset),
            std::iter::once(ByteRange::from_bounds(self.start, self.end)),
        );
        Box::new(WholeOnError {
            inner: Box::new(cut),
            diag: self.diag.clone(),
            index: self.index,
            pos: self.start,
            end: self.end,
            done: false,
        })
    }
}

/// A piece of the map, in disk order.
enum Segment {
    /// Space outside the partitions: only what the disk needs there is data.
    Gap(u64, u64),
    Part(Box<Part>),
    Member(Box<MemberPart>),
}

/// A part's stream that, on an error other than a cancel, reports the rest of the part as data
/// and ends: one unreadable file system does not stop the whole-disk map.
struct WholeOnError {
    inner: Ranges,
    diag: Diagnostics,
    index: u32,
    /// End of what was produced so far.
    pos: u64,
    end: u64,
    done: bool,
}

impl Iterator for WholeOnError {
    type Item = Result<ByteRange>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        match self.inner.next()? {
            Ok(r) => {
                self.pos = r.end();
                Some(Ok(r))
            }
            Err(e) => {
                self.done = true;
                if e.kind() == ErrorKind::Cancelled {
                    return Some(Err(e));
                }
                self.diag.warn(
                    DiagCode::CountedAsUsed,
                    format!(
                        "reading the allocation of partition {} stopped at {:#x} ({e}); the rest counts as data",
                        self.index, self.pos
                    ),
                );
                (self.pos < self.end).then(|| Ok(ByteRange::from_bounds(self.pos, self.end)))
            }
        }
    }
}

/// The map of one device of a set (a disk or a logical volume), in its coordinates, before
/// classification: its allocated ranges (a fresh stream each time) and must-be-zero ranges.
pub(crate) struct DeviceMap {
    segments: Vec<Segment>,
    /// What the device needs outside its partitions.
    keep: Vec<ByteRange>,
    overlaps: Vec<ByteRange>,
    zero: Vec<ByteRange>,
    /// What the volumes leave out (exact, sorted and coalesced).
    excluded: Vec<ByteRange>,
    /// Largest allocation unit of the volumes reached (at least 512).
    unit: u64,
}

impl DeviceMap {
    /// A fresh stream of the allocated ranges; each part's stream opens when it is reached.
    fn alloc(self: &Arc<Self>) -> Ranges {
        let me = self.clone();
        let all = (0..self.segments.len()).flat_map(move |i| -> Ranges {
            match &me.segments[i] {
                Segment::Gap(a, b) => {
                    let kept: Vec<ByteRange> =
                        intersect(me.keep.iter().copied(), [ByteRange::from_bounds(*a, *b)]).collect();
                    Box::new(kept.into_iter().map(Ok))
                }
                Segment::Part(p) => p.stream(),
                Segment::Member(m) => m.stream(),
            }
        });
        if self.overlaps.is_empty() {
            Box::new(all)
        } else {
            Box::new(Coalesce::new(Merge::new(all, self.overlaps.clone().into_iter())))
        }
    }
}

/// How a device map is made: each volume leaving out `exclude`, the slots in `unread` not
/// read (all data).
struct Rules {
    exclude: ExcludeOptions,
    zero: ZeroDetail,
    unread: HashSet<usize>,
}

/// The map of device `dev` (memoized per whole-disk map: a logical volume on several members
/// is mapped once), by `rules`.
fn device_map(
    (layout, wired): (&Layout, &Wired),
    dev: usize,
    rules: &Rules,
    memo: &mut HashMap<usize, Arc<DeviceMap>>,
) -> Result<Arc<DeviceMap>> {
    if let Some(m) = memo.get(&dev) {
        return Ok(m.clone());
    }
    let img: &Device = &wired.devices[dev];
    let disk = img.source().size();
    if layout.tables[dev].is_err() {
        // Its partition table cannot be read (reported when the set was laid out): all data.
        let whole = Part { at: 0, start: 0, end: disk, alloc: None };
        let m = Arc::new(DeviceMap {
            segments: vec![Segment::Part(Box::new(whole))],
            keep: Vec::new(),
            overlaps: Vec::new(),
            zero: Vec::new(),
            excluded: Vec::new(),
            unit: 512,
        });
        memo.insert(dev, m.clone());
        return Ok(m);
    }
    let needs = device_needs(img)?;
    let mut segments = Vec::new();
    let mut overlaps = Vec::new();
    let mut zero = Vec::new();
    let mut excluded = Vec::new();
    let mut unit = 512u64;
    let mut pos = 0u64;
    for e in img.parts()?.iter() {
        // A volume overlapping the previous one (a damaged table) adds what lies after it;
        // the overlap itself is all data (either file system may own it).
        let end = e.offset.saturating_add(e.length).min(disk);
        if e.offset.min(disk) < pos.min(end) {
            img.diag().warn(
                DiagCode::PartitionTable,
                format!("partition {} overlaps the previous one; the overlap counts as data", e.index),
            );
            overlaps.push(ByteRange::from_bounds(e.offset, pos.min(end)));
        }
        let start = e.offset.max(pos).min(disk);
        if end <= start {
            continue;
        }
        if start > pos {
            segments.push(Segment::Gap(pos, start));
        }
        pos = end;
        let slot = layout.slot_of.get(&(dev, e.index)).copied();
        // A volume the caller does not want read: all data.
        if slot.is_some_and(|s| rules.unread.contains(&s)) {
            segments.push(Segment::Part(Box::new(Part { at: e.offset, start, end, alloc: None })));
            continue;
        }
        let claim = slot.and_then(|s| layout.slots[s].claim);
        if let Some((ci, mi)) = claim {
            let acc = Acc { zero: &mut zero, excluded: &mut excluded, unit: &mut unit };
            let part = SlotPart { dev, index: e.index, slot_offset: e.offset, start, end, container: ci, member: mi };
            let m = member_part((layout, wired), &part, rules, memo, acc)?;
            segments.push(Segment::Member(Box::new(m)));
            continue;
        }
        let acc = Acc { zero: &mut zero, excluded: &mut excluded, unit: &mut unit };
        let index = slot.and_then(|s| layout.volume_of_slot.get(&s).copied());
        let alloc = open_part(wired, img, e, index, rules, (start, end), acc)?;
        segments.push(Segment::Part(Box::new(Part { at: e.offset, start, end, alloc })));
    }
    if pos < disk {
        segments.push(Segment::Gap(pos, disk));
    }
    // The parts of the space outside the partitions a disk needs (see the module docs).
    let keep: Vec<ByteRange> = union(needs.table, needs.reserved).collect();
    let m = Arc::new(DeviceMap {
        segments,
        keep,
        overlaps: sort_coalesce(overlaps),
        zero: sort_coalesce(zero),
        excluded: sort_coalesce(excluded),
        unit,
    });
    memo.insert(dev, m.clone());
    Ok(m)
}

/// The allocation of volume `e` of `img`, for the part `[start, end)` it contributes; `None`
/// when it cannot be opened (a warning: it counts as data). Its zero and excluded ranges in
/// the part, and its unit, go to `acc`.
fn open_part(
    wired: &Wired,
    img: &Device,
    e: &DevicePart,
    index: Option<VolumeIndex>,
    rules: &Rules,
    (start, end): (u64, u64),
    acc: Acc<'_>,
) -> Result<Option<Arc<Allocation>>> {
    let opened = Volume::open_or_raw(img.clone(), wired.peers.clone(), index, e.offset, e.length, e.fs);
    let opened = opened.and_then(|v| allocation(&v, &rules.exclude, rules.zero).map(|a| (v, a)));
    match opened {
        Ok((v, a)) => {
            if let Some(err) = &a.failed {
                let from = a.alloc.last().map_or(0, |r| r.end());
                v.diag().warn(
                    DiagCode::CountedAsUsed,
                    format!(
                        "reading the allocation of partition {} stopped at {:#x} ({err}); the rest counts as data",
                        e.index,
                        from.saturating_add(e.offset)
                    ),
                );
            }
            *acc.unit = (*acc.unit).max(v.info().fs.unit);
            let part = [ByteRange::from_bounds(start, end)];
            acc.zero.extend(intersect(a.zero.iter().map(|r| r.shifted(e.offset)).collect::<Vec<_>>(), part));
            acc.excluded.extend(intersect(a.excluded.iter().map(|r| r.shifted(e.offset)).collect::<Vec<_>>(), part));
            Ok(Some(a))
        }
        Err(err) if err.kind() == ErrorKind::Cancelled => Err(err),
        Err(err) => {
            img.diag()
                .for_volume(e.offset)
                .warn(DiagCode::OpenedAsRaw, format!("cannot open partition {} ({err}); it counts as data", e.index));
            Ok(None)
        }
    }
}

/// What the parts of a device add up as the map is built.
struct Acc<'a> {
    zero: &'a mut Vec<ByteRange>,
    excluded: &'a mut Vec<ByteRange>,
    unit: &'a mut u64,
}

/// A part of a device that is a container member's slot.
#[derive(Debug, Clone, Copy)]
struct SlotPart {
    /// Volume `index` of device `dev`, starting at `slot_offset` in it.
    dev: usize,
    index: u32,
    slot_offset: u64,
    /// The device bytes `[start, end)` it contributes.
    start: u64,
    end: u64,
    /// Member `member` of container `container`.
    container: usize,
    member: usize,
}

/// The member part `part` is.
fn member_part(
    (layout, wired): (&Layout, &Wired),
    part: &SlotPart,
    rules: &Rules,
    memo: &mut HashMap<usize, Arc<DeviceMap>>,
    acc: Acc<'_>,
) -> Result<MemberPart> {
    let SlotPart { dev, index, slot_offset, start, end, container: ci, member: mi } = *part;
    let p = &layout.containers[ci];
    let img = &wired.devices[dev];
    let diag = img.diag().for_volume(slot_offset);
    let slot_len = end - slot_offset;
    // What the container holds whatever its volumes do (the rules of `DiskSet::layout`).
    let mut fixed = member_fixed(p, mi, slot_len);
    let mut lvs = Vec::new();
    for (vi, lv) in p.c.volumes.iter().enumerate() {
        let Some(ld) = p.devices[vi] else { continue };
        if lv.map.segments.iter().all(|s| s.layout.areas().iter().all(|a| a.member != mi)) {
            continue; // nothing of it here
        }
        match device_map((layout, wired), ld, rules, memo) {
            Ok(child) => {
                *acc.unit = (*acc.unit).max(child.unit);
                let window = [ByteRange::from_bounds(start, end)];
                let z: Vec<ByteRange> =
                    project_zero(&lv.map, mi, &child.zero).into_iter().map(|r| r.shifted(slot_offset)).collect();
                acc.zero.extend(intersect(z, window));
                // Excluded bytes as they sit on this member (parity holds none of them).
                let x: Vec<ByteRange> =
                    project_zero(&lv.map, mi, &child.excluded).into_iter().map(|r| r.shifted(slot_offset)).collect();
                acc.excluded.extend(intersect(x, window));
                lvs.push((lv.map.clone(), mi, child));
            }
            Err(e) if e.kind() == ErrorKind::Cancelled => return Err(e),
            Err(e) => {
                diag.warn(
                    DiagCode::CountedAsUsed,
                    format!("cannot map logical volume {} ({e}); its part of this member counts as data", lv.name),
                );
                fixed.extend(footprint(&lv.map, mi));
            }
        }
    }
    let fixed = sort_coalesce(fixed);
    // Bytes past the slot (a damaged area list) are not this part's.
    let fixed: Vec<ByteRange> = subtract(fixed, [ByteRange::from_bounds(slot_len, u64::MAX)]).collect();
    Ok(MemberPart { index, start, end, slot_offset, fixed, lvs, diag })
}

impl DiskSet {
    /// The map of `device` (its coordinates; see the module docs of what the space outside
    /// the volumes is). On a disk: every volume's file system, every logical volume's
    /// projected onto the members on this disk, each container's metadata data, the rest of each
    /// member unused. On a logical volume: its partition table, its volumes' file systems, the
    /// logical volumes on it; project it onto the disks with
    /// [`device_to_disks`](Self::device_to_disks). Never finer than the device's sector. A volume
    /// that cannot be read, and a device whose partition table cannot be read, count as data (a
    /// diagnostic says so); only a cancel or a device that cannot be read fails it.
    pub fn map(
        &self,
        device: impl Into<DeviceRef>,
        opts: &DeviceMapOptions,
        cancel: Option<&CancelToken>,
    ) -> Result<Map> {
        fs_inspect_io::cancel::with_bound(cancel, || {
            let dev = self.device_index(device.into())?;
            let lw = self.wired()?;
            let mut unread = HashSet::new();
            for &v in &opts.unread {
                if v.ix() >= lw.0.leaves.len() {
                    return Err(fs_inspect_core::Error::not_found(format!("unread: no volume {v}")));
                }
                unread.extend(lw.0.slots_of(v));
            }
            let rules = Rules { exclude: opts.map.exclude(), zero: opts.map.zero(), unread };
            let m = device_map(lw, dev, &rules, &mut HashMap::new())?;
            let device = &lw.1.devices[dev];
            let len = device.source().size();
            let mut alloc = Vec::new();
            for r in m.alloc() {
                self.opts().cancel.check()?;
                fs_inspect_io::cancel::check_call()?;
                alloc.push(r?);
            }
            // Allocated bytes a dynamic container stores no data for read as zeros: zero.
            let (data, lacked) = match device.source().allocated_in(ByteRange::new(0, len))? {
                Some(h) => {
                    (intersect(alloc.iter().copied(), h.iter().copied()).collect(), subtract(alloc, h).collect())
                }
                None => (alloc, Vec::new()),
            };
            let zero: Vec<ByteRange> = union(m.zero.iter().copied(), lacked).collect();
            let sector = u64::from(device.sector()?);
            Ok(Map::new(data, zero, m.excluded.clone(), len, m.unit.max(sector), sector))
        })
    }
}
