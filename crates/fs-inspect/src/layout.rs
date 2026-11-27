//! What each byte of a device is ([`DiskLayout`], [`DiskSet::layout`]), where a volume's bytes
//! lie on the disks ([`DiskSet::volume_to_disks`], [`DiskSet::device_to_disks`]), and a device read
//! with some volumes from elsewhere ([`DiskSet::reader`]).
//!
//! The rules are the device map's ([`DiskSet::map`] derives from them): partition table
//! structures and the space before the first partition (boot loaders) belong to the table;
//! the last MiB outside the partitions is reserved (the LDM database of Windows dynamic disks,
//! firmware RAID metadata); a container member holds its volume manager's metadata and its
//! logical volumes' bytes; a device whose partition table cannot be read is unreadable, all of
//! it; the rest outside every volume is free. The same rules apply inside a logical volume (a
//! partitioned md array), projected onto its members.

use crate::CancelToken;
use crate::device::Device;
use crate::io::{SourceError, SourceErrorKind};
use crate::set::Ix;
use crate::set::{DeviceRef, DiskExtent, DiskProblem, DiskSet, Layout, Leaf, PlacedContainer, VolumeIndex};
use fs_inspect_core::range::{BoxRanges, sort_coalesce, subtract, union};
use fs_inspect_core::{ByteRange, Error, Result};
use fs_inspect_io::{BlockSource, DynSource, check_range};
use fs_inspect_volmgr::{self as vm, ContainerStatus, LogicalMap, MemberByte, MemberIx, RangesFactory};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

/// Bytes at the end of a device, outside its partitions, kept for metadata no table records.
const RESERVED_TAIL: u64 = 1 << 20;

fs_inspect_io::tagged_enum! {
    /// What a part of a device holds ([`DiskLayout`]).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum AreaContent ("area content") kind AreaContentKind {
        /// Partition table structures (MBR, EBRs, GPT headers and arrays, both copies) and the
        /// space before the first partition (boot loaders), of the device or of a partitioned
        /// logical volume on it.
        PartitionTable = 1 => "partition_table",
        /// A volume manager's metadata on its members: md superblock, write-intent bitmap and
        /// bad-block log; LVM label and metadata areas; the LDM database.
        VolumeManager = 2 => "volume_manager",
        /// What a volume manager holds on its members that no volume of the list describes: areas
        /// it uses for data no volume describes, all of a member of a container that cannot be
        /// mapped. Data, of any size.
        Opaque = 3 => "opaque",
        /// A volume of [`DiskSet::volumes`]: its partition, or on a logical volume the bytes
        /// holding it (every copy; with parity, whole rows; on the disks given when it cannot be
        /// read), or a ZFS pool's leaves.
        Volume(VolumeIndex) = 4 => "volume",
        /// A device (a disk, or a logical volume on it) whose partition table cannot be read
        /// ([`DiskLayout::problem`]): all data.
        Unreadable = 5 => "unreadable",
        /// The last MiB of a device outside its partitions: where the LDM database of Windows
        /// dynamic disks and firmware RAID metadata are kept, though no table records them.
        Reserved = 6 => "reserved",
        /// Nothing of the above: between partitions, free space of a container member.
        Free = 7 => "free",
    }
}

impl AreaContent {
    /// The volume's index, for [`AreaContent::Volume`].
    pub const fn volume(self) -> Option<VolumeIndex> {
        match self {
            AreaContent::Volume(i) => Some(i),
            _ => None,
        }
    }
}

/// Device bytes `range`, held by `kind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Area {
    pub range: ByteRange,
    pub content: AreaContent,
}

/// What each byte of one device of a set is: areas in order, covering the device
/// ([`DiskSet::layout`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskLayout {
    device: DeviceRef,
    len: u64,
    /// Sorted, adjacent, covering `[0, len)`; neighbours differ in kind.
    areas: Vec<Area>,
    /// Why the device's own partition table cannot be read.
    problem: Option<DiskProblem>,
    /// Sorted and coalesced.
    unsynced: Vec<ByteRange>,
}

impl DiskLayout {
    /// The device.
    pub fn device(&self) -> DeviceRef {
        self.device
    }

    /// The device's size in bytes.
    pub fn size(&self) -> u64 {
        self.len
    }

    /// Every area, in order.
    pub fn areas(&self) -> &[Area] {
        &self.areas
    }

    /// The area holding byte `offset` (`None` past the device's end).
    pub fn area_at(&self, offset: u64) -> Option<&Area> {
        let i = self.areas.partition_point(|a| a.range.end() <= offset);
        self.areas.get(i).filter(|a| a.range.offset <= offset)
    }

    /// `range` in pieces, in order, each in one area (cut at the device's end).
    pub fn split(&self, range: ByteRange) -> Vec<Area> {
        let end = range.end().min(self.len);
        let mut out = Vec::new();
        let mut at = range.offset;
        let mut i = self.areas.partition_point(|a| a.range.end() <= at);
        while at < end {
            let Some(a) = self.areas.get(i) else { break };
            let upto = a.range.end().min(end);
            out.push(Area { range: ByteRange::from_bounds(at, upto), content: a.content });
            at = upto;
            i += 1;
        }
        out
    }

    /// The bytes of the areas of `kind`, sorted.
    pub fn ranges(&self, kind: AreaContent) -> Vec<ByteRange> {
        self.areas.iter().filter(|a| a.content == kind).map(|a| a.range).collect()
    }

    /// The bytes of the areas of `kind`.
    pub fn bytes(&self, kind: AreaContent) -> u64 {
        self.areas.iter().filter(|a| a.content == kind).map(|a| a.range.length).sum()
    }

    /// The bytes the device needs outside its volumes, sorted and coalesced: partition
    /// tables and boot loaders, volume manager metadata, opaque and unreadable areas, the
    /// reserved tail. What [`DiskSet::map`] counts as data outside the volumes.
    pub fn system(&self) -> Vec<ByteRange> {
        sort_coalesce(
            self.areas
                .iter()
                .filter(|a| !matches!(a.content, AreaContent::Volume(_) | AreaContent::Free))
                .map(|a| a.range)
                .collect(),
        )
    }

    /// The device's own structures, sorted and coalesced: partition tables (with the space
    /// before the first partition), volume manager metadata, the reserved tail. Small and fixed,
    /// unlike [`system`](Self::system)'s opaque and unreadable areas (data of any size): what
    /// a backup keeps as the disk's layout, or compares by content.
    pub fn structures(&self) -> Vec<ByteRange> {
        sort_coalesce(
            self.areas
                .iter()
                .filter(|a| {
                    matches!(
                        a.content,
                        AreaContent::PartitionTable | AreaContent::VolumeManager | AreaContent::Reserved
                    )
                })
                .map(|a| a.range)
                .collect(),
        )
    }

    /// The bytes holding container members' copies that may not agree (sorted and
    /// coalesced; see [`MemberInfo::unsynced`](crate::MemberInfo::unsynced)): they may change
    /// while the volumes on top do not.
    pub fn unsynced(&self) -> &[ByteRange] {
        &self.unsynced
    }

    /// Why the device's partition table cannot be read (the device is then one
    /// [`AreaContent::Unreadable`] area).
    pub fn problem(&self) -> Option<DiskProblem> {
        self.problem
    }
}

fs_inspect_io::named_enum! {
    /// Which disk bytes stand for some of a volume's bytes ([`DiskSet::volume_to_disks`]).
    pub enum Projection ("projection") {
        /// Every disk byte that holds them or is computed from them: each copy, and with parity
        /// every chunk of each row they reach (parity included). What changes when they change.
        Written = 1 => "written",
        /// The disk bytes holding a copy of them (each mirror leg, the stripe chunk), parity left
        /// out. What reads back as them.
        Copies = 2 => "copies",
    }
}

/// What a device of a layout needs outside its partitions: its partition table's
/// ([`AreaContent::PartitionTable`]) and the reserved tail ([`AreaContent::Reserved`]), in its
/// coordinates, sorted, neither inside a partition.
pub(crate) struct Needs {
    pub(crate) table: Vec<ByteRange>,
    pub(crate) reserved: Vec<ByteRange>,
}

pub(crate) fn device_needs(dev: &Device) -> Result<Needs> {
    let len = dev.source().size();
    let parts: Vec<ByteRange> = sort_coalesce(
        dev.parts()?
            .iter()
            .map(|p| ByteRange::from_bounds(p.offset.min(len), p.offset.saturating_add(p.length).min(len)))
            .filter(|r| r.length > 0)
            .collect(),
    );
    let first = parts.first().map_or(len, |r| r.offset);
    let table: Vec<ByteRange> =
        union(dev.table_structures()?.iter().copied(), [ByteRange::from_bounds(0, first)]).collect();
    let table: Vec<ByteRange> = subtract(sort_coalesce(table), parts.iter().copied()).collect();
    let tail = [ByteRange::from_bounds(len.saturating_sub(RESERVED_TAIL), len)];
    let reserved = subtract(subtract(tail, parts.iter().copied()), table.iter().copied()).collect();
    Ok(Needs { table, reserved })
}

/// The bytes of member `mi`'s slot (`slot_len` bytes; slot coordinates, sorted and coalesced)
/// that its container holds whatever its volumes hold: its metadata
/// ([`AreaContent::VolumeManager`]) and what it holds that cannot be read as a volume
/// ([`AreaContent::Opaque`]).
pub(crate) fn member_fixed(p: &PlacedContainer, mi: MemberIx, slot_len: u64) -> Vec<ByteRange> {
    sort_coalesce([member_meta(p, mi, slot_len), member_opaque(p, mi, slot_len)].concat())
}

/// The metadata of member `mi`'s slot (slot coordinates, sorted and coalesced); none when the
/// container cannot be mapped (all of the slot is opaque).
fn member_meta(p: &PlacedContainer, mi: MemberIx, slot_len: u64) -> Vec<ByteRange> {
    if p.c.status == ContainerStatus::Unsupported {
        return Vec::new();
    }
    let meta = p.c.metadata.iter().filter(|(m, _)| *m == mi).map(|(_, r)| *r).collect();
    subtract(sort_coalesce(meta), [ByteRange::from_bounds(slot_len, u64::MAX)]).collect()
}

/// What member `mi`'s slot holds that cannot be read as a volume (slot coordinates, sorted and
/// coalesced, without the metadata): opaque areas and the areas of logical volumes that cannot
/// be read; all of the slot when the container cannot be mapped.
fn member_opaque(p: &PlacedContainer, mi: MemberIx, slot_len: u64) -> Vec<ByteRange> {
    if p.c.status == ContainerStatus::Unsupported {
        return vec![ByteRange::new(0, slot_len)];
    }
    let mut v: Vec<ByteRange> = p.c.opaque.iter().filter(|(m, _)| *m == mi).map(|(_, r)| *r).collect();
    for (vi, lv) in p.c.volumes.iter().enumerate() {
        if p.devices[vi].is_none() {
            v.extend(footprint(&lv.map, mi));
        }
    }
    let v = subtract(sort_coalesce(v), [ByteRange::from_bounds(slot_len, u64::MAX)]);
    subtract(v, member_meta(p, mi, slot_len)).collect()
}

/// The areas of logical volume `map` on member `mi` (slot coordinates).
pub(crate) fn footprint(map: &LogicalMap, mi: MemberIx) -> Vec<ByteRange> {
    map.footprint().into_iter().filter(|f| f.0 == mi).map(|(_, s, e)| ByteRange::from_bounds(s, e.max(s))).collect()
}

/// Most levels of logical volumes on logical volumes a projection follows.
const MAX_DEPTH: usize = 8;

/// The bytes holding `ranges` (sorted, coalesced) of device `dev` of the layout on every
/// device down to the disks, `dev` included: `(device, range)`.
fn down(
    l: &Layout,
    dev: usize,
    ranges: Vec<ByteRange>,
    how: Projection,
    depth: usize,
) -> Result<Vec<(usize, ByteRange)>> {
    if ranges.is_empty() {
        return Ok(Vec::new());
    }
    let mut out: Vec<(usize, ByteRange)> = ranges.iter().map(|&r| (dev, r)).collect();
    let DeviceRef::Logical { container, lv } = l.origins[dev] else { return Ok(out) };
    if depth >= MAX_DEPTH {
        return Err(Error::corrupt("logical volumes nested too deep"));
    }
    let p = &l.containers[container.ix()];
    let map = &p.c.volumes[lv.0 as usize].map;
    for (mi, m) in p.c.members.iter().enumerate() {
        let Some(s) = m.slot else { continue };
        let slot = &l.slots[s];
        let on: Vec<ByteRange> = match how {
            Projection::Written => {
                let r = Arc::new(ranges.clone());
                let f: RangesFactory =
                    Arc::new(move || Ok(Box::new(r.as_ref().clone().into_iter().map(Ok)) as BoxRanges<Error>));
                vm::project(map, mi, f).collect::<Result<Vec<_>>>()?
            }
            Projection::Copies => sort_coalesce(vm::project_zero(map, mi, &ranges)),
        };
        let on: Vec<ByteRange> =
            subtract(on, [ByteRange::from_bounds(slot.length, u64::MAX)]).map(|r| r.shifted(slot.offset)).collect();
        out.extend(down(l, slot.device, on, how, depth + 1)?);
    }
    Ok(out)
}

/// The disk bytes holding `ranges` (sorted, coalesced) of device `dev` of the layout, sorted.
fn to_disks(l: &Layout, dev: usize, ranges: Vec<ByteRange>, how: Projection) -> Result<Vec<DiskExtent>> {
    let mut out: Vec<DiskExtent> = down(l, dev, ranges, how, 0)?
        .into_iter()
        .filter_map(|(d, r)| match l.origins[d] {
            DeviceRef::Disk(disk) => Some(DiskExtent { disk, range: r }),
            DeviceRef::Logical { .. } => None,
        })
        .collect();
    out.sort();
    Ok(out)
}

/// The bytes of `ranges` of device `dev` on device `target`, sorted and coalesced.
fn on_device(l: &Layout, dev: usize, ranges: Vec<ByteRange>, target: usize) -> Result<Vec<ByteRange>> {
    Ok(sort_coalesce(
        down(l, dev, sort_coalesce(ranges), Projection::Written, 0)?
            .into_iter()
            .filter(|(d, _)| *d == target)
            .map(|(_, r)| r)
            .collect(),
    ))
}

/// `ranges` cut at `len`, sorted and coalesced.
fn within(ranges: &[ByteRange], len: u64) -> Vec<ByteRange> {
    sort_coalesce(
        ranges
            .iter()
            .filter_map(|r| {
                let end = r.end().min(len);
                (r.offset < end).then(|| ByteRange::from_bounds(r.offset, end))
            })
            .collect(),
    )
}

/// Each device's layout and reader, made once per set.
#[derive(Default)]
pub(crate) struct Made {
    layouts: Mutex<HashMap<DeviceRef, Arc<DiskLayout>>>,
    readers: Mutex<HashMap<DeviceRef, DynSource>>,
}

/// What `cell` keeps for `device`, else `make`'s (kept once made; an error is not).
fn made<T: Clone>(
    cell: &Mutex<HashMap<DeviceRef, T>>,
    device: DeviceRef,
    make: impl FnOnce() -> Result<T>,
) -> Result<T> {
    if let Some(v) = cell.lock().unwrap_or_else(PoisonError::into_inner).get(&device) {
        return Ok(v.clone());
    }
    // Made without the lock: another thread may make the same at once, and the first is kept.
    let v = make()?;
    Ok(cell.lock().unwrap_or_else(PoisonError::into_inner).entry(device).or_insert(v).clone())
}

impl DiskSet {
    /// What each byte of `device` is (a disk, or a logical volume in its own coordinates):
    /// partition table, volume manager metadata, what a volume manager holds that cannot be
    /// read, which volume, unreadable, reserved or free (see [`AreaContent`]); and which bytes
    /// hold members' copies that may not agree ([`DiskLayout::unsynced`]). Where kinds overlap
    /// (partitions of a damaged table), volumes come first (in index order), then unreadable
    /// devices, volume manager metadata, opaque areas, partition tables, then the reserved
    /// tail. Made once per set.
    pub fn layout(&self, device: impl Into<DeviceRef>, cancel: Option<&CancelToken>) -> Result<Arc<DiskLayout>> {
        fs_inspect_io::cancel::with_bound(cancel, || {
            let device = device.into();
            made(&self.made().layouts, device, || self.make_layout(device).map(Arc::new))
        })
    }

    fn make_layout(&self, device: DeviceRef) -> Result<DiskLayout> {
        let target = self.device_index(device)?;
        let (l, w) = self.wired()?;
        let len = w.devices[target].source().size();
        let mut kinds: Vec<(AreaContent, Vec<ByteRange>)> = Vec::new();
        for (i, leaf) in l.leaves.iter().enumerate() {
            let slots: Vec<usize> = match leaf {
                Leaf::Slot(s) => vec![*s],
                Leaf::Pool { slots, .. } => slots.iter().map(|&(_, s)| s).collect(),
                Leaf::Lv { .. } => Vec::new(),
            };
            let mut v = Vec::new();
            if let Leaf::Lv { .. } = leaf {
                // Not readable, its pieces on the disks given known all the same.
                for x in &l.volumes[i].disk_extents {
                    let Some(d) = l.device_of(DeviceRef::Disk(x.disk)) else { continue };
                    v.extend(on_device(l, d, vec![x.range], target)?);
                }
            }
            for s in slots {
                let s = &l.slots[s];
                let dev_len = w.devices[s.device].source().size();
                let r = ByteRange::from_bounds(s.offset.min(dev_len), s.offset.saturating_add(s.length).min(dev_len));
                v.extend(on_device(l, s.device, vec![r], target)?);
            }
            kinds.push((AreaContent::Volume(VolumeIndex(i as u32)), v));
        }
        let mut unreadable = Vec::new();
        for (d, t) in l.tables.iter().enumerate() {
            if t.is_err() {
                let whole = ByteRange::new(0, w.devices[d].source().size());
                unreadable.extend(on_device(l, d, vec![whole], target)?);
            }
        }
        kinds.push((AreaContent::Unreadable, unreadable));
        let (mut vmeta, mut opaque, mut unsynced) = (Vec::new(), Vec::new(), Vec::new());
        for s in &l.slots {
            let Some((ci, mi)) = s.claim else { continue };
            let p = &l.containers[ci];
            let at = |v: Vec<ByteRange>| v.into_iter().map(|r| r.shifted(s.offset)).collect::<Vec<_>>();
            vmeta.extend(on_device(l, s.device, at(member_meta(p, mi, s.length)), target)?);
            opaque.extend(on_device(l, s.device, at(member_opaque(p, mi, s.length)), target)?);
            let u: Vec<ByteRange> = p.c.unsynced.iter().filter(|(m, _)| *m == mi).map(|(_, r)| *r).collect();
            let u: Vec<ByteRange> = subtract(sort_coalesce(u), [ByteRange::from_bounds(s.length, u64::MAX)]).collect();
            unsynced.extend(on_device(l, s.device, at(u), target)?);
        }
        kinds.push((AreaContent::VolumeManager, vmeta));
        kinds.push((AreaContent::Opaque, opaque));
        let (mut table, mut reserved) = (Vec::new(), Vec::new());
        for (d, dev) in w.devices.iter().enumerate() {
            if l.tables[d].is_err() {
                continue;
            }
            let n = device_needs(dev)?;
            table.extend(on_device(l, d, n.table, target)?);
            reserved.extend(on_device(l, d, n.reserved, target)?);
        }
        kinds.push((AreaContent::PartitionTable, table));
        kinds.push((AreaContent::Reserved, reserved));
        let mut out = tile(device, len, kinds);
        out.problem = l.tables[target].as_ref().err().copied();
        out.unsynced = within(&unsynced, len);
        Ok(out)
    }

    /// The disk bytes holding bytes `ranges` of volume `index` (volume coordinates: 0 is the
    /// volume's first byte), sorted: on a partition, the same bytes moved by its offset; on a
    /// logical volume, as `how` says. Ranges past the volume's end are cut. A ZFS pool has no
    /// linear address space (`InvalidArgument`: its leaves are partitions,
    /// [`Volume::members`](crate::Volume::members)); a volume that cannot be read is
    /// `Unavailable`.
    pub fn volume_to_disks(
        &self,
        index: VolumeIndex,
        ranges: &[ByteRange],
        how: Projection,
        cancel: Option<&CancelToken>,
    ) -> Result<Vec<DiskExtent>> {
        fs_inspect_io::cancel::with_bound(cancel, || {
            let l = self.laid_out()?;
            let s = match l.leaves.get(index.ix()) {
                Some(Leaf::Slot(s)) => &l.slots[*s],
                Some(Leaf::Pool { .. }) => {
                    return Err(Error::invalid_argument(format!(
                        "volume {index} is a ZFS pool: no linear address space"
                    )));
                }
                Some(Leaf::Lv { .. }) => return Err(self.unreadable(l, index)),
                None => return Err(Error::not_found(format!("no volume {index}"))),
            };
            let v: Vec<ByteRange> = within(ranges, s.length).into_iter().map(|r| r.shifted(s.offset)).collect();
            to_disks(l, s.device, v, how)
        })
    }

    /// The disk bytes holding bytes `ranges` of `device` (its coordinates, as
    /// [`map`](Self::map)'s), sorted, as `how` says. Ranges past its end are cut.
    pub fn device_to_disks(
        &self,
        device: impl Into<DeviceRef>,
        ranges: &[ByteRange],
        how: Projection,
        cancel: Option<&CancelToken>,
    ) -> Result<Vec<DiskExtent>> {
        fs_inspect_io::cancel::with_bound(cancel, || {
            let dev = self.device_index(device.into())?;
            let (l, w) = self.wired()?;
            to_disks(l, dev, within(ranges, w.devices[dev].source().size()), how)
        })
    }

    /// `device` as this set reads it, as a source: the volumes read from elsewhere
    /// ([`replace_volume_source`](Self::replace_volume_source)) in place of their bytes, also where
    /// a logical volume's members on this device hold copies of them (linear, mirror and
    /// striped layouts; such a volume on a parity or RAID 10 layout is
    /// [`ErrorKind::Unsupported`](crate::ErrorKind::Unsupported): its member bytes are not
    /// copies of its bytes); everything else as the device reads. Made once per set.
    pub fn reader(&self, device: impl Into<DeviceRef>, cancel: Option<&CancelToken>) -> Result<DynSource> {
        fs_inspect_io::cancel::with_bound(cancel, || {
            let device = device.into();
            made(&self.made().readers, device, || self.make_reader(device))
        })
    }

    fn make_reader(&self, device: DeviceRef) -> Result<DynSource> {
        let target = self.device_index(device)?;
        let (l, w) = self.wired()?;
        let n = l.origins.len();
        // Per device: its bytes read from elsewhere (own volumes and from above), and the
        // pieces read from the logical volumes above it.
        let mut replaced: Vec<Vec<ByteRange>> = vec![Vec::new(); n];
        for &si in self.volume_sources().keys() {
            let s = &l.slots[si];
            replaced[s.device].push(ByteRange::new(s.offset, s.length));
        }
        let own: Vec<Vec<ByteRange>> = replaced.iter().map(|v| sort_coalesce(v.clone())).collect();
        let mut below: Vec<Vec<(ByteRange, Piece)>> = (0..n).map(|_| Vec::new()).collect();
        let mut composed: Vec<Option<DynSource>> = vec![None; n];
        for dev in (0..n).rev() {
            let base = w.devices[dev].source().clone();
            let pieces = std::mem::take(&mut below[dev]);
            let src: DynSource = if pieces.is_empty() { base } else { Arc::new(Spliced::new(base, pieces)) };
            composed[dev] = Some(src.clone());
            let DeviceRef::Logical { container, lv } = l.origins[dev] else { continue };
            let r = sort_coalesce(std::mem::take(&mut replaced[dev]));
            if r.is_empty() {
                continue;
            }
            let p = &l.containers[container.ix()];
            let map = &p.c.volumes[lv.0 as usize].map;
            if let Some(seg) = map.segments.iter().find(|seg| {
                !matches!(seg.layout, vm::Layout::Linear(_) | vm::Layout::Mirror { .. } | vm::Layout::Striped { .. })
                    && r.iter().any(|x| x.offset < seg.start + seg.len && seg.start < x.end())
            }) {
                return Err(Error::unsupported(format!(
                    "a volume read from elsewhere is on a {} logical volume: its member bytes are not copies of its \
                     bytes",
                    seg.layout.name()
                )));
            }
            for (mi, m) in p.c.members.iter().enumerate() {
                let Some(si) = m.slot else { continue };
                let slot = &l.slots[si];
                let on = sort_coalesce(vm::project_zero(map, mi, &r));
                let on = subtract(on, [ByteRange::from_bounds(slot.length, u64::MAX)]).map(|x| x.shifted(slot.offset));
                // The lower device's own volumes read from elsewhere come first.
                let on: Vec<ByteRange> = subtract(on, own[slot.device].iter().copied()).collect();
                for x in on {
                    let piece =
                        Piece::Member { map: map.clone(), member: mi, slot_offset: slot.offset, src: src.clone() };
                    below[slot.device].push((x, piece));
                    replaced[slot.device].push(x);
                }
            }
        }
        composed[target].take().ok_or_else(|| Error::corrupt(format!("no device for {device:?}")))
    }
}

/// Areas of each kind (earlier kinds first where they overlap) tiling `[0, len)`, the rest
/// free.
fn tile(device: DeviceRef, len: u64, kinds: Vec<(AreaContent, Vec<ByteRange>)>) -> DiskLayout {
    let mut taken: Vec<ByteRange> = Vec::new();
    let mut areas: Vec<Area> = Vec::new();
    for (kind, v) in kinds {
        let v: Vec<ByteRange> =
            subtract(subtract(sort_coalesce(v), [ByteRange::from_bounds(len, u64::MAX)]), taken.iter().copied())
                .collect();
        if v.is_empty() {
            continue;
        }
        areas.extend(v.iter().map(|&range| Area { range, content: kind }));
        taken = sort_coalesce(taken.into_iter().chain(v).collect());
    }
    areas.extend(
        fs_inspect_core::range::complement(taken, ByteRange::new(0, len))
            .map(|range| Area { range, content: AreaContent::Free }),
    );
    areas.sort_by_key(|a| a.range.offset);
    // Adjacent areas of one kind (a volume's copies side by side) as one.
    let mut merged: Vec<Area> = Vec::with_capacity(areas.len());
    for a in areas {
        match merged.last_mut() {
            Some(p) if p.content == a.content && p.range.end() == a.range.offset => {
                p.range = ByteRange::from_bounds(p.range.offset, a.range.end());
            }
            _ => merged.push(a),
        }
    }
    DiskLayout { device, len, areas: merged, problem: None, unsynced: Vec::new() }
}

/// Where a piece of a [`Spliced`] source is read from.
#[derive(Debug, Clone)]
pub(crate) enum Piece {
    /// A volume's own source: offset 0 is the piece's first byte; past its end, the base.
    Volume(DynSource),
    /// Member `member` of logical volume `map`, its slot at `slot_offset` of the base: each
    /// byte read from `src` (the logical volume) at the logical offset it is a copy of.
    Member { map: Arc<LogicalMap>, member: MemberIx, slot_offset: u64, src: DynSource },
}

/// A source read from `base` except for its pieces, each read from elsewhere.
#[derive(Debug)]
pub(crate) struct Spliced {
    base: DynSource,
    /// Sorted, disjoint, within the base.
    pieces: Vec<(ByteRange, Piece)>,
}

impl Spliced {
    /// `base` with each of `volumes` (its extent in the base, its source) read from its own
    /// source. Where extents overlap (a damaged table), the earlier one keeps the bytes.
    pub(crate) fn volumes(base: DynSource, volumes: Vec<(ByteRange, DynSource)>) -> Spliced {
        Spliced::new(base, volumes.into_iter().map(|(r, s)| (r, Piece::Volume(s))).collect())
    }

    pub(crate) fn new(base: DynSource, mut pieces: Vec<(ByteRange, Piece)>) -> Spliced {
        let len = base.size();
        pieces.sort_by_key(|(r, _)| r.offset);
        let mut out: Vec<(ByteRange, Piece)> = Vec::with_capacity(pieces.len());
        for (r, p) in pieces {
            let start = out.last().map_or(0, |(x, _)| x.end()).max(r.offset);
            let end = r.end().min(len);
            if start >= end {
                continue;
            }
            // A volume's piece cut at its start still reads its source from the right offset.
            let p = match p {
                Piece::Volume(s) if start > r.offset => match fs_inspect_io::OffsetSource::new(
                    s.clone(),
                    (start - r.offset).min(s.size()),
                    s.size().saturating_sub(start - r.offset),
                ) {
                    Ok(o) => Piece::Volume(Arc::new(o)),
                    Err(_) => Piece::Volume(Arc::new(fs_inspect_io::MemSource::new(Vec::new()))),
                },
                p => p,
            };
            out.push((ByteRange::from_bounds(start, end), p));
        }
        Spliced { base, pieces: out }
    }

    /// Reads the start of `buf` at `pos` from one place; how many bytes it read.
    fn read_some(&self, pos: u64, buf: &mut [u8]) -> Result<usize, SourceError> {
        let left = buf.len() as u64;
        let i = self.pieces.partition_point(|(r, _)| r.end() <= pos);
        let (r, p) = match self.pieces.get(i) {
            Some((r, p)) if r.offset <= pos => (r, p),
            Some((r, _)) => {
                let n = left.min(r.offset - pos) as usize;
                self.base.read_exact_at(pos, &mut buf[..n])?;
                return Ok(n);
            }
            None => {
                self.base.read_exact_at(pos, buf)?;
                return Ok(buf.len());
            }
        };
        let n = left.min(r.end() - pos);
        let k = match p {
            Piece::Volume(src) => {
                let o = pos - r.offset;
                if o < src.size() {
                    let k = n.min(src.size() - o) as usize;
                    src.read_exact_at(o, &mut buf[..k])?;
                    return Ok(k);
                }
                n
            }
            // A layout whose member bytes are not copies (parity) is refused when the reader is
            // built: an answer that fails is a map that contradicts itself.
            Piece::Member { map, member, slot_offset, src } => match map
                .logical_at(*member, pos - slot_offset)
                .map_err(|e| SourceError::caused_by(SourceErrorKind::Corrupt, e))?
            {
                MemberByte::Logical { offset, len } => {
                    let k = n.min(len) as usize;
                    src.read_exact_at(offset, &mut buf[..k])?;
                    return Ok(k);
                }
                MemberByte::Outside { len } => n.min(len),
                _ => n,
            },
        } as usize;
        self.base.read_exact_at(pos, &mut buf[..k])?;
        Ok(k)
    }
}

impl BlockSource for Spliced {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), SourceError> {
        check_range(offset, buf.len(), self.base.size())?;
        let mut done = 0usize;
        while done < buf.len() {
            done += self.read_some(offset + done as u64, &mut buf[done..])?;
        }
        Ok(())
    }

    fn size(&self) -> u64 {
        self.base.size()
    }

    fn alignment(&self) -> u32 {
        self.pieces.iter().map(|(_, p)| piece_source(p).alignment()).fold(self.base.alignment(), u32::max)
    }

    fn sector_size(&self) -> Option<u32> {
        self.base.sector_size()
    }

    fn queue_depth(&self) -> Option<std::num::NonZeroUsize> {
        let depth = |s: &dyn BlockSource| fs_inspect_io::queue_depth_of(s);
        let base = depth(&*self.base);
        std::num::NonZeroUsize::new(self.pieces.iter().map(|(_, p)| depth(&**piece_source(p))).fold(base, usize::min))
    }

    /// The base's answer outside the pieces; a volume's own inside its piece; a member's piece
    /// counts as allocated. `None` when neither the base nor any volume knows.
    fn allocated_in(&self, range: ByteRange) -> Result<Option<Vec<ByteRange>>, SourceError> {
        let end = range.end().min(self.base.size());
        let mut out = Vec::new();
        let mut known = false;
        let base = |r: ByteRange, out: &mut Vec<ByteRange>, known: &mut bool| -> Result<(), SourceError> {
            match self.base.allocated_in(r)? {
                Some(v) => {
                    *known = true;
                    out.extend(v);
                }
                None => out.push(r),
            }
            Ok(())
        };
        let mut at = range.offset;
        let mut i = self.pieces.partition_point(|(r, _)| r.end() <= at);
        while at < end {
            match self.pieces.get(i) {
                Some((r, p)) if r.offset <= at => {
                    let upto = r.end().min(end);
                    match p {
                        Piece::Volume(src) => {
                            let o = at - r.offset;
                            let mid = (r.offset + src.size()).clamp(at, upto);
                            if mid > at {
                                match src.allocated_in(ByteRange::new(o, mid - at))? {
                                    Some(v) => {
                                        known = true;
                                        out.extend(v.into_iter().map(|x| x.shifted(r.offset)));
                                    }
                                    None => out.push(ByteRange::from_bounds(at, mid)),
                                }
                            }
                            if upto > mid {
                                base(ByteRange::from_bounds(mid, upto), &mut out, &mut known)?;
                            }
                        }
                        Piece::Member { .. } => out.push(ByteRange::from_bounds(at, upto)),
                    }
                    at = upto;
                    i += 1;
                }
                Some((r, _)) => {
                    let upto = r.offset.min(end);
                    base(ByteRange::from_bounds(at, upto), &mut out, &mut known)?;
                    at = upto;
                }
                None => {
                    base(ByteRange::from_bounds(at, end), &mut out, &mut known)?;
                    at = end;
                }
            }
        }
        Ok(known.then(|| sort_coalesce(out)))
    }
}

fn piece_source(p: &Piece) -> &DynSource {
    match p {
        Piece::Volume(s) | Piece::Member { src: s, .. } => s,
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use fs_inspect_io::MemSource;

    const V0: VolumeIndex = VolumeIndex(0);

    fn r(o: u64, l: u64) -> ByteRange {
        ByteRange::new(o, l)
    }

    #[test]
    fn areas_tile_the_disk_earlier_kinds_first() {
        let l = tile(
            DeviceRef::Disk(crate::DiskIndex(0)),
            100,
            vec![
                (AreaContent::Volume(V0), vec![r(10, 40)]),
                (AreaContent::VolumeManager, vec![r(40, 20)]),
                (AreaContent::PartitionTable, vec![r(0, 10), r(95, 5)]),
                (AreaContent::Reserved, vec![r(90, 10)]),
            ],
        );
        let got: Vec<(u64, u64, AreaContent)> =
            l.areas().iter().map(|a| (a.range.offset, a.range.length, a.content)).collect();
        assert_eq!(
            got,
            [
                (0, 10, AreaContent::PartitionTable),
                (10, 40, AreaContent::Volume(V0)),
                (50, 10, AreaContent::VolumeManager),
                (60, 30, AreaContent::Free),
                (90, 5, AreaContent::Reserved),
                (95, 5, AreaContent::PartitionTable),
            ]
        );
        assert_eq!(l.area_at(55).unwrap().content, AreaContent::VolumeManager);
        assert!(l.area_at(100).is_none());
        let s = l.split(r(45, 20));
        assert_eq!(
            s.iter().map(|a| (a.range, a.content)).collect::<Vec<_>>(),
            [
                (r(45, 5), AreaContent::Volume(V0)),
                (r(50, 10), AreaContent::VolumeManager),
                (r(60, 5), AreaContent::Free)
            ]
        );
        assert_eq!(l.bytes(AreaContent::PartitionTable), 15);
    }

    #[test]
    fn a_spliced_volume_reads_its_source_then_the_base_past_its_end() {
        let base: DynSource = Arc::new(MemSource::new(vec![1; 64]));
        let snap: DynSource = Arc::new(MemSource::new(vec![2; 8]));
        let s = Spliced::volumes(base, vec![(r(16, 16), snap)]);
        let got = s.read_vec(12, 24).unwrap();
        assert_eq!(&got[..4], &[1; 4]);
        assert_eq!(&got[4..12], &[2; 8]);
        assert_eq!(&got[12..], &[1; 12]);
        assert!(s.read_vec(60, 8).is_err());
    }
}
