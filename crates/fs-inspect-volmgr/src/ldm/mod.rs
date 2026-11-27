//! Windows dynamic disks (LDM, the Logical Disk Manager database).
//!
//! The format is not documented by Microsoft. Every disk of a disk group holds a private
//! header (`PRIVHEAD`, version 2.11 or 2.12: on MBR disks at sector 6, on GPT disks in the
//! last sector of the LDM metadata partition) naming the disk, its group, its data area
//! (`logical_disk_start`/`size`) and the group's database (`config_start`/`size`, 1 MiB).
//! Only slots whose partition type marks them as LDM data are looked at. The database
//! (`VMDB` version 4.10): table-of-contents blocks (`TOCBLOCK`), whose `config` entry says
//! where the `VMDB` header is (17 sectors in on 512-byte sectors, 2 on 4Kn), followed by
//! fixed-size `VBLK` records (larger ones split into fragments): volumes, their components
//! (plexes), the partitions (subdisks) composing those and the disks. Every disk keeps a copy;
//! the one with the most records wins.
//!
//! The private header's and table of contents' sector counts are in the disk's logical
//! sectors: 4096 bytes on a 4Kn disk (seen on Windows Server 2016), where the private header
//! is in sector 6 or the metadata partition's last 4096 bytes. A disk's sector size is the one
//! under which its private header is found. The records count 512-byte sectors on any disk.
//!
//! Mapped volumes: simple and spanned (concatenated partitions: `simple` on one disk,
//! `spanned` over several, as Windows names them), striped, mirrored (two or more plexes of one
//! partition each) and RAID-5. Any other volume (a mirror whose plex has several partitions,
//! an unknown volume or component type) is unreadable and its partitions count as data. The
//! database keeps no resync state, so mirror and RAID-5 copies always count as possibly out of
//! sync. Big-endian throughout.

use crate::map::{Area, Layout, LogicalMap, ParityAlgo, Segment};
use crate::{Container, LogicalDef, Member, MemberRole, Readability, Slot, SlotHint, VolumeManager, status_of};
use fs_inspect_core::DiagnosticExt;
use fs_inspect_core::bytes::{be_u16_at, be_u32_at, be_u64_at};
use fs_inspect_core::{ByteRange, DiagCode, Diagnostic, Error, Limits, Result};
use fs_inspect_io::{BlockSource, DynSource};
use std::collections::HashMap;
use std::sync::Arc;

/// Logical sector sizes a dynamic disk may have.
const SECTOR_SIZES: [u64; 2] = [512, 4096];
/// The unit of the database records' sizes and positions, whatever the disk's sector size.
const REC_SECTOR: u64 = 512;
/// The database's size Windows uses (bytes).
const DB_BYTES: u64 = 1 << 20;
/// Where the `VMDB` header is when no `TOCBLOCK` says (bytes after the database's start).
const OFF_VMDB: u64 = 17 * 512;
/// Most records read from one database (more is a `Limit` error).
const MAX_VBLKS: usize = 1 << 16;

/// RAID-5 parity rotation of dynamic volumes: left-symmetric, columns in partition index
/// order. Found on a Windows Server 2022 RAID-5 volume (fixtures/ldm/windows): of the four
/// rotations and both column orders, only this one reads its NTFS consistently (a `$Bitmap`
/// of 14.7 MiB used, like the group's other empty volumes; about 2 GiB under the others).
pub const RAID5_ALGO: ParityAlgo = ParityAlgo::LeftSymmetric;

/// A disk's private header.
#[derive(Debug, Clone)]
pub struct PrivHead {
    /// The disk's logical sector size: the unit of the sector counts here and in the table of
    /// contents.
    pub sector: u64,
    /// The disk's GUID (lower case).
    pub disk_id: String,
    /// The disk group's GUID (lower case).
    pub group_id: String,
    pub group_name: String,
    /// The data area's start, in sectors from the start of the disk.
    pub data_start: u64,
    /// The data area's size, in sectors.
    pub data_size: u64,
    /// The database's start, in sectors from the start of the disk.
    pub config_start: u64,
    /// The database's size, in sectors (at most 4 MiB).
    pub config_size: u64,
}

fn ascii(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).trim().to_string()
}

/// The private header in `b`, on a disk of `sector`-byte sectors: `None` without the
/// signature, for a version other than 2.11 or 2.12, or a database size of 0 or over 4 MiB.
pub fn parse_privhead(b: &[u8], sector: u64) -> Option<PrivHead> {
    if b.get(..8)? != b"PRIVHEAD" {
        return None;
    }
    let (major, minor) = (be_u16_at(b, 0x0C).ok()?, be_u16_at(b, 0x0E).ok()?);
    if major != 2 || !(11..=12).contains(&minor) {
        return None;
    }
    let ph = PrivHead {
        sector,
        disk_id: ascii(b.get(0x30..0x70)?).to_ascii_lowercase(),
        group_id: ascii(b.get(0xB0..0xF0)?).to_ascii_lowercase(),
        group_name: ascii(b.get(0xF0..0x10F)?),
        data_start: be_u64_at(b, 0x11B).ok()?,
        data_size: be_u64_at(b, 0x123).ok()?,
        config_start: be_u64_at(b, 0x12B).ok()?,
        config_size: be_u64_at(b, 0x133).ok()?,
    };
    (ph.config_size > 0 && ph.config_size.checked_mul(sector)? <= 4 * DB_BYTES).then_some(ph)
}

/// A VBLK record's variable-length number: a length byte, then that many big-endian bytes.
fn vnum(b: &[u8], at: usize) -> Option<u64> {
    let n = *b.get(at)? as usize;
    if n > 8 {
        return None;
    }
    Some(b.get(at + 1..at + 1 + n)?.iter().fold(0u64, |a, &x| (a << 8) | u64::from(x)))
}

/// Position after the variable-length field at `base + rel` (relative to `base`).
fn after(b: &[u8], base: usize, rel: usize) -> Option<usize> {
    Some(rel + 1 + *b.get(base + rel)? as usize)
}

fn vstr(b: &[u8], at: usize) -> Option<String> {
    let n = *b.get(at)? as usize;
    Some(String::from_utf8_lossy(b.get(at + 1..at + 1 + n)?).into_owned())
}

/// A database record, the fields read from it.
#[derive(Debug, Clone)]
pub enum Vblk {
    /// A volume (record type 0x51); `kind`: `gen` (simple, spanned, striped, mirror) or
    /// `raid5`; `size` in 512-byte sectors.
    Volume { id: u64, name: String, kind: String, size: u64, guid: [u8; 16] },
    /// A component, or plex, of volume `parent` (0x32). `kind`: 1 striped, 2 concatenated,
    /// 3 RAID-5; `chunk` in 512-byte sectors.
    Component { id: u64, name: String, kind: u8, parent: u64, chunk: u64, columns: u64 },
    /// A partition, or subdisk, of component `parent` on disk record `disk` (0x33). `start`
    /// in 512-byte sectors from the disk's data area; `offset` (sectors) in its component;
    /// `index`: its column in a striped or RAID-5 component (absent for column 0).
    Partition { id: u64, name: String, start: u64, offset: u64, size: u64, parent: u64, disk: u64, index: Option<u8> },
    /// A disk (0x34, GUID as text; 0x44, GUID as bytes); `guid` lower case, dashed.
    Disk { id: u64, name: String, guid: String },
    /// The disk group (0x35, 0x45).
    Group { id: u64, name: String },
    /// Any other record type.
    Other,
}

/// A GUID stored as 16 bytes in a record (a 0x44 disk record, a volume): big-endian, so its
/// bytes in order are its text, the same Windows prints for the volume
/// (`\\?\Volume{...}`, and the `DMIO:ID:` value of `MountedDevices` decoded as a GUID
/// structure).
fn guid_bytes(b: &[u8]) -> String {
    let g = |r: std::ops::Range<usize>| b[r].iter().map(|x| format!("{x:02x}")).collect::<String>();
    format!("{}-{}-{}-{}-{}", g(0..4), g(4..6), g(6..8), g(8..10), g(10..16))
}

/// Parse one (reassembled) VBLK record: the 16-byte header, then the record.
pub fn parse_vblk(b: &[u8]) -> Option<Vblk> {
    if b.len() < 0x19 {
        return None;
    }
    let (flags, kind) = (b[0x12], b[0x13]);
    let r_objid = after(b, 0x18, 0)?;
    let r_name = after(b, 0x18, r_objid)?;
    let id = vnum(b, 0x18)?;
    let name = vstr(b, 0x18 + r_objid)?;
    Some(match kind {
        0x51 => {
            let r_vtype = after(b, 0x18, r_name)?;
            let r_ddl = after(b, 0x18, r_vtype)?;
            let r_child = after(b, 0x2D, r_ddl)?;
            let r_size = after(b, 0x3D, r_child)?;
            let mut guid = [0u8; 16];
            guid.copy_from_slice(b.get(0x42 + r_size..0x52 + r_size)?);
            Vblk::Volume { id, name, kind: vstr(b, 0x18 + r_name)?, size: vnum(b, 0x3D + r_child)?, guid }
        }
        0x32 => {
            let r_vstate = after(b, 0x18, r_name)?;
            let r_child = after(b, 0x1D, r_vstate)?;
            let r_parent = after(b, 0x2D, r_child)?;
            let (chunk, columns) = if flags & 0x10 != 0 {
                let r_stripe = after(b, 0x2E, r_parent)?;
                (vnum(b, 0x2E + r_parent)?, vnum(b, 0x2E + r_stripe)?)
            } else {
                (0, 0)
            };
            Vblk::Component {
                id,
                name,
                kind: *b.get(0x18 + r_vstate)?,
                parent: vnum(b, 0x2D + r_child)?,
                chunk,
                columns,
            }
        }
        0x33 => {
            let r_size = after(b, 0x34, r_name)?;
            let r_parent = after(b, 0x34, r_size)?;
            let r_diskid = after(b, 0x34, r_parent)?;
            Vblk::Partition {
                id,
                name,
                start: be_u64_at(b, 0x24 + r_name).ok()?,
                offset: be_u64_at(b, 0x2C + r_name).ok()?,
                size: vnum(b, 0x34 + r_name)?,
                parent: vnum(b, 0x34 + r_size)?,
                disk: vnum(b, 0x34 + r_parent)?,
                index: (flags & 0x08 != 0).then(|| b.get(0x35 + r_diskid).copied()).flatten(),
            }
        }
        0x34 => Vblk::Disk { id, name, guid: vstr(b, 0x18 + r_name)?.to_ascii_lowercase() },
        0x44 => Vblk::Disk { id, name, guid: guid_bytes(b.get(0x18 + r_name..0x28 + r_name)?) },
        0x35 | 0x45 => Vblk::Group { id, name },
        _ => Vblk::Other,
    })
}

/// Where the `VMDB` header is (bytes after the database's start), as a `TOCBLOCK` in the
/// database's first sectors says (its `config` entry, in sectors).
fn vmdb_offset(disk: &dyn BlockSource, base: u64, sector: u64) -> Result<u64> {
    let head = disk.read_vec(base, (4 * sector) as usize)?;
    for toc in head.as_chunks::<512>().0.iter().filter(|b| b.starts_with(b"TOCBLOCK")) {
        for e in [0x24, 0x46] {
            if toc.get(e..e + 8).is_some_and(|n| n.starts_with(b"config\0")) {
                let start = be_u64_at(toc, e + 10)?;
                if let Some(off) = start.checked_mul(sector).filter(|&o| o > 0 && o < DB_BYTES) {
                    return Ok(off);
                }
            }
        }
    }
    Ok(OFF_VMDB)
}

/// The records of the database at `config_start` of `disk` (sectors of `sector` bytes).
pub fn read_database(disk: &dyn BlockSource, config_start: u64, sector: u64) -> Result<Vec<Vblk>> {
    let base = config_start.checked_mul(sector).ok_or_else(|| Error::corrupt("LDM database past 2^64"))?;
    let at = base + vmdb_offset(disk, base, sector)?;
    let vmdb = disk.read_vec(at, 512)?;
    if &vmdb[..4] != b"VMDB" {
        return Err(Error::corrupt("LDM database without VMDB"));
    }
    let (last, size, offset) = (be_u32_at(&vmdb, 4)?, be_u32_at(&vmdb, 8)? as usize, be_u32_at(&vmdb, 12)? as u64);
    let (vmaj, vmin) = (be_u16_at(&vmdb, 0x12)?, be_u16_at(&vmdb, 0x14)?);
    if (vmaj, vmin) != (4, 10) || !(32..=512).contains(&size) || 512 % size != 0 {
        return Err(Error::corrupt(format!("LDM VMDB version {vmaj}.{vmin}, record size {size}")));
    }
    // Records run from `offset` to `size * last` bytes after the VMDB's sector start.
    let count = (last as usize).saturating_sub(offset as usize / size);
    if count > MAX_VBLKS {
        return Err(Error::limit(format!("LDM database with {count} records")));
    }
    let bytes = disk.read_vec(at + offset, count * size)?;
    let mut out = Vec::new();
    // Fragments: group -> (count, pieces by index).
    type Pieces = (u16, Vec<Option<Vec<u8>>>);
    let mut frags: HashMap<u32, Pieces> = HashMap::new();
    for rec in bytes.chunks_exact(size) {
        if &rec[..4] != b"VBLK" {
            continue;
        }
        let (group, index, n) = (be_u32_at(rec, 8)?, be_u16_at(rec, 12)?, be_u16_at(rec, 14)?);
        match n {
            0 => {}
            1 => out.extend(parse_vblk(rec)),
            _ => {
                if n > 64 || index >= n {
                    continue;
                }
                let e = frags.entry(group).or_insert_with(|| (n, vec![None; n as usize]));
                if e.0 == n {
                    e.1[index as usize] = Some(rec.to_vec());
                }
            }
        }
    }
    for (_, (_, pieces)) in frags {
        if pieces.iter().any(Option::is_none) {
            continue;
        }
        // The first piece's header, then every piece's body.
        let mut whole: Vec<u8> = pieces[0].as_ref().map(|p| p[..16].to_vec()).unwrap_or_default();
        for p in pieces.iter().flatten() {
            whole.extend_from_slice(&p[16..]);
        }
        out.extend(parse_vblk(&whole));
    }
    Ok(out)
}

/// A dynamic disk found among the slots: its data slot and header.
struct Found {
    slot: usize,
    ph: PrivHead,
    /// The disk the slot is on, and where the slot starts in it.
    disk: DynSource,
    slot_offset: u64,
}

fn same(a: &DynSource, b: &DynSource) -> bool {
    std::ptr::addr_eq(Arc::as_ptr(a), Arc::as_ptr(b))
}

/// Assemble the disk groups of the slots not in `taken`; LDM data partitions whose private
/// header could not be read go to `unreadable`.
pub fn assemble(
    slots: &[Slot],
    taken: &[usize],
    _limits: &Limits,
    unreadable: &mut Vec<(usize, Error)>,
) -> Vec<Container> {
    let mut found: Vec<Found> = Vec::new();
    for (i, s) in slots.iter().enumerate() {
        if taken.contains(&i) || s.hint != SlotHint::LdmData {
            continue;
        }
        let Some((disk, slot_offset)) = s.parent.clone() else { continue };
        // MBR: sector 6 of the disk; GPT: the last sector of the disk's LDM metadata partition.
        let mut candidates: Vec<(u64, u64)> = SECTOR_SIZES.iter().map(|&ss| (6 * ss, ss)).collect();
        for o in slots.iter() {
            if o.hint == SlotHint::LdmMetadata
                && let Some((d, off)) = &o.parent
                && same(d, &disk)
            {
                for ss in SECTOR_SIZES.into_iter().filter(|&ss| o.source.size() >= ss) {
                    candidates.push((off + o.source.size() - ss, ss));
                }
            }
        }
        let mut err = None;
        let ph = candidates.into_iter().find_map(|(at, ss)| match disk.read_vec(at, 512) {
            Ok(b) => parse_privhead(&b, ss),
            Err(e) => {
                err.get_or_insert(e);
                None
            }
        });
        match (ph, err) {
            (Some(ph), _) => found.push(Found { slot: i, ph, disk, slot_offset }),
            (None, Some(e)) => unreadable.push((i, e.context("LDM private header"))),
            (None, None) => {}
        }
    }
    let mut groups: HashMap<String, Vec<Found>> = HashMap::new();
    for f in found {
        groups.entry(f.ph.group_id.clone()).or_default().push(f);
    }
    let mut ids: Vec<_> = groups.keys().cloned().collect();
    ids.sort();
    let mut out = Vec::new();
    for id in ids {
        let g = groups.remove(&id).unwrap_or_default();
        match build(slots, g) {
            Ok(c) => out.push(c),
            Err(e) => tracing::warn!(group = %id, error = %e, "LDM disk group not assembled"),
        }
    }
    out
}

fn build(slots: &[Slot], g: Vec<Found>) -> Result<Container> {
    let mut notes = Vec::new();
    let db = best_database(&g, &mut notes)?;
    let group_name = db
        .iter()
        .find_map(|v| if let Vblk::Group { name, .. } = v { Some(name.clone()) } else { None })
        .unwrap_or_else(|| g[0].ph.group_name.clone());
    let (members, grp) = Group::new(&db, &g, &mut notes);
    let metadata = grp.database_areas(slots);
    let mut volumes = Vec::new();
    let mut opaque = Vec::new();
    for v in &db {
        let Vblk::Volume { id, name, kind, size, guid } = v else { continue };
        let comps: Vec<&Vblk> =
            db.iter().filter(|c| matches!(c, Vblk::Component { parent, .. } if parent == id)).collect();
        // Every partition of the volume is in use, mapped or not.
        let cids = db.iter().filter_map(|c| match c {
            Vblk::Component { id: cid, parent, .. } if parent == id => Some(*cid),
            _ => None,
        });
        for cid in cids {
            for p in grp.parts_of(cid) {
                if let Some(a) = grp.area(p.disk, p.start) {
                    opaque.push((a.member, ByteRange::new(a.start, p.size.saturating_mul(REC_SECTOR))));
                }
            }
        }
        let built = grp.volume_map(kind, &comps, size.saturating_mul(REC_SECTOR));
        volumes.push(define(slots, &members, name, guid_bytes(guid), kind, built, &mut notes));
    }
    let opaque = crate::uncovered(opaque, &volumes);
    let missing: Vec<String> = members.iter().filter(|m| m.slot.is_none()).map(|m| m.role.to_string()).collect();
    if !missing.is_empty() {
        notes.push(Diagnostic::warning(
            DiagCode::ContainerIncomplete,
            format!("LDM disk group {group_name}: disks not found: {}", missing.join(", ")),
        ));
    }
    let status = status_of(&members, &volumes);
    // The database keeps no resync state: a mirror's or RAID 5's copies are not known to agree.
    let unsynced = volumes
        .iter()
        .filter(|v| v.map.segments.iter().any(|s| matches!(s.layout, Layout::Mirror { .. } | Layout::Parity { .. })))
        .flat_map(|v| v.map.footprint())
        .map(|(m, s, e)| (m, ByteRange::from_bounds(s, e.max(s))))
        .collect();
    Ok(Container {
        kind: VolumeManager::Ldm,
        name: group_name,
        uuid: g[0].ph.group_id.clone(),
        members,
        volumes,
        metadata,
        opaque,
        unsynced,
        status,
        notes,
    })
}

/// The fullest readable copy of the group's database.
fn best_database(g: &[Found], notes: &mut Vec<Diagnostic>) -> Result<Vec<Vblk>> {
    let mut best: Option<Vec<Vblk>> = None;
    for f in g {
        match read_database(&*f.disk, f.ph.config_start, f.ph.sector) {
            Ok(v) if best.as_ref().is_none_or(|b| v.len() > b.len()) => best = Some(v),
            Ok(_) => {}
            Err(e) => notes.push(Diagnostic::warning(
                DiagCode::ChecksumMismatch,
                format!("LDM database on disk {}: {e}", f.ph.disk_id),
            )),
        }
    }
    best.ok_or_else(|| Error::corrupt("no readable LDM database"))
}

/// A partition record of the database: where it starts on its disk and in its component, its
/// size (sectors) and its column.
#[derive(Debug, Clone, Copy)]
struct Part {
    start: u64,
    offset: u64,
    size: u64,
    disk: u64,
    index: Option<u8>,
}

/// A disk group's database with its disks found.
struct Group<'a> {
    db: &'a [Vblk],
    g: &'a [Found],
    /// Member index of each disk record, by object id.
    by_obj: HashMap<u64, usize>,
    /// The disk found for each member.
    found_of: Vec<Option<usize>>,
}

impl<'a> Group<'a> {
    /// The members (every disk record, matched to a found disk by GUID) and the group. A
    /// GUID on two disks (a cloned disk) is the first of them; the other is not claimed.
    fn new(db: &'a [Vblk], g: &'a [Found], notes: &mut Vec<Diagnostic>) -> (Vec<Member>, Group<'a>) {
        let mut members = Vec::new();
        let mut by_obj = HashMap::new();
        let mut found_of = Vec::new();
        for v in db {
            if let Vblk::Disk { id, name, guid } = v {
                let f = g.iter().position(|f| &f.ph.disk_id == guid);
                let copies = g.iter().filter(|f| &f.ph.disk_id == guid).count();
                if copies > 1 {
                    notes.push(Diagnostic::warning(
                        DiagCode::DuplicateMember,
                        format!("LDM disk {name} ({guid}) is on {copies} disks (a clone?); the first is used"),
                    ));
                }
                by_obj.insert(*id, members.len());
                members.push(Member {
                    id: guid.clone(),
                    slot: f.map(|k| g[k].slot),
                    role: MemberRole::Disk(name.clone()),
                });
                found_of.push(f);
            }
        }
        (members, Group { db, g, by_obj, found_of })
    }

    /// Where each member's database lies inside its slot (MBR: the end of the 0x42 partition).
    fn database_areas(&self, slots: &[Slot]) -> Vec<(usize, ByteRange)> {
        let mut out = Vec::new();
        for (m, f) in self.found_of.iter().enumerate() {
            let Some(f) = f.map(|k| &self.g[k]) else { continue };
            let (a, b) = (
                f.ph.config_start.saturating_mul(f.ph.sector),
                f.ph.config_start.saturating_add(f.ph.config_size).saturating_mul(f.ph.sector),
            );
            let len = slots[f.slot].source.size();
            let (a, b) = (a.saturating_sub(f.slot_offset).min(len), b.saturating_sub(f.slot_offset).min(len));
            if b > a {
                out.push((m, ByteRange::from_bounds(a, b)));
            }
        }
        out
    }

    /// Member `m`'s data area start in its slot (bytes).
    fn base(&self, m: usize) -> Option<u64> {
        let f = &self.g[(*self.found_of.get(m)?)?];
        f.ph.data_start.checked_mul(f.ph.sector)?.checked_sub(f.slot_offset)
    }

    /// The area of the member that is disk record `disk`, `start` sectors into its data.
    fn area(&self, disk: u64, start: u64) -> Option<Area> {
        let m = *self.by_obj.get(&disk)?;
        Some(Area { member: m, start: self.base(m).unwrap_or(0).checked_add(start.checked_mul(REC_SECTOR)?)? })
    }

    /// The partitions of component `cid`, by column then offset.
    fn parts_of(&self, cid: u64) -> Vec<Part> {
        let mut p: Vec<Part> = self
            .db
            .iter()
            .filter_map(|x| match x {
                Vblk::Partition { start, offset, size, parent, disk, index, .. } if *parent == cid => {
                    Some(Part { start: *start, offset: *offset, size: *size, disk: *disk, index: *index })
                }
                _ => None,
            })
            .collect();
        p.sort_by_key(|x| (x.index, x.offset));
        p
    }

    /// Component `cid`'s partitions one after the other: (start in the volume, length, area),
    /// in bytes.
    fn concat(&self, cid: u64) -> std::result::Result<Vec<(u64, u64, Area)>, String> {
        let mut parts = Vec::new();
        for p in self.parts_of(cid) {
            let a = self.area(p.disk, p.start).ok_or("a partition on an unknown disk")?;
            parts.push((p.offset.saturating_mul(REC_SECTOR), p.size.saturating_mul(REC_SECTOR), a));
        }
        parts.sort_by_key(|p| p.0);
        Ok(parts)
    }

    /// The areas of component `cid`'s columns, one partition each: as many as the component
    /// says it has (`want`), or the volume would be mapped over the wrong columns.
    fn columns(&self, cid: u64, want: u64) -> std::result::Result<Vec<Area>, String> {
        let parts = self.parts_of(cid);
        if parts.len() as u64 != want
            || parts.iter().enumerate().any(|(i, p)| u64::from(p.index.unwrap_or(0)) != i as u64)
        {
            return Err(format!("{} column partitions for {want} columns", parts.len()));
        }
        parts
            .iter()
            .map(|c| self.area(c.disk, c.start))
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| "a column on an unknown disk".into())
    }

    /// The layout name and map of a volume of `kind` made of `comps`, `len` bytes long.
    fn volume_map(&self, kind: &str, comps: &[&Vblk], len: u64) -> std::result::Result<(String, LogicalMap), String> {
        let one = |layout: Layout| LogicalMap { len, segments: vec![Segment { start: 0, len, layout }] };
        match (kind, comps) {
            ("gen", [Vblk::Component { id: cid, kind: 2, .. }]) => {
                let parts = self.concat(*cid)?;
                let name = concat_layout(&parts);
                let segments = parts
                    .into_iter()
                    .map(|(start, len, a)| Segment { start, len, layout: Layout::Linear(a) })
                    .collect();
                Ok((name.into(), LogicalMap { len, segments }))
            }
            ("gen", [Vblk::Component { id: cid, kind: 1, chunk, columns, .. }]) => {
                let areas = self.columns(*cid, *columns)?;
                Ok(("striped".into(), one(Layout::Striped { chunk: chunk.saturating_mul(REC_SECTOR), areas })))
            }
            ("gen", plexes) if plexes.len() >= 2 => {
                let mut legs = Vec::new();
                for p in plexes {
                    let Vblk::Component { id: cid, kind: 2, .. } = p else {
                        return Err("a mirror of non-simple plexes".into());
                    };
                    match self.concat(*cid)?.as_slice() {
                        [(0, _, a)] => legs.push(*a),
                        _ => return Err("a mirror plex that is not one partition".into()),
                    }
                }
                Ok(("mirror".into(), one(Layout::Mirror { legs })))
            }
            ("raid5", [Vblk::Component { id: cid, kind: 3, chunk, columns, .. }]) => {
                let areas = self.columns(*cid, *columns)?;
                let layout = Layout::Parity {
                    chunk: chunk.saturating_mul(REC_SECTOR),
                    algo: RAID5_ALGO,
                    raid6: false,
                    first_row: 0,
                    areas,
                };
                Ok(("raid5".into(), one(layout)))
            }
            (k, c) => Err(format!("a {k} volume of {} plexes", c.len())),
        }
    }
}

/// The layout name of a concatenated volume, as Windows names it: `simple` when its partitions
/// are all on one disk (however many there are: a simple volume extended on its own disk keeps
/// its name), `spanned` when they are on several.
fn concat_layout(parts: &[(u64, u64, Area)]) -> &'static str {
    let mut disks = parts.iter().map(|p| p.2.member);
    let first = disks.next();
    if disks.all(|m| Some(m) == first) { "simple" } else { "spanned" }
}

/// Volume `name`'s definition from its map as built: unreadable (counted as data, with a
/// note) when it could not be built or does not fit its members.
fn define(
    slots: &[Slot],
    members: &[Member],
    name: &str,
    uuid: String,
    kind: &str,
    built: std::result::Result<(String, LogicalMap), String>,
    notes: &mut Vec<Diagnostic>,
) -> LogicalDef {
    let unreadable = |layout: String| LogicalDef {
        name: name.to_string(),
        uuid: uuid.clone(),
        layout,
        map: Arc::default(),
        readable: Readability::No,
    };
    match built {
        Ok((layout, map)) => {
            let lens = |m: usize| members.get(m).and_then(|x| x.slot).map(|s| slots[s].source.size());
            if let Err(e) = map.validate(&lens, usize::MAX) {
                notes.push(Diagnostic::warning(
                    DiagCode::Inconsistent,
                    format!("LDM volume {name}: {e}; it counts as data"),
                ));
                return unreadable(layout);
            }
            let readable = map.readable(&|m: usize| members.get(m).is_some_and(|x| x.slot.is_some()));
            LogicalDef { name: name.to_string(), uuid, layout, map: Arc::new(map), readable }
        }
        Err(why) => {
            notes.push(Diagnostic::warning(
                DiagCode::UnsupportedLayout,
                format!("LDM volume {name}: {why}; it counts as data"),
            ));
            unreadable(kind.to_string())
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    /// A volume record's GUID from a Windows Server 2025 dynamic disk: its bytes in order are
    /// the text Windows prints (`\?\Volume{266b2805-dfec-11f1-bcd3-00155d0be630}`).
    #[test]
    fn a_record_guid_reads_as_windows_prints_it() {
        let stored = [0x26, 0x6B, 0x28, 0x05, 0xDF, 0xEC, 0x11, 0xF1, 0xBC, 0xD3, 0x00, 0x15, 0x5D, 0x0B, 0xE6, 0x30];
        assert_eq!(guid_bytes(&stored), "266b2805-dfec-11f1-bcd3-00155d0be630");
    }

    fn disk(id: u64) -> Vblk {
        Vblk::Disk { id, name: format!("Disk{id}"), guid: format!("{id:08x}-0000-0000-0000-000000000000") }
    }

    /// Partition `id` of component 10 on disk record `disk`: `size` sectors at `start` on the
    /// disk, `offset` sectors into the component.
    fn part(id: u64, disk: u64, start: u64, offset: u64, size: u64) -> Vblk {
        Vblk::Partition { id, name: format!("P{id}"), start, offset, size, parent: 10, disk, index: None }
    }

    /// The layout name and the (member, start) of each segment of a `gen` volume whose one
    /// concatenated plex (component 10) holds `parts`, on disks 1 and 2.
    fn concatenated(parts: Vec<Vblk>) -> (String, Vec<(usize, u64)>) {
        let comp = Vblk::Component { id: 10, name: "Volume1-01".into(), kind: 2, parent: 9, chunk: 0, columns: 0 };
        let mut db = vec![disk(1), disk(2), comp.clone()];
        db.extend(parts);
        let len = db.iter().map(|v| if let Vblk::Partition { size, .. } = v { size * REC_SECTOR } else { 0 }).sum();
        let (_, g) = Group::new(&db, &[], &mut Vec::new());
        let (layout, map) = g.volume_map("gen", &[&comp], len).expect("mapped");
        let at = map
            .segments
            .iter()
            .map(|s| match s.layout {
                Layout::Linear(a) => (a.member, a.start),
                _ => panic!("not linear"),
            })
            .collect();
        (layout, at)
    }

    /// One partition on one disk is what Windows calls a simple volume, not `spanned`.
    #[test]
    fn one_partition_on_one_disk_is_simple() {
        let (layout, at) = concatenated(vec![part(20, 1, 2048, 0, 4096)]);
        assert_eq!((layout.as_str(), at), ("simple", vec![(0, 2048 * REC_SECTOR)]));
    }

    /// A simple volume extended on its own disk stays simple.
    #[test]
    fn partitions_on_one_disk_are_simple() {
        let (layout, at) = concatenated(vec![part(20, 2, 0, 0, 4096), part(21, 2, 8192, 4096, 4096)]);
        assert_eq!((layout.as_str(), at), ("simple", vec![(1, 0), (1, 8192 * REC_SECTOR)]));
    }

    #[test]
    fn partitions_on_two_disks_are_spanned() {
        let (layout, at) = concatenated(vec![part(20, 1, 0, 0, 4096), part(21, 2, 0, 4096, 4096)]);
        assert_eq!((layout.as_str(), at), ("spanned", vec![(0, 0), (1, 0)]));
    }

    fn comp(id: u64, kind: u8, chunk: u64, columns: u64) -> Vblk {
        Vblk::Component { id, name: format!("C{id}"), kind, parent: 9, chunk, columns }
    }

    /// Partition `id` of component `parent`, column `index`, `size` sectors at `start` of `disk`.
    fn column(id: u64, parent: u64, disk: u64, start: u64, index: Option<u8>) -> Vblk {
        Vblk::Partition { id, name: format!("P{id}"), start, offset: 0, size: 4096, parent, disk, index }
    }

    /// The layout name and map of a volume of `kind` over the components `comps` (ids), with
    /// `db` holding disks 1, 2 and 3 and everything else.
    fn mapped(db: Vec<Vblk>, kind: &str, comps: &[u64]) -> std::result::Result<(String, LogicalMap), String> {
        let mut all = vec![disk(1), disk(2), disk(3)];
        all.extend(db);
        let (_, g) = Group::new(&all, &[], &mut Vec::new());
        let comps: Vec<&Vblk> = comps
            .iter()
            .map(|c| all.iter().find(|v| matches!(v, Vblk::Component { id, .. } if id == c)).unwrap())
            .collect();
        g.volume_map(kind, &comps, 1 << 20)
    }

    fn area(member: usize, sectors: u64) -> Area {
        Area { member, start: sectors * REC_SECTOR }
    }

    #[test]
    fn striped_and_raid5_volumes_take_their_columns_in_order() {
        // The columns are listed out of order; column 0 has no index.
        let parts = vec![column(21, 10, 2, 100, Some(1)), column(20, 10, 1, 0, None), column(22, 10, 3, 7, Some(2))];
        let mut db = vec![comp(10, 1, 128, 3)];
        db.extend(parts.clone());
        let (name, map) = mapped(db, "gen", &[10]).unwrap();
        assert_eq!(name, "striped");
        let want = vec![area(0, 0), area(1, 100), area(2, 7)];
        assert_eq!(map.segments[0].layout, Layout::Striped { chunk: 128 * REC_SECTOR, areas: want.clone() });
        let mut db = vec![comp(10, 3, 128, 3)];
        db.extend(parts);
        let (name, map) = mapped(db, "raid5", &[10]).unwrap();
        assert_eq!(name, "raid5");
        assert_eq!(
            map.segments[0].layout,
            Layout::Parity { chunk: 128 * REC_SECTOR, algo: RAID5_ALGO, raid6: false, first_row: 0, areas: want }
        );
    }

    #[test]
    fn a_striped_volume_without_each_of_its_columns_is_not_mapped() {
        // Two partitions for three columns: mapping them would put data in the wrong columns.
        let db = vec![comp(10, 1, 128, 3), column(20, 10, 1, 0, None), column(21, 10, 2, 0, Some(1))];
        assert_eq!(mapped(db, "gen", &[10]).unwrap_err(), "2 column partitions for 3 columns");
        // Three partitions, but two claim column 1 and none column 2.
        let db = vec![
            comp(10, 1, 128, 3),
            column(20, 10, 1, 0, None),
            column(21, 10, 2, 0, Some(1)),
            column(22, 10, 3, 0, Some(1)),
        ];
        assert_eq!(mapped(db, "gen", &[10]).unwrap_err(), "3 column partitions for 3 columns");
        // A column on a disk the database does not list.
        let db = vec![comp(10, 1, 128, 2), column(20, 10, 1, 0, None), column(21, 10, 9, 0, Some(1))];
        assert_eq!(mapped(db, "gen", &[10]).unwrap_err(), "a column on an unknown disk");
        // A concatenated plex's partition on an unknown disk.
        let db = vec![comp(10, 2, 0, 0), column(20, 10, 9, 0, None)];
        assert_eq!(mapped(db, "gen", &[10]).unwrap_err(), "a partition on an unknown disk");
    }

    #[test]
    fn a_mirror_has_one_leg_per_simple_plex() {
        let db = vec![comp(10, 2, 0, 0), comp(11, 2, 0, 0), column(20, 10, 1, 64, None), column(21, 11, 2, 32, None)];
        let (name, map) = mapped(db, "gen", &[10, 11]).unwrap();
        assert_eq!(name, "mirror");
        assert_eq!(map.segments[0].layout, Layout::Mirror { legs: vec![area(0, 64), area(1, 32)] });
        // A plex of two partitions is no mirror leg.
        let db = vec![
            comp(10, 2, 0, 0),
            comp(11, 2, 0, 0),
            column(20, 10, 1, 0, None),
            Vblk::Partition {
                id: 22,
                name: "P22".into(),
                start: 9000,
                offset: 4096,
                size: 4096,
                parent: 10,
                disk: 1,
                index: None,
            },
            column(21, 11, 2, 0, None),
        ];
        assert_eq!(mapped(db, "gen", &[10, 11]).unwrap_err(), "a mirror plex that is not one partition");
        // A striped plex is no mirror leg either.
        let db = vec![comp(10, 2, 0, 0), comp(11, 1, 128, 1), column(20, 10, 1, 0, None), column(21, 11, 2, 0, None)];
        assert_eq!(mapped(db, "gen", &[10, 11]).unwrap_err(), "a mirror of non-simple plexes");
    }

    #[test]
    fn a_volume_of_another_kind_is_named_in_the_error() {
        let db = vec![comp(10, 2, 0, 0), column(20, 10, 1, 0, None)];
        assert_eq!(mapped(db.clone(), "raid1", &[10]).unwrap_err(), "a raid1 volume of 1 plexes");
        // A RAID-5 volume whose plex is concatenated.
        assert_eq!(mapped(db, "raid5", &[10]).unwrap_err(), "a raid5 volume of 1 plexes");
    }

    /// A private header (`PRIVHEAD`) of version 2.`minor` with a database of `config_size`
    /// sectors.
    fn privhead(minor: u16, config_size: u64) -> Vec<u8> {
        let mut b = vec![0u8; 512];
        b[..8].copy_from_slice(b"PRIVHEAD");
        b[0x0C..0x0E].copy_from_slice(&2u16.to_be_bytes());
        b[0x0E..0x10].copy_from_slice(&minor.to_be_bytes());
        b[0x30..0x34].copy_from_slice(b"AB-C");
        b[0xB0..0xB2].copy_from_slice(b"Gx");
        b[0xF0..0xF6].copy_from_slice(b"Dg0\0\0\0");
        b[0x11B..0x123].copy_from_slice(&63u64.to_be_bytes());
        b[0x123..0x12B].copy_from_slice(&1000u64.to_be_bytes());
        b[0x12B..0x133].copy_from_slice(&1100u64.to_be_bytes());
        b[0x133..0x13B].copy_from_slice(&config_size.to_be_bytes());
        b
    }

    #[test]
    fn a_private_header_is_read_only_in_the_versions_and_sizes_windows_writes() {
        for minor in [11, 12] {
            let ph = parse_privhead(&privhead(minor, 2048), 512).expect("read");
            assert_eq!((ph.disk_id.as_str(), ph.group_id.as_str(), ph.group_name.as_str()), ("ab-c", "gx", "Dg0"));
            assert_eq!((ph.data_start, ph.data_size, ph.config_start, ph.config_size), (63, 1000, 1100, 2048));
        }
        assert!(parse_privhead(&privhead(10, 2048), 512).is_none());
        // No database, or one larger than the 1 MiB Windows reserves (four times over).
        assert!(parse_privhead(&privhead(12, 0), 512).is_none());
        assert!(parse_privhead(&privhead(12, 1024), 4096).is_some());
        assert!(parse_privhead(&privhead(12, 1025), 4096).is_none());
        assert!(parse_privhead(&privhead(12, u64::MAX), 512).is_none());
        let mut other = privhead(12, 2048);
        other[0] = b'X';
        assert!(parse_privhead(&other, 512).is_none());
        assert!(parse_privhead(&privhead(12, 2048)[..0x100], 512).is_none());
    }

    /// A database record (`VBLK`) of `size` bytes: header, then `body` from 0x10.
    fn vblk(size: usize, group: u32, index: u16, count: u16, body: &[u8]) -> Vec<u8> {
        let mut r = vec![0u8; size];
        r[..4].copy_from_slice(b"VBLK");
        r[8..12].copy_from_slice(&group.to_be_bytes());
        r[12..14].copy_from_slice(&index.to_be_bytes());
        r[14..16].copy_from_slice(&count.to_be_bytes());
        r[16..16 + body.len()].copy_from_slice(body);
        r
    }

    /// The body (from 0x10) of a disk group record 0x45 of object id `id` named `name`.
    fn group_body(id: u8, name: &str) -> Vec<u8> {
        let mut b = vec![0u8; 8];
        b[2] = 0; // flags (0x12)
        b[3] = 0x45; // type (0x13)
        b.extend([1, id, name.len() as u8]);
        b.extend(name.as_bytes());
        b
    }

    const SIZE: usize = 128;

    /// A database at sector 0: a TOCBLOCK (when `toc` names the VMDB's sector), the VMDB with
    /// records of `size` bytes from 512 bytes after it, `version`, and `records`.
    fn database(toc: Option<u64>, version: (u16, u16), size: u32, records: &[Vec<u8>]) -> Vec<u8> {
        let vmdb_at = toc.map_or(OFF_VMDB, |s| s * 512) as usize;
        let mut img = vec![0u8; vmdb_at + 512 + records.len() * SIZE + 4096];
        if let Some(sector) = toc {
            let t = &mut img[512..1024];
            t[..8].copy_from_slice(b"TOCBLOCK");
            // The first entry names another area; the second the database's records.
            t[0x24..0x2B].copy_from_slice(b"bitmap\0");
            t[0x46..0x4D].copy_from_slice(b"config\0");
            t[0x46 + 10..0x46 + 18].copy_from_slice(&sector.to_be_bytes());
        }
        let v = &mut img[vmdb_at..vmdb_at + 512];
        v[..4].copy_from_slice(b"VMDB");
        let last = 512 / size + records.len() as u32;
        v[4..8].copy_from_slice(&last.to_be_bytes());
        v[8..12].copy_from_slice(&size.to_be_bytes());
        v[12..16].copy_from_slice(&512u32.to_be_bytes());
        v[0x12..0x14].copy_from_slice(&version.0.to_be_bytes());
        v[0x14..0x16].copy_from_slice(&version.1.to_be_bytes());
        for (i, r) in records.iter().enumerate() {
            let at = vmdb_at + 512 + i * SIZE;
            img[at..at + r.len()].copy_from_slice(r);
        }
        img
    }

    fn read(img: Vec<u8>) -> Result<Vec<Vblk>> {
        read_database(&fs_inspect_io::MemSource::new(img), 0, 512)
    }

    fn groups(v: &[Vblk]) -> Vec<(u64, String)> {
        let mut g: Vec<_> = v
            .iter()
            .filter_map(|v| if let Vblk::Group { id, name } = v { Some((*id, name.clone())) } else { None })
            .collect();
        g.sort();
        g
    }

    #[test]
    fn a_database_s_records_are_read_and_fragments_joined() {
        // Record 7 in two fragments (its name runs into the second), given second first.
        let whole = group_body(7, &"long-name-".repeat(15));
        let (first, rest) = whole.split_at(SIZE - 16);
        let records = vec![
            vblk(SIZE, 1, 0, 1, &group_body(5, "Dg0")),
            vblk(SIZE, 2, 1, 2, rest),
            // Not a record, a free slot (no fragment count), and an incomplete fragmented one.
            vec![0u8; SIZE],
            vblk(SIZE, 3, 0, 0, &group_body(6, "free")),
            vblk(SIZE, 4, 0, 2, &group_body(8, "half")),
            vblk(SIZE, 2, 0, 2, first),
            // A fragment index past its count, and a count past what Windows writes: ignored.
            vblk(SIZE, 5, 2, 2, &group_body(9, "bad")),
            vblk(SIZE, 6, 0, 65, &group_body(10, "bad")),
        ];
        let got = read(database(None, (4, 10), SIZE as u32, &records)).unwrap();
        let long = String::from_utf8_lossy(&whole[11..]).into_owned();
        assert_eq!(groups(&got), [(5, "Dg0".to_string()), (7, long)]);
        // The same where a TOCBLOCK puts the VMDB elsewhere.
        let got = read(database(Some(40), (4, 10), SIZE as u32, &records)).unwrap();
        assert_eq!(groups(&got).len(), 2);
    }

    #[test]
    fn a_database_that_is_not_one_windows_writes_is_refused() {
        let corrupt = |img: Vec<u8>, what: &str| {
            let e = read(img).unwrap_err();
            assert_eq!(e.kind(), fs_inspect_core::ErrorKind::Corrupt, "{e}");
            assert!(e.to_string().contains(what), "{e}");
        };
        let mut img = database(None, (4, 10), SIZE as u32, &[]);
        img[OFF_VMDB as usize] = b'X';
        corrupt(img, "without VMDB");
        corrupt(database(None, (4, 11), SIZE as u32, &[]), "VMDB version 4.11, record size 128");
        // A record size that does not divide a sector, or out of range.
        corrupt(database(None, (4, 10), 96, &[]), "record size 96");
        corrupt(database(None, (4, 10), 1024, &[]), "record size 1024");
        // More records than any database holds: refused before reading them.
        let mut img = database(None, (4, 10), SIZE as u32, &[]);
        img[OFF_VMDB as usize + 4..OFF_VMDB as usize + 8].copy_from_slice(&100_000u32.to_be_bytes());
        assert_eq!(read(img).unwrap_err().kind(), fs_inspect_core::ErrorKind::Limit);
        // A database whose start is past 2^64 bytes.
        let e = read_database(&fs_inspect_io::MemSource::new(vec![0; 512]), u64::MAX, 512).unwrap_err();
        assert!(e.to_string().contains("past 2^64"), "{e}");
    }

    #[test]
    fn a_record_s_numbers_and_type_are_read_with_their_lengths() {
        assert_eq!(vnum(&[2, 0x01, 0x02], 0), Some(0x102));
        assert_eq!(vnum(&[0], 0), Some(0));
        // More than 8 bytes cannot be a u64; a length past the record is no number.
        assert_eq!(vnum(&[9, 1, 2, 3, 4, 5, 6, 7, 8, 9], 0), None);
        assert_eq!(vnum(&[4, 1, 2], 0), None);
        // A record too short for its header, and one of a type not read.
        assert!(parse_vblk(&[0u8; 0x18]).is_none());
        let mut other = vblk(SIZE, 1, 0, 1, &group_body(5, "x"));
        other[0x13] = 0x99;
        assert!(matches!(parse_vblk(&other), Some(Vblk::Other)));
        // A disk record with its GUID as text (0x34) is read lower case.
        let mut body = vec![0, 0, 0, 0x34, 0, 0, 0, 0, 1, 3, 2];
        body.extend(b"D3");
        let guid = "ABCDEF01-0000-0000-0000-000000000000";
        body.push(guid.len() as u8);
        body.extend(guid.as_bytes());
        match parse_vblk(&vblk(SIZE, 1, 0, 1, &body)) {
            Some(Vblk::Disk { id, name, guid }) => {
                assert_eq!((id, name.as_str(), guid.as_str()), (3, "D3", "abcdef01-0000-0000-0000-000000000000"));
            }
            v => panic!("{v:?}"),
        }
    }
}
