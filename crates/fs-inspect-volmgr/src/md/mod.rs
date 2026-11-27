//! Linux md RAID: version 0.90 and 1.x superblocks and the array layouts (linear, RAID 0, 1,
//! 4, 5, 6 and 10).
//!
//! Superblocks: 0.90 in the 64 KiB reserved at the end of the device (host-endian; only
//! little-endian is read), 1.0 at the end (4 KiB aligned, 8 KiB before it), 1.1 at the start,
//! 1.2 at 4 KiB. Members are grouped by array UUID; a member whose event count lags the newest
//! is stale (not read; the array may still be read through redundancy).
//!
//! Not mapped (the container is `Unsupported` and its members count as data): a reshape in
//! progress (1.x, or a 0.91 superblock, which is not recognized at all), the clustered,
//! journal and PPL features, RAID 0 over members of different sizes (several zones), RAID 10
//! with far sets, and unknown levels and parity layouts.
//!
//! A linear or RAID 0 array with a member missing cannot be read or placed (where each
//! member's part lies in the array depends on the missing member's size): the container is
//! `Incomplete`, its volume is unreadable with an empty map, and the whole data area of every
//! member present counts as data.
//!
//! Each member keeps as data: its superblock, the write-intent bitmap (sized from its own
//! header; the whole space beside the data area when that header cannot be read) and the
//! bad-block log. Its data area beyond what the array uses is unused.
//!
//! Sync state ([`Container::unsynced`], redundant levels only): a resync checkpoint short of
//! the end (1.x `resync_offset`; 0.90 without its clean flag) leaves the rest of every
//! member's data out of sync; each chunk the write-intent bitmap marks is out of sync on every
//! member (RAID 10 counts its bits in array space: any bit, all of it); a stale or unreadable
//! bitmap, a stale member and a member being rebuilt (from its `recovery_offset`) are out of
//! sync whole or from there.

use crate::map::{Area, Layout, LogicalMap, ParityAlgo, Segment};
use crate::{Container, ContainerStatus, LogicalDef, Member, MemberRole, Readability, Slot, VolumeManager, status_of};
use fs_inspect_core::DiagnosticExt;
use fs_inspect_core::bytes::{u16_at, u32_at, u64_at};
use fs_inspect_core::{ByteRange, DiagCode, Diagnostic, Error, Limits, Result};
use fs_inspect_io::BlockSource;
use std::collections::HashMap;
use std::sync::Arc;

const MAGIC: u32 = 0xA92B_4EFC;
const SECTOR: u64 = 512;
const BITMAP_MAGIC: u32 = 0x6D74_6962; // "bitm"
/// Largest write-intent bitmap read (bytes of bits); a larger one counts as all set.
const MAX_BITMAP_BYTES: u64 = 16 << 20;
/// Every data byte.
const ALL: ByteRange = ByteRange { offset: 0, length: u64::MAX };

/// What a member's superblock says.
#[derive(Debug, Clone)]
pub struct Super {
    /// 0 (0.90), 10 (1.0), 11 (1.1), 12 (1.2).
    pub version: u8,
    /// The array UUID, shared by every member.
    pub uuid: [u8; 16],
    /// The array name (1.x), or `md<minor>` (0.90).
    pub name: String,
    /// RAID level: -1 linear, 0, 1, 4, 5, 6, 10.
    pub level: i32,
    /// md's layout number: the parity rotation (RAID 5/6) or the copy arrangement (RAID 10).
    pub layout: u32,
    /// Bytes.
    pub chunk: u64,
    /// Members holding a role (spares not counted).
    pub raid_disks: u32,
    /// Bytes of each member the array uses (0.90 `size`, 1.x `size`).
    pub size: u64,
    /// Where the data starts in the member, and how much it holds (1.x `data_size`).
    pub data_offset: u64,
    pub data_size: u64,
    /// Where this superblock is.
    pub sb_offset: u64,
    /// This member's role (`None`: a spare or a faulty device).
    pub role: Option<u32>,
    /// Event count: the newest among the members is current, lower ones are stale.
    pub events: u64,
    /// Member bytes that are metadata (superblock, bitmap, bad-block log).
    pub metadata: Vec<ByteRange>,
    /// Data bytes (from the data offset, in per-device space; RAID 10's bitmap: array space)
    /// this superblock says may not be in sync across the copies.
    pub unsynced: Vec<ByteRange>,
    /// This member is being rebuilt: its data from here on (bytes from the data offset).
    pub recovery: Option<u64>,
    /// Why the array cannot be mapped, if it cannot.
    pub unsupported: Option<String>,
}

fn fold(sum: u64) -> u32 {
    ((sum & 0xFFFF_FFFF) + (sum >> 32)) as u32
}

/// The 4 KiB at `off` (`Err`: the read error).
fn read_block(slot: &dyn BlockSource, off: u64) -> Result<Vec<u8>> {
    slot.read_vec(off, 4096)
}

/// 0.90 at the end of `slot`.
fn read_090(slot: &dyn BlockSource) -> Result<Option<Super>> {
    let len = slot.size();
    if len < 128 << 10 {
        return Ok(None);
    }
    let off = (len & !(64 * 1024 - 1)) - 64 * 1024;
    let b = read_block(slot, off)?;
    Ok(parse_090(slot, &b, off))
}

/// The 0.90 superblock `b` read at `off`, if it is one.
fn parse_090(slot: &dyn BlockSource, b: &[u8], off: u64) -> Option<Super> {
    let len = slot.size();
    let w = |i: usize| u32_at(b, i * 4).unwrap_or(0);
    if w(0) != MAGIC || w(1) != 0 || w(2) != 90 {
        return None;
    }
    let mut sum = 0u64;
    for i in 0..1024 {
        if i != 38 {
            sum += u64::from(w(i));
        }
    }
    if fold(sum) != w(38) && (sum & 0xFFFF_FFFF) as u32 != w(38) {
        return None;
    }
    let mut uuid = [0u8; 16];
    for (k, i) in [5usize, 13, 14, 15].iter().enumerate() {
        uuid[k * 4..k * 4 + 4].copy_from_slice(&w(*i).to_le_bytes());
    }
    // this_disk: the last 32 words; raid_disk at +3, state at +4 (active 1<<1, sync 1<<2).
    let (raid_disk, state) = (w(992 + 3), w(992 + 4));
    let role = (state & 0b110 == 0b110).then_some(raid_disk);
    let size = u64::from(w(8)) * 1024;
    let events = (u64::from(w(40)) << 32) | u64::from(w(39));
    // State: clean (bit 0), a bitmap after the superblock (bit 8).
    let state = w(33);
    let mut unsynced = Vec::new();
    if state & 1 == 0 {
        unsynced.push(ALL);
    }
    if state & (1 << 8) != 0 {
        unsynced.extend(read_bitmap(slot, off + 4096, events).map_or(vec![ALL], |(_, d)| d));
    }
    Some(Super {
        version: 0,
        uuid,
        name: format!("md{}", w(11)),
        level: w(7) as i32,
        layout: w(64),
        chunk: u64::from(w(65)),
        raid_disks: w(10),
        size,
        data_offset: 0,
        data_size: off,
        sb_offset: off,
        role,
        events,
        // The reserved area: superblock and any internal bitmap after it.
        metadata: vec![ByteRange::from_bounds(off, len)],
        unsynced,
        recovery: None,
        // 0.91 (a reshape in progress) is not read at all: the member stays data.
        unsupported: None,
    })
}

/// 1.x at `off` of `slot`.
fn read_1x(slot: &dyn BlockSource, off: u64, version: u8) -> Result<Option<Super>> {
    if off + 4096 > slot.size() {
        return Ok(None);
    }
    let b = read_block(slot, off)?;
    Ok(parse_1x(slot, &b, off, version))
}

/// The 1.x superblock `b` read at `off`, if it is one (checked: magic, major version, device
/// table size, checksum, its own offset).
fn parse_1x(slot: &dyn BlockSource, b: &[u8], off: u64, version: u8) -> Option<Super> {
    if u32_at(b, 0).ok()? != MAGIC || u32_at(b, 4).ok()? != 1 {
        return None;
    }
    let max_dev = u32_at(b, 220).ok()? as usize;
    if max_dev > 1920 || fold(checksum_1x(b, 256 + max_dev * 2)?) != u32_at(b, 216).ok()? {
        return None;
    }
    if u64_at(b, 144).ok()? * SECTOR != off {
        return None; // a copy of a superblock found somewhere else
    }
    let feature = u32_at(b, 8).ok()?;
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&b[16..32]);
    let name = String::from_utf8_lossy(&b[32..64]).trim_end_matches('\0').to_string();
    let dev_number = u32_at(b, 160).ok()? as usize;
    let role = if dev_number < max_dev {
        let r = u16_at(b, 256 + 2 * dev_number).ok()?;
        (r < 0xFFFD).then_some(u32::from(r))
    } else {
        None
    };
    let data_offset = u64_at(b, 128).ok()?.checked_mul(SECTOR)?;
    let data_size = u64_at(b, 136).ok()?.checked_mul(SECTOR)?;
    let events = u64_at(b, 200).ok()?;
    let gap = if data_offset > off {
        // 1.1 / 1.2: between the superblock and the data.
        ByteRange::from_bounds(off, data_offset)
    } else {
        // 1.0: from the end of the data to the end of the member.
        ByteRange::from_bounds(data_offset.saturating_add(data_size), slot.size())
    };
    let (metadata, unsynced) = areas_1x(slot, b, off, gap, events)?;
    Some(Super {
        version,
        uuid,
        name,
        level: u32_at(b, 72).ok()? as i32,
        layout: u32_at(b, 76).ok()?,
        chunk: u64::from(u32_at(b, 88).ok()?) * SECTOR,
        raid_disks: u32_at(b, 92).ok()?,
        size: u64_at(b, 80).ok()?.checked_mul(SECTOR)?,
        data_offset,
        data_size,
        sb_offset: off,
        role,
        events,
        metadata,
        unsynced,
        recovery: (feature & 2 != 0).then(|| u64_at(b, 152).ok().map(|r| r.saturating_mul(SECTOR))).flatten(),
        unsupported: unsupported_1x(feature),
    })
}

/// The sum of the first `n` bytes of a 1.x superblock (32-bit words, then a 16-bit tail),
/// without its checksum field.
fn checksum_1x(b: &[u8], n: usize) -> Option<u64> {
    let mut sum = 0u64;
    let mut i = 0;
    while i + 4 <= n {
        if i != 216 {
            sum += u64::from(u32_at(b, i).ok()?);
        }
        i += 4;
    }
    if i < n {
        sum += u64::from(u16_at(b, i).ok()?);
    }
    Some(sum)
}

/// The metadata areas of the 1.x superblock `b` at `off` (itself, its write-intent bitmap and
/// bad-block log; `gap` when the bitmap cannot be read), and what of the data may be out of
/// sync.
fn areas_1x(
    slot: &dyn BlockSource,
    b: &[u8],
    off: u64,
    gap: ByteRange,
    events: u64,
) -> Option<(Vec<ByteRange>, Vec<ByteRange>)> {
    let feature = u32_at(b, 8).ok()?;
    let mut metadata = vec![ByteRange::new(off, 4096)];
    let mut unsynced = Vec::new();
    let resync = u64_at(b, 208).ok()?;
    if resync != u64::MAX {
        unsynced.push(ByteRange::from_bounds(resync.saturating_mul(SECTOR), u64::MAX));
    }
    if feature & 1 != 0 {
        let rel = i64::from(u32_at(b, 96).ok()? as i32) * SECTOR as i64;
        let at = (off as i64 + rel) as u64;
        match read_bitmap(slot, at, events) {
            Some((n, dirty)) => {
                metadata.push(ByteRange::new(at, n));
                unsynced.extend(dirty);
            }
            None => {
                metadata.push(gap);
                unsynced.push(ALL);
            }
        }
    }
    let (bb_size, bb_off) = (u64::from(u16_at(b, 186).ok()?), u32_at(b, 188).ok()? as i32);
    if bb_size > 0 && bb_off != 0 {
        let at = (off as i64 + i64::from(bb_off) * SECTOR as i64) as u64;
        metadata.push(ByteRange::new(at, bb_size * SECTOR));
    }
    Some((metadata, unsynced))
}

/// Why a 1.x array with `feature` bits cannot be mapped, if it cannot.
fn unsupported_1x(feature: u32) -> Option<String> {
    if feature & 4 != 0 {
        Some("a reshape is in progress".to_string())
    } else if feature & (256 | 512 | 1024 | 2048) != 0 {
        Some(format!("features {feature:#x} (clustered, journal or PPL) are not mapped"))
    } else {
        None
    }
}

/// The write-intent bitmap at `at`: its bytes (the 256-byte header and one bit per chunk of
/// the sync range, 4 KiB aligned), and the sync-space bytes it says may be out of sync (the
/// chunks whose bit is set; all when it is older than the superblock (`events`), marked stale,
/// too large or unreadable). `None`: no bitmap header there.
fn read_bitmap(slot: &dyn BlockSource, at: u64, events: u64) -> Option<(u64, Vec<ByteRange>)> {
    let h = slot.read_vec(at, 256).ok()?;
    if u32_at(&h, 0).ok()? != BITMAP_MAGIC {
        return None;
    }
    let sync = u64_at(&h, 40).ok()?.checked_mul(SECTOR)?;
    let chunk = u64::from(u32_at(&h, 52).ok()?);
    if chunk < 512 || !chunk.is_power_of_two() {
        return None;
    }
    let bits = sync.div_ceil(chunk);
    let len = (256 + bits.div_ceil(8)).div_ceil(4096) * 4096;
    let stale = u64_at(&h, 24).ok()? < events || u32_at(&h, 48).ok()? & 2 != 0;
    let nbytes = bits.div_ceil(8);
    let raw = match (stale, nbytes <= MAX_BITMAP_BYTES) {
        (false, true) => slot.read_vec(at + 256, nbytes as usize).ok(),
        _ => None,
    };
    let Some(raw) = raw else { return Some((len, vec![ALL])) };
    let mut dirty = Vec::new();
    for (i, &x) in raw.iter().enumerate() {
        for k in (0..8).filter(|k| x >> k & 1 != 0) {
            let c = i as u64 * 8 + k;
            if c < bits {
                dirty.push(ByteRange::new(c * chunk, chunk));
            }
        }
    }
    Some((len, fs_inspect_core::range::sort_coalesce(dirty)))
}

/// The superblock of `slot`: 1.2, 1.1, 1.0, then 0.90. `Err`: none was found and a place one
/// may be could not be read (the read error).
pub fn read_super(slot: &dyn BlockSource) -> Result<Option<Super>> {
    let len = slot.size();
    if len < 8192 {
        return Ok(None);
    }
    let end10 = (len - 8192) & !4095;
    let mut err = None;
    let tries: [&dyn Fn() -> Result<Option<Super>>; 4] =
        [&|| read_1x(slot, 4096, 12), &|| read_1x(slot, 0, 11), &|| read_1x(slot, end10, 10), &|| read_090(slot)];
    for t in tries {
        match t() {
            Ok(Some(sb)) => return Ok(Some(sb)),
            Ok(None) => {}
            Err(e) => {
                err.get_or_insert(e);
            }
        }
    }
    err.map_or(Ok(None), Err)
}

fn uuid_str(u: &[u8; 16]) -> String {
    let h: Vec<String> = u.iter().map(|b| format!("{b:02x}")).collect();
    format!("{}:{}:{}:{}", h[0..4].concat(), h[4..8].concat(), h[8..12].concat(), h[12..16].concat())
}

fn level_name(level: i32) -> String {
    match level {
        -1 => "linear".into(),
        l if l >= 0 => format!("raid{l}"),
        l => format!("level {l}"),
    }
}

/// Assemble the md arrays of the slots not in `taken`; slots whose superblock places could
/// not be read go to `unreadable`.
pub fn assemble(
    slots: &[Slot],
    taken: &[usize],
    _limits: &Limits,
    unreadable: &mut Vec<(usize, Error)>,
) -> Vec<Container> {
    let mut groups: HashMap<[u8; 16], Vec<(usize, Super)>> = HashMap::new();
    for (i, s) in slots.iter().enumerate() {
        if taken.contains(&i) {
            continue;
        }
        let sb = match read_super(&*s.source) {
            Ok(Some(sb)) => sb,
            Ok(None) => continue,
            Err(e) => {
                unreadable.push((i, e.context("md superblock")));
                continue;
            }
        };
        // A file system recognized at the slot's start is the array's content only when the
        // array keeps its data there and in order (RAID 1, linear on its first member).
        if s.has_fs && !(sb.data_offset == 0 && matches!(sb.level, 1 | -1)) {
            continue;
        }
        groups.entry(sb.uuid).or_default().push((i, sb));
    }
    let mut keys: Vec<_> = groups.keys().copied().collect();
    keys.sort();
    let mut out = Vec::new();
    for k in keys {
        let mut g = groups.remove(&k).unwrap_or_default();
        g.sort_by_key(|(i, _)| *i);
        out.push(build(slots, g));
    }
    out
}

fn build(slots: &[Slot], g: Vec<(usize, Super)>) -> Container {
    let newest = g.iter().map(|(_, s)| s.events).max().unwrap_or(0);
    let lead = g.iter().find(|(_, s)| s.events == newest).map(|(_, s)| s.clone()).unwrap_or_else(|| g[0].1.clone());
    let name = if lead.name.is_empty() { uuid_str(&lead.uuid) } else { lead.name.clone() };
    let rd = lead.raid_disks as usize;
    let mut notes = Vec::new();
    let m = Members::place(slots, g, rd, newest);
    m.report(&name, rd, &mut notes);
    // Member bytes the array uses but no readable volume covers.
    let mut opaque: Vec<(usize, ByteRange)> = Vec::new();
    let (volumes, status) = match array_volume(&lead, &m, rd, &name) {
        Ok(v) => {
            let volumes = vec![v];
            let status = status_of(&m.members[..rd.min(m.members.len())], &volumes);
            (volumes, status)
        }
        Err(NoMap::Missing) => {
            // Where the array ends on each member present is not known: its whole data area.
            for (ix, sb) in m.supers.iter().enumerate().take(rd) {
                if let Some(sb) = sb {
                    opaque.push((ix, ByteRange::new(sb.data_offset, sb.data_size)));
                }
            }
            let volumes = vec![LogicalDef {
                name: name.clone(),
                uuid: uuid_str(&lead.uuid),
                layout: level_name(lead.level),
                map: Arc::default(),
                readable: Readability::No,
            }];
            let status = status_of(&m.members[..rd.min(m.members.len())], &volumes);
            (volumes, status)
        }
        Err(NoMap::Unsupported(why)) => {
            notes.push(Diagnostic::warning(
                DiagCode::UnsupportedLayout,
                format!("md array {name}: {why}; its members count as data"),
            ));
            (Vec::new(), ContainerStatus::Unsupported)
        }
    };
    // A stale member that is not read still gets the array projected (it is a member).
    opaque.extend(
        volumes
            .iter()
            .filter(|v| v.readable == Readability::No)
            .flat_map(|v| v.map.footprint())
            .map(|(m, s, e)| (m, ByteRange::from_bounds(s, e.max(s)))),
    );
    let unsynced = unsynced(&lead, &m.supers, &m.fresh, rd);
    Container {
        kind: VolumeManager::Md,
        name,
        uuid: uuid_str(&lead.uuid),
        members: m.members,
        volumes,
        metadata: m.metadata,
        opaque,
        unsynced,
        status,
        notes,
    }
}

/// An array's members: one per role (`raid_disks` of them), then spares and stale ones, each
/// with its superblock, whether that is the newest, and its slot's length.
struct Members {
    members: Vec<Member>,
    supers: Vec<Option<Super>>,
    fresh: Vec<bool>,
    len: Vec<u64>,
    metadata: Vec<(usize, ByteRange)>,
    /// Members older than the others (not read).
    stale: Vec<String>,
    /// Roles found on two slots with the same event count (a cloned disk): the first is used.
    cloned: Vec<String>,
}

impl Members {
    /// The slots of group `g` in their roles; `newest`: the newest event count.
    fn place(slots: &[Slot], g: Vec<(usize, Super)>, rd: usize, newest: u64) -> Members {
        let mut m = Members {
            members: Vec::new(),
            supers: Vec::new(),
            fresh: Vec::new(),
            len: Vec::new(),
            metadata: Vec::new(),
            stale: Vec::new(),
            cloned: Vec::new(),
        };
        for r in 0..rd.min(crate::MAX_MEMBERS) {
            m.push(MemberRole::Slot(r as u32));
        }
        let roles = m.members.len();
        for (i, sb) in g {
            let fresh = sb.events == newest;
            // The same role, as fresh as the slot holding it: a copy of that member, which
            // md would not add twice. It stays unclaimed.
            if let Some(r) = sb.role.map(|r| r as usize).filter(|&r| r < roles)
                && m.supers[r].as_ref().is_some_and(|held| held.events == sb.events)
            {
                m.cloned.push(m.members[r].role.to_string());
                continue;
            }
            let ix = match sb.role {
                Some(r) if (r as usize) < roles && m.members[r as usize].slot.is_none() => r as usize,
                _ => m.push(MemberRole::Spare),
            };
            m.members[ix].slot = Some(i);
            m.members[ix].id = format!("{}:{}", uuid_str(&sb.uuid), ix);
            m.fresh[ix] = fresh;
            m.len[ix] = slots[i].source.size();
            if !fresh {
                m.stale.push(m.members[ix].role.to_string());
            }
            m.metadata.extend(sb.metadata.iter().map(|r| (ix, *r)));
            m.supers[ix] = Some(sb);
        }
        m
    }

    /// A member with no slot yet; its index.
    fn push(&mut self, role: MemberRole) -> usize {
        self.members.push(Member { id: String::new(), slot: None, role });
        self.supers.push(None);
        self.fresh.push(false);
        self.len.push(0);
        self.members.len() - 1
    }

    /// Notes on the stale and the missing members.
    fn report(&self, name: &str, rd: usize, notes: &mut Vec<Diagnostic>) {
        if !self.cloned.is_empty() {
            notes.push(Diagnostic::warning(
                DiagCode::DuplicateMember,
                format!("md array {name}: {} found on two disks (a clone?); the first is used", self.cloned.join(", ")),
            ));
        }
        if !self.stale.is_empty() {
            notes.push(Diagnostic::warning(
                DiagCode::ContainerIncomplete,
                format!(
                    "md array {name}: members {} are older than the others and are not read",
                    self.stale.join(", ")
                ),
            ));
        }
        let missing: Vec<String> = self.members[..rd.min(self.members.len())]
            .iter()
            .filter(|m| m.slot.is_none())
            .map(|m| m.role.to_string())
            .collect();
        if !missing.is_empty() {
            notes.push(Diagnostic::warning(
                DiagCode::ContainerIncomplete,
                format!("md array {name}: {} not found", missing.join(", ")),
            ));
        }
    }
}

/// Why an array has no map.
#[derive(Debug)]
enum NoMap {
    /// A linear or RAID 0 member is missing: the others cannot be placed.
    Missing,
    /// Its layout or features are not mapped (why).
    Unsupported(String),
}

impl From<String> for NoMap {
    fn from(why: String) -> NoMap {
        NoMap::Unsupported(why)
    }
}

impl From<&str> for NoMap {
    fn from(why: &str) -> NoMap {
        NoMap::Unsupported(why.to_string())
    }
}

/// The array's volume (`Err`: why it cannot be mapped).
fn array_volume(lead: &Super, m: &Members, rd: usize, name: &str) -> std::result::Result<LogicalDef, NoMap> {
    let map = layout(lead, &m.supers, rd)?;
    map.validate(&|i| m.len.get(i).copied().filter(|_| m.supers.get(i).is_some_and(Option::is_some)), usize::MAX)
        .map_err(|e| format!("its layout does not fit its members ({e})"))?;
    // Only the members of a role holding the newest superblock are read.
    let readable = map.readable(&|i| i < rd && m.fresh.get(i).copied().unwrap_or(false));
    Ok(LogicalDef {
        name: name.to_string(),
        uuid: uuid_str(&lead.uuid),
        layout: level_name(lead.level),
        map: Arc::new(map),
        readable,
    })
}

/// The member bytes of a redundant array whose copies may not agree (see the module docs).
fn unsynced(lead: &Super, supers: &[Option<Super>], fresh: &[bool], rd: usize) -> Vec<(usize, ByteRange)> {
    if !matches!(lead.level, 1 | 4 | 5 | 6 | 10) {
        return Vec::new();
    }
    let mut array: Vec<ByteRange> = Vec::new();
    for (sb, _) in supers.iter().zip(fresh).filter(|(_, f)| **f) {
        array.extend(sb.iter().flat_map(|s| s.unsynced.iter().copied()));
    }
    if lead.level == 10 && !array.is_empty() {
        array = vec![ALL];
    }
    let array = fs_inspect_core::range::sort_coalesce(array);
    let mut out = Vec::new();
    for (ix, sb) in supers.iter().enumerate().take(rd) {
        let Some(sb) = sb else { continue };
        let mut own = array.clone();
        if !fresh[ix] {
            own.push(ALL);
        }
        if let Some(r) = sb.recovery {
            own.push(ByteRange::from_bounds(r, u64::MAX));
        }
        let data = [ByteRange::new(0, lead.size)];
        for r in fs_inspect_core::range::intersect(fs_inspect_core::range::sort_coalesce(own), data) {
            out.push((ix, r.shifted(sb.data_offset)));
        }
    }
    out
}

/// The array's map from its newest superblock and each member's data offset.
fn layout(sb: &Super, supers: &[Option<Super>], rd: usize) -> Result<LogicalMap, NoMap> {
    if let Some(u) = &sb.unsupported {
        return Err(u.clone().into());
    }
    if rd == 0 || rd > crate::MAX_MEMBERS {
        return Err(format!("{rd} devices").into());
    }
    let area = |r: usize| Area {
        member: r,
        start: supers.get(r).and_then(|s| s.as_ref()).map_or(sb.data_offset, |s| s.data_offset),
    };
    let areas: Vec<Area> = (0..rd).map(area).collect();
    let chunk = sb.chunk;
    let round = |v: u64| v.checked_div(chunk).map_or(v, |n| n * chunk);
    let seg = |len: u64, layout: Layout| LogicalMap { len, segments: vec![Segment { start: 0, len, layout }] };
    match sb.level {
        1 => Ok(seg(sb.size, Layout::Mirror { legs: areas })),
        -1 => {
            // In role order, each member's data rounded down to the chunk.
            let mut segments = Vec::new();
            let mut pos = 0u64;
            for (r, a) in areas.iter().enumerate() {
                let s = supers.get(r).and_then(|s| s.as_ref()).ok_or(NoMap::Missing)?;
                let n = round(s.data_size);
                if n > 0 {
                    segments.push(Segment { start: pos, len: n, layout: Layout::Linear(*a) });
                    pos += n;
                }
            }
            Ok(LogicalMap { len: pos, segments })
        }
        0 => {
            // One zone only: every member the same size (rounded to the chunk).
            let sizes: Vec<u64> = (0..rd)
                .map(|r| supers.get(r).and_then(|s| s.as_ref()).map(|s| round(s.data_size)))
                .collect::<Option<Vec<_>>>()
                .ok_or(NoMap::Missing)?;
            if sizes.iter().any(|&s| s != sizes[0]) {
                return Err("RAID 0 members of different sizes (several zones)".into());
            }
            if rd == 1 {
                return Ok(seg(sizes[0], Layout::Linear(areas[0])));
            }
            Ok(seg(sizes[0] * rd as u64, Layout::Striped { chunk, areas }))
        }
        4..=6 => {
            let raid6 = sb.level == 6;
            let algo = ParityAlgo::from_md(sb.level, sb.layout)
                .ok_or_else(|| format!("RAID {} layout {}", sb.level, sb.layout))?;
            let dd = rd as u64 - if raid6 { 2 } else { 1 };
            Ok(seg(round(sb.size) * dd, Layout::Parity { chunk, algo, raid6, first_row: 0, areas }))
        }
        10 => {
            let (near, far, offset) = (sb.layout & 0xFF, (sb.layout >> 8) & 0xFF, sb.layout & (1 << 16) != 0);
            if sb.layout >> 17 != 0 {
                return Err(format!("RAID 10 layout {:#x} (far sets)", sb.layout).into());
            }
            if chunk == 0 || near == 0 || far == 0 {
                return Err(format!("RAID 10 layout {:#x}", sb.layout).into());
            }
            let chunks = sb.size / chunk / u64::from(far);
            let array = chunks * rd as u64 / u64::from(near);
            let per_dev = (array * u64::from(near) * u64::from(far)).div_ceil(rd as u64);
            let stride = if offset { chunk } else { per_dev / u64::from(far) * chunk };
            Ok(seg(array * chunk, Layout::Raid10 { chunk, near, far, offset, stride, areas }))
        }
        l => Err(format!("level {l} is not mapped").into()),
    }
}

/// The md superblocks of `slot` that fail their checksum: where each is and what it is (one
/// found where its version keeps it, magic and version right, naming its own place).
pub(crate) fn damaged_supers(slot: &dyn BlockSource) -> fs_inspect_core::Result<Vec<(u64, String)>> {
    let len = slot.size();
    let mut out = Vec::new();
    if len < 8192 {
        return Ok(out);
    }
    let end10 = (len - 8192) & !4095;
    for (off, version) in [(4096, "1.2"), (0, "1.1"), (end10, "1.0")] {
        if off + 4096 > len {
            continue;
        }
        let b = slot.read_vec(off, 4096)?;
        if u32_at(&b, 0).ok() != Some(MAGIC) || u32_at(&b, 4).ok() != Some(1) {
            continue;
        }
        if u64_at(&b, 144).ok().and_then(|s| s.checked_mul(SECTOR)) != Some(off) {
            continue;
        }
        let max_dev = u32_at(&b, 220)? as usize;
        let ok = max_dev <= 1920 && checksum_1x(&b, 256 + max_dev * 2).map(fold) == u32_at(&b, 216).ok();
        if !ok {
            out.push((off, format!("md {version} superblock checksum mismatch")));
        }
    }
    if len >= 128 << 10 {
        let off = (len & !(64 * 1024 - 1)) - 64 * 1024;
        let b = slot.read_vec(off, 4096)?;
        let w = |i: usize| u32_at(&b, i * 4).unwrap_or(0);
        if w(0) == MAGIC && w(1) == 0 && w(2) == 90 {
            let sum: u64 = (0..1024).filter(|&i| i != 38).map(|i| u64::from(w(i))).sum();
            if fold(sum) != w(38) && (sum & 0xFFFF_FFFF) as u32 != w(38) {
                out.push((off, "md 0.90 superblock checksum mismatch".into()));
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::{LogicalSource, SlotHint, assemble as assemble_all};
    use fs_inspect_io::{DynSource, MemSource};
    use fs_inspect_testkit::volmgr::{MdSpec, md_10_offset, write_md_super};

    const KIB: u64 = 1024;

    fn spec(version: u8, level: i32, layout: u32, n: u32, size: u64) -> MdSpec {
        MdSpec {
            version,
            uuid: [0x11; 16],
            name: "host:0".into(),
            level,
            layout,
            chunk: 64 * KIB,
            raid_disks: n,
            size,
            data_offset: 1 << 20,
            events: 42,
            bitmap: None,
        }
    }

    /// Members of `spec` holding `data` (laid out through the array's own superblocks, then
    /// written through the map), and the map.
    fn array(spec: &MdSpec, member_len: u64, data: &[u8]) -> (Vec<Vec<u8>>, Container) {
        let n = spec.raid_disks as usize;
        let mut m = vec![vec![0u8; member_len as usize]; n];
        for (i, b) in m.iter_mut().enumerate() {
            write_md_super(b, spec, i as u32, Some(i as u32));
        }
        let c = assemble_all(&slots(&m, false), &[], &Limits::default()).remove(0);
        let map = &c.volumes[0].map;
        assert!(data.len() as u64 <= map.len);
        let lay = &map.segments[0].layout;
        // Sector by sector: md's chunks are whole sectors, a sector is never split.
        for (k, piece) in data.chunks(512).enumerate() {
            for (ai, at) in lay.locate(k as u64 * 512, map.len).copies {
                let at = at as usize;
                m[lay.areas()[ai].member][at..at + piece.len()].copy_from_slice(piece);
            }
        }
        // Parity: recompute every row's P as the XOR of its data chunks.
        if let Layout::Parity { chunk, algo, raid6, areas, .. } = lay {
            let (rd, dd) = (areas.len() as u64, areas.len() as u64 - if *raid6 { 2 } else { 1 });
            for r in 0..map.len.div_ceil(chunk * dd) {
                let (_, p, _) = crate::map::parity_place(*algo, *raid6, r, 0, rd, dd);
                let devs: Vec<usize> =
                    (0..dd).map(|d| crate::map::parity_place(*algo, *raid6, r, d, rd, dd).0 as usize).collect();
                let (at, len) = ((areas[0].start + r * chunk) as usize, *chunk as usize);
                let mut x = vec![0u8; len];
                for &dev in &devs {
                    for (x, b) in x.iter_mut().zip(&m[dev][at..at + len]) {
                        *x ^= b;
                    }
                }
                m[p as usize][at..at + len].copy_from_slice(&x);
            }
        }
        (m, c)
    }

    fn slots(m: &[Vec<u8>], has_fs: bool) -> Vec<Slot> {
        m.iter()
            .map(|b| Slot {
                source: Arc::new(MemSource::new(b.clone())) as DynSource,
                hint: SlotHint::Unknown,
                has_fs,
                parent: None,
            })
            .collect()
    }

    fn read_all(c: &Container, m: &[Vec<u8>], skip: Option<usize>) -> Vec<u8> {
        let srcs: Vec<Option<DynSource>> = c
            .members
            .iter()
            .map(|x| x.slot.filter(|&s| Some(s) != skip).map(|s| Arc::new(MemSource::new(m[s].clone())) as DynSource))
            .collect();
        let src = LogicalSource::new(c.volumes[0].map.clone(), srcs);
        let mut out = vec![0u8; src.map().len as usize];
        fs_inspect_io::BlockSource::read_exact_at(&src, 0, &mut out).unwrap();
        out
    }

    fn data(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 7 % 253) as u8 ^ (i >> 12) as u8).collect()
    }

    #[test]
    fn raid5_left_symmetric_with_a_bitmap() {
        let mut s = spec(12, 5, 2, 3, 2 << 20);
        s.bitmap = Some((8, 64 * 1024));
        let d = data(4 << 20);
        let (m, c) = array(&s, 4 << 20, &d);
        assert_eq!(
            (c.status, c.volumes[0].layout.as_str(), c.volumes[0].map.len),
            (ContainerStatus::Complete, "raid5", 4 << 20)
        );
        assert_eq!(&read_all(&c, &m, None)[..d.len()], &d[..]);
        // Each member: the superblock at 4 KiB and the bitmap 8 sectors after it.
        let meta: Vec<ByteRange> = c.metadata.iter().filter(|(x, _)| *x == 1).map(|(_, r)| *r).collect();
        assert_eq!(meta, [ByteRange::new(4096, 4096), ByteRange::new(8192, 4096)]);
        // Without member 1: rebuilt from parity.
        assert_eq!(&read_all(&c, &m, Some(1))[..d.len()], &d[..]);
        assert_eq!(c.volumes[0].map.readable(&|x| x != 1), Readability::Degraded);
    }

    #[test]
    fn raid10_near_on_1_0_and_raid6() {
        let s = spec(10, 10, 0x102, 4, 2 << 20); // near 2, far 1
        let (m, c) = array(&s, (2 << 20) + 64 * KIB, &data(4 << 20));
        assert_eq!(c.volumes[0].map.len, 4 << 20);
        assert_eq!(read_all(&c, &m, Some(2)), data(4 << 20));
        let s = spec(12, 6, 2, 4, 1 << 20);
        let (m, c) = array(&s, 3 << 20, &data(2 << 20));
        assert_eq!(read_all(&c, &m, Some(3)), data(2 << 20));
    }

    /// A RAID 1 member on 0.90 shows the array's file system at its start: still a member.
    #[test]
    fn raid1_090_member_with_its_file_system() {
        let s = spec(0, 1, 0, 2, 1 << 20);
        let (m, _) = array(&s, (1 << 20) + 128 * KIB, &data(1 << 20));
        let c = assemble_all(&slots(&m[..1], true), &[], &Limits::default()).remove(0);
        assert_eq!((c.status, c.volumes[0].readable), (ContainerStatus::Degraded, Readability::Degraded));
        assert_eq!(c.metadata, [(0, ByteRange::from_bounds((1 << 20) + 64 * KIB, (1 << 20) + 128 * KIB))]);
        // A RAID 5 member would not be (its start is not the file system's).
        let s = spec(0, 5, 2, 3, 1 << 20);
        let (m, _) = array(&s, (1 << 20) + 128 * KIB, &data(1 << 20));
        assert!(assemble_all(&slots(&m, true), &[], &Limits::default()).is_empty());
    }

    #[test]
    fn stale_member_and_unsupported() {
        let s = spec(12, 1, 0, 2, 1 << 20);
        let (mut m, _) = array(&s, 3 << 20, &data(1 << 20));
        let mut old = s.clone();
        old.events = 41;
        write_md_super(&mut m[1], &old, 1, Some(1));
        let c = assemble_all(&slots(&m, false), &[], &Limits::default()).remove(0);
        assert!(c.notes.iter().any(|n| n.message.contains("older")), "{:?}", c.notes);
        assert_eq!(c.volumes[0].readable, Readability::Degraded);
        // RAID 0 of members of different sizes: zones, not mapped; the whole members count.
        let s = spec(12, 0, 0, 2, 0);
        let mut m = vec![vec![0u8; 3 << 20], vec![0u8; 4 << 20]];
        for (i, b) in m.iter_mut().enumerate() {
            write_md_super(b, &s, i as u32, Some(i as u32));
        }
        let c = assemble_all(&slots(&m, false), &[], &Limits::default()).remove(0);
        assert_eq!((c.status, c.volumes.len()), (ContainerStatus::Unsupported, 0));
    }

    /// A cloned member (the same role, equally fresh) is not claimed and not taken for a
    /// spare: the first in slot order is used.
    #[test]
    fn cloned_member_is_left_unclaimed() {
        let s = spec(12, 1, 0, 2, 1 << 20);
        let (m, _) = array(&s, 3 << 20, &data(1 << 20));
        let disks = [m[0].clone(), m[1].clone(), m[1].clone()];
        let c = assemble_all(&slots(&disks, false), &[], &Limits::default()).remove(0);
        let claimed: Vec<(usize, String)> =
            c.members.iter().filter_map(|x| Some((x.slot?, x.role.to_string()))).collect();
        assert_eq!(claimed.len(), 2, "{claimed:?}");
        assert_eq!((claimed[0].0, claimed[1].0), (0, 1));
        assert!(c.members.iter().all(|x| x.role != MemberRole::Spare));
        assert_eq!(c.status, ContainerStatus::Complete);
        let note = c.notes.iter().find(|n| n.code == DiagCode::DuplicateMember).expect("a clone note");
        assert!(note.message.contains("clone"), "{}", note.message);
    }

    /// A linear or RAID 0 array without one member: incomplete, its volume unreadable and not
    /// mapped, and the whole data area of each member present in use.
    #[test]
    fn linear_and_raid0_with_a_member_missing() {
        for (level, n) in [(-1, 2u32), (0, 3)] {
            let s = spec(12, level, 0, n, 0);
            let mut m = vec![vec![0u8; 3 << 20]; n as usize];
            for (i, b) in m.iter_mut().enumerate() {
                write_md_super(b, &s, i as u32, Some(i as u32));
            }
            let present: Vec<Vec<u8>> = m.iter().enumerate().filter(|(i, _)| *i != 1).map(|(_, b)| b.clone()).collect();
            let sl = slots(&present, false);
            let c = assemble_all(&sl, &[], &Limits::default()).remove(0);
            assert_eq!(c.status, ContainerStatus::Incomplete, "level {level}");
            assert_eq!(c.volumes.len(), 1);
            let v = &c.volumes[0];
            assert_eq!((v.readable, v.map.segments.len()), (Readability::No, 0), "level {level}");
            assert_eq!(v.layout, level_name(level));
            assert!(c.notes.iter().all(|n| n.code != DiagCode::UnsupportedLayout), "{:?}", c.notes);
            assert!(c.notes.iter().any(|n| n.message.contains("not found")), "{:?}", c.notes);
            for (ix, mem) in c.members.iter().enumerate() {
                let Some(slot) = mem.slot else {
                    assert_eq!(ix, 1);
                    continue;
                };
                let sb = read_super(&*sl[slot].source).unwrap().unwrap();
                assert!(sb.data_size > 0);
                let area = ByteRange::new(sb.data_offset, sb.data_size);
                let foot = c.member_footprint(ix);
                assert!(foot.iter().any(|r| r.offset <= area.offset && area.end() <= r.end()), "{ix}: {foot:?}");
            }
        }
    }

    /// Members of `spec` (`member_len` bytes each, superblocks written) with `data` placed by
    /// `place(byte) -> [(member, offset)]`, md's layout written out independently of the map;
    /// and the container assembled from them.
    fn placed(
        spec: &MdSpec,
        member_len: u64,
        data: &[u8],
        place: impl Fn(u64) -> Vec<(usize, u64)>,
    ) -> (Vec<Vec<u8>>, Container) {
        let n = spec.raid_disks as usize;
        let mut m = vec![vec![0u8; member_len as usize]; n];
        for (i, b) in m.iter_mut().enumerate() {
            write_md_super(b, spec, i as u32, Some(i as u32));
        }
        for (p, &x) in data.iter().enumerate() {
            for (dev, at) in place(p as u64) {
                m[dev][at as usize] = x;
            }
        }
        let c = assemble_all(&slots(&m, false), &[], &Limits::default()).remove(0);
        (m, c)
    }

    /// Linear: the members one after the other.
    #[test]
    fn linear_concatenates_the_members() {
        let s = spec(12, -1, 0, 3, 0);
        let (len, off) = (3u64 << 20, 1u64 << 20);
        let per = len - off;
        let d = data(3 * per as usize);
        let (m, c) = placed(&s, len, &d, |p| vec![((p / per) as usize, off + p % per)]);
        assert_eq!((c.status, c.volumes[0].layout.as_str()), (ContainerStatus::Complete, "linear"));
        assert_eq!(c.volumes[0].map.len, 3 * per);
        assert_eq!(read_all(&c, &m, None), d);
        assert_eq!(c.volumes[0].map.readable(&|x| x != 2), Readability::No);
    }

    /// RAID 0: chunk k on member k % n, row k / n.
    #[test]
    fn raid0_stripes_chunks() {
        let s = spec(12, 0, 0, 3, 2 << 20);
        let ch = s.chunk;
        let d = data(6 << 20);
        let (m, c) = placed(&s, 3 << 20, &d, |p| {
            let k = p / ch;
            vec![((k % 3) as usize, (1 << 20) + (k / 3) * ch + p % ch)]
        });
        assert_eq!(c.volumes[0].layout, "raid0");
        assert_eq!(c.volumes[0].map.len, 6 << 20);
        assert_eq!(read_all(&c, &m, None), d);
        assert_eq!(c.volumes[0].map.readable(&|x| x != 0), Readability::No);
    }

    /// RAID 4: parity always on the last member; data chunk k on member k % (n - 1).
    #[test]
    fn raid4_keeps_parity_on_the_last_member() {
        let s = spec(12, 4, 5, 4, 2 << 20);
        let ch = s.chunk;
        let d = data(6 << 20);
        let (mut m, _) = placed(&s, 3 << 20, &d, |p| {
            let k = p / ch;
            vec![((k % 3) as usize, (1 << 20) + (k / 3) * ch + p % ch)]
        });
        let [a, b, c, p] = &mut m[..] else { unreachable!() };
        for (((p, a), b), c) in p.iter_mut().zip(&*a).zip(&*b).zip(&*c).skip(1 << 20) {
            *p = a ^ b ^ c;
        }
        let c = assemble_all(&slots(&m, false), &[], &Limits::default()).remove(0);
        assert_eq!(c.volumes[0].layout, "raid4");
        assert_eq!(c.volumes[0].map.len, 6 << 20);
        assert_eq!(read_all(&c, &m, None), d);
        // Without a data member: rebuilt from the parity member.
        assert_eq!(read_all(&c, &m, Some(1)), d);
        assert_eq!(c.volumes[0].map.readable(&|x| x != 1), Readability::Degraded);
    }

    /// RAID 10 offset ("o2"): each row of n chunks, then the same row again one member over.
    #[test]
    fn raid10_offset_rotates_the_second_copy() {
        let s = spec(12, 10, 0x1_0201, 3, 2 << 20);
        let ch = s.chunk;
        let d = data(3 << 20);
        let (m, c) = placed(&s, 3 << 20, &d, |p| {
            let (k, r) = (p / ch, p % ch);
            let (dev, row) = (k % 3, k / 3);
            (0..2u64).map(|j| (((dev + j) % 3) as usize, (1 << 20) + (row * 2 + j) * ch + r)).collect()
        });
        assert_eq!(c.volumes[0].map.len, 3 << 20);
        assert_eq!(read_all(&c, &m, None), d);
        for lost in 0..3 {
            assert_eq!(read_all(&c, &m, Some(lost)), d, "without member {lost}");
        }
    }

    /// Superblock 1.1 sits at the start of each member, before the data.
    #[test]
    fn superblock_1_1_at_the_start() {
        let s = spec(11, 1, 0, 2, 1 << 20);
        let d = data(1 << 20);
        let (m, c) = placed(&s, 3 << 20, &d, |p| vec![(0, (1 << 20) + p), (1, (1 << 20) + p)]);
        assert_eq!(c.status, ContainerStatus::Complete);
        assert_eq!(read_all(&c, &m, Some(0)), d);
        let meta: Vec<ByteRange> = c.metadata.iter().filter(|(x, _)| *x == 0).map(|(_, r)| *r).collect();
        assert_eq!(meta.first().map(|r| r.offset), Some(0), "{meta:?}");
    }

    /// Copies that may differ: write-intent bits, a resync checkpoint, a stale member; none
    /// on a level without redundancy.
    #[test]
    fn sync_state_from_bitmap_resync_and_stale_members() {
        let mut s = spec(12, 1, 0, 2, 2 << 20);
        s.bitmap = Some((8, 64 * 1024));
        let (mut m, c) = array(&s, 4 << 20, &data(1 << 20));
        assert!(c.unsynced.is_empty(), "{:?}", c.unsynced);
        let unsynced = |m: &[Vec<u8>]| assemble_all(&slots(m, false), &[], &Limits::default()).remove(0).unsynced;
        let both = |a: u64, b: u64| {
            vec![
                (0, ByteRange::from_bounds((1 << 20) + a, (1 << 20) + b)),
                (1, ByteRange::from_bounds((1 << 20) + a, (1 << 20) + b)),
            ]
        };
        // Bit 3 of member 1's bitmap (it starts 8 sectors after the superblock at 4 KiB).
        m[1][8192 + 256] = 1 << 3;
        assert_eq!(unsynced(&m), both(3 * 64 * KIB, 4 * 64 * KIB));
        m[1][8192 + 256] = 0;
        // A resync checkpoint at 1 MiB of the 2 MiB each member holds.
        fs_inspect_testkit::volmgr::md_set_resync(&mut m[0], &s, 2048);
        assert_eq!(unsynced(&m), both(1 << 20, 2 << 20));
        fs_inspect_testkit::volmgr::md_set_resync(&mut m[0], &s, u64::MAX);
        // A stale member: its whole data area.
        let mut old = s.clone();
        old.events = 41;
        write_md_super(&mut m[1], &old, 1, Some(1));
        assert_eq!(unsynced(&m), [(1, ByteRange::new(1 << 20, 2 << 20))]);
        // RAID 0 has no copies.
        let s = spec(12, 0, 0, 2, 1 << 20);
        let (mut m, _) = array(&s, 3 << 20, &data(1 << 20));
        fs_inspect_testkit::volmgr::md_set_resync(&mut m[0], &s, 0);
        assert!(unsynced(&m).is_empty());
    }

    /// Every RAID 6 layout number md writes (the RAID 5 rotations, the restart and continue
    /// rotations 8 to 10, and the RAID 5 ones with Q last, 16 to 20) assembles, and reads back
    /// with any one member missing; a RAID 6 only number on a RAID 5 array is unsupported.
    #[test]
    fn every_raid6_layout() {
        let d = data(3 << 20);
        for layout in [0, 1, 2, 3, 4, 5, 8, 9, 10, 16, 17, 18, 19, 20] {
            let s = spec(12, 6, layout, 5, 1 << 20);
            let (m, c) = array(&s, 3 << 20, &d);
            assert_eq!((c.status, c.volumes[0].map.len), (ContainerStatus::Complete, 3 << 20), "layout {layout}");
            for lost in 0..5 {
                assert_eq!(read_all(&c, &m, Some(lost)), d, "layout {layout} without member {lost}");
            }
        }
        let s = spec(12, 5, 8, 3, 1 << 20);
        let mut m = vec![vec![0u8; 3 << 20]; 3];
        for (i, b) in m.iter_mut().enumerate() {
            write_md_super(b, &s, i as u32, Some(i as u32));
        }
        let c = assemble_all(&slots(&m, false), &[], &Limits::default()).remove(0);
        assert_eq!((c.status, c.volumes.len()), (ContainerStatus::Unsupported, 0));
    }

    /// A superblock of `level` / `layout` with `chunk` and members of `data_size` bytes.
    fn sb(level: i32, layout: u32, chunk: u64, data_size: u64) -> Super {
        Super {
            version: 12,
            uuid: [0x11; 16],
            name: "host:0".into(),
            level,
            layout,
            chunk,
            raid_disks: 0,
            size: data_size,
            data_offset: 1 << 20,
            data_size,
            sb_offset: 4096,
            role: None,
            events: 1,
            metadata: Vec::new(),
            unsynced: Vec::new(),
            recovery: None,
            unsupported: None,
        }
    }

    fn why(r: Result<LogicalMap, NoMap>) -> String {
        match r {
            Err(NoMap::Unsupported(w)) => w,
            Err(NoMap::Missing) => "missing".into(),
            Ok(m) => panic!("mapped: {m:?}"),
        }
    }

    #[test]
    fn layouts_md_does_not_write_or_this_does_not_map_say_why() {
        let k = 64 * KIB;
        let all = |s: &Super, n: usize| vec![Some(s.clone()); n];
        let mut u = sb(5, 2, k, 1 << 20);
        u.unsupported = Some("a reshape is in progress".into());
        assert_eq!(why(layout(&u, &all(&u, 3), 3)), "a reshape is in progress");
        let s = sb(1, 0, 0, 1 << 20);
        assert_eq!(why(layout(&s, &[], 0)), "0 devices");
        assert_eq!(why(layout(&s, &[], crate::MAX_MEMBERS + 1)), format!("{} devices", crate::MAX_MEMBERS + 1));
        assert_eq!(why(layout(&sb(3, 0, k, 1 << 20), &all(&s, 2), 2)), "level 3 is not mapped");
        // RAID 5 with a RAID 6 only rotation.
        assert_eq!(why(layout(&sb(5, 8, k, 1 << 20), &all(&s, 3), 3)), "RAID 5 layout 8");
        // RAID 10: far sets (bit 17), and no copies or chunk.
        let r10 = |layout, chunk| sb(10, layout, chunk, 1 << 20);
        assert_eq!(why(layout(&r10(0x2_0102, k), &all(&s, 4), 4)), "RAID 10 layout 0x20102 (far sets)");
        assert_eq!(why(layout(&r10(0x0100, k), &all(&s, 4), 4)), "RAID 10 layout 0x100");
        assert_eq!(why(layout(&r10(0x0001, k), &all(&s, 4), 4)), "RAID 10 layout 0x1");
        assert_eq!(why(layout(&r10(0x0102, 0), &all(&s, 4), 4)), "RAID 10 layout 0x102");
        // Linear and RAID 0 cannot place the members after a missing one.
        let lin = sb(-1, 0, k, 1 << 20);
        assert_eq!(why(layout(&lin, &[Some(lin.clone()), None], 2)), "missing");
        let r0 = sb(0, 0, k, 1 << 20);
        assert_eq!(why(layout(&r0, &[Some(r0.clone()), None], 2)), "missing");
        // RAID 0 of members whose data differs by more than a chunk: several zones.
        let big = sb(0, 0, k, 2 << 20);
        assert_eq!(
            why(layout(&r0, &[Some(r0.clone()), Some(big)], 2)),
            "RAID 0 members of different sizes (several zones)"
        );
    }

    #[test]
    fn a_one_member_raid0_is_its_member_and_sizes_round_to_the_chunk() {
        let k = 64 * KIB;
        // Data sizes rounded down to the chunk: these two are one zone.
        let (a, b) = (sb(0, 0, k, (1 << 20) + 100), sb(0, 0, k, (1 << 20) + 5000));
        let m = layout(&a, &[Some(a.clone()), Some(b)], 2).unwrap();
        assert_eq!(m.len, 2 << 20);
        let m = layout(&a, &[Some(a.clone())], 1).unwrap();
        assert_eq!(
            m.segments,
            [Segment { start: 0, len: 1 << 20, layout: Layout::Linear(Area { member: 0, start: 1 << 20 }) }]
        );
        // Linear: a member with less than a chunk of data adds nothing.
        let (l, tiny) = (sb(-1, 0, k, 1 << 20), sb(-1, 0, k, 100));
        let m = layout(&l, &[Some(tiny), Some(l.clone())], 2).unwrap();
        assert_eq!(
            m.segments,
            [Segment { start: 0, len: 1 << 20, layout: Layout::Linear(Area { member: 1, start: 1 << 20 }) }]
        );
        // A member without a superblock takes the newest one's data offset.
        let r1 = sb(1, 0, 0, 1 << 20);
        let m = layout(&r1, &[Some(r1.clone()), None], 2).unwrap();
        let legs = vec![Area { member: 0, start: 1 << 20 }, Area { member: 1, start: 1 << 20 }];
        assert_eq!(m.segments[0].layout, Layout::Mirror { legs });
    }

    #[test]
    fn levels_are_named_as_md_names_them() {
        assert_eq!(level_name(-1), "linear");
        assert_eq!(level_name(6), "raid6");
        // Multipath (-4) and faulty (-5): no raid name.
        assert_eq!(level_name(-4), "level -4");
    }

    #[test]
    fn damaged_superblocks_are_found_where_each_version_keeps_them() {
        let len = 3 << 20;
        for (version, off, what) in [(12u8, 4096u64, "1.2"), (11, 0, "1.1"), (10, md_10_offset(len), "1.0")] {
            let s = spec(version, 1, 0, 2, 1 << 20);
            let mut m = vec![0u8; len as usize];
            write_md_super(&mut m, &s, 0, Some(0));
            let src = MemSource::new(m.clone());
            assert!(damaged_supers(&src).unwrap().is_empty(), "{what}");
            // A byte of the name changed: the checksum no longer matches.
            m[off as usize + 40] ^= 1;
            assert_eq!(
                damaged_supers(&MemSource::new(m.clone())).unwrap(),
                [(off, format!("md {what} superblock checksum mismatch"))]
            );
            // A superblock naming another place is a copy, not this one: not reported.
            m[off as usize + 144] ^= 1;
            assert!(damaged_supers(&MemSource::new(m)).unwrap().is_empty(), "{what}");
        }
        let s = spec(0, 1, 0, 2, 1 << 20);
        let mut m = vec![0u8; len as usize];
        write_md_super(&mut m, &s, 0, Some(0));
        assert!(damaged_supers(&MemSource::new(m.clone())).unwrap().is_empty());
        let off = ((len & !(64 * KIB - 1)) - 64 * KIB) as usize;
        m[off + 5 * 4] ^= 1;
        assert_eq!(
            damaged_supers(&MemSource::new(m)).unwrap(),
            [(off as u64, "md 0.90 superblock checksum mismatch".into())]
        );
        // Too small to hold any superblock.
        assert!(damaged_supers(&MemSource::new(vec![0u8; 4096])).unwrap().is_empty());
    }

    /// Words of the 0.90 superblock at `off` set, the checksum written again (folded, or,
    /// `unfolded`, as the low 32 bits of the sum, as old kernels did).
    fn set_090(m: &mut [u8], off: usize, edits: &[(usize, u32)], unfolded: bool) {
        let sb = &mut m[off..off + 4096];
        for &(i, v) in edits {
            sb[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
        }
        let sum: u64 = (0..1024)
            .filter(|&i| i != 38)
            .map(|i| u64::from(u32::from_le_bytes(sb[i * 4..i * 4 + 4].try_into().unwrap())))
            .sum();
        let c = if unfolded { sum as u32 } else { ((sum & 0xFFFF_FFFF) + (sum >> 32)) as u32 };
        sb[38 * 4..38 * 4 + 4].copy_from_slice(&c.to_le_bytes());
    }

    /// The 1.x superblock at `off` with `edit` applied, its checksum written again over its
    /// device table (`max_dev` at 220, a 16-bit tail when it is odd).
    fn set_1x(m: &mut [u8], off: usize, edit: impl FnOnce(&mut [u8])) {
        let sb = &mut m[off..off + 4096];
        edit(sb);
        let n = 256 + 2 * u32::from_le_bytes(sb[220..224].try_into().unwrap()) as usize;
        let mut sum = 0u64;
        let mut i = 0;
        while i + 4 <= n {
            if i != 216 {
                sum += u64::from(u32::from_le_bytes(sb[i..i + 4].try_into().unwrap()));
            }
            i += 4;
        }
        if i < n {
            sum += u64::from(u16::from_le_bytes(sb[i..i + 2].try_into().unwrap()));
        }
        let c = ((sum & 0xFFFF_FFFF) + (sum >> 32)) as u32;
        sb[216..220].copy_from_slice(&c.to_le_bytes());
    }

    fn assembled(m: &[Vec<u8>]) -> Container {
        assemble_all(&slots(m, false), &[], &Limits::default()).remove(0)
    }

    /// 0.90: an array not marked clean, or with a bitmap flag but no bitmap, is out of sync on
    /// every member; the checksum old kernels wrote (not folded) is accepted, a wrong one is
    /// not a superblock.
    #[test]
    fn superblock_0_90_sync_state_and_checksums() {
        let s = spec(0, 1, 0, 2, 1 << 20);
        let len = ((1 << 20) + 128 * KIB) as usize;
        let off = (len & !(64 * 1024 - 1)) - 64 * 1024;
        let mut m = vec![vec![0u8; len]; 2];
        for (i, b) in m.iter_mut().enumerate() {
            write_md_super(b, &s, i as u32, Some(i as u32));
        }
        assert!(assembled(&m).unsynced.is_empty());
        let whole = vec![(0, ByteRange::new(0, 1 << 20)), (1, ByteRange::new(0, 1 << 20))];
        for state in [0, 1 | 1 << 8] {
            let mut m = m.clone();
            for b in &mut m {
                set_090(b, off, &[(33, state)], false);
            }
            assert_eq!(assembled(&m).unsynced, whole, "state {state:#x}");
        }
        // A sum past 32 bits: the low half alone is accepted too.
        let mut b = m[0].clone();
        set_090(&mut b, off, &[(100, u32::MAX), (101, u32::MAX)], true);
        let sb = read_super(&MemSource::new(b.clone())).unwrap().expect("unfolded checksum");
        assert_eq!((sb.version, sb.name.as_str(), sb.role), (0, "md127", Some(0)));
        b[off + 38 * 4] ^= 1;
        assert!(read_super(&MemSource::new(b.clone())).unwrap().is_none());
        assert_eq!(
            damaged_supers(&MemSource::new(b)).unwrap(),
            [(off as u64, "md 0.90 superblock checksum mismatch".into())]
        );
        // The 0.90 magic with another major or minor version: neither read nor reported.
        for (word, v) in [(1usize, 1u32), (2, 91)] {
            let mut b = m[0].clone();
            set_090(&mut b, off, &[(word, v)], false);
            assert!(read_super(&MemSource::new(b.clone())).unwrap().is_none(), "word {word}");
            assert!(damaged_supers(&MemSource::new(b)).unwrap().is_empty(), "word {word}");
        }
    }

    /// 1.x fields beyond the common ones: a device number past the table is a spare, a role
    /// past the array's devices too; an odd table size sums a 16-bit tail; the bad-block log is
    /// metadata; a member being rebuilt is out of sync from its recovery offset; a reshape and
    /// the journal feature are not mapped and say so.
    #[test]
    fn superblock_1_x_roles_bad_blocks_recovery_and_features() {
        let s = spec(12, 1, 0, 2, 1 << 20);
        let len = 3usize << 20;
        let mut m = vec![vec![0u8; len]; 2];
        for (i, b) in m.iter_mut().enumerate() {
            write_md_super(b, &s, i as u32, Some(i as u32));
        }
        // An odd device table (383 entries): still checks out.
        let mut odd = m[1].clone();
        set_1x(&mut odd, 4096, |sb| sb[220..224].copy_from_slice(&383u32.to_le_bytes()));
        assert_eq!(read_super(&MemSource::new(odd)).unwrap().unwrap().role, Some(1));
        // Device number 500 of a 384-entry table: no role.
        let mut spare = m[1].clone();
        set_1x(&mut spare, 4096, |sb| sb[160..164].copy_from_slice(&500u32.to_le_bytes()));
        assert_eq!(read_super(&MemSource::new(spare)).unwrap().unwrap().role, None);
        // Role 7 of a 2-device array: a spare as well.
        let mut far = m[1].clone();
        set_1x(&mut far, 4096, |sb| sb[256 + 2..256 + 4].copy_from_slice(&7u16.to_le_bytes()));
        let c = assembled(&[m[0].clone(), far]);
        let roles: Vec<_> = c.members.iter().map(|x| (x.role.clone(), x.slot)).collect();
        assert_eq!(roles, [(MemberRole::Slot(0), Some(0)), (MemberRole::Slot(1), None), (MemberRole::Spare, Some(1))]);
        // A bad-block log of 8 sectors 16 sectors after the superblock.
        let mut bb = m[0].clone();
        set_1x(&mut bb, 4096, |sb| {
            sb[186..188].copy_from_slice(&8u16.to_le_bytes());
            sb[188..192].copy_from_slice(&16i32.to_le_bytes());
        });
        let sb = read_super(&MemSource::new(bb)).unwrap().unwrap();
        assert_eq!(sb.metadata, [ByteRange::new(4096, 4096), ByteRange::new(4096 + 16 * 512, 8 * 512)]);
        // Member 1 rebuilt up to 512 KiB (feature bit 1, recovery_offset at 152).
        let mut rec = m.clone();
        set_1x(&mut rec[1], 4096, |sb| {
            sb[8..12].copy_from_slice(&2u32.to_le_bytes());
            sb[152..160].copy_from_slice(&1024u64.to_le_bytes());
        });
        assert_eq!(assembled(&rec).unsynced, [(1, ByteRange::from_bounds((1 << 20) + (512 << 10), 2 << 20))]);
        // A reshape (bit 2), the journal (bit 9): unsupported, with the reason.
        for (bit, why) in [(4u32, "a reshape is in progress"), (512, "features 0x200 (clustered, journal or PPL)")] {
            let mut m = m.clone();
            for b in &mut m {
                set_1x(b, 4096, |sb| sb[8..12].copy_from_slice(&bit.to_le_bytes()));
            }
            let c = assembled(&m);
            assert_eq!(c.status, ContainerStatus::Unsupported, "{why}");
            assert!(c.notes.iter().any(|n| n.message.contains(why)), "{:?}", c.notes);
        }
    }

    /// Superblocks that are not this member's: at its place but naming another (a copy), the
    /// magic of another major version, a table too large; none is read, and only a checksum
    /// that fails is a damaged one.
    #[test]
    fn superblock_1_x_copies_and_other_versions_are_not_read() {
        let s = spec(12, 1, 0, 2, 1 << 20);
        let mut m = vec![0u8; 3 << 20];
        write_md_super(&mut m, &s, 0, Some(0));
        let mut copy = m.clone();
        set_1x(&mut copy, 4096, |sb| sb[144..152].copy_from_slice(&16u64.to_le_bytes()));
        assert!(read_super(&MemSource::new(copy)).unwrap().is_none());
        let mut v2 = m.clone();
        set_1x(&mut v2, 4096, |sb| sb[4..8].copy_from_slice(&2u32.to_le_bytes()));
        assert!(read_super(&MemSource::new(v2.clone())).unwrap().is_none());
        assert!(damaged_supers(&MemSource::new(v2)).unwrap().is_empty());
        let mut big = m.clone();
        big[4096 + 220..4096 + 224].copy_from_slice(&2000u32.to_le_bytes());
        assert!(read_super(&MemSource::new(big.clone())).unwrap().is_none());
        assert_eq!(
            damaged_supers(&MemSource::new(big)).unwrap(),
            [(4096, "md 1.2 superblock checksum mismatch".into())]
        );
        // Smaller than a 0.90 superblock's reserved area: only the 1.x places are looked at.
        let mut s16 = s.clone();
        s16.data_offset = 16 << 10;
        let mut small = vec![0u8; 64 << 10];
        write_md_super(&mut small, &s16, 0, Some(0));
        assert!(read_super(&MemSource::new(small.clone())).unwrap().is_some());
        assert!(damaged_supers(&MemSource::new(small)).unwrap().is_empty());
    }

    /// The write-intent bitmap: where none can be read (no header, a chunk size that is not a
    /// power of two of at least 512) its place is the whole gap before the data, and all of it
    /// is out of sync; an older or stale-marked one makes all of it out of sync; bits past the
    /// array's chunks are ignored.
    #[test]
    fn bitmaps_that_cannot_be_trusted_make_everything_unsynced() {
        let mut s = spec(12, 1, 0, 2, 2 << 20);
        s.bitmap = Some((8, 64 * 1024));
        let (m, _) = array(&s, 4 << 20, &data(1 << 20));
        let all = vec![(0, ByteRange::new(1 << 20, 2 << 20)), (1, ByteRange::new(1 << 20, 2 << 20))];
        let bm = 8192usize; // 8 sectors after the superblock at 4 KiB
        type Edit = Box<dyn Fn(&mut [u8])>;
        let edits: [(&str, Edit); 5] = [
            ("no header", Box::new(move |b| b[bm..bm + 4].fill(0))),
            ("chunk 256", Box::new(move |b| b[bm + 52..bm + 56].copy_from_slice(&256u32.to_le_bytes()))),
            ("chunk 3 KiB", Box::new(move |b| b[bm + 52..bm + 56].copy_from_slice(&3072u32.to_le_bytes()))),
            ("older events", Box::new(move |b| b[bm + 24..bm + 32].copy_from_slice(&1u64.to_le_bytes()))),
            ("stale flag", Box::new(move |b| b[bm + 48..bm + 52].copy_from_slice(&2u32.to_le_bytes()))),
        ];
        for (what, edit) in &edits {
            let mut m = m.clone();
            edit(&mut m[1]);
            let c = assembled(&m);
            assert_eq!(c.unsynced, all, "{what}");
            if *what == "no header" {
                // The whole space between the superblock and the data is metadata then.
                assert!(c.metadata.contains(&(1, ByteRange::from_bounds(4096, 1 << 20))), "{:?}", c.metadata);
            }
        }
        // 4 chunks of 512 KiB: bits 4 to 7 of the first byte are past the end.
        s.bitmap = Some((8, 512 * 1024));
        let (mut m, _) = array(&s, 4 << 20, &data(1 << 20));
        m[1][bm + 256] = 0xf0;
        assert!(assembled(&m).unsynced.is_empty());
        m[1][bm + 256] = 0xf1;
        let first = vec![(0, ByteRange::new(1 << 20, 512 << 10)), (1, ByteRange::new(1 << 20, 512 << 10))];
        assert_eq!(assembled(&m).unsynced, first);
    }

    /// RAID 10 counts its bitmap in array space: any bit set makes every member's data out of
    /// sync.
    #[test]
    fn a_raid10_bitmap_bit_makes_all_of_it_unsynced() {
        let mut s = spec(12, 10, 0x102, 4, 2 << 20);
        s.bitmap = Some((8, 64 * 1024));
        let (mut m, c) = array(&s, 4 << 20, &data(1 << 20));
        assert!(c.unsynced.is_empty());
        m[2][8192 + 256] = 1;
        let c = assembled(&m);
        assert_eq!(c.unsynced, (0..4).map(|i| (i, ByteRange::new(1 << 20, 2 << 20))).collect::<Vec<_>>());
    }

    /// A RAID 1 on 1.2 keeps its data 1 MiB in: a file system at the start of a slot is not its
    /// content, so that slot is no member; an array without a name is named by its UUID; one
    /// whose size passes its members' data does not fit them and is not mapped.
    #[test]
    fn slots_names_and_sizes_that_do_not_fit() {
        let s = spec(12, 1, 0, 2, 1 << 20);
        let (m, _) = array(&s, 3 << 20, &data(1 << 20));
        assert!(assemble_all(&slots(&m, true), &[], &Limits::default()).is_empty());
        let mut anon = s.clone();
        anon.name = String::new();
        let mut a = m.clone();
        for (i, b) in a.iter_mut().enumerate() {
            write_md_super(b, &anon, i as u32, Some(i as u32));
        }
        assert_eq!(assembled(&a).name, "11111111:11111111:11111111:11111111");
        let mut huge = s.clone();
        huge.size = 64 << 20;
        let mut h = m.clone();
        for (i, b) in h.iter_mut().enumerate() {
            write_md_super(b, &huge, i as u32, Some(i as u32));
        }
        let c = assembled(&h);
        assert_eq!((c.status, c.volumes.len()), (ContainerStatus::Unsupported, 0));
        assert!(c.notes.iter().any(|n| n.message.contains("does not fit its members")), "{:?}", c.notes);
    }
}
