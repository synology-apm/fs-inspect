//! The namespace of a FAT12/16/32 or exFAT volume: one root, nodes named by where their
//! directory entry is.
//!
//! - FAT keeps no inode numbers. A node's id is the volume offset of its directory entry: the
//!   short (8.3) entry on FAT, the File entry of its entry set on exFAT; the root directory,
//!   which has none, is id 0. On exFAT, bit 63 of the id says the directory holding the entry
//!   set is contiguous (`NoFatChain`), so a set running into the next cluster is found again.
//!   An id is checked when used: one not at a live entry of a file or directory is not found.
//! - Names compare without case (FAT: the long or the 8.3 name, simple uppercase; exFAT: the
//!   volume's Up-case Table). Listed names are the long names (FAT: the 8.3 name where there is
//!   none), as UTF-16.
//! - FAT time stamps are local time with no zone: they are reported as if UTC. exFAT's carry
//!   a UTC offset (15-minute steps, bit 7 set when valid) and are reported in UTC where they
//!   do, as if UTC where they do not.
//! - An exFAT file reads as zeros past its ValidDataLength.
//! - There are no extended attributes, links, hard links, named streams or access control:
//!   those facets of a node are unsupported; its streams are its main one.

use crate::format::exfat::{ExFatFs, Found as ExFound};
use crate::format::fat::{FatFs, Found as FatFound};
use fs_inspect_core::RootId;
use fs_inspect_core::bytes::{u16_at, u32_at};
use fs_inspect_core::ns::kit::{main_stream, name_utf16};
use fs_inspect_core::read::{ExtentReader, FileReader};
use fs_inspect_core::{
    ByteRange, DirEntry, Error, Name, Namespace, NodeId, NodeInfo, NodeKind, Result, RootInfo, Stat, StreamId, Times,
    Timestamp, Want, WinAttrs,
};
use fs_inspect_core::{DirEntryExt, NodeInfoExt, RootInfoExt, StatExt, WantExt};
use fs_inspect_core::{TimesExt, WinAttrsExt};
use std::ops::ControlFlow;
use std::sync::Arc;

/// The root directory's id.
const ROOT: u64 = 0;
/// exFAT: the entry set's directory is contiguous (`NoFatChain`).
const CONTIGUOUS: u64 = 1 << 63;
/// `ATTR_DIRECTORY`.
const ATTR_DIR: u32 = 0x10;

fn roots() -> Vec<RootInfo> {
    vec![RootInfo::main(NodeId::new(0, ROOT))]
}

/// The id of `node` in the only root; not found in another.
fn id(node: NodeId) -> Result<u64> {
    if node.root != RootId(0) {
        return Err(Error::not_found(format!("FAT node {node}")));
    }
    Ok(node.id)
}

fn kind(attr: u32) -> NodeKind {
    if attr & ATTR_DIR != 0 { NodeKind::Dir } else { NodeKind::File }
}

/// Days from 1970-01-01 to the civil date `y-m-d`.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// A FAT / exFAT date and time (`tenms`: 10 ms units, 0..=199), taken as UTC; `None` for no
/// date or an impossible one.
fn fat_time(date: u16, time: u16, tenms: u8) -> Option<Timestamp> {
    let (y, m, d) = (1980 + i64::from(date >> 9), i64::from((date >> 5) & 0xF), i64::from(date & 0x1F));
    if date == 0 || !(1..=12).contains(&m) || d == 0 {
        return None;
    }
    let secs = i64::from(time >> 11) * 3600 + i64::from((time >> 5) & 0x3F) * 60 + i64::from(time & 0x1F) * 2;
    let tenms = tenms.min(199);
    Some(Timestamp {
        secs: days_from_civil(y, m, d) * 86_400 + secs + i64::from(tenms / 100),
        nanos: u32::from(tenms % 100) * 10_000_000,
    })
}

/// An exFAT timestamp field (date in the high half, time in the low one) and its UTC offset
/// field (bit 7: valid; the low 7 bits signed, in 15-minute steps).
fn exfat_time(t: u32, tenms: u8, utc_offset: u8) -> Option<Timestamp> {
    let mut ts = fat_time((t >> 16) as u16, t as u16, tenms)?;
    if utc_offset & 0x80 != 0 {
        let quarter = i64::from(((utc_offset << 1) as i8) >> 1);
        ts.secs -= quarter * 15 * 60;
    }
    Some(ts)
}

/// `stat` and the facets in `want`: the main stream, nothing else FAT keeps.
fn info(st: Stat, want: Want) -> NodeInfo {
    fn none<T>(node: NodeId, what: &str) -> Result<T> {
        Err(Error::unsupported(format!("FAT node {node}: FAT keeps no {what}")))
    }
    let node = st.node;
    let streams = want.then(Want::STREAMS, || Ok(main_stream(st.kind, st.size)));
    let mut info = NodeInfo::new(st);
    info.xattrs = want.then(Want::XATTRS, || none(node, "extended attributes"));
    info.security = want.then(Want::SECURITY, || none(node, "access control"));
    info.link = want.then(Want::LINK, || none(node, "links"));
    // An entry does not say which directory holds it: its one name is not told.
    info.names = want.then(Want::NAMES, || none(node, "record of an entry's directory"));
    info.streams = streams;
    info
}

fn not_a_dir(node: NodeId) -> Error {
    Error::invalid_argument(format!("FAT node {node} is not a directory"))
}

fn not_a_file(node: NodeId) -> Error {
    Error::invalid_argument(format!("FAT node {node} is not a regular file"))
}

fn check_stream(node: NodeId, stream: StreamId) -> Result<()> {
    if stream != StreamId::MAIN {
        return Err(Error::not_found(format!("FAT node {node} has no stream {}", stream.get())));
    }
    Ok(())
}

// --- FAT12/16/32 ----------------------------------------------------------------------------

impl FatFs {
    /// The entry of `node` (`None`: the root).
    fn node(&self, node: NodeId) -> Result<Option<([u8; 32], FatFound)>> {
        match id(node)? {
            ROOT => Ok(None),
            off => self.entry_at(off).map(Some),
        }
    }

    /// The directory `dir` (`None`: not a directory).
    fn reader(&self, dir: NodeId) -> Result<Option<crate::format::chain::DirReader>> {
        match self.node(dir)? {
            None => self.root_reader().map(Some),
            Some((_, f)) if u32::from(f.attr) & ATTR_DIR != 0 => self.dir_reader(&f).map(Some),
            Some(_) => Ok(None),
        }
    }

    /// The regular file `node`.
    fn file(&self, node: NodeId) -> Result<Option<FatFound>> {
        Ok(self.node(node)?.map(|(_, f)| f).filter(|f| u32::from(f.attr) & ATTR_DIR == 0))
    }

    /// The stat of `node`, from its directory entry (the root has none).
    fn stat(&self, node: NodeId) -> Result<Stat> {
        let Some((e, f)) = self.node(node)? else { return Ok(Stat::new(node, NodeKind::Dir, 0)) };
        let attr = u32::from(f.attr);
        let mut st = Stat::new(node, kind(attr), u64::from(f.size));
        st.windows = Some(WinAttrs::new(attr, None, None));
        st.times = Times::new(
            fat_time(u16_at(&e, 16)?, u16_at(&e, 14)?, e[13]),
            fat_time(u16_at(&e, 24)?, u16_at(&e, 22)?, 0),
            None,
            fat_time(u16_at(&e, 18)?, 0, 0),
        );
        Ok(st)
    }
}

impl fs_inspect_core::sealed::Ns for FatFs {}

impl Namespace for FatFs {
    fn roots(&self) -> Result<Vec<RootInfo>> {
        Ok(roots())
    }

    fn node_info(&self, node: NodeId, want: Want) -> Result<NodeInfo> {
        Ok(info(self.stat(node)?, want))
    }

    fn read_dir(&self, dir: NodeId, f: &mut dyn FnMut(DirEntry) -> ControlFlow<()>) -> Result<()> {
        let r = self.reader(dir)?.ok_or_else(|| not_a_dir(dir))?;
        self.scan(r, &mut |off, long, short, found| {
            let e = DirEntry::new(
                Name::Utf16(long.unwrap_or(short).to_vec()),
                NodeId::new(0, off),
                Some(kind(u32::from(found.attr))),
            );
            f(e).is_break()
        })
    }

    fn lookup(&self, dir: NodeId, name: &Name) -> Result<Option<DirEntry>> {
        let Some(r) = self.reader(dir)? else { return Ok(None) };
        let Some(want) = name_utf16(name) else { return Ok(None) };
        Ok(self
            .find(r, &want)?
            .map(|(off, name, f)| DirEntry::new(Name::Utf16(name), NodeId::new(0, off), Some(kind(u32::from(f.attr))))))
    }

    fn open(self: Arc<Self>, node: NodeId, stream: StreamId) -> Result<Box<dyn FileReader>> {
        check_stream(node, stream)?;
        let f = self.file(node)?.ok_or_else(|| not_a_file(node))?;
        let extents = self.extents(&f)?;
        Ok(Box::new(ExtentReader::new(self.src().clone(), u64::from(f.size), &extents, 0)?))
    }

    fn case_insensitive(&self, _: u64) -> bool {
        true
    }

    /// The file's whole cluster chain, whatever its size says.
    fn exclusion_ranges(&self, node: NodeId) -> Result<Vec<ByteRange>> {
        match self.file(node)? {
            Some(f) => self.ranges(&f),
            None => Ok(Vec::new()),
        }
    }
}

// --- exFAT ----------------------------------------------------------------------------------

impl ExFatFs {
    /// The entry set of `node` (`None`: the root).
    fn node(&self, node: NodeId) -> Result<Option<(Vec<u8>, ExFound)>> {
        match id(node)? {
            ROOT => Ok(None),
            id => self.set_at(id & !CONTIGUOUS, id & CONTIGUOUS != 0).map(Some),
        }
    }

    /// The directory `dir` and the bit its entries' ids carry (`None`: not a directory).
    fn reader(&self, dir: NodeId) -> Result<Option<(crate::format::chain::DirReader, u64)>> {
        match self.node(dir)? {
            None => Ok(Some((self.root_reader()?, 0))),
            Some((_, f)) if f.is_dir => {
                let bit = if f.no_fat_chain { CONTIGUOUS } else { 0 };
                Ok(Some((self.dir_reader(&f)?, bit)))
            }
            Some(_) => Ok(None),
        }
    }

    /// The regular file `node`.
    fn file(&self, node: NodeId) -> Result<Option<ExFound>> {
        Ok(self.node(node)?.map(|(_, f)| f).filter(|f| !f.is_dir))
    }

    /// The stat of `node`, from its directory entry (the root has none).
    fn stat(&self, node: NodeId) -> Result<Stat> {
        let Some((set, f)) = self.node(node)? else { return Ok(Stat::new(node, NodeKind::Dir, 0)) };
        let attr = u32::from(u16_at(&set, 4)?);
        let mut st = Stat::new(node, kind(attr), f.data_length);
        st.windows = Some(WinAttrs::new(attr, None, None));
        st.times = Times::new(
            exfat_time(u32_at(&set, 8)?, set[20], set[22]),
            exfat_time(u32_at(&set, 12)?, set[21], set[23]),
            None,
            exfat_time(u32_at(&set, 16)?, 0, set[24]),
        );
        Ok(st)
    }
}

impl fs_inspect_core::sealed::Ns for ExFatFs {}

impl Namespace for ExFatFs {
    fn roots(&self) -> Result<Vec<RootInfo>> {
        Ok(roots())
    }

    fn node_info(&self, node: NodeId, want: Want) -> Result<NodeInfo> {
        Ok(info(self.stat(node)?, want))
    }

    fn read_dir(&self, dir: NodeId, f: &mut dyn FnMut(DirEntry) -> ControlFlow<()>) -> Result<()> {
        let (r, bit) = self.reader(dir)?.ok_or_else(|| not_a_dir(dir))?;
        self.scan(r, &mut |off, units, found| {
            let e = DirEntry::new(
                Name::Utf16(units.to_vec()),
                NodeId::new(0, off | bit),
                Some(if found.is_dir { NodeKind::Dir } else { NodeKind::File }),
            );
            f(e).is_break()
        })
    }

    fn lookup(&self, dir: NodeId, name: &Name) -> Result<Option<DirEntry>> {
        let Some((r, bit)) = self.reader(dir)? else { return Ok(None) };
        let Some(want) = name_utf16(name) else { return Ok(None) };
        Ok(self.find(r, &want)?.map(|(off, name, f)| {
            DirEntry::new(
                Name::Utf16(name),
                NodeId::new(0, off | bit),
                Some(if f.is_dir { NodeKind::Dir } else { NodeKind::File }),
            )
        }))
    }

    fn open(self: Arc<Self>, node: NodeId, stream: StreamId) -> Result<Box<dyn FileReader>> {
        check_stream(node, stream)?;
        let f = self.file(node)?.ok_or_else(|| not_a_file(node))?;
        let extents = self.extents(&f)?;
        let r = ExtentReader::new(self.src().clone(), f.data_length, &extents, 0)?;
        Ok(Box::new(r.with_valid_length(f.valid_data_length)))
    }

    fn case_insensitive(&self, _: u64) -> bool {
        true
    }

    /// The file's clusters: its whole FAT chain, or with `NoFatChain` what its length needs.
    fn exclusion_ranges(&self, node: NodeId) -> Result<Vec<ByteRange>> {
        match self.file(node)? {
            Some(f) => self.ranges(&f),
            None => Ok(Vec::new()),
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn fat_times_convert() {
        // 2020-02-29 13:45:58.50
        let date = ((2020 - 1980) << 9) | (2 << 5) | 29;
        let time = (13 << 11) | (45 << 5) | 29;
        assert_eq!(fat_time(date, time, 150), Some(Timestamp { secs: 1_582_983_959, nanos: 500_000_000 }));
        assert_eq!(fat_time(0, 0, 0), None);
        assert_eq!(fat_time((1 << 5) | 1, 0, 0), Some(Timestamp { secs: 315_532_800, nanos: 0 }));
    }

    #[test]
    fn exfat_utc_offsets_apply() {
        let t: u32 = ((((2020 - 1980) << 9) | (1 << 5) | 1) << 16) | (12 << 11);
        let local = exfat_time(t, 0, 0).unwrap().secs;
        // UTC+8 (32 quarters), UTC-5:30 (-22), and an offset not marked valid.
        assert_eq!(exfat_time(t, 0, 0x80 | 32).unwrap().secs, local - 8 * 3600);
        assert_eq!(exfat_time(t, 0, 0x80 | (-22i8 as u8 & 0x7F)).unwrap().secs, local + 5 * 3600 + 1800);
        assert_eq!(exfat_time(t, 0, 32).unwrap().secs, local);
    }
}
