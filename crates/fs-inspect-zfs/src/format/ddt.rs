//! The dedup tables (DDT): one entry per deduplicated block, keyed by its checksum, holding the
//! block's copies (DVAs), reference count and physical birth.
//!
//! A table is found from the MOS directory:
//!
//! - legacy: `DDT-<checksum>-zap-<class>` (`unique`, `duplicate`, `ditto`) names a ZAP object;
//! - fast dedup (`com.klarasystems:fast_dedup`): `DDT-<checksum>` names a micro ZAP with the
//!   table's `version` and `flags` (1: flat entries, 2: a log) and its objects,
//!   `DDT-<checksum>-zap-<class>` and the two logs `DDT-log-<checksum>-0` / `-1`.
//!
//! (`DDT-statistics` is a histogram, not a table.)
//!
//! A ZAP entry's value is a byte array: a header byte (the compression function in bits 0..7,
//! little-endian in bit 7, as in a block pointer), then the entry's phys, compressed. A legacy
//! phys is 4 groups of 64 bytes, a flat one 1 group and a word more (72 bytes); a group: 3 DVAs
//! (16 bytes each, as in a block pointer), the reference count, the physical birth.
//!
//! A log is an object of 64-bit words whose blocks hold records, never across a block (the
//! rest of a block is zero): a word `type (0..8) | length in bytes (8..24) | ...`, then for an
//! entry record (type 1) the 40-byte key and the phys.
//!
//! Until a log is flushed into the ZAPs its entries are the table's latest: with fast dedup a
//! block whose last reference went away stays allocated, held by a log entry with no
//! references, so no block pointer of the pool reaches it, and the next write of the same data
//! can take it back as it is.

use crate::format::ZfsFs;
use crate::format::blkptr::Dva;
use crate::format::codec;
use crate::format::objset::for_each_l0;
use crate::format::zap::{self, ZBT_LEAF};
use fs_inspect_core::bytes::u64_at;
use fs_inspect_core::{ByteRange, Error, Result};

/// Table flags (fast dedup): flat entries, a log.
const FLAG_FLAT: u64 = 1;
const FLAG_LOG: u64 = 2;
const KEY: usize = 40;
const GROUP: usize = 64;
const TRAD_PHYS: usize = 4 * GROUP;
const FLAT_PHYS: usize = GROUP + 8;
/// Log record types.
const REC_ENTRY: u64 = 1;
/// Value header: compression function, little-endian.
const COMP_MASK: u8 = 0x7f;
const LITTLE_ENDIAN: u8 = 0x80;

/// One table object: a ZAP of entries or a log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Table {
    pub obj: u64,
    pub log: bool,
    /// Flat entries (fast dedup) rather than the legacy 4 phys groups.
    pub flat: bool,
}

/// The table objects of the pool.
pub fn tables(fs: &ZfsFs) -> Result<Vec<Table>> {
    let max = fs.limits().max_tree_nodes;
    tables_of(fs.dir_entries(), &mut |obj| zap::entries(fs.reader(), &fs.mos_object(obj)?, max))
}

/// The table objects named by the MOS directory entries `dir`; `entries_of` reads the entries
/// of a fast dedup table's own directory (a ZAP object).
fn tables_of<'a>(
    dir: impl Iterator<Item = (&'a str, &'a [u64])>,
    entries_of: &mut dyn FnMut(u64) -> Result<Vec<zap::Entry>>,
) -> Result<Vec<Table>> {
    let mut out = Vec::new();
    for (name, values) in dir {
        let Some(rest) = name.strip_prefix("DDT-") else { continue };
        if rest == "statistics" {
            continue;
        }
        let Some(&obj) = values.first() else { continue };
        if rest.contains("-zap-") {
            out.push(Table { obj, log: false, flat: false });
            continue;
        }
        if rest.contains('-') {
            return Err(Error::unsupported(format!("dedup table directory entry {name}")));
        }
        // Fast dedup: the table's own directory.
        let entries = entries_of(obj)?;
        let num = |k: &str| entries.iter().find(|e| e.name == k.as_bytes()).and_then(|e| e.first());
        let version = num("version").unwrap_or(0);
        let flags = num("flags").unwrap_or(0);
        if version != 1 || flags & !(FLAG_FLAT | FLAG_LOG) != 0 {
            return Err(Error::unsupported(format!("dedup table {name}: version {version}, flags {flags:#x}")));
        }
        let flat = flags & FLAG_FLAT != 0;
        for e in &entries {
            let n = e.name_str();
            let Some(obj) = e.first() else { continue };
            if n.starts_with("DDT-log-") {
                out.push(Table { obj, log: true, flat });
            } else if n.contains("-zap-") {
                out.push(Table { obj, log: false, flat });
            } else if n != "version" && n != "flags" {
                return Err(Error::unsupported(format!("dedup table {name}: entry {n}")));
            }
        }
    }
    Ok(out)
}

/// Device ranges of the copies of every table entry born after txg `after` (some of them no
/// block pointer reaches). Only the tables' blocks written after `after` are read: an entry is
/// added or changed by rewriting the block holding it.
pub fn new_ranges(fs: &ZfsFs, after: u64, out: &mut Vec<ByteRange>) -> Result<()> {
    let _span = tracing::debug_span!("zfs.ddt").entered();
    let mut budget = fs.limits().max_tree_nodes;
    for t in tables(fs)? {
        let d = fs.mos_object(t.obj)?;
        let mut blocks = Vec::new();
        for_each_l0(fs.reader(), &d, &mut budget, &mut |_, bp| {
            if bp.max_birth() > after {
                blocks.push(*bp);
            }
            Ok(())
        })?;
        budget = budget.checked_sub(blocks.len() as u64).ok_or_else(|| Error::limit("too many dedup table blocks"))?;
        fs.reader().read_batch(&blocks, &mut |_, b| {
            let b = b?;
            let mut add = |phys: &[u8]| -> Result<()> {
                for d in new_copies(phys, after)? {
                    fs.dva_range(&d, out);
                }
                Ok(())
            };
            if t.log { log_records(&b, t.flat, &mut add) } else { zap_values(&b, t.flat, &mut add) }
        })?;
    }
    Ok(())
}

/// The phys of each entry of one ZAP block (header and pointer table blocks hold none).
fn zap_values(b: &[u8], flat: bool, f: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
    if u64_at(b, 0)? != ZBT_LEAF {
        return Ok(());
    }
    zap::leaf_entries(b, &mut |e| {
        let bytes: Vec<u8> = e.values.iter().map(|&v| v as u8).collect();
        f(&phys_of_value(&bytes, flat)?)
    })
}

/// A ZAP value's phys, decompressed and in host (little-endian) word order.
pub fn phys_of_value(v: &[u8], flat: bool) -> Result<Vec<u8>> {
    let (&hdr, body) = v.split_first().ok_or_else(|| Error::corrupt("empty dedup table entry"))?;
    let len = if flat { FLAT_PHYS } else { TRAD_PHYS };
    let mut p = codec::decompress(hdr & COMP_MASK, body, len)?;
    if hdr & LITTLE_ENDIAN == 0 {
        for w in p.as_chunks_mut::<8>().0 {
            w.reverse();
        }
    }
    Ok(p)
}

/// The phys of each entry record of one log block.
fn log_records(b: &[u8], flat: bool, f: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
    let want = KEY + if flat { FLAT_PHYS } else { TRAD_PHYS };
    let mut o = 0usize;
    while o + 8 <= b.len() {
        let info = u64_at(b, o)?;
        if info == 0 {
            break;
        }
        let ty = info & 0xff;
        let len = ((info >> 8) & 0xffff) as usize;
        if ty != REC_ENTRY {
            return Err(Error::unsupported(format!("dedup log record type {ty}")));
        }
        if len != 8 + want || o + len > b.len() {
            return Err(Error::corrupt(format!("dedup log record of {len} bytes at {o}")));
        }
        f(&b[o + 8 + KEY..o + len])?;
        o += len;
    }
    // The rest of the block is zero.
    if b[o.min(b.len())..].iter().any(|&x| x != 0) {
        return Err(Error::corrupt(format!("dedup log block: data after the records at {o}")));
    }
    Ok(())
}

/// The copies of each phys group born after `after`.
fn new_copies(phys: &[u8], after: u64) -> Result<Vec<Dva>> {
    let mut out = Vec::new();
    for g in phys.chunks(GROUP).filter(|g| g.len() == GROUP) {
        let birth = u64_at(g, 56)?;
        let dvas: Vec<Dva> =
            (0..3).map(|i| Ok(Dva::read(u64_at(g, 16 * i)?, u64_at(g, 16 * i + 8)?))).collect::<Result<_>>()?;
        if dvas.iter().all(Dva::is_empty) {
            continue;
        }
        // An entry always records its birth; without one it counts as new.
        if birth != 0 && birth <= after {
            continue;
        }
        for d in dvas.iter().filter(|d| !d.is_empty()) {
            if d.gang {
                return Err(Error::unsupported("a gang block in a dedup table entry"));
            }
            out.push(*d);
        }
    }
    Ok(out)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    /// A phys group: copies at these 512 B offsets (32 KiB each), reference count, birth.
    fn group(offsets: &[u64], refcnt: u64, birth: u64) -> Vec<u8> {
        let mut w = [0u64; 8];
        for (i, &o) in offsets.iter().enumerate() {
            w[2 * i] = 64; // 64 sectors
            w[2 * i + 1] = o;
        }
        w[6] = refcnt;
        w[7] = birth;
        w.iter().flat_map(|x| x.to_le_bytes()).collect()
    }

    fn flat(offsets: &[u64], refcnt: u64, birth: u64) -> Vec<u8> {
        let mut p = group(offsets, refcnt, birth);
        p.extend_from_slice(&0x6adb_ca91u64.to_le_bytes());
        p
    }

    fn record(phys: &[u8]) -> Vec<u8> {
        let len = (8 + KEY + phys.len()) as u64;
        let mut r = ((2u64 << 56) | (len << 8) | REC_ENTRY).to_le_bytes().to_vec();
        r.extend_from_slice(&[0xab; KEY]);
        r.extend_from_slice(phys);
        r
    }

    fn logged(b: &[u8], flat: bool) -> Result<Vec<Vec<u8>>> {
        let mut v = Vec::new();
        log_records(b, flat, &mut |p| {
            v.push(p.to_vec());
            Ok(())
        })?;
        Ok(v)
    }

    #[test]
    fn log_block_records_then_zeros() {
        let (a, b) = (flat(&[0x5c19, 0xc03c0], 0, 243), flat(&[0x10], 1, 9));
        let mut blk = [record(&a), record(&b)].concat();
        blk.resize(1024, 0);
        assert_eq!(logged(&blk, true).unwrap(), vec![a.clone(), b.clone()]);
        // An entry without references still holds its copies.
        let c = new_copies(&a, 200).unwrap();
        assert_eq!(
            c.iter().map(|d| (d.offset, d.asize)).collect::<Vec<_>>(),
            [(0x5c19 << 9, 32768), (0xc03c0 << 9, 32768)]
        );
        assert!(new_copies(&b, 200).unwrap().is_empty(), "born before");
        assert_eq!(new_copies(&b, 8).unwrap().len(), 1);
    }

    #[test]
    fn log_block_damage_and_unknown_records() {
        let mut blk = record(&flat(&[1], 1, 5));
        blk.resize(512, 0);
        let mut other = blk.clone();
        other[0] = 2;
        assert!(logged(&other, true).is_err(), "another record type");
        let mut tail = blk.clone();
        tail[500] = 1;
        assert!(logged(&tail, true).is_err(), "data after the records");
        assert!(logged(&blk, false).is_err(), "a flat record where legacy ones are expected");
    }

    #[test]
    fn zap_value_byte_order_and_compression() {
        let p = flat(&[7], 1, 30);
        // Little-endian, stored as is.
        let v = [&[LITTLE_ENDIAN | codec::comp::OFF][..], &p].concat();
        assert_eq!(phys_of_value(&v, true).unwrap(), p);
        // Big-endian words come back in host order.
        let be: Vec<u8> = p.chunks(8).flat_map(|w| w.iter().rev().copied().collect::<Vec<_>>()).collect();
        let v = [&[codec::comp::OFF][..], &be].concat();
        assert_eq!(phys_of_value(&v, true).unwrap(), p);
        // ZLE: runs of literals (length - 1, then the bytes).
        let mut z = vec![LITTLE_ENDIAN | codec::comp::ZLE];
        for c in p.chunks(64) {
            z.push(c.len() as u8 - 1);
            z.extend_from_slice(c);
        }
        assert_eq!(phys_of_value(&z, true).unwrap(), p);
        assert!(phys_of_value(&[], true).is_err());
    }

    #[test]
    fn legacy_phys_groups_by_birth_and_gang_copies() {
        let p = [group(&[1], 1, 10), group(&[], 0, 0), group(&[2, 3], 2, 50), group(&[], 0, 0)].concat();
        assert_eq!(p.len(), TRAD_PHYS);
        let c = new_copies(&p, 20).unwrap();
        assert_eq!(c.iter().map(|d| d.offset >> 9).collect::<Vec<_>>(), [2, 3]);
        let mut g = group(&[4], 1, 50);
        g[15] |= 0x80; // gang flag of DVA 0
        assert!(new_copies(&g, 20).is_err());
    }

    fn entry(name: &str, values: Vec<u64>) -> zap::Entry {
        zap::Entry { name: name.as_bytes().to_vec(), intlen: 8, values }
    }

    /// The tables the MOS directory names: legacy ZAPs by name; a fast dedup table's own
    /// directory read for its flags, ZAPs and logs. Statistics, empty values, and the versions,
    /// flags, names or entries this reader does not know are passed over or refused.
    #[test]
    fn tables_from_the_directory() {
        let fast = |entries: Vec<zap::Entry>| {
            move |obj: u64| -> Result<Vec<zap::Entry>> {
                assert_eq!(obj, 40);
                Ok(entries.clone())
            }
        };
        let dir: Vec<(&str, Vec<u64>)> = vec![
            ("DDT-statistics", vec![9]),
            ("DDT-sha256-zap-unique", vec![10]),
            ("DDT-sha256-zap-ditto", vec![]),
            ("root_dataset", vec![2]),
            ("DDT-blake3", vec![40]),
        ];
        fn of<'a>(d: &'a [(&'a str, Vec<u64>)]) -> Vec<(&'a str, &'a [u64])> {
            d.iter().map(|(n, v)| (*n, v.as_slice())).collect()
        }
        let good = vec![
            entry("version", vec![1]),
            entry("flags", vec![FLAG_FLAT | FLAG_LOG]),
            entry("DDT-blake3-zap-duplicate", vec![41]),
            entry("DDT-log-blake3-0", vec![42]),
            entry("DDT-log-blake3-1", vec![]),
        ];
        let t = tables_of(of(&dir).into_iter(), &mut fast(good.clone())).unwrap();
        assert_eq!(
            t,
            [
                Table { obj: 10, log: false, flat: false },
                Table { obj: 41, log: false, flat: true },
                Table { obj: 42, log: true, flat: true },
            ]
        );
        // Legacy entries in a fast dedup table: no flat flag.
        let legacy = vec![entry("version", vec![1]), entry("flags", vec![0]), entry("DDT-x-zap-unique", vec![43])];
        let t = tables_of(of(&dir[4..]).into_iter(), &mut fast(legacy)).unwrap();
        assert_eq!(t, [Table { obj: 43, log: false, flat: false }]);
        // Refused: another version, unknown flags, an unknown entry, an unknown directory name.
        for bad in [
            vec![entry("version", vec![2])],
            vec![entry("flags", vec![4]), entry("version", vec![1])],
            vec![entry("version", vec![1]), entry("DDT-other", vec![5])],
        ] {
            let e = tables_of(of(&dir[4..]).into_iter(), &mut fast(bad)).unwrap_err();
            assert_eq!(e.kind(), fs_inspect_core::ErrorKind::Unsupported);
        }
        let odd = [("DDT-sha256-other", vec![7])];
        assert!(tables_of(of(&odd).into_iter(), &mut |_| Ok(Vec::new())).is_err());
        // A table directory that does not read fails the listing.
        let e = tables_of(of(&dir[4..]).into_iter(), &mut |_| Err(Error::corrupt("unreadable"))).unwrap_err();
        assert!(e.message().contains("unreadable"));
    }

    /// Log records of legacy entries; a record running past the block; a ZAP block that is
    /// not a leaf holds no entries.
    #[test]
    fn log_records_and_zap_blocks() {
        let p = [group(&[1], 1, 5), group(&[], 0, 0), group(&[], 0, 0), group(&[], 0, 0)].concat();
        let mut blk = record(&p);
        blk.resize(1024, 0);
        assert_eq!(logged(&blk, false).unwrap(), vec![p.clone()]);
        assert!(logged(&blk[..200], false).is_err(), "cut inside the record");
        let mut hdr = vec![0u8; 512];
        hdr[0..8].copy_from_slice(&crate::format::zap::ZBT_HEADER.to_le_bytes());
        let mut n = 0;
        zap_values(&hdr, false, &mut |_| {
            n += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(n, 0);
        // A leaf of entries whose values are compressed phys bytes (here stored as they are).
        let flatp = flat(&[3], 1, 7);
        let v: Vec<u64> =
            [&[LITTLE_ENDIAN | codec::comp::OFF][..], &flatp].concat().into_iter().map(u64::from).collect();
        let leaf = crate::format::zap::encode::leaf(4096, &[("k", 1, v)]);
        let mut got = Vec::new();
        zap_values(&leaf, true, &mut |p| {
            got.push(p.to_vec());
            Ok(())
        })
        .unwrap();
        assert_eq!(got, [flatp]);
    }
}
