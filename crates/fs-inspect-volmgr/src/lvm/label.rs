//! PV labels and metadata areas.

use super::SECTOR;
use fs_inspect_core::Scope;
use fs_inspect_core::bytes::{u32_at, u64_at};
use fs_inspect_core::checksum::crc32_raw;
use fs_inspect_core::{Error, Result, StructureKind};
use fs_inspect_io::batch::BATCH_BYTES;

const LABEL_ID: &[u8; 8] = b"LABELONE";
const LABEL_TYPE: &[u8; 8] = b"LVM2 001";
const MDA_MAGIC: &[u8; 16] = b" LVM2 x[5A%r0N*>";
const INITIAL_CRC: u32 = 0xF597_A6CF;
const MDA_HEADER: u64 = 512;
/// Largest metadata text read.
const MAX_TEXT: u64 = 64 << 20;

/// A PV label and header.
#[derive(Debug, Clone)]
pub struct PvLabel {
    /// 32 characters, no dashes.
    pub uuid: String,
    /// The PV's size in bytes, as the PV header records it.
    pub device_size: u64,
    /// Metadata areas: (offset, size) in bytes from the start of the PV.
    pub mdas: Vec<(u64, u64)>,
    /// The sector (0 to 3) that holds the label.
    pub label_sector: u64,
}

/// The PV label of `slot`, if one of its first four sectors holds a valid one (signature,
/// sector number and CRC). A label whose PV header lists more than 64 areas is `Corrupt`.
pub fn read_label(slot: &dyn fs_inspect_io::BlockSource) -> Result<Option<PvLabel>> {
    if slot.size() < 4 * SECTOR {
        return Ok(None);
    }
    let head = slot.read_vec(0, (4 * SECTOR) as usize)?;
    for s in 0..4u64 {
        let l = &head[(s * SECTOR) as usize..((s + 1) * SECTOR) as usize];
        if &l[..8] != LABEL_ID || &l[24..32] != LABEL_TYPE {
            continue;
        }
        if u64_at(l, 8)? != s || u32_at(l, 16)? != crc32_raw(INITIAL_CRC, &l[20..]) {
            continue;
        }
        let off = u32_at(l, 20)? as usize;
        if off < 32 || off >= SECTOR as usize {
            continue;
        }
        // The PV header may run past the label sector into the next ones.
        let ph = &head[(s * SECTOR) as usize + off..];
        let uuid = String::from_utf8_lossy(&ph[..32]).into_owned();
        let device_size = u64_at(ph, 32)?;
        let mut p = 40usize;
        let mut lists: [Vec<(u64, u64)>; 2] = [Vec::new(), Vec::new()];
        for list in &mut lists {
            loop {
                let (o, sz) = (u64_at(ph, p)?, u64_at(ph, p + 8)?);
                p += 16;
                if o == 0 {
                    break;
                }
                if list.len() >= 64 {
                    return Err(Error::corrupt("LVM PV header lists more than 64 areas"));
                }
                list.push((o, sz));
            }
        }
        let [_, mdas] = lists;
        return Ok(Some(PvLabel { uuid, device_size, mdas, label_sector: s }));
    }
    Ok(None)
}

/// The committed metadata text of the area at `(offset, size)` of `slot`.
pub(super) fn read_mda(slot: &dyn fs_inspect_io::BlockSource, offset: u64, size: u64) -> Result<Option<Vec<u8>>> {
    // An area up to a batch is read whole, its header and text in one request (when that
    // fails, piece by piece).
    let whole = if size <= BATCH_BYTES && offset.checked_add(size).is_some_and(|e| e <= slot.size()) {
        match slot.read_vec(offset, size as usize) {
            Err(e) if e.is_cancelled() => return Err(Error::cancelled()),
            r => r.ok(),
        }
    } else {
        None
    };
    let at = |o: u64, n: u64| -> Result<Vec<u8>> {
        match &whole {
            Some(a) => Ok(a[o as usize..(o + n) as usize].to_vec()),
            None => Ok(slot.read_vec(offset + o, n as usize)?),
        }
    };
    let h = at(0, MDA_HEADER)?;
    if &h[4..20] != MDA_MAGIC || u32_at(&h, 0)? != crc32_raw(INITIAL_CRC, &h[4..]) {
        return Ok(None);
    }
    let (start, mda_size) = (u64_at(&h, 24)?, u64_at(&h, 32)?);
    if start != offset || mda_size != size || size <= MDA_HEADER {
        return Err(Error::corrupt(format!("LVM metadata area header at {offset} disagrees with the PV header")));
    }
    let (t_off, t_size, t_crc, flags) = (u64_at(&h, 40)?, u64_at(&h, 48)?, u32_at(&h, 56)?, u32_at(&h, 60)?);
    if t_off == 0 || flags & 1 != 0 {
        return Ok(None); // empty, or ignored
    }
    if t_size > MAX_TEXT || t_off >= size || t_size > size - MDA_HEADER || t_off < MDA_HEADER {
        return Err(Error::corrupt(format!("LVM metadata text [{t_off}, +{t_size}) outside its area")));
    }
    // Circular: what does not fit before the area's end continues after the header.
    let first = t_size.min(size - t_off);
    let mut text = at(t_off, first)?;
    if first < t_size {
        text.extend(at(MDA_HEADER, t_size - first)?);
    }
    if crc32_raw(INITIAL_CRC, &text) != t_crc {
        return Err(Error::corrupt(format!("LVM metadata text at {offset} fails its checksum")));
    }
    Ok(Some(text))
}

/// What fails its checksum in the LVM metadata of `slot`: a label (signature right), the
/// header or the committed text of a metadata area its label lists; where each is.
pub(crate) fn damaged(slot: &dyn fs_inspect_io::BlockSource) -> Result<Vec<(StructureKind, u64, String)>> {
    let mut out = Vec::new();
    if slot.size() < 4 * SECTOR {
        return Ok(out);
    }
    let head = slot.read_vec(0, (4 * SECTOR) as usize)?;
    for s in 0..4u64 {
        let l = &head[(s * SECTOR) as usize..((s + 1) * SECTOR) as usize];
        if &l[..8] == LABEL_ID
            && &l[24..32] == LABEL_TYPE
            && (u64_at(l, 8)? != s || u32_at(l, 16)? != crc32_raw(INITIAL_CRC, &l[20..]))
        {
            out.push((StructureKind::LvmPvLabel, s * SECTOR, "label checksum mismatch".to_string()));
        }
    }
    let Some(label) = read_label(slot)? else { return Ok(out) };
    for (offset, size) in label.mdas {
        if offset.checked_add(MDA_HEADER).is_none_or(|e| e > slot.size()) {
            continue;
        }
        let h = slot.read_vec(offset, MDA_HEADER as usize)?;
        if &h[4..20] != MDA_MAGIC {
            continue;
        }
        if u32_at(&h, 0)? != crc32_raw(INITIAL_CRC, &h[4..]) {
            out.push((StructureKind::LvmMetadataArea, offset, "metadata area header checksum mismatch".into()));
            continue;
        }
        match read_mda(slot, offset, size) {
            Ok(_) => {}
            Err(e) if e.scope() == Scope::Unit => out.push((StructureKind::LvmMetadata, offset, e.to_string())),
            Err(e) => return Err(e),
        }
    }
    Ok(out)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use fs_inspect_core::ErrorKind;
    use fs_inspect_io::test_util::FaultySource;
    use fs_inspect_io::{DynSource, MemSource};
    use fs_inspect_testkit::volmgr::write_lvm_pv;
    use std::sync::Arc;

    const MDA: u64 = 4096;
    const TEXT: &str = "vg { seqno = 3 }\n";

    fn pv(len: usize, mda_size: u64, wrap: Option<usize>) -> Vec<u8> {
        let mut b = vec![0u8; len];
        write_lvm_pv(&mut b, &"U".repeat(32), TEXT, mda_size, wrap);
        b
    }

    fn put32(b: &mut [u8], at: usize, v: u32) {
        b[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }

    fn put64(b: &mut [u8], at: usize, v: u64) {
        b[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }

    /// Re-seal the label in sector `s`.
    fn seal_label(b: &mut [u8], s: usize) {
        let l = s * 512;
        let crc = crc32_raw(INITIAL_CRC, &b[l + 20..l + 512]);
        put32(b, l + 16, crc);
    }

    /// Re-seal the metadata area header.
    fn seal_mda(b: &mut [u8]) {
        let h = MDA as usize;
        let crc = crc32_raw(INITIAL_CRC, &b[h + 4..h + 512]);
        put32(b, h, crc);
    }

    fn mem(b: &[u8]) -> MemSource {
        MemSource::new(b.to_vec())
    }

    #[test]
    fn a_label_in_any_of_the_first_four_sectors() {
        let mut b = pv(1 << 20, 64 << 10, None);
        let l = read_label(&mem(&b)).unwrap().unwrap();
        assert_eq!((l.uuid.as_str(), l.device_size, l.label_sector), ("U".repeat(32).as_str(), 1 << 20, 1));
        assert_eq!(l.mdas, [(MDA, 64 << 10)]);
        // Moved to sector 3 with its sector number: still found, there.
        let sector: Vec<u8> = b[512..1024].to_vec();
        b[512..1024].fill(0);
        b[1536..2048].copy_from_slice(&sector);
        put64(&mut b, 1536 + 8, 3);
        seal_label(&mut b, 3);
        let l = read_label(&mem(&b)).unwrap().unwrap();
        assert_eq!((l.label_sector, l.mdas.as_slice()), (3, [(MDA, 64 << 10)].as_slice()));
    }

    #[test]
    fn labels_that_do_not_count() {
        // Too small to hold the four label sectors.
        assert!(read_label(&MemSource::new(vec![0u8; 2047])).unwrap().is_none());
        assert!(damaged(&MemSource::new(vec![0u8; 2047])).unwrap().is_empty());

        // In sector 2 but claiming sector 1: not a label; reported as damage there.
        let mut b = pv(1 << 20, 64 << 10, None);
        let sector: Vec<u8> = b[512..1024].to_vec();
        b[512..1024].fill(0);
        b[1024..1536].copy_from_slice(&sector);
        assert!(read_label(&mem(&b)).unwrap().is_none());
        let d = damaged(&mem(&b)).unwrap();
        assert_eq!(d, [(StructureKind::LvmPvLabel, 1024, "label checksum mismatch".to_string())]);

        // A PV header offset inside the label header (sealed): skipped, not damage.
        let mut b = pv(1 << 20, 64 << 10, None);
        put32(&mut b, 512 + 20, 16);
        seal_label(&mut b, 1);
        assert!(read_label(&mem(&b)).unwrap().is_none());
        assert!(damaged(&mem(&b)).unwrap().is_empty());
    }

    #[test]
    fn more_than_64_areas_is_corrupt() {
        let mut b = pv(1 << 20, 64 << 10, None);
        let ph = 512 + 32;
        // 65 data areas, then the terminator; the list runs past the label sector.
        for i in 0..65 {
            put64(&mut b, ph + 40 + i * 16, (i as u64 + 1) << 20);
            put64(&mut b, ph + 48 + i * 16, 4096);
        }
        put64(&mut b, ph + 40 + 65 * 16, 0);
        put64(&mut b, ph + 48 + 65 * 16, 0);
        seal_label(&mut b, 1);
        let e = read_label(&mem(&b)).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Corrupt, "{e}");
        assert!(e.to_string().contains("more than 64 areas"), "{e}");
    }

    #[test]
    fn metadata_text_whole_wrapped_and_large() {
        let b = pv(1 << 20, 64 << 10, None);
        assert_eq!(read_mda(&mem(&b), MDA, 64 << 10).unwrap().unwrap(), TEXT.as_bytes());
        // The text wraps around the end of the circular area, after 5 bytes.
        let b = pv(1 << 20, 64 << 10, Some(5));
        assert_eq!(read_mda(&mem(&b), MDA, 64 << 10).unwrap().unwrap(), TEXT.as_bytes());
        // An area larger than a batch is read piece by piece.
        let big = BATCH_BYTES + (64 << 10);
        let b = pv((MDA + big) as usize, big, Some(3));
        assert_eq!(read_mda(&mem(&b), MDA, big).unwrap().unwrap(), TEXT.as_bytes());
        // So is one whose whole read fails.
        let b = pv(1 << 20, 64 << 10, None);
        let src: DynSource = Arc::new(MemSource::new(b));
        let f = FaultySource::new(src, 0..u64::MAX).longer_than(4096);
        assert_eq!(read_mda(&f, MDA, 64 << 10).unwrap().unwrap(), TEXT.as_bytes());
        assert!(f.hits() >= 1);
    }

    #[test]
    fn metadata_areas_without_text() {
        let size = 64 << 10;
        // No signature, a bad header checksum, empty, ignored: no text.
        let mut b = pv(1 << 20, size, None);
        b[MDA as usize + 4] ^= 1;
        assert!(read_mda(&mem(&b), MDA, size).unwrap().is_none());
        let mut b = pv(1 << 20, size, None);
        b[MDA as usize + 100] ^= 1;
        assert!(read_mda(&mem(&b), MDA, size).unwrap().is_none());
        assert_eq!(
            damaged(&mem(&b)).unwrap(),
            [(StructureKind::LvmMetadataArea, MDA, "metadata area header checksum mismatch".to_string())]
        );
        let mut b = pv(1 << 20, size, None);
        put64(&mut b, MDA as usize + 40, 0);
        seal_mda(&mut b);
        assert!(read_mda(&mem(&b), MDA, size).unwrap().is_none());
        let mut b = pv(1 << 20, size, None);
        put32(&mut b, MDA as usize + 60, 1);
        seal_mda(&mut b);
        assert!(read_mda(&mem(&b), MDA, size).unwrap().is_none());
        assert!(damaged(&mem(&b)).unwrap().is_empty());
    }

    #[test]
    fn malformed_metadata_areas_are_corrupt() {
        let size = 64 << 10;
        let corrupt = |b: &[u8], offset: u64, size: u64, what: &str| {
            let e = read_mda(&mem(b), offset, size).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Corrupt, "{e}");
            assert!(e.to_string().contains(what), "{e}");
        };
        let b = pv(1 << 20, size, None);
        // The PV header's area disagrees with the area's own header.
        corrupt(&b, MDA, size / 2, "disagrees with the PV header");
        // An area no larger than its header.
        let mut s = b.clone();
        put64(&mut s, MDA as usize + 32, 512);
        seal_mda(&mut s);
        corrupt(&s, MDA, 512, "disagrees with the PV header");
        // Text starting inside the header, past the area, or longer than the area.
        for (t_off, t_size) in [(100, 10), (size, 10), (512, size)] {
            let mut s = b.clone();
            put64(&mut s, MDA as usize + 40, t_off);
            put64(&mut s, MDA as usize + 48, t_size);
            seal_mda(&mut s);
            corrupt(&s, MDA, size, "outside its area");
        }
        // A changed byte of text.
        let mut s = b.clone();
        s[MDA as usize + 512 + 3] ^= 1;
        corrupt(&s, MDA, size, "fails its checksum");
        let d = damaged(&mem(&s)).unwrap();
        assert_eq!(d.len(), 1);
        assert_eq!((d[0].0, d[0].1), (StructureKind::LvmMetadata, MDA));
        assert!(d[0].2.contains("fails its checksum"), "{}", d[0].2);
    }
}
