//! Disk images for tests: partition tables (MBR with logical partitions, GPT) around volume
//! images, and VHD / VHDX containers around disks. Layouts follow the specifications (MBR and
//! EBR, UEFI GPT, Microsoft VHD 1.0, MS-VHDX), so other tools (sfdisk, qemu-img) read them too.

use fs_inspect_core::bytes::{put_u16, put_u32, put_u64};
use fs_inspect_core::checksum::{crc_with_zeroed_field, crc32, crc32c};
use fs_inspect_core::guid;

const KIB: u64 = 1 << 10;
const MIB: u64 = 1 << 20;

/// GPT "Microsoft basic data" partition type.
pub const GPT_BASIC_DATA: &str = "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7";
/// MBR type of NTFS / exFAT / IFS partitions.
pub const MBR_NTFS: u8 = 0x07;
/// GPT "Linux LVM" partition type.
pub const GPT_LINUX_LVM: &str = "E6D6D379-F507-44C2-A23C-238F2A3DF928";
/// GPT "Linux RAID" partition type.
pub const GPT_LINUX_RAID: &str = "A19D880F-05FC-4D3B-A006-743F0F84911E";
/// GPT "LDM metadata" partition type (Windows dynamic disks).
pub const GPT_LDM_METADATA: &str = "5808C8AA-7E8F-42E0-85D2-E1E90434CFB3";
/// GPT "LDM data" partition type (Windows dynamic disks).
pub const GPT_LDM_DATA: &str = "AF9B60A0-1431-4F62-BC68-3311714A69AD";

/// The partition table of a disk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TableKind {
    Mbr,
    Gpt,
}

/// One partition: its content and, for MBR, its type and whether it is a logical partition
/// (inside an extended partition), for GPT its type GUID.
#[derive(Clone, Copy, Debug)]
pub struct DiskPart<'a> {
    pub data: &'a [u8],
    pub mbr_type: u8,
    pub logical: bool,
    pub gpt_type: &'a str,
}

impl<'a> DiskPart<'a> {
    /// A primary partition of basic data type (MBR 0x07).
    pub fn primary(data: &'a [u8]) -> Self {
        DiskPart { data, mbr_type: MBR_NTFS, logical: false, gpt_type: GPT_BASIC_DATA }
    }
    /// A logical partition (MBR; a primary one on GPT) of basic data type.
    pub fn logical(data: &'a [u8]) -> Self {
        DiskPart { data, mbr_type: MBR_NTFS, logical: true, gpt_type: GPT_BASIC_DATA }
    }
    /// A primary partition of MBR type `mbr_type` and GPT type `gpt_type`.
    pub fn typed(data: &'a [u8], mbr_type: u8, gpt_type: &'a str) -> Self {
        DiskPart { data, mbr_type, logical: false, gpt_type }
    }
}

/// A disk image and where each partition (in input order) starts, in bytes.
#[derive(Debug, Clone)]
pub struct Disk {
    pub image: Vec<u8>,
    pub starts: Vec<u64>,
}

/// MBR disk signature (offset 440) of the disks written here.
pub const MBR_DISK_SIGNATURE: u32 = 0x4E44_4644;

fn round_up(v: u64, m: u64) -> u64 {
    v.div_ceil(m) * m
}

fn mbr_entry(b: &mut [u8], slot: usize, kind: u8, start: u64, len: u64) {
    let e = 446 + 16 * slot;
    b[e] = 0;
    b[e + 1..e + 4].copy_from_slice(&[0xFE, 0xFF, 0xFF]);
    b[e + 4] = kind;
    b[e + 5..e + 8].copy_from_slice(&[0xFE, 0xFF, 0xFF]);
    put_u32(b, e + 8, u32::try_from(start).expect("MBR start fits 32 bits"));
    put_u32(b, e + 12, u32::try_from(len).expect("MBR length fits 32 bits"));
    b[510] = 0x55;
    b[511] = 0xAA;
}

/// A disk with `parts` laid out 1 MiB aligned, 1 MiB apart (room for EBRs), with 1 MiB free
/// at the end (room for the backup GPT). `sector` is the logical sector size (512 or 4096).
/// MBR: primary partitions take the slots in order, then one extended partition (type 0x0F)
/// holds the logical partitions, each preceded by its EBR.
pub fn disk_image(kind: TableKind, sector: u32, parts: &[DiskPart]) -> Disk {
    disk_image_aligned(kind, sector, parts, MIB)
}

/// [`disk_image`] with `align` (a multiple of the sector, at least 64 KiB: room for a GPT of 4
/// KiB sectors) in place of 1 MiB.
pub fn disk_image_aligned(kind: TableKind, sector: u32, parts: &[DiskPart], align: u64) -> Disk {
    assert!(align >= 64 * KIB && align.is_multiple_of(u64::from(sector)), "alignment {align}");
    let ss = sector as u64;
    let order: Vec<usize> = (0..parts.len()).filter(|&i| kind == TableKind::Gpt || !parts[i].logical).collect();
    let logicals: Vec<usize> = (0..parts.len()).filter(|&i| kind == TableKind::Mbr && parts[i].logical).collect();
    assert!(order.len() + usize::from(!logicals.is_empty()) <= 4 || kind == TableKind::Gpt, "too many primaries");
    let mut starts = vec![0u64; parts.len()];
    let mut ebrs = Vec::new();
    let mut pos = align;
    for &i in &order {
        starts[i] = pos;
        pos = round_up(pos + parts[i].data.len() as u64, align);
    }
    let ext_start = pos;
    for &i in &logicals {
        ebrs.push(pos);
        starts[i] = pos + align;
        pos = round_up(pos + align + parts[i].data.len() as u64, align);
    }
    let ext_end = pos;
    let total = pos + align;
    let mut image = vec![0u8; total as usize];
    for (i, p) in parts.iter().enumerate() {
        image[starts[i] as usize..starts[i] as usize + p.data.len()].copy_from_slice(p.data);
    }
    let sectors = |bytes: u64| bytes.div_ceil(ss);
    match kind {
        TableKind::Mbr => {
            // Windows writes a disk signature to an MBR disk that has none, which fails on a
            // read-only attach (the disk never comes online).
            put_u32(&mut image, 440, MBR_DISK_SIGNATURE);
            for (slot, &i) in order.iter().enumerate() {
                mbr_entry(&mut image, slot, parts[i].mbr_type, starts[i] / ss, sectors(parts[i].data.len() as u64));
            }
            if !logicals.is_empty() {
                mbr_entry(&mut image, order.len(), 0x0F, ext_start / ss, (ext_end - ext_start) / ss);
                for (k, &i) in logicals.iter().enumerate() {
                    let ebr = ebrs[k] as usize;
                    let mut e = [0u8; 512];
                    mbr_entry(
                        &mut e,
                        0,
                        parts[i].mbr_type,
                        (starts[i] - ebrs[k]) / ss,
                        sectors(parts[i].data.len() as u64),
                    );
                    if let Some(&next) = ebrs.get(k + 1) {
                        let next_end = ebrs.get(k + 2).copied().unwrap_or(ext_end);
                        mbr_entry(&mut e, 1, 0x05, (next - ext_start) / ss, (next_end - next) / ss);
                    }
                    image[ebr..ebr + 512].copy_from_slice(&e);
                }
            }
        }
        TableKind::Gpt => write_gpt(&mut image, ss, parts, &starts),
    }
    Disk { image, starts }
}

fn write_gpt(image: &mut [u8], ss: u64, parts: &[DiskPart], starts: &[u64]) {
    let total = image.len() as u64 / ss;
    let entries = 128u64;
    let array = entries * 128;
    let array_sectors = array.div_ceil(ss);
    mbr_entry(image, 0, 0xEE, 1, (total - 1).min(u32::MAX as u64));
    let mut table = vec![0u8; array as usize];
    for (i, p) in parts.iter().enumerate() {
        let e = &mut table[i * 128..(i + 1) * 128];
        e[0..16].copy_from_slice(&guid::parse(p.gpt_type).expect("a GPT type GUID"));
        e[16..32].copy_from_slice(&[i as u8 + 1; 16]);
        put_u64(e, 32, starts[i] / ss);
        put_u64(e, 40, (starts[i] + round_up(p.data.len() as u64, ss)) / ss - 1);
        for (k, c) in format!("part{}", i + 1).encode_utf16().enumerate() {
            put_u16(e, 56 + 2 * k, c);
        }
    }
    let table_crc = crc32(&[&table]);
    let backup_array = total - 1 - array_sectors;
    for (my, alt, array_lba) in [(1, total - 1, 2), (total - 1, 1, backup_array)] {
        let mut h = vec![0u8; ss as usize];
        h[0..8].copy_from_slice(b"EFI PART");
        put_u32(&mut h, 8, 0x0001_0000);
        put_u32(&mut h, 12, 92);
        put_u64(&mut h, 24, my);
        put_u64(&mut h, 32, alt);
        put_u64(&mut h, 40, 2 + array_sectors);
        put_u64(&mut h, 48, backup_array - 1);
        h[56..72].copy_from_slice(&[0x5A; 16]);
        put_u64(&mut h, 72, array_lba);
        put_u32(&mut h, 80, entries as u32);
        put_u32(&mut h, 84, 128);
        put_u32(&mut h, 88, table_crc);
        let crc = crc_with_zeroed_field(crc32, &h[..92], 16).unwrap();
        put_u32(&mut h, 16, crc);
        let at = (my * ss) as usize;
        image[at..at + ss as usize].copy_from_slice(&h);
        let at = (array_lba * ss) as usize;
        image[at..at + array as usize].copy_from_slice(&table);
    }
}

// ---- VHD ----

fn be32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_be_bytes());
}
fn be64(b: &mut [u8], o: usize, v: u64) {
    b[o..o + 8].copy_from_slice(&v.to_be_bytes());
}

/// CHS geometry of the VHD specification (appendix "CHS calculation").
fn vhd_geometry(size: u64) -> (u16, u8, u8) {
    let total = (size / 512).min(65535 * 16 * 255);
    let (spt, heads, cth) = if total >= 65535 * 16 * 63 {
        (255, 16, total / 255)
    } else {
        let (mut spt, mut cth) = (17, total / 17);
        let mut heads = cth.div_ceil(1024).max(4);
        if cth >= heads * 1024 || heads > 16 {
            (spt, heads, cth) = (31, 16, total / 31);
        }
        if cth >= heads * 1024 {
            (spt, heads, cth) = (63, 16, total / 63);
        }
        (spt, heads, cth)
    };
    ((cth / heads) as u16, heads as u8, spt as u8)
}

fn vhd_footer(size: u64, disk_type: u32, data_offset: u64) -> [u8; 512] {
    let mut f = [0u8; 512];
    f[0..8].copy_from_slice(b"conectix");
    be32(&mut f, 8, 2);
    be32(&mut f, 12, 0x0001_0000);
    be64(&mut f, 16, data_offset);
    // creator "win ": qemu then takes the size from current_size rather than the geometry
    f[28..32].copy_from_slice(b"win ");
    be32(&mut f, 32, 0x000A_0000);
    f[36..40].copy_from_slice(b"Wi2k");
    be64(&mut f, 40, size);
    be64(&mut f, 48, size);
    let (c, h, s) = vhd_geometry(size);
    f[56..58].copy_from_slice(&c.to_be_bytes());
    f[58] = h;
    f[59] = s;
    be32(&mut f, 60, disk_type);
    f[68..84].copy_from_slice(&[0x11; 16]);
    let sum: u32 = f.iter().map(|&b| b as u32).sum();
    be32(&mut f, 64, !sum);
    f
}

fn pad_to(disk: &[u8], m: u64) -> Vec<u8> {
    let mut d = disk.to_vec();
    d.resize(round_up(d.len() as u64, m) as usize, 0);
    d
}

/// Fixed VHD: the disk (padded to whole sectors) followed by the footer.
pub fn vhd_fixed(disk: &[u8]) -> Vec<u8> {
    let mut out = pad_to(disk, 512);
    let footer = vhd_footer(out.len() as u64, 2, u64::MAX);
    out.extend_from_slice(&footer);
    out
}

/// Dynamic VHD with `block_size` blocks; all-zero blocks are left unallocated.
pub fn vhd_dynamic(disk: &[u8], block_size: u32) -> Vec<u8> {
    let disk = pad_to(disk, 512);
    let bs = block_size as usize;
    let blocks = disk.len().div_ceil(bs);
    let bat_bytes = round_up(blocks as u64 * 4, 512) as usize;
    let bitmap = round_up((bs / 512).div_ceil(8) as u64, 512) as usize;
    let footer = vhd_footer(disk.len() as u64, 3, 512);
    let mut out = Vec::new();
    out.extend_from_slice(&footer);
    let mut h = [0u8; 1024];
    h[0..8].copy_from_slice(b"cxsparse");
    be64(&mut h, 8, u64::MAX);
    be64(&mut h, 16, 1536);
    be32(&mut h, 24, 0x0001_0000);
    be32(&mut h, 28, blocks as u32);
    be32(&mut h, 32, block_size);
    let sum: u32 = h.iter().map(|&b| b as u32).sum();
    be32(&mut h, 36, !sum);
    out.extend_from_slice(&h);
    let mut bat = vec![0xFFu8; bat_bytes];
    let mut data = Vec::new();
    let first = 1536 + bat_bytes;
    for k in 0..blocks {
        let chunk = &disk[k * bs..((k + 1) * bs).min(disk.len())];
        if chunk.iter().all(|&b| b == 0) {
            continue;
        }
        be32(&mut bat, 4 * k, ((first + data.len()) / 512) as u32);
        data.extend(std::iter::repeat_n(0xFF, bitmap));
        data.extend_from_slice(chunk);
        data.resize(data.len() + bs - chunk.len(), 0);
    }
    out.extend_from_slice(&bat);
    out.extend_from_slice(&data);
    out.extend_from_slice(&footer);
    out
}

// ---- VHDX ----

const VHDX_BAT: &str = "2DC27766-F623-4200-9D64-115E9BFD4A08";
const VHDX_METADATA: &str = "8B7CA206-4790-4B9A-B8FE-575F050F886E";
const VHDX_FILE_PARAMETERS: &str = "CAA16737-FA36-4D43-B3B6-33F0AA44E76B";
const VHDX_DISK_SIZE: &str = "2FA54224-CD1B-4876-B211-5DBED83BF4B8";
const VHDX_PAGE83: &str = "BECA12AB-B2E6-4523-93EF-C309E000C746";
const VHDX_LOGICAL_SECTOR: &str = "8141BF1D-A96F-4709-BA47-F233A8FAAB5F";
const VHDX_PHYSICAL_SECTOR: &str = "CDA348C7-445D-4471-9CC9-E9885251C556";

/// Options of [`vhdx`].
#[derive(Debug, Clone, Copy)]
pub struct VhdxOptions {
    /// Payload block size (1 MiB to 256 MiB, a power of two).
    pub block_size: u32,
    /// 512 or 4096.
    pub logical_sector: u32,
    /// Set a non-zero log GUID in the header (the log may hold entries).
    pub log_guid: bool,
    /// Write a valid log entry for that GUID at the start of the log (an image not closed
    /// cleanly, which needs a replay).
    pub log_entry: bool,
    /// No log region (the log GUID must be zero, so the log is never read): the metadata at 1
    /// MiB, the BAT at 2 MiB and the payload from 3 MiB. The smallest VHDX: 4 MiB for a disk of
    /// one 1 MiB block.
    pub compact: bool,
}

impl Default for VhdxOptions {
    fn default() -> Self {
        VhdxOptions { block_size: 1 << 20, logical_sector: 512, log_guid: false, log_entry: false, compact: false }
    }
}

const LOG_GUID: [u8; 16] = [0x23; 16];

fn put_guid(b: &mut [u8], o: usize, s: &str) {
    b[o..o + 16].copy_from_slice(&guid::parse(s).unwrap());
}

/// Dynamic VHDX; all-zero blocks are left unallocated (state NOT_PRESENT).
pub fn vhdx(disk: &[u8], o: VhdxOptions) -> Vec<u8> {
    let disk = pad_to(disk, o.logical_sector as u64);
    let bs = o.block_size as u64;
    let size = disk.len() as u64;
    let blocks = size.div_ceil(bs);
    let chunk_ratio = ((1u64 << 23) * o.logical_sector as u64) / bs;
    let bat_entries = if blocks == 0 { 0 } else { blocks + (blocks - 1) / chunk_ratio };
    assert!(!(o.compact && o.log_guid), "a compact VHDX has no log");
    let (log_off, meta_off, bat_off) = if o.compact { (MIB, MIB, 2 * MIB) } else { (MIB, 2 * MIB, 3 * MIB) };
    let bat_len = round_up(bat_entries * 8, MIB).max(MIB);
    let mut payload_off = bat_off + bat_len;
    let mut out = vec![0u8; payload_off as usize];

    out[0..8].copy_from_slice(b"vhdxfile");
    for (k, c) in "fs-inspect testkit".encode_utf16().enumerate() {
        put_u16(&mut out, 8 + 2 * k, c);
    }
    for (n, at) in [(1u64, 64 * KIB), (2, 128 * KIB)] {
        let h = &mut out[at as usize..(at + 4 * KIB) as usize];
        h[0..4].copy_from_slice(b"head");
        put_u64(h, 8, n);
        h[16..32].copy_from_slice(&[0x21; 16]);
        h[32..48].copy_from_slice(&[0x22; 16]);
        if o.log_guid {
            h[48..64].copy_from_slice(&LOG_GUID);
        }
        put_u16(h, 66, 1);
        put_u32(h, 68, MIB as u32);
        put_u64(h, 72, log_off);
        let crc = crc_with_zeroed_field(crc32c, h, 4).unwrap();
        put_u32(h, 4, crc);
    }
    for at in [192 * KIB, 256 * KIB] {
        let r = &mut out[at as usize..(at + 64 * KIB) as usize];
        r[0..4].copy_from_slice(b"regi");
        put_u32(r, 8, 2);
        for (k, (id, off, len)) in
            [(VHDX_BAT, bat_off, bat_len), (VHDX_METADATA, meta_off, MIB)].into_iter().enumerate()
        {
            let e = 16 + 32 * k;
            put_guid(r, e, id);
            put_u64(r, e + 16, off);
            put_u32(r, e + 24, len as u32);
            put_u32(r, e + 28, 1);
        }
        let crc = crc_with_zeroed_field(crc32c, r, 4).unwrap();
        put_u32(r, 4, crc);
    }
    if o.log_entry {
        // A log entry header without descriptors ([MS-VHDX] 2.3.1.1).
        let e = &mut out[log_off as usize..(log_off + 4 * KIB) as usize];
        e[0..4].copy_from_slice(b"loge");
        put_u32(e, 8, 4 * KIB as u32);
        put_u64(e, 16, 1);
        e[32..48].copy_from_slice(&LOG_GUID);
        put_u64(e, 48, payload_off);
        put_u64(e, 56, payload_off);
        let crc = crc_with_zeroed_field(crc32c, e, 4).unwrap();
        put_u32(e, 4, crc);
    }
    {
        let m = &mut out[meta_off as usize..(meta_off + MIB) as usize];
        m[0..8].copy_from_slice(b"metadata");
        let items: [(&str, u32, u32); 5] = [
            (VHDX_FILE_PARAMETERS, 8, 0x4),
            (VHDX_DISK_SIZE, 8, 0x6),
            (VHDX_PAGE83, 16, 0x6),
            (VHDX_LOGICAL_SECTOR, 4, 0x6),
            (VHDX_PHYSICAL_SECTOR, 4, 0x6),
        ];
        put_u16(m, 10, items.len() as u16);
        let mut data_at = 64 * KIB as usize;
        for (k, (id, len, flags)) in items.into_iter().enumerate() {
            let e = 32 + 32 * k;
            put_guid(m, e, id);
            put_u32(m, e + 16, data_at as u32);
            put_u32(m, e + 20, len);
            put_u32(m, e + 24, flags);
            match id {
                VHDX_FILE_PARAMETERS => put_u32(m, data_at, o.block_size),
                VHDX_DISK_SIZE => put_u64(m, data_at, size),
                VHDX_PAGE83 => m[data_at..data_at + 16].copy_from_slice(&[0x31; 16]),
                VHDX_LOGICAL_SECTOR => put_u32(m, data_at, o.logical_sector),
                _ => put_u32(m, data_at, 4096),
            }
            data_at += len as usize;
        }
    }
    for b in 0..blocks {
        let chunk = &disk[(b * bs) as usize..((b + 1) * bs).min(size) as usize];
        if chunk.iter().all(|&x| x == 0) {
            continue;
        }
        let idx = b + b / chunk_ratio;
        put_u64(&mut out, (bat_off + idx * 8) as usize, payload_off | 6);
        out.extend_from_slice(chunk);
        out.resize((payload_off + bs) as usize, 0);
        payload_off += bs;
    }
    out
}

/// Small images of every supported layout, for mutation tests: each holds 1 MiB volumes that
/// have only an NTFS boot sector (and its backup), enough for partition probes. The layouts
/// [`structure_regions`] names.
#[cfg(feature = "ntfs")]
pub fn mutation_layouts() -> Vec<(&'static str, Vec<u8>)> {
    layouts(MIB, MIB, false)
}

/// Every layout of volumes of `vol` bytes (each with only an NTFS boot sector and its backup),
/// partitions `align`ed; with `compact`, the VHDX [`compact`](VhdxOptions::compact).
#[cfg(feature = "ntfs")]
pub fn layouts(vol: u64, align: u64, compact: bool) -> Vec<(&'static str, Vec<u8>)> {
    let mut vol = vec![0u8; vol as usize];
    let boot = fs_inspect_ntfs::encode::encode_boot_sector(&fs_inspect_ntfs::encode::BootSpec {
        bytes_per_sector: 512,
        sectors_per_cluster_raw: 8,
        total_sectors: vol.len() as u64 / 512 - 1,
        mft_lcn: 4,
        mftmirr_lcn: 8,
        clusters_per_record_raw: -10,
        clusters_per_index_raw: 1,
        serial: 0xF0F0,
    });
    vol[..512].copy_from_slice(&boot);
    let n = vol.len();
    vol[n - 512..].copy_from_slice(&boot);
    let image = |kind, sector, parts: &[DiskPart]| disk_image_aligned(kind, sector, parts, align).image;
    let mbr = image(TableKind::Mbr, 512, &[DiskPart::primary(&vol), DiskPart::logical(&vol)]);
    let gpt = image(TableKind::Gpt, 512, &[DiskPart::primary(&vol), DiskPart::primary(&vol)]);
    let gpt4k = image(TableKind::Gpt, 4096, &[DiskPart::primary(&vol)]);
    vec![
        ("vhd-fixed-mbr", vhd_fixed(&mbr)),
        ("vhd-dynamic-gpt", vhd_dynamic(&gpt, 512 << 10)),
        ("vhdx-mbr", vhdx(&mbr, VhdxOptions { compact, ..Default::default() })),
        ("vhdx-4k-gpt", vhdx(&gpt4k, VhdxOptions { logical_sector: 4096, compact, ..Default::default() })),
        ("mbr", mbr),
        ("gpt", gpt),
        ("gpt4k", gpt4k),
        ("volume", vol),
    ]
}

/// Byte ranges (offset, length) of an image of `len` bytes where the structures of the layouts
/// written here live, for aiming mutations. Narrow ranges cover the fields themselves (so that
/// a few patched bytes often hit a length or offset field); broad ranges cover the areas
/// around them.
pub fn structure_regions(len: usize) -> Vec<(usize, usize)> {
    const K: usize = 1 << 10;
    const M: usize = 1 << 20;
    let mut r = vec![
        (0, 512),                             // MBR / protective MBR, VHD footer copy, VHDX file identifier
        (446, 66),                            // MBR partition entries
        (512, 92),                            // GPT header (512-byte sectors)
        (1024, 512),                          // GPT partition entries (512-byte sectors)
        (4096, 92),                           // GPT header (4 KiB sectors)
        (8192, 512),                          // GPT partition entries (4 KiB sectors)
        (512, 1024),                          // VHD dynamic header
        (1536, 256),                          // VHD BAT
        (64 * K, 80),                         // VHDX header 1
        (128 * K, 80),                        // VHDX header 2
        (192 * K, 80),                        // VHDX region table 1
        (256 * K, 80),                        // VHDX region table 2
        (M, 64),                              // VHDX log entry
        (2 * M, 32 + 32 * 5),                 // VHDX metadata table
        (2 * M + 64 * K, 48),                 // VHDX metadata items
        (3 * M, 64),                          // VHDX BAT
        (0, 320 * K),                         // broad: everything in the first 320 KiB
        (len.saturating_sub(512), 512),       // VHD footer, GPT backup header (512)
        (len.saturating_sub(4096), 4096),     // GPT backup header (4 KiB)
        (len.saturating_sub(64 * K), 64 * K), // broad: the tail
    ];
    for m in 1..len / M {
        r.push((m * M, 512)); // boot sectors of partitions, EBRs
        r.push((m * M + 446, 66)); // EBR entries
    }
    r.retain(|&(at, n)| n > 0 && at + n <= len);
    r
}

/// Recompute the checksums of the structures found in `image` (VHDX headers and region
/// tables, VHD footers and dynamic header, GPT headers and partition arrays of a raw disk), so
/// that mutations reach the parsers behind the checksum checks.
pub fn fix_checksums(image: &mut [u8]) {
    let len = image.len();
    let le32 = |b: &[u8], o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap()) as usize;
    let le64 = |b: &[u8], o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
    if image.starts_with(b"vhdxfile") {
        for (at, n) in [(64 << 10, 4 << 10), (128 << 10, 4 << 10), (192 << 10, 64 << 10), (256 << 10, 64 << 10)] {
            if at + n <= len {
                let crc = crc_with_zeroed_field(crc32c, &image[at..at + n], 4).unwrap();
                put_u32(image, at + 4, crc);
            }
        }
    }
    let vhd_sum = |b: &mut [u8], at: usize| {
        let sum: u32 = b.iter().enumerate().filter(|(i, _)| !(at..at + 4).contains(i)).map(|(_, &v)| v as u32).sum();
        b[at..at + 4].copy_from_slice(&(!sum).to_be_bytes());
    };
    for at in [0, len.saturating_sub(512)] {
        if len >= 512 && image[at..].starts_with(b"conectix") {
            vhd_sum(&mut image[at..at + 512], 64);
            let dyn_at = u64::from_be_bytes(image[at + 16..at + 24].try_into().unwrap());
            if let Some(h) = usize::try_from(dyn_at).ok().filter(|&h| h.checked_add(1024).is_some_and(|e| e <= len))
                && image[h..].starts_with(b"cxsparse")
            {
                vhd_sum(&mut image[h..h + 1024], 36);
            }
        }
    }
    for ss in [512usize, 4096] {
        for lba in [1, (len / ss).saturating_sub(1)] {
            let at = lba * ss;
            if lba == 0 || at + ss > len || !image[at..].starts_with(b"EFI PART") {
                continue;
            }
            let (array, count, size) = (le64(image, at + 72), le32(image, at + 80), le32(image, at + 84));
            let bytes = count.saturating_mul(size);
            let start = usize::try_from(array).unwrap_or(usize::MAX).saturating_mul(ss);
            if bytes <= 4 << 20 && start.checked_add(bytes).is_some_and(|e| e <= len) {
                let crc = crc32(&[&image[start..start + bytes]]);
                put_u32(image, at + 88, crc);
            }
            let hsize = le32(image, at + 12).clamp(92, ss);
            let crc = crc_with_zeroed_field(crc32, &image[at..at + hsize], 16).unwrap();
            put_u32(image, at + 16, crc);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vhd_geometry_covers_at_most_the_disk() {
        for mib in [1u64, 32, 127, 1000, 4096, 130_000] {
            let size = mib << 20;
            let (c, h, s) = vhd_geometry(size);
            let chs = c as u64 * h as u64 * s as u64 * 512;
            assert!(chs <= size && chs * 10 >= size * 9, "{mib} MiB: {c}/{h}/{s}");
        }
    }

    #[test]
    fn gpt_headers_carry_valid_crcs() {
        let vol = vec![7u8; 3 << 20];
        let d = disk_image(TableKind::Gpt, 512, &[DiskPart::primary(&vol)]);
        let total = d.image.len() as u64 / 512;
        for lba in [1, total - 1] {
            let h = &d.image[(lba * 512) as usize..(lba * 512 + 92) as usize];
            assert_eq!(&h[0..8], b"EFI PART");
            let stored = u32::from_le_bytes(h[16..20].try_into().unwrap());
            assert_eq!(crc_with_zeroed_field(crc32, h, 16), Some(stored));
        }
        assert_eq!(d.starts, vec![1 << 20]);
    }
}
