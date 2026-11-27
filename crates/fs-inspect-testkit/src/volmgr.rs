//! Volume manager members for tests, written from the on-disk formats independently of the
//! parsers in fs-inspect-volmgr: LVM physical volumes (label, PV header, text metadata area) and
//! md array members (superblocks 0.90 and 1.x), with the data of RAID 5 and RAID 6 layouts.

use fs_inspect_core::bytes::{put_u32, put_u64};
use fs_inspect_core::checksum::crc32_raw;

const LVM_CRC: u32 = 0xF597_A6CF;
const SECTOR: usize = 512;

/// One segment of an LVM logical volume: `stripes` are (PV name, first extent).
#[derive(Debug, Clone)]
pub struct LvmSeg {
    pub start_extent: u64,
    pub extent_count: u64,
    pub kind: &'static str,
    pub stripes: Vec<(String, u64)>,
    /// Sectors (striped with more than one stripe, RAID).
    pub stripe_size: u64,
    /// RAID (`raid1`, `raid5_ls`, …): the `raids` list, rmeta and rimage names in order
    /// (`raid0`: the rimages, as `raid0_lvs`). `mirror`: the mimage names.
    pub subs: Vec<String>,
    /// `data_copies` (raid10), `data_offset` (sectors), the mirror log LV.
    pub data_copies: u64,
    pub data_offset: u64,
    pub log: Option<String>,
}

impl LvmSeg {
    /// A linear segment: the LV's `extent_count` extents from `start_extent` on, on PV `pv`
    /// from its extent `pe`.
    pub fn linear(start_extent: u64, extent_count: u64, pv: &str, pe: u64) -> Self {
        LvmSeg {
            start_extent,
            extent_count,
            kind: "striped",
            stripes: vec![(pv.into(), pe)],
            stripe_size: 0,
            subs: vec![],
            data_copies: 0,
            data_offset: 0,
            log: None,
        }
    }

    /// A RAID segment of LV `lv` over `n` images named as lvcreate names them
    /// (`{lv}_rmeta_N`, `{lv}_rimage_N`; raid0 without rmeta).
    pub fn raid(
        kind: &'static str,
        lv: &str,
        start_extent: u64,
        extent_count: u64,
        n: usize,
        stripe_size: u64,
    ) -> Self {
        let mut subs = Vec::new();
        for i in 0..n {
            if kind != "raid0" {
                subs.push(format!("{lv}_rmeta_{i}"));
            }
            subs.push(format!("{lv}_rimage_{i}"));
        }
        LvmSeg { kind, subs, stripe_size, stripes: vec![], ..Self::linear(start_extent, extent_count, "", 0) }
    }

    /// A `mirror` (not RAID) segment of LV `lv` over `n` mimages starting at their extent 0.
    pub fn mirror(lv: &str, start_extent: u64, extent_count: u64, n: usize, log: bool) -> Self {
        LvmSeg {
            kind: "mirror",
            subs: (0..n).map(|i| format!("{lv}_mimage_{i}")).collect(),
            log: log.then(|| format!("{lv}_mlog")),
            stripes: vec![],
            ..Self::linear(start_extent, extent_count, "", 0)
        }
    }
}

/// A logical volume of the group.
#[derive(Debug, Clone)]
pub struct LvmLv {
    pub name: String,
    pub visible: bool,
    pub segments: Vec<LvmSeg>,
}

/// A PV of the group: name in the metadata (`pv0`), 32-character UUID, first extent and
/// extent count.
#[derive(Debug, Clone)]
pub struct LvmPvDef {
    pub name: String,
    pub uuid: String,
    pub pe_start_sectors: u64,
    pub pe_count: u64,
}

/// A volume group: what its metadata text describes.
#[derive(Debug, Clone)]
pub struct LvmVg {
    pub name: String,
    pub id: String,
    pub seqno: u64,
    pub extent_sectors: u64,
    pub pvs: Vec<LvmPvDef>,
    pub lvs: Vec<LvmLv>,
}

fn dashed(u: &str) -> String {
    // LVM prints UUIDs as 6-4-4-4-4-4-6.
    let mut out = String::new();
    let mut i = 0;
    for (n, len) in [6, 4, 4, 4, 4, 4, 6].iter().enumerate() {
        if n > 0 {
            out.push('-');
        }
        out.push_str(&u[i..i + len]);
        i += len;
    }
    out
}

impl LvmVg {
    /// The metadata text, as `vgcfgbackup` / the metadata area store it.
    pub fn text(&self) -> String {
        let mut t = format!(
            "{} {{\nid = \"{}\"\nseqno = {}\nformat = \"lvm2\"\nstatus = [\"RESIZEABLE\", \"READ\", \"WRITE\"]\nflags = []\nextent_size = {}\nmax_lv = 0\nmax_pv = 0\nmetadata_copies = 0\n\nphysical_volumes {{\n",
            self.name,
            dashed(&self.id),
            self.seqno,
            self.extent_sectors
        );
        for pv in &self.pvs {
            t += &format!(
                "\n{} {{\nid = \"{}\"\ndevice = \"/dev/x\"\n\nstatus = [\"ALLOCATABLE\"]\nflags = []\ndev_size = 0\npe_start = {}\npe_count = {}\n}}\n",
                pv.name,
                dashed(&pv.uuid),
                pv.pe_start_sectors,
                pv.pe_count
            );
        }
        t += "}\n\nlogical_volumes {\n";
        for lv in &self.lvs {
            let status = if lv.visible { "\"READ\", \"WRITE\", \"VISIBLE\"" } else { "\"READ\", \"WRITE\"" };
            t += &format!(
                "\n{} {{\nid = \"lvid-{}\"\nstatus = [{status}]\nflags = []\nsegment_count = {}\n",
                lv.name,
                lv.name,
                lv.segments.len()
            );
            for (i, s) in lv.segments.iter().enumerate() {
                t += &format!(
                    "\nsegment{} {{\nstart_extent = {}\nextent_count = {}\n\ntype = \"{}\"\n",
                    i + 1,
                    s.start_extent,
                    s.extent_count,
                    s.kind,
                );
                let names = |v: &[String]| v.iter().map(|n| format!("\"{n}\"")).collect::<Vec<_>>().join(", ");
                if s.kind == "mirror" {
                    t += &format!("mirror_count = {}\nregion_size = 1024\n", s.subs.len());
                    if let Some(l) = &s.log {
                        t += &format!("mirror_log = \"{l}\"\n");
                    }
                    let items: Vec<String> = s.subs.iter().map(|n| format!("\"{n}\", 0")).collect();
                    t += &format!("\nmirrors = [\n{}\n]\n}}\n", items.join(",\n"));
                    continue;
                }
                if s.kind == "raid0" {
                    t += &format!(
                        "stripe_count = {}\nstripe_size = {}\n\nraid0_lvs = [\n{}\n]\n}}\n",
                        s.subs.len(),
                        s.stripe_size,
                        names(&s.subs)
                    );
                    continue;
                }
                if s.kind.starts_with("raid") {
                    t += &format!("device_count = {}\n", s.subs.len() / 2);
                    if s.stripe_size > 0 {
                        t += &format!("stripe_size = {}\n", s.stripe_size);
                    }
                    t += "region_size = 1024\n";
                    if s.data_copies > 0 {
                        t += &format!("data_copies = {}\n", s.data_copies);
                    }
                    if s.data_offset > 0 {
                        t += &format!("data_offset = {}\n", s.data_offset);
                    }
                    t += &format!("\nraids = [\n{}\n]\n}}\n", names(&s.subs));
                    continue;
                }
                t += &format!("stripe_count = {}\n", s.stripes.len());
                if s.stripes.len() > 1 {
                    t += &format!("stripe_size = {}\n", s.stripe_size);
                }
                t += "\nstripes = [\n";
                let items: Vec<String> = s.stripes.iter().map(|(pv, pe)| format!("\"{pv}\", {pe}")).collect();
                t += &items.join(",\n");
                t += "\n]\n}\n";
            }
            t += "}\n";
        }
        t += "}\n}\n# Generated by LVM2\n\ncontents = \"Text Format Volume Group\"\nversion = 1\n\ndescription = \"\"\n\ncreation_host = \"test\"\ncreation_time = 0\n\n";
        t
    }
}

/// Write PV `uuid`'s label (sector 1) and one metadata area at 4 KiB of `mda_size` bytes
/// holding `text` into `pv` (the PV's bytes, at least 1 MiB). `wrap_at`: put the text so it
/// wraps around the end of the circular area after that many bytes.
pub fn write_lvm_pv(pv: &mut [u8], uuid: &str, text: &str, mda_size: u64, wrap_at: Option<usize>) {
    assert_eq!(uuid.len(), 32);
    let mda = 4096usize;
    // Label header (sector 1) and PV header right after it.
    let l = SECTOR;
    pv[l..l + SECTOR].fill(0);
    pv[l..l + 8].copy_from_slice(b"LABELONE");
    put_u64(pv, l + 8, 1);
    put_u32(pv, l + 20, 32);
    pv[l + 24..l + 32].copy_from_slice(b"LVM2 001");
    let ph = l + 32;
    pv[ph..ph + 32].copy_from_slice(uuid.as_bytes());
    put_u64(pv, ph + 32, pv.len() as u64);
    // Data areas: one from 1 MiB, size 0 (to the end); then the metadata area.
    put_u64(pv, ph + 40, 1 << 20);
    put_u64(pv, ph + 48, 0);
    put_u64(pv, ph + 56, 0);
    put_u64(pv, ph + 64, 0);
    put_u64(pv, ph + 72, mda as u64);
    put_u64(pv, ph + 80, mda_size);
    put_u64(pv, ph + 88, 0);
    put_u64(pv, ph + 96, 0);
    let crc = crc32_raw(LVM_CRC, &pv[l + 20..l + SECTOR]);
    put_u32(pv, l + 16, crc);
    // Metadata area: header, then the text (circular).
    let text = text.as_bytes();
    let size = mda_size as usize;
    let t_off = match wrap_at {
        Some(w) => size - w,
        None => SECTOR,
    };
    for (i, &b) in text.iter().enumerate() {
        let mut p = t_off + i;
        if p >= size {
            p = p - size + SECTOR;
        }
        pv[mda + p] = b;
    }
    let h = mda;
    pv[h..h + SECTOR].fill(0);
    pv[h + 4..h + 20].copy_from_slice(b" LVM2 x[5A%r0N*>");
    put_u32(pv, h + 20, 1);
    put_u64(pv, h + 24, mda as u64);
    put_u64(pv, h + 32, mda_size);
    put_u64(pv, h + 40, t_off as u64);
    put_u64(pv, h + 48, text.len() as u64);
    put_u32(pv, h + 56, crc32_raw(LVM_CRC, text));
    put_u32(pv, h + 60, 0);
    let crc = crc32_raw(LVM_CRC, &pv[h + 4..h + SECTOR]);
    put_u32(pv, h, crc);
}

/// An md array as its superblocks describe it.
#[derive(Debug, Clone)]
pub struct MdSpec {
    /// 0 (0.90), 10 (1.0), 11 (1.1), 12 (1.2).
    pub version: u8,
    pub uuid: [u8; 16],
    pub name: String,
    pub level: i32,
    pub layout: u32,
    /// Bytes.
    pub chunk: u64,
    pub raid_disks: u32,
    /// Bytes of each member the array uses.
    pub size: u64,
    /// Bytes (1.1 / 1.2).
    pub data_offset: u64,
    pub events: u64,
    /// A write-intent bitmap `offset` sectors from the superblock with `chunk`-byte chunks
    /// (1.x).
    pub bitmap: Option<(i32, u32)>,
}

/// Where the 1.0 superblock of a `len`-byte member goes.
pub fn md_10_offset(len: u64) -> u64 {
    (len - 8192) & !4095
}

/// Where the data starts on a member of `spec`.
pub fn md_data_offset(spec: &MdSpec) -> u64 {
    match spec.version {
        0 | 10 => 0,
        _ => spec.data_offset,
    }
}

fn md_fold(sum: u64) -> u32 {
    ((sum & 0xFFFF_FFFF) + (sum >> 32)) as u32
}

/// Write member `dev_number`'s superblock (`role`: its slot in the array, `None` a spare).
pub fn write_md_super(member: &mut [u8], spec: &MdSpec, dev_number: u32, role: Option<u32>) {
    let len = member.len() as u64;
    if spec.version == 0 {
        let off = ((len & !(65536 - 1)) - 65536) as usize;
        let sb = &mut member[off..off + 4096];
        sb.fill(0);
        let mut w = |i: usize, v: u32| put_u32(sb, i * 4, v);
        w(0, 0xA92B_4EFC);
        w(1, 0);
        w(2, 90);
        w(4, 0);
        for (k, i) in [5usize, 13, 14, 15].iter().enumerate() {
            w(*i, u32::from_le_bytes(spec.uuid[k * 4..k * 4 + 4].try_into().expect("4 bytes")));
        }
        w(7, spec.level as u32);
        w(8, (spec.size / 1024) as u32);
        w(9, spec.raid_disks);
        w(10, spec.raid_disks);
        w(11, 127);
        w(33, 1); // clean
        w(39, spec.events as u32);
        w(40, (spec.events >> 32) as u32);
        w(64, spec.layout);
        w(65, spec.chunk as u32);
        // disks[k] and this_disk: number, major, minor, raid_disk, state.
        let state = if role.is_some() { 0b110 } else { 0 };
        let rd = role.unwrap_or(spec.raid_disks + dev_number);
        for base in [128 + 32 * dev_number as usize, 992] {
            w(base, dev_number);
            w(base + 3, rd);
            w(base + 4, state);
        }
        let sum: u64 =
            (0..1024).map(|i| u64::from(u32::from_le_bytes(sb[i * 4..i * 4 + 4].try_into().expect("4")))).sum();
        put_u32(sb, 38 * 4, md_fold(sum));
        return;
    }
    let off = match spec.version {
        10 => md_10_offset(len),
        11 => 0,
        _ => 4096,
    };
    let data_offset = md_data_offset(spec);
    let data_size = if spec.version == 10 { off } else { len - data_offset };
    let max_dev = 384usize;
    let o = off as usize;
    let sb = &mut member[o..o + 4096];
    sb.fill(0);
    put_u32(sb, 0, 0xA92B_4EFC);
    put_u32(sb, 4, 1);
    put_u32(sb, 8, u32::from(spec.bitmap.is_some()));
    sb[16..32].copy_from_slice(&spec.uuid);
    sb[32..32 + spec.name.len()].copy_from_slice(spec.name.as_bytes());
    put_u32(sb, 72, spec.level as u32);
    put_u32(sb, 76, spec.layout);
    put_u64(sb, 80, spec.size / 512);
    put_u32(sb, 88, (spec.chunk / 512) as u32);
    put_u32(sb, 92, spec.raid_disks);
    if let Some((b, _)) = spec.bitmap {
        put_u32(sb, 96, b as u32);
    }
    put_u64(sb, 128, data_offset / 512);
    put_u64(sb, 136, data_size / 512);
    put_u64(sb, 144, off / 512);
    put_u32(sb, 160, dev_number);
    put_u64(sb, 200, spec.events);
    put_u64(sb, 208, u64::MAX); // in sync
    put_u32(sb, 220, max_dev as u32);
    for k in 0..max_dev {
        let r: u16 = if k == dev_number as usize {
            role.map_or(0xFFFF, |r| r as u16)
        } else if (k as u32) < spec.raid_disks {
            k as u16
        } else {
            0xFFFF
        };
        sb[256 + 2 * k..258 + 2 * k].copy_from_slice(&r.to_le_bytes());
    }
    let n = 256 + max_dev * 2;
    let sum: u64 = (0..n / 4).map(|i| u64::from(u32::from_le_bytes(sb[i * 4..i * 4 + 4].try_into().expect("4")))).sum();
    put_u32(sb, 216, md_fold(sum));
    if let Some((b, chunk)) = spec.bitmap {
        let at = (off as i64 + i64::from(b) * 512) as usize;
        let h = &mut member[at..at + 256];
        h.fill(0);
        put_u32(h, 0, 0x6D74_6962);
        put_u32(h, 4, 4);
        put_u64(h, 24, spec.events);
        put_u64(h, 40, spec.size / 512);
        put_u32(h, 52, chunk);
    }
}

/// Set the 1.x superblock's `resync_offset` (sectors; `u64::MAX`: in sync) of a member written
/// by [`write_md_super`], checksum included.
pub fn md_set_resync(member: &mut [u8], spec: &MdSpec, sectors: u64) {
    let off = match spec.version {
        10 => md_10_offset(member.len() as u64),
        11 => 0,
        _ => 4096,
    } as usize;
    let sb = &mut member[off..off + 4096];
    put_u64(sb, 208, sectors);
    put_u32(sb, 216, 0);
    let n = 256 + 384 * 2;
    let sum: u64 = (0..n / 4).map(|i| u64::from(u32::from_le_bytes(sb[i * 4..i * 4 + 4].try_into().expect("4")))).sum();
    put_u32(sb, 216, md_fold(sum));
}

/// Write `data` to the members of an md RAID 5 left-symmetric array (md's default layout):
/// row `s` puts parity on member `n - 1 - s % n` and data chunk `d` on member
/// `(parity + 1 + d) % n`, each member's chunk of row `s` at `data_offset + s * chunk`.
/// Parity is computed for every row the data reaches.
pub fn raid5_ls_write(members: &mut [Vec<u8>], data_offset: u64, chunk: u64, data: &[u8]) {
    let n = members.len() as u64;
    let c = chunk as usize;
    let rows = (data.len() as u64).div_ceil(chunk * (n - 1));
    for s in 0..rows {
        let p = (n - 1 - s % n) as usize;
        let at = (data_offset + s * chunk) as usize;
        let mut parity = vec![0u8; c];
        for d in 0..n - 1 {
            let dev = ((p as u64 + 1 + d) % n) as usize;
            let k = (s * (n - 1) + d) as usize;
            let mut chunk_bytes = vec![0u8; c];
            let from = k * c;
            if from < data.len() {
                let take = (data.len() - from).min(c);
                chunk_bytes[..take].copy_from_slice(&data[from..from + take]);
            }
            members[dev][at..at + c].copy_from_slice(&chunk_bytes);
            for (x, y) in parity.iter_mut().zip(&chunk_bytes) {
                *x ^= *y;
            }
        }
        members[p][at..at + c].copy_from_slice(&parity);
    }
}

/// Write `data` to the images of an LVM `raid6` (`raid6_zr`, md's rotating-zero-restart) array:
/// row `s` puts P on image `s % n` and Q right after it, data chunk `d` on image `d` before P
/// and `d + 2` after; when P is the last image, Q is image 0 and data starts at image 1. Q is
/// filled with 0xEE (readers never use it), P is the XOR of the row's data.
pub fn raid6_zr_write(images: &mut [Vec<u8>], data_offset: u64, chunk: u64, data: &[u8]) {
    let n = images.len() as u64;
    let c = chunk as usize;
    let rows = (data.len() as u64).div_ceil(chunk * (n - 2));
    for s in 0..rows {
        let p = s % n;
        let (q, first) = if p == n - 1 { (0, 1) } else { (p + 1, 0) };
        let at = (data_offset + s * chunk) as usize;
        let mut parity = vec![0u8; c];
        for d in 0..n - 2 {
            let dev = if p == n - 1 {
                d + first
            } else if d < p {
                d
            } else {
                d + 2
            };
            let k = (s * (n - 2) + d) as usize;
            let mut chunk_bytes = vec![0u8; c];
            let from = k * c;
            if from < data.len() {
                let take = (data.len() - from).min(c);
                chunk_bytes[..take].copy_from_slice(&data[from..from + take]);
            }
            images[dev as usize][at..at + c].copy_from_slice(&chunk_bytes);
            for (x, y) in parity.iter_mut().zip(&chunk_bytes) {
                *x ^= *y;
            }
        }
        images[p as usize][at..at + c].copy_from_slice(&parity);
        images[q as usize][at..at + c].fill(0xEE);
    }
}
