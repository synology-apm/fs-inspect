//! The drive letters of a Windows system: the `\DosDevices\X:` values of the `MountedDevices`
//! key in its SYSTEM hive.
//!
//! Each value's data names the volume the letter belongs to:
//!
//! - 12 bytes: a volume on an MBR disk, as the disk signature (`u32` LE) and the partition's
//!   byte offset on the disk (`u64` LE).
//! - `DMIO:ID:` and 16 bytes: a GUID, in the binary form GPT stores. On a GPT disk it is the
//!   partition's unique GUID; on a dynamic disk, the LDM volume's GUID.
//! - Anything else (a UTF-16 device path, such as a removable drive's `\??\USBSTOR#...`) names
//!   no volume of a disk image.

use crate::regf::Hive;
use fs_inspect_core::Result;

/// The volume a drive letter belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WinDevice {
    /// A partition of an MBR disk: the disk signature and the partition's byte offset.
    Mbr { signature: u32, offset: u64 },
    /// A GPT partition's unique GUID or an LDM volume's GUID, in the text form of
    /// `fs_inspect_core::guid::format` (upper case, no braces), as fs-inspect shows GPT GUIDs.
    Gpt(String),
    /// Any other device.
    Other,
}

impl WinDevice {
    /// Decode the data of a `MountedDevices` value.
    pub fn decode(data: &[u8]) -> WinDevice {
        if let Ok(b) = <[u8; 12]>::try_from(data) {
            let [s0, s1, s2, s3, o @ ..] = b;
            return WinDevice::Mbr { signature: u32::from_le_bytes([s0, s1, s2, s3]), offset: u64::from_le_bytes(o) };
        }
        if let Some(g) = data.strip_prefix(b"DMIO:ID:").and_then(|g| <&[u8; 16]>::try_from(g).ok()) {
            return WinDevice::Gpt(fs_inspect_core::guid::format(g));
        }
        WinDevice::Other
    }
}

const PREFIX: &str = "\\DosDevices\\";

/// The drive letters of the SYSTEM hive `hive`, upper case and sorted, each with its volume.
/// Values of other names (`\??\Volume{...}`) are left out; a hive without a `MountedDevices`
/// key has no drive letters.
pub fn drive_letters(hive: &Hive) -> Result<Vec<(char, WinDevice)>> {
    let Some(key) = hive.key("MountedDevices")? else {
        return Ok(Vec::new());
    };
    let mut out: Vec<(char, WinDevice)> = key
        .values()?
        .into_iter()
        .filter_map(|v| {
            let letter = drive_letter(&v.name)?;
            Some((letter, WinDevice::decode(&v.data)))
        })
        .collect();
    out.sort_by_key(|(l, _)| *l);
    out.dedup_by_key(|(l, _)| *l);
    Ok(out)
}

/// `X` of a value named `\DosDevices\X:` (any case).
fn drive_letter(name: &str) -> Option<char> {
    let head = name.get(..PREFIX.len())?;
    if !head.eq_ignore_ascii_case(PREFIX) {
        return None;
    }
    let mut rest = name[PREFIX.len()..].chars();
    match (rest.next(), rest.next(), rest.next()) {
        (Some(l), Some(':'), None) if l.is_ascii_alphabetic() => Some(l.to_ascii_uppercase()),
        _ => None,
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use fs_inspect_testkit::regf::{HiveBuilder, gpt_value, mbr_value};

    const GUID: &str = "8C0F1E2A-1234-4ABC-9DEF-0123456789AB";

    #[test]
    fn decodes_mbr_gpt_and_other() {
        assert_eq!(
            WinDevice::decode(&mbr_value(0xDEAD_BEEF, 1 << 20)),
            WinDevice::Mbr { signature: 0xDEAD_BEEF, offset: 1 << 20 }
        );
        let gpt = gpt_value(GUID);
        assert_eq!(gpt.len(), 24);
        assert_eq!(WinDevice::decode(&gpt), WinDevice::Gpt(GUID.to_string()));
        // The same text fs-inspect gives a GPT partition's GUID (the mixed-endian form).
        assert_eq!(&gpt[8..12], &[0x2A, 0x1E, 0x0F, 0x8C]);
        let raw: [u8; 16] = gpt[8..].try_into().unwrap();
        assert_eq!(fs_inspect_core::guid::format(&raw), GUID);
        let path: Vec<u8> = "\\??\\USBSTOR#Disk&Ven_X".encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert_eq!(WinDevice::decode(&path), WinDevice::Other);
        assert_eq!(WinDevice::decode(&gpt[..23]), WinDevice::Other);
        assert_eq!(WinDevice::decode(b"DMIO:ID:"), WinDevice::Other);
        assert_eq!(WinDevice::decode(&[]), WinDevice::Other);
    }

    #[test]
    fn gpt_text_matches_the_partition_table() {
        use fs_inspect_disk::{Scheme, scan};
        use fs_inspect_io::{BlockSource, MemSource};
        use fs_inspect_testkit::disk::{self, DiskPart, TableKind};

        let data = vec![0u8; 4096];
        let mut d = disk::disk_image(TableKind::Gpt, 512, &[DiskPart::primary(&data)]);
        // A unique GUID whose fields read differently in each byte order, in both arrays.
        let raw: [u8; 16] = core::array::from_fn(|i| 0x10 + i as u8);
        let sectors = d.image.len() / 512;
        for array in [2, sectors - 1 - 32] {
            let e = array * 512 + 16;
            d.image[e..e + 16].copy_from_slice(&raw);
        }
        disk::fix_checksums(&mut d.image);
        let none = |_: &dyn BlockSource, _: u64, _: u64| Ok(None);
        let table = scan(&MemSource::new(d.image), None, &none).unwrap();
        let Scheme::Gpt { guid, .. } = &table.partitions[0].scheme else { panic!("{table:?}") };
        let mut value = b"DMIO:ID:".to_vec();
        value.extend_from_slice(&raw);
        assert_eq!(WinDevice::decode(&value), WinDevice::Gpt(guid.clone()));
        assert_eq!(guid, "13121110-1514-1716-1819-1A1B1C1D1E1F");
    }

    #[test]
    fn letters_are_sorted_upper_case_and_volume_names_left_out() {
        let bytes = HiveBuilder::new()
            .key("MountedDevices")
            .value_binary("\\DosDevices\\E:", &gpt_value(GUID))
            .value_binary("\\??\\Volume{6a1b2c3d-0000-0000-0000-100000000000}", &mbr_value(1, 2))
            .value_binary("\\DosDevices\\C:", &mbr_value(0x1234_5678, 0x10_0000))
            .value_binary("\\dosdevices\\d:", b"\\\0?\0?\0")
            .value_binary("\\DosDevices\\AB:", &mbr_value(3, 4))
            .value_binary("\\DosDevices\\1:", &mbr_value(3, 4))
            .value_binary("\\DosDevices\\F", &mbr_value(3, 4))
            .key("Select")
            .value_dword("Current", 1)
            .build();
        let hive = Hive::open(&bytes).unwrap();
        assert_eq!(
            drive_letters(&hive).unwrap(),
            vec![
                ('C', WinDevice::Mbr { signature: 0x1234_5678, offset: 0x10_0000 }),
                ('D', WinDevice::Other),
                ('E', WinDevice::Gpt(GUID.to_string())),
            ]
        );
    }

    #[test]
    fn a_letter_written_twice_is_kept_once() {
        let bytes = HiveBuilder::new()
            .key("MountedDevices")
            .value_binary("\\DosDevices\\c:", &mbr_value(1, 0))
            .value_binary("\\DosDevices\\C:", &mbr_value(2, 0))
            .build();
        let letters = drive_letters(&Hive::open(&bytes).unwrap()).unwrap();
        assert_eq!(letters, vec![('C', WinDevice::Mbr { signature: 1, offset: 0 })]);
    }

    #[test]
    fn no_mounted_devices_key_means_no_letters() {
        let bytes = HiveBuilder::new().key("Select").value_dword("Current", 1).build();
        assert!(drive_letters(&Hive::open(&bytes).unwrap()).unwrap().is_empty());
        let empty = HiveBuilder::new().key("MountedDevices").build();
        assert!(drive_letters(&Hive::open(&empty).unwrap()).unwrap().is_empty());
    }
}
