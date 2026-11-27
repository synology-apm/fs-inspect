//! `PartitionInfo::partition_type`: the well-known partition types, from GPT type GUIDs (any case)
//! and MBR type bytes.

#![allow(clippy::unwrap_used)] // test code

use super::{PartitionEntry, PartitionInfo, PartitionType};
use fs_inspect_core::Named;

fn gpt(type_guid: &str) -> PartitionType {
    PartitionInfo {
        number: 1,
        entry: PartitionEntry::Gpt {
            type_guid: type_guid.into(),
            guid: "00000000-0000-0000-0000-000000000001".into(),
            name: None,
        },
    }
    .partition_type()
}

fn mbr(type_byte: u8) -> PartitionType {
    PartitionInfo { number: 1, entry: PartitionEntry::Mbr { type_byte, logical: false } }.partition_type()
}

#[test]
fn gpt_types_are_known_by_their_guid_in_any_case() {
    for (guid, kind) in [
        ("C12A7328-F81F-11D2-BA4B-00A0C93EC93B", PartitionType::EfiSystem),
        ("e3c9e316-0b5c-4db8-817d-f92df00215ae", PartitionType::MicrosoftReserved),
        ("EBD0A0A2-B9E5-4433-87C0-68B6B72699C7", PartitionType::MicrosoftBasicData),
        ("de94bba4-06d1-4d40-a16a-bfd50179d6ac", PartitionType::WindowsRecovery),
        ("5808C8AA-7E8F-42E0-85D2-E1E90434CFB3", PartitionType::LdmMetadata),
        ("AF9B60A0-1431-4F62-BC68-3311714A69AD", PartitionType::LdmData),
        ("0FC63DAF-8483-4772-8E79-3D69D8477DE4", PartitionType::LinuxFs),
        ("4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709", PartitionType::LinuxFs),
        ("933AC7E1-2EB4-4F13-B844-0E14E2AEF915", PartitionType::LinuxFs),
        ("0657FD6D-A4AB-43C4-84E5-0933C84B4F4F", PartitionType::LinuxSwap),
        ("E6D6D379-F507-44C2-A23C-238F2A3DF928", PartitionType::LinuxLvm),
        ("A19D880F-05FC-4D3B-A006-743F0F84911E", PartitionType::LinuxRaid),
        ("BC13C2FF-59E6-4262-A352-B275FD6F7172", PartitionType::LinuxBoot),
        ("7C3457EF-0000-11AA-AA11-00306543ECAC", PartitionType::AppleApfs),
        ("48465300-0000-11AA-AA11-00306543ECAC", PartitionType::Other),
        ("", PartitionType::Other),
    ] {
        assert_eq!(gpt(guid), kind, "{guid}");
    }
}

#[test]
fn mbr_types_are_known_by_their_byte() {
    for (byte, kind) in [
        (0x07, PartitionType::MicrosoftBasicData),
        (0x0B, PartitionType::MicrosoftBasicData),
        (0x0C, PartitionType::MicrosoftBasicData),
        (0x0E, PartitionType::MicrosoftBasicData),
        (0x27, PartitionType::WindowsRecovery),
        (0x42, PartitionType::LdmData),
        (0x82, PartitionType::LinuxSwap),
        (0x83, PartitionType::LinuxFs),
        (0x8E, PartitionType::LinuxLvm),
        (0xEA, PartitionType::LinuxBoot),
        (0xEF, PartitionType::EfiSystem),
        (0xFD, PartitionType::LinuxRaid),
        (0x05, PartitionType::Other),
        (0x00, PartitionType::Other),
    ] {
        assert_eq!(mbr(byte), kind, "{byte:#04x}");
    }
}

#[test]
fn every_type_has_its_stable_name() {
    let names: Vec<String> = PartitionType::ALL.iter().map(ToString::to_string).collect();
    assert_eq!(
        names,
        [
            "efi_system",
            "microsoft_reserved",
            "microsoft_basic_data",
            "windows_recovery",
            "ldm_metadata",
            "ldm_data",
            "linux_fs",
            "linux_swap",
            "linux_lvm",
            "linux_raid",
            "linux_boot",
            "apple_apfs",
            "other"
        ]
    );
}

#[test]
fn every_type_is_found_by_its_stable_name() {
    for &kind in PartitionType::ALL {
        assert_eq!(PartitionType::from_name(kind.as_str()), Some(kind), "{kind}");
    }
    assert_eq!(PartitionType::from_name("ntfs"), None);
    assert_eq!(serde_json::to_string(&PartitionType::LdmData).unwrap(), r#""ldm_data""#);
    assert_eq!(serde_json::from_str::<PartitionType>(r#""linux_fs""#).unwrap(), PartitionType::LinuxFs);
    let err = serde_json::from_str::<PartitionType>(r#""ntfs""#).unwrap_err().to_string();
    assert!(err.contains(r#"unknown partition type "ntfs""#), "{err}");
}
