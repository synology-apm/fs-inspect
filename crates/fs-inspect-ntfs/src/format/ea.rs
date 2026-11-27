//! Extended attributes (`$EA`): a list of `FILE_FULL_EA_INFORMATION` entries,
//! `NextEntryOffset u32` (0 for the last), `Flags u8`, `EaNameLength u8`, `EaValueLength u16`,
//! the name (ASCII, upper-cased by NTFS) and a NUL, the value. WSL keeps a file's Unix
//! metadata in `$LXUID`, `$LXGID`, `$LXMOD` (u32 each) and `$LXDEV` (major and minor u32).

use fs_inspect_core::UnixModeExt;
use fs_inspect_core::bytes::{slice, u16_at, u32_at};
use fs_inspect_core::{Result, UnixMode};

/// One extended attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ea {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

/// The extended attributes in the bytes of a `$EA` attribute.
pub fn parse(b: &[u8]) -> Result<Vec<Ea>> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while at + 8 <= b.len() {
        let next = u32_at(b, at)? as usize;
        let name_len = usize::from(b[at + 5]);
        let value_len = usize::from(u16_at(b, at + 6)?);
        let name = slice(b, at + 8, name_len)?.to_vec();
        let value = slice(b, at + 8 + name_len + 1, value_len)?.to_vec();
        out.push(Ea { name, value });
        if next == 0 {
            break;
        }
        at += next;
    }
    Ok(out)
}

/// The Unix metadata WSL keeps in `eas`, when it keeps a mode.
pub fn wsl_unix(eas: &[Ea]) -> Option<UnixMode> {
    let u32_of = |n: &[u8]| {
        eas.iter()
            .find(|e| e.name == n)
            .and_then(|e| e.value.get(..4))
            .map(|v| u32::from_le_bytes([v[0], v[1], v[2], v[3]]))
    };
    let mode = u32_of(b"$LXMOD")?;
    let rdev = eas.iter().find(|e| e.name == b"$LXDEV").and_then(|e| {
        let v = e.value.get(..8)?;
        let (major, minor) =
            (u32::from_le_bytes([v[0], v[1], v[2], v[3]]), u32::from_le_bytes([v[4], v[5], v[6], v[7]]));
        Some((u64::from(major) << 32) | u64::from(minor))
    });
    Some(UnixMode::new(mode, u32_of(b"$LXUID").unwrap_or(0), u32_of(b"$LXGID").unwrap_or(0), rdev))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn entry(name: &[u8], value: &[u8], last: bool) -> Vec<u8> {
        let mut e = vec![0u8; 8];
        e[5] = name.len() as u8;
        e[6..8].copy_from_slice(&(value.len() as u16).to_le_bytes());
        e.extend_from_slice(name);
        e.push(0);
        e.extend_from_slice(value);
        if !last {
            e.resize(e.len().next_multiple_of(4), 0);
            let n = e.len() as u32;
            e[..4].copy_from_slice(&n.to_le_bytes());
        }
        e
    }

    #[test]
    fn entries_and_wsl_metadata() {
        let b = [
            entry(b"$LXUID", &1000u32.to_le_bytes(), false),
            entry(b"$LXMOD", &0o100644u32.to_le_bytes(), false),
            entry(b"USER.X", b"abc", true),
        ]
        .concat();
        let eas = parse(&b).unwrap();
        assert_eq!(eas.len(), 3);
        assert_eq!(eas[2], Ea { name: b"USER.X".to_vec(), value: b"abc".to_vec() });
        let u = wsl_unix(&eas).unwrap();
        assert_eq!((u.mode, u.uid, u.gid, u.rdev), (0o100644, 1000, 0, None));
        assert!(parse(&b[..30]).is_err());
    }
}
