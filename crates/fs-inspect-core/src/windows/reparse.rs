//! Windows reparse points (NTFS `$REPARSE_POINT`, the ReFS reparse attribute): the tag and data
//! of a file's, what they make of it.
//!
//! A reparse buffer holds `ReparseTag u32`, `ReparseDataLength u16`, 2 reserved bytes, then (for
//! a tag without the Microsoft bit) a 16-byte GUID, then the data. What fs-inspect reads of
//! the data:
//!
//! - Symbolic links (`IO_REPARSE_TAG_SYMLINK`) and junctions (`IO_REPARSE_TAG_MOUNT_POINT`):
//!   `SubstituteNameOffset`, `SubstituteNameLength`, `PrintNameOffset`, `PrintNameLength`
//!   (u16 each, bytes into the path buffer), a symbolic link's `Flags` u32 (1: relative), the
//!   UTF-16 path buffer.
//! - WSL symbolic links (`IO_REPARSE_TAG_LX_SYMLINK`): a version u32 (2), the UTF-8 target.
//! - WOF (`IO_REPARSE_TAG_WOF`): the NTFS driver's.
//! - Cloud Files (`IO_REPARSE_TAG_CLOUD`, `_CLOUD_1` to `_F`: the tag with bits 12..15 free):
//!   the provider's own data, kept as it is.

use crate::bytes::{slice, u16_at, u32_at, utf16_at};
use crate::{LinkTarget, Name, NodeKind, Result};

pub const SYMLINK: u32 = 0xA000_000C;
pub const MOUNT_POINT: u32 = 0xA000_0003;
pub const LX_SYMLINK: u32 = 0xA000_001D;
pub const AF_UNIX: u32 = 0x8000_0023;
pub const LX_FIFO: u32 = 0x8000_0024;
pub const LX_CHR: u32 = 0x8000_0025;
pub const LX_BLK: u32 = 0x8000_0026;
pub const WOF: u32 = 0x8000_0017;
pub const DEDUP: u32 = 0x8000_0013;
/// `IO_REPARSE_TAG_CLOUD`; `_CLOUD_1` to `_F` set bits 12..15.
pub const CLOUD: u32 = 0x9000_001A;
const CLOUD_MASK: u32 = 0xFFFF_0FFF;

/// Whether `tag` is a Cloud Files tag.
pub fn is_cloud(tag: u32) -> bool {
    tag & CLOUD_MASK == CLOUD
}

/// A file's reparse point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reparse {
    pub tag: u32,
    /// The data after the header (and GUID).
    pub data: Vec<u8>,
}

impl Reparse {
    /// The reparse point in reparse buffer `b`.
    pub fn parse(b: &[u8]) -> Result<Reparse> {
        let tag = u32_at(b, 0)?;
        let len = usize::from(u16_at(b, 4)?);
        let start = if tag & 0x8000_0000 == 0 { 24 } else { 8 };
        Ok(Reparse { tag, data: slice(b, start, len.saturating_sub(start - 8))?.to_vec() })
    }

    /// Where a link points: symbolic links, junctions and WSL links; `None` for other tags.
    pub fn link(&self) -> Result<Option<LinkTarget>> {
        let d = &self.data;
        Ok(Some(match self.tag {
            SYMLINK | MOUNT_POINT => {
                let field = |i: usize| -> Result<usize> { Ok(usize::from(u16_at(d, 2 * i)?)) };
                let (so, sl, po, pl) = (field(0)?, field(1)?, field(2)?, field(3)?);
                let (buf, relative) = if self.tag == SYMLINK { (12, u32_at(d, 8)? & 1 != 0) } else { (8, false) };
                let name = |o: usize, l: usize| -> Result<Name> { Ok(Name::Utf16(utf16_at(d, buf + o, l / 2)?)) };
                let target = name(so, sl)?;
                let print = Some(name(po, pl)?).filter(|n| !matches!(n, Name::Utf16(u) if u.is_empty()));
                if self.tag == SYMLINK {
                    LinkTarget::WindowsSymlink { target, print, relative }
                } else {
                    LinkTarget::Junction { target, print }
                }
            }
            LX_SYMLINK => LinkTarget::Symlink(Name::Bytes(slice(d, 4, d.len().saturating_sub(4))?.to_vec())),
            _ => return Ok(None),
        }))
    }
}

/// The node kind of a reparse point of `tag` on a file or directory (`dir`): symbolic links
/// and junctions are links, the WSL special files their kinds, WOF, Cloud Files and
/// deduplicated files keep their own kind (their data is the file's), any other tag is
/// [`NodeKind::Reparse`].
pub fn kind_of_tag(tag: u32, dir: bool) -> NodeKind {
    match tag {
        SYMLINK | MOUNT_POINT | LX_SYMLINK => NodeKind::Symlink,
        AF_UNIX => NodeKind::Socket,
        LX_FIFO => NodeKind::Fifo,
        LX_CHR => NodeKind::CharDev,
        LX_BLK => NodeKind::BlockDev,
        t if t == WOF || t == DEDUP || is_cloud(t) => {
            if dir {
                NodeKind::Dir
            } else {
                NodeKind::File
            }
        }
        _ => NodeKind::Reparse,
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    fn link(tag: u32, subst: &str, print: &str, flags: Option<u32>) -> Vec<u8> {
        let (s, p) = (utf16(subst), utf16(print));
        let mut d = Vec::new();
        for v in [0, s.len(), s.len(), p.len()] {
            d.extend_from_slice(&(v as u16).to_le_bytes());
        }
        if let Some(f) = flags {
            d.extend_from_slice(&f.to_le_bytes());
        }
        d.extend_from_slice(&s);
        d.extend_from_slice(&p);
        let mut b = tag.to_le_bytes().to_vec();
        b.extend_from_slice(&(d.len() as u16).to_le_bytes());
        b.extend_from_slice(&[0, 0]);
        b.extend_from_slice(&d);
        b
    }

    #[test]
    fn links_parse() {
        let r = Reparse::parse(&link(SYMLINK, "a.txt", "a.txt", Some(1))).unwrap();
        let Some(LinkTarget::WindowsSymlink { target, print, relative }) = r.link().unwrap() else { panic!() };
        assert!(target.eq_str("a.txt") && print.unwrap().eq_str("a.txt") && relative);
        let r = Reparse::parse(&link(MOUNT_POINT, "\\??\\C:\\d", "C:\\d", None)).unwrap();
        let Some(LinkTarget::Junction { target, print }) = r.link().unwrap() else { panic!() };
        assert!(target.eq_str("\\??\\C:\\d") && print.unwrap().eq_str("C:\\d"));
        assert_eq!(kind_of_tag(SYMLINK, true), NodeKind::Symlink);
        assert_eq!(kind_of_tag(0x9000_601A, false), NodeKind::File);
        assert_eq!(kind_of_tag(0x8000_001B, false), NodeKind::Reparse);
    }
}
