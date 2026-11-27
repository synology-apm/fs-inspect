//! The files of macOS an APFS backup leaves out by default.

use fs_inspect_core::{DefaultExclude, Verdict};

/// macOS's virtual memory files: at the root of the VM volume (macOS 10.15 on), or in
/// `/private/var/vm` of a single-volume system. `dynamic_pager` recreates the swap files; the
/// sleep image is kept while it holds a hibernated system.
pub(crate) const DEFAULT_EXCLUDES: &[DefaultExclude] = &[
    DefaultExclude::checked("/sleepimage", SLEEPIMAGE_HEAD, sleepimage),
    DefaultExclude::whole("/swapfile*"),
    DefaultExclude::checked("/private/var/vm/sleepimage", SLEEPIMAGE_HEAD, sleepimage),
    DefaultExclude::whole("/private/var/vm/swapfile*"),
];

/// Bytes a sleep image check reads: up to the header's `signature` field.
const SLEEPIMAGE_HEAD: usize = 92;
/// Offset of `signature` in xnu's `IOHibernateImageHeader` (little-endian `u32`).
const SLEEPIMAGE_SIGNATURE: usize = 88;
/// `kIOHibernateHeaderSignature`: a complete image the booter resumes from.
const SLEEPIMAGE_VALID: u32 = 0x7369_6d65;
/// `kIOHibernateHeaderOpenSignature`: an image being written.
const SLEEPIMAGE_OPEN: u32 = 0xf1e0_be9d;
/// `kIOHibernateHeaderInvalidSignature`: written once the system woke.
const SLEEPIMAGE_INVALID: u32 = 0x7a7a_7a7a;

/// macOS's sleep image: left out after a wake (invalid signature) or when never written (zeros);
/// kept while it holds a hibernated system and whenever its header cannot be told apart.
fn sleepimage(head: &[u8]) -> Verdict {
    let Some(b) = head.get(SLEEPIMAGE_SIGNATURE..SLEEPIMAGE_SIGNATURE + 4) else {
        return if head.iter().all(|&b| b == 0) { Verdict::Exclude } else { Verdict::Keep };
    };
    match u32::from_le_bytes([b[0], b[1], b[2], b[3]]) {
        SLEEPIMAGE_VALID | SLEEPIMAGE_OPEN => Verdict::Hibernated,
        SLEEPIMAGE_INVALID => Verdict::Exclude,
        0 if head.iter().all(|&b| b == 0) => Verdict::Exclude,
        _ => Verdict::Keep,
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn sleepimage_by_signature() {
        let image = |sig: u32| {
            let mut b = vec![0x11u8; SLEEPIMAGE_HEAD];
            b[SLEEPIMAGE_SIGNATURE..SLEEPIMAGE_SIGNATURE + 4].copy_from_slice(&sig.to_le_bytes());
            b
        };
        assert_eq!(sleepimage(&image(SLEEPIMAGE_VALID)), Verdict::Hibernated);
        assert_eq!(sleepimage(&image(SLEEPIMAGE_OPEN)), Verdict::Hibernated);
        assert_eq!(sleepimage(&image(SLEEPIMAGE_INVALID)), Verdict::Exclude);
        assert_eq!(sleepimage(&image(0x1234_5678)), Verdict::Keep);
        assert_eq!(sleepimage(&[0; SLEEPIMAGE_HEAD]), Verdict::Exclude);
        assert_eq!(sleepimage(&[]), Verdict::Exclude);
        assert_eq!(sleepimage(&[1, 2]), Verdict::Keep);
    }

    #[test]
    fn paths_are_absolute() {
        assert!(DEFAULT_EXCLUDES.iter().all(|d| d.path.starts_with('/')));
    }
}
