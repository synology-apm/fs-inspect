//! Default exclusions: the files of an operating system a backup never needs (paging and swap
//! files, hibernation images that nothing will resume from), as each file system driver lists
//! them through [`Filesystem::default_excludes`](crate::Filesystem::default_excludes): the
//! lists several drivers share (Windows, Linux) and the header checks they use. A list of one
//! driver's own (btrfs, APFS) is in that driver.

/// A file a driver leaves out of a backup by default.
#[derive(Debug, Clone, Copy)]
pub struct DefaultExclude {
    /// Absolute path in the volume, `/` separated. `*` and `?` in the last component are
    /// wildcards (only where patterns are supported; skipped otherwise).
    pub path: &'static str,
    /// What to leave out, decided from the file's first bytes; `None`: the whole file.
    pub check: Option<HeadCheck>,
}

/// Decides from up to `head_len` bytes of a file's start how much of it to leave out.
#[derive(Debug, Clone, Copy)]
pub struct HeadCheck {
    pub head_len: usize,
    pub verdict: fn(&[u8]) -> Verdict,
}

/// How much of a file to leave out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Nothing: the whole file is kept (it is not what the default is about).
    Keep,
    /// Nothing: the file holds a hibernated system the next boot resumes from.
    Hibernated,
    /// The whole file.
    Exclude,
    /// Everything from this logical offset on; the bytes before it are kept.
    ExcludeFrom(u64),
}

impl DefaultExclude {
    /// The whole file at `path`.
    pub const fn whole(path: &'static str) -> DefaultExclude {
        DefaultExclude { path, check: None }
    }

    /// The file at `path`, as much as `verdict` decides from its first `head_len` bytes.
    pub const fn checked(path: &'static str, head_len: usize, verdict: fn(&[u8]) -> Verdict) -> DefaultExclude {
        DefaultExclude { path, check: Some(HeadCheck { head_len, verdict }) }
    }
}

/// Files of a Windows system volume (NTFS, FAT, exFAT, ReFS): the paging files, the hibernation
/// file and the boot-time crash dump log. Windows recreates the paging files at boot; a
/// hibernation file without a valid signature is ignored.
pub const WINDOWS_DEFAULTS: &[DefaultExclude] = &[
    DefaultExclude::whole("/pagefile.sys"),
    DefaultExclude::checked("/hiberfil.sys", 4, hiberfil),
    DefaultExclude::whole("/swapfile.sys"),
    DefaultExclude::whole("/DumpStack.log.tmp"),
];

/// Swap files of a Linux root file system (ext2/3/4, XFS), where distributions and guides put
/// them: `/swapfile` (most), `/swap.img` (the Ubuntu server installer), `/var/swap` (Debian's
/// dphys-swapfile, Raspberry Pi OS), `/swap/swapfile` (the Arch wiki), `/var/swap/swapfile`
/// (Fedora's `btrfs filesystem mkswapfile` convention). Only a file with a swap signature is
/// left out, and its header page kept: Linux does not recreate it, `swapon` needs it.
pub const LINUX_DEFAULTS: &[DefaultExclude] = &[
    DefaultExclude::checked("/swapfile", SWAP_HEAD, swap_file),
    DefaultExclude::checked("/swap.img", SWAP_HEAD, swap_file),
    DefaultExclude::checked("/var/swap", SWAP_HEAD, swap_file),
    DefaultExclude::checked("/swap/swapfile", SWAP_HEAD, swap_file),
    DefaultExclude::checked("/var/swap/swapfile", SWAP_HEAD, swap_file),
];

/// Whether a hiberfil.sys header says the system is hibernated and the next boot resumes from
/// it (hibernation or a Fast Startup shutdown): `HIBR` (`RSTR` while resuming); after a resume
/// Windows writes `WAKE` or zeros.
pub fn hibernated(head: &[u8]) -> bool {
    head.len() == 4 && (head.eq_ignore_ascii_case(b"hibr") || head.eq_ignore_ascii_case(b"rstr"))
}

/// hiberfil.sys: kept while it holds a hibernated system (excluding it would make the resume
/// fail), else left out.
pub fn hiberfil(head: &[u8]) -> Verdict {
    if hibernated(head) { Verdict::Hibernated } else { Verdict::Exclude }
}

/// Page sizes swap headers are written for (the signature ends the first page).
pub const SWAP_PAGE_SIZES: [usize; 4] = [4096, 8192, 16384, 65536];
/// Bytes a swap header check reads: the largest page.
pub const SWAP_HEAD: usize = 65536;
/// Version 1 (the header after the boot block: version, last page, UUID, label) and the old
/// version 0 (the rest of the page is a bitmap of usable pages).
const SWAP: [&[u8; 10]; 2] = [b"SWAPSPACE2", b"SWAP-SPACE"];
/// Signatures the hibernation code writes in place of the swap signature.
const HIBERNATED: [&[u8]; 4] = [b"S1SUSPEND", b"S2SUSPEND", b"ULSUSPEND", b"LINHIB0001"];

/// What a Linux swap header says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwapKind {
    Swap,
    /// The hibernation code replaced the swap signature: the next boot resumes from it.
    Hibernated,
}

/// The page size and kind of the Linux swap area starting at `head`.
pub fn swap_signature(head: &[u8]) -> Option<(usize, SwapKind)> {
    for page in SWAP_PAGE_SIZES {
        let Some(sig) = head.get(page - 10..page) else { break };
        if SWAP.iter().any(|s| sig == &s[..]) {
            return Some((page, SwapKind::Swap));
        }
        if HIBERNATED.iter().any(|s| sig.starts_with(s)) {
            return Some((page, SwapKind::Hibernated));
        }
    }
    None
}

/// A Linux swap file: all but its header page left out; kept whole while it holds a hibernation
/// image, or when it is no swap file at all.
pub fn swap_file(head: &[u8]) -> Verdict {
    match swap_signature(head) {
        Some((page, SwapKind::Swap)) => Verdict::ExcludeFrom(page as u64),
        Some((_, SwapKind::Hibernated)) => Verdict::Hibernated,
        None => Verdict::Keep,
    }
}

/// Whether `path` names files by pattern (`*` or `?`).
pub fn is_pattern(path: &str) -> bool {
    path.contains(['*', '?'])
}

/// Whether `name` (one path component) matches `pattern`: `*` any run of characters, `?` one
/// character, anything else itself (without case when `fold`).
pub fn glob_match(pattern: &str, name: &str, fold: bool) -> bool {
    let norm = |s: &str| -> Vec<char> {
        if fold { s.chars().flat_map(char::to_lowercase).collect() } else { s.chars().collect() }
    };
    let (p, n) = (norm(pattern), norm(name));
    // Iterative matching with backtracking to the last `*`.
    let (mut pi, mut ni) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while ni < n.len() {
        match p.get(pi) {
            Some('*') => {
                star = Some((pi, ni));
                pi += 1;
            }
            Some(&c) if c == '?' || c == n[ni] => {
                pi += 1;
                ni += 1;
            }
            _ => match star {
                Some((sp, sn)) => {
                    pi = sp + 1;
                    ni = sn + 1;
                    star = Some((sp, sn + 1));
                }
                None => return false,
            },
        }
    }
    p[pi..].iter().all(|&c| c == '*')
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn swap_area(page: usize, sig: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; SWAP_HEAD];
        b[page - 10..page - 10 + sig.len()].copy_from_slice(sig);
        b
    }

    #[test]
    fn hiberfil_kept_while_hibernated() {
        assert_eq!(hiberfil(b"HIBR"), Verdict::Hibernated);
        assert_eq!(hiberfil(b"rstr"), Verdict::Hibernated);
        assert_eq!(hiberfil(b"WAKE"), Verdict::Exclude);
        assert_eq!(hiberfil(&[0; 4]), Verdict::Exclude);
        assert_eq!(hiberfil(b"HI"), Verdict::Exclude);
    }

    /// A swap file keeps its header page whatever the page size; a hibernation image or a file
    /// without the signature is kept whole.
    #[test]
    fn swap_file_keeps_its_header() {
        for page in SWAP_PAGE_SIZES {
            assert_eq!(swap_file(&swap_area(page, b"SWAPSPACE2")), Verdict::ExcludeFrom(page as u64), "page {page}");
            assert_eq!(swap_file(&swap_area(page, b"S1SUSPEND")), Verdict::Hibernated, "page {page}");
        }
        assert_eq!(swap_file(&swap_area(4096, b"SWAP-SPACE")), Verdict::ExcludeFrom(4096));
        assert_eq!(swap_file(&swap_area(4096, b"LINHIB0001")), Verdict::Hibernated);
        assert_eq!(swap_file(&[0; SWAP_HEAD]), Verdict::Keep);
        // A file shorter than a page has no signature.
        assert_eq!(swap_file(b"SWAPSPACE2"), Verdict::Keep);
    }

    #[test]
    fn default_lists_are_absolute() {
        for d in WINDOWS_DEFAULTS.iter().chain(LINUX_DEFAULTS) {
            assert!(d.path.starts_with('/'), "{}", d.path);
        }
        assert!(is_pattern("/swapfile*") && !is_pattern("/swapfile"));
    }

    #[test]
    fn glob() {
        assert!(glob_match("swapfile*", "swapfile", false));
        assert!(glob_match("swapfile*", "swapfile12", false));
        assert!(!glob_match("swapfile*", "swap", false));
        assert!(glob_match("*.sig", ".sig", false));
        assert!(!glob_match("*.sig", ".sig.tmp", false));
        assert!(glob_match("a?c", "abc", false) && !glob_match("a?c", "ac", false));
        assert!(glob_match("*a*b*", "xxaYYbzz", false));
        assert!(glob_match("*", "", false) && !glob_match("?", "", false));
        assert!(!glob_match("PAGEFILE.*", "pagefile.sys", false));
        assert!(glob_match("PAGEFILE.*", "pagefile.sys", true));
        assert!(glob_match("Ä*", "äbc", true));
    }
}
