//! Facts about Windows that several file system crates share (NTFS, FAT, exFAT, ReFS).

pub mod reparse;
pub mod usn;

/// Root-directory files Windows writes with paging I/O (the memory manager, the boot loader):
/// their writes update no time stamp, journal record or `$SI.Usn`. Compared without case.
pub const PAGING_IO_FILES: &[&str] = &["pagefile.sys", "hiberfil.sys", "swapfile.sys"];

/// Whether `name` (of a root-directory file) is one of the [`PAGING_IO_FILES`].
pub fn is_paging_io_file(name: &str) -> bool {
    PAGING_IO_FILES.iter().any(|p| p.eq_ignore_ascii_case(name))
}

/// `FILE_ATTRIBUTE_*` bits that say how a stream's data is stored or read (a change may move
/// or rewrite it); the others (read-only, hidden, archive, ...) change without touching it.
pub const DATA_FILE_ATTRS: u32 = 0x0000_0200 // SPARSE_FILE
    | 0x0000_0400 // REPARSE_POINT
    | 0x0000_0800 // COMPRESSED
    | 0x0000_1000 // OFFLINE
    | 0x0000_4000 // ENCRYPTED
    | 0x0000_8000 // INTEGRITY_STREAM
    | 0x0004_0000 // RECALL_ON_OPEN
    | 0x0008_0000 // PINNED
    | 0x0010_0000 // UNPINNED
    | 0x0040_0000; // RECALL_ON_DATA_ACCESS

/// Position of a USN change journal (NTFS, ReFS) on a live volume, read just before the
/// snapshot was requested (`FSCTL_QUERY_USN_JOURNAL`: `UsnJournalID`, `NextUsn`). It covers
/// writes whose journal records (and USN stamps) reached the snapshot before their data did:
/// NTFS reads the records written after this point again next time; ReFS copies the files
/// stamped after it again next time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UsnPosition {
    /// The journal the position belongs to (`None`: not known; then a journal deleted and
    /// created anew in between cannot be told apart).
    pub journal_id: Option<u64>,
    pub next_usn: i64,
}

/// FILETIME (100 ns units since 1601) of the unix epoch.
const FILETIME_UNIX_EPOCH: u64 = 116_444_736_000_000_000;
/// FILETIME units per second.
const FILETIME_SECOND: u64 = 10_000_000;

/// The FILETIME of unix time `secs` (saturating).
pub const fn filetime_of_unix(secs: u64) -> u64 {
    secs.saturating_mul(FILETIME_SECOND).saturating_add(FILETIME_UNIX_EPOCH)
}

/// The unix time of FILETIME `ft`, in whole seconds (0 before 1970).
pub const fn unix_of_filetime(ft: u64) -> u64 {
    ft.saturating_sub(FILETIME_UNIX_EPOCH) / FILETIME_SECOND
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn filetime_round_trips() {
        assert_eq!(filetime_of_unix(0), 116_444_736_000_000_000);
        assert_eq!(unix_of_filetime(filetime_of_unix(1_700_000_000)), 1_700_000_000);
        assert_eq!(unix_of_filetime(0), 0);
        assert!(is_paging_io_file("PageFile.SYS") && !is_paging_io_file("pagefile.sys.bak"));
    }
}
