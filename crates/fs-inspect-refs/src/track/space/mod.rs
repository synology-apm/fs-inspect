//! Dating the used space outside the files' data, from metadata only:
//!
//! - **node pages** ([`pages`]): every reference to a page carries the page's CRC, so a page
//!   read and checked against its reference is identified by where it is and that CRC. The
//!   pages read (every table the checkpoint and the Object ID table list, every directory, file
//!   record and extent table) are grouped in [`pages::PAGE_CHUNK`]s of the volume; a chunk whose
//!   pages are the same as in the previous snapshot (same places, same CRCs: one digest per
//!   chunk in the signature) holds unchanged pages.
//! - **the log** (MLog, [`log`]): 4 KiB pages written one after the other around a fixed area,
//!   each stamped with its log sequence number (its page in the low 32 bits; the high ones go
//!   up at every mount, so only the page counts). Pages written since the previous snapshot lie
//!   between the previous last page and the current one; the others did not change.
//! - **the change journal** ([`journal`], the stream as [`crate::track::journal`] reads it):
//!   only the clusters from the one that held the previous last record to the current last one
//!   changed, with [`journal::JOURNAL_SLACK`] on either side for pages flushed out of order;
//!   the others, mapped the same, did not.
//!
//! Both rest on the volume going on from the previous snapshot. A snapshot written to after it
//! was taken (VSS mounts one for its writers' recovery: ReFS then writes its tables, and may
//! log and journal, in that snapshot only) and the live volume after it are two branches, with
//! the same sequence numbers at the same places for different content. So each keeps its end
//! by content and the next scan checks it first: the log the digests of its last pages
//! ([`LogMark::recent`]: the first one with other content now is where the two went apart),
//! the journal its last record ([`Tail`]); not there, that structure is wholly dirty
//! ([`Kept::Diverged`]).
//! Node pages, compared by their CRCs, need no such check. The journal's end is the live one at
//! the snapshot when the caller read it ([`JournalState::locate`]): records the snapshot alone
//! added are then not part of the history the next scan goes on from.

mod journal;
mod log;
mod pages;

pub use journal::unchanged_journal;
pub use log::{LogMark, unchanged_log};
pub use pages::{page_digests, unchanged_pages};

use crate::RefsFs;
use crate::format::LogInfo;
use crate::format::tree::SeenPage;
#[cfg(doc)]
use crate::track::journal::JournalState;
#[cfg(doc)]
use fs_inspect_change::tail::Tail;
use fs_inspect_core::ByteRange;
use fs_inspect_core::range::list;

/// What a structure dated as append-only kept since the previous snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kept {
    /// These ranges did not change (none: all of it may have).
    Ranges(Vec<ByteRange>),
    /// Its previous tail is not there: it is on another branch, all of it may have changed.
    Diverged,
}

/// The clusters at the start of the volume Windows allocates: the boot sector, the superblock
/// (30), and reserved ones after it (zero on every volume seen).
const RESERVED_CLUSTERS: u64 = 36;

/// The regions compared by content, at places the boot sector, the superblock and the log
/// information give, rewritten at every checkpoint or log flush, small:
///
/// - the first [`RESERVED_CLUSTERS`] clusters, and the last four of the volume (superblock
///   copies, the boot sector copy);
/// - the checkpoints (a page each);
/// - the log control pages, to the end of their page (the clusters of node pages read there,
///   in `seen`, excepted: those are dated with the others).
pub fn fixed(fs: &RefsFs, volume_bytes: u64, log: Option<&LogInfo>, seen: &[SeenPage]) -> Vec<ByteRange> {
    let cluster = u64::from(fs.reader().cluster_bytes());
    let page = fs.reader().page_clusters() as u64;
    let clusters = volume_bytes / cluster;
    let mut v = vec![ByteRange::new(0, RESERVED_CLUSTERS.min(clusters) * cluster)];
    if clusters > 4 {
        v.push(ByteRange::new((clusters - 4) * cluster, volume_bytes - (clusters - 4) * cluster));
    }
    let lcns = |a: u64, n: u64| (a < clusters).then(|| ByteRange::new(a * cluster, n.min(clusters - a) * cluster));
    v.extend(fs.superblock().checkpoints.iter().filter_map(|&l| lcns(l, page)));
    if let Some(l) = log {
        let (a, b) = (l.control[0].min(l.control[1]), l.control[0].max(l.control[1]));
        if b - a <= page {
            let mut pages: Vec<ByteRange> =
                seen.iter().flat_map(|p| p.physical.iter().map(|&l| ByteRange::new(l * cluster, cluster))).collect();
            list::normalize(&mut pages);
            let ctl: Vec<ByteRange> = lcns(a, (b + 1 - a).max(page)).into_iter().collect();
            v.extend(list::subtract(&ctl, &pages));
        }
    }
    list::normalize(&mut v);
    v
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn ranges(k: Kept) -> Vec<ByteRange> {
        match k {
            Kept::Ranges(v) => v,
            Kept::Diverged => panic!("diverged"),
        }
    }
}
