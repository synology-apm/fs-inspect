//! A directory's entries held together ([`Listing`]): what a front end shows of a directory,
//! finds an entry in, sorts, and reads small files ahead from.

use crate::CancelToken;
use crate::ahead::Sibling;
use crate::fs::{DirCursor, Listed};
use fs_inspect_core::Result;
use fs_inspect_core::ns::{NodeId, NodeKind, Presence};
use fs_inspect_core::{EntryId, Name};
use std::sync::{Arc, OnceLock};

fs_inspect_io::named_enum! {
    /// In what order [`Listing::order`] puts a listing's entries.
    pub enum DirOrder ("directory order") {
        /// By their [`id`](Listed::id)s as text, in code point order.
        Ids = 1 => "ids",
        /// The directories first, then the rest, each part by id.
        DirsFirst = 2 => "dirs_first",
    }
    default Ids;
}

/// Entries of directory [`dir`](Self::dir) in the order the directory hands them
/// ([`DirCursor::collect`]): the whole directory, or its entries from where the cursor was.
/// What a [`ReadAhead`](crate::fs::ReadAhead) reads a directory's files ahead from: it holds
/// the directory and its entries as the read-ahead sees them ([`siblings`](Self::siblings)).
#[derive(Debug)]
pub struct Listing {
    dir: NodeId,
    entries: Vec<Listed>,
    whole: bool,
    /// Its entries as a [`ReadAhead`](crate::fs::ReadAhead) reads them, made at first use.
    siblings: OnceLock<Arc<[Sibling]>>,
}

impl Listing {
    /// A listing of directory `dir` with no entries but `siblings`, as a read-ahead sees
    /// them (a test's folder).
    #[cfg(test)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub(crate) fn of_siblings(dir: NodeId, siblings: Vec<Sibling>) -> Listing {
        Listing { dir, entries: Vec::new(), whole: false, siblings: OnceLock::from(Arc::from(siblings)) }
    }

    pub fn dir(&self) -> NodeId {
        self.dir
    }

    pub fn entries(&self) -> &[Listed] {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether it holds every entry of the directory ([`DirCursor::collect`] from the first).
    pub fn is_whole(&self) -> bool {
        self.whole
    }

    /// The position of the entry whose [`id`](Listed::id) is `id`; `None` when there is none.
    pub fn find(&self, id: &EntryId) -> Option<u64> {
        let at = self.entries.iter().position(|e| id.is(&e.entry.name, e.occurrence))?;
        Some(at as u64)
    }

    /// The position of the entry of `node` (the first, for a node of several names here).
    pub fn position(&self, node: NodeId) -> Option<u64> {
        let at = self.entries.iter().position(|e| e.entry.node == node)?;
        Some(at as u64)
    }

    /// The positions of the entries in `order`.
    pub fn order(&self, order: DirOrder) -> Vec<u64> {
        let dirs_first = order == DirOrder::DirsFirst;
        let keys: Vec<(bool, String)> =
            self.entries.iter().map(|e| (dirs_first && e.kind() != Some(NodeKind::Dir), e.id().to_string())).collect();
        let mut order: Vec<u64> = (0..keys.len() as u64).collect();
        order.sort_by(|&a, &b| keys[a as usize].cmp(&keys[b as usize]));
        order
    }

    /// Its entries as a [`ReadAhead`](crate::fs::ReadAhead) reads them: a file is readable
    /// when it was listed with its stat ([`Want::STAT`](crate::fs::Want::STAT) or more) and its
    /// content is there (not only in the cloud).
    pub fn siblings(&self) -> &Arc<[Sibling]> {
        self.siblings.get_or_init(|| {
            self.entries
                .iter()
                .map(|e| match e.info.as_ref().and_then(|i| i.as_ref().ok()) {
                    Some(i) => Sibling::new(
                        e.entry.node,
                        i.stat.size,
                        i.stat.kind == NodeKind::File && i.stat.presence() == Presence::Normal,
                    ),
                    None => Sibling::new(e.entry.node, 0, false),
                })
                .collect()
        })
    }

    /// About the memory it holds, in bytes (for a cache's budget).
    pub fn memory_bytes(&self) -> usize {
        let each = |e: &Listed| {
            let name = match &e.entry.name {
                Name::Bytes(b) => b.len(),
                Name::Utf16(u) => 2 * u.len(),
            };
            let info = match &e.info {
                Some(Ok(i)) => {
                    size_of::<fs_inspect_core::ns::NodeInfo>()
                        + i.link.as_ref().map_or(0, |_| size_of::<fs_inspect_core::ns::LinkTarget>() + 2 * name)
                }
                _ => 0,
            };
            size_of::<Listed>() + size_of::<Sibling>() + name + info
        };
        self.entries.iter().map(each).sum()
    }
}

impl DirCursor {
    /// Every entry from where the cursor is to the end, as one batch on the calling thread
    /// ([`read`](DirCursor::read) with no limit): the whole directory when the cursor is at
    /// its first entry. The listing is held whole anyway, so the file system is asked for all
    /// the entries' infos in one call: it merges their metadata reads over the whole directory
    /// and keeps the volume's queue depth busy with them itself, where batches split those
    /// reads at each batch's end. An error is the listing's (or a cancel's); the cursor then
    /// stays where it was.
    pub fn collect(&mut self, cancel: Option<&CancelToken>) -> Result<Listing> {
        let whole = self.position() == 0;
        let dir = self.dir();
        let entries = self.read_rest(cancel)?;
        Ok(Listing { dir, entries, whole, siblings: OnceLock::new() })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use crate::fs::{DirOptions, RootId, Want};
    use crate::testns::MemNs;

    #[test]
    fn a_listing_finds_orders_and_reads_ahead_its_entries() {
        let mut ns = MemNs::new();
        ns.file(1, "b", 10, b"bb").dir(1, "z", 11).file(1, "a", 12, b"a").file(1, "b", 13, b"b2");
        let fs = ns.handle();
        let root = fs.resolve(RootId(0), "/", None).unwrap().node;
        let l = fs.dir(root, &DirOptions::default().with_want(Want::STAT), None).collect(None).unwrap();
        assert!(l.is_whole() && l.len() == 4 && l.dir() == root);
        let ids: Vec<String> = l.entries().iter().map(|e| e.id().to_string()).collect();
        assert_eq!(ids, ["b", "z", "a", "b\\#2"]);
        let find = |s: &str| l.find(&s.parse().unwrap());
        assert_eq!((find("b"), find("b\\#2"), find("c")), (Some(0), Some(3), None));
        assert_eq!(l.order(crate::fs::DirOrder::Ids), [2, 0, 3, 1]);
        assert_eq!(l.order(crate::fs::DirOrder::DirsFirst), [1, 2, 0, 3]);
        let s = l.siblings();
        assert_eq!(
            s.iter().map(|s| (s.size, s.readable)).collect::<Vec<_>>(),
            [(2, true), (0, false), (1, true), (2, true)]
        );
        assert!(l.memory_bytes() > 0);

        let mut cur = fs.dir(root, &DirOptions::default(), None);
        cur.read(1, None).unwrap();
        let rest = cur.collect(None).unwrap();
        assert!(!rest.is_whole() && rest.len() == 3);
        assert!(rest.siblings().iter().all(|s| !s.readable), "no stat: nothing to read ahead");
    }
}
