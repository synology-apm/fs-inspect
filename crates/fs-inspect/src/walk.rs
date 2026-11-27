//! Walking a directory tree ([`walk`], public as
//! [`FsHandle::walker`](crate::fs::FsHandle::walker)): iterative (an explicit stack, however deep
//! the tree), cycle safe (a directory reached twice is entered once), in one of two [`Order`]s.
//! Every walk of this crate goes through it: [`FsHandle::walker`](crate::fs::FsHandle::walker) (and
//! so the command line's `ls` and `tree`) and [`export`](crate::fs::FsHandle::export).
//!
//! With [`WalkOptions::want`], each entry comes with its node's
//! [`NodeInfo`], read for up to [`WalkOptions::batch`] entries of a directory at a time
//! ([`Namespace::node_infos`]: a driver reads their records in the order they are on the
//! volume).
//!
//! A visitor sees each batch whole before its entries ([`Visitor::batch`]): what it reads of
//! them it can read together (an export reads small files' content so).
//!
//! What a walk holds does not grow with a directory's size in [`Order::DirsAfter`]: a
//! directory's entries stream past the visitor (a batch at a time), and only the
//! subdirectories it enters wait.

use fs_inspect_core::WantExt;
use fs_inspect_core::ns::{DirEntry, Namespace, NodeId, NodeInfo, Want};
use fs_inspect_core::{Error, Result};
use std::collections::{HashSet, VecDeque};
use std::ops::ControlFlow;
use std::sync::Arc;

/// Entries of a directory whose [`NodeInfo`]s a walk reads together, at most, by default.
pub const BATCH: usize = 4096;

fs_inspect_io::named_enum! {
    /// In what order a walk ([`FsHandle::walker`](crate::fs::FsHandle::walker)) visits a tree.
    pub enum Order ("walk order") {
        /// All of a directory's entries (streamed as it lists them), then each subdirectory
        /// entered, in turn. Holds only the subdirectories waiting, never a whole listing.
        DirsAfter = 1 => "dirs_after",
        /// Each entry, and a directory entered right after its own entry: what `tree` prints.
        /// Holds the listing of each directory on the way down.
        Preorder = 2 => "preorder",
    }
    default DirsAfter;
}

fs_inspect_io::named_enum! {
    /// What to do when an entry fails: a directory a walk cannot list
    /// ([`WalkOptions::on_error`]), an entry an export cannot write
    /// ([`ExportOptions::on_error`](crate::export::ExportOptions::on_error)).
    pub enum OnError ("error policy") {
        /// Stop at the first error, ending with it.
        Abort = 1 => "abort",
        /// Leave it out and go on: a walk hands the directory again with
        /// [`WalkEntry::failed`](crate::fs::WalkEntry::failed), an export lists the entry in
        /// [`ExportReport::skipped`](crate::export::ExportReport::skipped).
        SkipAndReport = 2 => "skip_and_report",
    }
    default Abort;
}

/// How a walk ([`FsHandle::walker`](crate::fs::FsHandle::walker)) goes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct WalkOptions {
    /// Levels of directories to list (`Some(1)`: only the top one); `None`: all.
    pub max_depth: Option<usize>,
    pub order: Order,
    /// Each entry's [`NodeInfo`] read, with these facets
    /// ([`WalkEntry::info`](crate::fs::WalkEntry::info); [`Want::STAT`]: the stat alone);
    /// [`Want::NONE`] (the default): none.
    pub want: Want,
    /// Entries of a directory whose infos are read together, at most (4096 by default).
    /// More reads fewer times where a directory lists its entries far from the order of
    /// their records (ext's hashed directories), and holds more.
    pub batch: usize,
    /// A directory that cannot be listed: [`OnError::Abort`] (the default) ends the walk with
    /// its error, [`OnError::SkipAndReport`] hands it again and goes on
    /// ([`FsHandle::walker`](crate::fs::FsHandle::walker)).
    pub on_error: OnError,
}

impl Default for WalkOptions {
    fn default() -> Self {
        WalkOptions {
            max_depth: None,
            order: Order::default(),
            want: Want::NONE,
            batch: BATCH,
            on_error: OnError::Abort,
        }
    }
}

impl WalkOptions {
    /// As a caller may ask: no file opened with the infos (the crate's own walks only).
    pub(crate) fn public(&self) -> WalkOptions {
        WalkOptions { want: self.want.without(Want::OPEN), ..self.clone() }
    }
}

fs_inspect_core::with_setters! { WalkOptions {
    max_depth / with_max_depth: Option<usize>,
    order / with_order: Order,
    want / with_want: Want,
    batch / with_batch: usize,
    on_error / with_on_error: OnError,
} }

/// What a [`Visitor`] does after an entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step<D> {
    /// Enter this entry, a directory, with `D` as what the visitor keeps of it (its path,
    /// say). Not entered past [`WalkOptions::max_depth`], nor a second time.
    Enter(D),
    /// Go on to the next entry.
    Next,
}

/// One entry a [`walk`] visits.
#[derive(Debug)]
pub struct Visit<'a, D> {
    /// Levels below the top (the top directory's entries: 0).
    pub depth: usize,
    /// What the visitor keeps of the directory holding the entry.
    pub parent: &'a D,
    pub entry: DirEntry,
    /// The node's [`NodeInfo`] with [`WalkOptions::want`]; `None` without.
    pub info: Option<Result<NodeInfo>>,
}

/// What a [`walk`] hands its entries to. `D` is what the visitor keeps of each directory it
/// enters, handed back with that directory's entries.
pub trait Visitor<D> {
    fn entry(&mut self, visit: Visit<'_, D>) -> Result<Step<D>>;

    /// The entries (and infos) about to be visited, in order, before the first of them: up to
    /// [`WalkOptions::batch`] of a directory with [`WalkOptions::want`], else one. Nothing by
    /// default.
    fn batch(&mut self, entries: &[(DirEntry, Option<Result<NodeInfo>>)]) {
        let _ = entries;
    }

    /// About to list the directory kept as `dir`, an entry the visitor entered (not the top):
    /// `false` leaves it out. Called when its listing starts, which in [`Order::DirsAfter`] is
    /// after its directory's whole listing. Yes by default.
    fn entering(&mut self, dir: &D) -> Result<bool> {
        let _ = dir;
        Ok(true)
    }

    /// Listing the directory kept as `dir` failed with `error` (after the entries it gave
    /// before): an error ends the walk with it (the default), `Ok` goes on with the rest.
    fn dir_failed(&mut self, dir: &D, error: Error) -> Result<()> {
        let _ = dir;
        Err(error)
    }
}

impl<D, F: FnMut(Visit<'_, D>) -> Result<Step<D>>> Visitor<D> for F {
    fn entry(&mut self, visit: Visit<'_, D>) -> Result<Step<D>> {
        self(visit)
    }
}

/// Walk the tree under directory `top` (kept as `data`), handing every entry to `v`.
pub fn walk<D>(
    ns: &Arc<dyn Namespace>,
    top: NodeId,
    data: D,
    opts: &WalkOptions,
    v: &mut dyn Visitor<D>,
) -> Result<()> {
    if opts.max_depth == Some(0) {
        return Ok(());
    }
    // Batches of infos may read the same structures again: the driver keeps what it read for
    // the walk.
    let _hold = opts.want.info().is_some().then(|| ns.hold());
    let mut w = Walker { ns, opts, seen: HashSet::from([top]), v };
    match opts.order {
        Order::DirsAfter => w.dirs_after(top, data),
        Order::Preorder => w.preorder(top, data),
    }
}

struct Walker<'a, D> {
    ns: &'a Arc<dyn Namespace>,
    opts: &'a WalkOptions,
    /// Directories entered.
    seen: HashSet<NodeId>,
    v: &'a mut dyn Visitor<D>,
}

impl<D> Walker<'_, D> {
    /// Entries visited together: [`WalkOptions::batch`] when their infos are read, else one (the
    /// visitor sees each as the directory lists it).
    fn batch(&self) -> usize {
        if self.opts.want.info().is_some() { self.opts.batch.max(1) } else { 1 }
    }

    /// Whether a directory found at `depth` (as `node`) is to be entered.
    fn enters(&mut self, depth: usize, node: NodeId) -> bool {
        self.opts.max_depth.is_none_or(|m| depth + 1 < m) && self.seen.insert(node)
    }

    /// The infos of `entries` (with [`WalkOptions::want`]), in their order.
    fn infos(&self, entries: &[DirEntry]) -> Vec<Option<Result<NodeInfo>>> {
        let Some(want) = self.opts.want.info() else { return entries.iter().map(|_| None).collect() };
        let nodes: Vec<NodeId> = entries.iter().map(|e| e.node).collect();
        let mut out: Vec<Option<Result<NodeInfo>>> = entries.iter().map(|_| None).collect();
        let done = self.ns.clone().node_infos(&nodes, want, &mut |i, r| {
            if let Some(slot) = out.get_mut(i) {
                *slot = Some(r);
            }
            ControlFlow::Continue(())
        });
        for (slot, e) in out.iter_mut().zip(entries) {
            if slot.is_none() {
                let err = match &done {
                    Err(err) => err.clone(),
                    Ok(()) => Error::corrupt(format!("node {} not read with its directory's others", e.node)),
                };
                *slot = Some(Err(err));
            }
        }
        out
    }

    /// Visit `entries` (of the directory kept as `data`, at `depth`), their infos read
    /// together; the subdirectories to enter into `subdirs`.
    fn visit(
        &mut self,
        depth: usize,
        data: &D,
        entries: Vec<DirEntry>,
        subdirs: &mut VecDeque<(NodeId, D)>,
    ) -> Result<()> {
        let infos = self.infos(&entries);
        let batch: Vec<_> = entries.into_iter().zip(infos).collect();
        self.v.batch(&batch);
        for (entry, info) in batch {
            let node = entry.node;
            match self.v.entry(Visit { depth, parent: data, entry, info })? {
                Step::Enter(d) => {
                    if self.enters(depth, node) {
                        subdirs.push_back((node, d));
                    }
                }
                Step::Next => {}
            }
        }
        Ok(())
    }

    fn dirs_after(&mut self, top: NodeId, data: D) -> Result<()> {
        let batch = self.batch();
        // Each level's subdirectories still to walk.
        let mut stack: Vec<VecDeque<(NodeId, D)>> = vec![VecDeque::from([(top, data)])];
        while let Some(level) = stack.last_mut() {
            let Some((dir, data)) = level.pop_front() else {
                stack.pop();
                continue;
            };
            let depth = stack.len() - 1;
            if depth > 0 && !self.v.entering(&data)? {
                continue;
            }
            let mut subdirs = VecDeque::new();
            let mut pending = Vec::new();
            let mut ended: Option<Error> = None;
            let ns = self.ns.clone();
            let listed = ns.read_dir(dir, &mut |e| {
                pending.push(e);
                if pending.len() < batch {
                    return ControlFlow::Continue(());
                }
                match self.visit(depth, &data, std::mem::take(&mut pending), &mut subdirs) {
                    Ok(()) => ControlFlow::Continue(()),
                    Err(e) => {
                        ended = Some(e);
                        ControlFlow::Break(())
                    }
                }
            });
            if let Some(e) = ended {
                return Err(e);
            }
            self.visit(depth, &data, pending, &mut subdirs)?;
            if let Err(e) = listed {
                self.v.dir_failed(&data, e)?;
            }
            if !subdirs.is_empty() {
                stack.push(subdirs);
            }
        }
        Ok(())
    }

    fn preorder(&mut self, top: NodeId, data: D) -> Result<()> {
        // Each directory on the way down: what it is kept as, its entries still to visit, and
        // those whose infos are read, waiting.
        let mut stack: Vec<Frame<D>> = Vec::new();
        self.push_listing(&mut stack, top, data)?;
        while let Some(depth) = stack.len().checked_sub(1) {
            let frame = &mut stack[depth];
            if frame.ready.is_empty() {
                let n = frame.entries.len().min(self.batch());
                if n == 0 {
                    stack.pop();
                    continue;
                }
                let next: Vec<DirEntry> = frame.entries.drain(..n).collect();
                let infos = self.infos(&next);
                stack[depth].ready = next.into_iter().zip(infos).collect();
                self.v.batch(stack[depth].ready.make_contiguous());
            }
            let frame = &mut stack[depth];
            let Some((entry, info)) = frame.ready.pop_front() else { continue };
            let node = entry.node;
            match self.v.entry(Visit { depth, parent: &frame.data, entry, info })? {
                Step::Enter(d) if self.enters(depth, node) => {
                    if self.v.entering(&d)? {
                        self.push_listing(&mut stack, node, d)?;
                    }
                }
                Step::Enter(_) | Step::Next => {}
            }
        }
        Ok(())
    }

    fn push_listing(&mut self, stack: &mut Vec<Frame<D>>, dir: NodeId, data: D) -> Result<()> {
        let mut entries = VecDeque::new();
        if let Err(e) = self.ns.read_dir(dir, &mut |e| {
            entries.push_back(e);
            ControlFlow::Continue(())
        }) {
            self.v.dir_failed(&data, e)?;
        }
        stack.push(Frame { data, entries, ready: VecDeque::new() });
        Ok(())
    }
}

/// A directory of a [`Order::Preorder`] walk.
struct Frame<D> {
    data: D,
    entries: VecDeque<DirEntry>,
    ready: VecDeque<(DirEntry, Option<Result<NodeInfo>>)>,
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::testns::MemNs;
    use fs_inspect_core::ns::NodeKind;

    /// /a/{x, b/{y}}, /c, with b also linking back to a (a cycle).
    fn tree() -> Arc<dyn Namespace> {
        let mut ns = MemNs::new();
        ns.dir(1, "a", 2).file(2, "x", 3, b"x").dir(2, "b", 4).file(4, "y", 5, b"y").link(4, "up", 2);
        ns.file(1, "c", 6, b"c");
        Arc::new(ns)
    }

    /// Every path the walk visits, entering every directory.
    fn paths(ns: &Arc<dyn Namespace>, opts: &WalkOptions) -> Vec<String> {
        let mut got = Vec::new();
        walk(ns, NodeId::new(0, 1), String::new(), opts, &mut |v: Visit<'_, String>| {
            let path = format!("{}/{}", v.parent, v.entry.name.escape());
            got.push(path.clone());
            Ok(if v.entry.kind == Some(NodeKind::Dir) { Step::Enter(path) } else { Step::Next })
        })
        .unwrap();
        got
    }

    #[test]
    fn dirs_after_lists_a_directory_whole_before_entering_its_subdirectories() {
        let got = paths(&tree(), &WalkOptions::default());
        assert_eq!(got, ["/a", "/c", "/a/x", "/a/b", "/a/b/y", "/a/b/up"]);
    }

    #[test]
    fn preorder_enters_a_directory_right_after_its_entry() {
        let got = paths(&tree(), &WalkOptions::default().with_order(Order::Preorder));
        assert_eq!(got, ["/a", "/a/x", "/a/b", "/a/b/y", "/a/b/up", "/c"]);
    }

    #[test]
    fn infos_change_nothing_of_the_order() {
        for order in [Order::DirsAfter, Order::Preorder] {
            let opts = WalkOptions::default().with_order(order);
            assert_eq!(paths(&tree(), &opts.clone().with_want(Want::ALL)), paths(&tree(), &opts));
        }
    }

    #[test]
    fn each_entry_comes_with_its_info() {
        // More entries than a batch, so infos are read a batch at a time.
        let mut ns = MemNs::new();
        for i in 0..(BATCH as u64 * 2 + 3) {
            ns.file(1, &format!("f{i}"), 10 + i, &vec![0; i as usize]);
        }
        let ns: Arc<dyn Namespace> = Arc::new(ns);
        for order in [Order::DirsAfter, Order::Preorder] {
            let opts = WalkOptions::default().with_order(order).with_want(Want::STAT);
            let mut n = 0;
            walk(&ns, NodeId::new(0, 1), (), &opts, &mut |v: Visit<'_, ()>| {
                let st = v.info.unwrap().unwrap().stat;
                assert_eq!((st.node, st.size), (v.entry.node, v.entry.node.id - 10));
                n += 1;
                Ok(Step::Next)
            })
            .unwrap();
            assert_eq!(n, BATCH * 2 + 3, "{order:?}");
        }
    }

    #[test]
    fn a_visitor_sees_each_batch_before_its_entries() {
        /// Entries announced by `batch` and not visited yet; and the batches' sizes.
        #[derive(Default)]
        struct V(std::collections::VecDeque<NodeId>, Vec<usize>);
        impl Visitor<()> for V {
            fn entry(&mut self, v: Visit<'_, ()>) -> Result<Step<()>> {
                assert_eq!(self.0.pop_front(), Some(v.entry.node));
                Ok(if v.entry.kind == Some(NodeKind::Dir) { Step::Enter(()) } else { Step::Next })
            }
            fn batch(&mut self, entries: &[(DirEntry, Option<Result<NodeInfo>>)]) {
                assert!(self.0.is_empty(), "a batch before the last one's entries");
                assert!(entries.iter().all(|(e, i)| i.as_ref().unwrap().as_ref().unwrap().stat.node == e.node));
                self.0.extend(entries.iter().map(|(e, _)| e.node));
                self.1.push(entries.len());
            }
        }
        let mut ns = MemNs::new();
        ns.dir(1, "d", 2);
        for i in 0..(BATCH as u64 + 5) {
            ns.file(2, &format!("f{i}"), 10 + i, b"x");
        }
        let ns: Arc<dyn Namespace> = Arc::new(ns);
        for order in [Order::DirsAfter, Order::Preorder] {
            let mut v = V::default();
            let opts = WalkOptions::default().with_order(order).with_want(Want::STAT);
            walk(&ns, NodeId::new(0, 1), (), &opts, &mut v).unwrap();
            assert_eq!(v.1, [1, BATCH, 5], "{order:?}");
        }
    }

    #[test]
    fn a_directory_linked_to_itself_ends() {
        let mut ns = MemNs::new();
        ns.dir(1, "d", 2).link(2, "self", 2).link(2, "root", 1);
        let ns: Arc<dyn Namespace> = Arc::new(ns);
        for order in [Order::DirsAfter, Order::Preorder] {
            let got = paths(&ns, &WalkOptions::default().with_order(order));
            assert_eq!(got, ["/d", "/d/self", "/d/root"], "{order:?}");
        }
    }

    #[test]
    fn max_depth_bounds_the_levels_listed() {
        let ns = tree();
        assert_eq!(paths(&ns, &WalkOptions::default().with_max_depth(Some(1))), ["/a", "/c"]);
        assert_eq!(paths(&ns, &WalkOptions::default().with_max_depth(Some(2))), ["/a", "/c", "/a/x", "/a/b"]);
        assert!(paths(&ns, &WalkOptions::default().with_max_depth(Some(0))).is_empty());
    }

    #[test]
    fn an_error_of_the_visitor_ends_the_walk_at_once() {
        for want in [Want::NONE, Want::STAT] {
            for order in [Order::DirsAfter, Order::Preorder] {
                let mut n = 0;
                let opts = WalkOptions::default().with_order(order).with_want(want);
                walk(&tree(), NodeId::new(0, 1), (), &opts, &mut |_: Visit<'_, ()>| {
                    n += 1;
                    if n == 2 { Err(Error::cancelled()) } else { Ok(Step::Enter(())) }
                })
                .unwrap_err();
                assert_eq!(n, 2, "{order:?} {want:?}");
            }
        }
    }

    #[test]
    fn a_directory_that_cannot_be_listed_goes_to_the_visitor() {
        struct V(Vec<String>);
        impl Visitor<u64> for V {
            fn entry(&mut self, v: Visit<'_, u64>) -> Result<Step<u64>> {
                Ok(Step::Enter(v.entry.node.id))
            }
            fn dir_failed(&mut self, dir: &u64, e: Error) -> Result<()> {
                self.0.push(format!("{dir}: {}", e.kind()));
                Ok(())
            }
        }
        // A file named as if it were a directory: listing it fails.
        let mut ns = MemNs::new();
        ns.file(1, "f", 2, b"").dir(1, "d", 3).file(3, "g", 4, b"");
        let ns: Arc<dyn Namespace> = Arc::new(ns);
        let mut v = V(Vec::new());
        walk(&ns, NodeId::new(0, 1), 1, &WalkOptions::default(), &mut v).unwrap();
        assert_eq!(v.0, ["2: invalid_argument", "4: invalid_argument"]);
        // By default the failure ends the walk.
        let err =
            walk(&ns, NodeId::new(0, 1), (), &WalkOptions::default(), &mut |_: Visit<'_, ()>| Ok(Step::Enter(())));
        assert!(err.is_err());
    }
}
