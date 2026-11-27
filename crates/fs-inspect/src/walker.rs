//! A walk pulled a batch at a time ([`FsHandle::walker`](crate::fs::FsHandle::walker)).
//!
//! The walk runs on a thread of its own (the crate's one walk, also under
//! [`export`](crate::fs::FsHandle::export)), at most two batches ahead of its caller: what
//! it holds does not grow with a directory's size, as a walk's does not. Before it enters a
//! directory it waits until the caller has taken every batch before it, so that
//! [`Walker::skip`] of a directory handed in the last batch keeps it from being entered.
//!
//! The thread is a helper of the process's budget
//! ([`set_max_helper_threads`](crate::set_max_helper_threads)): counted while the walk runs,
//! so that reads at a queue depth elsewhere take fewer helpers, but taken past the cap, as the
//! walk has no other thread to run on ([`spawn_helper`](fs_inspect_io::ahead::spawn_helper)).
//!
//! Cancelling: the walk reads under a token of its own, which [`Walker::close`] (and dropping
//! the walker) cancels, and under the walker's token (the one given to
//! [`FsHandle::walker`](crate::fs::FsHandle::walker), with the handle's). While a
//! [`next_batch`](Walker::next_batch) waits for the walk, it also watches its own call's
//! token. When that token is cancelled, the call fails with
//! [`Cancelled`](crate::ErrorKind::Cancelled) and stops the walk, since the reads in flight
//! were for that call. When the walker is closed, the call returns `false`: closing is the
//! owner's decision to stop, not an error.

use crate::fs::{FsHandle, Parent};
use crate::walk::{OnError, Step, Visit, Visitor, WalkOptions};
use fs_inspect_core::WantExt;
use fs_inspect_core::ns::{DirEntry, NodeId, NodeInfo};
use fs_inspect_core::{Error, Result};
use fs_inspect_io::CancelToken;
use std::collections::HashSet;
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

/// How often a [`Walker::next_batch`] waiting for the walk looks at the tokens that may cancel
/// it: the longest a cancel waits to be seen there.
const WATCH: Duration = Duration::from_millis(20);

/// Entries a batch holds at most when the walk reads no infos (with infos, a batch is those
/// read together, up to [`WalkOptions::batch`]).
const NAMES_BATCH: usize = 1024;

/// One entry of a [`Walker`] batch.
#[derive(Debug)]
#[non_exhaustive]
pub struct WalkEntry {
    /// Levels below the top (the top directory's entries: 0).
    pub depth: usize,
    /// The entry's path from the top: names [escaped](crate::fs::Name::escape), each after a `/`.
    pub path: String,
    pub entry: DirEntry,
    /// The node's info with [`WalkOptions::want`]; `None` without. An entry whose node cannot
    /// be read has its error here, the walk going on.
    pub info: Option<Result<NodeInfo>>,
    /// With [`OnError::SkipAndReport`]: this directory, handed before, could not be listed
    /// (or not to its end, after the entries it gave); handed again with the error.
    pub failed: Option<Error>,
}

/// A walk of a tree ([`FsHandle::walker`](crate::fs::FsHandle::walker)), pulled a batch at a
/// time with [`next_batch`](Self::next_batch) or by iterating `&Walker` (each batch, its
/// error last). [`close`](Self::close), or dropping it, stops the walk (a read under way ends
/// first, on the walk's thread). Shared between threads (`Send + Sync`): one thread may close
/// it while another waits in `next_batch`, which then returns at once.
///
/// ```no_run
/// # fn f(fs: &fs_inspect::fs::FsHandle, top: fs_inspect::fs::NodeId) -> fs_inspect::Result<()> {
/// use fs_inspect::fs::WalkOptions;
/// let walker = fs.walker(top, &WalkOptions::default(), None)?;
/// for batch in &walker {
///     for e in batch? {
///         if e.path.ends_with("/node_modules") {
///             walker.skip(e.entry.node);
///         }
///     }
/// }
/// # Ok(())
/// # }
/// ```
pub struct Walker {
    /// The caller's side, held by a `next_batch` while it waits.
    pulled: Mutex<Pulled>,
    shared: Arc<Shared>,
    /// The walk's own token: cancelled by [`close`](Self::close).
    token: CancelToken,
    /// The walker's token: [`walker`](crate::fs::FsHandle::walker)'s `cancel` with its
    /// handle's. The walk reads under it; a `next_batch` waits under it and its own call's.
    call: Option<CancelToken>,
}

/// What a [`Walker`]'s caller has pulled.
struct Pulled {
    /// `None` once the walk is closed: dropped, so that a walk waiting to send ends.
    rx: Option<Receiver<Msg>>,
    /// Batches taken.
    taken: u64,
    /// The walk has ended (its end, or its error, handed).
    ended: bool,
}

enum Msg {
    Batch(Vec<WalkEntry>),
    End(Result<()>),
}

#[derive(Default)]
struct Shared {
    state: Mutex<State>,
    changed: Condvar,
}

#[derive(Default)]
struct State {
    /// Batches the caller is done with: those it took before its last call.
    done: u64,
    /// Directories not to enter.
    skip: HashSet<NodeId>,
    /// The walker was closed.
    closed: bool,
}

impl Shared {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl std::fmt::Debug for Walker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("Walker");
        // Not waiting for a `next_batch` to say more.
        if let Ok(p) = self.pulled.try_lock() {
            d.field("taken", &p.taken).field("ended", &p.ended);
        }
        d.field("closed", &self.token.is_cancelled()).finish_non_exhaustive()
    }
}

impl Walker {
    pub(crate) fn start(fs: FsHandle, dir: NodeId, opts: WalkOptions) -> Result<Walker> {
        let (tx, rx) = sync_channel::<Msg>(2);
        let shared = Arc::new(Shared::default());
        // The walk reads under its own token and the call it was made in.
        let token = CancelToken::new();
        let call = fs_inspect_io::cancel::call_token();
        let made_in = call.clone();
        let limit = if opts.want.info().is_some() { opts.batch.max(1) } else { NAMES_BATCH };
        let (theirs, own) = (shared.clone(), token.clone());
        let walk = move || {
            fs_inspect_io::cancel::with_call_token(Some(own), || {
                fs_inspect_io::cancel::with_bound(call.as_ref(), || {
                    let mut v = Producer {
                        fs: &fs,
                        tx: &tx,
                        shared: &theirs,
                        items: Vec::new(),
                        sent: 0,
                        limit,
                        keep_going: opts.on_error == OnError::SkipAndReport,
                    };
                    let top = Parent::top(dir);
                    let r = crate::walk::walk(fs.namespace(), dir, top, &opts, &mut v);
                    // The entries before an error are handed before it.
                    let flushed = v.flush();
                    let r = r.and(flushed);
                    let _ = tx.send(Msg::End(r));
                })
            });
        };
        fs_inspect_io::ahead::spawn_helper("fs-inspect-walk", walk)
            .map_err(|e| Error::io(format!("starting a walk's thread: {e}")))?;
        let pulled = Pulled { rx: Some(rx), taken: 0, ended: false };
        Ok(Walker { pulled: Mutex::new(pulled), shared, token, call: made_in })
    }

    fn pulled(&self) -> MutexGuard<'_, Pulled> {
        self.pulled.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The next entries into `out` (cleared first). Returns `false`, with `out` empty, once
    /// the walk has ended or the walker was closed. The walk's error is returned once, then
    /// `false`.
    ///
    /// While it waits for the walk, a close returns `false`, and a cancel of `cancel` or of
    /// the walker's tokens fails with [`Cancelled`](crate::ErrorKind::Cancelled) and stops
    /// the walk. One call runs at a time: another waits for it.
    pub fn next_batch(&self, out: &mut Vec<WalkEntry>, cancel: Option<&CancelToken>) -> Result<bool> {
        fs_inspect_io::cancel::with_handle(self.call.as_ref(), cancel, || self.next_here(out))
    }

    /// [`next_batch`](Self::next_batch), under the walker's token and the call's.
    fn next_here(&self, out: &mut Vec<WalkEntry>) -> Result<bool> {
        out.clear();
        let mut p = self.pulled();
        if p.ended || self.token.is_cancelled() {
            p.ended = true;
            p.rx = None;
            return Ok(false);
        }
        {
            let mut s = self.shared.lock();
            s.done = p.taken;
        }
        self.shared.changed.notify_all();
        let got = loop {
            if self.token.is_cancelled() {
                // Closed: the walk ends quietly, whatever it sent meanwhile.
                p.ended = true;
                p.rx = None;
                return Ok(false);
            }
            if let Err(e) = fs_inspect_io::cancel::check_call() {
                // The walk's reads in flight were this call's: the walk ends with it.
                p.ended = true;
                p.rx = None;
                self.close();
                return Err(e);
            }
            let Some(rx) = &p.rx else { break Err(RecvTimeoutError::Disconnected) };
            match rx.recv_timeout(WATCH) {
                Err(RecvTimeoutError::Timeout) => continue,
                r => break r,
            }
        };
        if self.token.is_cancelled() {
            // Closed while waiting: what the walk sent or ended with (its reads cancelled) is
            // not handed out.
            p.ended = true;
            p.rx = None;
            return Ok(false);
        }
        match got {
            Ok(Msg::Batch(b)) => {
                p.taken += 1;
                *out = b;
                Ok(true)
            }
            Ok(Msg::End(r)) => {
                p.ended = true;
                r.map(|()| false)
            }
            Err(_) => {
                p.ended = true;
                Err(Error::io("a walk's thread ended without its result"))
            }
        }
    }

    /// Do not enter directory `node`, an entry of the last batch.
    pub fn skip(&self, node: NodeId) {
        self.shared.lock().skip.insert(node);
    }

    /// Stop the walk now: its reads are cancelled and it enters no more directories; the walker
    /// hands nothing more (a [`next_batch`](Self::next_batch) waiting meanwhile and later ones
    /// return `false`: closing is not an error). Does not wait for the walk's thread, nor for a
    /// `next_batch` under way. Dropping the walker closes it.
    pub fn close(&self) {
        self.token.cancel();
        self.shared.lock().closed = true;
        self.shared.changed.notify_all();
        // Let a walk waiting to send end, unless a `next_batch` holds the receiver: that one
        // sees the token within `WATCH` and lets it go.
        if let Ok(mut p) = self.pulled.try_lock() {
            p.rx = None;
        }
    }
}

impl Drop for Walker {
    fn drop(&mut self) {
        self.close();
    }
}

/// The batches of [`next_batch`](Walker::next_batch), its error last; `None` once the walk
/// has ended or was closed.
impl Iterator for &Walker {
    type Item = Result<Vec<WalkEntry>>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut batch = Vec::new();
        match self.next_batch(&mut batch, None) {
            Ok(true) => Some(Ok(batch)),
            Ok(false) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

/// The walk's side: entries gathered into batches and sent.
struct Producer<'a> {
    fs: &'a FsHandle,
    tx: &'a SyncSender<Msg>,
    shared: &'a Shared,
    items: Vec<WalkEntry>,
    /// Batches sent.
    sent: u64,
    limit: usize,
    keep_going: bool,
}

impl Producer<'_> {
    /// Send the entries gathered (none: nothing).
    fn flush(&mut self) -> Result<()> {
        if self.items.is_empty() {
            return Ok(());
        }
        let batch = std::mem::take(&mut self.items);
        self.tx.send(Msg::Batch(batch)).map_err(|_| Error::cancelled())?;
        self.sent += 1;
        Ok(())
    }

    fn push(&mut self, e: WalkEntry) -> Result<()> {
        self.items.push(e);
        if self.items.len() >= self.limit { self.flush() } else { Ok(()) }
    }
}

impl Visitor<Parent> for Producer<'_> {
    fn entry(&mut self, v: Visit<'_, Parent>) -> Result<Step<Parent>> {
        let path = format!("{}/{}", v.parent.path, v.entry.name.escape());
        let dir = self.fs.is_dir(&v.entry, v.info.as_ref())?;
        let depth = v.depth;
        let next = dir.then(|| Parent { path: path.clone(), depth: depth + 1, entry: v.entry.clone() });
        self.push(WalkEntry { depth, path, entry: v.entry, info: v.info, failed: None })?;
        Ok(next.map_or(Step::Next, Step::Enter))
    }

    fn entering(&mut self, dir: &Parent) -> Result<bool> {
        self.flush()?;
        let mut s = self.shared.lock();
        while s.done < self.sent && !s.closed {
            s = self.shared.changed.wait(s).unwrap_or_else(PoisonError::into_inner);
        }
        if s.closed {
            return Err(Error::cancelled());
        }
        Ok(!s.skip.remove(&dir.entry.node))
    }

    fn dir_failed(&mut self, dir: &Parent, error: Error) -> Result<()> {
        if !self.keep_going || error.is_cancelled() {
            return Err(error);
        }
        let e = WalkEntry {
            depth: dir.depth.saturating_sub(1),
            path: dir.path.clone(),
            entry: dir.entry.clone(),
            info: None,
            failed: Some(error),
        };
        self.push(e)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::fs::{Order, RootId};
    use crate::testns::{Flag, MemNs};
    use fs_inspect_core::ns::Want;
    use std::time::Instant;

    /// /a/{x, b/{y}}, /c, /d/{z}, b also linking back to a (a cycle).
    fn tree() -> FsHandle {
        let mut ns = MemNs::new();
        ns.dir(1, "a", 2).file(2, "x", 3, b"x").dir(2, "b", 4).file(4, "y", 5, b"y").link(4, "up", 2);
        ns.file(1, "c", 6, b"c").dir(1, "d", 7).file(7, "z", 8, b"z");
        ns.handle()
    }

    fn root(fs: &FsHandle) -> NodeId {
        fs.resolve(RootId(0), "/", None).unwrap().node
    }

    /// The paths (and depths) a walker hands, skipping the directories named in `skip`.
    fn pulled(fs: &FsHandle, opts: &WalkOptions, skip: &[&str]) -> Vec<(usize, String)> {
        let w = fs.walker(root(fs), opts, None).unwrap();
        let (mut got, mut batch) = (Vec::new(), Vec::new());
        while w.next_batch(&mut batch, None).unwrap() {
            for e in batch.drain(..) {
                if skip.contains(&e.path.as_str()) {
                    w.skip(e.entry.node);
                }
                assert_eq!(e.info.is_some(), opts.want != Want::NONE, "{}", e.path);
                got.push((e.depth, e.path));
            }
        }
        assert!(!w.next_batch(&mut batch, None).unwrap() && batch.is_empty());
        got
    }

    /// The same of the crate's walk on the caller's thread.
    fn walked(fs: &FsHandle, opts: &WalkOptions, skip: &[&str]) -> Vec<(usize, String)> {
        let mut got = Vec::new();
        crate::walk::walk(fs.namespace(), root(fs), String::new(), opts, &mut |v: Visit<'_, String>| {
            let path = format!("{}/{}", v.parent, v.entry.name.escape());
            got.push((v.depth, path.clone()));
            let enter = !skip.contains(&path.as_str()) && fs.is_dir(&v.entry, v.info.as_ref())?;
            Ok(if enter { Step::Enter(path) } else { Step::Next })
        })
        .unwrap();
        got
    }

    /// Iterating a walker hands its batches; a skip between them holds.
    #[test]
    fn iterating_a_walker_hands_its_batches() {
        let fs = tree();
        let opts = WalkOptions::default().with_batch(2);
        let w = fs.walker(root(&fs), &opts, None).unwrap();
        let mut got = Vec::new();
        for batch in &w {
            for e in batch.unwrap() {
                if e.path == "/a" {
                    w.skip(e.entry.node);
                }
                got.push((e.depth, e.path));
            }
        }
        assert_eq!(got, walked(&fs, &opts, &["/a"]));
        assert!((&w).next().is_none());
        // The walk's error last, then nothing.
        let mut ns = MemNs::new();
        ns.dir(1, "d", 2).file(2, "e", 3, b"").file(2, "f", 4, b"");
        ns.node(2).bad_listing = true;
        let fs = ns.handle();
        let w = fs.walker(root(&fs), &WalkOptions::default(), None).unwrap();
        let all: Vec<Result<Vec<WalkEntry>>> = (&w).collect();
        assert!(all.last().unwrap().is_err() && all[..all.len() - 1].iter().all(Result::is_ok));
    }

    #[test]
    fn a_walker_hands_what_the_walk_does_and_skips_what_it_is_told() {
        let fs = tree();
        for order in [Order::DirsAfter, Order::Preorder] {
            for want in [Want::NONE, Want::STAT] {
                // Batches of two: directories entered after batches the caller has not taken.
                let opts = WalkOptions::default().with_order(order).with_want(want).with_batch(2);
                for skip in [&[][..], &["/a"], &["/a/b", "/d"]] {
                    let got = pulled(&fs, &opts, skip);
                    assert_eq!(got, walked(&fs, &opts, skip), "{order:?} {want:?} {skip:?}");
                    assert!(got.iter().any(|(_, p)| p == "/c"));
                    assert_eq!(got.iter().any(|(_, p)| p == "/a/x"), !skip.contains(&"/a"));
                }
            }
        }
    }

    #[test]
    fn a_directory_that_cannot_be_listed_ends_the_walk_or_is_handed_again() {
        // /d lists its first entry, then fails.
        let mut ns = MemNs::new();
        ns.dir(1, "d", 2).file(2, "e", 3, b"").file(2, "f", 4, b"").file(1, "g", 5, b"");
        ns.node(2).bad_listing = true;
        let fs = ns.handle();
        let all = |opts: &WalkOptions| {
            let w = fs.walker(root(&fs), opts, None).unwrap();
            let (mut got, mut batch) = (Vec::new(), Vec::new());
            let end = loop {
                match w.next_batch(&mut batch, None) {
                    Ok(true) => got.extend(batch.drain(..).map(|e| (e.path, e.failed.map(|e| e.kind())))),
                    r => break r.map(|_| ()),
                }
            };
            (got, end)
        };
        let (got, end) = all(&WalkOptions::default());
        assert_eq!(got, [("/d".to_owned(), None), ("/g".to_owned(), None), ("/d/e".to_owned(), None)]);
        assert!(end.is_err());
        let (got, end) = all(&WalkOptions::default().with_on_error(OnError::SkipAndReport));
        end.unwrap();
        assert_eq!(got.len(), 4);
        assert_eq!(got[3].0, "/d");
        assert!(got[3].1.is_some());
    }

    #[test]
    fn a_walker_dropped_part_way_stops_its_walk() {
        let mut ns = MemNs::new();
        for i in 0..50u64 {
            ns.dir(1, &format!("d{i}"), 100 + i).file(100 + i, "f", 1000 + i, b"f");
        }
        let fs = ns.handle();
        let w = fs.walker(root(&fs), &WalkOptions::default().with_want(Want::STAT).with_batch(1), None).unwrap();
        let mut batch = Vec::new();
        assert!(w.next_batch(&mut batch, None).unwrap());
        drop(w);
    }

    #[test]
    fn a_walker_made_under_a_cancelled_call_stops() {
        let fs = tree();
        let token = CancelToken::new();
        token.cancel();
        let w = fs.walker(root(&fs), &WalkOptions::default(), Some(&token)).unwrap();
        let mut batch = Vec::new();
        let e = w.next_batch(&mut batch, None).unwrap_err();
        assert!(e.is_cancelled(), "{e}");
        assert!(!w.next_batch(&mut batch, None).unwrap());
    }

    /// A tree whose root's listing does not answer until cancelled, and the flag set once it
    /// waits.
    fn hanging() -> (FsHandle, Arc<Flag>) {
        let mut ns = MemNs::new();
        ns.file(1, "a", 2, b"a");
        ns.node(1).hangs = true;
        let flag = ns.hanging.clone();
        (ns.handle(), flag)
    }

    #[test]
    fn closing_a_walker_stops_a_next_batch_waiting_on_another_thread() {
        let (fs, hung) = hanging();
        let w = fs.walker(root(&fs), &WalkOptions::default(), None).unwrap();
        std::thread::scope(|s| {
            let waiting = s.spawn(|| w.next_batch(&mut Vec::new(), None));
            assert!(hung.wait(), "the listing waits");
            // Does not wait for the lock the waiting call holds, nor for the walk.
            let t = Instant::now();
            w.close();
            assert!(t.elapsed() < Duration::from_secs(1), "{:?}", t.elapsed());
            // Closing is the owner's decision to stop, not a cancel: the walk ends quietly.
            assert!(!waiting.join().unwrap().unwrap());
        });
        assert!(!w.next_batch(&mut Vec::new(), None).unwrap());
        // Closed before the call: nothing more, no error.
        let w = fs.walker(root(&fs), &WalkOptions::default(), None).unwrap();
        w.close();
        w.close();
        assert!(!w.next_batch(&mut Vec::new(), None).unwrap());
    }

    #[test]
    fn a_next_batch_whose_call_is_cancelled_stops_waiting_and_the_walk() {
        let (fs, hung) = hanging();
        let w = fs.walker(root(&fs), &WalkOptions::default(), None).unwrap();
        let token = CancelToken::new();
        std::thread::scope(|s| {
            s.spawn(|| {
                hung.wait();
                token.cancel();
            });
            let e = w.next_batch(&mut Vec::new(), Some(&token)).unwrap_err();
            assert!(e.is_cancelled(), "{e}");
        });
        assert!(!w.next_batch(&mut Vec::new(), None).unwrap());
    }

    #[test]
    fn a_walker_reads_under_the_call_it_was_made_in() {
        // Made in a call cancelled later, pulled outside it: the walk stops.
        let (fs, hung) = hanging();
        let made_in = CancelToken::new();
        let w = fs.walker(root(&fs), &WalkOptions::default(), Some(&made_in)).unwrap();
        std::thread::scope(|s| {
            s.spawn(|| {
                hung.wait();
                made_in.cancel();
            });
            let e = w.next_batch(&mut Vec::new(), None).unwrap_err();
            assert!(e.is_cancelled(), "{e}");
        });
    }
}
