//! Work done ahead on helper threads and handed back in order. Reading a stream, or a list of
//! runs at a queue depth, is built on it ([`ordered`], [`Pipeline`]).
//!
//! Helper threads take jobs as the caller pulls them. The caller's thread receives the results
//! in job order, at most `depth` jobs ahead. A helper of [`ordered`] that reads runs of its
//! own (a logical volume over its members) reads them one at a time, unless its jobs ask for
//! [`HelperReads::Ahead`].
//!
//! All helpers of the process share one budget ([`set_max_helpers`]).

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError, mpsc};

/// Helper threads all [`ordered`] calls of the process may run at once ([`set_max_helpers`]).
static MAX_HELPERS: AtomicUsize = AtomicUsize::new(usize::MAX);
/// Helper threads running now.
static HELPERS: AtomicUsize = AtomicUsize::new(0);

/// Cap at `max` the helper threads that all readers of the process run at once: those of
/// [`ordered`] and [`Pipeline`] (reads ahead of a stream, runs read at a queue depth, batches
/// in flight), and those of [`spawn_helper`], which count but start past the cap.
///
/// A call that finds no helper free does not wait: it reads on its own thread, one job at a
/// time. This keeps the threads of a server bounded however many callers read at once. Each
/// call takes its helpers when it needs them, so a new cap applies to the helpers taken after
/// it. `Some(0)`: no helpers but those of [`spawn_helper`]; `None` (the default): no cap.
pub fn set_max_helpers(max: Option<usize>) {
    MAX_HELPERS.store(max.unwrap_or(usize::MAX), Ordering::Relaxed);
}

/// Helper threads running now (all [`ordered`] calls of the process).
pub fn helpers_running() -> usize {
    HELPERS.load(Ordering::Relaxed)
}

/// Helper threads taken from the process's budget, given back when dropped.
struct Permits(usize);

impl Permits {
    /// Up to `want` of them, as many as are free (maybe none).
    fn take(want: usize) -> Permits {
        let max = MAX_HELPERS.load(Ordering::Relaxed);
        let mut got = 0;
        let _ = HELPERS.try_update(Ordering::AcqRel, Ordering::Acquire, |now| {
            got = want.min(max.saturating_sub(now));
            Some(now + got)
        });
        Permits(got)
    }
}

/// Run `f` on a new thread named `name`, for work that lives as long as `f` runs (a walk
/// pulled one batch at a time).
///
/// The thread counts in the process's budget ([`set_max_helpers`], [`helpers_running`]), so
/// other calls get fewer helpers while it runs. Unlike the helpers of [`ordered`], it starts
/// even when the budget is spent: its caller pulls from it and has no other thread to run the
/// work on. `f` runs in the caller's I/O phase; the caller hands it a cancel token if needed.
/// Fails only when the OS cannot start the thread.
pub fn spawn_helper(name: &str, f: impl FnOnce() + Send + 'static) -> std::io::Result<()> {
    // Taken whatever the cap: given back when the thread ends, or here if it does not start.
    HELPERS.fetch_add(1, Ordering::AcqRel);
    let permit = Permits(1);
    let phase = crate::stats::phase();
    std::thread::Builder::new()
        .name(name.into())
        .spawn(move || {
            let _permit = permit;
            crate::stats::set_phase(phase);
            f();
        })
        .map(drop)
}

impl Drop for Permits {
    fn drop(&mut self) {
        HELPERS.fetch_sub(self.0, Ordering::AcqRel);
    }
}

/// A job of a [`Pipeline`]: work that returns `Result<T>`.
type Work<T> = Box<dyn FnOnce() -> Result<T, crate::Error> + Send>;

/// A job of a [`Pipeline`], started or not.
enum Job<T> {
    /// On a helper thread; its own `token`, cancelled when the job is dropped unawaited,
    /// stops its reads.
    Helper { handle: std::thread::JoinHandle<Option<Result<T, crate::Error>>>, token: crate::CancelToken },
    /// Not started: it runs on the thread that waits for it.
    Here(Work<T>),
}

impl<T: Send + 'static> Job<T> {
    /// `work` on a helper of the process's budget, under this thread's I/O phase and call
    /// token and a token of its own; with no helper free (or the thread not started), left
    /// to run where it is waited for.
    fn start(work: Work<T>) -> Job<T> {
        let permit = Permits::take(1);
        if permit.0 == 0 {
            return Job::Here(work);
        }
        let token = crate::CancelToken::new();
        let (phase, call, own) = (crate::stats::phase(), crate::cancel::call_token(), token.clone());
        // Handed back when the thread does not start, to run here.
        let slot = std::sync::Arc::new(Mutex::new(Some(work)));
        let theirs = slot.clone();
        let spawned = std::thread::Builder::new().name("fs-inspect-ahead".into()).spawn(move || {
            let _permit = permit;
            crate::stats::set_phase(phase);
            let work = theirs.lock().unwrap_or_else(PoisonError::into_inner).take()?;
            Some(crate::cancel::with_call_token(Some(own), || crate::cancel::with_bound(call.as_ref(), work)))
        });
        match spawned {
            Ok(handle) => Job::Helper { handle, token },
            Err(e) => match slot.lock().unwrap_or_else(PoisonError::into_inner).take() {
                Some(work) => Job::Here(work),
                None => Job::Here(Box::new(move || Err(crate::Error::io(format!("starting a helper thread: {e}"))))),
            },
        }
    }

    /// Its result: waited for (a helper's panic goes on here), or worked out here.
    fn wait(self) -> Result<T, crate::Error> {
        match self {
            Job::Here(work) => work(),
            Job::Helper { handle, token } => {
                // Joined: the drop below then has nothing to stop.
                let _keep = token;
                match handle.join() {
                    Ok(Some(r)) => r,
                    Ok(None) => Err(crate::Error::io("a helper thread ended without its result")),
                    Err(panic) => std::panic::resume_unwind(panic),
                }
            }
        }
    }
}

/// Jobs pushed in order and handed back in order, with the next ones running ahead on helper
/// threads. It pulls a listing's batches, or a list of nodes' records, from a slow store.
///
/// The first job pushed runs on the thread that waits for it. Each later job starts on a
/// helper from the process's budget ([`set_max_helpers`]) when it is pushed, or runs where it
/// is waited for when no helper is free. Helpers keep the caller's I/O phase and its call's
/// cancel token ([`with_bound`](crate::cancel::with_bound)), and read at their source's queue
/// depth (as with [`HelperReads::Ahead`]).
///
/// Dropping it with jobs in flight cancels their reads and does not wait for them: each
/// helper stops at its next read and its result is dropped.
pub struct Pipeline<T> {
    jobs: std::collections::VecDeque<Job<T>>,
    depth: usize,
}

impl<T> std::fmt::Debug for Pipeline<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pipeline").field("jobs", &self.jobs.len()).field("depth", &self.depth).finish()
    }
}

impl<T: Send + 'static> Pipeline<T> {
    /// A pipeline keeping `depth` jobs in flight (at least 1: none ahead).
    pub fn new(depth: usize) -> Pipeline<T> {
        Pipeline { jobs: std::collections::VecDeque::new(), depth: depth.max(1) }
    }

    /// Whether fewer than `depth` jobs are pending, so another may be pushed.
    pub fn wants(&self) -> bool {
        self.jobs.len() < self.depth
    }

    /// Jobs pushed and not yet handed back.
    pub fn len(&self) -> usize {
        self.jobs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.jobs.is_empty()
    }

    /// Add `work` after the pending jobs. With none pending it runs where it is waited for;
    /// otherwise it starts on a helper now.
    pub fn push(&mut self, work: impl FnOnce() -> Result<T, crate::Error> + Send + 'static) {
        let work: Work<T> = Box::new(work);
        let job = if self.jobs.is_empty() { Job::Here(work) } else { Job::start(work) };
        self.jobs.push_back(job);
    }

    /// The result of the oldest pending job, waited for or run on this thread; `None` when no
    /// job is pending.
    pub fn wait_next(&mut self) -> Option<Result<T, crate::Error>> {
        self.jobs.pop_front().map(Job::wait)
    }
}

impl<T> Drop for Pipeline<T> {
    fn drop(&mut self) {
        for job in &self.jobs {
            if let Job::Helper { token, .. } = job {
                token.cancel();
            }
        }
    }
}

/// How a helper of [`ordered`] reads the runs of its job.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HelperReads {
    /// One run at a time: the helpers are the reads in flight.
    Serial,
    /// At its source's queue depth, for jobs that each read runs of their own (a batch of a
    /// directory's infos): `depth` jobs each keep their own reads in flight. Their own helpers
    /// come from the same budget.
    Ahead,
}

/// Run `work` on each of `jobs` on up to `depth` helper threads, and hand each result to `f`
/// on this thread, in job order.
///
/// `jobs` is pulled as results are handed, at most `depth` ahead, so a lazy iterator makes
/// each job when it is due. Everything runs on this thread when `depth` is under 2, when there
/// is a single job, or when fewer than 2 helpers are free in the process's budget
/// ([`set_max_helpers`]). An error of `f` ends the call: no more jobs start, and the results of
/// those running are dropped. Helpers keep the caller's I/O phase (the label
/// [`IoStats`](crate::IoStats) counts reads under) and its call's cancel token
/// ([`with_bound`](crate::cancel::with_bound)). `reads` says how each helper reads its job's
/// runs.
pub fn ordered<J: Send, R: Send, E>(
    depth: usize,
    reads: HelperReads,
    jobs: impl IntoIterator<Item = J>,
    work: &(dyn Fn(J) -> R + Sync),
    f: &mut dyn FnMut(R) -> Result<(), E>,
) -> Result<(), E> {
    let mut jobs = jobs.into_iter().peekable();
    let Some(first) = jobs.next() else { return Ok(()) };
    let permits = if depth < 2 || jobs.peek().is_none() { Permits(0) } else { Permits::take(depth) };
    if permits.0 < 2 {
        for j in std::iter::once(first).chain(jobs) {
            f(work(j))?;
        }
        return Ok(());
    }
    let depth = permits.0;
    let mut jobs = std::iter::once(first).chain(jobs);
    let phase = crate::stats::phase();
    let call = crate::cancel::call_token();
    let stop = AtomicBool::new(false);
    let (ask, asked) = mpsc::channel::<(usize, J)>();
    let asked = Mutex::new(asked);
    let (done, results) = mpsc::channel::<(usize, R)>();
    std::thread::scope(|s| {
        let (asked, stop) = (&asked, &stop);
        let call = &call;
        let helper = move |done: mpsc::Sender<(usize, R)>| {
            if reads == HelperReads::Serial {
                crate::batch::set_helper();
            }
            crate::stats::set_phase(phase);
            crate::cancel::with_call_token(call.clone(), || {
                loop {
                    let next = asked.lock().unwrap_or_else(PoisonError::into_inner).recv();
                    let Ok((n, job)) = next else { return };
                    if stop.load(Ordering::Relaxed) {
                        return;
                    }
                    if done.send((n, work(job))).is_err() {
                        return;
                    }
                }
            });
        };
        let (mut asked_for, mut helpers, mut handed) = (0usize, 0usize, 0usize);
        let mut arrived: BTreeMap<usize, R> = BTreeMap::new();
        // Owns `ask` and `done`: dropped at the end, it lets the helpers leave.
        let mut ask_more = move |handed: usize| {
            while asked_for < handed + depth {
                let Some(j) = jobs.next() else { break };
                if helpers < depth && helpers <= asked_for - handed {
                    let done = done.clone();
                    s.spawn(move || helper(done));
                    helpers += 1;
                }
                // The helpers wait for asks until `ask` is dropped: the send succeeds.
                let _ = ask.send((asked_for, j));
                asked_for += 1;
            }
            asked_for
        };
        let mut total = ask_more(0);
        let r = loop {
            if handed == total {
                break Ok(());
            }
            let r = match arrived.remove(&handed) {
                Some(r) => r,
                None => match results.recv() {
                    Ok((n, r)) if n == handed => r,
                    Ok((n, r)) => {
                        arrived.insert(n, r);
                        continue;
                    }
                    // Every helper left: none can (a helper's panic ends the scope with it).
                    Err(_) => break Ok(()),
                },
            };
            handed += 1;
            total = ask_more(handed);
            if let Err(e) = f(r) {
                break Err(e);
            }
        };
        stop.store(true, Ordering::Relaxed);
        drop(ask_more);
        r
    })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    /// Held by the tests that count helpers or change the process's budget (`cargo test` runs
    /// a binary's tests on threads of one process).
    static BUDGET: Mutex<()> = Mutex::new(());

    fn budget() -> std::sync::MutexGuard<'static, ()> {
        BUDGET.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The budget set to `max` while it lives, no cap after.
    struct Capped(#[expect(dead_code, reason = "held")] std::sync::MutexGuard<'static, ()>);

    impl Capped {
        fn new(max: usize) -> Capped {
            let g = budget();
            set_max_helpers(Some(max));
            Capped(g)
        }
    }

    impl Drop for Capped {
        fn drop(&mut self) {
            set_max_helpers(None);
        }
    }

    #[test]
    fn helpers_stay_within_the_process_budget() {
        // Other tests of this process may hold helpers too: only what this call runs is
        // pinned down.
        let here = std::thread::current().id();
        let work = |_: u32| std::thread::current().id();
        // Fewer than two free: every job runs on the caller's thread.
        {
            let _c = Capped::new(1);
            ordered::<_, _, ()>(8, HelperReads::Serial, 0..20, &work, &mut |t| {
                assert_eq!(t, here);
                Ok(())
            })
            .unwrap();
        }
        // Three at most for a call asking eight.
        let _c = Capped::new(3);
        let mut threads = std::collections::HashSet::new();
        ordered::<_, _, ()>(8, HelperReads::Serial, 0..40, &work, &mut |t| {
            threads.insert(t);
            Ok(())
        })
        .unwrap();
        assert!(threads.len() <= 3, "{threads:?}");
    }

    #[test]
    fn a_long_lived_helper_counts_in_the_budget_and_is_not_refused() {
        let _c = Capped::new(0);
        // Other tests' helpers may come and go: only a lower bound is pinned down.
        let (go, wait) = mpsc::channel::<()>();
        let (ran, started) = mpsc::channel::<()>();
        spawn_helper("test-helper", move || {
            ran.send(()).unwrap();
            let _ = wait.recv();
        })
        .unwrap();
        started.recv().unwrap();
        assert!(helpers_running() >= 1);
        // The budget spent: an ordered call reads on its own thread.
        let here = std::thread::current().id();
        ordered::<_, _, ()>(4, HelperReads::Serial, 0..4, &|_: u32| std::thread::current().id(), &mut |t| {
            assert_eq!(t, here);
            Ok(())
        })
        .unwrap();
        drop(go);
    }

    #[test]
    fn helpers_read_under_their_caller_s_cancel_token() {
        let _b = budget();
        let token = crate::CancelToken::new();
        token.cancel();
        let work = |_: u32| crate::cancel::check_call().is_err();
        let mut cancelled = Vec::new();
        crate::cancel::with_bound(Some(&token), || {
            ordered::<_, _, ()>(4, HelperReads::Serial, 0..8, &work, &mut |c| {
                cancelled.push(c);
                Ok(())
            })
        })
        .unwrap();
        assert_eq!(cancelled, [true; 8]);
        // Outside the call: not cancelled.
        assert!(crate::cancel::check_call().is_ok());
    }

    #[test]
    fn results_come_in_job_order() {
        for depth in [0, 1, 2, 4, 16] {
            let mut got = Vec::new();
            let work = |j: u64| {
                // Later jobs finish first.
                std::thread::sleep(Duration::from_micros(200 * (20 - j % 20)));
                j * 10
            };
            ordered::<_, _, ()>(depth, HelperReads::Serial, 0..50u64, &work, &mut |r| {
                got.push(r);
                Ok(())
            })
            .unwrap();
            assert_eq!(got, (0..50).map(|j| j * 10).collect::<Vec<_>>(), "depth {depth}");
        }
    }

    #[test]
    fn at_most_depth_jobs_run_ahead() {
        let _b = budget();
        let running = AtomicUsize::new(0);
        let most = AtomicUsize::new(0);
        let started = AtomicUsize::new(0);
        let work = |_: u32| {
            let now = running.fetch_add(1, Ordering::SeqCst) + 1;
            most.fetch_max(now, Ordering::SeqCst);
            started.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(2));
            running.fetch_sub(1, Ordering::SeqCst);
        };
        let mut handed = 0;
        ordered::<_, _, ()>(3, HelperReads::Serial, 0..30, &work, &mut |()| {
            handed += 1;
            // Never more than `depth` started past what was handed.
            assert!(started.load(Ordering::SeqCst) <= handed + 3);
            Ok(())
        })
        .unwrap();
        assert_eq!(handed, 30);
        assert!(most.load(Ordering::SeqCst) <= 3);
        assert!(most.load(Ordering::SeqCst) >= 2);
    }

    #[test]
    fn an_error_stops_the_jobs() {
        let started = AtomicUsize::new(0);
        let work = |j: u32| {
            started.fetch_add(1, Ordering::SeqCst);
            j
        };
        let r = ordered(4, HelperReads::Serial, 0..1000, &work, &mut |j| if j == 5 { Err(j) } else { Ok(()) });
        assert_eq!(r, Err(5));
        assert!(started.load(Ordering::SeqCst) < 20);
    }

    #[test]
    fn helpers_read_as_helpers() {
        let _b = budget();
        let work = |_: u32| crate::batch::is_helper();
        let mut seen = Vec::new();
        ordered::<_, _, ()>(2, HelperReads::Serial, 0..4, &work, &mut |h| {
            seen.push(h);
            Ok(())
        })
        .unwrap();
        assert!(seen.iter().all(|h| *h));
        assert!(!crate::batch::is_helper());
        // A single job runs here: not a helper.
        ordered::<_, _, ()>(2, HelperReads::Serial, 0..1, &work, &mut |h| {
            assert!(!h);
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn reader_helpers_read_at_their_own_queue_depth() {
        let _b = budget();
        let work = |_: u32| (crate::batch::is_helper(), std::thread::current().id());
        let mut seen = Vec::new();
        ordered::<_, _, ()>(2, HelperReads::Ahead, 0..4, &work, &mut |h| {
            seen.push(h);
            Ok(())
        })
        .unwrap();
        assert_eq!(seen.len(), 4);
        assert!(seen.iter().all(|(helper, _)| !helper));
        assert!(seen.iter().all(|(_, t)| *t != std::thread::current().id()));
    }

    #[test]
    fn a_pipeline_hands_its_jobs_in_order_the_first_worked_out_here() {
        let _c = Capped::new(8);
        let here = std::thread::current().id();
        let mut p = Pipeline::new(2);
        assert!(p.wants() && p.is_empty());
        for i in 0..2u32 {
            p.push(move || Ok((i, std::thread::current().id())));
        }
        assert!(!p.wants() && p.len() == 2);
        let (i, t) = p.wait_next().unwrap().unwrap();
        assert_eq!((i, t), (0, here), "the first job runs where it is waited for");
        p.push(|| Ok((2, std::thread::current().id())));
        for want in 1..3 {
            let (i, t) = p.wait_next().unwrap().unwrap();
            assert_eq!(i, want);
            assert_ne!(t, here, "a job after the first runs on a helper");
        }
        assert!(p.wait_next().is_none());
        // An error is handed in its place.
        p.push(|| Err(crate::Error::io("broken")));
        p.push(move || Ok((3, here)));
        assert!(p.wait_next().unwrap().is_err());
        assert_eq!(p.wait_next().unwrap().unwrap().0, 3);
    }

    #[test]
    fn a_pipeline_dropped_cancels_its_helpers_without_waiting() {
        let _c = Capped::new(8);
        let (tx, rx) = mpsc::channel::<bool>();
        let mut p = Pipeline::new(2);
        p.push(|| Ok(()));
        p.push(move || {
            let start = std::time::Instant::now();
            while crate::cancel::check_call().is_ok() && start.elapsed() < Duration::from_secs(10) {
                std::thread::sleep(Duration::from_millis(1));
            }
            let _ = tx.send(crate::cancel::check_call().is_err());
            Ok(())
        });
        let start = std::time::Instant::now();
        drop(p);
        assert!(start.elapsed() < Duration::from_secs(5), "the drop did not wait");
        assert!(rx.recv_timeout(Duration::from_secs(10)).unwrap(), "the helper saw its cancel");
    }
}
