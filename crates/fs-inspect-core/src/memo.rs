//! What a reader remembers of what it read:
//!
//! - [`Lru`]: the bounded memo of decoded structures read again (tree nodes, blocks, bitmaps),
//!   least recently used first out. Each entry is charged a cost in bytes, so the bound is
//!   memory, not a count; all of them together stay within the process's
//!   [cache budget](set_cache_budget).
//! - [`ReadLog`]: the structures read while it records (a change tracker dates them).

use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// A log of the structures a reader (and its clones, which share the log) read while it
/// records. A log made with [`Default`] records only within [`record`](Self::record); one made
/// with [`recording`](Self::recording) records from the start.
#[derive(Debug)]
pub struct ReadLog<T>(Arc<Mutex<Option<Vec<T>>>>);

impl<T> Clone for ReadLog<T> {
    fn clone(&self) -> Self {
        ReadLog(self.0.clone())
    }
}

impl<T> Default for ReadLog<T> {
    fn default() -> Self {
        ReadLog(Arc::new(Mutex::new(None)))
    }
}

impl<T: Clone> ReadLog<T> {
    pub fn recording() -> Self {
        ReadLog(Arc::new(Mutex::new(Some(Vec::new()))))
    }

    fn lock(&self) -> MutexGuard<'_, Option<Vec<T>>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Log the structure `item` makes, when recording (`item` is not called otherwise).
    pub fn push_with(&self, item: impl FnOnce() -> T) {
        if let Some(v) = self.lock().as_mut() {
            v.push(item());
        }
    }

    /// Log `items` (read earlier, counted as read again), when recording.
    pub fn extend(&self, items: &[T]) {
        if let Some(v) = self.lock().as_mut() {
            v.extend_from_slice(items);
        }
    }

    /// `f` of what was logged so far.
    pub fn with<R>(&self, f: impl FnOnce(&[T]) -> R) -> R {
        f(self.lock().as_deref().unwrap_or_default())
    }

    /// Run `f`, returning what was logged meanwhile. Within an outer recording, it goes to
    /// that too.
    pub fn record<R>(&self, f: impl FnOnce() -> R) -> (R, Vec<T>) {
        let outer = self.lock().replace(Vec::new());
        let r = f();
        let mut lock = self.lock();
        let seen = lock.take().unwrap_or_default();
        if let Some(mut outer) = outer {
            outer.extend_from_slice(&seen);
            *lock = Some(outer);
        }
        (r, seen)
    }
}

/// A least-recently-used map holding entries of at most `capacity` bytes in all, and within
/// the process's [cache budget](set_cache_budget) together with every other one.
pub struct Lru<K, V> {
    shard: Arc<Shard<K, V>>,
}

impl<K: std::fmt::Debug, V> std::fmt::Debug for Lru<K, V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let i = self.shard.lock();
        f.debug_struct("Lru").field("len", &i.entries.len()).field("bytes", &i.bytes).finish()
    }
}

/// One cache: its entries, and when it was last used (for the budget's order).
struct Shard<K, V> {
    inner: Mutex<Inner<K, V>>,
    last_used: AtomicU64,
}

struct Inner<K, V> {
    entries: HashMap<K, Entry<V>>,
    /// Keys by the tick of their last use, oldest first.
    order: BTreeMap<u64, K>,
    tick: u64,
    bytes: usize,
    capacity: usize,
}

struct Entry<V> {
    value: V,
    tick: u64,
    cost: usize,
}

impl<K, V> Shard<K, V> {
    fn lock(&self) -> MutexGuard<'_, Inner<K, V>> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl<K: Hash + Eq, V> Inner<K, V> {
    /// Drop the least recently used entry; its cost (0: none left).
    fn drop_oldest(&mut self) -> usize {
        let Some((_, k)) = self.order.pop_first() else { return 0 };
        let cost = self.entries.remove(&k).map_or(0, |e| e.cost);
        self.bytes -= cost;
        budget::release(cost);
        cost
    }
}

impl<K, V> Drop for Shard<K, V> {
    fn drop(&mut self) {
        let bytes = self.inner.get_mut().unwrap_or_else(PoisonError::into_inner).bytes;
        budget::release(bytes);
    }
}

impl<K: Hash + Eq + Send + 'static, V: Send + 'static> budget::Evict for Shard<K, V> {
    fn last_used(&self) -> u64 {
        self.last_used.load(Ordering::Relaxed)
    }
    fn evict(&self, want: usize) -> usize {
        let Ok(mut i) = self.inner.try_lock() else { return 0 };
        let mut freed = 0;
        while freed < want {
            match i.drop_oldest() {
                0 if i.entries.is_empty() => break,
                n => freed += n,
            }
        }
        freed
    }
}

impl<K: Hash + Eq + Clone + Send + 'static, V: Clone + Send + 'static> Lru<K, V> {
    pub fn new(capacity: usize) -> Self {
        let shard = Arc::new(Shard {
            inner: Mutex::new(Inner { entries: HashMap::new(), order: BTreeMap::new(), tick: 0, bytes: 0, capacity }),
            last_used: AtomicU64::new(budget::tick()),
        });
        budget::register(Arc::downgrade(&shard) as std::sync::Weak<dyn budget::Evict>);
        Lru { shard }
    }

    /// The value of `key`, now the most recently used.
    pub fn get(&mut self, key: &K) -> Option<V> {
        self.shard.last_used.store(budget::tick(), Ordering::Relaxed);
        let mut i = self.shard.lock();
        i.tick += 1;
        let tick = i.tick;
        let e = i.entries.get_mut(key)?;
        let old = std::mem::replace(&mut e.tick, tick);
        let value = e.value.clone();
        let k = i.order.remove(&old)?;
        i.order.insert(tick, k);
        Some(value)
    }

    /// Take `key`'s value out, giving its bytes back.
    pub fn remove(&mut self, key: &K) -> Option<V> {
        let mut i = self.shard.lock();
        let e = i.entries.remove(key)?;
        i.order.remove(&e.tick);
        i.bytes -= e.cost;
        budget::release(e.cost);
        Some(e.value)
    }

    /// Drop every entry, giving their bytes back.
    pub fn clear(&mut self) {
        let mut i = self.shard.lock();
        while !i.order.is_empty() {
            i.drop_oldest();
        }
    }

    /// Whether `key` is held (its use order unchanged).
    pub fn contains(&self, key: &K) -> bool {
        self.shard.lock().entries.contains_key(key)
    }

    /// Hold `value` for `key` at `cost` bytes, dropping the least recently used entries past
    /// the capacity, and past the process's budget the least recently used entries of the
    /// caches least recently used. An entry costing more than the whole capacity (or budget)
    /// is not kept.
    pub fn insert(&mut self, key: K, value: V, cost: usize) {
        self.shard.last_used.store(budget::tick(), Ordering::Relaxed);
        let mut i = self.shard.lock();
        if let Some(old) = i.entries.remove(&key) {
            i.order.remove(&old.tick);
            i.bytes -= old.cost;
            budget::release(old.cost);
        }
        if cost > i.capacity || budget::too_big(cost) {
            return;
        }
        i.tick += 1;
        let tick = i.tick;
        i.order.insert(tick, key.clone());
        i.entries.insert(key, Entry { value, tick, cost });
        i.bytes += cost;
        budget::take(cost);
        while i.bytes > i.capacity && i.drop_oldest() > 0 {}
        // Past the budget: the other caches first (this one was just used), then this one's
        // oldest entries but the new one.
        if budget::over() > 0 {
            budget::reclaim(Arc::as_ptr(&self.shard).cast());
            while budget::over() > 0 && i.entries.len() > 1 && i.drop_oldest() > 0 {}
        }
    }

    pub fn len(&self) -> usize {
        self.shard.lock().entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.shard.lock().entries.is_empty()
    }

    /// Bytes held.
    pub fn bytes(&self) -> usize {
        self.shard.lock().bytes
    }
}

/// Cap at `bytes` what all driver caches of the process hold together (decoded tree nodes,
/// blocks and bitmaps of every open volume). `None` (the default) sets no cap beyond each
/// cache's own ([`DriverContext::max_cache_bytes`](crate::DriverContext::max_cache_bytes));
/// `Some(0)` keeps nothing cached.
///
/// Past the cap, the caches used least recently give up their oldest entries first, so an
/// idle volume makes room for a busy one. Lowering the cap frees the excess at once, except
/// in a cache in use, which frees it the next time it is filled.
pub fn set_cache_budget(bytes: Option<u64>) {
    budget::set(bytes.unwrap_or(u64::MAX));
}

/// Bytes the driver caches of the process hold now.
pub fn cache_bytes() -> u64 {
    budget::held()
}

/// The process's cache budget: what every [`Lru`] holds, counted together.
mod budget {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Mutex, PoisonError, Weak};

    /// A cache that can give up entries to the budget.
    pub(super) trait Evict: Send + Sync {
        fn last_used(&self) -> u64;
        /// Drop at least `want` bytes of the oldest entries if it can now (not when it is in
        /// use); the bytes dropped.
        fn evict(&self, want: usize) -> usize;
    }

    /// The cap; `u64::MAX`: none.
    static BUDGET: AtomicU64 = AtomicU64::new(u64::MAX);
    static HELD: AtomicU64 = AtomicU64::new(0);
    static TICK: AtomicU64 = AtomicU64::new(0);
    static CACHES: Mutex<Vec<Weak<dyn Evict>>> = Mutex::new(Vec::new());

    pub(super) fn tick() -> u64 {
        TICK.fetch_add(1, Ordering::Relaxed)
    }

    pub(super) fn register(c: Weak<dyn Evict>) {
        let mut all = CACHES.lock().unwrap_or_else(PoisonError::into_inner);
        all.retain(|w| w.strong_count() > 0);
        all.push(c);
    }

    pub(super) fn take(bytes: usize) {
        HELD.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub(super) fn release(bytes: usize) {
        HELD.fetch_sub(bytes as u64, Ordering::Relaxed);
    }

    pub(super) fn held() -> u64 {
        HELD.load(Ordering::Relaxed)
    }

    /// Bytes past the budget (0 within it, or with none).
    pub(super) fn over() -> u64 {
        held().saturating_sub(BUDGET.load(Ordering::Relaxed))
    }

    /// Whether one entry of `cost` bytes is more than the whole budget.
    pub(super) fn too_big(cost: usize) -> bool {
        cost as u64 > BUDGET.load(Ordering::Relaxed)
    }

    pub(super) fn set(bytes: u64) {
        BUDGET.store(bytes, Ordering::Relaxed);
        reclaim(std::ptr::null());
    }

    /// Free what is past the budget from the caches least recently used, oldest first, but
    /// `skip` (the cache asking, whose lock it holds).
    pub(super) fn reclaim(skip: *const ()) {
        if over() == 0 {
            return;
        }
        let mut all: Vec<_> =
            CACHES.lock().unwrap_or_else(PoisonError::into_inner).iter().filter_map(Weak::upgrade).collect();
        all.sort_by_key(|c| c.last_used());
        for c in all {
            let want = over();
            if want == 0 {
                break;
            }
            if std::sync::Arc::as_ptr(&c).cast::<()>() != skip {
                c.evict(usize::try_from(want).unwrap_or(usize::MAX));
            }
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn read_log_records_nested() {
        let log = ReadLog::<u32>::default();
        log.push_with(|| 1);
        let ((), outer) = log.record(|| {
            log.push_with(|| 2);
            let ((), inner) = log.record(|| log.extend(&[3, 4]));
            assert_eq!(inner, [3, 4]);
        });
        assert_eq!(outer, [2, 3, 4]);
        assert_eq!(log.with(<[u32]>::len), 0);

        let log = ReadLog::recording();
        log.clone().push_with(|| 5);
        assert_eq!(log.with(<[u32]>::to_vec), [5]);
    }

    #[test]
    fn drops_the_least_recently_used() {
        let mut c = Lru::new(30);
        c.insert(1, 'a', 10);
        c.insert(2, 'b', 10);
        c.insert(3, 'c', 10);
        assert_eq!(c.get(&1), Some('a'));
        c.insert(4, 'd', 10);
        assert!(!c.contains(&2) && c.contains(&1) && c.contains(&3) && c.contains(&4));
        assert_eq!(c.bytes(), 30);

        c.insert(3, 'C', 5);
        assert_eq!((c.get(&3), c.bytes()), (Some('C'), 25));
        c.insert(5, 'e', 31);
        assert!(!c.contains(&5));
        c.insert(6, 'f', 20);
        assert_eq!(c.len(), 2);
        assert!(c.contains(&3) && c.contains(&6));

        assert_eq!((c.remove(&3), c.remove(&3), c.bytes()), (Some('C'), None, 20));
        c.insert(7, 'g', 0);
        c.clear();
        assert_eq!((c.len(), c.bytes()), (0, 0));
    }
}
