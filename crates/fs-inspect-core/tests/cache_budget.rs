//! The process's cache budget over several caches (its own process: the budget is global).
#![allow(clippy::unwrap_used)]

use fs_inspect_core::memo::{Lru, cache_bytes, set_cache_budget};

#[test]
fn caches_share_one_budget_the_least_recently_used_giving_way() {
    let mut idle: Lru<u32, u32> = Lru::new(1000);
    let mut busy: Lru<u32, u32> = Lru::new(1000);
    for k in 0..5 {
        idle.insert(k, k, 100);
    }
    for k in 0..3 {
        busy.insert(k, k, 100);
    }
    assert_eq!((idle.bytes(), busy.bytes(), cache_bytes()), (500, 300, 800));

    // Below what they hold: the idle cache gives up its oldest entries first.
    set_cache_budget(Some(600));
    assert_eq!((idle.bytes(), busy.bytes(), cache_bytes()), (300, 300, 600));
    assert!(!idle.contains(&0) && !idle.contains(&1) && idle.contains(&4));

    // A busy cache filling up takes from the idle one, then from itself.
    for k in 3..7 {
        busy.insert(k, k, 100);
    }
    assert_eq!((idle.bytes(), busy.bytes()), (0, 600));
    busy.insert(7, 7, 100);
    assert_eq!(busy.bytes(), 600);
    assert!(!busy.contains(&0) && busy.contains(&7));

    // An entry bigger than the whole budget is not kept; dropping a cache gives back its bytes.
    busy.insert(8, 8, 700);
    assert!(!busy.contains(&8));
    drop(busy);
    assert_eq!(cache_bytes(), idle.bytes() as u64);

    // No budget: each cache's own capacity only.
    set_cache_budget(None);
    for k in 0..10 {
        idle.insert(k, k, 100);
    }
    assert_eq!(idle.bytes(), 1000);
}
