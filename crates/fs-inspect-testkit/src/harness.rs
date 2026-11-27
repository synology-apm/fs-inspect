//! A test binary of its own (`harness = false`) whose tests are known only at run time: one per
//! entry of the fixture manifests ([`crate::manifest`]). It takes the arguments of libtest that
//! `cargo test` and `cargo nextest` pass (filters, `--exact`, `--skip`, `--list --format terse`,
//! `--ignored`, `--test-threads`) and reports the same way, so each test is listed, filtered
//! and run on its own like a `#[test]`.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

/// One test: its name and what it runs (a panic fails it).
pub struct Trial {
    pub name: String,
    pub run: Box<dyn FnOnce() + Send>,
}

impl Trial {
    pub fn new(name: impl Into<String>, run: impl FnOnce() + Send + 'static) -> Trial {
        Trial { name: name.into(), run: Box::new(run) }
    }
}

#[derive(Default)]
struct Args {
    list: bool,
    exact: bool,
    ignored: bool,
    threads: Option<usize>,
    filters: Vec<String>,
    skip: Vec<String>,
}

fn parse(args: impl Iterator<Item = String>) -> Args {
    let mut a = Args::default();
    let mut it = args.peekable();
    while let Some(arg) = it.next() {
        let (flag, inline) = match arg.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f.to_string(), Some(v.to_string())),
            _ => (arg.clone(), None),
        };
        let value = |it: &mut std::iter::Peekable<_>| inline.clone().or_else(|| it.next());
        match flag.as_str() {
            "--list" => a.list = true,
            "--exact" => a.exact = true,
            "--ignored" => a.ignored = true,
            "--test-threads" => a.threads = value(&mut it).and_then(|v| v.parse().ok()),
            "--skip" => a.skip.extend(value(&mut it)),
            "--format" | "--color" | "--logfile" | "-Z" | "--report-time" => {
                let _ = value(&mut it);
            }
            f if f.starts_with('-') => {} // --nocapture, --quiet, --include-ignored, --show-output ...
            _ => a.filters.push(arg),
        }
    }
    a
}

impl Args {
    fn selects(&self, name: &str) -> bool {
        let hit = |f: &String| if self.exact { name == f } else { name.contains(f.as_str()) };
        (self.filters.is_empty() || self.filters.iter().any(hit)) && !self.skip.iter().any(hit)
    }
}

/// Run the selected `trials` as the command line asks and exit: 0 when all pass, 101 when one
/// fails (as libtest). None is ignored, so `--ignored` selects none.
pub fn main(trials: Vec<Trial>) -> ! {
    let args = parse(std::env::args().skip(1));
    let total = trials.len();
    let chosen: Vec<Trial> = trials.into_iter().filter(|t| !args.ignored && args.selects(&t.name)).collect();
    if args.list {
        for t in &chosen {
            println!("{}: test", t.name);
        }
        std::process::exit(0);
    }
    println!("\nrunning {} tests", chosen.len());
    let threads = args
        .threads
        .or_else(|| std::env::var("RUST_TEST_THREADS").ok().and_then(|v| v.parse().ok()))
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(1, usize::from))
        .max(1);
    let filtered = total - chosen.len();
    let names: Vec<String> = chosen.iter().map(|t| t.name.clone()).collect();
    let queue = Mutex::new(chosen.into_iter().map(Some).collect::<Vec<_>>());
    let next = AtomicUsize::new(0);
    let failed = Mutex::new(Vec::new());
    std::thread::scope(|s| {
        for _ in 0..threads.min(names.len()).max(1) {
            s.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(t) = queue.lock().unwrap_or_else(|e| e.into_inner()).get_mut(i).and_then(Option::take)
                    else {
                        break;
                    };
                    let ok = catch_unwind(AssertUnwindSafe(t.run)).is_ok();
                    println!("test {} ... {}", t.name, if ok { "ok" } else { "FAILED" });
                    if !ok {
                        failed.lock().unwrap_or_else(|e| e.into_inner()).push(t.name);
                    }
                }
            });
        }
    });
    let failed = failed.into_inner().unwrap_or_else(|e| e.into_inner());
    if !failed.is_empty() {
        println!("\nfailures:");
        for f in &failed {
            println!("    {f}");
        }
    }
    println!(
        "\ntest result: {}. {} passed; {} failed; 0 ignored; 0 measured; {filtered} filtered out\n",
        if failed.is_empty() { "ok" } else { "FAILED" },
        names.len() - failed.len(),
        failed.len()
    );
    std::process::exit(if failed.is_empty() { 0 } else { 101 })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Args {
        parse(s.split_whitespace().map(str::to_string))
    }

    #[test]
    fn filters_as_libtest() {
        let a = args("--exact ext/linux/ext4 --nocapture");
        assert!(a.selects("ext/linux/ext4") && !a.selects("ext/linux/ext4-1k"));
        let a = args("ext4 --skip 1k --test-threads=2");
        assert!(a.selects("ext/linux/ext4") && !a.selects("ext/linux/ext4-1k"));
        assert_eq!(a.threads, Some(2));
        let a = args("--list --format terse --ignored");
        assert!(a.list && a.ignored && a.filters.is_empty());
    }
}
