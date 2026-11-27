//! `--profile FILE`: where a command's time goes. Every read of the disks is timed
//! ([`IoStats::traced`]) and labelled with the `tracing` span it was made in (the scan phase or
//! the structure being read); every span of the library is timed too. When the command ends the
//! spans and reads are written to FILE as a Chrome trace (open it in Perfetto or
//! `chrome://tracing`), and a summary goes to stderr as one JSON line (`"type":"profile"`):
//! wall time, how much of it the disks were busy, the gaps between reads (what the scan did
//! while no read was in flight, by phase), each phase's time, and the read sizes.
//! docs/contributing/profiling.md describes how to read it.

use anyhow::Context as _;
use fs_inspect::IoStats;
use fs_inspect::io::ReadEvent;
use fs_inspect::unstable::io::thread_slot;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};
use tracing::Subscriber;
use tracing::span::Id;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;

/// One time a span was entered and left.
#[derive(Debug, Clone, Copy)]
struct SpanEvent {
    name: &'static str,
    start: Duration,
    end: Duration,
    thread: u32,
    /// Spans it was entered inside of.
    depth: u32,
}

/// The spans left so far, timed from the reads' epoch.
#[derive(Debug)]
struct Recorder {
    epoch: Instant,
    spans: Mutex<Vec<SpanEvent>>,
}

/// The `tracing` layer that times the library's spans into a [`Profile`].
#[derive(Debug)]
pub struct SpanLayer(Arc<Recorder>);

/// When a span was entered (a stack: a span may be entered again inside itself).
struct Entered(Vec<Instant>);

impl<S> tracing_subscriber::Layer<S> for SpanLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_enter(&self, id: &Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else { return };
        let mut ext = span.extensions_mut();
        match ext.get_mut::<Entered>() {
            Some(e) => e.0.push(Instant::now()),
            None => ext.insert(Entered(vec![Instant::now()])),
        }
    }

    fn on_exit(&self, id: &Id, ctx: Context<'_, S>) {
        let end = self.0.epoch.elapsed();
        let Some(span) = ctx.span(id) else { return };
        let start = span.extensions_mut().get_mut::<Entered>().and_then(|e| e.0.pop());
        let Some(start) = start else { return };
        let depth = u32::try_from(span.scope().skip(1).count()).unwrap_or(u32::MAX);
        let start = start.saturating_duration_since(self.0.epoch);
        let event = SpanEvent { name: span.name(), start, end, thread: thread_slot(), depth };
        self.0.spans.lock().unwrap_or_else(PoisonError::into_inner).push(event);
    }
}

/// A command being profiled: its reads' counters (give them to the disks it opens) and spans.
#[derive(Debug)]
pub struct Profile {
    path: PathBuf,
    stats: Arc<IoStats>,
    rec: Arc<Recorder>,
}

impl Profile {
    /// A profile written to `path`, and the layer that records its spans.
    pub fn new(path: &Path) -> (Profile, SpanLayer) {
        let stats = IoStats::traced();
        let epoch = stats.epoch().unwrap_or_else(Instant::now);
        let rec = Arc::new(Recorder { epoch, spans: Mutex::new(Vec::new()) });
        (Profile { path: path.to_path_buf(), stats, rec: rec.clone() }, SpanLayer(rec))
    }

    /// The counters the disks read into.
    pub fn stats(&self) -> Arc<IoStats> {
        self.stats.clone()
    }

    /// Write the trace file and return the summary.
    pub fn finish(&self) -> anyhow::Result<Value> {
        let wall = self.rec.epoch.elapsed();
        let mut reads = self.stats.reads_traced();
        reads.sort_by_key(|r| r.start);
        let mut spans = self.rec.spans.lock().unwrap_or_else(PoisonError::into_inner).clone();
        spans.sort_by_key(|s| (s.thread, s.start, s.depth));
        write_trace(&self.path, &spans, &reads)
            .with_context(|| format!("writing the profile {}", self.path.display()))?;
        Ok(summary(&self.path, wall, &spans, &reads))
    }
}

fn micros(d: Duration) -> f64 {
    d.as_secs_f64() * 1e6
}

fn millis(d: Duration) -> f64 {
    (d.as_secs_f64() * 1e6).round() / 1e3
}

/// The Chrome trace event format: one complete event (`"ph":"X"`) per span and per read; the
/// reads of a thread on their own track, named after it.
fn write_trace(path: &Path, spans: &[SpanEvent], reads: &[ReadEvent]) -> std::io::Result<()> {
    let mut w = BufWriter::new(std::fs::File::create(path)?);
    w.write_all(b"{\"displayTimeUnit\":\"ms\",\"traceEvents\":[\n")?;
    let mut first = true;
    let mut put = |w: &mut BufWriter<std::fs::File>, v: Value| -> std::io::Result<()> {
        if !first {
            w.write_all(b",\n")?;
        }
        first = false;
        serde_json::to_writer(&mut *w, &v).map_err(std::io::Error::other)
    };
    let mut threads: Vec<u32> = spans.iter().map(|s| s.thread).chain(reads.iter().map(|r| r.thread)).collect();
    threads.sort_unstable();
    threads.dedup();
    for t in threads {
        let name = |what: &str| json!({"ph": "M", "name": "thread_name", "pid": 1, "args": {"name": what}});
        let mut phases = name(&format!("thread {t}"));
        phases["tid"] = json!(t);
        put(&mut w, phases)?;
        let mut io = name(&format!("thread {t} reads"));
        io["tid"] = json!(READ_TRACK + t);
        put(&mut w, io)?;
    }
    for s in spans {
        put(
            &mut w,
            json!({"name": s.name, "cat": "phase", "ph": "X", "pid": 1, "tid": s.thread,
                   "ts": micros(s.start), "dur": micros(s.end.saturating_sub(s.start))}),
        )?;
    }
    for r in reads {
        put(
            &mut w,
            json!({"name": phase_name(r.phase), "cat": "read", "ph": "X", "pid": 1, "tid": READ_TRACK + r.thread,
                   "ts": micros(r.start), "dur": micros(r.took),
                   "args": {"offset": r.offset, "length": r.length, "ok": r.ok}}),
        )?;
    }
    w.write_all(b"\n]}\n")?;
    w.flush()
}

/// The track number of a thread's reads: its spans' plus this.
const READ_TRACK: u32 = 1000;

fn phase_name(p: &str) -> &str {
    if p.is_empty() { "(no span)" } else { p }
}

/// Upper bounds of the gap classes, in microseconds; the last class is everything longer.
const GAP_CLASSES: [u64; 5] = [10, 100, 1_000, 10_000, 100_000];

/// Upper bounds of the read size classes, in bytes; the last class is everything larger.
const SIZE_CLASSES: [u64; 7] = [4 << 10, 16 << 10, 64 << 10, 256 << 10, 1 << 20, 4 << 20, 16 << 20];

/// Per phase: the time its spans took, and the reads made in it.
#[derive(Default)]
struct Phase {
    calls: u64,
    total: Duration,
    /// `total` less the spans entered inside it.
    own: Duration,
    reads: u64,
    bytes: u64,
    read: Duration,
    /// The gaps that ended with a read of this phase: what ran between the previous read and it.
    gap: Duration,
}

fn summary(path: &Path, wall: Duration, spans: &[SpanEvent], reads: &[ReadEvent]) -> Value {
    let mut phases: BTreeMap<&str, Phase> = BTreeMap::new();
    let mut top = Duration::ZERO;
    for (i, s) in spans.iter().enumerate() {
        let took = s.end.saturating_sub(s.start);
        // Its children: the spans one deeper, on its thread, inside it (sorted by start).
        let inner: Duration = spans[i + 1..]
            .iter()
            .take_while(|c| c.thread == s.thread && c.start < s.end)
            .filter(|c| c.depth == s.depth + 1)
            .map(|c| c.end.saturating_sub(c.start))
            .sum();
        let p = phases.entry(s.name).or_default();
        p.calls += 1;
        p.total += took;
        p.own += took.saturating_sub(inner);
        if s.depth == 0 {
            top += took;
        }
    }
    // The disks were busy while any read was in flight; a gap is time with none.
    let (mut busy, mut gaps_total) = (Duration::ZERO, Duration::ZERO);
    let mut gap_classes = [(0u64, Duration::ZERO); GAP_CLASSES.len() + 1];
    let mut size_classes = [(0u64, 0u64); SIZE_CLASSES.len() + 1];
    let mut idle_from = Duration::ZERO;
    let mut bytes = 0u64;
    for r in reads {
        let end = r.start + r.took;
        let gap = r.start.saturating_sub(idle_from);
        busy += end.saturating_sub(r.start.max(idle_from));
        idle_from = idle_from.max(end);
        let p = phases.entry(r.phase).or_default();
        p.reads += 1;
        p.bytes += r.length;
        p.read += r.took;
        p.gap += gap;
        gaps_total += gap;
        let us = gap.as_micros();
        let g = GAP_CLASSES.iter().position(|&c| us < u128::from(c)).unwrap_or(GAP_CLASSES.len());
        gap_classes[g].0 += 1;
        gap_classes[g].1 += gap;
        let z = SIZE_CLASSES.iter().position(|&c| r.length <= c).unwrap_or(SIZE_CLASSES.len());
        size_classes[z].0 += 1;
        size_classes[z].1 += r.length;
        bytes += r.length;
    }
    let tail = wall.saturating_sub(idle_from);
    let mut by_own: Vec<(&str, Phase)> = phases.into_iter().collect();
    by_own.sort_by_key(|(_, p)| std::cmp::Reverse(p.own));
    let phases: Vec<Value> = by_own
        .iter()
        .map(|(name, p)| {
            json!({"name": phase_name(name), "calls": p.calls, "total_ms": millis(p.total), "own_ms": millis(p.own),
                   "reads": p.reads, "bytes": p.bytes, "read_ms": millis(p.read), "gap_ms": millis(p.gap)})
        })
        .collect();
    let gaps: Vec<Value> = gap_classes
        .iter()
        .enumerate()
        .map(|(i, (n, d))| json!({"under_us": GAP_CLASSES.get(i), "count": n, "ms": millis(*d)}))
        .collect();
    let sizes: Vec<Value> = size_classes
        .iter()
        .enumerate()
        .map(|(i, (n, b))| json!({"up_to": SIZE_CLASSES.get(i), "count": n, "bytes": b}))
        .collect();
    let ratio =
        |d: Duration| if wall.is_zero() { 0.0 } else { (d.as_secs_f64() / wall.as_secs_f64() * 1e4).round() / 1e4 };
    json!({
        "type": "profile",
        "trace": path.display().to_string(),
        "wall_ms": millis(wall),
        "reads": reads.len(),
        "bytes": bytes,
        "busy_ms": millis(busy),
        "io_busy": ratio(busy),
        "gap_ms": millis(gaps_total),
        "after_last_read_ms": millis(tail),
        "outside_spans_ms": millis(wall.saturating_sub(top)),
        "gaps": gaps,
        "sizes": sizes,
        "phases": phases,
    })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    fn read(start: u64, took: u64, len: u64, phase: &'static str) -> ReadEvent {
        <ReadEvent as fs_inspect::unstable::io::ReadEventExt>::new(ms(start), ms(took), 0, len, 1, phase, true)
    }

    #[test]
    fn summary_splits_busy_time_gaps_and_phases() {
        let spans = [
            SpanEvent { name: "scan.files", start: ms(0), end: ms(100), thread: 1, depth: 0 },
            SpanEvent { name: "ntfs.walk", start: ms(10), end: ms(60), thread: 1, depth: 1 },
        ];
        // Busy 10..20, 30..40 (gap 10), 35..45 overlaps (no gap), 80..90 (gap 35).
        let reads = [
            read(10, 10, 4096, "ntfs.walk"),
            read(30, 10, 65536, "ntfs.walk"),
            read(35, 10, 4096, "ntfs.walk"),
            read(80, 10, 1 << 20, "scan.files"),
        ];
        let s = summary(Path::new("t.json"), ms(120), &spans, &reads);
        assert_eq!(s["busy_ms"], 35.0);
        assert_eq!(s["gap_ms"], 10.0 + 10.0 + 35.0);
        assert_eq!(s["after_last_read_ms"], 30.0);
        assert_eq!(s["outside_spans_ms"], 20.0);
        let phase = |n: &str| s["phases"].as_array().unwrap().iter().find(|p| p["name"] == n).unwrap().clone();
        assert_eq!(phase("scan.files")["own_ms"], 50.0);
        assert_eq!(phase("ntfs.walk")["reads"], 3);
        assert_eq!(phase("scan.files")["gap_ms"], 35.0);
        assert_eq!(s["sizes"][0]["count"], 2);
    }
}
