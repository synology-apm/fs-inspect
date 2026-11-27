//! The options every command takes, and the frame a command runs in: logging, `--profile`,
//! `--io-stats`, Ctrl-C, `--diagnostics`, the exit code.

use crate::diag::write_diagnostics;
use crate::profile::Profile;
use clap::Args;
use fs_inspect::Named;
use fs_inspect::{CancelToken, DiskSet, ErrorKind, IoStats, OpenOptions};
use serde_json::json;
use std::path::PathBuf;
use std::process::ExitCode;

/// The exit code of `verify` when it found damage (not an error of the library).
pub const EXIT_DAMAGED: u8 = 15;

/// The process exit code of a command that fails with an error of `kind`. The other codes are
/// 0 (success), 1 (an error of no kind) and 15 (`verify` found damage). The error table of
/// `docs/design/reference.md` lists the code of each kind.
pub const fn kind_exit_code(kind: ErrorKind) -> u8 {
    match kind {
        ErrorKind::InvalidArgument => 2,
        ErrorKind::NotFound => 3,
        ErrorKind::Format => 4,
        ErrorKind::Unsupported => 5,
        ErrorKind::Corrupt => 6,
        ErrorKind::Io => 7,
        ErrorKind::Cancelled => 8,
        ErrorKind::Limit => 9,
        ErrorKind::ContentUnavailable => 14,
        ErrorKind::PermissionDenied => 16,
        ErrorKind::IsADirectory => 17,
        ErrorKind::Unavailable => 18,
        ErrorKind::NoSpace => 19,
        ErrorKind::DataMissing => 20,
    }
}

/// What an exit code of `kind` means, for the `--help` text: the kind's summary, said for
/// someone at a terminal.
const fn kind_exit_text(kind: ErrorKind) -> &'static str {
    match kind {
        ErrorKind::Io => "I/O error",
        ErrorKind::Format => "unrecognized format",
        ErrorKind::Corrupt => "corrupt",
        ErrorKind::Unsupported => "unsupported",
        ErrorKind::NotFound => "not found",
        ErrorKind::InvalidArgument => "invalid argument",
        ErrorKind::Cancelled => "cancelled (Ctrl-C)",
        ErrorKind::Limit => "a safety limit against hostile input hit",
        ErrorKind::ContentUnavailable => "content not on the volume",
        ErrorKind::PermissionDenied => "permission denied",
        ErrorKind::IsADirectory => "is a directory",
        ErrorKind::Unavailable => "unavailable (members missing)",
        ErrorKind::NoSpace => "no space left to write",
        ErrorKind::DataMissing => "data missing from the source",
    }
}

/// The exit codes, for the `--help` text: success, every [`ErrorKind`]'s, and `verify`'s.
pub fn exit_codes() -> String {
    let mut codes: Vec<(u8, &str)> = ErrorKind::ALL.iter().map(|&k| (kind_exit_code(k), kind_exit_text(k))).collect();
    codes.push((EXIT_DAMAGED, "damage found (verify)"));
    codes.sort_unstable();
    let mut out = String::from("0 ok (also when stdout is closed early)");
    for (code, what) in codes {
        out.push_str(&format!(", {code} {what}"));
    }
    out
}

/// Options of every command.
#[derive(Args, Debug)]
pub struct GlobalArgs {
    /// Log level for messages on stderr: error, warn, info, debug or trace.
    #[arg(long, global = true, default_value = "warn", value_name = "LEVEL")]
    pub log: String,
    /// Write what the library worked around (damaged structures, exclusions not applied, ...)
    /// as JSON Lines to this file, `-` for stderr. Written only when the command succeeds.
    #[arg(long, global = true, value_name = "FILE")]
    pub diagnostics: Option<PathBuf>,
    /// Count the reads of the disks and write them to stderr as one JSON line when the
    /// command ends: `{"type":"io_stats","reads":N,"bytes":N,"largest":N}`.
    #[arg(long, global = true)]
    pub io_stats: bool,
    /// Time every read of the disks and every phase of the library, write them to this file as
    /// a Chrome trace (Perfetto, chrome://tracing), and a summary to stderr as one JSON line:
    /// `{"type":"profile","wall_ms":N,"io_busy":R,"gaps":[..],"phases":[..],..}`. See
    /// docs/contributing/profiling.md.
    #[arg(long, global = true, value_name = "FILE")]
    pub profile: Option<PathBuf>,
    /// Most reads in flight at once on the disks (1-64): an image file's handles. The scan
    /// itself stays one thread; reads it has listed ahead go out together.
    #[arg(long, global = true, default_value_t = 4, value_name = "N", value_parser = clap::value_parser!(u16).range(1..=64))]
    pub queue_depth: u16,
    /// Read a volume a crash left with a log to replay (a crash-consistent snapshot) as it is
    /// on disk: its log not replayed in memory for the map, browsing and verification.
    #[arg(long, global = true)]
    pub no_replay: bool,
    /// Where a replay of a volume's log keeps what it holds (temporary files, in proportion to
    /// the log; the volume's metadata): not on a volume being read. Default: the system's
    /// temporary directory.
    #[arg(long, global = true, value_name = "DIR")]
    pub scratch_dir: Option<PathBuf>,
}

/// The exit code for an error (listed in the `--help` text).
pub fn exit_code(e: &anyhow::Error) -> u8 {
    if e.downcast_ref::<crate::verify::Damaged>().is_some() {
        return EXIT_DAMAGED;
    }
    e.downcast_ref::<fs_inspect::Error>().map_or(1, |e| kind_exit_code(e.kind()))
}

/// `e` and its causes, joined by ": ". A library error's message already includes its
/// source's message, so a cause already in the text is left out (anyhow's `{:#}` would repeat
/// it at every level).
pub fn error_chain(e: &anyhow::Error) -> String {
    let mut out = String::new();
    for cause in e.chain() {
        let s = cause.to_string();
        if !out.contains(&s) {
            if !out.is_empty() {
                out.push_str(": ");
            }
            out.push_str(&s);
        }
    }
    out
}

/// The token Ctrl-C cancels: the token of every set the command opens and of every other call
/// that reads.
pub fn interrupt() -> &'static CancelToken {
    static TOKEN: std::sync::OnceLock<CancelToken> = std::sync::OnceLock::new();
    TOKEN.get_or_init(CancelToken::new)
}

/// Run `cmd` with the image options `g` asks for; the disks it returns give the diagnostics.
/// Its error becomes the exit code (a closed stdout is success).
pub fn run(g: &GlobalArgs, cmd: impl FnOnce(&OpenOptions) -> anyhow::Result<Option<DiskSet>>) -> ExitCode {
    use tracing_subscriber::Layer as _;
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::util::SubscriberInitExt as _;
    let (profile, spans) = g.profile.as_deref().map(Profile::new).unzip();
    let filter = tracing_subscriber::EnvFilter::try_new(&g.log).unwrap_or_else(|_| "warn".into());
    // The profile sees every span of the libraries, whatever the log level.
    let library_spans = tracing_subscriber::filter::filter_fn(|m| m.is_span() && m.target().starts_with("fs_inspect"));
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr).with_filter(filter))
        .with(spans.map(|l| l.with_filter(library_spans)))
        .init();
    // Ctrl-C cancels: reads stop, an unfinished output file is removed, the exit code is 8.
    let io_stats = match &profile {
        Some(p) => Some(p.stats()),
        None => g.io_stats.then(IoStats::new),
    };
    let opts = OpenOptions::default()
        .with_io_stats(io_stats)
        .with_queue_depth(std::num::NonZeroUsize::new(usize::from(g.queue_depth)))
        .with_replay(!g.no_replay)
        .with_scratch_dir(g.scratch_dir.clone());
    let cancel = interrupt().clone();
    if let Err(e) = ctrlc::set_handler(move || cancel.cancel()) {
        tracing::debug!(error = %e, "no Ctrl-C handler");
    }
    let r = cmd(&opts).and_then(|set| match (&g.diagnostics, set) {
        (Some(to), Some(set)) => {
            let dropped = set.diagnostics_dropped();
            if dropped > 0 {
                tracing::warn!("{dropped} more diagnostics over the cap were not written (they are in the log)");
            }
            write_diagnostics(to, &set.diagnostics())
        }
        (Some(to), None) => write_diagnostics(to, &[]),
        (None, _) => Ok(()),
    });
    if let Some(p) = &profile {
        match p.finish() {
            Ok(summary) => eprintln!("{summary}"),
            Err(e) => eprintln!("error: {}", error_chain(&e)),
        }
    }
    if let Some(stats) = opts.io_stats.as_ref().filter(|_| g.io_stats) {
        let c = stats.counts();
        eprintln!("{}", json!({"type": "io_stats", "reads": c.reads, "bytes": c.bytes, "largest": c.largest}));
    }
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            if e.downcast_ref::<std::io::Error>().is_some_and(|io| io.kind() == std::io::ErrorKind::BrokenPipe) {
                return ExitCode::SUCCESS;
            }
            eprintln!("error: {}", error_chain(&e));
            ExitCode::from(exit_code(&e))
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    /// The error table of docs/design/reference.md has one row per kind, and its exit code
    /// column matches [`kind_exit_code`].
    #[test]
    fn the_documented_exit_codes_are_the_code() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/design/reference.md");
        let text = std::fs::read_to_string(&path).unwrap();
        let mut rows = std::collections::HashMap::new();
        for line in text.lines() {
            let cells: Vec<&str> = line.split('|').map(str::trim).collect();
            if cells.len() < 6 || !cells[1].starts_with('`') || !cells[3].starts_with("`FS_INSPECT_") {
                continue;
            }
            let exit: u8 = cells[4].parse().expect(line);
            assert!(rows.insert(cells[1].trim_matches('`').to_string(), exit).is_none(), "{line}");
        }
        for &k in ErrorKind::ALL {
            assert_eq!(rows.remove(&format!("{k:?}")), Some(kind_exit_code(k)), "{k:?}");
        }
        assert!(rows.is_empty(), "rows for no kind: {rows:?}");
        let mut codes: Vec<u8> = ErrorKind::ALL.iter().map(|&k| kind_exit_code(k)).collect();
        codes.push(EXIT_DAMAGED);
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), ErrorKind::ALL.len() + 1, "every exit code once");
    }
}
