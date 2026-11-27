//! Output files and the JSON lines common to the commands.

use fs_inspect::ByteRange;
use std::io::{BufWriter, Write};
use std::path::Path;

/// Run `f` on the output (`path`, written atomically, or stdout).
pub fn with_output(path: Option<&Path>, f: impl FnOnce(&mut dyn Write) -> anyhow::Result<()>) -> anyhow::Result<()> {
    match path {
        Some(p) => {
            let mut a = fs_inspect_host::atomic::AtomicFile::create(p)?;
            f(&mut a)?;
            Ok(a.commit()?)
        }
        None => {
            let mut out = BufWriter::new(std::io::stdout().lock());
            f(&mut out)?;
            Ok(out.flush()?)
        }
    }
}

pub fn range_line(out: &mut dyn Write, ty: &str, r: ByteRange) -> anyhow::Result<()> {
    Ok(writeln!(out, "{{\"type\":\"{ty}\",\"offset\":{},\"length\":{}}}", r.offset, r.length)?)
}

/// Write `ranges` as lines of type `ty`; their total length.
pub fn write_ranges(out: &mut dyn Write, ty: &str, ranges: &[ByteRange]) -> anyhow::Result<u64> {
    for r in ranges {
        range_line(out, ty, *r)?;
    }
    Ok(ranges.iter().map(|r| r.length).sum())
}

/// A volume's state ([`fs_inspect::Volume::state`]) as JSON: `consistency` (`consistent`,
/// `inconsistent`, `unknown`) and `replay` (`not_needed`, `done`, `disabled`, `unsupported`,
/// `failed`), with what explains them.
pub fn state_json(state: &fs_inspect::VolumeState) -> serde_json::Value {
    use fs_inspect::{NotReplayed, StoreKind, VolumeState};
    use serde_json::json;
    match state {
        VolumeState::Clean => json!({ "consistency": "consistent", "replay": "not_needed" }),
        VolumeState::Recovered(s) => json!({
            "consistency": "inconsistent",
            "replay": "done",
            "log": s.log,
            "records": s.records,
            "patched_bytes": s.patched_bytes,
            "store": match s.store {
                StoreKind::File => "file",
                StoreKind::Memory => "memory",
                _ => "other",
            },
            "stored_bytes": s.stored_bytes,
        }),
        VolumeState::Inconsistent { why, allocation_covered, not_replayed } => {
            let mut v = json!({
                "consistency": "inconsistent",
                "why": why,
                "allocation_covered": allocation_covered,
            });
            match not_replayed {
                NotReplayed::Disabled => v["replay"] = json!("disabled"),
                NotReplayed::Unsupported => v["replay"] = json!("unsupported"),
                NotReplayed::Failed { error } => {
                    v["replay"] = json!("failed");
                    v["replay_error"] = json!(error);
                }
                _ => v["replay"] = json!("unsupported"),
            }
            v
        }
        VolumeState::Unknown(why) => json!({ "consistency": "unknown", "replay": "unsupported", "why": why }),
        _ => json!({ "consistency": "unknown", "replay": "unsupported" }),
    }
}
