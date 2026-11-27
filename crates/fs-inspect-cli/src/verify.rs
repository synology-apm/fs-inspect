//! `verify`: a volume's file system checked whole ([`fs_inspect::Volume::verify`]), or with
//! `--disks` what holds the volumes ([`fs_inspect::DiskSet::verify`]).

use crate::source::VolumeArgs;
use clap::Args;
use fs_inspect::Named;
use fs_inspect::verify::{MAX_FINDINGS, VerifyOptions, VerifyReport};
use fs_inspect::{DiskSet, OpenOptions};
use serde_json::{Value, json};
use std::io::Write;

/// Arguments of `verify`.
#[derive(Args, Debug)]
pub struct VerifyArgs {
    #[command(flatten)]
    pub volume: VolumeArgs,
    /// Read every file's content too: data checksums where the file system keeps them
    /// (btrfs, ZFS, a sealed APFS volume), read errors elsewhere.
    #[arg(long)]
    pub data: bool,
    /// Findings written, at most; past it they are counted (`dropped`).
    #[arg(long, value_name = "N", default_value_t = MAX_FINDINGS)]
    pub max_findings: usize,
    /// Verify what holds the volumes instead of a file system: each disk's container (VHD,
    /// VHDX) and GPT, each volume's LVM and md metadata. Takes no volume.
    #[arg(long, conflicts_with = "data")]
    pub disks: bool,
}

/// The verification found a structure (or data) no copy of which is right: exit code 15.
#[derive(Debug)]
pub struct Damaged(pub u64);

impl std::fmt::Display for Damaged {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "verification found {} damaged structure(s)", self.0)
    }
}

impl std::error::Error for Damaged {}

/// `verify`: each finding as a JSON line, then a summary line. Exit code 15 when something is
/// damaged (a finding `"outcome": "damaged"`); a copy that is wrong while another is right
/// (`"recovered"`) is written but passes.
pub fn verify(a: &VerifyArgs, opts: &OpenOptions) -> anyhow::Result<Option<DiskSet>> {
    let vo = VerifyOptions::default().with_data(a.data).with_max_findings(a.max_findings);
    if a.disks {
        let s = &a.volume.select;
        anyhow::ensure!(s.volume.is_none() && s.logical.is_none() && s.offset.is_none(), "--disks takes no volume");
        let set = crate::source::open_set(&a.volume.source, opts)?;
        let r = set.verify(&vo, None)?;
        print(&r, "disks")?;
        return done(r, set);
    }
    let (set, vol) = a.volume.open(opts)?;
    let r = vol.verify(&vo, None)?;
    print(&r, vol.info().fs.kind.as_str())?;
    done(r, set)
}

/// Each finding of `r` as a JSON line, then the summary line (`"fs"`: what was verified).
fn print(r: &VerifyReport, what: &str) -> anyhow::Result<()> {
    let mut out = std::io::stdout().lock();
    for f in &r.findings {
        let mut v = serde_json::to_value(f)?;
        if let Value::Object(m) = &mut v {
            m.insert("type".into(), json!("finding"));
        }
        writeln!(out, "{v}")?;
    }
    let mut summary = serde_json::to_value(r)?;
    if let Value::Object(m) = &mut summary {
        m.remove("findings");
        m.insert("type".into(), json!("summary"));
        m.insert("mode".into(), json!("verify"));
        m.insert("fs".into(), json!(what));
    }
    writeln!(out, "{summary}")?;
    out.flush()?;
    Ok(())
}

/// The exit of a verification that found `r`.
fn done(r: VerifyReport, set: DiskSet) -> anyhow::Result<Option<DiskSet>> {
    if !r.passed {
        return Err(Damaged(r.damaged).into());
    }
    if let Some(s) = r.stopped {
        return Err(s.error.into());
    }
    Ok(Some(set))
}
