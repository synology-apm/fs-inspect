//! `--diagnostics`.

use anyhow::Context as _;
use fs_inspect::Diagnostic;
use fs_inspect::Named;
use serde::Serialize;
use std::io::{BufWriter, Write};
use std::path::Path;

/// One line of `--diagnostics`.
#[derive(Serialize, Debug)]
pub struct DiagnosticRecord<'a> {
    pub severity: &'static str,
    pub code: &'static str,
    pub message: &'a str,
    pub volume: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logical: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk: Option<u32>,
}

pub fn write_diagnostics(to: &Path, all: &[Diagnostic]) -> anyhow::Result<()> {
    let mut out: Box<dyn Write> = if to == Path::new("-") {
        Box::new(std::io::stderr().lock())
    } else {
        Box::new(BufWriter::new(std::fs::File::create(to).with_context(|| format!("creating {}", to.display()))?))
    };
    for d in all {
        let r = DiagnosticRecord {
            severity: d.severity.as_str(),
            code: d.code.as_str(),
            message: &d.message,
            volume: d.volume.map(|i| i.0),
            logical: d.logical.as_ref().map(ToString::to_string),
            disk: d.disk.map(|i| i.0),
        };
        serde_json::to_writer(&mut out, &r)?;
        writeln!(out)?;
    }
    out.flush()?;
    Ok(())
}
