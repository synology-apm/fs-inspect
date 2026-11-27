//! Change tracking for an external log device: the log is written only at its head, so what
//! changed since the previous snapshot is the window between the previous and the current
//! head ([`stamp::log_window`](super::stamp::log_window)). Without its file system (the size
//! of the log is not known) or a previous head, the whole log is dirty.

use crate::format::logdev::XfsLogFs;
use fs_inspect_change::{
    Continuity, Degrade, DegradeCode, DriverExtra, FileState, FsScanner, Identity, Opened, Result, ScanContext,
    TypedScanner,
};
use fs_inspect_core::range::list;
use fs_inspect_core::{ByteRange, Filesystem};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub(super) fn open(fs: Arc<dyn Filesystem>) -> Result<Box<dyn FsScanner>> {
    Ok(Box::new(LogScanner { fs: Opened::<XfsLogFs>::new(fs)? }))
}

#[derive(Debug)]
struct LogScanner {
    fs: Opened<XfsLogFs>,
}

/// The `FS_STATE` blob.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct State {
    /// Bytes of the log (the whole device when its file system was not given).
    bytes: u64,
    /// LSN of the last log record (`None`: not known).
    head_lsn: Option<u64>,
}

impl LogScanner {
    fn state_value(&self) -> State {
        State { bytes: self.fs.info().size, head_lsn: self.fs.log_state().and_then(|s| s.head_lsn()) }
    }
}

impl TypedScanner for LogScanner {
    type State = State;
    const STATE_VERSION: u32 = 1;
    const STATE_CODE: DegradeCode = super::codes::LOG_STATE;

    fn identity(&self) -> Identity {
        Identity::new(fs_inspect_core::FsKind::XfsLog, self.fs.info().uuid.clone(), 512)
    }

    fn current(&self) -> Result<State> {
        Ok(self.state_value())
    }

    fn continuity(&self, prev: &State, cur: &State, _offline: bool) -> Continuity {
        if prev.bytes != cur.bytes {
            return Continuity::Broken(Degrade::new(
                super::codes::LOG_SIZE,
                format!("the log was {} bytes, now {}", prev.bytes, cur.bytes),
            ));
        }
        if let (Some(p), Some(c)) = (prev.head_lsn, cur.head_lsn)
            && c < p
        {
            return Continuity::Broken(Degrade::new(
                super::codes::LOG_REWIND,
                format!("log head LSN went back from {p:#x} to {c:#x} (older snapshot restored or log reformatted)"),
            ));
        }
        Continuity::Ok
    }

    fn scan_files(
        &self,
        cx: &ScanContext<'_>,
        prev: Option<&State>,
        _cur: &mut State,
        _emit: &mut dyn FnMut(FileState),
    ) -> Result<DriverExtra> {
        let mut extra = DriverExtra::default();
        let Some(area) = self.fs.area() else {
            extra.degraded.push(Degrade::new(
                super::codes::LOG_ALONE,
                "the file system of this log was not given with it; the whole log counts as changed",
            ));
            return Ok(extra);
        };
        let (Some(p), Some(c)) = (prev.and_then(|p| p.head_lsn), self.state_value().head_lsn) else {
            return Ok(extra);
        };
        let used = cx.allocated();
        if p == c {
            extra.tracked = used;
        } else if let Some(window) = super::stamp::log_window(p, c, area.bytes / 512) {
            let w: Vec<ByteRange> = window.iter().map(|&(b, n)| ByteRange::new(b * 512, n * 512)).collect();
            extra.tracked = list::subtract(&used, &w);
        }
        Ok(extra)
    }
}
