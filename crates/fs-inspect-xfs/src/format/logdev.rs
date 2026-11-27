//! An external log device: a volume that holds nothing but the log of an XFS file system on
//! another volume (`mkfs.xfs -l logdev=`). Its record headers name the file system
//! (`h_fs_uuid`); the size of the log is in that file system's superblock (`sb_logblocks`),
//! read when the data device is among the volumes given with the log device. Used: the log,
//! or the whole device when the data device was not given.

use crate::format::log::{LogArea, LogState, device_uuid, is_log_device};
use crate::format::sb::{SB_MIN_BYTES, Superblock};
use fs_inspect_core::FsInfoExt;
use fs_inspect_core::{
    ByteRange, Confidence, Consistency, DiagCode, DriverContext, Error, Filesystem, FsInfo, FsKind, RangeCursor,
    Result, Sniff,
};
use fs_inspect_io::DynSource;
use std::sync::{Arc, OnceLock};

/// `Low`: the start of a log has no magic of its own at sector 0, so any file system or
/// partition table found there wins.
pub fn probe(s: &Sniff<'_>) -> Option<(FsKind, Confidence)> {
    is_log_device(s.head).then_some((FsKind::XfsLog, Confidence::Low))
}

/// Open the external log device `src`.
pub fn open(src: DynSource, ctx: &DriverContext) -> Result<Arc<dyn Filesystem>> {
    Ok(Arc::new(XfsLogFs::open(src, ctx)?))
}

/// An opened external log device.
#[derive(Debug)]
pub struct XfsLogFs {
    info: FsInfo,
    /// The log (`None`: its file system was not given, so its size is not known).
    area: Option<LogArea>,
    state: OnceLock<Option<LogState>>,
}

impl XfsLogFs {
    /// Open the external log device `src`; its file system is looked for among `ctx.peers`.
    pub fn open(src: DynSource, ctx: &DriverContext) -> Result<Self> {
        let uuid = device_uuid(&src).ok_or_else(|| Error::format("xfs log: no record header at its start"))?;
        // The data device: an XFS volume whose external log names it.
        let sb = ctx.peers.iter().flat_map(|p| p.volumes(FsKind::Xfs)).find_map(|v| {
            let sb = Superblock::parse(&v.read_vec(0, SB_MIN_BYTES).ok()?).ok()?;
            (sb.validate().is_ok() && sb.logstart == 0 && sb.uuid == uuid).then_some(sb)
        });
        let area = sb
            .map(|sb| LogArea { src: src.clone(), offset: 0, bytes: u64::from(sb.logblocks) * sb.bs(), external: true })
            .filter(|a| a.bytes <= src.size());
        if area.is_none() {
            ctx.diagnostics.warn(
                DiagCode::CountedAsUsed,
                "xfs log: the file system it belongs to was not given, so the size of the log is not known; \
                 the whole device counts as used",
            );
        }
        let info = FsInfo::new(
            FsKind::XfsLog,
            512,
            area.as_ref().map_or(src.size(), |a| a.bytes),
            None,
            Some(fs_inspect_core::guid::format_uuid(&uuid)),
        );
        Ok(XfsLogFs { info, area, state: OnceLock::new() })
    }

    /// The log, when its file system was given.
    pub fn area(&self) -> Option<&LogArea> {
        self.area.as_ref()
    }

    /// The state of the log, when its file system was given (read once).
    pub fn log_state(&self) -> Option<&LogState> {
        self.state.get_or_init(|| self.area.as_ref().map(LogArea::inspect)).as_ref()
    }
}

impl fs_inspect_core::sealed::Fs for XfsLogFs {}

impl Filesystem for XfsLogFs {
    fn info(&self) -> &FsInfo {
        &self.info
    }

    /// The log's, as its file system reports it.
    fn consistency(&self) -> Consistency {
        match self.log_state() {
            Some(LogState::Clean { .. }) => Consistency::Clean,
            Some(LogState::Dirty { why, .. }) => Consistency::Inconsistent {
                why: format!("the log holds changes to replay ({why})"),
                allocation_covered: false,
                notes: Vec::new(),
            },
            Some(LogState::Missing) | None => Consistency::Unknown("the file system of this log was not given".into()),
        }
    }

    fn allocated(self: Arc<Self>) -> Result<Box<dyn RangeCursor>> {
        Ok(Box::new(fs_inspect_core::cursor::VecCursor::new(vec![ByteRange::new(0, self.info.size)])))
    }
}
