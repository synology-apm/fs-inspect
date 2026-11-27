//! Verifying a volume's file system ([`Volume::verify`]): every checksum it keeps computed,
//! every copy of a structure that has copies checked, every directory listed and every node
//! read; with [`VerifyOptions::data`], every file's content read too.
//!
//! The file system is opened again for it, with a [`FindingSink`] that collects what is wrong
//! as [`Finding`]s with where it is. Damage is a finding and the verification goes on; a
//! failure (an I/O error, a cancel) stops it ([`VerifyReport::stopped`]).
//!
//! A structure with copies passes when one copy is right ([`Outcome::Recovered`] for each
//! wrong one); the verification passes when nothing is [`Outcome::Damaged`].
//!
//! Below the file systems, [`DiskSet::verify`] checks what holds the volumes: each disk's
//! container (VHD, VHDX) and GPT, each slot's volume-manager metadata (LVM, md).
//!
//! Only checksums, copies and reading: not the consistency between structures (link counts,
//! a bitmap against what is allocated), as a file system checker does.
use crate::CancelToken;
use fs_inspect_core::FindingExt;
pub use fs_inspect_core::{Finding, FindingKind, FindingSite, FindingSiteKind, Outcome, StructureKind};

use crate::device::window;
use crate::recovery::View;
use crate::set::DiskSet;
use crate::volume::Volume;
use crate::walk::{Step, Visit, Visitor, WalkOptions, walk};
use fs_inspect_core::Scope;
use fs_inspect_core::ns::{Namespace, NodeId, NodeKind, StreamId, Want};
use fs_inspect_core::{Checksums, Diagnostics, Error, ErrorKind, FindingSink, Integrity, Result, Site, VerifyScope};
use serde::Serialize;
use std::collections::{BTreeMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

/// Findings a report keeps, at most, by default.
pub const MAX_FINDINGS: usize = 10_000;

/// How a volume is verified ([`Volume::verify`]).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VerifyOptions {
    /// Read every file's content too: where the file system keeps checksums of data (btrfs,
    /// ZFS, a sealed APFS volume) they are computed; elsewhere a read error is found.
    pub data: bool,
    /// Findings kept, at most; past it they are counted ([`VerifyReport::dropped`]).
    pub max_findings: usize,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        VerifyOptions { data: false, max_findings: MAX_FINDINGS }
    }
}

fs_inspect_core::with_setters! { VerifyOptions {
    data / with_data: bool,
    max_findings / with_max_findings: usize,
} }

/// How many structures of a kind a verification checked.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Counts {
    pub structures: u64,
    /// Bytes of them, where counted (file data).
    pub bytes: u64,
}

/// What stopped a verification before its end. Serialized as its error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
#[non_exhaustive]
pub struct Stopped {
    /// The error it stopped at.
    pub error: Error,
}

/// What a verification found.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct VerifyReport {
    /// Nothing is [`Outcome::Damaged`]: every structure (and, with
    /// [`VerifyOptions::data`], all data) reads right from at least one copy.
    pub passed: bool,
    /// Findings with [`Outcome::Damaged`], kept or not.
    pub damaged: u64,
    /// Findings with [`Outcome::Recovered`], kept or not.
    pub recovered: u64,
    /// Structures checked, by kind.
    pub checked: BTreeMap<StructureKind, Counts>,
    /// In the order found; each once.
    pub findings: Vec<Finding>,
    /// Findings past [`VerifyOptions::max_findings`], not kept.
    pub dropped: u64,
    /// Structures of this volume this verification does not check, by kind: which of them
    /// (`"of encrypted volumes"`; several apart with `"; "`).
    pub not_covered: BTreeMap<StructureKind, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stopped: Option<Stopped>,
}

/// Collects a verification's findings: each once, up to the most kept.
#[derive(Debug)]
struct Collector {
    max: usize,
    /// Damaged findings handed in, kept or not: whether a step found its own damage is told
    /// by the count changing (a wrong copy beside a right one does not count: the step may
    /// still fail when no copy is right).
    damaged_count: AtomicU64,
    state: Mutex<State>,
}

/// What tells findings apart: structure, offset, id, site, kind.
type Seen = (StructureKind, Option<u64>, Option<u64>, Option<FindingSite>, FindingKind);

#[derive(Debug, Default)]
struct State {
    seen: HashSet<Seen>,
    report: VerifyReport,
}

impl Collector {
    fn new(max: usize) -> Collector {
        Collector { max, damaged_count: AtomicU64::new(0), state: Mutex::default() }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn count(&self) -> u64 {
        self.damaged_count.load(Ordering::Relaxed)
    }

    /// The report, `stopped` by what stopped the verification if anything.
    fn finish(&self, stopped: Option<Error>) -> VerifyReport {
        let mut r = std::mem::take(&mut self.state().report);
        r.stopped = stopped.map(|error| Stopped { error });
        r.passed = r.damaged == 0;
        r
    }

    fn add_bytes(&self, structure: StructureKind, bytes: u64) {
        let mut s = self.state();
        let c = s.report.checked.entry(structure).or_default();
        c.structures += 1;
        c.bytes += bytes;
    }
}

impl FindingSink for Collector {
    fn finding(&self, f: Finding) {
        let mut s = self.state();
        if !s.seen.insert((f.structure, f.offset, f.id, f.site, f.kind)) {
            return;
        }
        match f.outcome {
            Outcome::Damaged => {
                s.report.damaged += 1;
                self.damaged_count.fetch_add(1, Ordering::Relaxed);
            }
            Outcome::Recovered => s.report.recovered += 1,
            _ => {}
        }
        if s.report.findings.len() < self.max {
            s.report.findings.push(f);
        } else {
            s.report.dropped += 1;
        }
    }

    fn checked(&self, structure: StructureKind, bytes: u64) {
        self.add_bytes(structure, bytes);
    }

    fn not_covered(&self, structure: StructureKind, which: &str) {
        let mut s = self.state();
        let have = s.report.not_covered.entry(structure).or_default();
        if !have.split("; ").any(|w| w == which) {
            if !have.is_empty() {
                have.push_str("; ");
            }
            have.push_str(which);
        }
    }
}

impl Volume {
    /// Verify the volume's file system as `opts` say (see [`crate::verify`]). `Err` only when
    /// the volume has no file system to verify (a raw volume: `Unsupported`); what stops a
    /// verification part way is in the report ([`VerifyReport::stopped`]), a cancel (of
    /// `cancel` or of the set's token) too.
    pub fn verify(&self, opts: &VerifyOptions, cancel: Option<&CancelToken>) -> Result<VerifyReport> {
        fs_inspect_io::cancel::with_bound(cancel, || {
            let sink = Arc::new(Collector::new(opts.max_findings));
            let dyn_sink: Arc<dyn FindingSink> = sink.clone();
            // The structures as they are on disk; the files as recovery leaves them (a log replayed
            // in memory: the same instance when there is none).
            let opened = self.reopen(View::OnDisk, Checksums::Verify, Some(dyn_sink.clone())).and_then(|fs| {
                let Some(fs) = fs else { return Ok(None) };
                let files = match self.recovery()?.replayed() {
                    Some(_) => {
                        self.reopen(View::Recovered, Checksums::Verify, Some(dyn_sink))?.unwrap_or_else(|| fs.clone())
                    }
                    None => fs.clone(),
                };
                Ok(Some((fs, files)))
            });
            let stopped = match opened {
                Ok(None) => return Err(Error::unsupported(format!("verifying {}", self.info().fs.kind))),
                Ok(Some((fs, files))) => run(&sink, &fs, &files, opts).err(),
                Err(e) => {
                    if e.scope() == Scope::Unit {
                        let site = Site::new(StructureKind::FileSystem);
                        let msg = format!("cannot be opened: {e}");
                        sink.finding(Finding::new(&site, FindingKind::Unreadable, Outcome::Damaged, msg));
                    }
                    Some(e)
                }
            };
            Ok(sink.finish(stopped))
        })
    }
}

impl DiskSet {
    /// Verify what holds the set's volumes (see [`crate::verify`]): every device's container
    /// (a VHD's footer and its copy, a VHDX's headers and region tables) and GPT (both
    /// headers and their partition arrays), every volume's LVM label and metadata areas and
    /// md superblock. A finding's [`site`](Finding::site) is the device, or the volume
    /// ([`DiskSet::volumes`]) whose volume-manager metadata it is; its offset is in that device.
    /// The file systems are not verified: [`Volume::verify`] does each. A cancel (of `cancel` or of
    /// the set's token) stops it, as the report's `stopped` says.
    pub fn verify(&self, opts: &VerifyOptions, cancel: Option<&CancelToken>) -> Result<VerifyReport> {
        fs_inspect_io::cancel::with_bound(cancel, || {
            let sink = Arc::new(Collector::new(opts.max_findings));
            let stopped = self.verify_layers(&sink).err();
            Ok(sink.finish(stopped))
        })
    }

    fn verify_layers(&self, sink: &Arc<Collector>) -> Result<()> {
        let (l, w) = self.wired()?;
        let at = |site: FindingSite| {
            let stamp: Arc<dyn FindingSink> = Arc::new(Stamp { sink: sink.clone(), site });
            Integrity::new(Checksums::Verify, Diagnostics::default()).verifying(stamp)
        };
        // One device read per device of the layout, in its order.
        for (d, &origin) in w.devices.iter().zip(&l.origins) {
            let integrity = at(FindingSite::Device(origin));
            fs_inspect_disk::verify(d.disk(), &integrity)?;
            let ss = d.info_here()?.sector_size.unwrap_or(512);
            fs_inspect_disk::verify_gpt(&**d.source(), u64::from(ss), &integrity)?;
        }
        for (k, s) in l.slots.iter().enumerate() {
            let site = match l.volume_of_slot.get(&k) {
                Some(&v) if s.claim.is_none() => FindingSite::Volume(v),
                _ => FindingSite::Device(l.origins[s.device]),
            };
            let src = window(w.devices[s.device].source(), s.offset, s.length)?;
            fs_inspect_volmgr::verify_slot(&*src, s.offset, s.claim.is_some(), &at(site))?;
        }
        Ok(())
    }
}

/// Hands findings on to a [`Collector`], placed at `site`.
#[derive(Debug)]
struct Stamp {
    sink: Arc<Collector>,
    site: FindingSite,
}

impl FindingSink for Stamp {
    fn finding(&self, mut f: Finding) {
        f.site = Some(self.site);
        self.sink.finding(f);
    }

    fn checked(&self, structure: StructureKind, bytes: u64) {
        self.sink.checked(structure, bytes);
    }

    fn not_covered(&self, structure: StructureKind, which: &str) {
        self.sink.not_covered(structure, which);
    }
}

/// The driver's own checks of `fs` (on disk), then every node through the namespace of `files`
/// (as recovery leaves the volume).
fn run(
    sink: &Collector,
    fs: &Arc<dyn fs_inspect_core::Filesystem>,
    files: &Arc<dyn fs_inspect_core::Filesystem>,
    opts: &VerifyOptions,
) -> Result<()> {
    fs.verify(&VerifyScope::default().with_data(opts.data))?;
    let Some(ns) = files.clone().namespace() else { return Ok(()) };
    let mut v = Walk { sink, ns: &ns, data: opts.data, files: HashSet::new(), mark: 0 };
    for root in ns.roots()? {
        let before = sink.count();
        if let Err(e) = ns.node_info(root.node, Want::ALL) {
            v.damage(before, StructureKind::Root, Some(root.node), e)?;
            continue;
        }
        let wopts = WalkOptions::default().with_want(Want::ALL);
        walk(&ns, root.node, (), &wopts, &mut v)?;
    }
    Ok(())
}

/// Visits every entry: its node read whole, a file's content with [`VerifyOptions::data`].
struct Walk<'a> {
    sink: &'a Collector,
    ns: &'a Arc<dyn Namespace>,
    data: bool,
    /// Files whose content was read (a hard link's other names are not read again).
    files: HashSet<fs_inspect_core::ns::NodeId>,
    /// The finding count after the last entry: what listing a directory found since.
    mark: u64,
}

impl Walk<'_> {
    /// `e` from reading `what`: damage is a finding (unless the read reported its own since
    /// `before`), and the walk goes on; content not on the volume (a cloud file) is not
    /// covered; anything else stops it.
    fn damage(&self, before: u64, what: StructureKind, node: Option<NodeId>, e: Error) -> Result<()> {
        if e.kind() == ErrorKind::ContentUnavailable {
            self.sink.not_covered(StructureKind::FileData, "cloud files' content not on the volume");
            return Ok(());
        }
        let found = |kind, outcome, e: Error| {
            let mut f = Finding::new(&Site::new(what), kind, outcome, e.to_string());
            f.site = node.map(FindingSite::Node);
            self.sink.finding(f);
        };
        if e.kind() == ErrorKind::Unsupported {
            found(FindingKind::Unsupported, Outcome::Unknown, e);
            return Ok(());
        }
        if e.scope() != Scope::Unit {
            return Err(e);
        }
        if self.sink.count() == before {
            found(FindingKind::Unreadable, Outcome::Damaged, e);
        }
        Ok(())
    }

    /// Every byte of `stream` of `node` read.
    fn read(&self, node: fs_inspect_core::ns::NodeId, stream: StreamId) -> Result<u64> {
        let r = self.ns.clone().open(node, stream)?;
        let mut buf = vec![0u8; 1 << 20];
        let mut at = 0u64;
        while at < r.len() {
            let want = usize::try_from((r.len() - at).min(buf.len() as u64)).unwrap_or(buf.len());
            let got = r.read_at(at, &mut buf[..want])?;
            if got == 0 {
                break;
            }
            at += got as u64;
        }
        Ok(at)
    }
}

impl Visitor<()> for Walk<'_> {
    fn entry(&mut self, visit: Visit<'_, ()>) -> Result<Step<()>> {
        let step = self.visit(visit);
        self.mark = self.sink.count();
        step
    }

    fn dir_failed(&mut self, dir: &(), error: Error) -> Result<()> {
        let _ = dir;
        self.damage(self.mark, StructureKind::Directory, None, error)
    }
}

impl Walk<'_> {
    fn visit(&mut self, visit: Visit<'_, ()>) -> Result<Step<()>> {
        let node = visit.entry.node;
        let before = self.mark;
        let info = match visit.info {
            Some(Ok(i)) => i,
            Some(Err(e)) => {
                self.damage(before, StructureKind::Node, Some(node), e)?;
                return Ok(Step::Next);
            }
            None => return Ok(Step::Next),
        };
        self.sink.add_bytes(StructureKind::Node, 0);
        // Each facet read whole: its own error is the node's damage (a facet the driver does
        // not give, `Unsupported`, is nothing found).
        let facets = [
            info.xattrs.as_ref().and_then(|r| r.as_ref().err()),
            info.security.as_ref().and_then(|r| r.as_ref().err()),
            info.link.as_ref().and_then(|r| r.as_ref().err()),
            info.streams.as_ref().and_then(|r| r.as_ref().err()),
            info.names.as_ref().and_then(|r| r.as_ref().err()),
        ];
        for e in facets.into_iter().flatten().filter(|e| e.kind() != ErrorKind::Unsupported) {
            self.damage(before, StructureKind::Node, Some(node), e.clone())?;
        }
        match info.stat.kind {
            NodeKind::Dir => {
                self.sink.add_bytes(StructureKind::Directory, 0);
                return Ok(Step::Enter(()));
            }
            NodeKind::File if self.data && self.files.insert(node) => {
                let streams: Vec<StreamId> = match &info.streams {
                    Some(Ok(s)) => s.iter().map(|s| s.id).collect(),
                    _ => vec![StreamId::MAIN],
                };
                for s in streams {
                    let before = self.sink.count();
                    match self.read(node, s) {
                        Ok(n) => self.sink.add_bytes(StructureKind::FileData, n),
                        Err(e) => self.damage(before, StructureKind::FileData, Some(node), e)?,
                    }
                }
            }
            _ => {}
        }
        Ok(Step::Next)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn finding(structure: StructureKind, at: u64, outcome: Outcome) -> Finding {
        Finding::new(&Site::new(structure).at(at), FindingKind::Mismatch, outcome, "x")
    }

    #[test]
    fn findings_are_kept_once_up_to_the_most() {
        let c = Collector::new(2);
        for f in [
            finding(StructureKind::ExtInode, 1, Outcome::Damaged),
            finding(StructureKind::ExtInode, 1, Outcome::Damaged),
            finding(StructureKind::ExtInode, 2, Outcome::Recovered),
            finding(StructureKind::ExtSuperblock, 1, Outcome::Damaged),
        ] {
            c.finding(f);
        }
        let r = &c.state().report;
        assert_eq!((r.findings.len(), r.dropped, r.damaged, r.recovered), (2, 1, 2, 1));
    }

    #[test]
    fn a_wrong_copy_does_not_hide_a_read_that_failed() {
        let c = Collector::new(10);
        let ns: Arc<dyn Namespace> = Arc::new(crate::testns::MemNs::default());
        let w = Walk { sink: &c, ns: &ns, data: false, files: HashSet::new(), mark: 0 };
        let before = c.count();
        c.finding(finding(StructureKind::ExtSuperblock, 1, Outcome::Recovered));
        w.damage(before, StructureKind::FileData, Some(NodeId::new(0, 7)), Error::corrupt("no copy holds")).unwrap();
        assert_eq!(c.state().report.damaged, 1);
        // Damage the read reported itself is not reported again.
        let before = c.count();
        c.finding(finding(StructureKind::ZfsBlock, 9, Outcome::Damaged));
        w.damage(before, StructureKind::FileData, Some(NodeId::new(0, 8)), Error::corrupt("mismatch")).unwrap();
        assert_eq!(c.state().report.damaged, 2);
        // A failure stops; content not on the volume is not covered.
        assert!(w.damage(c.count(), StructureKind::FileData, None, Error::cancelled()).is_err());
        w.damage(c.count(), StructureKind::FileData, None, Error::new(ErrorKind::ContentUnavailable, "cloud")).unwrap();
        assert_eq!(c.state().report.not_covered.len(), 1);
    }
}
