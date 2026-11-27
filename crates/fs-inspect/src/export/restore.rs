//! Restoring a node's metadata onto a host file ([`FsHandle::restore_metadata`]): the one
//! implementation of it, which a directory export ([`DirSink`](super::DirSink)) applies to
//! each entry it writes.

use super::{Content, NamePolicy};
use crate::CancelToken;
use crate::fs::{FsHandle, NodeKind, Security, Stat, StreamId, Timestamp, Want};
use fs_inspect_core::ns::NodeId;
use fs_inspect_core::{Error, ErrorKind, Name, Result};
use fs_inspect_host::write as host;
use std::path::Path;
use std::time::{Duration, SystemTime};

/// Which of a node's metadata [`FsHandle::restore_metadata`] writes onto a host file.
///
/// A facet the node has but the host cannot represent for it is skipped as
/// [`Unsupported`](ErrorKind::Unsupported) ([`MetadataReport::skipped`]); a facet the node
/// does not have is nothing to write.
///
/// The value holds only the facets defined here: [`from_bits_truncate`](Self::from_bits_truncate)
/// drops other bits (the C API and the Python binding refuse them instead).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct MetaFacets(u32);

impl MetaFacets {
    /// No facet.
    pub const NONE: MetaFacets = MetaFacets(0);
    /// The modification and access times, and the creation time on Windows; a link's own, not
    /// its target's.
    pub const TIMES: MetaFacets = MetaFacets(1);
    /// The host's access bits: the Unix permission bits (with the set-id and sticky bits) on a
    /// Unix host, the read-only, hidden, system, archive and not-indexed attributes on Windows.
    /// A node with only the other kind (Unix bits on Windows, Windows attributes on Unix) is
    /// skipped as unsupported. A symbolic link's own bits are set on macOS and the BSDs; a
    /// Linux link has none, so there is nothing to write.
    pub const MODE: MetaFacets = MetaFacets(1 << 1);
    /// The owner and group: a Unix node's on a Unix host (giving a file away needs root), a
    /// Windows security descriptor's on Windows (another account than the process's own needs
    /// the restore privilege). A refusal is skipped as
    /// [`PermissionDenied`](ErrorKind::PermissionDenied); the other kind of owner as
    /// unsupported.
    pub const OWNER: MetaFacets = MetaFacets(1 << 2);
    /// The extended attributes (Linux, macOS; unsupported on Windows).
    pub const XATTRS: MetaFacets = MetaFacets(1 << 3);
    /// The access control: POSIX ACLs as `system.posix_acl_*` extended attributes on Linux;
    /// a Windows security descriptor's DACL (as it holds it, with its protection from
    /// inheritance) on Windows. Either on another host is unsupported.
    pub const ACL: MetaFacets = MetaFacets(1 << 4);
    /// The named streams (alternate data streams, resource forks): alternate data streams
    /// `dest:NAME` on Windows, extended attributes `user.fsinspect.stream.NAME` on Unix (a
    /// stream larger than 16 MiB is unsupported there).
    pub const STREAMS: MetaFacets = MetaFacets(1 << 5);
    /// Every facet.
    pub const ALL: MetaFacets = MetaFacets((1 << 6) - 1);

    /// Whether every facet of `f` is set.
    pub const fn contains(self, f: MetaFacets) -> bool {
        self.0 & f.0 == f.0
    }

    /// Whether no facet is set.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// These facets but `f`'s.
    #[must_use]
    pub const fn without(self, f: MetaFacets) -> MetaFacets {
        MetaFacets(self.0 & !f.0)
    }

    /// The bits set.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// The facets of `bits` defined here ([`ALL`](Self::ALL)); the others are dropped.
    pub const fn from_bits_truncate(bits: u32) -> MetaFacets {
        MetaFacets(bits & Self::ALL.0)
    }

    /// The name of a single facet, for a note.
    fn name(self) -> &'static str {
        match self {
            Self::TIMES => "times",
            Self::MODE => "mode",
            Self::OWNER => "owner",
            Self::XATTRS => "extended attributes",
            Self::ACL => "ACL",
            Self::STREAMS => "named stream",
            _ => "metadata",
        }
    }
}

impl std::ops::BitOr for MetaFacets {
    type Output = MetaFacets;
    fn bitor(self, o: MetaFacets) -> MetaFacets {
        MetaFacets(self.0 | o.0)
    }
}

impl std::ops::BitOrAssign for MetaFacets {
    fn bitor_assign(&mut self, o: MetaFacets) {
        self.0 |= o.0;
    }
}

/// What [`FsHandle::restore_metadata`] could not write.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct MetadataReport {
    /// Each facet (or named stream) the destination did not take, in the order tried.
    pub skipped: Vec<SkippedFacet>,
}

/// A facet the destination did not take ([`MetadataReport::skipped`]).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SkippedFacet {
    /// The facet: a single one of [`MetaFacets`].
    pub facet: MetaFacets,
    /// The named stream, for [`MetaFacets::STREAMS`]; `None` for the other facets.
    pub stream: Option<Name>,
    /// Why: [`Unsupported`](ErrorKind::Unsupported) where the host or the destination's file
    /// system has no such thing for this node, [`PermissionDenied`](ErrorKind::PermissionDenied)
    /// where it refused, or the host's own error. It says what the host answered, not the
    /// destination's path.
    pub reason: Error,
}

impl SkippedFacet {
    fn new(facet: MetaFacets, reason: Error) -> Self {
        SkippedFacet { facet, stream: None, reason }
    }

    /// As text for an export's note: the facet (and stream) and why.
    pub(crate) fn note(&self) -> String {
        match &self.stream {
            Some(n) => format!("{} {}: {}", self.facet.name(), n.escape(), self.reason),
            None => format!("{}: {}", self.facet.name(), self.reason),
        }
    }
}

impl FsHandle {
    /// Write the metadata `what` names of `node` onto the existing host file, directory or
    /// link `dest` (a link itself, not what it points to): what restoring a file the caller
    /// wrote itself needs, the step a directory export ([`DirSink`](super::DirSink)) takes
    /// after each entry it writes.
    ///
    /// A facet the destination does not take is listed in [`MetadataReport::skipped`], the
    /// others still written: [`Unsupported`](ErrorKind::Unsupported) when the node has it but
    /// the host (or the destination's file system) cannot represent it for this node,
    /// [`PermissionDenied`](ErrorKind::PermissionDenied) when the process may not set it. A
    /// facet the node does not have is nothing to write. [`MetaFacets`] says per facet what
    /// each host takes. The call fails only when the node cannot be read (its stat, extended
    /// attributes, security or named streams) or `dest` does not exist.
    ///
    /// Writing into a directory changes its times: restore a directory's
    /// [`TIMES`](MetaFacets::TIMES) after what it holds is written (and a read-only one's
    /// [`MODE`](MetaFacets::MODE), or a DACL that takes away the process's access, last);
    /// the order is the caller's.
    pub fn restore_metadata(
        &self,
        node: NodeId,
        dest: &Path,
        what: MetaFacets,
        cancel: Option<&CancelToken>,
    ) -> Result<MetadataReport> {
        fs_inspect_io::cancel::with_handle(self.cancel.as_ref(), cancel, || restore(self, node, dest, what))
    }
}

/// A facet read: nothing when the driver keeps none of it.
fn facet<T: Default>(read: Option<Result<T>>) -> Result<T> {
    match read {
        None => Ok(T::default()),
        Some(Err(e)) if e.kind() == ErrorKind::Unsupported => Ok(T::default()),
        Some(r) => r,
    }
}

fn restore(fs: &FsHandle, node: NodeId, dest: &Path, what: MetaFacets) -> Result<MetadataReport> {
    std::fs::symlink_metadata(dest).map_err(|e| Error::file(dest.display(), e))?;
    let mut want = Want::STAT;
    for (f, w) in [
        (MetaFacets::XATTRS, Want::XATTRS),
        (MetaFacets::ACL, Want::SECURITY),
        // A Windows owner is the security descriptor's.
        (MetaFacets::OWNER, Want::SECURITY),
        (MetaFacets::STREAMS, Want::STREAMS),
    ] {
        if what.contains(f) {
            want |= w;
        }
    }
    let info = fs.info(node, want, None)?;
    let mut xattrs = Vec::new();
    for x in facet(info.xattrs)? {
        let v = match x.value {
            Some(v) => Some(v),
            None => fs.read_xattr(node, &x.name, None)?,
        };
        if let Some(v) = v {
            xattrs.push((x.name, v));
        }
    }
    let security = facet(info.security)?;
    let mut readers = Vec::new();
    for s in facet(info.streams)?.into_iter().filter(|s| s.id != StreamId::MAIN) {
        let name = s.name.unwrap_or_else(|| Name::new(""));
        readers.push((name, fs.namespace().clone().open(node, s.id)?));
    }
    let mut streams = Vec::with_capacity(readers.len());
    for (n, r) in &readers {
        streams.push((n.clone(), Content::of(&**r, false, fs.queue_depth(), None)?));
    }
    let meta = Meta { stat: &info.stat, xattrs: &xattrs, security: security.as_ref(), streams: &streams };
    Ok(MetadataReport { skipped: apply(dest, what, &meta)? })
}

/// A node's metadata, read: what [`apply`] writes.
pub(crate) struct Meta<'a> {
    pub stat: &'a Stat,
    pub xattrs: &'a [(Name, Vec<u8>)],
    pub security: Option<&'a Security>,
    pub streams: &'a [(Name, Content<'a>)],
}

/// Windows attributes kept: read-only, hidden, system, archive, not content indexed.
const KEPT_ATTRIBUTES: u32 = 0x1 | 0x2 | 0x4 | 0x20 | 0x2000;

/// The largest named stream kept as an extended attribute.
const MAX_STREAM_XATTR: u64 = super::tar::MAX_INLINE as u64;

fn system_time(t: Timestamp) -> Option<SystemTime> {
    if t.secs >= 0 {
        SystemTime::UNIX_EPOCH.checked_add(Duration::new(t.secs as u64, t.nanos))
    } else {
        SystemTime::UNIX_EPOCH
            .checked_sub(Duration::from_secs(t.secs.unsigned_abs()))?
            .checked_add(Duration::from_nanos(u64::from(t.nanos)))
    }
}

/// The bytes of an extended attribute name.
fn name_bytes(n: &Name) -> Vec<u8> {
    match n.as_bytes() {
        Some(b) => b.to_vec(),
        None => n.to_string_lossy().into_bytes(),
    }
}

/// The host's error as a skipped facet's reason: what the OS said, of the kind it maps to
/// ([`Unsupported`](ErrorKind::Unsupported) where it has no such thing). No path: the caller
/// knows the destination, and a note names the entry.
pub(crate) fn host_err(e: std::io::Error) -> Error {
    let kind = if e.kind() == std::io::ErrorKind::Unsupported { ErrorKind::Unsupported } else { ErrorKind::of_io(&e) };
    Error::caused_by(kind, e.to_string(), e)
}

/// Skipped as unsupported: the node has this facet, the host cannot represent it.
fn unsupported(what: &str) -> Error {
    Error::unsupported(format!("{what} cannot be set on this host"))
}

/// Write the facets `what` of `m` onto `dest`, in an order where one does not undo another:
/// named streams, extended attributes and POSIX ACLs (writing them changes the times), the
/// times, the owner (changing it clears the set-id bits), the mode (a read-only file takes
/// nothing after it), a Windows DACL (it may take away the access the others need). What the
/// destination does not take is returned; the call fails only when a named stream cannot be
/// read (or on a cancel).
pub(crate) fn apply(dest: &Path, what: MetaFacets, m: &Meta<'_>) -> Result<Vec<SkippedFacet>> {
    let mut skipped = Vec::new();
    let st = m.stat;
    let link = matches!(st.kind, NodeKind::Symlink | NodeKind::Reparse);
    if what.contains(MetaFacets::STREAMS) {
        for (n, c) in m.streams {
            if let Err(reason) = stream(dest, n, c)? {
                skipped.push(SkippedFacet { facet: MetaFacets::STREAMS, stream: Some(n.clone()), reason });
            }
        }
    }
    if what.contains(MetaFacets::XATTRS) {
        for (n, v) in m.xattrs {
            let name = name_bytes(n);
            if let Err(e) = host::set_xattr(dest, &name, v) {
                // A host without extended attributes, or a file system that takes no `user.`
                // ones, takes none of the others either; another namespace may be the only
                // one refused.
                let none = e.kind() == std::io::ErrorKind::Unsupported && (!cfg!(unix) || name.starts_with(b"user."));
                skipped.push(SkippedFacet::new(MetaFacets::XATTRS, host_err(e)));
                if none {
                    break;
                }
            }
        }
    }
    let mut ntfs = None;
    if what.contains(MetaFacets::ACL) {
        match m.security {
            Some(Security::Posix { access, default }) => {
                if cfg!(target_os = "linux") {
                    for (n, v) in [("system.posix_acl_access", access), ("system.posix_acl_default", default)] {
                        if let Some(v) = v
                            && let Err(e) = host::set_xattr(dest, n.as_bytes(), &fs_inspect_core::acl::to_xattr(v))
                        {
                            skipped.push(SkippedFacet::new(MetaFacets::ACL, host_err(e)));
                        }
                    }
                } else if access.is_some() || default.is_some() {
                    skipped.push(SkippedFacet::new(MetaFacets::ACL, unsupported("a POSIX ACL")));
                }
            }
            Some(Security::Ntfs(sd)) if cfg!(windows) => ntfs = Some(sd),
            Some(Security::Ntfs(_)) => {
                skipped.push(SkippedFacet::new(MetaFacets::ACL, unsupported("a Windows security descriptor")))
            }
            _ => {}
        }
    }
    if what.contains(MetaFacets::TIMES) {
        let t = &st.times;
        let (modified, accessed) = (t.modified.and_then(system_time), t.accessed.and_then(system_time));
        let created = if cfg!(windows) { t.created.and_then(system_time) } else { None };
        if (modified.is_some() || accessed.is_some() || created.is_some())
            && let Err(e) = host::set_times(dest, modified, accessed, created)
        {
            skipped.push(SkippedFacet::new(MetaFacets::TIMES, host_err(e)));
        }
    }
    if what.contains(MetaFacets::OWNER)
        && let Err(reason) = owner(dest, st, m.security)
    {
        skipped.push(SkippedFacet::new(MetaFacets::OWNER, reason));
    }
    if what.contains(MetaFacets::MODE)
        && let Err(reason) = mode(dest, st, link)
    {
        skipped.push(SkippedFacet::new(MetaFacets::MODE, reason));
    }
    if let Some(sd) = ntfs
        && let Err(e) = host::set_dacl(dest, sd)
    {
        skipped.push(SkippedFacet::new(MetaFacets::ACL, host_err(e)));
    }
    Ok(skipped)
}

/// The owner of `st` (a Unix node's) or of its security descriptor `sd` (a Windows node's)
/// onto `dest`: nothing when the node has neither.
fn owner(dest: &Path, st: &Stat, sd: Option<&Security>) -> std::result::Result<(), Error> {
    if let Some(u) = st.unix {
        if !cfg!(unix) {
            return Err(unsupported("a Unix owner"));
        }
        return host::set_owner(dest, u.uid, u.gid).map_err(host_err);
    }
    if let Some(Security::Ntfs(sd)) = sd {
        if !cfg!(windows) {
            return Err(unsupported("a Windows owner"));
        }
        return host::set_descriptor_owner(dest, sd).map_err(host_err);
    }
    Ok(())
}

/// Write named stream `n` of `dest`: `Ok(Err(why))` when the destination does not take it,
/// `Err` when it cannot be read.
fn stream(dest: &Path, n: &Name, c: &Content<'_>) -> Result<std::result::Result<(), Error>> {
    if cfg!(windows) {
        // An alternate data stream: `dest:name` (the name escaped like a file name).
        let sname = match NamePolicy::Escape.apply(n) {
            Ok(s) => s,
            Err(e) => return Ok(Err(e)),
        };
        let mut sp = dest.as_os_str().to_owned();
        sp.push(":");
        sp.push(&sname);
        let sp = std::path::PathBuf::from(sp);
        let mut f = match std::fs::OpenOptions::new().write(true).create(true).truncate(true).open(&sp) {
            Ok(f) => f,
            // ERROR_INVALID_NAME, ERROR_INVALID_PARAMETER: a file system without alternate
            // data streams (FAT, exFAT).
            Err(e) if matches!(e.raw_os_error(), Some(123 | 87)) => {
                return Ok(Err(host_err(std::io::Error::new(std::io::ErrorKind::Unsupported, e))));
            }
            Err(e) => return Ok(Err(host_err(e))),
        };
        return Ok(write_into(&mut f, c)?.map_err(host_err));
    }
    if c.size > MAX_STREAM_XATTR {
        return Ok(Err(Error::unsupported(format!("too large for an extended attribute ({} bytes)", c.size))));
    }
    let mut v = vec![0; c.size as usize];
    c.copy(&mut |off, b| {
        v[off as usize..off as usize + b.len()].copy_from_slice(b);
        Ok(())
    })?;
    let mut name = b"user.fsinspect.stream.".to_vec();
    name.extend(name_bytes(n));
    Ok(host::set_xattr(dest, &name, &v).map_err(host_err))
}

/// Write `c` into the new file `f` (made sparse first when it has holes): `Ok(Err)` with the
/// host's error when it does not take it, `Err` when `c` cannot be read.
pub(crate) fn write_into(f: &mut std::fs::File, c: &Content<'_>) -> Result<std::io::Result<()>> {
    use std::io::{Seek, SeekFrom, Write};
    if c.sparse()
        && let Err(e) = host::set_sparse(f)
    {
        // Written without holes then: the bytes are the same.
        tracing::debug!("not sparse: {e}");
    }
    let mut failed = None;
    let r = c.copy(&mut |off, b| {
        f.seek(SeekFrom::Start(off)).and_then(|_| f.write_all(b)).map_err(|e| {
            let x = Error::io(&e);
            failed = Some(e);
            x
        })
    });
    if let Some(e) = failed {
        return Ok(Err(e));
    }
    r?;
    Ok(f.set_len(c.size))
}

/// The host's access bits of `st` onto `dest`: nothing when the node has none; unsupported
/// when it has only the other host's kind.
fn mode(dest: &Path, st: &Stat, link: bool) -> std::result::Result<(), Error> {
    #[cfg(unix)]
    {
        if let Some(u) = st.unix {
            use std::os::unix::fs::PermissionsExt;
            if link {
                // A Linux link has no mode of its own: nothing to write.
                if cfg!(target_os = "linux") {
                    return Ok(());
                }
                return host::set_link_mode(dest, u.mode & 0o7777).map_err(host_err);
            }
            return std::fs::set_permissions(dest, std::fs::Permissions::from_mode(u.mode & 0o7777)).map_err(host_err);
        }
        if st.windows.is_some_and(|w| w.attributes & KEPT_ATTRIBUTES != 0) {
            return Err(unsupported("Windows file attributes"));
        }
    }
    #[cfg(windows)]
    {
        if let Some(w) = st.windows {
            let _ = link;
            let base = if st.kind == NodeKind::Dir { 0x10 } else { 0 };
            let a = w.attributes & KEPT_ATTRIBUTES;
            if a != 0 {
                host::set_attributes(dest, a | base).map_err(host_err)?;
            }
            return Ok(());
        }
        if st.unix.is_some() {
            return Err(unsupported("a Unix mode"));
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (dest, link, KEPT_ATTRIBUTES);
        if st.unix.is_some() || st.windows.is_some() {
            return Err(unsupported("a mode"));
        }
    }
    Ok(())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::export::tar::tests::FailingReader;
    use fs_inspect_core::ByteRange;
    use fs_inspect_core::StatExt;
    use fs_inspect_core::ns::{UnixMode, UnixModeExt, WinAttrs, WinAttrsExt};

    fn content(r: &FailingReader, size: u64) -> Content<'_> {
        Content { ahead: 4, reader: r, size, data: vec![ByteRange::new(0, size)], prefetched: None }
    }

    #[test]
    fn metafacets_combine_as_want_does() {
        let f = MetaFacets::TIMES | MetaFacets::MODE;
        assert!(f.contains(MetaFacets::TIMES) && !f.contains(MetaFacets::OWNER));
        assert_eq!(f.without(MetaFacets::TIMES), MetaFacets::MODE);
        assert!(MetaFacets::NONE.is_empty() && MetaFacets::default().is_empty() && !f.is_empty());
        assert_eq!(MetaFacets::ALL.without(MetaFacets::ALL), MetaFacets::NONE);
        assert_eq!(MetaFacets::from_bits_truncate(u32::MAX), MetaFacets::ALL);
        // The bits are the C API's and the Python binding's flags.
        assert_eq!(MetaFacets::ALL.bits(), 0x3F);
        assert_eq!((MetaFacets::OWNER | MetaFacets::STREAMS).bits(), (1 << 2) | (1 << 5));
        assert_eq!(MetaFacets::from_bits_truncate((1 << 4) | (1 << 6)), MetaFacets::ACL);
    }

    /// An export's note names the facet it could not write (and the stream, escaped), then why.
    #[test]
    fn a_skipped_facet_s_note_names_the_facet() {
        let why = || Error::unsupported("not here");
        for (f, name) in [
            (MetaFacets::TIMES, "times"),
            (MetaFacets::MODE, "mode"),
            (MetaFacets::OWNER, "owner"),
            (MetaFacets::XATTRS, "extended attributes"),
            (MetaFacets::ACL, "ACL"),
            (MetaFacets::TIMES | MetaFacets::MODE, "metadata"),
        ] {
            let note = SkippedFacet::new(f, why()).note();
            assert!(note.starts_with(&format!("{name}: ")) && note.contains("not here"), "{note}");
        }
        let s = SkippedFacet { facet: MetaFacets::STREAMS, stream: Some(Name::new("a\nb")), reason: why() };
        assert!(s.note().starts_with("named stream a\\u{000A}b: "), "{}", s.note());
    }

    /// Named streams on Unix are `user.fsinspect.stream.NAME` extended attributes: one larger
    /// than an extended attribute may be is skipped as unsupported, with its name, and not
    /// read; the others are written, or skipped as unsupported where the file system takes
    /// no `user.` attributes.
    #[cfg(unix)]
    #[test]
    fn streams_on_unix_are_extended_attributes_up_to_their_limit() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("f");
        std::fs::write(&dest, b"").unwrap();
        let small = FailingReader { data: b"a stream".to_vec(), fail_at: u64::MAX };
        let big = FailingReader { data: Vec::new(), fail_at: 0 };
        let streams =
            [(Name::new("small"), content(&small, 8)), (Name::new("big"), content(&big, MAX_STREAM_XATTR + 1))];
        let st = Stat::new(NodeId::new(0, 1), NodeKind::File, 0);
        let m = Meta { stat: &st, xattrs: &[], security: None, streams: &streams };
        let skipped = apply(&dest, MetaFacets::STREAMS, &m).unwrap();
        let big = skipped.iter().find(|s| s.stream == Some(Name::new("big"))).expect("the large stream is skipped");
        assert_eq!((big.facet, big.reason.kind()), (MetaFacets::STREAMS, ErrorKind::Unsupported));
        assert!(big.note().starts_with("named stream big: "), "{}", big.note());
        for s in skipped.iter().filter(|s| s.stream == Some(Name::new("small"))) {
            assert_eq!(s.reason.kind(), ErrorKind::Unsupported, "{}", s.reason);
        }
    }

    /// The other host's access bits are skipped as unsupported; a node with none is nothing
    /// to write.
    #[test]
    fn the_other_host_s_mode_is_unsupported() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("f");
        std::fs::write(&dest, b"").unwrap();
        let mut st = Stat::new(NodeId::new(0, 1), NodeKind::File, 0);
        let none = Meta { stat: &st, xattrs: &[], security: None, streams: &[] };
        assert!(apply(&dest, MetaFacets::MODE | MetaFacets::OWNER, &none).unwrap().is_empty());
        if cfg!(windows) {
            st.unix = Some(UnixMode::new(0o100644, 1000, 1000, None));
        } else {
            st.windows = Some(WinAttrs::new(0x2, None, None));
        }
        let other = Meta { stat: &st, xattrs: &[], security: None, streams: &[] };
        let skipped = apply(&dest, MetaFacets::MODE, &other).unwrap();
        assert_eq!(skipped.len(), 1);
        assert_eq!((skipped[0].facet, skipped[0].reason.kind()), (MetaFacets::MODE, ErrorKind::Unsupported));
        assert!(skipped[0].stream.is_none());
        // The reason says what the host answered; the note adds the facet, never the path.
        assert!(skipped[0].note().starts_with("mode: "), "{}", skipped[0].note());
        assert!(!skipped[0].note().contains(&*tmp.path().to_string_lossy()), "{}", skipped[0].note());
    }

    /// A Windows security descriptor on another host, and POSIX ACLs off Linux, are skipped
    /// as unsupported (the owner too, for the descriptor).
    #[test]
    fn access_control_the_host_cannot_represent_is_unsupported() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("f");
        std::fs::write(&dest, b"").unwrap();
        let st = Stat::new(NodeId::new(0, 1), NodeKind::File, 0);
        let ntfs = Security::Ntfs(vec![1, 0, 4, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let posix = Security::Posix { access: Some(Vec::new()), default: None };
        for (sd, skipped_here) in [(&ntfs, !cfg!(windows)), (&posix, !cfg!(target_os = "linux"))] {
            let m = Meta { stat: &st, xattrs: &[], security: Some(sd), streams: &[] };
            let skipped = apply(&dest, MetaFacets::ACL | MetaFacets::OWNER, &m).unwrap();
            if skipped_here {
                assert!(skipped.iter().any(|s| s.facet == MetaFacets::ACL), "{sd:?}");
                for s in &skipped {
                    assert_eq!(s.reason.kind(), ErrorKind::Unsupported, "{sd:?}: {}", s.reason);
                }
            }
        }
    }

    /// A time before 1970 counts back from the epoch, its nanoseconds forward.
    #[test]
    fn times_before_the_epoch_count_back_from_it() {
        let t = system_time(Timestamp { secs: -5, nanos: 250 }).unwrap();
        assert_eq!(t, SystemTime::UNIX_EPOCH - Duration::from_secs(5) + Duration::from_nanos(250));
        let t = system_time(Timestamp { secs: 7, nanos: 1 }).unwrap();
        assert_eq!(t, SystemTime::UNIX_EPOCH + Duration::new(7, 1));
    }

    /// An extended attribute named in UTF-16 is written by its UTF-8 bytes (an unpaired
    /// surrogate as U+FFFD); a byte name as it is.
    #[test]
    fn extended_attribute_names_are_bytes() {
        assert_eq!(name_bytes(&Name::Utf16(vec![u16::from(b'a'), 0xD800])), "a\u{FFFD}".as_bytes());
        assert_eq!(name_bytes(&Name::Bytes(vec![b'u', 0xFF])), [b'u', 0xFF]);
    }

    /// A facet a driver keeps none of, or does not support, is empty; any other failure to
    /// read it is the call's.
    #[test]
    fn a_facet_the_driver_does_not_keep_is_empty() {
        assert_eq!(facet::<Vec<u8>>(None).unwrap(), Vec::<u8>::new());
        assert_eq!(facet::<Vec<u8>>(Some(Err(Error::unsupported("no xattrs")))).unwrap(), Vec::<u8>::new());
        assert_eq!(facet(Some(Ok(vec![1u8]))).unwrap(), [1]);
        let e = facet::<Vec<u8>>(Some(Err(Error::corrupt("damaged")))).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Corrupt);
    }

    /// The host's error keeps its kind; one the OS calls unsupported is `Unsupported`.
    #[test]
    fn host_errors_keep_their_kind() {
        let gone = host_err(std::io::Error::from(std::io::ErrorKind::NotFound));
        assert_eq!(gone.kind(), ErrorKind::NotFound);
        let no = host_err(std::io::Error::new(std::io::ErrorKind::Unsupported, "no such thing"));
        assert_eq!(no.kind(), ErrorKind::Unsupported);
        assert!(no.to_string().contains("no such thing"), "{no}");
    }

    /// A destination that is gone takes nothing: each facet the node has is skipped with the
    /// host's error (not found), the others still tried; only an access time is still a time
    /// to set.
    #[test]
    fn a_destination_that_is_gone_skips_each_facet() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("gone");
        let mut st = Stat::new(NodeId::new(0, 1), NodeKind::File, 0);
        st.times.accessed = Some(Timestamp { secs: 1_000_000, nanos: 0 });
        if cfg!(windows) {
            st.windows = Some(WinAttrs::new(0x1, None, None));
        } else {
            st.unix = Some(UnixMode::new(0o100644, 1000, 1000, None));
        }
        let sd = Security::Ntfs(vec![1, 0, 4, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let security = cfg!(windows).then_some(&sd);
        let m = Meta { stat: &st, xattrs: &[], security, streams: &[] };
        let skipped = apply(&dest, MetaFacets::ALL, &m).unwrap();
        let facets: Vec<MetaFacets> = skipped.iter().map(|s| s.facet).collect();
        for f in [MetaFacets::TIMES, MetaFacets::MODE] {
            let s = skipped.iter().find(|s| s.facet == f).unwrap_or_else(|| panic!("{f:?}: {facets:?}"));
            assert_eq!(s.reason.kind(), ErrorKind::NotFound, "{f:?}: {}", s.reason);
        }
        if cfg!(windows) {
            // The descriptor names no owner: nothing to write; its DACL is still tried.
            assert!(facets.contains(&MetaFacets::ACL) && !facets.contains(&MetaFacets::OWNER), "{facets:?}");
        } else {
            assert!(facets.contains(&MetaFacets::OWNER), "{facets:?}");
        }
    }

    /// Windows has no extended attributes: the first is skipped as unsupported and the others
    /// are not tried; a named stream of a destination that is gone is skipped with the host's
    /// error.
    #[cfg(windows)]
    #[test]
    fn windows_takes_no_extended_attributes_and_streams_need_their_file() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("f");
        std::fs::write(&dest, b"").unwrap();
        let st = Stat::new(NodeId::new(0, 1), NodeKind::File, 0);
        let xattrs = [(Name::new("user.a"), b"1".to_vec()), (Name::new("user.b"), b"2".to_vec())];
        let m = Meta { stat: &st, xattrs: &xattrs, security: None, streams: &[] };
        let skipped = apply(&dest, MetaFacets::XATTRS, &m).unwrap();
        assert_eq!(skipped.len(), 1);
        assert_eq!((skipped[0].facet, skipped[0].reason.kind()), (MetaFacets::XATTRS, ErrorKind::Unsupported));

        let r = FailingReader { data: b"a stream".to_vec(), fail_at: u64::MAX };
        let streams = [(Name::new("s"), content(&r, 8))];
        let m = Meta { stat: &st, xattrs: &[], security: None, streams: &streams };
        let skipped = apply(&tmp.path().join("no").join("f"), MetaFacets::STREAMS, &m).unwrap();
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0].stream, Some(Name::new("s")));
        assert_eq!(skipped[0].reason.kind(), ErrorKind::NotFound, "{}", skipped[0].reason);
        // Written where the file is.
        assert!(apply(&dest, MetaFacets::STREAMS, &m).unwrap().is_empty());
        assert_eq!(std::fs::read(format!("{}:s", dest.display())).unwrap(), b"a stream");
    }

    /// A file that does not take the bytes (opened read-only) gives the host's error, not the
    /// call's; content that cannot be read is the call's error.
    #[test]
    fn writing_into_a_file_that_refuses_is_the_host_s_error() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("f");
        std::fs::write(&path, b"").unwrap();
        let r = FailingReader { data: vec![7u8; 4096], fail_at: u64::MAX };
        let mut ro = std::fs::File::open(&path).unwrap();
        assert!(write_into(&mut ro, &content(&r, 4096)).unwrap().is_err());
        let mut rw = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        write_into(&mut rw, &content(&r, 4096)).unwrap().unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), vec![7u8; 4096]);
        let bad = FailingReader { data: vec![7u8; 4096], fail_at: 0 };
        assert!(write_into(&mut rw, &content(&bad, 4096)).is_err());
    }
}
