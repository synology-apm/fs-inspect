//! The library's errors.
//!
//! [`Error`] is the one error type of the whole library. It has an [`ErrorKind`], may have a
//! place on disk ([`Location`]), and keeps the error that caused it ([`Error::source_error`]
//! finds a caller's own error again). [`SourceError`] is what a source's read fails with; past
//! the read it becomes the [`Error`] of the same kind.

use std::fmt;
use std::sync::Arc;

fs_inspect_io::named_enum! {
    /// Stable classification of an [`Error`], for callers that map errors to codes of their
    /// own (exit codes, status codes). Exhaustive: a new kind is a breaking change. Most callers
    /// decide on its [`scope`](Self::scope).
    pub enum ErrorKind ("error kind") exhaustive {
        /// The caller passed an invalid argument.
        InvalidArgument = 1 => "invalid_argument",
        /// Reading the source failed.
        Io = 2 => "io",
        /// The data is not the expected format (not this file system, unknown image format).
        Format = 3 => "format",
        /// The format was recognized but a structure is damaged or inconsistent.
        Corrupt = 4 => "corrupt",
        /// A recognized feature this library does not handle.
        Unsupported = 5 => "unsupported",
        /// A requested item (volume, path) does not exist.
        NotFound = 6 => "not_found",
        /// The operation was cancelled.
        Cancelled = 7 => "cancelled",
        /// A resource limit protecting against hostile input was hit.
        Limit = 8 => "limit",
        /// A file of the library's own (a replay's scratch file, an export's output) could not be
        /// written for lack of space (a full disk, a quota).
        NoSpace = 9 => "no_space",
        /// File content that is not on the volume: a cloud file's dehydrated range (it is held by
        /// its sync provider). Not [`NotFound`](ErrorKind::NotFound): the file exists.
        ContentUnavailable = 10 => "content_unavailable",
        /// The operating system refused access to a file or device (not elevated, a locked
        /// volume, a file's permissions).
        PermissionDenied = 11 => "permission_denied",
        /// A file operation on a directory (opening it for its content).
        IsADirectory = 12 => "is_a_directory",
        /// Something known to exist that cannot be read as it is: a logical volume whose
        /// container lacks members. Not [`NotFound`](ErrorKind::NotFound): giving the missing
        /// disks makes it readable.
        Unavailable = 13 => "unavailable",
        /// Bytes the source does not have: a range a backup lost or never kept. The source
        /// works, but what those bytes held is unknown. As with a damaged structure, the unit
        /// they belong to is left out ([`Scope::Unit`]).
        DataMissing = 14 => "data_missing",
    }
}

impl ErrorKind {
    /// A few words saying what the kind is (`"I/O error"`, `"not found"`, ...): what an
    /// [`Error`]'s [`Display`](fmt::Display) puts before its message.
    pub const fn summary(self) -> &'static str {
        match self {
            ErrorKind::Io => "I/O error",
            ErrorKind::Format => "unrecognized format",
            ErrorKind::Corrupt => "corrupt structure",
            ErrorKind::Unsupported => "unsupported",
            ErrorKind::NotFound => "not found",
            ErrorKind::InvalidArgument => "invalid argument",
            ErrorKind::Cancelled => "cancelled",
            ErrorKind::Limit => "limit exceeded",
            ErrorKind::ContentUnavailable => "content unavailable",
            ErrorKind::PermissionDenied => "permission denied",
            ErrorKind::IsADirectory => "is a directory",
            ErrorKind::Unavailable => "unavailable",
            ErrorKind::NoSpace => "no space left",
            ErrorKind::DataMissing => "data missing",
        }
    }

    /// What the kind is about, and so what a reader does with it ([`Scope`]).
    pub const fn scope(self) -> Scope {
        match self {
            ErrorKind::Format
            | ErrorKind::Corrupt
            | ErrorKind::Unsupported
            | ErrorKind::Limit
            | ErrorKind::DataMissing
            | ErrorKind::Unavailable
            | ErrorKind::ContentUnavailable => Scope::Unit,
            ErrorKind::Io | ErrorKind::PermissionDenied | ErrorKind::NoSpace => Scope::Source,
            ErrorKind::InvalidArgument | ErrorKind::NotFound | ErrorKind::IsADirectory => Scope::Caller,
            ErrorKind::Cancelled => Scope::Cancelled,
        }
    }

    /// The kind of an OS error: [`NotFound`](Self::NotFound),
    /// [`PermissionDenied`](Self::PermissionDenied), [`NoSpace`](Self::NoSpace), else
    /// [`Io`](Self::Io).
    pub fn of_io(e: &std::io::Error) -> ErrorKind {
        match e.kind() {
            std::io::ErrorKind::NotFound => ErrorKind::NotFound,
            std::io::ErrorKind::PermissionDenied => ErrorKind::PermissionDenied,
            std::io::ErrorKind::StorageFull | std::io::ErrorKind::QuotaExceeded => ErrorKind::NoSpace,
            _ => ErrorKind::Io,
        }
    }
}

fs_inspect_io::named_enum! {
    /// What an [`ErrorKind`] is about ([`ErrorKind::scope`]), and so how far it reaches. Readers
    /// decide on this classification only. Exhaustive.
    ///
    /// The drivers' rule: an error of [`Unit`](Scope::Unit) scope leaves out the unit it was
    /// found in (an ext group, an XFS AG, a file, an APFS volume). That unit counts as used or
    /// changed, with a diagnostic, and the rest of the volume stands. Any other scope stops the
    /// read with the error: what a failing source hides is not known to be absent, a caller's
    /// mistake is reported to it, and a cancel is the caller's wish.
    pub enum Scope ("error scope") exhaustive {
        /// The bytes read and what they mean, for the unit they belong to: not the expected
        /// format, damaged, a feature not handled, a limit against hostile input, bytes the source
        /// does not have, members missing, content held elsewhere.
        Unit = 1 => "unit",
        /// What the bytes are read from or written to: a read that failed, access refused, no
        /// space to write. Retrying (once the source works) may succeed.
        Source = 2 => "source",
        /// The request: an invalid argument, a path or volume that does not exist, a directory
        /// opened as a file.
        Caller = 3 => "caller",
        /// The caller cancelled.
        Cancelled = 4 => "cancelled",
    }
}

fs_inspect_io::named_enum! {
    /// The coordinates a [`Location`]'s offset is in.
    pub enum Space ("coordinate space") {
        /// The volume's: from the start of the volume a file system driver reads (add the
        /// volume's offset for its device's).
        Volume = 1 => "volume",
        /// The device's: from the start of a disk of the set or a logical volume (partition
        /// tables, volume manager metadata, an image's own structures).
        Device = 2 => "device",
    }
}

/// Where on disk an error was found: the structure being read and its byte offset, in the
/// coordinates [`space`](Self::space) says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
#[non_exhaustive]
pub struct Location {
    pub space: Space,
    pub structure: &'static str,
    pub offset: u64,
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.space {
            Space::Volume => write!(f, "{} at {:#x}", self.structure, self.offset),
            Space::Device => write!(f, "{} at device offset {:#x}", self.structure, self.offset),
        }
    }
}

/// The source of a [`SourceError::out_of_range`]: a read past the end of a source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("read of {length} bytes at offset {offset} is outside the source (size {source_size})")]
#[non_exhaustive]
pub struct OutOfRange {
    pub offset: u64,
    pub length: u64,
    pub source_size: u64,
}

/// Library error. Cheap to clone (a stream that stopped at an error hands out the same error
/// again); `Send + Sync + 'static`.
#[derive(Clone)]
pub struct Error(Arc<Inner>);

struct Inner {
    kind: ErrorKind,
    /// What the caller said: without the kind's summary and the location.
    message: String,
    location: Option<Location>,
    source: Option<Arc<dyn std::error::Error + Send + Sync>>,
}

impl Error {
    /// An error of `kind` saying `message` (shown after the kind's
    /// [`summary`](ErrorKind::summary)).
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Error(Arc::new(Inner { kind, message: message.into(), location: None, source: None }))
    }

    /// An error of `kind` saying `message`, caused by `cause` (found again with
    /// [`source_error`](Self::source_error)). The cause is given here, once: an error never
    /// trades one cause for another.
    pub fn caused_by(
        kind: ErrorKind,
        message: impl Into<String>,
        cause: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Error(Arc::new(Inner { kind, message: message.into(), location: None, source: Some(Arc::new(cause)) }))
    }

    pub fn format(msg: impl fmt::Display) -> Self {
        Self::new(ErrorKind::Format, msg.to_string())
    }
    pub fn corrupt(msg: impl fmt::Display) -> Self {
        Self::new(ErrorKind::Corrupt, msg.to_string())
    }
    /// An image that ends at byte `readable`, before the end of its file system (`fs_end`),
    /// with a used block from byte `at` past it: a change tracker refuses what it cannot read
    /// rather than lose it.
    pub fn used_past_end(readable: u64, fs_end: u64, at: u64) -> Self {
        Self::corrupt(format_args!(
            "the image ends at byte {readable}, before the end of its file system ({fs_end}): used blocks from \
             byte {} cannot be read (a truncated image or a short snapshot device)",
            at.max(readable)
        ))
    }
    /// Writing or reading something other than the source failed (an export's output).
    pub fn io(msg: impl fmt::Display) -> Self {
        Self::new(ErrorKind::Io, msg.to_string())
    }
    pub fn unsupported(msg: impl fmt::Display) -> Self {
        Self::new(ErrorKind::Unsupported, msg.to_string())
    }
    pub fn not_found(msg: impl fmt::Display) -> Self {
        Self::new(ErrorKind::NotFound, msg.to_string())
    }
    pub fn invalid_argument(msg: impl fmt::Display) -> Self {
        Self::new(ErrorKind::InvalidArgument, msg.to_string())
    }
    /// A file operation on a directory ([`ErrorKind::IsADirectory`]).
    pub fn is_a_directory(msg: impl fmt::Display) -> Self {
        Self::new(ErrorKind::IsADirectory, msg.to_string())
    }
    /// Known to exist, cannot be read as it is ([`ErrorKind::Unavailable`]).
    pub fn unavailable(msg: impl fmt::Display) -> Self {
        Self::new(ErrorKind::Unavailable, msg.to_string())
    }
    pub fn limit(msg: impl fmt::Display) -> Self {
        Self::new(ErrorKind::Limit, msg.to_string())
    }
    /// The operation was cancelled: no message of its own (shown as `cancelled`).
    pub fn cancelled() -> Self {
        Self::new(ErrorKind::Cancelled, "")
    }
    /// File content not on the volume ([`ErrorKind::ContentUnavailable`]).
    pub fn content_unavailable(msg: impl fmt::Display) -> Self {
        Self::new(ErrorKind::ContentUnavailable, msg.to_string())
    }
    /// A file at `path` (an image, a device, a file of the library's own) could not be opened
    /// or written: kind by the OS error ([`ErrorKind::of_io`]). Not for a read of a source,
    /// which fails with a [`SourceError`].
    pub fn file(path: impl fmt::Display, error: std::io::Error) -> Self {
        Self::caused_by(ErrorKind::of_io(&error), format!("{path}: {error}"), error)
    }

    pub fn kind(&self) -> ErrorKind {
        self.0.kind
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.kind == ErrorKind::Cancelled
    }

    /// [`ErrorKind::scope`] of its kind.
    pub fn scope(&self) -> Scope {
        self.0.kind.scope()
    }

    /// What the error says: the text it was made with (and the contexts it went through),
    /// without the kind's [`summary`](ErrorKind::summary) and the location that
    /// [`Display`](fmt::Display) adds.
    pub fn message(&self) -> &str {
        &self.0.message
    }

    /// Where on disk the error was found, when known.
    pub fn location(&self) -> Option<Location> {
        self.0.location
    }

    /// The first error of type `T` in this error's chain of causes: what a caller's
    /// [`BlockSource`](crate::BlockSource) failed with ([`SourceError::caused_by`]), an
    /// [`std::io::Error`], an [`OutOfRange`].
    pub fn source_error<T: std::error::Error + 'static>(&self) -> Option<&T> {
        let mut cur = std::error::Error::source(self);
        while let Some(e) = cur {
            if let Some(t) = e.downcast_ref::<T>() {
                return Some(t);
            }
            cur = e.source();
        }
        None
    }

    /// This error, found in `structure` at byte `offset` of the volume a driver reads
    /// ([`Space::Volume`]). A location already set is kept: the innermost one is the most
    /// precise.
    pub fn at(self, structure: &'static str, offset: u64) -> Self {
        self.located(Location { space: Space::Volume, structure, offset })
    }

    /// This error, found in `structure` at byte `offset` of a device ([`Space::Device`]). A
    /// location already set is kept.
    pub fn at_device(self, structure: &'static str, offset: u64) -> Self {
        self.located(Location { space: Space::Device, structure, offset })
    }

    fn located(self, location: Location) -> Self {
        if self.0.location.is_some() {
            return self;
        }
        let mut inner = self.into_inner();
        inner.location = Some(location);
        Error(Arc::new(inner))
    }

    /// This error, in `what` (its message prefixed with `what: `); kind, location and source are
    /// kept.
    pub fn context(self, what: impl fmt::Display) -> Self {
        let mut inner = self.into_inner();
        inner.message = format!("{what}: {}", inner.message);
        Error(Arc::new(inner))
    }

    fn into_inner(self) -> Inner {
        match Arc::try_unwrap(self.0) {
            Ok(inner) => inner,
            Err(shared) => Inner {
                kind: shared.kind,
                message: shared.message.clone(),
                location: shared.location,
                source: shared.source.clone(),
            },
        }
    }
}

/// `{summary}: {message} ({location})`: the kind's [`summary`](ErrorKind::summary), put here
/// once, then the message (when there is one) and the location (when known).
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0.kind.summary())?;
        if !self.0.message.is_empty() {
            write!(f, ": {}", self.0.message)?;
        }
        match &self.0.location {
            Some(l) => write!(f, " ({l})"),
            None => Ok(()),
        }
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("Error");
        d.field("kind", &self.0.kind).field("message", &self.0.message);
        if let Some(l) = &self.0.location {
            d.field("location", l);
        }
        if let Some(s) = &self.0.source {
            d.field("source", s);
        }
        d.finish()
    }
}

/// Equal when kind, message and location are: the cause is not compared (an error kept in a
/// report is a value).
impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
            || (self.0.kind == other.0.kind && self.0.message == other.0.message && self.0.location == other.0.location)
    }
}

impl Eq for Error {}

/// `{"kind": "...", "message": "...", "location": {"space", "structure", "offset"} | null}`.
impl serde::Serialize for Error {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = s.serialize_struct("Error", 3)?;
        st.serialize_field("kind", &self.0.kind)?;
        st.serialize_field("message", &self.0.message)?;
        st.serialize_field("location", &self.0.location)?;
        st.end()
    }
}

/// The [`std::io::Error`] of the nearest kind, carrying the error (found again with
/// `get_ref` and a downcast): `NotFound`, `PermissionDenied`, `IsADirectory`, `InvalidInput`
/// (an invalid argument), `StorageFull` (no space), `InvalidData` (a format, damage, missing
/// data, a limit), `Unsupported`; an I/O error keeps the kind of the OS error under it. A cancel
/// is `Other`, not `Interrupted`: readers retry an interrupted read (`read_exact`,
/// `read_to_end`, `io::copy`), and a cancelled call fails again on every try.
impl From<Error> for std::io::Error {
    fn from(e: Error) -> std::io::Error {
        use std::io::ErrorKind as Io;
        let kind = match e.kind() {
            ErrorKind::NotFound => Io::NotFound,
            ErrorKind::PermissionDenied => Io::PermissionDenied,
            ErrorKind::IsADirectory => Io::IsADirectory,
            ErrorKind::InvalidArgument => Io::InvalidInput,
            ErrorKind::NoSpace => Io::StorageFull,
            ErrorKind::Format
            | ErrorKind::Corrupt
            | ErrorKind::DataMissing
            | ErrorKind::Limit
            | ErrorKind::ContentUnavailable
            | ErrorKind::Unavailable => Io::InvalidData,
            ErrorKind::Unsupported => Io::Unsupported,
            ErrorKind::Io => e.source_error::<std::io::Error>().map_or(Io::Other, std::io::Error::kind),
            ErrorKind::Cancelled => Io::Other,
        };
        std::io::Error::new(kind, e)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.source.as_deref().map(|e| e as &(dyn std::error::Error + 'static))
    }
}

fs_inspect_io::named_enum! {
    /// What a source may fail a read with ([`SourceError::kind`]): the six things a source can
    /// tell. Exhaustive. Each is the [`ErrorKind`] of the same name once the error leaves the
    /// source.
    pub enum SourceErrorKind ("source error kind") exhaustive {
        /// Reading failed (a device, a store that does not answer): retrying may succeed.
        Io = 1 => "io",
        /// The source does not have the bytes: a range a backup lost or never kept, an image file
        /// shorter than it says it is.
        DataMissing = 2 => "data_missing",
        /// What holds the bytes is damaged (an image's block table), or the read is past the
        /// source's end (a structure pointing outside what holds it).
        Corrupt = 3 => "corrupt",
        /// The source holds the bytes in a form it does not read (a compression or a container
        /// feature it does not handle): the same on every try.
        Unsupported = 4 => "unsupported",
        /// Access refused.
        PermissionDenied = 5 => "permission_denied",
        /// The read was cancelled.
        Cancelled = 6 => "cancelled",
    }
}

impl SourceErrorKind {
    /// The [`ErrorKind`] of the same name.
    pub const fn kind(self) -> ErrorKind {
        match self {
            SourceErrorKind::Io => ErrorKind::Io,
            SourceErrorKind::DataMissing => ErrorKind::DataMissing,
            SourceErrorKind::Corrupt => ErrorKind::Corrupt,
            SourceErrorKind::Unsupported => ErrorKind::Unsupported,
            SourceErrorKind::PermissionDenied => ErrorKind::PermissionDenied,
            SourceErrorKind::Cancelled => ErrorKind::Cancelled,
        }
    }
}

/// A read of a source that failed ([`BlockSource::read_exact_at`](crate::BlockSource)): one of
/// the [`SourceErrorKind`]s, with its message and the error that caused it (a caller's own,
/// found again with [`Error::source_error`]). At the trait's boundary it becomes the [`Error`]
/// of the same kind (`?`, [`From`]). Cheap to clone.
#[derive(Clone)]
pub struct SourceError {
    kind: SourceErrorKind,
    error: Error,
}

impl SourceError {
    /// An error of `kind` whose whole message is `message`.
    pub fn new(kind: SourceErrorKind, message: impl Into<String>) -> Self {
        SourceError { kind, error: Error::new(kind.kind(), message) }
    }

    /// An error of `kind` caused by `cause`, the error of a device or of a caller's reader (an
    /// network disk, a store). Its message is the cause's, and [`Error::source_error`] finds
    /// the cause again. The caller gives the kind, because a cause does not tell whether it is a
    /// failed read, missing data or a cancel.
    pub fn caused_by(kind: SourceErrorKind, cause: impl std::error::Error + Send + Sync + 'static) -> Self {
        SourceError { kind, error: Error::caused_by(kind.kind(), cause.to_string(), cause) }
    }

    /// Reading `length` bytes at `offset` failed with the OS error `error`:
    /// [`PermissionDenied`](SourceErrorKind::PermissionDenied) when the OS refused access, else
    /// [`Io`](SourceErrorKind::Io).
    pub fn os(offset: u64, length: usize, error: std::io::Error) -> Self {
        let kind = match error.kind() {
            std::io::ErrorKind::PermissionDenied => SourceErrorKind::PermissionDenied,
            _ => SourceErrorKind::Io,
        };
        let message = format!("reading {length} bytes at offset {offset}: {error}");
        SourceError { kind, error: Error::caused_by(kind.kind(), message, error) }
    }

    /// A read of `length` bytes at `offset` past the end of a source of `source_size` bytes:
    /// [`SourceErrorKind::Corrupt`] (a structure pointing outside what holds it).
    pub fn out_of_range(offset: u64, length: usize, source_size: u64) -> Self {
        let r = OutOfRange { offset, length: length as u64, source_size };
        let kind = SourceErrorKind::Corrupt;
        SourceError { kind, error: Error::caused_by(kind.kind(), r.to_string(), r) }
    }

    /// The read was cancelled ([`CancelSource`](crate::CancelSource)).
    pub fn cancelled() -> Self {
        Self::new(SourceErrorKind::Cancelled, "")
    }

    /// A read of one of fs-inspect's own sources (a volume of a set, read as a source) that
    /// failed with `error`. The error is kept whole: turned back into an [`Error`], it is
    /// `error` again, kind and all.
    ///
    /// Its [`kind`](Self::kind) is the source kind of the same name, or else the nearest by
    /// meaning: a missing structure or content is `DataMissing`, a format or limit error is
    /// `Corrupt`, and no space or a caller's error is `Io`.
    pub fn from_error(error: Error) -> Self {
        let kind = match error.kind() {
            ErrorKind::Io | ErrorKind::NoSpace => SourceErrorKind::Io,
            ErrorKind::PermissionDenied => SourceErrorKind::PermissionDenied,
            ErrorKind::DataMissing | ErrorKind::Unavailable | ErrorKind::ContentUnavailable => {
                SourceErrorKind::DataMissing
            }
            ErrorKind::Corrupt | ErrorKind::Format | ErrorKind::Limit => SourceErrorKind::Corrupt,
            ErrorKind::Unsupported => SourceErrorKind::Unsupported,
            ErrorKind::Cancelled => SourceErrorKind::Cancelled,
            ErrorKind::InvalidArgument | ErrorKind::NotFound | ErrorKind::IsADirectory => SourceErrorKind::Io,
        };
        SourceError { kind, error }
    }

    /// This error, in `what` (its message prefixed with `what: `).
    pub fn context(self, what: impl fmt::Display) -> Self {
        SourceError { kind: self.kind, error: self.error.context(what) }
    }

    /// What the source tells ([`SourceErrorKind`]).
    pub fn kind(&self) -> SourceErrorKind {
        self.kind
    }

    /// [`ErrorKind::scope`] of its kind: a reader decides on it as on an [`Error`]'s.
    pub fn scope(&self) -> Scope {
        self.kind.kind().scope()
    }

    /// Whether the read was cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.kind == SourceErrorKind::Cancelled
    }

    /// The message ([`Error::message`]).
    pub fn message(&self) -> &str {
        self.error.message()
    }

    /// [`Error::source_error`].
    pub fn source_error<T: std::error::Error + 'static>(&self) -> Option<&T> {
        self.error.source_error()
    }
}

impl From<SourceError> for Error {
    fn from(e: SourceError) -> Error {
        e.error
    }
}

impl fmt::Display for SourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(f)
    }
}

impl fmt::Debug for SourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SourceError").field("kind", &self.kind).field("error", &self.error).finish()
    }
}

impl std::error::Error for SourceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        std::error::Error::source(&self.error)
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// [`Error::at`] for results.
pub trait ResultExt<T> {
    /// On error: found in `structure` at byte `offset` of the volume ([`Error::at`]).
    fn at(self, structure: &'static str, offset: u64) -> Result<T>;
    /// On error: found in `structure` at byte `offset` of a device ([`Error::at_device`]).
    fn at_device(self, structure: &'static str, offset: u64) -> Result<T>;
}

impl<T, E: Into<Error>> ResultExt<T> for std::result::Result<T, E> {
    fn at(self, structure: &'static str, offset: u64) -> Result<T> {
        self.map_err(|e| e.into().at(structure, offset))
    }
    fn at_device(self, structure: &'static str, offset: u64) -> Result<T> {
        self.map_err(|e| e.into().at_device(structure, offset))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::names::Named;

    #[test]
    fn kinds_messages_and_locations() {
        let e = Error::corrupt("bad magic").at("superblock", 0x400);
        assert_eq!(e.kind(), ErrorKind::Corrupt);
        assert_eq!(e.to_string(), "corrupt structure: bad magic (superblock at 0x400)");
        assert_eq!(e.message(), "bad magic");
        assert_eq!(e.location(), Some(Location { space: Space::Volume, structure: "superblock", offset: 0x400 }));
        // The innermost location wins.
        assert_eq!(e.clone().at("volume", 0).location().map(|l| l.offset), Some(0x400));
        // Context goes in front; kind and location stay.
        let c = Error::corrupt("bad magic").at("superblock", 0x400).context("xfs");
        assert_eq!(c.location().map(|l| l.offset), Some(0x400));
        assert_eq!(c.to_string(), "corrupt structure: xfs: bad magic (superblock at 0x400)");
        assert_eq!(Error::cancelled().to_string(), "cancelled");
        let d = Error::new(ErrorKind::Io, "gpt header").at_device("gpt header", 0x200);
        assert_eq!(d.to_string(), "I/O error: gpt header (gpt header at device offset 0x200)");
        assert_eq!(
            serde_json::to_value(&d).unwrap(),
            serde_json::json!({"kind": "io", "message": "gpt header",
                "location": {"space": "device", "structure": "gpt header", "offset": 512}})
        );
        assert_eq!(serde_json::to_value(Error::not_found("x")).unwrap()["location"], serde_json::Value::Null);
    }

    #[test]
    fn source_errors_keep_their_source_and_kind() {
        let e = Error::from(SourceError::out_of_range(10, 4, 12));
        assert_eq!(e.kind(), ErrorKind::Corrupt);
        assert_eq!(e.source_error::<OutOfRange>(), Some(&OutOfRange { offset: 10, length: 4, source_size: 12 }));
        assert!(std::error::Error::source(&e).is_some());
        let r: Result<()> = Err(Error::cancelled());
        assert_eq!(r.at("bitmap", 7).unwrap_err().kind(), ErrorKind::Cancelled);
        let denied = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        assert_eq!(SourceError::os(0, 512, denied).kind(), SourceErrorKind::PermissionDenied);
        // An OS error of any other kind is a failed read: the source's, not the caller's.
        let gone = std::io::Error::from(std::io::ErrorKind::NotFound);
        assert_eq!(SourceError::os(0, 512, gone).kind(), SourceErrorKind::Io);
        let missing = std::io::Error::from(std::io::ErrorKind::NotFound);
        assert_eq!(Error::file("x.img", missing).kind(), ErrorKind::NotFound);
        let lost = SourceError::caused_by(SourceErrorKind::DataMissing, std::io::Error::other("not kept"));
        assert_eq!(Error::from(lost).kind(), ErrorKind::DataMissing);
        assert_eq!(Error::from(SourceError::cancelled()).kind(), ErrorKind::Cancelled);
    }

    /// Each kind a source tells is the error kind of the same name.
    #[test]
    fn source_kinds_are_error_kinds() {
        for (k, e) in [
            (SourceErrorKind::Io, ErrorKind::Io),
            (SourceErrorKind::DataMissing, ErrorKind::DataMissing),
            (SourceErrorKind::Corrupt, ErrorKind::Corrupt),
            (SourceErrorKind::Unsupported, ErrorKind::Unsupported),
            (SourceErrorKind::PermissionDenied, ErrorKind::PermissionDenied),
            (SourceErrorKind::Cancelled, ErrorKind::Cancelled),
        ] {
            assert_eq!(k.kind(), e);
            assert_eq!(Error::from(SourceError::new(k, "x")).kind(), e);
        }
    }

    /// What a caller's source failed with comes back, through any number of contexts and
    /// wrapping errors.
    #[test]
    fn a_callers_error_is_found_again() {
        #[derive(Debug, thiserror::Error)]
        #[error("repository offline (code {0})")]
        struct Mine(u32);
        let e = Error::from(SourceError::caused_by(SourceErrorKind::Io, Mine(7))).at("mft", 0).context("ntfs");
        assert_eq!(e.source_error::<Mine>().map(|m| m.0), Some(7));
        let wrapped = Error::caused_by(ErrorKind::Corrupt, "x", e);
        assert_eq!(wrapped.source_error::<Mine>().map(|m| m.0), Some(7));
        assert!(wrapped.source_error::<std::io::Error>().is_none());
    }

    /// A caller's error keeps the kind the caller gave it, whatever it is.
    #[test]
    fn a_cause_does_not_choose_the_kind() {
        #[derive(Debug, thiserror::Error)]
        #[error("stopped by the user")]
        struct Stopped;
        let e = SourceError::caused_by(SourceErrorKind::Cancelled, Stopped);
        assert_eq!(e.scope(), Scope::Cancelled);
        assert_eq!(e.message(), "stopped by the user");
        assert!(Error::from(e).source_error::<Stopped>().is_some());
    }

    /// An error of the library read back as a source's is the same error once it leaves the
    /// source; its source kind is the nearest by meaning.
    #[test]
    fn errors_read_through_a_source_come_back_whole() {
        for &k in ErrorKind::ALL {
            let e = Error::new(k, "x").at("superblock", 9);
            let s = SourceError::from_error(e.clone());
            let back = Error::from(s.clone());
            assert_eq!(back.kind(), k);
            assert_eq!(back.location(), e.location());
            // Only a cancel is a cancel; the source kinds are themselves.
            assert_eq!(s.kind() == SourceErrorKind::Cancelled, k == ErrorKind::Cancelled);
            if let Some(same) = [
                SourceErrorKind::Io,
                SourceErrorKind::DataMissing,
                SourceErrorKind::Corrupt,
                SourceErrorKind::Unsupported,
                SourceErrorKind::PermissionDenied,
            ]
            .into_iter()
            .find(|sk| sk.kind() == k)
            {
                assert_eq!(s.kind(), same);
            }
        }
        assert_eq!(SourceError::from_error(Error::format("x")).kind(), SourceErrorKind::Corrupt);
        assert_eq!(SourceError::from_error(Error::unavailable("x")).kind(), SourceErrorKind::DataMissing);
    }

    #[test]
    fn scopes() {
        assert_eq!(Error::corrupt("x").scope(), Scope::Unit);
        assert_eq!(Error::from(SourceError::out_of_range(10, 4, 12)).scope(), Scope::Unit);
        assert_eq!(Error::unsupported("x").scope(), Scope::Unit);
        assert_eq!(Error::from(SourceError::os(0, 1, std::io::Error::other("bad sector"))).scope(), Scope::Source);
        assert_eq!(Error::cancelled().scope(), Scope::Cancelled);
        assert_eq!(Error::invalid_argument("x").scope(), Scope::Caller);
        // Every kind has one.
        for k in ErrorKind::ALL {
            let _ = k.scope();
        }
    }

    #[test]
    fn io_errors_of_the_nearest_kind() {
        use std::io::ErrorKind as Io;
        let io = |e: Error| std::io::Error::from(e).kind();
        assert_eq!(io(Error::not_found("x")), Io::NotFound);
        assert_eq!(io(Error::corrupt("x")), Io::InvalidData);
        assert_eq!(io(Error::invalid_argument("x")), Io::InvalidInput);
        // Never Interrupted: a reader would retry a cancelled read for ever.
        assert_eq!(io(Error::cancelled()), Io::Other);
        let os = SourceError::os(0, 1, std::io::Error::from(Io::TimedOut));
        assert_eq!(io(Error::from(os)), Io::TimedOut);
        let back = std::io::Error::from(Error::corrupt("bad"));
        let inner = back.get_ref().and_then(|e| e.downcast_ref::<Error>()).map(Error::kind);
        assert_eq!(inner, Some(ErrorKind::Corrupt));
    }

    #[test]
    fn send_sync_static() {
        fn check<T: Send + Sync + 'static>() {}
        check::<Error>();
        check::<SourceError>();
    }
    /// Every kind becomes the `std::io::Error` kind the `From` impl documents, and the error
    /// stays inside it.
    #[test]
    fn every_kind_has_its_io_error_kind() {
        use std::io::ErrorKind as Io;
        for &k in ErrorKind::ALL {
            let want = match k {
                ErrorKind::NotFound => Io::NotFound,
                ErrorKind::PermissionDenied => Io::PermissionDenied,
                ErrorKind::IsADirectory => Io::IsADirectory,
                ErrorKind::InvalidArgument => Io::InvalidInput,
                ErrorKind::NoSpace => Io::StorageFull,
                ErrorKind::Unsupported => Io::Unsupported,
                ErrorKind::Io | ErrorKind::Cancelled => Io::Other,
                ErrorKind::Format
                | ErrorKind::Corrupt
                | ErrorKind::DataMissing
                | ErrorKind::Limit
                | ErrorKind::ContentUnavailable
                | ErrorKind::Unavailable => Io::InvalidData,
            };
            let e = std::io::Error::from(Error::new(k, "x"));
            assert_eq!(e.kind(), want, "{k:?}");
            assert_eq!(e.get_ref().and_then(|e| e.downcast_ref::<Error>()).map(Error::kind), Some(k));
            // The text starts with the kind's summary.
            assert!(e.to_string().starts_with(k.summary()), "{e}");
        }
    }

    /// Two errors are equal on kind, message and location; their causes are not compared.
    #[test]
    fn errors_compare_without_their_cause() {
        let a = Error::caused_by(ErrorKind::Io, "read", std::io::Error::other("one"));
        let b = Error::caused_by(ErrorKind::Io, "read", std::io::Error::other("two"));
        assert_eq!(a, b);
        assert_eq!(a, a.clone());
        assert_ne!(a.clone().at("bitmap", 1), b.clone().at("bitmap", 2));
        assert_ne!(a.clone().at("bitmap", 1), b.clone().at_device("bitmap", 1));
        assert_ne!(Error::corrupt("read"), Error::io("read"));
        // Debug shows the location and the cause.
        let d = format!("{:?}", a.at("bitmap", 1));
        assert!(d.contains("location") && d.contains("source") && d.contains("one"), "{d}");
    }

    /// An image cut short names the first used byte it cannot give: the used block's, or the
    /// image's end when the block starts before it.
    #[test]
    fn a_used_block_past_the_image_s_end_names_the_first_byte_missing() {
        let e = Error::used_past_end(1000, 4096, 2048);
        assert_eq!(e.kind(), ErrorKind::Corrupt);
        assert!(e.message().contains("ends at byte 1000, before the end of its file system (4096)"), "{e}");
        assert!(e.message().contains("from byte 2048 cannot be read"), "{e}");
        assert!(Error::used_past_end(1000, 4096, 512).message().contains("from byte 1000 cannot be read"));
    }

    /// `at_device` on a result places its error on a device, and an inner location stays.
    #[test]
    fn a_result_s_error_is_placed_once() {
        let r: Result<(), SourceError> = Err(SourceError::out_of_range(10, 4, 12));
        let e = r.at_device("vhdx bat", 0x300).unwrap_err();
        assert_eq!(e.location(), Some(Location { space: Space::Device, structure: "vhdx bat", offset: 0x300 }));
        let r: Result<()> = Err(e);
        assert_eq!(r.at("superblock", 0).unwrap_err().location().map(|l| l.space), Some(Space::Device));
        // A source error's text and cause are its error's.
        let s = SourceError::out_of_range(10, 4, 12);
        assert_eq!(s.to_string(), Error::from(s.clone()).to_string());
        assert!(std::error::Error::source(&s).is_some_and(|c| c.is::<OutOfRange>()));
        assert!(format!("{s:?}").starts_with("SourceError"));
    }
}
