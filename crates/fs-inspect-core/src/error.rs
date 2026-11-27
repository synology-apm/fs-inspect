//! [`Error`] (the library's one error type, defined with the sources it starts at in
//! `fs_inspect_io`) and [`ParseError`], what a structure's parser fails with.

pub use fs_inspect_io::error::{
    Error, ErrorKind, Location, OutOfRange, Result, ResultExt, Scope, SourceError, SourceErrorKind, Space,
};

/// Local (per-structure) parse failure: offsets are relative to the slice being parsed. Turn it
/// into an [`Error`] with `?`, and say where the slice lies with [`Error::at`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    #[error("truncated structure: need {need} bytes at offset {offset}, have {have}")]
    Truncated { offset: usize, need: usize, have: usize },
    #[error("invalid {what}: {detail}")]
    Invalid { what: &'static str, detail: String },
    #[error("limit exceeded: {0}")]
    Limit(&'static str),
}

impl ParseError {
    pub fn invalid(what: &'static str, detail: impl Into<String>) -> Self {
        ParseError::Invalid { what, detail: detail.into() }
    }
}

/// The message without what the kind says (`limit exceeded`, `corrupt structure`), which the
/// error's display puts in front.
impl From<ParseError> for Error {
    fn from(e: ParseError) -> Self {
        match e {
            ParseError::Limit(what) => Error::new(ErrorKind::Limit, what),
            ParseError::Truncated { offset, need, have } => {
                Error::new(ErrorKind::Corrupt, format!("truncated: need {need} bytes at offset {offset}, have {have}"))
            }
            ParseError::Invalid { .. } => Error::new(ErrorKind::Corrupt, e.to_string()),
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn parse_errors_have_their_kinds() {
        let e: Error = ParseError::Limit("records").into();
        assert_eq!((e.kind(), e.to_string().as_str()), (ErrorKind::Limit, "limit exceeded: records"));
        let c = e.context("xfs inode 5");
        assert_eq!((c.kind(), c.to_string().as_str()), (ErrorKind::Limit, "limit exceeded: xfs inode 5: records"));
        let t: Error = ParseError::Truncated { offset: 4, need: 8, have: 6 }.into();
        assert_eq!(t.kind(), ErrorKind::Corrupt);
        assert!(t.scope() == Scope::Unit);
    }
}
