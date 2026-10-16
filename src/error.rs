//! Error types for OpenSentinel.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// Bad user input (unknown flag, missing path).
    InvalidArgument,
    /// I/O failure on a file the scan targeted.
    Io,
    /// Configuration problem.
    Config,
    /// Quarantine problem.
    Quarantine,
    /// Signature database problem.
    Signatures,
    /// Scan was cancelled by the user.
    Cancelled,
}

#[derive(Debug)]
pub struct Error {
    pub kind: ErrorKind,
    pub msg: String,
}

impl Error {
    pub fn new(kind: ErrorKind, msg: impl Into<String>) -> Self {
        Self {
            kind,
            msg: msg.into(),
        }
    }
    /// Process exit code associated with this error.
    pub fn code(&self) -> i32 {
        match self.kind {
            ErrorKind::Cancelled => 130,
            _ => 1,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.msg)
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::new(ErrorKind::Io, e.to_string())
    }
}

/// Result alias using OpenSentinel's error type.
pub type Result<T> = std::result::Result<T, Error>;
