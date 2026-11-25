//! Why an operation failed, and why a candidate was refused.

use mls_rs::error::MlsError;

/// Why an operation failed. A failed operation writes nothing: the
/// current state stays as the last batch left it. Two exceptions, both a
/// store's failure: a batch whose sync failed may be found applied after a
/// reopen, and an error reading the group back after
/// a written batch leaves that batch written.
#[derive(Debug)]
pub enum Error {
    Store(fjall::Error),
    /// A row the store cannot hold: an empty key, a key over 65,535 bytes
    /// or a value of 4 GiB or more.
    Unstorable,
    Mls(MlsError),
    /// A candidate refused: it is not a commit this group's rules and
    /// state accept. Its committer's to answer for.
    Refused(Refusal),
    /// No group yet, or none any more.
    NoGroup,
    /// A group already, where an operation makes one.
    Grouped,
    /// A commit is held already: confirm or void it first.
    Held,
    /// No commit held, or not the candidate's, or not for the epoch after
    /// the current one.
    NotHeld,
    /// A candidate swapped over a state it was not made from: another
    /// group or epoch than the current one, or, for the device's own, a
    /// commit held since.
    Stale,
    /// A namespace row that does not read.
    Corrupt,
    /// A credential that is not a device's 64 bytes.
    Credential,
}

impl From<fjall::Error> for Error {
    fn from(error: fjall::Error) -> Self {
        Error::Store(error)
    }
}

impl From<MlsError> for Error {
    fn from(error: MlsError) -> Self {
        Error::Mls(error)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Store(error) => write!(f, "the MLS store: {error}"),
            Error::Unstorable => f.write_str("a row the MLS store cannot hold"),
            Error::Mls(error) => write!(f, "MLS: {error:?}"),
            Error::Refused(refusal) => write!(f, "a candidate refused: {refusal:?}"),
            Error::NoGroup => f.write_str("no group"),
            Error::Grouped => f.write_str("a group already"),
            Error::Held => f.write_str("a commit is held already"),
            Error::NotHeld => f.write_str("not the commit held"),
            Error::Stale => f.write_str("a candidate of a state no longer current"),
            Error::Corrupt => f.write_str("an MLS row does not read"),
            Error::Credential => f.write_str("a credential that is not a device's"),
        }
    }
}

impl std::error::Error for Error {}

/// Why a candidate was refused.
#[derive(Debug)]
pub enum Refusal {
    /// Not an MLS message.
    Malformed,
    /// A handshake in the clear: the group's are encrypted.
    Plaintext,
    /// Not a commit.
    NotCommit,
    /// A commit whose committer kept its leaf: no path.
    NoPath,
    /// A Welcome into a group this layer does not keep: its id longer than
    /// the suite's hash, or its epoch past half of what a `u64` counts.
    Group,
    /// A commit whose committer's leaf is not the one its log entry names:
    /// another credential than the expected one (the renewed one, when a
    /// renewal is expected), or another signature key.
    Leaf,
    /// mls-rs refused it: its framing, its signature, its secrets, or the
    /// group's rules.
    Rejected(MlsError),
}
