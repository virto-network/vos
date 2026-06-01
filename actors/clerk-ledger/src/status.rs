//! Handler status enum + kernel `EventStatus` mapping.
//!
//! `Status` is the wire return type for every state-mutating
//! handler in `ClerkLedger`. `map_event_status` collapses the
//! kernel's finer-grained `EventStatus` taxonomy into the coarser
//! Status variants exposed at the handler boundary.

use cipher_clerk::error::EventStatus;

/// Return type for every state-mutating handler. The variants
/// classify what happened in coarse-but-meaningful buckets:
/// callers `match` on this to decide what to do rather than
/// comparing raw byte codes. The `#[repr(u8)]` discriminants are
/// wire-stable — bumping the type or reordering variants WILL
/// shift the rkyv archive bytes and break peer banks running
/// older builds.
///
/// Many of these collapse multiple kernel `EventStatus` variants
/// (see `map_event_status`). The kernel's taxonomy is
/// finer-grained than what's useful at the handler boundary;
/// callers that need the kernel's exact reason should consult
/// the kernel directly via the refine path. The handler boundary
/// is for "did this work and if not, broadly why".
#[derive(
    vos::rkyv::Archive,
    vos::rkyv::Serialize,
    vos::rkyv::Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
)]
#[rkyv(crate = vos::rkyv)]
#[repr(u8)]
pub enum Status {
    /// Handler succeeded.
    Ok = 0,
    /// Input bytes had the wrong length or rkyv shape.
    BadInput = 1,
    /// `bootstrap` called twice with conflicting arguments.
    /// Identical re-calls return `Ok`.
    AlreadyBootstrapped = 2,
    /// Operation requires `bootstrap` to have run first.
    NotBootstrapped = 3,
    /// Kernel rejected for `InvalidSignature`. Also the
    /// state-hiding bucket the pre-verify gate collapses
    /// signature failure, account-not-found, and
    /// signature-count mismatch into, so attackers can't probe
    /// state by submitting junk-signed transfers.
    SignatureInvalid = 4,
    /// Kernel rejected for `AccountIdAlreadyExists` or
    /// `TransferIdAlreadyExists` — the operation collided with a
    /// record already in state.
    IdAlreadyExists = 5,
    /// Kernel rejected for `JournalNotFound` or
    /// `JournalIdMustNotBeZero`.
    WrongJournal = 6,
    /// Kernel rejected for an account-creation field-invariant
    /// violation: `IdMustNotBeZero`, `TimestampMustBeZero`,
    /// `BalancesMustBeZeroOnCreate`.
    InvalidAccount = 7,
    /// Kernel rejected for a transfer field-invariant violation:
    /// `EntriesMustNotBeEmpty`, `AccountsMustBeDifferent`,
    /// `DuplicateEntryId`, `SignatureCountMismatch`,
    /// `AccountsMustHaveSameJournal`, `EntryLedgerMismatch`,
    /// `LayerMismatchWithPending`, `VoidEntriesMustMirror`,
    /// `UnbalancedTransfer`, `BalanceMustNotBeNegative`,
    /// `OverflowsBalance`, …
    TransferInvariant = 8,
    /// An `Amount` commitment in the transfer could not be
    /// opened against the caller-supplied openings, or the
    /// reveal didn't match the commitment.
    AmountUnrecoverable = 9,
    /// An account referenced by the transfer doesn't exist (in
    /// paths that don't collapse this into `SignatureInvalid`).
    AccountNotFound = 10,
    /// Transfer's `external_id` was already used by a prior
    /// accepted transfer in this journal.
    ExternalIdReused = 11,
    /// Pending-lifecycle violation: `PendingTransferNotPending`,
    /// `PendingTransferAlreadyPosted`,
    /// `PendingTransferAlreadyVoided`, `PendingIdMustBeSet`,
    /// `PendingIdMustNotBeSet`, …
    PendingViolation = 12,
    /// Account is closed and cannot accept further debits or
    /// credits.
    AccountClosed = 13,
    /// Linked-chain semantics broke: one of the linked events
    /// failed or the chain was left open.
    LinkedChainFailure = 14,
    /// Caller submitted an `IMPORTED`-flagged transfer
    /// (cipher-clerk's replay-from-history mode). clerk-ledger
    /// doesn't yet support that workflow — rejected loudly with
    /// this status rather than silently bucketing into
    /// `TransferInvariant`.
    ImportedUnsupported = 15,
    /// The kernel returned an `EventStatus` variant the handler's
    /// taxonomy doesn't map — should be unreachable; widen
    /// `map_event_status` if it fires.
    KernelUnexpected = 255,
}

/// Map the kernel's `EventStatus` to clerk-ledger's coarser
/// `Status` taxonomy. Covers both account-creation and transfer
/// paths so a single handler doesn't need a dispatch-specific
/// mapper.
pub(crate) fn map_event_status(s: EventStatus) -> Status {
    use EventStatus::*;
    match s {
        Created => Status::Ok,

        InvalidSignature => Status::SignatureInvalid,

        AccountIdAlreadyExists | TransferIdAlreadyExists => Status::IdAlreadyExists,
        JournalNotFound | JournalIdMustNotBeZero => Status::WrongJournal,

        IdMustNotBeZero | TimestampMustBeZero | BalancesMustBeZeroOnCreate => {
            Status::InvalidAccount
        }

        AccountNotFound | TransferNotFound => Status::AccountNotFound,
        ExternalIdAlreadyUsed => Status::ExternalIdReused,
        DebitAccountAlreadyClosed | CreditAccountAlreadyClosed => Status::AccountClosed,
        LinkedEventFailed | LinkedChainOpen => Status::LinkedChainFailure,

        InvalidAmount | RangeCheckFailed | BlindingMismatch => Status::AmountUnrecoverable,

        PendingTransferNotPending
        | PendingTransferAlreadyPosted
        | PendingTransferAlreadyVoided
        | PendingIdMustBeSet
        | PendingIdMustNotBeSet
        | PendingTransferNotMarkedPending
        | PendingFlagRequiresPendingLayer
        | PendingFinalizationMustHaveNoEntries
        | PendingFinalizationMustNotVoid => Status::PendingViolation,

        LedgerMustNotBeZero
        | EntriesMustNotBeEmpty
        | AccountsMustBeDifferent
        | DuplicateEntryId
        | SignatureCountMismatch
        | TransferAlreadyVoided
        | AccountsMustHaveSameJournal
        | EntryLedgerMismatch
        | LayerMismatchWithPending
        | VoidEntriesMustMirror
        | UnbalancedTransfer
        | BalanceMustNotBeNegative
        | OverflowsBalance => Status::TransferInvariant,

        // IMPORTED-flagged transfers (cipher-clerk's
        // replay-from-history mode) are not yet supported. Surface
        // a dedicated status so debuggers don't misread a valid
        // IMPORTED rejection as a generic invariant violation.
        ImportedTimestampMustPostdateAccount | ImportedTimestampMustBeNonzero => {
            Status::ImportedUnsupported
        }
    }
}
