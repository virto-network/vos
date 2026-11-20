//! Why a flow of the personal space stopped: each case the state it names,
//! so a UI branches on it and words it itself. [`Error`]'s `Display` is
//! the plain sentence a log or a test reads.

use vos_wire::credentials::CredentialError;
use vos_wire::homes::HomesError;
use vos_wire::personal::PersonalError;

/// Why a flow stopped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    // ----- what the device holds -----
    /// The device holds no personal space.
    NoSpace,
    /// It holds one already.
    AlreadyHeld,
    /// It holds a personal space's keys already: restore or pair it.
    HoldsKeys,
    /// A claim at the home whose handle this is is under way: claim there
    /// again to finish it.
    ClaimElsewhere { home: [u8; 32] },
    /// The personal space is at that home already.
    AtThatHome,
    /// No restore is pending.
    NoRestore,
    /// No pairing was offered.
    NoPairing,
    /// The personal space's store, or a row of it, is one this build does
    /// not read: kept as it is; sign-in and payments run.
    NeedsRepair(String),

    // ----- the user -----
    /// The user declined a prompt.
    Declined,
    /// The user cancelled the pairing.
    Cancelled,
    /// Those are not the kit's 24 words.
    NotAKit,
    /// The kit opens no archive the agent holds.
    WrongKit,
    /// Not a pairing code.
    NotAPairingCode,
    /// Not a device's admin-key code.
    NotAnOffer,
    /// An admin-key code not signed by the device it names, or signed
    /// over an admin key the set no longer shows.
    StaleOffer,
    /// A device signs no replacement of its own key.
    OwnKey,
    /// The device named is not in the set as this device read it.
    NotInSet,
    /// The secret source, a security key or the keystore failed.
    Source(String),

    // ----- the home -----
    /// The home admits no open claim.
    NoOpenClaim,
    /// The home's registrar refused the open claim.
    OpenClaimRefused(String),
    /// The home has no agent to give.
    NoAgentToGive,
    /// The home holds no agent for this kit.
    NoAgentForKit,
    /// This device holds an agent at that home already.
    HoldsAgentThere,
    /// The home's node knows no such agent.
    UnknownAgent,
    /// The home's tree holds no leaf of this device yet.
    NoLeaf,
    /// `Homes` refused the claim.
    HomeRefused(HomesError),
    /// The space no longer admits this app's proofs: update the app.
    Update,
    /// A space's ingress refused a proven call.
    Rejected(String),

    // ----- the personal agent and the device set -----
    /// The agent refused.
    AgentRefused(PersonalError),
    /// The agent has not taken the claim yet.
    NotTakenYet,
    /// The commit adding this device is not confirmed yet.
    NotJoinedYet,
    /// The commit adding the device awaits the other devices' votes.
    AwaitsVotes,
    /// Another device's commit is undecided: pair once the others synced.
    Undecided,
    /// The commit adding the device was void: pair again.
    CommitVoid,
    /// Another device committed during the pairing: pair again.
    CommittedMeanwhile,
    /// The pairing's slot expired.
    SlotExpired,
    /// The other device declined the pairing, which closed its slot.
    PairingDeclined,
    /// The device is in that personal space already.
    InSetAlready,
    /// The agent's set holds no device of this sync key.
    NotInAgentSet,
    /// Device `by`'s regroup starts a new group of it alone: this device
    /// pairs again from it.
    Regrouped { by: u32 },
    /// This device is a delayed admin (its admin key is not
    /// hardware-backed): a pairing is opened on a strong admin's device.
    DelayedAdmin,

    // ----- other spaces -----
    /// This device is not enrolled in that space here yet.
    NotEnrolled,
    /// Nothing is owed there.
    NothingOwed,
    /// The registrar's replacements are spent for the year.
    Spent,
    /// The registrar refused, with its error if it named one.
    RegistrarRefused(Option<CredentialError>),

    // ----- the machinery -----
    /// No answer came.
    Unreachable(String),
    /// The proof was not made.
    Prove(String),
    /// The light node's store failed.
    Store(String),
    /// Anything else.
    Failed(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::NoSpace => f.write_str("this device holds no personal space"),
            Error::AlreadyHeld => f.write_str("this device holds a personal space already"),
            Error::HoldsKeys => {
                f.write_str("this device holds a personal space's keys already: restore or pair it")
            }
            Error::ClaimElsewhere { .. } => {
                f.write_str("a claim at another home is under way: claim there again to finish it")
            }
            Error::AtThatHome => f.write_str("the personal space is at that home already"),
            Error::NoRestore => f.write_str("no restore is pending"),
            Error::NoPairing => f.write_str("no pairing was offered"),
            Error::NeedsRepair(why) => write!(
                f,
                "the personal space needs repair: {why}. Nothing was changed; sign-in and \
                 payments are not affected"
            ),
            Error::Declined => f.write_str("the user declined"),
            Error::Cancelled => f.write_str("the pairing was cancelled"),
            Error::NotAKit => f.write_str("those are not the kit's 24 words"),
            Error::WrongKit => f.write_str("the kit opens no archive the agent holds"),
            Error::NotAPairingCode => f.write_str("not a pairing code"),
            Error::NotAnOffer => f.write_str("that is no device's admin-key code"),
            Error::StaleOffer => {
                f.write_str("that admin-key code is not signed by the device it names, or is stale")
            }
            Error::OwnKey => f.write_str(
                "the personal agent refused: Targeted (a device signs no replacement of its own \
                 key)",
            ),
            Error::NotInSet => f.write_str(
                "that device is not in the set as this device has read it: sync and try again",
            ),
            Error::Source(why) => f.write_str(why),
            Error::NoOpenClaim => f.write_str("the home admits no open claim"),
            Error::OpenClaimRefused(why) => write!(f, "the open claim: {why}"),
            Error::NoAgentToGive => f.write_str("the home has no agent to give"),
            Error::NoAgentForKit => f.write_str("the home holds no agent for this kit"),
            Error::HoldsAgentThere => {
                f.write_str("this device holds an agent at that home already")
            }
            Error::UnknownAgent => f.write_str("the home's node knows no such agent"),
            Error::NoLeaf => f.write_str("the home's tree holds no leaf of this device"),
            Error::HomeRefused(error) => write!(f, "`Homes` refused the claim: {error:?}"),
            Error::Update => {
                f.write_str("the space no longer admits this app's proofs: update the app")
            }
            Error::Rejected(why) => write!(f, "the space's ingress: {why}"),
            Error::AgentRefused(error) => write!(f, "the personal agent refused: {error:?}"),
            Error::NotTakenYet => f.write_str("the agent has not taken the claim yet"),
            Error::NotJoinedYet => f.write_str(
                "the commit adding this device is not confirmed yet: it joins once the other \
                 devices confirm it, unless the device it paired from shows it void",
            ),
            Error::AwaitsVotes => f.write_str(
                "the commit adding the device awaits the other devices' votes: it is the set's \
                 once they confirm it",
            ),
            Error::Undecided => f.write_str(
                "another device's commit is undecided: pair once the other devices have synced",
            ),
            Error::CommitVoid => f.write_str("the commit adding the device was void: pair again"),
            Error::CommittedMeanwhile => {
                f.write_str("another device committed during the pairing: pair again")
            }
            Error::SlotExpired => f.write_str("the pairing's slot expired"),
            Error::PairingDeclined => f.write_str("the other device declined the pairing"),
            Error::InSetAlready => f.write_str("this device is in that personal space already"),
            Error::NotInAgentSet => f.write_str("the agent's set holds no device of this sync key"),
            Error::Regrouped { by } => write!(
                f,
                "device {by}'s regroup starts a new group of it alone: this device pairs again \
                 from it"
            ),
            Error::DelayedAdmin => f.write_str(
                "this device's admin key is not hardware-backed: open the pairing on a device \
                 whose key is",
            ),
            Error::NotEnrolled => f.write_str("this device is not enrolled in that space here yet"),
            Error::NothingOwed => f.write_str("nothing is owed there"),
            Error::Spent => f.write_str("replacements spent; next year, or ask the registrar"),
            Error::RegistrarRefused(error) => write!(f, "the registrar refused: {error:?}"),
            Error::Unreachable(why) | Error::Prove(why) | Error::Failed(why) => f.write_str(why),
            Error::Store(why) => write!(f, "the personal space's store: {why}"),
        }
    }
}

impl std::error::Error for Error {}

/// The light node's failure as a flow names it.
pub(crate) fn failed(error: impl std::fmt::Display) -> Error {
    Error::Failed(error.to_string())
}

pub(crate) fn unreached(error: impl std::fmt::Display) -> Error {
    Error::Unreachable(error.to_string())
}

/// A link's answer as a flow names it: the link's failure, then the
/// agent's refusal.
pub(crate) fn answered<T>(answer: crate::personal::Answer<T, String>) -> Result<T, Error> {
    answer.map_err(unreached)?.map_err(Error::AgentRefused)
}

/// The control log from `from` to its head over `link`, read as a pass
/// reads it ([`crate::job::log`]: each page through the onion, past the
/// one before): the agent's refusal, or the link's failure.
pub(crate) fn logged(
    link: &mut impl crate::job::Control<Error = String>,
    from: u64,
) -> Result<Vec<(u64, vos_wire::personal::Entry)>, Error> {
    crate::job::log(link, from).map_err(|error| match error {
        crate::personal::SyncError::Refused(error) => Error::AgentRefused(error),
        error => unreached(error),
    })
}

pub(crate) fn store_failed(error: impl std::fmt::Display) -> Error {
    Error::Store(error.to_string())
}
