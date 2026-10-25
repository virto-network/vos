//! The pallet's types as SCALE encodes them (`spaces-pallet.md` §5, §6,
//! §8): each derived, its variants and fields in the design's order and at
//! its pinned indices, so its bytes are FRAME's.

use parity_scale_codec::{Decode, Encode};
use vos_anchor::venue::{self as rules, Held, Roots, VenueState};
use vos_anchor::{RootKind, RootRead, SpaceId, VenueId};
use vos_statement::{StatementId, Venue};

use super::Chain;
use super::keys;

/// An `AccountId32`.
pub type AccountId = [u8; 32];
/// A space's id, its genesis's hash.
pub type Space = [u8; 32];
/// Kreivo's balance.
pub type Balance = u128;

/// The pallet's index in Kreivo's runtime, every call's first byte.
pub const PALLET_INDEX: u8 = 90;
/// Kreivo's `Balances` index, the one inner call the mock dispatches as a
/// space's sovereign account (`dispatch_as_sovereign`).
pub const BALANCES_INDEX: u8 = 10;

/// A space's status. Index 1 is retired, never reused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub enum SpaceStatus {
    Active = 0,
    /// Governance blocked it.
    Blocked = 2,
    /// An equivocation ended it, for good.
    Ended = 3,
}

impl From<SpaceStatus> for rules::Status {
    fn from(status: SpaceStatus) -> Self {
        match status {
            SpaceStatus::Active => Self::Active,
            SpaceStatus::Blocked => Self::Blocked,
            SpaceStatus::Ended => Self::Ended,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Handler {
    Record = 0,
}

/// `Spaces[space]`.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct SpaceInfo {
    pub sovereign: AccountId,
    pub controller: AccountId,
    pub origin_ms: u64,
    pub length_ms: u64,
    /// The first window anchored here: the venue's next at registration.
    pub start_window: u64,
    pub status: SpaceStatus,
    pub authorities: u8,
    pub anchor_keys: u8,
    pub registered_ms: u64,
    pub max_spend_per_window: Balance,
}

/// `Authorities[space][who]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct AuthorityInfo {
    pub anchor_key: Option<[u8; 32]>,
}

/// `Anchors[(space, kind, window)]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct AnchorRecord {
    pub root: [u8; 32],
    pub at_ms: u64,
    pub signer: [u8; 32],
}

/// `Equivocations[(space, kind, window)]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Evidence {
    pub first: [u8; 32],
    pub second: [u8; 32],
    pub first_signer: [u8; 32],
    pub second_signer: [u8; 32],
}

/// `Budget[space]`: the spend of one window, by the venue's time.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Spend {
    pub window: u64,
    pub spent: Balance,
}

/// When a format or a program is accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Active {
    pub from_ms: u64,
    pub until_ms: Option<u64>,
}

impl Active {
    /// Whether it is active at `now`.
    pub fn at(&self, now: u64) -> bool {
        self.from_ms <= now && self.until_ms.is_none_or(|until| now < until)
    }
}

/// `Programs[program]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct ProgramInfo {
    pub handler: Handler,
    pub active: Active,
}

/// `anchor`'s argument: `vos-anchor`'s `Anchor`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct AnchorArg {
    pub space: Space,
    pub window: u64,
    pub kind: u8,
    pub root: [u8; 32],
    /// The ed25519 anchor key.
    pub signer: [u8; 32],
    pub signature: [u8; 64],
}

/// The pallet's calls at their pinned indices (§6); 5 and 6 are retired,
/// never reused. The vectors are `BoundedVec<u8, _>`, whose encoding is a
/// `Vec<u8>`'s: the bounds are checked after the decode
/// ([`Call::within`]).
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Call {
    #[codec(index = 0)]
    Register {
        genesis: Vec<u8>,
        controller: AccountId,
        founder_key: [u8; 32],
        founder_sig: [u8; 64],
    },
    #[codec(index = 1)]
    SetController { space: Space, controller: AccountId },
    #[codec(index = 2)]
    AddAuthority {
        space: Space,
        who: AccountId,
        anchor_key: Option<[u8; 32]>,
    },
    #[codec(index = 3)]
    RemoveAuthority { space: Space, who: AccountId },
    #[codec(index = 4)]
    RemoveAnchorKey { space: Space, key: [u8; 32] },
    #[codec(index = 7)]
    Anchor { anchor: AnchorArg },
    #[codec(index = 8)]
    Submit {
        payer: Space,
        statement: Vec<u8>,
        proof: Vec<u8>,
    },
    #[codec(index = 9)]
    DispatchAsSovereign {
        space: Space,
        call: Box<RuntimeCall>,
    },
    #[codec(index = 10)]
    SetBudget {
        space: Space,
        max_spend_per_window: Balance,
    },
    #[codec(index = 16)]
    SetFormat { format: u32, active: Active },
    #[codec(index = 17)]
    SetProgram {
        program: [u32; 8],
        info: Option<ProgramInfo>,
    },
    #[codec(index = 18)]
    SetPaused { flags: u8 },
    #[codec(index = 19)]
    SetStatus { space: Space, blocked: bool },
}

/// `Balances`' one call the mock dispatches.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum BalancesCall {
    #[codec(index = 3)]
    TransferKeepAlive {
        dest: MultiAddress,
        #[codec(compact)]
        value: Balance,
    },
}

/// Kreivo's lookup source, its `Id` variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub enum MultiAddress {
    #[codec(index = 0)]
    Id(AccountId),
}

/// Kreivo's `RuntimeCall`, as far as the mock dispatches it.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum RuntimeCall {
    #[codec(index = 10)]
    Balances(BalancesCall),
    #[codec(index = 90)]
    Spaces(Call),
}

/// The design's bounds on the calls' vectors (`MaxGenesisLen`,
/// `MaxStatementLen`, `MaxProofLen`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bounds {
    pub genesis: usize,
    pub statement: usize,
    pub proof: usize,
}

impl RuntimeCall {
    /// Whether every bounded vector in it, nested calls' too, is within
    /// its bound: a `BoundedVec` longer than its bound does not decode.
    pub fn within(&self, bounds: &Bounds) -> bool {
        match self {
            Self::Balances(_) => true,
            Self::Spaces(call) => call.within(bounds),
        }
    }
}

impl Call {
    pub fn within(&self, bounds: &Bounds) -> bool {
        match self {
            Self::Register { genesis, .. } => genesis.len() <= bounds.genesis,
            Self::Submit {
                statement, proof, ..
            } => statement.len() <= bounds.statement && proof.len() <= bounds.proof,
            Self::DispatchAsSovereign { call, .. } => call.within(bounds),
            _ => true,
        }
    }
}

/// `sp_runtime::DispatchError`, its variants the mock reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub enum DispatchError {
    #[codec(index = 2)]
    BadOrigin,
    #[codec(index = 3)]
    Module(ModuleError),
    #[codec(index = 7)]
    Token(TokenError),
}

/// `sp_runtime::ModuleError`: the pallet's index and the error's, then
/// three zero bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct ModuleError {
    pub index: u8,
    pub error: [u8; 4],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub enum TokenError {
    #[codec(index = 0)]
    FundsUnavailable,
}

/// The pallet's errors at their pinned indices (§8); 18, 23, 24, 26 and 28
/// are retired, never reused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Error {
    SpaceExists = 0,
    UnknownSpace = 1,
    BadGenesis = 2,
    BadClock = 3,
    BadFounder = 4,
    SovereignInUse = 5,
    NotController = 6,
    NotAuthority = 7,
    TooManyAuthorities = 8,
    TooManyAnchorKeys = 9,
    AnchorKeyInUse = 10,
    UnknownAnchorKey = 11,
    BadAnchorSignature = 12,
    BadKind = 13,
    AlreadyAnchored = 14,
    WindowNotAfterLast = 15,
    WindowInFuture = 16,
    WindowTooOld = 17,
    SpaceNotActive = 19,
    Paused = 20,
    InsufficientSovereignBalance = 21,
    TooEarly = 22,
    BadHandler = 25,
    OverBudget = 27,
    /// `add_authority` of an account that is one already.
    AuthorityExists = 29,
    /// An anchor key of small order (`vos_anchor::venue::small_order`).
    BadAnchorKey = 30,
}

impl From<Error> for DispatchError {
    fn from(error: Error) -> Self {
        Self::Module(ModuleError {
            index: PALLET_INDEX,
            error: [error as u8, 0, 0, 0],
        })
    }
}

/// The pallet's events at their pinned indices (§8); 5 and 9 are retired,
/// never reused.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Event {
    #[codec(index = 0)]
    SpaceRegistered {
        space: Space,
        sovereign: AccountId,
        controller: AccountId,
        origin_ms: u64,
        length_ms: u64,
        start_window: u64,
    },
    #[codec(index = 1)]
    ControllerSet { space: Space, controller: AccountId },
    #[codec(index = 2)]
    AuthorityAdded {
        space: Space,
        who: AccountId,
        anchor_key: Option<[u8; 32]>,
    },
    #[codec(index = 3)]
    AuthorityRemoved { space: Space, who: AccountId },
    #[codec(index = 4)]
    AnchorKeyRemoved { space: Space, key: [u8; 32] },
    #[codec(index = 6)]
    Anchored {
        space: Space,
        kind: u8,
        window: u64,
        root: [u8; 32],
    },
    #[codec(index = 7)]
    Equivocated {
        space: Space,
        kind: u8,
        window: u64,
        first: [u8; 32],
        second: [u8; 32],
        first_signer: [u8; 32],
        second_signer: [u8; 32],
    },
    #[codec(index = 8)]
    SpaceEnded { space: Space },
    #[codec(index = 10)]
    SpaceStatusSet { space: Space, status: SpaceStatus },
    #[codec(index = 11)]
    Accepted {
        id: [u8; 32],
        program: [u32; 8],
        space: Space,
        payer: Space,
        output_hash: [u8; 32],
    },
    #[codec(index = 12)]
    Refused {
        payer: Space,
        statement_hash: [u8; 32],
        code: u32,
    },
    #[codec(index = 13)]
    DepositForfeited { space: Space, amount: Balance },
    #[codec(index = 14)]
    FormatSet { format: u32, active: Active },
    #[codec(index = 15)]
    ProgramSet {
        program: [u32; 8],
        info: Option<ProgramInfo>,
    },
    #[codec(index = 16)]
    PausedSet { flags: u8 },
    #[codec(index = 17)]
    SovereignDispatched {
        space: Space,
        result: Result<(), DispatchError>,
    },
    #[codec(index = 18)]
    BudgetSet {
        space: Space,
        max_spend_per_window: Balance,
    },
}

/// `Paused`'s flags.
pub const PAUSE_SUBMIT: u8 = 1;
pub const PAUSE_ANCHOR: u8 = 2;
pub const PAUSE_REGISTER: u8 = 4;

/// The pallet's storage as the venue rules (`vos_anchor::venue`) and
/// `judge` read it (§3, §6.1).
pub(crate) struct StorageVenue<'a> {
    pub(super) chain: &'a Chain,
}

impl Roots for StorageVenue<'_> {
    fn now(&self) -> u64 {
        self.chain.now_ms
    }

    fn space(&self, space: &SpaceId) -> Option<rules::Space> {
        self.chain.space(&space.0).map(|info| rules::Space {
            clock: Chain::clock(&info),
            start: info.start_window,
            status: info.status.into(),
        })
    }

    fn held(&self, space: &SpaceId, kind: RootKind, window: u64) -> Option<Held> {
        self.chain
            .get::<AnchorRecord>(&keys::anchors(&space.0, kind as u8, window))
            .map(|record| Held {
                root: record.root,
                signer: record.signer,
            })
    }
}

impl VenueState for StorageVenue<'_> {
    fn venue(&self) -> VenueId {
        self.chain.constants.venue
    }

    fn listed(&self, space: &SpaceId, key: &[u8; 32]) -> bool {
        self.chain
            .storage
            .contains_key(&keys::anchor_keys(&space.0, key))
    }

    fn last(&self, space: &SpaceId, kind: RootKind) -> Option<u64> {
        self.chain.get(&keys::last(&space.0, kind as u8))
    }

    fn verify(&self, key: &[u8; 32], digest: &[u8; 32], signature: &[u8; 64]) -> bool {
        crate::verify(key, digest, signature)
    }
}

impl Venue for StorageVenue<'_> {
    fn accepts(&self, format: u32) -> bool {
        self.chain
            .get::<Active>(&keys::formats(format))
            .is_some_and(|active| self.chain.active(&active))
    }

    fn anchored(&self, root: &RootRead) -> bool {
        rules::anchored(self, root)
    }

    fn seen(&self, id: &StatementId) -> bool {
        self.chain.storage.contains_key(&keys::seen(&id.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every error at its pinned index, as FRAME reports it:
    /// `DispatchError::Module { index: 90, error: [i, 0, 0, 0] }`.
    #[test]
    fn the_errors_are_at_their_pinned_indices() {
        use Error::*;
        let all = [
            (0, SpaceExists),
            (1, UnknownSpace),
            (2, BadGenesis),
            (3, BadClock),
            (4, BadFounder),
            (5, SovereignInUse),
            (6, NotController),
            (7, NotAuthority),
            (8, TooManyAuthorities),
            (9, TooManyAnchorKeys),
            (10, AnchorKeyInUse),
            (11, UnknownAnchorKey),
            (12, BadAnchorSignature),
            (13, BadKind),
            (14, AlreadyAnchored),
            (15, WindowNotAfterLast),
            (16, WindowInFuture),
            (17, WindowTooOld),
            (19, SpaceNotActive),
            (20, Paused),
            (21, InsufficientSovereignBalance),
            (22, TooEarly),
            (25, BadHandler),
            (27, OverBudget),
            (29, AuthorityExists),
            (30, BadAnchorKey),
        ];
        for (index, error) in all {
            assert_eq!(error as usize, index);
            assert_eq!(
                DispatchError::from(error).encode(),
                [3, PALLET_INDEX, index as u8, 0, 0, 0]
            );
        }
    }

    /// A call's bytes are `[90, call_index] ++ SCALE(args)`; `anchor`'s
    /// argument is an `Anchor` in `vos-anchor`'s encoding.
    #[test]
    fn a_call_is_its_pinned_bytes() {
        let budget = RuntimeCall::Spaces(Call::SetBudget {
            space: [7; 32],
            max_spend_per_window: 1,
        })
        .encode();
        assert_eq!(budget[..34], [&[90, 10][..], &[7; 32]].concat());
        let paused = RuntimeCall::Spaces(Call::SetPaused { flags: 5 }).encode();
        assert_eq!(paused, [90, 18, 5]);
        let anchor = vos_anchor::Anchor {
            space: vos_anchor::SpaceId([1; 32]),
            window: 0x0102_0304,
            kind: vos_anchor::RootKind::Space,
            root: [2; 32],
            signer: [3; 32],
            signature: [4; 64],
        };
        let arg = AnchorArg {
            space: anchor.space.0,
            window: anchor.window,
            kind: 0,
            root: anchor.root,
            signer: anchor.signer,
            signature: anchor.signature,
        };
        let call = RuntimeCall::Spaces(Call::Anchor { anchor: arg }).encode();
        assert_eq!(call, [&[90, 7][..], &anchor.encode()].concat());
    }

    /// An event's first byte is its pinned index.
    #[test]
    fn an_event_leads_with_its_pinned_index() {
        let budget = Event::BudgetSet {
            space: [0; 32],
            max_spend_per_window: 1,
        };
        assert_eq!(budget.encode()[0], 18);
        let refused = Event::Refused {
            payer: [0; 32],
            statement_hash: [0; 32],
            code: 0x112,
        };
        assert_eq!(
            refused.encode(),
            [&[12][..], &[0; 64], &[0x12, 1, 0, 0]].concat()
        );
    }
}
