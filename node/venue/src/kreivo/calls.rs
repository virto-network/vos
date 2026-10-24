//! Kreivo's spaces pallet as the node's client speaks it
//! (`spaces-pallet.md` §5, §6, §8, §9): the calls by their pinned bytes,
//! `[90, call_index] ++ SCALE(args)`; the storage the node reads by its
//! raw keys; the pallet's events, errors and stored values by their pinned
//! layouts. Written apart from the mock's types, so the conformance
//! vectors, which the mock made, check the one against the other.

use parity_scale_codec::{Decode, DecodeAll, Encode};
use vos_anchor::{Anchor, SpaceId};

/// An `AccountId32`.
pub type AccountId = [u8; 32];
/// Kreivo's balance.
pub type Balance = u128;

/// The pallet's index in Kreivo's runtime: every call's first byte, and
/// its module errors' index.
pub const PALLET: u8 = 90;
/// Kreivo's `Balances` index.
pub const BALANCES: u8 = 10;
/// `MaxGenesisLen`, `MaxStatementLen` and `MaxProofLen`: a call past one
/// does not decode at the venue.
pub const MAX_GENESIS_LEN: usize = 2_048;
pub const MAX_STATEMENT_LEN: usize = 65_536;
pub const MAX_PROOF_LEN: usize = 262_144;
/// `Paused`'s bits.
pub const PAUSED_SUBMIT: u8 = 1;
pub const PAUSED_ANCHOR: u8 = 2;

/// When a format or a program is accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Active {
    pub from_ms: u64,
    pub until_ms: Option<u64>,
}

impl Active {
    /// Whether it is accepted at the venue's time `now`.
    pub fn at(&self, now: u64) -> bool {
        self.from_ms <= now && self.until_ms.is_none_or(|until| now < until)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Handler {
    Record = 0,
}

/// `Programs[program]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct ProgramInfo {
    pub handler: Handler,
    pub venue_bound: bool,
    pub active: Active,
}

/// `anchor`'s argument: `vos-anchor`'s `Anchor`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct AnchorArg {
    pub space: [u8; 32],
    pub window: u64,
    pub kind: u8,
    pub root: [u8; 32],
    pub signer: [u8; 32],
    pub signature: [u8; 64],
}

impl From<&Anchor> for AnchorArg {
    fn from(anchor: &Anchor) -> Self {
        Self {
            space: anchor.space.0,
            window: anchor.window,
            kind: anchor.kind as u8,
            root: anchor.root,
            signer: anchor.signer,
            signature: anchor.signature,
        }
    }
}

/// The pallet's calls at their pinned indices (§6).
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Call {
    #[codec(index = 0)]
    Register {
        genesis: Vec<u8>,
        controller: AccountId,
        start_window: u64,
        founder_key: [u8; 32],
        founder_sig: [u8; 64],
    },
    #[codec(index = 1)]
    SetController {
        space: [u8; 32],
        controller: AccountId,
    },
    #[codec(index = 2)]
    AddAuthority {
        space: [u8; 32],
        who: AccountId,
        anchor_key: Option<[u8; 32]>,
    },
    #[codec(index = 3)]
    RemoveAuthority { space: [u8; 32], who: AccountId },
    #[codec(index = 4)]
    RemoveAnchorKey { space: [u8; 32], key: [u8; 32] },
    #[codec(index = 5)]
    Migrate {
        space: [u8; 32],
        to: [u8; 32],
        from_window: u64,
    },
    #[codec(index = 6)]
    Resume { space: [u8; 32] },
    #[codec(index = 7)]
    Anchor { anchor: AnchorArg },
    #[codec(index = 8)]
    Submit {
        payer: [u8; 32],
        statement: Vec<u8>,
        proof: Vec<u8>,
    },
    #[codec(index = 9)]
    DispatchAsSovereign {
        space: [u8; 32],
        call: Box<RuntimeCall>,
    },
    #[codec(index = 10)]
    SetBudget {
        space: [u8; 32],
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
    SetStatus { space: [u8; 32], blocked: bool },
}

impl Call {
    /// The call's bytes: `[90, call_index] ++ SCALE(args)`.
    pub fn bytes(&self) -> Vec<u8> {
        let mut bytes = vec![PALLET];
        self.encode_to(&mut bytes);
        bytes
    }

    /// The anchor call of `anchor`.
    pub fn anchor(anchor: &Anchor) -> Self {
        Self::Anchor {
            anchor: anchor.into(),
        }
    }

    /// Whether its vectors are within the venue's bounds, a nested call's
    /// too.
    pub fn within(&self) -> bool {
        match self {
            Self::Register { genesis, .. } => genesis.len() <= MAX_GENESIS_LEN,
            Self::Submit {
                statement, proof, ..
            } => statement.len() <= MAX_STATEMENT_LEN && proof.len() <= MAX_PROOF_LEN,
            Self::DispatchAsSovereign { call, .. } => match &**call {
                RuntimeCall::Spaces(call) => call.within(),
                RuntimeCall::Balances(_) => true,
            },
            _ => true,
        }
    }
}

/// `Balances::transfer_keep_alive`, the call a space's controller has its
/// sovereign account make (`dispatch_as_sovereign`).
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

/// Kreivo's `RuntimeCall`, as far as the client builds it.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum RuntimeCall {
    #[codec(index = 10)]
    Balances(BalancesCall),
    #[codec(index = 90)]
    Spaces(Call),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub enum SpaceStatus {
    Active = 0,
    /// An equivocation suspended it.
    Suspended = 1,
    /// Governance blocked it.
    Blocked = 2,
}

impl From<SpaceStatus> for crate::Status {
    fn from(status: SpaceStatus) -> Self {
        match status {
            SpaceStatus::Active => Self::Active,
            SpaceStatus::Suspended => Self::Suspended,
            SpaceStatus::Blocked => Self::Blocked,
        }
    }
}

/// `Spaces[space]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct SpaceInfo {
    pub sovereign: AccountId,
    pub controller: AccountId,
    pub origin_ms: u64,
    pub length_ms: u64,
    pub start_window: u64,
    /// Exclusive; set by `migrate`.
    pub end_window: Option<u64>,
    pub status: SpaceStatus,
    pub authorities: u8,
    pub anchor_keys: u8,
    pub registered_ms: u64,
    pub max_spend_per_window: Balance,
}

impl SpaceInfo {
    pub fn clock(&self) -> vos_anchor::WindowClock {
        vos_anchor::WindowClock {
            origin_ms: self.origin_ms,
            length_ms: self.length_ms,
        }
    }

    /// Whether window `w` is within the space's range here.
    pub fn holds(&self, w: u64) -> bool {
        self.start_window <= w && self.end_window.is_none_or(|end| w < end)
    }
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

/// `System.Account[who]`: `AccountInfo<u32, AccountData<u128>>`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Encode, Decode)]
pub struct AccountInfo {
    pub nonce: u32,
    pub consumers: u32,
    pub providers: u32,
    pub sufficients: u32,
    pub free: Balance,
    pub reserved: Balance,
    pub frozen: Balance,
    pub flags: u128,
}

/// The pallet's events at their pinned indices (§8).
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Event {
    #[codec(index = 0)]
    SpaceRegistered {
        space: [u8; 32],
        sovereign: AccountId,
        controller: AccountId,
        origin_ms: u64,
        length_ms: u64,
        start_window: u64,
    },
    #[codec(index = 1)]
    ControllerSet {
        space: [u8; 32],
        controller: AccountId,
    },
    #[codec(index = 2)]
    AuthorityAdded {
        space: [u8; 32],
        who: AccountId,
        anchor_key: Option<[u8; 32]>,
    },
    #[codec(index = 3)]
    AuthorityRemoved { space: [u8; 32], who: AccountId },
    #[codec(index = 4)]
    AnchorKeyRemoved { space: [u8; 32], key: [u8; 32] },
    #[codec(index = 5)]
    Migrated {
        space: [u8; 32],
        to: [u8; 32],
        from_window: u64,
    },
    #[codec(index = 6)]
    Anchored {
        space: [u8; 32],
        kind: u8,
        window: u64,
        root: [u8; 32],
    },
    #[codec(index = 7)]
    Equivocated {
        space: [u8; 32],
        kind: u8,
        window: u64,
        first: [u8; 32],
        second: [u8; 32],
        first_signer: [u8; 32],
        second_signer: [u8; 32],
    },
    #[codec(index = 8)]
    SpaceSuspended { space: [u8; 32] },
    #[codec(index = 9)]
    SpaceResumed { space: [u8; 32] },
    #[codec(index = 10)]
    SpaceStatusSet {
        space: [u8; 32],
        status: SpaceStatus,
    },
    #[codec(index = 11)]
    Accepted {
        id: [u8; 32],
        program: [u32; 8],
        space: [u8; 32],
        payer: [u8; 32],
        output_hash: [u8; 32],
    },
    #[codec(index = 12)]
    Refused {
        payer: [u8; 32],
        statement_hash: [u8; 32],
        code: u32,
    },
    #[codec(index = 13)]
    DepositForfeited { space: [u8; 32], amount: Balance },
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
        space: [u8; 32],
        result: Result<(), Failure>,
    },
    #[codec(index = 18)]
    BudgetSet {
        space: [u8; 32],
        max_spend_per_window: Balance,
    },
}

/// The pallet's errors at their pinned indices (§8).
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
    OutOfRange = 18,
    SpaceNotActive = 19,
    Paused = 20,
    InsufficientSovereignBalance = 21,
    TooEarly = 22,
    StillEquivocating = 23,
    AlreadyMigrated = 24,
    BadHandler = 25,
    BadStartWindow = 26,
    OverBudget = 27,
    SameVenue = 28,
}

impl Error {
    const ALL: [Self; 29] = [
        Self::SpaceExists,
        Self::UnknownSpace,
        Self::BadGenesis,
        Self::BadClock,
        Self::BadFounder,
        Self::SovereignInUse,
        Self::NotController,
        Self::NotAuthority,
        Self::TooManyAuthorities,
        Self::TooManyAnchorKeys,
        Self::AnchorKeyInUse,
        Self::UnknownAnchorKey,
        Self::BadAnchorSignature,
        Self::BadKind,
        Self::AlreadyAnchored,
        Self::WindowNotAfterLast,
        Self::WindowInFuture,
        Self::WindowTooOld,
        Self::OutOfRange,
        Self::SpaceNotActive,
        Self::Paused,
        Self::InsufficientSovereignBalance,
        Self::TooEarly,
        Self::StillEquivocating,
        Self::AlreadyMigrated,
        Self::BadHandler,
        Self::BadStartWindow,
        Self::OverBudget,
        Self::SameVenue,
    ];

    /// The error at pinned index `index`.
    pub fn from_index(index: u8) -> Option<Self> {
        Self::ALL.get(usize::from(index)).copied()
    }
}

/// `sp_runtime::DispatchError`, as far as the client tells its variants
/// apart: a module's error, a bad origin, a token error, and any other by
/// its index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    BadOrigin,
    /// `Module { index, error: [error, ..] }`.
    Module {
        pallet: u8,
        error: u8,
    },
    Token(u8),
    Other(u8),
}

impl Failure {
    /// The pallet's error, when it is one.
    pub fn pallet(&self) -> Option<Error> {
        match *self {
            Self::Module { pallet, error } if pallet == PALLET => Error::from_index(error),
            _ => None,
        }
    }
}

impl Encode for Failure {
    fn encode_to<T: parity_scale_codec::Output + ?Sized>(&self, out: &mut T) {
        match *self {
            Self::BadOrigin => out.push_byte(2),
            Self::Module { pallet, error } => out.write(&[3, pallet, error, 0, 0, 0]),
            Self::Token(token) => out.write(&[7, token]),
            Self::Other(index) => out.push_byte(index),
        }
    }
}

impl Decode for Failure {
    /// A `DispatchError` led by its variant: a module's error is its
    /// pallet and its error's four bytes, a token error its one; another
    /// is read as its index alone, which is all the client needs of it.
    fn decode<I: parity_scale_codec::Input>(
        input: &mut I,
    ) -> Result<Self, parity_scale_codec::Error> {
        Ok(match input.read_byte()? {
            2 => Self::BadOrigin,
            3 => {
                let [pallet, error, ..] = <[u8; 5]>::decode(input)?;
                Self::Module { pallet, error }
            }
            7 => Self::Token(input.read_byte()?),
            other => Self::Other(other),
        })
    }
}

/// What the client makes of a value, all of its bytes.
pub fn read<T: Decode>(bytes: &[u8]) -> Option<T> {
    T::decode_all(&mut &bytes[..]).ok()
}

/// The raw storage keys the node reads (§5, §9):
/// `twox128("Spaces") ++ twox128(item) ++` the item's hashed key.
pub mod keys {
    use blake2::digest::consts::U16;
    use blake2::{Blake2b, Digest};
    use twox_hash::XxHash64;

    use super::AccountId;

    /// FRAME's `twox_64`: xxHash64 with seed 0, little-endian.
    pub fn twox64(data: &[u8]) -> [u8; 8] {
        XxHash64::oneshot(0, data).to_le_bytes()
    }

    /// FRAME's `twox_128`: xxHash64 with seeds 0 and 1, each
    /// little-endian.
    pub fn twox128(data: &[u8]) -> [u8; 16] {
        let mut out = [0; 16];
        out[..8].copy_from_slice(&twox64(data));
        out[8..].copy_from_slice(&XxHash64::oneshot(1, data).to_le_bytes());
        out
    }

    /// FRAME's `blake2_128`: unkeyed BLAKE2b with a 16-byte output.
    pub fn blake2_128(data: &[u8]) -> [u8; 16] {
        Blake2b::<U16>::digest(data).into()
    }

    /// FRAME's `Twox64Concat`: `twox64(data) ++ data`.
    pub(crate) fn twox64_concat(data: &[u8]) -> Vec<u8> {
        [&twox64(data)[..], data].concat()
    }

    /// FRAME's `Blake2_128Concat`: `blake2_128(data) ++ data`.
    pub(crate) fn blake2_128_concat(data: &[u8]) -> Vec<u8> {
        [&blake2_128(data)[..], data].concat()
    }

    /// `twox128(pallet) ++ twox128(item)`.
    pub fn plain(pallet: &str, item: &str) -> Vec<u8> {
        [twox128(pallet.as_bytes()), twox128(item.as_bytes())].concat()
    }

    fn item(name: &str) -> Vec<u8> {
        plain("Spaces", name)
    }

    /// `Spaces[space]`, Identity.
    pub fn spaces(space: &[u8; 32]) -> Vec<u8> {
        [item("Spaces"), space.to_vec()].concat()
    }

    /// `SovereignOf[account]`, Blake2_128Concat.
    pub fn sovereign_of(account: &AccountId) -> Vec<u8> {
        [item("SovereignOf"), blake2_128_concat(account)].concat()
    }

    /// `Authorities[space][who]`: Identity, Blake2_128Concat.
    pub fn authorities(space: &[u8; 32], who: &AccountId) -> Vec<u8> {
        [item("Authorities"), space.to_vec(), blake2_128_concat(who)].concat()
    }

    /// Every `AnchorKeys[space][..]`'s prefix.
    pub fn anchor_keys_of(space: &[u8; 32]) -> Vec<u8> {
        [item("AnchorKeys"), space.to_vec()].concat()
    }

    /// `AnchorKeys[space][key]`: Identity, Identity.
    pub fn anchor_keys(space: &[u8; 32], key: &[u8; 32]) -> Vec<u8> {
        [anchor_keys_of(space), key.to_vec()].concat()
    }

    /// `item[space][kind][window]`: Identity, Twox64Concat, Twox64Concat.
    fn windowed(name: &str, space: &[u8; 32], kind: u8, window: u64) -> Vec<u8> {
        [
            item(name),
            space.to_vec(),
            twox64_concat(&[kind]),
            twox64_concat(&window.to_le_bytes()),
        ]
        .concat()
    }

    /// `Anchors[space][kind][window]`: Identity, Twox64Concat,
    /// Twox64Concat.
    pub fn anchors(space: &[u8; 32], kind: u8, window: u64) -> Vec<u8> {
        windowed("Anchors", space, kind, window)
    }

    /// `Last[space][kind]`: Identity, Twox64Concat.
    pub fn last(space: &[u8; 32], kind: u8) -> Vec<u8> {
        [item("Last"), space.to_vec(), twox64_concat(&[kind])].concat()
    }

    /// `Equivocations[space][kind][window]`, as `Anchors`.
    pub fn equivocations(space: &[u8; 32], kind: u8, window: u64) -> Vec<u8> {
        windowed("Equivocations", space, kind, window)
    }

    /// `Budget[space]`, Identity.
    pub fn budget(space: &[u8; 32]) -> Vec<u8> {
        [item("Budget"), space.to_vec()].concat()
    }

    /// `Formats[format]`, Twox64Concat.
    pub fn formats(format: u32) -> Vec<u8> {
        [item("Formats"), twox64_concat(&format.to_le_bytes())].concat()
    }

    /// `Programs[program]`, Blake2_128Concat.
    pub fn programs(program: &[u32; 8]) -> Vec<u8> {
        let bytes: Vec<u8> = program.iter().flat_map(|word| word.to_le_bytes()).collect();
        [item("Programs"), blake2_128_concat(&bytes)].concat()
    }

    /// `Seen[id]`, Identity.
    pub fn seen(id: &[u8; 32]) -> Vec<u8> {
        [item("Seen"), id.to_vec()].concat()
    }

    /// `Paused`, a value.
    pub fn paused() -> Vec<u8> {
        item("Paused")
    }

    /// `Timestamp.Now`, the venue's time.
    pub fn now() -> Vec<u8> {
        plain("Timestamp", "Now")
    }

    /// `System.Account[who]`, Blake2_128Concat.
    pub fn account(who: &AccountId) -> Vec<u8> {
        [plain("System", "Account"), blake2_128_concat(who)].concat()
    }
}

/// The sovereign account of `space`: `PalletId(*b"kv/space")
/// .into_sub_account_truncating(space)`, `b"modl" ‖ b"kv/space" ‖
/// space[0..20]`, derivable before registration so the founder funds it
/// first.
pub fn sovereign(space: &SpaceId) -> AccountId {
    let mut account = [0; 32];
    account[..4].copy_from_slice(b"modl");
    account[4..12].copy_from_slice(b"kv/space");
    account[12..].copy_from_slice(&space.0[..20]);
    account
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every error at its pinned index, and a module error's bytes as
    /// FRAME's `DispatchError` encodes them.
    #[test]
    fn the_errors_are_at_their_pinned_indices() {
        for (index, error) in Error::ALL.into_iter().enumerate() {
            assert_eq!(error as usize, index);
            assert_eq!(Error::from_index(index as u8), Some(error));
            let failure = Failure::Module {
                pallet: PALLET,
                error: index as u8,
            };
            assert_eq!(failure.encode(), [3, PALLET, index as u8, 0, 0, 0]);
            assert_eq!(read::<Failure>(&failure.encode()), Some(failure));
            assert_eq!(failure.pallet(), Some(error));
        }
        assert_eq!(Error::from_index(29), None);
    }

    /// The anchor call is `[90, 7]` and an `Anchor` in `vos-anchor`'s
    /// encoding.
    #[test]
    fn an_anchor_call_is_its_pinned_bytes() {
        let anchor = Anchor {
            space: SpaceId([1; 32]),
            window: 0x0102_0304,
            kind: vos_anchor::RootKind::Space,
            root: [2; 32],
            signer: [3; 32],
            signature: [4; 64],
        };
        assert_eq!(
            Call::anchor(&anchor).bytes(),
            [&[90, 7][..], &anchor.encode()].concat()
        );
    }

    /// The sovereign account of a space, as `into_sub_account_truncating`
    /// cuts it.
    #[test]
    fn the_sovereign_account_is_the_pallets_sub_account() {
        let account = sovereign(&SpaceId([9; 32]));
        assert_eq!(&account[..12], b"modlkv/space");
        assert_eq!(account[12..], [9; 20]);
    }
}
