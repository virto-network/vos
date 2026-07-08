//! Clerk-settle — the settlement venue actor.
//!
//! Runs on the venue (a third space that both banks federate over) and is
//! the neutral end of the bilateral net-settlement wire whose bank end is
//! `clerk-bridge`. Banks accumulate a window's cross-clerk flow into a
//! single Pedersen net-flow commitment (a `cipher_clerk::settlement::
//! SettlementClaim`), sign it with their clerk key, and submit it here.
//! When both banks' claims for one `(pair, currency, window)` have
//! arrived, the venue operator settles the window: the two net-flow
//! commitments must cancel (`reconcile`), which proves the two
//! independently-kept books reconcile without either amount ever being
//! revealed to the venue.
//!
//! ## Role in the federation
//!
//! - `clerk-ledger` (per bank) holds the confidential double-entry state.
//! - `clerk-bridge` (per bank) is the voucher ingress + the window
//!   accumulator that makes the receiver term of each claim honest.
//! - `clerk-settle` (the venue) is where the two banks' signed claims meet
//!   and reconcile.
//!
//! ## Trust posture
//!
//! Wave-1: mutually-known operators. The venue checks mutual **consistency**
//! of the two banks' books (the commitments cancel), not solvency — that is
//! the Wave-2 proof slot. `submit_claim` is authenticated by the claim
//! signature against a *registered* bank key, NOT by venue-space
//! membership: submitting banks are not members of the venue space, exactly
//! like `clerk-bridge::submit_voucher`. `register_bank` / `settle_window`
//! are the venue operator's, and are role-gated (see [`roles`]).
//!
//! ## State
//!
//! - `banks`: registered `(name, clerk_pubkey)`, sorted by name.
//! - `claims`: one `StoredClaim` per **directional** `(claimant, peer,
//!   currency, window)` — replaceable (latest-signed wins) while the
//!   window is unsettled, frozen once it settles.
//! - `settled`: the log of settled `(pair, currency, window)` outcomes; a
//!   present entry freezes that window against further `submit_claim`.
//!
//! ## Wave-2 seam
//!
//! The stored claim body carries a `version` byte and the diagnostics
//! (`voucher_count`, `rk_set_hash`) travel *alongside* the signed claim,
//! not inside it — so the cipher-clerk claim schema is untouched and can
//! grow state-root/proof fields (its v0.2 note) without a store migration.
//! `reconcile` is the seam Wave-2 upgrades to STARK verification of a
//! settlement statement.

use vos::prelude::*;

mod store;

pub mod roles;
pub use roles::{CLERK_SETTLE_SPACE_ROLE_MAP, ClerkSettleRole};

// ── Handler status ──────────────────────────────────────────────

/// Return type for the venue handlers. `#[repr(u8)]` keeps the wire bytes
/// stable — reordering variants breaks any peer running an older build.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
#[repr(u8)]
pub enum Status {
    /// Handler succeeded.
    Ok = 0,
    /// Input bytes had the wrong length or the claim failed to parse.
    BadInput = 1,
    /// A referenced bank (claimant, peer, or a `settle_window` name) is not
    /// registered at the venue.
    UnknownBank = 2,
    /// The claim signature did not verify against the claimant bank's key,
    /// or `reconcile` rejected a stored claim's signature.
    SignatureInvalid = 3,
    /// The `(pair, currency, window)` has already settled and is frozen —
    /// `submit_claim` cannot replace a frozen window; `settle_window` is a
    /// no-op (idempotent).
    AlreadySettled = 4,
    /// `settle_window`: one or both directional claims are absent, so the
    /// pair cannot be reconciled yet.
    ClaimMissing = 5,
    /// `reconcile`: the two net-flow commitments do not cancel. The window
    /// is NOT frozen — a bank can resubmit a corrected claim and retry.
    NetFlowMismatch = 6,
    /// `reconcile`: the two claims' claimant/peer pair does not mirror.
    PeerMismatch = 7,
    /// `reconcile`: the two claims disagree on currency.
    CurrencyMismatch = 8,
    /// `reconcile`: the two claims disagree on the window bracket.
    WindowMismatch = 9,
}

/// Stored-claim body layout version. The signed claim is stored as
/// `cipher_clerk::settlement::SettlementClaim::to_bytes` bytes; this byte
/// tags which layout produced them so a Wave-2 claim schema can be
/// distinguished without a store migration.
pub const CLAIM_VERSION_V1: u8 = 1;

// ── Wire types ──────────────────────────────────────────────────

/// A registered bank: a federation-visible `name` bound to the bank's
/// clerk pubkey. Sorted by `name` in the actor's `banks` Vec.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct BankEntry {
    pub name: Vec<u8>,
    pub clerk_pubkey: [u8; 32],
}

/// A submitted, signature-verified settlement claim, keyed by its
/// *directional* `(claimant, peer, currency, window)`. `claim_bytes` is the
/// canonical `SettlementClaim` wire form; `version` tags its layout; the
/// diagnostics (`voucher_count`, `rk_set_hash`) travel alongside the signed
/// body to localize a reconcile mismatch without opening any commitment.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct StoredClaim {
    pub claimant: [u8; 32],
    pub peer: [u8; 32],
    pub currency: u32,
    pub window_start: u64,
    pub window_end: u64,
    pub version: u8,
    pub claim_bytes: Vec<u8>,
    pub voucher_count: u32,
    pub rk_set_hash: [u8; 32],
}

/// A settled `(pair, currency, window)` outcome. `bank_lo`/`bank_hi` are the
/// pair's two clerk pubkeys in ascending byte order, so the entry is
/// direction-independent. A present entry freezes the window.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct SettledEntry {
    pub bank_lo: [u8; 32],
    pub bank_hi: [u8; 32],
    pub currency: u32,
    pub window_start: u64,
    pub window_end: u64,
    /// The settle outcome as a `Status` byte — `Status::Ok` for a recorded
    /// (successful) settlement.
    pub outcome: u8,
}

/// The diagnostics a stored claim carries, for `settle_window` mismatch
/// triage. `present == false` (with zeroed fields) means no claim is stored
/// for the queried directional key.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct ClaimReport {
    pub present: bool,
    pub voucher_count: u32,
    pub rk_set_hash: Vec<u8>,
}

// ── Actor ───────────────────────────────────────────────────────

#[actor(
    role = ClerkSettleRole,
    default_role = ClerkSettleRole::None,
    space_role_map = CLERK_SETTLE_SPACE_ROLE_MAP,
)]
pub struct ClerkSettle {
    /// Registered banks, sorted by `name` ascending.
    banks: Vec<BankEntry>,
    /// Submitted claims, one per directional `(claimant, peer, currency,
    /// window)`.
    claims: Vec<StoredClaim>,
    /// Settled `(pair, currency, window)` log — a present entry freezes the
    /// window.
    settled: Vec<SettledEntry>,
}

#[messages]
impl ClerkSettle {
    fn new() -> Self {
        Self {
            banks: Vec::new(),
            claims: Vec::new(),
            settled: Vec::new(),
        }
    }

    /// Register (or refresh) a bank's clerk pubkey under a federation-visible
    /// name. Re-registering the same name overwrites the pubkey (an operator
    /// asserting the bank rotated its clerk key). Operator-gated.
    #[msg(role = ClerkSettleRole::Operator)]
    async fn register_bank(&mut self, name: Vec<u8>, clerk_pubkey: [u8; 32]) -> Status {
        store::register_bank(&mut self.banks, name, clerk_pubkey)
    }

    /// Submit a bank's signed net-flow claim for one window. OPEN handler:
    /// the authentication is the claim signature verified against the
    /// registered claimant bank's key (submitting banks are not venue-space
    /// members). Replaces an earlier claim for the same directional key
    /// while the window is unsettled; refused once the window is frozen.
    #[msg]
    async fn submit_claim(
        &mut self,
        claim: Vec<u8>,
        voucher_count: u32,
        rk_set_hash: [u8; 32],
    ) -> Status {
        store::submit_claim(
            &self.banks,
            &mut self.claims,
            &self.settled,
            claim,
            voucher_count,
            rk_set_hash,
        )
    }

    /// Settle one `(pair, currency, window)`: reconcile the two banks'
    /// directional claims (their net-flow commitments must cancel) and, on
    /// success, record the outcome and freeze the window. A `NetFlowMismatch`
    /// leaves the window open for a corrected resubmission. Operator-gated.
    #[msg(role = ClerkSettleRole::Operator)]
    async fn settle_window(
        &mut self,
        bank_a: Vec<u8>,
        bank_b: Vec<u8>,
        currency: u32,
        window_start: u64,
        window_end: u64,
    ) -> Status {
        store::settle_window(
            &self.banks,
            &self.claims,
            &mut self.settled,
            bank_a,
            bank_b,
            currency,
            window_start,
            window_end,
        )
    }

    /// Number of registered banks (watch view).
    #[msg]
    async fn bank_count(&self) -> u32 {
        self.banks.len() as u32
    }

    /// Number of stored (directional) claims (watch view).
    #[msg]
    async fn claim_count(&self) -> u32 {
        self.claims.len() as u32
    }

    /// Number of settled windows (watch view).
    #[msg]
    async fn settled_count(&self) -> u32 {
        self.settled.len() as u32
    }

    /// A registered bank's clerk pubkey by name, or an empty `Vec` if the
    /// name is unknown.
    #[msg]
    async fn bank(&self, name: Vec<u8>) -> Vec<u8> {
        store::bank_pubkey(&self.banks, &name)
            .map(|pk| pk.to_vec())
            .unwrap_or_default()
    }

    /// The recorded settle outcome for a `(pair, currency, window)` as a
    /// `Status` byte, or `255` when the window has not settled (or a name is
    /// unknown). `Status::Ok as u8` means a successful settlement.
    #[msg]
    async fn settlement_status(
        &self,
        bank_a: Vec<u8>,
        bank_b: Vec<u8>,
        currency: u32,
        window_start: u64,
        window_end: u64,
    ) -> u8 {
        store::settlement_status(
            &self.banks,
            &self.settled,
            &bank_a,
            &bank_b,
            currency,
            window_start,
            window_end,
        )
    }

    /// The diagnostics (`voucher_count`, `rk_set_hash`) a stored claim
    /// carries for a directional key — used to localize a `settle_window`
    /// mismatch without opening any commitment (count differs ⇒
    /// missed/in-flight voucher; count equal but hash differs ⇒ set
    /// divergence).
    #[msg]
    async fn claim_diagnostics(
        &self,
        claimant: [u8; 32],
        peer: [u8; 32],
        currency: u32,
        window_start: u64,
        window_end: u64,
    ) -> ClaimReport {
        store::claim_diagnostics(
            &self.claims,
            claimant,
            peer,
            currency,
            window_start,
            window_end,
        )
    }
}
