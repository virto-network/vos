//! A plain-Rust model of Kreivo's spaces pallet (`spaces-pallet.md` §4–§8),
//! not a FRAME pallet: the reference the conformance vectors are generated
//! from, and the chain the Kreivo client is tested against.
//!
//! - **Storage** is raw, a map from the pinned keys ([`keys`]) to SCALE
//!   values ([`types`]), so what a call writes is FRAME's bytes.
//! - **Calls** arrive as bytes, `[90, call_index] ++ SCALE(args)` (or
//!   another pallet's call for `dispatch_as_sovereign`), decoded whole; a
//!   call that does not decode, or a bounded vector past its bound, is
//!   [`Verdict::Undecodable`].
//! - **A call is transactional**, as FRAME dispatches it: an error leaves
//!   no write and no event; only its fee stays paid.
//! - **Balances:** each account's free balance, its holds (registration,
//!   submit) and its provider and consumer counts. A hold keeps the
//!   existential deposit free.
//! - **Fees** ([`Chain::with_fees`]): off, the pallet's own mock runtime,
//!   with no fee pipeline; on, Kreivo's runtime with `ChargeSpaceFee`
//!   (§7): an authority's `anchor` or `submit` of an active space paid by
//!   its sovereign account within the window's budget, every other signed
//!   call by its signer. The model charges every fee at `FeeBound`, the
//!   most one can be: the vectors pin fees by sign only.
//! - **Time** is a settable `now_ms` (Kreivo's `Timestamp.Now`); verdicts
//!   are `vos_statement::judge`'s, over `StorageVenue`.

mod chain;
pub mod keys;
mod pallet;
pub mod transport;
pub mod types;

#[cfg(test)]
pub(crate) use chain::Broken;
pub use chain::{Account, Chain, Constants, Origin, Outcome, Payer, Verdict};
