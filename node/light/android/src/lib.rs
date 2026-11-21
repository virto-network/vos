// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The `vos.credential` client facility: a member of a VOS space proves, on
//! its own device, that it is a member (to sign in) or that it holds a ledger
//! account (to pay), and the server that asked only relays what the device
//! made. The proofs are VOS's stock kernels' runs, proved against programs
//! from release artifacts this crate embeds ([`Stock`]), never from what a
//! server sends.
//!
//! A server calls it with three operations, each confirmed by the user in the
//! client's own chrome, never in the server's document:
//!
//! - **`enroll`** names the space's handle, the space, its agents and the
//!   methods the device may prove for. The chrome shows them and the device
//!   pins them, with the gateway it was made through; a secret source's key
//!   is made, and the device's member and owner digests are answered, which
//!   the space's operator invites.
//! - **`sign_in`** asks for a call of a pinned method under its auth guard.
//!   The chrome names the method and, for a `once` guard, that the call
//!   spends the member's one admission in its scope; the facility proves
//!   the node-API `Credentialed` request on the path the device holds,
//!   sends it over Tor itself, and answers the server with the node's
//!   answer.
//! - **`pay`** pre-fills a transfer from the account of this device's owner
//!   digest. The chrome's own form lets the user edit the payee and the
//!   amount; the transfer is encoded from what the user confirmed, whatever
//!   the server asked.
//!
//! A request naming another space, agent or method than enrollment pinned is
//! refused. The secret is derived again at each use from the source's output
//! and dropped once the proof is made; the device keeps the source's
//! reference and what enrollment pinned, nothing else.
//!
//! Every request goes over Tor through one client ([`net`]): the credential
//! tree read from its feed on the space's feed connection, apart from its
//! proofs, on a jittered timer, not because a proof is about to be made (a
//! sign-in waiting for its leaf aside, `session`);
//! the node's time read as a fetch of its own before an expiry is picked;
//! each proof sent by the facility itself as a proven call, so no
//! anonymous call ever takes the clearnet. A sync run ([`Facility::sync`],
//! the background job's, [`job`]) reads every enrollment's tree; the
//! personal space's ([`personal`]) has its own job.
//!
//! On Android the facility runs in the app's own `:vos` process ([`node`],
//! and its JNI under the `android` feature), behind two Binder interfaces:
//! `s4-credential-contract`'s `IVosNode`, which s4's client calls, and the
//! facility's own `IVosPersonal` ([`personal::contract`]), which its
//! screens call; their operations' requests, results and refusals typed,
//! the chrome and the secret sources' prompts the UI process's, reached
//! back through the interface.

#[cfg(feature = "android")]
mod android;
pub mod chrome;
pub mod enrollment;
pub mod job;
pub mod kept;
pub mod net;
pub mod node;
pub mod personal;
mod session;
pub mod source;
pub mod stream;
#[cfg(feature = "testing")]
pub mod testing;
mod warm;

pub use personal::{Notice, Pending, Seen, Synced};
pub use s4_credential_contract::{
    Answer, Code, Enroll, Enrolled, EnrolledSpace, FACILITY, Field, Form, Gateway, JobRun, MAJOR,
    Onion, Operation, Outcome, Paid, Pay, Refusal, SignIn, SignedIn, StreamTarget,
};
pub use session::{Facility, Session, Stock, WAITING_FOR_LIST};
pub use warm::Warming;

/// `mutex` locked, whether or not a holder panicked.
pub(crate) fn lock<T>(mutex: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// A refusal of `code`.
pub(crate) fn refused(code: Code, message: impl Into<String>) -> Refusal {
    Refusal::new(code, message)
}

const _: () = assert!(s4_credential_contract::MAX_NAME == vos_light::NAME_BYTES);
const _: () = assert!(s4_credential_contract::MAX_ARGUMENTS == vos_abi::abi::cap::REQUEST);
