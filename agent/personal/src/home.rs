//! The home's `Homes` (`agent/homes`), as `Personal` messages it: its
//! answer to a claim, each device's nullifier once its add is confirmed,
//! and each new kit's keys. `Homes` depends on this crate for the
//! messages it sends here, so these are declared by hand, their ids the
//! handlers' names derive.

use alloc::vec::Vec;

use vos_sdk::context::{Method, Never};
use vos_sdk::method_id;
use vos_sdk::prelude::*;
use vos_wire::personal::PersonalError;

/// `Homes`, named only as the actor these messages go to.
pub enum Homes {}

/// The claim was taken: the agent is assigned.
#[derive(Encode)]
pub struct Assigned {}

/// The claim was refused, and nothing written.
#[derive(Encode)]
pub struct Refused {
    pub error: PersonalError,
}

/// A device's nullifier in the home's scope, recorded for its re-proofs.
#[derive(Encode)]
pub struct Record {
    pub nullifier: [u8; 32],
}

/// The kit's signing keys after its rotation or a restore.
#[derive(Encode)]
pub struct Rekey {
    pub keys: Vec<[u8; 32]>,
}

macro_rules! sent {
    ($message:ident, $name:literal) => {
        impl Method for $message {
            type Actor = Homes;
            const ID: u32 = method_id!($name);
            type Reply = ();
            type Error = Never;
        }
    };
}

sent!(Assigned, "assigned");
sent!(Refused, "refused");
sent!(Record, "record");
sent!(Rekey, "rekey");
