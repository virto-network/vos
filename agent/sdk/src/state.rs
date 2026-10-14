//! An instance's struct state, stored encoded in its struct row.

use alloc::vec::Vec;

use vos_wire::abi::Rows;

use crate::{Decode, Encode, host};

/// Binds an actor's `Table` and `CommittedMap` fields to their tags.
/// `#[actor]` implements it.
pub trait Tables {
    fn bind_tables(&mut self);
}

/// The state of a new instance. `#[messages]` implements it with the
/// actor's `fn new() -> Self`.
pub trait New {
    fn new() -> Self;
}

/// The instance's state, or a new instance's when none is stored. State
/// that does not decode traps.
pub fn load<A: Encode + Decode + Tables + New>() -> A {
    let mut state = match host::get(Rows::Struct, &[]) {
        Some(bytes) => match A::decode(&bytes) {
            Ok((state, _)) => state,
            Err(_) => panic!("undecodable state"),
        },
        None => A::new(),
    };
    state.bind_tables();
    state
}

/// Write the state back if its encoding changed from `before`.
pub fn save<A: Encode>(state: &A, before: &[u8]) {
    let after: Vec<u8> = state.encode();
    if after != before {
        host::put(Rows::Struct, &[], &after);
    }
}
