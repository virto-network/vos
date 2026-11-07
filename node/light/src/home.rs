//! The home (`light-node.md` §3.3): its open claim's work, a device's
//! nullifier in its scope, and the scope reserved.
//!
//! - **The open claim:** a home-only space admits anyone whose work meets
//!   its registrar's difficulty under the period's salt ([`work`], over
//!   the registrar's answer [`vos_wire::credentials::Open`]).
//! - **The scope "home"** ([`SCOPE`]) is reserved: [`Prover::prove_auth`]
//!   refuses it, and [`Prover::prove_home`] proves in it only a claim or a
//!   re-proof of `Homes`, so no other call can be linked to the device's
//!   pseudonym there. A device's own nullifier in it, which its add
//!   records, is computed without a proof ([`nullifier`]).

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use vos_wire::credentials::{Digest as Bytes, meets, open_work};

pub use vos_wire::homes::SCOPE;

use crate::{AuthWitness, Call, DeviceError, DeviceProgram, DeviceSecret, Proven, Prover};
use crate::{call, secret};

/// The device's nullifier in `Homes`' scope: the home's `space`, `Homes`'
/// `agent` and `instance`.
pub fn nullifier(secret: &DeviceSecret, space: &[u8; 32], agent: u32, instance: u32) -> [u8; 32] {
    let scope = call::scope(space, agent, instance, SCOPE).expect("the scope's name is in bounds");
    secret::nullifier(secret, &scope).to_bytes()
}

/// A nonce whose work for `member` in the space whose handle is `handle`
/// meets `difficulty` under `salt`, searched on `threads` threads: about
/// `2^difficulty` hashes; `u64::MAX` if no nonce does.
pub fn work(
    handle: &[u8; 32],
    member: &Bytes,
    salt: &[u8; 32],
    difficulty: u8,
    threads: usize,
) -> u64 {
    let threads = threads.max(1) as u64;
    let found = AtomicBool::new(false);
    let nonce = AtomicU64::new(u64::MAX);
    std::thread::scope(|scope| {
        for start in 0..threads {
            let (found, nonce) = (&found, &nonce);
            scope.spawn(move || {
                let mut at = start;
                while !found.load(Ordering::Relaxed) {
                    if meets(&open_work(handle, member, salt, at), difficulty) {
                        nonce.fetch_min(at, Ordering::Relaxed);
                        found.store(true, Ordering::Relaxed);
                        return;
                    }
                    match at.checked_add(threads) {
                        Some(next) => at = next,
                        None => return,
                    }
                }
            });
        }
    });
    nonce.load(Ordering::Relaxed)
}

/// The methods of `Homes` a proof in its scope may name.
fn reserved_for(method: u32) -> bool {
    method == call::method_id("claim") || method == call::method_id("renew")
}

impl Prover {
    /// [`Prover::prove_auth`] in the scope "home", for `call` of `Homes`'
    /// `claim` or `renew` alone; any other method is
    /// [`DeviceError::Reserved`].
    pub fn prove_home(
        &self,
        secret: &DeviceSecret,
        witness: &AuthWitness,
        call: &Call,
        program: &DeviceProgram,
    ) -> Result<Proven, DeviceError> {
        if !reserved_for(call.method) {
            return Err(DeviceError::Reserved);
        }
        self.prove_in_scope(secret, witness, SCOPE, call, program)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The work found meets the difficulty, on one thread or several.
    #[test]
    fn the_work_found_meets_its_difficulty() {
        let (handle, member, salt) = ([1; 32], [2; 32], [3; 32]);
        for threads in [1, 4] {
            let nonce = work(&handle, &member, &salt, 10, threads);
            assert!(meets(&open_work(&handle, &member, &salt, nonce), 10));
        }
        assert_eq!(work(&handle, &member, &salt, 0, 2), 0);
    }
}
