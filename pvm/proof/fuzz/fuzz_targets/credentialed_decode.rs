//! Fuzz target: arbitrary bytes through a proven call's decode, the body
//! of the node API's `Credentialed` kind as ingress reads it before any
//! check, and the digests ingress computes of what decodes.
//!
//! Properties: **no panic, no abort**, and **one encoding:** a request
//! that decodes re-encodes to the bytes; its claim's binding, the stock
//! claims, its binding digest, its scope and its claim's io-hash are
//! computed for every request.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vos_wire::credentials::{self, AuthClaim, Bound, OwnerClaim};
use vos_wire::ids::AgentId;
use vos_wire::ingress::Credentialed;
use vos_wire::{Decode, Encode, SpaceId};

fuzz_target!(|data: &[u8]| {
    let Some((agent, call)) = <(AgentId, Credentialed)>::decode_exact(data) else {
        return;
    };
    assert_eq!((agent, call.clone()).encode(), data, "one encoding");
    if let Some(binding) = credentials::claim_binding(&call.claim) {
        assert_eq!(&call.claim[call.claim.len() - 32..], binding);
    }
    if let Some(claim) = AuthClaim::decode_exact(&call.claim) {
        assert_eq!(claim.encode(), call.claim);
    }
    if let Some(claim) = OwnerClaim::decode_exact(&call.claim) {
        assert_eq!(claim.encode(), call.claim);
    }
    let space = SpaceId([0x5a; 32]);
    let b = Bound {
        space: &space,
        agent,
        instance: call.instance,
        method: call.method,
        program: &[0; 32],
        arguments: &call.arguments,
        nonce: &call.nonce,
        expires_ms: call.expires_ms,
    }
    .digest();
    assert!(credentials::words(&credentials::binding(&b)).is_some());
    let name = &call.arguments[..call.arguments.len().min(64)];
    let scope = credentials::scope(&space, agent, call.instance, name);
    assert!(credentials::words(&scope).is_some());
    if call.claim.len() <= vos_wire::abi::cap::CLAIM {
        assert!(vos_pvm_precompiles::compute_device_io_hash(&call.claim, &[], &[]).is_some());
    }
});
