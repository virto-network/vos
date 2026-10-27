//! Fuzz target: arbitrary bytes through a credentialed call's decode, the
//! body of the node API's `Credentialed` kind as ingress reads it before
//! any check, and the digests ingress computes of what decodes.
//!
//! Properties: **no panic, no abort**, and **one encoding:** a request
//! that decodes re-encodes to the bytes; its public words, its origin and
//! its binding digest and scope are computed for every request.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vos_wire::credentials::{self, Bound};
use vos_wire::ids::AgentId;
use vos_wire::ingress::Credentialed;
use vos_wire::{Decode, Encode, SpaceId};

fuzz_target!(|data: &[u8]| {
    let Some((agent, call)) = <(AgentId, Credentialed)>::decode_exact(data) else {
        return;
    };
    assert_eq!((agent, &call).encode(), data, "one encoding");
    if let Some(words) = call.public.words() {
        assert_eq!(words[0], u32::from(call.public.kind()));
    }
    let _ = call.public.origin();
    let space = SpaceId([0x5a; 32]);
    let b = Bound {
        space: &space,
        agent,
        instance: call.instance,
        method: call.method,
        program: &[0; 32],
        kind: call.public.kind(),
        arguments: &call.arguments,
        nonce: &call.nonce,
        expires_ms: call.expires_ms,
    }
    .digest();
    assert!(credentials::words(&credentials::binding(&b)).is_some());
    let name = &call.arguments[..call.arguments.len().min(64)];
    let scope = credentials::scope(&space, agent, call.instance, name);
    assert!(credentials::words(&scope).is_some());
});
