//! Fuzz target: arbitrary bytes through `vos-api`'s `Operated::decode`, an
//! operator kind's body as the node reads it before any check.
//!
//! Properties: **no panic, no abort**, and **one encoding:** an envelope
//! that decodes re-encodes to the bytes; its message is computed for every
//! kind, and its credentials carry it back.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vos_api::{Kind, Operated};
use vos_wire::{Decode, Encode};

fuzz_target!(|data: &[u8]| {
    let Some(operated) = Operated::decode_exact(data) else {
        return;
    };
    assert_eq!(operated.encode(), data, "one encoding");
    for kind in Kind::ALL {
        let message = operated.message(kind);
        assert!(message.ends_with(&operated.body));
    }
    let back = Operated::with_credentials(&operated.credentials(), operated.body.clone());
    assert_eq!(back, operated);
});
