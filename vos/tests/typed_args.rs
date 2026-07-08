//! Full-fidelity `#[msg]` typed-argument + reply codegen gate.
//!
//! Exercises the macro-generated `{Actor}Ref` sender bound and the
//! `{Actor}Msg::from_msg` dynamic-dispatch accessor against custom rkyv
//! structs, `[u8; N]` fixed arrays, and `Vec<[u8; 32]>` — the shapes the
//! federation handler surface needs. Runs natively (the PVM entry points
//! are `cfg`-gated off on the host), so it needs the `macros` feature:
//!
//! ```text
//! cargo test -p vos --features macros --test typed_args
//! ```
//!
//! Under the default feature set the file compiles to nothing.
#![cfg(feature = "macros")]
// The `#[actor]` macro emits `#[cfg(feature = "bin")]` PVM entry gates;
// `bin` is a feature actor crates declare, not `vos`, so silence the
// host-side unknown-cfg warning here (mirrors the fixture crates).
#![allow(unexpected_cfgs)]

use vos::abi::service::ServiceId;
use vos::actors::client::{ClientError, Invoker};
use vos::value::{Msg, Value};

// The actor lives in its own module because `#[messages]` emits a
// module-scoped `type Result<T>` alias (one error type per actor);
// isolating it keeps the bare `Result` in the test bodies pointing at
// `std::result::Result`.
mod fixture {
    use vos::prelude::*;

    /// A custom rkyv reply/argument payload — not one of the macro's
    /// built-in scalar types, so it travels rkyv-encoded inside
    /// `Value::Bytes` and is decoded through the checked `rkyv::access`
    /// path (G28) and the `from_bytes` fallback accessor (G25).
    #[derive(
        vos::rkyv::Archive,
        vos::rkyv::Serialize,
        vos::rkyv::Deserialize,
        Debug,
        Clone,
        PartialEq,
    )]
    #[rkyv(crate = vos::rkyv)]
    pub struct Receipt {
        pub id: u64,
        pub tag: [u8; 32],
    }

    #[actor]
    pub struct Vault;

    #[messages]
    impl Vault {
        fn new() -> Self {
            Vault
        }

        /// Returns a custom rkyv struct — reply travels as `Value::Bytes`.
        #[msg]
        fn last_receipt(&self) -> Receipt {
            Receipt {
                id: 1,
                tag: [0u8; 32],
            }
        }
    }
}

use fixture::{Receipt, VaultMsg, VaultRef};

/// An `Invoker` that ignores the request and hands back a canned
/// reply `Value`, so a `{Actor}Ref` method can be driven end-to-end
/// on the host without a live daemon.
struct MockInvoker {
    reply: Value,
}

impl Invoker for MockInvoker {
    fn invoke(
        &mut self,
        _target: ServiceId,
        _payload: Vec<u8>,
    ) -> impl core::future::Future<Output = core::result::Result<Value, ClientError>> + '_ {
        let reply = self.reply.clone();
        async move { Ok(reply) }
    }
}

/// rkyv-encode a value the same way the macro-generated reply path
/// does, so the mock reply bytes match what a real actor would ship.
macro_rules! rkyv_bytes {
    ($v:expr) => {
        vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&$v)
            .expect("rkyv encode")
            .to_vec()
    };
}

// ── G28: checked reply decode ──────────────────────────────────────

#[test]
fn ref_decodes_valid_custom_reply() {
    let receipt = Receipt {
        id: 7,
        tag: [9u8; 32],
    };
    let mut inv = MockInvoker {
        reply: Value::Bytes(rkyv_bytes!(receipt)),
    };
    let vault = VaultRef::at(ServiceId(5));
    let got = vos::block_on(vault.last_receipt(&mut inv)).expect("valid reply decodes");
    assert_eq!(got, receipt);
}

#[test]
fn ref_rejects_corrupted_custom_reply() {
    // Peer-supplied bytes that are not a valid `Receipt` archive.
    // The old `access_unchecked` path would reinterpret them as an
    // archived struct (UB / garbage); checked `access` must reject.
    let mut inv = MockInvoker {
        reply: Value::Bytes(vec![0xff, 0x00, 0x13, 0x37]),
    };
    let vault = VaultRef::at(ServiceId(5));
    let got = vos::block_on(vault.last_receipt(&mut inv));
    assert!(
        matches!(got, Err(ClientError::Decode)),
        "corrupted reply bytes must fail checked decode, got {got:?}"
    );
}

#[test]
fn ref_rejects_truncated_custom_reply() {
    // A valid archive with its tail lopped off — access must catch the
    // out-of-bounds pointer window rather than read past the buffer.
    let receipt = Receipt {
        id: 42,
        tag: [1u8; 32],
    };
    let mut bytes = rkyv_bytes!(receipt);
    bytes.truncate(bytes.len() / 2);
    let mut inv = MockInvoker {
        reply: Value::Bytes(bytes),
    };
    let vault = VaultRef::at(ServiceId(5));
    let got = vos::block_on(vault.last_receipt(&mut inv));
    assert!(
        matches!(got, Err(ClientError::Decode)),
        "truncated reply must fail checked decode, got {got:?}"
    );
}

// Keep the dynamic-dispatch surface referenced so later commits build
// on a compiling base.
#[test]
fn from_msg_rejects_unknown_method() {
    assert!(VaultMsg::from_msg(&Msg::new("nope")).is_none());
}
