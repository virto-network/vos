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

        /// Scalar argument — must keep the pre-existing `Value::U64`
        /// wire shape so callers written against the old surface work.
        #[msg]
        fn deposit(&mut self, amount: u64) -> u64 {
            amount
        }

        /// Custom rkyv struct as an argument (G25).
        #[msg]
        fn record(&mut self, receipt: Receipt) -> u64 {
            receipt.id
        }

        /// `Vec<[u8; 32]>` argument — the allowlist-style shape that
        /// falls out of the custom-struct path (G25).
        #[msg]
        fn pin_roots(&mut self, roots: Vec<[u8; 32]>) -> u32 {
            roots.len() as u32
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

/// An `Invoker` that captures the encoded request payload (so the
/// `{Actor}Ref` sender bound can be inspected / round-tripped through
/// `from_msg`) and returns a canned reply.
#[derive(Default)]
struct CapturingInvoker {
    payload: Option<Vec<u8>>,
    reply: Option<Value>,
}

impl Invoker for CapturingInvoker {
    fn invoke(
        &mut self,
        _target: ServiceId,
        payload: Vec<u8>,
    ) -> impl core::future::Future<Output = core::result::Result<Value, ClientError>> + '_ {
        self.payload = Some(payload);
        let reply = self.reply.clone().unwrap_or(Value::U64(0));
        async move { Ok(reply) }
    }
}

impl CapturingInvoker {
    /// Decode the captured `[TAG_DYNAMIC] ++ rkyv(Msg)` payload back
    /// into the dynamic `Msg` the daemon dispatch layer would see.
    fn captured_msg(&self) -> Msg {
        let payload = self.payload.as_ref().expect("a request was captured");
        assert_eq!(payload[0], vos::value::TAG_DYNAMIC, "dynamic tag prefix");
        <Msg as vos::Decode>::decode(&payload[1..])
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

#[test]
fn from_msg_rejects_unknown_method() {
    assert!(VaultMsg::from_msg(&Msg::new("nope")).is_none());
}

// ── G25: custom rkyv structs as arguments ──────────────────────────

#[test]
fn scalar_arg_keeps_its_wire_shape() {
    // A whitelisted scalar must still travel as its own `Value`
    // variant, not rkyv-wrapped — this is the backward-compat contract.
    let mut inv = CapturingInvoker::default();
    let vault = VaultRef::at(ServiceId(1));
    let _ = vos::block_on(vault.deposit(&mut inv, 500u64)).expect("invoke");
    let msg = inv.captured_msg();
    assert_eq!(msg.name, "deposit");
    assert_eq!(msg.args.get("amount"), Some(&Value::U64(500)));
    let VaultMsg::Deposit(inner) = VaultMsg::from_msg(&msg).expect("from_msg decodes") else {
        panic!("expected Deposit variant");
    };
    assert_eq!(inner.amount, 500);
}

#[test]
fn custom_struct_arg_round_trips_ref_to_from_msg() {
    let receipt = Receipt {
        id: 99,
        tag: [7u8; 32],
    };
    let mut inv = CapturingInvoker::default();
    let vault = VaultRef::at(ServiceId(5));
    let _ = vos::block_on(vault.record(&mut inv, receipt.clone())).expect("invoke");
    let msg = inv.captured_msg();
    // On the wire, a custom struct is rkyv bytes.
    assert!(
        matches!(msg.args.get("receipt"), Some(Value::Bytes(_))),
        "custom struct arg must travel as Value::Bytes"
    );
    let VaultMsg::Record(inner) = VaultMsg::from_msg(&msg).expect("from_msg decodes custom arg")
    else {
        panic!("expected Record variant");
    };
    assert_eq!(inner.receipt, receipt);
}

#[test]
fn vec_byte_array_arg_round_trips() {
    let roots = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
    let mut inv = CapturingInvoker::default();
    let vault = VaultRef::at(ServiceId(9));
    let _ = vos::block_on(vault.pin_roots(&mut inv, roots.clone())).expect("invoke");
    let msg = inv.captured_msg();
    let VaultMsg::PinRoots(inner) = VaultMsg::from_msg(&msg).expect("from_msg decodes Vec<[u8;32]>")
    else {
        panic!("expected PinRoots variant");
    };
    assert_eq!(inner.roots, roots);
}

#[test]
fn from_msg_rejects_corrupted_custom_arg() {
    // A `record` message whose `receipt` bytes are not a valid archive
    // must fail `from_msg` (checked `from_bytes`) rather than mis-decode.
    let msg = Msg::new("record").with("receipt", Value::Bytes(vec![0x00, 0x99, 0xab]));
    assert!(VaultMsg::from_msg(&msg).is_none());
}

#[test]
fn from_msg_rejects_wrong_variant_for_custom_arg() {
    // The right name but a scalar where bytes are expected.
    let msg = Msg::new("record").with("receipt", Value::U64(3));
    assert!(VaultMsg::from_msg(&msg).is_none());
}
