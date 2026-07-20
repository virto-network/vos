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
        vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Debug, Clone, PartialEq,
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
        #[msg(attested, space_role = SpaceRole::Member)]
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

        /// `[u8; 32]` argument and return — raw-bytes wire shape (G26).
        #[msg]
        fn echo_root(&self, root: [u8; 32]) -> [u8; 32] {
            root
        }

        /// `Result<T>` return — the schema records the success type `T`,
        /// not `Result` (the error surfaces as `ClientError`).
        #[msg]
        fn try_thing(&self) -> Result<u32> {
            Ok(3)
        }
    }
}

use fixture::{Receipt, Vault, VaultMsg, VaultRef};

mod crdt_fixture {
    use vos::prelude::*;

    #[actor(crdt)]
    pub struct Board {
        title: crdt::Value<String>,
        edits: crdt::Counter,
        #[crdt(const)]
        space: u64,
        #[crdt(skip)]
        cache: Option<u64>,
    }

    #[messages]
    impl Board {
        fn new() -> Self {
            Self {
                title: crdt::Value::default(),
                edits: crdt::Counter::default(),
                space: 1,
                cache: None,
            }
        }

        #[msg]
        fn edits(&self) -> i64 {
            self.edits.value()
        }
    }

    #[test]
    fn generated_crdt_merger_folds_fields_checks_constants_and_resets_skips() {
        let mut left = Board::new();
        left.edits
            .increment_with_id(crdt::ChangeId([1; 32]).operation(0), 2)
            .unwrap();
        left.cache = Some(99);
        let mut right = Board::new();
        right
            .edits
            .increment_with_id(crdt::ChangeId([2; 32]).operation(0), 3)
            .unwrap();

        <Board as vos::Actor>::__merge_crdt(&mut left, &right).unwrap();
        assert_eq!(left.edits.value(), 5);
        assert_eq!(left.cache, None, "#[crdt(skip)] resets on materialization");

        let mut wrong_space = Board::new();
        wrong_space.space = 2;
        assert_eq!(
            <Board as vos::Actor>::__merge_crdt(&mut left, &wrong_space),
            Err(crdt::Error::ConstMismatch)
        );
        assert_eq!(left.edits.value(), 5, "a rejected merge is atomic");
    }
}

/// An `Invoker` that ignores the request and hands back a canned
/// reply `Value`, so a `{Actor}Ref` method can be driven end-to-end
/// on the host without a live daemon.
struct MockInvoker {
    reply: Value,
}

#[test]
fn crdt_actor_metadata_is_explicit() {
    assert!(crdt_fixture::BoardMsg::META.crdt);
}

#[test]
fn attested_and_regular_method_policies_are_generated_together() {
    let attested = VaultMsg::from_msg(&Msg::new("last_receipt")).expect("attested message");
    assert!(attested.is_attested());
    assert_eq!(
        attested.required_space_role(),
        Some(vos::SpaceRole::Member.as_u8())
    );

    let regular = VaultMsg::from_msg(&Msg::new("deposit").with("amount", Value::U64(1)))
        .expect("regular message");
    assert!(!regular.is_attested());
    assert_eq!(regular.required_space_role(), None);

    let meta = VaultMsg::META
        .messages
        .iter()
        .find(|message| message.name == "last_receipt")
        .expect("attested method metadata");
    assert!(meta.attested);
    assert_eq!(meta.space_role, Some(vos::SpaceRole::Member.as_u8()));
}

#[test]
fn attested_space_role_is_enforced_before_the_handler_runs() {
    let mut guest_actor = <Vault as vos::Actor>::create();
    let mut guest_ctx = vos::Context::new(ServiceId(7));
    guest_ctx.set_caller_roles(Some(vos::SpaceRole::Guest.as_u8()), None);
    let guest_message = VaultMsg::from_msg(&Msg::new("last_receipt")).expect("message");
    assert!(matches!(
        vos::Actor::dispatch(&mut guest_actor, guest_message, &mut guest_ctx),
        vos::RunResult::Complete(false)
    ));
    assert!(guest_ctx.was_forbidden());

    let mut member_actor = <Vault as vos::Actor>::create();
    let mut member_ctx = vos::Context::new(ServiceId(7));
    member_ctx.set_caller_roles(Some(vos::SpaceRole::Member.as_u8()), None);
    let member_message = VaultMsg::from_msg(&Msg::new("last_receipt")).expect("message");
    assert!(matches!(
        vos::Actor::dispatch(&mut member_actor, member_message, &mut member_ctx),
        vos::RunResult::Complete(false)
    ));
    assert!(!member_ctx.was_forbidden());
}

#[test]
fn bound_handle_methods_do_not_take_an_invoker_argument() {
    use vos::ActorReference;

    let mut invoker = MockInvoker {
        reply: Value::U64(42),
    };
    let mut handle = VaultRef::bind(ServiceId(7), &mut invoker);
    let value = vos::block_on(handle.deposit(42)).unwrap();
    assert_eq!(value, 42);
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
    let VaultMsg::PinRoots(inner) =
        VaultMsg::from_msg(&msg).expect("from_msg decodes Vec<[u8;32]>")
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

// ── G26: [u8; N] arguments and returns ─────────────────────────────

#[test]
fn byte_array_arg_and_reply_travel_as_raw_bytes() {
    let root = [5u8; 32];
    let mut inv = CapturingInvoker {
        reply: Some(Value::Bytes(root.to_vec())),
        ..Default::default()
    };
    let vault = VaultRef::at(ServiceId(3));
    let got = vos::block_on(vault.echo_root(&mut inv, root)).expect("invoke");
    // Reply decodes back into the fixed array (G26 reply path).
    assert_eq!(got, root);
    let msg = inv.captured_msg();
    // The arg is raw bytes of exactly 32 — not rkyv-framed.
    match msg.args.get("root") {
        Some(Value::Bytes(b)) => assert_eq!(b.len(), 32),
        other => panic!("expected 32 raw bytes, got {other:?}"),
    }
    let VaultMsg::EchoRoot(inner) = VaultMsg::from_msg(&msg).expect("from_msg decodes [u8;32]")
    else {
        panic!("expected EchoRoot variant");
    };
    assert_eq!(inner.root, root);
}

#[test]
fn byte_array_reply_wrong_length_is_rejected() {
    let mut inv = CapturingInvoker {
        reply: Some(Value::Bytes(vec![0u8; 31])),
        ..Default::default()
    };
    let vault = VaultRef::at(ServiceId(3));
    let got = vos::block_on(vault.echo_root(&mut inv, [0u8; 32]));
    assert!(
        matches!(got, Err(ClientError::Decode)),
        "31 bytes must not decode into [u8;32], got {got:?}"
    );
}

#[test]
fn from_msg_rejects_wrong_length_byte_array_arg() {
    let msg = Msg::new("echo_root").with("root", Value::Bytes(vec![1u8; 10]));
    assert!(VaultMsg::from_msg(&msg).is_none());
}

#[test]
fn byte_array_field_meta_records_normalized_type() {
    let m = VaultMsg::META
        .messages
        .iter()
        .find(|m| m.name == "echo_root")
        .expect("echo_root meta present");
    assert_eq!(m.fields[0].name, "root");
    assert_eq!(m.fields[0].ty, "[u8;32]");
}

// ── G27a: return types in schema metadata ──────────────────────────

fn meta_return(name: &str) -> &'static str {
    VaultMsg::META
        .messages
        .iter()
        .find(|m| m.name == name)
        .unwrap_or_else(|| panic!("{name} meta present"))
        .returns
}

#[test]
fn message_meta_records_return_types() {
    assert_eq!(meta_return("last_receipt"), "Receipt");
    assert_eq!(meta_return("deposit"), "u64");
    assert_eq!(meta_return("echo_root"), "[u8;32]");
    assert_eq!(meta_return("pin_roots"), "u32");
    // Result<u32> unwraps to the success type.
    assert_eq!(meta_return("try_thing"), "u32");
}

#[test]
fn return_types_survive_meta_encode_decode() {
    // The compile-time META round-trips through the binary .vos_meta
    // codec with return types intact (trailing-append section).
    let (buf, len) = vos::metadata::encode::<4096>(&VaultMsg::META);
    let parsed = vos::metadata::decode(&buf[..len]).expect("decode");
    let by = |name: &str| {
        parsed
            .messages
            .iter()
            .find(|m| m.name == name)
            .unwrap_or_else(|| panic!("{name} present"))
    };
    assert_eq!(by("last_receipt").returns, "Receipt");
    assert_eq!(by("echo_root").returns, "[u8;32]");
    assert_eq!(by("deposit").returns, "u64");
    assert_eq!(by("try_thing").returns, "u32");
}
