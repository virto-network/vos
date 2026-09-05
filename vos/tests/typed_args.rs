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
use vos::actors::client::{
    ActorReference, AttestationInvoker, AttestedInvocationResult, ClientError, ExtensionInvoker,
    ExtensionReference, Invoker,
};
use vos::service::{
    AccumulationReceipt, ActorId, ConsistencyMode, DeploymentId, Hash, InvocationId, ProducerId,
    ProgramId, ReplyRecord, RootServiceId, ServiceIdentity, SpaceId,
};
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

    /// Zero-sized capability marker used to prove that `Option<T>` claim
    /// encoding distinguishes `None` from `Some(T)` even when rkyv(T) is
    /// empty.
    #[derive(
        vos::rkyv::Archive,
        vos::rkyv::Serialize,
        vos::rkyv::Deserialize,
        Debug,
        Clone,
        Copy,
        PartialEq,
        Eq,
    )]
    #[rkyv(crate = vos::rkyv)]
    pub struct MembershipToken;

    #[derive(
        vos::rkyv::Archive,
        vos::rkyv::Serialize,
        vos::rkyv::Deserialize,
        Clone,
        Copy,
        Debug,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
    )]
    #[rkyv(crate = vos::rkyv)]
    #[repr(u8)]
    pub enum VaultRole {
        Guest = 0,
        Admin = 1,
    }

    impl vos::RoleByte for VaultRole {
        fn from_byte(byte: u8) -> Option<Self> {
            match byte {
                0 => Some(Self::Guest),
                1 => Some(Self::Admin),
                _ => None,
            }
        }

        fn as_byte(self) -> u8 {
            self as u8
        }
    }

    const VAULT_SPACE_ROLE_MAP: vos::SpaceRoleMap<VaultRole> = vos::SpaceRoleMap {
        admin: Some(VaultRole::Admin),
        developer: Some(VaultRole::Guest),
        member: Some(VaultRole::Guest),
        guest: Some(VaultRole::Guest),
    };

    #[actor(
        role = VaultRole,
        default_role = VaultRole::Guest,
        space_role_map = VAULT_SPACE_ROLE_MAP
    )]
    pub struct Vault;

    #[messages(extension)]
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

        #[msg(attested)]
        fn optional_token(&self, issue: bool) -> Option<MembershipToken> {
            issue.then_some(MembershipToken)
        }

        #[msg(attested)]
        fn acknowledge(&mut self) {}

        #[msg(attested)]
        fn try_acknowledge(&mut self) -> Result<()> {
            Ok(())
        }

        #[msg(attested)]
        fn scalar(&self) -> u64 {
            7
        }

        /// The same custom wire shape on a regular method, used to prove that
        /// ordinary and attested generated handles expose different types.
        #[msg]
        fn read_receipt(&self) -> Receipt {
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

        #[msg(role = VaultRole::Admin)]
        fn rotate_key(&mut self) -> bool {
            true
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

    pub mod gate {
        use super::{LastReceipt, Receipt};
        use vos::prelude::*;

        #[actor]
        pub struct Gate;

        #[messages]
        impl Gate {
            fn new() -> Self {
                Gate
            }

            /// Transport-only codec gate. Application authorization must call
            /// the verifier path and consume `Verified<T>`, not this package.
            #[msg]
            fn receive_package(&self, package: vos::Attestation<Receipt, LastReceipt>) -> bool {
                let _ = package;
                true
            }
        }
    }
}

use fixture::gate::{GateMsg, GateRef};
use fixture::{MembershipToken, Receipt, Vault, VaultMsg, VaultRef};

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

mod installation_data_fixture {
    use vos::prelude::*;

    mod parameterized_actor {
        use vos::prelude::*;

        #[actor(agent)]
        pub struct Parameterized {
            #[state(const)]
            pub(super) tenant: u64,
            pub(super) value: u64,
        }

        #[messages(agent)]
        impl Parameterized {
            fn new(tenant: u64) -> Self {
                Self { tenant, value: 0 }
            }

            #[msg]
            fn value(&self) -> u64 {
                self.value
            }
        }
    }

    mod fixed_array_actor {
        use vos::prelude::*;

        #[actor(agent)]
        pub struct FixedArrayConfigured {
            #[state(const)]
            pub(super) seed: [u8; 32],
        }

        #[messages(agent)]
        impl FixedArrayConfigured {
            fn new(seed: [u8; 32]) -> Self {
                Self { seed }
            }

            #[msg(query)]
            fn seed(&self) -> [u8; 32] {
                self.seed
            }
        }
    }

    mod unconfigured_actor {
        use vos::prelude::*;

        #[actor(agent)]
        pub struct Unconfigured {
            value: u64,
        }

        #[messages(agent)]
        impl Unconfigured {
            fn new() -> Self {
                Self { value: 0 }
            }

            #[msg]
            fn value(&self) -> u64 {
                self.value
            }
        }
    }

    mod const_only_actor {
        use vos::prelude::*;

        #[actor(agent)]
        pub struct ConstOnly {
            #[state(const)]
            pub(super) tenant: u64,
        }

        #[messages(agent)]
        impl ConstOnly {
            fn new() -> Self {
                Self { tenant: 17 }
            }

            #[msg]
            fn tenant(&self) -> u64 {
                self.tenant
            }
        }
    }

    mod raw_actor {
        use vos::prelude::*;

        #[actor(agent)]
        pub struct RawConfigured {
            pub(super) length: u64,
        }

        #[messages(agent)]
        impl RawConfigured {
            fn new(bytes: &[u8]) -> Self {
                Self {
                    length: bytes.len() as u64,
                }
            }

            #[msg]
            fn length(&self) -> u64 {
                self.length
            }
        }
    }

    mod portable_role_actor {
        use vos::prelude::*;

        #[actor(agent)]
        pub struct PortableRole;

        #[messages(agent)]
        impl PortableRole {
            fn new() -> Self {
                Self
            }

            #[msg(
                query,
                space_role = SpaceRole::Member,
                space_role_id = "3131313131313131313131313131313131313131313131313131313131313131"
            )]
            fn guarded(&self) {}
        }
    }

    use const_only_actor::{ConstOnly, ConstOnlyMsg};
    use fixed_array_actor::FixedArrayConfigured;
    use parameterized_actor::{Parameterized, ParameterizedMsg};
    use portable_role_actor::PortableRoleMsg;
    use raw_actor::{RawConfigured, RawConfiguredMsg};
    use unconfigured_actor::{Unconfigured, UnconfiguredMsg};

    fn encoded_constructor_schema(
        constructor: vos::agent::sdk::schema::ConstructorMeta,
    ) -> Vec<u8> {
        let (encoded, len) =
            vos::agent::sdk::schema::encode::<1024>(&vos::agent::sdk::schema::SchemaMeta {
                constructor,
                fields: &[],
                methods: &[],
            });
        encoded[..len].to_vec()
    }

    #[test]
    fn agent_macro_emits_exact_aas2_constructor_contracts() {
        let forbidden = encoded_constructor_schema(UnconfiguredMsg::AGENT_CONSTRUCTOR);
        assert_eq!(forbidden.get(..4), Some(b"AAS2".as_slice()));
        assert!(matches!(
            vos::agent::sdk::schema::decode(&forbidden)
                .unwrap()
                .constructor,
            vos::agent::sdk::schema::ConstructorContract::Forbidden
        ));

        let raw = encoded_constructor_schema(RawConfiguredMsg::AGENT_CONSTRUCTOR);
        let raw = vos::agent::sdk::schema::decode(&raw).unwrap();
        let vos::agent::sdk::schema::ConstructorContract::RequiredRaw(argument) = raw.constructor
        else {
            panic!("one &[u8] constructor must be RequiredRaw")
        };
        assert_eq!(argument.name, "bytes");
        assert_eq!(
            argument.type_identity,
            vos::agent::sdk::schema::RAW_CONSTRUCTOR_TYPE_IDENTITY
        );

        let named = encoded_constructor_schema(ParameterizedMsg::AGENT_CONSTRUCTOR);
        let named = vos::agent::sdk::schema::decode(&named).unwrap();
        let vos::agent::sdk::schema::ConstructorContract::RequiredNamed(arguments) =
            named.constructor
        else {
            panic!("typed constructor must be RequiredNamed")
        };
        assert_eq!(arguments.len(), 1);
        assert_eq!(arguments[0].name, "tenant");
        assert!(arguments[0].type_identity.ends_with("::u64"));

        let no_arg_const = encoded_constructor_schema(ConstOnlyMsg::AGENT_CONSTRUCTOR);
        assert!(matches!(
            vos::agent::sdk::schema::decode(&no_arg_const)
                .unwrap()
                .constructor,
            vos::agent::sdk::schema::ConstructorContract::Forbidden
        ));

        let mut old_magic = forbidden;
        old_magic[..4].copy_from_slice(b"AAS1");
        assert!(vos::agent::sdk::schema::decode(&old_magic).is_err());
    }

    #[test]
    fn agent_macro_preserves_exact_portable_role_identity() {
        let (encoded, len) = vos::metadata::encode_agent_authorizations::<512>(
            PortableRoleMsg::AGENT_AUTHORIZATIONS,
        );
        let parsed = vos::metadata::decode_agent_authorizations(&encoded[..len]).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].name, "guarded");
        assert_eq!(
            parsed[0].selector,
            vos::metadata::ParsedAgentAuthorizationSelector::SpaceRole([0x31; 32])
        );
    }

    #[test]
    fn generated_agent_construction_uses_exact_installation_args_on_every_hydration() {
        let args = vos::value::Args::new().with("tenant", 7_u64).encode();
        let mut fresh =
            <Parameterized as vos::Actor>::__load_agent_state(Some(&args), None, None, None)
                .unwrap();
        assert_eq!(fresh.tenant, 7);
        assert_eq!(fresh.value, 0);

        fresh.value = 91;
        let linear =
            <Parameterized as vos::Actor>::__save_agent_lane(&fresh, vos::agent::StateLane::Linear);
        let restarted = <Parameterized as vos::Actor>::__load_agent_state(
            Some(&args),
            Some(&linear),
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            restarted.tenant, 7,
            "const state is reconstructed from args"
        );
        assert_eq!(
            restarted.value, 91,
            "row-free mutable state remains lane-backed"
        );

        assert!(
            <Parameterized as vos::Actor>::__load_agent_state(None, None, None, None).is_none(),
            "a parameterized/const actor has no default-construction fallback"
        );
        assert!(
            <Unconfigured as vos::Actor>::__load_agent_state(Some(&[]), None, None, None,)
                .is_none(),
            "unexpected present-empty data is distinct from absence"
        );
        assert!(<Unconfigured as vos::Actor>::__load_agent_state(None, None, None, None).is_some());

        assert_eq!(
            <RawConfigured as vos::Actor>::__load_agent_state(Some(&[]), None, None, None,)
                .unwrap()
                .length,
            0,
            "RequiredRaw preserves present-empty installation data"
        );
        assert!(
            <RawConfigured as vos::Actor>::__load_agent_state(None, None, None, None).is_none(),
            "RequiredRaw distinguishes absence from present-empty"
        );

        assert_eq!(
            <ConstOnly as vos::Actor>::__load_agent_state(None, None, None, None,)
                .unwrap()
                .tenant,
            17,
            "const state follows the zero-argument constructor and needs no payload"
        );
        assert!(
            <ConstOnly as vos::Actor>::__load_agent_state(Some(&[]), None, None, None,).is_none(),
            "even present-empty data is unexpected for a zero-argument constructor"
        );
        assert!(
            <ConstOnly as vos::Actor>::__load_agent_state(Some(&[1]), None, None, None,).is_none(),
            "const-only zero-argument construction cannot ignore non-empty bytes"
        );
    }

    #[test]
    fn fixed_byte_array_installation_args_are_exact_and_fail_closed() {
        let seed = [0x5a; 32];
        let args = vos::value::Args::new().with("seed", seed.to_vec()).encode();
        let actor =
            <FixedArrayConfigured as vos::Actor>::__load_agent_state(Some(&args), None, None, None)
                .unwrap();
        assert_eq!(actor.seed, seed);

        let short = vos::value::Args::new()
            .with("seed", vec![0x5a_u8; 31])
            .encode();
        assert!(
            std::panic::catch_unwind(|| {
                let _ = <FixedArrayConfigured as vos::Actor>::__load_agent_state(
                    Some(&short),
                    None,
                    None,
                    None,
                );
            })
            .is_err(),
            "a fixed-size constructor argument must never truncate or pad"
        );
    }

    #[test]
    fn malformed_typed_installation_args_never_fall_back_to_new_defaults() {
        assert!(
            std::panic::catch_unwind(|| {
                let _ = <Parameterized as vos::Actor>::__load_agent_state(
                    Some(&[0xff]),
                    None,
                    None,
                    None,
                );
            })
            .is_err()
        );
    }
}

/// An `Invoker` that ignores the request and hands back a canned
/// reply `Value`, so a `{Actor}Ref` method can be driven end-to-end
/// on the host without a live daemon.
struct MockInvoker {
    reply: Value,
}

struct MockAttestationInvoker {
    result: Option<AttestedInvocationResult>,
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

    let actor_local = VaultMsg::from_msg(&Msg::new("rotate_key")).expect("actor-local message");
    assert_eq!(
        actor_local.required_role(),
        Some(fixture::VaultRole::Admin as u8)
    );
    let meta = VaultMsg::META
        .messages
        .iter()
        .find(|message| message.name == "rotate_key")
        .expect("actor-local policy metadata");
    assert_eq!(meta.space_role, None);
    assert_eq!(meta.actor_role, Some(fixture::VaultRole::Admin as u8));
}

#[test]
fn attested_dispatch_reply_wire_matches_claim_wire_for_every_return_shape() {
    fn dispatch(actor: &mut Vault, context: &mut vos::Context<Vault>, message: Msg) -> Vec<u8> {
        let message = VaultMsg::from_msg(&message).expect("typed message");
        assert!(matches!(
            vos::Actor::dispatch(actor, message, context),
            vos::RunResult::Complete(false)
        ));
        context.take_reply_bytes()
    }

    let mut actor = <Vault as vos::Actor>::create();
    let mut context = vos::Context::new(ServiceId(7));
    context.set_caller_roles(Some(vos::SpaceRole::Member.as_u8()), None);

    let receipt = Receipt {
        id: 1,
        tag: [0; 32],
    };
    assert_eq!(
        dispatch(&mut actor, &mut context, Msg::new("last_receipt")),
        <fixture::LastReceipt as vos::AttestedMethod<Receipt>>::claim_wire(&receipt)
    );
    assert_eq!(
        dispatch(
            &mut actor,
            &mut context,
            Msg::new("optional_token").with("issue", false)
        ),
        <fixture::OptionalToken as vos::AttestedMethod<Option<MembershipToken>>>::claim_wire(&None)
    );
    assert_eq!(
        dispatch(
            &mut actor,
            &mut context,
            Msg::new("optional_token").with("issue", true)
        ),
        <fixture::OptionalToken as vos::AttestedMethod<Option<MembershipToken>>>::claim_wire(
            &Some(MembershipToken)
        )
    );
    assert_eq!(
        dispatch(&mut actor, &mut context, Msg::new("acknowledge")),
        <fixture::Acknowledge as vos::AttestedMethod<()>>::claim_wire(&())
    );
    assert_eq!(
        dispatch(&mut actor, &mut context, Msg::new("try_acknowledge")),
        <fixture::TryAcknowledge as vos::AttestedMethod<()>>::claim_wire(&())
    );
    assert_eq!(
        dispatch(&mut actor, &mut context, Msg::new("scalar")),
        <fixture::Scalar as vos::AttestedMethod<u64>>::claim_wire(&7)
    );
}

#[test]
fn attested_option_claims_tag_none_some_and_zero_sized_values() {
    type Marker = fixture::OptionalToken;
    let none = <Marker as vos::AttestedMethod<Option<MembershipToken>>>::claim_wire(&None);
    let some = <Marker as vos::AttestedMethod<Option<MembershipToken>>>::claim_wire(&Some(
        MembershipToken,
    ));
    assert_ne!(none, some);
    assert_eq!(
        <Marker as vos::AttestedMethod<Option<MembershipToken>>>::decode_claim_wire(&none),
        Some(None)
    );
    assert_eq!(
        <Marker as vos::AttestedMethod<Option<MembershipToken>>>::decode_claim_wire(&some),
        Some(Some(MembershipToken))
    );
}

#[test]
fn attested_unit_methods_compile_and_commit_a_typed_unit_reply() {
    let mut actor = <Vault as vos::Actor>::create();
    let mut context = vos::Context::new(ServiceId(7));
    let message = VaultMsg::from_msg(&Msg::new("acknowledge")).expect("unit message");
    assert!(matches!(
        vos::Actor::dispatch(&mut actor, message, &mut context),
        vos::RunResult::Complete(false)
    ));
    assert_eq!(
        <Value as vos::Decode>::decode(&context.take_reply_bytes()),
        Value::Unit
    );

    let message = VaultMsg::from_msg(&Msg::new("try_acknowledge")).expect("result unit message");
    assert!(matches!(
        vos::Actor::dispatch(&mut actor, message, &mut context),
        vos::RunResult::Complete(false)
    ));
    assert_eq!(
        <Value as vos::Decode>::decode(&context.take_reply_bytes()),
        Value::Unit
    );
}

#[test]
fn attested_handle_returns_a_typed_package_not_a_bare_claim() {
    let claim = Receipt {
        id: 8,
        tag: [10; 32],
    };
    let mut invoker = MockAttestationInvoker {
        result: Some(attested_receipt_result(&claim)),
    };
    let mut vault = VaultRef::bind(ActorId([5; 32]), &mut invoker);
    let package: vos::Attestation<Receipt, fixture::LastReceipt> =
        vos::block_on(vault.last_receipt()).unwrap();
    assert_eq!(package.unverified_preview(), &claim);
    assert_eq!(package.statement().method, "last_receipt");
    assert_eq!(package.producer(), ProducerId([15; 32]));
    let portable = package.to_portable_bytes().unwrap();
    let decoded =
        vos::Attestation::<Receipt, fixture::LastReceipt>::from_portable_bytes(&portable).unwrap();
    assert_eq!(decoded.unverified_preview(), &claim);
}

#[test]
fn attested_handle_rejects_a_reply_that_does_not_match_the_statement() {
    let claim = Receipt {
        id: 8,
        tag: [10; 32],
    };
    let mut result = attested_receipt_result(&claim);
    result.value = Value::Bytes(
        vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&Receipt {
            id: 9,
            tag: [10; 32],
        })
        .unwrap()
        .to_vec(),
    );
    let mut invoker = MockAttestationInvoker {
        result: Some(result),
    };
    let mut vault = VaultRef::bind(ActorId([5; 32]), &mut invoker);
    assert!(matches!(
        vos::block_on(vault.last_receipt()),
        Err(ClientError::InvalidAttestation(
            vos::AttestationError::ClaimCommitmentMismatch
        ))
    ));
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
fn actor_local_role_is_emitted_and_enforced_before_the_handler_runs() {
    let mut actor = <Vault as vos::Actor>::create();
    let mut denied = vos::Context::new(ServiceId(7));
    denied.set_caller_roles(None, Some(fixture::VaultRole::Guest as u8));
    let message = VaultMsg::from_msg(&Msg::new("rotate_key")).expect("message");
    assert!(matches!(
        vos::Actor::dispatch(&mut actor, message, &mut denied),
        vos::RunResult::Complete(false)
    ));
    assert!(denied.was_forbidden());

    let mut actor = <Vault as vos::Actor>::create();
    let mut allowed = vos::Context::new(ServiceId(7));
    allowed.set_caller_roles(None, Some(fixture::VaultRole::Admin as u8));
    let message = VaultMsg::from_msg(&Msg::new("rotate_key")).expect("message");
    assert!(matches!(
        vos::Actor::dispatch(&mut actor, message, &mut allowed),
        vos::RunResult::Complete(false)
    ));
    assert!(!allowed.was_forbidden());
}

#[test]
fn bound_handle_methods_do_not_take_an_invoker_argument() {
    use vos::ActorReference;

    let actor = ActorId([7; 32]);
    let mut invoker = BoundMockInvoker {
        reply: Value::U64(42),
        actor: None,
    };
    let mut handle = VaultRef::bind(actor, &mut invoker);
    assert_eq!(handle.actor_id(), actor);
    let value = vos::block_on(handle.deposit(42)).unwrap();
    assert_eq!(value, 42);
    assert_eq!(invoker.actor, Some(actor));
}

#[test]
fn generated_reference_is_bound_to_the_exact_actor_type() {
    fn assert_reference_for<A, R>()
    where
        A: vos::Actor,
        R: vos::actors::client::ActorReferenceFor<A>,
    {
    }

    assert_reference_for::<Vault, VaultRef>();
    assert_reference_for::<fixture::gate::Gate, GateRef>();
}

#[test]
fn bound_handles_preserve_authorization_denials() {
    use vos::ActorReference;

    let mut invoker = DeniedBoundInvoker;
    let mut handle = VaultRef::bind(ActorId([7; 32]), &mut invoker);
    assert!(matches!(
        vos::block_on(handle.deposit(42)),
        Err(ClientError::Forbidden)
    ));
}

#[test]
fn bound_attested_handles_bind_the_exact_supplied_claim_wire() {
    use vos::ActorReference;

    // `Option<MembershipToken>::Some` has the canonical payload `[1]`.
    // rkyv accepts trailing bytes for the zero-sized token, so a generated
    // handle must commit to the supplied Value wire before decoding rather
    // than re-encoding the decoded preview.
    let canonical = Value::Bytes(vec![1]);
    let mut result = attested_value_result("optional_token", canonical);
    result.value = Value::Bytes(vec![1, 0xaa]);

    let mut invoker = MockAttestationInvoker {
        result: Some(result),
    };
    let mut handle = VaultRef::bind(ActorId([7; 32]), &mut invoker);
    assert!(matches!(
        vos::block_on(handle.optional_token(true)),
        Err(ClientError::InvalidAttestation(
            vos::AttestationError::ClaimCommitmentMismatch
        ))
    ));
}

struct BoundMockInvoker {
    reply: Value,
    actor: Option<ActorId>,
}

struct BoundExtensionInvoker {
    reply: Value,
    target: Option<String>,
    payload: Option<Vec<u8>>,
}

struct DeniedBoundInvoker;

impl Invoker for DeniedBoundInvoker {
    fn invoke_actor(
        &mut self,
        _target: ActorId,
        _payload: Vec<u8>,
    ) -> impl core::future::Future<Output = core::result::Result<Value, ClientError>> + '_ {
        core::future::ready(Err(ClientError::from(vos::InvokeError::Forbidden)))
    }
}

impl Invoker for BoundMockInvoker {
    fn invoke_actor(
        &mut self,
        target: ActorId,
        _payload: Vec<u8>,
    ) -> impl core::future::Future<Output = core::result::Result<Value, ClientError>> + '_ {
        self.actor = Some(target);
        core::future::ready(Ok(self.reply.clone()))
    }
}

impl ExtensionInvoker for BoundExtensionInvoker {
    fn invoke_extension(
        &mut self,
        target: String,
        payload: Vec<u8>,
    ) -> impl core::future::Future<Output = core::result::Result<Value, ClientError>> + '_ {
        self.target = Some(target);
        self.payload = Some(payload);
        core::future::ready(Ok(self.reply.clone()))
    }
}

impl Invoker for MockInvoker {
    fn invoke_actor(
        &mut self,
        _target: ActorId,
        _payload: Vec<u8>,
    ) -> impl core::future::Future<Output = core::result::Result<Value, ClientError>> + '_ {
        let reply = self.reply.clone();
        async move { Ok(reply) }
    }
}

impl Invoker for MockAttestationInvoker {
    async fn invoke_actor(
        &mut self,
        _target: ActorId,
        _payload: Vec<u8>,
    ) -> core::result::Result<Value, ClientError> {
        Err(ClientError::Unreachable)
    }
}

impl AttestationInvoker for MockAttestationInvoker {
    fn invoke_actor_attested(
        &mut self,
        _target: ActorId,
        _payload: Vec<u8>,
    ) -> impl core::future::Future<
        Output = core::result::Result<AttestedInvocationResult, ClientError>,
    > + '_ {
        let result = self.result.take().ok_or(ClientError::Unreachable);
        async move { result }
    }
}

fn attested_receipt_result(claim: &Receipt) -> AttestedInvocationResult {
    use vos::Encode;

    let value = Value::Bytes(
        vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(claim)
            .expect("rkyv encode")
            .to_vec(),
    );
    let deployment = DeploymentId([3; 32]);
    let invocation = InvocationId([10; 32]);
    let actor = ActorId([7; 32]);
    let reply = ReplyRecord {
        call_id: invocation.root_reply_id(),
        producer: actor,
        result: value.encode(),
    };
    let receipt = AccumulationReceipt {
        service: ServiceIdentity {
            space: SpaceId([6; 32]),
            root_service: RootServiceId([1; 32]),
            deployment,
            service_program: ProgramId([2; 32]),
            platform: vos::service::PLATFORM_ID,
            execution_semantics: vos::service::EXECUTION_SEMANTICS_ID,
            gas_schedule: vos::service::GasSchedule::new(1_000_000_000, 5_000_000_000),
        },
        accepted_transition: Hash([4; 32]),
        reply_commitment: Some(reply.commitment()),
        outbox_commitment: None,
        resulting_state_root: Some(Hash([5; 32])),
        resulting_crdt_heads: vec![],
        sequence: 1,
        checkpoint: 1,
        consistency: ConsistencyMode::Local,
    };
    AttestedInvocationResult {
        producer_name: "private-vault".into(),
        producer: ProducerId([15; 32]),
        statement: vos::AttestationStatement {
            space: SpaceId([6; 32]),
            actor,
            producer_name: "private-vault".into(),
            producer: ProducerId([15; 32]),
            deployment,
            actor_program: ProgramId([8; 32]),
            method: "last_receipt".into(),
            schema: Hash([9; 32]),
            invocation,
            reply_call: reply.call_id,
            before: vos::StateCommitment::Linear(Hash([11; 32])),
            after: vos::StateCommitment::Linear(Hash([5; 32])),
            claim_commitment: Hash::digest(b"vos/attestation-claim", &[&value.encode()]),
            input_commitment: Hash([13; 32]),
            authorization_policy: Hash([14; 32]),
            accumulation_receipt: receipt,
        },
        trace: Hash([16; 32]),
        proof: vec![1],
        value,
    }
}

fn attested_value_result(method: &str, value: Value) -> AttestedInvocationResult {
    use vos::Encode;

    let mut result = attested_receipt_result(&Receipt {
        id: 1,
        tag: [0; 32],
    });
    result.statement.method = method.into();
    result.statement.claim_commitment = Hash::digest(b"vos/attestation-claim", &[&value.encode()]);
    result.statement.accumulation_receipt.reply_commitment = Some(
        ReplyRecord {
            call_id: result.statement.reply_call,
            producer: result.statement.actor,
            result: value.encode(),
        }
        .commitment(),
    );
    result.value = value;
    result
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
    fn invoke_actor(
        &mut self,
        _target: ActorId,
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
    let mut vault = VaultRef::bind(ActorId([5; 32]), &mut inv);
    let got = vos::block_on(vault.read_receipt()).expect("valid reply decodes");
    assert_eq!(got, receipt);
}

#[test]
fn extension_ref_binds_name_and_uses_the_ordinary_typed_wire() {
    let mut invoker = BoundExtensionInvoker {
        reply: Value::U64(500),
        target: None,
        payload: None,
    };
    let mut vault = VaultRef::bind_extension("substrate".into(), &mut invoker);
    assert_eq!(vault.extension_name(), "substrate");
    assert_eq!(vos::block_on(vault.deposit(500)).unwrap(), 500);
    assert_eq!(invoker.target.as_deref(), Some("substrate"));

    let payload = invoker
        .payload
        .expect("typed extension payload was captured");
    assert_eq!(payload.first(), Some(&vos::value::TAG_DYNAMIC));
    let message = <Msg as vos::Decode>::decode(&payload[1..]);
    assert_eq!(message.name, "deposit");
    assert_eq!(message.args.get("amount"), Some(&Value::U64(500)));
}

#[test]
fn ref_rejects_corrupted_custom_reply() {
    // Peer-supplied bytes that are not a valid `Receipt` archive.
    // The old `access_unchecked` path would reinterpret them as an
    // archived struct (UB / garbage); checked `access` must reject.
    let mut inv = MockInvoker {
        reply: Value::Bytes(vec![0xff, 0x00, 0x13, 0x37]),
    };
    let mut vault = VaultRef::bind(ActorId([5; 32]), &mut inv);
    let got = vos::block_on(vault.read_receipt());
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
    let mut vault = VaultRef::bind(ActorId([5; 32]), &mut inv);
    let got = vos::block_on(vault.read_receipt());
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
    // A scalar travels as its canonical `Value` variant, not rkyv-wrapped.
    let mut inv = CapturingInvoker::default();
    let mut vault = VaultRef::bind(ActorId([1; 32]), &mut inv);
    let _ = vos::block_on(vault.deposit(500u64)).expect("invoke");
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
    let mut vault = VaultRef::bind(ActorId([5; 32]), &mut inv);
    let _ = vos::block_on(vault.record(receipt.clone())).expect("invoke");
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
fn portable_attestation_round_trips_as_a_generated_actor_argument() {
    let claim = Receipt {
        id: 101,
        tag: [11; 32],
    };
    let mut producer = MockAttestationInvoker {
        result: Some(attested_receipt_result(&claim)),
    };
    let mut vault = VaultRef::bind(ActorId([5; 32]), &mut producer);
    let package = vos::block_on(vault.last_receipt()).unwrap();

    let mut gate_invoker = CapturingInvoker {
        reply: Some(Value::Bool(true)),
        ..Default::default()
    };
    let mut gate = GateRef::bind(ActorId([6; 32]), &mut gate_invoker);
    let received = vos::block_on(gate.receive_package(package)).unwrap();
    assert!(received);
    let GateMsg::ReceivePackage(message) = GateMsg::from_msg(&gate_invoker.captured_msg()).unwrap();
    assert_eq!(message.package.unverified_preview(), &claim);
}

#[test]
fn vec_byte_array_arg_round_trips() {
    let roots = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
    let mut inv = CapturingInvoker::default();
    let mut vault = VaultRef::bind(ActorId([9; 32]), &mut inv);
    let _ = vos::block_on(vault.pin_roots(roots.clone())).expect("invoke");
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
    let mut vault = VaultRef::bind(ActorId([3; 32]), &mut inv);
    let got = vos::block_on(vault.echo_root(root)).expect("invoke");
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
    let mut vault = VaultRef::bind(ActorId([3; 32]), &mut inv);
    let got = vos::block_on(vault.echo_root([0u8; 32]));
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
