//! The device library: the derivation from a source's output, the scope
//! and the binding, the stock kernels' proofs verified against their calls
//! and refused against others, the witness checked before proving, the
//! prover's configuration, the wire's requests and answers, the path kept
//! apart from proofs, a `RootUnknown` answer fetching it again and proving
//! anew, and the stock kernels' programs from their release artifacts.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use blake2::{Blake2b512, Digest as _};
use ed25519_dalek::{Signature, VerifyingKey};
use scale::{Decode, Encode};
use sha2::Sha256;
use vos_api::Kind;
use vos_light::wire::{self, Answer};
use vos_light::{
    AuthWitness, Call, DEVICE_FORMAT, DeviceError, DeviceProgram, Digest, PEAK_BYTES, PathKeeper,
    Proven, Prover, ProverConfig, Threads, derive_secret, member, owner, scope, source_input,
    verify,
};
use vos_wire::credentials::{
    self, AuthClaim, DEPTH, EMPTY, OwnerClaim, P, Path, RING, Ring, RootEntry, RootRefusal,
    Siblings, Tag, Words, compress, leaf,
};
use vos_wire::ids::{AgentId, InstanceId, MethodId, derive_id};
use vos_wire::ingress::{
    AdmissionRefusal, Consistency, CredentialRefusal, Credentialed, QueryCall, Rejection, Response,
    query_message,
};
use vos_wire::result::Outcome;

const HANDLE: [u8; 32] = [7; 32];
const NAME: &[u8] = b"login";
/// `scope([0x51; 32], 4, 2, "login")`'s bytes, the name in SCALE.
const SCOPE_VECTOR: [u8; 32] = [
    176, 47, 24, 3, 211, 3, 208, 103, 92, 44, 198, 75, 144, 255, 58, 99, 210, 27, 59, 25, 235, 172,
    49, 126, 162, 142, 147, 35, 82, 189, 54, 43,
];

/// A sparse tree of depth 32 over `C`, rebuilt from its leaves: the
/// credential actor's, as `proving.md` §8 defines it.
#[derive(Default)]
struct Tree {
    leaves: BTreeMap<u32, Words>,
}

impl Tree {
    fn enroll(&mut self, slot: u32, member: &Digest) {
        self.leaves.insert(slot, leaf(&member.0));
    }

    fn node(&self, level: usize, index: u64) -> Words {
        let first = index << level;
        let last = first + (1u64 << level) - 1;
        if self
            .leaves
            .range(first as u32..=last.min(u64::from(u32::MAX)) as u32)
            .next()
            .is_none()
        {
            return EMPTY[level];
        }
        if level == 0 {
            return self.leaves[&(index as u32)];
        }
        compress(
            &self.node(level - 1, 2 * index),
            &self.node(level - 1, 2 * index + 1),
        )
    }

    fn root(&self) -> Digest {
        Digest(self.node(DEPTH, 0))
    }

    /// The path the actor's `path` answers, as the node's API carries it.
    fn path(&self, slot: u32) -> Path {
        Path {
            root: self.root().to_bytes(),
            slot,
            siblings: Siblings(core::array::from_fn(|level| {
                credentials::digest(&self.node(level, u64::from(slot >> level ^ 1)))
            })),
        }
    }

    fn witness(&self, slot: u32) -> AuthWitness {
        let answer = Response::Ran {
            outcome: Outcome::Done(Some(self.path(slot)).encode()),
            at: 1,
        };
        wire::path_answer(&answer.encode())
            .unwrap()
            .expect("an enrolled member's path")
    }
}

fn secret(seed: u8) -> vos_light::DeviceSecret {
    derive_secret(&[seed; 32], &HANDLE)
}

fn call(arguments: &[u8]) -> Call {
    Call {
        space: [0x51; 32],
        agent: 4,
        instance: 2,
        method: derive_id("vos/method/", "vote"),
        arguments: arguments.to_vec(),
        nonce: [9; 16],
        expires_ms: 1_000_000,
    }
}

/// The stock kernels' programs, `auth`'s and `owner`'s, from their release
/// artifacts: computed once.
fn programs() -> &'static (DeviceProgram, DeviceProgram) {
    static PROGRAMS: OnceLock<(DeviceProgram, DeviceProgram)> = OnceLock::new();
    PROGRAMS.get_or_init(|| {
        let elf = std::fs::read(vos_testkit::programs::credentials_elf()).unwrap();
        let program = |kernel| {
            DeviceProgram::released(&vos_light::release::device(&elf, kernel).unwrap()).unwrap()
        };
        (program("auth"), program("owner"))
    })
}

fn auth_program() -> &'static DeviceProgram {
    &programs().0
}

fn owner_program() -> &'static DeviceProgram {
    &programs().1
}

fn prover() -> Prover {
    Prover::new(ProverConfig {
        threads: Threads::Count(4),
        ..ProverConfig::default()
    })
    .unwrap()
}

/// A tree holding `secret`'s member at `slot` and others beside it.
fn tree_with(secret: &vos_light::DeviceSecret, slot: u32) -> Tree {
    let mut tree = Tree::default();
    tree.enroll(slot, &member(secret));
    for other in [0, 1, 0xffff_ffff] {
        if other != slot {
            tree.enroll(other, &member(&derive_secret(&[other as u8; 32], &[1; 32])));
        }
    }
    tree
}

/// The input is `SHA-256("vos/device/input/v1" ‖ handle)`; the secret is
/// BLAKE2b-512's eight little-endian `u64`s reduced mod p; one source
/// gives unrelated secrets for two handles and the same for one.
#[test]
fn the_secret_is_derived_as_pinned() {
    let expected: [u8; 32] = Sha256::new()
        .chain_update(b"vos/device/input/v1")
        .chain_update(HANDLE)
        .finalize()
        .into();
    assert_eq!(source_input(&HANDLE), expected);
    assert_ne!(source_input(&HANDLE), source_input(&[8; 32]));

    let output = [0xa5; 32];
    let w: [u8; 64] = Blake2b512::new()
        .chain_update(b"vos/device/secret/v1")
        .chain_update(HANDLE)
        .chain_update(output)
        .finalize()
        .into();
    let words: Words = core::array::from_fn(|i| {
        (u64::from_le_bytes(w[8 * i..8 * i + 8].try_into().unwrap()) % u64::from(P)) as u32
    });
    let secret = derive_secret(&output, &HANDLE);
    assert_eq!(
        member(&secret),
        Digest(compress(&Tag::Member.block(), &words))
    );
    assert_eq!(
        owner(&secret),
        Digest(compress(&Tag::Owner.block(), &words))
    );
    assert_ne!(member(&secret), owner(&secret));
    assert_eq!(member(&derive_secret(&output, &HANDLE)), member(&secret));
    assert_ne!(member(&derive_secret(&output, &[8; 32])), member(&secret));
    assert_ne!(
        member(&derive_secret(&[0xa6; 32], &HANDLE)),
        member(&secret)
    );
}

/// The scope hashes the space, agent, instance and the name with its
/// length; the binding every field of the call and the program.
#[test]
fn the_scope_and_the_binding_name_the_call() {
    let space = [0x51; 32];
    let expected = vos_pvm_precompiles::blake2b_hash::<32>(
        b"vos/cred/scope/v1",
        &[
            &space,
            &4u32.to_le_bytes(),
            &2u32.to_le_bytes(),
            &5u32.to_le_bytes(),
            b"login",
        ],
    );
    assert_eq!(
        scope(&space, 4, 2, b"login"),
        Some(Digest(compress(
            &Tag::Scope.block(),
            &credentials::reduced(&expected)
        )))
    );
    for other in [
        scope(&[0x52; 32], 4, 2, b"login"),
        scope(&space, 5, 2, b"login"),
        scope(&space, 4, 3, b"login"),
        scope(&space, 4, 2, b"login2"),
    ] {
        assert_ne!(other, scope(&space, 4, 2, b"login"));
    }
    // A vector the ingress's scope must give too.
    assert_eq!(
        scope(&space, 4, 2, b"login").unwrap().to_bytes(),
        SCOPE_VECTOR
    );
    assert_eq!(scope(&space, 4, 2, b""), None);
    assert_eq!(scope(&space, 4, 2, &[b'a'; 65]), None);
    assert!(scope(&space, 4, 2, &[b'a'; 64]).is_some());

    let base = call(b"args");
    let program = [3; 32];
    let b = base.binding_digest(&program);
    let changed = [
        Call {
            space: [0; 32],
            ..base.clone()
        },
        Call {
            agent: 5,
            ..base.clone()
        },
        Call {
            instance: 9,
            ..base.clone()
        },
        Call {
            method: 1,
            ..base.clone()
        },
        Call {
            arguments: b"argt".to_vec(),
            ..base.clone()
        },
        Call {
            nonce: [0; 16],
            ..base.clone()
        },
        Call {
            expires_ms: 1,
            ..base.clone()
        },
    ];
    for other in &changed {
        assert_ne!(other.binding_digest(&program), b);
    }
    assert_ne!(base.binding_digest(&[4; 32]), b);
    assert_eq!(
        base.binding(&program),
        Digest(compress(&Tag::Binding.block(), &credentials::reduced(&b)))
    );
    let fresh = Call::new([0x51; 32], 4, 2, 1, Vec::new(), 1).unwrap();
    assert_ne!(
        fresh.nonce,
        Call::new([0x51; 32], 4, 2, 1, Vec::new(), 1).unwrap().nonce
    );
}

/// A method's id and a transfer's arguments are what the node derives and
/// decodes.
#[test]
fn a_method_id_and_a_transfer_s_arguments_are_the_node_s() {
    assert_eq!(vos_light::method_id("increment"), 0xf251_d1d4);
    assert_eq!(
        vos_light::method_id("transfer"),
        derive_id("vos/method/", "transfer")
    );
    let arguments = vos_light::transfer_arguments("bob", 7);
    assert_eq!(
        arguments,
        [&3u32.to_le_bytes()[..], b"bob", &7u64.to_le_bytes()].concat()
    );
    assert_eq!(
        <(Vec<u8>, u64)>::decode(&arguments).unwrap(),
        ((b"bob".to_vec(), 7), arguments.len())
    );
}

/// Auth and owner prove by the stock kernels and verify against their
/// calls; each is refused against another call, another name, another
/// format, another program or another claim.
#[test]
fn each_proof_verifies_against_its_call_alone() {
    let prover = prover();
    let secret = secret(1);
    let tree = tree_with(&secret, 0x8000_0001);
    let witness = tree.witness(0x8000_0001);
    let call = call(b"yes");
    let (auth_program, owner_program) = (auth_program(), owner_program());

    let auth = prover
        .prove_auth(&secret, &witness, NAME, &call, auth_program)
        .unwrap();
    assert_eq!(auth.format, DEVICE_FORMAT);
    verify(&auth, &call, auth_program, Some(NAME)).unwrap();
    let claim = AuthClaim::decode_exact(&auth.claim).expect("auth's claim, its digests alone");
    assert_eq!(claim.map_root, tree.root().to_bytes());
    assert_eq!(
        Some(claim.scope),
        scope(&call.space, call.agent, call.instance, NAME).map(|scope| scope.to_bytes())
    );
    assert_eq!(claim.binding, call.binding(auth_program.id()).to_bytes());
    assert_eq!(
        verify(&auth, &self::call(b"no"), auth_program, Some(NAME)),
        Err(DeviceError::Verify)
    );
    assert_eq!(
        verify(&auth, &call, auth_program, Some(b"vote")),
        Err(DeviceError::Verify)
    );
    assert_eq!(
        verify(&auth, &call, owner_program, Some(NAME)),
        Err(DeviceError::Verify),
        "another program"
    );
    // Digests the call does not fix, changed: refused by the proof itself.
    for changed in [
        AuthClaim {
            nullifier: Digest(compress(&[1; 8], &[2; 8])).to_bytes(),
            ..claim
        },
        AuthClaim {
            map_root: Tree::default().root().to_bytes(),
            ..claim
        },
    ] {
        let changed = Proven {
            claim: changed.encode(),
            ..auth.clone()
        };
        assert_eq!(
            verify(&changed, &call, auth_program, Some(NAME)),
            Err(DeviceError::Verify)
        );
    }
    let relabelled = Proven {
        format: 38,
        ..auth.clone()
    };
    assert_eq!(
        verify(&relabelled, &call, auth_program, Some(NAME)),
        Err(DeviceError::Verify)
    );
    let mut tampered = auth.clone();
    let last = tampered.proof.len() - 1;
    tampered.proof[last] ^= 1;
    assert_eq!(
        verify(&tampered, &call, auth_program, Some(NAME)),
        Err(DeviceError::Verify)
    );

    let paid = prover.prove_owner(&secret, &call, owner_program).unwrap();
    verify(&paid, &call, owner_program, None).unwrap();
    let claimed = OwnerClaim::decode_exact(&paid.claim).expect("owner's claim");
    assert_eq!(claimed.owner, owner(&secret).to_bytes());
    assert_eq!(
        verify(&paid, &self::call(b"no"), owner_program, None),
        Err(DeviceError::Verify)
    );
    assert_eq!(
        verify(&paid, &call, owner_program, Some(NAME)),
        Err(DeviceError::Verify),
        "an owner claim is no auth claim"
    );
    // Another secret's owner digest under this proof: refused.
    let other = Proven {
        claim: OwnerClaim {
            owner: owner(&self::secret(2)).to_bytes(),
            ..claimed
        }
        .encode(),
        ..paid.clone()
    };
    assert_eq!(
        verify(&other, &call, owner_program, None),
        Err(DeviceError::Verify)
    );
}

/// A witness that does not place the secret's member under its root is
/// refused before any proving: another member's path, a changed sibling,
/// a word at or above p; and a call or name out of bounds.
#[test]
fn a_bad_witness_is_refused_before_proving() {
    let prover = prover();
    let secret = secret(1);
    let tree = tree_with(&secret, 5);
    let witness = tree.witness(5);
    let call = call(b"yes");
    let refused =
        |witness: &AuthWitness| prover.prove_auth(&secret, witness, NAME, &call, auth_program());
    let elsewhere = tree.witness(0);
    assert_eq!(refused(&elsewhere).unwrap_err(), DeviceError::Witness);
    let mut sibling = witness.clone();
    sibling.siblings[9].0[0] ^= 1;
    assert_eq!(refused(&sibling).unwrap_err(), DeviceError::Witness);
    let mut above = witness.clone();
    above.siblings[0].0[0] = P;
    assert_eq!(refused(&above).unwrap_err(), DeviceError::Witness);
    let mut slot = witness.clone();
    slot.slot ^= 1 << 20;
    assert_eq!(refused(&slot).unwrap_err(), DeviceError::Witness);
    assert_eq!(
        prover
            .prove_auth(&self::secret(2), &witness, NAME, &call, auth_program())
            .unwrap_err(),
        DeviceError::Witness
    );
    assert_eq!(
        prover
            .prove_auth(&secret, &witness, b"", &call, auth_program())
            .unwrap_err(),
        DeviceError::Config
    );
    let long = Call {
        arguments: vec![0; vos_wire::abi::cap::REQUEST - vos_wire::abi::cap::CLAIM + 1],
        ..call.clone()
    };
    assert_eq!(
        prover
            .prove_owner(&secret, &long, owner_program())
            .unwrap_err(),
        DeviceError::Config
    );
}

/// The configuration: a memory allowance below a proof's refused; no
/// threads refused; `Auto` at most one thread a core; pinned cores prove.
#[test]
fn the_configuration_is_checked() {
    let refused = Prover::new(ProverConfig {
        max_memory: PEAK_BYTES - 1,
        ..ProverConfig::default()
    });
    assert_eq!(refused.err(), Some(DeviceError::Memory));
    let none = Prover::new(ProverConfig {
        threads: Threads::Count(0),
        ..ProverConfig::default()
    });
    assert_eq!(none.err(), Some(DeviceError::Config));
    let empty = Prover::new(ProverConfig {
        threads: Threads::Cores(Vec::new()),
        ..ProverConfig::default()
    });
    assert_eq!(empty.err(), Some(DeviceError::Config));
    let auto = Prover::new(ProverConfig::default()).unwrap();
    assert!(
        (1..=std::thread::available_parallelism().unwrap().get()).contains(&auto.threads()),
        "at most a thread a core"
    );
    let pinned = Prover::new(ProverConfig {
        threads: Threads::Cores(vec![0, 1]),
        ..ProverConfig::default()
    })
    .unwrap();
    assert_eq!(pinned.threads(), 2);
    let secret = secret(3);
    let proof = pinned
        .prove_owner(&secret, &call(b""), owner_program())
        .unwrap();
    verify(&proof, &call(b""), owner_program(), None).unwrap();
}

/// The requests: `Time` its kind alone; `path` and `root()` queries signed
/// over the agent's identity by a key drawn for each; the credentialed
/// request the call and the proof. The answers: the time, a path, none,
/// the root, and a credentialed call's, `RootUnknown` among them.
#[test]
fn the_wire_requests_and_answers() {
    assert_eq!(wire::time_request(), 0x0002u16.to_le_bytes());
    assert_eq!(wire::time_answer(&77u64.encode()), Ok(77));
    assert_eq!(wire::time_answer(&[1, 2]), Err(DeviceError::Decode));

    let identity = [0x1d; 32];
    let member = member(&secret(1));
    let decode = |request: &[u8]| {
        assert_eq!(request[..2], 0x0102u16.to_le_bytes());
        <(AgentId, QueryCall)>::decode_exact(&request[2..]).expect("a query's body")
    };
    let (agent, path) = decode(&wire::path_query(4, &identity, 2, &member, 900).unwrap());
    assert_eq!(agent, AgentId(4));
    assert_eq!(path.instance, InstanceId(2));
    assert_eq!(path.method, MethodId(derive_id("vos/method/", "path")));
    assert_eq!(path.arguments, member.to_bytes().to_vec());
    assert_eq!(path.not_after, 900);
    assert_eq!(path.consistency, Consistency::Applied { at: 0 });
    let signed = |query: &QueryCall| {
        VerifyingKey::from_bytes(&query.key)
            .unwrap()
            .verify_strict(
                &query_message(
                    &identity,
                    &query.key,
                    query.not_after,
                    query.consistency,
                    query.instance,
                    query.method,
                    &query.arguments,
                ),
                &Signature::from_bytes(&query.signature),
            )
            .is_ok()
    };
    assert!(signed(&path));
    let (_, again) = decode(&wire::path_query(4, &identity, 2, &member, 900).unwrap());
    assert_ne!(again.key, path.key, "a key a query");
    let (_, root) = decode(&wire::root_query(4, &identity, 2, 900).unwrap());
    assert_eq!(root.method, MethodId(derive_id("vos/method/", "root")));
    assert!(root.arguments.is_empty());
    assert!(signed(&root));

    let ran = |reply: Vec<u8>| {
        Response::Ran {
            outcome: Outcome::Done(reply),
            at: 3,
        }
        .encode()
    };
    assert_eq!(wire::path_answer(&ran(None::<Path>.encode())), Ok(None));
    assert_eq!(
        wire::path_answer(&Response::Busy.encode()),
        Err(DeviceError::Decode)
    );
    // Ingress's refusal is the device's to show, as the node gave it.
    let onion_only = Rejection::Admission(AdmissionRefusal::OnionOnly);
    assert_eq!(
        wire::path_answer(&Response::Rejected(onion_only).encode()),
        Err(DeviceError::Rejected(onion_only))
    );
    assert_eq!(
        wire::root_answer(&Response::Rejected(Rejection::Behind).encode()),
        Err(DeviceError::Rejected(Rejection::Behind))
    );
    let mut above = Tree::default().path(0);
    above.siblings.0[3] = [0xff; 32];
    assert_eq!(
        wire::path_answer(&ran(Some(above).encode())),
        Err(DeviceError::Decode)
    );
    let entry = RootEntry {
        root: Tree::default().root().to_bytes(),
        since: 44,
    };
    assert_eq!(
        wire::root_answer(&ran(entry.encode())),
        Ok((Tree::default().root(), 44))
    );

    let prover = prover();
    let secret = secret(1);
    let call = call(b"yes");
    let proof = prover.prove_owner(&secret, &call, owner_program()).unwrap();
    let request = wire::credentialed(&call, &proof);
    assert_eq!(request[..2], (Kind::Credentialed as u16).to_le_bytes());
    let (agent, body) = <(AgentId, Credentialed)>::decode_exact(&request[2..]).unwrap();
    assert_eq!(agent, AgentId(call.agent));
    assert_eq!(
        body,
        Credentialed {
            instance: InstanceId(call.instance),
            method: MethodId(call.method),
            arguments: call.arguments.clone(),
            nonce: call.nonce,
            expires_ms: call.expires_ms,
            format: DEVICE_FORMAT,
            claim: OwnerClaim {
                owner: owner(&secret).to_bytes(),
                binding: call.binding(owner_program().id()).to_bytes(),
            }
            .encode(),
            proof: proof.proof.clone(),
        }
    );
    // The body's layout as identity §5 pins it: the instance and method
    // four bytes each, the arguments a `u32` length and their bytes.
    let bytes = &request[6..];
    assert_eq!(bytes[..4], call.instance.to_le_bytes());
    assert_eq!(bytes[4..8], call.method.to_le_bytes());
    assert_eq!(bytes[8..12], (call.arguments.len() as u32).to_le_bytes());

    let refused = |refusal| Response::Rejected(Rejection::Credential(refusal)).encode();
    assert_eq!(refused(CredentialRefusal::RootUnknown), [2, 9, 10]);
    assert_eq!(
        wire::credentialed_answer(&[2, 9, 10]),
        Ok(Answer::RootUnknown)
    );
    assert_eq!(
        wire::credentialed_answer(&[2, 9, 11]),
        Ok(Answer::RootStale)
    );
    assert_eq!(
        wire::credentialed_answer(&[2, 9, 6]),
        Ok(Answer::Refused(CredentialRefusal::Scope))
    );
    let mut expiry = vec![2, 9, 3];
    expiry.extend(1_234u64.to_le_bytes());
    assert_eq!(
        wire::credentialed_answer(&expiry),
        Ok(Answer::Expiry { now: 1_234 })
    );
    for malformed in [&[2, 9, 10, 0][..], &[2, 9, 3], &[2, 9, 13], &[2, 9]] {
        assert_eq!(
            wire::credentialed_answer(malformed),
            Err(DeviceError::Decode)
        );
    }
    assert_eq!(
        wire::credentialed_answer(&ran(vec![1])),
        Ok(Answer::Ran {
            outcome: Outcome::Done(vec![1]),
            at: 3
        })
    );
    assert_eq!(
        wire::credentialed_answer(&Response::Busy.encode()),
        Ok(Answer::Other(Response::Busy.encode()))
    );
    assert_eq!(wire::credentialed_answer(&[]), Err(DeviceError::Decode));
}

/// The keeper: due with no path; a path not its member's refused; due when
/// the root moved; its timer between half and one and a half periods;
/// `unknown` drops the path and halves the period, a quiet fetch doubles
/// it back.
#[test]
fn the_path_is_kept_apart_from_proofs() {
    let secret = secret(1);
    let tree = tree_with(&secret, 5);
    let mut keeper = PathKeeper::new(member(&secret));
    assert!(keeper.due(0, None));
    assert!(keeper.witness().is_none());
    assert_eq!(keeper.update(tree.witness(0), 0), Err(DeviceError::Witness));
    assert!(keeper.witness().is_none());

    let period = PathKeeper::PERIOD_MS;
    keeper.update(tree.witness(5), 1_000).unwrap();
    assert_eq!(keeper.witness(), Some(&tree.witness(5)));
    assert!(!keeper.due(1_000 + period / 2 - 1, None));
    assert!(!keeper.due(1_000 + period / 2 - 1, Some(&tree.root())));
    assert!(keeper.due(1_000 + period * 3 / 2, None));
    // A moved root brings the fetch forward, spread below
    // `MOVED_SPREAD_MS` from when it is first seen: before the timer's
    // earliest, half a period on.
    keeper.update(tree.witness(5), 1_000).unwrap();
    let seen = 2_000;
    assert!(seen + PathKeeper::MOVED_SPREAD_MS < 1_000 + period / 2);
    keeper.due(seen, Some(&Tree::default().root()));
    assert!(keeper.due(seen + PathKeeper::MOVED_SPREAD_MS, None));

    keeper.unknown();
    assert!(keeper.witness().is_none());
    assert!(keeper.due(1_001, Some(&tree.root())));
    assert_eq!(keeper.period(), period / 2);
    for _ in 0..10 {
        keeper.unknown();
    }
    assert_eq!(keeper.period(), PathKeeper::MIN_PERIOD_MS);
    keeper.update(tree.witness(5), 2_000).unwrap();
    assert!(!keeper.due(2_000 + PathKeeper::MIN_PERIOD_MS / 2 - 1, None));
    keeper.update(tree.witness(5), 3_000).unwrap();
    assert_eq!(keeper.period(), 2 * PathKeeper::MIN_PERIOD_MS);
}

/// The path's freshness in a busy space: 64 tree-changing batches after
/// the member's fetch push its root out of the ring, so ingress answers
/// `RootUnknown` before the root is ever stale; the answer drops the path,
/// the keeper says to fetch again, and the call proved anew on the new
/// path is admitted by the ring and verifies.
#[test]
fn a_root_unknown_answer_fetches_the_path_again_and_proves_anew() {
    let prover = prover();
    let secret = secret(1);
    let slot = 40;
    let mut tree = tree_with(&secret, slot);
    let mut ring = Ring::installed(0);
    ring.record(tree.root().to_bytes(), 10);

    let mut keeper = PathKeeper::new(member(&secret));
    keeper.update(tree.witness(slot), 10).unwrap();
    let call = call(b"yes");
    let held = keeper.witness().unwrap().clone();
    let first = prover
        .prove_auth(&secret, &held, NAME, &call, auth_program())
        .unwrap();
    assert_eq!(ring.accepts(&held.root.to_bytes(), 10), Ok(()));

    // 64 batches, each enrolling one member: one second apart, well within
    // `ROOT_MAX_AGE`, so the held root drops out unknown, not stale.
    for batch in 0..RING as u32 {
        tree.enroll(
            1_000 + batch,
            &member(&derive_secret(
                &[9; 32],
                &batch.to_le_bytes().repeat(8).try_into().unwrap(),
            )),
        );
        ring.record(tree.root().to_bytes(), 11_000 + 1_000 * u64::from(batch));
    }
    let now = 11_000 + 1_000 * RING as u64;
    assert!(now - 10 < vos_wire::defaults::ROOT_MAX_AGE);
    assert_eq!(
        ring.accepts(&held.root.to_bytes(), now),
        Err(RootRefusal::Unknown)
    );

    // Ingress's answer: `Rejected(Credential(RootUnknown))`.
    let answer = [2, 9, 10];
    assert_eq!(wire::credentialed_answer(&answer), Ok(Answer::RootUnknown));
    verify(&first, &call, auth_program(), Some(NAME)).unwrap();
    keeper.unknown();
    assert!(keeper.due(now, None));
    keeper.update(tree.witness(slot), now).unwrap();
    let fresh = keeper.witness().unwrap();
    assert_ne!(fresh.root, held.root);
    let again = prover
        .prove_auth(&secret, fresh, NAME, &call, auth_program())
        .unwrap();
    let claim = AuthClaim::decode_exact(&again.claim).unwrap();
    assert_eq!(ring.accepts(&claim.map_root, now), Ok(()));
    verify(&again, &call, auth_program(), Some(NAME)).unwrap();
    let before = AuthClaim::decode_exact(&first.claim).unwrap().nullifier;
    assert_eq!(claim.nullifier, before, "one pseudonym in one scope");
}

/// The stock kernels' release artifacts, computed from the credential
/// actor's ELF as a node's install computes their programs: each one's
/// program committed from the artifact alone, no reference run, and one
/// whose shape or id is not the artifact's refused.
#[test]
fn the_stock_kernels_programs_come_from_their_release_artifacts() {
    let elf = std::fs::read(vos_testkit::programs::credentials_elf()).unwrap();
    let devices = vos_light::release::devices(&elf).unwrap();
    let methods: Vec<MethodId> = devices.iter().map(|device| device.method).collect();
    let mut expected = vec![
        MethodId(derive_id("vos/method/", "auth")),
        MethodId(derive_id("vos/method/", "owner")),
    ];
    expected.sort();
    assert_eq!(methods, expected);
    for device in &devices {
        assert_eq!(device.elf, vos_pvm_compiler::derive(&elf).unwrap().elf);
        let program = DeviceProgram::released(device).unwrap();
        assert_eq!(program.id(), &device.id);
        assert_eq!(program.log_sizes(), &device.log_sizes[..]);
        let mut raised = device.clone();
        raised.log_sizes[0] += 1;
        assert!(DeviceProgram::released(&raised).is_err(), "another shape");
        let mut renamed = device.clone();
        renamed.id[0] ^= 1;
        assert!(DeviceProgram::released(&renamed).is_err(), "another id");
    }
}
