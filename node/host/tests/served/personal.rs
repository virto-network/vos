//! A personal space end to end on three nodes (`light-node.md` §3.3, §3.8),
//! every request as the device library makes it and through a node's socket
//! with the onion's mark, at a test home whose delays and lease are seconds and
//! whose open claim's difficulty is low: a phone joins the home-only space by
//! its open claim and claims a personal agent there with a phrase kit, sealed
//! to the pooled agent `Homes` names; a second phone is paired through a slot
//! over Noise, its "home" nullifier recorded at `Homes` as its add is
//! confirmed; the first enrolls it in another space by its owner proof and it
//! confirms by its own; the first is retired, removed by the second and revoked
//! in that space; and a second claim is refused at the device and at `Homes`.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use ed25519_dalek::{Signer as _, SigningKey};
use vos_abi::ids::{AgentId, InstanceId, MethodId, Session};
use vos_abi::result::Outcome;
use vos_abi::{Decode, Encode};
use vos_api::{Framing, Kind, Mark, marked};
use vos_checker::programs::program_elf;
use vos_light::group::{DeviceGroup, Event};
use vos_light::home::{self, Claim, ClaimError, Home as HomeSpace};
use vos_light::kit::KitSecret;
use vos_light::memberships;
use vos_light::pairing::{Code, Hello, Joined, Joiner, Membership, Offer, Opened, Opener, Put};
use vos_light::wire::{self, Answer};
use vos_light::{Call, Config, DeviceProgram, Light, Prover, ProverConfig, Threads};
use vos_node::client::Client;
use vos_wire::books::DeviceHandle;
use vos_wire::credentials::{CredentialError, Open, Path};
use vos_wire::homes::HomesError;
use vos_wire::ingress::{Call as Signed, Response};
use vos_wire::personal::{
    AdminClass, Attached, Attestation, Body, Candidacy, Entry, InboxItem, NewDevice, Overview,
    PersonalError, Place, Policy, Recorded, Vote,
};

use crate::harness::{NODES, OPERATOR_SEED, answer, assert_done, witness};
use crate::homes::{CREDENTIALS, Founded, HANDLE, HOMES, PERSONAL};

/// The other space's credential actor, and its handle.
const CLUB: InstanceId = InstanceId(9);
const CLUB_HANDLE: [u8; 32] = [0xc1; 32];

/// A test home's policy: seconds, not days.
pub(crate) fn policy() -> Policy {
    Policy {
        operation_delay_ms: 3_000,
        kit_delay_ms: 6_000,
        probation_ms: 2_000,
        seasoning_ms: 3_000,
        confirm_window_ms: 120_000,
        lease_ms: 600_000,
        slot_ttl_ms: 120_000,
        ..Policy::DEFAULT
    }
}

/// The nodes' sockets, asked in turn: a request goes to the next node
/// while one cannot take it.
pub(crate) struct Sockets {
    pub(crate) paths: Vec<std::path::PathBuf>,
    pub(crate) at: usize,
}

impl Sockets {
    /// `request`, as the device library makes it (its kind's two bytes,
    /// then its body), marked as the gateway marks what its onion took.
    pub(crate) fn ask(&mut self, request: &[u8]) -> Vec<u8> {
        let kind = u16::from_le_bytes([request[0], request[1]]);
        for _ in 0..60 {
            let mut stream = UnixStream::connect(&self.paths[self.at]).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(30)))
                .unwrap();
            stream
                .write_all(&marked(
                    Framing::Stream,
                    kind,
                    Mark::Onion,
                    1,
                    &request[2..],
                ))
                .unwrap();
            let mut header = [0u8; Framing::Stream.header()];
            stream.read_exact(&mut header).unwrap();
            let length = u32::from_le_bytes(header[..4].try_into().unwrap()) as usize;
            let mut body = vec![0u8; length - (Framing::Stream.header() - 4)];
            stream.read_exact(&mut body).unwrap();
            match Response::decode_exact(&body) {
                Some(
                    Response::NotLeader { .. }
                    | Response::Busy
                    | Response::Unavailable
                    | Response::Elsewhere { .. }
                    | Response::TimedOut,
                ) => {
                    self.at = (self.at + 1) % self.paths.len();
                    std::thread::sleep(Duration::from_millis(50));
                }
                _ => return body,
            }
        }
        panic!("no node took the request")
    }

    pub(crate) fn time(&mut self) -> u64 {
        wire::time_answer(&self.ask(&wire::time_request())).unwrap()
    }

    /// The identity of `agent`, from its record.
    pub(crate) fn identity(&mut self, agent: u32) -> [u8; 32] {
        wire::agent_answer(&self.ask(&wire::agent_request(agent)))
            .unwrap()
            .expect("the agent's record")
    }

    pub(crate) fn query<T: Decode>(
        &mut self,
        agent: u32,
        identity: &[u8; 32],
        instance: InstanceId,
        name: &str,
        arguments: impl Encode,
    ) -> T {
        let not_after = self.time() + 60_000;
        let request = wire::query_request(
            agent,
            identity,
            instance.0,
            vos_abi::ids::MethodId(vos_light::method_id(name)),
            arguments.encode(),
            not_after,
        )
        .unwrap();
        wire::query_answer(&self.ask(&request)).unwrap()
    }

    /// `call` proved by `prove` and sent: its outcome.
    pub(crate) fn credentialed(&mut self, call: &Call, proof: &vos_light::Proven) -> Outcome {
        match wire::credentialed_answer(&self.ask(&wire::credentialed(call, proof))).unwrap() {
            Answer::Ran { outcome, .. } => outcome,
            other => panic!("{other:?}"),
        }
    }
}

/// A client key's session at the personal agent.
pub(crate) struct Signer {
    pub(crate) key: SigningKey,
    pub(crate) session: Option<Session>,
    pub(crate) next: u64,
}

impl Signer {
    pub(crate) fn new(key: SigningKey) -> Self {
        Self {
            key,
            session: None,
            next: 1,
        }
    }

    pub(crate) fn public(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }
}

/// A personal agent as a device reaches it.
#[derive(Clone, Copy)]
pub(crate) struct Personal {
    pub(crate) agent: u32,
    pub(crate) identity: [u8; 32],
}

impl Personal {
    /// `signer`'s call of `name`: its answer, and the message and
    /// signature an admin call's evidence carries. Refused with
    /// `Settling`, the call goes again after a `wake`.
    pub(crate) fn call<T: Decode>(
        &self,
        sockets: &mut Sockets,
        signer: &mut Signer,
        name: &str,
        arguments: Vec<u8>,
    ) -> (Result<T, PersonalError>, Vec<u8>, [u8; 64]) {
        loop {
            let (outcome, message, signature) = self.send(sockets, signer, name, arguments.clone());
            let result = answer::<T, PersonalError>(&outcome);
            if result.as_ref().err() == Some(&PersonalError::Settling) {
                self.send(sockets, signer, "wake", Vec::new());
                continue;
            }
            return (result, message, signature);
        }
    }

    /// `signer`'s call of `name`, signed in its session at its next
    /// sequence, and the message signed.
    pub(crate) fn sign(
        &self,
        sockets: &mut Sockets,
        signer: &mut Signer,
        name: &str,
        arguments: Vec<u8>,
    ) -> (Signed, Vec<u8>) {
        if signer.session.is_none() {
            let t0 = sockets.time();
            let mut name = [0; 16];
            name[..8].copy_from_slice(&t0.to_le_bytes());
            signer.session = Some(Session {
                key: signer.public(),
                name,
                t0,
            });
            signer.next = 1;
        }
        let mut call = Signed {
            session: signer.session.unwrap(),
            sequence: signer.next,
            instance: PERSONAL,
            method: MethodId(vos_light::method_id(name)),
            arguments,
            signature: [0; 64],
        };
        let message = call.message(&self.identity);
        call.signature = signer.key.sign(&message).to_bytes();
        (call, message)
    }

    /// `call` sent: its outcome.
    pub(crate) fn submit(
        &self,
        sockets: &mut Sockets,
        signer: &mut Signer,
        call: &Signed,
    ) -> Outcome {
        let mut request = (Kind::Call as u16).to_le_bytes().to_vec();
        (AgentId(self.agent), call.clone()).encode_to(&mut request);
        match Response::decode_exact(&sockets.ask(&request)) {
            Some(Response::Ran { outcome, .. }) => {
                signer.next += 1;
                outcome
            }
            other => panic!("{other:?}"),
        }
    }

    pub(crate) fn send(
        &self,
        sockets: &mut Sockets,
        signer: &mut Signer,
        name: &str,
        arguments: Vec<u8>,
    ) -> (Outcome, Vec<u8>, [u8; 64]) {
        let (call, message) = self.sign(sockets, signer, name, arguments);
        (self.submit(sockets, signer, &call), message, call.signature)
    }

    pub(crate) fn query<T: Decode>(
        &self,
        sockets: &mut Sockets,
        key: &SigningKey,
        name: &str,
        arguments: impl Encode,
    ) -> Result<T, PersonalError> {
        let not_after = sockets.time() + 60_000;
        let query = vos_node::client::signed_query(
            &self.identity,
            key,
            not_after,
            vos_wire::ingress::Consistency::Applied { at: 0 },
            PERSONAL,
            MethodId(vos_light::method_id(name)),
            arguments.encode(),
        );
        let mut request = (Kind::Query as u16).to_le_bytes().to_vec();
        (AgentId(self.agent), query).encode_to(&mut request);
        match Response::decode_exact(&sockets.ask(&request)) {
            Some(Response::Ran { outcome, .. }) => answer(&outcome),
            other => panic!("{name}: {other:?}"),
        }
    }

    pub(crate) fn log(
        &self,
        sockets: &mut Sockets,
        key: &SigningKey,
        from: u64,
    ) -> Vec<(u64, Entry)> {
        let mut entries = Vec::new();
        let mut next = from;
        loop {
            let page: Vec<(u64, Entry)> = self.query(sockets, key, "log", next).unwrap();
            let Some((last, _)) = page.last() else {
                return entries;
            };
            next = last + 1;
            entries.extend(page);
        }
    }
}

/// A phone: its light node, its device group, its keys, and its secret
/// source's output for each space.
pub(crate) struct Phone {
    pub(crate) n: u8,
    pub(crate) light: Light,
    pub(crate) group: Option<DeviceGroup>,
    pub(crate) sync: Signer,
    pub(crate) admin: Signer,
    pub(crate) keys: NewDevice,
    pub(crate) _dir: tempfile::TempDir,
}

impl Phone {
    pub(crate) fn new(n: u8, home: &HomeSpace) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let agent = vos_light::release::agent(
            &std::fs::read(vos_testkit::programs::program_elf("vos-agent")).unwrap(),
        )
        .unwrap();
        let light = Light::open(dir.path(), &agent, Config::default()).unwrap();
        let admin = SigningKey::from_bytes(&[n | 0x80; 32]);
        let mut phone = Self {
            n,
            sync: Signer::new(light.sync_key().clone()),
            keys: NewDevice {
                sync: light.sync_key().verifying_key().to_bytes(),
                admin: admin.verifying_key().to_bytes(),
                class: AdminClass::Strong,
                attestation: Attestation {
                    hardware: true,
                    verified_boot: true,
                },
                nullifier: [0; 32],
                label: vec![n; 8],
            },
            admin: Signer::new(admin),
            light,
            group: None,
            _dir: dir,
        };
        phone.keys.nullifier = home.nullifier(&phone.secret(&home.handle));
        phone
    }

    /// Its secret in the space whose handle is `handle`.
    pub(crate) fn secret(&self, handle: &[u8; 32]) -> vos_light::DeviceSecret {
        vos_light::derive_secret(&[self.n; 32], handle)
    }

    pub(crate) fn handle(&self, handle: &[u8; 32]) -> DeviceHandle {
        let secret = self.secret(handle);
        DeviceHandle {
            handle: *handle,
            member: vos_light::member(&secret).to_bytes(),
            owner: vos_light::owner(&secret).to_bytes(),
        }
    }

    pub(crate) fn group(&mut self) -> &mut DeviceGroup {
        self.group.as_mut().expect("a device group")
    }

    /// Read the log and act on it, posting each vote, evidence and
    /// `alive` it asks for: every other event.
    pub(crate) fn read(&mut self, sockets: &mut Sockets, personal: Personal) -> Vec<Event> {
        let mut seen = Vec::new();
        for _ in 0..8 {
            let cursor = self.group().cursor();
            let entries = personal.log(sockets, &self.sync.key, cursor);
            let events = self.group().follow(entries).unwrap();
            let mut posted = false;
            for event in events {
                match event {
                    Event::Vote {
                        epoch,
                        vote,
                        message,
                    } => {
                        let signature = self.sync.key.sign(&message).to_bytes();
                        let arguments = match vote {
                            Vote::Confirm(h) => (epoch, h, signature).encode(),
                            Vote::Nack => (epoch, signature).encode(),
                        };
                        let name = if matches!(vote, Vote::Confirm(_)) {
                            "confirm"
                        } else {
                            "nack"
                        };
                        personal
                            .call::<vos_wire::personal::Voted>(
                                sockets,
                                &mut self.sync,
                                name,
                                arguments,
                            )
                            .0
                            .unwrap();
                        posted = true;
                    }
                    Event::Evidence {
                        index,
                        message,
                        signature,
                        attached,
                    } => {
                        self.evidence(sockets, personal, index, message, signature, attached);
                        posted = true;
                    }
                    Event::Alive => {
                        personal
                            .call::<Recorded>(sockets, &mut self.sync, "alive", Vec::new())
                            .0
                            .unwrap();
                        posted = true;
                    }
                    other => seen.push(other),
                }
            }
            if !posted {
                return seen;
            }
        }
        panic!("the phone keeps posting")
    }

    pub(crate) fn evidence(
        &mut self,
        sockets: &mut Sockets,
        personal: Personal,
        index: u64,
        message: Vec<u8>,
        signature: [u8; 64],
        attached: Attached,
    ) {
        let arguments = ((index, message), (signature, attached)).encode();
        personal
            .call::<Recorded>(sockets, &mut self.sync, "evidence", arguments)
            .0
            .unwrap();
    }

    /// Make `prepared`'s commit call under the admin key, its message
    /// signed and written before the call, and post its evidence.
    pub(crate) fn commit(
        &mut self,
        sockets: &mut Sockets,
        personal: Personal,
        prepared: &vos_light::group::Prepared,
    ) {
        let candidacy = loop {
            let (call, message) =
                personal.sign(sockets, &mut self.admin, "commit", prepared.arguments());
            self.group().signed_commit(message, call.signature).unwrap();
            let outcome = personal.submit(sockets, &mut self.admin, &call);
            match answer::<Candidacy, PersonalError>(&outcome) {
                Err(PersonalError::Settling) => {
                    personal.send(sockets, &mut self.sync, "wake", Vec::new());
                }
                answered => break answered.unwrap(),
            }
        };
        let Event::Evidence {
            index,
            message,
            signature,
            attached,
        } = self.group().called_commit(candidacy.index).unwrap()
        else {
            unreachable!()
        };
        self.evidence(sockets, personal, index, message, signature, attached);
    }

    /// Its path in the credential actor of `agent` at `instance`.
    pub(crate) fn path(
        &self,
        sockets: &mut Sockets,
        agent: u32,
        identity: &[u8; 32],
        instance: InstanceId,
        handle: &[u8; 32],
    ) -> Option<Path> {
        sockets.query(
            agent,
            identity,
            instance,
            "path",
            self.handle(handle).member,
        )
    }
}

/// The home's terms for an open claim, as a device reads them, and the
/// device's open claim made by its work: its slot.
pub(crate) fn open_claim(sockets: &mut Sockets, home: &HomeSpace, phone: &Phone) -> u32 {
    let terms: Option<Open> =
        sockets.query(home.agent, &home.identity, home.credentials, "opening", ());
    let terms = terms.expect("the home is open");
    let member = phone.handle(&home.handle).member;
    let nonce = home::work(&home.handle, &member, &terms.salt, terms.difficulty, 2);
    let now = sockets.time();
    let request = home::open_claim(home, &member, nonce, now).unwrap();
    let outcome = wire::outcome(&sockets.ask(&request)).unwrap();
    answer::<u32, CredentialError>(&outcome).unwrap()
}

/// The pairing slot's items as `key` reads them.
pub(crate) fn inbox(sockets: &mut Sockets, personal: Personal, key: &SigningKey) -> Vec<InboxItem> {
    personal
        .query(sockets, key, "inbox", Option::<(u64, [u8; 16])>::None)
        .unwrap()
}

pub(crate) fn leave(sockets: &mut Sockets, personal: Personal, signer: &mut Signer, put: &Put) {
    personal
        .call::<u64>(sockets, signer, "put", put.arguments())
        .0
        .unwrap();
}

/// Wait until `done`, a second at most between tries, for a minute.
pub(crate) fn wait(what: &str, mut done: impl FnMut() -> bool) {
    vos_checker::wait_until(what, Duration::from_secs(60), || {
        let ok = done();
        if !ok {
            std::thread::sleep(Duration::from_millis(200));
        }
        ok
    });
}

#[test]
fn a_personal_space_is_claimed_paired_and_its_first_phone_retired() {
    let home = Founded::with(policy());
    let keeper = home.keeper();
    let personal_elf = std::fs::read(program_elf("vos-personal")).unwrap();
    assert_eq!(keeper.top_up(2, &personal_elf, 16).unwrap(), 2);
    home.write::<(), CredentialError>(CREDENTIALS, "open", (4u8, 16u32, 86_400_000u64))
        .unwrap();
    let mut sockets = Sockets {
        paths: (1..=NODES)
            .map(|n| home.cluster.dir(n).join("api.sock"))
            .collect(),
        at: 0,
    };
    let space = HomeSpace {
        space: home.space.0,
        handle: HANDLE,
        agent: home.agent.0,
        identity: sockets.identity(home.agent.0),
        homes: HOMES,
        credentials: CREDENTIALS,
    };
    let credentials = std::fs::read(program_elf("vos-credentials")).unwrap();
    let owner_kernel = DeviceProgram::from_release(
        &vos_light::release::device(&credentials, "owner").expect("the stock kernel"),
    )
    .unwrap();
    let prover = Prover::new(ProverConfig {
        threads: Threads::Count(4),
        ..ProverConfig::default()
    })
    .unwrap();
    let expires = |sockets: &mut Sockets| sockets.time() + 60_000;

    // The first phone joins the home-only space by its open claim, then
    // claims the pooled agent `Homes` names, its kit a phrase sealed to
    // that agent's identity.
    let mut first = Phone::new(1, &space);
    open_claim(&mut sockets, &space, &first);
    let pooled: Option<u32> = sockets.query(space.agent, &space.identity, HOMES, "pooled", ());
    let agent = pooled.expect("a pooled agent");
    let identity = sockets.identity(agent);
    let phrase = KitSecret::phrase().unwrap();
    let claim = Claim::prepare(
        first.light.store(),
        first.keys.clone(),
        vec![phrase.key()],
        agent,
        identity,
        Vec::new(),
    )
    .unwrap();
    let path = first
        .path(
            &mut sockets,
            space.agent,
            &space.identity,
            CREDENTIALS,
            &HANDLE,
        )
        .unwrap();
    let call = claim.call(&space, expires(&mut sockets)).unwrap();
    let proof = prover
        .prove_home(&first.secret(&HANDLE), &witness(&path), &call, &home.auth)
        .unwrap();
    let outcome = sockets.credentialed(&call, &proof);
    assert_eq!(answer::<u32, HomesError>(&outcome), Ok(agent));
    let personal = Personal { agent, identity };
    let mut entries = Vec::new();
    // The device's keys are admitted once the agent took the claim.
    wait("the claim assigned", || {
        let admitted: Result<Vec<(u64, Entry)>, PersonalError> =
            personal.query(&mut sockets, &first.sync.key, "log", 0u64);
        if admitted.is_err() {
            return false;
        }
        entries = personal.log(&mut sockets, &first.sync.key, 0);
        entries
            .iter()
            .any(|(_, entry)| matches!(entry.body, Body::Assigned { .. }))
    });
    let claim = Claim::pending(first.light.store())
        .unwrap()
        .expect("held until the group starts");
    first.group = Some(
        claim
            .claimed(first.light.store(), PERSONAL, &entries, sockets.time())
            .unwrap(),
    );
    assert!(Claim::pending(first.light.store()).unwrap().is_none());
    first.read(&mut sockets, personal);

    // The second phone is paired through a slot, offered the club.
    let club = Club::found(&home);
    club.write("enroll", first.handle(&CLUB_HANDLE).member);
    let me = first.handle(&CLUB_HANDLE);
    club.write("register", (me.member, me.owner, 4u8));
    // The club's agent is in the nodes' one space beside the home's, its
    // credential actor apart by its handle.
    let membership = Membership {
        space: home.space.0,
        handle: CLUB_HANDLE,
        agent: club.agent.0,
        identity: sockets.identity(club.agent.0),
        credentials: CLUB,
    };
    let offer = Offer {
        home: space.clone(),
        memberships: vec![membership.clone()],
    };
    let mut second = Phone::new(2, &space);
    let item_bytes = first.group().policy().inbox_item_bytes;
    let (mut opener, drawn) = Opener::open(identity, offer.clone(), item_bytes).unwrap();
    let at = personal
        .call::<u64>(
            &mut sockets,
            &mut first.sync,
            "open_slot",
            drawn.slot.arguments(),
        )
        .0
        .unwrap();
    let qr = opener
        .code(
            &drawn,
            at + policy().slot_ttl_ms,
            agent,
            PERSONAL,
            vec![vos_wire::credentials::Onion {
                key: [0x0e; 32],
                ssh_host_key: [0x0f; 32],
            }],
        )
        .to_bytes();
    let code = Code::from_bytes(&qr).unwrap();
    let mut slot = Signer::new(code.slot_key());
    let (mut joiner, put) = Joiner::scan(&code).unwrap();
    leave(&mut sockets, personal, &mut slot, &put);
    let Opened::Check { check, put } = opener
        .read(&inbox(&mut sockets, personal, &first.sync.key))
        .unwrap()
    else {
        panic!("the joiner's handshake message")
    };
    leave(&mut sockets, personal, &mut first.sync, &put);
    let Joined::Check(shown) = joiner
        .read(&inbox(&mut sockets, personal, &slot.key))
        .unwrap()
    else {
        panic!("the check")
    };
    assert_eq!(shown, check);
    let put = opener.offer().unwrap();
    leave(&mut sockets, personal, &mut first.sync, &put);
    let Joined::Offer(offered) = joiner
        .read(&inbox(&mut sockets, personal, &slot.key))
        .unwrap()
    else {
        panic!("the offer")
    };
    let hello = Hello {
        device: second.keys.clone(),
        key_package: DeviceGroup::key_package(second.light.store(), &second.keys, sockets.time())
            .unwrap(),
        handles: offered
            .memberships
            .iter()
            .map(|membership| (membership.space, second.handle(&membership.handle)))
            .collect(),
    };
    let put = joiner.hello(&hello).unwrap();
    leave(&mut sockets, personal, &mut slot, &put);
    let Opened::Hello(heard) = opener
        .read(&inbox(&mut sockets, personal, &first.sync.key))
        .unwrap()
    else {
        panic!("the hello")
    };
    let enrollments = memberships::plan(&offer.memberships, &heard);
    let now = sockets.time();
    let (prepared, pairing) = first
        .group()
        .pair(heard.device.clone(), heard.key_package.clone(), now)
        .unwrap();
    for put in opener.hand_over(&pairing).unwrap() {
        leave(&mut sockets, personal, &mut first.sync, &put);
    }
    let Joined::Handover(pairing, ack) = joiner
        .read(&inbox(&mut sockets, personal, &slot.key))
        .unwrap()
    else {
        panic!("the handover")
    };
    second.group = Some(
        DeviceGroup::join(
            second.light.store(),
            second.keys.clone(),
            *pairing,
            Vec::new(),
        )
        .unwrap(),
    );
    memberships::expect(second.light.store(), &offered.memberships).unwrap();
    leave(&mut sockets, personal, &mut slot, &ack);
    assert!(matches!(
        opener
            .read(&inbox(&mut sockets, personal, &first.sync.key))
            .unwrap(),
        Opened::Received
    ));
    first.commit(&mut sockets, personal, &prepared);
    memberships::hold(first.light.store(), &enrollments).unwrap();
    for _ in 0..3 {
        first.read(&mut sockets, personal);
        second.read(&mut sockets, personal);
    }
    assert_eq!(second.group().id(), Some(1), "its add confirmed");

    // Its nullifier is recorded at `Homes` as its add is confirmed.
    wait("the second phone's nullifier recorded", || {
        home.read::<Option<u32>>(HOMES, "agent", second.keys.nullifier) == Some(agent)
    });

    // The first enrolls it in the club by its owner proof; it confirms by
    // its own.
    assert_eq!(enrollments.len(), 1);
    let call = enrollments[0].call(expires(&mut sockets)).unwrap();
    let proof = prover
        .prove_owner(&first.secret(&CLUB_HANDLE), &call, &owner_kernel)
        .unwrap();
    answer::<u32, CredentialError>(&sockets.credentialed(&call, &proof)).unwrap();
    memberships::done(first.light.store(), &membership).unwrap();
    let club_identity = membership.identity;
    assert!(
        second
            .path(
                &mut sockets,
                club.agent.0,
                &club_identity,
                CLUB,
                &CLUB_HANDLE
            )
            .is_some()
    );
    let owed = memberships::confirmations(second.light.store()).unwrap();
    assert_eq!(owed, vec![membership.clone()]);
    let mine = vos_light::member(&second.secret(&CLUB_HANDLE)).to_bytes();
    let call = memberships::confirm_call(&owed[0], &mine, expires(&mut sockets)).unwrap();
    let proof = prover
        .prove_owner(&second.secret(&CLUB_HANDLE), &call, &owner_kernel)
        .unwrap();
    answer::<(), CredentialError>(&sockets.credentialed(&call, &proof)).unwrap();
    memberships::confirmed(second.light.store(), &membership).unwrap();

    // The first phone retired: once past its probation the second removes
    // it, the removal matures after its delay, and the second's commit
    // carries it; its nullifier is forgotten at `Homes`, and its leaf in
    // the club revoked by the second's owner proof.
    std::thread::sleep(Duration::from_millis(policy().probation_ms + 200));
    personal
        .call::<Recorded>(&mut sockets, &mut second.sync, "alive", Vec::new())
        .0
        .unwrap();
    // Placed at the log's head, as a device-set call names it.
    let overview: Overview = personal
        .query(&mut sockets, &second.sync.key, "overview", ())
        .unwrap();
    let place = Place {
        next: overview.next,
        chain: overview.chain,
    };
    let (removal, message, signature) = personal.call::<Recorded>(
        &mut sockets,
        &mut second.admin,
        "remove",
        place.arguments(&0u32.encode()),
    );
    let index = removal.unwrap().index;
    let attached = Attached {
        welcome: None,
        r2: None,
    };
    second.evidence(&mut sockets, personal, index, message, signature, attached);
    std::thread::sleep(Duration::from_millis(policy().operation_delay_ms + 200));
    personal
        .call::<vos_wire::personal::Woken>(&mut sockets, &mut second.sync, "wake", Vec::new())
        .0
        .unwrap();
    second.read(&mut sockets, personal);
    let prepared = second.group().commit(None, sockets.time()).unwrap();
    assert_eq!(prepared.effect.remove, vec![0]);
    second.commit(&mut sockets, personal, &prepared);
    second.read(&mut sockets, personal);
    let cursor = first.group().cursor();
    let entries = personal.log(&mut sockets, &second.sync.key, cursor);
    let removed = first.group().follow(entries).unwrap();
    assert!(removed.contains(&Event::Removed), "{removed:?}");
    wait("the first phone's nullifier forgotten", || {
        home.read::<Option<u32>>(HOMES, "agent", first.keys.nullifier)
            .is_none()
    });
    let call = memberships::revoke_call(&membership, &me.member, expires(&mut sockets)).unwrap();
    let proof = prover
        .prove_owner(&second.secret(&CLUB_HANDLE), &call, &owner_kernel)
        .unwrap();
    answer::<(), CredentialError>(&sockets.credentialed(&call, &proof)).unwrap();
    assert!(
        first
            .path(
                &mut sockets,
                club.agent.0,
                &club_identity,
                CLUB,
                &CLUB_HANDLE
            )
            .is_none()
    );

    // A second claim: refused at the device, which holds the archive, and
    // at `Homes`, whose nullifier index holds the agent, once the second
    // made the open claim a claim starts with.
    assert!(matches!(
        Claim::prepare(
            second.light.store(),
            second.keys.clone(),
            vec![phrase.key()],
            agent,
            identity,
            Vec::new()
        ),
        Err(ClaimError::Held)
    ));
    let other: Option<u32> = sockets.query(space.agent, &space.identity, HOMES, "pooled", ());
    let kit = vos_light::kit::Split::draw(&[KitSecret::phrase().unwrap().key()], &identity)
        .unwrap()
        .claim();
    let arguments = (second.keys.clone(), kit, other.expect("one left")).encode();
    let call = Call::new(
        space.space,
        space.agent,
        HOMES.0,
        vos_light::method_id("claim"),
        arguments,
        expires(&mut sockets),
    )
    .unwrap();
    open_claim(&mut sockets, &space, &second);
    let path = second
        .path(
            &mut sockets,
            space.agent,
            &space.identity,
            CREDENTIALS,
            &HANDLE,
        )
        .unwrap();
    let proof = prover
        .prove_home(&second.secret(&HANDLE), &witness(&path), &call, &home.auth)
        .unwrap();
    assert_eq!(
        answer::<u32, HomesError>(&sockets.credentialed(&call, &proof)),
        Err(HomesError::Claimed)
    );
}

/// Another space on the same nodes: its own agent holding a credential
/// actor, whose registrar enrolls and registers the first device.
struct Club {
    agent: AgentId,
    caller: std::sync::Mutex<Client>,
}

impl Club {
    fn found(home: &Founded) -> Self {
        let credentials = std::fs::read(program_elf("vos-credentials")).unwrap();
        let (agent, caller) = home.cluster.found_agent(
            &[(CLUB, &credentials[..], "registrar")],
            1,
            SigningKey::from_bytes(&OPERATOR_SEED),
        );
        let club = Self {
            agent,
            caller: std::sync::Mutex::new(caller),
        };
        club.write("found", CLUB_HANDLE);
        club
    }

    #[track_caller]
    fn write(&self, name: &str, arguments: impl Encode) {
        let answer = self
            .caller
            .lock()
            .unwrap()
            .call(
                self.agent,
                CLUB,
                MethodId(vos_light::method_id(name)),
                &arguments.encode(),
            )
            .unwrap();
        assert_done(name, &answer);
    }
}
