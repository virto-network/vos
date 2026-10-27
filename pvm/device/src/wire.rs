//! The node-API requests a client sends for its credentials, and the
//! answers it decodes (`identity-and-authority.md` §5–§6, `node-api.md`):
//! each request is its kind's two little-endian bytes, then its SCALE
//! body; the transport adds the frame's length and any request id. So
//! neither a client nor a gateway encodes a credential's bytes.
//!
//! A query of `path` or `root()` is a `QueryCall` signed by an ed25519 key
//! drawn for that query alone, so a fetch links to no client key; it reads
//! the replica's applied state.

use ed25519_dalek::{Signer, SigningKey};
use scale::{Decode, Encode};
use vos_api::Kind;
use vos_wire::credentials::{Path, RootEntry};
use vos_wire::ids::{AgentId, InstanceId, MethodId, derive_id};
use vos_wire::ingress::{
    self, Consistency, CredentialRefusal, Credentialed, QueryCall, Rejection, Response,
    query_message,
};
use vos_wire::result::Outcome;
use zeroize::Zeroize;

use crate::{AuthWitness, Call, CredentialProof, CredentialPublic, DeviceError, Digest};

/// `kind`'s request holding `body`.
fn request(kind: u16, body: impl Encode) -> Vec<u8> {
    let mut bytes = kind.to_le_bytes().to_vec();
    body.encode_to(&mut bytes);
    bytes
}

/// The node's time: a `Time` request, no body.
pub fn time_request() -> Vec<u8> {
    (Kind::Time as u16).to_le_bytes().to_vec()
}

/// The node's time in milliseconds, from a `Time` answer.
pub fn time_answer(body: &[u8]) -> Result<u64, DeviceError> {
    u64::decode_exact(body).ok_or(DeviceError::Decode)
}

/// A query of `method` with `arguments` at `instance` of `agent`, whose
/// identity is `identity`, good until `not_after` by the node's clock,
/// signed by a key drawn for it alone; [`DeviceError::Prove`] if the
/// operating system has no randomness to give.
fn query(
    agent: u32,
    identity: &[u8; 32],
    instance: u32,
    method: &str,
    arguments: Vec<u8>,
    not_after: u64,
) -> Result<Vec<u8>, DeviceError> {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|_| DeviceError::Prove)?;
    let key = SigningKey::from_bytes(&seed);
    seed.zeroize();
    let mut query = QueryCall {
        key: key.verifying_key().to_bytes(),
        not_after,
        consistency: Consistency::Applied { at: 0 },
        instance: InstanceId(instance),
        method: MethodId(derive_id("vos/method/", method)),
        arguments,
        signature: [0; 64],
    };
    query.signature = key
        .sign(&query_message(
            identity,
            &query.key,
            query.not_after,
            query.consistency,
            query.instance,
            query.method,
            &query.arguments,
        ))
        .to_bytes();
    Ok(request(Kind::Query as u16, (AgentId(agent), query)))
}

/// A query of the credential actor's `path(member)` at `instance` of
/// `agent`, signed by a fresh key over the agent's `identity`.
pub fn path_query(
    agent: u32,
    identity: &[u8; 32],
    instance: u32,
    member: &Digest,
    not_after: u64,
) -> Result<Vec<u8>, DeviceError> {
    query(
        agent,
        identity,
        instance,
        "path",
        member.to_bytes().encode(),
        not_after,
    )
}

/// A query of the credential actor's `root()`, as [`path_query`].
pub fn root_query(
    agent: u32,
    identity: &[u8; 32],
    instance: u32,
    not_after: u64,
) -> Result<Vec<u8>, DeviceError> {
    query(agent, identity, instance, "root", Vec::new(), not_after)
}

/// A query's reply bytes, from its answer: `Ran` with the handler's
/// reply, or [`DeviceError::Decode`].
fn reply(body: &[u8]) -> Result<Vec<u8>, DeviceError> {
    match Response::decode_exact(body) {
        Some(Response::Ran {
            outcome: Outcome::Done(reply),
            ..
        }) => Ok(reply),
        _ => Err(DeviceError::Decode),
    }
}

/// The path from a `path` query's answer; `None` for a member not
/// enrolled.
pub fn path_answer(body: &[u8]) -> Result<Option<AuthWitness>, DeviceError> {
    let Some(path) = Option::<Path>::decode_exact(&reply(body)?).ok_or(DeviceError::Decode)? else {
        return Ok(None);
    };
    let digest = |bytes: &[u8; 32]| Digest::from_bytes(bytes).ok_or(DeviceError::Decode);
    let mut siblings = [Digest([0; 8]); vos_wire::credentials::DEPTH];
    for (sibling, bytes) in siblings.iter_mut().zip(&path.siblings.0) {
        *sibling = digest(bytes)?;
    }
    Ok(Some(AuthWitness {
        root: digest(&path.root)?,
        slot: path.slot,
        siblings,
    }))
}

/// The root and the batch time it became the root, from a `root()` query's
/// answer.
pub fn root_answer(body: &[u8]) -> Result<(Digest, u64), DeviceError> {
    let entry = RootEntry::decode_exact(&reply(body)?).ok_or(DeviceError::Decode)?;
    Ok((
        Digest::from_bytes(&entry.root).ok_or(DeviceError::Decode)?,
        entry.since,
    ))
}

impl From<&CredentialPublic> for ingress::CredentialPublic {
    fn from(public: &CredentialPublic) -> Self {
        match *public {
            CredentialPublic::Auth {
                map_root,
                scope,
                nullifier,
                binding,
            } => ingress::CredentialPublic::Auth {
                map_root: map_root.to_bytes(),
                scope: scope.to_bytes(),
                nullifier: nullifier.to_bytes(),
                binding: binding.to_bytes(),
            },
            CredentialPublic::Owner { owner, binding } => ingress::CredentialPublic::Owner {
                owner: owner.to_bytes(),
                binding: binding.to_bytes(),
            },
        }
    }
}

/// The credentialed request of `call` under `proof`, addressed to
/// `call.agent` (`identity-and-authority.md` §5).
pub fn credentialed(call: &Call, proof: &CredentialProof) -> Vec<u8> {
    let body = Credentialed {
        instance: InstanceId(call.instance),
        method: MethodId(call.method),
        arguments: call.arguments.clone(),
        nonce: call.nonce,
        expires_ms: call.expires_ms,
        format: proof.format,
        public: ingress::CredentialPublic::from(&proof.public),
        proof: proof.proof.clone(),
    };
    request(Kind::Credentialed as u16, (AgentId(call.agent), body))
}

/// What a credentialed call's answer means to the client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Answer {
    /// The call ran: its outcome, at the applied index of the state it
    /// reflects.
    Ran { outcome: Outcome, at: u64 },
    /// The replica's ring does not hold the proof's root: drop the path
    /// ([`crate::PathKeeper::unknown`]), fetch it again, prove anew.
    RootUnknown,
    /// The proof's root was superseded more than `ROOT_MAX_AGE` ago: drop
    /// the path as for [`Answer::RootUnknown`]; a new path proves anew.
    RootStale,
    /// The expiry is outside the node's window: `now` is the node's clock,
    /// from which a new proof picks its expiry.
    Expiry { now: u64 },
    /// Any other credential refusal at ingress: this proof will not be
    /// admitted.
    Refused(CredentialRefusal),
    /// Any other answer, as the node sent it: busy, not the leader, a
    /// refusal at apply.
    Other(Vec<u8>),
}

/// The answer to a credentialed request, decoded exactly; an answer that
/// does not decode is [`DeviceError::Decode`].
pub fn credentialed_answer(body: &[u8]) -> Result<Answer, DeviceError> {
    Ok(
        match Response::decode_exact(body).ok_or(DeviceError::Decode)? {
            Response::Ran { outcome, at } => Answer::Ran { outcome, at },
            Response::Rejected(Rejection::Credential(refusal)) => match refusal {
                CredentialRefusal::RootUnknown => Answer::RootUnknown,
                CredentialRefusal::RootStale => Answer::RootStale,
                CredentialRefusal::Expiry { now } => Answer::Expiry { now },
                refusal => Answer::Refused(refusal),
            },
            _ => Answer::Other(body.to_vec()),
        },
    )
}
