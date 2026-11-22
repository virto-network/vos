//! The node-API requests a client sends for its credentials, and the
//! answers it decodes (`identity-and-authority.md` §5–§6, `node-api.md`):
//! each request is its kind's two little-endian bytes, then its SCALE
//! body; the transport adds the frame's length, its mark and any request
//! id. So neither a client nor a gateway encodes a credential's bytes.
//!
//! A query of `feed` is a `QueryCall` signed by an ed25519 key drawn for
//! that query alone, so a read links to no client key; it reads the
//! replica's applied state.

use ed25519_dalek::{Signer, SigningKey};
use scale::{Decode, Encode};
use vos_abi::abi::Failure;
use vos_abi::ids::Session;
use vos_abi::ids::{AgentId, InstanceId, MethodId};
use vos_abi::result::Outcome;
use vos_api::Kind;
use vos_wire::credentials::{Feed, method};
use vos_wire::ingress::{
    self, AgentInfo, Consistency, CredentialRefusal, Credentialed, QueryCall, Rejection, Response,
    query_message,
};
use zeroize::Zeroize;

use crate::{Call, DeviceError, Proven};

/// `kind`'s request holding `body`.
pub(crate) fn request(kind: u16, body: impl Encode) -> Vec<u8> {
    let mut bytes = kind.to_le_bytes().to_vec();
    body.encode_to(&mut bytes);
    bytes
}

/// The device window of `instance` of `agent`: a `Devices` request.
pub fn devices_request(agent: u32, instance: u32) -> Vec<u8> {
    request(Kind::Devices as u16, (AgentId(agent), InstanceId(instance)))
}

/// The device window from a `Devices` answer: `None` for an instance the
/// node does not hold.
pub fn devices_answer(body: &[u8]) -> Result<Option<ingress::DeviceWindow>, DeviceError> {
    Option::<ingress::DeviceWindow>::decode_exact(body).ok_or(DeviceError::Decode)
}

/// The node's time: a `Time` request, no body.
pub fn time_request() -> Vec<u8> {
    (Kind::Time as u16).to_le_bytes().to_vec()
}

/// The node's time in milliseconds, from a `Time` answer.
pub fn time_answer(body: &[u8]) -> Result<u64, DeviceError> {
    u64::decode_exact(body).ok_or(DeviceError::Decode)
}

/// `agent`'s record: an `AgentInfo` request, which a device asks of a
/// pooled agent before it seals its kit to that agent's identity.
pub fn agent_request(agent: u32) -> Vec<u8> {
    request(Kind::AgentInfo as u16, AgentId(agent))
}

/// The agent's identity from an `AgentInfo` answer, the hash of its
/// creation record, as every node computes it; `None` for an agent the
/// node does not know. It is the answering node's word: a device that
/// seals to it (a claim's kit) asks a second node too.
pub fn agent_answer(body: &[u8]) -> Result<Option<[u8; 32]>, DeviceError> {
    let info = Option::<AgentInfo>::decode_exact(body).ok_or(DeviceError::Decode)?;
    Ok(info.map(|info| vos_pvm::precompile::blake2b_256(&info.record.encode())))
}

/// A call of `method` with `arguments` at `instance` of `agent`, whose
/// identity is `identity`: the first of a session of its own, at the
/// node's time `now`, signed by a key drawn for it alone, so it links to
/// no other call (an open claim's). [`DeviceError::Prove`] if the
/// operating system has no randomness to give.
pub fn call_request(
    agent: u32,
    identity: &[u8; 32],
    instance: u32,
    method: MethodId,
    arguments: Vec<u8>,
    now: u64,
) -> Result<Vec<u8>, DeviceError> {
    let mut seed = [0u8; 32];
    let mut name = [0u8; 16];
    getrandom::getrandom(&mut seed).map_err(|_| DeviceError::Prove)?;
    getrandom::getrandom(&mut name).map_err(|_| DeviceError::Prove)?;
    let key = SigningKey::from_bytes(&seed);
    seed.zeroize();
    let session = Session {
        key: key.verifying_key().to_bytes(),
        name,
        t0: now,
    };
    let instance = InstanceId(instance);
    let message = ingress::call_message(identity, &session, 1, instance, method, &arguments);
    let call = ingress::Call {
        session,
        sequence: 1,
        instance,
        method,
        arguments,
        signature: key.sign(&message).to_bytes(),
    };
    Ok(request(Kind::Call as u16, (AgentId(agent), call)))
}

/// A call's or a query's outcome, from its answer: `Ran`'s; ingress's
/// refusal, [`DeviceError::Rejected`] with it; any other,
/// [`DeviceError::Decode`].
pub fn outcome(body: &[u8]) -> Result<Outcome, DeviceError> {
    match Response::decode_exact(body) {
        Some(Response::Ran { outcome, .. }) => Ok(outcome),
        Some(Response::Rejected(rejection)) => Err(DeviceError::Rejected(rejection)),
        _ => Err(DeviceError::Decode),
    }
}

/// A handler's answer in `outcome`, a call's or a query's: its reply, or
/// the actor's error `E` (`PersonalError`, `HomesError`,
/// `CredentialError`); any other outcome, or one that does not decode,
/// [`DeviceError::Decode`]. The one reading of a stock actor's answer
/// every flow and test shares.
pub fn answer<T: Decode, E: Decode>(outcome: &Outcome) -> Result<Result<T, E>, DeviceError> {
    match outcome {
        Outcome::Done(bytes) => T::decode_exact(bytes).map(Ok).ok_or(DeviceError::Decode),
        Outcome::Failed {
            code: Failure::Handler,
            detail,
        } => E::decode_exact(detail).map(Err).ok_or(DeviceError::Decode),
        _ => Err(DeviceError::Decode),
    }
}

/// Whether a proven call's `answer` refuses its proof's format, or the
/// kernel release it was proved under, at apply: the space no longer
/// admits this app's proofs, and the app is to be updated.
pub fn format_refused(answer: &[u8]) -> bool {
    use vos_abi::abi::Refusal;
    use vos_wire::ingress::CredentialRefusal;
    match credentialed_answer(answer) {
        Ok(Answer::Refused(CredentialRefusal::Format)) => true,
        Ok(Answer::Other(body)) => matches!(
            Response::decode_exact(&body),
            Some(Response::Refused(Refusal::Format | Refusal::Release))
        ),
        _ => false,
    }
}

/// A query's reply, decoded as `T`, from its answer.
pub fn query_answer<T: Decode>(body: &[u8]) -> Result<T, DeviceError> {
    T::decode_exact(&reply(body)?).ok_or(DeviceError::Decode)
}

/// A query of `method` with `arguments` at `instance` of `agent`, whose
/// identity is `identity`, good until `not_after` by the node's clock,
/// signed by a key drawn for it alone: the open claim's terms
/// (`opening`), `Homes`' lowest pooled agent (`pooled`) and its terms
/// (`configured`) among them. [`DeviceError::Prove`] if the operating
/// system has no randomness to give.
pub fn query_request(
    agent: u32,
    identity: &[u8; 32],
    instance: u32,
    method: MethodId,
    arguments: Vec<u8>,
    not_after: u64,
) -> Result<Vec<u8>, DeviceError> {
    let query = (instance, method, arguments);
    query_request_at(
        agent,
        identity,
        query,
        not_after,
        Consistency::Applied { at: 0 },
    )
}

/// The same, answered at `consistency`: [`Consistency::Linearizable`]
/// for a read whose "no" must not be a replica's that is behind.
pub fn query_request_at(
    agent: u32,
    identity: &[u8; 32],
    (instance, method, arguments): (u32, MethodId, Vec<u8>),
    not_after: u64,
    consistency: Consistency,
) -> Result<Vec<u8>, DeviceError> {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|_| DeviceError::Prove)?;
    let key = SigningKey::from_bytes(&seed);
    seed.zeroize();
    let mut query = QueryCall {
        key: key.verifying_key().to_bytes(),
        not_after,
        consistency,
        instance: InstanceId(instance),
        method,
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

/// A query of the credential actor's `feed(from)`, the tree's changes from
/// the `from`th on, at `instance` of `agent`, signed by a fresh key over
/// the agent's `identity`: it names no member.
pub fn feed_query(
    agent: u32,
    identity: &[u8; 32],
    instance: u32,
    from: u64,
    not_after: u64,
) -> Result<Vec<u8>, DeviceError> {
    query_request(
        agent,
        identity,
        instance,
        method::FEED,
        from.encode(),
        not_after,
    )
}

/// A query of the credential actor's `feed_after(root)`, the tree's
/// changes after the last that left `root`, at `instance` of `agent`,
/// signed by a fresh key over the agent's `identity`: it names the root,
/// which every member that read the feed as far holds, and no place.
pub fn feed_after_query(
    agent: u32,
    identity: &[u8; 32],
    instance: u32,
    root: &[u8; 32],
    not_after: u64,
) -> Result<Vec<u8>, DeviceError> {
    query_request(
        agent,
        identity,
        instance,
        method::FEED_AFTER,
        root.encode(),
        not_after,
    )
}

/// The page from a `feed` query's answer.
pub fn feed_answer(body: &[u8]) -> Result<Feed, DeviceError> {
    query_answer(body)
}

/// The page from a `feed_after` query's answer: none for a root the actor
/// knows of no change leaving.
pub fn feed_after_answer(body: &[u8]) -> Result<Option<Feed>, DeviceError> {
    query_answer(body)
}

/// A query's reply bytes, from its answer: `Ran` with the handler's
/// reply; ingress's refusal, [`DeviceError::Rejected`] with it; any other,
/// [`DeviceError::Decode`].
fn reply(body: &[u8]) -> Result<Vec<u8>, DeviceError> {
    match Response::decode_exact(body) {
        Some(Response::Ran {
            outcome: Outcome::Done(reply),
            ..
        }) => Ok(reply),
        Some(Response::Rejected(rejection)) => Err(DeviceError::Rejected(rejection)),
        _ => Err(DeviceError::Decode),
    }
}

/// The credentialed request of `call` under `proof`, addressed to
/// `call.agent` (`identity-and-authority.md` §5).
pub fn credentialed(call: &Call, proof: &Proven) -> Vec<u8> {
    let body = Credentialed {
        instance: InstanceId(call.instance),
        method: MethodId(call.method),
        arguments: call.arguments.clone(),
        nonce: call.nonce,
        expires_ms: call.expires_ms,
        format: proof.format,
        claim: proof.claim.clone(),
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
    /// The replica's ring does not hold the proof's root: read the feed
    /// again ([`crate::TreeKeeper::unknown`]), prove anew at its root.
    RootUnknown,
    /// The proof's root was superseded more than `ROOT_GRACE_MS` ago: read
    /// the feed again as for [`Answer::RootUnknown`] and prove anew.
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
