//! Today's HTTP routes as node-API requests: each route's kind and frame
//! body, the answers given without a node (a path naming no agent, an
//! unknown path), an operator route's authorization, and an answer
//! frame's HTTP form. The node's own HTTP and the gateway run this one
//! table, so the two answer alike.

use base64::Engine;
use vos_api::{CREDENTIALS, FRAME_ERROR, FrameError, Kind, Operated};
use vos_wire::abi::Refusal;
use vos_wire::ingress::{CredentialRefusal, OperatorRefusal, Rejection, Response as Answer};
use vos_wire::{Decode, Encode};

use crate::server::{Request, Response};

/// The scheme of an `Authorization` header carrying an operator's
/// envelope.
pub const OPERATED_SCHEME: &str = "Operated ";

/// What an operator route's `Authorization` header holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Authorization {
    /// No header.
    None,
    /// A bearer token: the node's own HTTP takes its own.
    Bearer(Vec<u8>),
    /// An operator's envelope's fields, its body the route's.
    Operated(Box<[u8; CREDENTIALS]>),
    /// A header that is neither.
    Unreadable,
}

impl Authorization {
    fn of(request: &Request) -> Self {
        let Some(value) = request.header("authorization") else {
            return Authorization::None;
        };
        if let Some(token) = value.strip_prefix(b"Bearer ") {
            return Authorization::Bearer(token.to_vec());
        }
        let Some(encoded) = value.strip_prefix(OPERATED_SCHEME.as_bytes()) else {
            return Authorization::Unreadable;
        };
        let decoded = base64::engine::general_purpose::STANDARD.decode(encoded.trim_ascii());
        match decoded
            .ok()
            .and_then(|bytes| <[u8; CREDENTIALS]>::try_from(bytes).ok())
        {
            Some(credentials) => Authorization::Operated(Box::new(credentials)),
            None => Authorization::Unreadable,
        }
    }
}

/// The `Authorization` header's value carrying `operated`'s fields but its
/// body.
pub fn operated_header(operated: &Operated) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(operated.credentials());
    format!("{OPERATED_SCHEME}{encoded}")
}

/// A route, as the node API takes it.
#[derive(Debug, PartialEq, Eq)]
pub enum Routed {
    /// Answered here, with no node: an unknown path, or a path whose id
    /// is not a `u32`.
    Answer(Response),
    /// A request of `kind` holding `body`.
    Request { kind: Kind, body: Vec<u8> },
    /// An operator's request: its authorization, then its kind and inner
    /// body, or the answer to a path naming no agent.
    Operator {
        authorization: Authorization,
        kind: Kind,
        inner: Result<Vec<u8>, Response>,
    },
}

/// The agent a path's `id` names.
fn agent(id: &str) -> Option<u32> {
    id.parse::<u32>().ok()
}

/// `agent ‖ body`: a body naming the agent a path's `id` gives, or the
/// answer to a path naming none.
fn agent_and(id: &str, body: &[u8]) -> Result<Vec<u8>, Response> {
    let agent = agent(id).ok_or_else(|| respond(&Answer::NoAgent))?;
    let mut bytes = agent.encode();
    bytes.extend_from_slice(body);
    Ok(bytes)
}

/// `request`'s route.
pub fn route(request: &Request) -> Routed {
    let path = request.path.split('?').next().unwrap_or_default();
    let segments: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    let body = &request.body;
    let operator = |kind: Kind, inner: Result<Vec<u8>, Response>| Routed::Operator {
        authorization: Authorization::of(request),
        kind,
        inner,
    };
    let to = |kind: Kind, body: Result<Vec<u8>, Response>| match body {
        Ok(body) => Routed::Request { kind, body },
        Err(answer) => Routed::Answer(answer),
    };
    match (request.method.as_str(), segments.as_slice()) {
        ("GET", []) => to(Kind::NodeKey, Ok(Vec::new())),
        ("GET", ["time"]) => to(Kind::Time, Ok(Vec::new())),
        ("GET", ["agents", id]) => match agent(id) {
            Some(agent) => to(Kind::AgentInfo, Ok(agent.encode())),
            None => Routed::Answer(Response::not_found()),
        },
        ("GET", ["agents", id, "instances", instance, "schema"]) => {
            match (agent(id), instance.parse::<u32>()) {
                (Some(agent), Ok(instance)) => to(Kind::Schema, Ok((agent, instance).encode())),
                _ => Routed::Answer(Response::not_found()),
            }
        }
        ("POST", ["agents", id, "calls"]) => to(Kind::Call, agent_and(id, body)),
        ("POST", ["agents", id, "queries"]) => to(Kind::Query, agent_and(id, body)),
        ("POST", ["agents", id, "workflows"]) => to(Kind::Workflow, agent_and(id, body)),
        ("POST", ["agents", id, "credentialed"]) => to(Kind::Credentialed, agent_and(id, body)),
        ("GET", ["stats"]) => operator(Kind::Stats, Ok(Vec::new())),
        ("GET", ["agents", id, "status"]) => operator(Kind::Status, agent_and(id, &[])),
        ("POST", ["agents"]) => operator(Kind::CreateAgent, Ok(body.clone())),
        ("POST", ["representative"]) => operator(Kind::CreateRepresentative, Ok(body.clone())),
        ("POST", ["agents", id, "install"]) => operator(Kind::Install, agent_and(id, body)),
        ("POST", ["agents", id, "replicas"]) => operator(Kind::Replace, agent_and(id, body)),
        ("POST", ["agents", id, "roles"]) => operator(Kind::Grant, agent_and(id, body)),
        ("POST", ["agents", id, "reports"]) => operator(Kind::Reports, agent_and(id, body)),
        _ => Routed::Answer(Response::not_found()),
    }
}

/// An answer's HTTP status.
pub fn status(answer: &Answer) -> u16 {
    match answer {
        Answer::Ran { .. }
        | Answer::Created(_)
        | Answer::Placed(_)
        | Answer::Status(_)
        | Answer::Stats(_)
        | Answer::Workflow { .. } => 200,
        Answer::Unplaced(_) => 409,
        Answer::Unconfirmed(_) => 202,
        // The session is done with: the client starts another.
        Answer::Refused(Refusal::Expired | Refusal::StaleSession) => 410,
        // No new session until some are collected.
        Answer::Refused(Refusal::SessionsFull) => 503,
        Answer::Refused(Refusal::KeySessionsFull) => 429,
        // A credentialed call too late, or on a root too old: a new proof.
        Answer::Refused(Refusal::CredentialExpired | Refusal::StaleRoot) => 403,
        Answer::Refused(_) => 409,
        Answer::Rejected(rejection) => match rejection {
            Rejection::TooOld | Rejection::StaleSession { .. } => 410,
            Rejection::BadSignature | Rejection::Unauthorized => 401,
            Rejection::Gap { .. } | Rejection::Ahead => 409,
            Rejection::StaleQuery { .. } | Rejection::Malformed => 400,
            // Another replica may be further along.
            Rejection::Behind => 503,
            Rejection::Credential(refusal) => match refusal {
                CredentialRefusal::Replayed | CredentialRefusal::Once => 409,
                // Retryable: fetch the path again, or ask another replica.
                CredentialRefusal::RootUnknown => 503,
                CredentialRefusal::NoSpace
                | CredentialRefusal::Format
                | CredentialRefusal::Size
                | CredentialRefusal::Expiry { .. }
                | CredentialRefusal::Method
                | CredentialRefusal::Kind
                | CredentialRefusal::Scope
                | CredentialRefusal::Binding
                | CredentialRefusal::RootStale
                | CredentialRefusal::Proof => 403,
            },
            Rejection::Operator(refusal) => match refusal {
                OperatorRefusal::Expiry { .. } | OperatorRefusal::SocketOnly => 403,
                OperatorRefusal::Replayed => 409,
                OperatorRefusal::OtherNode => 421,
            },
        },
        Answer::NotConsumed => 500,
        Answer::NoAgent => 404,
        Answer::Busy | Answer::Stopped | Answer::Unavailable => 503,
        Answer::TimedOut => 504,
        // Another node serves it: the answer says which.
        Answer::NotLeader { .. } | Answer::Elsewhere { .. } => 421,
    }
}

/// An answer as HTTP gives it: its status, its encoding the body.
pub fn respond(answer: &Answer) -> Response {
    Response::new(status(answer), answer.encode())
}

/// An answer frame of `kind` holding `body`, as HTTP gives it: the node's
/// key and time as they are, an `Option`'s value without its tag (none an
/// empty 404), a `Response` with its status. A frame error is the status
/// that says why, with no body.
pub fn answer(kind: u16, body: &[u8]) -> Response {
    let unreadable = || Response::new(502, Vec::new());
    if kind == FRAME_ERROR {
        return match FrameError::decode_exact(body) {
            Some(FrameError::Oversize { .. }) => Response::new(413, Vec::new()),
            Some(FrameError::Unavailable) => Response::new(503, Vec::new()),
            _ => unreadable(),
        };
    }
    match Kind::from_u16(kind) {
        Some(Kind::NodeKey | Kind::Time) => Response::new(200, body.to_vec()),
        Some(Kind::AgentInfo | Kind::Schema) => match body.split_first() {
            Some((0, [])) => Response::not_found(),
            Some((1, value)) => Response::new(200, value.to_vec()),
            _ => unreadable(),
        },
        Some(_) => match Answer::decode_exact(body) {
            Some(answer) => Response::new(status(&answer), body.to_vec()),
            None => unreadable(),
        },
        None => unreadable(),
    }
}

#[cfg(test)]
mod tests {
    use vos_wire::ingress::NodeId;

    use super::*;

    fn request(method: &str, path: &str, body: &[u8]) -> Request {
        Request {
            method: method.into(),
            path: path.into(),
            headers: Vec::new(),
            body: body.to_vec(),
            peer: None,
            large: None,
        }
    }

    #[test]
    fn routes_are_kinds_with_their_bodies() {
        let routed = |method, path, body: &[u8]| route(&request(method, path, body));
        assert_eq!(
            routed("GET", "/", b"ignored"),
            Routed::Request {
                kind: Kind::NodeKey,
                body: Vec::new()
            }
        );
        assert_eq!(
            routed("POST", "/agents/7/calls?x=1", b"abc"),
            Routed::Request {
                kind: Kind::Call,
                body: [&7u32.to_le_bytes()[..], b"abc"].concat()
            }
        );
        assert_eq!(
            routed("GET", "/agents/7/instances/2/schema", b""),
            Routed::Request {
                kind: Kind::Schema,
                body: [7u32.to_le_bytes(), 2u32.to_le_bytes()].concat()
            }
        );
        // A path naming no agent is answered as today, with no node.
        assert_eq!(
            routed("POST", "/agents/x/queries", b""),
            Routed::Answer(respond(&Answer::NoAgent))
        );
        assert_eq!(
            routed("GET", "/agents/-1", b""),
            Routed::Answer(Response::not_found())
        );
        assert_eq!(
            routed("PUT", "/agents", b""),
            Routed::Answer(Response::not_found())
        );
        assert_eq!(
            routed("GET", "/agents/1/instances/x/schema", b""),
            Routed::Answer(Response::not_found())
        );
    }

    #[test]
    fn operator_routes_carry_their_authorization() {
        let operated = Operated {
            node: NodeId([1; 32]),
            key: [2; 32],
            nonce: [3; 16],
            expires_ms: 4,
            body: Vec::new(),
            signature: [5; 64],
        };
        let mut install = request("POST", "/agents/9/install", b"elf");
        install.headers.push((
            "Authorization".into(),
            operated_header(&operated).into_bytes(),
        ));
        assert_eq!(
            route(&install),
            Routed::Operator {
                authorization: Authorization::Operated(Box::new(operated.credentials())),
                kind: Kind::Install,
                inner: Ok([&9u32.to_le_bytes()[..], b"elf"].concat()),
            }
        );
        let mut stats = request("GET", "/stats", b"");
        stats
            .headers
            .push(("authorization".into(), b"Bearer 00".to_vec()));
        assert_eq!(
            route(&stats),
            Routed::Operator {
                authorization: Authorization::Bearer(b"00".to_vec()),
                kind: Kind::Stats,
                inner: Ok(Vec::new()),
            }
        );
        let mut status = request("GET", "/agents/x/status", b"");
        status
            .headers
            .push(("authorization".into(), b"Operated !!".to_vec()));
        assert_eq!(
            route(&status),
            Routed::Operator {
                authorization: Authorization::Unreadable,
                kind: Kind::Status,
                inner: Err(respond(&Answer::NoAgent)),
            }
        );
        assert!(matches!(
            route(&request("POST", "/representative", b"")),
            Routed::Operator {
                authorization: Authorization::None,
                kind: Kind::CreateRepresentative,
                ..
            }
        ));
    }

    #[test]
    fn answers_take_their_http_form() {
        assert_eq!(answer(Kind::AgentInfo as u16, &[0]), Response::not_found());
        assert_eq!(
            answer(Kind::Schema as u16, &[1, 7, 7]),
            Response::new(200, vec![7, 7])
        );
        let busy = Answer::Busy.encode();
        assert_eq!(answer(Kind::Call as u16, &busy), Response::new(503, busy));
        assert_eq!(answer(Kind::Call as u16, &[0xee]).status, 502);
        let oversize = FrameError::Oversize { limit: 1 }.encode();
        assert_eq!(answer(FRAME_ERROR, &oversize).status, 413);
        assert_eq!(
            answer(FRAME_ERROR, &FrameError::Unavailable.encode()).status,
            503
        );
    }
}
