//! How a client reaches a node: the node API over its socket or QUIC, or a
//! gateway's HTTP, behind one interface of the node API's requests, a kind
//! and its body, answered as HTTP gives an answer.

use std::time::Duration;

use vos_api::{Kind, Operated};

use super::api::Api;
use super::http::{ANSWER, Http};
use super::{ClientError, Target};

pub(super) enum Transport {
    Http(Http),
    Api(Api),
}

/// What a request of a kind carries: a frame's body, or an operator's
/// envelope over its inner body.
#[derive(Clone, Copy)]
pub(super) enum Body<'a> {
    Plain(&'a [u8]),
    Operated(&'a Operated),
}

impl Transport {
    pub(super) fn new(target: &Target) -> Self {
        Self::within(target, ANSWER)
    }

    /// One whose requests are answered within `answer`, connecting within
    /// it too.
    pub(super) fn within(target: &Target, answer: Duration) -> Self {
        match target.api {
            Some(_) => Transport::Api(Api::new(target, answer)),
            None => Transport::Http(Http::within(target, answer)),
        }
    }

    pub(super) fn target(&self) -> &Target {
        match self {
            Transport::Http(http) => &http.target,
            Transport::Api(api) => &api.target,
        }
    }

    /// A request of `kind` carrying `body`: its answer's status and body,
    /// as HTTP gives them. Sent once more on a fresh connection when a kept
    /// one failed before any answer if `repeatable`: the node takes it
    /// twice as once (a read, a signed call or query, a signed command).
    pub(super) fn send(
        &self,
        kind: Kind,
        body: Body<'_>,
        repeatable: bool,
    ) -> Result<(u16, Vec<u8>), ClientError> {
        match self {
            Transport::Api(api) => api.send(kind, body, repeatable),
            Transport::Http(http) => {
                let (inner, authorization) = match body {
                    Body::Plain(body) => (body, None),
                    Body::Operated(operated) => (
                        &operated.body[..],
                        Some(vos_http::routes::operated_header(operated)),
                    ),
                };
                let (method, path, body) =
                    vos_http::routes::path(kind, inner).ok_or_else(|| {
                        ClientError::Http(format!("{kind:?}: a body its route cannot name"))
                    })?;
                http.request(method, &path, authorization.as_deref(), body, repeatable)
            }
        }
    }

    /// A read, or a signed request the node takes twice as once.
    pub(super) fn repeatable(
        &self,
        kind: Kind,
        body: &[u8],
    ) -> Result<(u16, Vec<u8>), ClientError> {
        self.send(kind, Body::Plain(body), true)
    }

    /// A request the node may not take twice as once: never sent again.
    pub(super) fn once(&self, kind: Kind, body: &[u8]) -> Result<(u16, Vec<u8>), ClientError> {
        self.send(kind, Body::Plain(body), false)
    }
}
