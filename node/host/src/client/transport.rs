//! How a client reaches a node: HTTP, or the node API over its socket or
//! QUIC, behind one interface of HTTP's requests.

use std::time::Duration;

use super::api::Api;
use super::http::{ANSWER, Http};
use super::{ClientError, Target};

pub(super) enum Transport {
    Http(Http),
    Api(Api),
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

    fn request(
        &self,
        method: &str,
        path: &str,
        authorization: Option<&str>,
        body: &[u8],
        repeatable: bool,
    ) -> Result<(u16, Vec<u8>), ClientError> {
        match self {
            Transport::Http(http) => http.request(method, path, authorization, body, repeatable),
            Transport::Api(api) => api.request(method, path, authorization, body, repeatable),
        }
    }

    /// A read, with an `Authorization` header's value if any.
    pub(super) fn get(
        &self,
        path: &str,
        authorization: Option<&str>,
    ) -> Result<(u16, Vec<u8>), ClientError> {
        self.request("GET", path, authorization, &[], true)
    }

    /// A post, with an `Authorization` header's value if any, sent again
    /// on a fresh connection when a kept one failed if `repeatable`.
    pub(super) fn post(
        &self,
        path: &str,
        authorization: Option<&str>,
        body: &[u8],
        repeatable: bool,
    ) -> Result<(u16, Vec<u8>), ClientError> {
        self.request("POST", path, authorization, body, repeatable)
    }

    /// A request the node may not take twice as once: never sent again.
    pub(super) fn post_once(
        &self,
        path: &str,
        authorization: Option<&str>,
        body: &[u8],
    ) -> Result<(u16, Vec<u8>), ClientError> {
        self.request("POST", path, authorization, body, false)
    }

    /// A request the node takes twice as once: a signed call or read.
    pub(super) fn post_repeatable(
        &self,
        path: &str,
        body: &[u8],
    ) -> Result<(u16, Vec<u8>), ClientError> {
        self.request("POST", path, None, body, true)
    }
}
