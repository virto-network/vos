//! Dedicated signed-body administration. This is not generic actor invocation
//! authentication: the owner pins the destination node and the Authority actor
//! verifies the signed administrator/credential/node tuple and current policy.
use super::*;
use crate::agent::clean_bootstrap::NativeAuthorityAdminSubmission;
use crate::agent::local_lifecycle::LocalLifecycleIngressError;
use crate::agent::sdk::authority::AuthorityAdminCall;
use crate::agent::sdk::wire::CanonicalWire;
use crate::ingress::types::{text, with_content_type};

fn validate_request(
    request: &crate::ingress::types::Request,
    maximum: usize,
) -> Option<crate::ingress::types::Response> {
    if request.body().len() > MAX_BODY_BYTES.min(maximum) {
        return Some(text(413, "admin request body too large"));
    }
    if request.method() != http::Method::POST {
        return Some(text(405, "admin requests are POST-only"));
    }
    if request.uri().query().is_some() {
        return Some(text(400, "admin requests do not accept query parameters"));
    }
    if request
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        != Some("application/octet-stream")
    {
        return Some(text(415, "admin requests require application/octet-stream"));
    }
    None
}

fn queue_error(error: LocalLifecycleIngressError) -> crate::ingress::types::Response {
    match error {
        LocalLifecycleIngressError::Invalid => text(400, "invalid signed admin request"),
        LocalLifecycleIngressError::Busy => text(503, "Local lifecycle queue is full"),
        LocalLifecycleIngressError::Unavailable => text(503, "admin delivery unavailable"),
    }
}

pub(super) fn prepare(
    request: &crate::ingress::types::Request,
    handle: &IngressHandle,
) -> crate::ingress::types::Response {
    if let Some(response) = validate_request(request, AuthorityAdminCall::MAX_ENCODED_BYTES) {
        return response;
    }
    let draft = match AuthorityAdminCall::decode(request.body()) {
        Ok(draft) => draft,
        Err(_) => return text(400, "invalid admin draft"),
    };
    let reply = match handle.prepare_clean_authority_admin(draft.clone()) {
        Ok(reply) => reply,
        Err(error) => return queue_error(error),
    };
    match reply.recv_timeout(Duration::from_secs(120)) {
        Ok(Ok(preparation)) if preparation.call_to_sign(&draft).is_ok() => {
            match preparation.encode() {
                Ok(bytes) => with_content_type(200, "application/octet-stream", bytes),
                Err(_) => text(500, "invalid admin preparation"),
            }
        }
        Ok(Ok(_)) => text(500, "invalid admin preparation binding"),
        Ok(Err(_)) => text(503, "admin preparation incomplete; retry the signed draft"),
        Err(_) => text(
            504,
            "admin preparation outcome unknown; retry the signed draft",
        ),
    }
}

pub(super) fn submit(
    request: &crate::ingress::types::Request,
    handle: &IngressHandle,
) -> crate::ingress::types::Response {
    if let Some(response) =
        validate_request(request, NativeAuthorityAdminSubmission::MAX_ENCODED_BYTES)
    {
        return response;
    }
    let submission = match NativeAuthorityAdminSubmission::decode(request.body()) {
        Ok(submission) => submission,
        Err(_) => return text(400, "invalid signed admin submission"),
    };
    let (call, preparation) = submission.clone().into_parts();
    let reply = match handle.submit_clean_authority_admin(call, preparation) {
        Ok(reply) => reply,
        Err(error) => return queue_error(error),
    };
    match reply.recv_timeout(Duration::from_secs(120)) {
        Ok(Ok(completion))
            if submission
                .verify_completion(completion.exact_bytes())
                .is_ok() =>
        {
            with_content_type(
                if completion.result().is_some() {
                    200
                } else {
                    403
                },
                "application/octet-stream",
                completion.exact_bytes().to_vec(),
            )
        }
        Ok(Ok(_)) => text(500, "invalid admin completion binding"),
        Ok(Err(_)) => text(503, "admin submission incomplete; retry identical NAS1"),
        Err(_) => text(504, "admin outcome unknown; retry identical NAS1"),
    }
}
