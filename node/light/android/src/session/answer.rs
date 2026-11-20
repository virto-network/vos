// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What a node's answer to a credentialed call refused.

use vos_abi::abi;
use vos_light::wire;
use vos_wire::ingress::{CredentialRefusal, Response};

use super::UPDATE;
use crate::{Code, Refusal, refused};

/// Whether the node answered a proof as one on a root it does not judge
/// current: `Some(false)` for one its ring does not hold (`RootUnknown`),
/// `Some(true)` for one superseded past its grace, at ingress
/// (`RootStale`) or at apply (`StaleRoot`).
pub(super) fn root_refused(answer: &[u8]) -> Option<bool> {
    match wire::credentialed_answer(answer) {
        Ok(wire::Answer::RootUnknown) => Some(false),
        Ok(wire::Answer::RootStale) => Some(true),
        Ok(wire::Answer::Other(body)) => {
            (node_refusal(&body) == Some(abi::Refusal::StaleRoot)).then_some(true)
        }
        _ => None,
    }
}

/// The node's refusal an answer's body carries, if it is one.
fn node_refusal(body: &[u8]) -> Option<abi::Refusal> {
    match <Response as vos_abi::Decode>::decode_exact(body) {
        Some(Response::Refused(refusal)) => Some(refusal),
        _ => None,
    }
}

/// Refused, as an app to update, when the node refused a proof for its
/// device format: one its ingress does not admit, or one the release or
/// the agent's log retired by the batch's time.
pub(crate) fn update_refused(answer: &[u8]) -> Result<(), Refusal> {
    let format = match wire::credentialed_answer(answer) {
        Ok(wire::Answer::Refused(CredentialRefusal::Format)) => true,
        Ok(wire::Answer::Other(body)) => node_refusal(&body) == Some(abi::Refusal::Format),
        _ => false,
    };
    match format {
        true => Err(refused(Code::Refused, UPDATE)),
        false => Ok(()),
    }
}
