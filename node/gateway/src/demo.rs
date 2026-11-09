//! The demo's three screens on the SSH port:
//! *Enroll*, *Sign in* and *Pay*, server-owned s4 documents over the
//! credential actor and the ledger, `Payments`, of one agent. *Sign in*
//! offers the poll's `login`, proven by the stock `auth` kernel; *Pay* the
//! ledger's `transfer`, proven by the stock `owner` kernel, from the
//! account of the device's owner digest. The proofs are the member's
//! device's: the client's `vos.credential` facility, which the app asks,
//! sends each proof itself over Tor to the onions its enrollment pinned,
//! and hands the screen the node's answer, which it shows; the screens
//! relay nothing the device hands back. What the screen shows of that
//! answer is the client's word: it grants nothing here, as the proven call
//! itself is the action, at the node. The gateway builds no credential
//! bytes and holds no authority; its app key sends only the claims an
//! operator's invitations allow.

use std::sync::Arc;

use s4_server::rui::{App, Cx, Effect, EffectOutput, EffectRequest, View, ViewContext, view};
use s4_server::{HostServiceError, HostServiceRequest, Identifier, Value};
use tokio::sync::{Mutex, OnceCell};
use vos_api::{FRAME_ERROR, Kind, Mark};
use vos_wire::abi::Failure;
use vos_wire::credentials::{CredentialError, RootEntry};
use vos_wire::ids::{AgentId, InstanceId, MethodId, Session, derive_id};
use vos_wire::ingress::{AgentInfo, CredentialRefusal, Rejection, Response};
use vos_wire::result::Outcome;
use vos_wire::{Decode, Encode, SpaceId};

use crate::Gateway;
use crate::app::AppClient;

mod screens;
mod service;

pub use screens::{Message, Screen, Screens};
pub use service::Service;

/// The host service the screens call, server-side.
pub const SERVICE: &str = "vos.gateway";
/// The client facility that proves.
pub const FACILITY: &str = "vos.credential";
/// The application identity the screens are served as.
pub const APPLICATION: &str = "vos.gateway";

/// The agent the demo serves and its actors' instances, from the gateway's
/// file.
#[derive(Clone, Debug, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Demo {
    pub agent: u32,
    pub credentials: u32,
    pub payments: u32,
    pub poll: u32,
    /// The onion keys the enrollment pins: the gateway's own onion, from
    /// its key file, never the file's `[demo]` section.
    #[serde(skip)]
    pub onions: Vec<[u8; 32]>,
}

/// The guarded methods the device is asked to pin, and the ledger's.
const LOGIN: &str = "login";
const VOTE: &str = "vote";
const TRANSFER: &str = "transfer";

fn method(name: &str) -> MethodId {
    MethodId(derive_id("vos/method/", name))
}

fn identifier(text: &str) -> Identifier {
    Identifier::new(text).expect("a valid identifier")
}

fn object(entries: impl IntoIterator<Item = (&'static str, Value)>) -> Value {
    Value::object(
        entries
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value)),
    )
}
