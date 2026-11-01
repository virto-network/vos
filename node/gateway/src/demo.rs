//! The demo's three screens on the SSH port:
//! *Enroll*, *Sign in* and *Pay*, server-owned s4 documents over the
//! credential actor and the `purses` ledger of one agent. *Sign in* offers
//! the credential proof (the poll's `login`) and, where the file names the
//! device actor, a device proof of its kernel `auth` (its `login`, whose
//! guard names that kernel): the enrollment pins the kernel's bytes,
//! which the device proves under the device profile. The proofs are
//! the member's device's: the client's `vos.credential` facility, which the
//! app asks and whose answer, a node-API `Credentialed` request, the gateway
//! relays as it is after checking it names this agent and the screen's
//! method. The gateway builds no credential bytes and holds no authority;
//! its app key sends only the claims an operator's invitations allow.

use std::path::PathBuf;
use std::sync::Arc;

use s4_server::rui::{App, Cx, Effect, EffectOutput, EffectRequest, View, ViewContext, view};
use s4_server::{HostServiceError, HostServiceRequest, Identifier, Value};
use tokio::sync::{Mutex, OnceCell};
use vos_api::{FRAME_ERROR, Kind};
use vos_wire::abi::Failure;
use vos_wire::credentials::{CredentialError, RootEntry};
use vos_wire::ids::{AgentId, InstanceId, MethodId, Session, derive_id};
use vos_wire::ingress::{AgentInfo, CredentialRefusal, Credentialed, Rejection, Response};
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
    pub purses: u32,
    pub poll: u32,
    /// The device actor, whose `login` also takes a device proof of its
    /// kernel `auth`: none, and *Sign in* offers the credential proof
    /// alone.
    #[serde(default)]
    pub device: Option<DeviceSignIn>,
}

/// The device actor's instance, and the file holding its kernel `auth` as
/// the install derived it, which the enrollment pins on the device.
#[derive(Clone, Debug, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeviceSignIn {
    pub instance: u32,
    pub kernel: PathBuf,
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
