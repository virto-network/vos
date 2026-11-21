//! The demo's s4 app on the gateway's SSH port
//! ([`vos_gateway::ssh::App`]), its three screens
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
//! itself is the action, at the node. The app builds no credential bytes;
//! its key ([`AppClient`]) only reads. The screens hold each enrollment's
//! digests, which the operator's invitation claims at once.

use std::sync::Arc;

use s4_server::rui::{App, Cx, Effect, EffectOutput, EffectRequest, View, ViewContext, view};
use s4_server::{HostServiceError, HostServiceRequest, Identifier, Server, Value};
use tokio::sync::OnceCell;
use vos_abi::abi::Failure;
use vos_abi::ids::{AgentId, InstanceId, MethodId, derive_id};
use vos_abi::result::Outcome;
use vos_abi::{Decode, Encode, SpaceId};
use vos_api::{FRAME_ERROR, Kind, Mark};
use vos_gateway::Gateway;
use vos_gateway::ssh::APPLICATION;
use vos_wire::credentials::{CredentialError, RootEntry};
use vos_wire::ingress::{AgentInfo, CredentialRefusal, Rejection, Response};

mod client;
mod screens;
mod service;

pub use client::AppClient;
pub use screens::{Message, Screen, Screens};
pub use service::{Held, Service};

/// The host service the screens call, server-side.
pub const SERVICE: &str = "vos.gateway";
/// The client facility that proves.
pub const FACILITY: &str = "vos.credential";

/// The agent the demo serves and its actors' instances.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Demo {
    pub agent: u32,
    pub credentials: u32,
    pub payments: u32,
    pub poll: u32,
    /// The onion keys the enrollment pins: the gateway's own onion.
    pub onions: Vec<[u8; 32]>,
}

/// The demo's screens as an SSH port serves them: on each port, its reads
/// going as the app key's seed `key`, marked with the port's transport;
/// the enrollments `held` for the operator's invitations, every port's.
pub struct DemoApp {
    pub demo: Demo,
    pub key: [u8; 32],
    pub held: Held,
}

impl vos_gateway::ssh::App for DemoApp {
    fn server(&self, gateway: &Arc<Gateway>, mark: Mark, host_key: Option<[u8; 32]>) -> Server {
        let app = Arc::new(AppClient::new(self.key, Arc::clone(gateway), mark));
        let service = Arc::new(Service::new(
            self.demo.clone(),
            host_key,
            Arc::clone(gateway),
            mark,
            app,
            self.held.clone(),
        ));
        let demo = self.demo.clone();
        Server::new(APPLICATION, move || Screens::new(demo.clone(), mark))
            .facility(FACILITY, 1)
            .host_service_fn(SERVICE, move |request| Arc::clone(&service).serve(request))
    }
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
