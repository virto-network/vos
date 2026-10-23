//! Alice, the run's client: her calls, signed for the agent's service.

use ed25519_dalek::SigningKey;
use vos_jam::{Error, admit};
use vos_node::client::signed_call;
use vos_wire::batch::Input;
use vos_wire::ids::{InstanceId, MethodId, Principal, Session};
use vos_wire::package::identity;
use vos_wire::result::digest;

/// Alice: her key, the session her first call starts, and the sequence of
/// her last call in it.
pub(super) struct Alice {
    key: SigningKey,
    session: Option<Session>,
    sequence: u64,
}

impl Alice {
    /// Alice with a key of her own, new to every run.
    pub(super) fn new() -> Result<Self, String> {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).map_err(|error| error.to_string())?;
        Ok(Self {
            key: SigningKey::from_bytes(&seed),
            session: None,
            sequence: 0,
        })
    }

    /// Who she is to the agent.
    pub(super) fn principal(&self) -> Principal {
        Principal::Client(self.key.verifying_key().to_bytes())
    }

    /// Her next call, signed for the agent of `service`, as the builder
    /// admits it.
    pub(super) fn call(
        &mut self,
        service: u64,
        instance: InstanceId,
        method: MethodId,
        arguments: Vec<u8>,
    ) -> Result<Input, Error> {
        let key = self.key.verifying_key().to_bytes();
        let session = *self.session.get_or_insert(Session {
            key,
            name: digest(&key)[..16].try_into().expect("16 bytes"),
            t0: vos_node::wall_clock(),
        });
        self.sequence += 1;
        let call = signed_call(
            &identity(service),
            &self.key,
            session,
            self.sequence,
            instance,
            method,
            arguments,
        );
        admit(service, call)
    }
}
