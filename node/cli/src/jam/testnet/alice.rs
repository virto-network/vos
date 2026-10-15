//! Alice, the run's client: her calls, signed for the agent's service.

use ed25519_dalek::Signer;
use vos_jam::admit;
use vos_wire::batch::Input;
use vos_wire::ids::{InstanceId, MethodId, Session};
use vos_wire::ingress::{Call, call_message};
use vos_wire::package::identity;
use vos_wire::result::digest;

use super::{Testnet, now, said};

impl Testnet {
    /// Alice's next call, signed for the agent of `service`, as the
    /// builder admits it.
    pub(super) fn call(
        &mut self,
        service: u64,
        instance: InstanceId,
        method: MethodId,
        arguments: Vec<u8>,
    ) -> Result<Input, String> {
        let key = self.alice.verifying_key().to_bytes();
        let session = *self.session.get_or_insert(Session {
            key,
            name: digest(&key)[..16].try_into().expect("16 bytes"),
            t0: now(),
        });
        self.sequence += 1;
        let message = call_message(
            &identity(service),
            &session,
            self.sequence,
            instance,
            method,
            &arguments,
        );
        let call = Call {
            session,
            sequence: self.sequence,
            instance,
            method,
            arguments,
            signature: self.alice.sign(&message).to_bytes(),
        };
        admit(service, call).map_err(said)
    }
}
