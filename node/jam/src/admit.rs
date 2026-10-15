//! A client's call, as a builder takes it.

use ed25519_dalek::{Signature, VerifyingKey};
use vos_wire::batch::{Input, Request};
use vos_wire::ids::Principal;
use vos_wire::ingress::{Call, call_message};

use crate::Error;

/// A client's call to the agent of JAM service `service`, as its builder
/// takes it: signed by its session's key, as a VOS node's ingress checks
/// it, else `Error::Signature`.
pub fn admit(service: u64, call: Call) -> Result<Input, Error> {
    let message = call_message(
        &vos_wire::package::identity(service),
        &call.session,
        call.sequence,
        call.instance,
        call.method,
        &call.arguments,
    );
    let signed = VerifyingKey::from_bytes(&call.session.key).is_ok_and(|key| {
        key.verify_strict(&message, &Signature::from_bytes(&call.signature))
            .is_ok()
    });
    if !signed {
        return Err(Error::Signature);
    }
    Ok(Input::Request(Request {
        session: call.session,
        sequence: call.sequence,
        caller: Principal::Client(call.session.key),
        instance: call.instance,
        method: call.method,
        arguments: call.arguments,
    }))
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};
    use vos_wire::ids::{InstanceId, MethodId, Session};

    use super::*;

    /// A call signed by its session's key for the agent's service is a
    /// request of that key's; signed for another service, or by another
    /// key, it is refused.
    #[test]
    fn a_call_is_admitted_signed_by_its_sessions_key() {
        let key = SigningKey::from_bytes(&[3; 32]);
        let session = Session {
            key: key.verifying_key().to_bytes(),
            name: [4; 16],
            t0: 5,
        };
        let signed = |service: u64, key: &SigningKey| {
            let message = call_message(
                &vos_wire::package::identity(service),
                &session,
                6,
                InstanceId(7),
                MethodId(8),
                &[9],
            );
            Call {
                session,
                sequence: 6,
                instance: InstanceId(7),
                method: MethodId(8),
                arguments: vec![9],
                signature: key.sign(&message).to_bytes(),
            }
        };
        let Ok(Input::Request(request)) = admit(1, signed(1, &key)) else {
            panic!("admitted");
        };
        assert_eq!(request.caller, Principal::Client(session.key));
        assert_eq!((request.sequence, request.arguments), (6, vec![9]));
        assert_eq!(admit(2, signed(1, &key)), Err(Error::Signature));
        let other = SigningKey::from_bytes(&[4; 32]);
        assert_eq!(admit(1, signed(1, &other)), Err(Error::Signature));
    }
}
