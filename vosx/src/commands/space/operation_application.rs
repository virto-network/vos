//! Bind physical application to the exact retained authorization decision.
use crate::commands::space::{
    clean_store::{CleanInvocationFile, CleanOperationClientFile, CleanPreparationClientFile},
    local_invocation,
};
use std::path::Path;
use vos::agent::clean_bootstrap::NativeAuthorityOperationDecision;
use vos::agent::local_lifecycle::AuthorityOperationSubmission;
use vos::agent::sdk::wire::CanonicalWire as _;
use vos::agent::supervisor_adapters::{
    AgentTargetedPreparationRequest, AgentTargetedPreparationResponse,
};

/// Retain ASQ1 before any application HTTP. The caller must hold the credential
/// reservation across this handoff, delivery, continuation and completion.
/// Historical issuance verification is not a waiver of runtime expiry/policy.
pub(crate) fn retain(
    authorization_root: &Path,
    preparation_root: &Path,
    application_root: &Path,
) -> anyhow::Result<Vec<u8>> {
    let mut authorization = CleanOperationClientFile::open_or_create(authorization_root)?;
    let request = authorization
        .load_request()?
        .ok_or_else(|| anyhow::anyhow!("no retained authorization request"))?;
    let response = authorization
        .load_response()?
        .ok_or_else(|| anyhow::anyhow!("no retained authorization decision"))?;
    let submission = AuthorityOperationSubmission::decode(&request)
        .map_err(|e| anyhow::anyhow!("invalid AOQ1: {e:?}"))?;
    let NativeAuthorityOperationDecision::Issued(issued) = submission
        .decode_response(&response)
        .map_err(|e| anyhow::anyhow!("invalid AOR1: {e:?}"))?
    else {
        anyhow::bail!("denied authorization cannot be applied");
    };
    let mut preparation = CleanPreparationClientFile::open_or_create(preparation_root)?;
    let intent = preparation
        .load_request()?
        .ok_or_else(|| anyhow::anyhow!("no retained physical intent"))?;
    let prepared = preparation
        .load_response()?
        .ok_or_else(|| anyhow::anyhow!("no retained physical preparation"))?;
    let intent = AgentTargetedPreparationRequest::decode(&intent)
        .map_err(|e| anyhow::anyhow!("invalid ATQ1: {e:?}"))?;
    let prepared = AgentTargetedPreparationResponse::decode(&prepared)
        .map_err(|e| anyhow::anyhow!("invalid ATP1: {e:?}"))?;
    let prepared = prepared
        .for_request(&intent)
        .ok_or_else(|| anyhow::anyhow!("preparation differs from retained intent"))?;
    anyhow::ensure!(
        submission
            .call()
            .intent
            .matches_invocation_work(prepared.work()),
        "issued authorization differs from exact prepared work"
    );
    let bytes = local_invocation::assemble(prepared, Some(issued.receipt))?;
    let mut application = CleanInvocationFile::open_or_create(application_root)?;
    // Publishing also validates retained response/progress predecessors and
    // rejects a different existing ASQ1, including a public-preflight envelope.
    application.publish_request(&bytes)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::DirBuilderExt as _;
    use vos::agent::authority_operation_issuer::IssuedAuthorityOperation;
    use vos::agent::sdk::{authority::*, authority_operation::*, *};

    // Real Ed25519 signatures over shaped protocol evidence. This fixture is
    // not a native Authority decision or proof of actor execution.
    fn issued(
        prepared: &vos::agent::supervisor_adapters::PreparedAgentInvocation,
    ) -> (AuthorityOperationSubmission, Vec<u8>) {
        let (operator, old_authority, descriptor, runtime) =
            crate::commands::space::local_create::tests::fixture();
        let public = operator.public().try_into_ed25519().unwrap().to_bytes();
        let package = crate::bundled::root_signed_actor_package(
            crate::bundled::system_authority_package_template(),
            "system-authority",
            &operator,
        )
        .unwrap();
        let (authority, _) = crate::commands::space::clean_startup::derive_system_authority_target(
            old_authority.space,
            public,
            &runtime,
            &package,
        )
        .unwrap();
        let work = prepared.work();
        let managed = ManagedAgentTarget {
            space: work.space,
            agent: work.agent,
            owner: descriptor.identity.owner,
            profile: AgentProfile::Local,
            runtime_deployment: work.runtime_deployment,
            transition_producer: ProducerId::of_public_key(&[0x42; 32]),
        };
        let mut call = AuthorityOperationCall {
            invocation: InvocationId::ZERO,
            authority,
            principal: descriptor.identity.owner,
            credential: CredentialId::of_public_key(&public),
            request_sequence: 1.try_into().unwrap(),
            authentication: AuthorityIngressAuthentication::ApiCredentialSignature {
                credential_public_key: public,
                signature: [1; 64],
            },
            requested_valid_from: 10,
            requested_expires_at: 100,
            intent: AuthorityOperationIntent::invoke(managed, work).unwrap(),
        };
        call.invocation = call.expected_invocation();
        call.authentication = AuthorityIngressAuthentication::ApiCredentialSignature {
            credential_public_key: public,
            signature: operator
                .sign(&call.signing_bytes())
                .unwrap()
                .try_into()
                .unwrap(),
        };
        let context = InvocationContext {
            invocation: call.invocation,
            actor: authority.binding.issuer.actor,
            mode: MethodMode::Linear,
            origin: work.origin,
            roles: InvocationRoleClaims::none(),
            observed_slot: 20,
        };
        let approval = AuthorityOperationApproval::from_call(
            &call,
            7.try_into().unwrap(),
            AuthorityEvidence {
                package: Some(BlobRef {
                    hash: Hash([0x42; 32]),
                    len: 43,
                }),
                proof: None,
                commitment: Hash([0x44; 32]),
            },
            AuthorityLaneRoots {
                control: Some(Hash([0x45; 32])),
                linear: Some(Hash([0x46; 32])),
                merge: None,
                local: None,
            },
            3,
            12,
            28,
        )
        .unwrap();
        let mut receipt = AuthorityReceipt {
            selector: approval.selector.clone(),
            public_key: public,
            signature: [1; 64],
        };
        receipt.signature = operator
            .sign(&receipt.signing_bytes())
            .unwrap()
            .try_into()
            .unwrap();
        let mut ack = AuthorityOperationIssuanceAck {
            authorization_invocation: call.invocation,
            acknowledgement_invocation: approval.acknowledgement_invocation,
            authority,
            operation_call: call.commitment(),
            approval: approval.commitment(),
            authorization_sequence: approval.authorization_sequence,
            receipt: receipt.clone(),
            issued_at: 20,
            signature: [1; 64],
        };
        ack.signature = operator
            .sign(&ack.signing_bytes())
            .unwrap()
            .try_into()
            .unwrap();
        let submission = AuthorityOperationSubmission::new(call, context, 20).unwrap();
        let response = submission
            .encode_response(&NativeAuthorityOperationDecision::Issued(
                IssuedAuthorityOperation {
                    receipt,
                    issuance_ack: ack,
                },
            ))
            .unwrap();
        (submission, response)
    }

    #[test]
    fn managed_application_retries_delivery_and_retirement_before_credential_completion() {
        use crate::commands::space::{
            clean_store::{
                CleanCredentialReservation, CredentialReservationStatus, ensure_private_directory,
            },
            local_operation,
        };
        use std::io::{Read as _, Write as _};
        use vos::agent::supervisor_adapters::{
            AgentAcknowledgementRequest, AgentInvocationResponse,
        };
        let (operator, _, _, _) = crate::commands::space::local_create::tests::fixture();
        let signer =
            crate::commands::space::clean_identity::CleanOperatorIdentitySigner::new(&operator)
                .unwrap();
        let origin = InvocationOrigin {
            principal: Some(signer.principal()),
            credential: Some(signer.credential()),
            ..InvocationOrigin::anonymous()
        };
        let (intent, physical) =
            local_invocation::tests::preparation_fixture_with_origin(61, origin);
        let parsed = AgentTargetedPreparationResponse::decode(&physical).unwrap();
        let (submission, decision) = issued(parsed.for_request(&intent).unwrap());
        let space = submission.call().authority.space;
        let nonce = Hash(intent.intent().invocation().0);
        let mut random = [0; 8];
        getrandom::getrandom(&mut random).unwrap();
        let data =
            std::env::temp_dir().join(format!("vosx-managed-application-{}", hex::encode(random)));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&data)
            .unwrap();
        let root = data.join("agent-client");
        ensure_private_directory(&root).unwrap();
        let claims = root.join("credentials");
        ensure_private_directory(&claims).unwrap();
        let mut reservation =
            CleanCredentialReservation::open_or_create(&claims, space, signer.credential())
                .unwrap();
        reservation.reserve(nonce).unwrap();
        drop(reservation);
        let operations = root.join("operations");
        ensure_private_directory(&operations).unwrap();
        let operation = operations.join(format!(
            "{}-{}",
            hex::encode(signer.credential().0),
            hex::encode(nonce.0)
        ));
        ensure_private_directory(&operation).unwrap();
        let auth_root = operation.join("request");
        let prep_root = operation.join("preparation");
        let app_root = operation.join("application");
        let mut auth = CleanOperationClientFile::open_or_create(&auth_root).unwrap();
        auth.publish_request(&submission.encode().unwrap()).unwrap();
        auth.publish_response(&decision).unwrap();
        drop(auth);
        let mut prep = CleanPreparationClientFile::open_or_create(&prep_root).unwrap();
        prep.publish_request(&intent.encode().unwrap()).unwrap();
        prep.publish_response(&physical).unwrap();
        drop(prep);
        let envelope = retain(&auth_root, &prep_root, &app_root).unwrap();
        let call = local_invocation::validate_request(&envelope).unwrap();
        let initial = AgentInvocationResponse::Direct {
            request: call.commitment(),
            outcome: RuntimeOutcome::Completed(Err(InvocationError::NotFound)),
        }
        .encode()
        .unwrap();
        let ack = AgentAcknowledgementRequest::new(
            RuntimeExecutionContext::Direct,
            None,
            call.work().clone(),
            call.authorization().clone(),
        )
        .unwrap();
        let transition = RuntimeTransition {
            state: RuntimeState::default(),
            outcome: RuntimeOutcome::Acknowledged(Ok(InvocationAcknowledgement {
                invocation: call.work().invocation,
                actor: call.work().actor,
                incarnation: call.work().incarnation,
                deployment: call.work().deployment,
                mode: call.work().mode,
                work: call.work().commitment(),
                authorization: call.authorization().commitment(),
            })),
        }
        .encode()
        .unwrap();
        let mut retired = b"AAR3".to_vec();
        retired.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
        retired.extend_from_slice(ack.commitment().as_bytes());
        retired.extend_from_slice(&(transition.len() as u32).to_le_bytes());
        retired.extend_from_slice(&transition);
        let ack_bytes = ack.encode().unwrap();
        for (exchanges, success) in [
            (vec![("invoke", envelope.clone(), 504, vec![])], false),
            (
                vec![
                    ("invoke", envelope.clone(), 200, initial),
                    ("acknowledge", ack_bytes.clone(), 504, vec![]),
                ],
                false,
            ),
            (vec![("acknowledge", ack_bytes, 200, retired)], true),
        ] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server_claims = claims.clone();
            let credential = signer.credential();
            let server = std::thread::spawn(move || {
                for (path, expected, status, response) in exchanges {
                    let (mut stream, _) = listener.accept().unwrap();
                    stream
                        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                        .unwrap();
                    let mut header = Vec::new();
                    while !header.ends_with(b"\r\n\r\n") {
                        let mut byte = [0];
                        stream.read_exact(&mut byte).unwrap();
                        header.push(byte[0]);
                        assert!(header.len() < 8192);
                    }
                    assert!(
                        header
                            .starts_with(format!("POST /__agents/{path} HTTP/1.1\r\n").as_bytes())
                    );
                    let mut body = vec![0; expected.len()];
                    stream.read_exact(&mut body).unwrap();
                    assert_eq!(body, expected);
                    assert!(
                        CleanCredentialReservation::open_or_create(
                            &server_claims,
                            space,
                            credential
                        )
                        .is_err()
                    );
                    write!(stream, "HTTP/1.1 {status} Test\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", response.len()).unwrap();
                    let _ = stream.write_all(&response);
                }
            });
            let result = local_operation::authorize_with_application(
                &data, address, &operator, space, [0x42; 32], None, true,
            );
            assert_eq!(result.is_ok(), success, "{result:?}");
            server.join().unwrap();
            let mut reservation =
                CleanCredentialReservation::open_or_create(&claims, space, signer.credential())
                    .unwrap();
            assert_eq!(
                reservation.current().unwrap(),
                Some((
                    nonce,
                    if success {
                        CredentialReservationStatus::Completed
                    } else {
                        CredentialReservationStatus::Pending
                    }
                ))
            );
            if !success {
                assert!(reservation.reserve(Hash([0x72; 32])).is_err());
            }
        }
        // No server remains: all decisions, application and retirement replies
        // are re-verified locally and the exact completion is idempotent.
        assert!(
            local_operation::authorize_with_application(
                &data,
                "127.0.0.1:1".parse().unwrap(),
                &operator,
                space,
                [0x42; 32],
                None,
                true
            )
            .is_ok()
        );
        let mut reservation =
            CleanCredentialReservation::open_or_create(&claims, space, signer.credential())
                .unwrap();
        reservation.reserve(Hash([0x72; 32])).unwrap();
        let mut auth = CleanOperationClientFile::open_or_create(&auth_root).unwrap();
        let mut app = CleanInvocationFile::open_or_create(&app_root).unwrap();
        assert!(reservation.complete_operation(&mut auth, &mut app).is_err());
        drop(app);
        drop(auth);
        drop(reservation);
        std::fs::remove_dir_all(data).unwrap();
    }

    #[test]
    fn application_requires_exact_prepared_work_and_verified_retained_issuance() {
        let (operator, _, _, _) = crate::commands::space::local_create::tests::fixture();
        let signer =
            crate::commands::space::clean_identity::CleanOperatorIdentitySigner::new(&operator)
                .unwrap();
        let origin = InvocationOrigin {
            principal: Some(signer.principal()),
            credential: Some(signer.credential()),
            ..InvocationOrigin::anonymous()
        };
        let (intent, physical) =
            local_invocation::tests::preparation_fixture_with_origin(41, origin);
        let parsed = AgentTargetedPreparationResponse::decode(&physical).unwrap();
        let prepared = parsed.for_request(&intent).unwrap();
        let (submission, response) = issued(prepared);
        let mut random = [0; 8];
        getrandom::getrandom(&mut random).unwrap();
        let root = std::env::temp_dir().join(format!(
            "vosx-operation-application-{}",
            hex::encode(random)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .unwrap();
        let auth_root = root.join("authorization");
        let prep_root = root.join("preparation");
        let app_root = root.join("application");
        let mut auth = CleanOperationClientFile::open_or_create(&auth_root).unwrap();
        auth.publish_request(&submission.encode().unwrap()).unwrap();
        drop(auth);
        assert!(retain(&auth_root, &prep_root, &app_root).is_err());
        assert!(!app_root.exists());
        let mut auth = CleanOperationClientFile::open_or_create(&auth_root).unwrap();
        let mut corrupt = response.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(auth.publish_response(&corrupt).is_err());
        auth.publish_response(&response).unwrap();
        let mut reservation =
            crate::commands::space::clean_store::CleanCredentialReservation::open_or_create(
                &root,
                submission.call().authority.space,
                submission.call().credential,
            )
            .unwrap();
        reservation
            .reserve(Hash(prepared.work().invocation.0))
            .unwrap();
        assert!(reservation.deny_operation(&mut auth).is_err());
        assert_eq!(
            reservation.current().unwrap(),
            Some((
                Hash(prepared.work().invocation.0),
                crate::commands::space::clean_store::CredentialReservationStatus::Pending
            ))
        );
        drop(reservation);
        drop(auth);
        assert!(retain(&auth_root, &prep_root, &app_root).is_err());
        assert!(!app_root.exists());
        let mut preparation = CleanPreparationClientFile::open_or_create(&prep_root).unwrap();
        preparation
            .publish_request(&intent.encode().unwrap())
            .unwrap();
        preparation.publish_response(&physical).unwrap();
        drop(preparation);
        let bytes = retain(&auth_root, &prep_root, &app_root).unwrap();
        let invocation = local_invocation::validate_request(&bytes).unwrap();
        assert_eq!(invocation.work(), prepared.work());
        assert!(matches!(
            invocation.authorization(),
            InvocationAuthorization::AuthorityReceipt(_)
        ));
        assert_eq!(retain(&auth_root, &prep_root, &app_root).unwrap(), bytes);
        let (other_intent, other_physical) =
            local_invocation::tests::preparation_fixture_with_origin(42, origin);
        let other_root = root.join("other-preparation");
        let mut other = CleanPreparationClientFile::open_or_create(&other_root).unwrap();
        other
            .publish_request(&other_intent.encode().unwrap())
            .unwrap();
        other.publish_response(&other_physical).unwrap();
        drop(other);
        assert!(retain(&auth_root, &other_root, &root.join("wrong-application")).is_err());
        assert!(!root.join("wrong-application").exists());
        let public_root = root.join("public-application");
        // A previously retained public invocation cannot be overwritten by
        // the protected invocation, even if the client points at its directory.
        let mut public = CleanInvocationFile::open_or_create(&public_root).unwrap();
        let (public_intent, public_physical) =
            local_invocation::tests::preparation_fixture_with_origin(
                41,
                InvocationOrigin::anonymous(),
            );
        let public_physical = AgentTargetedPreparationResponse::decode(&public_physical).unwrap();
        let public_request =
            local_invocation::assemble(public_physical.for_request(&public_intent).unwrap(), None)
                .unwrap();
        public.publish_request(&public_request).unwrap();
        drop(public);
        assert!(retain(&auth_root, &prep_root, &public_root).is_err());
        let mut public = CleanInvocationFile::open_or_create(&public_root).unwrap();
        assert_eq!(public.load_request().unwrap(), Some(public_request));
        drop(public);
        std::fs::remove_dir_all(root).unwrap();
    }
}
