//! Exact retained Local Install delivery. No sequence allocation or signing
//! occurs during submission; an ambiguous response never changes the request.

use vos::agent::local_lifecycle::LocalInstallSubmission;
use vos::agent::sdk::authority::ManagementApplicationAck;
use vos::agent::sdk::wire::CanonicalWire as _;

/// Prepare exact bytes using an already allocated credential sequence and
/// independently selected descriptor/Authority. No clock or nonce is generated.
pub(crate) fn prepare(
    operator: &libp2p::identity::Keypair,
    authority: vos::agent::sdk::authority::AuthorityActorTarget,
    descriptor: &vos::agent::sdk::AgentDescriptor,
    install: vos::agent::sdk::InstallActor,
    package: vos::agent::package_admission::AdmittedActorPackage,
    sequence: std::num::NonZeroU64,
    valid_from: u64,
    expires_at: u64,
) -> anyhow::Result<LocalInstallSubmission> {
    use vos::agent::sdk::authority::{AuthorityCredentialCall, ManagedAgentTarget};
    use vos::agent::sdk::{InvocationId, ManagementRequest};
    let identity = super::clean_identity::CleanOperatorIdentitySigner::new(operator)?;
    anyhow::ensure!(
        descriptor.validate().is_ok()
            && descriptor.identity.owner == identity.principal()
            && descriptor.authority == authority.binding
            && descriptor.identity.space == authority.space,
        "Local Install descriptor differs from selected operator/Authority"
    );
    package
        .envelope()
        .require_compatible_with(descriptor.runtime_contract, descriptor.capabilities)
        .map_err(|error| anyhow::anyhow!("unsupported actor requirements: {error:?}"))?;
    let managed = ManagedAgentTarget {
        space: descriptor.identity.space,
        agent: descriptor.identity.agent,
        owner: descriptor.identity.owner,
        profile: descriptor.identity.profile,
        runtime_deployment: descriptor.identity.runtime_deployment,
        transition_producer: descriptor.identity.transition_producer,
    };
    let request = ManagementRequest::Install(Box::new(install.clone()));
    let mut call = AuthorityCredentialCall {
        invocation: InvocationId::ZERO,
        authority,
        managed,
        principal: identity.principal(),
        credential: identity.credential(),
        request_sequence: sequence,
        credential_public_key: identity.raw_public_key(),
        authenticated_node: None,
        requested_valid_from: valid_from,
        requested_expires_at: expires_at,
        plan: request
            .authorization_plan()
            .ok_or_else(|| anyhow::anyhow!("invalid Install plan"))?,
        signature: [0; 64],
    };
    call.invocation = call.expected_invocation();
    call.signature = operator
        .sign(&call.signing_bytes())?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Install signature must be Ed25519"))?;
    LocalInstallSubmission::new(install, call, package)
        .map_err(|error| anyhow::anyhow!("invalid signed Local Install: {error:?}"))
}

pub(crate) fn verify_acknowledgement(
    request: &[u8],
    response: &[u8],
) -> anyhow::Result<ManagementApplicationAck> {
    let submission = LocalInstallSubmission::decode(request)
        .map_err(|error| anyhow::anyhow!("invalid retained Local Install: {error:?}"))?;
    let (_, call, _) = submission.into_parts();
    super::local_create::verify_call_acknowledgement(&call, response)
}

pub(crate) fn submit_retained(
    root: &std::path::Path,
    address: std::net::SocketAddr,
) -> anyhow::Result<ManagementApplicationAck> {
    anyhow::ensure!(
        address.ip().is_loopback() && address.port() != 0,
        "plaintext Local Install requires a nonzero loopback endpoint"
    );
    let mut store = super::clean_store::CleanLocalInstallFile::open_or_create(root)?;
    let request = store
        .load_request()?
        .ok_or_else(|| anyhow::anyhow!("no retained Local Install request"))?;
    let result = (|| {
        if let Some(bytes) = store.load_acknowledgement()? {
            return verify_acknowledgement(&request, &bytes);
        }
        let response = super::local_create::post_binary(
            address,
            "/__agents/local/install",
            201,
            &request,
            vos::agent::sdk::wire::MAX_MANAGEMENT_APPLICATION_ACK_WIRE_BYTES,
        )?;
        let acknowledgement = verify_acknowledgement(&request, &response)?;
        store.publish_acknowledgement(&response)?;
        Ok(acknowledgement)
    })();
    result.map_err(|error: anyhow::Error| {
        anyhow::anyhow!(
            "{error}; Install request retained: retry identical bytes, outcome may be unknown"
        )
    })
}

pub(crate) fn run_submit(
    root: &std::path::Path,
    address: std::net::SocketAddr,
) -> anyhow::Result<()> {
    let acknowledgement = submit_retained(root, address)?;
    if crate::output::is_json() {
        crate::output::print_json(&serde_json::json!({
            "agent": hex::encode(acknowledgement.managed.agent.0),
            "acknowledgement": hex::encode(acknowledgement.encode()
                .map_err(|error| anyhow::anyhow!("encode acknowledgement: {error:?}"))?),
        }));
    } else {
        println!(
            "Local Agent {}: verified installation acknowledgement",
            hex::encode(acknowledgement.managed.agent.0)
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::NonZeroU64;
    use vos::agent::sdk::authority::{
        AuthorityEvidence, AuthorityLaneRoots, AuthorityReceipt, AuthorityReceiptSelector,
        ManagementApproval,
    };
    use vos::agent::sdk::{Hash, ManagementReply, ManagementRequest};

    fn fixture() -> (Vec<u8>, ManagementApplicationAck, libp2p::identity::Keypair) {
        let (operator, authority, descriptor, _) = super::super::local_create::tests::fixture();
        let package = vos::agent::package_admission::admit_actor_package(include_bytes!(
            "../../../blobs/system_catalog.vos"
        ))
        .unwrap();
        let ManagementRequest::Install(install) =
            super::super::clean_startup::install_request_fixture(
                descriptor.identity.agent,
                &package,
            )
        else {
            unreachable!()
        };
        let submission = prepare(
            &operator,
            authority,
            &descriptor,
            *install.clone(),
            package.clone(),
            NonZeroU64::new(2).unwrap(),
            10,
            30,
        )
        .unwrap();
        let request = submission.encode();
        assert_eq!(
            prepare(
                &operator,
                authority,
                &descriptor,
                *install.clone(),
                package,
                NonZeroU64::new(2).unwrap(),
                10,
                30
            )
            .unwrap()
            .encode(),
            request
        );
        let (_, call, _) = submission.into_parts();
        let approval = ManagementApproval::from_call(
            &call,
            NonZeroU64::new(3).unwrap(),
            AuthorityEvidence {
                package: None,
                proof: None,
                commitment: Hash([10; 32]),
            },
            AuthorityLaneRoots::default(),
            1,
            10,
            30,
        )
        .unwrap();
        let mut receipt = AuthorityReceipt {
            selector: AuthorityReceiptSelector {
                policy: authority.binding.policy,
                issuer: authority.binding.issuer,
                space: call.managed.space,
                agent: call.managed.agent,
                operation: call.plan.authority_operation(),
                runtime_deployment: call.managed.runtime_deployment,
                actor: Some(install.entry.actor),
                actor_deployment: Some(install.entry.deployment),
                evidence: approval.evidence.clone(),
                lane_roots: approval.lane_roots,
                epoch: 1,
                decision_sequence: 1,
                acknowledged_through: 0,
                valid_from: 10,
                expires_at: 30,
                request: approval.plan_commitment,
            },
            public_key: authority.binding.public_key,
            signature: [0; 64],
        };
        receipt.signature = operator
            .sign(&receipt.signing_bytes())
            .unwrap()
            .try_into()
            .unwrap();
        let mut ack = ManagementApplicationAck {
            authorization_invocation: call.invocation,
            acknowledgement_invocation: approval.acknowledgement_invocation,
            authority,
            managed: call.managed,
            credential_call: call.commitment(),
            approval: approval.commitment(),
            authorization_sequence: approval.authorization_sequence,
            request: approval.plan_commitment,
            receipt,
            application: ManagementReply::Installed(install.entry.clone()),
            reopened_state: Hash([11; 32]),
            applied_at: 20,
            signature: [0; 64],
        };
        ack.signature = operator
            .sign(&ack.signing_bytes())
            .unwrap()
            .try_into()
            .unwrap();
        (request, ack, operator)
    }

    #[test]
    fn install_reservation_requires_durable_exact_completion_and_serializes_successors() {
        use super::super::clean_store::{
            CleanCredentialReservation, CleanFileStoreError, CleanLocalInstallFile,
            CredentialReservationStatus, ensure_private_directory,
        };
        use std::os::unix::fs::DirBuilderExt as _;
        let (request, ack, _) = fixture();
        let (install, call, _) = LocalInstallSubmission::decode(&request)
            .unwrap()
            .into_parts();
        let nonce = Hash(install.installation_id.0);
        let mut random = [0; 8];
        getrandom::getrandom(&mut random).unwrap();
        let directory =
            std::env::temp_dir().join(format!("vosx-install-reservation-{}", hex::encode(random)));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let claims = directory.join("claims");
        let _claims = ensure_private_directory(&claims).unwrap();
        let mut reservation = CleanCredentialReservation::open_or_create(
            &claims,
            call.managed.space,
            call.credential,
        )
        .unwrap();
        assert!(matches!(
            CleanCredentialReservation::open_or_create(
                &claims,
                call.managed.space,
                call.credential
            ),
            Err(CleanFileStoreError::Busy)
        ));
        assert_eq!(
            reservation.reserve(nonce).unwrap(),
            CredentialReservationStatus::Pending
        );
        let successor = Hash([0x71; 32]);
        assert!(matches!(
            reservation.reserve(successor),
            Err(CleanFileStoreError::RequestConflict)
        ));
        let mut delivery =
            CleanLocalInstallFile::open_or_create(directory.join("request")).unwrap();
        delivery.publish_request(&request).unwrap();
        assert!(reservation.complete_install(&mut delivery).is_err());
        assert_eq!(
            reservation.current().unwrap(),
            Some((nonce, CredentialReservationStatus::Pending))
        );
        delivery
            .publish_acknowledgement(&ack.encode().unwrap())
            .unwrap();
        reservation.complete_install(&mut delivery).unwrap();
        reservation.complete_install(&mut delivery).unwrap();
        assert_eq!(
            reservation.current().unwrap(),
            Some((nonce, CredentialReservationStatus::Completed))
        );
        drop(reservation);
        let mut reservation = CleanCredentialReservation::open_or_create(
            &claims,
            call.managed.space,
            call.credential,
        )
        .unwrap();
        reservation.complete_install(&mut delivery).unwrap();
        assert_eq!(
            reservation.reserve(successor).unwrap(),
            CredentialReservationStatus::Pending
        );
        assert!(reservation.complete_install(&mut delivery).is_err());
        assert_eq!(
            reservation.current().unwrap(),
            Some((successor, CredentialReservationStatus::Pending))
        );
        let mut other = CleanCredentialReservation::open_or_create(
            &claims,
            vos::agent::sdk::SpaceId([0x72; 32]),
            call.credential,
        )
        .unwrap();
        other.reserve(nonce).unwrap();
        assert!(other.complete_install(&mut delivery).is_err());
        drop(other);
        drop(reservation);
        drop(delivery);
        drop(_claims);
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn retained_install_transport_preserves_request_and_verifies_before_completion() {
        use super::super::clean_store::{CleanFileStoreError, CleanLocalInstallFile};
        use std::io::{Read as _, Write as _};
        use std::os::unix::fs::DirBuilderExt as _;
        let (request, ack, _) = fixture();
        let encoded = ack.encode().unwrap();
        for (status, content_type, body, success) in [
            (201, "application/octet-stream", encoded.clone(), true),
            (503, "application/octet-stream", encoded.clone(), false),
            (403, "application/octet-stream", encoded.clone(), false),
            (302, "application/octet-stream", encoded.clone(), false),
            (201, "text/plain", encoded.clone(), false),
            (
                201,
                "application/octet-stream",
                encoded[..encoded.len() - 1].to_vec(),
                false,
            ),
        ] {
            let mut nonce = [0; 8];
            getrandom::getrandom(&mut nonce).unwrap();
            let directory =
                std::env::temp_dir().join(format!("vosx-install-http-{}", hex::encode(nonce)));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&directory)
                .unwrap();
            let root = directory.join("request");
            CleanLocalInstallFile::open_or_create(&root)
                .unwrap()
                .publish_request(&request)
                .unwrap();
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            listener.set_nonblocking(true).unwrap();
            let expected = request.clone();
            let leased = root.clone();
            let server = std::thread::spawn(move || {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(
                                std::time::Instant::now() < deadline,
                                "client did not connect"
                            );
                            std::thread::sleep(std::time::Duration::from_millis(10));
                        }
                        Err(error) => panic!("accept: {error}"),
                    }
                };
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                let mut headers = Vec::new();
                while !headers.ends_with(b"\r\n\r\n") {
                    assert!(headers.len() < 8192);
                    let mut byte = [0];
                    stream.read_exact(&mut byte).unwrap();
                    headers.push(byte[0]);
                }
                assert!(headers.starts_with(b"POST /__agents/local/install HTTP/1.1\r\n"));
                let mut received = vec![0; expected.len()];
                stream.read_exact(&mut received).unwrap();
                assert_eq!(received, expected);
                assert!(matches!(
                    CleanLocalInstallFile::open_or_create(&leased),
                    Err(CleanFileStoreError::Busy)
                ));
                write!(stream, "HTTP/1.1 {status} Result\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
                stream.write_all(&body).unwrap();
            });
            let result = submit_retained(&root, address);
            server.join().unwrap();
            assert_eq!(result.is_ok(), success, "status={status}: {result:?}");
            let mut store = CleanLocalInstallFile::open_or_create(&root).unwrap();
            assert_eq!(store.load_request().unwrap(), Some(request.clone()));
            assert_eq!(
                store.load_acknowledgement().unwrap(),
                success.then(|| encoded.clone())
            );
            drop(store);
            if success {
                assert_eq!(submit_retained(&root, address).unwrap(), ack);
            }
            std::fs::remove_dir_all(&directory).unwrap();
        }
    }

    #[test]
    fn exact_install_acknowledgement_and_immutable_storage() {
        use super::super::clean_store::{CleanFileStoreError, CleanLocalInstallFile};
        use std::os::unix::fs::DirBuilderExt as _;
        let (request, ack, operator) = fixture();
        let response = ack.encode().unwrap();
        assert_eq!(verify_acknowledgement(&request, &response).unwrap(), ack);
        let mut wrong = ack.clone();
        wrong.signature[0] ^= 1;
        assert!(verify_acknowledgement(&request, &wrong.encode().unwrap()).is_err());
        wrong = ack.clone();
        wrong.receipt.signature[0] ^= 1;
        wrong.signature = operator
            .sign(&wrong.signing_bytes())
            .unwrap()
            .try_into()
            .unwrap();
        assert!(verify_acknowledgement(&request, &wrong.encode().unwrap()).is_err());
        wrong = ack.clone();
        if let ManagementReply::Installed(entry) = &mut wrong.application {
            entry.suspended = true;
        }
        wrong.signature = operator
            .sign(&wrong.signing_bytes())
            .unwrap()
            .try_into()
            .unwrap();
        assert!(verify_acknowledgement(&request, &wrong.encode().unwrap()).is_err());
        assert!(verify_acknowledgement(&request, &response[..response.len() - 1]).is_err());
        let mut nonce = [0; 8];
        getrandom::getrandom(&mut nonce).unwrap();
        let directory =
            std::env::temp_dir().join(format!("vosx-install-client-{}", hex::encode(nonce)));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let root = directory.join("request");
        let mut store = CleanLocalInstallFile::open_or_create(&root).unwrap();
        assert!(matches!(
            CleanLocalInstallFile::open_or_create(&root),
            Err(CleanFileStoreError::Busy)
        ));
        assert!(store.publish_acknowledgement(&response).is_err());
        store.publish_request(&request).unwrap();
        store.publish_request(&request).unwrap();
        let (install, mut call, package) = LocalInstallSubmission::decode(&request)
            .unwrap()
            .into_parts();
        call.request_sequence = NonZeroU64::new(4).unwrap();
        call.invocation = call.expected_invocation();
        call.signature = operator
            .sign(&call.signing_bytes())
            .unwrap()
            .try_into()
            .unwrap();
        let other_request = LocalInstallSubmission::new(install, call, package)
            .unwrap()
            .encode();
        assert!(matches!(
            store.publish_request(&other_request),
            Err(CleanFileStoreError::RequestConflict)
        ));
        assert!(
            store
                .publish_acknowledgement(&wrong.encode().unwrap())
                .is_err()
        );
        store.publish_acknowledgement(&response).unwrap();
        let mut conflicting = ack.clone();
        conflicting.reopened_state = Hash([12; 32]);
        conflicting.signature = operator
            .sign(&conflicting.signing_bytes())
            .unwrap()
            .try_into()
            .unwrap();
        assert!(verify_acknowledgement(&request, &conflicting.encode().unwrap()).is_ok());
        assert!(matches!(
            store.publish_acknowledgement(&conflicting.encode().unwrap()),
            Err(CleanFileStoreError::RequestConflict)
        ));
        drop(store);
        let mut store = CleanLocalInstallFile::open_or_create(&root).unwrap();
        assert_eq!(store.load_request().unwrap(), Some(request.clone()));
        assert_eq!(store.load_acknowledgement().unwrap(), Some(response));
        drop(store);
        // Retained verified completion is returned without connecting to a daemon.
        assert_eq!(
            submit_retained(&root, "127.0.0.1:1".parse().unwrap()).unwrap(),
            ack
        );
        std::fs::remove_file(root.join("local-install.request")).unwrap();
        let mut orphaned = CleanLocalInstallFile::open_or_create(&root).unwrap();
        assert!(orphaned.load_acknowledgement().is_err());
        assert!(orphaned.publish_request(&request).is_err());
        assert!(!root.join("local-install.request").exists());
        drop(orphaned);
        std::fs::remove_dir_all(&directory).unwrap();
    }
}
