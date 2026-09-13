//! Preparation of an exact signed Local Create request for the native operator.
//!
//! Sequence allocation and durable request-file publication belong to the
//! caller. This module never reads a clock, generates a nonce, loads a key, or
//! submits a request: retries must reuse the persisted LCQ1 bytes.

use std::num::NonZeroU64;

use libp2p::identity::Keypair;
use vos::agent::local_lifecycle::LocalCreateSubmission;
use vos::agent::package_admission::AdmittedRuntimePackage;
use vos::agent::sdk::authority::{
    AuthorityActorTarget, AuthorityCredentialCall, ManagedAgentTarget,
};
use vos::agent::sdk::{AgentDescriptor, InvocationId, ManagementRequest};

use super::clean_identity::CleanOperatorIdentitySigner;

/// Submit an already persisted request to a local daemon. No signing or
/// sequence allocation occurs here; every error leaves the request retained.
pub(crate) fn submit_retained(
    root: &std::path::Path,
    address: std::net::SocketAddr,
) -> anyhow::Result<vos::agent::sdk::authority::ManagementApplicationAck> {
    use super::clean_store::CleanLocalCreateRequestFile;
    use std::io::Read as _;
    use std::time::Duration;
    use vos::agent::sdk::wire::MAX_MANAGEMENT_APPLICATION_ACK_WIRE_BYTES;
    anyhow::ensure!(
        address.ip().is_loopback() && address.port() != 0,
        "plaintext Local Create submission requires a nonzero loopback address"
    );
    let mut store = CleanLocalCreateRequestFile::open_or_create(root)?;
    let bytes = store
        .load()?
        .ok_or_else(|| anyhow::anyhow!("no retained Local Create request"))?;
    let result = (|| -> anyhow::Result<_> {
        let agent = ureq::AgentBuilder::new()
            .try_proxy_from_env(false)
            .redirects(0)
            .timeout_connect(Duration::from_secs(5))
            .timeout(Duration::from_secs(130))
            .build();
        let response = agent
            .post(&format!("http://{address}/__agents/local"))
            .set("Content-Type", "application/octet-stream")
            .send_bytes(&bytes)
            .map_err(|error| anyhow::anyhow!("Local Create HTTP submission failed: {error}"))?;
        anyhow::ensure!(
            response.status() == 201,
            "Local Create expected HTTP 201, received {}",
            response.status()
        );
        anyhow::ensure!(
            response.header("Content-Type") == Some("application/octet-stream"),
            "Local Create acknowledgement has unexpected content type"
        );
        let mut reply = Vec::new();
        response
            .into_reader()
            .take((MAX_MANAGEMENT_APPLICATION_ACK_WIRE_BYTES + 1) as u64)
            .read_to_end(&mut reply)?;
        anyhow::ensure!(
            reply.len() <= MAX_MANAGEMENT_APPLICATION_ACK_WIRE_BYTES,
            "Local Create acknowledgement exceeds the wire limit"
        );
        verify_acknowledgement(&bytes, &reply)
    })();
    // The store and its exclusive lease remain alive through verification.
    result.map_err(|error| {
        anyhow::anyhow!(
            "{error}; request retained: retry these exact bytes, outcome may be unknown"
        )
    })
}

pub(crate) fn run_submit(
    root: &std::path::Path,
    address: std::net::SocketAddr,
) -> anyhow::Result<()> {
    use vos::agent::sdk::wire::CanonicalWire as _;
    let ack = submit_retained(root, address)?;
    let agent = hex::encode(ack.managed.agent.0);
    if crate::output::is_json() {
        crate::output::print_json(&serde_json::json!({
            "agent": agent,
            "acknowledgement": hex::encode(ack.encode().map_err(|error| anyhow::anyhow!("encode acknowledgement: {error:?}"))?),
        }));
    } else {
        println!("Local Agent {agent}: verified creation acknowledgement");
    }
    Ok(())
}

/// Verify a response against the retained request, never a key supplied only
/// by the response. This verifies the issuer's application claim, not an
/// independent replay proof or proof of HTTP route publication.
pub(crate) fn verify_acknowledgement(
    request: &[u8],
    response: &[u8],
) -> anyhow::Result<vos::agent::sdk::authority::ManagementApplicationAck> {
    use vos::agent::sdk::authority::{
        AuthorityVerifier, ManagementApplicationAck, ManagementApproval,
    };
    use vos::agent::sdk::wire::CanonicalWire as _;

    struct Verifier;
    impl AuthorityVerifier for Verifier {
        fn verify(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
            libp2p::identity::ed25519::PublicKey::try_from_bytes(public_key)
                .is_ok_and(|key| key.verify(message, signature))
        }
    }

    let submission = LocalCreateSubmission::decode(request)
        .map_err(|error| anyhow::anyhow!("invalid retained Local Create: {error:?}"))?;
    let (_, call, _) = submission.into_parts();
    anyhow::ensure!(
        call.authenticated_node.is_none(),
        "retained request is not HTTP-compatible"
    );
    let ack = ManagementApplicationAck::decode(response)
        .map_err(|error| anyhow::anyhow!("invalid Local Create acknowledgement: {error:?}"))?;
    anyhow::ensure!(
        ack.authority == call.authority,
        "acknowledgement Authority differs from retained request"
    );
    ack.verify_with(&Verifier)
        .map_err(|error| anyhow::anyhow!("invalid acknowledgement signature: {error:?}"))?;
    let selector = &ack.receipt.selector;
    let approval = ManagementApproval::from_call(
        &call,
        ack.authorization_sequence,
        selector.evidence.clone(),
        selector.lane_roots,
        selector.epoch,
        selector.valid_from,
        selector.expires_at,
    )
    .map_err(|error| {
        anyhow::anyhow!("acknowledgement approval differs from retained request: {error:?}")
    })?;
    anyhow::ensure!(
        ack.matches_pending(&call, &approval),
        "acknowledgement does not match the exact retained Local Create"
    );
    Ok(ack)
}

pub(crate) fn prepare(
    operator: &Keypair,
    authority: AuthorityActorTarget,
    descriptor: AgentDescriptor,
    runtime: AdmittedRuntimePackage,
    sequence: NonZeroU64,
    valid_from: u64,
    expires_at: u64,
) -> anyhow::Result<LocalCreateSubmission> {
    let identity = CleanOperatorIdentitySigner::new(operator)?;
    anyhow::ensure!(
        descriptor.identity.owner == identity.principal(),
        "operator Local Create requires the operator as owner"
    );
    let managed = ManagedAgentTarget {
        space: descriptor.identity.space,
        agent: descriptor.identity.agent,
        owner: descriptor.identity.owner,
        profile: descriptor.identity.profile,
        runtime_deployment: descriptor.identity.runtime_deployment,
        transition_producer: descriptor.identity.transition_producer,
    };
    let request = ManagementRequest::Create(Box::new(descriptor.clone()));
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
            .ok_or_else(|| anyhow::anyhow!("invalid Local Create authorization plan"))?,
        signature: [0; 64],
    };
    call.invocation = call.expected_invocation();
    call.signature = operator
        .sign(&call.signing_bytes())
        .map_err(|_| anyhow::anyhow!("Local Create signing failed"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Local Create signature must be Ed25519"))?;
    LocalCreateSubmission::new(descriptor, call, runtime)
        .map_err(|error| anyhow::anyhow!("invalid signed Local Create: {error:?}"))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use vos::agent::sdk::authority::{AgentAuthorityBinding, AuthorityIssuer};
    use vos::agent::sdk::{
        ActorId, AgentId, AgentIdentity, AgentProfile, AgentReplica, DeploymentId, Hash, NodeId,
        ProducerId, ProgramId, ReplicaRole, SpaceId,
    };

    pub(crate) fn fixture() -> (
        Keypair,
        AuthorityActorTarget,
        AgentDescriptor,
        AdmittedRuntimePackage,
    ) {
        let operator = Keypair::ed25519_from_bytes([0x63; 32]).unwrap();
        let signer = CleanOperatorIdentitySigner::new(&operator).unwrap();
        let runtime = crate::bundled::root_signed_agent_runtime_package(&operator).unwrap();
        let space = SpaceId([1; 32]);
        let nonce = Hash([2; 32]);
        let binding = AgentAuthorityBinding {
            policy: Hash([3; 32]),
            issuer: AuthorityIssuer {
                principal: signer.principal(),
                actor: ActorId([4; 32]),
                deployment: DeploymentId([5; 32]),
                program: ProgramId([6; 32]),
                producer: ProducerId::of_public_key(&signer.raw_public_key()),
            },
            public_key: signer.raw_public_key(),
            initial_epoch: 1,
        };
        let authority = AuthorityActorTarget {
            space,
            system_agent: AgentId([7; 32]),
            system_runtime_deployment: runtime.deployment(),
            binding,
        };
        let descriptor = AgentDescriptor {
            identity: AgentIdentity {
                space,
                agent: AgentId::derive(space, signer.principal(), nonce.as_bytes()),
                owner: signer.principal(),
                profile: AgentProfile::Local,
                runtime_deployment: runtime.deployment(),
                runtime_program: runtime.program(),
                runtime_producer: runtime.producer(),
                transition_producer: ProducerId([8; 32]),
            },
            creation_nonce: nonce,
            authority: binding,
            private_recovery: None,
            runtime_package: runtime.package_ref().clone(),
            runtime_contract: runtime.manifest().contract,
            capabilities: runtime.capabilities(),
            replicas: vec![AgentReplica {
                node: NodeId([9; 32]),
                principal: signer.principal(),
                role: ReplicaRole::Voter,
            }],
        };
        (operator, authority, descriptor, runtime)
    }

    #[test]
    fn exact_inputs_produce_identical_http_compatible_signed_submissions() {
        let (operator, authority, descriptor, runtime) = fixture();
        let sequence = NonZeroU64::new(2).unwrap();
        let first = prepare(
            &operator,
            authority,
            descriptor.clone(),
            runtime.clone(),
            sequence,
            10,
            30,
        )
        .unwrap()
        .encode();
        let repeated = prepare(
            &operator,
            authority,
            descriptor.clone(),
            runtime.clone(),
            sequence,
            10,
            30,
        )
        .unwrap()
        .encode();
        assert_eq!(first, repeated);
        assert!(first.len() <= 1024 * 1024);
        let (_, call, _) = LocalCreateSubmission::decode(&first).unwrap().into_parts();
        assert_eq!(call.authenticated_node, None);
        assert_eq!(call.request_sequence, sequence);
        assert_eq!(
            (call.requested_valid_from, call.requested_expires_at),
            (10, 30)
        );
        let changed = prepare(
            &operator,
            authority,
            descriptor,
            runtime,
            NonZeroU64::new(3).unwrap(),
            10,
            30,
        )
        .unwrap();
        assert_ne!(changed.into_parts().1.invocation, call.invocation);
    }

    #[test]
    fn acknowledgement_requires_both_signatures_and_exact_request_and_reply() {
        use vos::agent::sdk::authority::{
            AuthorityEvidence, AuthorityLaneRoots, AuthorityReceipt, AuthorityReceiptSelector,
            ManagementApplicationAck, ManagementApproval,
        };
        use vos::agent::sdk::{ManagementReply, wire::CanonicalWire as _};
        let (operator, authority, descriptor, runtime) = fixture();
        let request = prepare(
            &operator,
            authority,
            descriptor.clone(),
            runtime.clone(),
            NonZeroU64::new(2).unwrap(),
            10,
            30,
        )
        .unwrap()
        .encode();
        let (_, call, _) = LocalCreateSubmission::decode(&request)
            .unwrap()
            .into_parts();
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
                actor: None,
                actor_deployment: None,
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
            application: ManagementReply::Created(descriptor.identity.clone()),
            reopened_state: Hash([11; 32]),
            applied_at: 20,
            signature: [0; 64],
        };
        let sign = |ack: &mut ManagementApplicationAck| {
            ack.signature = operator
                .sign(&ack.signing_bytes())
                .unwrap()
                .try_into()
                .unwrap();
        };
        sign(&mut ack);
        let bytes = ack.encode().unwrap();
        assert_eq!(verify_acknowledgement(&request, &bytes).unwrap(), ack);
        let mut http = format!("HTTP/1.1 201 Created\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", bytes.len()).into_bytes();
        http.extend_from_slice(&bytes);
        assert_eq!(submit_fixture(&request, &http).unwrap(), ack);
        for response in [
            b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/elsewhere\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_slice(),
            b"HTTP/1.1 503 Busy\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_slice(),
            b"HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_slice(),
            b"HTTP/1.1 201 Created\r\nContent-Type: application/octet-stream\r\nContent-Length: 4\r\nConnection: close\r\n\r\nMAA2".as_slice(),
        ] {
            assert!(submit_fixture(&request, response).unwrap_err().to_string().contains("request retained"));
        }
        let size = vos::agent::sdk::wire::MAX_MANAGEMENT_APPLICATION_ACK_WIRE_BYTES + 1;
        let mut oversized = format!("HTTP/1.1 201 Created\r\nContent-Type: application/octet-stream\r\nContent-Length: {size}\r\nConnection: close\r\n\r\n").into_bytes();
        oversized.resize(oversized.len() + size, 0);
        assert!(
            submit_fixture(&request, &oversized)
                .unwrap_err()
                .to_string()
                .contains("wire limit")
        );
        assert!(verify_acknowledgement(&request, &bytes[..bytes.len() - 1]).is_err());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(verify_acknowledgement(&request, &trailing).is_err());
        let other_request = prepare(
            &operator,
            authority,
            descriptor,
            runtime,
            NonZeroU64::new(3).unwrap(),
            10,
            30,
        )
        .unwrap()
        .encode();
        assert!(verify_acknowledgement(&other_request, &bytes).is_err());
        let mut forged = ack.clone();
        forged.signature[0] ^= 1;
        assert!(verify_acknowledgement(&request, &forged.encode().unwrap()).is_err());
        forged = ack.clone();
        forged.receipt.signature[0] ^= 1;
        sign(&mut forged);
        assert!(verify_acknowledgement(&request, &forged.encode().unwrap()).is_err());
        forged = ack.clone();
        forged.approval = Hash([12; 32]);
        sign(&mut forged);
        assert!(verify_acknowledgement(&request, &forged.encode().unwrap()).is_err());
        forged = ack.clone();
        forged.authority.system_agent = AgentId([14; 32]);
        sign(&mut forged);
        assert!(verify_acknowledgement(&request, &forged.encode().unwrap()).is_err());
        forged = ack;
        let ManagementReply::Created(identity) = &mut forged.application else {
            unreachable!()
        };
        identity.runtime_program = ProgramId([13; 32]);
        sign(&mut forged);
        assert!(verify_acknowledgement(&request, &forged.encode().unwrap()).is_err());
    }

    fn submit_fixture(
        request: &[u8],
        response: &[u8],
    ) -> anyhow::Result<vos::agent::sdk::authority::ManagementApplicationAck> {
        use super::super::clean_store::{CleanFileStoreError, CleanLocalCreateRequestFile};
        use std::io::{Read as _, Write as _};
        use std::os::unix::fs::DirBuilderExt as _;
        struct Directory(std::path::PathBuf);
        impl Drop for Directory {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let mut nonce = [0; 8];
        getrandom::getrandom(&mut nonce).unwrap();
        let dir = Directory(
            std::env::temp_dir().join(format!("vosx-local-submit-{}", hex::encode(nonce))),
        );
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir.0)
            .unwrap();
        let root = dir.0.join("request");
        CleanLocalCreateRequestFile::open_or_create(&root)
            .unwrap()
            .publish(request)
            .unwrap();
        let expected = request.to_vec();
        let response = response.to_vec();
        let leased_root = root.clone();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let server = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "client never connected"
                        );
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(error) => panic!("accept: {error}"),
                }
            };
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                assert!(header.len() < 8192);
                let mut byte = [0];
                stream.read_exact(&mut byte).unwrap();
                header.push(byte[0]);
            }
            assert!(header.starts_with(b"POST /__agents/local HTTP/1.1\r\n"));
            let mut body = vec![0; expected.len()];
            stream.read_exact(&mut body).unwrap();
            assert_eq!(body, expected);
            assert!(matches!(
                CleanLocalCreateRequestFile::open_or_create(leased_root),
                Err(CleanFileStoreError::Busy)
            ));
            let _ = stream.write_all(&response);
        });
        let result = submit_retained(&root, address);
        server.join().unwrap();
        assert_eq!(
            CleanLocalCreateRequestFile::open_or_create(&root)
                .unwrap()
                .load()
                .unwrap()
                .unwrap(),
            request
        );
        result
    }

    #[test]
    fn preparation_rejects_wrong_owner_scope_window_and_runtime() {
        let (operator, authority, descriptor, runtime) = fixture();
        let sequence = NonZeroU64::new(2).unwrap();
        let other = Keypair::ed25519_from_bytes([0x64; 32]).unwrap();
        assert!(
            prepare(
                &other,
                authority,
                descriptor.clone(),
                runtime.clone(),
                sequence,
                10,
                30
            )
            .is_err()
        );
        assert!(
            prepare(
                &operator,
                authority,
                descriptor.clone(),
                runtime.clone(),
                sequence,
                30,
                10
            )
            .is_err()
        );
        let mut wrong_scope = authority;
        wrong_scope.space = SpaceId([99; 32]);
        assert!(
            prepare(
                &operator,
                wrong_scope,
                descriptor.clone(),
                runtime.clone(),
                sequence,
                10,
                30
            )
            .is_err()
        );
        let wrong_runtime = crate::bundled::root_signed_agent_runtime_package(&other).unwrap();
        assert!(
            prepare(
                &operator,
                authority,
                descriptor,
                wrong_runtime,
                sequence,
                10,
                30
            )
            .is_err()
        );
    }
}
