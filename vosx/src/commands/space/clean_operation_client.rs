//! One exclusively leased, immutable operation request and bound signed response.
use super::*;
use vos::agent::local_lifecycle::AuthorityOperationSubmission;
use vos::agent::sdk::wire::CanonicalWire as _;
use vos::agent::supervisor_adapters::{
    AgentTargetedPreparationRequest, AgentTargetedPreparationResponse,
};

#[derive(Clone, Copy)]
enum ClientPairKind {
    AdminPreparation,
    AdminSubmission,
    Operation,
    Preparation,
    AuthorizationPreparation,
}

pub(crate) struct CleanOperationClientFile {
    kind: ClientPairKind,
    request: ExactFileStore,
    response: ExactFileStore,
}

/// Physical preparation is retained separately from signed authorization.
/// Response binding is not proof of Authority approval or live applicability.
pub(crate) struct CleanPreparationClientFile(CleanOperationClientFile);

impl CleanPreparationClientFile {
    pub(crate) fn open_or_create(root: impl AsRef<Path>) -> Result<Self, CleanFileStoreError> {
        CleanOperationClientFile::open_pair(root, ClientPairKind::Preparation).map(Self)
    }

    pub(crate) fn load_request(&mut self) -> Result<Option<Vec<u8>>, CleanFileStoreError> {
        self.0.load_request()
    }

    pub(crate) fn publish_request(&mut self, bytes: &[u8]) -> Result<(), CleanFileStoreError> {
        self.0.publish_request(bytes)
    }

    pub(crate) fn load_response(&mut self) -> Result<Option<Vec<u8>>, CleanFileStoreError> {
        self.0.load_response()
    }

    pub(crate) fn publish_response(&mut self, bytes: &[u8]) -> Result<(), CleanFileStoreError> {
        self.0.publish_response(bytes)
    }
}

impl CleanCredentialReservation {
    /// Complete only the exact receipt-bearing invocation after its retained
    /// positive retirement exchange. Actor-level failure may retire, but an
    /// issuance, yield, HTTP error or failed acknowledgement cannot complete.
    pub(crate) fn complete_operation(
        &mut self,
        authorization: &mut CleanOperationClientFile,
        application: &mut CleanInvocationFile,
    ) -> Result<(), CleanFileStoreError> {
        use vos::agent::clean_bootstrap::NativeAuthorityOperationDecision;
        use vos::agent::sdk::authority_operation::AuthorityOperationIntent;
        use vos::agent::sdk::{Hash, InvocationAuthorization};
        let request = authorization
            .load_request()?
            .ok_or(CleanFileStoreError::RequestConflict)?;
        let decision = authorization
            .load_response()?
            .ok_or(CleanFileStoreError::RequestConflict)?;
        let submission = AuthorityOperationSubmission::decode(&request)
            .map_err(|_| CleanFileStoreError::Corrupt)?;
        let NativeAuthorityOperationDecision::Issued(issued) = submission
            .decode_response(&decision)
            .map_err(|_| CleanFileStoreError::Corrupt)?
        else {
            return Err(CleanFileStoreError::RequestConflict);
        };
        let call = submission.call();
        let AuthorityOperationIntent::InvokeActor {
            managed,
            operation_invocation,
            ..
        } = &call.intent
        else {
            return Err(CleanFileStoreError::Corrupt);
        };
        if call.authority.space != self.space
            || managed.space != self.space
            || call.credential != self.credential
        {
            return Err(CleanFileStoreError::Corrupt);
        }
        let invocation = application
            .load_request()?
            .ok_or(CleanFileStoreError::RequestConflict)?;
        let response = application
            .load_response()?
            .ok_or(CleanFileStoreError::RequestConflict)?;
        let history = application
            .load_progress()?
            .ok_or(CleanFileStoreError::RequestConflict)?;
        let envelope = super::super::local_invocation::validate_request(&invocation)
            .map_err(|_| CleanFileStoreError::Corrupt)?;
        if !call.intent.matches_invocation_work(envelope.work())
            || envelope.authorization()
                != &InvocationAuthorization::AuthorityReceipt(issued.receipt)
        {
            return Err(CleanFileStoreError::Corrupt);
        }
        let progress =
            super::super::invocation_progress::Progress::decode(&history, &invocation, &response)
                .map_err(|_| CleanFileStoreError::Corrupt)?;
        if !progress
            .is_retired(&invocation, &response)
            .map_err(|_| CleanFileStoreError::Corrupt)?
        {
            return Err(CleanFileStoreError::RequestConflict);
        }
        let nonce = Hash(operation_invocation.0);
        let current = self.load()?.ok_or(CleanFileStoreError::RequestConflict)?;
        if current[68..100] != nonce.0 {
            return Err(CleanFileStoreError::RequestConflict);
        }
        let completed = self.image(
            nonce,
            Some((
                Hash::digest(b"vos/agent-operation/retained-request/v1", &[&request]),
                Hash::digest(
                    b"vos/agent-operation/retained-application/v1",
                    &[&invocation, &response, &history],
                ),
            )),
        );
        if current[100] != 0 && current != completed {
            return Err(CleanFileStoreError::RequestConflict);
        }
        self.store.commit(&completed)
    }

    /// Release an invocation reservation only after its exact signed denial
    /// has been verified and synchronized under the delivery lease. Issuance
    /// is not application completion and cannot release the reservation here.
    pub(crate) fn deny_operation(
        &mut self,
        delivery: &mut CleanOperationClientFile,
    ) -> Result<(), CleanFileStoreError> {
        use vos::agent::clean_bootstrap::NativeAuthorityOperationDecision;
        use vos::agent::sdk::Hash;
        use vos::agent::sdk::authority_operation::AuthorityOperationIntent;
        let request = delivery
            .load_request()?
            .ok_or(CleanFileStoreError::RequestConflict)?;
        let response = delivery
            .load_response()?
            .ok_or(CleanFileStoreError::RequestConflict)?;
        let submission = AuthorityOperationSubmission::decode(&request)
            .map_err(|_| CleanFileStoreError::Corrupt)?;
        let call = submission.call();
        let AuthorityOperationIntent::InvokeActor {
            managed,
            operation_invocation,
            ..
        } = &call.intent
        else {
            return Err(CleanFileStoreError::Corrupt);
        };
        if call.authority.space != self.space
            || managed.space != self.space
            || call.credential != self.credential
        {
            return Err(CleanFileStoreError::Corrupt);
        }
        if !matches!(
            submission
                .decode_response(&response)
                .map_err(|_| CleanFileStoreError::Corrupt)?,
            NativeAuthorityOperationDecision::Denied { .. }
        ) {
            return Err(CleanFileStoreError::RequestConflict);
        }
        let nonce = Hash(operation_invocation.0);
        let current = self.load()?.ok_or(CleanFileStoreError::RequestConflict)?;
        if current[68..100] != nonce.0 {
            return Err(CleanFileStoreError::RequestConflict);
        }
        let mut denied = self.image(
            nonce,
            Some((
                Hash::digest(b"vos/agent-operation/retained-request/v1", &[&request]),
                Hash::digest(b"vos/agent-operation/retained-denial/v1", &[&response]),
            )),
        );
        denied[100] = 2;
        if current[100] != 0 && current != denied {
            return Err(CleanFileStoreError::RequestConflict);
        }
        self.store.commit(&denied)
    }
}

#[cfg(test)]
mod tests {
    use super::super::operation_journal_tests::submission;
    use super::super::tests::Fixture;
    use super::*;
    use vos::agent::clean_bootstrap::NativeAuthorityOperationDecision;

    #[test]
    fn authorization_preparation_retains_call_across_http_failures_and_reopen() {
        use crate::commands::space::operation_authorization::prepare_retained;
        use std::io::{Read as _, Write as _};
        let fixture = Fixture::new("authorization-preparation");
        let prepared = submission(1);
        let call = prepared.call().encode().unwrap();
        let response = prepared.encode().unwrap();
        let mut store =
            CleanOperationClientFile::open_authorization_preparation(&fixture.root).unwrap();
        store.publish_request(&call).unwrap();
        assert!(
            store
                .publish_request(&submission(2).call().encode().unwrap())
                .is_err()
        );
        drop(store);
        for (status, body, minimum, success) in [
            (504, Vec::new(), 20, false),
            (200, submission(2).encode().unwrap(), 20, false),
            (200, response.clone(), 21, false),
            (200, response.clone(), 20, true),
        ] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let expected = call.clone();
            let root = fixture.root.clone();
            let server = std::thread::spawn(move || {
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
                assert!(header.starts_with(b"POST /__agents/prepare-authorization HTTP/1.1\r\n"));
                let mut request = vec![0; expected.len()];
                stream.read_exact(&mut request).unwrap();
                assert_eq!(request, expected);
                assert!(matches!(
                    CleanOperationClientFile::open_authorization_preparation(root),
                    Err(CleanFileStoreError::Busy)
                ));
                write!(stream, "HTTP/1.1 {status} Test\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
                let _ = stream.write_all(&body);
            });
            let mut store =
                CleanOperationClientFile::open_authorization_preparation(&fixture.root).unwrap();
            let result = prepare_retained(&mut store, address, minimum);
            assert_eq!(result.is_ok(), success, "{result:?}");
            server.join().unwrap();
            assert_eq!(store.load_request().unwrap().unwrap(), call);
            assert_eq!(store.load_response().unwrap().is_some(), success);
        }
        let mut store =
            CleanOperationClientFile::open_authorization_preparation(&fixture.root).unwrap();
        assert_eq!(
            prepare_retained(&mut store, "127.0.0.1:1".parse().unwrap(), 20).unwrap(),
            response
        );
        super::super::tests::stage(&store.response, None, b"invalid AOQ1");
        let staged =
            fs::read(fixture.root.join("authorization-preparation.response.next")).unwrap();
        assert!(store.load_response().is_err());
        assert_eq!(
            fs::read(fixture.root.join("authorization-preparation.response.next")).unwrap(),
            staged
        );
    }

    #[test]
    fn authorization_preparation_rejects_orphan_and_invalid_signature_without_repair() {
        let fixture = Fixture::new("authorization-preparation-orphan");
        let mut store =
            CleanOperationClientFile::open_authorization_preparation(&fixture.root).unwrap();
        let prepared = submission(1);
        let mut invalid = prepared.call().clone();
        if let vos::agent::sdk::authority::AuthorityIngressAuthentication::ApiCredentialSignature { signature, .. } = &mut invalid.authentication {
            signature[0] ^= 1;
        }
        assert!(store.publish_request(&invalid.encode().unwrap()).is_err());
        assert!(store.load_request().unwrap().is_none());
        super::super::tests::stage(&store.response, None, &prepared.encode().unwrap());
        assert!(
            store
                .publish_request(&prepared.call().encode().unwrap())
                .is_err()
        );
        assert!(store.load_request().unwrap().is_none());
        assert!(
            fixture
                .root
                .join("authorization-preparation.response.next")
                .exists()
        );
    }

    // Synthetic source/input commitments test signature binding and storage,
    // not native execution. Native denial proof is tested in the library.
    fn denial(request: &AuthorityOperationSubmission) -> Vec<u8> {
        let (key, _, _, _) = crate::commands::space::local_create::tests::fixture();
        let (_, _, dispatch) = super::super::operation_journal_tests::record_scoped(
            request.call().request_sequence.get(),
            100,
            Some((
                request.call().authority,
                request.call().intent.managed().transition_producer,
            )),
        );
        let fields = [
            request.call().invocation.0,
            vos::agent::sdk::Hash::digest(b"vos/agent/native-operation-dispatch/v1", &[&dispatch])
                .0,
            request.call().commitment().0,
            [0x66; 32],
        ]
        .concat();
        let abi = vos::agent::sdk::RUNTIME_ABI_ID.as_bytes();
        let mut signed = b"vos/agent/native-operation-denial-retirement/v1".to_vec();
        signed.extend_from_slice(abi);
        signed.extend_from_slice(&fields);
        let mut bytes = b"NDR1".to_vec();
        bytes.extend_from_slice(abi);
        bytes.extend_from_slice(&fields);
        bytes.extend_from_slice(&64u32.to_le_bytes());
        bytes.extend_from_slice(&key.sign(&signed).unwrap());
        request
            .encode_response(&NativeAuthorityOperationDecision::Denied {
                certificate: bytes,
                dispatch,
            })
            .unwrap()
    }

    #[test]
    fn managed_operation_resume_skips_discovery_and_releases_only_retained_denial() {
        use std::io::{Read as _, Write as _};
        use vos::agent::sdk::{Hash, ProducerId};
        let fixture = Fixture::new("managed-operation");
        let (operator, old_authority, _, runtime) =
            crate::commands::space::local_create::tests::fixture();
        let identity =
            crate::commands::space::clean_identity::CleanOperatorIdentitySigner::new(&operator)
                .unwrap();
        let package = crate::bundled::root_signed_actor_package(
            crate::bundled::system_authority_package_template(),
            "system-authority",
            &operator,
        )
        .unwrap();
        let (authority, _) = crate::commands::space::clean_startup::derive_system_authority_target(
            old_authority.space,
            identity.raw_public_key(),
            &runtime,
            &package,
        )
        .unwrap();
        let node = [0x42; 32];
        let request = super::super::operation_journal_tests::submission_scoped(
            1,
            Some((authority, ProducerId::of_public_key(&node))),
        );
        let bytes = request.encode().unwrap();
        let response = denial(&request);
        let root = fixture.parent.join("agent-client");
        ensure_private_directory(&root).unwrap();
        let claims = root.join("credentials");
        ensure_private_directory(&claims).unwrap();
        let mut reservation = CleanCredentialReservation::open_or_create(
            &claims,
            authority.space,
            identity.credential(),
        )
        .unwrap();
        let nonce = Hash([0x61; 32]);
        reservation.reserve(nonce).unwrap();
        drop(reservation);
        let operations = root.join("operations");
        ensure_private_directory(&operations).unwrap();
        let operation = operations.join(format!(
            "{}-{}",
            hex::encode(identity.credential().0),
            hex::encode(nonce.0)
        ));
        ensure_private_directory(&operation).unwrap();
        let request_root = operation.join("request");
        let mut store = CleanOperationClientFile::open_or_create(&request_root).unwrap();
        store.publish_request(&bytes).unwrap();
        drop(store);
        let run = |address, node| {
            crate::commands::space::local_operation::authorize(
                &fixture.parent,
                address,
                &operator,
                authority.space,
                node,
                None,
            )
        };
        assert!(run("127.0.0.1:1".parse().unwrap(), [0x43; 32]).is_err());
        for (status, success) in [(504, false), (200, true)] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let expected = bytes.clone();
            let reply = response.clone();
            let server_claims = claims.clone();
            let credential = identity.credential();
            let server = std::thread::spawn(move || {
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
                assert!(header.starts_with(b"POST /__agents/authorize HTTP/1.1\r\n"));
                let mut body = vec![0; expected.len()];
                stream.read_exact(&mut body).unwrap();
                assert_eq!(body, expected);
                assert!(matches!(
                    CleanCredentialReservation::open_or_create(
                        &server_claims,
                        authority.space,
                        credential
                    ),
                    Err(CleanFileStoreError::Busy)
                ));
                write!(stream, "HTTP/1.1 {status} Test\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", reply.len()).unwrap();
                let _ = stream.write_all(&reply);
            });
            let result = run(address, node);
            assert_eq!(result.is_ok(), success, "{result:?}");
            server.join().unwrap();
            let mut reservation = CleanCredentialReservation::open_or_create(
                &claims,
                authority.space,
                identity.credential(),
            )
            .unwrap();
            assert_eq!(
                reservation.current().unwrap(),
                Some((
                    nonce,
                    if success {
                        CredentialReservationStatus::Denied
                    } else {
                        CredentialReservationStatus::Pending
                    }
                ))
            );
            assert!(!operation.join("query").exists());
            assert!(!operation.join("preparation").exists());
        }
        assert_eq!(
            run("127.0.0.1:1".parse().unwrap(), node).unwrap(),
            (request_root, response)
        );
    }

    #[test]
    fn operation_denial_releases_only_its_exact_durable_credential_reservation() {
        use vos::agent::sdk::{CredentialId, Hash, SpaceId};
        let fixture = Fixture::new("operation-reservation");
        let request = submission(1);
        let nonce = Hash([0x61; 32]);
        let space = request.call().authority.space;
        let credential = request.call().credential;
        let mut reservation =
            CleanCredentialReservation::open_or_create(&fixture.parent, space, credential).unwrap();
        reservation.reserve(nonce).unwrap();
        assert!(
            CleanCredentialReservation::open_or_create(&fixture.parent, space, credential).is_err()
        );
        let mut delivery = CleanOperationClientFile::open_or_create(&fixture.root).unwrap();
        assert!(reservation.deny_operation(&mut delivery).is_err());
        delivery
            .publish_request(&request.encode().unwrap())
            .unwrap();
        assert!(reservation.deny_operation(&mut delivery).is_err());
        assert!(reservation.reserve(Hash([0x71; 32])).is_err());
        assert_eq!(
            reservation.current().unwrap(),
            Some((nonce, CredentialReservationStatus::Pending))
        );
        delivery.publish_response(&denial(&request)).unwrap();
        // A published canonical response does not permit releasing the
        // reservation while a conflicting/invalid staged response exists.
        super::super::tests::stage(&delivery.response, None, b"invalid AOR1");
        let staged = fs::read(fixture.root.join("operation.response.next")).unwrap();
        assert!(reservation.deny_operation(&mut delivery).is_err());
        assert_eq!(
            reservation.current().unwrap(),
            Some((nonce, CredentialReservationStatus::Pending))
        );
        assert_eq!(
            fs::read(fixture.root.join("operation.response.next")).unwrap(),
            staged
        );
        fs::remove_file(fixture.root.join("operation.response.next")).unwrap();
        for (space, credential, wrong_nonce) in [
            (SpaceId([0x72; 32]), credential, nonce),
            (space, CredentialId([0x73; 32]), nonce),
        ] {
            let mut other =
                CleanCredentialReservation::open_or_create(&fixture.parent, space, credential)
                    .unwrap();
            other.reserve(wrong_nonce).unwrap();
            assert!(other.deny_operation(&mut delivery).is_err());
            assert_eq!(
                other.current().unwrap(),
                Some((wrong_nonce, CredentialReservationStatus::Pending))
            );
        }
        reservation.deny_operation(&mut delivery).unwrap();
        reservation.deny_operation(&mut delivery).unwrap();
        assert_eq!(
            reservation.current().unwrap(),
            Some((nonce, CredentialReservationStatus::Denied))
        );
        drop(reservation);
        drop(delivery);
        let mut reservation =
            CleanCredentialReservation::open_or_create(&fixture.parent, space, credential).unwrap();
        let mut delivery = CleanOperationClientFile::open_or_create(&fixture.root).unwrap();
        reservation.deny_operation(&mut delivery).unwrap();
        // Same invocation nonce with a different signed sequence/decision must
        // not replace an already committed denial marker.
        let mut other =
            CleanOperationClientFile::open_or_create(fixture.parent.join("other")).unwrap();
        other
            .publish_request(&submission(2).encode().unwrap())
            .unwrap();
        other.publish_response(&denial(&submission(2))).unwrap();
        assert!(reservation.deny_operation(&mut other).is_err());
        reservation.reserve(Hash([0x74; 32])).unwrap();
        assert!(reservation.deny_operation(&mut delivery).is_err());
        assert_eq!(
            reservation.current().unwrap(),
            Some((Hash([0x74; 32]), CredentialReservationStatus::Pending))
        );
    }

    #[test]
    fn operation_client_retains_exact_bound_response_and_exclusive_lease() {
        let fixture = Fixture::new("operation-client");
        let request = submission(1);
        let bytes = request.encode().unwrap();
        let response = denial(&request);
        let mut store = CleanOperationClientFile::open_or_create(&fixture.root).unwrap();
        assert!(store.publish_response(&response).is_err());
        assert!(store.load_request().unwrap().is_none());
        store.publish_request(&bytes).unwrap();
        assert!(matches!(
            CleanOperationClientFile::open_or_create(&fixture.root),
            Err(CleanFileStoreError::Busy)
        ));
        assert!(
            store
                .publish_request(&submission(2).encode().unwrap())
                .is_err()
        );
        assert!(store.publish_response(&denial(&submission(2))).is_err());
        let mut corrupt = response.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(store.publish_response(&corrupt).is_err());
        store.publish_response(&response).unwrap();
        let saved = fs::read(fixture.root.join("operation.response")).unwrap();
        store.publish_request(&bytes).unwrap();
        store.publish_response(&response).unwrap();
        assert_eq!(
            fs::read(fixture.root.join("operation.response")).unwrap(),
            saved
        );
        drop(store);
        let mut reopened = CleanOperationClientFile::open_or_create(&fixture.root).unwrap();
        assert_eq!(reopened.load_request().unwrap(), Some(bytes));
        assert_eq!(reopened.load_response().unwrap(), Some(response));
    }

    #[test]
    fn operation_client_recovers_stages_but_never_repairs_orphan_response() {
        let fixture = Fixture::new("operation-client-stage");
        let request = submission(1);
        let bytes = request.encode().unwrap();
        let response = denial(&request);
        let mut store = CleanOperationClientFile::open_or_create(&fixture.root).unwrap();
        store.publish_request(&bytes).unwrap();
        store.publish_response(&response).unwrap();
        drop(store);
        for name in ["operation.request", "operation.response"] {
            fs::rename(
                fixture.root.join(name),
                fixture.root.join(format!("{name}.next")),
            )
            .unwrap();
        }
        let mut store = CleanOperationClientFile::open_or_create(&fixture.root).unwrap();
        assert_eq!(store.load_response().unwrap(), Some(response));
        assert_eq!(store.load_request().unwrap(), Some(bytes.clone()));
        drop(store);
        let saved = fs::read(fixture.root.join("operation.response")).unwrap();
        fs::rename(
            fixture.root.join("operation.request"),
            fixture.parent.join("held-request"),
        )
        .unwrap();
        let mut store = CleanOperationClientFile::open_or_create(&fixture.root).unwrap();
        assert!(store.load_response().is_err());
        assert!(store.publish_request(&bytes).is_err());
        assert!(!fixture.root.join("operation.request").exists());
        assert_eq!(
            fs::read(fixture.root.join("operation.response")).unwrap(),
            saved
        );
    }

    #[test]
    fn operation_client_preserves_invalid_or_replacing_stages() {
        use super::super::tests::stage;
        let request = submission(1);
        let response = denial(&request);
        for case in 0..3 {
            let fixture = Fixture::new("operation-client-conflict");
            let mut store = CleanOperationClientFile::open_or_create(&fixture.root).unwrap();
            store.publish_request(&request.encode().unwrap()).unwrap();
            store.publish_response(&response).unwrap();
            let current = store
                .response
                .read_optional(
                    store.response.file(),
                    AuthorityOperationSubmission::MAX_RESPONSE_BYTES,
                )
                .unwrap()
                .unwrap();
            let mut candidate = response.clone();
            let predecessor = match case {
                0 => {
                    candidate.push(0);
                    None
                }
                1 => {
                    candidate = denial(&submission(2));
                    None
                }
                _ => Some(current.commitment()),
            };
            stage(&store.response, predecessor, &candidate);
            let canonical = fs::read(fixture.root.join("operation.response")).unwrap();
            let staged = fs::read(fixture.root.join("operation.response.next")).unwrap();
            assert!(store.load_response().is_err());
            assert!(store.publish_response(&response).is_err());
            assert_eq!(
                fs::read(fixture.root.join("operation.response")).unwrap(),
                canonical
            );
            assert_eq!(
                fs::read(fixture.root.join("operation.response.next")).unwrap(),
                staged
            );
        }
        let fixture = Fixture::new("operation-client-invalid-request");
        let mut store = CleanOperationClientFile::open_or_create(&fixture.root).unwrap();
        stage(&store.request, None, b"invalid AOQ1");
        let staged = fs::read(fixture.root.join("operation.request.next")).unwrap();
        assert!(store.load_request().is_err());
        assert!(store.publish_request(&request.encode().unwrap()).is_err());
        assert!(!fixture.root.join("operation.request").exists());
        assert_eq!(
            fs::read(fixture.root.join("operation.request.next")).unwrap(),
            staged
        );
    }

    #[test]
    fn operation_authorization_http_retries_exact_bytes_and_retains_verified_decision() {
        use std::io::{Read as _, Write as _};
        let fixture = Fixture::new("operation-http");
        let request = submission(1);
        let bytes = request.encode().unwrap();
        let response = denial(&request);
        let input = fixture.parent.join("initial.aoq1");
        super::super::tests::write_private(&input, &bytes);
        let mut last_address = None;
        for (status, content_type, body, succeeds) in [
            (503, "application/octet-stream", Vec::new(), false),
            (504, "application/octet-stream", Vec::new(), false),
            (302, "application/octet-stream", response.clone(), false),
            (200, "application/json", response.clone(), false),
            (
                200,
                "application/octet-stream",
                denial(&submission(2)),
                false,
            ),
            (
                200,
                "application/octet-stream",
                response[..response.len() - 1].to_vec(),
                false,
            ),
            (200, "application/octet-stream", response.clone(), true),
        ] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            last_address = Some(address);
            let expected = bytes.clone();
            let root = fixture.root.clone();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                let mut received = Vec::new();
                loop {
                    let mut byte = [0];
                    stream.read_exact(&mut byte).unwrap();
                    received.push(byte[0]);
                    if received.ends_with(b"\r\n\r\n") {
                        break;
                    }
                    assert!(received.len() < 8192);
                }
                assert!(received.starts_with(b"POST /__agents/authorize HTTP/1.1\r\n"));
                let mut body_received = vec![0; expected.len()];
                stream.read_exact(&mut body_received).unwrap();
                assert_eq!(body_received, expected);
                assert!(matches!(
                    CleanOperationClientFile::open_or_create(root),
                    Err(CleanFileStoreError::Busy)
                ));
                write!(stream, "HTTP/1.1 {status} Test\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
                stream.write_all(&body).unwrap();
            });
            let result = crate::commands::space::operation_authorization::submit(
                &fixture.root,
                Some(&input),
                address,
            );
            server.join().unwrap();
            assert_eq!(result.is_ok(), succeeds, "{result:?}");
            let mut store = CleanOperationClientFile::open_or_create(&fixture.root).unwrap();
            assert_eq!(store.load_request().unwrap(), Some(bytes.clone()));
            assert_eq!(
                store.load_response().unwrap(),
                succeeds.then(|| response.clone())
            );
            drop(store);
            if input.exists() {
                fs::rename(&input, fixture.parent.join("held-input")).unwrap();
            }
        }
        // No listener remains, and initial input no longer exists. Exact local
        // completion must still succeed without repreparation or HTTP traffic.
        assert_eq!(
            crate::commands::space::operation_authorization::submit(
                &fixture.root,
                Some(&input),
                last_address.unwrap()
            )
            .unwrap(),
            response
        );
        assert!(
            crate::commands::space::operation_authorization::submit(
                &fixture.root,
                None,
                "192.0.2.1:80".parse().unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn operation_response_denial_requires_exact_call_and_signature() {
        let request = submission(1);
        let response = denial(&request);
        assert!(matches!(
            request.decode_response(&response),
            Ok(NativeAuthorityOperationDecision::Denied { .. })
        ));
        assert!(submission(2).decode_response(&response).is_err());
        let mut context = request.context().clone();
        context.observed_slot += 1;
        let changed_context = AuthorityOperationSubmission::new(
            request.call().clone(),
            context,
            request.issued_at() + 1,
        )
        .unwrap();
        assert!(changed_context.decode_response(&response).is_err());
        for end in 0..response.len() {
            assert!(request.decode_response(&response[..end]).is_err());
        }
        let mut trailing = response.clone();
        trailing.push(0);
        assert!(request.decode_response(&trailing).is_err());
        let mut corrupt = response.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(request.decode_response(&corrupt).is_err());
        let mut wrong_kind = response;
        wrong_kind[4] = 0;
        assert!(request.decode_response(&wrong_kind).is_err());
    }
}

impl CleanOperationClientFile {
    pub(crate) fn open_admin_preparation(
        root: impl AsRef<Path>,
    ) -> Result<Self, CleanFileStoreError> {
        Self::open_pair(root, ClientPairKind::AdminPreparation)
    }
    pub(crate) fn open_admin_submission(
        root: impl AsRef<Path>,
    ) -> Result<Self, CleanFileStoreError> {
        Self::open_pair(root, ClientPairKind::AdminSubmission)
    }
    pub(crate) fn open_authorization_preparation(
        root: impl AsRef<Path>,
    ) -> Result<Self, CleanFileStoreError> {
        Self::open_pair(root, ClientPairKind::AuthorizationPreparation)
    }
    fn candidates(file: &ExactFileStore) -> Result<Vec<Vec<u8>>, CleanFileStoreError> {
        let _guard = file.root.guard()?;
        file.root.audit_entries()?;
        [file.file(), file.stage_file()]
            .into_iter()
            .map(|name| {
                file.read_optional(name, file.role.maximum_bytes())
                    .map(|image| image.map(|image| image.payload))
            })
            .collect::<Result<Vec<_>, _>>()
            .map(|images| images.into_iter().flatten().collect())
    }

    pub(crate) fn open_or_create(root: impl AsRef<Path>) -> Result<Self, CleanFileStoreError> {
        Self::open_pair(root, ClientPairKind::Operation)
    }

    fn open_pair(
        root: impl AsRef<Path>,
        kind: ClientPairKind,
    ) -> Result<Self, CleanFileStoreError> {
        let (request, response) = match kind {
            ClientPairKind::AdminPreparation => (
                StoreRole::AdminPreparationRequest,
                StoreRole::AdminPreparationResponse,
            ),
            ClientPairKind::AdminSubmission => (
                StoreRole::AdminClientRequest,
                StoreRole::AdminClientResponse,
            ),
            ClientPairKind::Operation => {
                (StoreRole::OperationRequest, StoreRole::OperationResponse)
            }
            ClientPairKind::Preparation => (
                StoreRole::PreparationRequest,
                StoreRole::PreparationResponse,
            ),
            ClientPairKind::AuthorizationPreparation => (
                StoreRole::AuthorizationPreparationRequest,
                StoreRole::AuthorizationPreparationResponse,
            ),
        };
        let entries: &'static [&'static str] = match kind {
            ClientPairKind::AdminPreparation => &[
                LOCK_FILE,
                "admin-preparation.request",
                "admin-preparation.request.next",
                "admin-preparation.response",
                "admin-preparation.response.next",
            ],
            ClientPairKind::AdminSubmission => &[
                LOCK_FILE,
                "admin-client.request",
                "admin-client.request.next",
                "admin-client.response",
                "admin-client.response.next",
            ],
            ClientPairKind::AuthorizationPreparation => &[
                LOCK_FILE,
                "authorization-preparation.request",
                "authorization-preparation.request.next",
                "authorization-preparation.response",
                "authorization-preparation.response.next",
            ],
            ClientPairKind::Operation => &[
                LOCK_FILE,
                "operation.request",
                "operation.request.next",
                "operation.response",
                "operation.response.next",
            ],
            ClientPairKind::Preparation => &[
                LOCK_FILE,
                "preparation.request",
                "preparation.request.next",
                "preparation.response",
                "preparation.response.next",
            ],
        };
        let root = Arc::new(StoreRoot::open_with_entries(root.as_ref(), entries)?);
        Ok(Self {
            kind,
            request: ExactFileStore::new(root.clone(), request),
            response: ExactFileStore::new(root, response),
        })
    }

    fn validate_request(&self, bytes: &[u8]) -> Result<(), CleanFileStoreError> {
        match self.kind {
            ClientPairKind::AdminPreparation => {
                let draft = vos::agent::sdk::authority::AuthorityAdminCall::decode(bytes)
                    .map_err(|_| CleanFileStoreError::Corrupt)?;
                if draft.observed_slot != 0
                    || draft
                        .verify_with(&super::super::local_create::CredentialVerifier)
                        .is_err()
                {
                    return Err(CleanFileStoreError::Corrupt);
                }
                Ok(())
            }
            ClientPairKind::AdminSubmission => {
                vos::agent::clean_bootstrap::NativeAuthorityAdminSubmission::decode(bytes)
                    .map(|_| ())
            }
            ClientPairKind::AuthorizationPreparation => {
                let call =
                    vos::agent::sdk::authority_operation::AuthorityOperationCall::decode(bytes)
                        .map_err(|_| CleanFileStoreError::Corrupt)?;
                if call.authenticated_node().is_some()
                    || call
                        .verify_api_with(&super::super::local_create::CredentialVerifier)
                        .is_err()
                {
                    return Err(CleanFileStoreError::Corrupt);
                }
                Ok(())
            }
            ClientPairKind::Operation => AuthorityOperationSubmission::decode(bytes).map(|_| ()),
            ClientPairKind::Preparation => {
                AgentTargetedPreparationRequest::decode(bytes).map(|_| ())
            }
        }
        .map_err(|_| CleanFileStoreError::Corrupt)
    }

    pub(crate) fn load_request(&mut self) -> Result<Option<Vec<u8>>, CleanFileStoreError> {
        for bytes in Self::candidates(&self.request)? {
            self.validate_request(&bytes)?;
        }
        let bytes = self.request.load(self.request.role.maximum_bytes())?;
        if let Some(bytes) = &bytes {
            self.validate_request(bytes)?;
            self.request.commit_with_replacement(bytes, false)?;
        }
        Ok(bytes)
    }

    pub(crate) fn publish_request(&mut self, bytes: &[u8]) -> Result<(), CleanFileStoreError> {
        self.validate_request(bytes)?;
        self.load_response()?; // Never repair an orphan response from fresh input.
        self.load_request()?;
        self.request.commit_with_replacement(bytes, false)
    }

    fn verify_response(&mut self, bytes: &[u8]) -> Result<(), CleanFileStoreError> {
        let request = self.load_request()?.ok_or(CleanFileStoreError::Corrupt)?;
        match self.kind {
            ClientPairKind::AdminPreparation => {
                let draft = vos::agent::sdk::authority::AuthorityAdminCall::decode(&request)
                    .map_err(|_| CleanFileStoreError::Corrupt)?;
                vos::agent::clean_bootstrap::NativeAuthorityAdminPreparation::decode(bytes)
                    .map_err(|_| CleanFileStoreError::Corrupt)?
                    .call_to_sign(&draft)
                    .map_err(|_| CleanFileStoreError::Corrupt)?;
            }
            ClientPairKind::AdminSubmission => {
                vos::agent::clean_bootstrap::NativeAuthorityAdminSubmission::decode(&request)
                    .map_err(|_| CleanFileStoreError::Corrupt)?
                    .verify_completion(bytes)
                    .map_err(|_| CleanFileStoreError::Corrupt)?;
            }
            ClientPairKind::AuthorizationPreparation => {
                let call =
                    vos::agent::sdk::authority_operation::AuthorityOperationCall::decode(&request)
                        .map_err(|_| CleanFileStoreError::Corrupt)?;
                let submission = AuthorityOperationSubmission::decode(bytes)
                    .map_err(|_| CleanFileStoreError::Corrupt)?;
                if submission.call() != &call
                    || submission.issued_at() != submission.context().observed_slot
                {
                    return Err(CleanFileStoreError::Corrupt);
                }
            }
            ClientPairKind::Operation => {
                AuthorityOperationSubmission::decode(&request)
                    .map_err(|_| CleanFileStoreError::Corrupt)?
                    .decode_response(bytes)
                    .map_err(|_| CleanFileStoreError::Corrupt)?;
            }
            ClientPairKind::Preparation => {
                let request = AgentTargetedPreparationRequest::decode(&request)
                    .map_err(|_| CleanFileStoreError::Corrupt)?;
                let response = AgentTargetedPreparationResponse::decode(bytes)
                    .map_err(|_| CleanFileStoreError::Corrupt)?;
                response
                    .for_request(&request)
                    .ok_or(CleanFileStoreError::Corrupt)?;
            }
        }
        Ok(())
    }

    pub(crate) fn load_response(&mut self) -> Result<Option<Vec<u8>>, CleanFileStoreError> {
        for bytes in Self::candidates(&self.response)? {
            self.verify_response(&bytes)?;
        }
        let bytes = self.response.load(self.response.role.maximum_bytes())?;
        if let Some(bytes) = &bytes {
            self.verify_response(bytes)?;
            self.response.commit_with_replacement(bytes, false)?;
        }
        Ok(bytes)
    }

    pub(crate) fn publish_response(&mut self, bytes: &[u8]) -> Result<(), CleanFileStoreError> {
        self.load_response()?;
        self.verify_response(bytes)?;
        self.response.commit_with_replacement(bytes, false)
    }
}
