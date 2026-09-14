//! One exclusively leased, immutable operation request and bound signed response.
use super::*;
use vos::agent::local_lifecycle::AuthorityOperationSubmission;
use vos::agent::sdk::wire::CanonicalWire as _;
use vos::agent::supervisor_adapters::{
    AgentTargetedPreparationRequest, AgentTargetedPreparationResponse,
};

#[derive(Clone, Copy)]
enum ClientPairKind {
    Operation,
    Preparation,
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

#[cfg(test)]
mod tests {
    use super::super::operation_journal_tests::submission;
    use super::super::tests::Fixture;
    use super::*;
    use vos::agent::clean_bootstrap::NativeAuthorityOperationDecision;

    // Synthetic source/input commitments test signature binding and storage,
    // not native execution. Native denial proof is tested in the library.
    fn denial(request: &AuthorityOperationSubmission) -> Vec<u8> {
        let (key, _, _, _) = crate::commands::space::local_create::tests::fixture();
        let (_, _, dispatch) = super::super::operation_journal_tests::record(
            request.call().request_sequence.get(),
            100,
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
            ClientPairKind::Operation => {
                (StoreRole::OperationRequest, StoreRole::OperationResponse)
            }
            ClientPairKind::Preparation => (
                StoreRole::PreparationRequest,
                StoreRole::PreparationResponse,
            ),
        };
        let entries: &'static [&'static str] = match kind {
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
