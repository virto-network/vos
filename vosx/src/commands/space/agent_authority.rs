//! Production Agent trust and system-genesis archive backed by a local
//! generation-2 authority socket.
//!
//! Payloads use existing canonical [`ServiceWire`] envelopes wherever VOS has
//! a public wire type. The small operation envelope is intentionally separate
//! from the older service-production-trust protocol: changing either protocol
//! cannot make a response valid for the other authority surface.

use std::path::Path;

use vos::agent::authority::{AgentAuthorityBinding, AgentAuthorityReceipt};
use vos::agent::bootstrap::{
    MAX_SYSTEM_AGENT_GENESIS_PROPOSAL_BYTES, MAX_SYSTEM_AGENT_GENESIS_PROVISION_BYTES,
    SystemAgentGenesisLocator, SystemAgentGenesisProposal, SystemAgentGenesisProvider,
    SystemAgentGenesisProviderError, SystemAgentGenesisProvision,
    validate_system_agent_genesis_catalog,
};
use vos::agent::driver::{AgentTrustProvider, MAX_AGENT_CONFIG_BYTES};
use vos::agent::execution::RuntimeBlob;
use vos::agent::host::PreparedLifecycleRequest;
use vos::agent::package::{MAX_ENCODED_PACKAGE_BYTES, Package};
use vos::agent::wire::{RuntimeCall, RuntimeState};
use vos::agent::{AgentConfig, MAX_CATALOG_ARTIFACT_BYTES};
use vos::service::{BlobRef, Hash, ServiceWire, SpaceId};

use super::authority_socket::{
    AuthoritySocket, MAX_SOCKET_PAYLOAD_BYTES, SocketExchangeError, SocketResponse, query_policy,
};

// Generation-2 operation tags. Tag zero is permanently the policy handshake.
pub(super) const QUERY_POLICY: u8 = 0;
pub(super) const CURRENT_LOGICAL_SLOT: u8 = 1;
pub(super) const AUTHORITY_FOR_SPACE: u8 = 2;
pub(super) const VERIFY_PACKAGE: u8 = 3;
pub(super) const CREATE_SYSTEM_GENESIS: u8 = 4;
pub(super) const REPRODUCE_SYSTEM_GENESIS: u8 = 5;
pub(super) const LOAD_SYSTEM_GENESIS_CATALOG: u8 = 6;
/// Issue or reproduce the authority receipt for one exact Host-prepared
/// lifecycle operation. The authority service must durably return the same
/// receipt for the same operation commitment.
pub(super) const ISSUE_LIFECYCLE: u8 = 7;

const LIFECYCLE_ISSUE_MAGIC: [u8; 4] = *b"ALI1";
const MAX_LIFECYCLE_RECEIPT_BYTES: usize = 4 * 1024;

// Every non-OK status has an empty payload. NOT_FOUND is meaningful only for
// LOAD_SYSTEM_GENESIS_CATALOG; accepting it elsewhere would erase the
// distinction between an absent archive and a missing catalog preimage.
pub(super) const STATUS_OK: u8 = 0;
pub(super) const STATUS_UNAVAILABLE: u8 = 1;
pub(super) const STATUS_NOT_CONFIGURED: u8 = 2;
pub(super) const STATUS_REFUSED: u8 = 3;
pub(super) const STATUS_CONFLICT: u8 = 4;
pub(super) const STATUS_CORRUPT: u8 = 5;
pub(super) const STATUS_NOT_FOUND: u8 = 6;

/// One startup-pinned Agent authority capability.
///
/// `open` performs a real policy query. A successful value therefore always
/// carries a nonzero immutable policy ID; every later response is checked
/// against it by the transport before operation payloads are interpreted.
#[derive(Clone, Debug)]
pub(super) struct SocketAgentAuthority {
    socket: AuthoritySocket,
}

impl SocketAgentAuthority {
    pub(super) fn open(path: impl AsRef<Path>) -> Result<Self, SystemAgentGenesisProviderError> {
        let path = path.as_ref().to_path_buf();
        let response = query_policy(&path, QUERY_POLICY).map_err(map_exchange_error)?;
        let policy = response.policy;
        let payload =
            provider_payload(response, false)?.ok_or(SystemAgentGenesisProviderError::Corrupt)?;
        if !payload.is_empty() {
            return Err(SystemAgentGenesisProviderError::Corrupt);
        }
        let socket = AuthoritySocket::from_sampled_policy(path, policy)
            .ok_or(SystemAgentGenesisProviderError::Corrupt)?;
        Ok(Self { socket })
    }

    pub(super) const fn policy_id(&self) -> Hash {
        self.socket.policy()
    }

    fn request_provider(
        &self,
        tag: u8,
        payload: &[u8],
        allow_catalog_miss: bool,
    ) -> Result<Option<Vec<u8>>, SystemAgentGenesisProviderError> {
        let response = self
            .socket
            .request(tag, payload)
            .map_err(map_exchange_error)?;
        provider_payload(response, allow_catalog_miss)
    }

    fn request_trust(&self, tag: u8, payload: &[u8]) -> Option<Vec<u8>> {
        self.request_provider(tag, payload, false).ok().flatten()
    }

    /// Ask the startup-pinned production authority to approve one exact
    /// operation prepared through the privately owned Agent Host.
    ///
    /// The socket receives both the canonical lifecycle request and all claim
    /// selectors. Its response is accepted only when the guest-verifiable
    /// signature and every selector match the prepared operation byte for
    /// byte. Policy refusal and authority unavailability remain distinct from
    /// malformed evidence.
    pub(super) fn issue_lifecycle(
        &self,
        prepared: &PreparedLifecycleRequest,
    ) -> Result<AgentAuthorityReceipt, SystemAgentGenesisProviderError> {
        self.issue_lifecycle_exact(
            prepared.authority(),
            prepared.space(),
            prepared.agent(),
            prepared.capability(),
            prepared.operation(),
            prepared.request(),
        )
    }

    fn issue_lifecycle_exact(
        &self,
        authority: &AgentAuthorityBinding,
        space: SpaceId,
        agent: vos::service::AgentId,
        capability: vos::service::CapabilityId,
        operation: Hash,
        lifecycle: &vos::agent::LifecycleRequest,
    ) -> Result<AgentAuthorityReceipt, SystemAgentGenesisProviderError> {
        if lifecycle
            .required_capability()
            .map(vos::service::CapabilityId::named)
            != Some(capability)
            || lifecycle.commitment() != operation
        {
            return Err(SystemAgentGenesisProviderError::Corrupt);
        }
        let request = RuntimeCall::new(RuntimeState::default(), lifecycle.clone()).encode();
        let payload = encode_lifecycle_issue_payload(
            authority, space, agent, capability, operation, &request,
        )
        .ok_or(SystemAgentGenesisProviderError::Corrupt)?;
        let response = self
            .request_provider(ISSUE_LIFECYCLE, &payload, false)?
            .ok_or(SystemAgentGenesisProviderError::Corrupt)?;
        validate_lifecycle_receipt(&response, authority, space, agent, capability, operation)
    }
}

impl AgentTrustProvider for SocketAgentAuthority {
    fn current_logical_slot(&self) -> Option<u64> {
        let payload = self.request_trust(CURRENT_LOGICAL_SLOT, &[])?;
        let bytes: [u8; 8] = payload.as_slice().try_into().ok()?;
        let slot = u64::from_le_bytes(bytes);
        (slot != 0).then_some(slot)
    }

    fn authority_for_space(&self, space: SpaceId) -> Option<AgentAuthorityBinding> {
        if space == SpaceId::ZERO {
            return None;
        }
        let payload = self.request_trust(AUTHORITY_FOR_SPACE, &space.0)?;
        if payload.len() > vos::agent::authority::MAX_AGENT_AUTHORITY_BINDING_WIRE_BYTES {
            return None;
        }
        let binding = AgentAuthorityBinding::decode(&payload).ok()?;
        (binding.encode() == payload).then_some(binding)
    }

    fn verify_package(&self, agent: &AgentConfig, package: &Package) -> bool {
        if agent.replicas.len() > 512 || agent.validate().is_err() || package.validate().is_err() {
            return false;
        }
        let config = agent.encode();
        let package = package.encode();
        if config.len() > MAX_AGENT_CONFIG_BYTES || package.len() > MAX_ENCODED_PACKAGE_BYTES {
            return false;
        }
        let Some(payload) = encode_pair(&config, &package) else {
            return false;
        };
        self.request_trust(VERIFY_PACKAGE, &payload)
            .is_some_and(|payload| payload.is_empty())
    }
}

impl SystemAgentGenesisProvider for SocketAgentAuthority {
    fn create(
        &self,
        proposal: &SystemAgentGenesisProposal,
        catalog: &[RuntimeBlob],
    ) -> Result<SystemAgentGenesisProvision, SystemAgentGenesisProviderError> {
        validate_system_agent_genesis_catalog(proposal, catalog)
            .map_err(|_| SystemAgentGenesisProviderError::Corrupt)?;
        let proposal_bytes = proposal.encode();
        if proposal_bytes.len() > MAX_SYSTEM_AGENT_GENESIS_PROPOSAL_BYTES {
            return Err(SystemAgentGenesisProviderError::Corrupt);
        }
        let payload = encode_create_payload(&proposal_bytes, catalog)
            .ok_or(SystemAgentGenesisProviderError::Corrupt)?;
        let response = self
            .request_provider(CREATE_SYSTEM_GENESIS, &payload, false)?
            .ok_or(SystemAgentGenesisProviderError::Corrupt)?;
        let provision = decode_provision(&response)?;
        if provision.proposal() != proposal {
            return Err(SystemAgentGenesisProviderError::Corrupt);
        }
        Ok(provision)
    }

    fn reproduce(
        &self,
        locator: SystemAgentGenesisLocator,
    ) -> Result<SystemAgentGenesisProvision, SystemAgentGenesisProviderError> {
        locator
            .validate()
            .map_err(|_| SystemAgentGenesisProviderError::Corrupt)?;
        let request = locator.encode();
        let response = self
            .request_provider(REPRODUCE_SYSTEM_GENESIS, &request, false)?
            .ok_or(SystemAgentGenesisProviderError::Corrupt)?;
        let provision = decode_provision(&response)?;
        if provision.proposal().locator() != locator {
            return Err(SystemAgentGenesisProviderError::Corrupt);
        }
        Ok(provision)
    }

    fn load_catalog(
        &self,
        locator: SystemAgentGenesisLocator,
        reference: &BlobRef,
    ) -> Result<Option<Vec<u8>>, SystemAgentGenesisProviderError> {
        locator
            .validate()
            .map_err(|_| SystemAgentGenesisProviderError::Corrupt)?;
        if reference.hash == Hash::ZERO
            || reference.len == 0
            || reference.len > MAX_CATALOG_ARTIFACT_BYTES
        {
            return Err(SystemAgentGenesisProviderError::Corrupt);
        }
        let locator = locator.encode();
        let request = encode_catalog_request(&locator, reference)
            .ok_or(SystemAgentGenesisProviderError::Corrupt)?;
        match self.request_provider(LOAD_SYSTEM_GENESIS_CATALOG, &request, true)? {
            Some(bytes)
                if bytes.len() <= MAX_CATALOG_ARTIFACT_BYTES as usize
                    && reference.matches(&bytes) =>
            {
                Ok(Some(bytes))
            }
            Some(_) => Err(SystemAgentGenesisProviderError::Corrupt),
            None => Ok(None),
        }
    }
}

fn map_exchange_error(error: SocketExchangeError) -> SystemAgentGenesisProviderError {
    match error {
        SocketExchangeError::Unavailable | SocketExchangeError::PolicyChanged => {
            SystemAgentGenesisProviderError::Unavailable
        }
        SocketExchangeError::Corrupt => SystemAgentGenesisProviderError::Corrupt,
    }
}

fn provider_payload(
    response: SocketResponse,
    allow_catalog_miss: bool,
) -> Result<Option<Vec<u8>>, SystemAgentGenesisProviderError> {
    if response.status == STATUS_OK {
        return Ok(Some(response.payload));
    }
    if !response.payload.is_empty() {
        return Err(SystemAgentGenesisProviderError::Corrupt);
    }
    match response.status {
        STATUS_UNAVAILABLE => Err(SystemAgentGenesisProviderError::Unavailable),
        STATUS_NOT_CONFIGURED => Err(SystemAgentGenesisProviderError::NotConfigured),
        STATUS_REFUSED => Err(SystemAgentGenesisProviderError::Refused),
        STATUS_CONFLICT => Err(SystemAgentGenesisProviderError::Conflict),
        STATUS_CORRUPT => Err(SystemAgentGenesisProviderError::Corrupt),
        STATUS_NOT_FOUND if allow_catalog_miss => Ok(None),
        _ => Err(SystemAgentGenesisProviderError::Corrupt),
    }
}

fn encode_pair(left: &[u8], right: &[u8]) -> Option<Vec<u8>> {
    let capacity = 8usize.checked_add(left.len())?.checked_add(right.len())?;
    if capacity > MAX_SOCKET_PAYLOAD_BYTES {
        return None;
    }
    let mut payload = Vec::with_capacity(capacity);
    push_bytes(&mut payload, left)?;
    push_bytes(&mut payload, right)?;
    Some(payload)
}

fn encode_create_payload(proposal: &[u8], catalog: &[RuntimeBlob]) -> Option<Vec<u8>> {
    let mut payload = Vec::new();
    push_bytes(&mut payload, proposal)?;
    payload.extend_from_slice(&u32::try_from(catalog.len()).ok()?.to_le_bytes());
    for blob in catalog {
        payload.extend_from_slice(&blob.reference.hash.0);
        payload.extend_from_slice(&blob.reference.len.to_le_bytes());
        push_bytes(&mut payload, &blob.bytes)?;
    }
    (payload.len() <= MAX_SOCKET_PAYLOAD_BYTES).then_some(payload)
}

fn encode_catalog_request(locator: &[u8], reference: &BlobRef) -> Option<Vec<u8>> {
    let capacity = 4usize.checked_add(locator.len())?.checked_add(32 + 8)?;
    if capacity > MAX_SOCKET_PAYLOAD_BYTES {
        return None;
    }
    let mut payload = Vec::with_capacity(capacity);
    push_bytes(&mut payload, locator)?;
    payload.extend_from_slice(&reference.hash.0);
    payload.extend_from_slice(&reference.len.to_le_bytes());
    Some(payload)
}

fn encode_lifecycle_issue_payload(
    authority: &AgentAuthorityBinding,
    space: SpaceId,
    agent: vos::service::AgentId,
    capability: vos::service::CapabilityId,
    operation: Hash,
    canonical_request: &[u8],
) -> Option<Vec<u8>> {
    if !authority.validate()
        || space == SpaceId::ZERO
        || agent == vos::service::AgentId::ZERO
        || capability == vos::service::CapabilityId::ZERO
        || operation == Hash::ZERO
        || canonical_request.is_empty()
    {
        return None;
    }
    let authority = authority.encode();
    let capacity = LIFECYCLE_ISSUE_MAGIC
        .len()
        .checked_add(4 + authority.len())?
        .checked_add(4 * 32)?
        .checked_add(4 + canonical_request.len())?;
    if capacity > MAX_SOCKET_PAYLOAD_BYTES {
        return None;
    }
    let mut payload = Vec::with_capacity(capacity);
    payload.extend_from_slice(&LIFECYCLE_ISSUE_MAGIC);
    push_bytes(&mut payload, &authority)?;
    payload.extend_from_slice(&space.0);
    payload.extend_from_slice(&agent.0);
    payload.extend_from_slice(&capability.0);
    payload.extend_from_slice(&operation.0);
    push_bytes(&mut payload, canonical_request)?;
    Some(payload)
}

fn validate_lifecycle_receipt(
    bytes: &[u8],
    authority: &AgentAuthorityBinding,
    space: SpaceId,
    agent: vos::service::AgentId,
    capability: vos::service::CapabilityId,
    operation: Hash,
) -> Result<AgentAuthorityReceipt, SystemAgentGenesisProviderError> {
    if bytes.len() > MAX_LIFECYCLE_RECEIPT_BYTES {
        return Err(SystemAgentGenesisProviderError::Corrupt);
    }
    let receipt = AgentAuthorityReceipt::decode(bytes)
        .map_err(|_| SystemAgentGenesisProviderError::Corrupt)?;
    let claim = &receipt.claim;
    if receipt.encode() != bytes
        || claim.authority != *authority
        || claim.space != space
        || claim.agent != agent
        || claim.capability != capability
        || claim.operation != operation
        || receipt.verify_guest_signature(authority).is_err()
    {
        return Err(SystemAgentGenesisProviderError::Corrupt);
    }
    Ok(receipt)
}

fn push_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Option<()> {
    let len = u32::try_from(bytes.len()).ok()?;
    let required = output.len().checked_add(4)?.checked_add(bytes.len())?;
    if required > MAX_SOCKET_PAYLOAD_BYTES {
        return None;
    }
    output.extend_from_slice(&len.to_le_bytes());
    output.extend_from_slice(bytes);
    Some(())
}

fn decode_provision(
    bytes: &[u8],
) -> Result<SystemAgentGenesisProvision, SystemAgentGenesisProviderError> {
    if bytes.len() > MAX_SYSTEM_AGENT_GENESIS_PROVISION_BYTES {
        return Err(SystemAgentGenesisProviderError::Corrupt);
    }
    let provision = SystemAgentGenesisProvision::decode(bytes)
        .map_err(|_| SystemAgentGenesisProviderError::Corrupt)?;
    if provision.encode() != bytes {
        return Err(SystemAgentGenesisProviderError::Corrupt);
    }
    Ok(provision)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;
    use std::time::{Duration, Instant};

    use ed25519_dalek::{Signer, SigningKey};
    use vos::agent::authority::{AgentAuthorityClaim, ed25519_public_key_wire};
    use vos::agent::contract::RuntimePackageContract;
    use vos::agent::package::PackageManifest;
    use vos::agent::{
        AgentIdentity, AgentProfile, AgentReplica, PackageKind, ReplicaRole, RuntimeCapabilities,
    };
    use vos::service::{
        ActorId, AgentId, CapabilityId, CredentialId, DeploymentId, DeploymentSignature, NodeId,
        PrincipalId, ProducerId, ProgramId, artifact_hash, task_dependencies_hash,
    };

    use super::super::authority_socket::{
        MAX_SOCKET_PAYLOAD_BYTES, REQUEST_MAGIC, RESPONSE_MAGIC, SocketExchangeError,
        encode_request, exchange_with_timeout, request_hash,
    };

    static SOCKET_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[derive(Clone, Copy)]
    enum ResponseMutation {
        Exact,
        WrongMagic,
        WrongRequest,
        Trailing,
        Oversized,
        Trickle(Duration),
    }

    struct Reply {
        policy: Hash,
        status: u8,
        payload: Vec<u8>,
        mutation: ResponseMutation,
    }

    impl Reply {
        fn exact(policy: Hash, status: u8, payload: Vec<u8>) -> Self {
            Self {
                policy,
                status,
                payload,
                mutation: ResponseMutation::Exact,
            }
        }

        fn mutated(policy: Hash, mutation: ResponseMutation) -> Self {
            Self {
                policy,
                status: STATUS_OK,
                payload: Vec::new(),
                mutation,
            }
        }
    }

    #[derive(Debug)]
    struct ParsedRequest {
        policy: Hash,
        tag: u8,
        payload: Vec<u8>,
    }

    fn socket_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "vos-agent-authority-{label}-{}-{}.sock",
            std::process::id(),
            SOCKET_SEQUENCE.fetch_add(1, Ordering::Relaxed),
        ))
    }

    fn serve(path: &Path, replies: Vec<Reply>) -> thread::JoinHandle<Vec<Vec<u8>>> {
        let listener = UnixListener::bind(path).unwrap();
        thread::spawn(move || {
            let mut requests = Vec::with_capacity(replies.len());
            for reply in replies {
                let (mut stream, _) = listener.accept().unwrap();
                let request = read_request(&mut stream);
                let mut response = response_bytes(&request, &reply);
                requests.push(request);
                match reply.mutation {
                    ResponseMutation::Oversized => {
                        let oversized = u32::try_from(73 + MAX_SOCKET_PAYLOAD_BYTES + 1).unwrap();
                        stream.write_all(&oversized.to_le_bytes()).unwrap();
                    }
                    ResponseMutation::Trickle(delay) => {
                        let len = u32::try_from(response.len()).unwrap();
                        stream.write_all(&len.to_le_bytes()).unwrap();
                        for byte in response.drain(..) {
                            if stream.write_all(&[byte]).is_err() {
                                break;
                            }
                            thread::sleep(delay);
                        }
                    }
                    _ => {
                        let len = u32::try_from(response.len()).unwrap();
                        stream.write_all(&len.to_le_bytes()).unwrap();
                        stream.write_all(&response).unwrap();
                    }
                }
            }
            requests
        })
    }

    fn read_request(stream: &mut UnixStream) -> Vec<u8> {
        let mut len = [0; 4];
        stream.read_exact(&mut len).unwrap();
        let len = u32::from_le_bytes(len) as usize;
        assert!(len <= 41 + MAX_SOCKET_PAYLOAD_BYTES);
        let mut request = vec![0; len];
        stream.read_exact(&mut request).unwrap();
        request
    }

    fn response_bytes(request: &[u8], reply: &Reply) -> Vec<u8> {
        let mut commitment = request_hash(request);
        if matches!(reply.mutation, ResponseMutation::WrongRequest) {
            commitment.0[0] ^= 1;
        }
        let mut response = Vec::with_capacity(73 + reply.payload.len() + 1);
        response.extend_from_slice(&RESPONSE_MAGIC);
        response.extend_from_slice(&commitment.0);
        response.extend_from_slice(&reply.policy.0);
        response.push(reply.status);
        response.extend_from_slice(&(reply.payload.len() as u32).to_le_bytes());
        response.extend_from_slice(&reply.payload);
        if matches!(reply.mutation, ResponseMutation::WrongMagic) {
            response[0] ^= 1;
        }
        if matches!(reply.mutation, ResponseMutation::Trailing) {
            response.push(0xff);
        }
        response
    }

    fn parse_request(request: &[u8]) -> ParsedRequest {
        assert_eq!(request.get(..4), Some(REQUEST_MAGIC.as_slice()));
        let policy = Hash(request[4..36].try_into().unwrap());
        let tag = request[36];
        let len = u32::from_le_bytes(request[37..41].try_into().unwrap()) as usize;
        assert_eq!(request.len(), 41 + len);
        ParsedRequest {
            policy,
            tag,
            payload: request[41..].to_vec(),
        }
    }

    fn cleanup(path: PathBuf, server: thread::JoinHandle<Vec<Vec<u8>>>) -> Vec<Vec<u8>> {
        let requests = server.join().unwrap();
        let _ = std::fs::remove_file(path);
        requests
    }

    fn locator() -> SystemAgentGenesisLocator {
        SystemAgentGenesisLocator {
            space: SpaceId([0x11; 32]),
            agent: AgentId([0x12; 32]),
            node: NodeId([0x13; 32]),
        }
    }

    fn authority_binding() -> AgentAuthorityBinding {
        let public_key = ed25519_public_key_wire([0x31; 32]);
        AgentAuthorityBinding {
            agent: AgentId([0x21; 32]),
            actor: ActorId([0x22; 32]),
            deployment: DeploymentId([0x23; 32]),
            program: ProgramId([0x24; 32]),
            producer: ProducerId::of_public_key(&public_key),
            public_key,
        }
    }

    fn agent_config() -> AgentConfig {
        let owner = PrincipalId([0x41; 32]);
        let space = SpaceId([0x42; 32]);
        let nonce = Hash([0x43; 32]);
        AgentConfig {
            identity: AgentIdentity {
                space,
                agent: AgentId::derive(space, owner, &nonce.0),
                owner,
                profile: AgentProfile::Local,
                runtime_deployment: DeploymentId([0x44; 32]),
                runtime_program: ProgramId([0x45; 32]),
                runtime_producer: ProducerId([0x46; 32]),
                transition_producer: ProducerId([0x47; 32]),
            },
            creation_nonce: nonce,
            authority: authority_binding(),
            system_authority_genesis: None,
            runtime_package: BlobRef::of_bytes(b"runtime package"),
            runtime_contract: RuntimePackageContract::canonical(),
            capabilities: RuntimeCapabilities::standard(),
            replicas: vec![AgentReplica {
                node: NodeId([0x47; 32]),
                principal: owner,
                role: ReplicaRole::Voter,
            }],
        }
    }

    fn package() -> Package {
        let pvm = crate::bundled::agent_runtime_pvm().to_vec();
        let interfaces = b"fixture interfaces".to_vec();
        let schemas = b"fixture schemas".to_vec();
        Package {
            manifest: PackageManifest {
                name: "socket-fixture".into(),
                platform: vos::service::PLATFORM_ID,
                execution_semantics: vos::agent::EXECUTION_SEMANTICS_ID,
                kind: PackageKind::AgentRuntime {
                    contract: RuntimePackageContract::canonical(),
                    capabilities: RuntimeCapabilities::standard(),
                },
                program: ProgramId::of_pvm(&pvm),
                interfaces_hash: artifact_hash(b"interfaces", &interfaces),
                role_policies_hash: artifact_hash(b"role-policies", &[]),
                schemas_hash: artifact_hash(b"schemas", &schemas),
                agent_schema_hash: artifact_hash(b"agent-schema", &[]),
                dependencies_hash: task_dependencies_hash(&[]),
            },
            pvm,
            generated_interfaces: interfaces,
            role_policies: Vec::new(),
            schemas,
            agent_schema: Vec::new(),
            task_dependencies: Vec::new(),
            diagnostics: None,
            deployment_signature: DeploymentSignature {
                producer: ProducerId::of_public_key(b"fixture package key"),
                public_key: b"fixture package key".to_vec(),
                signature: vec![6],
            },
        }
    }

    fn signed_lifecycle_receipt(
        signing: &SigningKey,
        authority: AgentAuthorityBinding,
        space: SpaceId,
        agent: AgentId,
        capability: CapabilityId,
        operation: Hash,
    ) -> AgentAuthorityReceipt {
        let claim = AgentAuthorityClaim {
            authority,
            space,
            agent,
            principal: PrincipalId([0x51; 32]),
            credential: CredentialId([0x52; 32]),
            capability,
            operation,
            sequence: 7,
            valid_from: 10,
            valid_until: 20,
        };
        let signature = signing.sign(&claim.signing_message().0).to_bytes().to_vec();
        AgentAuthorityReceipt { claim, signature }
    }

    #[test]
    fn lifecycle_issue_payload_and_receipt_bind_every_prepared_selector() {
        let signing = SigningKey::from_bytes(&[0x53; 32]);
        let public_key = ed25519_public_key_wire(signing.verifying_key().to_bytes());
        let agent = AgentId([0x54; 32]);
        let authority = AgentAuthorityBinding {
            agent: AgentId([0x55; 32]),
            actor: ActorId([0x56; 32]),
            deployment: DeploymentId([0x57; 32]),
            program: ProgramId([0x58; 32]),
            producer: ProducerId::of_public_key(&public_key),
            public_key,
        };
        let space = SpaceId([0x59; 32]);
        let capability = CapabilityId::named(vos::agent::authority::CAPABILITY_ACTOR_LIFECYCLE);
        let lifecycle = vos::agent::LifecycleRequest::Suspend {
            actor: ActorId([0x5a; 32]),
            expected_deployment: DeploymentId([0x5b; 32]),
        };
        let operation = lifecycle.commitment();
        let request = RuntimeCall::new(RuntimeState::default(), lifecycle).encode();
        let payload = encode_lifecycle_issue_payload(
            &authority, space, agent, capability, operation, &request,
        )
        .unwrap();

        assert_eq!(&payload[..4], &LIFECYCLE_ISSUE_MAGIC);
        let authority_len = u32::from_le_bytes(payload[4..8].try_into().unwrap()) as usize;
        assert_eq!(&payload[8..8 + authority_len], authority.encode());
        let fixed = 8 + authority_len;
        assert_eq!(&payload[fixed..fixed + 32], &space.0);
        assert_eq!(&payload[fixed + 32..fixed + 64], &agent.0);
        assert_eq!(&payload[fixed + 64..fixed + 96], &capability.0);
        assert_eq!(&payload[fixed + 96..fixed + 128], &operation.0);
        let request_len =
            u32::from_le_bytes(payload[fixed + 128..fixed + 132].try_into().unwrap()) as usize;
        assert_eq!(request_len, request.len());
        assert_eq!(&payload[fixed + 132..], request);

        let receipt = signed_lifecycle_receipt(
            &signing,
            authority.clone(),
            space,
            agent,
            capability,
            operation,
        );
        assert_eq!(
            validate_lifecycle_receipt(
                &receipt.encode(),
                &authority,
                space,
                agent,
                capability,
                operation,
            ),
            Ok(receipt.clone()),
        );

        let mismatches = [
            (SpaceId([0x60; 32]), agent, capability, operation),
            (space, AgentId([0x61; 32]), capability, operation),
            (space, agent, CapabilityId([0x62; 32]), operation),
            (space, agent, capability, Hash([0x63; 32])),
        ];
        for (wrong_space, wrong_agent, wrong_capability, wrong_operation) in mismatches {
            assert_eq!(
                validate_lifecycle_receipt(
                    &receipt.encode(),
                    &authority,
                    wrong_space,
                    wrong_agent,
                    wrong_capability,
                    wrong_operation,
                ),
                Err(SystemAgentGenesisProviderError::Corrupt),
            );
        }

        let mut forged = receipt;
        forged.signature[0] ^= 1;
        assert_eq!(
            validate_lifecycle_receipt(
                &forged.encode(),
                &authority,
                space,
                agent,
                capability,
                operation,
            ),
            Err(SystemAgentGenesisProviderError::Corrupt),
        );
    }

    #[test]
    fn lifecycle_issue_transport_reproduces_one_exact_receipt_for_one_request() {
        let signing = SigningKey::from_bytes(&[0x64; 32]);
        let public_key = ed25519_public_key_wire(signing.verifying_key().to_bytes());
        let agent = AgentId([0x65; 32]);
        let authority_binding = AgentAuthorityBinding {
            agent: AgentId([0x66; 32]),
            actor: ActorId([0x67; 32]),
            deployment: DeploymentId([0x68; 32]),
            program: ProgramId([0x69; 32]),
            producer: ProducerId::of_public_key(&public_key),
            public_key,
        };
        let space = SpaceId([0x6a; 32]);
        let capability = CapabilityId::named(vos::agent::authority::CAPABILITY_ACTOR_LIFECYCLE);
        let lifecycle = vos::agent::LifecycleRequest::Resume {
            actor: ActorId([0x6b; 32]),
            expected_deployment: DeploymentId([0x6c; 32]),
        };
        let operation = lifecycle.commitment();
        let receipt = signed_lifecycle_receipt(
            &signing,
            authority_binding.clone(),
            space,
            agent,
            capability,
            operation,
        );

        let path = socket_path("lifecycle-reproduce");
        let policy = Hash([0x6d; 32]);
        let server = serve(
            &path,
            vec![
                Reply::exact(policy, STATUS_OK, Vec::new()),
                Reply::exact(policy, STATUS_OK, receipt.encode()),
                Reply::exact(policy, STATUS_OK, receipt.encode()),
            ],
        );
        let authority = SocketAgentAuthority::open(&path).unwrap();
        for _ in 0..2 {
            assert_eq!(
                authority.issue_lifecycle_exact(
                    &authority_binding,
                    space,
                    agent,
                    capability,
                    operation,
                    &lifecycle,
                ),
                Ok(receipt.clone()),
            );
        }
        let requests = cleanup(path, server);
        assert_eq!(
            requests[1], requests[2],
            "retry request bytes must be stable"
        );
        let request = parse_request(&requests[1]);
        assert_eq!(request.policy, policy);
        assert_eq!(request.tag, ISSUE_LIFECYCLE);
        assert_eq!(
            request.payload.get(..4),
            Some(LIFECYCLE_ISSUE_MAGIC.as_slice())
        );
    }

    #[test]
    fn startup_policy_and_every_later_request_are_exactly_bound() {
        let path = socket_path("binding");
        let policy = Hash([7; 32]);
        let server = serve(
            &path,
            vec![
                Reply::exact(policy, STATUS_OK, Vec::new()),
                Reply::exact(policy, STATUS_OK, 77_u64.to_le_bytes().to_vec()),
                Reply::exact(policy, STATUS_OK, 0_u64.to_le_bytes().to_vec()),
            ],
        );
        let authority = SocketAgentAuthority::open(&path).unwrap();
        assert_eq!(authority.policy_id(), policy);
        assert_eq!(authority.current_logical_slot(), Some(77));
        assert_eq!(authority.current_logical_slot(), None);

        let requests = cleanup(path, server);
        let query = parse_request(&requests[0]);
        assert_eq!(query.policy, Hash::ZERO);
        assert_eq!(query.tag, QUERY_POLICY);
        assert!(query.payload.is_empty());
        let slot = parse_request(&requests[1]);
        assert_eq!(slot.policy, policy);
        assert_eq!(slot.tag, CURRENT_LOGICAL_SLOT);
        assert!(slot.payload.is_empty());
        let zero_slot = parse_request(&requests[2]);
        assert_eq!(zero_slot.policy, policy);
        assert_eq!(zero_slot.tag, CURRENT_LOGICAL_SLOT);
        assert!(zero_slot.payload.is_empty());

        let encoded = encode_request(Hash::ZERO, QUERY_POLICY, &[]).unwrap();
        assert_eq!(encoded, requests[0]);
        assert_eq!(
            request_hash(&encoded),
            Hash::digest(
                super::super::authority_socket::REQUEST_HASH_DOMAIN,
                &[&encoded]
            )
        );
    }

    #[test]
    fn policy_change_is_unavailable_and_all_trust_calls_fail_closed() {
        let path = socket_path("policy-change");
        let policy = Hash([8; 32]);
        let changed = Hash([9; 32]);
        let server = serve(
            &path,
            vec![
                Reply::exact(policy, STATUS_OK, Vec::new()),
                Reply::exact(changed, STATUS_OK, 1_u64.to_le_bytes().to_vec()),
                Reply::exact(changed, STATUS_OK, Vec::new()),
            ],
        );
        let authority = SocketAgentAuthority::open(&path).unwrap();
        assert_eq!(authority.current_logical_slot(), None);
        assert_eq!(
            authority.reproduce(locator()),
            Err(SystemAgentGenesisProviderError::Unavailable),
        );
        cleanup(path, server);
    }

    #[test]
    fn authority_binding_uses_the_standalone_aab1_wire_and_fails_closed() {
        let path = socket_path("binding-wire");
        let policy = Hash([10; 32]);
        let binding = authority_binding();
        let mut malformed = binding.encode();
        malformed.push(0);
        let server = serve(
            &path,
            vec![
                Reply::exact(policy, STATUS_OK, Vec::new()),
                Reply::exact(policy, STATUS_OK, binding.encode()),
                Reply::exact(policy, STATUS_OK, malformed),
            ],
        );
        let authority = SocketAgentAuthority::open(&path).unwrap();
        let space = SpaceId([0x61; 32]);
        assert_eq!(authority.authority_for_space(space), Some(binding));
        assert_eq!(authority.authority_for_space(space), None);
        let requests = cleanup(path, server);
        let request = parse_request(&requests[1]);
        assert_eq!(request.tag, AUTHORITY_FOR_SPACE);
        assert_eq!(request.payload, space.0);
    }

    #[test]
    fn package_verification_sends_exact_canonical_inputs_and_refusal_is_false() {
        let path = socket_path("package");
        let policy = Hash([11; 32]);
        let server = serve(
            &path,
            vec![
                Reply::exact(policy, STATUS_OK, Vec::new()),
                Reply::exact(policy, STATUS_OK, Vec::new()),
                Reply::exact(policy, STATUS_REFUSED, Vec::new()),
            ],
        );
        let authority = SocketAgentAuthority::open(&path).unwrap();
        let config = agent_config();
        let package = package();
        assert!(authority.verify_package(&config, &package));
        assert!(!authority.verify_package(&config, &package));

        let requests = cleanup(path, server);
        let request = parse_request(&requests[1]);
        assert_eq!(request.tag, VERIFY_PACKAGE);
        let config_len = u32::from_le_bytes(request.payload[..4].try_into().unwrap()) as usize;
        assert_eq!(&request.payload[4..4 + config_len], config.encode());
        let package_start = 4 + config_len;
        let package_len = u32::from_le_bytes(
            request.payload[package_start..package_start + 4]
                .try_into()
                .unwrap(),
        ) as usize;
        assert_eq!(
            &request.payload[package_start + 4..package_start + 4 + package_len],
            package.encode(),
        );
        assert_eq!(request.payload.len(), package_start + 4 + package_len);
    }

    #[test]
    fn provider_statuses_are_mapped_exactly_and_catalog_miss_is_narrow() {
        let cases = [
            (
                STATUS_UNAVAILABLE,
                SystemAgentGenesisProviderError::Unavailable,
            ),
            (
                STATUS_NOT_CONFIGURED,
                SystemAgentGenesisProviderError::NotConfigured,
            ),
            (STATUS_REFUSED, SystemAgentGenesisProviderError::Refused),
            (STATUS_CONFLICT, SystemAgentGenesisProviderError::Conflict),
            (STATUS_CORRUPT, SystemAgentGenesisProviderError::Corrupt),
            (STATUS_NOT_FOUND, SystemAgentGenesisProviderError::Corrupt),
            (0xff, SystemAgentGenesisProviderError::Corrupt),
        ];
        for (index, (status, expected)) in cases.into_iter().enumerate() {
            let path = socket_path(&format!("status-{index}"));
            let policy = Hash([12; 32]);
            let server = serve(
                &path,
                vec![
                    Reply::exact(policy, STATUS_OK, Vec::new()),
                    Reply::exact(policy, status, Vec::new()),
                ],
            );
            let authority = SocketAgentAuthority::open(&path).unwrap();
            assert_eq!(authority.reproduce(locator()), Err(expected));
            cleanup(path, server);
        }

        let bytes = b"archived runtime".to_vec();
        let reference = BlobRef::of_bytes(&bytes);
        let path = socket_path("catalog-miss");
        let policy = Hash([13; 32]);
        let server = serve(
            &path,
            vec![
                Reply::exact(policy, STATUS_OK, Vec::new()),
                Reply::exact(policy, STATUS_NOT_FOUND, Vec::new()),
            ],
        );
        let authority = SocketAgentAuthority::open(&path).unwrap();
        assert_eq!(authority.load_catalog(locator(), &reference), Ok(None));
        cleanup(path, server);
    }

    #[test]
    fn catalog_preimages_must_match_both_hash_and_length() {
        let bytes = b"exact archived runtime".to_vec();
        let reference = BlobRef::of_bytes(&bytes);
        let path = socket_path("catalog-exact");
        let policy = Hash([14; 32]);
        let server = serve(
            &path,
            vec![
                Reply::exact(policy, STATUS_OK, Vec::new()),
                Reply::exact(policy, STATUS_OK, bytes.clone()),
            ],
        );
        let authority = SocketAgentAuthority::open(&path).unwrap();
        assert_eq!(
            authority.load_catalog(locator(), &reference),
            Ok(Some(bytes)),
        );
        let requests = cleanup(path, server);
        let request = parse_request(&requests[1]);
        assert_eq!(request.tag, LOAD_SYSTEM_GENESIS_CATALOG);
        assert!(request.payload.ends_with(&reference.len.to_le_bytes()));
        assert_eq!(
            &request.payload[request.payload.len() - 40..request.payload.len() - 8],
            reference.hash.0.as_slice(),
        );

        let path = socket_path("catalog-mismatch");
        let server = serve(
            &path,
            vec![
                Reply::exact(policy, STATUS_OK, Vec::new()),
                Reply::exact(policy, STATUS_OK, b"different runtime".to_vec()),
            ],
        );
        let authority = SocketAgentAuthority::open(&path).unwrap();
        assert_eq!(
            authority.load_catalog(locator(), &reference),
            Err(SystemAgentGenesisProviderError::Corrupt),
        );
        cleanup(path, server);
    }

    #[test]
    fn malformed_oversized_and_trailing_frames_are_corrupt() {
        let mutations = [
            ResponseMutation::Exact,
            ResponseMutation::WrongMagic,
            ResponseMutation::WrongRequest,
            ResponseMutation::Trailing,
            ResponseMutation::Oversized,
        ];
        for (index, mutation) in mutations.into_iter().enumerate() {
            let path = socket_path(&format!("malformed-{index}"));
            let policy = Hash([15; 32]);
            let server = serve(
                &path,
                vec![
                    Reply::exact(policy, STATUS_OK, Vec::new()),
                    Reply::mutated(policy, mutation),
                ],
            );
            let authority = SocketAgentAuthority::open(&path).unwrap();
            assert_eq!(
                authority.reproduce(locator()),
                Err(SystemAgentGenesisProviderError::Corrupt),
            );
            cleanup(path, server);
        }

        assert_eq!(
            encode_request(Hash([1; 32]), 1, &vec![0; MAX_SOCKET_PAYLOAD_BYTES + 1]),
            Err(SocketExchangeError::Corrupt),
        );
    }

    #[test]
    fn malformed_status_payload_and_zero_policy_are_corrupt() {
        let path = socket_path("status-payload");
        let policy = Hash([16; 32]);
        let server = serve(
            &path,
            vec![
                Reply::exact(policy, STATUS_OK, Vec::new()),
                Reply::exact(policy, STATUS_NOT_CONFIGURED, vec![1]),
            ],
        );
        let authority = SocketAgentAuthority::open(&path).unwrap();
        assert_eq!(
            authority.reproduce(locator()),
            Err(SystemAgentGenesisProviderError::Corrupt),
        );
        cleanup(path, server);

        let path = socket_path("zero-policy");
        let server = serve(&path, vec![Reply::exact(Hash::ZERO, STATUS_OK, Vec::new())]);
        assert!(matches!(
            SocketAgentAuthority::open(&path),
            Err(SystemAgentGenesisProviderError::Corrupt),
        ));
        cleanup(path, server);
    }

    #[test]
    fn io_failure_and_one_absolute_deadline_are_unavailable() {
        let path = socket_path("io");
        let policy = Hash([17; 32]);
        let server = serve(&path, vec![Reply::exact(policy, STATUS_OK, Vec::new())]);
        let authority = SocketAgentAuthority::open(&path).unwrap();
        cleanup(path, server);
        assert_eq!(
            authority.reproduce(locator()),
            Err(SystemAgentGenesisProviderError::Unavailable),
        );

        let path = socket_path("deadline");
        let server = serve(
            &path,
            vec![Reply {
                policy,
                status: STATUS_OK,
                payload: Vec::new(),
                mutation: ResponseMutation::Trickle(Duration::from_millis(10)),
            }],
        );
        let started = Instant::now();
        assert_eq!(
            exchange_with_timeout(&path, None, QUERY_POLICY, &[], Duration::from_millis(75),),
            Err(SocketExchangeError::Unavailable),
        );
        assert!(started.elapsed() < Duration::from_millis(500));
        cleanup(path, server);
    }

    #[test]
    fn create_payload_is_one_bounded_proposal_and_catalog() {
        let proposal = b"canonical proposal";
        let bytes = b"runtime package".to_vec();
        let blob = RuntimeBlob {
            reference: BlobRef::of_bytes(&bytes),
            bytes: bytes.clone(),
        };
        let payload = encode_create_payload(proposal, &[blob]).unwrap();
        let proposal_len = u32::from_le_bytes(payload[..4].try_into().unwrap()) as usize;
        assert_eq!(&payload[4..4 + proposal_len], proposal);
        let count_at = 4 + proposal_len;
        assert_eq!(
            u32::from_le_bytes(payload[count_at..count_at + 4].try_into().unwrap()),
            1,
        );
        assert!(payload.len() <= MAX_SOCKET_PAYLOAD_BYTES);
    }
}
