//! Serialized read-only control boundary for one clean Local host.
//!
//! A [`CleanLocalHostControlOwner`] moves the complete
//! [`CleanSystemAgentBootstrapOwner`] onto one dedicated worker thread.  The
//! cloneable [`CleanLocalHostControl`] can inspect that owner only through a
//! capacity-one command channel; it cannot obtain the host, issuer, stores,
//! or any mutation/invocation capability.  Dropping the lifecycle owner first
//! closes admission and then joins the worker, even while cloned controls
//! remain alive.

use alloc::vec::Vec;
use core::fmt;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use super::clean_authority_issuer::CleanManagementIssuerStore;
use super::clean_bootstrap::{
    CleanSystemAgentBootstrapOwner, CleanSystemAgentBootstrapStore, CleanSystemAgentPins,
};
use super::local_sdk_host::LocalAgentHostError;
use super::sdk::authority::AuthorityReceipt;
use super::sdk::{AgentDescriptor, AgentId, AgentIdentity};

/// Exact number of commands which may wait behind the operation currently
/// holding the clean Local host.
pub const CLEAN_LOCAL_HOST_CONTROL_QUEUE_CAPACITY: usize = 1;

const OWNER_RUNNING: u8 = 0;
const OWNER_CLOSING: u8 = 1;
const OWNER_CLOSED: u8 = 2;
const OWNER_FAILED: u8 = 3;

/// Stable errors exposed by the read-only control boundary.
///
/// Storage, issuer, and host implementation errors remain on the owner
/// thread. `QueryFailed` reports a failed durable read without leaking a
/// generic backend error through cloned handles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CleanLocalHostControlError {
    /// The sole waiting slot is occupied. The request was not admitted.
    Busy,
    /// Shutdown began before the request was admitted or completed.
    Closed,
    /// The owner thread panicked, disconnected, or could not be started.
    OwnerFailed,
    /// The exact full SDK `AgentId` is not present in this host.
    NotFound,
    /// The owner remained alive, but its durable read failed closed.
    QueryFailed,
}

impl fmt::Display for CleanLocalHostControlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "clean Local-host control failed: {self:?}")
    }
}

impl core::error::Error for CleanLocalHostControlError {}

/// Externally meaningful bootstrap phase. A control is not published until
/// bootstrap has completed, so no provisional or backend-specific state can
/// escape this boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CleanLocalHostBootstrapPhase {
    Complete,
}

/// Immutable owner state returned from the worker as one bounded snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CleanLocalHostStatus {
    pins: CleanSystemAgentPins,
    creation_receipt: AuthorityReceipt,
    phase: CleanLocalHostBootstrapPhase,
    issuer_sequence_high_water: u64,
    issuer_acknowledged_through: u64,
}

impl CleanLocalHostStatus {
    pub const fn pins(&self) -> &CleanSystemAgentPins {
        &self.pins
    }

    pub const fn creation_receipt(&self) -> &AuthorityReceipt {
        &self.creation_receipt
    }

    pub const fn descriptor(&self) -> &AgentDescriptor {
        self.pins.descriptor()
    }

    pub const fn identity(&self) -> &AgentIdentity {
        &self.pins.descriptor().identity
    }

    pub const fn phase(&self) -> CleanLocalHostBootstrapPhase {
        self.phase
    }

    pub const fn issuer_sequence_high_water(&self) -> u64 {
        self.issuer_sequence_high_water
    }

    pub const fn issuer_acknowledged_through(&self) -> u64 {
        self.issuer_acknowledged_through
    }
}

struct SharedControl {
    commands: SyncSender<Command>,
    state: Arc<AtomicU8>,
    // Admission and the Running -> Closing transition are serialized. No
    // caller holds this lock while waiting for the worker, so shutdown/join
    // cannot form a lock cycle with a request.
    admission: Mutex<()>,
}

/// Cloneable, bounded, read-only handle to one clean Local owner thread.
///
/// All routing uses complete `vos_agent_sdk::AgentId` values. A handle cannot
/// mutate lifecycle state, invoke an actor, access a legacy service route, or
/// extend the lifetime of the lifecycle guard's worker after shutdown.
#[derive(Clone)]
pub struct CleanLocalHostControl {
    shared: Arc<SharedControl>,
}

impl fmt::Debug for CleanLocalHostControl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CleanLocalHostControl")
            .field("running", &self.is_running())
            .finish_non_exhaustive()
    }
}

impl CleanLocalHostControl {
    /// Whether the lifecycle owner is still admitting read operations.
    pub fn is_running(&self) -> bool {
        self.shared.state.load(Ordering::Acquire) == OWNER_RUNNING
    }

    /// List complete SDK Agent identifiers in canonical order.
    pub fn list(&self) -> Result<Vec<AgentId>, CleanLocalHostControlError> {
        self.request(Command::List)
    }

    /// Read the exact immutable descriptor selected by a complete SDK ID.
    pub fn show(&self, agent: AgentId) -> Result<AgentDescriptor, CleanLocalHostControlError> {
        self.request(|reply| Command::Show { agent, reply })
    }

    /// Read immutable system pins, creation evidence, and issuer progress.
    pub fn status(&self) -> Result<CleanLocalHostStatus, CleanLocalHostControlError> {
        self.request(Command::Status)
    }

    fn request<T>(
        &self,
        command: impl FnOnce(SyncSender<Result<T, CleanLocalHostControlError>>) -> Command,
    ) -> Result<T, CleanLocalHostControlError> {
        let result = {
            let _admission = self
                .shared
                .admission
                .lock()
                .map_err(|_| CleanLocalHostControlError::OwnerFailed)?;
            match self.shared.state.load(Ordering::Acquire) {
                OWNER_RUNNING => {}
                OWNER_CLOSING | OWNER_CLOSED => {
                    return Err(CleanLocalHostControlError::Closed);
                }
                _ => return Err(CleanLocalHostControlError::OwnerFailed),
            }
            let (reply, result) = mpsc::sync_channel(1);
            match self.shared.commands.try_send(command(reply)) {
                Ok(()) => result,
                Err(TrySendError::Full(_)) => return Err(CleanLocalHostControlError::Busy),
                Err(TrySendError::Disconnected(_)) => {
                    mark_owner_failed(&self.shared.state);
                    return Err(CleanLocalHostControlError::OwnerFailed);
                }
            }
        };
        result.recv().unwrap_or_else(|_| {
            if matches!(
                self.shared.state.load(Ordering::Acquire),
                OWNER_CLOSING | OWNER_CLOSED
            ) {
                Err(CleanLocalHostControlError::Closed)
            } else {
                mark_owner_failed(&self.shared.state);
                Err(CleanLocalHostControlError::OwnerFailed)
            }
        })
    }

    #[cfg(test)]
    fn block_owner_for_test(
        &self,
        active: SyncSender<()>,
        release: Receiver<()>,
    ) -> Result<(), CleanLocalHostControlError> {
        self.request(|reply| Command::BlockForTest {
            active,
            release,
            reply,
        })
    }

    #[cfg(test)]
    fn panic_owner_for_test(&self) -> Result<(), CleanLocalHostControlError> {
        self.request(Command::PanicForTest)
    }

    #[cfg(test)]
    fn owner_thread_for_test(&self) -> Result<thread::ThreadId, CleanLocalHostControlError> {
        self.request(Command::ThreadForTest)
    }
}

/// Non-cloneable lifecycle guard for a serialized clean Local host.
///
/// This is the only value which owns the worker's join handle. Explicit
/// shutdown and `Drop` both close admission before joining; cloned controls
/// become terminally `Closed` and cannot keep the bootstrap stores, issuer,
/// or filesystem host alive.
pub struct CleanLocalHostControlOwner {
    control: CleanLocalHostControl,
    worker: Option<JoinHandle<()>>,
}

impl fmt::Debug for CleanLocalHostControlOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CleanLocalHostControlOwner")
            .field("running", &self.control.is_running())
            .finish_non_exhaustive()
    }
}

impl CleanLocalHostControlOwner {
    /// Move a fully bootstrapped owner onto its dedicated single-writer
    /// thread. The method returns only after that thread has taken ownership.
    pub fn start<P, R, I>(
        owner: CleanSystemAgentBootstrapOwner<P, R, I>,
    ) -> Result<Self, CleanLocalHostControlError>
    where
        P: CleanSystemAgentBootstrapStore + Send + 'static,
        R: CleanSystemAgentBootstrapStore + Send + 'static,
        I: CleanManagementIssuerStore + Send + 'static,
    {
        let (commands, receiver) = mpsc::sync_channel(CLEAN_LOCAL_HOST_CONTROL_QUEUE_CAPACITY);
        let state = Arc::new(AtomicU8::new(OWNER_RUNNING));
        let worker_state = state.clone();
        let (ready, started) = mpsc::sync_channel(0);
        let worker = thread::Builder::new()
            .name("vos-clean-local-host".into())
            .spawn(move || {
                let _ = ready.send(());
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    clean_local_host_worker(owner, receiver, &worker_state)
                }));
                let terminal = match outcome {
                    Ok(true) => OWNER_CLOSED,
                    Ok(false) | Err(_) => OWNER_FAILED,
                };
                worker_state.store(terminal, Ordering::Release);
            })
            .map_err(|_| CleanLocalHostControlError::OwnerFailed)?;
        if started.recv().is_err() {
            let _ = worker.join();
            return Err(CleanLocalHostControlError::OwnerFailed);
        }
        Ok(Self {
            control: CleanLocalHostControl {
                shared: Arc::new(SharedControl {
                    commands,
                    state,
                    admission: Mutex::new(()),
                }),
            },
            worker: Some(worker),
        })
    }

    /// Obtain a read-only handle. Clones are invalidated by owner shutdown.
    pub fn control(&self) -> CleanLocalHostControl {
        self.control.clone()
    }

    pub fn is_running(&self) -> bool {
        self.control.is_running()
    }

    /// Stop admitting commands without waiting for the active read to finish.
    /// [`Self::shutdown_and_join`] or `Drop` still performs the mandatory join.
    pub fn request_shutdown(&self) {
        let admission = self.control.shared.admission.lock();
        // Poisoning can only come from a panic while changing lifecycle state;
        // fail closed and continue waking the worker.
        let _admission = match admission {
            Ok(admission) => admission,
            Err(poisoned) => poisoned.into_inner(),
        };
        if self
            .control
            .shared
            .state
            .compare_exchange(
                OWNER_RUNNING,
                OWNER_CLOSING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            // A full channel already contains the wake-up. The state change,
            // rather than delivery of this best-effort marker, closes admission.
            let _ = self.control.shared.commands.try_send(Command::Wake);
        }
    }

    /// Close admission and join the owner thread. Returning success proves
    /// that the complete bootstrap owner was dropped on that thread.
    pub fn shutdown_and_join(mut self) -> Result<(), CleanLocalHostControlError> {
        self.request_shutdown();
        self.join_worker()
    }

    fn join_worker(&mut self) -> Result<(), CleanLocalHostControlError> {
        let Some(worker) = self.worker.take() else {
            return match self.control.shared.state.load(Ordering::Acquire) {
                OWNER_CLOSED => Ok(()),
                _ => Err(CleanLocalHostControlError::OwnerFailed),
            };
        };
        if worker.join().is_err() {
            mark_owner_failed(&self.control.shared.state);
        }
        match self.control.shared.state.load(Ordering::Acquire) {
            OWNER_CLOSED => Ok(()),
            _ => Err(CleanLocalHostControlError::OwnerFailed),
        }
    }
}

impl Drop for CleanLocalHostControlOwner {
    fn drop(&mut self) {
        self.request_shutdown();
        // Do not hold the admission mutex while joining. Every production
        // command is a finite read and never has access to this lifecycle guard.
        let _ = self.join_worker();
    }
}

enum Command {
    List(SyncSender<Result<Vec<AgentId>, CleanLocalHostControlError>>),
    Show {
        agent: AgentId,
        reply: SyncSender<Result<AgentDescriptor, CleanLocalHostControlError>>,
    },
    Status(SyncSender<Result<CleanLocalHostStatus, CleanLocalHostControlError>>),
    Wake,
    #[cfg(test)]
    BlockForTest {
        active: SyncSender<()>,
        release: Receiver<()>,
        reply: SyncSender<Result<(), CleanLocalHostControlError>>,
    },
    #[cfg(test)]
    PanicForTest(SyncSender<Result<(), CleanLocalHostControlError>>),
    #[cfg(test)]
    ThreadForTest(SyncSender<Result<thread::ThreadId, CleanLocalHostControlError>>),
}

fn clean_local_host_worker<P, R, I>(
    owner: CleanSystemAgentBootstrapOwner<P, R, I>,
    receiver: Receiver<Command>,
    state: &AtomicU8,
) -> bool
where
    P: CleanSystemAgentBootstrapStore,
    R: CleanSystemAgentBootstrapStore,
    I: CleanManagementIssuerStore,
{
    loop {
        if state.load(Ordering::Acquire) != OWNER_RUNNING {
            reject_queued_commands(&receiver);
            drop(owner);
            return true;
        }
        match receiver.recv() {
            Ok(command) if state.load(Ordering::Acquire) == OWNER_RUNNING => {
                run_command(&owner, command)
            }
            Ok(command) => reject_command(command),
            Err(_) => {
                drop(owner);
                return false;
            }
        }
    }
}

fn run_command<P, R, I>(owner: &CleanSystemAgentBootstrapOwner<P, R, I>, command: Command)
where
    P: CleanSystemAgentBootstrapStore,
    R: CleanSystemAgentBootstrapStore,
    I: CleanManagementIssuerStore,
{
    match command {
        Command::List(reply) => {
            let result = owner.host().list().map_err(map_host_read_error);
            let _ = reply.send(result);
        }
        Command::Show { agent, reply } => {
            let result = owner
                .host()
                .show(agent)
                .cloned()
                .map_err(map_host_read_error);
            let _ = reply.send(result);
        }
        Command::Status(reply) => {
            let _ = reply.send(Ok(CleanLocalHostStatus {
                pins: owner.pins().clone(),
                creation_receipt: owner.creation_receipt().clone(),
                phase: CleanLocalHostBootstrapPhase::Complete,
                issuer_sequence_high_water: owner.issuer_sequence_high_water(),
                issuer_acknowledged_through: owner.issuer_acknowledged_through(),
            }));
        }
        Command::Wake => {}
        #[cfg(test)]
        Command::BlockForTest {
            active,
            release,
            reply,
        } => {
            let result = active
                .send(())
                .and_then(|()| release.recv().map_err(|_| mpsc::SendError(())))
                .map_err(|_| CleanLocalHostControlError::OwnerFailed);
            let _ = reply.send(result);
        }
        #[cfg(test)]
        Command::PanicForTest(_reply) => panic!("intentional clean Local-owner panic"),
        #[cfg(test)]
        Command::ThreadForTest(reply) => {
            let _ = reply.send(Ok(thread::current().id()));
        }
    }
}

fn reject_queued_commands(receiver: &Receiver<Command>) {
    loop {
        match receiver.try_recv() {
            Ok(command) => reject_command(command),
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => return,
        }
    }
}

fn reject_command(command: Command) {
    match command {
        Command::List(reply) => {
            let _ = reply.send(Err(CleanLocalHostControlError::Closed));
        }
        Command::Show { reply, .. } => {
            let _ = reply.send(Err(CleanLocalHostControlError::Closed));
        }
        Command::Status(reply) => {
            let _ = reply.send(Err(CleanLocalHostControlError::Closed));
        }
        Command::Wake => {}
        #[cfg(test)]
        Command::BlockForTest { reply, .. } => {
            let _ = reply.send(Err(CleanLocalHostControlError::Closed));
        }
        #[cfg(test)]
        Command::PanicForTest(reply) => {
            let _ = reply.send(Err(CleanLocalHostControlError::Closed));
        }
        #[cfg(test)]
        Command::ThreadForTest(reply) => {
            let _ = reply.send(Err(CleanLocalHostControlError::Closed));
        }
    }
}

fn map_host_read_error(error: LocalAgentHostError) -> CleanLocalHostControlError {
    match error {
        LocalAgentHostError::NotFound => CleanLocalHostControlError::NotFound,
        _ => CleanLocalHostControlError::QueryFailed,
    }
}

fn mark_owner_failed(state: &AtomicU8) {
    let mut current = state.load(Ordering::Acquire);
    while current == OWNER_RUNNING {
        match state.compare_exchange_weak(
            OWNER_RUNNING,
            OWNER_FAILED,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

#[cfg(test)]
mod tests {
    use core::num::NonZeroU64;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use ed25519_dalek::{Signer as _, SigningKey};

    use super::*;
    use crate::agent::clean_authority_issuer::{
        AuthorizedCleanManagementDecision, CleanManagementDecisionContext,
        CleanManagementReceiptSigner,
    };
    use crate::agent::clean_bootstrap::AuthorizedCleanSystemAgentBootstrap;
    use crate::agent::package_admission::admit_runtime_package;
    use crate::agent::sdk::authority::{
        AgentAuthorityBinding, AuthorityEvidence, AuthorityIssuer, AuthorityLaneRoots,
    };
    use crate::agent::sdk::contract::RuntimePackageContract;
    use crate::agent::sdk::package::{
        AgentRuntimePackageManifest, PackageArtifact, PackageEnvelope, PackageManifest,
        PackageSigning,
    };
    use crate::agent::sdk::{
        ActorId, AgentIdentity, AgentProfile, AgentReplica, BlobRef, DeploymentId, Hash,
        ManagementRequest, NodeId, PrincipalId, ProducerId, ProgramId, ReplicaRole,
        RuntimeCapabilities, SpaceId,
    };

    const PACKAGE_SEED: [u8; 32] = [0x71; 32];
    const AUTHORITY_SEED: [u8; 32] = [0x72; 32];
    const RUNTIME_PVM: &[u8] = include_bytes!("../../../vosx/blobs/agent_runtime.pvm");
    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "vos-clean-control-{label}-{}-{sequence}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn host_root(&self) -> PathBuf {
            self.0.join("agents")
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[derive(Clone, Copy, Debug)]
    struct MemoryStoreError;

    impl fmt::Display for MemoryStoreError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("memory store failed")
        }
    }

    impl std::error::Error for MemoryStoreError {}

    #[derive(Default)]
    struct MemoryStore {
        image: Option<Vec<u8>>,
        drops: Option<Arc<Mutex<Vec<thread::ThreadId>>>>,
    }

    impl MemoryStore {
        fn tracked(drops: Arc<Mutex<Vec<thread::ThreadId>>>) -> Self {
            Self {
                image: None,
                drops: Some(drops),
            }
        }
    }

    impl Drop for MemoryStore {
        fn drop(&mut self) {
            if let Some(drops) = &self.drops
                && let Ok(mut drops) = drops.lock()
            {
                drops.push(thread::current().id());
            }
        }
    }

    impl CleanSystemAgentBootstrapStore for MemoryStore {
        type Error = MemoryStoreError;

        fn load(&mut self, maximum_bytes: usize) -> Result<Option<Vec<u8>>, Self::Error> {
            if self
                .image
                .as_ref()
                .is_some_and(|image| image.len() > maximum_bytes)
            {
                return Err(MemoryStoreError);
            }
            Ok(self.image.clone())
        }

        fn commit(&mut self, image: &[u8]) -> Result<(), Self::Error> {
            self.image = Some(image.to_vec());
            Ok(())
        }
    }

    impl CleanManagementIssuerStore for MemoryStore {
        type Error = MemoryStoreError;

        fn load(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
            Ok(self.image.clone())
        }

        fn commit(&mut self, image: &[u8]) -> Result<(), Self::Error> {
            self.image = Some(image.to_vec());
            Ok(())
        }
    }

    #[derive(Clone, Copy, Debug)]
    struct SignerError;

    impl fmt::Display for SignerError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("signer failed")
        }
    }

    impl std::error::Error for SignerError {}

    struct TestSigner(SigningKey);

    impl CleanManagementReceiptSigner for TestSigner {
        type Error = SignerError;

        fn public_key(&self) -> [u8; 32] {
            self.0.verifying_key().to_bytes()
        }

        fn sign_authority_receipt(&mut self, message: &[u8]) -> Result<[u8; 64], Self::Error> {
            Ok(self.0.sign(message).to_bytes())
        }
    }

    struct Fixture {
        space: SpaceId,
        node: NodeId,
        descriptor: AgentDescriptor,
        plan: AuthorizedCleanSystemAgentBootstrap,
    }

    fn signed_runtime_package() -> Vec<u8> {
        let key = SigningKey::from_bytes(&PACKAGE_SEED);
        let public_key = key.verifying_key().to_bytes();
        let mut package = PackageEnvelope {
            manifest: PackageManifest::AgentRuntime(AgentRuntimePackageManifest {
                name: "clean-control-runtime".into(),
                outer_program: BlobRef::of_bytes(RUNTIME_PVM),
                contract: RuntimePackageContract::canonical(),
                capabilities: RuntimeCapabilities::standard(),
                signing: PackageSigning {
                    producer: ProducerId::of_public_key(&public_key),
                    public_key,
                    signature: [0; 64],
                },
            }),
            artifacts: vec![PackageArtifact {
                identity: BlobRef::of_bytes(RUNTIME_PVM),
                bytes: RUNTIME_PVM.to_vec(),
            }],
        };
        let signing_bytes = package.signing_bytes().unwrap();
        package.manifest.signing_mut().signature = key.sign(&signing_bytes).to_bytes();
        package.encode().unwrap()
    }

    fn fixture(discriminator: u8) -> Fixture {
        let space = SpaceId([0x41; 32]);
        let node = NodeId([0x42; 32]);
        let runtime_package_bytes = signed_runtime_package();
        let runtime = admit_runtime_package(&runtime_package_bytes).unwrap();
        let authority_key = SigningKey::from_bytes(&AUTHORITY_SEED);
        let authority_public_key = authority_key.verifying_key().to_bytes();
        let principal = PrincipalId([discriminator; 32]);
        let creation_nonce = Hash([discriminator.wrapping_add(1); 32]);
        let agent = AgentId::derive(space, principal, creation_nonce.as_bytes());
        let descriptor = AgentDescriptor {
            identity: AgentIdentity {
                space,
                agent,
                owner: principal,
                profile: AgentProfile::Local,
                runtime_deployment: runtime.deployment(),
                runtime_program: runtime.program(),
                runtime_producer: runtime.producer(),
            },
            creation_nonce,
            authority: AgentAuthorityBinding {
                policy: Hash([0x43; 32]),
                issuer: AuthorityIssuer {
                    principal: PrincipalId([0x44; 32]),
                    actor: ActorId([0x45; 32]),
                    deployment: DeploymentId([0x46; 32]),
                    program: ProgramId([0x47; 32]),
                    producer: ProducerId::of_public_key(&authority_public_key),
                },
                public_key: authority_public_key,
                initial_epoch: 1,
            },
            runtime_package: runtime.package_ref().clone(),
            runtime_contract: runtime.manifest().contract,
            capabilities: runtime.capabilities(),
            replicas: vec![AgentReplica {
                node,
                principal,
                role: ReplicaRole::Voter,
            }],
        };
        descriptor.validate().unwrap();
        let request = ManagementRequest::Create(Box::new(descriptor.clone()));
        let decision = AuthorizedCleanManagementDecision::new(
            NonZeroU64::new(1).unwrap(),
            CleanManagementDecisionContext {
                space,
                agent,
                runtime_deployment: descriptor.identity.runtime_deployment,
                evidence: AuthorityEvidence {
                    package: None,
                    proof: None,
                    commitment: Hash([0x48; 32]),
                },
                lane_roots: AuthorityLaneRoots::default(),
                epoch: 1,
                valid_from: 10,
                expires_at: 20,
            },
            &request,
        )
        .unwrap();
        let plan = AuthorizedCleanSystemAgentBootstrap::new(
            descriptor.clone(),
            runtime_package_bytes,
            decision,
        )
        .unwrap();
        Fixture {
            space,
            node,
            descriptor,
            plan,
        }
    }

    fn start_control(
        label: &str,
        discriminator: u8,
        drops: Option<Arc<Mutex<Vec<thread::ThreadId>>>>,
    ) -> (
        TestDirectory,
        Fixture,
        AuthorityReceipt,
        CleanLocalHostControlOwner,
        CleanLocalHostControl,
    ) {
        let directory = TestDirectory::new(label);
        let fixture = fixture(discriminator);
        let store = || {
            drops.as_ref().map_or_else(MemoryStore::default, |drops| {
                MemoryStore::tracked(drops.clone())
            })
        };
        let mut signer = TestSigner(SigningKey::from_bytes(&AUTHORITY_SEED));
        let owner = CleanSystemAgentBootstrapOwner::open_or_bootstrap(
            store(),
            store(),
            store(),
            &mut signer,
            &fixture.plan,
            directory.host_root(),
            fixture.space,
            fixture.node,
            10,
        )
        .unwrap();
        let receipt = owner.creation_receipt().clone();
        let lifecycle = CleanLocalHostControlOwner::start(owner).unwrap();
        let control = lifecycle.control();
        (directory, fixture, receipt, lifecycle, control)
    }

    #[test]
    fn exact_full_id_descriptor_and_status_survive_cloned_control() {
        fn assert_send<T: Send>() {}
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send::<CleanLocalHostControlOwner>();
        assert_send_sync::<CleanLocalHostControl>();

        let (_directory, fixture, receipt, lifecycle, control) = start_control("exact", 0x51, None);
        let clone = control.clone();
        assert_eq!(
            control.list().unwrap(),
            vec![fixture.descriptor.identity.agent]
        );
        assert_eq!(
            clone.show(fixture.descriptor.identity.agent).unwrap(),
            fixture.descriptor
        );

        // Preserve the low-order bytes and change only the remote end of the
        // 256-bit route. Any truncated service-style lookup would alias it.
        let mut wrong = fixture.descriptor.identity.agent;
        wrong.0[31] ^= 0x80;
        assert_eq!(
            control.show(wrong),
            Err(CleanLocalHostControlError::NotFound)
        );

        let status = clone.status().unwrap();
        assert_eq!(status.phase(), CleanLocalHostBootstrapPhase::Complete);
        assert_eq!(status.descriptor(), &fixture.descriptor);
        assert_eq!(status.identity(), &fixture.descriptor.identity);
        assert_eq!(status.pins().agent(), fixture.descriptor.identity.agent);
        assert_eq!(status.creation_receipt(), &receipt);
        assert_eq!(status.issuer_sequence_high_water(), 1);
        assert_eq!(status.issuer_acknowledged_through(), 1);

        lifecycle.shutdown_and_join().unwrap();
        assert!(!control.is_running());
        assert_eq!(control.list(), Err(CleanLocalHostControlError::Closed));
        assert_eq!(control.show(wrong), Err(CleanLocalHostControlError::Closed));
        assert_eq!(control.status(), Err(CleanLocalHostControlError::Closed));
    }

    #[test]
    fn full_queue_backpressures_and_shutdown_rejects_queued_and_new_reads() {
        let (_directory, fixture, _receipt, lifecycle, control) =
            start_control("bounded", 0x52, None);
        let (active, active_rx) = mpsc::sync_channel(0);
        let (release, release_rx) = mpsc::sync_channel(0);
        let active_control = control.clone();
        let active_thread =
            thread::spawn(move || active_control.block_owner_for_test(active, release_rx));
        active_rx.recv().unwrap();

        let (queued_reply, queued_result) = mpsc::sync_channel(1);
        {
            let _admission = control.shared.admission.lock().unwrap();
            assert_eq!(control.shared.state.load(Ordering::Acquire), OWNER_RUNNING);
            assert!(
                control
                    .shared
                    .commands
                    .try_send(Command::Status(queued_reply))
                    .is_ok()
            );
        }
        assert_eq!(control.list(), Err(CleanLocalHostControlError::Busy));

        lifecycle.request_shutdown();
        // This request begins after shutdown and therefore cannot enter even
        // though the worker and its one queued request still physically exist.
        assert_eq!(
            control.show(fixture.descriptor.identity.agent),
            Err(CleanLocalHostControlError::Closed)
        );
        release.send(()).unwrap();
        assert_eq!(active_thread.join().unwrap(), Ok(()));
        assert_eq!(
            queued_result.recv_timeout(Duration::from_secs(5)).unwrap(),
            Err(CleanLocalHostControlError::Closed)
        );
        lifecycle.shutdown_and_join().unwrap();
    }

    #[test]
    fn owner_panic_disconnects_handles_and_is_reported_by_join() {
        let (_directory, _fixture, _receipt, lifecycle, control) =
            start_control("panic", 0x53, None);
        assert_eq!(
            control.panic_owner_for_test(),
            Err(CleanLocalHostControlError::OwnerFailed)
        );
        assert_eq!(control.list(), Err(CleanLocalHostControlError::OwnerFailed));
        assert_eq!(
            lifecycle.shutdown_and_join(),
            Err(CleanLocalHostControlError::OwnerFailed)
        );
    }

    #[test]
    fn drop_closes_a_full_queue_joins_and_drops_all_stores_on_owner_thread() {
        let drops = Arc::new(Mutex::new(Vec::new()));
        let (_directory, _fixture, _receipt, lifecycle, control) =
            start_control("drop", 0x54, Some(drops.clone()));
        let owner_thread = control.owner_thread_for_test().unwrap();
        let (active, active_rx) = mpsc::sync_channel(0);
        let (release, release_rx) = mpsc::sync_channel(0);
        let active_control = control.clone();
        let active_thread =
            thread::spawn(move || active_control.block_owner_for_test(active, release_rx));
        active_rx.recv().unwrap();

        let (queued_reply, queued_result) = mpsc::sync_channel(1);
        assert!(
            control
                .shared
                .commands
                .try_send(Command::Status(queued_reply))
                .is_ok()
        );
        lifecycle.request_shutdown();
        let (dropped, drop_complete) = mpsc::sync_channel(0);
        let drop_thread = thread::spawn(move || {
            drop(lifecycle);
            dropped.send(()).unwrap();
        });
        assert_eq!(control.status(), Err(CleanLocalHostControlError::Closed));

        release.send(()).unwrap();
        assert_eq!(active_thread.join().unwrap(), Ok(()));
        assert_eq!(
            queued_result.recv_timeout(Duration::from_secs(5)).unwrap(),
            Err(CleanLocalHostControlError::Closed)
        );
        drop_complete.recv_timeout(Duration::from_secs(5)).unwrap();
        drop_thread.join().unwrap();

        let observed = drops.lock().unwrap();
        assert_eq!(observed.len(), 3);
        assert!(observed.iter().all(|thread| *thread == owner_thread));
        assert_eq!(control.list(), Err(CleanLocalHostControlError::Closed));
    }
}
