//! Public warm handoff through actual locked production owners. The packaged
//! workflow uses the ordinary retained CLI Create path; separate candidate
//! cases retain their fault fixtures. This is not daemon or load qualification.

use super::*;
use std::io::Write as _;
use std::net::{SocketAddr, TcpListener};
use std::os::unix::fs::OpenOptionsExt as _;
use vos::agent::genesis::AgentGenesisArchiveRecord;
use vos::agent::local_lifecycle::{
    SharedCreateDisposition, SharedCreateSubmission, SharedMemberAdmissionSubmission,
};
use vos::agent::package_admission::{
    AdmittedRuntimePackage, AdmittedStateRuntimePackage, admit_runtime_package,
    admit_state_runtime_package,
};
use vos::agent::sdk::contract::{ExternalStateResourceLimits, RuntimePackageContract};
use vos::agent::sdk::package::{PackageArtifact, PackageEnvelope, PackageManifest};
use vos::agent::sdk::wire::CanonicalWire as _;
use vos::agent::sdk::{BlobRef, LaneSet, ProofSystemSet, StateLane};
use vos::service::ServiceWire as _;

pub(super) fn fresh_system_runtime(operator: &Keypair) -> AdmittedRuntimePackage {
    let bytes =
        std::fs::read(std::env::var_os("VOS_AGENT_RUNTIME_COST_CANDIDATE").unwrap()).unwrap();
    admit_runtime_package(&signed_runtime(operator, bytes, false)).unwrap()
}

fn external_runtime(operator: &Keypair) -> AdmittedStateRuntimePackage {
    let target = PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").unwrap());
    let elf =
        std::fs::read(target.join("agent-state-standard/riscv64em-vos/release/agent_runtime.elf"))
            .unwrap();
    let pvm = vos_pvm_compiler::link_elf_spi(&elf).unwrap();
    admit_state_runtime_package(&signed_runtime(operator, pvm, true)).unwrap()
}

fn signed_runtime(operator: &Keypair, bytes: Vec<u8>, external: bool) -> Vec<u8> {
    let image = crate::bundled::root_signed_agent_runtime_package(operator).unwrap();
    let mut envelope = PackageEnvelope::decode(image.exact_bytes()).unwrap();
    let reference = BlobRef::of_bytes(&bytes);
    let PackageManifest::AgentRuntime(manifest) = &mut envelope.manifest else {
        unreachable!()
    };
    manifest.outer_program = reference.clone();
    if external {
        manifest.contract = RuntimePackageContract::experimental_state_blocks();
        manifest.contract.resources.max_runtime_state_bytes =
            vos::agent::sdk::state_execution::MAX_ADMITTED_EXTERNAL_RUNTIME_STATE_BYTES as u32;
        // Existing explicit fixture policy, not release ceilings or capacity
        // evidence. The real 100,000-transfer acceptance target is unchanged.
        manifest.external_state_limits = Some(ExternalStateResourceLimits {
            max_rows_per_lane: 1_000_000,
            max_row_bytes_per_lane: 1 << 30,
        });
        manifest.capabilities.lanes = LaneSet::of(StateLane::Linear);
        manifest.capabilities.scheduling = false;
        manifest.capabilities.proof_systems = ProofSystemSet::EMPTY;
    } else {
        // Exact opt-in implements Observe; do not relabel the bundled Local guest.
        manifest.contract = RuntimePackageContract::system_observation_image();
        manifest.external_state_limits = None;
    }
    envelope.artifacts = vec![PackageArtifact {
        identity: reference,
        bytes,
    }];
    envelope.manifest.signing_mut().signature =
        sign_exact(operator, &envelope.signing_bytes().unwrap()).unwrap();
    envelope.encode().unwrap()
}

#[allow(clippy::too_many_arguments)]
pub(super) fn public_handoff(
    nodes: &mut [VosNode],
    data: &[PathBuf],
    operator: &Keypair,
    daemons: &[Keypair],
    enrollments: &[vos::agent::sdk::private::NodeEncryptionEnrollment],
    space: SpaceId,
    authority: AuthorityActorTarget,
    inputs: &StartupTestInputs,
    packaged: bool,
    restart: bool,
    recovery_deadline: Option<std::time::Instant>,
    retained: &mut Option<(SharedCreateSubmission, AgentGenesisArchiveRecord)>,
) {
    if let Some(deadline) = recovery_deadline {
        assert!(packaged && restart);
        assert!(std::time::Instant::now() < deadline);
    }
    let addresses: Vec<_> = nodes
        .iter_mut()
        .enumerate()
        .map(|(index, node)| {
            if !restart {
                let mut key = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(data[index].join("node.key"))
                    .unwrap();
                key.write_all(&daemons[index].to_protobuf_encoding().unwrap())
                    .unwrap();
                key.sync_all().unwrap();
                // Exercise client selection from the immutable deployed plan,
                // without an optional bootstrap-bundle setting on either run.
                super::super::super::local_config::save(
                    &data[index],
                    &super::super::super::local_config::LocalConfig::default(),
                )
                .unwrap();
            }
            let probe = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = probe.local_addr().unwrap();
            drop(probe);
            node.add_http_ingress(vos::ingress::HttpIngressConfig {
                name: format!("warm-member-{index}"),
                listen: address,
                tls: None,
                max_connections: 8,
            })
            .unwrap();
            address
        })
        .collect();

    if retained.is_none() {
        assert!(!restart);
        let (submission, archive) = if packaged {
            assert_eq!(
                inputs.runtime.exact_bytes(),
                crate::bundled::root_signed_system_agent_runtime_package(operator)
                    .unwrap()
                    .exact_bytes(),
            );
            assert_eq!(
                inputs.authority.exact_bytes(),
                crate::bundled::root_signed_actor_package(
                    crate::bundled::system_authority_package_template(),
                    SYSTEM_AUTHORITY_NAME,
                    operator,
                )
                .unwrap()
                .exact_bytes(),
            );
            create_packaged(
                &data[0],
                addresses[0],
                operator,
                space,
                raw_public_key(&daemons[0]).unwrap(),
                enrollments,
            )
        } else {
            let runtime = external_runtime(operator);
            let (descriptor, committee) = super::super::super::shared_operation::create_materials(
                operator,
                authority,
                raw_public_key(&daemons[0]).unwrap(),
                Hash([0xc1; 32]),
                &runtime,
                enrollments,
            )
            .unwrap();
            let public = raw_public_key(operator).unwrap();
            let request = ManagementRequest::Create(Box::new(descriptor.clone()));
            let mut call = AuthorityCredentialCall {
                invocation: InvocationId::ZERO,
                authority,
                managed: ManagedAgentTarget {
                    space,
                    agent: descriptor.identity.agent,
                    owner: descriptor.identity.owner,
                    profile: AgentProfile::Shared,
                    runtime_deployment: runtime.deployment(),
                    transition_producer: descriptor.identity.transition_producer,
                },
                principal: descriptor.identity.owner,
                credential: CredentialId::of_public_key(&public),
                request_sequence: NonZeroU64::new(2).unwrap(),
                credential_public_key: public,
                authenticated_node: None,
                requested_valid_from: inputs.clock.load(std::sync::atomic::Ordering::Acquire),
                requested_expires_at: u64::MAX,
                plan: request.authorization_plan().unwrap(),
                signature: [0; 64],
            };
            call.invocation = call.expected_invocation();
            call.signature = sign_exact(operator, &call.signing_bytes()).unwrap();
            let submission =
                SharedCreateSubmission::new(descriptor, call, runtime, committee).unwrap();
            let archive = create_public(addresses[0], &submission, None);
            (submission, archive)
        };
        *retained = Some((submission, archive));
    }
    let (submission, record) = retained.as_ref().unwrap();
    let locator = record.provision().proposal().locator();
    let bytes = record.encode();

    if restart {
        assert_eq!(create_public(addresses[0], submission, recovery_deadline), *record);
    }
    for index in 1..3 {
        let archive_path = data[index].join("public-member.ogar");
        if !restart {
            std::fs::write(&archive_path, &bytes).unwrap();
            if index == 1 {
                // A's valid data and archive cannot admit B or report B as A.
                // Target refusal precedes even member namespace preparation.
                let wrong_root = data[2].join("shared-agent-members");
                assert!(!wrong_root.exists());
                retry_target_refusal(|| {
                    let result = super::super::super::shared_operation::admit_shared_archive(
                        &data[index],
                        addresses[2],
                        operator,
                        space,
                        raw_public_key(&daemons[index]).unwrap(),
                        &archive_path,
                    );
                    assert!(
                        !wrong_root.exists(),
                        "wrong-target attempt prepared a member namespace"
                    );
                    result
                });
                assert!(!wrong_root.exists());
            }
            lose_successful_admission_response(addresses[index], &bytes, enrollments[index].node);
        }
        let admit = || {
            super::super::super::shared_operation::admit_shared_archive(
                &data[index],
                addresses[index],
                operator,
                space,
                raw_public_key(&daemons[index]).unwrap(),
                &archive_path,
            )
        };
        let retry_deadline = || {
            recovery_deadline.unwrap_or_else(|| {
                std::time::Instant::now() + Duration::from_secs(120)
            })
        };
        assert_eq!(retry_exact_until("member handoff", retry_deadline(), admit), locator);
        assert_eq!(
            retry_exact_until("already attached member", retry_deadline(), admit),
            locator
        );
        assert_eq!(std::fs::read(&archive_path).unwrap(), bytes);
        assert!(
            super::super::super::shared_operation::admit_shared_archive(
                &data[index],
                addresses[index],
                operator,
                space,
                raw_public_key(&daemons[(index + 1) % 3]).unwrap(),
                &archive_path,
            )
            .is_err(),
            "a different actual node identity cannot select this member"
        );
    }
    for node in nodes {
        assert!(
            !node
                .shutdown_handle()
                .load(std::sync::atomic::Ordering::Acquire)
        );
    }
    if let Some(deadline) = recovery_deadline {
        assert!(
            std::time::Instant::now() <= deadline,
            "whole locked-owner reopen exceeded 30s during retained handoff"
        );
    }
}

fn write_fresh_input(path: &Path, bytes: &[u8]) {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

fn create_packaged(
    data: &Path,
    address: SocketAddr,
    operator: &Keypair,
    space: SpaceId,
    node_public: [u8; 32],
    enrollments: &[vos::agent::sdk::private::NodeEncryptionEnrollment],
) -> (SharedCreateSubmission, AgentGenesisArchiveRecord) {
    use super::super::super::{clean_identity, clean_store, shared_operation};

    // Supply the emitted, admitted role package unchanged. In particular, do
    // not relink a target-directory guest or construct fixture resource limits.
    let runtime = crate::bundled::shared_external_runtime_package_template().unwrap();
    let runtime_path = data.join("packaged-shared-runtime.vos");
    write_fresh_input(&runtime_path, runtime);
    let enrollment_paths = enrollments
        .iter()
        .enumerate()
        .map(|(index, enrollment)| {
            let path = data.join(format!("packaged-member-{index}.nen"));
            write_fresh_input(&path, &enrollment.encode().unwrap());
            path
        })
        .collect();
    let mut args = shared_operation::CreateSharedArgs {
        space: "explicit-packaged-public-workflow".into(),
        runtime: Some(runtime_path.clone()),
        enrollments: enrollment_paths,
        archive_out: data.join("public-create.ogar"),
        http: Some(address),
        resume: false,
    };
    let mut diagnostic_attempt = 0u64;
    let disposition = retry_exact("ordinary packaged CLI Shared Create", || {
        if std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some() {
            diagnostic_attempt += 1;
            tracing::debug!(target: "vos", phase = "ordinary_create_attempt",
                status = "start", attempt = diagnostic_attempt,
                thread = ?std::thread::current().id(), "VOS causal fixture");
        }
        let result = shared_operation::create_shared_for_test(
            data,
            address,
            operator,
            space,
            node_public,
            &args,
        );
        // A transient response can follow durable request publication. Reuse
        // the existing CLI reservation/WAL and unchanged supplied artifacts;
        // never allocate another nonce or re-sign a replacement Create.
        args.resume = true;
        result
    });
    let SharedCreateDisposition::Applied(applied) = disposition else {
        panic!("packaged Root Shared Create did not apply: {disposition:?}")
    };
    if std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some() {
        tracing::debug!(target: "vos", phase = "ordinary_create_complete",
            status = "applied", attempt = diagnostic_attempt,
            thread = ?std::thread::current().id(), "VOS causal fixture");
    }
    let archive = applied.archive().clone();
    super::super::publish_shared_archive(&args.archive_out, &archive.encode()).unwrap();

    let identity = clean_identity::CleanOperatorIdentitySigner::new(operator).unwrap();
    let operation = super::member_workflow::current_operation(data, space, &identity);
    let mut store =
        clean_store::CleanSharedCreateFile::open_or_create(operation.join("request")).unwrap();
    let request = store.load_request().unwrap().unwrap();
    let response = store.load_response().unwrap().unwrap();
    let submission = SharedCreateSubmission::decode(&request).unwrap();
    assert_eq!(submission.encode(), request);
    assert_eq!(submission.runtime().exact_bytes(), runtime);
    assert_eq!(std::fs::read(&runtime_path).unwrap(), runtime);
    assert_eq!(submission.call().principal, identity.principal());
    assert_eq!(submission.call().credential, identity.credential());
    assert_eq!(
        submission.call().managed.transition_producer,
        ProducerId::of_public_key(&node_public),
    );
    // Exercise the existing CLI's signed window, not the candidate fixture's
    // unbounded authorization. This is its current now-60 .. now+3600 policy.
    assert_ne!(submission.call().requested_expires_at, u64::MAX);
    assert_eq!(
        submission.call().requested_expires_at - submission.call().requested_valid_from,
        3660,
    );
    let SharedCreateDisposition::Applied(retained) = submission.decode_response(&response).unwrap()
    else {
        panic!("ordinary Create WAL did not retain its exact Applied terminal")
    };
    assert_eq!(retained.archive(), &archive);
    assert_eq!(std::fs::read(&args.archive_out).unwrap(), archive.encode());
    drop(store);

    let resume = shared_operation::CreateSharedArgs {
        space: args.space,
        runtime: None,
        enrollments: Vec::new(),
        archive_out: args.archive_out,
        http: Some(address),
        resume: true,
    };
    let SharedCreateDisposition::Applied(repeated) = shared_operation::create_shared_for_test(
        data,
        address,
        operator,
        space,
        node_public,
        &resume,
    )
    .expect("ordinary retained Create resume without replacing signed inputs") else {
        panic!("retained packaged Shared Create did not remain Applied")
    };
    assert_eq!(repeated.archive(), &archive);
    (submission, archive)
}

fn lose_successful_admission_response(
    address: SocketAddr,
    bytes: &[u8],
    expected_node: vos::agent::sdk::NodeId,
) {
    let response = retry_exact("lost successful admission response", || {
        ureq::AgentBuilder::new()
            .try_proxy_from_env(false)
            .redirects(0)
            .timeout_connect(Duration::from_secs(5))
            .timeout(Duration::from_secs(130))
            .build()
            .post(&format!("http://{address}/_vos/agents/shared/admit"))
            .set("Content-Type", "application/octet-stream")
            .set(
                SharedMemberAdmissionSubmission::TARGET_NODE_HEADER,
                &hex::encode(expected_node.0),
            )
            .send_bytes(bytes)
            .map_err(anyhow::Error::from)
    });
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.header("Content-Type"),
        Some("application/octet-stream")
    );
    // The real handler generates 200 only after native admission and actual
    // local attachment. Drop its body without obtaining/verifying AGNL; this
    // deterministically loses a completed result, unlike send-and-close.
    drop(response);
}

fn create_public(
    address: SocketAddr,
    submission: &SharedCreateSubmission,
    recovery_deadline: Option<std::time::Instant>,
) -> AgentGenesisArchiveRecord {
    let request = submission.encode();
    let deadline = recovery_deadline
        .unwrap_or_else(|| std::time::Instant::now() + Duration::from_secs(120));
    retry_exact_until("public Shared Create", deadline, || {
        let (status, bytes) = super::super::super::local_create::post_binary_response(
            address,
            "/_vos/agents/shared/create",
            202,
            &request,
            SharedCreateSubmission::MAX_RESPONSE_BYTES,
            Some(SharedCreateSubmission::MAX_RESPONSE_BYTES),
            None,
        )?;
        match submission.decode_response(&bytes).unwrap() {
            SharedCreateDisposition::Applied(applied) => {
                assert_eq!(status, 202);
                Ok(applied.archive().clone())
            }
            SharedCreateDisposition::Denied(_) => panic!("genuine Root Create was denied"),
        }
    })
}

pub(super) fn retry_exact<T>(phase: &str, mut operation: impl FnMut() -> anyhow::Result<T>) -> T {
    // Correctness retries only. This is not the production recovery deadline or
    // workload latency gate; startup and phase time are measured separately.
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    retry_exact_until(phase, deadline, &mut operation)
}

pub(super) fn retry_exact_until<T>(
    phase: &str,
    deadline: std::time::Instant,
    mut operation: impl FnMut() -> anyhow::Result<T>,
) -> T {
    loop {
        assert!(
            std::time::Instant::now() < deadline,
            "{phase} exceeded its phase bound"
        );
        match operation() {
            Ok(value) => {
                assert!(
                    std::time::Instant::now() <= deadline,
                    "{phase} completed after its phase bound"
                );
                return value;
            }
            Err(error)
                if matches!(
                    error.downcast_ref::<ureq::Error>(),
                    Some(ureq::Error::Status(409 | 429 | 503 | 504, _))
                        | Some(ureq::Error::Transport(_))
                ) =>
            {
                assert!(std::time::Instant::now() < deadline, "{phase}: {error:?}");
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(error) => panic!("{phase} failed without retryable transport: {error:?}"),
        }
    }
}

fn retry_target_refusal<T>(mut operation: impl FnMut() -> anyhow::Result<T>) {
    retry_exact("authoritative member target refusal", || {
        let refused = match operation() {
            Ok(_) => panic!("wrong-target member admission succeeded"),
            Err(error) => error,
        };
        if matches!(
            refused.downcast_ref::<ureq::Error>(),
            Some(ureq::Error::Status(503, _))
        ) {
            return Err(refused);
        }
        assert!(
            matches!(
                refused.downcast_ref::<ureq::Error>(),
                Some(ureq::Error::Status(403, _))
            ),
            "expected authoritative node-target refusal, got {refused:?}"
        );
        Ok(())
    });
}

#[test]
fn target_refusal_retries_only_recovering_then_requires_forbidden() {
    let mut attempts = 0;
    retry_target_refusal::<()>(|| {
        attempts += 1;
        let status = if attempts == 1 { 503 } else { 403 };
        Err(ureq::Error::Status(status, ureq::Response::new(status, "fixture", "").unwrap()).into())
    });
    assert_eq!(attempts, 2);
    for status in [200, 409, 504] {
        assert!(
            std::panic::catch_unwind(|| {
                retry_target_refusal::<()>(|| {
                    if status == 200 {
                        return Ok(());
                    }
                    Err(ureq::Error::Status(
                        status,
                        ureq::Response::new(status, "fixture", "").unwrap(),
                    )
                    .into())
                });
            })
            .is_err()
        );
    }
}

#[test]
fn exact_retry_recognizes_retained_submission_unavailability() {
    let mut attempts = 0;
    let result = retry_exact("retained unavailable response", || {
        attempts += 1;
        if attempts == 1 {
            return Err(
                super::super::super::local_create::retained_submission_error(
                    ureq::Error::Status(503, ureq::Response::new(503, "Busy", "").unwrap()).into(),
                ),
            );
        }
        Ok(7)
    });
    assert_eq!(attempts, 2);
    assert_eq!(result, 7);
}

#[test]
fn exact_retry_rejects_success_returning_after_deadline() {
    let entered = std::cell::Cell::new(false);
    let returned = std::cell::Cell::new(false);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let deadline = std::time::Instant::now() + Duration::from_millis(50);
            retry_exact_until("late success fixture", deadline, || {
                entered.set(true);
                std::thread::sleep(Duration::from_millis(100));
                returned.set(true);
                Ok(())
            });
        }))
        .is_err()
    );
    assert!(
        entered.get() && returned.get(),
        "must reject a late successful operation, not only an elapsed precheck"
    );
}
