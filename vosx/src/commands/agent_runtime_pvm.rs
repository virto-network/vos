//! Build and physically validate a standard agent-runtime PVM.

use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow, bail, ensure};
use vos::agent::sdk::wire::CanonicalWire as _;
use vos::agent::sdk::{
    AgentId, DeploymentId, ManagementError, ManagementRequest, ProgramId, RuntimeExecutionContext,
    RuntimeOutcome, RuntimeState, RuntimeTransition, RuntimeWork, SpaceId,
};
use vos_pvm::ExitReason;
use vos_pvm::refine_host::RefineContext;

const ABI_PROBE_GAS: u64 = 1_000_000_000;

pub fn run(
    elf: Option<&Path>,
    out: Option<PathBuf>,
    experimental_state_blocks: bool,
) -> anyhow::Result<()> {
    #[cfg(not(feature = "experimental-state-blocks"))]
    ensure!(
        !experimental_state_blocks,
        "experimental state-runtime probe requires an experimental-state-blocks vosx build"
    );
    let pvm = match elf {
        Some(elf) => {
            let elf_bytes =
                std::fs::read(elf).with_context(|| format!("read {}", elf.display()))?;
            if experimental_state_blocks {
                #[cfg(feature = "experimental-state-blocks")]
                {
                    let pvm = vos_pvm_compiler::link_elf_spi(&elf_bytes)
                        .map_err(|error| anyhow!("transpile state-runtime ELF: {error:?}"))?;
                    validate_state_runtime_pvm(&pvm)?;
                    pvm
                }
                #[cfg(not(feature = "experimental-state-blocks"))]
                unreachable!()
            } else {
                canonical_agent_runtime_pvm(&elf_bytes)?
            }
        }
        None => {
            ensure!(
                !experimental_state_blocks,
                "experimental state-runtime probe requires an explicit candidate ELF"
            );
            let pvm = crate::bundled::agent_runtime_pvm().to_vec();
            validate_agent_runtime_pvm(&pvm)?;
            pvm
        }
    };
    let program = ProgramId::of_pvm(&pvm);
    let out = out.or_else(|| elf.map(|elf| elf.with_extension("pvm")));
    if let Some(out) = out {
        if let Some(parent) = out.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create {}", parent.display()))?;
        }
        std::fs::write(&out, &pvm).with_context(|| format!("write {}", out.display()))?;
        println!("built {}", out.display());
    } else {
        println!("verified bundled standard agent runtime");
    }
    println!("  agent_runtime_program_id = {}", hex::encode(program.0));
    Ok(())
}

#[cfg(feature = "experimental-state-blocks")]
pub(super) fn validate_state_runtime_pvm(pvm: &[u8]) -> anyhow::Result<()> {
    use vos::agent::sdk::authority::{
        AgentAuthorityBinding, AuthorityEvidence, AuthorityIssuer, AuthorityLaneRoots,
        AuthorityOperationKind, AuthorityReceipt, AuthorityReceiptSelector,
    };
    use vos::agent::sdk::contract::ExternalStateResourceLimits;
    use vos::agent::sdk::state_blocks::BlockScope;
    use vos::agent::sdk::state_execution::{
        ExternalLaneWork, MAX_STATE_EXECUTION_OUTPUT_BYTES, StateExecutionOutput,
        StateExecutionWork,
    };
    use vos::agent::sdk::state_root::{RootContext, StateRootDescriptor};
    use vos::agent::sdk::{
        ActorId, AgentDescriptor, AgentIdentity, AgentProfile, AgentReplica, BlobRef, Hash,
        ManagementReply, NodeId, PrincipalId, ProducerId, ReplicaRole, RuntimeCapabilities,
        StateLane,
    };

    let mut allowed = vos_pvm::spi::REFINE_HOST_CALL_ALLOWLIST.to_vec();
    allowed.push(u64::from(
        vos::agent::sdk::state_blocks::STATE_BLOCK_FETCH_CALL,
    ));
    vos_pvm::spi::validate_standard_program_host_calls(pvm, &allowed)
        .map_err(|error| anyhow!("state-runtime outer host-call surface is invalid: {error:?}"))?;
    // Create is the only external operation that can execute with empty
    // authenticated roots. Later inspection must read a published metadata
    // tree and cannot be probed through an unbacked raw RefineContext.
    let signer = libp2p::identity::Keypair::ed25519_from_bytes([0x42; 32])
        .map_err(|error| anyhow!("state-runtime probe signer: {error}"))?;
    let public_key = signer
        .public()
        .try_into_ed25519()
        .map_err(|_| anyhow!("state-runtime probe signer is not Ed25519"))?
        .to_bytes();
    let space = SpaceId([1; 32]);
    let owner = PrincipalId([2; 32]);
    let nonce = Hash([3; 32]);
    let agent = AgentId::derive(space, owner, nonce.as_bytes());
    let descriptor = AgentDescriptor {
        identity: AgentIdentity {
            space,
            agent,
            owner,
            profile: AgentProfile::Local,
            runtime_deployment: DeploymentId([4; 32]),
            runtime_program: vos::agent::sdk::ProgramId::of_pvm(pvm),
            runtime_producer: ProducerId([5; 32]),
            transition_producer: ProducerId([6; 32]),
        },
        creation_nonce: nonce,
        authority: AgentAuthorityBinding {
            policy: Hash([7; 32]),
            issuer: AuthorityIssuer {
                principal: owner,
                actor: ActorId([8; 32]),
                deployment: DeploymentId([9; 32]),
                program: vos::agent::sdk::ProgramId([10; 32]),
                producer: ProducerId::of_public_key(&public_key),
            },
            public_key,
            initial_epoch: 1,
        },
        private_recovery: None,
        runtime_package: BlobRef {
            hash: Hash([11; 32]),
            len: 100,
        },
        runtime_contract:
            vos::agent::sdk::contract::RuntimePackageContract::experimental_state_blocks(),
        capabilities: RuntimeCapabilities::standard(),
        replicas: vec![AgentReplica {
            node: NodeId([12; 32]),
            principal: owner,
            role: ReplicaRole::Voter,
        }],
    };
    descriptor
        .validate()
        .map_err(|error| anyhow!("state-runtime probe descriptor: {error:?}"))?;
    let request = ManagementRequest::Create(Box::new(descriptor.clone()));
    let mut receipt = AuthorityReceipt {
        selector: AuthorityReceiptSelector {
            policy: descriptor.authority.policy,
            issuer: descriptor.authority.issuer,
            space,
            agent,
            operation: AuthorityOperationKind::CreateAgent,
            runtime_deployment: descriptor.identity.runtime_deployment,
            actor: None,
            actor_deployment: None,
            evidence: AuthorityEvidence {
                package: None,
                proof: None,
                commitment: Hash([13; 32]),
            },
            lane_roots: AuthorityLaneRoots::default(),
            epoch: 1,
            decision_sequence: 1,
            acknowledged_through: 0,
            valid_from: 1,
            expires_at: 10,
            request: request.commitment(),
        },
        public_key,
        signature: [0; 64],
    };
    receipt.signature = signer
        .sign(&receipt.signing_bytes())
        .map_err(|error| anyhow!("sign state-runtime probe receipt: {error}"))?
        .try_into()
        .map_err(|_| anyhow!("state-runtime probe signature is not Ed25519"))?;
    let lanes = [StateLane::Linear, StateLane::Merge, StateLane::Local]
        .into_iter()
        .enumerate()
        .map(|(index, lane)| {
            let scope = BlockScope::new(space, agent, Hash([14; 32]), lane)
                .map_err(|error| anyhow!("state-runtime probe scope: {error:?}"))?;
            let before = RootContext::new(scope, Hash([15; 32]), Hash([16; 32]))
                .map_err(|error| anyhow!("state-runtime probe base: {error:?}"))?;
            let next = RootContext::new(scope, Hash([15; 32]), Hash([17 + index as u8; 32]))
                .map_err(|error| anyhow!("state-runtime probe successor: {error:?}"))?;
            Ok(ExternalLaneWork {
                base: StateRootDescriptor::new(before, None),
                next,
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let work = StateExecutionWork::new(
        RuntimeWork::Manage {
            context: RuntimeExecutionContext::Direct,
            space,
            agent,
            runtime_deployment: descriptor.identity.runtime_deployment,
            state: RuntimeState::default(),
            request: Box::new(request),
            authority: Some(Box::new(receipt)),
            observed_slot: 1,
        },
        lanes,
        ExternalStateResourceLimits {
            max_rows_per_lane: 1_000_000,
            max_row_bytes_per_lane: 1 << 30,
        },
    )
    .map_err(|error| anyhow!("state-runtime ABI probe work: {error}"))?;
    let input = work
        .encode()
        .map_err(|error| anyhow!("encode state-runtime ABI probe: {error}"))?;
    let invocation = RefineContext::load(pvm, &input, 5_000_000_000)
        .map_err(|error| anyhow!("load state-runtime PVM: {error}"))?
        .run();
    ensure!(
        invocation.exit == ExitReason::Halt,
        "state-runtime ABI probe did not halt: {:?}",
        invocation.exit
    );
    let output = invocation
        .output_bounded(MAX_STATE_EXECUTION_OUTPUT_BYTES)
        .ok_or_else(|| anyhow!("state-runtime ABI probe returned an invalid output window"))?;
    let output = StateExecutionOutput::decode_for(&output, &work)
        .map_err(|error| anyhow!("decode state-runtime ABI probe: {error}"))?;
    ensure!(
        output.transition().outcome
            == RuntimeOutcome::Management(Ok(ManagementReply::Created(descriptor.identity)))
            && !output.changes().is_empty(),
        "state-runtime ABI probe returned an unexpected transition"
    );
    Ok(())
}

fn canonical_agent_runtime_pvm(elf: &[u8]) -> anyhow::Result<Vec<u8>> {
    if elf.is_empty() {
        bail!("agent-runtime ELF is empty")
    }
    let pvm = vos_pvm_compiler::link_elf_spi(elf)
        .map_err(|error| anyhow!("transpile agent-runtime ELF: {error:?}"))?;
    validate_agent_runtime_pvm(&pvm)?;
    Ok(pvm)
}

pub(super) fn validate_agent_runtime_pvm(pvm: &[u8]) -> anyhow::Result<()> {
    vos_pvm::spi::validate_refine_host_calls(pvm)
        .map_err(|error| anyhow!("agent-runtime outer host-call surface is invalid: {error:?}"))?;
    let probe = RuntimeWork::Manage {
        context: RuntimeExecutionContext::Direct,
        space: SpaceId([1; 32]),
        agent: AgentId([2; 32]),
        runtime_deployment: DeploymentId([3; 32]),
        state: RuntimeState::default(),
        request: Box::new(ManagementRequest::InspectActors {
            after: None,
            limit: 1,
        }),
        authority: None,
        observed_slot: 0,
    }
    .encode()
    .map_err(|error| anyhow!("encode clean agent-runtime ABI probe: {error}"))?;
    let invocation = RefineContext::load(pvm, &probe, ABI_PROBE_GAS)
        .map_err(|error| anyhow!("load agent-runtime PVM: {error}"))?
        .run();
    ensure!(
        invocation.exit == ExitReason::Halt,
        "agent-runtime ABI probe did not halt: {:?}",
        invocation.exit
    );
    let output = invocation
        .output_bounded(RuntimeTransition::MAX_ENCODED_BYTES)
        .ok_or_else(|| anyhow!("agent-runtime ABI probe returned an invalid output window"))?;
    let output = RuntimeTransition::decode(&output)
        .map_err(|error| anyhow!("decode clean agent-runtime ABI probe: {error}"))?;
    ensure!(
        output.state == RuntimeState::default()
            && output.outcome == RuntimeOutcome::Management(Err(ManagementError::NotCreated)),
        "agent-runtime clean ABI probe returned an unexpected transition"
    );
    Ok(())
}

/// Validate the separately signed System image role through actual nested guest
/// execution. The ordinary image ABI probe above does not establish Observe
/// support. No native runtime transition or private state decoder is used here.
#[cfg(feature = "experimental-state-blocks")]
pub(super) fn validate_system_observation_runtime_pvm(pvm: &[u8]) -> anyhow::Result<()> {
    validate_agent_runtime_pvm(pvm)?;
    for changes_state in [false, true] {
        let work = system_observation_probe(pvm, changes_state)?;
        let RuntimeWork::Observe {
            state, invocation, ..
        } = &work
        else {
            unreachable!()
        };
        let transition = run_image_probe(pvm, &work)?;
        ensure!(
            transition.state == *state,
            "System Observe changed opaque runtime state"
        );
        if changes_state {
            ensure!(
                transition.outcome
                    == RuntimeOutcome::Completed(Err(
                        vos::agent::sdk::InvocationError::InvalidActorOutput
                    )),
                "System Observe admitted a state-changing actor outcome"
            );
        } else {
            let RuntimeOutcome::Completed(Ok(reply)) = &transition.outcome else {
                bail!(
                    "System Observe did not execute the real actor: {:?}",
                    transition.outcome
                );
            };
            ensure!(
                reply.invocation == invocation.invocation
                    && reply.actor == invocation.actor
                    && reply.incarnation == invocation.incarnation
                    && reply.deployment == invocation.deployment
                    && reply.mode == invocation.mode
                    && reply.status == vos::agent::sdk::InvocationStatus::Done
                    && reply.reply == [0xa7],
                "System Observe returned an unexpected actor result"
            );
            // Repeating an observation needs no ACK and must not create an
            // exact-result record, advance state or change the answer.
            let repeated = run_image_probe(pvm, &work)?;
            ensure!(
                repeated == transition,
                "System Observe was not repeatable without retirement"
            );
        }
    }
    Ok(())
}

#[cfg(feature = "experimental-state-blocks")]
fn run_image_probe(pvm: &[u8], work: &RuntimeWork) -> anyhow::Result<RuntimeTransition> {
    let input = work
        .encode()
        .map_err(|error| anyhow!("encode image role probe: {error}"))?;
    let invocation = RefineContext::load(pvm, &input, ABI_PROBE_GAS)
        .map_err(|error| anyhow!("load image role probe: {error}"))?
        .run();
    ensure!(
        invocation.exit == ExitReason::Halt,
        "image role probe did not halt: {:?}",
        invocation.exit
    );
    let output = invocation
        .output_bounded(RuntimeTransition::MAX_ENCODED_BYTES)
        .ok_or_else(|| anyhow!("image role probe returned an invalid output window"))?;
    RuntimeTransition::decode(&output).map_err(|error| anyhow!("decode image role probe: {error}"))
}

#[cfg(feature = "experimental-state-blocks")]
fn system_observation_probe(pvm: &[u8], changes_state: bool) -> anyhow::Result<RuntimeWork> {
    use vos::actors::codec::Encode as _;
    use vos::actors::value::{Msg, TAG_DYNAMIC};
    use vos::agent::sdk::authority::{AgentAuthorityBinding, AuthorityIssuer};
    use vos::agent::sdk::contract::{ActorPackageContract, RuntimePackageContract};
    use vos::agent::sdk::method_policy::{
        ActorMethodPolicy, ActorMethodPolicyArtifact, AttestationRequirement,
        AuthorizationPolicySelector, IdempotencyRequirement,
    };
    use vos::agent::sdk::schema::{
        ConstructorContract, ParsedField, ParsedInlineField, ParsedMethod, ParsedSchema,
    };
    use vos::agent::sdk::{
        ActorEntry, ActorId, AgentDescriptor, AgentIdentity, AgentProfile, AgentReplica, BlobRef,
        Hash, InstallActor, InstallationId, InvocationAuthorization, InvocationId,
        InvocationOrigin, InvocationRoleClaims, InvocationWork, LaneSet, ManagementReply,
        MethodMode, NodeId, PrincipalId, ProducerId, ProofSystemSet, PublicPreflight, ReplicaRole,
        RuntimeBlob, RuntimeCapabilities, StateLane,
    };
    use vos_pvm_compiler::assembler::{Assembler, Reg};

    // Real actor ABI: status, three lane lengths, lane bytes, reply bytes.
    // The negative fixture attempts to change Linear state from empty to 0xee.
    let mut actor_output = vec![0; 13];
    actor_output[0] = vos::actors::STATUS_DONE;
    if changes_state {
        actor_output[1..5].copy_from_slice(&1_u32.to_le_bytes());
        actor_output.push(0xee);
    }
    actor_output.push(0xa7);
    let output_len = actor_output.len();
    let mut assembler = Assembler::new();
    assembler
        .set_rw_data(actor_output)
        .load_imm_64(Reg::A0, 2 * u64::from(vos_pvm::PVM_ZONE_SIZE))
        .load_imm_64(Reg::A1, output_len as u64)
        .jump_ind(Reg::RA, 0);
    let program_bytes = assembler.build_standard();
    let signer = libp2p::identity::Keypair::ed25519_from_bytes([0x42; 32])?;
    let public_key = signer
        .public()
        .try_into_ed25519()
        .map_err(|_| anyhow!("System role probe signer is not Ed25519"))?
        .to_bytes();
    let space = SpaceId([1; 32]);
    let owner = PrincipalId([2; 32]);
    let nonce = Hash([3; 32]);
    let agent = AgentId::derive(space, owner, nonce.as_bytes());
    let actor = ActorId::top_level(agent, "system-authority");
    let actor_deployment = DeploymentId([4; 32]);
    let producer = ProducerId::of_public_key(&public_key);
    let descriptor = AgentDescriptor {
        identity: AgentIdentity {
            space,
            agent,
            owner,
            profile: AgentProfile::Shared,
            runtime_deployment: DeploymentId([5; 32]),
            runtime_program: ProgramId::of_pvm(pvm),
            runtime_producer: producer,
            transition_producer: ProducerId([6; 32]),
        },
        creation_nonce: nonce,
        authority: AgentAuthorityBinding {
            policy: Hash([7; 32]),
            issuer: AuthorityIssuer {
                principal: owner,
                actor,
                deployment: actor_deployment,
                program: ProgramId::of_pvm(&program_bytes),
                producer,
            },
            public_key,
            initial_epoch: 1,
        },
        private_recovery: None,
        runtime_package: BlobRef::of_bytes(pvm),
        runtime_contract: RuntimePackageContract::system_observation_image(),
        capabilities: RuntimeCapabilities::standard(),
        replicas: (8..=10)
            .map(|marker| AgentReplica {
                node: NodeId([marker; 32]),
                principal: owner,
                role: ReplicaRole::Voter,
            })
            .collect(),
    };
    descriptor
        .validate()
        .map_err(|error| anyhow!("System role descriptor: {error:?}"))?;
    let created = run_image_probe(
        pvm,
        &signed_probe_management(
            &signer,
            &descriptor,
            RuntimeState::default(),
            ManagementRequest::Create(Box::new(descriptor.clone())),
            1,
        )?,
    )?;
    ensure!(
        created.outcome
            == RuntimeOutcome::Management(Ok(ManagementReply::Created(
                descriptor.identity.clone()
            ))),
        "System role Create failed: {:?}",
        created.outcome
    );

    let schema = ParsedSchema {
        constructor: ConstructorContract::Forbidden,
        fields: vec![ParsedField::Inline(ParsedInlineField {
            source_index: 0,
            name: "value".into(),
            type_identity: "core::primitive::u8".into(),
            persistence: vos::agent::sdk::FieldPersistence::State(StateLane::Linear),
        })],
        methods: vec![ParsedMethod {
            source_index: 0,
            name: "genesis_signing_committee".into(),
            mode: MethodMode::Query,
            explicit: true,
        }],
    };
    let schema_bytes = schema.encode()?;
    let schema_ref = BlobRef::of_bytes(&schema_bytes);
    let policy_bytes = ActorMethodPolicyArtifact {
        actor_schema: schema_ref.clone(),
        methods: vec![ActorMethodPolicy {
            name: "genesis_signing_committee".into(),
            mode: MethodMode::Query,
            arguments: Vec::new(),
            return_type_identity: "core::primitive::u8".into(),
            authorization_policy: AuthorizationPolicySelector::Public,
            idempotency: IdempotencyRequirement::NotRequired,
            attestation: AttestationRequirement::None,
        }],
    }
    .encode()?;
    let package = BlobRef::of_bytes(b"non-authoritative System role ABI probe actor");
    let policy_ref = BlobRef::of_bytes(&policy_bytes);
    let entry = ActorEntry {
        actor,
        name: "system-authority".into(),
        parent: None,
        deployment: actor_deployment,
        program: ProgramId::of_pvm(&program_bytes),
        package: package.clone(),
        agent_schema: schema_ref.clone(),
        method_policy: policy_ref.clone(),
        constructor_abi: schema.constructor_abi()?,
        installation_data: None,
        state_layout: schema.state_layout_hash()?,
        lanes: LaneSet::of(StateLane::Linear),
        suspended: false,
    };
    let install = InstallActor {
        installation_id: InstallationId([11; 32]),
        registry_reservation: Hash([12; 32]),
        entry: entry.clone(),
        producer,
        package,
        agent_schema: schema_ref,
        method_policy: policy_ref,
        constructor_abi: entry.constructor_abi,
        installation_data: None,
        state_layout: entry.state_layout,
        contract: ActorPackageContract::canonical(),
        requirements: schema.runtime_requirements(false, ProofSystemSet::EMPTY),
    };
    let installed = run_image_probe(
        pvm,
        &signed_probe_management(
            &signer,
            &descriptor,
            created.state,
            ManagementRequest::Install(Box::new(install)),
            2,
        )?,
    )?;
    ensure!(
        installed.outcome
            == RuntimeOutcome::Management(Ok(ManagementReply::Installed(entry.clone()))),
        "System role Install failed: {:?}",
        installed.outcome
    );
    let directory = run_image_probe(
        pvm,
        &RuntimeWork::Manage {
            context: RuntimeExecutionContext::Direct,
            space,
            agent,
            runtime_deployment: descriptor.identity.runtime_deployment,
            state: installed.state.clone(),
            request: Box::new(ManagementRequest::InspectActors {
                after: None,
                limit: 1,
            }),
            authority: None,
            observed_slot: 0,
        },
    )?;
    ensure!(
        directory.state == installed.state,
        "System role directory inspection changed state"
    );
    let RuntimeOutcome::Management(Ok(ManagementReply::Actors(page))) = directory.outcome else {
        bail!("System role directory inspection failed");
    };
    ensure!(
        page.entries.len() == 1 && page.entries[0].entry == entry && page.next.is_none(),
        "System role directory returned another installation"
    );
    let mut availability = [program_bytes, schema_bytes, policy_bytes]
        .into_iter()
        .map(|bytes| RuntimeBlob {
            reference: BlobRef::of_bytes(&bytes),
            bytes,
        })
        .collect::<Vec<_>>();
    availability.sort_unstable_by(|a, b| a.reference.cmp(&b.reference));
    let mut message = vec![TAG_DYNAMIC];
    message.extend_from_slice(&Msg::new("genesis_signing_committee").encode());
    let invocation = InvocationWork {
        space,
        agent,
        runtime_deployment: descriptor.identity.runtime_deployment,
        invocation: InvocationId([13; 32]),
        actor,
        incarnation: page.entries[0].incarnation,
        deployment: actor_deployment,
        program: entry.program,
        mode: MethodMode::Query,
        origin: InvocationOrigin::anonymous(),
        roles: InvocationRoleClaims::none(),
        message,
        installation_data: None,
        availability,
        gas: 100_000,
        recovery_only: false,
    };
    let authorization =
        InvocationAuthorization::PublicPreflight(PublicPreflight::for_work(&invocation, 3));
    Ok(RuntimeWork::Observe {
        context: RuntimeExecutionContext::Direct,
        state: installed.state,
        invocation: Box::new(invocation),
        authorization: Box::new(authorization),
        observed_slot: 3,
    })
}

#[cfg(feature = "experimental-state-blocks")]
fn signed_probe_management(
    signer: &libp2p::identity::Keypair,
    descriptor: &vos::agent::sdk::AgentDescriptor,
    state: RuntimeState,
    request: ManagementRequest,
    sequence: u64,
) -> anyhow::Result<RuntimeWork> {
    use vos::agent::sdk::Hash;
    use vos::agent::sdk::authority::{
        AuthorityEvidence, AuthorityLaneRoots, AuthorityOperationKind, AuthorityReceipt,
        AuthorityReceiptSelector,
    };
    let (operation, actor, actor_deployment) = match &request {
        ManagementRequest::Create(_) => (AuthorityOperationKind::CreateAgent, None, None),
        ManagementRequest::Install(install) => (
            AuthorityOperationKind::InstallActor,
            Some(install.entry.actor),
            Some(install.entry.deployment),
        ),
        _ => bail!("unsupported System role probe management operation"),
    };
    let mut receipt = AuthorityReceipt {
        selector: AuthorityReceiptSelector {
            policy: descriptor.authority.policy,
            issuer: descriptor.authority.issuer,
            space: descriptor.identity.space,
            agent: descriptor.identity.agent,
            operation,
            runtime_deployment: descriptor.identity.runtime_deployment,
            actor,
            actor_deployment,
            evidence: AuthorityEvidence {
                package: None,
                proof: None,
                commitment: Hash([14; 32]),
            },
            lane_roots: AuthorityLaneRoots::default(),
            epoch: 1,
            decision_sequence: sequence,
            acknowledged_through: 0,
            valid_from: sequence,
            expires_at: 10,
            request: request.commitment(),
        },
        public_key: descriptor.authority.public_key,
        signature: [0; 64],
    };
    receipt.signature = signer
        .sign(&receipt.signing_bytes())?
        .try_into()
        .map_err(|_| anyhow!("System role probe receipt signature is not Ed25519"))?;
    Ok(RuntimeWork::Manage {
        context: RuntimeExecutionContext::Direct,
        space: descriptor.identity.space,
        agent: descriptor.identity.agent,
        runtime_deployment: descriptor.identity.runtime_deployment,
        state,
        request: Box::new(request),
        authority: Some(Box::new(receipt)),
        observed_slot: sequence,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_and_non_elf_inputs() {
        assert!(canonical_agent_runtime_pvm(&[]).is_err());
        assert!(canonical_agent_runtime_pvm(b"not an ELF").is_err());
    }

    #[test]
    fn experimental_probe_requires_an_explicit_candidate_elf() {
        let error = run(None, None, true).unwrap_err().to_string();
        #[cfg(feature = "experimental-state-blocks")]
        assert!(error.contains("explicit candidate ELF"));
        #[cfg(not(feature = "experimental-state-blocks"))]
        assert!(error.contains("experimental-state-blocks vosx build"));
    }

    #[test]
    fn rejects_non_program_bytes() {
        assert!(validate_agent_runtime_pvm(b"not a standard PVM").is_err());
    }

    #[cfg(feature = "experimental-state-blocks")]
    #[test]
    fn ordinary_local_runtime_cannot_qualify_system_observation_role() {
        assert!(
            validate_system_observation_runtime_pvm(crate::bundled::agent_runtime_pvm()).is_err()
        );
    }

    #[test]
    fn rejects_retired_jar_and_vos_only_outer_host_calls() {
        use vos_pvm_compiler::assembler::Assembler;

        let mut legacy = Assembler::new();
        assert!(validate_agent_runtime_pvm(&legacy.trap().build()).is_err());

        let mut vos_only = Assembler::new();
        let vos_only = vos_only
            .trap()
            .ecalli(vos::abi::hostcall::DEBUG_WRITE)
            .build_standard();
        assert!(validate_agent_runtime_pvm(&vos_only).is_err());
    }

    #[test]
    #[ignore = "set VOS_AGENT_RUNTIME_ELF and VOS_AGENT_RUNTIME_CANDIDATE_OUT for a freshly built guest"]
    fn compiled_runtime_candidate_uses_current_abi() {
        let elf = std::env::var_os("VOS_AGENT_RUNTIME_ELF").expect("candidate ELF path");
        let out =
            std::env::var_os("VOS_AGENT_RUNTIME_CANDIDATE_OUT").expect("candidate output path");
        // Use the production conversion and physical ABI probe without
        // replacing or silently accepting the checked-in release pin.
        run(Some(Path::new(&elf)), Some(PathBuf::from(out)), false).unwrap();
    }

    #[test]
    fn bundled_runtime_has_the_current_clean_outer_surface() {
        validate_agent_runtime_pvm(crate::bundled::agent_runtime_pvm())
            .expect("the checked-in runtime uses only the current clean outer surface");
    }
}
