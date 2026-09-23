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
fn validate_state_runtime_pvm(pvm: &[u8]) -> anyhow::Result<()> {
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

fn validate_agent_runtime_pvm(pvm: &[u8]) -> anyhow::Result<()> {
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
