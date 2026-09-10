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

pub fn run(elf: Option<&Path>, out: Option<PathBuf>) -> anyhow::Result<()> {
    let pvm = match elf {
        Some(elf) => {
            let elf_bytes =
                std::fs::read(elf).with_context(|| format!("read {}", elf.display()))?;
            canonical_agent_runtime_pvm(&elf_bytes)?
        }
        None => {
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
    fn prior_bundled_runtime_is_rejected_until_its_outer_surface_is_regenerated() {
        let error = validate_agent_runtime_pvm(crate::bundled::agent_runtime_pvm())
            .expect_err("the checked-in predecessor artifact contains DEBUG_WRITE");
        assert!(
            error.to_string().contains("UnsupportedHostCall(118)"),
            "unexpected rejection: {error:#}"
        );
    }
}
