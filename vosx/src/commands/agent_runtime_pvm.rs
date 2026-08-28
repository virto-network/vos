//! Build and physically validate a standard agent-runtime PVM.

use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow, bail, ensure};
use vos::agent::wire::{RuntimeCall, RuntimeReturn};
use vos::agent::{LifecycleError, LifecycleRequest};
use vos::service::{ProgramId, ServiceWire};
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
    let probe = RuntimeCall {
        state: Vec::new(),
        request: LifecycleRequest::Inspect {
            after: None,
            limit: 1,
        },
    }
    .encode();
    let invocation = RefineContext::load(pvm, &probe, ABI_PROBE_GAS)
        .map_err(|error| anyhow!("load agent-runtime PVM: {error}"))?
        .run();
    ensure!(
        invocation.exit == ExitReason::Halt,
        "agent-runtime ABI probe did not halt: {:?}",
        invocation.exit
    );
    let output = invocation
        .output()
        .ok_or_else(|| anyhow!("agent-runtime ABI probe returned an invalid output window"))?;
    let output = RuntimeReturn::decode(&output)
        .map_err(|error| anyhow!("decode agent-runtime ABI probe: {error:?}"))?;
    ensure!(
        output.result == Err(LifecycleError::NotCreated),
        "agent-runtime ABI probe returned an unexpected lifecycle result"
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
}
