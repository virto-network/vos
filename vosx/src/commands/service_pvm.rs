//! Build the protocol infrastructure PVM consumed by `vosx build`.

use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow, bail};
use vos::v2::{ProgramId, ServicePvmV2};

pub fn run(elf: &Path, out: Option<PathBuf>) -> anyhow::Result<()> {
    let elf_bytes = std::fs::read(elf).with_context(|| format!("read {}", elf.display()))?;
    let pvm = canonical_service_pvm(&elf_bytes)?;
    let program = ProgramId::of_pvm(&pvm);
    let out = out.unwrap_or_else(|| elf.with_extension("pvm"));
    if let Some(parent) = out.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    std::fs::write(&out, &pvm).with_context(|| format!("write {}", out.display()))?;

    println!("built {}", out.display());
    println!("  service_program_id = {}", hex::encode(program.0));
    Ok(())
}

fn canonical_service_pvm(elf: &[u8]) -> anyhow::Result<Vec<u8>> {
    if elf.is_empty() {
        bail!("service ELF is empty")
    }
    let pvm = vos::v2::transpile_service_elf(elf)
        .map_err(|error| anyhow!("transpile generic service ELF: {error:?}"))?;
    let program = ProgramId::of_pvm(&pvm);
    ServicePvmV2::new(pvm.clone(), program).map_err(|error| {
        anyhow!("generic service has no valid JAM Refine/Accumulate entries: {error}")
    })?;
    Ok(pvm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_and_non_elf_inputs() {
        assert!(canonical_service_pvm(&[]).is_err());
        assert!(canonical_service_pvm(b"not an ELF").is_err());
    }
}
