//! A standard program's run as `program_blob` makes it and
//! `examples/paths.rs` labels it: the blob loaded with no arguments under a
//! bounded gas, run to its first exit (a host call ends it: none is
//! dispatched).

#![allow(dead_code)]

use vos_pvm::refine::{Invocation, Machine, MemoryModel, RefineError};
use vos_pvm::{Gas, PvmBackend};

/// The gas a run gets: a looping program stops within milliseconds.
pub const GAS: Gas = 1_000_000;

/// The run of `blob` on `backend`: the interpreter over the sparse memory,
/// which allocates the pages a run touches alone; the recompiler over the
/// memory it maps.
pub fn run(blob: &[u8], backend: PvmBackend) -> Result<Invocation, RefineError> {
    let model = match backend {
        PvmBackend::ForceInterpreter => MemoryModel::Sparse,
        _ => MemoryModel::Auto,
    };
    let mut machine = Machine::load_with_backend(blob, &[], GAS, model, backend)?;
    let exit = machine.try_resume()?;
    Ok(machine.finish(exit))
}

/// A run's verdict: its exit's kind, or its load's refusal.
pub fn label(result: &Result<Invocation, RefineError>) -> String {
    match result {
        Ok(invocation) => variant(&format!("{:?}", invocation.exit)).to_owned(),
        Err(refusal) => format!("refused: {}", variant(&format!("{refusal:?}"))),
    }
}

/// A value's `Debug` up to its first field: its variant's name.
pub fn variant(debug: &str) -> &str {
    debug.split(['(', ' ', '{']).next().unwrap_or(debug)
}
