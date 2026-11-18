//! Whether this host can run the recompiler: asked once per process, by
//! doing what a native machine does (the CPU features its code uses, an
//! executable flip of a compiled program, a full 4 GiB guest window with
//! write tracking, and a native run), never by guessing from the kernel
//! version.

use std::sync::OnceLock;

use crate::ExitReason;
use crate::backend::Unavailable;

static PROBE: OnceLock<Result<(), Unavailable>> = OnceLock::new();

/// This host's answer, probed on first use.
pub(crate) fn available() -> Result<(), Unavailable> {
    *PROBE.get_or_init(|| {
        let result = probe();
        if let Err(reason) = &result {
            tracing::warn!(%reason, "the recompiler is unavailable on this host");
        }
        result
    })
}

/// The first CPU feature generated code uses past the x86-64 baseline
/// that this CPU lacks.
fn missing_feature() -> Option<&'static str> {
    use std::arch::is_x86_feature_detected as has;
    [
        ("lzcnt", has!("lzcnt")),
        ("bmi1", has!("bmi1")),
        ("popcnt", has!("popcnt")),
    ]
    .into_iter()
    .find_map(|(feature, present)| (!present).then_some(feature))
}

fn probe() -> Result<(), Unavailable> {
    if let Some(feature) = missing_feature() {
        return Err(Unavailable::CpuFeature(feature));
    }
    // A trap: the smallest program that enters and leaves native code.
    let (code, bitmask) = ([0u8], [1u8]);
    let compiled = super::compile_code(&code, &bitmask, &[]).map_err(|error| {
        tracing::debug!(%error, "executable-mapping probe");
        Unavailable::ExecutableMappings
    })?;
    super::write_tracking::available().map_err(|error| {
        tracing::debug!(%error, "write-tracking probe");
        Unavailable::WriteTracking
    })?;
    let memory = crate::interpreter::Memory::native(1 << 32).map_err(|error| {
        tracing::debug!(%error, "guest-memory probe");
        Unavailable::GuestMemory
    })?;
    let program = crate::Interpreter::predecode(&code, &bitmask, &[]);
    let mut machine = crate::Interpreter::from_predecoded(&program, [0; 13], memory, 1_000);
    match super::run_standard(&compiled, &mut machine) {
        Ok(Some(ExitReason::Panic)) => Ok(()),
        outcome => {
            tracing::debug!(?outcome, "native-run probe");
            Err(Unavailable::NativeRun)
        }
    }
}
