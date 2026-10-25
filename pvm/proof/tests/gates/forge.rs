//! What the gates share: a forgery's child process, a chip's constraint
//! check, and a trace's rows as stored (bit-reversed).

use stwo::core::fields::m31::BaseField;
#[cfg(feature = "debug-internals")]
use {
    stwo::core::channel::Blake2sChannel, vos_pvm_proof::SideNote,
    vos_pvm_proof::framework_access::AllLookupElements,
    vos_pvm_proof::harness::MachineProverComponent,
    vos_pvm_proof::trace::component::ComponentTrace,
};

/// Run the calling test again in a child process, which forges and asserts
/// (`true` there); in the parent `false`, once the child has failed. Stwo's
/// assertion evaluator panics before finalizing its `LogupAtRow`, whose Drop
/// guard aborts the double panic: a refusal is the child's failure.
#[cfg(feature = "debug-internals")]
macro_rules! in_child {
    ($test:expr) => {
        $crate::forge::in_child(module_path!(), $test)
    };
}

/// [`in_child!`]'s body: `module` is the caller's `module_path!()`, whose
/// first segment is this binary's name, `test` its test's name.
#[cfg(feature = "debug-internals")]
pub fn in_child(module: &str, test: &str) -> bool {
    const CHILD: &str = "VOS_GATE_CHILD";
    if std::env::var_os(CHILD).is_some() {
        return true;
    }
    let module = module.split_once("::").map_or("", |(_, path)| path);
    let name = format!("{module}::{test}");
    let status = std::process::Command::new(std::env::current_exe().expect("test executable"))
        .arg("--exact")
        .arg(&name)
        .env(CHILD, "1")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("run the forgery in a child process");
    assert!(
        !status.success(),
        "SOUNDNESS GAP: the forgery of {name} was accepted"
    );
    false
}

/// `chip`'s constraints and logup over `trace`: a panic on a violation.
#[cfg(feature = "debug-internals")]
pub fn assert_chip<C: MachineProverComponent + ?Sized>(
    chip: &C,
    trace: &ComponentTrace,
    side_note: &SideNote,
) {
    let mut lookup_elements = AllLookupElements::default();
    let channel = &mut Blake2sChannel::default();
    chip.draw_lookup_elements(&mut lookup_elements, channel.into());
    let (interaction_trace, claimed_sum) =
        chip.generate_interaction_trace(trace, side_note, &lookup_elements);
    chip.debug_assert_constraints(trace, &interaction_trace, &lookup_elements, claimed_sum);
}

/// [`assert_chip`], its violation returned as the panic's message.
#[cfg(feature = "debug-internals")]
pub fn check_chip<C: MachineProverComponent + ?Sized>(
    chip: &C,
    trace: &ComponentTrace,
    side_note: &SideNote,
) -> Result<(), String> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert_chip(chip, trace, side_note)
    }))
    .map_err(|panic| {
        panic
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| panic.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_else(|| "<non-string panic>".into())
    })
}

/// Where row `row` of a `log_size` trace is stored: the finalized columns
/// are bit-reversed.
pub fn stored(log_size: u32, row: usize) -> usize {
    let rows: Vec<BaseField> = (0..1u32 << log_size).map(BaseField::from).collect();
    let order = vos_pvm_proof::trace::utils::finalize_columns(vec![rows]);
    order[0]
        .as_slice()
        .iter()
        .position(|&at| at == BaseField::from(row as u32))
        .expect("a row of the trace")
}

/// Column `offset`'s value at row `row`.
#[cfg(feature = "debug-internals")]
pub fn get(trace: &ComponentTrace, offset: usize, row: usize) -> u32 {
    trace.original_trace[offset].as_slice()[stored(trace.log_size, row)].0
}

/// Set column `offset`'s value at row `row`.
#[cfg(feature = "debug-internals")]
pub fn set_field(trace: &mut ComponentTrace, offset: usize, row: usize, value: BaseField) {
    let at = stored(trace.log_size, row);
    trace.original_trace[offset].as_mut_slice()[at] = value;
}

/// [`set_field`] with a `u32`.
#[cfg(feature = "debug-internals")]
pub fn set(trace: &mut ComponentTrace, offset: usize, row: usize, value: u32) {
    set_field(trace, offset, row, BaseField::from(value));
}

/// The first stored row `pred` holds on, reading a row's columns by offset.
#[cfg(feature = "debug-internals")]
pub fn find_row(
    trace: &ComponentTrace,
    pred: impl Fn(&dyn Fn(usize) -> BaseField) -> bool,
) -> usize {
    let n = trace.original_trace[0].as_slice().len();
    (0..n)
        .find(|&r| {
            let at = |off: usize| trace.original_trace[off].as_slice()[r];
            pred(&at)
        })
        .expect("no row matched the search predicate")
}
