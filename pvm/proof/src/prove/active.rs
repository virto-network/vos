//! The chips a trace activates: which of the segment AIR's chips a run's
//! steps, or an opcode, select, and the chip set as prover components.

use crate::{BASE_COMPONENTS, chip_idx, chips_of_mask, framework, side_note};

/// Diagnostics: the full BASE_COMPONENTS slice (no activity filter).
/// Returns ALL chips, in declaration order. Test harnesses use this
/// to bisect ConstraintsNotSatisfied failures — force a chip to be
/// active even when its activity flag would normally drop it.
#[doc(hidden)]
pub fn all_components() -> &'static [&'static dyn framework::MachineProverComponent] {
    BASE_COMPONENTS
}

/// Deterministic, side-note-driven filter on `BASE_COMPONENTS`.
/// Returns the components active for THIS trace, in declaration order.
///
/// Both prover and verifier MUST construct the same list.  The predicate
/// reads only `SideNote` fields the verifier also has access to (the
/// public side_note is an input to `verify`).
///
/// Skipping a chip is safe iff all of its lookup producers and consumers
/// have multiplicity 0 across the trace. For Blake2bChip: no calls in
/// `side_note.blake2b_calls` ⇒ no Blake2b producers/consumers fire on
/// CpuChip or MemoryChip ⇒ all relevant lookup balances stay 0=0. Each
/// `chip_idx::OPTIONAL` chip has its arm in `ChipActivity::is_active`.
#[doc(hidden)]
pub fn active_components(
    side_note: &side_note::SideNote,
) -> alloc::vec::Vec<&'static dyn framework::MachineProverComponent> {
    chips_of_mask(active_component_mask(side_note))
        .map(|chip| BASE_COMPONENTS[chip])
        .collect()
}

/// Per-chip activity flags inferred from `side_note.steps`
/// alone (no entries-vec dependency), so the predicate can run BEFORE
/// CpuChip's trace_fill populates side_note's per-family entries.
///
/// Each flag: "is there ≥ 1 step with a corresponding opcode in the
/// trace?".  Uses `classify_opcode` for opcode-class detection plus
/// direct `(opcode, imm)` matching for the blake2b ECALL.
fn activity_from_steps(side_note: &side_note::SideNote) -> ChipActivity {
    use crate::core::ecall::{ECALL_BLAKE2B_COMPRESS, ECALL_POSEIDON2, ECALL_WITNESS_INPUT};
    let mut a = ChipActivity::default();
    for step in &side_note.steps {
        // A precompile call counts only when served
        // (`PvmStep::served_ecall`).
        let ecall = step.served_ecall();
        if ecall == Some(ECALL_BLAKE2B_COMPRESS as u64) {
            a.blake2b = true;
        }
        if ecall == Some(u64::from(ECALL_POSEIDON2)) {
            a.poseidon2 = true;
        }
        // A witness-input call compares its count with its capacity; one
        // that wrote bytes hands them to WitnessInputChip.
        if ecall == Some(u64::from(ECALL_WITNESS_INPUT)) {
            a.compare = true;
        }
        if step.witness.is_some() {
            a.witness_input = true;
        }
        a.opcode(step.opcode);
    }
    a
}

#[derive(Default, Clone, Copy)]
struct ChipActivity {
    blake2b: bool,
    poseidon2: bool,
    jump_table: bool,
    popcount: bool,
    bitcount: bool,
    mul: bool,
    bitwise: bool,
    compare: bool,
    divrem: bool,
    witness_input: bool,
}

impl ChipActivity {
    /// Mark the chips a step of opcode `op` uses.
    fn opcode(&mut self, op: crate::core::opcode::Opcode) {
        let f = crate::chips::cpu::classify::classify_opcode(op);
        self.jump_table |= f.is_jump_ind || f.is_load_imm_jump_ind;
        self.popcount |= f.is_count_set_bits;
        self.bitcount |= f.is_lzb || f.is_tzb;
        self.mul |= f.is_mul
            || f.is_mul_upper_uu
            || f.is_mul_upper_su
            || f.is_mul_upper_ss
            || f.is_rotate_l64
            || f.is_rotate_r64
            || f.is_rotate_l32
            || f.is_rotate_r32;
        self.bitwise |= f.is_and || f.is_or || f.is_xor || f.is_and_inv || f.is_or_inv || f.is_xnor;
        // Compare = SetLt*/Cmov*/Min/Max + branches.
        self.compare |= f.is_set_lt_u
            || f.is_set_lt_s
            || f.is_cmov_iz
            || f.is_cmov_nz
            || f.is_min_s
            || f.is_min_u
            || f.is_max_s
            || f.is_max_u
            || f.is_branch;
        self.divrem |= f.is_div_rem;
    }

    /// The component mask of the active chips.
    fn mask(&self) -> u32 {
        (0..chip_idx::COUNT)
            .filter(|&index| self.is_active(index))
            .fold(0, |mask, index| mask | 1 << index)
    }

    fn is_active(&self, idx: usize) -> bool {
        // Indices are pinned by `chip_idx` (see lib.rs `mod chip_idx`).
        // Always-active chips fall through to the default arm — only the
        // optional chips (`chip_idx::OPTIONAL`) need an explicit arm.
        match idx {
            chip_idx::BLAKE2B => self.blake2b,
            chip_idx::POSEIDON2 => self.poseidon2,
            chip_idx::JUMP_TABLE => self.jump_table,
            chip_idx::WITNESS_INPUT => self.witness_input,
            chip_idx::POPCOUNT => self.popcount,
            chip_idx::BITCOUNT => self.bitcount,
            chip_idx::MUL => self.mul,
            chip_idx::BITWISE => self.bitwise,
            chip_idx::COMPARE => self.compare,
            chip_idx::DIVREM => self.divrem,
            _ => true,
        }
    }
}

/// Bitmask of active chips (bit i ⇔ BASE_COMPONENTS[i] is
/// included).  Embedded in `Proof::component_mask` so the standalone
/// verifier can reconstruct the active set without a SideNote.
/// The chips every proof holds are among them: the least set a segment of
/// the trace proves over.
#[doc(hidden)]
pub fn active_component_mask(side_note: &side_note::SideNote) -> u32 {
    activity_from_steps(side_note).mask()
}

/// The chips a step of opcode `op` activates, the chips every proof holds
/// among them: what a kernel's shape takes from each instruction of its
/// code.
#[doc(hidden)]
pub fn opcode_component_mask(op: crate::core::opcode::Opcode) -> u32 {
    let mut a = ChipActivity::default();
    a.opcode(op);
    a.mask()
}

/// Verifier-side mirror of `active_components`, returning the
/// same selection upcast to `&dyn MachineComponent`.
pub(crate) fn active_components_verifier(
    side_note: &side_note::SideNote,
) -> alloc::vec::Vec<&'static dyn framework::MachineComponent> {
    chips_of_mask(active_component_mask(side_note))
        .map(|chip| BASE_COMPONENTS[chip] as &dyn framework::MachineComponent)
        .collect()
}
