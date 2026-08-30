//! Per-basic-block gas simulation.
//!
//! Standard programs use the Gray Paper v0.8.0 priority-loop model: a
//! 32-entry reorder buffer, all-or-nothing four-slot decode, five starts per
//! cycle, persistent execution-unit occupancy, data dependencies, and
//! in-order retirement.  The capability-manifest/JAR profile retains its
//! frozen register-ready approximation because its gas costs are already part
//! of the signed service execution contract.

use crate::gas_cost::FastCost;

const REGISTER_COUNT: usize = 13;
const ROB_CAPACITY: usize = 32;
const DECODE_SLOTS: u8 = 4;
const START_SLOTS: u8 = 5;
const EXEC_UNITS: [u8; 5] = [4, 4, 4, 1, 1];

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum RobState {
    #[default]
    Dec,
    Wait,
    Exe,
    Fin,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct RobEntry {
    state: RobState,
    cycles_left: u8,
    deps: u32,
    dest_mask: u16,
    exec_unit: u8,
}

/// Exact, fixed-memory state from Gray Paper v0.8.0, equations A.49--A.57
/// (release commit `07f041d`). Retired entries are an in-order prefix, so we
/// compact that prefix and shift dependency bitsets after every tick.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ConformanceState {
    cycles: u32,
    decode_slots: u8,
    start_slots: u8,
    exec_units: [u8; 5],
    rob: [RobEntry; ROB_CAPACITY],
    rob_len: u8,
}

impl Default for ConformanceState {
    fn default() -> Self {
        Self {
            cycles: 0,
            decode_slots: DECODE_SLOTS,
            start_slots: START_SLOTS,
            exec_units: EXEC_UNITS,
            rob: [RobEntry::default(); ROB_CAPACITY],
            rob_len: 0,
        }
    }
}

impl ConformanceState {
    #[inline]
    fn can_decode(&self, decode_slots: u8) -> bool {
        decode_slots <= self.decode_slots && usize::from(self.rob_len) < ROB_CAPACITY
    }

    fn feed(&mut self, cost: FastCost) {
        assert!(
            (1..=DECODE_SLOTS).contains(&cost.decode_slots),
            "PVM gas decode width must be in 1..=4"
        );
        assert!(
            cost.exec_unit <= 6,
            "PVM gas execution-unit class must be in 0..=6"
        );
        // X gives decode strict priority, but only when the *whole*
        // instruction fits and fewer than 32 active ROB entries exist.
        while !self.can_decode(cost.decode_slots) {
            if !self.dispatch_one() {
                self.tick();
            }
        }

        self.decode_slots -= cost.decode_slots;
        if cost.is_move_reg {
            self.decode_move(cost.src_mask, cost.dst_mask);
        } else {
            self.decode_into_rob(cost);
        }
    }

    /// `move_reg` is a frontend rename. It does not enter the ROB; instead it
    /// transfers or kills every outstanding clobber exactly as A.53 defines.
    fn decode_move(&mut self, src_mask: u16, dst_mask: u16) {
        for entry in &mut self.rob[..usize::from(self.rob_len)] {
            if entry.dest_mask & src_mask != 0 {
                entry.dest_mask |= dst_mask;
            } else {
                entry.dest_mask &= !dst_mask;
            }
        }
    }

    fn decode_into_rob(&mut self, cost: FastCost) {
        let len = usize::from(self.rob_len);
        let mut deps = 0u32;
        for (index, entry) in self.rob[..len].iter().enumerate() {
            if entry.dest_mask & cost.src_mask != 0 {
                deps |= 1u32 << index;
            }
        }

        // A younger writer becomes the only outstanding clobber for its
        // destination registers. Dependencies above were intentionally
        // captured against the old clobber sets first.
        for entry in &mut self.rob[..len] {
            entry.dest_mask &= !cost.dst_mask;
        }
        self.rob[len] = RobEntry {
            state: RobState::Dec,
            cycles_left: cost.cycles,
            deps,
            dest_mask: cost.dst_mask,
            exec_unit: cost.exec_unit,
        };
        self.rob_len += 1;
    }

    /// Dispatch the lowest-index ready WAIT entry, if the current cycle has a
    /// start slot and all required execution units remain available.
    fn dispatch_one(&mut self) -> bool {
        if self.start_slots == 0 {
            return false;
        }
        let len = usize::from(self.rob_len);
        let Some(index) = (0..len).find(|&index| {
            let entry = self.rob[index];
            entry.state == RobState::Wait
                && self.dependencies_ready(entry.deps)
                && units_fit(self.exec_units, entry.exec_unit)
        }) else {
            return false;
        };

        let unit = self.rob[index].exec_unit;
        consume_units(&mut self.exec_units, unit);
        self.rob[index].state = RobState::Exe;
        self.start_slots -= 1;
        true
    }

    fn dependencies_ready(&self, mut deps: u32) -> bool {
        while deps != 0 {
            let index = deps.trailing_zeros() as usize;
            deps &= deps - 1;
            if self.rob[index].cycles_left != 0 {
                return false;
            }
        }
        true
    }

    /// Apply A.57 from one immutable old state. Execution units are released
    /// only by an old EXE entry at cycle 1; DEC becomes WAIT; EXE at zero
    /// becomes FIN; and only an old all-FIN prefix retires.
    fn tick(&mut self) {
        let len = usize::from(self.rob_len);

        for entry in &self.rob[..len] {
            if entry.state == RobState::Exe && entry.cycles_left == 1 {
                release_units(&mut self.exec_units, entry.exec_unit);
            }
        }

        let retired = self.rob[..len]
            .iter()
            .take_while(|entry| entry.state == RobState::Fin)
            .count();

        for entry in &mut self.rob[..len] {
            let old_state = entry.state;
            let old_cycles = entry.cycles_left;
            entry.state = match old_state {
                RobState::Dec => RobState::Wait,
                RobState::Exe if old_cycles == 0 => RobState::Fin,
                state => state,
            };
            if old_state == RobState::Exe && old_cycles > 0 {
                entry.cycles_left -= 1;
            }
        }

        if retired != 0 {
            self.rob.copy_within(retired..len, 0);
            let remaining = len - retired;
            for entry in &mut self.rob[..remaining] {
                entry.deps >>= retired;
            }
            self.rob[remaining..len].fill(RobEntry::default());
            self.rob_len = remaining as u8;
        }

        self.cycles += 1;
        self.decode_slots = DECODE_SLOTS;
        self.start_slots = START_SLOTS;
    }

    fn drain(mut self) -> u32 {
        while self.rob_len != 0 {
            if !self.dispatch_one() {
                self.tick();
            }
        }
        self.cycles.saturating_sub(3).max(1)
    }
}

#[inline]
fn unit_requirements(unit: u8) -> [u8; 5] {
    match unit {
        0 => [0, 0, 0, 0, 0],
        1 => [1, 0, 0, 0, 0],
        2 => [1, 1, 0, 0, 0],
        3 => [1, 0, 1, 0, 0],
        4 => [1, 0, 0, 1, 0],
        5 => [1, 0, 0, 0, 1],
        6 => [2, 0, 0, 0, 0],
        _ => [u8::MAX; 5],
    }
}

#[inline]
fn units_fit(available: [u8; 5], unit: u8) -> bool {
    let required = unit_requirements(unit);
    (0..5).all(|index| required[index] <= available[index])
}

#[inline]
fn consume_units(available: &mut [u8; 5], unit: u8) {
    let required = unit_requirements(unit);
    for index in 0..5 {
        available[index] -= required[index];
    }
}

#[inline]
fn release_units(available: &mut [u8; 5], unit: u8) {
    let required = unit_requirements(unit);
    for index in 0..5 {
        available[index] += required[index];
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct JarState {
    reg_done: [u32; REGISTER_COUNT],
    cycle: u32,
    decode_used: u8,
    max_done: u32,
}

impl JarState {
    fn feed(&mut self, cost: FastCost) {
        // This is the frozen JAR/service rule. In particular, it intentionally
        // admits an instruction while any frontend slot remains.
        if self.decode_used >= DECODE_SLOTS {
            self.cycle += 1;
            self.decode_used = cost.decode_slots;
        } else {
            self.decode_used += cost.decode_slots;
        }

        if cost.is_move_reg {
            let src_reg = cost.src_mask.trailing_zeros() as usize;
            let dst_reg = cost.dst_mask.trailing_zeros() as usize;
            if src_reg < REGISTER_COUNT && dst_reg < REGISTER_COUNT {
                self.reg_done[dst_reg] = self.reg_done[src_reg];
            }
            return;
        }

        let mut start = self.cycle;
        let mut src = cost.src_mask;
        while src != 0 {
            let register = src.trailing_zeros() as usize;
            src &= src - 1;
            if register < REGISTER_COUNT {
                start = start.max(self.reg_done[register]);
            }
        }
        let done = start + u32::from(cost.cycles);
        let mut dst = cost.dst_mask;
        while dst != 0 {
            let register = dst.trailing_zeros() as usize;
            dst &= dst - 1;
            if register < REGISTER_COUNT {
                self.reg_done[register] = done;
            }
        }
        self.max_done = self.max_done.max(done);
    }

    fn cost(self) -> u32 {
        self.max_done.saturating_sub(3).max(1)
    }
}

/// Online, fixed-memory gas simulator shared by the interpreter and native
/// recompiler. Select the profile explicitly with [`Self::new_for_mode`].
pub struct GasSimulator {
    mode: crate::IsaMode,
    jar: JarState,
    conformance: ConformanceState,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GasSimulatorState {
    mode: crate::IsaMode,
    jar: JarState,
    conformance: ConformanceState,
}

impl Default for GasSimulator {
    fn default() -> Self {
        Self::new()
    }
}

impl GasSimulator {
    pub fn new() -> Self {
        Self::new_for_mode(crate::IsaMode::Jar)
    }

    pub fn new_for_mode(mode: crate::IsaMode) -> Self {
        Self {
            mode,
            jar: JarState::default(),
            conformance: ConformanceState::default(),
        }
    }

    /// Test-only snapshot of the full simulator state, so two feed paths can
    /// be checked for identical ROB effect (not just identical block cost).
    #[cfg(test)]
    pub(crate) fn state(&self) -> GasSimulatorState {
        GasSimulatorState {
            mode: self.mode,
            jar: self.jar,
            conformance: self.conformance,
        }
    }

    /// Fast path: feed an instruction using direct register indices instead of
    /// bitmasks. Avoids the shift+OR bitmask construction and trailing_zeros
    /// extraction loop. For typical 2-source, 1-dest instructions.
    /// `src1`/`src2` are source register indices (0..12, or 0xFF for "none").
    /// `dst` is destination register index (0..12, or 0xFF for "none").
    #[inline(always)]
    pub fn feed_direct(&mut self, cycles: u8, decode_slots: u8, src1: u8, src2: u8, dst: u8) {
        self.feed_direct_with_unit(cycles, decode_slots, 1, src1, src2, dst);
    }

    /// Direct feed path including the execution-unit class from `FastCost`.
    #[inline(always)]
    pub fn feed_direct_with_unit(
        &mut self,
        cycles: u8,
        decode_slots: u8,
        exec_unit: u8,
        src1: u8,
        src2: u8,
        dst: u8,
    ) {
        let src_mask = u16::from(src1 < REGISTER_COUNT as u8) << src1.min(15)
            | u16::from(src2 < REGISTER_COUNT as u8) << src2.min(15);
        let dst_mask = u16::from(dst < REGISTER_COUNT as u8) << dst.min(15);
        self.feed(&FastCost {
            cycles,
            decode_slots,
            exec_unit,
            src_mask,
            dst_mask,
            is_terminator: false,
            is_move_reg: false,
        });
    }

    /// Process one instruction. O(1).
    #[inline]
    pub fn feed(&mut self, cost: &FastCost) {
        match self.mode {
            crate::IsaMode::Jar => self.jar.feed(*cost),
            crate::IsaMode::Conformance => self.conformance.feed(*cost),
        }
    }

    /// Return block gas cost: max(max_done - 3, 1).
    #[inline]
    pub fn flush_and_get_cost(&self) -> u32 {
        match self.mode {
            crate::IsaMode::Jar => self.jar.cost(),
            crate::IsaMode::Conformance => self.conformance.drain(),
        }
    }

    /// Reset for the next gas block.
    #[inline]
    pub fn reset(&mut self) {
        self.jar = JarState::default();
        self.conformance = ConformanceState::default();
    }
}

#[cfg(test)]
fn reference_conformance_cost(costs: &[FastCost]) -> u32 {
    use alloc::vec::Vec;

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum State {
        Dec,
        Wait,
        Exe,
        Fin,
        None,
    }

    #[derive(Clone, Copy)]
    struct Entry {
        state: State,
        cycles_left: u8,
        deps: u64,
        dest_mask: u16,
        exec_unit: u8,
    }

    let mut ip = 0usize;
    let mut cycles = 0u32;
    let mut decode_slots = DECODE_SLOTS;
    let mut start_slots = START_SLOTS;
    let mut available = EXEC_UNITS;
    let mut rob = Vec::<Entry>::new();

    loop {
        let active = rob
            .iter()
            .filter(|entry| entry.state != State::None)
            .count();
        if let Some(cost) = costs.get(ip).copied()
            && cost.decode_slots <= decode_slots
            && active < ROB_CAPACITY
        {
            decode_slots -= cost.decode_slots;
            if cost.is_move_reg {
                for entry in &mut rob {
                    if entry.dest_mask & cost.src_mask != 0 {
                        entry.dest_mask |= cost.dst_mask;
                    } else {
                        entry.dest_mask &= !cost.dst_mask;
                    }
                }
            } else {
                let mut deps = 0u64;
                for (index, entry) in rob.iter().enumerate() {
                    if entry.dest_mask & cost.src_mask != 0 {
                        deps |= 1u64 << index;
                    }
                }
                for entry in &mut rob {
                    entry.dest_mask &= !cost.dst_mask;
                }
                rob.push(Entry {
                    state: State::Dec,
                    cycles_left: cost.cycles,
                    deps,
                    dest_mask: cost.dst_mask,
                    exec_unit: cost.exec_unit,
                });
            }
            ip += 1;
            continue;
        }

        let ready = if start_slots == 0 {
            None
        } else {
            rob.iter().position(|entry| {
                entry.state == State::Wait
                    && units_fit(available, entry.exec_unit)
                    && rob.iter().enumerate().all(|(index, dependency)| {
                        entry.deps & (1u64 << index) == 0 || dependency.cycles_left == 0
                    })
            })
        };
        if let Some(index) = ready {
            consume_units(&mut available, rob[index].exec_unit);
            rob[index].state = State::Exe;
            start_slots -= 1;
            continue;
        }

        if ip == costs.len() && active == 0 {
            break;
        }

        let old = rob.clone();
        for entry in &old {
            if entry.state == State::Exe && entry.cycles_left == 1 {
                release_units(&mut available, entry.exec_unit);
            }
        }
        for (index, entry) in rob.iter_mut().enumerate() {
            let old_entry = old[index];
            let prefix_finished = old[..=index]
                .iter()
                .all(|prior| matches!(prior.state, State::Fin | State::None));
            entry.state = if prefix_finished {
                State::None
            } else {
                match old_entry.state {
                    State::Dec => State::Wait,
                    State::Exe if old_entry.cycles_left == 0 => State::Fin,
                    state => state,
                }
            };
            if old_entry.state == State::Exe && old_entry.cycles_left > 0 {
                entry.cycles_left -= 1;
            }
        }
        cycles += 1;
        decode_slots = DECODE_SLOTS;
        start_slots = START_SLOTS;
    }

    cycles.saturating_sub(3).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cost(cycles: u8, slots: u8, unit: u8, src_mask: u16, dst_mask: u16) -> FastCost {
        FastCost {
            cycles,
            decode_slots: slots,
            exec_unit: unit,
            src_mask,
            dst_mask,
            is_terminator: false,
            is_move_reg: false,
        }
    }

    fn standard_cost(costs: &[FastCost]) -> u32 {
        let mut simulator = GasSimulator::new_for_mode(crate::IsaMode::Conformance);
        for cost in costs {
            simulator.feed(cost);
        }
        simulator.flush_and_get_cost()
    }

    // === flush_and_get_cost ===

    #[test]
    fn test_empty_block_cost_is_one() {
        let sim = GasSimulator::new();
        assert_eq!(sim.flush_and_get_cost(), 1, "empty block should cost 1");
    }

    // === feed_direct ===

    #[test]
    fn test_single_alu_instruction() {
        // One ALU op: 1 cycle, 1 decode slot, r0 → r2
        let mut sim = GasSimulator::new();
        sim.feed_direct(1, 1, 0, 0xFF, 2); // src1=r0, no src2, dst=r2
        // max_done = 0 (start) + 1 (cycles) = 1
        // cost = max(1 - 3, 1) = 1
        assert_eq!(sim.flush_and_get_cost(), 1);
    }

    #[test]
    fn test_data_dependency_chain() {
        // Chain: r0 → r1 (1 cycle), r1 → r2 (1 cycle)
        // r1 is ready at cycle 1, r2 at cycle 2
        let mut sim = GasSimulator::new();
        sim.feed_direct(1, 1, 0, 0xFF, 1); // r1 done at cycle 1
        sim.feed_direct(1, 1, 1, 0xFF, 2); // depends on r1, r2 done at cycle 2
        // max_done = 2, cost = max(2 - 3, 1) = 1
        assert_eq!(sim.flush_and_get_cost(), 1);
    }

    #[test]
    fn test_long_dependency_chain() {
        // 5-deep chain, each 1 cycle: r0→r1→r2→r3→r4→r5
        let mut sim = GasSimulator::new();
        for i in 0..5u8 {
            sim.feed_direct(1, 1, i, 0xFF, i + 1);
        }
        // r5 done at cycle 5, cost = max(5 - 3, 1) = 2
        assert_eq!(sim.flush_and_get_cost(), 2);
    }

    #[test]
    fn test_independent_instructions_parallel() {
        // Two independent ALU ops: r0→r2 and r1→r3, both 1 cycle
        let mut sim = GasSimulator::new();
        sim.feed_direct(1, 1, 0, 0xFF, 2);
        sim.feed_direct(1, 1, 1, 0xFF, 3);
        // Both start at cycle 0, done at cycle 1
        // max_done = 1, cost = 1
        assert_eq!(sim.flush_and_get_cost(), 1);
    }

    #[test]
    fn test_multi_cycle_instruction() {
        // One 4-cycle instruction (e.g., multiply)
        let mut sim = GasSimulator::new();
        sim.feed_direct(4, 1, 0, 1, 2); // 4 cycles, src r0+r1, dst r2
        // max_done = 4, cost = max(4 - 3, 1) = 1
        assert_eq!(sim.flush_and_get_cost(), 1);
    }

    #[test]
    fn test_high_latency_chain() {
        // 4-cycle MUL → 1-cycle ALU dependent on result
        let mut sim = GasSimulator::new();
        sim.feed_direct(4, 1, 0, 1, 2); // MUL: r2 done at cycle 4
        sim.feed_direct(1, 1, 2, 0xFF, 3); // ALU: depends on r2, r3 done at cycle 5
        // max_done = 5, cost = max(5 - 3, 1) = 2
        assert_eq!(sim.flush_and_get_cost(), 2);
    }

    #[test]
    fn test_decode_throughput_limit() {
        // 5 independent 1-slot instructions: 4 fit in cycle 0, 5th bumps to cycle 1
        let mut sim = GasSimulator::new();
        for i in 0..5u8 {
            sim.feed_direct(1, 1, 0xFF, 0xFF, i); // no deps, 1 slot each
        }
        // First 4 decode in cycle 0 (done at 1), 5th decodes in cycle 1 (done at 2)
        // max_done = 2, cost = max(2 - 3, 1) = 1
        assert_eq!(sim.flush_and_get_cost(), 1);
    }

    #[test]
    fn test_no_src_no_dst() {
        // Instruction with no register deps (e.g., NOP-like)
        let mut sim = GasSimulator::new();
        sim.feed_direct(1, 1, 0xFF, 0xFF, 0xFF);
        // max_done = 1 (start 0 + 1 cycle)
        assert_eq!(sim.flush_and_get_cost(), 1);
    }

    #[test]
    fn test_two_sources() {
        // r2 = r0 + r1 where r0 available at cycle 0, r1 available at cycle 3
        let mut sim = GasSimulator::new();
        sim.feed_direct(3, 1, 0xFF, 0xFF, 1); // r1 done at cycle 3
        sim.feed_direct(1, 1, 0, 1, 2); // depends on r0 (ready 0) and r1 (ready 3)
        // r2 starts at max(0, 3) = 3, done at 4
        // max_done = 4, cost = max(4 - 3, 1) = 1
        assert_eq!(sim.flush_and_get_cost(), 1);
    }

    // === feed (bitmask-based) ===

    #[test]
    fn test_feed_move_reg_propagates_done() {
        // move_reg: zero-cycle, propagates reg_done from src to dst
        let mut sim = GasSimulator::new();
        sim.feed_direct(3, 1, 0xFF, 0xFF, 0); // r0 done at cycle 3
        sim.feed(&FastCost {
            cycles: 0,
            decode_slots: 1,
            exec_unit: 0,
            src_mask: 1 << 0, // r0
            dst_mask: 1 << 1, // r1
            is_terminator: false,
            is_move_reg: true,
        });
        // r1 should inherit r0's done time (3)
        sim.feed_direct(1, 1, 1, 0xFF, 2); // depends on r1
        // r2 starts at 3, done at 4
        // max_done = 4, cost = max(4 - 3, 1) = 1
        assert_eq!(sim.flush_and_get_cost(), 1);
    }

    #[test]
    fn test_feed_bitmask_multiple_sources() {
        let mut sim = GasSimulator::new();
        sim.feed_direct(2, 1, 0xFF, 0xFF, 0); // r0 done at 2
        sim.feed_direct(3, 1, 0xFF, 0xFF, 1); // r1 done at 3
        sim.feed(&FastCost {
            cycles: 1,
            decode_slots: 1,
            exec_unit: 1,                  // ALU
            src_mask: (1 << 0) | (1 << 1), // r0 + r1
            dst_mask: 1 << 2,              // r2
            is_terminator: false,
            is_move_reg: false,
        });
        // r2 starts at max(2, 3) = 3, done at 4
        // max_done = 4, cost = max(4 - 3, 1) = 1
        assert_eq!(sim.flush_and_get_cost(), 1);
    }

    #[test]
    fn conformance_div_unit_stays_occupied_until_completion() {
        let div = cost(60, 4, 5, 0, 0);
        assert_eq!(standard_cost(&[div]), 60, "one isolated DIV");
        assert_eq!(
            standard_cost(&[div, div]),
            120,
            "two independent instructions serialize on the one DIV unit"
        );
        assert_eq!(
            standard_cost(&[div, div]),
            reference_conformance_cost(&[div, div])
        );
    }

    #[test]
    fn conformance_standalone_trap_cost_includes_in_order_retirement() {
        let trap = cost(2, 1, 0, 0, 0);
        assert_eq!(standard_cost(&[trap]), 2);
        assert_eq!(reference_conformance_cost(&[trap]), 2);
    }

    #[test]
    fn conformance_decode_requires_the_whole_instruction_to_fit() {
        let one_slot_alu = cost(1, 1, 1, 0, 0);
        let four_slot_div = cost(60, 4, 5, 0, 0);
        let costs = [one_slot_alu, four_slot_div];
        assert_eq!(
            standard_cost(&costs),
            61,
            "the DIV waits for the next cycle's four-slot reset"
        );
        assert_eq!(standard_cost(&costs), reference_conformance_cost(&costs));
    }

    #[test]
    fn conformance_rob_capacity_retires_in_order() {
        let costs = [cost(60, 4, 5, 0, 0); 33];
        assert_eq!(standard_cost(&costs), 1_980);
        assert_eq!(standard_cost(&costs), reference_conformance_cost(&costs));
    }

    #[test]
    fn conformance_dispatches_at_most_five_ready_entries_per_cycle() {
        let producer = cost(5, 1, 1, 0, 1 << 0);
        let consumer = cost(10, 1, 0, 1 << 0, 0);
        let costs = [
            producer, consumer, consumer, consumer, consumer, consumer, consumer,
        ];
        assert_eq!(
            standard_cost(&costs),
            16,
            "the sixth newly-ready consumer starts one cycle after the first five"
        );
        assert_eq!(standard_cost(&costs), reference_conformance_cost(&costs));
    }

    #[test]
    fn conformance_move_rewrites_outstanding_clobbers() {
        let producer = cost(10, 1, 1, 0, 1 << 0);
        let rename = FastCost {
            cycles: 0,
            decode_slots: 1,
            exec_unit: 0,
            src_mask: 1 << 0,
            dst_mask: 1 << 1,
            is_terminator: false,
            is_move_reg: true,
        };
        let consumer = cost(5, 1, 1, 1 << 1, 1 << 2);
        let costs = [producer, rename, consumer];
        assert_eq!(standard_cost(&costs), 15);
        assert_eq!(standard_cost(&costs), reference_conformance_cost(&costs));
    }

    // === reset ===

    #[test]
    fn test_reset_clears_state() {
        let mut sim = GasSimulator::new();
        sim.feed_direct(10, 1, 0xFF, 0xFF, 0); // large cost
        assert!(sim.flush_and_get_cost() > 1);
        sim.reset();
        assert_eq!(sim.flush_and_get_cost(), 1, "after reset, cost should be 1");
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// The fixed 32-entry online implementation must remain identical to
        /// a literal, allocation-heavy transcription of the v0.8.0 equations.
        #[test]
        fn conformance_online_matches_spec_reference(
            raw in proptest::collection::vec(
                (1u8..20, 1u8..5, 0u8..7, 0u8..13, 0u8..13, any::<bool>()),
                0..49,
            ),
        ) {
            let costs: alloc::vec::Vec<FastCost> = raw
                .into_iter()
                .map(|(cycles, decode_slots, exec_unit, src, dst, is_move_reg)| {
                    if is_move_reg {
                        FastCost {
                            cycles: 0,
                            decode_slots: 1,
                            exec_unit: 0,
                            src_mask: 1u16 << src,
                            dst_mask: 1u16 << dst,
                            is_terminator: false,
                            is_move_reg: true,
                        }
                    } else {
                        FastCost {
                            cycles,
                            decode_slots,
                            exec_unit,
                            src_mask: 1u16 << src,
                            dst_mask: 1u16 << dst,
                            is_terminator: false,
                            is_move_reg: false,
                        }
                    }
                })
                .collect();
            let mut simulator = GasSimulator::new_for_mode(crate::IsaMode::Conformance);
            for cost in &costs {
                simulator.feed(cost);
            }
            prop_assert_eq!(
                simulator.flush_and_get_cost(),
                reference_conformance_cost(&costs),
            );
        }

        /// flush_and_get_cost always returns at least 1.
        #[test]
        fn cost_always_at_least_one(
            instrs in proptest::collection::vec(
                (1u8..20, 1u8..4, 0u8..13, 0u8..13),
                0..10,
            ),
        ) {
            let mut sim = GasSimulator::new();
            for (cycles, slots, src, dst) in &instrs {
                sim.feed_direct(*cycles, *slots, *src, 0xFF, *dst);
            }
            prop_assert!(sim.flush_and_get_cost() >= 1);
        }

        /// reset returns the simulator to the empty state (cost = 1).
        #[test]
        fn reset_restores_empty_state(
            instrs in proptest::collection::vec(
                (1u8..20, 1u8..4, 0u8..13, 0u8..13),
                1..10,
            ),
        ) {
            let mut sim = GasSimulator::new();
            for (cycles, slots, src, dst) in &instrs {
                sim.feed_direct(*cycles, *slots, *src, 0xFF, *dst);
            }
            sim.reset();
            prop_assert_eq!(sim.flush_and_get_cost(), 1);
        }

        /// Independent instructions (no register deps) never cost more than
        /// a dependency chain of the same length would.
        #[test]
        fn independent_no_more_than_chained(
            count in 1usize..8,
            cycles in 1u8..10,
        ) {
            // Independent: all use different dst, no src deps
            let mut indep = GasSimulator::new();
            for i in 0..count.min(13) {
                indep.feed_direct(cycles, 1, 0xFF, 0xFF, i as u8);
            }
            // Chained: r0 -> r1 -> r2 -> ...
            let mut chain = GasSimulator::new();
            for i in 0..count.min(12) {
                chain.feed_direct(cycles, 1, i as u8, 0xFF, (i + 1) as u8);
            }
            prop_assert!(indep.flush_and_get_cost() <= chain.flush_and_get_cost());
        }

        /// feed_direct with no sources and no dest (0xFF) is equivalent to
        /// a no-dep instruction — cost grows only from decode throughput.
        #[test]
        fn no_reg_deps_bounded_by_decode(
            count in 1usize..20,
            cycles in 1u8..5,
        ) {
            let mut sim = GasSimulator::new();
            for _ in 0..count {
                sim.feed_direct(cycles, 1, 0xFF, 0xFF, 0xFF);
            }
            // max_done = (cycle_when_last_decoded) + cycles
            // With 4 decode slots/cycle, last decode is at cycle floor((count-1)/4)
            // So max_done <= floor((count-1)/4) + cycles
            let expected_max = ((count - 1) / 4) as u32 + cycles as u32;
            let cost = sim.flush_and_get_cost();
            let expected_cost = if expected_max > 3 { expected_max - 3 } else { 1 };
            prop_assert_eq!(cost, expected_cost);
        }

        /// feed and feed_direct produce the same cost for single-source,
        /// single-dest instructions.
        #[test]
        fn feed_matches_feed_direct(
            cycles in 1u8..20,
            decode_slots in 1u8..4,
            src in 0u8..13,
            dst in 0u8..13,
        ) {
            let mut sim_direct = GasSimulator::new();
            sim_direct.feed_direct(cycles, decode_slots, src, 0xFF, dst);

            let mut sim_feed = GasSimulator::new();
            sim_feed.feed(&FastCost {
                cycles,
                decode_slots,
                exec_unit: 1,
                src_mask: 1u16 << src,
                dst_mask: 1u16 << dst,
                is_terminator: false,
                is_move_reg: false,
            });

            prop_assert_eq!(
                sim_direct.flush_and_get_cost(),
                sim_feed.flush_and_get_cost()
            );
        }

        /// Adding more instructions never decreases the cost.
        #[test]
        fn cost_monotonic_with_instructions(
            base_count in 1usize..6,
            extra_count in 1usize..4,
            cycles in 1u8..10,
        ) {
            let mut sim_base = GasSimulator::new();
            let mut sim_more = GasSimulator::new();
            for i in 0..base_count.min(12) {
                sim_base.feed_direct(cycles, 1, i as u8, 0xFF, (i + 1) as u8);
                sim_more.feed_direct(cycles, 1, i as u8, 0xFF, (i + 1) as u8);
            }
            let base_cost = sim_base.flush_and_get_cost();
            let last = base_count.min(12);
            for i in 0..extra_count.min(12 - last) {
                sim_more.feed_direct(cycles, 1, (last + i) as u8, 0xFF, (last + i + 1).min(12) as u8);
            }
            prop_assert!(sim_more.flush_and_get_cost() >= base_cost);
        }
    }
}
