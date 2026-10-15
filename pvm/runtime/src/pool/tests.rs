use super::*;
use crate::inner::{InnerError, InnerExit, InnerMachines, InvokeState, PageMode};
use crate::instruction::Opcode;
use proptest::prelude::*;

const ZONE: u32 = 0x1_0000;

/// A standard program whose code stores φ9 at φ8 (8 bytes) and φ11 at
/// φ10 (2 bytes), compresses with BLAKE2b (h at φ7, m at φ8), stops at
/// host call 0x77, stores φ9's low byte at φ12, then traps.
///
/// The compression exits to the outer machine, as every inner
/// precompile call does; [`run`] serves it as an agent does.
fn program() -> Vec<u8> {
    let code = vec![
        Opcode::StoreIndU64 as u8,
        9 | (8 << 4),
        Opcode::StoreIndU16 as u8,
        11 | (10 << 4),
        Opcode::Ecalli as u8,
        0x00,
        0x04,
        Opcode::Ecalli as u8,
        0x77,
        Opcode::StoreIndU8 as u8,
        9 | (12 << 4),
        Opcode::Trap as u8,
    ];
    standard(code, &[0, 2, 4, 7, 9, 11])
}

/// A standard program whose code counts φ2 up to 100, storing it at φ8
/// each round, then traps: a loop whose body is a block of its own,
/// after the fallthrough at 0.
fn counting() -> Vec<u8> {
    let code = vec![
        Opcode::Fallthrough as u8,
        Opcode::AddImm64 as u8,
        2 | (2 << 4),
        1,
        Opcode::StoreIndU64 as u8,
        2 | (8 << 4),
        Opcode::BranchNeImm as u8,
        2 | (1 << 4),
        100,
        // Back to the body at 1, from 6.
        (-5i8) as u8,
        Opcode::Trap as u8,
    ];
    standard(code, &[0, 1, 4, 6, 10])
}

/// A standard program of `code`, its instructions starting at
/// `starts`, with [`program`]'s regions.
fn standard(code: Vec<u8>, starts: &[usize]) -> Vec<u8> {
    let mut bitmask = vec![0; code.len()];
    for &start in starts {
        bitmask[start] = 1;
    }
    let code = vos_pvm_program::build_compact_code_blob(&CodeBlob {
        code,
        bitmask,
        jump_table: Vec::new(),
    })
    .unwrap();
    let ro: Vec<u8> = (0..300).map(|i| (i * 7) as u8 | 1).collect();
    let rw: Vec<u8> = (0..5000).map(|i| (i * 13) as u8).collect();
    let (heap_pages, stack) = (2u16, 8192u32);
    let mut blob = Vec::new();
    blob.extend_from_slice(&(ro.len() as u32).to_le_bytes()[..3]);
    blob.extend_from_slice(&(rw.len() as u32).to_le_bytes()[..3]);
    blob.extend_from_slice(&heap_pages.to_le_bytes());
    blob.extend_from_slice(&stack.to_le_bytes()[..3]);
    blob.extend_from_slice(&ro);
    blob.extend_from_slice(&rw);
    blob.extend_from_slice(&(code.len() as u32).to_le_bytes());
    blob.extend_from_slice(&code);
    blob
}

/// The machine a loader builds with `machine`, then `pages` and `poke`:
/// the reference a pooled machine must equal.
fn loaded(blob: &[u8], backend: PvmBackend) -> (InnerMachines, u32) {
    loaded_at(blob, backend, 0)
}

/// As [`loaded`], the machine made at instruction counter `pc`.
fn loaded_at(blob: &[u8], backend: PvmBackend, pc: u32) -> (InnerMachines, u32) {
    let program = crate::spi::parse_standard_program(blob).unwrap();
    let layout = program.layout(&[]).unwrap();
    let mut machines = InnerMachines::with_backend(backend);
    let id = machines
        .create(&program.compact_code().unwrap(), pc)
        .unwrap();
    let page = PVM_PAGE_SIZE as u64;
    let pages = |machines: &mut InnerMachines, region: crate::spi::SpiRegion, mode| {
        machines
            .pages(
                id,
                (region.base / page) as u32,
                (region.size / page) as u32,
                mode,
            )
            .unwrap();
    };
    if layout.ro.size > 0 {
        pages(&mut machines, layout.ro, PageMode::AllocateReadWrite);
        machines
            .poke(id, layout.ro.base as u32, layout.ro_data)
            .unwrap();
        pages(&mut machines, layout.ro, PageMode::SetReadOnly);
    }
    if layout.rw.size > 0 {
        pages(&mut machines, layout.rw, PageMode::AllocateReadWrite);
        if !layout.rw_data.is_empty() {
            machines
                .poke(id, layout.rw.base as u32, layout.rw_data)
                .unwrap();
        }
    }
    if layout.stack.size > 0 {
        pages(&mut machines, layout.stack, PageMode::AllocateReadWrite);
    }
    (machines, id)
}

/// Everything a guest or a host can observe of a machine: registers, gas,
/// counter and continuation state, permissions, and the contents of
/// every mapped page and every page in `extra`.
#[derive(Debug, PartialEq, Eq)]
struct Dump {
    program: Vec<u8>,
    initial_pc: u32,
    registers: [u64; PVM_REGISTER_COUNT],
    gas: Gas,
    pc: u32,
    pending: Option<(u64, u32, u32)>,
    gas_charged: bool,
    need_gas_charge: bool,
    permissions: Vec<(usize, usize, u8)>,
    pages: BTreeMap<u32, Vec<u8>>,
}

fn dump(machines: &InnerMachines, id: u32, extra: &[u32]) -> Dump {
    let view = machines
        .views()
        .find(|view| view.identity.slot == id)
        .unwrap();
    let vm = view.machine.unwrap();
    let memory = vm.memory();
    let permissions = memory.permission_runs();
    let mut indices: Vec<u32> = permissions
        .iter()
        .filter(|&&(_, _, permission)| permission != PERM_NONE)
        .flat_map(|&(first, count, _)| first as u32..(first + count) as u32)
        .chain(extra.iter().copied())
        .collect();
    indices.sort_unstable();
    indices.dedup();
    let pages = indices
        .into_iter()
        .map(|index| {
            let mut bytes = vec![0; PAGE];
            memory.read_bytes(index * PVM_PAGE_SIZE, &mut bytes);
            (index, bytes)
        })
        .filter(|(_, bytes)| bytes.iter().any(|&byte| byte != 0))
        .collect();
    Dump {
        program: view.program.to_vec(),
        initial_pc: view.initial_pc,
        registers: vm.registers,
        gas: vm.gas,
        pc: vm.pc,
        pending: vm
            .pending_host_call()
            .map(|call| (call.id, call.cause_pc, call.resume_pc)),
        gas_charged: vm.gas_charged,
        need_gas_charge: vm.need_gas_charge,
        permissions,
        pages,
    }
}

/// Addresses the test aims at: inside the layout's regions, across page
/// boundaries next to mapped and unmapped pages, and outside the layout.
fn address() -> impl Strategy<Value = u32> {
    let stack_top = ((1u64 << 32) - 2 * u64::from(ZONE) - (1 << 24)) as u32;
    prop_oneof![
        (0u32..300).prop_map(|offset| ZONE + offset),
        (0u32..4 * 4096).prop_map(|offset| 3 * ZONE + offset),
        (0u32..2 * 4096).prop_map(move |offset| stack_top - 2 * 4096 + offset),
        Just(3 * ZONE + 4 * 4096 - 1),
        Just(stack_top - 1),
        Just(ZONE - 1),
        (0u32..64).prop_map(|offset| 0x50_0000 + offset * 4096),
    ]
}

#[derive(Clone, Debug)]
enum Op {
    Poke(u32, u8, u16),
    Pages(u32, u32, u8),
    Invoke(Gas, [u32; 5], u64),
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        (address(), any::<u8>(), 1u16..6000).prop_map(|(at, byte, len)| Op::Poke(at, byte, len)),
        (address(), 1u32..20, 0u8..5).prop_map(|(at, count, mode)| Op::Pages(
            at / 4096,
            count,
            mode
        )),
        (
            0u64..2000,
            proptest::array::uniform5(address()),
            any::<u64>()
        )
            .prop_map(|(gas, at, value)| Op::Invoke(gas, at, value)),
    ]
}

fn apply(machines: &mut InnerMachines, id: u32, op: &Op, carried: &mut InvokeState) -> Vec<u32> {
    match *op {
        Op::Poke(at, byte, len) => {
            let _ = machines.poke(id, at, &vec![byte; len as usize]);
            (at / 4096..=(at.saturating_add(u32::from(len)) - 1) / 4096).collect()
        }
        Op::Pages(first, count, mode) => {
            let _ = machines.pages(
                id,
                first,
                count,
                PageMode::try_from(u64::from(mode)).unwrap(),
            );
            (first..first.saturating_add(count)).collect()
        }
        Op::Invoke(gas, at, value) => {
            // φ7 h, φ8 store base and m, φ10 second store, φ12 last store.
            let mut registers = carried.registers;
            for (register, &address) in [7, 8, 10, 12, 11].iter().zip(&at) {
                registers[*register] = u64::from(address);
            }
            registers[9] = value;
            registers[11] = value.rotate_left(17);
            let outcome = run(machines, id, InvokeState { gas, registers });
            if let Ok(outcome) = outcome {
                *carried = outcome.state;
            }
            at.iter()
                .flat_map(|&address| [address / 4096, address.saturating_add(8) / 4096])
                .collect()
        }
    }
}

/// What [`program`] runs with: h at the read-write data's start, m two
/// pages on, a 2-byte store across its first page boundary, and the
/// last store 100 bytes in.
fn probe_state() -> InvokeState {
    let mut registers = [0; PVM_REGISTER_COUNT];
    registers[7] = u64::from(3 * ZONE);
    registers[8] = u64::from(3 * ZONE + 2 * 4096);
    registers[9] = 0x0123_4567_89ab_cdef;
    registers[10] = u64::from(3 * ZONE + 4095);
    registers[11] = 0xbeef;
    registers[12] = u64::from(3 * ZONE + 100);
    InvokeState {
        gas: 1_000_000,
        registers,
    }
}

fn probe(machines: &mut InnerMachines, id: u32) -> (InnerExit, InvokeState) {
    let mut state = probe_state();
    loop {
        let outcome = run(machines, id, state).unwrap();
        state = outcome.state;
        if outcome.exit != InnerExit::Host(0x77) {
            return (outcome.exit, state);
        }
    }
}

/// Invoke, serving BLAKE2b compressions as an agent does: their price
/// from the machine's gas, then the output poked over h. Any other
/// exit, or a call that cannot be paid or read, returns.
fn run(
    machines: &mut InnerMachines,
    id: u32,
    mut state: InvokeState,
) -> Result<crate::inner::InvokeOutcome, InnerError> {
    use crate::precompile::{BLAKE2B_COMPRESS, BLAKE2B_COMPRESS_GAS, compress};
    loop {
        let outcome = machines.invoke(id, state)?;
        let registers = outcome.state.registers;
        let words = |bytes: Vec<u8>| -> Vec<u64> {
            bytes
                .chunks(8)
                .map(|word| u64::from_le_bytes(word.try_into().unwrap()))
                .collect()
        };
        let served = (outcome.exit == InnerExit::Host(BLAKE2B_COMPRESS)
            && outcome.state.gas >= BLAKE2B_COMPRESS_GAS)
            .then(|| {
                let h = machines.peek(id, registers[7] as u32, 64).ok()?;
                let m = machines.peek(id, registers[8] as u32, 128).ok()?;
                let out = compress(
                    &words(h).try_into().unwrap(),
                    &words(m).try_into().unwrap(),
                    u128::from(registers[9]),
                    registers[10] != 0,
                );
                let bytes: Vec<u8> = out.iter().flat_map(|word| word.to_le_bytes()).collect();
                machines.poke(id, registers[7] as u32, &bytes).ok()
            })
            .flatten();
        if served.is_none() {
            return Ok(outcome);
        }
        state = outcome.state;
        state.gas -= BLAKE2B_COMPRESS_GAS;
    }
}

/// The counting program, installed in a pool, the page its loop writes,
/// and the state that starts it with `gas`.
fn counting_in_a_pool() -> (Vec<u8>, Arc<MachinePool>, Arc<PoolProgram>) {
    let blob = counting();
    let pool = Arc::new(MachinePool::new());
    let program = pool.program(&pool.install(&blob).unwrap()).unwrap();
    (blob, pool, program)
}

/// The page [`counting`] writes.
const COUNTED: u32 = 3 * ZONE + 2 * 4096;

/// The state [`counting`] starts in, with `gas`.
fn counting_from(gas: Gas) -> InvokeState {
    let mut registers = [0; PVM_REGISTER_COUNT];
    registers[8] = u64::from(COUNTED);
    InvokeState { gas, registers }
}

/// The gas a starved or faulting [`counting`] resumes with.
const GAS: Gas = 1_000_000;

#[test]
fn instantiate_lays_out_what_a_loader_builds() {
    let blob = program();
    let pool = Arc::new(MachinePool::new());
    let hash = pool.install(&blob).unwrap();
    assert_eq!(hash, CodeHash::of(&blob));
    assert_eq!(
        pool.install(&blob).unwrap(),
        hash,
        "installing again is a no-op"
    );
    let program = pool.program(&hash).unwrap();
    for backend in crate::test_support::backends() {
        let mut pooled = InnerMachines::with_backend(backend);
        pooled.set_pool(Arc::clone(&pool));
        let id = pooled.instantiate(&program, 0).unwrap();
        let (mut reference, reference_id) = loaded(&blob, backend);
        assert_eq!(
            dump(&pooled, id, &[]),
            dump(&reference, reference_id, &[]),
            "{backend:?}"
        );
        assert_eq!(
            probe(&mut pooled, id),
            probe(&mut reference, reference_id),
            "{backend:?}"
        );
        assert_eq!(
            dump(&pooled, id, &[]),
            dump(&reference, reference_id, &[]),
            "{backend:?}"
        );
    }
    // What the loader paid in host calls: machine, then pages, poke and
    // set-read-only for one read-only page, pages and poke for four
    // read-write pages (5,000 data bytes and two heap pages), and pages
    // for two stack pages.
    let code = program.code_blob().len() as u64;
    let expected = gas::MACHINE_BASE
        + gas::memory(gas::MACHINE_PER_KIB, code)
        + gas::PAGES_ALLOC_BASE
        + gas::PAGES_ALLOC_PER_PAGE
        + gas::POKE_BASE
        + gas::memory(gas::POKE_PER_KIB, 300)
        + gas::PAGES_SET_MODE_BASE
        + gas::PAGES_SET_MODE_PER_PAGE
        + gas::PAGES_ALLOC_BASE
        + 4 * gas::PAGES_ALLOC_PER_PAGE
        + gas::POKE_BASE
        + gas::memory(gas::POKE_PER_KIB, 5000)
        + gas::PAGES_ALLOC_BASE
        + 2 * gas::PAGES_ALLOC_PER_PAGE;
    assert_eq!(program.price(), expected);
}

/// A machine suspended at a host call, restored from the counter
/// `expunge` gives and the pages it wrote: a pooled machine
/// instantiated at that counter, the pages poked back, equals a
/// loader's machine made there, and resumes right after the call as it
/// does. Entered mid-block, both are charged the whole block again,
/// where the machine that never stopped pays nothing more.
#[test]
fn instantiate_at_a_counter_resumes_a_suspended_machine() {
    let blob = program();
    let pool = Arc::new(MachinePool::new());
    let program = pool.program(&pool.install(&blob).unwrap()).unwrap();
    // The read-write region's four pages: every page the program writes.
    let first = 3 * ZONE / 4096;
    let written: Vec<u32> = (first..first + 4).collect();
    let state = probe_state();
    let [h, m, last] = [7, 8, 12].map(|register| state.registers[register] as u32);
    let half = state.registers[10] as u32;
    for backend in crate::test_support::backends() {
        let mut machines = InnerMachines::with_backend(backend);
        machines.set_pool(Arc::clone(&pool));
        let to_the_call = |machines: &mut InnerMachines| {
            let id = machines.instantiate(&program, 0).unwrap();
            let outcome = run(machines, id, probe_state()).unwrap();
            assert_eq!(outcome.exit, InnerExit::Host(0x77), "{backend:?}");
            (id, outcome.state)
        };

        let (stopped, suspended) = to_the_call(&mut machines);
        let pages: Vec<(u32, Vec<u8>)> = written
            .iter()
            .map(|&page| (page, machines.peek(stopped, page * 4096, PAGE).unwrap()))
            .collect();
        let pc = machines.expunge(stopped).unwrap();
        assert_eq!(pc, 9, "{backend:?}: right after the 2-byte call at 7");
        let block = state.gas - suspended.gas - crate::precompile::BLAKE2B_COMPRESS_GAS;

        let (going, at_call) = to_the_call(&mut machines);
        let continued = machines.invoke(going, at_call.clone()).unwrap();
        assert_eq!(continued.exit, InnerExit::Panic, "{backend:?}");
        assert_eq!(continued.state.gas, at_call.gas, "{backend:?}: funded");
        machines.expunge(going).unwrap();

        // Marks where the stores before the call wrote: a resume that
        // ran them again would overwrite them.
        let restore = |machines: &mut InnerMachines, id: u32| {
            for (page, bytes) in &pages {
                machines.poke(id, page * 4096, bytes).unwrap();
            }
            for (address, len) in [(h, 64), (m, 8), (half, 2)] {
                machines.poke(id, address, &vec![0xa5; len]).unwrap();
            }
        };
        let restored = machines.instantiate(&program, pc).unwrap();
        restore(&mut machines, restored);
        let (mut reference, reference_id) = loaded_at(&blob, backend, pc);
        restore(&mut reference, reference_id);
        assert_eq!(
            dump(&machines, restored, &[]),
            dump(&reference, reference_id, &[]),
            "{backend:?}"
        );

        let resumed = machines.invoke(restored, suspended.clone()).unwrap();
        let expected = reference.invoke(reference_id, suspended.clone()).unwrap();
        assert_eq!(resumed, expected, "{backend:?}");
        assert_eq!(
            resumed.exit,
            InnerExit::Panic,
            "{backend:?}: no second call"
        );
        assert_eq!(
            suspended.gas - resumed.state.gas,
            block,
            "{backend:?}: the whole block again"
        );
        assert_eq!(
            machines.peek(restored, last, 1).unwrap(),
            [0xef],
            "{backend:?}: the store after the call landed"
        );
        for (address, len) in [(h, 64), (m, 8), (half, 2)] {
            assert_eq!(
                machines.peek(restored, address, len).unwrap(),
                vec![0xa5; len],
                "{backend:?}: nothing before the call ran again"
            );
        }
        assert_eq!(
            dump(&machines, restored, &[]),
            dump(&reference, reference_id, &[]),
            "{backend:?}"
        );
        assert_eq!(machines.expunge(restored), Ok(0), "{backend:?}");
        assert_eq!(
            machines
                .instantiate(&program, 0)
                .map(|id| machines.expunge(id)),
            Ok(Ok(0)),
            "{backend:?}: a machine returned to the pool starts at 0"
        );
    }
}

/// A machine out of gas at the start of a block, restored at the
/// counter `expunge` gives with the page it wrote, pooled or loaded:
/// the block it stopped at is charged once, on resume, so it ends as
/// the machine that never stopped, with the same gas in all, on both
/// backends.
#[test]
fn instantiate_at_an_out_of_gas_counter_resumes_a_starved_machine() {
    let (blob, pool, program) = counting_in_a_pool();
    let (page, start) = (COUNTED, counting_from);
    let mut observed = Vec::new();
    for backend in crate::test_support::backends() {
        let mut stops = Vec::new();
        let mut machines = InnerMachines::with_backend(backend);
        machines.set_pool(Arc::clone(&pool));
        let id = machines.instantiate(&program, 0).unwrap();
        let straight = machines.invoke(id, start(GAS)).unwrap();
        assert_eq!(straight.exit, InnerExit::Panic, "{backend:?}");
        assert_eq!(straight.state.registers[2], 100, "{backend:?}");
        let used = GAS - straight.state.gas;
        let stored = machines.peek(id, page, 4096).unwrap();
        machines.expunge(id).unwrap();
        for starve in [1, used / 3, used / 2 + 7, used - 1] {
            let id = machines.instantiate(&program, 0).unwrap();
            let starved = machines.invoke(id, start(starve)).unwrap();
            assert_eq!(starved.exit, InnerExit::OutOfGas, "{backend:?}, {starve}");
            assert!(starved.state.gas <= starve, "{backend:?}: not wrapped");
            let rounds = starved.state.registers[2];
            let bytes = machines.peek(id, page, 4096).unwrap();
            let pc = machines.expunge(id).unwrap();
            // A block's start: the entry, the loop's body or the trap.
            assert!([0, 1, 10].contains(&pc), "{backend:?}, {starve}: at {pc}");
            let pooled = machines.instantiate(&program, pc).unwrap();
            let (mut loader, loaded) = loaded_at(&blob, backend, pc);
            for (machines, id) in [(&mut machines, pooled), (&mut loader, loaded)] {
                machines.poke(id, page, &bytes).unwrap();
                let state = InvokeState {
                    gas: GAS,
                    registers: starved.state.registers,
                };
                let resumed = machines.invoke(id, state).unwrap();
                assert_eq!(resumed.exit, InnerExit::Panic, "{backend:?}");
                assert_eq!(resumed.state.registers, straight.state.registers);
                assert_eq!(machines.peek(id, page, 4096).unwrap(), stored);
                assert_eq!(
                    (starve - starved.state.gas) + (GAS - resumed.state.gas),
                    used,
                    "{backend:?}, {starve}: the block it stopped at, charged once"
                );
                machines.expunge(id).unwrap();
            }
            stops.push((starve, rounds, starved.state.gas, pc));
        }
        observed.push(stops);
    }
    // Both backends stop at the same block, with the same gas left.
    assert!(
        observed.windows(2).all(|pair| pair[0] == pair[1]),
        "starved at {observed:?}"
    );
}

/// A machine stopped by a fault at a store, restored at the counter
/// `expunge` gives, the faulting store's, with its page made writable,
/// pooled or loaded: it re-enters the store's block and is charged that
/// block again, so it ends as the machine that never stopped, one
/// block's gas the dearer, on both backends.
#[test]
fn instantiate_at_a_faulting_store_charges_its_block_again() {
    let (blob, pool, program) = counting_in_a_pool();
    let (page, start) = (COUNTED, counting_from);
    let mut observed = Vec::new();
    for backend in crate::test_support::backends() {
        let mut machines = InnerMachines::with_backend(backend);
        machines.set_pool(Arc::clone(&pool));
        let run = |machines: &mut InnerMachines, gas| {
            let id = machines.instantiate(&program, 0).unwrap();
            let outcome = machines.invoke(id, start(gas)).unwrap();
            (id, outcome)
        };
        let (id, straight) = run(&mut machines, GAS);
        let used = GAS - straight.state.gas;
        let stored = machines.peek(id, page, 4096).unwrap();
        machines.expunge(id).unwrap();
        // The loop's body costs what two starved runs differ by a round.
        let starved: Vec<(Gas, u64)> = [used / 3, used / 2]
            .into_iter()
            .map(|gas| {
                let (id, outcome) = run(&mut machines, gas);
                assert_eq!(machines.expunge(id), Ok(1), "{backend:?}");
                (gas - outcome.state.gas, outcome.state.registers[2])
            })
            .collect();
        let body = (starved[1].0 - starved[0].0) / (starved[1].1 - starved[0].1);

        let id = machines.instantiate(&program, 0).unwrap();
        machines
            .pages(id, page / 4096, 1, PageMode::SetReadOnly)
            .unwrap();
        let fault = machines.invoke(id, start(GAS)).unwrap();
        assert_eq!(fault.exit, InnerExit::Fault(page), "{backend:?}");
        assert_eq!(fault.state.registers[2], 1, "{backend:?}: before the store");
        let pc = machines.expunge(id).unwrap();
        assert_eq!(pc, 4, "{backend:?}: the store's counter");
        let pooled = machines.instantiate(&program, pc).unwrap();
        let (mut loader, loaded) = loaded_at(&blob, backend, pc);
        for (machines, id) in [(&mut machines, pooled), (&mut loader, loaded)] {
            let state = InvokeState {
                gas: GAS,
                registers: fault.state.registers,
            };
            let resumed = machines.invoke(id, state).unwrap();
            assert_eq!(resumed.exit, InnerExit::Panic, "{backend:?}");
            assert_eq!(resumed.state.registers, straight.state.registers);
            assert_eq!(machines.peek(id, page, 4096).unwrap(), stored);
            assert_eq!(
                (GAS - fault.state.gas) + (GAS - resumed.state.gas),
                used + body,
                "{backend:?}: the store's block, charged again"
            );
            machines.expunge(id).unwrap();
        }
        observed.push((used, body, fault.state.gas));
    }
    // Both backends: the gas straight, the body's, and the gas left at
    // the fault.
    assert!(
        observed.windows(2).all(|pair| pair[0] == pair[1]),
        "{observed:?}"
    );
}

#[test]
fn instantiate_refuses_a_counter_that_starts_no_instruction() {
    let blob = program();
    let pool = Arc::new(MachinePool::new());
    let program = pool.program(&pool.install(&blob).unwrap()).unwrap();
    let mut machines = InnerMachines::new();
    machines.set_pool(Arc::clone(&pool));
    for pc in [1, 3, 8, 12, u32::MAX] {
        assert_eq!(
            machines.instantiate(&program, pc),
            Err(InnerError::Invalid),
            "{pc}"
        );
    }
    assert!(machines.is_empty());
    let id = machines.instantiate(&program, 11).unwrap();
    assert_eq!(machines.expunge(id), Ok(11));
}

#[test]
fn machines_whose_backend_failed_never_return() {
    let blob = program();
    let pool = Arc::new(MachinePool::new());
    let program = pool.program(&pool.install(&blob).unwrap()).unwrap();
    let mut machines = InnerMachines::new();
    machines.set_pool(Arc::clone(&pool));
    let id = machines.instantiate(&program, 0).unwrap();
    machines.fail_backend_for_test(id);
    machines.expunge(id).unwrap();
    assert_eq!(pool.idle(), 0);
}

#[test]
fn uninstalled_programs_and_full_programs_keep_no_machines() {
    let blob = program();
    let pool = Arc::new(MachinePool::with_idle_limits(8, 1));
    let hash = pool.install(&blob).unwrap();
    let program = pool.program(&hash).unwrap();
    let mut machines = InnerMachines::new();
    machines.set_pool(Arc::clone(&pool));
    let first = machines.instantiate(&program, 0).unwrap();
    let second = machines.instantiate(&program, 0).unwrap();
    machines.expunge(first).unwrap();
    machines.expunge(second).unwrap();
    assert_eq!(pool.idle(), 1, "one idle machine per program");

    let lent = machines.instantiate(&program, 0).unwrap();
    pool.uninstall(&hash);
    assert!(pool.program(&hash).is_none());
    machines.expunge(lent).unwrap();
    assert_eq!(
        pool.idle(),
        0,
        "an uninstalled program's machines are dropped"
    );
}

/// A native machine whose resets zeroed many pages in place has all its
/// pages discarded, and still equals a fresh one.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn scattered_writes_trigger_a_deep_clean() {
    let blob = program();
    let pool = Arc::new(MachinePool::new());
    let program = pool.program(&pool.install(&blob).unwrap()).unwrap();
    let mut machines = InnerMachines::with_backend(PvmBackend::ForceRecompiler);
    machines.set_pool(Arc::clone(&pool));
    let base = 0x50_0000u32 / 4096;
    let zeroed = |pool: &MachinePool| {
        lock(&pool.idle)
            .by_program
            .values()
            .flatten()
            .map(|machine| machine.zeroed)
            .sum::<usize>()
    };
    let mut cleaned = false;
    for _ in 0..4 {
        let id = machines.instantiate(&program, 0).unwrap();
        machines
            .pages(id, base, 400, PageMode::AllocateReadWrite)
            .unwrap();
        for page in (0..400).step_by(2) {
            machines.poke(id, (base + page) * 4096, &[1]).unwrap();
        }
        machines.expunge(id).unwrap();
        cleaned |= zeroed(&pool) == 0;
    }
    assert!(cleaned, "a deep clean ran");
    let id = machines.instantiate(&program, 0).unwrap();
    let (reference, reference_id) = loaded(&blob, PvmBackend::ForceRecompiler);
    let touched: Vec<u32> = (base..base + 400).collect();
    assert_eq!(
        dump(&machines, id, &touched),
        dump(&reference, reference_id, &touched)
    );
}

/// A standard program that stores u64 `args[8..16]` at address
/// `args[0..8]`, then halts with output `args[24..32]` bytes at address
/// `args[16..24]`.
fn scribe() -> Vec<u8> {
    let mut code = Vec::new();
    let mut starts = Vec::new();
    let mut asm = |instruction: &[u8]| {
        starts.push(code.len());
        code.extend_from_slice(instruction);
    };
    let load = Opcode::LoadIndU64 as u8;
    asm(&[load, 2 | (7 << 4)]);
    asm(&[load, 3 | (7 << 4), 8]);
    asm(&[load, 4 | (7 << 4), 16]);
    asm(&[load, 5 | (7 << 4), 24]);
    asm(&[Opcode::StoreIndU64 as u8, 3 | (2 << 4)]);
    asm(&[Opcode::MoveReg as u8, 7 | (4 << 4)]);
    asm(&[Opcode::MoveReg as u8, 8 | (5 << 4)]);
    asm(&[Opcode::JumpInd as u8, 0]);
    let mut bitmask = vec![0; code.len()];
    for start in starts {
        bitmask[start] = 1;
    }
    let code = vos_pvm_program::build_compact_code_blob(&CodeBlob {
        code,
        bitmask,
        jump_table: Vec::new(),
    })
    .unwrap();
    let ro: Vec<u8> = (0..300).map(|i| (i * 7) as u8 | 1).collect();
    let rw: Vec<u8> = (0..5000).map(|i| (i * 13) as u8).collect();
    let (heap_pages, stack) = (2u16, 8192u32);
    let mut blob = Vec::new();
    blob.extend_from_slice(&(ro.len() as u32).to_le_bytes()[..3]);
    blob.extend_from_slice(&(rw.len() as u32).to_le_bytes()[..3]);
    blob.extend_from_slice(&heap_pages.to_le_bytes());
    blob.extend_from_slice(&stack.to_le_bytes()[..3]);
    blob.extend_from_slice(&ro);
    blob.extend_from_slice(&rw);
    blob.extend_from_slice(&(code.len() as u32).to_le_bytes());
    blob.extend_from_slice(&code);
    blob
}

/// `scribe`'s regions: read-only data, read-write data and heap, the
/// stack, and the arguments.
const SCRIBE_RO: u64 = 0x1_0000;
const SCRIBE_RW: u64 = 0x3_0000;
const SCRIBE_RW_END: u64 = 0x3_4000;
const SCRIBE_STACK: u64 = 0xFEFD_E000;
const SCRIBE_ARGS: u64 = 0xFEFF_0000;

/// An address in or around one of `scribe`'s regions.
fn scribe_address() -> impl Strategy<Value = u64> {
    prop_oneof![
        (0..0x4000u64 - 8).prop_map(|offset| SCRIBE_RW + offset),
        (0..0x2000u64 - 8).prop_map(|offset| SCRIBE_STACK + offset),
        (0..0x1000u64).prop_map(|offset| SCRIBE_RO + offset),
        (0..0x3000u64).prop_map(|offset| SCRIBE_ARGS + offset),
        Just(SCRIBE_RW_END - 4),
        Just(0x2_0000),
    ]
}

/// One run of `scribe`: its arguments, padded with a pattern to a
/// length that spans zero to three pages, and its gas.
fn scribe_run() -> impl Strategy<Value = (Vec<u8>, u64)> {
    (
        scribe_address(),
        any::<u64>(),
        scribe_address(),
        prop_oneof![Just(0u64), Just(8), Just(100), Just(5000)],
        prop_oneof![Just(0usize), Just(16), 32..0x2800usize],
        any::<u8>(),
        prop_oneof![Just(5u64), Just(1_000_000)],
    )
        .prop_map(|(at, value, out, len, size, pattern, gas)| {
            let mut args = Vec::new();
            for word in [at, value, out, len] {
                args.extend_from_slice(&word.to_le_bytes());
            }
            args.resize(size.max(32), pattern | 1);
            args.truncate(size);
            (args, gas)
        })
}

fn finish(mut machine: Machine) -> Invocation {
    let exit = machine.try_resume().unwrap();
    machine.finish(exit)
}

/// What a run shows: its exit, gas, registers, counter and output, and
/// the bytes of every page it may have touched or read.
fn shown(invocation: &Invocation, args: usize) -> (String, Option<Vec<u8>>, Vec<u8>) {
    let mut bytes = Vec::new();
    let mut page = |at: u64| {
        let mut buffer = vec![0u8; PAGE];
        invocation.memory().read_bytes(at as u32, &mut buffer);
        bytes.extend_from_slice(&buffer);
    };
    for at in (SCRIBE_RO..SCRIBE_RO + 0x1000).step_by(PAGE) {
        page(at);
    }
    for at in (SCRIBE_RW..SCRIBE_RW_END).step_by(PAGE) {
        page(at);
    }
    for at in (SCRIBE_STACK..SCRIBE_STACK + 0x2000).step_by(PAGE) {
        page(at);
    }
    for at in (SCRIBE_ARGS..SCRIBE_ARGS + args.next_multiple_of(PAGE) as u64).step_by(PAGE) {
        page(at);
    }
    let state = format!(
        "{:?} {} {:?} {}",
        invocation.exit, invocation.gas_used, invocation.registers, invocation.pc
    );
    (state, invocation.output_bounded(0x4000), bytes)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Over any sequence of runs, each laying in arguments of a
    /// different length, storing anywhere, faulting or running out of
    /// gas, a kept outer machine runs as a freshly loaded one does, and
    /// leaves nothing behind: its earlier arguments and stores read as
    /// they would on a fresh machine.
    #[test]
    fn kept_outer_machines_equal_fresh_ones(
        runs in proptest::collection::vec(scribe_run(), 1..8),
    ) {
        let blob = scribe();
        for backend in crate::test_support::backends() {
            let outer = OuterMachines::new(&blob, backend).unwrap();
            let prepared =
                crate::refine::PreparedProgram::new_with_backend(&blob, backend).unwrap();
            for (args, gas) in &runs {
                let kept = finish(outer.load(0, args, *gas).unwrap());
                let fresh = finish(
                    Machine::load_prepared_at(
                        &prepared,
                        0,
                        args,
                        *gas,
                        crate::refine::MemoryModel::Auto,
                    )
                    .unwrap(),
                );
                prop_assert_eq!(
                    shown(&kept, args.len()),
                    shown(&fresh, args.len()),
                    "{:?}",
                    backend
                );
                outer.restore(kept);
                prop_assert_eq!(outer.idle(), 1, "the machine is kept");
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// After any sequence of guest stores (straddling ones included),
    /// precompile output, `poke`, `pages` changes, host-call stops and
    /// running out of gas, a released machine comes back equal to one a
    /// loader builds from scratch, and behaves the same.
    #[test]
    fn released_machines_equal_fresh_ones(ops in proptest::collection::vec(op(), 1..12)) {
        let blob = program();
        let pool = Arc::new(MachinePool::new());
        let program = pool.program(&pool.install(&blob).unwrap()).unwrap();
        for backend in crate::test_support::backends() {
            let mut pooled = InnerMachines::with_backend(backend);
            pooled.set_pool(Arc::clone(&pool));
            let id = pooled.instantiate(&program, 0).unwrap();
            let mut carried = InvokeState { gas: 0, registers: [0; PVM_REGISTER_COUNT] };
            let mut touched = Vec::new();
            for op in &ops {
                touched.extend(apply(&mut pooled, id, op, &mut carried));
            }
            pooled.expunge(id).unwrap();
            prop_assert_eq!(pool.idle(), 1, "the released machine is kept");

            let id = pooled.instantiate(&program, 0).unwrap();
            prop_assert_eq!(pool.idle(), 0, "and lent again");
            let (mut reference, reference_id) = loaded(&blob, backend);
            prop_assert_eq!(
                dump(&pooled, id, &touched),
                dump(&reference, reference_id, &touched),
                "{:?}", backend
            );
            prop_assert_eq!(probe(&mut pooled, id), probe(&mut reference, reference_id));
            prop_assert_eq!(
                dump(&pooled, id, &touched),
                dump(&reference, reference_id, &touched),
                "{:?} after a run", backend
            );
            pooled.expunge(id).unwrap();
            drop(pooled);
            prop_assert_eq!(pool.idle(), 1);
            let _ = pool.acquire(&program, backend).unwrap();
        }
    }
}
