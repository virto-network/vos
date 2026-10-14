//! The probe's host side:
//! - `link <service.elf> <out.jam> <name>`: a Gray Paper 0.8.0 service
//!   blob, `E(↕metadata) ‖ standard program`;
//! - `local <out.jam> <payload>`: refine on VOS's JAM-only host
//!   (`RefineContext::try_run_jam`), on the interpreter and the recompiler;
//! - `decode <hex>`: a stored accumulate input, as PolkaJam produced it;
//! - `compare <out.jam> <hex>`: PolkaJam's records beside the local ones.

use std::process::ExitCode;

use vos_pvm::refine::MemoryModel;
use vos_pvm::refine_host::RefineContext;
use vos_pvm::{ExitReason, PvmBackend};
use vos_pvm_program::{encode_nat, read_nat};

/// G_R: the refine gas limit of a work package.
const REFINE_GAS: u64 = 5_000_000_000;
const SERVICE: u64 = 1;

fn encode_bytes(bytes: &[u8], out: &mut Vec<u8>) {
    encode_nat(bytes.len() as u64, out);
    out.extend_from_slice(bytes);
}

/// Conventional metadata, as shipped with PolkaJam's own services:
/// version 0, name, version, license, then a sequence of authors.
fn metadata(name: &str) -> Vec<u8> {
    let mut out = vec![0u8];
    encode_bytes(name.as_bytes(), &mut out);
    encode_bytes(b"0.1.0", &mut out);
    encode_bytes(b"AGPL-3.0-or-later", &mut out);
    encode_nat(1, &mut out);
    encode_bytes(b"VOS spike", &mut out);
    out
}

fn program_of(blob: &[u8]) -> &[u8] {
    let (len, used) = read_nat(blob, 0).expect("metadata length");
    &blob[used + len as usize..]
}

/// `E(c, i, s, ↕payload, H(p))`.
fn refine_args(payload: &[u8]) -> Vec<u8> {
    let mut args = Vec::new();
    encode_nat(0, &mut args);
    encode_nat(0, &mut args);
    encode_nat(SERVICE, &mut args);
    encode_bytes(payload, &mut args);
    args.extend_from_slice(&[0; 32]);
    args
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Record {
    step: u8,
    r7: u64,
    r8: u64,
    gas: u64,
    extra: u64,
}

fn decode_output(output: &[u8]) -> (String, Vec<Record>) {
    let tag = usize::from(output[0]);
    let payload = String::from_utf8_lossy(&output[1..1 + tag]).into_owned();
    let word = |bytes: &[u8], index: usize| {
        u64::from_le_bytes(bytes[1 + index * 8..9 + index * 8].try_into().unwrap())
    };
    let records = output[1 + tag..]
        .chunks_exact(33)
        .map(|chunk| Record {
            step: chunk[0],
            r7: word(chunk, 0),
            r8: word(chunk, 1),
            gas: word(chunk, 2),
            extra: word(chunk, 3),
        })
        .collect();
    (payload, records)
}

fn step_name(step: u8) -> &'static str {
    match step {
        1 => "calibrate (gas)",
        2 => "machine",
        3 => "pages alloc rw",
        4 => "pages set ro",
        5 => "invoke",
        6 => "pages set rw",
        7 => "peek 4 KiB",
        8 => "expunge",
        9 => "poke 4 KiB",
        10 => "check",
        11 => "pages alloc rw arena",
        12 => "pages set ro arena",
        13 => "pages set rw arena",
        14 => "export 4 KiB",
        15 => "fetch our import",
        16 => "fetch any import",
        17 => "unserved 0x480",
        18 => "log",
        19 => "start (gas left)",
        20 => "parameters",
        21 => "poke read-only page",
        22 => "imported page hash",
        23 => "inner run straight",
        24 => "inner run starved",
        25 => "inner run resumed",
        26 => "historical_lookup",
        0xff => "done",
        _ => "?",
    }
}

fn value(value: u64) -> String {
    match u64::MAX - value {
        0 => "NONE".into(),
        1 => "WHAT".into(),
        2 => "OOB".into(),
        3 => "WHO".into(),
        4 => "FULL".into(),
        5 => "CORE".into(),
        6 => "CASH".into(),
        7 => "LOW".into(),
        8 => "HUH".into(),
        _ if value >= 0x1000 => format!("{value:#x}"),
        _ => value.to_string(),
    }
}

fn exit_name(code: u64) -> &'static str {
    match code {
        0 => "HALT",
        1 => "PANIC",
        2 => "FAULT",
        3 => "HOST",
        4 => "OOG",
        _ => "?",
    }
}

/// One line per record: the results, the gas difference, and the call's
/// own charge (the difference less one `gas` call, and for `invoke` less
/// the inner gas used).
fn describe(records: &[Record]) -> Vec<String> {
    let gas_call = records
        .iter()
        .find(|record| record.step == 1)
        .map_or(0, |record| record.gas / 2);
    records
        .iter()
        .map(|record| {
            let charge = record.gas.wrapping_sub(gas_call);
            match record.step {
                1 => format!("{:<22} diff={} (gas call={gas_call})", step_name(1), record.gas),
                5 => format!(
                    "{:<22} exit={}({}) φ8={} diff={} inner-used={} invoke-charge={}",
                    step_name(5),
                    exit_name(record.r7),
                    record.r7,
                    value(record.r8),
                    record.gas,
                    record.extra,
                    charge.wrapping_sub(record.extra) as i64
                ),
                19 => format!("{:<22} {}", step_name(19), record.r7),
                23..=25 => format!(
                    "{:<22} exit={}({}) φ8={} gas-left={} inner-used={}",
                    step_name(record.step),
                    exit_name(record.r7),
                    record.r7,
                    value(record.r8),
                    record.gas,
                    record.extra
                ),
                22 => format!(
                    "{:<22} fnv={} index={}",
                    step_name(22),
                    value(record.r7),
                    record.r8
                ),
                20 if record.extra == 0 => format!(
                    "{:<22} G_A={} G_I={} (fetch kind 0: {} bytes)",
                    step_name(20),
                    value(record.r7),
                    value(record.r8),
                    value(record.gas)
                ),
                20 => format!(
                    "{:<22} G_R={} G_T={}",
                    step_name(20),
                    value(record.r7),
                    value(record.r8)
                ),
                10 => format!(
                    "{:<22} a={} b={} c={} ok={}",
                    step_name(10),
                    value(record.r7),
                    value(record.r8),
                    value(record.gas),
                    record.extra
                ),
                0xff => step_name(0xff).into(),
                step => format!(
                    "{:<22} φ7={} arg={} extra={} diff={} charge={}",
                    step_name(step),
                    value(record.r7),
                    value(record.r8),
                    value(record.extra),
                    record.gas,
                    charge as i64
                ),
            }
        })
        .collect()
}

struct LocalRun {
    exit: ExitReason,
    gas_used: u64,
    output: Option<Vec<u8>>,
}

fn run_local(blob: &[u8], payload: &[u8], backend: PvmBackend) -> LocalRun {
    let program = program_of(blob);
    let context = RefineContext::load_with_backend(
        program,
        &refine_args(payload),
        REFINE_GAS,
        MemoryModel::Auto,
        backend,
    )
    .expect("load the service program")
    .without_precompiles();
    let invocation = context
        .try_run_jam(vos_pvm::refine_host::JamRefine::default())
        .expect("the backend runs")
        .invocation;
    LocalRun {
        exit: invocation.exit.clone(),
        gas_used: invocation.gas_used,
        output: invocation.output_bounded(48 * 1024),
    }
}

fn backends() -> [(&'static str, PvmBackend); 2] {
    [
        ("interpreter", PvmBackend::ForceInterpreter),
        ("recompiler", PvmBackend::ForceRecompiler),
    ]
}

fn local(blob: &[u8], payload: &[u8]) {
    for (name, backend) in backends() {
        let run = run_local(blob, payload, backend);
        println!(
            "== VOS JAM-only host, {name}: exit {:?}, gas used {}",
            run.exit, run.gas_used
        );
        if let Some(output) = run.output {
            let (_, records) = decode_output(&output);
            for line in describe(&records) {
                println!("  {line}");
            }
        }
    }
}

fn hex_decode(text: &str) -> Vec<u8> {
    let text: String = text
        .trim()
        .trim_start_matches("0x")
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect();
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

struct StoredOperand {
    package_hash: [u8; 32],
    segment_root: [u8; 32],
    gas_limit: u64,
    result: Result<Vec<u8>, u8>,
}

fn decode_operand(input: &[u8]) -> StoredOperand {
    assert_eq!(input[0], 0, "an operand input");
    let bytes = &input[1..];
    let (gas_limit, used) = read_nat(bytes, 128).unwrap();
    let at = 128 + used;
    let result = match bytes[at] {
        0 => {
            let (len, used) = read_nat(bytes, at + 1).unwrap();
            let start = at + 1 + used;
            Ok(bytes[start..start + len as usize].to_vec())
        }
        error => Err(error),
    };
    StoredOperand {
        package_hash: bytes[..32].try_into().unwrap(),
        segment_root: bytes[32..64].try_into().unwrap(),
        gas_limit,
        result,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode(text: &str) -> Option<(String, Vec<Record>)> {
    let operand = decode_operand(&hex_decode(text));
    println!("package hash  {}", hex(&operand.package_hash));
    println!("segment root  {}", hex(&operand.segment_root));
    println!("gas limit     {}", operand.gas_limit);
    match operand.result {
        Ok(output) => {
            let (payload, records) = decode_output(&output);
            println!("payload       {payload:?}");
            for line in describe(&records) {
                println!("  {line}");
            }
            Some((payload, records))
        }
        Err(error) => {
            println!("refine error  {error}");
            None
        }
    }
}

/// A record as both hosts can agree on it: the results, and the call's own
/// charge (the gas difference less one `gas` call, and for `invoke` less
/// the inner gas used, which stays in `extra`). The start record holds the
/// budget, which differs by construction; it compares as its step alone.
fn normalized(records: &[Record]) -> Vec<(u8, u64, u64, i64, u64)> {
    let gas_call = records
        .iter()
        .find(|record| record.step == 1)
        .map_or(0, |record| record.gas / 2);
    records
        .iter()
        .map(|record| {
            let charge = match record.step {
                _ if record.gas == 0 => 0,
                1 => gas_call as i64,
                5 => record.gas as i64 - gas_call as i64 - record.extra as i64,
                _ => record.gas as i64 - gas_call as i64,
            };
            match record.step {
                19 => (19, 0, 0, 0, 0),
                step => (step, record.r7, record.r8, charge, record.extra),
            }
        })
        .collect()
}

fn compare(blob: &[u8], text: &str) {
    println!("== PolkaJam");
    let Some((payload, jam)) = decode(text) else {
        return;
    };
    let theirs = normalized(&jam);
    for (name, backend) in backends() {
        let run = run_local(blob, payload.as_bytes(), backend);
        let Some(output) = run.output else {
            println!("== {name}: no output ({:?})", run.exit);
            continue;
        };
        let (_, vos) = decode_output(&output);
        let ours = normalized(&vos);
        let lines = describe(&vos);
        let same = (0..theirs.len().max(ours.len()))
            .filter(|&index| theirs.get(index) == ours.get(index))
            .count();
        println!(
            "== VOS JAM-only host, {name} (gas used {}): {same} of {} records agree in \
             results and own charge; the others:",
            run.gas_used,
            theirs.len()
        );
        let described = describe(&jam);
        for index in 0..theirs.len().max(ours.len()) {
            if theirs.get(index) != ours.get(index) {
                println!(
                    "  #{index:<2} PolkaJam: {}\n      VOS:      {}",
                    described.get(index).map_or("-", String::as_str),
                    lines.get(index).map_or("-", String::as_str)
                );
            }
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let arguments: Vec<&str> = args.iter().skip(1).map(String::as_str).collect();
    match arguments.as_slice() {
        ["link", elf_path, out_path, name] => {
            let elf = std::fs::read(elf_path).expect("read ELF");
            let program = match vos_pvm_compiler::link_elf_spi(&elf) {
                Ok(program) => program,
                Err(error) => {
                    eprintln!("link failed: {error}");
                    return ExitCode::FAILURE;
                }
            };
            let mut blob = Vec::new();
            encode_bytes(&metadata(name), &mut blob);
            blob.extend_from_slice(&program);
            std::fs::write(out_path, &blob).expect("write service blob");
            println!(
                "{out_path}: {} bytes (program {} bytes)",
                blob.len(),
                program.len()
            );
        }
        ["local", blob, payload] => local(&std::fs::read(blob).unwrap(), payload.as_bytes()),
        ["decode", text] => {
            decode(text);
        }
        ["compare", blob, text] => compare(&std::fs::read(blob).unwrap(), text),
        _ => {
            eprintln!(
                "usage: sj-probe-tool link <elf> <out.jam> <name> | local <jam> <payload> \
                 | decode <hex> | compare <jam> <hex>"
            );
            return ExitCode::FAILURE;
        }
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    //! The plan's fault-and-repair loop on VOS's own inner machines, on the
    //! interpreter and the recompiler: a write to a read-only page faults,
    //! `SetReadWrite` repairs it, the resumed write lands, and `poke` into a
    //! read-only page is refused.

    use vos_pvm::inner::{InnerError, InnerExit, InnerMachines, InvokeState, PageMode};
    use vos_pvm::PvmBackend;
    use vos_pvm_program::{CodeBlob, build_compact_code_blob, parse_compact_code_blob};

    /// The guest's inner program (see `guest/src/main.rs`).
    const INNER: [u8; 45] = [
        0x00, 0x01, 37, //
        32, 3, 0x00, 0x00, 0x01, 0xdd, 0xcc, 0xbb, 0xaa, //
        32, 3, 0x08, 0x10, 0x01, 0x44, 0x33, 0x22, 0x11, //
        10, 7, //
        32, 3, 0x04, 0x00, 0x01, 0x88, 0x77, 0x66, 0x55, //
        51, 0x00, 0x00, 0x00, 0xff, 0xff, //
        50, 0x00, //
        0x01, 0x02, 0x14, 0x20, 0x08,
    ];
    const GAS: u64 = 1_000_000;

    fn backends() -> [PvmBackend; 2] {
        [PvmBackend::ForceInterpreter, PvmBackend::ForceRecompiler]
    }

    fn invoke(machines: &mut InnerMachines, id: u32, registers: [u64; 13]) -> (InnerExit, u64, [u64; 13]) {
        let outcome = machines
            .invoke(id, InvokeState { gas: GAS, registers })
            .unwrap();
        (outcome.exit, GAS - outcome.state.gas, outcome.state.registers)
    }

    #[test]
    fn the_inner_program_is_canonical() {
        let code = parse_compact_code_blob(&INNER).unwrap();
        assert_eq!(build_compact_code_blob(&code).unwrap(), INNER);
        assert!(vos_pvm::spi::deblob(&INNER, 20).is_some());
    }

    #[test]
    fn writes_to_read_only_pages_fault_and_resume_after_repair() {
        for backend in backends() {
            let mut machines = InnerMachines::with_backend(backend);
            let id = machines.create(&INNER, 0).unwrap();
            machines.pages(id, 16, 2, PageMode::AllocateReadWrite).unwrap();
            machines.pages(id, 16, 2, PageMode::SetReadOnly).unwrap();
            assert_eq!(
                machines.poke(id, 0x10000, &[1, 2, 3, 4]),
                Err(InnerError::OutOfBounds),
                "{backend:?}: poke into a read-only page"
            );
            let registers = [0; 13];
            let (exit, used, registers) = invoke(&mut machines, id, registers);
            assert_eq!((exit, used), (InnerExit::Fault(0x10000), 101), "{backend:?}");
            machines.pages(id, 16, 1, PageMode::SetReadWrite).unwrap();
            let (exit, used, registers) = invoke(&mut machines, id, registers);
            assert_eq!((exit, used), (InnerExit::Fault(0x11000), 0), "{backend:?}");
            machines.pages(id, 17, 1, PageMode::SetReadWrite).unwrap();
            let (exit, used, registers) = invoke(&mut machines, id, registers);
            assert_eq!((exit, used), (InnerExit::Host(7), 0), "{backend:?}");
            assert_eq!(machines.peek(id, 0x10000, 4).unwrap(), [0xdd, 0xcc, 0xbb, 0xaa]);
            assert_eq!(machines.peek(id, 0x11008, 4).unwrap(), [0x44, 0x33, 0x22, 0x11]);
            let (exit, _, _) = invoke(&mut machines, id, registers);
            assert_eq!(exit, InnerExit::Halt, "{backend:?}");
            assert_eq!(
                machines.peek(id, 0x10000, 8).unwrap(),
                [0xdd, 0xcc, 0xbb, 0xaa, 0x88, 0x77, 0x66, 0x55]
            );
        }
    }

    /// A machine created at the counter `expunge` returned after the host
    /// call (20, inside the block that starts at 0) is charged that whole
    /// block again; the same instructions as a block of their own cost less.
    #[test]
    fn a_machine_created_mid_block_pays_the_whole_block() {
        let code = parse_compact_code_blob(&INNER).unwrap();
        let tail = CodeBlob {
            jump_table: vec![],
            code: code.code[20..].to_vec(),
            bitmask: code.bitmask[20..].to_vec(),
        };
        let tail = build_compact_code_blob(&tail).unwrap();
        for backend in backends() {
            let mut machines = InnerMachines::with_backend(backend);
            let id = machines.create(&INNER, 0).unwrap();
            machines.pages(id, 16, 2, PageMode::AllocateReadWrite).unwrap();
            let (exit, whole, registers) = invoke(&mut machines, id, [0; 13]);
            assert_eq!(exit, InnerExit::Host(7));
            assert_eq!(machines.expunge(id), Ok(20));

            let id = machines.create(&INNER, 20).unwrap();
            machines.pages(id, 16, 2, PageMode::AllocateReadWrite).unwrap();
            let (exit, restored, _) = invoke(&mut machines, id, registers);
            assert_eq!(exit, InnerExit::Halt);
            machines.expunge(id).unwrap();

            let id = machines.create(&tail, 0).unwrap();
            machines.pages(id, 16, 2, PageMode::AllocateReadWrite).unwrap();
            let (exit, alone, _) = invoke(&mut machines, id, [0; 13]);
            assert_eq!(exit, InnerExit::Halt);
            println!("{backend:?}: block from 0 = {whole}, restored at 20 = {restored}, tail alone = {alone}");
            assert_eq!(restored, whole, "{backend:?}");
            assert!(alone < whole, "{backend:?}");
        }
    }
}
