//! The agent program's functions named in perf's map. This test binary turns
//! the map on for its whole process, so it holds these tests alone.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::io::Write;
use std::sync::{Arc, Mutex};

use vos_pvm::perf_map;

fn agent() -> (Vec<u8>, Vec<(u32, String)>) {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../agent/default/target/riscv64em-vos/release/vos-agent.elf"
    );
    let elf = std::fs::read(path).expect("run `just build-agent`");
    vos_pvm_compiler::link_elf_spi_with_symbols(&elf).expect("links")
}

/// Each function's first instruction is a basic-block start: the dispatch
/// table the map reads maps only those.
#[test]
fn the_agent_s_functions_start_basic_blocks() {
    let (blob, functions) = agent();
    let program = vos_pvm::spi::parse_standard_program(&blob).unwrap();
    let code = &program.code;
    let starts = vos_pvm::interpreter::compute_basic_block_starts(&code.code, &code.bitmask);
    assert!(functions.len() > 100, "{} functions", functions.len());
    let outside: Vec<&(u32, String)> = functions
        .iter()
        .filter(|(at, _)| !starts.get(*at as usize).copied().unwrap_or(false))
        .collect();
    assert!(
        outside.is_empty(),
        "{} of {}: {:?}",
        outside.len(),
        functions.len(),
        &outside[..outside.len().min(5)]
    );
}

/// A sink the test reads back.
#[derive(Clone, Default)]
struct Lines(Arc<Mutex<Vec<u8>>>);

impl Write for Lines {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Compiled with its functions registered, the agent is named a line a
/// function, in order, inside its region, with its entry and exits apart.
#[test]
fn the_agent_is_named_a_line_a_function() {
    let (blob, functions) = agent();
    let program = vos_pvm::spi::parse_standard_program(&blob).unwrap();
    let code = program.code;
    perf_map::register(&code.code, functions);
    let lines = Lines::default();
    perf_map::enable_into(Box::new(lines.clone()));
    let compiled =
        vos_pvm::recompiler::compile_code(&code.code, &code.bitmask, &code.jump_table).unwrap();
    let start = compiled.native_code.ptr as usize;
    let end = start + compiled.native_code.len;
    // Every entry maps exactly: none falls forward onto another's.
    let registered = agent().1;
    let unmapped: Vec<&(u32, String)> = registered
        .iter()
        .filter(|(pc, _)| compiled.dispatch_table[*pc as usize] == compiled.panic_offset)
        .collect();
    assert!(
        unmapped.is_empty(),
        "{} unmapped: {:?}",
        unmapped.len(),
        &unmapped[..unmapped.len().min(5)]
    );
    let name = perf_map::program_name(&code.code);
    let written = String::from_utf8(lines.0.lock().unwrap().clone()).unwrap();
    let regions: Vec<(usize, usize, &str)> = written
        .lines()
        .map(|line| {
            let mut parts = line.splitn(3, ' ');
            let from = usize::from_str_radix(parts.next().unwrap(), 16).unwrap();
            let size = usize::from_str_radix(parts.next().unwrap(), 16).unwrap();
            (from, from + size, parts.next().unwrap())
        })
        .filter(|(from, _, _)| (start..end).contains(from))
        .collect();
    assert!(regions.len() > 100, "{} regions", regions.len());
    assert_eq!(regions.first().unwrap().2, format!("{name}:entry"));
    assert_eq!(regions.last().unwrap().2, format!("{name}:exits"));
    assert_eq!(regions.first().unwrap().0, start);
    assert_eq!(regions.last().unwrap().1, end);
    for pair in regions.windows(2) {
        assert_eq!(pair[0].1, pair[1].0, "{pair:?}");
    }
    assert!(
        regions
            .iter()
            .any(|(_, _, function)| function.contains("run_batch")),
        "refine's batch loop is named"
    );
}
