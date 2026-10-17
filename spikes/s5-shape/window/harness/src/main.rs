//! The settlement-window kernel proved over its shape.
//!
//! `s5-shape-window <actor.elf> <args> <out> [<cut class>] [<full: segments>]`:
//! derive the actor's one attestable method's kernel and its shape, run
//! `state` on `args` live on the agent's reference model, re-trace the
//! kernel from the attest, and prove the run on the Poseidon2-M31 segment
//! format cut at the class's budgets, each window at the first class that
//! holds it. Each proof is written to `<out>/<name>-segN.postcard` beside
//! its class's preprocessed root (`.commitment.postcard`), for the guest
//! verifier. The chain verifies natively against the kernel's program.
//!
//! The segments named in `full` (comma-separated indices) are proved again
//! over the full set of chips, the shape's at its class's sizes and the
//! rest at their natural sizes, into `<name>-full-segN.postcard`: the same
//! statement, the cost of the full shape; and at their natural sizes over
//! the chips they use, as an unshaped proof is, into
//! `<name>-natural-segN.postcard`. `S5_NATURAL` prints each window's
//! natural sizes at the cut instead, and proves nothing.
//!
//! From `spikes/s5-shape/window`:
//!
//! ```sh
//! (cd actor && cargo build --release --target riscv64em-vos.json)
//! (cd harness && cargo build --release)
//! systemd-run --user --scope -q -p MemoryMax=14G -p MemorySwapMax=0 nice -n 10 \
//!   harness/target/release/s5-shape-window \
//!   actor/target/riscv64em-vos/release/settle-window.elf args/n1000000-j8.args runs/j8 1 4,7
//! ../guest-verify/run.sh runs/j8/n1000000-j8-seg4.postcard runs/j8/n1000000-j8-full-seg4.postcard
//! ```

use std::path::{Path, PathBuf};
use std::time::Instant;

use vos_pvm_proof::chip_idx;
use vos_pvm_proof::format::SEGMENT;
use vos_pvm_proof::framework_access::create_verifier_components::trace_and_preprocessed_sizes;
use vos_pvm_proof::kernel::{kernel_side_note, trace_kernel};
use vos_pvm_proof::program_id::{KernelProgram, LeafCircuits};
use vos_pvm_proof::segment::SegmentCursor;
use vos_pvm_proof::shape::{KernelShape, SegmentClass, SegmentShape};
use vos_pvm_proof::{
    natural_log_sizes_for, program_commitment_for_shape, program_commitment_of_proof, prove_kernel,
    prove_shaped,
};
use vos_testkit::Testkit;
use vos_testkit::programs::method;
use vos_wire::abi::cap::Target;
use vos_wire::ids::{AgentId, InstanceId, Principal};

const GAS: u64 = 10_000_000_000;

fn peak_rss_mib() -> f64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find(|line| line.starts_with("VmHWM:"))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|kib| kib.parse::<f64>().ok())
        .unwrap_or(0.0)
        / 1024.0
}

/// Reset the process's peak RSS to its current RSS.
fn reset_peak_rss() {
    let _ = std::fs::write("/proc/self/clear_refs", "5");
}

/// A shape's columns: preprocessed, main, interaction and composition.
fn columns(components: u32, log_sizes: &[u32]) -> [usize; 4] {
    let (trees, preprocessed) = trace_and_preprocessed_sizes(log_sizes, components);
    let tree = |index: usize| trees.iter().map(|sizes| sizes[index].len()).sum::<usize>();
    [preprocessed.len(), tree(1), tree(2), 8]
}

fn cells(components: u32, log_sizes: &[u32]) -> u64 {
    let (trees, preprocessed) = trace_and_preprocessed_sizes(log_sizes, components);
    let rows = |sizes: &[u32]| sizes.iter().map(|&size| 1u64 << size).sum::<u64>();
    rows(&preprocessed)
        + trees
            .iter()
            .map(|sizes| rows(&sizes[1]) + rows(&sizes[2]))
            .sum::<u64>()
}

fn write(path: PathBuf, bytes: &[u8]) {
    std::fs::write(&path, bytes).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!(
            "usage: s5-shape-window <actor.elf> <args> <out> [<cut class>] [<full segments>]"
        );
        std::process::exit(2);
    }
    let elf = std::fs::read(&args[1]).expect("the actor's ELF");
    let arguments = std::fs::read(&args[2]).expect("the arguments");
    let out = Path::new(&args[3]);
    let cut: usize = args.get(4).map_or(1, |cut| cut.parse().expect("a class"));
    let full: Vec<usize> = args
        .get(5)
        .map(|list| {
            list.split(',')
                .map(|index| index.parse().unwrap())
                .collect()
        })
        .unwrap_or_default();
    std::fs::create_dir_all(out).unwrap();
    let name = Path::new(&args[2])
        .file_stem()
        .unwrap()
        .to_string_lossy()
        .to_string();

    let started = Instant::now();
    let derived = vos_pvm_compiler::derive(&elf).expect("derives");
    assert_eq!(derived.kernels.len(), 1, "one attestable method");
    let (_, blob) = &derived.kernels[0];
    let record = &derived.shapes[0];
    let derivation = vos_wire::records::Derivation::new(
        &elf,
        &derived.actor,
        &derived.kernels,
        &derived.shapes,
        derived.transpiler_version,
        derived.heap,
    );
    println!(
        "derived in {:.2}s: kernel {} B, {} instructions' code {} B, jump table {}",
        started.elapsed().as_secs_f64(),
        blob.len(),
        derived.kernels.len(),
        vos_pvm_program::parse_standard_program(blob)
            .map(|program| program.code.code.len())
            .unwrap_or(0),
        vos_pvm_program::parse_standard_program(blob)
            .map(|program| program.code.jump_table.len())
            .unwrap_or(0),
    );
    let shape = KernelShape {
        components: record.chips,
        classes: record
            .classes
            .iter()
            .map(|class| SegmentClass {
                log_steps: class.log_steps,
                pages: class.pages,
                log_sizes: (0..chip_idx::COUNT)
                    .filter(|chip| record.chips & 1 << chip != 0)
                    .map(|chip| class.log_sizes[chip])
                    .collect(),
            })
            .collect(),
    };
    shape.check().unwrap();
    println!(
        "shape: chips {:#x} ({} of {}), left out {:#x}",
        shape.components,
        shape.components.count_ones(),
        chip_idx::COUNT,
        chip_idx::ALL & !shape.components
    );
    for (index, class) in shape.classes.iter().enumerate() {
        let segment = shape.segment(index).unwrap();
        println!(
            "class {index}: 2^{} steps, {} pages, log sizes {:?}, columns {:?}, cells {}",
            class.log_steps,
            class.pages,
            class.log_sizes,
            columns(segment.components, &segment.log_sizes),
            cells(segment.components, &segment.log_sizes)
        );
    }

    // The live run, and its attest.
    let mut kit = Testkit::new(AgentId(7));
    kit.install_derived(Target::Vos, InstanceId(9), &derived, &[])
        .expect("installs");
    let step = kit.command(
        Principal::Client([1; 32]),
        InstanceId(9),
        method(&derived.actor, "state"),
        &arguments,
    );
    assert!(
        matches!(step.outcome, vos_wire::result::Outcome::Done(_)),
        "{:?}",
        step.outcome
    );
    let attest = step.attests.into_iter().next().expect("an attest");
    if let Ok(expected) = std::fs::read(Path::new(&args[2]).with_extension("expected")) {
        // The output is the method's return value, a byte vector, encoded.
        let encoded = [&(expected.len() as u32).to_le_bytes()[..], &expected].concat();
        assert_eq!(attest.output, encoded, "the window's output");
    }
    let started = Instant::now();
    let trace = trace_kernel(blob, &attest.witness_input, GAS).expect("re-runs");
    assert_eq!(trace.output, attest.output);
    println!(
        "traced in {:.2}s: {} steps, {} compressions, witness input {} B",
        started.elapsed().as_secs_f64(),
        trace.side_note.steps.len(),
        trace.side_note.blake2b_calls.len(),
        attest.witness_input.len()
    );

    // `S5_NATURAL`: each window's natural log sizes at the cut, and stop.
    if std::env::var_os("S5_NATURAL").is_some() {
        let class = &shape.classes[cut];
        let bounds = vos_pvm_proof::segment::segment_bounds_budgeted(
            &trace.side_note,
            1 << class.log_steps,
            usize::from(class.pages),
        );
        let all: Vec<usize> = (0..chip_idx::COUNT).collect();
        let mut cursor = SegmentCursor::new(&trace.side_note);
        for (index, &(a, b)) in bounds.iter().enumerate() {
            let mut window = cursor.side_note(a, b);
            let touched = vos_pvm_proof::page_merkle::touched_pages(&window);
            let natural = natural_log_sizes_for(&mut window, &all);
            let pages = window
                .memory_pages
                .as_ref()
                .map_or(0, |pages| pages.pages.len());
            println!(
                "window {index}: steps {a}..{b} ({}), {} compressions, {} boundary \
                 compressions, {pages} pages ({} touched: {touched:x?}), natural {natural:?}",
                b - a,
                window.blake2b_calls.len(),
                window.merkle_blake2b_calls.len(),
                touched.len(),
            );
        }
        return;
    }

    // The program: each class's preprocessed root from the code alone.
    let started = Instant::now();
    let statics = kernel_side_note(blob).unwrap();
    let preprocessed_roots = (0..shape.classes.len())
        .map(|class| {
            program_commitment_for_shape(&statics, &shape.segment(class).unwrap(), &SEGMENT)
                .unwrap()
        })
        .collect();
    let kernel = &derivation.kernels[0];
    let program = KernelProgram {
        transpiler: derivation.transpiler,
        program: kernel.program.0,
        shape: shape.clone(),
        format: SEGMENT.number,
        preprocessed_roots,
        image_root: kernel.image_root,
        leaf_circuits: LeafCircuits::None,
    };
    program.check().unwrap();
    println!(
        "program id {:02x?} (roots in {:.2}s)",
        program.id().to_bytes(),
        started.elapsed().as_secs_f64()
    );

    // The run, proved over its shape.
    reset_peak_rss();
    let started = Instant::now();
    let segments = prove_kernel(&trace.side_note, &shape, cut, &SEGMENT).expect("proves");
    let seconds = started.elapsed().as_secs_f64();
    println!(
        "proved {} segments in {seconds:.2}s, peak RSS {:.0} MiB",
        segments.len(),
        peak_rss_mib()
    );
    let mut proofs = Vec::new();
    for (index, segment) in segments.iter().enumerate() {
        let proof = &segment.proof;
        let bytes = postcard::to_allocvec(proof).unwrap();
        write(out.join(format!("{name}-seg{index}.postcard")), &bytes);
        write(
            out.join(format!("{name}-seg{index}.commitment.postcard")),
            &postcard::to_allocvec(&program.preprocessed_roots[segment.class]).unwrap(),
        );
        assert_eq!(
            program_commitment_of_proof(proof),
            program.preprocessed_roots[segment.class]
        );
        println!(
            "segment {index}: steps {:?} ({}), class {}, {} B, columns {:?}",
            segment.steps,
            segment.steps.1 - segment.steps.0,
            segment.class,
            bytes.len(),
            columns(proof.component_mask, &proof.log_sizes)
        );
        proofs.push(proof.clone());
    }
    let started = Instant::now();
    let root = vos_pvm_proof_verifier::verify_kernel_chain(&proofs, &program).expect("verifies");
    println!(
        "chain verified natively in {:.3}s, final root {:02x?}",
        started.elapsed().as_secs_f64(),
        &root[..8]
    );

    // The same segments over the full set of chips.
    let mut cursor = SegmentCursor::new(&trace.side_note);
    for &index in &full {
        let segment = &segments[index];
        let (a, b) = segment.steps;
        let class = shape.segment(segment.class).unwrap();
        let all: Vec<usize> = (0..chip_idx::COUNT).collect();
        let natural = natural_log_sizes_for(&mut cursor.side_note(a, b), &all);
        let mut pinned = class.log_sizes.iter();
        let log_sizes = (0..chip_idx::COUNT)
            .map(|chip| {
                if shape.components & 1 << chip != 0 {
                    *pinned.next().unwrap()
                } else {
                    natural[chip]
                }
            })
            .collect();
        let full_shape = SegmentShape {
            components: chip_idx::ALL,
            log_sizes,
        };
        reset_peak_rss();
        let started = Instant::now();
        let proof = prove_shaped(&mut cursor.side_note(a, b), &full_shape, &SEGMENT)
            .expect("the full set proves");
        let seconds = started.elapsed().as_secs_f64();
        let bytes = postcard::to_allocvec(&proof).unwrap();
        write(out.join(format!("{name}-full-seg{index}.postcard")), &bytes);
        write(
            out.join(format!("{name}-full-seg{index}.commitment.postcard")),
            &postcard::to_allocvec(&program_commitment_of_proof(&proof)).unwrap(),
        );
        let refused = vos_pvm_proof_verifier::verify_kernel_segment(proof.clone(), &program)
            .expect_err("the full set is not the kernel's shape");
        println!(
            "segment {index} over the full set: proved in {seconds:.2}s, peak RSS {:.0} MiB, \
             {} B, columns {:?}; as the kernel's: {refused}",
            peak_rss_mib(),
            bytes.len(),
            columns(proof.component_mask, &proof.log_sizes)
        );
        // And at its natural sizes over the chips it uses, as an unshaped
        // proof is.
        reset_peak_rss();
        let started = Instant::now();
        let natural = vos_pvm_proof::prove_format(&mut cursor.side_note(a, b), &SEGMENT)
            .expect("the natural shape proves");
        let natural_seconds = started.elapsed().as_secs_f64();
        let natural_bytes = postcard::to_allocvec(&natural).unwrap();
        write(
            out.join(format!("{name}-natural-seg{index}.postcard")),
            &natural_bytes,
        );
        write(
            out.join(format!("{name}-natural-seg{index}.commitment.postcard")),
            &postcard::to_allocvec(&program_commitment_of_proof(&natural)).unwrap(),
        );
        println!(
            "segment {index} at natural sizes: proved in {natural_seconds:.2}s, peak RSS {:.0} \
             MiB, {} B, chips {:#x}, log sizes {:?}, columns {:?}",
            peak_rss_mib(),
            natural_bytes.len(),
            natural.component_mask,
            natural.log_sizes,
            columns(natural.component_mask, &natural.log_sizes)
        );
    }

    // Each segment proved alone, for its time and memory.
    let mut cursor = SegmentCursor::new(&trace.side_note);
    for (index, segment) in segments.iter().enumerate() {
        let (a, b) = segment.steps;
        let class = shape.segment(segment.class).unwrap();
        reset_peak_rss();
        let started = Instant::now();
        prove_shaped(&mut cursor.side_note(a, b), &class, &SEGMENT).unwrap();
        println!(
            "segment {index} alone: proved in {:.2}s, peak RSS {:.0} MiB",
            started.elapsed().as_secs_f64(),
            peak_rss_mib()
        );
    }
}
