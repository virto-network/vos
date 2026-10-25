//! The device baseline on today's AIR (slice 7's 7.0a, throwaway): the
//! authentication statement as a derived kernel, one segment, proved on the
//! segment prover with the Blake2s channel in two shapes, at chosen PCS
//! parameters and threads, plain or under the masked-cost proxy.
//!
//! - `gen <elf> <dir>`: a vos-tree of 10^6 rows holding a member's row; the
//!   statement's witness input (`auth.input`) and its nullifier
//!   (`auth.expected`), checked natively first.
//! - `run [--elf PATH --input PATH] [--cells LIST] [--threads N] [--reps N]
//!   [--pause S] [--out DIR] [--inline]`: each cell in a child process of
//!   its own (so its peak RSS is its own), one JSON line a cell. A cell is
//!   `shape/blowup:queries:pow/proxy`:
//!   - `built`: the kernel's chips as derived, each at the run's natural
//!     log size; verified;
//!   - `lean`: the floor without BLAKE2b and its AND table (lever 1's
//!     shape, the Poseidon2 chip not counted; a cost proxy too);
//!   - `floor`: the page-Merkle boundary chips out, the memory ledger's
//!     boundary entries for accessed bytes only (pin J's shape, as a cost
//!     proxy: its relations do not balance, so it is not verified);
//!   - `plain`, or `masked<P>`: every chip padded to 2^P rows at least, then
//!     committed one log size up (the composition so two up), as masking
//!     (c) commits a component of at least 4h rows. A chip whose size its
//!     content fixes (the tables, the program) stays at it;
//!   - `real`: masked for real, by the masked segment prover (7.14), each
//!     chip padded to four times its `h` (`2·(8 + 3q)` rounded up), the
//!     masks from the OS; verified for the built shape.
//! - `grind [--bits B] [--n N] [--threads N]`: N grinds of the Blake2s-M31
//!   channel's PoW, each from its own transcript: mean, median, 95th
//!   percentile.
//!
//! With the `phone` feature the ELF and the input are embedded; with no
//! known subcommand the binary runs session P1's cells and a grind.

use std::path::Path;
use std::process::Command;
use std::time::Instant;

use sha2::{Digest, Sha256};
use vos_pvm_proof::chip_idx;
use vos_pvm_proof::format::{
    ChannelKind, DEVICE_PROOF, Format, FormatParams, Masking, ProofKind, SPIKE_FORMAT, Status,
};
use vos_pvm_proof::kernel::trace_kernel;
use vos_pvm_proof::segment::SegmentCursor;
use vos_pvm_proof::shape::SegmentShape;
use vos_pvm_proof::{
    ProvingError, canonical_profile_for_bounds, program_commitment_of_proof, prove_shaped,
};
use vos_tree::{BatchProof, Blake2b, Encode, Leaf, MemStore, keys};

#[cfg(feature = "mimalloc")]
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

const GAS: u64 = 50_000_000;
const ROWS: usize = 1_000_000;

#[cfg(feature = "phone")]
const ELF: &[u8] = include_bytes!("../../guest/target/riscv64em-vos/release/device-statements.elf");
#[cfg(feature = "phone")]
const INPUT: &[u8] = include_bytes!("../../data/auth.input");
#[cfg(feature = "phone")]
const EXPECTED: &[u8] = include_bytes!("../../data/auth.expected");

/// The x86 proofs' SHA-256, `cell=sha256` comma-separated.
#[cfg(feature = "seeded-masks")]
const REFERENCES: &str = env!("S7_REFERENCES");

/// Session P1's cells: the built shape once (verified on the phone, the ARM
/// factor), then the floor and lean shapes at the two device candidates
/// nearest today's AIR, plain and under the proxy at each one's floor
/// (2^12 rows at 86 queries, 2^11 at 43: `device-params.md`). The built
/// shape's proxy is left out: 4.7-7.5 GiB on x86, past the phone's memory.
const P1_CELLS: &str = "built/1:86:20/plain,floor/1:86:20/plain,floor/1:86:20/masked12,\
lean/1:86:20/plain,lean/1:86:20/masked12,floor/2:43:20/plain,floor/2:43:20/masked11,lean/2:43:20/masked11";

/// The page-Merkle boundary chips.
const BOUNDARY: u32 = 1 << chip_idx::BLAKE2B_BOUNDARY
    | 1 << chip_idx::MEMORY_PAGE
    | 1 << chip_idx::MEMORY_MERKLE
    | 1 << chip_idx::MEMORY_ROOT_BOUNDARY;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn read(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}

fn json_str(value: &str) -> String {
    let escaped: String = value
        .chars()
        .flat_map(|c| match c {
            '"' => vec!['\\', '"'],
            '\\' => vec!['\\', '\\'],
            c if (c as u32) < 0x20 => vec![' '],
            c => vec![c],
        })
        .collect();
    format!("\"{escaped}\"")
}

fn peak_rss_mib() -> f64 {
    read("/proc/self/status")
        .and_then(|status| {
            status
                .lines()
                .find(|line| line.starts_with("VmHWM:"))
                .and_then(|line| line.split_whitespace().nth(1))
                .and_then(|kib| kib.parse::<f64>().ok())
        })
        .unwrap_or(0.0)
        / 1024.0
}

/// The process's CPU time so far (user + system, every thread), seconds.
fn cpu_seconds() -> f64 {
    let stat = read("/proc/self/stat").unwrap_or_default();
    let fields: Vec<&str> = stat[stat.rfind(')').map_or(0, |at| at + 2)..]
        .split(' ')
        .collect();
    let ticks = |index: usize| {
        fields
            .get(index)
            .and_then(|v| v.parse::<f64>().ok())
            .unwrap_or(0.0)
    };
    (ticks(11) + ticks(12)) / 100.0
}

fn median(values: &[f64]) -> f64 {
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    sorted[sorted.len() / 2]
}

fn percentile(values: &[f64], p: f64) -> f64 {
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let rank = ((p * sorted.len() as f64).ceil() as usize).clamp(1, sorted.len());
    sorted[rank - 1]
}

/// splitmix64: the filler rows' bytes, reproducible.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn fill(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(8) {
            let word = self.next().to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
    }
}

fn member_value(secret: &[u8; 32]) -> [u8; 32] {
    vos_pvm_precompiles::blake2b_hash::<32>(b"vos/auth/member", &[secret])
}

fn nullifier(secret: &[u8; 32], scope: &[u8; 32]) -> [u8; 32] {
    vos_pvm_precompiles::blake2b_hash::<32>(b"vos/auth/nullifier", &[secret, scope])
}

/// The tree, the member's path and the statement's witness input: the
/// method's arguments in order, as its message encodes them.
fn generate(elf: &Path, dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    let started = Instant::now();
    let seed = [3u8; 32];
    let secret = [0x11u8; 32];
    let member = keys::hashed(&Blake2b, b"member/000000042");
    let mut rng = Rng(0x5eed_0000 + ROWS as u64);
    let mut writes: Vec<(Vec<u8>, Option<Leaf>)> = Vec::with_capacity(ROWS);
    for _ in 1..ROWS {
        let mut id = [0u8; 16];
        rng.fill(&mut id);
        let mut value = [0u8; 32];
        rng.fill(&mut value);
        let key = keys::hashed(&Blake2b, &id);
        writes.push((
            key.clone(),
            Some(Leaf::salted(&Blake2b, &seed, &key, &value)),
        ));
    }
    writes.push((
        member.clone(),
        Some(Leaf::salted(
            &Blake2b,
            &seed,
            &member,
            &member_value(&secret),
        )),
    ));
    writes.sort_by(|a, b| a.0.cmp(&b.0));
    writes.dedup_by(|a, b| a.0 == b.0);
    let mut store = MemStore::default();
    let root = vos_tree::update(&Blake2b, &mut store, &writes).expect("the tree");
    drop(writes);
    let proof = BatchProof::generate(&store, std::slice::from_ref(&member)).unwrap();
    let salt = vos_tree::salt(&Blake2b, &seed, &member);
    let encoded = proof.encode();
    let commitment = vos_tree::value_hash(&Blake2b, &salt, &member_value(&secret));
    vos_tree::verify_encoded(&Blake2b, &encoded, &root, &[(&member, Some(commitment))])
        .expect("the path verifies natively");
    println!(
        "tree: {} rows, root {}, path {} B, {:.1}s",
        store.leaves.len(),
        hex(&root),
        encoded.len(),
        started.elapsed().as_secs_f64()
    );
    let (scope, binding) = ([0x5cu8; 32], [0xb1u8; 32]);
    let mut input = Vec::new();
    for part in [&root, &scope, &binding] {
        input.extend_from_slice(part);
    }
    member.encode_to(&mut input);
    input.extend_from_slice(&secret);
    input.extend_from_slice(&salt);
    encoded.encode_to(&mut input);
    let expected = nullifier(&secret, &scope);
    std::fs::write(dir.join("auth.input"), &input).unwrap();
    std::fs::write(dir.join("auth.expected"), expected).unwrap();
    let run = Run::of(&std::fs::read(elf).unwrap(), &input, &expected);
    println!(
        "auth: input {} B, {} steps, nullifier {}",
        input.len(),
        run.steps(),
        hex(&expected)
    );
}

/// The auth kernel, derived, and its run.
struct Run {
    side_note: vos_pvm_proof::SideNote,
    chips: u32,
}

impl Run {
    fn of(elf: &[u8], input: &[u8], expected: &[u8]) -> Self {
        let derived = vos_pvm_compiler::derive(elf).expect("derive");
        let id = {
            let hash = vos_pvm_precompiles::blake2b_hash::<32>(b"vos/method/", &[b"auth"]);
            u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]])
        };
        let position = derived
            .kernels
            .iter()
            .position(|(method, _)| *method == id)
            .expect("the auth kernel");
        let trace =
            trace_kernel(&derived.kernels[position].1, input, GAS).expect("the kernel runs");
        assert!(
            trace
                .output
                .windows(expected.len())
                .any(|window| window == expected),
            "the kernel's output holds the nullifier"
        );
        Self {
            side_note: trace.side_note,
            chips: derived.shapes[position].chips,
        }
    }

    fn steps(&self) -> usize {
        self.side_note.steps.len()
    }

    fn whole(&self) -> vos_pvm_proof::SideNote {
        SegmentCursor::new(&self.side_note).side_note(0, self.steps())
    }
}

/// A cell: a shape, the PCS parameters, and the proxy's floor (none: plain).
#[derive(Clone)]
struct Cell {
    floor: bool,
    /// The floor without BLAKE2b and its AND table: lever 1's shape, the
    /// Poseidon2 chip that replaces them not counted.
    lean: bool,
    log_blowup: u32,
    queries: usize,
    pow: u32,
    masked: Option<u32>,
    /// Masked for real: the segment's chips proved by the masked prover
    /// (slice 7's 7.14), each padded to four times its `h`.
    real: bool,
}

impl Cell {
    fn parse(text: &str) -> Self {
        let parts: Vec<&str> = text.split('/').collect();
        assert_eq!(
            parts.len(),
            3,
            "a cell is shape/blowup:queries:pow/proxy: {text}"
        );
        let (floor, lean) = match parts[0] {
            "built" => (false, false),
            "floor" => (true, false),
            "lean" => (true, true),
            other => panic!("unknown shape {other}"),
        };
        let config: Vec<&str> = parts[1].split(':').collect();
        let real = parts[2] == "real";
        let masked = match parts[2] {
            "plain" | "real" => None,
            proxy => Some(
                proxy
                    .strip_prefix("masked")
                    .and_then(|log| log.parse().ok())
                    .unwrap_or_else(|| panic!("unknown proxy {proxy}")),
            ),
        };
        Self {
            floor,
            lean,
            log_blowup: config[0].parse().unwrap(),
            queries: config[1].parse().unwrap(),
            pow: config[2].parse().unwrap(),
            masked,
            real,
        }
    }

    fn name(&self) -> String {
        format!(
            "{}/{}:{}:{}/{}",
            match (self.floor, self.lean) {
                (_, true) => "lean",
                (true, false) => "floor",
                (false, false) => "built",
            },
            self.log_blowup,
            self.queries,
            self.pow,
            if self.real {
                "real".into()
            } else {
                self.masked
                    .map_or("plain".into(), |log| format!("masked{log}"))
            }
        )
    }

    /// The spike's format: the device number, on the Blake2s channel, at
    /// this cell's parameters, admitted for this process.
    fn install_format(&self) -> &'static Format {
        let format: &'static Format = Box::leak(Box::new(Format {
            kind: ProofKind::Segment,
            channel: ChannelKind::Blake2s,
            params: FormatParams {
                log_blowup: self.log_blowup,
                n_queries: self.queries,
                pow_bits: self.pow,
                ..DEVICE_PROOF.params
            },
            masked: false,
            masking: None,
            status: Status::Admitted,
            ..DEVICE_PROOF
        }));
        SPIKE_FORMAT.store(
            format as *const Format as *mut Format,
            std::sync::atomic::Ordering::Release,
        );
        format
    }
}

/// One cell, in this process: trace, prove `reps` times, verify, report.
fn cell(cell: &Cell, elf: &[u8], input: &[u8], expected: &[u8], reps: usize, out: Option<&Path>) {
    if cell.floor {
        // SAFETY: set before any proving thread starts; the memory chip
        // reads it.
        unsafe { std::env::set_var("S7_TOUCHED_BYTES", "1") };
    }
    let format = cell.install_format();
    let started = Instant::now();
    let run = Run::of(elf, input, expected);
    if cell.real {
        return real(cell, &run, started.elapsed().as_secs_f64(), reps);
    }
    let trace_seconds = started.elapsed().as_secs_f64();
    let steps = run.steps();
    let natural = canonical_profile_for_bounds(&run.side_note, &[(0, steps)]).expect("a profile");
    let mut mask = run.chips;
    if cell.floor {
        mask &= !BOUNDARY;
    }
    if cell.lean {
        mask &= !(1 << chip_idx::BLAKE2B | 1 << chip_idx::BITWISE_AND_BYTE);
    }
    let chips: Vec<usize> = (0..chip_idx::COUNT)
        .filter(|chip| mask & (1 << chip) != 0)
        .collect();
    let mut fixed: Vec<usize> = Vec::new();
    let sizes = |fixed: &[usize]| -> Vec<u32> {
        chips
            .iter()
            .map(|&chip| match cell.masked {
                Some(_) if fixed.contains(&chip) => natural[chip],
                Some(floor) => natural[chip].max(floor) + 1,
                None => natural[chip],
            })
            .collect()
    };
    // Under the proxy, find the chips whose size their content fixes: each
    // refuses a pinned size other than its own before any commitment.
    if cell.masked.is_some() {
        loop {
            let shape = SegmentShape {
                components: mask,
                log_sizes: sizes(&fixed),
            };
            match prove_shaped(&mut run.whole(), &shape, format) {
                Ok(_) => break,
                Err(ProvingError::Shape {
                    chip,
                    log_size,
                    pinned,
                }) if log_size < pinned => fixed.push(chip),
                Err(error) => panic!("the proxy's shape: {error:?}"),
            }
        }
    }
    let shape = SegmentShape {
        components: mask,
        log_sizes: sizes(&fixed),
    };
    let mut times = Vec::new();
    let mut cpu = Vec::new();
    let mut proof = None;
    let mut rss_reset = true;
    for rep in 0..reps {
        let mut segment = run.whole();
        rss_reset &= std::fs::write("/proc/self/clear_refs", "5").is_ok();
        let cpu_started = cpu_seconds();
        let started = Instant::now();
        let made = prove_shaped(&mut segment, &shape, format).expect("the segment proves");
        times.push(started.elapsed().as_secs_f64());
        cpu.push(cpu_seconds() - cpu_started);
        eprintln!(
            "  {} rep {}/{reps}: {:.3} s",
            cell.name(),
            rep + 1,
            times[rep]
        );
        proof = Some(made);
    }
    let rss = peak_rss_mib();
    let proof = proof.unwrap();
    let bytes = postcard::to_allocvec(&proof).unwrap();
    let digest = hex(&Sha256::digest(&bytes));
    if let Some(dir) = out {
        std::fs::create_dir_all(dir).unwrap();
        let file = cell.name().replace(['/', ':'], "-");
        std::fs::write(dir.join(format!("auth-{file}.postcard")), &bytes).unwrap();
    }
    let (verified, verify_ms) = if cell.floor {
        ("null".to_string(), 0.0)
    } else {
        let commitment = program_commitment_of_proof(&proof);
        let mut best = f64::INFINITY;
        let mut ok = true;
        for _ in 0..3 {
            let started = Instant::now();
            ok &= vos_pvm_proof_verifier::verify_standalone(proof.clone(), commitment).is_ok();
            best = best.min(started.elapsed().as_secs_f64());
        }
        (ok.to_string(), best * 1e3)
    };
    #[cfg(feature = "seeded-masks")]
    let matches = REFERENCES
        .split(',')
        .find_map(|entry| entry.strip_prefix(&format!("{}=", cell.name())))
        .map_or("null".to_string(), |expected| {
            (expected == digest).to_string()
        });
    #[cfg(not(feature = "seeded-masks"))]
    let matches = "null".to_string();
    // Every committed column (preprocessed, main, interaction) and its rows;
    // and what masking (c) at the proxy's floor would commit: every chip,
    // the fixed ones too, padded to the floor, its main and interaction
    // columns one log size up, its preprocessed ones at the padded size.
    let (mut columns, mut cells, mut model) = (0usize, 0u64, 0u64);
    for (&log, &chip) in shape.log_sizes.iter().zip(&chips) {
        let component = vos_pvm_proof::all_components()[chip];
        for tree in component.trace_sizes(log).iter() {
            columns += tree.len();
            cells += tree.iter().map(|&size| 1u64 << size).sum::<u64>();
        }
        let padded = natural[chip].max(cell.masked.unwrap_or(0));
        for (index, tree) in component.trace_sizes(padded).iter().enumerate() {
            let up = u32::from(cell.masked.is_some() && index > 0);
            model += tree.iter().map(|&size| 1u64 << (size + up)).sum::<u64>();
        }
    }
    let threads = std::env::var("RAYON_NUM_THREADS").unwrap_or_else(|_| "auto".into());
    let list = |values: &[f64], digits: usize| {
        values
            .iter()
            .map(|v| format!("{v:.digits$}"))
            .collect::<Vec<_>>()
            .join(",")
    };
    println!(
        "{{\"kind\":\"cell\",\"cell\":\"{}\",\"steps\":{steps},\"threads\":{},\"pool\":{},\"mask\":\"{mask:#010x}\",\
         \"chips\":{},\"log_sizes\":{:?},\"fixed\":{:?},\"columns\":{columns},\"cells\":{cells},\"model_cells\":{model},\"reps\":{reps},\
         \"prove_s_best\":{:.4},\"prove_s_median\":{:.4},\"prove_s_runs\":[{}],\"cpu_s_median\":{:.3},\
         \"peak_rss_mib\":{rss:.0},\"peak_rss_reset\":{rss_reset},\"trace_s\":{trace_seconds:.3},\
         \"proof_bytes\":{},\"proof_sha256\":\"{digest}\",\"verified\":{verified},\"verify_ms\":{verify_ms:.1},\
         \"matches_x86\":{matches}}}",
        cell.name(),
        json_str(&threads),
        rayon_threads(),
        chips.len(),
        shape.log_sizes,
        fixed,
        times.iter().copied().fold(f64::INFINITY, f64::min),
        median(&times),
        list(&times, 4),
        median(&cpu),
        bytes.len(),
    );
}

/// The masked format at `cell`'s parameters: the device number on the
/// Blake2s channel, 8 salts a tree, an `R` of 8, `h` twice the rows a
/// column reading two rows reveals (`4·2 + 3q`), rounded up.
fn masked_format(cell: &Cell) -> Format {
    let h = (2 * (8 + 3 * cell.queries)).next_power_of_two();
    Format {
        kind: ProofKind::Segment,
        channel: ChannelKind::Blake2s,
        params: FormatParams {
            log_blowup: cell.log_blowup,
            n_queries: cell.queries,
            pow_bits: cell.pow,
            ..DEVICE_PROOF.params
        },
        masked: true,
        masking: Some(Masking {
            salt_columns: 8,
            fri_mask_columns: 8,
            log_mask_rows: h.ilog2(),
        }),
        status: Status::Admitted,
        ..DEVICE_PROOF
    }
}

/// A cell masked for real: the shape's chips proved by the masked segment
/// prover from the OS's randomness `reps` times, verified when the shape
/// balances (not the floor's).
fn real(cell: &Cell, run: &Run, trace_seconds: f64, reps: usize) {
    use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleChannel;
    use vos_pvm_recair::masked::MaskRng;
    use vos_pvm_recair::masked::segment::{prove_segment, verify_segment};
    let format = masked_format(cell);
    let steps = run.steps();
    let mut mask = run.chips;
    if cell.floor {
        mask &= !BOUNDARY;
    }
    if cell.lean {
        mask &= !(1 << chip_idx::BLAKE2B | 1 << chip_idx::BITWISE_AND_BYTE);
    }
    let (mut times, mut cpu) = (Vec::new(), Vec::new());
    let mut made = None;
    let mut rss_reset = true;
    for rep in 0..reps {
        let mut segment = run.whole();
        rss_reset &= std::fs::write("/proc/self/clear_refs", "5").is_ok();
        let cpu_started = cpu_seconds();
        let started = Instant::now();
        let proof = prove_segment::<Blake2sMerkleChannel>(&format, &mut segment, mask, MaskRng::default())
            .expect("the masked segment proves");
        times.push(started.elapsed().as_secs_f64());
        cpu.push(cpu_seconds() - cpu_started);
        eprintln!("  {} rep {}/{reps}: {:.3} s", cell.name(), rep + 1, times[rep]);
        made = Some(proof);
    }
    let rss = peak_rss_mib();
    let (proof, stats) = made.unwrap();
    let bytes = postcard::to_allocvec(&(
        &proof.proof.stark_proof,
        &proof.proof.claimed_sums,
        proof.proof.interaction_pow,
    ))
    .unwrap();
    let (verified, verify_ms) = if cell.floor {
        ("null".to_string(), 0.0)
    } else {
        let mut best = f64::INFINITY;
        let mut ok = true;
        for _ in 0..3 {
            let started = Instant::now();
            ok &= verify_segment::<Blake2sMerkleChannel>(&format, &proof, None).is_ok();
            best = best.min(started.elapsed().as_secs_f64());
        }
        (ok.to_string(), best * 1e3)
    };
    let mut cells = 0u64;
    let mut columns = 0usize;
    let chips: Vec<usize> = (0..chip_idx::COUNT).filter(|chip| mask & (1 << chip) != 0).collect();
    for (&log, &chip) in proof.log_sizes.iter().zip(&chips) {
        let component = vos_pvm_proof::all_components()[chip];
        for (index, tree) in component.trace_sizes(log).iter().enumerate() {
            let blinding = if index == 1 { 4 } else { 0 };
            columns += tree.len() + blinding;
            cells += (tree.len() + blinding) as u64 * (2u64 << log);
        }
    }
    let threads = std::env::var("RAYON_NUM_THREADS").unwrap_or_else(|_| "auto".into());
    let list = |values: &[f64]| {
        values.iter().map(|v| format!("{v:.4}")).collect::<Vec<_>>().join(",")
    };
    println!(
        "{{\"kind\":\"cell\",\"cell\":\"{}\",\"steps\":{steps},\"threads\":{},\"pool\":{},\"mask\":\"{mask:#010x}\",\
         \"chips\":{},\"log_sizes\":{:?},\"log_mask_rows\":{},\"columns\":{columns},\"cells\":{cells},\"reps\":{reps},\
         \"prove_s_best\":{:.4},\"prove_s_median\":{:.4},\"prove_s_runs\":[{}],\"cpu_s_median\":{:.3},\
         \"peak_rss_mib\":{rss:.0},\"peak_rss_reset\":{rss_reset},\"trace_s\":{trace_seconds:.3},\
         \"proof_bytes\":{},\"verified\":{verified},\"verify_ms\":{verify_ms:.1},\
         \"r1_attempts\":{},\"r1_classes\":{},\"r1_rows\":{},\"r1_ms\":{:.1}}}",
        cell.name(),
        json_str(&threads),
        rayon_threads(),
        chips.len(),
        proof.log_sizes,
        format.masking.unwrap().log_mask_rows,
        times.iter().copied().fold(f64::INFINITY, f64::min),
        median(&times),
        list(&times),
        median(&cpu),
        bytes.len(),
        stats.attempts,
        stats.classes,
        stats.revealed_rows,
        stats.rank_check.as_secs_f64() * 1e3,
    );
}

fn rayon_threads() -> usize {
    vos_pvm_proof::install_thread_pool()
}

/// `n` grinds at `bits` on the Blake2s-M31 channel, each from a transcript
/// of its own.
fn grind(bits: u32, n: usize) {
    use stwo::core::channel::{Blake2sM31Channel, Channel};
    use stwo::core::proof_of_work::GrindOps;
    use stwo::prover::backend::simd::SimdBackend;
    let pool = rayon_threads();
    let mut times = Vec::with_capacity(n);
    for index in 0..n {
        let mut channel = Blake2sM31Channel::default();
        channel.mix_u64(0x5eed_0000 + index as u64);
        let started = Instant::now();
        let nonce = <SimdBackend as GrindOps<Blake2sM31Channel>>::grind(&channel, bits);
        times.push(started.elapsed().as_secs_f64() * 1e3);
        assert!(channel.verify_pow_nonce(bits, nonce));
    }
    let mean = times.iter().sum::<f64>() / n as f64;
    println!(
        "{{\"kind\":\"grind\",\"channel\":\"blake2s-m31\",\"bits\":{bits},\"n\":{n},\"pool\":{pool},\
         \"mean_ms\":{mean:.2},\"median_ms\":{:.2},\"p95_ms\":{:.2},\"max_ms\":{:.2}}}",
        median(&times),
        percentile(&times, 0.95),
        times.iter().copied().fold(0.0, f64::max),
    );
}

/// What the device is: CPU parts and maximum frequencies, memory, and the
/// battery where the kernel exposes it.
fn device() -> String {
    let cpuinfo = read("/proc/cpuinfo").unwrap_or_default();
    let parts: Vec<String> = cpuinfo
        .lines()
        .filter(|line| line.starts_with("CPU part"))
        .filter_map(|line| line.split(':').nth(1).map(|v| json_str(v.trim())))
        .collect();
    let freqs: Vec<String> = (0..64)
        .filter_map(|cpu| {
            read(&format!(
                "/sys/devices/system/cpu/cpu{cpu}/cpufreq/cpuinfo_max_freq"
            ))
        })
        .collect();
    let mem_total = read("/proc/meminfo")
        .and_then(|m| {
            m.lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1).map(str::to_string))
        })
        .unwrap_or_default();
    let battery =
        |name: &str| read(&format!("/sys/class/power_supply/battery/{name}")).unwrap_or_default();
    format!(
        "{{\"kind\":\"device\",\"arch\":{},\"cpus\":{},\"cpu_parts\":[{}],\"cpu_max_khz\":[{}],\
         \"mem_total_kib\":{},\"battery_temp_decic\":{},\"battery_capacity\":{},\"kernel\":{}}}",
        json_str(std::env::consts::ARCH),
        std::thread::available_parallelism().map_or(0, |n| n.get()),
        parts.join(","),
        freqs.join(","),
        json_str(&mem_total),
        json_str(&battery("temp")),
        json_str(&battery("capacity")),
        json_str(&read("/proc/sys/kernel/osrelease").unwrap_or_default()),
    )
}

fn usage() -> ! {
    eprintln!(
        "usage: s7-device gen <elf> <dir>\n\
         \x20      s7-device run [--elf PATH --input PATH] [--cells LIST] [--threads N|auto] [--reps N] \
         [--pause S] [--out DIR] [--inline] [--grind N]\n\
         \x20      s7-device grind [--bits B] [--n N]"
    );
    std::process::exit(2);
}

struct Options {
    elf: Option<String>,
    input: Option<String>,
    cells: String,
    threads: String,
    reps: usize,
    pause: u64,
    out: Option<String>,
    inline: bool,
    grinds: usize,
}

fn options(args: &[String]) -> Options {
    let mut options = Options {
        elf: None,
        input: None,
        cells: P1_CELLS.to_string(),
        threads: "auto".into(),
        reps: 5,
        pause: 5,
        out: None,
        inline: false,
        grinds: if cfg!(feature = "phone") { 64 } else { 0 },
    };
    let mut iter = args.iter();
    while let Some(flag) = iter.next() {
        let mut value = || iter.next().cloned().unwrap_or_else(|| usage());
        match flag.as_str() {
            "--elf" => options.elf = Some(value()),
            "--input" => options.input = Some(value()),
            "--cells" => options.cells = value(),
            "--threads" => options.threads = value(),
            "--reps" => options.reps = value().parse().unwrap_or_else(|_| usage()),
            "--pause" => options.pause = value().parse().unwrap_or_else(|_| usage()),
            "--out" => options.out = Some(value()),
            "--inline" => options.inline = true,
            "--grind" => options.grinds = value().parse().unwrap_or_else(|_| usage()),
            _ => usage(),
        }
    }
    options
}

/// The ELF, the input and the expected nullifier: the embedded ones on the
/// phone, else from the files named.
fn statement(options: &Options) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    #[cfg(feature = "phone")]
    if options.elf.is_none() {
        return (ELF.to_vec(), INPUT.to_vec(), EXPECTED.to_vec());
    }
    let elf = options.elf.as_ref().unwrap_or_else(|| usage());
    let input = options.input.as_ref().unwrap_or_else(|| usage());
    let expected = Path::new(input).with_extension("expected");
    (
        std::fs::read(elf).unwrap(),
        std::fs::read(input).unwrap(),
        std::fs::read(expected).unwrap(),
    )
}

fn run(args: &[String]) {
    let options = options(args);
    if options.threads != "auto" {
        // SAFETY: no thread exists yet.
        unsafe { std::env::set_var("RAYON_NUM_THREADS", &options.threads) };
    }
    println!("{}", device());
    println!(
        "{{\"kind\":\"build\",\"version\":\"s7-device/1\",\"channel\":\"blake2s\",\"format\":{},\
         \"seeded_masks\":{},\"cells\":{}}}",
        DEVICE_PROOF.number,
        cfg!(feature = "seeded-masks"),
        json_str(&options.cells),
    );
    let started = Instant::now();
    let exe = std::env::current_exe().expect("the binary's own path");
    // Under qemu-user without binfmt, a child starts through the emulator.
    let launcher = std::env::var("S7_LAUNCHER").ok().filter(|l| !l.is_empty());
    let mut failed = false;
    for (index, name) in options.cells.split(',').enumerate() {
        if index > 0 && options.pause > 0 {
            std::thread::sleep(std::time::Duration::from_secs(options.pause));
        }
        let parsed = Cell::parse(name);
        eprintln!(
            "cell {name}: threads {}, {} reps",
            options.threads, options.reps
        );
        if options.inline {
            let (elf, input, expected) = statement(&options);
            cell(
                &parsed,
                &elf,
                &input,
                &expected,
                options.reps,
                options.out.as_deref().map(Path::new),
            );
            continue;
        }
        let mut command = match &launcher {
            Some(launcher) => {
                let mut command = Command::new(launcher);
                command.arg(&exe);
                command
            }
            None => Command::new(&exe),
        };
        command.args(["--child", name, &options.reps.to_string()]);
        for (flag, value) in [
            ("--elf", &options.elf),
            ("--input", &options.input),
            ("--out", &options.out),
        ] {
            if let Some(value) = value {
                command.args([flag, value]);
            }
        }
        let status = command.status().expect("the child runs");
        if !status.success() {
            failed = true;
            println!(
                "{{\"kind\":\"error\",\"cell\":\"{name}\",\"status\":{}}}",
                json_str(&status.to_string())
            );
        }
    }
    if options.grinds > 0 {
        for bits in [20, 16] {
            grind(bits, options.grinds);
        }
    }
    println!(
        "{{\"kind\":\"done\",\"ok\":{},\"wall_s\":{:.1}}}",
        !failed,
        started.elapsed().as_secs_f64()
    );
    if failed {
        std::process::exit(1);
    }
}

fn child(args: &[String]) {
    let name = args.first().unwrap_or_else(|| usage());
    let reps = args
        .get(1)
        .and_then(|n| n.parse().ok())
        .unwrap_or_else(|| usage());
    let options = options(&args[2..]);
    let (elf, input, expected) = statement(&options);
    cell(
        &Cell::parse(name),
        &elf,
        &input,
        &expected,
        reps,
        options.out.as_deref().map(Path::new),
    );
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("gen") if args.len() == 4 => generate(Path::new(&args[2]), Path::new(&args[3])),
        Some("run") => run(&args[2..]),
        Some("--child") => child(&args[2..]),
        Some("grind") => {
            let options: Vec<&str> = args[2..].iter().map(String::as_str).collect();
            let value = |flag: &str, default: usize| {
                options
                    .iter()
                    .position(|arg| *arg == flag)
                    .and_then(|at| options.get(at + 1))
                    .map_or(default, |v| v.parse().unwrap_or_else(|_| usage()))
            };
            grind(value("--bits", 20) as u32, value("--n", 64));
        }
        _ if cfg!(feature = "phone") => run(&args[1..]),
        _ => usage(),
    }
}
