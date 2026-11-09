//! The device cells (`proving.md` §8): a device kernel
//! proved masked under the device profile at one candidate's parameters, on
//! one channel, timed, verified, its peak memory read and its bytes
//! counted.
//!
//! A cell is `statement/log_blowup:queries:pow[:log_h]/channel[/cpu]`, the
//! statement a kernel `<statement>.kernel` and its witness input
//! `<statement>.input` in the kernels' directory, or `auth` or `owner`, the
//! stock kernel from its embedded release artifact on its reference
//! program's arguments; the channel `b2sm31` (Blake2s-M31) or `b2b`
//! (Blake2b-256); the CPU `full` (the default) or `program`, the
//! per-program CPU ([`Cpu`]). Its format is [`DEVICE_PROOF`] at the cell's
//! parameters, `h` `2^log_h` where the cell names it, else twice the rows a
//! column reading two rows reveals, `4·2 + 3q`, rounded up to a power of
//! two. The program is installed once, its preprocessed tree committed
//! then: a stock kernel's at its release's chips and log sizes, any other's
//! from a reference run of the same witness (the shape its run needs, each
//! chip at least its floor); each rep traces the kernel and proves it
//! against the program.

use std::path::{Path, PathBuf};
use std::time::Instant;

use sha2::{Digest as _, Sha256};
use stwo::core::channel::MerkleChannel;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
use stwo::core::vcs_lifted::blake2b_merkle::Blake2bMerkleChannel;
use stwo::prover::backend::BackendForChannel;
use stwo::prover::backend::simd::SimdBackend;
use vos_pvm_proof::format::{ChannelKind, Cpu, DEVICE_PROOF, Format, FormatParams, Masking};
use vos_pvm_proof::masked::DeviceComponents;
use vos_pvm_recair::masked::device::{
    DeviceProof, DeviceProver, device_shape, install, verify_device,
};
use vos_pvm_recair::masked::{MaskRng, MaskedProof};
use vos_pvm_recair_air::masked::MaskedComponents;

use crate::{hex, ms, peak_rss_mib, quantile};

/// The gas a device kernel's run takes at most.
const GAS: u64 = 50_000_000;

/// The cells by default: the auth statement over the Poseidon2 tree (`p2`)
/// at every candidate on Blake2s-M31, then the statement over the vos-tree
/// (`b2`) beside it. Blake2b-256, about ten times slower on the prover's
/// trees, is asked for by name.
pub const CELLS: &str = "p2/1:86:20/b2sm31,p2/1:87:20/b2sm31,p2/2:43:20/b2sm31,\
p2/2:47:16/b2sm31,p2/3:29:20/b2sm31,\
b2/1:86:20/b2sm31,b2/2:43:20/b2sm31,b2/2:47:16/b2sm31,b2/3:29:20/b2sm31";

/// One device cell, parsed.
pub struct Cell {
    pub statement: String,
    pub log_blowup: u32,
    pub queries: usize,
    pub pow: u32,
    /// `log2 h`, when the cell names it (unchecked: an `h` below the
    /// rows its columns reveal fails R1 on every attempt, and the prover
    /// gives up); else the least power of two at
    /// least the rows a column reading two rows reveals, the device
    /// format's rule (`proving.md` §5).
    pub log_mask_rows: Option<u32>,
    pub channel: ChannelKind,
    pub cpu: Cpu,
}

impl Cell {
    pub fn parse(text: &str) -> Self {
        let parts: Vec<&str> = text.split('/').collect();
        assert!(
            matches!(parts.len(), 3 | 4),
            "a cell is statement/blowup:queries:pow/channel[/cpu]: {text}"
        );
        let config: Vec<u32> = parts[1]
            .split(':')
            .map(|part| part.parse().expect("a number"))
            .collect();
        assert!(
            matches!(config.len(), 3 | 4),
            "blowup:queries:pow[:log_h]: {text}"
        );
        let channel = match parts[2] {
            "b2sm31" => ChannelKind::Blake2sM31,
            "b2b" => ChannelKind::Blake2b256,
            other => panic!("unknown channel {other}"),
        };
        let cpu = match parts.get(3).copied() {
            None | Some("full") => Cpu::Full,
            Some("program") => Cpu::PerProgram,
            Some(other) => panic!("unknown CPU {other}"),
        };
        Self {
            statement: parts[0].to_string(),
            log_blowup: config[0],
            queries: config[1] as usize,
            pow: config[2],
            log_mask_rows: config.get(3).copied(),
            channel,
            cpu,
        }
    }

    /// The device format at this cell's parameters.
    pub fn format(&self) -> Format {
        let h = (4 * 2 + 3 * self.queries).next_power_of_two();
        Format {
            channel: self.channel,
            params: FormatParams {
                log_blowup: self.log_blowup,
                n_queries: self.queries,
                pow_bits: self.pow,
                ..DEVICE_PROOF.params
            },
            masking: Some(Masking {
                log_mask_rows: self.log_mask_rows.unwrap_or(h.ilog2()),
                ..DEVICE_PROOF.masking.expect("the device format's masking")
            }),
            cpu: self.cpu,
            ..DEVICE_PROOF
        }
    }
}

/// A proof's masks: the operating system's, or the seeded build's fixed
/// seed, so a proof's bytes are the same on any machine and in any pool.
fn masks() -> MaskRng {
    #[cfg(feature = "seeded")]
    return MaskRng::Seeded(crate::SEED);
    #[cfg(not(feature = "seeded"))]
    MaskRng::default()
}

/// The stock kernels' reference arguments, as the build computed them from
/// the credential actor's ELF; empty without it.
static AUTH_INPUT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/auth.input"));
static OWNER_INPUT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/owner.input"));

/// A cell's statement: its kernel, its witness input and, for a stock
/// kernel, its release's chips and log sizes.
struct Statement {
    kernel: Vec<u8>,
    input: Vec<u8>,
    released: Option<(u32, Vec<u32>)>,
}

/// The statement `statement`: a stock kernel's from its embedded release
/// artifact, any other's `<statement>.kernel` and `<statement>.input` in
/// `dir`.
fn statement(dir: &Path, statement: &str) -> Statement {
    let stock = match statement {
        "auth" => Some(AUTH_INPUT),
        "owner" => Some(OWNER_INPUT),
        _ => None,
    };
    if let Some(input) = stock {
        let device = crate::device_artifact(statement);
        return Statement {
            kernel: device.kernel,
            input: input.to_vec(),
            released: Some((device.chips, device.log_sizes)),
        };
    }
    let read = |extension: &str| {
        let path = dir.join(format!("{statement}.{extension}"));
        std::fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
    };
    Statement {
        kernel: read("kernel"),
        input: read("input"),
        released: None,
    }
}

/// The steps of the kernel's run `trace` gives, and the program's chips and
/// log sizes: the release's where it has one, else the shape that run needs.
fn shape(
    format: &Format,
    kernel: &[u8],
    released: Option<(u32, Vec<u32>)>,
    trace: impl Fn() -> vos_pvm_proof::SideNote,
) -> (usize, u32, Vec<u32>) {
    let mut reference = trace();
    let steps = reference.steps.len();
    let (active, log_sizes) = match released {
        Some(shape) => shape,
        None => device_shape(format, kernel, &mut reference).expect("a shape"),
    };
    (steps, active, log_sizes)
}

/// The file `device --out` writes cell `name`'s last proof to.
fn file_name(name: &str) -> String {
    name.replace('/', "~").replace(':', "-")
}

/// The cell whose proof [`file_name`] names `file`.
fn cell_name(file: &str) -> String {
    file.replace('-', ":").replace('~', "/")
}

/// Verifies the proofs `device --out DIR` wrote in `dir`, each against its
/// cell's program installed here: a phone's device proofs verified on
/// x86. One `device_verify` line a proof; exits 1 when one fails.
pub fn verify_dir(dir: &Path) {
    let mut files: Vec<String> = std::fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("{}: {error}", dir.display()))
        .map(|entry| {
            entry
                .expect("an entry")
                .file_name()
                .into_string()
                .expect("a name")
        })
        .collect();
    files.sort();
    let mut all = true;
    for file in files {
        let name = cell_name(&file);
        let cell = Cell::parse(&name);
        let bytes = std::fs::read(dir.join(&file)).expect("the proof's bytes");
        let verified = match cell.channel {
            ChannelKind::Blake2sM31 => verify_one::<Blake2sM31MerkleChannel>(&cell, dir, &bytes),
            ChannelKind::Blake2b256 => verify_one::<Blake2bMerkleChannel>(&cell, dir, &bytes),
            other => panic!("no device cell on {other:?}"),
        };
        all &= verified;
        println!(
            "{{\"kind\":\"device_verify\",\"cell\":\"{name}\",\"proof_bytes\":{},\"proof_sha256\":\"{}\",\"verified\":{verified}}}",
            bytes.len(),
            hex(&Sha256::digest(&bytes))
        );
    }
    if !all {
        std::process::exit(1);
    }
}

fn verify_one<MC: MerkleChannel>(cell: &Cell, dir: &Path, bytes: &[u8]) -> bool
where
    SimdBackend: BackendForChannel<MC>,
    MC::H: serde::de::DeserializeOwned,
{
    let format = cell.format();
    let Statement {
        kernel,
        input,
        released,
    } = statement(dir, &cell.statement);
    let trace = || {
        vos_pvm_proof::kernel::trace_kernel(&kernel, &input, GAS)
            .expect("the kernel runs to its halt")
            .side_note
    };
    let (_, active, log_sizes) = shape(&format, &kernel, released, trace);
    let program = install::<MC>(&format, &kernel, active, &log_sizes).expect("installed");
    let Ok((io, stark_proof, claimed_sums, interaction_pow)) = postcard::from_bytes(bytes) else {
        return false;
    };
    let proof = DeviceProof {
        io,
        proof: MaskedProof {
            interaction_pow,
            claimed_sums,
            stark_proof,
        },
    };
    verify_device::<MC>(&format, &program, &proof).is_ok()
}

/// Runs `name` in this process: install, `warmups` proofs, then `reps`
/// timed, each verified; prints its line.
pub fn cell(name: &str, dir: &Path, reps: usize, warmups: usize, out: Option<&PathBuf>) {
    let cell = Cell::parse(name);
    match cell.channel {
        ChannelKind::Blake2sM31 => {
            measure::<Blake2sM31MerkleChannel>(name, &cell, dir, reps, warmups, out)
        }
        ChannelKind::Blake2b256 => {
            measure::<Blake2bMerkleChannel>(name, &cell, dir, reps, warmups, out)
        }
        other => panic!("no device cell on {other:?}"),
    }
}

fn measure<MC: MerkleChannel>(
    name: &str,
    cell: &Cell,
    dir: &Path,
    reps: usize,
    warmups: usize,
    out: Option<&PathBuf>,
) where
    SimdBackend: BackendForChannel<MC>,
    MC::H: serde::Serialize,
{
    let format = cell.format();
    let Statement {
        kernel,
        input,
        released,
    } = statement(dir, &cell.statement);
    let trace = || {
        vos_pvm_proof::kernel::trace_kernel(&kernel, &input, GAS)
            .expect("the kernel runs to its halt")
            .side_note
    };
    let started = Instant::now();
    let (steps, active, log_sizes) = shape(&format, &kernel, released, trace);
    let prover = DeviceProver::<MC>::install(&format, &kernel, active, &log_sizes)
        .unwrap_or_else(|error| panic!("{name} at {log_sizes:?}: {error:?}"));
    let program = prover.program();
    let install_ms = ms(started.elapsed());
    let (mut traces, mut proves, mut verifies) = (Vec::new(), Vec::new(), Vec::new());
    let (mut hashes, mut bytes, mut stats) = (Vec::new(), Vec::new(), None);
    for rep in 0..warmups + reps {
        let started = Instant::now();
        let mut side_note = trace();
        let traced = started.elapsed();
        let started = Instant::now();
        let (proof, made) = prover
            .prove(&mut side_note, masks())
            .expect("the device kernel proves");
        let proved = started.elapsed();
        let started = Instant::now();
        assert!(
            verify_device::<MC>(&format, program, &proof).is_ok(),
            "{name} verifies"
        );
        let verified = started.elapsed();
        if rep < warmups {
            continue;
        }
        traces.push(ms(traced));
        proves.push(ms(proved));
        verifies.push(ms(verified));
        eprintln!(
            "  {name} rep {}/{reps}: {:.1} ms",
            rep + 1 - warmups,
            ms(proved)
        );
        bytes = postcard::to_allocvec(&(
            &proof.io,
            &proof.proof.stark_proof,
            &proof.proof.claimed_sums,
            proof.proof.interaction_pow,
        ))
        .expect("the proof's bytes");
        hashes.push(hex(&Sha256::digest(&bytes)));
        stats = Some(made);
    }
    let stats = stats.expect("a rep");
    if let Some(out) = out {
        std::fs::create_dir_all(out).expect("the output directory");
        std::fs::write(out.join(file_name(name)), &bytes).expect("written");
    }
    let layout = DeviceComponents::layout(program.shape(), &log_sizes).expect("laid out");
    let (mut columns, mut cells) = (0usize, 0u64);
    let mut by_chip = Vec::new();
    for component in layout.components() {
        let (mut chip_columns, mut chip_cells) = (0usize, 0u64);
        for tree in component.trace_log_degree_bounds().iter() {
            chip_columns += tree.len();
            chip_cells += tree.iter().map(|&log| 2u64 << log).sum::<u64>();
        }
        columns += chip_columns;
        cells += chip_cells;
        by_chip.push(format!("[{chip_columns},{chip_cells}]"));
    }
    let chips: Vec<usize> = vos_pvm_proof::device::device_chips_of_mask(active).collect();
    let sorted = |values: &[f64]| {
        let mut sorted = values.to_vec();
        sorted.sort_by(f64::total_cmp);
        sorted
    };
    let (proves_sorted, traces_sorted, verifies_sorted) =
        (sorted(&proves), sorted(&traces), sorted(&verifies));
    let distinct = {
        let mut unique = hashes.clone();
        unique.sort();
        unique.dedup();
        unique.len()
    };
    let list = |values: &[f64]| {
        values
            .iter()
            .map(|value| format!("{value:.1}"))
            .collect::<Vec<_>>()
            .join(",")
    };
    println!(
        "{{\"kind\":\"device_cell\",\"cell\":\"{name}\",\"format\":{},\"cpu\":\"{:?}\",\"cpu_columns\":{},\"threads\":{},\"steps\":{steps},\
         \"chips\":{chips:?},\"log_sizes\":{log_sizes:?},\"log_mask_rows\":{},\"columns\":{columns},\"cells\":{cells},\"by_chip\":[{}],\
         \"reps\":{reps},\"install_ms\":{install_ms:.1},\"trace_ms_p50\":{:.1},\
         \"prove_ms_p50\":{:.1},\"prove_ms_p95\":{:.1},\"prove_ms_min\":{:.1},\"prove_ms_max\":{:.1},\"prove_ms_runs\":[{}],\
         \"verify_ms_p50\":{:.2},\"r1_attempts\":{},\"r1_ms\":{:.1},\"proof_bytes\":{},\"distinct_proofs\":{distinct},\
         \"proof_sha256\":\"{}\",\"verified\":true,\"peak_rss_mib\":{:.1}}}",
        format.number,
        format.cpu,
        program.cpu.width(),
        rayon::current_num_threads(),
        format.masking.expect("masked").log_mask_rows,
        by_chip.join(","),
        quantile(&traces_sorted, 0.5),
        quantile(&proves_sorted, 0.5),
        quantile(&proves_sorted, 0.95),
        proves_sorted[0],
        proves_sorted[proves_sorted.len() - 1],
        list(&proves),
        quantile(&verifies_sorted, 0.5),
        stats.attempts,
        stats.rank_check.as_secs_f64() * 1e3,
        bytes.len(),
        hashes.last().expect("a rep"),
        peak_rss_mib().unwrap_or(-1.0),
    );
}
