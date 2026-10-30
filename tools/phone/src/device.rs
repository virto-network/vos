//! The device cells (`slice-7-mobile.md` 7.16, pin J): a device kernel
//! proved masked under the device profile at one candidate's parameters, on
//! one channel, timed, verified, its peak memory read and its bytes
//! counted.
//!
//! A cell is `statement/log_blowup:queries:pow/channel`, the statement a
//! kernel `<statement>.kernel` and its witness input `<statement>.input` in
//! the kernels' directory, the channel `b2sm31` (Blake2s-M31) or `b2b`
//! (Blake2b-256). Its format is [`DEVICE_PROOF`] at the cell's parameters,
//! `h` twice the rows a column reading two rows reveals, `4·2 + 3q`,
//! rounded up to a power of two. The program is installed once from a
//! reference run of the same witness (the shape its run needs, each chip at
//! least its floor); each rep traces the kernel and proves it against the
//! program.

use std::path::{Path, PathBuf};
use std::time::Instant;

use sha2::{Digest as _, Sha256};
use stwo::core::channel::MerkleChannel;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
use stwo::core::vcs_lifted::blake2b_merkle::Blake2bMerkleChannel;
use stwo::prover::backend::BackendForChannel;
use stwo::prover::backend::simd::SimdBackend;
use vos_pvm_proof::format::{ChannelKind, DEVICE_PROOF, Format, FormatParams, Masking};
use vos_pvm_proof::masked::DeviceComponents;
use vos_pvm_recair::masked::MaskRng;
use vos_pvm_recair::masked::device::{device_shape, install, prove_device, verify_device};
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
    pub channel: ChannelKind,
}

impl Cell {
    pub fn parse(text: &str) -> Self {
        let parts: Vec<&str> = text.split('/').collect();
        assert_eq!(
            parts.len(),
            3,
            "a cell is statement/blowup:queries:pow/channel: {text}"
        );
        let config: Vec<u32> = parts[1]
            .split(':')
            .map(|part| part.parse().expect("a number"))
            .collect();
        assert_eq!(config.len(), 3, "blowup:queries:pow: {text}");
        let channel = match parts[2] {
            "b2sm31" => ChannelKind::Blake2sM31,
            "b2b" => ChannelKind::Blake2b256,
            other => panic!("unknown channel {other}"),
        };
        Self {
            statement: parts[0].to_string(),
            log_blowup: config[0],
            queries: config[1] as usize,
            pow: config[2],
            channel,
        }
    }

    /// The device format at this cell's parameters.
    pub fn format(&self) -> Format {
        let h = (2 * (4 * 2 + 3 * self.queries)).next_power_of_two();
        Format {
            channel: self.channel,
            params: FormatParams {
                log_blowup: self.log_blowup,
                n_queries: self.queries,
                pow_bits: self.pow,
                ..DEVICE_PROOF.params
            },
            masking: Some(Masking {
                log_mask_rows: h.ilog2(),
                ..DEVICE_PROOF.masking.expect("the device format's masking")
            }),
            ..DEVICE_PROOF
        }
    }
}

/// The kernel and the witness input of `statement` in `dir`.
fn statement(dir: &Path, statement: &str) -> (Vec<u8>, Vec<u8>) {
    let read = |extension: &str| {
        let path = dir.join(format!("{statement}.{extension}"));
        std::fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
    };
    (read("kernel"), read("input"))
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
    let (kernel, input) = statement(dir, &cell.statement);
    let trace = || {
        vos_pvm_proof::kernel::trace_device_kernel(&kernel, &input, GAS)
            .expect("the kernel runs to its halt")
            .side_note
    };
    let started = Instant::now();
    let mut reference = trace();
    let steps = reference.steps.len();
    let (active, log_sizes) = device_shape(&format, &kernel, &mut reference).expect("a shape");
    let program = install::<MC>(&format, &kernel, active, &log_sizes)
        .unwrap_or_else(|error| panic!("{name} at {log_sizes:?}: {error:?}"));
    let install_ms = ms(started.elapsed());
    let (mut traces, mut proves, mut verifies) = (Vec::new(), Vec::new(), Vec::new());
    let (mut hashes, mut bytes, mut stats) = (Vec::new(), Vec::new(), None);
    for rep in 0..warmups + reps {
        let started = Instant::now();
        let mut side_note = trace();
        let traced = started.elapsed();
        let started = Instant::now();
        let (proof, made) =
            prove_device::<MC>(&format, &program, &mut side_note, MaskRng::default())
                .expect("the device kernel proves");
        let proved = started.elapsed();
        let started = Instant::now();
        assert!(
            verify_device::<MC>(&format, &program, &proof).is_ok(),
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
        std::fs::write(out.join(name.replace(['/', ':'], "-")), &bytes).expect("written");
    }
    let layout = DeviceComponents::layout(active, &log_sizes).expect("laid out");
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
        "{{\"kind\":\"device_cell\",\"cell\":\"{name}\",\"format\":{},\"threads\":{},\"steps\":{steps},\
         \"chips\":{chips:?},\"log_sizes\":{log_sizes:?},\"log_mask_rows\":{},\"columns\":{columns},\"cells\":{cells},\"by_chip\":[{}],\
         \"reps\":{reps},\"install_ms\":{install_ms:.1},\"trace_ms_p50\":{:.1},\
         \"prove_ms_p50\":{:.1},\"prove_ms_p95\":{:.1},\"prove_ms_min\":{:.1},\"prove_ms_max\":{:.1},\"prove_ms_runs\":[{}],\
         \"verify_ms_p50\":{:.2},\"r1_attempts\":{},\"r1_ms\":{:.1},\"proof_bytes\":{},\"distinct_proofs\":{distinct},\
         \"verified\":true,\"peak_rss_mib\":{:.1}}}",
        format.number,
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
        peak_rss_mib().unwrap_or(-1.0),
    );
}
