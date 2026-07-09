//! `vosx zk pin` — measure and emit a provable-program **catalog** artifact.
//!
//! A `#[provable]` program's verifiers need a trusted program-identity anchor:
//! the canonical-shape commitment allowlist (`{C_0, C_1, …}`), the forcing
//! profile + segment-step bound the chain was proved under, and the
//! `__VOS_WITNESS` address. Historically these lived as constants scattered
//! through test files that drift silently. `vosx zk pin` derives them from the
//! actual program build and writes them into a checked-in
//! [`vos::zk::ProvableCatalog`] TOML that verifiers load as the allowlist source.
//! It also records the UNPATCHED image root as a DIAGNOSTIC — not a verifier pin
//! (a witness-injecting program's live entering root is the patched root; the
//! pinnable masked root is pending `docs/design/masked-image-root.md`).
//!
//! Pipeline: read the ELF → transpile to a PVM blob (`grey_transpiler`) → locate
//! `__VOS_WITNESS` → trace the UNPATCHED image for its page-Merkle root → measure
//! the commitment allowlist by proving one representative canonical segment per
//! distinct shape (or record a `--allowlist` supplied out-of-band) → upsert the
//! pin into the catalog.
//!
//! The proving step is heavy (canonical prove of a handful of segments, minutes,
//! tens of GB) — a publish-time tool, not a hot path. Pass `--allowlist` to skip
//! proving and re-pin only the cheap fields (witness address + entering root)
//! against an already-established allowlist.

use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail};

use vos::zk::{ProgramPin, ProvableCatalog, bytes_to_hex, witness_addr};

/// Generous trace-gas ceiling — matches the prover extension's budget so a
/// program that traces there traces here.
const TRACE_GAS: u64 = 100_000_000;

/// Stack for the canonical-prove measurement thread. A canonical proof's
/// prove/verify overflows the default ~2 MiB (the elf_integration federation
/// path documents `RUST_MIN_STACK=268435456`); give the measurement its own
/// large stack so the tool works without an env var.
const PROVE_STACK: usize = 512 * 1024 * 1024;

#[derive(clap::Subcommand)]
pub enum ZkCommand {
    /// Pin a provable actor into a catalog: measure its canonical commitment
    /// allowlist, entering-image root, and witness address, then write them to
    /// a catalog TOML verifiers consume as the trusted allowlist source.
    Pin(PinArgs),
}

#[derive(clap::Args)]
pub struct PinArgs {
    /// Provable actor ELF (built for the PVM target, exporting `__VOS_WITNESS`).
    #[arg(long, value_name = "FILE")]
    elf: PathBuf,
    /// Catalog identity for this program (e.g. `voucher-check`).
    #[arg(long)]
    name: String,
    /// Per-segment step bound the canonical profile was tuned against.
    #[arg(long, value_name = "N")]
    seg_steps: u64,
    /// File holding the canonical forcing profile: `zkpvm::chip_idx::COUNT`
    /// unsigned integers, whitespace/comma/newline separated (`0` = not forced).
    #[arg(long, value_name = "FILE")]
    profile: PathBuf,
    /// Catalog TOML to write (upserts this program; created if absent).
    #[arg(long, value_name = "FILE")]
    out: PathBuf,
    /// Representative witness payload to inject at `__VOS_WITNESS` before
    /// tracing (the `[u32 pub_len][pub][u32 sec_len][sec]` bytes). Required to
    /// MEASURE the commitment allowlist; unused with `--allowlist`.
    #[arg(long, value_name = "FILE")]
    witness: Option<PathBuf>,
    /// Comma-separated hex commitments to RECORD as the allowlist instead of
    /// proving for them — re-pins only the cheap fields (witness address +
    /// entering root) against an already-trusted allowlist.
    #[arg(long, value_name = "HEX,HEX")]
    allowlist: Option<String>,
    /// Trace-gas ceiling.
    #[arg(long, default_value_t = TRACE_GAS)]
    gas: u64,
}

pub fn run(cmd: ZkCommand) -> Result<()> {
    match cmd {
        ZkCommand::Pin(args) => pin(args),
    }
}

fn pin(args: PinArgs) -> Result<()> {
    let elf = std::fs::read(&args.elf)
        .with_context(|| format!("read provable ELF {}", args.elf.display()))?;
    let blob = grey_transpiler::link_elf(&elf)
        .map_err(|e| anyhow!("transpile {}: {e:?}", args.elf.display()))?;
    let waddr = witness_addr(&elf)
        .with_context(|| format!("{} must export a resolved __VOS_WITNESS", args.elf.display()))?;
    let profile = read_profile(&args.profile)?;

    // Entering-image root over the UNPATCHED image (witness buffer all-zero):
    // trace with no patches and page-Merkle its initial memory. DIAGNOSTIC —
    // this is NOT the verifier's entering-image pin: a witness-injecting
    // program's live segment-0 root is the PATCHED root, which differs here in
    // the witness region. The pinnable value is the MASKED root (witness region
    // excluded), pending docs/design/masked-image-root.md.
    let unpatched = zkpvm::actor::trace_blob(&blob, args.gas)
        .context("trace unpatched blob for the entering-image root")?;
    let image_root = zkpvm::page_merkle::image_root(&unpatched.initial_memory);

    let commitments: Vec<[u8; 32]> = match &args.allowlist {
        Some(list) => {
            let cs = parse_allowlist(list)?;
            eprintln!("recorded {} supplied commitment(s) (proving skipped)", cs.len());
            cs
        }
        None => {
            let witness_path = args.witness.as_ref().context(
                "--witness <FILE> is required to measure the commitment allowlist \
                 (or pass --allowlist to record a known one)",
            )?;
            let witness = std::fs::read(witness_path)
                .with_context(|| format!("read witness {}", witness_path.display()))?;
            measure_commitments(&blob, waddr as usize, &witness, args.seg_steps, &profile, args.gas)?
        }
    };
    if commitments.is_empty() {
        bail!("no commitments measured/supplied — nothing to pin");
    }

    let pin = ProgramPin {
        name: args.name.clone(),
        commitments: commitments.iter().map(|c| bytes_to_hex(c)).collect(),
        canonical_profile: profile,
        seg_steps: args.seg_steps,
        witness_addr: waddr,
        unpatched_image_root: bytes_to_hex(&image_root),
    };

    let mut catalog = if args.out.exists() {
        ProvableCatalog::load(&args.out).map_err(|e| anyhow!("load existing catalog: {e}"))?
    } else {
        ProvableCatalog::new()
    };
    catalog.upsert(pin);
    catalog
        .save(&args.out)
        .map_err(|e| anyhow!("write catalog {}: {e}", args.out.display()))?;

    eprintln!("pinned '{}' into {}", args.name, args.out.display());
    eprintln!("  witness_addr         = {waddr:#x}");
    eprintln!("  unpatched_image_root = {}", bytes_to_hex(&image_root));
    eprintln!("  seg_steps            = {}", args.seg_steps);
    eprintln!("  commitments          = {}", commitments.len());
    for c in &commitments {
        eprintln!("    {}", bytes_to_hex(c));
    }
    Ok(())
}

/// Trace the witness-injected run, segment it, and prove one representative
/// canonical segment per distinct shape (seg 0, the last/short segment, and the
/// first segment of each distinct fixed-base-scalar-mult "comb" count), yielding
/// the distinct program commitments — the canonical allowlist. Mirrors the
/// federation e2e's `voucher_check_allowlist_coverage` probe so the pinned
/// allowlist is complete without proving all ~N segments.
fn measure_commitments(
    blob: &[u8],
    witness_addr: usize,
    witness: &[u8],
    seg_steps: u64,
    profile: &[u32],
    gas: u64,
) -> Result<Vec<[u8; 32]>> {
    // Own everything on the heap so the large-stack measurement thread is 'static.
    let blob = blob.to_vec();
    let witness = witness.to_vec();
    let profile = profile.to_vec();
    let seg_steps = seg_steps as usize;
    std::thread::Builder::new()
        .stack_size(PROVE_STACK)
        .spawn(move || measure_commitments_inner(&blob, witness_addr, &witness, seg_steps, &profile, gas))
        .context("spawn prove thread")?
        .join()
        .map_err(|_| anyhow!("prove thread panicked"))?
}

fn measure_commitments_inner(
    blob: &[u8],
    witness_addr: usize,
    witness: &[u8],
    seg_steps: usize,
    profile: &[u32],
    gas: u64,
) -> Result<Vec<[u8; 32]>> {
    let full = zkpvm::actor::trace_blob_with_patches(blob, gas, &[(witness_addr, witness)])
        .context("trace the witness-injected run")?;
    let total = full.steps.len();
    let bounds = zkpvm::segment::segment_bounds(total, seg_steps);
    let n = bounds.len();
    if n == 0 {
        bail!("empty trace — stale ELF or witness that early-exits?");
    }
    let comb_counts: Vec<usize> = bounds
        .iter()
        .map(|&(a, b)| zkpvm::segment::segment_side_note(&full, a, b).ristretto_comb_calls.len())
        .collect();

    // Probe seg 0, the last (possibly short) segment, and the first segment of
    // each distinct comb count — one representative per distinct canonical shape.
    let mut probe = std::collections::BTreeSet::new();
    probe.insert(0);
    probe.insert(n - 1);
    for i in 0..n {
        if comb_counts[..i].iter().all(|&x| x != comb_counts[i]) {
            probe.insert(i);
        }
    }
    eprintln!(
        "trace = {total} steps, {n} segments @ {seg_steps}; proving {} representative segment(s)",
        probe.len()
    );

    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for i in probe {
        let (a, b) = bounds[i];
        let mut sn = zkpvm::segment::segment_side_note(&full, a, b);
        let proof = zkpvm::prove_canonical(&mut sn, profile)
            .map_err(|e| anyhow!("prove_canonical seg {i} [{a},{b}): {e:?}"))?;
        let c = zkpvm::recursion_pcs::commitment_bytes(&zkpvm::program_commitment_of_proof(&proof));
        eprintln!("  seg {i:3} combs={} commitment={}", comb_counts[i], bytes_to_hex(&c));
        if seen.insert(c) {
            out.push(c);
        }
    }
    Ok(out)
}

/// Parse a canonical profile file: unsigned integers separated by any of
/// whitespace, commas, or newlines. Comments (`#` to end of line) are ignored.
fn read_profile(path: &PathBuf) -> Result<Vec<u32>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read profile {}", path.display()))?;
    let mut out = Vec::new();
    for (lineno, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("");
        for tok in line.split(|c: char| c.is_whitespace() || c == ',') {
            let tok = tok.trim();
            if tok.is_empty() {
                continue;
            }
            let v: u32 = tok
                .parse()
                .with_context(|| format!("{}:{}: not a u32: {tok:?}", path.display(), lineno + 1))?;
            out.push(v);
        }
    }
    if out.is_empty() {
        bail!("profile {} is empty", path.display());
    }
    Ok(out)
}

/// Parse a comma-separated list of 64-char hex commitments into 32-byte values.
fn parse_allowlist(list: &str) -> Result<Vec<[u8; 32]>> {
    let mut out = Vec::new();
    for tok in list.split(',') {
        let tok = tok.trim();
        if tok.is_empty() {
            continue;
        }
        let bytes = hex::decode(tok).with_context(|| format!("invalid hex commitment {tok:?}"))?;
        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("commitment {tok:?} is {} bytes, expected 32", bytes.len()))?;
        out.push(arr);
    }
    if out.is_empty() {
        bail!("--allowlist had no commitments");
    }
    Ok(out)
}
