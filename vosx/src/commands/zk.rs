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
//! The CLI owns the ELF/transpile half (which `vosx` already does everywhere):
//! read the ELF → transpile to a PVM blob (`grey_transpiler`) → locate
//! `__VOS_WITNESS` → write the catalog TOML. The heavy zkpvm half — trace the
//! unpatched image for its page-Merkle root, and prove one representative
//! canonical segment per distinct shape to measure the commitment allowlist —
//! lives in the **prover extension**'s `measure_catalog` handler, so `vosx`
//! carries no zkpvm dependency. `pin` therefore needs a space whose daemon has
//! the prover extension loaded (`vosx space up`).
//!
//! The proving step is heavy (canonical prove of a handful of segments, minutes,
//! tens of GB) — a publish-time tool, not a hot path. The measure invoke uses an
//! extended timeout ([`MEASURE_TIMEOUT`]); the extension runs on its own thread,
//! so a busy pin doesn't stall the node. Pass `--allowlist` to skip proving and
//! re-pin only the cheap fields (witness address + entering root) against an
//! already-established allowlist. Omit `--profile` to DERIVE the canonical
//! forcing profile (per-chip max natural log_size over every `--seg-steps`
//! window): the measure path derives it extension-side from the same trace
//! the allowlist probe uses (empty profile = derive, echoed in the reply),
//! and the `--allowlist` path uses the trace-only `measure_floors` — either
//! way, retuning a deployment's `seg_steps` is a single `pin` invocation
//! with no hand-authored profile.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};

use vos::value::{Msg, Value};
use vos::zk::{ProgramPin, ProvableCatalog, bytes_to_hex, witness_addr};

use crate::commands::dynamic::resolve_space;
use crate::commands::space::client::DaemonClient;

/// Generous trace-gas ceiling — matches the prover extension's budget so a
/// program that traces there traces here.
const TRACE_GAS: u64 = 100_000_000;

/// Timeout for the `measure_catalog` invoke. The prover traces + proves a
/// handful of canonical segments (minutes, tens of GB), far past the 10s
/// dispatch default. One hour covers a debug-build measure with headroom; the
/// prover runs on its own thread, so the wait doesn't stall the node.
const MEASURE_TIMEOUT: Duration = Duration::from_secs(60 * 60);

#[derive(clap::Subcommand)]
pub enum ZkCommand {
    /// Pin a provable actor into a catalog: measure its canonical commitment
    /// allowlist, entering-image root, and witness address, then write them to
    /// a catalog TOML verifiers consume as the trusted allowlist source. Drives
    /// the prover extension's `measure_catalog` handler, so the space must be
    /// `up` with the prover extension loaded.
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
    #[arg(long, value_name = "N", value_parser = clap::value_parser!(u64).range(1..))]
    seg_steps: u64,
    /// File holding the canonical forcing profile: `zkpvm::chip_idx::COUNT`
    /// unsigned integers, whitespace/comma/newline separated (`0` = not
    /// forced). Omit to DERIVE the profile from the `--witness` run
    /// (per-chip max natural log_size over every `--seg-steps` window) —
    /// the whole re-pin in one command.
    #[arg(long, value_name = "FILE")]
    profile: Option<PathBuf>,
    /// Write the profile that was pinned (derived or read) to this file, in
    /// the same format `--profile` reads.
    #[arg(long, value_name = "FILE")]
    profile_out: Option<PathBuf>,
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
    /// Space whose daemon hosts the prover extension. Defaults to the current
    /// space (`VOSX_SPACE` or the sole registered space).
    #[arg(long)]
    space: Option<String>,
    /// Registry name of the prover extension instance to drive.
    #[arg(long, default_value = "prover")]
    extension: String,
}

pub fn run(cmd: ZkCommand) -> Result<()> {
    match cmd {
        ZkCommand::Pin(args) => pin(args),
    }
}

fn pin(args: PinArgs) -> Result<()> {
    // ── ELF/transpile half (host-owned; no zkpvm) ────────────────────
    let elf = std::fs::read(&args.elf)
        .with_context(|| format!("read provable ELF {}", args.elf.display()))?;
    let blob = grey_transpiler::link_elf(&elf)
        .map_err(|e| anyhow!("transpile {}: {e:?}", args.elf.display()))?;
    let waddr = witness_addr(&elf)
        .with_context(|| format!("{} must export a resolved __VOS_WITNESS", args.elf.display()))?;
    let profile_arg = args.profile.as_ref().map(read_profile).transpose()?;

    // The witness drives the MEASURE path; the `--allowlist` re-pin path passes
    // an empty witness (the extension then returns only the entering root) and
    // records the supplied allowlist instead.
    let witness = match (&args.witness, &args.allowlist) {
        (Some(path), _) => std::fs::read(path)
            .with_context(|| format!("read witness {}", path.display()))?,
        (None, Some(_)) => Vec::new(),
        (None, None) => bail!(
            "--witness <FILE> is required to measure the commitment allowlist \
             (or pass --allowlist to record a known one)"
        ),
    };
    // Deriving floors measures the REAL (witness-injected) run — an empty
    // witness would profile the fallback path's shape instead.
    if profile_arg.is_none() && witness.is_empty() {
        bail!("--witness <FILE> is required to derive the profile (or pass --profile)");
    }

    // ── zkpvm half (prover extension over the daemon) ────────────────
    let space = resolve_space(args.space.as_deref())?;
    let reply = DaemonClient::with_connect(&space, |client| {
        let ext = client.resolve_target(&args.extension).map_err(|_| {
            anyhow!(
                "no '{}' extension loaded in space '{space}' — add \
                 `[[extension]] name = \"{}\"` to the manifest and restart `vosx space up`",
                args.extension,
                args.extension,
            )
        })?;
        // The `--allowlist` re-pin never proves: floors come from the
        // trace-only `measure_floors` when they must be derived, and the
        // catalog invoke goes out with an empty witness (root-only). The
        // full measure is ONE invoke — an empty profile tells the extension
        // to derive the floors from the same trace the allowlist probe uses.
        let (witness_to_send, profile_to_send) = if args.allowlist.is_some() {
            let profile = match profile_arg.clone() {
                Some(p) => p,
                None => {
                    eprintln!(
                        "deriving canonical profile for '{}' at seg_steps={} (trace-only — minutes)…",
                        args.name, args.seg_steps
                    );
                    let reply = client.invoke_dyn_with_timeout(
                        ext,
                        &Msg::new("measure_floors")
                            .with("pvm_blob", blob.clone())
                            .with("witness_bytes", witness.clone())
                            .with("witness_addr", waddr)
                            .with("seg_steps", args.seg_steps)
                            .with("gas", args.gas),
                        MEASURE_TIMEOUT,
                    )?;
                    parse_floors_reply(reply)?
                }
            };
            eprintln!("measuring '{}' entering root (trace-only)…", args.name);
            (Vec::new(), profile)
        } else {
            eprintln!(
                "measuring '{}' via the '{}' extension (this is heavy — minutes)…",
                args.name, args.extension
            );
            (witness.clone(), profile_arg.clone().unwrap_or_default())
        };
        client.invoke_dyn_with_timeout(
            ext,
            &Msg::new("measure_catalog")
                .with("pvm_blob", blob.clone())
                .with("witness_bytes", witness_to_send)
                .with("witness_addr", waddr)
                .with("seg_steps", args.seg_steps)
                .with("profile", profile_to_send)
                .with("gas", args.gas),
            MEASURE_TIMEOUT,
        )
    })?;

    let (image_root, profile, measured) = parse_measure_reply(reply)?;
    if profile.is_empty() {
        bail!("prover measure_catalog echoed no profile — measurement failed. Check the daemon log.");
    }

    // With `--allowlist`, record the supplied commitments; otherwise use the
    // ones the extension measured.
    let commitments: Vec<[u8; 32]> = match &args.allowlist {
        Some(list) => {
            let cs = parse_allowlist(list)?;
            eprintln!("recorded {} supplied commitment(s) (proving skipped)", cs.len());
            cs
        }
        None => measured,
    };
    if commitments.is_empty() {
        bail!("no commitments measured/supplied — nothing to pin");
    }

    let pin = ProgramPin {
        name: args.name.clone(),
        commitments: commitments.iter().map(|c| bytes_to_hex(c)).collect(),
        canonical_profile: profile.clone(),
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

    if let Some(path) = &args.profile_out {
        std::fs::write(path, format!("{}\n", format_profile(&profile)))
            .with_context(|| format!("write profile {}", path.display()))?;
    }

    eprintln!("pinned '{}' into {}", args.name, args.out.display());
    eprintln!("  witness_addr         = {waddr:#x}");
    eprintln!("  unpatched_image_root = {}", bytes_to_hex(&image_root));
    eprintln!("  seg_steps            = {}", args.seg_steps);
    if args.profile.is_none() {
        eprintln!("  profile (derived)    = {}", format_profile(&profile));
    }
    eprintln!("  commitments          = {}", commitments.len());
    for c in &commitments {
        eprintln!("    {}", bytes_to_hex(c));
    }
    Ok(())
}

/// Decode a `measure_floors` reply — the derived canonical profile as a u32
/// list. An empty list means the extension failed the measurement.
fn parse_floors_reply(reply: Value) -> Result<Vec<u32>> {
    match reply {
        Value::ListU32(floors) if !floors.is_empty() => Ok(floors),
        Value::ListU32(_) | Value::Unit => bail!(
            "prover measure_floors returned nothing — the measurement failed \
             (unparseable blob or trace out of gas). Check the daemon log."
        ),
        other => bail!("prover measure_floors returned {other:?}, expected a u32 list"),
    }
}

/// Decode a `measure_catalog` reply — `image_root(32) ++ n(u32 LE) ++
/// profile(u32 LE × n) ++ commitment(32)…` — into the entering-image root,
/// the profile the measurement ran under (supplied or derived), and the
/// measured commitments. An empty reply means the extension failed the
/// measurement (bad blob / trace / prove error).
fn parse_measure_reply(reply: Value) -> Result<([u8; 32], Vec<u32>, Vec<[u8; 32]>)> {
    let bytes = match reply {
        Value::Bytes(b) => b,
        Value::Unit => bail!(
            "prover measure_catalog returned nothing — the measurement failed \
             (unparseable blob, trace out of gas, or prove error). Check the daemon log."
        ),
        other => bail!("prover measure_catalog returned {other:?}, expected Bytes"),
    };
    if bytes.is_empty() {
        bail!(
            "prover measure_catalog failed (empty reply) — unparseable blob, trace out of gas, \
             or prove error. Check the daemon log."
        );
    }
    if bytes.len() < 36 {
        bail!("measure_catalog reply is {} bytes, shorter than root + profile length", bytes.len());
    }
    let mut image_root = [0u8; 32];
    image_root.copy_from_slice(&bytes[..32]);
    let n = u32::from_le_bytes(bytes[32..36].try_into().expect("4 bytes")) as usize;
    let floors_end = 36 + n * 4;
    if bytes.len() < floors_end {
        bail!("measure_catalog reply truncates its {n}-entry profile");
    }
    let profile = bytes[36..floors_end]
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes(c.try_into().expect("4-byte chunks")))
        .collect();
    let rest = &bytes[floors_end..];
    if rest.len() % 32 != 0 {
        bail!("measure_catalog commitments are {} bytes, not a multiple of 32", rest.len());
    }
    let commitments = rest
        .chunks_exact(32)
        .map(|c| {
            let mut a = [0u8; 32];
            a.copy_from_slice(c);
            a
        })
        .collect();
    Ok((image_root, profile, commitments))
}

/// Serialize a profile in the format [`read_profile`] reads back.
fn format_profile(profile: &[u32]) -> String {
    profile.iter().map(u32::to_string).collect::<Vec<_>>().join(" ")
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
