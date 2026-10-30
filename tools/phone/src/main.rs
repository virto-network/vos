//! The phone bench (`slice-7-mobile.md` 7.12, phone gate PG1): the device
//! library's three credential proofs, auth, owner and membership and
//! payment, proved through `vos-device` on fixed statements, timed,
//! verified, their peak memory read, and the PoW grinds timed alone.
//!
//! - `vos-phone run [--reps N] [--threads auto|N] [--cells auth,owner,joint] [--grind N] [--out DIR]`:
//!   a `device` line, one `cell` line a statement (each statement in a
//!   child process of its own, so its peak resident size is its own), and
//!   a `grind` line a PoW (20, the retired format 42's, and 16, 44's);
//!   every line JSON.
//! - `vos-phone verify DIR`: verifies the proofs `run --out DIR` wrote,
//!   against the same calls: a phone's proofs verified on x86.
//! - `vos-phone device [--kernels DIR] [--cells LIST] [--reps N] [--warmups N] [--threads auto|N] [--out DIR]`:
//!   device kernels proved masked under the device profile at candidate
//!   parameters (`device.rs`, 7.16), one `device_cell` line a cell, each in
//!   a child process of its own; the kernels and their witness inputs read
//!   from DIR (default `kernels` beside the binary).
//!
//! **Two builds:** the timing build (masks from the operating system, as
//! the library's every build) and the seeded build (`--features seeded`:
//! each proof's masks from a fixed seed, so its bytes are any machine's;
//! its cells say `matches_x86` against the SHA-256 compiled in from
//! `VOS_PHONE_REFERENCES`, `cell=hex` pairs). `tools/phone/build.sh`
//! builds both for `aarch64-linux-android` with the references of an x86
//! seeded run.

#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use sha2::{Digest as _, Sha256};
use stwo::core::channel::{Blake2sM31Channel, Channel};
use stwo::core::proof_of_work::GrindOps;
use stwo::prover::backend::simd::SimdBackend;
use vos_device::{
    AuthWitness, Call, Digest, Prover, ProverConfig, Threads, derive_secret, member, verify,
    verify_joint,
};
use vos_wire::credentials::{DEPTH, EMPTY, leaf, root_of};

mod device;

/// The cells, in order.
const CELLS: [&str; 3] = ["auth", "owner", "joint"];
/// The fixed handle, source output, slot and guard name of every cell.
const HANDLE: [u8; 32] = [0x48; 32];
const SOURCE_OUTPUT: [u8; 32] = [0x6f; 32];
const SLOT: u32 = 0x1234_5678;
const NAME: &[u8] = b"login";
/// The seeded build's masks.
#[cfg(feature = "seeded")]
const SEED: u64 = 0x7612;

/// The cell's call: one space, agent, instance and method, fixed
/// arguments, nonce and expiry.
fn call() -> Call {
    Call {
        space: [0x53; 32],
        agent: 7,
        instance: 3,
        method: 0x5ca1_ab1e,
        arguments: b"phone gate".to_vec(),
        nonce: [0x4e; 16],
        expires_ms: 1_800_000_000_000,
    }
}

/// The member's path in a tree whose other leaves are a few fixed
/// digests: the siblings at levels 0, 5 and 17 occupied.
fn witness(member: &Digest) -> AuthWitness {
    let mut siblings: [[u32; 8]; DEPTH] = core::array::from_fn(|level| EMPTY[level]);
    for (n, level) in [0, 5, 17].into_iter().enumerate() {
        siblings[level] = core::array::from_fn(|i| (n as u32 + 1) * 1_000_003 + i as u32);
    }
    let root = root_of(&leaf(&member.0), SLOT, &siblings);
    AuthWitness {
        root: Digest(root),
        slot: SLOT,
        siblings: siblings.map(Digest),
    }
}

struct Options {
    reps: usize,
    threads: Option<usize>,
    cells: Vec<String>,
    grind: u64,
    out: Option<PathBuf>,
    kernels: Option<PathBuf>,
    warmups: usize,
}

fn options(args: &[String]) -> Options {
    let mut options = Options {
        reps: 20,
        threads: None,
        cells: CELLS.iter().map(|cell| cell.to_string()).collect(),
        grind: 300,
        out: None,
        kernels: None,
        warmups: 1,
    };
    let mut args = args.iter();
    while let Some(flag) = args.next() {
        let mut value = || args.next().expect("a flag's value").clone();
        match flag.as_str() {
            "--reps" => options.reps = value().parse().expect("a count"),
            "--threads" => {
                options.threads = match value().as_str() {
                    "auto" => None,
                    count => Some(count.parse().expect("a thread count")),
                }
            }
            "--cells" => options.cells = value().split(',').map(str::to_string).collect(),
            "--grind" => options.grind = value().parse().expect("a count"),
            "--out" => options.out = Some(PathBuf::from(value())),
            "--kernels" => options.kernels = Some(PathBuf::from(value())),
            "--warmups" => options.warmups = value().parse().expect("a count"),
            other => panic!("unknown flag {other}"),
        }
    }
    options
}

fn threads(options: &Options) -> Threads {
    options.threads.map_or(Threads::Auto, Threads::Count)
}

fn ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1e3
}

/// The value at quantile `q` of `sorted`.
fn quantile(sorted: &[f64], q: f64) -> f64 {
    sorted[((sorted.len() as f64 * q) as usize).min(sorted.len() - 1)]
}

/// This process's peak resident size, in MiB, from `/proc/self/status`.
fn peak_rss_mib() -> Option<f64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|line| line.starts_with("VmHWM:"))?;
    let kib: f64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kib / 1024.0)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The x86 reference of `cell`, compiled in.
fn reference(cell: &str) -> Option<&'static str> {
    option_env!("VOS_PHONE_REFERENCES")?
        .split(',')
        .find_map(|pair| pair.strip_prefix(cell)?.strip_prefix('='))
}

/// One proof of `cell`'s statement, verified against its call: its bytes
/// and the verification's time.
fn prove(prover: &Prover, cell: &str) -> (Vec<u8>, Duration) {
    let secret = derive_secret(&SOURCE_OUTPUT, &HANDLE);
    let call = call();
    let timed = |check: &dyn Fn() -> bool| {
        let started = Instant::now();
        assert!(check(), "{cell} verifies");
        started.elapsed()
    };
    match cell {
        "auth" => {
            let proof = prover
                .prove_auth(&secret, &witness(&member(&secret)), NAME, &call)
                .expect("auth proves");
            let took = timed(&|| verify(&proof, &call, Some(NAME)).is_ok());
            (proof.proof, took)
        }
        "owner" => {
            let proof = prover.prove_owner(&secret, &call).expect("owner proves");
            let took = timed(&|| verify(&proof, &call, None).is_ok());
            (proof.proof, took)
        }
        "joint" => {
            let proof = prover
                .prove_membership_and_payment(&secret, &witness(&member(&secret)), NAME, &call)
                .expect("membership and payment proves");
            let took = timed(&|| verify_joint(&proof, &call, NAME).is_ok());
            (proof.proof, took)
        }
        other => panic!("unknown cell {other}"),
    }
}

/// Times `cell`'s proofs, `options.reps` after two warm-ups, and prints its
/// line: run in a child process, so its peak is its own.
fn cell(cell: &str, options: &Options) {
    let prover = Prover::new(ProverConfig {
        threads: threads(options),
        ..ProverConfig::default()
    })
    .expect("a prover");
    #[cfg(feature = "seeded")]
    let prover = prover.seeded(SEED);
    for _ in 0..2 {
        prove(&prover, cell);
    }
    let mut times = Vec::new();
    let mut verifies = Vec::new();
    let mut hashes = Vec::new();
    let mut bytes = Vec::new();
    for rep in 0..options.reps {
        let started = Instant::now();
        let (proof, verified) = prove(&prover, cell);
        times.push(ms(started.elapsed() - verified));
        verifies.push(ms(verified));
        eprintln!(
            "  {cell} rep {}/{}: {:.1} ms",
            rep + 1,
            options.reps,
            times[rep]
        );
        hashes.push(hex(&Sha256::digest(&proof)));
        bytes = proof;
    }
    verifies.sort_by(f64::total_cmp);
    let verify_ms = quantile(&verifies, 0.5);
    if let Some(out) = &options.out {
        std::fs::create_dir_all(out).expect("the output directory");
        std::fs::write(out.join(cell), &bytes).expect("the proof written");
    }
    let mut sorted = times.clone();
    sorted.sort_by(f64::total_cmp);
    let distinct = {
        let mut unique = hashes.clone();
        unique.sort();
        unique.dedup();
        unique.len()
    };
    let last = hashes.last().cloned().unwrap_or_default();
    let matches_x86 = if cfg!(feature = "seeded") {
        reference(cell).map_or("null".into(), |reference| (reference == last).to_string())
    } else {
        "null".into()
    };
    println!(
        "{{\"kind\":\"cell\",\"cell\":\"{cell}\",\"format\":{},\"threads\":{},\"reps\":{},\"prove_ms_p50\":{:.1},\"prove_ms_p95\":{:.1},\"prove_ms_min\":{:.1},\"prove_ms_max\":{:.1},\"prove_ms_runs\":[{}],\"verify_ms\":{verify_ms:.2},\"proof_bytes\":{},\"distinct_proofs\":{distinct},\"proof_sha256\":\"{last}\",\"matches_x86\":{matches_x86},\"verified\":true,\"peak_rss_mib\":{:.1}}}",
        vos_device::FORMAT,
        prover.threads(),
        options.reps,
        quantile(&sorted, 0.5),
        quantile(&sorted, 0.95),
        sorted[0],
        sorted[sorted.len() - 1],
        times
            .iter()
            .map(|time| format!("{time:.1}"))
            .collect::<Vec<_>>()
            .join(","),
        bytes.len(),
        peak_rss_mib().unwrap_or(-1.0),
    );
}

/// Times `count` grinds at `bits` on the Blake2s-M31 channel, in a pool of
/// `threads`.
fn grind(bits: u32, count: u64, options: &Options) {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(options.threads.unwrap_or(0))
        .build()
        .expect("a pool");
    let mut times: Vec<f64> = pool.install(|| {
        (0..count)
            .map(|round| {
                let mut channel = Blake2sM31Channel::default();
                channel.mix_u64(round);
                let started = Instant::now();
                let nonce = <SimdBackend as GrindOps<Blake2sM31Channel>>::grind(&channel, bits);
                let took = ms(started.elapsed());
                assert!(channel.verify_pow_nonce(bits, nonce));
                took
            })
            .collect()
    });
    let mean = times.iter().sum::<f64>() / times.len() as f64;
    times.sort_by(f64::total_cmp);
    println!(
        "{{\"kind\":\"grind\",\"channel\":\"blake2s-m31\",\"bits\":{bits},\"n\":{count},\"threads\":{},\"mean_ms\":{mean:.2},\"p50_ms\":{:.2},\"p95_ms\":{:.2},\"max_ms\":{:.2}}}",
        pool.current_num_threads(),
        quantile(&times, 0.5),
        quantile(&times, 0.95),
        times[times.len() - 1],
    );
}

fn device() {
    let read = |path: &str| std::fs::read_to_string(path).ok();
    let threads = std::thread::available_parallelism().map_or(0, usize::from);
    let max_khz: Vec<String> = (0..)
        .map_while(|cpu| {
            read(&format!(
                "/sys/devices/system/cpu/cpu{cpu}/cpufreq/cpuinfo_max_freq"
            ))
        })
        .map(|khz| khz.trim().to_string())
        .collect();
    let allowed = read("/proc/self/status")
        .and_then(|status| {
            let line = status
                .lines()
                .find(|line| line.starts_with("Cpus_allowed_list:"))?;
            Some(line.split_whitespace().nth(1)?.to_string())
        })
        .unwrap_or_default();
    println!(
        "{{\"kind\":\"device\",\"arch\":\"{}\",\"os\":\"{}\",\"threads\":{threads},\"cpus_allowed\":\"{allowed}\",\"cpu_max_khz\":[{}],\"build\":\"{}\",\"format\":{}}}",
        std::env::consts::ARCH,
        std::env::consts::OS,
        max_khz.join(","),
        if cfg!(feature = "seeded") {
            "seeded"
        } else {
            "timing"
        },
        vos_device::FORMAT,
    );
}

fn run(args: &[String]) {
    let options = options(args);
    device();
    let exe = std::env::current_exe().expect("this binary's path");
    for name in &options.cells {
        let status = Command::new(&exe)
            .arg("cell")
            .arg(name)
            .args(args)
            .status()
            .expect("the cell's process");
        if !status.success() {
            println!("{{\"kind\":\"error\",\"cell\":\"{name}\",\"status\":\"{status}\"}}");
        }
    }
    if options.grind > 0 {
        grind(20, options.grind, &options);
        grind(16, options.grind, &options);
    }
    println!("{{\"kind\":\"done\"}}");
}

/// The device cells, each in a child process of its own.
fn device_run(args: &[String]) {
    device();
    let mut options = options(args);
    if !args.iter().any(|arg| arg == "--cells") {
        options.cells = device::CELLS.split(',').map(str::to_string).collect();
    }
    let exe = std::env::current_exe().expect("this binary's path");
    for name in &options.cells {
        let status = Command::new(&exe)
            .arg("device-cell")
            .arg(name)
            .args(args)
            .status()
            .expect("the cell's process");
        if !status.success() {
            println!("{{\"kind\":\"error\",\"cell\":\"{name}\",\"status\":\"{status}\"}}");
        }
    }
    println!("{{\"kind\":\"done\"}}");
}

/// A device cell's worker threads' stacks: the prover's nested joins at
/// blowup 8 overflowed the default 2 MiB about once in 18 proves on 8
/// threads, and never in 24 at this size.
const DEVICE_STACK: usize = 16 << 20;

/// One device cell, in a pool of the threads asked for.
fn device_cell(name: &str, args: &[String]) {
    let options = options(args);
    rayon::ThreadPoolBuilder::new()
        .num_threads(options.threads.unwrap_or(0))
        .stack_size(DEVICE_STACK)
        .build_global()
        .expect("the pool");
    let kernels = options.kernels.clone().unwrap_or_else(|| {
        let exe = std::env::current_exe().expect("this binary's path");
        exe.with_file_name("kernels")
    });
    device::cell(
        name,
        &kernels,
        options.reps,
        options.warmups,
        options.out.as_ref(),
    );
}

/// Verifies the proofs `run --out` wrote in `dir` against their calls.
fn verify_dir(dir: &str) {
    let secret = derive_secret(&SOURCE_OUTPUT, &HANDLE);
    let call = call();
    let probe = Prover::new(ProverConfig {
        threads: Threads::Count(1),
        ..ProverConfig::default()
    })
    .expect("a prover");
    for cell in CELLS {
        let Ok(bytes) = std::fs::read(PathBuf::from(dir).join(cell)) else {
            continue;
        };
        // The public words are the statement's: a fresh proof's, the same
        // whatever its masks.
        let verified = match cell {
            "joint" => {
                let mut proof = probe
                    .prove_membership_and_payment(&secret, &witness(&member(&secret)), NAME, &call)
                    .expect("proves");
                proof.proof = bytes.clone();
                verify_joint(&proof, &call, NAME).is_ok()
            }
            _ => {
                let mut proof = match cell {
                    "auth" => probe.prove_auth(&secret, &witness(&member(&secret)), NAME, &call),
                    _ => probe.prove_owner(&secret, &call),
                }
                .expect("proves");
                proof.proof = bytes.clone();
                verify(&proof, &call, (cell == "auth").then_some(NAME)).is_ok()
            }
        };
        println!(
            "{{\"kind\":\"verify\",\"cell\":\"{cell}\",\"proof_sha256\":\"{}\",\"verified\":{verified}}}",
            hex(&Sha256::digest(&bytes))
        );
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("run") => run(&args[1..]),
        Some("cell") => cell(&args[1], &options(&args[2..])),
        Some("verify") => verify_dir(&args[1]),
        Some("device") => device_run(&args[1..]),
        Some("device-cell") => device_cell(&args[1], &args[2..]),
        _ => {
            eprintln!(
                "vos-phone run [--reps N] [--threads auto|N] [--cells LIST] [--grind N] [--out DIR] | verify DIR \
                 | device [--kernels DIR] [--cells LIST] [--reps N] [--warmups N] [--threads auto|N] [--out DIR]"
            );
            std::process::exit(2);
        }
    }
}
