//! Poseidon2-M31 hashing throughput: the scalar permutation, sixteen packed
//! permutations at once, and a commitment of about 25M permutations on
//! `SimdBackend` against the same commitment under Blake2s.
//!
//!     cargo bench --bench poseidon2             # on 8 threads
//!     THREADS=4 cargo bench --bench poseidon2
//!
//! Requires the `prover` feature (on by default).

fn main() {
    #[cfg(feature = "prover")]
    imp::run();
    #[cfg(not(feature = "prover"))]
    eprintln!("the Poseidon2 benchmark requires the `prover` feature (default-on)");
}

#[cfg(feature = "prover")]
mod imp {
    use std::hint::black_box;
    use std::time::Instant;

    use rayon::prelude::*;
    use stwo::core::fields::m31::BaseField;
    use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleHasher;
    use stwo::prover::backend::simd::SimdBackend;
    use stwo::prover::backend::simd::column::BaseColumn;
    use stwo::prover::vcs_lifted::prover::MerkleProverLifted;
    use vos_pvm_proof::poseidon2::packed::{self, LANES, States, permute_x16};
    use vos_pvm_proof::poseidon2::{N_STATE, P2MerkleHasher, RATE, permute};

    /// The commitment's shape: 176 columns of 2^20 rows hash 23 blocks a
    /// leaf, plus the nodes, about 25.2M permutations.
    const LOG_ROWS: u32 = 20;
    const COLUMNS: usize = 176;

    pub fn run() {
        let threads: usize = std::env::var("THREADS")
            .ok()
            .and_then(|threads| threads.parse().ok())
            .unwrap_or(8);
        let load = std::fs::read_to_string("/proc/loadavg").unwrap_or_default();
        println!(
            "poseidon2: {} lanes, vectorized {}, {threads} threads, load average {}",
            LANES,
            packed::VECTORIZED,
            load.split_whitespace()
                .take(3)
                .collect::<Vec<_>>()
                .join(" ")
        );
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .expect("a thread pool");

        let scalar_one = rate(SCALAR_RUN, || scalar_run(SCALAR_RUN));
        let packed_one = rate(PACKED_RUN * LANES, || packed_run(PACKED_RUN));
        println!(
            "1 thread: scalar {:.2} M/s, packed {:.2} M/s",
            scalar_one / 1e6,
            packed_one / 1e6
        );
        let (scalar_many, packed_many) = pool.install(|| {
            let scalar = rate(threads * SCALAR_RUN, || {
                (0..threads)
                    .into_par_iter()
                    .for_each(|_| scalar_run(SCALAR_RUN))
            });
            let packed = rate(threads * PACKED_RUN * LANES, || {
                (0..threads)
                    .into_par_iter()
                    .for_each(|_| packed_run(PACKED_RUN))
            });
            (scalar, packed)
        });
        println!(
            "{threads} threads: scalar {:.2} M/s, packed {:.2} M/s",
            scalar_many / 1e6,
            packed_many / 1e6
        );
        println!(
            "projected leaf commitment (25M permutations) on {threads} threads: \
             {:.3} s packed, {:.3} s scalar",
            25e6 / packed_many,
            25e6 / scalar_many
        );

        let columns: Vec<BaseColumn> = (0..COLUMNS)
            .into_par_iter()
            .map(|c| {
                (0..1u32 << LOG_ROWS)
                    .map(|row| {
                        let x =
                            row.wrapping_mul(0x9e37_79b9) ^ (c as u32).wrapping_mul(0x85eb_ca6b);
                        BaseField::from_u32_unchecked(x & 0x7fff_fffe)
                    })
                    .collect()
            })
            .collect();
        let refs: Vec<&BaseColumn> = columns.iter().collect();
        let permutations =
            (1u64 << LOG_ROWS) * (COLUMNS + 1).div_ceil(RATE) as u64 + (1u64 << LOG_ROWS) - 1;
        pool.install(|| {
            let started = Instant::now();
            let tree = MerkleProverLifted::<SimdBackend, P2MerkleHasher>::commit(
                refs.clone(),
                LOG_ROWS,
                0,
            );
            let seconds = started.elapsed().as_secs_f64();
            black_box(tree.root());
            println!(
                "commit {COLUMNS} columns of 2^{LOG_ROWS} rows on {threads} threads: \
                 Poseidon2 {seconds:.3} s ({:.1} M permutations, {:.2} M/s)",
                permutations as f64 / 1e6,
                permutations as f64 / seconds / 1e6
            );
            let started = Instant::now();
            let tree =
                MerkleProverLifted::<SimdBackend, Blake2sMerkleHasher>::commit(refs, LOG_ROWS, 0);
            let seconds = started.elapsed().as_secs_f64();
            black_box(tree.root());
            println!("commit the same columns under Blake2s: {seconds:.3} s");
        });
    }

    /// Permutations a run of each kind does on one thread.
    const SCALAR_RUN: usize = 1 << 17;
    const PACKED_RUN: usize = 1 << 15;

    /// `permutations` over the wall-clock time of `run`.
    fn rate(permutations: usize, run: impl FnOnce()) -> f64 {
        let started = Instant::now();
        run();
        permutations as f64 / started.elapsed().as_secs_f64()
    }

    /// `count` permutations, one at a time.
    fn scalar_run(count: usize) {
        let mut state: [BaseField; N_STATE] =
            core::array::from_fn(|i| BaseField::from_u32_unchecked(i as u32));
        for _ in 0..count {
            permute(&mut state);
        }
        black_box(state);
    }

    /// `calls` times sixteen permutations at once.
    fn packed_run(calls: usize) {
        let mut state: States =
            core::array::from_fn(|i| core::array::from_fn(|l| (i * LANES + l) as u32));
        for _ in 0..calls {
            permute_x16(&mut state);
        }
        black_box(state);
    }
}
