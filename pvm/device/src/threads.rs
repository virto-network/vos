//! The prover's thread pool: a thread count, or the system's core classes
//! read and the fastest kept, each thread pinned to its core.

use crate::DeviceError;
use crate::prover::{STACK_BYTES, Threads};

/// Whether `core` is one a thread can be pinned to.
fn pinnable(core: usize) -> bool {
    core < libc::CPU_SETSIZE as usize
}

/// A pool as `threads` says, each thread's stack [`STACK_BYTES`]: what a
/// [`Prover`] proves in, and what a device kernel's proof runs in.
pub fn thread_pool(threads: &Threads) -> Result<rayon::ThreadPool, DeviceError> {
    let builder = rayon::ThreadPoolBuilder::new().stack_size(STACK_BYTES);
    let auto = match threads {
        Threads::Auto => classes::auto_cores(),
        _ => None,
    };
    let builder = match (threads, auto) {
        (Threads::Auto, Some(cores)) => builder
            .num_threads(cores.len())
            .start_handler(move |index| pin(cores[index])),
        (Threads::Auto, None) => builder.num_threads(
            std::thread::available_parallelism()
                .map(usize::from)
                .unwrap_or(1),
        ),
        (Threads::Count(0), _) => return Err(DeviceError::Config),
        (Threads::Count(count), _) => builder.num_threads(*count),
        (Threads::Cores(cores), _) => {
            if cores.is_empty() || !cores.iter().all(|&core| pinnable(core)) {
                return Err(DeviceError::Config);
            }
            let cores = cores.clone();
            builder
                .num_threads(cores.len())
                .start_handler(move |index| pin(cores[index]))
        }
    };
    builder.build().map_err(|_| DeviceError::Config)
}

/// Pins the calling thread to `core`, as far as the system allows.
fn pin(core: usize) {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    // SAFETY: `set` is a zeroed `cpu_set_t` the calls below only write
    // within, and `core` is below `CPU_SETSIZE` (`pinnable`).
    unsafe {
        let mut set: libc::cpu_set_t = core::mem::zeroed();
        libc::CPU_SET(core, &mut set);
        libc::sched_setaffinity(0, core::mem::size_of::<libc::cpu_set_t>(), &set);
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let _ = core;
}

/// `Threads::Auto`'s core classes and their measured rates.
pub(crate) mod classes {
    use super::pin;

    /// The cores `Auto` pins one thread to each of, or `None` for one
    /// unpinned thread a core: every class taking work, or no classes.
    pub(crate) fn auto_cores() -> Option<Vec<usize>> {
        let cores = allowed()?;
        let capacities: Option<Vec<u64>> = cores
            .iter()
            .map(|&core| read(core, "cpu_capacity"))
            .collect();
        let by_capacity =
            capacities.is_some_and(|all| all.windows(2).any(|pair| pair[0] != pair[1]));
        let stated = |core| {
            read(
                core,
                if by_capacity {
                    "cpu_capacity"
                } else {
                    "cpufreq/cpuinfo_max_freq"
                },
            )
        };
        let classes = classes(&cores, &stated)?;
        let rates: Vec<f64> = classes.iter().map(|class| rate(class[0])).collect();
        kept(&classes, &rates)
    }

    /// The cores of the fastest classes whose even split is quickest,
    /// their count times the slowest kept rate the greatest (`classes` the
    /// fastest first), in class order; `None` when that is every class, or
    /// no rate was measured.
    pub(crate) fn kept(classes: &[Vec<usize>], rates: &[f64]) -> Option<Vec<usize>> {
        let mut best = (0.0, 0);
        let (mut cores, mut slowest) = (0, f64::INFINITY);
        for (k, (class, &rate)) in classes.iter().zip(rates).enumerate() {
            cores += class.len();
            slowest = slowest.min(rate);
            let split = cores as f64 * slowest;
            if split > best.0 {
                best = (split, k + 1);
            }
        }
        (0 < best.1 && best.1 < classes.len()).then(|| classes[..best.1].concat())
    }

    /// `cores` grouped by `stated`'s rate (a core's capacity where the
    /// cores' capacities differ, else its highest clock), the highest
    /// first: a class is the cores within a sixth of its highest. `None`
    /// for one class, or a core with no stated rate.
    pub(crate) fn classes(
        cores: &[usize],
        stated: &dyn Fn(usize) -> Option<u64>,
    ) -> Option<Vec<Vec<usize>>> {
        let mut rated: Vec<(u64, usize)> = cores
            .iter()
            .map(|&core| Some((stated(core)?, core)))
            .collect::<Option<_>>()?;
        rated.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        let mut classes: Vec<(u64, Vec<usize>)> = Vec::new();
        for (rate, core) in rated {
            match classes.last_mut() {
                Some((top, class)) if rate * 6 >= *top * 5 => class.push(core),
                _ => classes.push((rate, vec![core])),
            }
        }
        (classes.len() > 1).then(|| classes.into_iter().map(|(_, class)| class).collect())
    }

    /// `core`'s `name` under the system's CPU directory, a number: its
    /// capacity, or its highest clock in kHz.
    fn read(core: usize, name: &str) -> Option<u64> {
        std::fs::read_to_string(format!("/sys/devices/system/cpu/cpu{core}/{name}"))
            .ok()?
            .trim()
            .parse()
            .ok()
    }

    /// The cores this process may run on, in order; `None` where the
    /// system does not say.
    fn allowed() -> Option<Vec<usize>> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        // SAFETY: `set` is a zeroed `cpu_set_t` the call fills, and every
        // core tested is below `CPU_SETSIZE`.
        unsafe {
            let mut set: libc::cpu_set_t = core::mem::zeroed();
            if libc::sched_getaffinity(0, core::mem::size_of::<libc::cpu_set_t>(), &mut set) != 0 {
                return None;
            }
            Some(
                (0..libc::CPU_SETSIZE as usize)
                    .filter(|&core| libc::CPU_ISSET(core, &set))
                    .collect(),
            )
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        None
    }

    /// The bytes a rate's run hashes: about 2 ms on an x86 performance
    /// core.
    const WORK: usize = 1 << 20;

    /// How long a core is kept busy before its rate is measured, so its
    /// clock has risen.
    const WARM_UP: std::time::Duration = std::time::Duration::from_millis(40);

    /// `core`'s rate, in hashed bytes a second: BLAKE2s over [`WORK`]
    /// bytes on a thread pinned to it, the best of three after [`WARM_UP`]
    /// of the same work; 0 when no thread can be made.
    fn rate(core: usize) -> f64 {
        use blake2::Digest;
        std::thread::Builder::new()
            .spawn(move || {
                pin(core);
                let block = [0x5au8; 4096];
                let run = || {
                    let started = std::time::Instant::now();
                    let mut hasher = blake2::Blake2s256::new();
                    for _ in 0..WORK / block.len() {
                        hasher.update(block);
                    }
                    std::hint::black_box(hasher.finalize());
                    started.elapsed().as_secs_f64()
                };
                let warming = std::time::Instant::now();
                while warming.elapsed() < WARM_UP {
                    run();
                }
                let best = (0..3).map(|_| run()).fold(f64::INFINITY, f64::min);
                WORK as f64 / best.max(f64::MIN_POSITIVE)
            })
            .map_or(0.0, |thread| thread.join().unwrap_or(0.0))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// The Fairphone 6's clocks: the A520s at 1.8 GHz a class, the
        /// A720s at 2.4 and 2.5 GHz another; x86's performance, efficient
        /// and low-power cores three. One class, or a core with no stated
        /// rate, is none.
        #[test]
        fn cores_are_grouped_by_their_stated_rate() {
            let phone = [
                1_804_800, 1_804_800, 1_804_800, 1_804_800, 2_400_000, 2_400_000, 2_400_000,
                2_496_000,
            ];
            let stated = |core: usize| phone.get(core).copied();
            assert_eq!(
                classes(&(0..8).collect::<Vec<_>>(), &stated),
                Some(vec![vec![7, 4, 5, 6], vec![0, 1, 2, 3]])
            );
            let x86 = |core: usize| {
                Some(match core {
                    0..=11 => 4_800_000,
                    12..=19 => 3_800_000,
                    _ => 2_500_000,
                })
            };
            assert_eq!(
                classes(&[1, 3, 12, 13, 20], &x86),
                Some(vec![vec![1, 3], vec![12, 13], vec![20]])
            );
            assert_eq!(classes(&[4, 5, 6], &stated), None);
            assert_eq!(classes(&[4, 9], &stated), None);
        }

        /// The fastest classes whose even split is quickest take the
        /// work: a slow class takes none, and every class kept is the even
        /// split.
        #[test]
        fn a_slow_class_takes_no_work() {
            let classes = vec![vec![4, 5], vec![0, 1], vec![9]];
            assert_eq!(kept(&classes, &[1.0, 0.7, 0.6]), None);
            assert_eq!(kept(&classes, &[1.0, 0.4, 0.3]), Some(vec![4, 5]));
            assert_eq!(kept(&classes, &[1.0, 0.6, 0.3]), Some(vec![4, 5, 0, 1]));
            let phone = vec![vec![7, 4, 5, 6], vec![0, 1, 2, 3]];
            assert_eq!(kept(&phone, &[1.0, 0.4]), Some(vec![7, 4, 5, 6]));
            assert_eq!(kept(&phone, &[1.0, 0.6]), None);
            assert_eq!(kept(&phone, &[0.0, 0.0]), None);
        }
    }
}
