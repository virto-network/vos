#![cfg(feature = "prover")]

//! The prover's pool when another user built rayon's global pool first, at
//! rayon's default 2 MiB stacks, where a release prover's worker overflows:
//! the prover proves on a pool of its own, of 16 MiB stacks. Its own test
//! binary, as the global pool is the process's.

use rayon::prelude::*;

fn names() -> Vec<String> {
    (0..64)
        .into_par_iter()
        .map(|_| std::thread::current().name().unwrap_or("").to_owned())
        .collect()
}

#[test]
fn the_prover_proves_on_its_own_pool_beside_another_global_pool() {
    rayon::ThreadPoolBuilder::new()
        .num_threads(2)
        .thread_name(|index| format!("other-{index}"))
        .build_global()
        .expect("the first global pool");
    assert!(vos_pvm_proof::install_thread_pool() >= 1);
    assert!(names().iter().all(|name| name.starts_with("other-")));
    let proving = vos_pvm_proof::on_prover_pool(names);
    assert!(
        proving.iter().all(|name| name.starts_with("vos-prover-")),
        "{proving:?}"
    );

    // A caller on a pool of its own sizes its threads' stacks: its work
    // stays there.
    let own = rayon::ThreadPoolBuilder::new()
        .num_threads(2)
        .stack_size(16 << 20)
        .thread_name(|index| format!("caller-{index}"))
        .build()
        .expect("a pool");
    let staying = own.install(|| vos_pvm_proof::on_prover_pool(names));
    assert!(staying.iter().all(|name| name.starts_with("caller-")));
}
