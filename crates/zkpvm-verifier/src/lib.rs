// zkpvm-verifier: standalone verification crate for PVM zkVM proofs.
//
// Currently re-exports from zkpvm-machine. The plan is to make this
// #![no_std] + alloc by:
// 1. Pre-computing the preprocessed trace commitment per-program
// 2. Including it in the Proof struct
// 3. Using CpuBackend instead of SimdBackend
// 4. Depending on stwo without prover/parallel/std features

pub use zkpvm_machine::{verify, Proof, SideNote};
