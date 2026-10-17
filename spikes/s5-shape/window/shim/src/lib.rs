//! vos-core's precompile shim under the name cipher-clerk asks for, and the
//! Ristretto types it names, in software.

#![no_std]

pub use vos_pvm_precompiles::*;

pub mod ristretto;
pub mod scalar;

pub use ristretto::{
    RISTRETTO_BASEPOINT_TABLE, RistrettoBasepointTable, RistrettoPoint, ristretto_point_add,
    ristretto_scalar_mult,
};
pub use scalar::{Scalar, scalar_add_mod_l, scalar_from_bytes_mod_order_wide, scalar_mul_mod_l};
