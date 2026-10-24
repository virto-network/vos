//! The mutations `final_verifier_mutate` applies to a golden wrap, by its
//! structure and by its bytes; `examples/paths.rs` replays them too.

#![allow(dead_code)]

use arbitrary::Arbitrary;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::poly::line::LinePoly;
use stwo::core::vcs::blake2b_hash::Blake2bHash;
use vos_pvm_final_verifier::WrapProof;

/// Where in the proof a structural mutation lands.
#[derive(Arbitrary, Debug, Clone, Copy)]
pub enum Place {
    Commitments,
    Sampled,
    Decommitments,
    Queried,
    FirstLayer,
    InnerLayers,
    InnerWitness,
    InnerHashes,
    LastLayer,
}

/// How a vector is resized.
#[derive(Arbitrary, Debug, Clone, Copy)]
pub enum Resize {
    /// Grown by a copy of its last item.
    Grow,
    Shrink,
    /// Emptied.
    Clear,
}

#[derive(Arbitrary, Debug)]
pub enum Mutation {
    /// The encoding's byte at `at` (modulo its length) xored with `with`.
    Flip {
        at: u32,
        with: u8,
    },
    Insert {
        at: u32,
        bytes: Vec<u8>,
    },
    Remove {
        at: u32,
        len: u16,
    },
    Truncate {
        len: u32,
    },
    /// A vector at `place` (its `outer`th, then `inner`th, as it nests)
    /// resized.
    Resize {
        place: Place,
        outer: u8,
        inner: u8,
        how: Resize,
    },
    /// A value at `place` set to `limbs` (unreduced: any `u32`).
    Value {
        place: Place,
        outer: u8,
        inner: u8,
        at: u16,
        limbs: [u32; 4],
    },
    /// A hash at `place` set to `hash`.
    Hash {
        place: Place,
        outer: u8,
        at: u16,
        hash: [u8; 32],
    },
    ProofOfWork(u64),
    InteractionPow(u64),
    ClaimedSum {
        at: u8,
        limbs: [u32; 4],
    },
    Config {
        field: u8,
        value: u32,
    },
    LogSize {
        at: u8,
        value: u32,
    },
    Format(u32),
}

fn pick<T>(items: &mut [T], at: usize) -> Option<&mut T> {
    let len = items.len();
    (len > 0).then(|| &mut items[at % len])
}

fn resize<T: Clone>(items: &mut Vec<T>, how: Resize) {
    match how {
        Resize::Grow => {
            if let Some(last) = items.last().cloned() {
                items.push(last);
            }
        }
        Resize::Shrink => {
            items.pop();
        }
        Resize::Clear => items.clear(),
    }
}

fn secure(limbs: [u32; 4]) -> SecureField {
    SecureField::from_m31_array(limbs.map(BaseField::from_u32_unchecked))
}

/// A vector at `place` resized by `how`.
fn reshape(proof: &mut WrapProof, place: Place, outer: usize, inner: usize, how: Resize) {
    let stark = &mut proof.stark_proof.0;
    let fri = &mut stark.fri_proof;
    match place {
        Place::Commitments => resize(&mut stark.commitments.0, how),
        Place::Sampled => match pick(&mut stark.sampled_values.0, outer) {
            Some(tree) if inner == 0 => resize(tree, how),
            Some(tree) => {
                if let Some(column) = pick(tree, inner) {
                    resize(column, how);
                }
            }
            None => resize(&mut stark.sampled_values.0, how),
        },
        Place::Decommitments => match pick(&mut stark.decommitments.0, outer) {
            Some(tree) => resize(&mut tree.hash_witness, how),
            None => resize(&mut stark.decommitments.0, how),
        },
        Place::Queried => match pick(&mut stark.queried_values.0, outer) {
            Some(tree) if inner == 0 => resize(tree, how),
            Some(tree) => {
                if let Some(column) = pick(tree, inner) {
                    resize(column, how);
                }
            }
            None => resize(&mut stark.queried_values.0, how),
        },
        Place::FirstLayer => resize(&mut fri.first_layer.fri_witness, how),
        Place::InnerLayers => resize(&mut fri.inner_layers, how),
        Place::InnerWitness => {
            if let Some(layer) = pick(&mut fri.inner_layers, outer) {
                resize(&mut layer.fri_witness, how);
            }
        }
        Place::InnerHashes => {
            if let Some(layer) = pick(&mut fri.inner_layers, outer) {
                resize(&mut layer.decommitment.hash_witness, how);
            }
        }
        Place::LastLayer => {
            let mut coeffs = fri.last_layer_poly.to_vec();
            resize(&mut coeffs, how);
            if coeffs.len().is_power_of_two() {
                fri.last_layer_poly = LinePoly::new(coeffs);
            }
        }
    }
}

/// A value at `place` set.
fn set_value(
    proof: &mut WrapProof,
    place: Place,
    outer: usize,
    inner: usize,
    at: usize,
    limbs: [u32; 4],
) {
    let stark = &mut proof.stark_proof.0;
    let fri = &mut stark.fri_proof;
    let value = secure(limbs);
    let target = match place {
        Place::Sampled => pick(&mut stark.sampled_values.0, outer)
            .and_then(|tree| pick(tree, inner))
            .and_then(|column| pick(column, at)),
        Place::Queried => {
            if let Some(value) = pick(&mut stark.queried_values.0, outer)
                .and_then(|tree| pick(tree, inner))
                .and_then(|column| pick(column, at))
            {
                *value = BaseField::from_u32_unchecked(limbs[0]);
            }
            None
        }
        Place::FirstLayer => pick(&mut fri.first_layer.fri_witness, at),
        Place::InnerWitness | Place::InnerLayers | Place::InnerHashes => {
            pick(&mut fri.inner_layers, outer).and_then(|layer| pick(&mut layer.fri_witness, at))
        }
        Place::LastLayer => {
            let mut coeffs = fri.last_layer_poly.to_vec();
            if let Some(coeff) = pick(&mut coeffs, at) {
                *coeff = value;
            }
            fri.last_layer_poly = LinePoly::new(coeffs);
            None
        }
        Place::Commitments | Place::Decommitments => None,
    };
    if let Some(target) = target {
        *target = value;
    }
}

/// A hash at `place` set.
fn set_hash(proof: &mut WrapProof, place: Place, outer: usize, at: usize, hash: [u8; 32]) {
    let stark = &mut proof.stark_proof.0;
    let fri = &mut stark.fri_proof;
    let target = match place {
        Place::Commitments => pick(&mut stark.commitments.0, at),
        Place::Decommitments => pick(&mut stark.decommitments.0, outer)
            .and_then(|tree| pick(&mut tree.hash_witness, at)),
        Place::FirstLayer => Some(&mut fri.first_layer.commitment),
        Place::InnerLayers => pick(&mut fri.inner_layers, outer).map(|layer| &mut layer.commitment),
        Place::InnerHashes | Place::InnerWitness => pick(&mut fri.inner_layers, outer)
            .and_then(|layer| pick(&mut layer.decommitment.hash_witness, at)),
        _ => pick(&mut fri.first_layer.decommitment.hash_witness, at),
    };
    if let Some(target) = target {
        *target = Blake2bHash(hash);
    }
}

pub fn apply(proof: &mut WrapProof, mutation: &Mutation) {
    match *mutation {
        Mutation::Resize {
            place,
            outer,
            inner,
            how,
        } => reshape(proof, place, outer.into(), inner.into(), how),
        Mutation::Value {
            place,
            outer,
            inner,
            at,
            limbs,
        } => set_value(proof, place, outer.into(), inner.into(), at.into(), limbs),
        Mutation::Hash {
            place,
            outer,
            at,
            hash,
        } => set_hash(proof, place, outer.into(), at.into(), hash),
        Mutation::ProofOfWork(nonce) => proof.stark_proof.0.proof_of_work = nonce,
        Mutation::InteractionPow(nonce) => proof.interaction_pow = nonce,
        Mutation::ClaimedSum { at, limbs } => {
            proof.claimed_sums[usize::from(at) % 3] = secure(limbs)
        }
        Mutation::Config { field, value } => {
            let config = &mut proof.stark_proof.0.config;
            match field % 5 {
                0 => config.pow_bits = value,
                1 => config.fri_config.log_blowup_factor = value,
                2 => config.fri_config.log_last_layer_degree_bound = value,
                3 => config.fri_config.n_queries = value as usize,
                _ => config.fri_config.fold_step = value,
            }
        }
        Mutation::LogSize { at, value } => proof.log_sizes[usize::from(at) % 3] = value,
        Mutation::Format(format) => proof.format_version = format,
        Mutation::Flip { .. }
        | Mutation::Insert { .. }
        | Mutation::Remove { .. }
        | Mutation::Truncate { .. } => {}
    }
}

pub fn apply_bytes(bytes: &mut Vec<u8>, mutation: &Mutation) {
    let len = bytes.len().max(1);
    match mutation {
        Mutation::Flip { at, with } => {
            if let Some(byte) = bytes.get_mut(*at as usize % len) {
                *byte ^= with;
            }
        }
        Mutation::Insert {
            at,
            bytes: inserted,
        } => {
            let at = (*at as usize) % (bytes.len() + 1);
            bytes.splice(at..at, inserted.iter().copied());
        }
        Mutation::Remove { at, len: removed } => {
            let at = (*at as usize) % len;
            let end = (at + usize::from(*removed)).min(bytes.len());
            bytes.drain(at.min(end)..end);
        }
        Mutation::Truncate { len: kept } => bytes.truncate(*kept as usize % len),
        _ => {}
    }
}
