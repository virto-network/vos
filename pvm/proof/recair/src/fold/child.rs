//! A fold's child verified in a circuit (`recursion-air.md` §6): a leaf's or
//! a fold's proof, format 32 at the padded shape, the recursion AIR's own.
//!
//! **What a child's circuit is built for** ([`ChildShape`]): the recursion
//! AIR's three components at the padded log sizes
//! ([`LEAF_FOLD_LOG_SIZES`]), their constraints compiled by the gate compiler
//! from the components' own `evaluate`, the `Gate` relation the one drawn,
//! under format 32's parameters. Every child has this shape, a leaf or a
//! fold: what tells them apart is the preprocessed root, which a child's
//! circuit is, and the fold takes it as a witness.
//!
//! **The transcript,** as [`crate::verify`] runs it: the statement header
//! (constants of the fold's circuit), the preprocessed root (a witness),
//! the main root, the child's outputs (its output digest's two wires, which
//! the fold re-hashes from the child's preimage), the interaction PoW, the
//! relation, the claimed sums; then the logup sums with the public terms:
//! the claimed sums, `u`'s use and each output's add to zero; then Stwo's
//! protocol, as a segment's ([`verify_rest`]).
//!
//! **The circuit hash** ([`circuit_hash`]) is [`vos_pvm_recair_air::circuit_hash`]
//! in rows: one transcript absorption, from the zero digest, of the format's
//! constant words and the preprocessed root's wires.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::OnceLock;

use num_traits::{One, Zero};
use stwo::core::air::Component;
use stwo::core::channel::Channel as _;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use vos_pvm_proof::format::LEAF_FOLD_LOG_SIZES;
use vos_pvm_proof::framework_access::{AllLookupElements, air_layout};
use vos_pvm_proof::poseidon2::{P2MerkleChannel, Poseidon2M31Channel};
use vos_pvm_proof::proof::{check_format_security, check_interaction_pow, mix_statement_header};
use vos_pvm_proof::{RecursionData, SampleLayout, sample_layout_of};
use vos_pvm_recair_air::gate::{FIRST_OUTPUT_ADDRESS, GATE_WIDTH, U_ADDRESS};
use vos_pvm_recair_air::{Components, GateRelation, LogSizes, h8, p2, qm31};

use crate::circuit::Qm31Op;
use crate::compile::{self, Recording};
use crate::context::{Context, Var};
use crate::gadgets::TranscriptGadget;
use crate::prove::{FORMAT, RecairProof, circuit_hash_of, committed_log_sizes, hashed_params};
use crate::value::Value;
use crate::verifier::bits::linear;
use crate::verifier::channel::Channel;
use crate::verifier::shape::header_words;
use crate::verifier::stark::{Draws, StarkShape, StarkValues, interaction, verify_rest};
use crate::verifier::witness::{digest_wires, drawn_positions, pack};
use crate::verifier::{ShapeMismatch, WitnessError};

/// The relation a recursion AIR proof draws, by the name its components'
/// recordings give it.
const GATE: &str = "Gate";

/// What a child's verifier circuit is built for.
pub struct ChildShape {
    pub stark: StarkShape,
    /// The components' log sizes: the padded shape's.
    pub log_sizes: LogSizes,
    /// The statement header's words: the domain, the format, the PCS
    /// configuration, then each log size.
    pub header: Vec<u64>,
}

/// The components at `log_sizes`, their claimed sums zero: what their
/// layout and constraints are read from.
fn components(log_sizes: &LogSizes) -> Components {
    Components::new(&GateRelation::dummy(), log_sizes, &[SecureField::zero(); 3])
}

/// The [`SampleLayout`] of a recursion AIR proof at `log_sizes`, as
/// `vos_pvm_proof::sample_layout` lays out a segment's.
fn sample_layout(log_sizes: &LogSizes, config: &PcsConfig) -> SampleLayout {
    let components = components(log_sizes);
    let dyns = components.as_dyn();
    let committed = committed_log_sizes(&components, log_sizes);
    let mut security_shape = air_layout(config, &dyns, &committed)
        .expect("the recursion AIR's layout")
        .security_shape(&dyns);
    security_shape.relation_width = GATE_WIDTH as u64;
    let chips: Vec<(usize, u32)> = log_sizes.iter().copied().enumerate().collect();
    sample_layout_of(config, &dyns, &chips, &committed, security_shape)
}

impl ChildShape {
    /// The shape of a recursion AIR proof under format 32 at `log_sizes`.
    ///
    /// # Panics
    /// When the format's floors refuse the shape.
    pub fn new(log_sizes: LogSizes) -> Self {
        let config = FORMAT.pcs_config();
        let layout = sample_layout(&log_sizes, &config);
        if let Err(refusal) = check_format_security(FORMAT, &config, &layout.security_shape) {
            panic!("a shape the format's floors admit: {refusal}");
        }
        let relation = GateRelation::dummy();
        let recordings = [
            Recording::of(
                "p2",
                &p2::P2Eval {
                    log_size: log_sizes[0],
                    relation: relation.clone(),
                },
            ),
            Recording::of(
                "qm31",
                &qm31::Qm31Eval {
                    log_size: log_sizes[1],
                    relation: relation.clone(),
                },
            ),
            Recording::of(
                "h8",
                &h8::H8Eval {
                    log_size: log_sizes[2],
                    relation,
                },
            ),
        ];
        let compiled = compile::compile(&recordings, &[(GATE.into(), GATE_WIDTH)]);
        Self {
            stark: StarkShape::new(FORMAT, layout, vec![GATE.into()], compiled),
            log_sizes,
            header: header_words(FORMAT.number, &config, &log_sizes),
        }
    }

    /// The padded shape's, every leaf's and fold's, built once.
    pub fn padded() -> &'static Self {
        static SHAPE: OnceLock<ChildShape> = OnceLock::new();
        SHAPE.get_or_init(|| Self::new(LEAF_FOLD_LOG_SIZES))
    }

    /// Refuses a proof of another format, configuration or log sizes.
    pub fn check(&self, proof: &RecairProof) -> Result<(), ShapeMismatch> {
        if proof.format_version != FORMAT.number {
            return Err(ShapeMismatch::Format {
                circuit: FORMAT.number,
                proof: proof.format_version,
            });
        }
        if FORMAT.verifier_config(&proof.stark_proof.config) != self.stark.config() {
            return Err(ShapeMismatch::Config);
        }
        if proof.log_sizes != self.log_sizes {
            return Err(ShapeMismatch::LogSizes);
        }
        if proof.outputs.len() != 2 {
            return Err(ShapeMismatch::Structure("a node's two output wires"));
        }
        Ok(())
    }
}

/// The values a child's verifier circuit guesses.
#[derive(Clone, Debug)]
pub struct ChildValues<V> {
    /// The child's circuit: its preprocessed root.
    pub preprocessed_root: [V; 2],
    pub stark: StarkValues<V>,
}

impl<V: Value> ChildValues<V> {
    /// The layout of `shape`'s values, every value zero (or no value).
    pub fn blank(shape: &ChildShape) -> Self {
        let zero = V::from_qm31(SecureField::zero());
        Self {
            preprocessed_root: [zero; 2],
            stark: StarkValues::blank(&shape.stark),
        }
    }
}

/// The native verifier's walk over `proof`, a valid proof of `shape`: its
/// transcript through the interaction root as [`crate::verify`] runs it,
/// then Stwo's protocol replayed ([`vos_pvm_proof::replay_stark`]).
///
/// # Panics
/// When the proof does not verify natively.
pub fn recursion_data(
    shape: &ChildShape,
    proof: &RecairProof,
) -> Result<RecursionData, WitnessError> {
    shape.check(proof)?;
    let stark = &proof.stark_proof;
    let root = stark.commitments[0];
    crate::verify(proof.clone(), &circuit_hash_of(&proof.log_sizes, &root)).expect("a valid proof");
    let config = FORMAT.pcs_config();
    let recorder = Rc::new(RefCell::new(Vec::new()));
    let channel = &mut Poseidon2M31Channel::recording(recorder.clone());
    mix_statement_header(channel, FORMAT.number, &config, &proof.log_sizes);
    let scheme = &mut CommitmentSchemeVerifier::<P2MerkleChannel>::new(config);
    let trace_log_sizes = committed_log_sizes(&components(&proof.log_sizes), &proof.log_sizes);
    scheme.commit(root, &trace_log_sizes[0], channel);
    scheme.commit(stark.commitments[1], &trace_log_sizes[1], channel);
    channel.mix_felts(&proof.outputs);
    check_interaction_pow(channel, FORMAT, proof.interaction_pow).expect("verified");
    let relation = GateRelation::draw(channel);
    channel.mix_felts(&proof.claimed_sums);
    scheme.commit(stark.commitments[2], &trace_log_sizes[2], channel);
    let components = Components::new(&relation, &proof.log_sizes, &proof.claimed_sums);
    let dyns: Vec<&dyn Component> = components.as_dyn().to_vec();
    Ok(vos_pvm_proof::replay_stark(
        stark,
        &dyns,
        &recorder,
        channel,
        scheme,
        AllLookupElements::default(),
    ))
}

impl ChildValues<SecureField> {
    /// The values of `proof`, a valid proof of `shape`.
    ///
    /// # Panics
    /// When the proof does not verify natively: the builder lays out a valid
    /// proof's values, which a test may then tamper.
    pub fn from_proof(shape: &ChildShape, proof: &RecairProof) -> Result<Self, WitnessError> {
        let data = recursion_data(shape, proof)?;
        let stark = &proof.stark_proof;
        let drawn = drawn_positions(&shape.stark, &data);
        Ok(Self {
            preprocessed_root: digest_wires(&stark.commitments[0]),
            stark: StarkValues::lay_out(
                &shape.stark,
                stark,
                &data,
                &drawn,
                proof.interaction_pow,
                proof.claimed_sums.to_vec(),
            )?,
        })
    }
}

/// A verified child's wires.
#[derive(Clone, Debug)]
pub struct VerifiedChild<V> {
    pub channel: Channel<V>,
    pub draws: Draws,
    /// The child's circuit: its preprocessed root.
    pub preprocessed_root: [Var; 2],
    /// Each query's first-layer value, the DEEP quotient.
    pub answers: Vec<Var>,
}

/// `combine(address, wire)⁻¹`: `1 / (address + Σ_j α^(j+1)·wire_j − z)`,
/// Horner from the wire's last limb.
fn inverse_combined<V: Value>(
    context: &mut Context<V>,
    [z, alpha]: [Var; 2],
    address: u32,
    wire: Var,
) -> Var {
    let mut acc = context.limb(wire, 3);
    for j in (0..3).rev() {
        let mut lanes = [BaseField::zero(); 4];
        lanes[j] = BaseField::one();
        acc = context.qm31(
            Qm31Op {
                k_m: BaseField::one(),
                lanes,
                ..Default::default()
            },
            Some(acc),
            Some(alpha),
            Some(wire),
        );
    }
    let one = context.one();
    acc = context.qm31(
        Qm31Op {
            k_m: BaseField::one(),
            k_c: BaseField::from(address),
            ..Default::default()
        },
        Some(acc),
        Some(alpha),
        Some(one),
    );
    let combined = context.sub(acc, z);
    context.inverse(combined)
}

/// The logup sums as [`crate::verify`] checks them: the claimed sums and
/// the public terms, `u`'s use and each output's, add to zero.
fn check_logup<V: Value>(
    context: &mut Context<V>,
    relation: [Var; 2],
    claimed_sums: &[Var],
    outputs: [Var; 2],
) {
    let u = context.u();
    let mut terms: Vec<(BaseField, Var)> = claimed_sums
        .iter()
        .map(|&sum| (BaseField::one(), sum))
        .collect();
    terms.push((
        BaseField::one(),
        inverse_combined(context, relation, U_ADDRESS, u),
    ));
    for (i, output) in outputs.into_iter().enumerate() {
        let term = inverse_combined(context, relation, FIRST_OUTPUT_ADDRESS + i as u32, output);
        terms.push((BaseField::one(), term));
    }
    let zero = context.zero();
    linear(context, &terms, Some(zero));
}

/// Verifies the child proof whose values are `values` in `context`, a
/// circuit of `shape`, its output digest the wires `outputs`.
///
/// # Panics
/// When a length of `values` is not `shape`'s.
pub fn verify_child<V: Value>(
    context: &mut Context<V>,
    shape: &ChildShape,
    values: &ChildValues<V>,
    outputs: [Var; 2],
) -> VerifiedChild<V> {
    values.stark.assert_lengths(&shape.stark);
    context.piece("channel");
    let mut channel = Channel::new(context);
    for &word in &shape.header {
        channel.mix_u64(context, word);
    }
    let preprocessed_root = context.guess_pair(values.preprocessed_root);
    channel.mix_root(context, preprocessed_root);
    let main_root = context.guess_pair(values.stark.roots[0]);
    channel.mix_root(context, main_root);
    channel.mix_felts(context, &outputs);
    let (relations, claimed_sums) = interaction(context, &shape.stark, &mut channel, &values.stark);
    context.piece("logup");
    check_logup(context, relations[0], &claimed_sums, outputs);
    let (draws, answers) = verify_rest(
        context,
        &shape.stark,
        &mut channel,
        [preprocessed_root, main_root],
        relations,
        &claimed_sums,
        &values.stark,
    );
    VerifiedChild {
        channel,
        draws,
        preprocessed_root,
        answers,
    }
}

/// The circuit hash of a format-32 circuit at `log_sizes` whose
/// preprocessed root is the wires `root`: [`vos_pvm_recair_air::circuit_hash`]'s
/// one absorption, its constant words then the root's.
pub fn circuit_hash<V: Value>(
    context: &mut Context<V>,
    log_sizes: &LogSizes,
    root: [Var; 2],
) -> [Var; 2] {
    let prefix: Vec<BaseField> =
        vos_pvm_recair_air::circuit_hash_prefix(FORMAT.number, hashed_params(FORMAT), log_sizes)
            .iter()
            .map(|word| BaseField::from(word.value()))
            .collect();
    assert!(
        prefix.len().is_multiple_of(4),
        "the root on whole wires after the prefix"
    );
    let mut wires: Vec<Var> = pack(&prefix)
        .into_iter()
        .map(|value| context.constant(value))
        .collect();
    wires.extend(root);
    let mut transcript = TranscriptGadget::new(context);
    transcript.absorb(context, &wires, prefix.len() + 8);
    transcript.digest()
}
