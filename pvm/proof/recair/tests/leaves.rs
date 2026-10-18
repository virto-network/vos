//! The first feasibility gate (`recursion-air.md` §10, step 4): COMPARE's
//! leaf, and the window kernel leaf's rows.
//!
//! - **COMPARE's leaf:** a chip-isolated COMPARE proof of format 35, verified
//!   natively and in a circuit, the circuit proved and verified; its rows
//!   against `count-35.log`'s "verify COMPARE alone"; a tampered OODS
//!   sample, queried value, Merkle sibling, FRI value and nonce each refused
//!   by its check.
//! - **The window kernel's class-1 leaf topology,** built without values:
//!   its rows pinned term by term, each beside `count-35.log`'s model.

use std::sync::OnceLock;

use num_traits::One;
use stwo::core::fields::qm31::SecureField;
use vos_pvm_proof::format::SEGMENT;
use vos_pvm_proof::pcs::Commitment;
use vos_pvm_proof::poseidon2::P2Hash;
use vos_pvm_proof::{
    PcsPolicy, Proof, RecursionData, SideNote, chip_idx, extract_recursion_data,
    prove_chip_isolated_format, verify_with_explicit_components,
};
use vos_recair::verifier::{SegmentShape, SegmentValues, verify_segment};
use vos_recair::{Bit, Context, NoValue, Value};

// ── COMPARE's leaf ─────────────────────────────────────────────────────────

/// COMPARE, with the byte-range table its range checks look up: COMPARE
/// commits no preprocessed column and a proof's preprocessed tree is never
/// empty, so the table's one column is it (`count-35.log`'s model counts one
/// preprocessed column too).
const COMPARE_MASK: u32 = 1 << chip_idx::RANGE_MULTIPLICITY_256 | 1 << chip_idx::COMPARE;
/// The model's COMPARE at 2^12 rows; the table at its own 2^8.
const COMPARE_FLOORS: [u32; 2] = [0, 12];

/// `count-35.log`'s "verify COMPARE alone" at 40 queries: the verifier's
/// rows, without a leaf's own work (the boundary terms and digests, which a
/// chip-isolated proof has none of).
const COMPARE_MODEL: [usize; 3] = [8_644, 10_352, 280];

struct Compare {
    proof: Proof,
    shape: SegmentShape,
    values: SegmentValues<SecureField>,
    data: RecursionData,
}

/// COMPARE proved alone under format 35, over a trace of padding rows: with
/// no CPU in the proof to produce its lookups, only an idle COMPARE's sums
/// close. The circuit's rows do not depend on the values.
fn compare() -> &'static Compare {
    static COMPARE: OnceLock<Compare> = OnceLock::new();
    COMPARE.get_or_init(|| {
        let mut side_note = SideNote::new(Vec::new(), Vec::new(), Vec::new());
        let proof =
            prove_chip_isolated_format(&mut side_note, &SEGMENT, COMPARE_MASK, &COMPARE_FLOORS)
                .expect("proves");
        assert_eq!(proof.format_version, SEGMENT.number);
        assert_eq!(proof.log_sizes, [8, 12]);

        let components: Vec<_> = (0..chip_idx::COUNT)
            .filter(|&chip| COMPARE_MASK & 1 << chip != 0)
            .map(|chip| vos_pvm_proof::all_components()[chip])
            .collect();
        let verifier: Vec<&dyn vos_pvm_proof::harness::MachineComponent> = components
            .iter()
            .map(|&c| c as &dyn vos_pvm_proof::harness::MachineComponent)
            .collect();
        let config = SEGMENT.pcs_config();
        let policy = PcsPolicy {
            min_pow_bits: config.pow_bits,
            min_fri_queries: config.fri_config.n_queries,
            min_fri_log_blowup: config.fri_config.log_blowup_factor,
        };
        verify_with_explicit_components(proof.clone(), &side_note, &verifier, &components, &policy)
            .expect("verifies natively");

        let Some(Commitment::Poseidon2M31(root)) = proof.preprocessed_commitment() else {
            panic!("a Poseidon2-M31 preprocessed root")
        };
        let shape = SegmentShape::chip_isolated(&SEGMENT, COMPARE_MASK, &proof.log_sizes, root);
        let values = SegmentValues::from_proof(&shape, &proof).expect("the proof's values");
        let data = extract_recursion_data(&proof);
        Compare {
            proof,
            shape,
            values,
            data,
        }
    })
}

fn position_of(context: &Context<SecureField>, bits: &[Bit]) -> usize {
    bits.iter()
        .enumerate()
        .map(|(i, bit)| usize::from(context.value(bit.var()) == SecureField::one()) << i)
        .sum()
}

fn print_rows(name: &str, context: &Context<impl Value>) {
    eprintln!("{name}: {:?} rows (p2, qm31, h8)", context.rows());
    for (piece, rows) in context.piece_rows() {
        eprintln!("  {piece}: {rows:?}");
    }
}

/// COMPARE's proof verified in a circuit as natively (its transcript the
/// native recorder's permutation for permutation, each query's DEEP
/// quotient its first-layer value), the circuit proved and verified; its
/// rows within 15% of the model's.
#[test]
fn compares_leaf_verifies_proves_and_verifies() {
    let compare = compare();
    let data = &compare.data;
    let mut context = Context::<SecureField>::new();
    let verified = verify_segment(&mut context, &compare.shape, &compare.values);

    let permutations = verified.channel.transcript().permutations();
    assert_eq!(permutations.len(), data.transcript.records.len());
    for (i, (permutation, record)) in permutations
        .iter()
        .zip(&data.transcript.records)
        .enumerate()
    {
        let words = record.output.map(|w| vos_pvm_poseidon2::M31::new(w.0));
        assert_eq!(
            *permutation,
            vos_recair::value::wires_of(words),
            "permutation {i}"
        );
    }
    for (bits, &answer) in verified.draws.queries.iter().zip(&verified.answers) {
        let position = position_of(&context, bits);
        let index = data.query_positions.binary_search(&position).unwrap();
        assert_eq!(context.value(answer), data.first_layer_evals[index]);
    }

    print_rows("COMPARE's leaf", &context);
    let rows = context.rows();
    for ((&rows, model), name) in rows.iter().zip(COMPARE_MODEL).zip(["p2", "qm31", "h8"]) {
        let ratio = rows as f64 / model as f64;
        eprintln!("  {name}: {rows} against the model's {model} ({ratio:.3})");
        assert!(
            (0.85..=1.15).contains(&ratio),
            "{name}: {rows} against {model}"
        );
    }

    let finalized = context.finalize().expect("the wiring checks");
    let started = std::time::Instant::now();
    let proof = vos_recair::prove(&finalized.circuit, &finalized.witness).expect("proves");
    let proving = started.elapsed();
    let (_, hash) = vos_recair::circuit_commitment(&finalized.circuit).unwrap();
    let started = std::time::Instant::now();
    vos_recair::verify(proof, &hash).expect("verifies");
    eprintln!(
        "COMPARE's leaf, padded to 2^{:?}: proved in {:.3}s, verified in {:.3}s",
        finalized.circuit.log_sizes(),
        proving.as_secs_f64(),
        started.elapsed().as_secs_f64()
    );
}

/// The composed circuit over `values`, lenient: the first mismatch's piece.
fn first_refusal(values: &SegmentValues<SecureField>) -> Option<&'static str> {
    let mut context = Context::<SecureField>::new().lenient();
    verify_segment(&mut context, &compare().shape, values);
    context.mismatches().first().map(|mismatch| mismatch.piece)
}

fn bump(value: &mut SecureField) {
    *value += SecureField::one();
}

/// A tampered OODS sample, queried value, Merkle sibling, FRI value and
/// nonce are each refused by the check the native verifier refuses it with;
/// a tampered witness, proved, does not verify.
#[test]
fn compares_leaf_refuses_each_tamper() {
    let compare = compare();
    assert_eq!(first_refusal(&compare.values), None);
    // COMPARE's running sum at the OODS point.
    let running_sum = {
        let component = &compare.shape.layout.components[1];
        assert_eq!(component.chip, chip_idx::COMPARE);
        let column = component.interaction_columns.end - 1;
        compare.shape.sample_index[2][column] + 1
    };
    type Edit = Box<dyn Fn(&mut SegmentValues<SecureField>)>;
    let cases: Vec<(&str, &str, Edit)> = vec![
        (
            "an OODS sample",
            "oods",
            Box::new(move |v| bump(&mut v.sampled[running_sum])),
        ),
        (
            "a queried value",
            "merkle",
            Box::new(|v| bump(&mut v.queries[7].trees[1].leaf[3])),
        ),
        (
            "a Merkle sibling",
            "merkle",
            Box::new(|v| bump(&mut v.queries[3].trees[2].path[5][0])),
        ),
        (
            "a FRI value",
            "fri",
            Box::new(|v| bump(&mut v.queries[0].fri[3].sibling)),
        ),
        ("the PoW nonce", "pow", Box::new(|v| bump(&mut v.nonce))),
        (
            "the interaction PoW nonce",
            "pow",
            Box::new(|v| bump(&mut v.interaction_nonce)),
        ),
        (
            "a claimed sum",
            "logup",
            Box::new(|v| bump(&mut v.claimed_sums[1])),
        ),
    ];
    for (name, piece, edit) in &cases {
        let mut values = compare.values.clone();
        edit(&mut values);
        assert_eq!(first_refusal(&values), Some(*piece), "{name}");
    }

    let mut values = compare.values.clone();
    bump(&mut values.queries[3].trees[2].path[5][0]);
    let mut context = Context::<SecureField>::new().lenient();
    verify_segment(&mut context, &compare.shape, &values);
    let finalized = context.finalize().expect("the wiring checks");
    let refused = match vos_recair::prove(&finalized.circuit, &finalized.witness) {
        Err(_) => true,
        Ok(proof) => {
            let (_, hash) = vos_recair::circuit_commitment(&finalized.circuit).unwrap();
            vos_recair::verify(proof, &hash).is_err()
        }
    };
    assert!(refused, "a tampered witness proves and verifies");
}

/// A chip-isolated shape is no segment's: a mask with the boundary chips
/// builds its shape with the binding only, and the COMPARE proof's shape is
/// refused by a segment's.
#[test]
fn a_chip_isolated_shape_holds_no_boundary_chip() {
    let compare = compare();
    assert!(compare.shape.boundary.is_none());
    assert_eq!(compare.shape.check(&compare.proof), Ok(()));
    let message = std::panic::catch_unwind(|| {
        SegmentShape::chip_isolated(&SEGMENT, WINDOW_MASK, &WINDOW_LOG_SIZES, P2Hash::default());
    })
    .expect_err("refused");
    assert_eq!(
        message.downcast_ref::<&str>(),
        Some(&"a mask without the boundary chips")
    );
    assert!(
        std::panic::catch_unwind(|| {
            SegmentShape::new(&SEGMENT, COMPARE_MASK, &[8, 12], P2Hash::default());
        })
        .is_err()
    );
}

// ── The window kernel's leaf rows ──────────────────────────────────────────

/// The window kernel's class-1 leaf topology: its mask and log sizes.
const WINDOW_MASK: u32 = 0x01f9_ffff;
const WINDOW_LOG_SIZES: [u32; 23] = [
    15, 14, 16, 18, 9, 8, 4, 17, 4, 4, 4, 16, 8, 16, 8, 8, 6, 8, 15, 15, 15, 15, 16,
];
const QUERIES: usize = 40;

/// A term of `count-35.log`'s "verify window kernel class 1": its
/// component, whether it is per query, its measured rows and the model's.
struct Term {
    name: &'static str,
    component: usize,
    per_query: bool,
    measured: usize,
    model: usize,
}

const fn term(
    name: &'static str,
    component: usize,
    per_query: bool,
    measured: usize,
    model: usize,
) -> Term {
    Term {
        name,
        component,
        per_query,
        measured,
        model,
    }
}

/// The terms, measured and model. The deltas: the lifting height is 2^20,
/// not the model's 2^21 (Stwo's composition bound is the largest component's
/// log size plus one, split once), a path level and a FRI layer fewer a
/// query; 16 sample points, not 18 (the largest columns' periodicity points
/// coincide with their second samples'); the transcript absorbs the proof's
/// 8,997 sampled values where the model's channel counts DEEP's 9,985
/// samples, the periodicity ones among them (494 permutations), and the
/// statement header and the 296 boundary bytes, which it leaves out; the
/// PoW nonces' 16-bit limb checks, 100
/// rows each, and the boundary chips' public terms, which the model leaves
/// out; the header and preprocessed root checked against the shape.
const WINDOW_TERMS: [Term; 17] = [
    term("p2: leaf hashes, four trees", 0, true, 1_004, 1_004),
    term("p2: Merkle paths, four trees", 0, true, 78, 84),
    term("p2: FRI leaves and paths", 0, true, 243, 266),
    term("p2: channel, PoWs and query draws", 0, false, 4_655, 5_082),
    term("qm31: query word and 31 bits", 1, true, 64, 63),
    term("qm31: query point from bits", 1, true, 75, 84),
    term("qm31: DEEP, per point", 1, true, 96, 108),
    term("qm31: DEEP, samples off the h8 runs", 1, true, 785, 769),
    term("qm31: FRI folds and twiddles", 1, true, 106, 133),
    term(
        "qm31: OODS (compiled, accumulation, challenge powers, point, vanishing, check)",
        1,
        false,
        35_216,
        29_420 + 5_175 + 573 + 54,
    ),
    term(
        "qm31: logup, with the boundary public terms",
        1,
        false,
        655,
        25,
    ),
    term(
        "qm31: DEEP sums of sampled values",
        1,
        false,
        20_445,
        20_458,
    ),
    term("qm31: proof-of-work checks", 1, false, 246, 64),
    term(
        "qm31: header and preprocessed root against the shape",
        1,
        false,
        34,
        0,
    ),
    term("qm31: the context's constants", 1, false, 2, 0),
    term("h8: DEEP, 8-sample runs", 2, true, 1_150, 1_152),
    term("h8: nothing else", 2, false, 0, 0),
];

/// The window kernel's class-1 leaf topology (mask `0x01f9ffff`), built
/// without values: each term's rows as measured, pinned, beside
/// `count-35.log`'s model (59,242 / 102,049 / 46,080 before the leaf's own
/// work, which 5.12 adds), and the totals within 2^16 / 2^17 / 2^16.
#[test]
fn the_window_kernels_leaf_rows_per_term() {
    let shape = SegmentShape::new(&SEGMENT, WINDOW_MASK, &WINDOW_LOG_SIZES, P2Hash::default());
    let mut context = Context::<NoValue>::new();
    verify_segment(&mut context, &shape, &SegmentValues::blank(&shape));
    print_rows("the window kernel's class-1 leaf", &context);

    assert_eq!(shape.layout.lifting_log_size, 20);
    assert_eq!(shape.config().fri_config.n_queries, QUERIES);
    let (blocks, singles, samples) = shape.deep.counts();
    let points = shape.deep.points.len();
    eprintln!(
        "{} sampled values; DEEP: {samples} samples at {points} points, a query's {blocks} h8 \
         blocks and {singles} single samples",
        shape.n_samples
    );
    assert_eq!(points, 16);

    let pieces = context.piece_rows();
    let piece = |name: &str| pieces.get(name).copied().unwrap_or_default();
    assert!(
        pieces.keys().all(|name| [
            "channel",
            "circle",
            "context",
            "deep",
            "deep once",
            "fri",
            "logup",
            "merkle",
            "oods",
            "pow",
            "queries",
            "shape"
        ]
        .contains(name)),
        "{pieces:?}"
    );
    let per_query = |rows: usize| {
        assert_eq!(rows % QUERIES, 0, "{rows} rows over {QUERIES} queries");
        rows / QUERIES
    };
    let paths: usize = shape.heights.iter().map(|&h| h as usize).sum();
    let deep = piece("deep");
    let measured = [
        per_query(piece("merkle")[0]) - paths,
        paths,
        per_query(piece("fri")[0]),
        piece("channel")[0] + piece("pow")[0] + piece("queries")[0],
        per_query(piece("queries")[1]),
        per_query(piece("circle")[1]),
        per_query(deep[1]) - singles,
        singles,
        per_query(piece("fri")[1]),
        piece("oods")[1],
        piece("logup")[1],
        piece("deep once")[1],
        piece("pow")[1],
        piece("shape")[1],
        piece("context")[1],
        per_query(deep[2]),
        context.rows()[2] - deep[2],
    ];
    // Six rows a point: D(q), its inverse, the numerator, the sum.
    assert_eq!(measured[6], 6 * points);
    assert_eq!(measured[15], blocks);

    let mut totals = [[0usize; 3]; 2];
    for (term, measured) in WINDOW_TERMS.iter().zip(measured) {
        let delta = measured as i64 - term.model as i64;
        eprintln!(
            "  {}{}: {measured} [measured], {} [model], {delta:+}",
            term.name,
            if term.per_query { " (a query)" } else { "" },
            term.model,
        );
        assert_eq!(measured, term.measured, "{}", term.name);
        let times = if term.per_query { QUERIES } else { 1 };
        totals[0][term.component] += term.measured * times;
        totals[1][term.component] += term.model * times;
    }
    assert_eq!(totals[0], context.rows(), "the terms cover every row");
    assert_eq!(totals[0], [57_655, 101_638, 46_000]);
    assert_eq!(
        totals[1],
        [59_242, 102_049, 46_080],
        "count-35.log's totals"
    );
    let rows = context.rows();
    assert!(
        rows[0] <= 1 << 16 && rows[1] <= 1 << 17 && rows[2] <= 1 << 16,
        "{rows:?}"
    );
}
