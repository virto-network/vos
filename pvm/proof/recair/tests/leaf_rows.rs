//! A derivation's leaf rows (`vos_pvm_compiler::leaf`) held to the built
//! leaves: its tables are the AIR's, its terms are the built leaf's piece by
//! piece, and its bound is the leaf circuit's rows on every shape tried,
//! exactly its `p2` and `h8` rows, its `qm31` rows plus the finalizing
//! allowance it names, which covers the finalized rows.

use std::cell::RefCell;
use std::rc::Rc;

use stwo::core::channel::Channel as _;
use stwo::core::circle::CirclePoint;
use stwo::core::fields::qm31::SecureField;
use vos_pvm_compiler::leaf::{self, CHIPS, FINALIZE, Mask, RELATIONS};
use vos_pvm_proof::format::SEGMENT;
use vos_pvm_proof::framework_access::{AllLookupElements, draw_all_lookup_elements};
use vos_pvm_proof::poseidon2::{P2Hash, PermKind, Poseidon2M31Channel};
use vos_pvm_proof::{chip_idx, sample_layout};
use vos_pvm_recair::compile::{self, Recording};
use vos_pvm_recair::leaf::{LeafCircuit, LeafValues, State};
use vos_pvm_recair::verifier::SegmentShape;
use vos_pvm_recair::{Context, NoValue};

/// The relations `mask`'s chips draw, by name, in draw order.
fn drawn(mask: u32) -> (Vec<String>, AllLookupElements) {
    let records = Rc::new(RefCell::new(Vec::new()));
    let mut channel = Poseidon2M31Channel::recording(records.clone());
    channel.mix_u64(1);
    let mut lookup = AllLookupElements::default();
    draw_all_lookup_elements(&mut lookup, &mut channel, mask);
    let challenges = lookup.relation_challenges();
    let names = records
        .borrow()
        .iter()
        .filter(|record| record.kind == PermKind::Squeeze)
        .map(|record| {
            let z = SecureField::from_m31_array(core::array::from_fn(|i| record.output[i]));
            let name = &challenges.iter().find(|c| c.z == z).unwrap().name;
            name.trim_end_matches("LookupElements").to_string()
        })
        .collect();
    (names, lookup)
}

/// A tree's columns' masks as runs.
fn runs(
    layout: &vos_pvm_proof::SampleLayout,
    tree: usize,
    columns: core::ops::Range<usize>,
) -> Vec<(Mask, u16)> {
    let mut runs: Vec<(Mask, u16)> = Vec::new();
    for column in columns {
        let offsets = &layout.sample_offsets[tree][column];
        let mask = match offsets[..] {
            [_] => Mask::Current,
            [first, _] if first == CirclePoint::zero() => Mask::Next,
            _ => Mask::Previous,
        };
        match runs.last_mut() {
            Some((last, count)) if *last == mask => *count += 1,
            _ => runs.push((mask, 1)),
        }
    }
    runs
}

/// The derivation's tables are the AIR's: each chip's columns, masks,
/// relations and compiled gates, each relation's tuple size, and the
/// format's parameters and padded shape.
#[test]
fn the_tables_are_the_airs() {
    let log_sizes = vec![12; chip_idx::COUNT];
    let layout = sample_layout(chip_idx::ALL, &log_sizes, &SEGMENT.pcs_config());
    let (names, lookup) = drawn(chip_idx::ALL);
    let relations = compile::relations_of(&lookup.relation_challenges());
    assert_eq!(names.len(), RELATIONS.len());
    for (name, &(table, size)) in names.iter().zip(&RELATIONS) {
        assert_eq!(name, table);
        let tuple = relations
            .iter()
            .find(|(full, _)| full.trim_end_matches("LookupElements") == name)
            .unwrap()
            .1;
        assert_eq!(tuple, size as usize, "{name}");
    }
    for component in &layout.components {
        let chip = &CHIPS[component.chip];
        let name = compile::CHIP_NAMES[component.chip];
        assert_eq!(
            usize::from(chip.preprocessed),
            component.preprocessed_indices.len(),
            "{name}"
        );
        assert_eq!(
            chip.main,
            runs(&layout, 1, component.main_columns.clone()),
            "{name}"
        );
        assert_eq!(
            chip.interaction,
            runs(&layout, 2, component.interaction_columns.clone()),
            "{name}"
        );
        for &index in &component.preprocessed_indices {
            assert_eq!(
                layout.column_log_sizes[0][index],
                component.log_size + 2,
                "{name}"
            );
        }
        let (own, _) = drawn(1 << component.chip);
        let bits = own
            .iter()
            .map(|name| 1u32 << names.iter().position(|known| known == name).unwrap())
            .fold(0, |bits, bit| bits | bit);
        assert_eq!(chip.relations, bits, "{name}");
        let compiled = compile::compile(
            &[Recording::chip(component.chip, component.log_size, &lookup)],
            &relations,
        );
        assert_eq!(chip.gates as usize, compiled.gate_rows(), "{name}");
        assert_eq!(
            chip.constraints as usize,
            compiled.components[0].constraints.len(),
            "{name}"
        );
    }
    assert_eq!(leaf::PADDED, vos_pvm_recair::leaf::PADDED_ROWS);
    assert_eq!(SEGMENT.params.n_queries, leaf::QUERIES);
    assert_eq!(SEGMENT.params.log_blowup, 2);
    assert_eq!(SEGMENT.params.fold_step, 1);
}

/// The leaf's topology over `mask` at `log_sizes` (in chip order), built
/// without values: its context, its DEEP plan's counts and its rows after
/// finalizing.
fn built(mask: u32, log_sizes: &[u32]) -> (Context<NoValue>, (usize, usize, usize), [usize; 3]) {
    let shape = SegmentShape::new(&SEGMENT, mask, log_sizes, P2Hash::default());
    let entry = State {
        registers: [0; 13],
        pc: 0,
        timestamp: 1,
        memory_root: [0; 32],
    };
    let leaf = LeafCircuit::new(shape, entry);
    let mut context = Context::<NoValue>::with_outputs(2);
    let wires = leaf.verify(&mut context, &LeafValues::blank(&leaf.shape));
    context.set_outputs(&wires.digest);
    let (blocks, singles, _) = leaf.shape.stark.deep.counts();
    let finalized = context.finalized_rows();
    (
        context,
        (leaf.shape.stark.deep.points.len(), blocks, singles),
        finalized,
    )
}

/// SplitMix64.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

/// The bound holds every leaf built: the window kernel's class-1 shape, the
/// full shape, and shapes of random chips and sizes; every piece's term the
/// built piece's rows, `p2` and `h8` exactly.
#[test]
fn the_bound_holds_the_built_leaves() {
    let window: [u32; 25] = [
        15, 14, 16, 18, 9, 8, 4, 17, 4, 4, 4, 16, 8, 16, 8, 8, 6, 0, 0, 8, 15, 15, 15, 15, 16,
    ];
    let mut shapes: Vec<(u32, [u32; 25])> = vec![
        (0x01f9_ffff, window),
        (chip_idx::ALL, window.map(|log| log.max(8))),
    ];
    // Every chip at one size, the lifting height's columns: no two-sample
    // column in a clean block.
    shapes.push((0x01f9_ffff, window.map(|log| if log == 0 { 0 } else { 12 })));
    let mut rng = Rng(0x1eaf);
    for _ in 0..6 {
        let mask = vos_pvm_compiler::shape::ALWAYS | (rng.next() as u32 & chip_idx::OPTIONAL);
        let sizes: [u32; 25] = core::array::from_fn(|_| 4 + (rng.next() % 15) as u32);
        shapes.push((mask, sizes));
    }
    for (mask, sizes) in shapes {
        let log_sizes: Vec<u32> = (0..25)
            .filter(|&c| mask & 1 << c != 0)
            .map(|c| sizes[c])
            .collect();
        let (context, plan, finalized) = built(mask, &log_sizes);
        let rows = context.rows();
        let record: [u8; 25] = core::array::from_fn(|c| {
            if mask & 1 << c != 0 {
                sizes[c] as u8
            } else {
                0
            }
        });
        let terms = leaf::leaf_terms(mask, &record);
        let bound = leaf::leaf_rows(mask, &record);
        eprintln!("{mask:#x}: built {rows:?}, finalized {finalized:?}, bound {bound:?}");
        assert_eq!(
            (terms.points, terms.blocks, terms.singles),
            plan,
            "{mask:#x}: DEEP's plan"
        );
        let pieces = context.piece_rows();
        let piece = |name: &str| pieces.get(name).copied().unwrap_or_default();
        let leaf_piece: [usize; 3] = core::array::from_fn(|c| {
            [
                "leaf: flags",
                "leaf: io-hash",
                "leaf: digests",
                "leaf: output",
            ]
            .iter()
            .map(|name| piece(name)[c])
            .sum()
        });
        for (name, term, built) in [
            ("channel", terms.channel, piece("channel")),
            ("pow", terms.pow, piece("pow")),
            ("queries", terms.queries, piece("queries")),
            ("circle", terms.circle, piece("circle")),
            ("merkle", terms.merkle, piece("merkle")),
            ("fri", terms.fri, piece("fri")),
            ("deep", terms.deep, piece("deep")),
            ("deep once", terms.deep_once, piece("deep once")),
            ("oods", terms.oods, piece("oods")),
            ("logup", terms.logup, piece("logup")),
            ("shape", terms.shape, piece("shape")),
            ("context", terms.context, piece("context")),
            ("leaf", terms.leaf, leaf_piece),
        ] {
            assert_eq!(term, built, "{mask:#x}: {name}");
        }
        assert_eq!(terms.rows(), rows, "{mask:#x}: the terms' rows");
        assert_eq!(bound[0], rows[0], "{mask:#x}: p2");
        assert_eq!(bound[2], rows[2], "{mask:#x}: h8");
        assert_eq!(bound[1], rows[1] + FINALIZE, "{mask:#x}: qm31");
        assert!(bound[1] >= finalized[1], "{mask:#x}: qm31 finalized");
        assert!(finalized[1] - rows[1] <= FINALIZE, "{mask:#x}: finalizing");
    }
}
