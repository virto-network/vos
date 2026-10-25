//! A kernel leaf's rows, from its shape alone (`proving.md` §3.3): a
//! derivation refuses a kernel whose leaf, for any class, would not fit the
//! recursion AIR's padded shape, 2^16 `p2`, 2^17 `qm31` and 2^16 `h8` rows.
//!
//! **A bound, without building the circuit.** The leaf is the in-AIR
//! verifier of a segment of the class (`vos_pvm_recair::verifier`) plus its own
//! work, and its rows follow from the shape by the verifier's structure:
//! - **the chips' AIR** ([`CHIPS`], [`RELATIONS`]): each chip's preprocessed
//!   columns, its main and interaction columns as runs of masks, the
//!   relations it draws, and its compiled OODS gates and constraints, none
//!   of which depend on its log size;
//! - **the shape's heights:** the lifting height `L`, the largest chip's
//!   log size plus the blowup's 2, and FRI's `L − 2` layers;
//! - **DEEP's plan,** as the circuit lays it: each column's samples, their
//!   points (the circle group's elements as indices modulo 2^31), and the
//!   clean blocks of eight leaf lanes an `h8` row takes;
//! - **the rest** of each piece's rows, a count per query or once.
//!
//! Every term is the circuit's own count but two, which bound it: a
//! relation's `α` powers, counted to its tuple's size, and the rows a
//! circuit's finalizing adds ([`FINALIZE`]). The prover's tests hold
//! the tables to the AIR and the bound to the built circuit, term by term,
//! on the window kernel's classes, the full shape and kernels of their own.
//!
//! The segment format the bound is for is 35's (`vos_pvm_proof::format`):
//! blowup 4, [`QUERIES`] queries, FRI at fold step 1.

use std::collections::{BTreeMap, BTreeSet};

use vos_wire::records::{SEGMENT_CHIPS, Shape};

/// A column's mask: the rows its constraints read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mask {
    /// The row alone.
    Current,
    /// The row and the next.
    Next,
    /// The previous row and the row.
    Previous,
}

/// A chip of the segment AIR, as its leaf reads it.
#[derive(Clone, Copy, Debug)]
pub struct Chip {
    /// Its preprocessed columns, at its log size.
    pub preprocessed: u16,
    /// Its main columns, as runs of one mask, in its order.
    pub main: &'static [(Mask, u16)],
    /// Its interaction columns.
    pub interaction: &'static [(Mask, u16)],
    /// Bit `r`: it draws relation `r` of [`RELATIONS`].
    pub relations: u32,
    /// The compiled rows that evaluate its constraints at the OODS point.
    pub gates: u32,
    pub constraints: u32,
}

use Mask::{Current, Next, Previous};

/// The statement header's words before its log sizes
/// (`vos_pvm_proof::proof::statement_header_words`): the domain's two, the
/// format, the PCS configuration's five, and no lifting height's one.
const HEADER_WORDS: usize = 9;

/// The transcript before the relations are drawn, past the header: the
/// preprocessed and main trees' roots, then the boundary states' 296
/// bytes, eight a word, 37 absorptions.
const ROOTS_AND_BOUNDARY: usize = 2 + 37;

/// The transcript between the claimed sums and the samples: the
/// interaction root mixed, the composition coefficient drawn, the
/// composition root mixed, the OODS point drawn.
const COMPOSITION_STEPS: usize = 4;

/// The DEEP coefficient's draw, after the samples.
const DEEP_COEFFICIENT: usize = 1;

/// FRI's last layer mixed, after its layers' roots and folding draws.
const LAST_LAYER: usize = 1;

/// The two proof-of-work checks: their rows, `[p2, qm31, h8]`.
const POW: [usize; 3] = [6, 246, 0];

/// The context's own constants' rows, `[p2, qm31, h8]`.
const CONTEXT: [usize; 3] = [0, 2, 0];

/// The segment AIR's relations, each its tuple's size.
pub const RELATIONS: [(&str, u32); 20] = [
    ("Range256", 1),
    ("MemoryAccess", 15),
    ("ProgramExecution", 12),
    ("BitwiseAnd", 3),
    ("PowerOfTwo", 9),
    ("Blake2bCall", 25),
    ("RegisterMemory", 18),
    ("ProgramMemory", 37),
    ("JumpTable", 8),
    ("Popcount", 2),
    ("Bitcount", 3),
    ("Multiplication", 35),
    ("Bitwise", 30),
    ("Compare", 17),
    ("DivRem", 41),
    ("ByteToBits", 9),
    ("WitnessCall", 13),
    ("BitwiseAndByte", 3),
    ("Blake2bCompression", 265),
    ("MerkleNode", 66),
];

/// The segment AIR's chips, in its order (`vos_wire::records::segment_chip`).
pub const CHIPS: [Chip; SEGMENT_CHIPS] = [
    // CPU
    Chip {
        preprocessed: 0,
        main: &[(Current, 56), (Next, 1), (Current, 523)],
        interaction: &[(Current, 188), (Previous, 4)],
        relations: 0x1ffff,
        gates: 2850,
        constraints: 815,
    },
    // BLAKE2B
    Chip {
        preprocessed: 44,
        main: &[
            (Current, 168),
            (Next, 209),
            (Current, 16),
            (Next, 128),
            (Current, 192),
            (Next, 16),
            (Current, 778),
            (Next, 1),
            (Current, 236),
        ],
        interaction: &[(Current, 1340), (Previous, 4)],
        relations: 0x20023,
        gates: 12307,
        constraints: 2043,
    },
    // BLAKE2B_BOUNDARY
    Chip {
        preprocessed: 43,
        main: &[
            (Current, 168),
            (Next, 209),
            (Current, 16),
            (Next, 128),
            (Current, 192),
            (Next, 1),
            (Current, 237),
        ],
        interaction: &[(Current, 432), (Previous, 4)],
        relations: 0x60001,
        gates: 5341,
        constraints: 1022,
    },
    // MEMORY
    Chip {
        preprocessed: 0,
        main: &[
            (Next, 4),
            (Current, 1),
            (Next, 10),
            (Current, 1),
            (Next, 1),
            (Current, 30),
            (Next, 1),
            (Current, 2),
            (Next, 3),
            (Current, 1),
        ],
        interaction: &[(Previous, 4)],
        relations: 0x00002,
        gates: 202,
        constraints: 66,
    },
    // MEMORY_PAGE
    Chip {
        preprocessed: 21,
        main: &[
            (Current, 256),
            (Next, 128),
            (Current, 136),
            (Next, 21),
            (Current, 49),
        ],
        interaction: &[(Current, 516), (Previous, 4)],
        relations: 0xc0002,
        gates: 4876,
        constraints: 480,
    },
    // MEMORY_MERKLE
    Chip {
        preprocessed: 0,
        main: &[(Current, 268)],
        interaction: &[(Current, 8), (Previous, 4)],
        relations: 0xc0000,
        gates: 709,
        constraints: 80,
    },
    // MEMORY_ROOT_BOUNDARY
    Chip {
        preprocessed: 0,
        main: &[(Current, 65)],
        interaction: &[(Previous, 4)],
        relations: 0x80000,
        gates: 76,
        constraints: 2,
    },
    // REGISTER_MEMORY
    Chip {
        preprocessed: 0,
        main: &[
            (Next, 1),
            (Current, 8),
            (Next, 17),
            (Current, 1),
            (Next, 1),
            (Current, 31),
        ],
        interaction: &[(Previous, 4)],
        relations: 0x00040,
        gates: 191,
        constraints: 64,
    },
    // REGISTER_MEMORY_BOUNDARY
    Chip {
        preprocessed: 0,
        main: &[(Current, 10)],
        interaction: &[(Previous, 4)],
        relations: 0x00040,
        gates: 19,
        constraints: 1,
    },
    // REGISTER_MEMORY_CLOSING
    Chip {
        preprocessed: 0,
        main: &[(Current, 18)],
        interaction: &[(Previous, 4)],
        relations: 0x00040,
        gates: 26,
        constraints: 1,
    },
    // PROGRAM_BOUNDARY
    Chip {
        preprocessed: 0,
        main: &[(Current, 25)],
        interaction: &[(Previous, 4)],
        relations: 0x00004,
        gates: 37,
        constraints: 1,
    },
    // PROGRAM_MEMORY
    Chip {
        preprocessed: 38,
        main: &[(Current, 1)],
        interaction: &[(Previous, 4)],
        relations: 0x00080,
        gates: 48,
        constraints: 2,
    },
    // JUMP_TABLE
    Chip {
        preprocessed: 9,
        main: &[(Current, 1)],
        interaction: &[(Previous, 4)],
        relations: 0x00100,
        gates: 19,
        constraints: 2,
    },
    // WITNESS_INPUT
    Chip {
        preprocessed: 0,
        main: &[
            (Next, 2),
            (Current, 2),
            (Next, 13),
            (Current, 1),
            (Next, 1),
            (Current, 3),
        ],
        interaction: &[(Current, 12), (Previous, 4)],
        relations: 0x10003,
        gates: 126,
        constraints: 31,
    },
    // RANGE_MULTIPLICITY_256
    Chip {
        preprocessed: 1,
        main: &[(Current, 1)],
        interaction: &[(Previous, 4)],
        relations: 0x00001,
        gates: 10,
        constraints: 1,
    },
    // BITWISE_LOOKUP
    Chip {
        preprocessed: 3,
        main: &[(Current, 1)],
        interaction: &[(Previous, 4)],
        relations: 0x00008,
        gates: 12,
        constraints: 1,
    },
    // POWER_OF_TWO
    Chip {
        preprocessed: 9,
        main: &[(Current, 1)],
        interaction: &[(Previous, 4)],
        relations: 0x00010,
        gates: 18,
        constraints: 1,
    },
    // POPCOUNT
    Chip {
        preprocessed: 2,
        main: &[(Current, 1)],
        interaction: &[(Previous, 4)],
        relations: 0x00200,
        gates: 11,
        constraints: 1,
    },
    // BITCOUNT
    Chip {
        preprocessed: 3,
        main: &[(Current, 1)],
        interaction: &[(Previous, 4)],
        relations: 0x00400,
        gates: 12,
        constraints: 1,
    },
    // BYTE_TO_BITS
    Chip {
        preprocessed: 9,
        main: &[(Current, 1)],
        interaction: &[(Previous, 4)],
        relations: 0x08000,
        gates: 18,
        constraints: 1,
    },
    // MUL
    Chip {
        preprocessed: 0,
        main: &[(Current, 162)],
        interaction: &[(Current, 128), (Previous, 4)],
        relations: 0x00801,
        gates: 830,
        constraints: 191,
    },
    // BITWISE
    Chip {
        preprocessed: 0,
        main: &[(Current, 63)],
        interaction: &[(Current, 32), (Previous, 4)],
        relations: 0x01008,
        gates: 353,
        constraints: 66,
    },
    // COMPARE
    Chip {
        preprocessed: 0,
        main: &[(Current, 34)],
        interaction: &[(Current, 16), (Previous, 4)],
        relations: 0x02001,
        gates: 141,
        constraints: 24,
    },
    // DIVREM
    Chip {
        preprocessed: 0,
        main: &[(Current, 213)],
        interaction: &[(Current, 192), (Previous, 4)],
        relations: 0x04001,
        gates: 1199,
        constraints: 279,
    },
    // BITWISE_AND_BYTE
    Chip {
        preprocessed: 3,
        main: &[(Current, 1)],
        interaction: &[(Previous, 4)],
        relations: 0x20000,
        gates: 12,
        constraints: 1,
    },
];

/// The queries a segment's proof opens.
pub const QUERIES: usize = 40;

/// The blowup's log.
const LOG_BLOWUP: u32 = 2;

/// The recursion AIR's padded shape: `p2`, `qm31` and `h8` rows.
pub const PADDED: [usize; 3] = [1 << 16, 1 << 17, 1 << 16];

/// The `qm31` rows a leaf's finalizing adds, bounded: its constants, each
/// at most two rows, and its guesses no operand yields, an identity row
/// each. The leaves built add 30 to 120.
pub const FINALIZE: usize = 512;

/// The `p2` and `qm31` rows of the leaf's own work: the state digests and
/// the output's hash; the flags, the io-hash's range checks and limbs, the
/// outputs.
const LEAF_WORK: [usize; 2] = [2 * 19 + 7, 85 + 448 + 2];

/// The boundary chips' public logup terms over the boundary states.
const BOUNDARY_TERMS: usize = 644;

/// The `qm31` rows of a query's domain point (recair's
/// `verifier::circle::domain_point`) at `log_size`: two for the bit above
/// the first, four for each bit after it, one to conjugate on the first.
/// A circle domain has at least four points: `log_size` is at least 2.
const fn domain_point_rows(log_size: usize) -> usize {
    debug_assert!(log_size >= 2, "a circle domain of at least four points");
    2 + 4 * (log_size - 2) + 1
}

/// The `qm31` rows of a query's FRI folds (recair's
/// `verifier::fri::verify_query`) over `layers`: in each layer the
/// twiddle's inverse, the pair's difference, its scaling, their sum and the
/// fold; and the query point's `x` doubled in each layer past the second.
/// A segment's FRI has at least two layers: `layers` is at least 2.
const fn fri_fold_rows(layers: usize) -> usize {
    debug_assert!(layers >= 2, "at least two FRI layers");
    5 * layers + (layers - 2)
}

/// The `qm31` rows of the OODS piece beside the compiled constraints and
/// the two doubling chains (recair's `verifier::circle::random_point` and
/// `verifier::oods::check`): the OODS point from its draw (4), the shift
/// onto the canonic coset (2), the vanishing inverse (1), the sampled
/// composition's two halves (3 each), their sum (1) and the product checked
/// against it (1).
const OODS_ROWS: usize = 4 + 2 + 1 + 2 * 3 + 1 + 1;

/// The `qm31` rows the shape piece checks beside the header's words, one a
/// word (recair's `verifier::segment`): the preprocessed root's two.
const PREPROCESSED_ROOT_WORDS: usize = 2;

/// The rows of a sum of `n` wires: three terms a first row, two each next.
fn linear_rows(n: usize) -> usize {
    1 + n.saturating_sub(3).div_ceil(2)
}

/// A column of a tree: its log size on the evaluation domain and its
/// mask.
#[derive(Clone, Copy)]
struct Column {
    log_size: u32,
    mask: Mask,
}

/// The circle group's elements as indices modulo 2^31: the generator of
/// the subgroup of order 2^n is 2^(31 − n).
const GROUP: u64 = 1 << 31;

fn generator(log_size: u32) -> u64 {
    1 << (31 - log_size)
}

/// A column's samples' points, in the order the proof samples them: a mask
/// offset is a step of the lifted trace's domain, of the largest chip's log
/// size, `lifting − 2`; two offsets take the periodicity sample first, at
/// the second offset's point plus the column's period, the lifting step
/// doubled its log size times.
fn sample_points(column: Column, lifting: u32) -> Vec<u64> {
    let step = generator(lifting - LOG_BLOWUP);
    let offsets = match column.mask {
        Current => return vec![0],
        Next => [0, step],
        Previous => [GROUP - step, 0],
    };
    let period = (generator(lifting) << column.log_size) % GROUP;
    vec![(offsets[1] + period) % GROUP, offsets[0], offsets[1]]
}

/// DEEP's per-query rows and its once rows: the samples' points, the clean
/// blocks, the single samples, and the `α` powers the chains read.
struct Deep {
    points: usize,
    blocks: usize,
    singles: usize,
    once: usize,
}

/// A sample: its point and its exponent.
type Sample = (u64, usize);

/// Each column's samples, numbered across the trees.
type Samples = Vec<Vec<Vec<Sample>>>;

/// A point's items, `(low, high, step)`: clean blocks, then singles.
type Items = BTreeMap<u64, Vec<(usize, usize, usize)>>;

fn deep(trees: &[Vec<Column>; 4], lifting: u32) -> Deep {
    let samples = numbered_samples(trees, lifting);
    let mut by_point: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
    for &(point, exponent) in samples.iter().flatten().flatten() {
        by_point.entry(point).or_default().push(exponent);
    }
    let (mut items, taken, blocks) = clean_blocks(trees, &samples, &by_point);
    let mut singles = 0;
    for (tree, columns) in samples.iter().enumerate() {
        for (column, column_samples) in columns.iter().enumerate() {
            for &(point, exponent) in column_samples {
                if !taken.contains(&(tree, column, point)) {
                    singles += 1;
                    items
                        .entry(point)
                        .or_default()
                        .push((exponent, exponent, 0));
                }
            }
        }
    }
    Deep {
        points: by_point.len(),
        blocks,
        singles,
        once: once_rows(&by_point, &mut items),
    }
}

/// Each column's samples, numbered across the trees in their order.
fn numbered_samples(trees: &[Vec<Column>; 4], lifting: u32) -> Samples {
    let mut exponent = 0;
    trees
        .iter()
        .map(|tree| {
            tree.iter()
                .map(|&column| {
                    sample_points(column, lifting)
                        .into_iter()
                        .map(|point| {
                            exponent += 1;
                            (point, exponent - 1)
                        })
                        .collect()
                })
                .collect()
        })
        .collect()
}

/// The clean blocks of eight lanes, a tree's columns in log-size order:
/// at a point, each lane's one sample there, their exponents a step apart
/// and no other sample of the point between them. Their items, the
/// `(tree, column, point)`s they take, and their count.
fn clean_blocks(
    trees: &[Vec<Column>; 4],
    samples: &Samples,
    by_point: &BTreeMap<u64, Vec<usize>>,
) -> (Items, BTreeSet<(usize, usize, u64)>, usize) {
    let mut items: Items = BTreeMap::new();
    let mut taken: BTreeSet<(usize, usize, u64)> = BTreeSet::new();
    let orders: Vec<Vec<usize>> = trees
        .iter()
        .map(|tree| {
            let mut order: Vec<usize> = (0..tree.len()).collect();
            order.sort_by_key(|&column| tree[column].log_size);
            order
        })
        .collect();
    let mut blocks = 0;
    for (tree, order) in orders.iter().enumerate() {
        for lanes in order.chunks_exact(8) {
            for (&point, exponents) in by_point {
                let at: Option<Vec<usize>> = lanes
                    .iter()
                    .map(|&column| {
                        let mut at = samples[tree][column]
                            .iter()
                            .filter(|sample| sample.0 == point);
                        match (at.next(), at.next()) {
                            (Some(sample), None) => Some(sample.1),
                            _ => None,
                        }
                    })
                    .collect();
                let Some(at) = at else { continue };
                let (low, high) = (at[0], at[7]);
                let Some(step) = at[1].checked_sub(low).filter(|&step| step > 0) else {
                    continue;
                };
                let stepped = at
                    .iter()
                    .enumerate()
                    .all(|(j, &exponent)| exponent == low + j * step);
                let alone = exponents
                    .iter()
                    .filter(|&&exponent| (low..=high).contains(&exponent))
                    .count()
                    == 8;
                if stepped && alone {
                    blocks += 1;
                    items.entry(point).or_default().push((low, high, step));
                    for &column in lanes {
                        taken.insert((tree, column, point));
                    }
                }
            }
        }
    }
    (items, taken, blocks)
}

/// DEEP's once rows: the powers of `α` the chains and the constants read,
/// as `vos_pvm_recair::verifier::deep::prepare` takes them, and each
/// point's own.
fn once_rows(by_point: &BTreeMap<u64, Vec<usize>>, items: &mut Items) -> usize {
    let (mut powers, mut conjugates) = (BTreeSet::new(), BTreeSet::new());
    let mut point_rows = 0;
    for (point, exponents) in by_point {
        let mut exponents = exponents.clone();
        exponents.sort_unstable_by(|a, b| b.cmp(a));
        for pair in exponents.windows(2) {
            powers.insert(pair[0] - pair[1]);
            conjugates.insert(pair[0] - pair[1]);
        }
        let lowest = *exponents.last().expect("a sample");
        powers.insert(lowest);
        conjugates.insert(lowest);
        let point_items = items.get_mut(point).expect("a point's items");
        point_items.sort_unstable_by(|a, b| b.1.cmp(&a.1));
        for pair in point_items.windows(2) {
            powers.insert(pair[0].0 - pair[1].0);
        }
        for &(_, _, step) in point_items.iter() {
            if step > 0 {
                powers.insert(step);
            }
        }
        // The point, its coordinates' parts, its constants and the two
        // chains over its samples.
        point_rows += 13 + 2 * exponents.len() + 3 * usize::from(lowest > 0);
    }
    powers.remove(&0);
    conjugates.remove(&0);
    let squarings = powers.last().map_or(0, |&max: &usize| max.ilog2() as usize);
    let products: usize = powers
        .iter()
        .map(|&power: &usize| power.count_ones() as usize - 1)
        .sum();
    squarings + products + conjugates.len() + point_rows
}

/// A leaf's rows by the verifier's pieces, as `vos_pvm_recair`'s context counts
/// them (`Context::piece`): `[p2, qm31, h8]` each.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Terms {
    /// The transcript's absorptions and draws.
    pub channel: [usize; 3],
    /// The two PoW checks, their nonces' limbs.
    pub pow: [usize; 3],
    /// The queries' draws and their bits.
    pub queries: [usize; 3],
    /// The queries' domain points.
    pub circle: [usize; 3],
    /// The four trees' openings.
    pub merkle: [usize; 3],
    /// FRI's layers.
    pub fri: [usize; 3],
    /// DEEP's quotients a query, and its constants once.
    pub deep: [usize; 3],
    pub deep_once: [usize; 3],
    /// The compiled constraints and the composition check.
    pub oods: [usize; 3],
    /// The logup sums and the boundary chips' public terms.
    pub logup: [usize; 3],
    /// The header and the preprocessed root against the shape's.
    pub shape: [usize; 3],
    /// The context's own constants' rows, and the leaf's own work.
    pub context: [usize; 3],
    pub leaf: [usize; 3],
    /// DEEP's sample points, and a query's blocks and single samples.
    pub points: usize,
    pub blocks: usize,
    pub singles: usize,
}

impl Terms {
    /// The rows before finalizing.
    pub fn rows(&self) -> [usize; 3] {
        let terms = [
            self.channel,
            self.pow,
            self.queries,
            self.circle,
            self.merkle,
            self.fri,
            self.deep,
            self.deep_once,
            self.oods,
            self.logup,
            self.shape,
            self.context,
            self.leaf,
        ];
        core::array::from_fn(|component| terms.iter().map(|term| term[component]).sum())
    }
}

/// The terms of the leaf of a segment over `chips` at `log_sizes` (chip
/// `i`'s log size, 0 for a chip outside the shape).
///
/// # Panics
/// When `chips` names a chip outside the segment AIR or a chip of it has no
/// log size.
pub fn leaf_terms(chips: u32, log_sizes: &[u8; SEGMENT_CHIPS]) -> Terms {
    assert_eq!(chips >> SEGMENT_CHIPS, 0, "chips of the segment AIR");
    let active: Vec<(usize, u32)> = (0..SEGMENT_CHIPS)
        .filter(|&chip| chips & 1 << chip != 0)
        .map(|chip| {
            assert_ne!(log_sizes[chip], 0, "a log size a chip");
            (chip, u32::from(log_sizes[chip]))
        })
        .collect();
    let n = active.len();
    let max_log = active.iter().map(|&(_, log)| log).max().expect("a chip");
    let lifting = max_log + LOG_BLOWUP;
    let fri_layers = max_log as usize;

    let expand = |runs: &[(Mask, u16)], trace_log_size: u32| -> Vec<Column> {
        runs.iter()
            .flat_map(|&(mask, count)| {
                (0..count).map(move |_| Column {
                    log_size: trace_log_size + LOG_BLOWUP,
                    mask,
                })
            })
            .collect()
    };
    let mut trees: [Vec<Column>; 4] = Default::default();
    for &(chip, log) in &active {
        let air = &CHIPS[chip];
        trees[0].extend(expand(&[(Current, air.preprocessed)], log));
        trees[1].extend(expand(air.main, log));
        trees[2].extend(expand(air.interaction, log));
    }
    trees[3] = expand(&[(Current, 8)], lifting - LOG_BLOWUP);
    let samples: usize = trees
        .iter()
        .flatten()
        .map(|column| sample_points(*column, lifting).len().min(2))
        .sum();
    let relations = active
        .iter()
        .fold(0u32, |drawn, &(chip, _)| drawn | CHIPS[chip].relations);
    let preprocessed_height = trees[0]
        .iter()
        .map(|column| column.log_size)
        .max()
        .expect("a preprocessed column") as usize;
    let deep = deep(&trees, lifting);
    let lifting = lifting as usize;
    let q = QUERIES;
    let header = HEADER_WORDS + n;

    let leaves: usize = trees.iter().map(|tree| (tree.len() + 1).div_ceil(8)).sum();
    let paths = preprocessed_height + 3 * lifting;
    let fri: usize = (0..fri_layers).map(|layer| 3 + lifting - 1 - layer).sum();
    let channel = header
        + ROOTS_AND_BOUNDARY
        + relations.count_ones() as usize
        + n.div_ceil(2)
        + COMPOSITION_STEPS
        + samples.div_ceil(2)
        + DEEP_COEFFICIENT
        + 2 * fri_layers
        + LAST_LAYER;
    let sum = |field: fn(&Chip) -> u32| -> usize {
        active
            .iter()
            .map(|&(chip, _)| field(&CHIPS[chip]) as usize)
            .sum()
    };
    let powers: usize = RELATIONS
        .iter()
        .enumerate()
        .filter(|&(r, _)| relations & 1 << r != 0)
        .map(|(_, &(_, size))| (size as usize).saturating_sub(2))
        .sum();
    Terms {
        channel: [channel, 0, 0],
        pow: POW,
        queries: [q.div_ceil(8), 64 * q, 0],
        circle: [0, domain_point_rows(lifting) * q, 0],
        merkle: [(leaves + paths) * q, 0, 0],
        fri: [fri * q, fri_fold_rows(fri_layers) * q, 0],
        deep: [0, (deep.singles + 6 * deep.points) * q, deep.blocks * q],
        deep_once: [0, deep.once, 0],
        oods: [
            0,
            sum(|chip| chip.gates) + powers + sum(|chip| chip.constraints) - 1
                + 2 * (max_log as usize - 1)
                + OODS_ROWS,
            0,
        ],
        logup: [0, linear_rows(n) + BOUNDARY_TERMS, 0],
        shape: [0, header + PREPROCESSED_ROOT_WORDS, 0],
        context: CONTEXT,
        leaf: [LEAF_WORK[0], LEAF_WORK[1], 0],
        points: deep.points,
        blocks: deep.blocks,
        singles: deep.singles,
    }
}

/// The rows of the leaf of a segment over `chips` at `log_sizes`: `p2`,
/// `qm31`, `h8`, at least the leaf circuit's once finalized.
///
/// # Panics
/// As [`leaf_terms`].
pub fn leaf_rows(chips: u32, log_sizes: &[u8; SEGMENT_CHIPS]) -> [usize; 3] {
    let [p2, qm31, h8] = leaf_terms(chips, log_sizes).rows();
    [p2, qm31 + FINALIZE, h8]
}

/// Each class of `shape` whose leaf would not fit the padded shape, with
/// its rows.
pub(crate) fn oversized_leaves(shape: &Shape) -> Vec<(usize, [usize; 3])> {
    shape
        .classes
        .iter()
        .enumerate()
        .map(|(class, sizes)| (class, leaf_rows(shape.chips, &sizes.log_sizes)))
        .filter(|(_, rows)| rows.iter().zip(PADDED).any(|(&rows, padded)| rows > padded))
        .collect()
}

#[cfg(test)]
mod tests {
    use vos_wire::records::SegmentClass;

    use super::*;

    /// The window kernel's class-1 shape (`0x01f9ffff`).
    fn window() -> Shape {
        let sizes = [
            15, 14, 16, 18, 9, 8, 4, 17, 4, 4, 4, 16, 8, 16, 8, 8, 6, 0, 0, 8, 15, 15, 15, 15, 16,
        ];
        Shape {
            policy: crate::shape::POLICY,
            chips: 0x01f9_ffff,
            classes: vec![SegmentClass {
                log_steps: 15,
                pages: 8,
                log_sizes: sizes,
            }],
        }
    }

    /// The window kernel's class-1 leaf, as `vos_pvm_recair` builds it: its rows
    /// by piece, its DEEP plan's 16 points, and the finalizing's allowance.
    #[test]
    fn the_window_kernels_leaf_is_counted() {
        let shape = window();
        let terms = leaf_terms(shape.chips, &shape.classes[0].log_sizes);
        assert_eq!(
            (terms.points, terms.blocks, terms.singles),
            (16, 1_150, 785)
        );
        assert_eq!(terms.merkle[0], 40 * (1_004 + 78));
        assert_eq!(terms.fri, [40 * 243, 40 * 106, 0]);
        assert_eq!(terms.oods[1], 35_216);
        assert_eq!(terms.deep_once[1], 20_445);
        assert_eq!(terms.rows(), [57_700, 102_173, 46_000]);
        assert_eq!(
            leaf_rows(shape.chips, &shape.classes[0].log_sizes),
            [57_700, 102_173 + FINALIZE, 46_000]
        );
        assert!(oversized_leaves(&shape).is_empty());
    }

    /// A class whose every chip has one log size is refused, named with its
    /// rows: every column is at the lifting height, where a column's
    /// periodicity sample falls on its second sample's point, so no
    /// two-sample column is in a clean block and DEEP takes their samples
    /// one row each, past 2^17 `qm31` rows.
    #[test]
    fn a_class_of_one_size_is_refused() {
        let mut shape = window();
        let mut flat = shape.classes[0];
        flat.log_sizes = flat.log_sizes.map(|size| if size == 0 { 0 } else { 12 });
        shape.classes.push(flat);
        let rows = leaf_rows(shape.chips, &flat.log_sizes);
        assert!(rows[1] > PADDED[1], "{rows:?}");
        assert_eq!(oversized_leaves(&shape), vec![(1, rows)]);
        let terms = leaf_terms(shape.chips, &flat.log_sizes);
        assert!(terms.singles > 2 * 785, "{} single samples", terms.singles);
    }
}
