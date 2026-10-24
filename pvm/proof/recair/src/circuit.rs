//! A circuit: the components' wiring, which the preprocessed columns hold,
//! and its static check (`vos_pvm_recair_air::gate`).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;

use num_traits::Zero;
use stwo::core::fields::m31::{BaseField, P};
use vos_pvm_recair_air::gate::Layout;
use vos_pvm_recair_air::p2::P2Mode;

use crate::value::{Value, embed};

/// An operand's entry in the `Gate` relation. A multiplicity of zero leaves
/// the relation untouched, whatever the address.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Entry {
    pub address: u32,
    pub multiplicity: i64,
}

impl Entry {
    /// No entry: a free operand.
    pub const FREE: Self = Self {
        address: 0,
        multiplicity: 0,
    };
}

/// A `p2` row's wiring; `mode` is `None` on a padding row.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct P2Wiring {
    pub mode: Option<P2Mode>,
    pub act: [BaseField; 8],
    pub c: [BaseField; 10],
    /// The message's two wires.
    pub m: [Entry; 2],
    /// The output's first wire's address; the second's is the next.
    pub out_address: u32,
    pub out_multiplicity: [i64; 2],
    /// The bit's address, a use in node rows.
    pub bit_address: u32,
}

impl P2Wiring {
    /// The lanes of message slot `w` its `act` absorbs.
    pub fn absorbed(&self, w: usize) -> [bool; 4] {
        core::array::from_fn(|j| !self.act[4 * w + j].is_zero())
    }
}

/// The QM31 gate's coefficients:
/// `out = k_m·a·b + k_p·(a⊙b) + k_a·a + k_b·b + k_c·c + Σ_j λ_j·c_j`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Qm31Op {
    pub k_m: BaseField,
    pub k_p: BaseField,
    pub k_a: BaseField,
    pub k_b: BaseField,
    pub k_c: BaseField,
    pub lanes: [BaseField; 4],
}

impl Qm31Op {
    /// The gate's output over `a`, `b` and `c`.
    pub fn apply<V: Value>(&self, a: V, b: V, c: V) -> V {
        let k = |k: BaseField| V::from_qm31(embed(k));
        k(self.k_m) * a * b
            + k(self.k_p) * a.pointwise_mul(b)
            + k(self.k_a) * a
            + k(self.k_b) * b
            + k(self.k_c) * c
            + c.lane_sum(self.lanes)
    }

    /// The lanes the gate reads of operand `i` (`a`, `b`, `c`): every lane
    /// under a product or the operand's own coefficient, lane `j` of `c`
    /// under `λ_j`.
    pub fn reads(&self, i: usize) -> [bool; 4] {
        let product = i < 2 && !(self.k_m.is_zero() && self.k_p.is_zero());
        let own = ![self.k_a, self.k_b, self.k_c][i].is_zero();
        if product || own {
            [true; 4]
        } else if i == 2 {
            self.lanes.map(|lane| !lane.is_zero())
        } else {
            [false; 4]
        }
    }
}

/// A `qm31` row's wiring.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Qm31Wiring {
    pub op: Qm31Op,
    /// `a`, `b`, `c` and `out`.
    pub operands: [Entry; 4],
}

/// An `h8` row's wiring: its five inputs' addresses (`acc`, `σ`, `μ`, the two
/// sample wires), each a use, and its output.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct H8Wiring {
    pub inputs: [u32; 5],
    pub out: Entry,
}

/// A circuit's wiring, padded to its components' sizes, and where its
/// reserved wires sit: its outputs and `u`, the public uses.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Circuit {
    pub p2: Vec<P2Wiring>,
    pub qm31: Vec<Qm31Wiring>,
    pub h8: Vec<H8Wiring>,
    pub layout: Layout,
}

/// Why a circuit's wiring is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WiringError {
    /// A component's rows are not a power of two of at least 16.
    Size {
        component: &'static str,
        rows: usize,
    },
    /// A chained `p2` row in row 0, whose predecessor is the last row.
    ChainedFirstRow,
    /// An address at or beyond `p`, or an output pair past it.
    Address(u64),
    /// An address yielded more than once.
    YieldedTwice { address: u32 },
    /// An address used, but yielded nowhere.
    NotYielded { address: u32 },
    /// An address whose yield does not count its uses.
    Unbalanced { address: u32, total: i64 },
    /// The absolute multiplicities sum to `p` or more.
    TotalMultiplicity(u128),
    /// A `qm31` row reads an operand that is no wire (address 0,
    /// multiplicity 0): a value no other operand sees, injected into the
    /// gate.
    FreeOperandRead { row: usize, operand: usize },
    /// A `p2` row other than a node absorbs a lane of a message that is no
    /// wire: only a Merkle sibling is free.
    FreeMessageAbsorbed { row: usize },
    /// An operand reads a lane of a wire that every `p2` row absorbing it
    /// leaves unread and no gate computes: a lane the prover chooses.
    UnreadLaneRead { address: u32, lane: usize },
}

impl fmt::Display for WiringError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Size { component, rows } => {
                write!(
                    f,
                    "{component} has {rows} rows, not a power of two of at least 16"
                )
            }
            Self::ChainedFirstRow => write!(f, "a chained p2 row is row 0"),
            Self::Address(address) => write!(f, "address {address} is not below p"),
            Self::YieldedTwice { address } => write!(f, "address {address} is yielded twice"),
            Self::NotYielded { address } => write!(f, "address {address} is used but not yielded"),
            Self::Unbalanced { address, total } => {
                write!(f, "address {address}'s multiplicities sum to {total}")
            }
            Self::TotalMultiplicity(total) => {
                write!(
                    f,
                    "the multiplicities' absolute values sum to {total}, not below p"
                )
            }
            Self::FreeOperandRead { row, operand } => {
                write!(f, "qm31 row {row} reads its free operand {operand}")
            }
            Self::FreeMessageAbsorbed { row } => {
                write!(f, "p2 row {row} absorbs a free message outside a node")
            }
            Self::UnreadLaneRead { address, lane } => {
                write!(
                    f,
                    "lane {lane} of address {address} is read, which no row absorbs and no gate computes"
                )
            }
        }
    }
}

impl std::error::Error for WiringError {}

/// What the check counted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WiringStats {
    /// The addresses some entry touches.
    pub addresses: usize,
    /// The sum of the absolute multiplicities, the public uses among them.
    pub total_multiplicity: u64,
}

/// The least rows a component has: one SIMD vector.
pub const MIN_ROWS: usize = 16;

/// What [`Circuit::lane_census`] counts.
struct LaneCensus {
    absorbed: HashMap<u32, [bool; 4]>,
    partial: HashSet<u32>,
    computed: HashSet<u32>,
}

impl Circuit {
    /// The components' log sizes.
    pub fn log_sizes(&self) -> [u32; 3] {
        [self.p2.len(), self.qm31.len(), self.h8.len()].map(|rows| rows.ilog2())
    }

    /// Every entry of the relation: each operand's, and the public uses.
    pub fn entries(&self) -> impl Iterator<Item = Entry> + '_ {
        let p2 = self.p2.iter().flat_map(|row| {
            [
                row.m[0],
                row.m[1],
                Entry {
                    address: row.out_address,
                    multiplicity: row.out_multiplicity[0],
                },
                Entry {
                    address: row.out_address.wrapping_add(1),
                    multiplicity: row.out_multiplicity[1],
                },
                Entry {
                    address: row.bit_address,
                    multiplicity: i64::from(row.mode == Some(P2Mode::Node)),
                },
            ]
        });
        let qm31 = self.qm31.iter().flat_map(|row| row.operands);
        let h8 = self.h8.iter().flat_map(|row| {
            row.inputs
                .map(|address| Entry {
                    address,
                    multiplicity: 1,
                })
                .into_iter()
                .chain([row.out])
        });
        let layout = self.layout;
        let public = core::iter::once(layout.u())
            .chain((0..layout.n_outputs).map(move |i| layout.output(i)))
            .map(|address| Entry {
                address,
                multiplicity: 1,
            });
        p2.chain(qm31).chain(h8).chain(public)
    }

    /// The static check of `vos_pvm_recair_air::gate`: every component a power of
    /// two of at least [`MIN_ROWS`] rows, no chained first row, every address
    /// below `p`, every used address yielded exactly once with the
    /// multiplicity of its uses, and the absolute multiplicities' sum below
    /// `p`; and every read bound (`check_reads`).
    pub fn check_wiring(&self) -> Result<WiringStats, WiringError> {
        let stats = self.check_relation()?;
        self.check_reads()?;
        Ok(stats)
    }

    /// Every value a gate reads is a wire's, or a lane some row absorbs:
    /// - no `qm31` row reads an operand that is no wire (multiplicity 0, at
    ///   address 0 or at an address another entry holds), under a
    ///   coefficient or a lane;
    /// - no `p2` row but a node (whose free message is a Merkle sibling)
    ///   absorbs a lane of a message that is no wire;
    /// - no operand reads a lane of a wire that every `p2` row absorbing it
    ///   leaves unread and that no gate computes: such a lane is the
    ///   prover's, held at no value by the relation or a constraint.
    ///
    /// A wire some gate yields with no use (multiplicity 0 at its own
    /// address) is a guess read once, and stays admitted.
    fn check_reads(&self) -> Result<(), WiringError> {
        // A read with no multiplicity is a guess read once only at an
        // address no wire holds; at a wire's (the free slots' address 0
        // among them, the zero wire's), it is a value the relation does not
        // tie to that wire. Entries with no multiplicity hold no address: a
        // `p2` row whose output no gate uses states address 0 and 1.
        let wires: HashSet<u32> = self
            .entries()
            .filter(|entry| entry.multiplicity != 0)
            .map(|entry| entry.address)
            .collect();
        let free = |entry: &Entry| {
            entry.multiplicity == 0 && (entry.address == 0 || wires.contains(&entry.address))
        };
        for (row, wiring) in self.qm31.iter().enumerate() {
            for (operand, entry) in wiring.operands[..3].iter().enumerate() {
                if free(entry) && wiring.op.reads(operand).contains(&true) {
                    return Err(WiringError::FreeOperandRead { row, operand });
                }
            }
        }
        for (row, wiring) in self.p2.iter().enumerate() {
            let node = wiring.mode == Some(P2Mode::Node);
            let absorbs_free =
                (0..2).any(|w| free(&wiring.m[w]) && wiring.absorbed(w).contains(&true));
            if wiring.mode.is_some() && !node && absorbs_free {
                return Err(WiringError::FreeMessageAbsorbed { row });
            }
        }
        if let Some((address, lane)) = self.unread_lane_reads().first() {
            return Err(WiringError::UnreadLaneRead {
                address: *address,
                lane: *lane,
            });
        }
        Ok(())
    }

    /// Each read of a lane of a wire that every `p2` row absorbing it leaves
    /// unread, the wire computed by no gate: its address and lane.
    ///
    /// A lane is absorbed by a message slot whose `act` reads it, or by a
    /// node row, which reads its whole message. A wire is computed when some
    /// gate's output is at its address, a yield or a use. Readers: a `qm31`
    /// operand ([`Qm31Op::reads`]); an `h8` input, whole; a node's bit, its
    /// lane 0; a public use, whole.
    pub fn unread_lane_reads(&self) -> Vec<(u32, usize)> {
        let LaneCensus {
            absorbed,
            partial,
            computed,
        } = self.lane_census();
        if partial.iter().all(|address| computed.contains(address)) {
            return Vec::new();
        }

        let mut reads = Vec::new();
        let mut read = |entry: Entry, lanes: [bool; 4]| {
            if entry.multiplicity == 0
                || !partial.contains(&entry.address)
                || computed.contains(&entry.address)
            {
                return;
            }
            let all = absorbed[&entry.address];
            reads.extend(
                (0..4)
                    .filter(|&j| lanes[j] && !all[j])
                    .map(|j| (entry.address, j)),
            );
        };
        for wiring in &self.qm31 {
            for (i, &entry) in wiring.operands[..3].iter().enumerate() {
                read(entry, wiring.op.reads(i));
            }
        }
        for wiring in &self.h8 {
            for &address in &wiring.inputs {
                read(
                    Entry {
                        address,
                        multiplicity: 1,
                    },
                    [true; 4],
                );
            }
        }
        for wiring in &self.p2 {
            if wiring.mode == Some(P2Mode::Node) {
                let bit = Entry {
                    address: wiring.bit_address,
                    multiplicity: 1,
                };
                read(bit, [true, false, false, false]);
            }
        }
        let layout = self.layout;
        for address in (0..layout.n_outputs)
            .map(|i| layout.output(i))
            .chain([layout.u()])
        {
            let public = Entry {
                address,
                multiplicity: 1,
            };
            read(public, [true; 4]);
        }
        reads
    }

    /// The lanes the `p2` rows absorb of each wire, the wires some row
    /// absorbs only in part, and the wires a gate computes.
    fn lane_census(&self) -> LaneCensus {
        let mut absorbed: HashMap<u32, [bool; 4]> = HashMap::new();
        let mut partial: HashSet<u32> = HashSet::new();
        let mut computed: HashSet<u32> = HashSet::new();
        for wiring in &self.p2 {
            for w in 0..2 {
                let entry = wiring.m[w];
                if entry.multiplicity == 0 {
                    continue;
                }
                let lanes = if wiring.mode == Some(P2Mode::Node) {
                    [true; 4]
                } else {
                    wiring.absorbed(w)
                };
                let all = absorbed.entry(entry.address).or_default();
                for (all, lane) in all.iter_mut().zip(lanes) {
                    *all |= lane;
                }
                if lanes.contains(&false) {
                    partial.insert(entry.address);
                }
            }
            for w in 0..2 {
                if wiring.out_multiplicity[w] != 0 {
                    computed.insert(wiring.out_address.wrapping_add(w as u32));
                }
            }
        }
        computed.extend(
            self.qm31
                .iter()
                .map(|wiring| wiring.operands[3])
                .chain(self.h8.iter().map(|wiring| wiring.out))
                .filter(|entry| entry.multiplicity != 0)
                .map(|entry| entry.address),
        );
        LaneCensus {
            absorbed,
            partial,
            computed,
        }
    }

    /// The relation's part of [`Circuit::check_wiring`].
    fn check_relation(&self) -> Result<WiringStats, WiringError> {
        for (component, rows) in [
            ("p2", self.p2.len()),
            ("qm31", self.qm31.len()),
            ("h8", self.h8.len()),
        ] {
            if rows < MIN_ROWS || !rows.is_power_of_two() {
                return Err(WiringError::Size { component, rows });
            }
        }
        if self.p2[0].mode.is_some_and(P2Mode::is_chained) {
            return Err(WiringError::ChainedFirstRow);
        }
        if let Some(row) = self
            .p2
            .iter()
            .find(|row| u64::from(row.out_address) + 1 >= u64::from(P))
        {
            return Err(WiringError::Address(u64::from(row.out_address) + 1));
        }
        let end = u64::from(self.layout.first_output) + u64::from(self.layout.n_outputs);
        if end > u64::from(P) || u64::from(self.layout.zero) + 3 > u64::from(P) {
            return Err(WiringError::Address(
                end.max(u64::from(self.layout.zero) + 3),
            ));
        }

        #[derive(Default)]
        struct Tally {
            yields: usize,
            total: i64,
        }
        let mut tallies = BTreeMap::<u32, Tally>::new();
        let mut absolute: u128 = 0;
        for entry in self.entries().filter(|entry| entry.multiplicity != 0) {
            if entry.address >= P {
                return Err(WiringError::Address(u64::from(entry.address)));
            }
            absolute += u128::from(entry.multiplicity.unsigned_abs());
            let tally = tallies.entry(entry.address).or_default();
            tally.yields += usize::from(entry.multiplicity < 0);
            tally.total += entry.multiplicity;
        }
        if absolute >= u128::from(P) {
            return Err(WiringError::TotalMultiplicity(absolute));
        }
        for (&address, tally) in &tallies {
            match tally.yields {
                0 => return Err(WiringError::NotYielded { address }),
                1 => {}
                _ => return Err(WiringError::YieldedTwice { address }),
            }
            if tally.total != 0 {
                return Err(WiringError::Unbalanced {
                    address,
                    total: tally.total,
                });
            }
        }
        Ok(WiringStats {
            addresses: tallies.len(),
            total_multiplicity: absolute as u64,
        })
    }
}

/// A signed multiplicity as a field element. Its magnitude is below `p`,
/// which [`Circuit::check_wiring`] ensures of every entry.
pub fn signed(multiplicity: i64) -> BaseField {
    let magnitude = multiplicity.unsigned_abs();
    assert!(
        magnitude < u64::from(P),
        "the multiplicity {multiplicity} is not below p in magnitude"
    );
    let magnitude = BaseField::from_u32_unchecked(magnitude as u32);
    if multiplicity < 0 {
        -magnitude
    } else {
        magnitude
    }
}
