//! A circuit: the components' wiring, which the preprocessed columns hold,
//! and its static check (`vos_recair_air::gate`).

use std::collections::BTreeMap;
use std::fmt;

use stwo::core::fields::m31::{BaseField, P};
use vos_recair_air::gate::Layout;
use vos_recair_air::p2::P2Mode;

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

    /// The static check of `vos_recair_air::gate`: every component a power of
    /// two of at least [`MIN_ROWS`] rows, no chained first row, every address
    /// below `p`, every used address yielded exactly once with the
    /// multiplicity of its uses, and the absolute multiplicities' sum below
    /// `p`.
    pub fn check_wiring(&self) -> Result<WiringStats, WiringError> {
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
