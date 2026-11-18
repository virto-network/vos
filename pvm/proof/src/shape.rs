//! A kernel's shape: the chips its segment proofs hold, and the log size of
//! each per class of segment.
//!
//! - **The chips** are those the kernel's code can reach, its instructions'
//!   and its precompiles' (`vos_pvm_compiler::shape`, at its install), and
//!   always [`chip_idx::ALWAYS`]: the ledgers, the boundaries, the program's
//!   memory and the fixed tables, which bind a segment's states and code.
//! - **A class** pins every chip's log size, so a segment's proof has one of
//!   a few shapes, each fixed before any run: what a leaf circuit takes as
//!   constants, and what bounds a verifier's work.
//! - **A verifier accepts exactly the shape:** a proof over more chips (the
//!   full set) or fewer, or at sizes no class gives, is refused before any
//!   cryptographic check.
//!
//! **Dropping a chip is sound.** A proof over a subset of the chips is a
//! proof of the full AIR in which each dropped chip's trace is its padding:
//! padding rows satisfy the chip's constraints and add nothing to any
//! relation, as every full-set canonical proof of a run that leaves a chip
//! idle shows. So a witness of the subset's constraints and relations
//! extends, by those padding traces, to one of the full set's: a subset
//! proves no statement the full set cannot. Concretely, each
//! optional chip ([`chip_idx::OPTIONAL`]) answers requests whose
//! multiplicities are flags of the committed code (the CPU's opcode flags
//! and host-call dispatch, which `ProgramMemory` binds per pc, zero on
//! padding rows): without the chip, a relation balances only if no row
//! makes such a request. The chips that bind a segment's states and code,
//! [`chip_idx::ALWAYS`], are in every shape, and a shape without one is
//! refused. A cheating prover gains no statement from a smaller set; the
//! shape pins the set so that it gains no other proof of the kernel either.

use alloc::vec::Vec;

use crate::chip_idx;

/// Why a shape, or a proof against one, is refused. Value-free: a shape is
/// public (its kernel's install record), and a variant names the rule it
/// breaks, never a run's value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShapeError {
    /// The record is of another shape policy (`vos_abi::records::Shape::POLICY`).
    Policy,
    /// A chip outside the segment AIR.
    Outside,
    /// A chip every proof holds ([`chip_idx::ALWAYS`]) left out.
    Missing,
    /// No class.
    NoClass,
    /// More than [`MAX_CLASSES`] classes.
    Classes,
    /// A class sizes other chips than the shape's.
    ClassChips,
    /// A class's log size outside a lane's 2^4 rows to [`MAX_LOG_SIZE`].
    LogSize,
    /// A class's steps outside one to `2^MAX_LOG_SIZE`, or more than its
    /// CPU's rows, a row a step.
    Steps,
    /// A class of no page.
    Pages,
    /// A class gives a fixed table fewer rows than its entries
    /// ([`FIXED_TABLES`]).
    Table,
    /// A class whose proofs would count below its format's security
    /// floor at their shape.
    Security,
    /// A proof holds a chip its shape does not.
    MoreChips,
    /// A proof lacks a chip its shape holds.
    FewerChips,
    /// A proof's log sizes are no class of the shape.
    NoSuchClass,
}

impl ShapeError {
    /// What it says, a static text a log may hold.
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::Policy => "the record's shape is of another policy",
            Self::Outside => "the shape names a chip outside the segment AIR",
            Self::Missing => "the shape leaves out chips every proof holds",
            Self::NoClass => "the shape has no class",
            Self::Classes => "the shape has more classes than a kernel's record holds",
            Self::ClassChips => "a class sizes other chips than the shape's",
            Self::LogSize => "a class has a log size out of range",
            Self::Steps => "a class's steps are out of range or past its CPU's rows",
            Self::Pages => "a class has no page",
            Self::Table => "a class gives a fixed table fewer rows than its entries",
            Self::Security => "a class's proofs count below its format's floor",
            Self::MoreChips => "the proof holds more chips than its kernel's shape",
            Self::FewerChips => "the proof holds fewer chips than its kernel's shape",
            Self::NoSuchClass => "the proof's log sizes are no class of its kernel's shape",
        }
    }
}

impl core::fmt::Display for ShapeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.reason())
    }
}

impl core::error::Error for ShapeError {}

impl From<ShapeError> for stwo::core::verifier::VerificationError {
    fn from(refusal: ShapeError) -> Self {
        Self::InvalidStructure(alloc::string::ToString::to_string(&refusal))
    }
}

/// A class of segment as the prover and verifier pin it: its cut, and the
/// log size of each chip of the shape alone, in chip order (the form the
/// program id hashes). A kernel's record holds the same class at a fixed
/// size, a slot for every chip of the AIR
/// (`vos_abi::records::SegmentClass`), read into this one by
/// `KernelShape`'s `TryFrom` of the record's shape (feature `abi`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClassShape {
    /// At most 2^`log_steps` steps a segment.
    pub log_steps: u8,
    /// At most this many pages touched a segment.
    pub pages: u16,
    /// A log size for each chip of the shape, in chip order.
    pub log_sizes: Vec<u8>,
}

/// A kernel's shape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KernelShape {
    /// Bit i: chip i ([`chip_idx`]).
    pub components: u32,
    /// Cheapest first, at most [`MAX_CLASSES`].
    pub classes: Vec<ClassShape>,
}

/// One segment's shape: its chips, and each one's log size in chip order,
/// as a proof carries them (`Proof::component_mask`, `Proof::log_sizes`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofShape {
    pub components: u32,
    pub log_sizes: Vec<u32>,
}

/// The most a pinned log size may be: a verifier's default cap.
pub const MAX_LOG_SIZE: u8 = crate::proof::MAX_PROOF_LOG_SIZE as u8;

/// Each fixed table's chip and the log size of its entries, the least a
/// class gives it: a table at more rows repeats its entries, at fewer it
/// does not hold them.
pub const FIXED_TABLES: [(usize, u8); 7] = [
    (chip_idx::POWER_OF_TWO, 6),
    (chip_idx::RANGE_MULTIPLICITY_256, 8),
    (chip_idx::BITWISE_LOOKUP, 8),
    (chip_idx::POPCOUNT, 8),
    (chip_idx::BITCOUNT, 8),
    (chip_idx::BYTE_TO_BITS, 8),
    (chip_idx::BITWISE_AND_BYTE, 16),
];

/// The most classes a shape has: a kernel's record's cap
/// (`vos_abi::records::MAX_CLASSES`).
pub const MAX_CLASSES: usize = 4;

#[cfg(feature = "abi")]
const _: () = assert!(MAX_CLASSES == vos_abi::records::MAX_CLASSES);

impl KernelShape {
    /// Whether it is a shape a verifier accepts: within the segment AIR,
    /// holding every chip of [`chip_idx::ALWAYS`], with one to
    /// [`MAX_CLASSES`] classes, each giving every chip a log size from a
    /// lane's 2^4 rows to [`MAX_LOG_SIZE`] and each fixed table at least
    /// its entries ([`FIXED_TABLES`]), cutting at a page or more and at
    /// most as many steps as its CPU's rows. A shape it accepts cuts and
    /// sizes without a panic; whether its proofs meet their format's
    /// security floor is [`KernelShape::check_security`]'s.
    pub fn check(&self) -> Result<(), ShapeError> {
        if self.components & !chip_idx::ALL != 0 {
            return Err(ShapeError::Outside);
        }
        if self.components & chip_idx::ALWAYS != chip_idx::ALWAYS {
            return Err(ShapeError::Missing);
        }
        if self.classes.is_empty() {
            return Err(ShapeError::NoClass);
        }
        if self.classes.len() > MAX_CLASSES {
            return Err(ShapeError::Classes);
        }
        let chips = self.components.count_ones() as usize;
        for class in &self.classes {
            if class.log_sizes.len() != chips {
                return Err(ShapeError::ClassChips);
            }
            if class
                .log_sizes
                .iter()
                .any(|&size| !(4..=MAX_LOG_SIZE).contains(&size))
            {
                return Err(ShapeError::LogSize);
            }
            // The CPU is the first chip of every shape.
            if class.log_steps > class.log_sizes[0] {
                return Err(ShapeError::Steps);
            }
            if class.pages == 0 {
                return Err(ShapeError::Pages);
            }
            let short = FIXED_TABLES.iter().any(|&(chip, least)| {
                self.components & 1 << chip != 0
                    && class.log_sizes[(self.components & ((1 << chip) - 1)).count_ones() as usize]
                        < least
            });
            if short {
                return Err(ShapeError::Table);
            }
        }
        Ok(())
    }

    /// Whether every class's proofs under `format` count at least its
    /// security floor at their shape, as a verifier counts them
    /// ([`crate::proof::check_format_security`]): what a venue holds an
    /// install's shape to before building its leaves, whose circuits
    /// assume it. The shape is [`KernelShape::check`]'s first. A prover
    /// build's: the leaves are built in one.
    #[cfg(feature = "prover")]
    pub fn check_security(&self, format: &crate::format::Format) -> Result<(), ShapeError> {
        self.check()?;
        let config = format.pcs_config();
        for index in 0..self.classes.len() {
            let segment = self.segment(index).ok_or(ShapeError::NoClass)?;
            let layout = crate::sample_layout(segment.components, &segment.log_sizes, &config);
            crate::proof::check_format_security(format, &config, &layout.security_shape)
                .map_err(|_| ShapeError::Security)?;
        }
        Ok(())
    }

    /// Class `index`'s segment shape.
    pub fn segment(&self, index: usize) -> Option<ProofShape> {
        self.classes.get(index).map(|class| ProofShape {
            components: self.components,
            log_sizes: class
                .log_sizes
                .iter()
                .map(|&size| u32::from(size))
                .collect(),
        })
    }

    /// The class a proof over `components` at `log_sizes` is of: the first
    /// whose sizes they are. A proof over other chips than the shape's,
    /// more or fewer, or at sizes no class gives, is refused.
    pub fn class_of(&self, components: u32, log_sizes: &[u32]) -> Result<usize, ShapeError> {
        if components & !self.components != 0 {
            return Err(ShapeError::MoreChips);
        }
        if components != self.components {
            return Err(ShapeError::FewerChips);
        }
        self.classes
            .iter()
            .position(|class| {
                class.log_sizes.len() == log_sizes.len()
                    && class
                        .log_sizes
                        .iter()
                        .zip(log_sizes)
                        .all(|(&pinned, &size)| u32::from(pinned) == size)
            })
            .ok_or(ShapeError::NoSuchClass)
    }
}

/// The shape a kernel's install records: its chips, and each class's log
/// sizes of those chips in chip order. Refused when the record is of
/// another shape policy, names a chip past the segment AIR, sizes a chip
/// outside its chips, leaves out a chip every proof holds, or has more than
/// [`MAX_CLASSES`] classes, or the
/// shape is otherwise not one [`KernelShape::check`] accepts; so a record a
/// verifier takes is of exactly one shape.
#[cfg(feature = "abi")]
impl TryFrom<&vos_abi::records::Shape> for KernelShape {
    type Error = ShapeError;

    fn try_from(record: &vos_abi::records::Shape) -> Result<Self, ShapeError> {
        if record.policy != vos_abi::records::Shape::POLICY {
            return Err(ShapeError::Policy);
        }
        if record.chips & !chip_idx::ALL != 0 {
            return Err(ShapeError::Outside);
        }
        if record.classes.len() > MAX_CLASSES {
            return Err(ShapeError::Classes);
        }
        let outside = |size: (usize, &u8)| record.chips & 1 << size.0 == 0 && *size.1 != 0;
        if record
            .classes
            .iter()
            .any(|class| class.log_sizes.iter().enumerate().any(outside))
        {
            return Err(ShapeError::ClassChips);
        }
        let shape = KernelShape {
            components: record.chips,
            classes: record
                .classes
                .iter()
                .map(|class| ClassShape {
                    log_steps: class.log_steps,
                    pages: class.pages,
                    log_sizes: class
                        .log_sizes
                        .iter()
                        .enumerate()
                        .filter(|(chip, _)| record.chips & 1 << chip != 0)
                        .map(|(_, &size)| size)
                        .collect(),
                })
                .collect(),
        };
        shape.check()?;
        Ok(shape)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn shape() -> KernelShape {
        let components = chip_idx::ALWAYS | 1 << chip_idx::MUL;
        let chips = components.count_ones() as usize;
        KernelShape {
            components,
            classes: vec![
                ClassShape {
                    log_steps: 12,
                    pages: 8,
                    log_sizes: vec![16; chips],
                },
                ClassShape {
                    log_steps: 15,
                    pages: 8,
                    log_sizes: vec![17; chips],
                },
            ],
        }
    }

    /// A proof is of the class whose sizes it carries, over exactly the
    /// shape's chips: a superset, a subset or another size is refused.
    #[test]
    fn a_proof_is_of_exactly_one_class() {
        let shape = shape();
        shape.check().unwrap();
        let chips = shape.components.count_ones() as usize;
        assert_eq!(shape.class_of(shape.components, &vec![17; chips]), Ok(1));
        assert_eq!(shape.class_of(shape.components, &vec![16; chips]), Ok(0));
        let mut other = vec![17; chips];
        other[0] = 18;
        assert!(shape.class_of(shape.components, &other).is_err());
        assert!(
            shape
                .class_of(
                    shape.components | 1 << chip_idx::DIVREM,
                    &vec![17; chips + 1]
                )
                .is_err()
        );
        assert!(
            shape
                .class_of(
                    shape.components & !(1 << chip_idx::MUL),
                    &vec![17; chips - 1]
                )
                .is_err()
        );
        assert!(
            shape
                .class_of(shape.components, &vec![17; chips - 1])
                .is_err()
        );
    }

    /// A shape without a chip every proof holds, past the AIR, without a
    /// class, or with a class of another chip count, is refused.
    #[test]
    fn a_malformed_shape_is_refused() {
        let mut missing = shape();
        missing.components &= !(1 << chip_idx::MEMORY);
        assert_eq!(missing.check(), Err(ShapeError::Missing));
        let mut outside = shape();
        outside.components |= 1 << chip_idx::COUNT;
        assert!(outside.check().is_err());
        let mut classless = shape();
        classless.classes.clear();
        assert!(classless.check().is_err());
        let mut short = shape();
        short.classes[0].log_sizes.pop();
        assert!(short.check().is_err());
        let mut huge = shape();
        huge.classes[1].log_sizes[0] = MAX_LOG_SIZE + 1;
        assert!(huge.check().is_err());
        let mut many = shape();
        many.classes = vec![many.classes[0].clone(); MAX_CLASSES + 1];
        assert_eq!(many.check(), Err(ShapeError::Classes));
    }

    /// Each fixed table's least log size is its chip's trace's at its
    /// natural size.
    #[cfg(feature = "prover")]
    #[test]
    fn the_fixed_tables_are_their_chips_sizes() {
        let side_note = crate::SideNote::new(vec![], vec![0], vec![1]);
        for (chip, least) in FIXED_TABLES {
            let trace = crate::BASE_COMPONENTS[chip].generate_component_trace_immut_min(&side_note, 0);
            assert_eq!(trace.log_size(), u32::from(least), "chip {chip}");
        }
    }

    /// A class giving a fixed table fewer rows than its entries, at which its
    /// preprocessed columns would not fit their domain, is refused.
    #[test]
    fn a_class_short_of_a_fixed_table_is_refused() {
        let mut short = shape();
        let position = (short.components & ((1 << chip_idx::POWER_OF_TWO) - 1)).count_ones();
        short.classes[0].log_sizes[position as usize] = 5;
        assert_eq!(short.check(), Err(ShapeError::Table));
    }

    /// A class of no page, of more steps than its CPU's rows, or of a shift
    /// past a word's bits, which a hostile install record may name and a
    /// cut would panic on, is refused.
    #[test]
    fn a_class_that_cannot_cut_is_refused() {
        let mut pageless = shape();
        pageless.classes[0].pages = 0;
        assert_eq!(pageless.check(), Err(ShapeError::Pages));
        for log_steps in [17, 64, u8::MAX] {
            let mut long = shape();
            long.classes[0].log_steps = log_steps;
            assert_eq!(long.check(), Err(ShapeError::Steps));
        }
        let mut most = shape();
        most.classes[0].log_steps = 16;
        assert!(most.check().is_ok());
    }

    /// A record of [`shape`]'s chips, each class sized as its.
    #[cfg(feature = "abi")]
    fn record() -> vos_abi::records::Shape {
        let shape = shape();
        vos_abi::records::Shape {
            policy: vos_abi::records::Shape::POLICY,
            chips: shape.components,
            classes: shape
                .classes
                .iter()
                .map(|class| {
                    let mut sizes = class.log_sizes.iter();
                    vos_abi::records::SegmentClass {
                        log_steps: class.log_steps,
                        pages: class.pages,
                        log_sizes: core::array::from_fn(|chip| {
                            if shape.components & 1 << chip == 0 {
                                0
                            } else {
                                *sizes.next().unwrap()
                            }
                        }),
                    }
                })
                .collect(),
        }
    }

    /// A record converts to the shape of its chips, each class's sizes
    /// those of its chips in chip order.
    #[cfg(feature = "abi")]
    #[test]
    fn a_record_is_of_one_shape() {
        assert_eq!(KernelShape::try_from(&record()), Ok(shape()));
        let mut sized = record();
        sized.classes[0].log_sizes[chip_idx::MUL] = 9;
        let shape = KernelShape::try_from(&sized).unwrap();
        let position = (0..chip_idx::MUL)
            .filter(|chip| sized.chips & 1 << chip != 0)
            .count();
        assert_eq!(shape.classes[0].log_sizes[position], 9);
    }

    /// A record of another shape policy (one stored before the policy
    /// moved, its classes laid out otherwise), naming a chip past the AIR,
    /// sizing a chip outside its chips, without a chip every proof holds,
    /// or with more classes than the cap is refused.
    #[cfg(feature = "abi")]
    #[test]
    fn a_malformed_record_is_refused() {
        let refusal = |change: fn(&mut vos_abi::records::Shape)| {
            let mut record = record();
            change(&mut record);
            KernelShape::try_from(&record).unwrap_err()
        };
        assert_eq!(refusal(|r| r.policy -= 1), ShapeError::Policy);
        assert_eq!(refusal(|r| r.policy += 1), ShapeError::Policy);
        assert_eq!(
            refusal(|r| r.chips |= 1 << chip_idx::COUNT),
            ShapeError::Outside
        );
        assert_eq!(refusal(|r| r.chips |= 1 << 31), ShapeError::Outside);
        assert_eq!(
            refusal(|r| r.classes[1].log_sizes[chip_idx::DIVREM] = 12),
            ShapeError::ClassChips
        );
        assert_eq!(
            refusal(|r| {
                r.chips &= !(1 << chip_idx::MEMORY);
                for class in &mut r.classes {
                    class.log_sizes[chip_idx::MEMORY] = 0;
                }
            }),
            ShapeError::Missing
        );
        assert_eq!(
            refusal(|r| r.classes = vec![r.classes[0]; MAX_CLASSES + 1]),
            ShapeError::Classes
        );
        assert_eq!(refusal(|r| r.classes.clear()), ShapeError::NoClass);
        assert_eq!(
            refusal(|r| r.classes[0].log_sizes[chip_idx::CPU] = 0),
            ShapeError::LogSize
        );
        let mut most = record();
        most.classes = vec![most.classes[0]; MAX_CLASSES];
        assert!(KernelShape::try_from(&most).is_ok());
    }
}
