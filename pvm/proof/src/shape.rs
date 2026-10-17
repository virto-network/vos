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

use alloc::string::String;
use alloc::vec::Vec;

use crate::chip_idx;

/// A class of segment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SegmentClass {
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
    /// Smallest first.
    pub classes: Vec<SegmentClass>,
}

/// One segment's shape: its chips, and each one's log size in chip order,
/// as a proof carries them (`Proof::component_mask`, `Proof::log_sizes`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SegmentShape {
    pub components: u32,
    pub log_sizes: Vec<u32>,
}

/// The most a pinned log size may be: a verifier's default cap.
pub const MAX_LOG_SIZE: u8 = 24;

impl KernelShape {
    /// Whether it is a shape a verifier accepts: within the segment AIR,
    /// holding every chip of [`chip_idx::ALWAYS`], with at least one class,
    /// each giving every chip a log size from a lane's 2^4 rows to
    /// [`MAX_LOG_SIZE`].
    pub fn check(&self) -> Result<(), String> {
        if self.components & !chip_idx::ALL != 0 {
            return Err("the shape names a chip outside the segment AIR".into());
        }
        if self.components & chip_idx::ALWAYS != chip_idx::ALWAYS {
            return Err(alloc::format!(
                "the shape leaves out chips every proof holds: {:#x}",
                chip_idx::ALWAYS & !self.components
            ));
        }
        if self.classes.is_empty() {
            return Err("the shape has no class".into());
        }
        let chips = self.components.count_ones() as usize;
        for (index, class) in self.classes.iter().enumerate() {
            if class.log_sizes.len() != chips {
                return Err(alloc::format!(
                    "class {index} sizes {} chips, the shape has {chips}",
                    class.log_sizes.len()
                ));
            }
            if class
                .log_sizes
                .iter()
                .any(|&size| !(4..=MAX_LOG_SIZE).contains(&size))
            {
                return Err(alloc::format!("class {index} has a log size out of range"));
            }
        }
        Ok(())
    }

    /// Class `index`'s segment shape.
    pub fn segment(&self, index: usize) -> Option<SegmentShape> {
        self.classes.get(index).map(|class| SegmentShape {
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
    pub fn class_of(&self, components: u32, log_sizes: &[u32]) -> Result<usize, String> {
        if components != self.components {
            let (more, fewer) = (components & !self.components, self.components & !components);
            return Err(alloc::format!(
                "the proof's chips differ from its kernel's shape: {more:#x} more, \
                 {fewer:#x} fewer"
            ));
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
            .ok_or_else(|| "the proof's log sizes are no class of its kernel's shape".into())
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
                SegmentClass {
                    log_steps: 12,
                    pages: 8,
                    log_sizes: vec![12; chips],
                },
                SegmentClass {
                    log_steps: 15,
                    pages: 8,
                    log_sizes: vec![15; chips],
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
        assert_eq!(shape.class_of(shape.components, &vec![15; chips]), Ok(1));
        assert_eq!(shape.class_of(shape.components, &vec![12; chips]), Ok(0));
        let mut other = vec![15; chips];
        other[0] = 16;
        assert!(shape.class_of(shape.components, &other).is_err());
        assert!(
            shape
                .class_of(
                    shape.components | 1 << chip_idx::DIVREM,
                    &vec![15; chips + 1]
                )
                .is_err()
        );
        assert!(
            shape
                .class_of(
                    shape.components & !(1 << chip_idx::MUL),
                    &vec![15; chips - 1]
                )
                .is_err()
        );
        assert!(
            shape
                .class_of(shape.components, &vec![15; chips - 1])
                .is_err()
        );
    }

    /// A shape without a chip every proof holds, past the AIR, without a
    /// class, or with a class of another chip count, is refused.
    #[test]
    fn a_malformed_shape_is_refused() {
        let mut missing = shape();
        missing.components &= !(1 << chip_idx::MEMORY);
        assert!(missing.check().unwrap_err().contains("leaves out"));
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
    }
}
