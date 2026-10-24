//! Proving over a kernel's shape ([`crate::shape`]): exactly its chips, each
//! at exactly a class's log size.

use super::{
    ProvingError, Sizes, Target, install_thread_pool, prepare_side_note_for_verification,
    prove_impl_with_components_overridden,
};
use crate::format::Format;
use crate::framework::MachineProverComponent;
use crate::pcs::Commitment;
use crate::proof::Proof;
use crate::shape::{KernelShape, SegmentShape};
use crate::side_note::SideNote;

/// The chips `components` selects, in chip order.
fn selected(components: u32) -> Vec<&'static dyn MachineProverComponent> {
    crate::chips_of_mask(components)
        .map(|chip| crate::all_components()[chip])
        .collect()
}

/// Whether `shape` names chips of the segment AIR, a log size each.
fn check(shape: &SegmentShape) -> Result<(), ProvingError> {
    if shape.components & !crate::chip_idx::ALL != 0
        || shape.components.count_ones() as usize != shape.log_sizes.len()
    {
        return Err(ProvingError::MalformedShape);
    }
    Ok(())
}

/// Prove a segment under `format` over `shape`: exactly its chips, each at
/// exactly its log size. [`ProvingError::Shape`] when a chip's rows need a
/// larger size than the shape gives it, or a fixed chip's size is not the
/// shape's; [`ProvingError::MalformedShape`] when the shape is not one of
/// the segment AIR.
pub fn prove_shaped(
    side_note: &mut SideNote,
    shape: &SegmentShape,
    format: &'static Format,
) -> Result<Proof, ProvingError> {
    check(shape)?;
    install_thread_pool();
    prepare_side_note_for_verification(side_note);
    let components = selected(shape.components);
    let (proof, _) = prove_impl_with_components_overridden(
        side_note,
        Target::of(format)?,
        false,
        &components,
        shape.components,
        None,
        Sizes::Pinned(&shape.log_sizes),
    )?;
    Ok(proof)
}

/// The preprocessed root of a segment over `shape` under `format`, for the
/// program `side_note` holds ([`crate::kernel::kernel_side_note`]): the
/// root every segment of the class commits, whatever its run, which a
/// kernel's program id pins. `None` on a format the registry does not admit
/// or a malformed shape.
pub fn program_commitment_for_shape(
    side_note: &SideNote,
    shape: &SegmentShape,
    format: &'static Format,
) -> Option<Commitment> {
    check(shape).ok()?;
    install_thread_pool();
    let target = Target::of(format).ok()?;
    let components = selected(shape.components);
    crate::with_stack!(format.channel, Stack => {
        super::canonical::program_commitment_on::<Stack>(
            side_note,
            &components,
            &shape.log_sizes,
            target,
        )
    }, unbuilt => None)
}

/// A segment of a kernel's run, proved: its steps `[a, b)`, its class and
/// its proof.
pub struct KernelSegment {
    pub steps: (usize, usize),
    pub class: usize,
    pub proof: Proof,
}

/// A kernel's run, traced whole in `full`, proved under `format` over
/// `shape`: cut by class `cut`'s budgets, its steps and its pages
/// ([`crate::segment::segment_bounds_budgeted`]), and each window proved at
/// the first class whose sizes hold its rows. A class is tried by proving
/// at it: its traces are generated once, at its sizes, and a chip whose
/// rows need more refuses it before any commitment; a class of fewer steps
/// than the window's is skipped, as its CPU holds a row a step. A window
/// none holds is cut in half, down to one step; a step no class holds is
/// refused with [`ProvingError::Shape`].
pub fn prove_kernel(
    full: &SideNote,
    shape: &KernelShape,
    cut: usize,
    format: &'static Format,
) -> Result<Vec<KernelSegment>, ProvingError> {
    shape.check().map_err(|_| ProvingError::MalformedShape)?;
    let class = shape.classes.get(cut).ok_or(ProvingError::MalformedShape)?;
    let bounds = crate::segment::segment_bounds_budgeted(
        full,
        1 << class.log_steps,
        usize::from(class.pages),
    );
    let mut cursor = crate::segment::SegmentCursor::new(full);
    let mut segments = Vec::with_capacity(bounds.len());
    for (a, b) in bounds {
        let mut pending = vec![(a, b)];
        while let Some((a, b)) = pending.pop() {
            match prove_at_first_class(&mut cursor, (a, b), shape, format) {
                Ok((class, proof)) => segments.push(KernelSegment {
                    steps: (a, b),
                    class,
                    proof,
                }),
                Err(ProvingError::Shape {
                    log_size, pinned, ..
                }) if log_size > pinned && b - a > 1 => {
                    let middle = a + (b - a) / 2;
                    pending.push((middle, b));
                    pending.push((a, middle));
                }
                Err(error) => return Err(error),
            }
        }
    }
    Ok(segments)
}

/// Window `[a, b)` proved at the first class of `shape` that holds its
/// rows, and the class; or the overflow of the last class tried, a
/// [`ProvingError::Shape`] whose size is past its pin.
fn prove_at_first_class(
    cursor: &mut crate::segment::SegmentCursor<'_>,
    (a, b): (usize, usize),
    shape: &KernelShape,
    format: &'static Format,
) -> Result<(usize, Proof), ProvingError> {
    let steps = (b - a).next_power_of_two().trailing_zeros();
    let mut overflow = ProvingError::Shape {
        chip: crate::chip_idx::CPU,
        log_size: steps,
        pinned: 0,
    };
    for (index, class) in shape.classes.iter().enumerate() {
        if steps > u32::from(class.log_steps) {
            continue;
        }
        let segment = shape.segment(index).ok_or(ProvingError::MalformedShape)?;
        match prove_shaped(&mut cursor.side_note(a, b), &segment, format) {
            Ok(proof) => return Ok((index, proof)),
            Err(
                error @ ProvingError::Shape {
                    log_size, pinned, ..
                },
            ) if log_size > pinned => overflow = error,
            Err(error) => return Err(error),
        }
    }
    Err(overflow)
}
