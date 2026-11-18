//! Proving over a kernel's shape ([`crate::shape`]): exactly its chips, each
//! at exactly a class's log size.

use super::{
    ProveRequest, SegmentError, Sizes, Target, install_thread_pool,
    prepare_side_note_for_verification, prove_with,
};
use crate::core::step::TraceStep;
use crate::format::Format;
use crate::framework::MachineProverComponent;
use crate::pcs::Commitment;
use crate::proof::Proof;
use crate::shape::{KernelShape, ProofShape};
use crate::side_note::SideNote;

/// The chips `components` selects, in chip order.
fn selected(components: u32) -> Vec<&'static dyn MachineProverComponent> {
    crate::chips_of_mask(components)
        .map(|chip| crate::all_components()[chip])
        .collect()
}

/// Whether `shape` names chips of the segment AIR, a log size each.
fn check(shape: &ProofShape) -> Result<(), SegmentError> {
    if shape.components & !crate::chip_idx::ALL != 0
        || shape.components.count_ones() as usize != shape.log_sizes.len()
    {
        return Err(SegmentError::MalformedShape);
    }
    Ok(())
}

/// Prove a segment under `format` over `shape`: exactly its chips, each at
/// exactly its log size. [`SegmentError::Shape`] when a chip's rows need a
/// larger size than the shape gives it, or a fixed chip's size is not the
/// shape's; [`SegmentError::MalformedShape`] when the shape is not one of
/// the segment AIR.
pub fn prove_shaped(
    side_note: &mut SideNote,
    shape: &ProofShape,
    format: &'static Format,
) -> Result<Proof, SegmentError> {
    check(shape)?;
    install_thread_pool();
    prepare_side_note_for_verification(side_note);
    let components = selected(shape.components);
    let request = ProveRequest::new(
        Target::of(format)?,
        &components,
        shape.components,
        Sizes::Pinned(&shape.log_sizes),
    );
    let (proof, _) = prove_with(side_note, request)?;
    Ok(proof)
}

/// The preprocessed root of a segment over `shape` under `format`, for the
/// program `side_note` holds ([`crate::kernel::kernel_side_note`]): the
/// root every segment of the class commits, whatever its run, which a
/// kernel's program id pins. `None` on a format the registry does not admit,
/// a malformed or empty shape, one whose code or jump table is larger than
/// its chip's log size holds, or one whose proofs would count below the
/// format's security floor (refused before any column is generated).
pub fn program_commitment_for_shape(
    side_note: &SideNote,
    shape: &ProofShape,
    format: &'static Format,
) -> Option<Commitment> {
    use crate::pcs::ProofHash;
    check(shape).ok()?;
    if shape.components == 0 || shape.log_sizes.contains(&0) {
        return None;
    }
    let size_of = |chip: usize| {
        (shape.components & 1 << chip != 0)
            .then(|| shape.log_sizes[(shape.components & ((1 << chip) - 1)).count_ones() as usize])
    };
    let tables = [
        (
            crate::chip_idx::PROGRAM_MEMORY,
            crate::chips::program_memory::table_log_size(side_note),
        ),
        (
            crate::chip_idx::JUMP_TABLE,
            crate::chips::jump_table::table_log_size(side_note),
        ),
    ];
    if tables
        .iter()
        .any(|&(chip, table)| size_of(chip).is_some_and(|size| size < table))
    {
        return None;
    }
    let config = Target::of(format).ok()?.format.pcs_config();
    let layout = crate::sample_layout(shape.components, &shape.log_sizes, &config);
    crate::proof::check_format_security(format, &config, &layout.security_shape).ok()?;
    install_thread_pool();
    let components = selected(shape.components);
    super::on_prover_pool(|| {
        crate::with_stack!(format.channel, Stack => {
            Some(
                super::preprocessed_root::<Stack>(side_note, &components, &shape.log_sizes, config)
                    .into_commitment(),
            )
        }, unbuilt => None)
    })
}

/// A segment of a kernel's run, proved: its steps `[a, b)`, its class and
/// its proof.
pub struct KernelSegment {
    pub steps: (usize, usize),
    pub class: usize,
    pub proof: Proof,
}

/// A kernel's run, traced whole in `full` (its steps compact, as
/// [`crate::kernel::trace_kernel`] records them, or full), proved under
/// `format` over `shape`: planned first ([`super::plan_kernel`]: cut by
/// class `cut`'s budgets, its steps and its pages, each window held by the
/// classes whose page boundary takes it, cut in half while none does), and
/// refused before any proof when its gas does not buy its segments
/// ([`SegmentError::Segments`], [`super::max_segments`]). Each segment is
/// then proved at the first class that holds it. A class is tried by
/// proving at it: the window's side note is built anew for each class tried
/// (its steps expanded, its records sliced, its program shared, not
/// copied), a class whose page boundary does not take the window passed
/// over before any trace, the others' traces generated once, at the class's
/// sizes, and a chip whose rows need more refuses it before any commitment;
/// a class of fewer steps than the window's is skipped, as its CPU holds a
/// row a step. A window none holds is cut in half, down to one step, and
/// the segments so added are held to the same gas; a step no class holds
/// is refused with [`SegmentError::Shape`]: one touching more pages than
/// the largest class's (24, or 17 for a shape holding the Poseidon2 chip),
/// as a witness-input call writing more than about 64 KiB at once.
///
/// Host work beside the proofs: each window's page multiproof, built twice
/// (planned, proved), hashes the window's pages and every nonzero page of
/// the memory image entering it, whose pages are the kernel's data or pages
/// its gas wrote.
pub fn prove_kernel<S: TraceStep>(
    full: &SideNote<S>,
    shape: &KernelShape,
    cut: usize,
    format: &'static Format,
) -> Result<Vec<KernelSegment>, SegmentError> {
    let plan = super::plan_kernel(full, shape, cut)?;
    let most = super::max_segments(plan.gas);
    let mut cursor = crate::segment::SegmentCursor::new(full);
    let mut segments = Vec::with_capacity(plan.segments.len());
    let mut planned = plan.segments.len();
    for segment in plan.segments {
        let mut pending = vec![segment.steps];
        while let Some((a, b)) = pending.pop() {
            match prove_at_first_class(&mut cursor, (a, b), shape, format) {
                Ok((class, proof)) => segments.push(KernelSegment {
                    steps: (a, b),
                    class,
                    proof,
                }),
                Err(SegmentError::Shape { overflow: true, .. }) if b - a > 1 => {
                    planned += 1;
                    if planned > most {
                        return Err(SegmentError::Segments);
                    }
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
/// [`SegmentError::Shape`] whose size is past its pin. The classes whose
/// page boundary does not take the window are passed over untraced
/// ([`super::plan::holding`]).
fn prove_at_first_class<S: TraceStep>(
    cursor: &mut crate::segment::SegmentCursor<'_, S>,
    (a, b): (usize, usize),
    shape: &KernelShape,
    format: &'static Format,
) -> Result<(usize, Proof), SegmentError> {
    let mut window = Some(cursor.side_note(a, b));
    let holding = super::plan::holding(window.as_mut().expect("a window"), b - a, shape)?;
    let mut overflow = SegmentError::Shape {
        chip: crate::chip_idx::CPU,
        overflow: true,
    };
    for (index, _) in shape.classes.iter().enumerate() {
        if holding & 1 << index == 0 {
            continue;
        }
        let segment = shape.segment(index).ok_or(SegmentError::MalformedShape)?;
        let mut side_note = window.take().unwrap_or_else(|| cursor.side_note(a, b));
        match prove_shaped(&mut side_note, &segment, format) {
            Ok(proof) => return Ok((index, proof)),
            Err(error @ SegmentError::Shape { overflow: true, .. }) => overflow = error,
            Err(error) => return Err(error),
        }
    }
    Err(overflow)
}
