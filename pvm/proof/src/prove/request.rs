//! A proof to make, and the sizes its chips take.

use super::{SegmentState, Target};

/// A proof to make: its target, its chips (`component_mask` names them, 0
/// for an explicit set), their sizes, whether to profile the run, and the
/// boundary states the forgery seam ships instead of the trace's.
pub(crate) struct ProveRequest<'a> {
    pub target: Target,
    pub components: &'a [&'a dyn crate::framework::MachineProverComponent],
    pub component_mask: u32,
    pub sizes: Sizes<'a>,
    pub profile: bool,
    pub boundary_override: Option<(SegmentState, SegmentState)>,
}

impl<'a> ProveRequest<'a> {
    /// A proof under `target` of `components` at `sizes`, unprofiled, with
    /// the trace's boundary states.
    pub(crate) fn new(
        target: Target,
        components: &'a [&'a dyn crate::framework::MachineProverComponent],
        component_mask: u32,
        sizes: Sizes<'a>,
    ) -> Self {
        Self {
            target,
            components,
            component_mask,
            sizes,
            profile: false,
            boundary_override: None,
        }
    }
}

/// The log sizes a proof's chips take: at least floors (none: natural
/// sizes), or exactly a shape's.
#[derive(Clone, Copy)]
pub(crate) enum Sizes<'a> {
    Floors(&'a [u32]),
    Pinned(&'a [u32]),
}

impl<'a> Sizes<'a> {
    pub(crate) const NATURAL: Sizes<'static> = Sizes::Floors(&[]);

    pub(super) fn floors(self) -> &'a [u32] {
        match self {
            Self::Floors(sizes) | Self::Pinned(sizes) => sizes,
        }
    }
}
