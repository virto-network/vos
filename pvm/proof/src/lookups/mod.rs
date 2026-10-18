use alloc::vec::Vec;
use core::any::TypeId;

use num_traits::{One, Zero};
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;

use impl_trait_for_tuples::impl_for_tuples;

#[cfg(feature = "prover")]
mod logup_trace_builder;
mod macros;
mod range_check;
mod relations;

#[cfg(feature = "prover")]
pub use self::logup_trace_builder::LogupTraceBuilder;
pub use self::relations::{
    MAX_RELATION_WIDTH, PROG_MEMORY_N_FLAG_BYTES, PROG_MEMORY_N_FLAGS, boundary_relation_challenges,
};
pub use self::{
    range_check::Range256LookupElements,
    relations::{
        BitcountLookupElements, BitwiseAndByteLookupElements, BitwiseAndLookupElements,
        BitwiseLookupElements, Blake2bCallLookupElements, Blake2bCompressionLookupElements,
        ByteToBitsLookupElements, CompareLookupElements, DivRemLookupElements,
        JumpTableLookupElements, MemoryAccessLookupElements, MerkleNodeLookupElements,
        MultiplicationLookupElements, PopcountLookupElements, PowerOfTwoLookupElements,
        ProgramExecutionLookupElements, ProgramMemoryLookupElements, RegisterMemoryLookupElements,
        WitnessCallLookupElements,
    },
};

macros::register_relation! {
    enum RelationVariant {
        ProgramExecutionLookupElements,
        RegisterMemoryLookupElements,
        ProgramMemoryLookupElements,
        JumpTableLookupElements,
        Range256LookupElements,
        MemoryAccessLookupElements,
        BitwiseAndLookupElements,
        BitwiseAndByteLookupElements,
        PowerOfTwoLookupElements,
        PopcountLookupElements,
        BitcountLookupElements,
        Blake2bCallLookupElements,
        Blake2bCompressionLookupElements,
        MerkleNodeLookupElements,
        MultiplicationLookupElements,
        BitwiseLookupElements,
        CompareLookupElements,
        DivRemLookupElements,
        ByteToBitsLookupElements,
        WitnessCallLookupElements,
    };
    pub(crate) trait RegisteredLookupBound {}
}

/// The drawn relations, in the order the channel drew them. Never in
/// `TypeId` order: a type's id moves with the build (a crate's features
/// change it), and the leaf circuits, so a kernel's program id, are
/// compiled over [`AllLookupElements::relation_challenges`]'s order.
#[derive(Default, Debug, Clone)]
pub struct AllLookupElements(Vec<(TypeId, RelationVariant)>);

impl AllLookupElements {
    fn get(&self, type_id: TypeId) -> Option<&RelationVariant> {
        self.0
            .iter()
            .find_map(|(id, variant)| (*id == type_id).then_some(variant))
    }
}

impl<T: RegisteredLookupBound> AsRef<T> for AllLookupElements {
    fn as_ref(&self) -> &T {
        let variant = self
            .get(TypeId::of::<T>())
            .expect("lookup elements weren't initialized");
        T::unwrap_ref(variant)
    }
}

/// A drawn relation's name and challenges: `z` and the powers
/// `1, α, α², …` its tuples combine with, one per limb. A tuple `v`
/// enters the logup as `Σ_i α^i·v_i − z`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelationChallenges {
    pub name: alloc::string::String,
    pub z: SecureField,
    pub alpha_powers: alloc::vec::Vec<SecureField>,
}

impl RelationChallenges {
    /// Read through the relation's own `combine`: `combine([]) = −z`, and
    /// the tuple with a one at limb `i` combines to `α^i − z`.
    pub fn of<R: stwo_constraint_framework::Relation<BaseField, SecureField>>(
        relation: &R,
    ) -> Self {
        let z = -relation.combine(&[]);
        let alpha_powers = (0..relation.get_size())
            .map(|i| {
                let mut unit = alloc::vec![BaseField::zero(); i + 1];
                unit[i] = BaseField::one();
                relation.combine(&unit) + z
            })
            .collect();
        Self {
            name: relation.get_name().into(),
            z,
            alpha_powers,
        }
    }
}

impl AllLookupElements {
    /// Every drawn relation's challenges, in the order drawn.
    pub fn relation_challenges(&self) -> alloc::vec::Vec<RelationChallenges> {
        self.0
            .iter()
            .map(|(_, variant)| variant.challenges())
            .collect()
    }
}

mod private {
    pub trait Sealed {}
}
impl<T: RegisteredLookupBound> private::Sealed for T {}

pub(crate) trait ComponentLookupElements: private::Sealed {
    fn dummy() -> Self;

    fn get(lookup_elements: &AllLookupElements) -> Self;

    fn draw(
        lookup_elements: &mut AllLookupElements,
        channel: &mut impl stwo::core::channel::Channel,
    );
}

impl<T: RegisteredLookupBound> ComponentLookupElements for T {
    fn dummy() -> Self {
        <Self as RegisteredLookupBound>::dummy()
    }

    fn get(lookup_elements: &AllLookupElements) -> Self {
        let this: &Self = lookup_elements.as_ref();
        this.clone()
    }

    fn draw(
        lookup_elements: &mut AllLookupElements,
        channel: &mut impl stwo::core::channel::Channel,
    ) {
        let type_id = TypeId::of::<Self>();
        if lookup_elements.get(type_id).is_none() {
            let variant = <Self as RegisteredLookupBound>::draw(channel).into();
            lookup_elements.0.push((type_id, variant));
        }
    }
}

#[impl_for_tuples(9)]
impl private::Sealed for T {}

#[impl_for_tuples(9)]
#[allow(clippy::unused_unit)]
impl ComponentLookupElements for T {
    fn dummy() -> Self {
        for_tuples!( ( #( <T as ComponentLookupElements>::dummy() ),* ) )
    }

    fn get(lookup_elements: &AllLookupElements) -> Self {
        for_tuples!( ( #( <T as ComponentLookupElements>::get(lookup_elements) ),* ) )
    }

    fn draw(
        lookup_elements: &mut AllLookupElements,
        channel: &mut impl stwo::core::channel::Channel,
    ) {
        for_tuples!( #( <T as ComponentLookupElements>::draw(lookup_elements, channel); )* );
    }
}
