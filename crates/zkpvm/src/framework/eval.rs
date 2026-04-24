use num_traits::{One, Zero};
use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::{EvalAtRow, FrameworkEval};

use crate::trace::eval::TraceEval;

use crate::framework::traits::builtin::BuiltInComponent;

/// Combine up to 8 LE bytes into a single field element representing the
/// same u64 (mod p).  Shared by CpuChip's Phi7 inversion witness and the
/// ShiftQuotient identity.  `bytes.len() <= 8`.
pub fn combine_le_u64<E: EvalAtRow>(bytes: &[E::F]) -> E::F {
    debug_assert!(bytes.len() <= 8);
    let b256 = E::F::from(BaseField::from(256u32));
    let mut out = E::F::zero();
    let mut pow = E::F::one();
    for b in bytes {
        out += b.clone() * pow.clone();
        pow = pow.clone() * b256.clone();
    }
    out
}

pub struct BuiltInComponentEval<'a, C: BuiltInComponent> {
    pub(crate) component: &'a C,
    pub(crate) log_size: u32,
    pub(crate) lookup_elements: C::LookupElements,
}

impl<C: BuiltInComponent> BuiltInComponentEval<'_, C> {
    pub(crate) const fn max_constraint_log_degree_bound(log_size: u32) -> u32 {
        log_size + C::LOG_CONSTRAINT_DEGREE_BOUND
    }
}

impl<C: BuiltInComponent> FrameworkEval for BuiltInComponentEval<'_, C> {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        Self::max_constraint_log_degree_bound(self.log_size)
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let trace_eval = TraceEval::new(&mut eval);
        C::add_constraints(self.component, &mut eval, trace_eval, &self.lookup_elements);
        eval
    }
}

pub type FrameworkComponent<'a, C> =
    stwo_constraint_framework::FrameworkComponent<BuiltInComponentEval<'a, C>>;
