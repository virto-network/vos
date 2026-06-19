//! Auto-witnessing OODS re-evaluation.
//!
//! The stwo verifier's DEEP-ALI check re-runs every inner-AIR constraint at the
//! OODS point and Horner-combines them into the composition value
//! (`core/air/components.rs::eval_composition_polynomial_at_point`). To embed
//! that check *in-AIR* for the recursion join, every QM31 product must be
//! witnessed so each constraint stays degree ≤ 2 (the lifted protocol's bound).
//!
//! Rather than hand-port each chip's constraints, this module drives a chip's
//! own generic `evaluate<E: EvalAtRow>` through a degree-reducing symbolic
//! evaluator ([`OodsEval`]). Its field handle ([`Handle`]) carries a value and a
//! degree; whenever two degree-1 handles are multiplied the product is lowered
//! to a fresh committed column (the witnessed-product idiom of
//! `oods_composition_chip.rs`).
//!
//! The same walk runs twice, parameterised by a [`WitBackend`] so the column
//! layout agrees by construction (the chip's `evaluate` is the shared cursor):
//!
//! * [`RecordBackend`] (host, `V = SecureField`): computes each witnessed
//!   product's concrete value and appends it to an ordered column schedule — the
//!   join's main-trace fill — and accumulates the composition value.
//! * [`VerifyBackend`] (in-AIR, `V = E::EF`): re-reads those columns via
//!   `next_trace_mask` in the *same* order and emits the degree-2 binding
//!   constraints plus the final DEEP-ALI equality.
//!
//! Aux columns the chip doesn't itself read (the random coefficient, the
//! vanishing-quotient denominator inverse, the doubled-OODS-x factor, and the
//! composition mask) are allocated through [`WitBackend::aux`] at fixed points
//! in [`drive`], so they too land in a deterministic order.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub};
use std::rc::{Rc, Weak};

use num_traits::{One, Zero};
use stwo::core::Fraction;
use stwo::core::fields::FieldExpOps;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::{SECURE_EXTENSION_DEGREE, SecureField};
use stwo_constraint_framework::logup::LogupAtRow;
use stwo_constraint_framework::{
    EvalAtRow, FrameworkEval, INTERACTION_TRACE_IDX, PREPROCESSED_TRACE_IDX,
};

// ── The mode abstraction (host record vs in-AIR verify) ────────────────────

/// An auxiliary committed input column — OODS protocol data the inner chip's
/// `evaluate` doesn't itself read, allocated by [`drive`] around the walk.
#[derive(Clone, Copy, Debug)]
pub enum AuxKind {
    /// The random coefficient (Horner base) drawn after committing the trace.
    Rc,
    /// The vanishing-quotient denominator inverse at the OODS point.
    Dinv,
    /// `oods_point.repeated_double(mlbd-1).x` — recombines the composition mask.
    Ox,
    /// The `i`-th composition-trace OODS mask sample.
    Comp(usize),
}

/// Backs an [`OodsEval`] walk: how a column value is obtained, how a degree-2
/// product is witnessed, and how the final equality is discharged. The two
/// impls differ only here; the walk itself is the inner chip's `evaluate`.
pub trait WitBackend: Sized {
    /// A field value: a concrete `SecureField` (host) or the underlying
    /// evaluator's `EF` expression (in-AIR).
    type V: Clone;

    fn v_const(x: SecureField) -> Self::V;
    fn v_add(a: Self::V, b: Self::V) -> Self::V;
    fn v_sub(a: Self::V, b: Self::V) -> Self::V;
    fn v_mul(a: Self::V, b: Self::V) -> Self::V;
    fn v_neg(a: Self::V) -> Self::V;

    /// The OODS mask of one inner column at `interaction`, one value per offset.
    /// Allocates the matching committed join column(s).
    fn next_mask<const N: usize>(
        &mut self,
        interaction: usize,
        offsets: [isize; N],
    ) -> [Self::V; N];

    /// An auxiliary committed input column (see [`AuxKind`]).
    fn aux(&mut self, kind: AuxKind) -> Self::V;

    /// Lower a product of two degree-1 handles to a fresh committed column equal
    /// to `a*b`. In-AIR this also emits the degree-2 binding `col - a*b == 0`.
    fn witness_mul(&mut self, a: Self::V, b: Self::V) -> Self::V;

    /// Discharge the final DEEP-ALI equality `lhs == rhs` (degree 1).
    fn assert_eq(&mut self, lhs: Self::V, rhs: Self::V);

    /// Advance to the next component's mask (multi-component walks via
    /// [`drive_multi`]). Default no-op — single-component backends and the
    /// sequential-reading in-AIR backend don't switch masks.
    fn start_component(&mut self) {}
}

// ── The degree-tracking field handle ───────────────────────────────────────

/// A field element threaded through a chip's `evaluate`: its backing value plus
/// a degree bound. A `degree`-0 handle is a constant; column reads and witnessed
/// products are degree 1. Multiplying two degree-1 handles witnesses the product
/// back down to degree 1, keeping every emitted constraint degree ≤ 2.
pub struct Handle<B: WitBackend> {
    value: B::V,
    degree: u8,
    ctx: Weak<RefCell<B>>,
}

impl<B: WitBackend> Clone for Handle<B> {
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
            degree: self.degree,
            ctx: self.ctx.clone(),
        }
    }
}

impl<B: WitBackend> core::fmt::Debug for Handle<B> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Handle(degree {})", self.degree)
    }
}

impl<B: WitBackend> Handle<B> {
    fn lift(value: B::V, degree: u8, ctx: Weak<RefCell<B>>) -> Self {
        Self { value, degree, ctx }
    }

    fn konst(x: SecureField) -> Self {
        Self {
            value: B::v_const(x),
            degree: 0,
            ctx: Weak::new(),
        }
    }

    /// The live backend handle from whichever operand carries one (constants
    /// don't), for propagating context through arithmetic.
    fn pick_ctx(a: &Self, b: &Self) -> Weak<RefCell<B>> {
        if a.ctx.strong_count() > 0 {
            a.ctx.clone()
        } else {
            b.ctx.clone()
        }
    }

    /// The exposed value (in-AIR: the `EF` expression). Used by [`drive`] to feed
    /// the final equality into the backend.
    fn into_value(self) -> B::V {
        self.value
    }
}

impl<B: WitBackend> Add for Handle<B> {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        let ctx = Self::pick_ctx(&self, &rhs);
        Self::lift(
            B::v_add(self.value, rhs.value),
            self.degree.max(rhs.degree),
            ctx,
        )
    }
}

impl<B: WitBackend> Sub for Handle<B> {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        let ctx = Self::pick_ctx(&self, &rhs);
        Self::lift(
            B::v_sub(self.value, rhs.value),
            self.degree.max(rhs.degree),
            ctx,
        )
    }
}

impl<B: WitBackend> Mul for Handle<B> {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        if self.degree >= 1 && rhs.degree >= 1 {
            // A genuine degree-2 product: witness it down to a fresh column.
            let ctx = self
                .ctx
                .upgrade()
                .or_else(|| rhs.ctx.upgrade())
                .expect("backend alive during witnessing");
            let w = ctx
                .borrow_mut()
                .witness_mul(self.value.clone(), rhs.value.clone());
            Self::lift(w, 1, Rc::downgrade(&ctx))
        } else {
            // At least one constant operand: no degree increase, no witness.
            let ctx = Self::pick_ctx(&self, &rhs);
            Self::lift(
                B::v_mul(self.value, rhs.value),
                self.degree + rhs.degree,
                ctx,
            )
        }
    }
}

impl<B: WitBackend> Neg for Handle<B> {
    type Output = Self;
    fn neg(self) -> Self {
        let ctx = self.ctx.clone();
        Self::lift(B::v_neg(self.value), self.degree, ctx)
    }
}

impl<B: WitBackend> AddAssign for Handle<B> {
    fn add_assign(&mut self, rhs: Self) {
        *self = self.clone() + rhs;
    }
}

impl<B: WitBackend> MulAssign for Handle<B> {
    fn mul_assign(&mut self, rhs: Self) {
        *self = self.clone() * rhs;
    }
}

impl<B: WitBackend> AddAssign<BaseField> for Handle<B> {
    fn add_assign(&mut self, rhs: BaseField) {
        *self = self.clone() + Handle::konst(rhs.into());
    }
}

impl<B: WitBackend> Add<BaseField> for Handle<B> {
    type Output = Self;
    fn add(self, rhs: BaseField) -> Self {
        self + Handle::konst(rhs.into())
    }
}

impl<B: WitBackend> Mul<BaseField> for Handle<B> {
    type Output = Self;
    fn mul(self, rhs: BaseField) -> Self {
        self * Handle::konst(rhs.into())
    }
}

impl<B: WitBackend> Add<SecureField> for Handle<B> {
    type Output = Self;
    fn add(self, rhs: SecureField) -> Self {
        self + Handle::konst(rhs)
    }
}

impl<B: WitBackend> Sub<SecureField> for Handle<B> {
    type Output = Self;
    fn sub(self, rhs: SecureField) -> Self {
        self - Handle::konst(rhs)
    }
}

impl<B: WitBackend> Mul<SecureField> for Handle<B> {
    type Output = Self;
    fn mul(self, rhs: SecureField) -> Self {
        self * Handle::konst(rhs)
    }
}

impl<B: WitBackend> From<BaseField> for Handle<B> {
    fn from(x: BaseField) -> Self {
        Handle::konst(x.into())
    }
}

impl<B: WitBackend> From<SecureField> for Handle<B> {
    fn from(x: SecureField) -> Self {
        Handle::konst(x)
    }
}

impl<B: WitBackend> Zero for Handle<B> {
    fn zero() -> Self {
        Handle::konst(SecureField::zero())
    }
    fn is_zero(&self) -> bool {
        panic!("Handle: cannot test an OODS expression for zero")
    }
}

impl<B: WitBackend> One for Handle<B> {
    fn one() -> Self {
        Handle::konst(SecureField::one())
    }
}

impl<B: WitBackend> FieldExpOps for Handle<B> {
    fn inverse(&self) -> Self {
        // Chips witness inverses as committed columns (`a * inv == 1`); a literal
        // `.inverse()` on a column handle has no degree-bounded arithmetisation.
        panic!("Handle: .inverse() unsupported — witness the inverse as a column")
    }
}

// ── The evaluator that drives a chip's `evaluate` ──────────────────────────

/// An [`EvalAtRow`] whose field type is [`Handle`]; reading a column returns a
/// degree-1 handle and `add_constraint` folds the constraint into the running
/// Horner accumulator (with each `acc·rc` multiply witnessed).
pub struct OodsEval<B: WitBackend> {
    ctx: Rc<RefCell<B>>,
    rc: B::V,
    acc: Option<B::V>,
    /// Logup state for chips that emit lookups (`add_to_relation`): the prefix-sum
    /// constraints are folded into the same Horner accumulator, with every QM31
    /// denominator product witnessed.
    logup: LogupAtRow<Self>,
}

impl<B: WitBackend> OodsEval<B> {
    /// Reset the logup for the next component (its own `claimed_sum`/`log_size`),
    /// leaving the Horner accumulator intact — the multi-component continuous fold.
    /// The previous logup must already be finalized (every component finalizes its
    /// own; constraint-free ones start finalized).
    pub fn set_logup(&mut self, claimed_sum: SecureField, log_size: u32) {
        self.logup = LogupAtRow::new(INTERACTION_TRACE_IDX, claimed_sum, log_size);
    }
}

impl<B: WitBackend> EvalAtRow for OodsEval<B> {
    type F = Handle<B>;
    type EF = Handle<B>;

    fn next_interaction_mask<const N: usize>(
        &mut self,
        interaction: usize,
        offsets: [isize; N],
    ) -> [Self::F; N] {
        let vals = self.ctx.borrow_mut().next_mask(interaction, offsets);
        let w = Rc::downgrade(&self.ctx);
        vals.map(|v| Handle::lift(v, 1, w.clone()))
    }

    fn add_constraint<G>(&mut self, constraint: G)
    where
        Self::EF: Mul<G, Output = Self::EF> + From<G>,
    {
        let c: Handle<B> = constraint.into();
        match self.acc.take() {
            None => self.acc = Some(c.value),
            Some(acc) => {
                // Horner: acc·rc + c. The `acc·rc` product is degree 2 → witness.
                let m = self.ctx.borrow_mut().witness_mul(acc, self.rc.clone());
                self.acc = Some(B::v_add(m, c.value));
            }
        }
    }

    fn combine_ef(values: [Self::F; SECURE_EXTENSION_DEGREE]) -> Self::EF {
        combine4(values)
    }

    // The logup path, replicating stwo's `logup_proxy!()` (which is `pub(crate)`
    // and so cannot be imported). Lookups (`add_to_relation`, the default impl)
    // push fractions; `finalize_logup*` emits the cumulative-sum constraints.
    // Each `diff·denominator` is a degree-2 product → witnessed by `Handle`'s
    // `Mul`, like every other product, and the constraints fold into the same
    // Horner accumulator as the chip's `add_constraint`s.

    fn write_logup_frac(&mut self, fraction: Fraction<Self::EF, Self::EF>) {
        if self.logup.fracs.is_empty() {
            self.logup.is_finalized = false;
        }
        self.logup.fracs.push(fraction);
    }

    #[allow(clippy::ptr_arg)] // signature must match the trait's `&Batching` (= &Vec<usize>)
    fn finalize_logup_batched(&mut self, batching: &Vec<usize>) {
        assert!(!self.logup.is_finalized, "LogupAtRow was already finalized");
        let fracs = self.logup.fracs.clone();
        let interaction = self.logup.interaction;
        let cumsum_shift = self.logup.cumsum_shift;
        assert_eq!(
            batching.len(),
            fracs.len(),
            "Batching must match the number of logup entries"
        );

        let last_batch = *batching.iter().max().unwrap();

        type Frac<B> = Fraction<Handle<B>, Handle<B>>;
        let mut fracs_by_batch: HashMap<usize, Vec<Frac<B>>> = HashMap::new();
        for (batch, frac) in batching.iter().zip(fracs.iter()) {
            fracs_by_batch.entry(*batch).or_default().push(frac.clone());
        }

        let keys: HashSet<usize> = fracs_by_batch.keys().copied().collect();
        let all_batches: HashSet<usize> = (0..last_batch + 1).collect();
        assert_eq!(
            keys, all_batches,
            "Batching must contain all consecutive batches"
        );

        let mut prev_col_cumsum = <Handle<B> as Zero>::zero();
        for batch_id in 0..last_batch {
            let cur_frac: Frac<B> = fracs_by_batch[&batch_id].iter().cloned().sum();
            let [cur_cumsum] = self.next_extension_interaction_mask(interaction, [0]);
            let diff = cur_cumsum.clone() - prev_col_cumsum.clone();
            prev_col_cumsum = cur_cumsum;
            self.add_constraint(diff * cur_frac.denominator - cur_frac.numerator);
        }

        let frac: Frac<B> = fracs_by_batch[&last_batch].clone().into_iter().sum();
        let [prev_row_cumsum, cur_cumsum] =
            self.next_extension_interaction_mask(interaction, [-1, 0]);
        let diff = cur_cumsum - prev_row_cumsum - prev_col_cumsum.clone();
        // `cumsum_shift = claimed_sum / n_rows` makes the per-row constraint
        // uniform (sum-zero) so it applies on every row.
        let shifted_diff = diff + cumsum_shift;
        self.add_constraint(shifted_diff * frac.denominator - frac.numerator);

        self.logup.is_finalized = true;
    }

    fn finalize_logup(&mut self) {
        let batches = (0..self.logup.fracs.len()).collect::<Vec<_>>();
        self.finalize_logup_batched(&batches)
    }

    fn finalize_logup_in_pairs(&mut self) {
        let batches = (0..self.logup.fracs.len())
            .map(|n| n / 2)
            .collect::<Vec<_>>();
        self.finalize_logup_batched(&batches)
    }
}

/// `from_partial_evals`: combine four QM31-coordinate column handles into one
/// extension handle, `v0 + v1·u1 + v2·u2 + v3·u3` (a degree-preserving linear
/// combine — `u1,u2,u3` are constant basis units, so no product is witnessed).
fn combine4<B: WitBackend>(values: [Handle<B>; SECURE_EXTENSION_DEGREE]) -> Handle<B> {
    let unit =
        |coords: [u32; 4]| Handle::konst(SecureField::from_m31_array(coords.map(BaseField::from)));
    let [v0, v1, v2, v3] = values;
    v0 + v1 * unit([0, 1, 0, 0]) + v2 * unit([0, 0, 1, 0]) + v3 * unit([0, 0, 0, 1])
}

// ── The shared walk: the chip's `evaluate` sandwiched by aux reads ─────────

/// Re-evaluate a chip's constraints at the OODS point, in walk order: read the
/// random coefficient, run the chip (samples + witnessed products + the Horner
/// fold, plus any logup cumulative-sum constraints), then recombine against the
/// composition mask and discharge the DEEP-ALI equality
/// `dinv·Σ rcᵏ·cₖ == composition_value`.
///
/// `walk` runs the chip's generic `evaluate<E>` against the supplied
/// [`OodsEval`] — for a [`FrameworkEval`] that is `|e| chip.evaluate(e)`; for a
/// chip reachable only through a crate seam it is the seam call. `claimed_sum`
/// and `inner_log_size` are the chip's own (for the logup `cumsum_shift`); the
/// composition value is `dinv · acc` where `acc` is the Horner sum the chip's
/// `add_constraint`s accumulate.
pub fn drive<B: WitBackend>(
    ctx: &Rc<RefCell<B>>,
    claimed_sum: SecureField,
    inner_log_size: u32,
    walk: impl FnOnce(OodsEval<B>) -> OodsEval<B>,
) {
    let rc = ctx.borrow_mut().aux(AuxKind::Rc);
    let eval = OodsEval {
        ctx: Rc::clone(ctx),
        rc,
        acc: None,
        logup: LogupAtRow::new(INTERACTION_TRACE_IDX, claimed_sum, inner_log_size),
    };
    let eval = walk(eval);
    // A constraint-free component contributes 0 to the composition.
    let acc = eval
        .acc
        .clone()
        .unwrap_or_else(|| B::v_const(SecureField::zero()));
    drop(eval); // release the strong ctx clone so the caller can reclaim the backend
    finalize_composition(ctx, acc);
}

/// Walk the FULL canonical AIR (all 31 components in `BASE_COMPONENTS` order)
/// through ONE evaluator, accumulating their constraints into a SINGLE Horner
/// fold — the single-uniform-component shape the recursion join takes. `comps`
/// is `(chip_idx, log_size, claimed_sum)` per component; `walk(idx, log_size,
/// eval)` runs that component's `evaluate`. The backend advances to each
/// component's mask via [`WitBackend::start_component`]; the logup is reset per
/// component (its own `claimed_sum`/`log_size`), while the Horner accumulator
/// runs continuously across all of them.
pub fn drive_multi<B: WitBackend>(
    ctx: &Rc<RefCell<B>>,
    comps: &[(usize, u32, SecureField)],
    walk: impl Fn(usize, u32, OodsEval<B>) -> OodsEval<B>,
) {
    let rc = ctx.borrow_mut().aux(AuxKind::Rc);
    let mut eval = OodsEval {
        ctx: Rc::clone(ctx),
        rc,
        acc: None,
        logup: LogupAtRow::dummy(),
    };
    for &(idx, log_size, claimed_sum) in comps {
        ctx.borrow_mut().start_component();
        eval.set_logup(claimed_sum, log_size);
        eval = walk(idx, log_size, eval);
    }
    let acc = eval
        .acc
        .clone()
        .unwrap_or_else(|| B::v_const(SecureField::zero()));
    drop(eval);
    finalize_composition(ctx, acc);
}

/// Scale the Horner sum by `dinv`, recombine the composition mask, and discharge
/// the DEEP-ALI equality `dinv·Σ rcᵏ·cₖ == left + ox·right`. The denominator
/// inverse is the same for every component, so it factors out of the whole fold.
fn finalize_composition<B: WitBackend>(ctx: &Rc<RefCell<B>>, acc: B::V) {
    let w = Rc::downgrade(ctx);
    let acc = Handle::lift(acc, 1, w.clone());
    let dinv = Handle::lift(ctx.borrow_mut().aux(AuxKind::Dinv), 1, w.clone());
    let comp = dinv * acc;

    let comp_mask: [Handle<B>; 2 * SECURE_EXTENSION_DEGREE] =
        std::array::from_fn(|i| Handle::lift(ctx.borrow_mut().aux(AuxKind::Comp(i)), 1, w.clone()));
    let ox = Handle::lift(ctx.borrow_mut().aux(AuxKind::Ox), 1, w.clone());
    let [c0, c1, c2, c3, c4, c5, c6, c7] = comp_mask;
    let left = combine4([c0, c1, c2, c3]);
    let right = combine4([c4, c5, c6, c7]);
    let lhs = left + ox * right;

    ctx.borrow_mut()
        .assert_eq(comp.into_value(), lhs.into_value());
}

// ── Host-record backend (V = SecureField) ──────────────────────────────────

/// The OODS data a [`RecordBackend`] replays: the inner proof's mask samples
/// (`mask[interaction][column][offset]`) plus the protocol scalars. The
/// preprocessed tree (`mask[PREPROCESSED_TRACE_IDX]`) is the FULL preprocessed
/// column set; a component's reads index into it via its
/// `preprocessed_column_indices` ([`RecordBackend::set_preproc_indices`]), the
/// same remap stwo applies — needed when a chip's preprocessed reads aren't a
/// contiguous identity range.
pub struct OodsInputs {
    pub mask: Vec<Vec<Vec<SecureField>>>,
    pub random_coeff: SecureField,
    pub denom_inverse: SecureField,
    pub oods_x_doubled: SecureField,
    pub comp: [SecureField; 2 * SECURE_EXTENSION_DEGREE],
}

/// Walks the chip with concrete OODS values, recording every committed column's
/// value (in allocation order — the join's host trace fill) and the composition
/// value the DEEP-ALI equality must match.
pub struct RecordBackend {
    inputs: OodsInputs,
    col_cursor: Vec<usize>,
    /// Per-read preprocessed column indices (stwo's `preprocessed_column_indices`).
    /// Empty ⇒ read the preprocessed tree sequentially (identity).
    preproc_indices: Vec<usize>,
    preproc_cursor: usize,
    /// Every committed join column's value, in allocation order.
    pub schedule: Vec<SecureField>,
    /// Count of witnessed products (degree-2 reductions).
    pub witnessed: usize,
    /// The two sides of the discharged DEEP-ALI equality.
    pub final_lhs: Option<SecureField>,
    pub final_rhs: Option<SecureField>,
}

impl RecordBackend {
    pub fn new(inputs: OodsInputs) -> Self {
        let n_interactions = inputs.mask.len().max(3);
        Self {
            inputs,
            col_cursor: vec![0; n_interactions],
            preproc_indices: Vec::new(),
            preproc_cursor: 0,
            schedule: Vec::new(),
            witnessed: 0,
            final_lhs: None,
            final_rhs: None,
        }
    }

    /// Map preprocessed reads through the component's `preprocessed_column_indices`
    /// (stwo's remap) instead of reading the preprocessed tree sequentially.
    pub fn set_preproc_indices(&mut self, indices: Vec<usize>) {
        self.preproc_indices = indices;
    }

    fn push(&mut self, v: SecureField) -> SecureField {
        self.schedule.push(v);
        v
    }
}

impl WitBackend for RecordBackend {
    type V = SecureField;

    fn v_const(x: SecureField) -> Self::V {
        x
    }
    fn v_add(a: Self::V, b: Self::V) -> Self::V {
        a + b
    }
    fn v_sub(a: Self::V, b: Self::V) -> Self::V {
        a - b
    }
    fn v_mul(a: Self::V, b: Self::V) -> Self::V {
        a * b
    }
    fn v_neg(a: Self::V) -> Self::V {
        -a
    }

    fn next_mask<const N: usize>(
        &mut self,
        interaction: usize,
        _offsets: [isize; N],
    ) -> [Self::V; N] {
        // Preprocessed reads remap through `preprocessed_column_indices` (when set)
        // — the same the verifier applies; a column may be re-read or skipped, so a
        // sequential cursor would diverge. (Each preprocessed read is offset [0].)
        if interaction == PREPROCESSED_TRACE_IDX && !self.preproc_indices.is_empty() {
            let col = self.preproc_indices[self.preproc_cursor];
            self.preproc_cursor += 1;
            let samples = self.inputs.mask[interaction][col].clone();
            assert_eq!(
                samples.len(),
                N,
                "preprocessed OODS mask offset count mismatch"
            );
            return std::array::from_fn(|i| self.push(samples[i]));
        }
        let col = self.col_cursor[interaction];
        self.col_cursor[interaction] += 1;
        let samples = self.inputs.mask[interaction][col].clone();
        assert_eq!(samples.len(), N, "OODS mask offset count mismatch");
        std::array::from_fn(|i| self.push(samples[i]))
    }

    fn aux(&mut self, kind: AuxKind) -> Self::V {
        let v = match kind {
            AuxKind::Rc => self.inputs.random_coeff,
            AuxKind::Dinv => self.inputs.denom_inverse,
            AuxKind::Ox => self.inputs.oods_x_doubled,
            AuxKind::Comp(i) => self.inputs.comp[i],
        };
        self.push(v)
    }

    fn witness_mul(&mut self, a: Self::V, b: Self::V) -> Self::V {
        self.witnessed += 1;
        self.push(a * b)
    }

    fn assert_eq(&mut self, lhs: Self::V, rhs: Self::V) {
        self.final_lhs = Some(lhs);
        self.final_rhs = Some(rhs);
    }
}

// ── Multi-component host-record backend (the full canonical AIR) ────────────

/// One component's OODS mask for a [`MultiRecordBackend`] walk. The preprocessed
/// tree (`mask[PREPROCESSED_TRACE_IDX]`) is the full column set; reads index into
/// it via `preproc_indices` (stwo's preprocessed remap).
pub struct ComponentMask {
    pub mask: Vec<Vec<Vec<SecureField>>>,
    pub preproc_indices: Vec<usize>,
}

/// Like [`RecordBackend`] but for [`drive_multi`]: one mask per component,
/// advanced by [`WitBackend::start_component`]. The shared aux columns (rc, dinv,
/// ox, composition mask) and the growing `schedule` span all components; the
/// per-interaction + preprocessed cursors reset at each component boundary.
pub struct MultiRecordBackend {
    components: Vec<ComponentMask>,
    cur: usize, // usize::MAX until the first start_component
    random_coeff: SecureField,
    denom_inverse: SecureField,
    oods_x_doubled: SecureField,
    comp: [SecureField; 2 * SECURE_EXTENSION_DEGREE],
    col_cursor: Vec<usize>,
    preproc_cursor: usize,
    /// Every committed join column's value, in allocation order.
    pub schedule: Vec<SecureField>,
    /// Count of witnessed products across all components.
    pub witnessed: usize,
    pub final_lhs: Option<SecureField>,
    pub final_rhs: Option<SecureField>,
}

impl MultiRecordBackend {
    pub fn new(
        components: Vec<ComponentMask>,
        random_coeff: SecureField,
        denom_inverse: SecureField,
        oods_x_doubled: SecureField,
        comp: [SecureField; 2 * SECURE_EXTENSION_DEGREE],
    ) -> Self {
        Self {
            components,
            cur: usize::MAX,
            random_coeff,
            denom_inverse,
            oods_x_doubled,
            comp,
            col_cursor: vec![0; 3],
            preproc_cursor: 0,
            schedule: Vec::new(),
            witnessed: 0,
            final_lhs: None,
            final_rhs: None,
        }
    }

    fn push(&mut self, v: SecureField) -> SecureField {
        self.schedule.push(v);
        v
    }
}

impl WitBackend for MultiRecordBackend {
    type V = SecureField;

    fn v_const(x: SecureField) -> Self::V {
        x
    }
    fn v_add(a: Self::V, b: Self::V) -> Self::V {
        a + b
    }
    fn v_sub(a: Self::V, b: Self::V) -> Self::V {
        a - b
    }
    fn v_mul(a: Self::V, b: Self::V) -> Self::V {
        a * b
    }
    fn v_neg(a: Self::V) -> Self::V {
        -a
    }

    fn next_mask<const N: usize>(
        &mut self,
        interaction: usize,
        _offsets: [isize; N],
    ) -> [Self::V; N] {
        let cur = self.cur;
        let col = if interaction == PREPROCESSED_TRACE_IDX
            && !self.components[cur].preproc_indices.is_empty()
        {
            let c = self.components[cur].preproc_indices[self.preproc_cursor];
            self.preproc_cursor += 1;
            c
        } else {
            let c = self.col_cursor[interaction];
            self.col_cursor[interaction] += 1;
            c
        };
        let samples = self.components[cur].mask[interaction][col].clone();
        assert_eq!(samples.len(), N, "OODS mask offset count mismatch");
        std::array::from_fn(|i| self.push(samples[i]))
    }

    fn aux(&mut self, kind: AuxKind) -> Self::V {
        let v = match kind {
            AuxKind::Rc => self.random_coeff,
            AuxKind::Dinv => self.denom_inverse,
            AuxKind::Ox => self.oods_x_doubled,
            AuxKind::Comp(i) => self.comp[i],
        };
        self.push(v)
    }

    fn witness_mul(&mut self, a: Self::V, b: Self::V) -> Self::V {
        self.witnessed += 1;
        self.push(a * b)
    }

    fn assert_eq(&mut self, lhs: Self::V, rhs: Self::V) {
        self.final_lhs = Some(lhs);
        self.final_rhs = Some(rhs);
    }

    fn start_component(&mut self) {
        self.cur = self.cur.wrapping_add(1);
        self.col_cursor = vec![0; 3];
        self.preproc_cursor = 0;
    }
}

// ── Bandwidth-measurement backend (P5.3 task #0: flat-schedule dataflow) ────

/// The streamable *support* of a value threaded through a chip's `evaluate`: the
/// sorted set of streamed-schedule node indices it linearly depends on. Latched
/// columns (the aux `rc`/`dinv`/`ox`/composition mask) and constants contribute
/// nothing — in the streamed layout they are held on EVERY row, so they are
/// reachable at offset 0 from anywhere and never count toward cross-row distance.
/// Only mask samples and witnessed products are nodes.
#[derive(Clone, Default)]
pub struct LinForm {
    support: Vec<u32>,
}

impl LinForm {
    fn empty() -> Self {
        Self {
            support: Vec::new(),
        }
    }
    fn node(i: u32) -> Self {
        Self { support: vec![i] }
    }
    /// Sorted, deduplicated union of two supports (linear combination).
    fn union(a: &Self, b: &Self) -> Self {
        if a.support.is_empty() {
            return b.clone();
        }
        if b.support.is_empty() {
            return a.clone();
        }
        let mut s = Vec::with_capacity(a.support.len() + b.support.len());
        s.extend_from_slice(&a.support);
        s.extend_from_slice(&b.support);
        s.sort_unstable();
        s.dedup();
        Self { support: s }
    }
}

/// Measures the cross-row operand *bandwidth* of the flat OODS schedule
/// [`drive_multi`] produces. For every witnessed product it records how far back
/// in the streamed schedule the product's furthest operand node lives (the offset
/// a streamed row would have to reach), and it tracks each node's lifetime so the
/// live-set width `W` (the number of simultaneously-live nodes — the window a
/// banded layout must hold) can be computed, both for the naive
/// (`TraceEval::new` reads-all-masks-up-front) order and for a lazy order that
/// defers each mask read to its first use.
///
/// It carries NO field values: the schedule's *shape* — which products witness,
/// in what order, referencing which nodes — is fixed by the walk alone,
/// independent of the concrete OODS samples. So the same `drive_multi` walk that
/// the record/verify backends use yields the identical node sequence here.
pub struct BandwidthBackend {
    next_node: u32,
    /// `death[n]` = the last streamed position at which node `n` is consumed
    /// (defaults to its own birth index, so an unused node has a unit lifetime).
    death: Vec<u32>,
    /// `first_use[n]` = the first position node `n` is consumed (`u32::MAX` until
    /// used) — the earliest a lazy schedule could place a deferred mask read.
    first_use: Vec<u32>,
    /// Whether node `n` is a mask sample (deferrable) vs a witnessed product
    /// (pinned to its creation, since it depends on earlier nodes).
    is_mask: Vec<bool>,
    /// Per witnessed product: the distance to its furthest streamable operand.
    pub distances: Vec<u32>,
    /// The component index each recorded distance belongs to (parallel array).
    pub dist_component: Vec<usize>,
    cur_component: usize,
    pub n_mask_nodes: usize,
    pub n_witness_nodes: usize,
    /// Witnessed products whose operands are ALL latched (e.g. `ox·right`): these
    /// stay latched in the streamed layout, so they are not streamed nodes.
    pub n_latched_products: usize,
}

impl Default for BandwidthBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl BandwidthBackend {
    pub fn new() -> Self {
        Self {
            next_node: 0,
            death: Vec::new(),
            first_use: Vec::new(),
            is_mask: Vec::new(),
            distances: Vec::new(),
            dist_component: Vec::new(),
            cur_component: usize::MAX,
            n_mask_nodes: 0,
            n_witness_nodes: 0,
            n_latched_products: 0,
        }
    }

    /// Total streamed nodes (mask samples + witnessed products).
    pub fn n_nodes(&self) -> usize {
        self.next_node as usize
    }

    /// Record that every node in `lf` is consumed at streamed position `at`.
    fn consume(&mut self, lf: &LinForm, at: u32) {
        for &n in &lf.support {
            self.death[n as usize] = at; // monotonic: `at` only ever grows
            if self.first_use[n as usize] == u32::MAX {
                self.first_use[n as usize] = at;
            }
        }
    }

    fn new_node(&mut self, is_mask: bool) -> u32 {
        let n = self.next_node;
        self.next_node += 1;
        self.death.push(n);
        self.first_use.push(u32::MAX);
        self.is_mask.push(is_mask);
        n
    }

    /// Max live-set under the naive (read-all-masks-up-front) order: a node is
    /// live from its creation index to its last use.
    pub fn live_set_naive(&self) -> u32 {
        self.sweep(false)
    }

    /// Max live-set if every mask read is deferred to its first use (the lazy-read
    /// restructure): a mask node is live only across `[first_use, last_use]`.
    pub fn live_set_lazy(&self) -> u32 {
        self.sweep(true)
    }

    fn sweep(&self, lazy: bool) -> u32 {
        let n = self.next_node as usize;
        if n == 0 {
            return 0;
        }
        // A node may die at position `n` (consumed by the final equality), so
        // `death + 1` reaches `n + 1`.
        let mut delta = vec![0i64; n + 2];
        for node in 0..n {
            let death = self.death[node];
            let birth = if lazy && self.is_mask[node] && self.first_use[node] != u32::MAX {
                self.first_use[node].min(death)
            } else {
                node as u32
            };
            delta[birth as usize] += 1;
            delta[death as usize + 1] -= 1;
        }
        let mut cur = 0i64;
        let mut max = 0i64;
        for d in delta {
            cur += d;
            if cur > max {
                max = cur;
            }
        }
        max as u32
    }
}

impl WitBackend for BandwidthBackend {
    type V = LinForm;

    fn v_const(_x: SecureField) -> Self::V {
        LinForm::empty()
    }
    fn v_add(a: Self::V, b: Self::V) -> Self::V {
        LinForm::union(&a, &b)
    }
    fn v_sub(a: Self::V, b: Self::V) -> Self::V {
        LinForm::union(&a, &b)
    }
    fn v_mul(a: Self::V, b: Self::V) -> Self::V {
        // Reached only when at least one operand is a constant (degree 0 ⇒ empty
        // support), so this preserves the support of the non-constant operand.
        LinForm::union(&a, &b)
    }
    fn v_neg(a: Self::V) -> Self::V {
        a
    }

    fn next_mask<const N: usize>(
        &mut self,
        _interaction: usize,
        _offsets: [isize; N],
    ) -> [Self::V; N] {
        // One streamed node per offset sample (each is a distinct committed OODS
        // value); values are irrelevant — only the count and order matter.
        std::array::from_fn(|_| {
            self.n_mask_nodes += 1;
            LinForm::node(self.new_node(true))
        })
    }

    fn aux(&mut self, _kind: AuxKind) -> Self::V {
        // Latched: held on every row, never a streamed node.
        LinForm::empty()
    }

    fn witness_mul(&mut self, a: Self::V, b: Self::V) -> Self::V {
        let at = self.next_node; // the product's prospective node index
        let union = LinForm::union(&a, &b);
        self.consume(&union, at);
        if union.support.is_empty() {
            // latched · latched ⇒ a latched product, not a streamed node.
            self.n_latched_products += 1;
            return LinForm::empty();
        }
        let dist = at - union.support[0]; // distance to the furthest operand node
        self.distances.push(dist);
        self.dist_component.push(self.cur_component);
        self.n_witness_nodes += 1;
        LinForm::node(self.new_node(false))
    }

    fn assert_eq(&mut self, lhs: Self::V, rhs: Self::V) {
        let at = self.next_node;
        self.consume(&lhs, at);
        self.consume(&rhs, at);
    }

    fn start_component(&mut self) {
        self.cur_component = self.cur_component.wrapping_add(1);
    }
}

// ── In-AIR verify backend (V = E::EF) ──────────────────────────────────────

/// Re-reads the recorded columns via `next_trace_mask` (in the same allocation
/// order) and emits the degree-2 binding constraints plus the DEEP-ALI equality
/// over the underlying evaluator `E`.
pub struct VerifyBackend<E: EvalAtRow> {
    eval: E,
}

impl<E: EvalAtRow> VerifyBackend<E> {
    pub fn new(eval: E) -> Self {
        Self { eval }
    }
    pub fn into_eval(self) -> E {
        self.eval
    }

    /// Read one QM31 (four base columns) from the join's main trace.
    fn read_qm31(&mut self) -> E::EF {
        let coords: [E::F; SECURE_EXTENSION_DEGREE] =
            std::array::from_fn(|_| self.eval.next_trace_mask());
        E::combine_ef(coords)
    }
}

impl<E: EvalAtRow> WitBackend for VerifyBackend<E> {
    type V = E::EF;

    fn v_const(x: SecureField) -> Self::V {
        E::EF::from(x)
    }
    fn v_add(a: Self::V, b: Self::V) -> Self::V {
        // `EvalAtRow::EF` is not bounded by `Add<Self>`, but is by `AddAssign`.
        let mut acc = a;
        acc += b;
        acc
    }
    fn v_sub(a: Self::V, b: Self::V) -> Self::V {
        a - b
    }
    fn v_mul(a: Self::V, b: Self::V) -> Self::V {
        a * b
    }
    fn v_neg(a: Self::V) -> Self::V {
        -a
    }

    fn next_mask<const N: usize>(
        &mut self,
        _interaction: usize,
        _offsets: [isize; N],
    ) -> [Self::V; N] {
        std::array::from_fn(|_| self.read_qm31())
    }

    fn aux(&mut self, _kind: AuxKind) -> Self::V {
        self.read_qm31()
    }

    fn witness_mul(&mut self, a: Self::V, b: Self::V) -> Self::V {
        let w = self.read_qm31();
        // The degree-2 binding: the committed column equals the product.
        let bound = Self::v_sub(w.clone(), a * b);
        self.eval.add_constraint(bound);
        w
    }

    fn assert_eq(&mut self, lhs: Self::V, rhs: Self::V) {
        self.eval.add_constraint(Self::v_sub(lhs, rhs));
    }
}

// ── The join AIR: one uniform component re-evaluating the OODS composition ──

/// A [`FrameworkEval`] that re-evaluates `chip`'s OODS composition in-AIR by
/// driving its `evaluate` through a [`VerifyBackend`]. Degree ≤ 2. `log_size` is
/// the join trace's row count; `inner_log_size`/`claimed_sum` are the inner
/// chip's, for the logup `cumsum_shift` (use `0`/anything when the chip has no
/// lookups).
#[derive(Clone)]
pub struct OodsJoinEval<C: FrameworkEval + Clone> {
    pub chip: C,
    pub log_size: u32,
    pub inner_log_size: u32,
    pub claimed_sum: SecureField,
}

impl<C: FrameworkEval + Clone> FrameworkEval for OodsJoinEval<C> {
    fn log_size(&self) -> u32 {
        self.log_size
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }
    fn evaluate<E: EvalAtRow>(&self, eval: E) -> E {
        let ctx = Rc::new(RefCell::new(VerifyBackend::new(eval)));
        let chip = &self.chip;
        drive(&ctx, self.claimed_sum, self.inner_log_size, |e| {
            chip.evaluate(e)
        });
        Rc::try_unwrap(ctx)
            .unwrap_or_else(|_| panic!("a Handle outlived the OODS walk"))
            .into_inner()
            .into_eval()
    }
}

// ── Shared prove/verify harness for an OODS join AIR ───────────────────────

use stwo::core::air::Component;
use stwo::core::pcs::PcsConfig;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::verifier::verify;
use stwo::prover::backend::{Col, Column, CpuBackend};
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo::prover::{CommitmentSchemeProver, prove};
use stwo_constraint_framework::{FrameworkComponent, TraceLocationAllocator};

use super::{P2MerkleChannel, Poseidon2M31Channel};

/// Lay out the recorded column schedule into the join's main trace: each QM31
/// becomes four M31 columns. Every join constraint is read-at-offset-0 (no
/// cross-row coupling) but not necessarily homogeneous — the logup
/// `cumsum_shift` and relation `z` leave constant terms that don't vanish on a
/// zero row — so the meaningful row is REPLICATED across all rows, making every
/// row an identical valid witness. With `tamper_col` set, bumps one committed
/// M31 on row 0 so its constraint fails (rejection check).
pub fn gen_join_trace(
    schedule: &[SecureField],
    trace_log: u32,
    tamper_col: Option<usize>,
) -> Vec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>> {
    let n_cols = schedule.len() * SECURE_EXTENSION_DEGREE;
    let n = 1usize << trace_log;
    let mut cols: Vec<Col<CpuBackend, BaseField>> = (0..n_cols)
        .map(|_| Col::<CpuBackend, BaseField>::zeros(n))
        .collect();
    let row: Vec<BaseField> = schedule.iter().flat_map(|q| q.to_m31_array()).collect();
    for (c, v) in row.into_iter().enumerate() {
        for r in 0..n {
            cols[c].set(r, v);
        }
    }
    if let Some(c) = tamper_col {
        let orig = cols[c].at(0);
        cols[c].set(0, orig + BaseField::one());
    }
    let domain = CanonicCoset::new(trace_log).circle_domain();
    cols.into_iter()
        .map(|col| CircleEvaluation::new(domain, col))
        .collect()
}

/// Prove + verify an OODS join AIR through the lifted Poseidon2-M31 protocol over
/// the recorded `schedule` (optionally tampered). `Err` ⇒ rejected.
pub fn prove_and_verify_join<J: FrameworkEval + Clone + Sync>(
    join: J,
    schedule: &[SecureField],
    trace_log: u32,
    tamper_col: Option<usize>,
    config: PcsConfig,
) -> Result<(), String> {
    let trace = gen_join_trace(schedule, trace_log, tamper_col);
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(trace_log + 1 + config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
    );
    let channel = &mut Poseidon2M31Channel::default();
    let mut cs = CommitmentSchemeProver::<CpuBackend, P2MerkleChannel>::new(config, &twiddles);
    let mut tb = cs.tree_builder();
    tb.extend_evals(Vec::new());
    tb.commit(channel);
    let mut tb = cs.tree_builder();
    tb.extend_evals(trace);
    tb.commit(channel);
    let component = FrameworkComponent::<J>::new(
        &mut TraceLocationAllocator::default(),
        join,
        SecureField::zero(),
    );
    let proof = prove::<CpuBackend, P2MerkleChannel>(&[&component], channel, cs)
        .map_err(|e| format!("prove: {e:?}"))?;

    let vch = &mut Poseidon2M31Channel::default();
    let mut vs = stwo::core::pcs::CommitmentSchemeVerifier::<P2MerkleChannel>::new(config);
    let sizes = component.trace_log_degree_bounds();
    vs.commit(proof.commitments[0], &sizes[0], vch);
    vs.commit(proof.commitments[1], &sizes[1], vch);
    verify(&[&component as &dyn Component], vch, &mut vs, proof)
        .map_err(|e| format!("verify: {e:?}"))
}
