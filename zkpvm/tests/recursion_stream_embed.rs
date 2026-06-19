//! Recursion build P5.3 — the STREAMED OODS-embed AIR (the session milestone).
//!
//! The single-uniform-component OODS embed (`oods_auto_join31`) proves the full
//! 31-component composition re-eval as PURE WIDTH (160600 M31 cols, log 6). That
//! width replicated across the channel's ~16384 rows OOMs. This AIR distributes the
//! embed down the rows via the proven route-spike mechanism, scaled to the
//! co-locate two-stream layout (recursion_stream_two):
//!
//!   * macs + products share ONE dense stream (`OPS_S` slots/row); each slot is
//!     uniform `r = oa·ob`, a mac being `ob = 1` so `r = oa`.
//!   * each slot's `oa`/`ob` is reconstructed from the window — co-located mask
//!     leaves (offset 0), prior stream results (offset `[0,-DR]`), latched OODS
//!     scalars (offset 0) — via PREPROCESSED coefficients (the schedule is fixed
//!     across canonical segments; only the OODS VALUES differ per proof).
//!   * `coeff·window = preproc(deg1)·main(deg1) = deg2`; the recon sum is ONE deg-2
//!     constraint (term count free); the product `r − oa·ob` is deg2; the final
//!     `is_final·r` (= lhs−rhs) and the latched constancy `not_last·(lat₁−lat₀)`
//!     are deg2. Every constraint ≤ degree 2 — the lifted protocol's bound.
//!
//! `assert_constraints_on_trace` checks only ZERO-ness, NOT the degree bound (a
//! degree-3 slip surfaces only as a FRI failure), so the milestone is the PROVE,
//! not the assert; the assert is the fast value-bug gate run first.
//!
//! Fast gate (default suite): `assert_constraints` on the real co-locate layout.
//! Milestone (`#[ignore]`, release): prove+verify; a tampered cell is rejected.
//! Run: `cargo test -p zkpvm --release --features poseidon2-channel \
//!        --test recursion_stream_embed -- --ignored --nocapture`

mod recursion_common;

use num_traits::{One, Zero};
use recursion_common::oods_auto::{ColocateLayout, N_LATCHED, WinPos};
use recursion_common::synth::{build_capture, synthetic_setup};
use recursion_common::{P2MerkleChannel, Poseidon2M31Channel, mobile_config};
use stwo::core::air::Component;
use stwo::core::fields::m31::{BaseField, M31};
use stwo::core::fields::qm31::{SECURE_EXTENSION_DEGREE, SecureField};
use stwo::core::pcs::{CommitmentSchemeVerifier, TreeVec};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::utils::{bit_reverse_index, coset_index_to_circle_domain_index};
use stwo::core::verifier::verify;
use stwo::prover::backend::{Col, Column, CpuBackend};
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo::prover::{CommitmentSchemeProver, prove};
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, ORIGINAL_TRACE_IDX, TraceLocationAllocator,
    assert_constraints_on_trace, preprocessed_columns::PreProcessedColumnId,
};

// ── Locked layout parameters (recursion_stream_two sweet spot) ──────────────
const T_PER_MAC: usize = 16; // terms/mac: minimises macs (1709) ⇒ small dr
const OPS_S: usize = 4; // dense-stream slots per row
const DR: usize = 24; // stream window depth in rows (measured dr=21 ≤ 24)
const N_OFF: usize = DR + 1; // window offsets [0,-1,…,-DR]
const NLEAF: usize = 80; // co-located leaf columns per row (measured max 74 ≤ 80)
const L_SYNTH: u32 = 4; // synthetic component log_size

/// Window positions a recon reads, in canonical order: leaves, then per-lane
/// stream offsets, then latched.
const WIN: usize = NLEAF + OPS_S * N_OFF + N_LATCHED;

const fn offsets() -> [isize; N_OFF] {
    let mut o = [0isize; N_OFF];
    let mut k = 0;
    while k < N_OFF {
        o[k] = -(k as isize);
        k += 1;
    }
    o
}
const OFFSETS: [isize; N_OFF] = offsets();

fn storage_index(i: usize, log_size: u32) -> usize {
    bit_reverse_index(coset_index_to_circle_domain_index(i, log_size), log_size)
}

// ── Preprocessed column ids (the fixed routing "program") ───────────────────
const NOT_LAST: &str = "emb_not_last";
fn final_id(l: usize) -> String {
    format!("emb_final_{l}")
}
fn const_id(l: usize, r: usize, c: usize) -> String {
    format!("emb_c_{l}_{r}_{c}")
}
fn coeff_id(l: usize, r: usize, p: usize, c: usize) -> String {
    format!("emb_k_{l}_{r}_{p}_{c}")
}

/// All preprocessed ids, in registration order (the fill must match).
fn preproc_ids() -> Vec<PreProcessedColumnId> {
    let mut ids = vec![PreProcessedColumnId {
        id: NOT_LAST.to_string(),
    }];
    for l in 0..OPS_S {
        ids.push(PreProcessedColumnId { id: final_id(l) });
    }
    for l in 0..OPS_S {
        for r in 0..2 {
            for c in 0..SECURE_EXTENSION_DEGREE {
                ids.push(PreProcessedColumnId {
                    id: const_id(l, r, c),
                });
            }
            for p in 0..WIN {
                for c in 0..SECURE_EXTENSION_DEGREE {
                    ids.push(PreProcessedColumnId {
                        id: coeff_id(l, r, p, c),
                    });
                }
            }
        }
    }
    ids
}

/// Map a resolved [`WinPos`] to its canonical window-position index.
fn win_index(pos: &WinPos) -> usize {
    match *pos {
        WinPos::Leaf { lane, .. } => lane,
        WinPos::Slot { lane, off } => NLEAF + lane * N_OFF + off,
        WinPos::Latched(s) => NLEAF + OPS_S * N_OFF + s,
        _ => unreachable!("co-locate layout uses Leaf/Slot/Latched"),
    }
}

// ── The streamed embed AIR ──────────────────────────────────────────────────

#[derive(Clone)]
struct EmbedEval {
    log_n_rows: u32,
}

impl FrameworkEval for EmbedEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1 // degree ≤ 2
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let lift =
            |f: E::F| -> E::EF { E::combine_ef([f, E::F::zero(), E::F::zero(), E::F::zero()]) };

        // Preprocessed selectors + routing program (read by id — order-free).
        let not_last = eval.get_preprocessed_column(PreProcessedColumnId {
            id: NOT_LAST.to_string(),
        });
        let is_final: [E::F; OPS_S] = std::array::from_fn(|l| {
            eval.get_preprocessed_column(PreProcessedColumnId { id: final_id(l) })
        });

        // recon program[l*2+r] = (constant, [coeff; WIN]). `get_preprocessed_column`
        // is CURSOR-based (ignores the id), so read in EXACT registration order:
        // per (l, side): const then its WIN coeffs.
        let mut prog: Vec<(E::EF, Vec<E::EF>)> = Vec::with_capacity(2 * OPS_S);
        for l in 0..OPS_S {
            for r in 0..2 {
                let cst = E::combine_ef(std::array::from_fn(|c| {
                    eval.get_preprocessed_column(PreProcessedColumnId {
                        id: const_id(l, r, c),
                    })
                }));
                let cf: Vec<E::EF> = (0..WIN)
                    .map(|p| {
                        E::combine_ef(std::array::from_fn(|c| {
                            eval.get_preprocessed_column(PreProcessedColumnId {
                                id: coeff_id(l, r, p, c),
                            })
                        }))
                    })
                    .collect();
                prog.push((cst, cf));
            }
        }

        // Main reads, IN COLUMN ORDER: leaves (offset 0), then per lane oa,ob
        // (offset 0) + r (window), then latched (offsets [0,1]).
        let read4_0 = |eval: &mut E| -> E::EF {
            E::combine_ef(std::array::from_fn(|_| eval.next_trace_mask()))
        };
        let leaves: [E::EF; NLEAF] = std::array::from_fn(|_| read4_0(&mut eval));

        let mut oa: Vec<E::EF> = Vec::with_capacity(OPS_S);
        let mut ob: Vec<E::EF> = Vec::with_capacity(OPS_S);
        // r window coords per lane: [coord][offset].
        let mut r_coords: Vec<[[E::F; N_OFF]; SECURE_EXTENSION_DEGREE]> = Vec::with_capacity(OPS_S);
        for _ in 0..OPS_S {
            oa.push(read4_0(&mut eval));
            ob.push(read4_0(&mut eval));
            let rc: [[E::F; N_OFF]; SECURE_EXTENSION_DEGREE] =
                std::array::from_fn(|_| eval.next_interaction_mask(ORIGINAL_TRACE_IDX, OFFSETS));
            r_coords.push(rc);
        }
        let r_at = |l: usize,
                    off: usize,
                    r_coords: &[[[E::F; N_OFF]; SECURE_EXTENSION_DEGREE]]|
         -> E::EF {
            E::combine_ef(std::array::from_fn(|c| r_coords[l][c][off].clone()))
        };

        let mut lat_cur: [E::EF; N_LATCHED] = std::array::from_fn(|_| E::EF::zero());
        let mut lat_next: [E::EF; N_LATCHED] = std::array::from_fn(|_| E::EF::zero());
        for s in 0..N_LATCHED {
            let c: [[E::F; 2]; SECURE_EXTENSION_DEGREE] =
                std::array::from_fn(|_| eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, 1]));
            lat_cur[s] = E::combine_ef(std::array::from_fn(|i| c[i][0].clone()));
            lat_next[s] = E::combine_ef(std::array::from_fn(|i| c[i][1].clone()));
        }

        // Assemble the window in canonical order.
        let window: Vec<E::EF> = (0..WIN)
            .map(|p| {
                if p < NLEAF {
                    leaves[p].clone()
                } else if p < NLEAF + OPS_S * N_OFF {
                    let q = p - NLEAF;
                    r_at(q / N_OFF, q % N_OFF, &r_coords)
                } else {
                    lat_cur[p - (NLEAF + OPS_S * N_OFF)].clone()
                }
            })
            .collect();

        // Per-slot constraints.
        for l in 0..OPS_S {
            for (r, side) in [&oa[l], &ob[l]].into_iter().enumerate() {
                let (cst, cf) = &prog[l * 2 + r];
                let mut recon = cst.clone();
                for p in 0..WIN {
                    recon += cf[p].clone() * window[p].clone();
                }
                eval.add_constraint(side.clone() - recon); // deg 2, UNGATED
            }
            let r_l = r_at(l, 0, &r_coords);
            eval.add_constraint(r_l.clone() - oa[l].clone() * ob[l].clone()); // deg 2
            eval.add_constraint(lift(is_final[l].clone()) * r_l); // final: lhs−rhs == 0
        }

        // Latched held constant across rows (ONE consistent OODS scalar set).
        for s in 0..N_LATCHED {
            eval.add_constraint(
                lift(not_last.clone()) * (lat_next[s].clone() - lat_cur[s].clone()),
            );
        }
        eval
    }
}

const fn main_qm31_per_row() -> usize {
    NLEAF + OPS_S * 3 + N_LATCHED
}

struct EmbedTrace {
    preprocessed: Vec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>>,
    main: Vec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>>,
    log_size: u32,
}

/// Host-fill the streamed embed trace from the co-locate layout. `tamper` bumps one
/// committed MAIN base column on a meaningful (non-padding) row for the reject test.
fn gen_trace(lay: &ColocateLayout, tamper: Option<usize>) -> EmbedTrace {
    assert!(lay.ops_s == OPS_S && lay.nleaf == NLEAF);
    assert!(lay.dr <= DR, "layout dr={} exceeds DR={DR}", lay.dr);
    assert!(lay.max_leaf_in_row <= NLEAF);

    let log_size = lay.n_rows.next_power_of_two().trailing_zeros().max(1);
    let n = 1usize << log_size;

    let z = SecureField::zero();
    // ── Main logical columns (QM31), in read order ──
    // leaves[NLEAF], then per lane oa,ob,r, then latched[N_LATCHED].
    let mut main_q: Vec<Vec<SecureField>> = Vec::new();
    for j in 0..NLEAF {
        main_q.push(
            (0..n)
                .map(|i| {
                    if i < lay.n_rows {
                        lay.leaf_val[i][j]
                    } else {
                        z
                    }
                })
                .collect(),
        );
    }
    for l in 0..OPS_S {
        main_q.push(
            (0..n)
                .map(|i| {
                    if i < lay.n_rows {
                        lay.slot_oa_val[i][l]
                    } else {
                        z
                    }
                })
                .collect(),
        );
        main_q.push(
            (0..n)
                .map(|i| {
                    if i < lay.n_rows {
                        lay.slot_ob_val[i][l]
                    } else {
                        z
                    }
                })
                .collect(),
        );
        main_q.push(
            (0..n)
                .map(|i| if i < lay.n_rows { lay.slot_r[i][l] } else { z })
                .collect(),
        );
    }
    // Latched held constant on ALL rows (incl. padding) — keeps not_last constancy.
    for s in 0..N_LATCHED {
        let v = lay.latched_value[s];
        main_q.push(vec![v; n]);
    }
    debug_assert_eq!(main_q.len(), main_qm31_per_row());

    // ── Preprocessed logical columns, in registration order ──
    let mut pre_b: Vec<Vec<BaseField>> = Vec::new();
    // not_last: 1 everywhere except the last row.
    pre_b.push(
        (0..n)
            .map(|i| {
                if i + 1 < n {
                    BaseField::one()
                } else {
                    BaseField::zero()
                }
            })
            .collect(),
    );
    // is_final per lane.
    for l in 0..OPS_S {
        pre_b.push(
            (0..n)
                .map(|i| {
                    if i == lay.final_row && l == lay.final_lane {
                        BaseField::one()
                    } else {
                        BaseField::zero()
                    }
                })
                .collect(),
        );
    }
    // recon programs: const(QM31) then coeffs(WIN×QM31), per (lane, side).
    for l in 0..OPS_S {
        for r in 0..2 {
            // const
            let mut cst = vec![z; n];
            for i in 0..lay.n_rows {
                let rec = if r == 0 {
                    &lay.slot_oa[i][l]
                } else {
                    &lay.slot_ob[i][l]
                };
                cst[i] = rec.constant;
            }
            for c in 0..SECURE_EXTENSION_DEGREE {
                pre_b.push(cst.iter().map(|q| q.to_m31_array()[c]).collect());
            }
            // coeffs[p]
            let mut coeff = vec![vec![z; n]; WIN];
            for i in 0..lay.n_rows {
                let rec = if r == 0 {
                    &lay.slot_oa[i][l]
                } else {
                    &lay.slot_ob[i][l]
                };
                for (pos, c) in &rec.terms {
                    coeff[win_index(pos)][i] += *c; // merged terms already, but += is safe
                }
            }
            for p in 0..WIN {
                for c in 0..SECURE_EXTENSION_DEGREE {
                    pre_b.push(coeff[p].iter().map(|q| q.to_m31_array()[c]).collect());
                }
            }
        }
    }

    // ── Flatten QM31 main → base, storage-index both trees ──
    let domain = CanonicCoset::new(log_size).circle_domain();
    let wrap = |logical: Vec<BaseField>| {
        let mut c = Col::<CpuBackend, BaseField>::zeros(n);
        for (i, v) in logical.into_iter().enumerate() {
            c.set(storage_index(i, log_size), v);
        }
        CircleEvaluation::<CpuBackend, _, BitReversedOrder>::new(domain, c)
    };
    // preproc columns are already base + at LOGICAL index → storage-index on wrap.
    let preprocessed: Vec<_> = pre_b.into_iter().map(wrap).collect();

    let mut main_logical: Vec<Vec<BaseField>> = Vec::new();
    for q in &main_q {
        for c in 0..SECURE_EXTENSION_DEGREE {
            main_logical.push(q.iter().map(|v| v.to_m31_array()[c]).collect());
        }
    }
    if let Some(col) = tamper {
        // Bump a committed main base column on the final slot's row (always
        // constrained + consumed by the final equality).
        let r = lay.final_row;
        main_logical[col][r] += BaseField::one();
    }
    let main: Vec<_> = main_logical.into_iter().map(wrap).collect();

    EmbedTrace {
        preprocessed,
        main,
        log_size,
    }
}

fn build_layout() -> ColocateLayout {
    let s = synthetic_setup(L_SYNTH);
    let capture = build_capture(&s);
    let sched = capture.schedule_two_stream(T_PER_MAC);
    sched.layout_colocate(OPS_S, NLEAF)
}

fn prove_and_verify(trace: EmbedTrace) -> Result<(), String> {
    let config = mobile_config();
    let log_size = trace.log_size;
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(log_size + 1 + config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
    );
    let channel = &mut Poseidon2M31Channel::default();
    let mut cs = CommitmentSchemeProver::<CpuBackend, P2MerkleChannel>::new(config, &twiddles);
    let mut tb = cs.tree_builder();
    tb.extend_evals(trace.preprocessed);
    tb.commit(channel);
    let mut tb = cs.tree_builder();
    tb.extend_evals(trace.main);
    tb.commit(channel);

    let mut alloc = TraceLocationAllocator::new_with_preprocessed_columns(&preproc_ids());
    let component = FrameworkComponent::<EmbedEval>::new(
        &mut alloc,
        EmbedEval {
            log_n_rows: log_size,
        },
        SecureField::zero(),
    );
    let proof = prove::<CpuBackend, P2MerkleChannel>(&[&component], channel, cs)
        .map_err(|e| format!("prove: {e:?}"))?;

    let vch = &mut Poseidon2M31Channel::default();
    let mut vs = CommitmentSchemeVerifier::<P2MerkleChannel>::new(config);
    let sizes = component.trace_log_degree_bounds();
    vs.commit(proof.commitments[0], &sizes[0], vch);
    vs.commit(proof.commitments[1], &sizes[1], vch);
    verify(&[&component as &dyn Component], vch, &mut vs, proof)
        .map_err(|e| format!("verify: {e:?}"))
}

/// FAST gate: the streamed embed trace satisfies the AIR (AssertEvaluator) on the
/// REAL co-locate layout — catches value bugs before the heavy prove.
#[test]
fn embed_air_satisfied() {
    let lay = build_layout();
    let trace = gen_trace(&lay, None);
    let log_size = trace.log_size;
    let pre: Vec<Vec<M31>> = trace
        .preprocessed
        .iter()
        .map(|e| e.values.to_cpu())
        .collect();
    let main: Vec<Vec<M31>> = trace.main.iter().map(|e| e.values.to_cpu()).collect();
    let tv: TreeVec<Vec<&Vec<M31>>> =
        TreeVec::new(vec![pre.iter().collect(), main.iter().collect(), vec![]]);
    assert_constraints_on_trace(
        &tv,
        log_size,
        |e| {
            EmbedEval {
                log_n_rows: log_size,
            }
            .evaluate(e);
        },
        SecureField::zero(),
    );
    eprintln!(
        "embed_air_satisfied: streamed OODS embed (all 31 chips, {} stream rows → log {log_size}, \
         OPS_S={OPS_S} T={T_PER_MAC} dr={} nleaf={}) satisfies the AIR. main {} M31 cols/row, \
         preproc {} M31 cols/row.",
        lay.n_rows,
        lay.dr,
        lay.max_leaf_in_row,
        main_qm31_per_row() * SECURE_EXTENSION_DEGREE,
        preproc_ids().len(),
    );
}

/// THE MILESTONE (heavy): the streamed OODS embed proves+verifies at degree ≤ 2
/// through the lifted Poseidon2-M31 protocol; a tampered cell is rejected.
#[test]
#[ignore = "heavy: streamed OODS embed prove+verify at canonical node scale (release)"]
fn embed_gate() {
    let lay = build_layout();
    let n_preproc = preproc_ids().len();

    // Tamper the final slot's oa base column (constrained by its recon + the final
    // equality) on the final row.
    let oa_col = (NLEAF + lay.final_lane * 3) * SECURE_EXTENSION_DEGREE;

    prove_and_verify(gen_trace(&lay, None))
        .expect("honest streamed OODS embed must prove+verify at degree ≤ 2");
    assert!(
        prove_and_verify(gen_trace(&lay, Some(oa_col))).is_err(),
        "a tampered committed cell must be rejected"
    );

    eprintln!(
        "embed_gate GREEN: the streamed OODS embed (all 31 chips' composition, 40139 nodes) \
         proves+verifies through the lifted Poseidon2-M31 protocol at degree ≤ 2 — {} stream rows \
         (log {}), OPS_S={OPS_S}, T={T_PER_MAC}, dr={}, {} main M31 cols/row, {} preproc M31 cols. \
         A tampered cell is rejected. This is the standalone OODS-embed milestone: the 160600-M31 \
         single-row width is now distributed into a streamed co-locate layout that shares the \
         channel's row count.",
        lay.n_rows,
        gen_trace(&lay, None).log_size,
        lay.dr,
        main_qm31_per_row() * SECURE_EXTENSION_DEGREE,
        n_preproc,
    );
}

// ── Real-segment gate: swap the synthetic mask for a real prove_canonical proof ──
//
// The synthetic mask fuzzes the arithmetisation (the per-component contribution is
// a pure function of the mask). This gate drives the SAME streamed embed on a REAL
// canonical segment's OODS data (via `reconstruct_oods_for_recursion`, the same
// real-data path `oods_auto_real_segment` uses for the non-streamed embed) and
// confirms (a) the schedule shape is SEGMENT-INVARIANT — the real layout's row
// count + window depth match the synthetic — and (b) the embed proves+verifies on
// real values + rejects a tamper. (a) is the design's core claim that lets the
// routing "program" be PREPROCESSED (fixed across canonical segments).

#[cfg(feature = "poseidon2-channel")]
use recursion_common::oods_auto::{ComponentMask, StreamBackend, drive_multi};

#[cfg(feature = "poseidon2-channel")]
fn canonical_segment() -> (zkpvm::Proof, zkpvm::SideNote) {
    use javm::PVM_REGISTER_COUNT;
    use javm::instruction::Opcode;
    use javm::interpreter::Interpreter;
    use zkpvm::core::tracing::TracingPvm;
    use zkpvm::prove_canonical;

    let code = vec![
        Opcode::Add64 as u8,
        0x10,
        2,
        Opcode::Add64 as u8,
        0x12,
        3,
        Opcode::Add64 as u8,
        0x13,
        4,
        Opcode::Add64 as u8,
        0x14,
        5,
        Opcode::Add64 as u8,
        0x15,
        6,
        Opcode::Add64 as u8,
        0x16,
        7,
        Opcode::Trap as u8,
    ];
    let bitmask: Vec<u8> = vec![1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1];
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 100;
    regs[1] = 1;
    let initial_memory = vec![0u8; 4 * 1024 * 1024];
    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        initial_memory.clone(),
        10_000,
        25,
    );
    let mut tracing = TracingPvm::new(pvm);
    assert_eq!(tracing.run(), javm::ExitReason::Trap);
    let steps = tracing.into_trace();
    let mut sn = zkpvm::SideNote::new(steps, code, bitmask).with_memory(initial_memory);
    let proof = prove_canonical(&mut sn, &[]).expect("prove_canonical under Poseidon2-M31");
    (proof, sn)
}

/// Build the co-locate layout from a REAL canonical segment's reconstructed OODS
/// data (same `StreamBackend` capture, just real masks/scalars).
#[cfg(feature = "poseidon2-channel")]
fn real_layout() -> ColocateLayout {
    use std::cell::RefCell;
    use std::rc::Rc;
    use zkpvm::framework_access::drive_chip_oods;
    use zkpvm::reconstruct_oods_for_recursion;

    let (proof, sn) = canonical_segment();
    assert_eq!(
        proof.num_components,
        zkpvm::chip_idx::COUNT,
        "canonical proof must carry all 31 components"
    );
    let r = reconstruct_oods_for_recursion(&proof, &sn);
    let component_masks: Vec<ComponentMask> = r
        .component_masks
        .into_iter()
        .map(|m| ComponentMask {
            mask: m.mask,
            preproc_indices: m.preproc_indices,
        })
        .collect();
    let backend = StreamBackend::new(
        component_masks,
        r.random_coeff,
        r.denom_inverse,
        r.oods_x_doubled,
        r.comp_mask,
    );
    let ctx = Rc::new(RefCell::new(backend));
    let lookup = &r.lookup_elements;
    drive_multi(&ctx, &r.comps, |idx, ls, e| {
        drive_chip_oods(idx, ls, lookup, e)
    });
    let capture = Rc::try_unwrap(ctx)
        .unwrap_or_else(|_| panic!("a Handle outlived the real capture walk"))
        .into_inner()
        .finish();
    capture
        .schedule_two_stream(T_PER_MAC)
        .layout_colocate(OPS_S, NLEAF)
}

/// THE REAL GATE (heavy): the streamed embed reproduces a REAL canonical segment's
/// composition and proves+verifies; the layout shape matches the synthetic
/// (schedule is segment-invariant); a tampered cell is rejected.
#[cfg(feature = "poseidon2-channel")]
#[test]
#[ignore = "heavy: prove_canonical + real-segment streamed embed prove+verify (release)"]
fn embed_gate_real() {
    let lay = real_layout();
    let syn = build_layout();

    // (a) schedule invariance: the real segment's layout has the SAME shape as the
    // synthetic — the design's claim that the routing program is segment-fixed.
    assert_eq!(
        (lay.n_rows, lay.dr, lay.max_leaf_in_row),
        (syn.n_rows, syn.dr, syn.max_leaf_in_row),
        "real-segment layout shape must match the synthetic (schedule not segment-invariant)"
    );

    // (b) the embed proves+verifies on REAL OODS values + rejects a tamper.
    let oa_col = (NLEAF + lay.final_lane * 3) * SECURE_EXTENSION_DEGREE;
    prove_and_verify(gen_trace(&lay, None))
        .expect("real-segment streamed OODS embed must prove+verify at degree ≤ 2");
    assert!(
        prove_and_verify(gen_trace(&lay, Some(oa_col))).is_err(),
        "a tampered committed cell must be rejected"
    );

    eprintln!(
        "embed_gate_real GREEN: a REAL prove_canonical segment's 31-component OODS composition \
         re-evaluates in the streamed embed and proves+verifies at degree ≤ 2 — {} stream rows \
         (log {}), dr={}, identical shape to the synthetic layout (schedule SEGMENT-INVARIANT). \
         A tampered cell is rejected. The streamed OODS embed now runs on real data, not just the \
         synthetic fuzz.",
        lay.n_rows,
        gen_trace(&lay, None).log_size,
        lay.dr,
    );
}
