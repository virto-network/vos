//! The run's measurements, noted: each statement's latency from its
//! window's boundary to its acceptance, against the gate; the JAM
//! service's gas; what the Kreivo mock charged the sovereign account; the
//! prover's throughput.

use std::time::Duration;

use vos_statement_service::state::Outcome as Judged;
use vos_venue::kreivo::mock::Origin;

use crate::kreivo::{self, UNITS};
use crate::representative::delay;
use crate::run::{Run, Stated, accepted};

/// The gate's margin past `L + D + t_prove`.
const MARGIN_MS: u64 = 30_000;

pub fn all(run: &mut Run, stated: &[Stated], judged: &[(String, Judged)]) {
    latency(run, stated);
    gas(run, judged);
    fees(run);
    throughput(run);
}

/// Each statement's latency from `B_w` to its acceptance, within `L + D +
/// t_prove + 30 s`; `proving.md` §7's `L/2 + D + t_prove + inclusion`, the
/// wait of a request asked at a random time in its window, noted as a
/// reference, its `L/2` computed, not measured.
fn latency(run: &mut Run, stated: &[Stated]) {
    let (l, d) = (run.clock.length_ms, delay(&run.clock));
    let proved = run.prover.proved();
    let (kreivo, jam) = (run.kreivo_judged(), run.jam_a.recorded.judged());
    run.record.note(format!(
        "latency from B_w to acceptance (L {} s, D {} s), against the gate L + D + t_prove + \
         30 s:",
        l / 1_000,
        d / 1_000
    ));
    let mut references = Vec::new();
    for Stated {
        asked, statement, ..
    } in stated
    {
        let (venue, judged) = if asked.window < run.k {
            ("Kreivo", &kreivo)
        } else {
            ("JAM", &jam)
        };
        let judgement = accepted(judged, statement).expect("accepted");
        let proof = proved
            .iter()
            .find(|proved| proved.of(statement))
            .expect("proved");
        let latency = judgement.at_ms - run.clock.boundary(asked.window).unwrap();
        let t_prove = proof.took.as_millis() as u64;
        let inclusion = judgement.at_ms.saturating_sub(proof.ended_ms);
        let gate = l + d + t_prove + MARGIN_MS;
        references.push(l / 2 + d + t_prove + inclusion);
        run.record.note(format!(
            "  {venue}, window {}, {}: {:.1} s (t_prove {:.1} s, after its proof {:.1} s); \
             gate {:.1} s",
            asked.window,
            asked.what,
            latency as f64 / 1e3,
            t_prove as f64 / 1e3,
            inclusion as f64 / 1e3,
            gate as f64 / 1e3,
        ));
        assert!(
            latency <= gate,
            "{venue}'s {} statement of window {}: {latency} ms past B_w, over {gate} ms",
            asked.what,
            asked.window
        );
    }
    let (low, high) = (
        references.iter().min().unwrap(),
        references.iter().max().unwrap(),
    );
    run.record.note(format!(
        "  for reference, L/2 + D + t_prove + inclusion with these terms (L/2 \
         computed): {:.1}–{:.1} s",
        *low as f64 / 1e3,
        *high as f64 / 1e3
    ));
}

/// The refine gas of each statement at the JAM service, by its own count,
/// and its last accumulate's.
fn gas(run: &mut Run, judged: &[(String, Judged)]) {
    run.record
        .note("the JAM service's refine gas, by its own count:");
    for (what, outcome) in judged {
        run.record.note(format!(
            "  {what}: code {:#x}, refine {} gas",
            outcome.code, outcome.refine_gas
        ));
    }
    if let Ok(Some(gas)) = run.jam_a.venue.statements.accumulate_gas() {
        run.record.note(format!("  the last accumulate: {gas} gas"));
    }
}

/// What the mock charged the space's sovereign account: each authority's
/// fee, and the refused statement's deposit, asserted.
fn fees(run: &mut Run) {
    let kreivo = &run.kreivo;
    let account = kreivo.account(&kreivo.sovereign_of(&run.space));
    let (fee, deposit, budget) = kreivo.chain.with(|chain| {
        let constants = &chain.constants;
        (
            constants.fee_bound,
            constants.submit_deposit,
            constants.default_spend_per_window,
        )
    });
    let (mut anchors, mut submits) = (0u128, 0u128);
    for (origin, call) in kreivo.included() {
        let authority = (1..=3).any(|n| origin == Origin::Signed(kreivo::node_account(n)));
        match &call[..2] {
            [90, 7] if authority => anchors += 1,
            [90, 8] if authority => submits += 1,
            _ => {}
        }
    }
    let charged = kreivo::FUNDING - account.free - account.held_registration - account.held_submit;
    let alerts: Vec<String> = run
        .kreivo_clients
        .lock()
        .unwrap()
        .values()
        .flat_map(|(client, ..)| client.alerts())
        .map(|alert| format!("{alert:?}"))
        .collect();
    let units = |balance: u128| balance as f64 / UNITS as f64;
    run.record.note(format!(
        "Kreivo's sovereign account, funded {} UNITS: {anchors} anchors and {submits} submits by \
         the authorities, each a fee of {} UNITS; one deposit of {} UNITS forfeited (the \
         statement refused); {} UNITS held for the registration, none for submits; charged {} \
         UNITS in all; the budget {} UNITS a window; the clients' alerts {alerts:?}",
        units(kreivo::FUNDING),
        units(fee),
        units(deposit),
        units(account.held_registration),
        units(charged),
        units(budget),
    ));
    assert_eq!(account.held_submit, 0, "every submit's deposit settled");
    assert_eq!(
        charged,
        (anchors + submits) * fee + deposit,
        "the sovereign paid each authority's fee, and the refused statement's deposit"
    );
    assert!(alerts.is_empty(), "no funding or configuration alert");
}

/// The prover's time a statement, and what it proves in a window.
fn throughput(run: &mut Run) {
    let proved = run.prover.proved();
    let at_cuts: Vec<_> = proved
        .iter()
        .filter(|proved| proved.attest.window.is_some())
        .collect();
    let total: Duration = at_cuts.iter().map(|proved| proved.took).sum();
    let average = total / at_cuts.len().max(1) as u32;
    let l = run.clock.length_ms;
    run.record.note(format!(
        "the prover: {} statements at cuts in {:.1} s, {:.1} s each on average; at that rate \
         {:.0} a 10-minute window, {:.0} a {}-second one",
        at_cuts.len(),
        total.as_secs_f64(),
        average.as_secs_f64(),
        600.0 / average.as_secs_f64(),
        l as f64 / 1e3 / average.as_secs_f64(),
        l / 1_000,
    ));
    for proved in &proved {
        let what = match proved.attest.window {
            Some(w) => format!("window {w}'s"),
            None => "a rootless".into(),
        };
        run.record.note(format!(
            "  {what} statement: {:.1} s",
            proved.took.as_secs_f64()
        ));
    }
}
