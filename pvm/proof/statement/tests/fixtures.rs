//! The golden fixtures (`proving.md` A.6, `pvm/proof/fixtures`) as the
//! venues judge them: natively, and on the JAM-only host by the venue's
//! refine program (`final-verify.elf`, built by `just check-no-std`); the
//! Wasm harness judges them with `judge` (`final-verifier/wasm/run`). Each
//! verdict is its fixture's: the same acceptance, or the same refusal's
//! class, and an accepted statement's id the same. `vos-anchor`'s golden
//! vectors alike: each vector's digests the pinned bytes, by the same
//! program on the JAM-only host (natively, `vos-anchor`'s own test; in Wasm,
//! the harness's `anchors`).

#[path = "support/jam.rs"]
mod jam;

use vos_statement::Refusal;
use vos_statement::fixtures::{self, Fixture};
use vos_statement::model::judge_bytes;
use vos_statement::vos_anchor::vectors;
use vos_statement::vos_pvm_final_verifier::{self, MAX_PROOF_BYTES};

fn load() -> Vec<Fixture> {
    let fixtures = fixtures::load(&fixtures::directory());
    let names: Vec<&str> = fixtures.iter().map(|f| f.name.as_str()).collect();
    for name in [
        "valid",
        "tampered",
        "wrong program",
        "unanchored root",
        "prefix",
        "mid-way",
        "repeated",
        "unaccepted format",
        "wrong io-hash",
        "rootless, another space",
        "the same run, another accepted format",
    ] {
        assert!(names.contains(&name), "the fixture {name:?}");
    }
    fixtures
}

/// Natively: each fixture's verdict, from its input and proof as the
/// harnesses pass them; only the valid one accepted, with its statement's
/// id.
#[test]
fn every_fixture_is_judged_natively_as_recorded() {
    for fixture in load() {
        let verdict = judge_bytes(&fixture.bytes());
        let code = vos_statement::code(&verdict);
        eprintln!("{}: {code:#x} {verdict:?}", fixture.name);
        assert_eq!(code, fixture.verdict, "{}", fixture.name);
        assert_eq!(code == 0, fixture.name == "valid", "{}", fixture.name);
        if let Ok(id) = verdict {
            assert_eq!(id, fixture.input.statement.id());
        }
    }
}

/// On the JAM-only host: each fixture's verdict, by the guest; its gas.
#[test]
fn every_fixture_is_judged_on_the_jam_only_host_as_recorded() {
    let (program, _) = jam::program();
    for fixture in load() {
        let request = jam::judge_request(&fixture.input);
        let (gas, report) = jam::run(&program, &request, &fixture.proof);
        eprintln!(
            "{}: {:#x}, {:.1}M gas: {}",
            fixture.name,
            report.code,
            gas as f64 / 1e6,
            report.error
        );
        assert_eq!(report.code, u64::from(fixture.verdict), "{}", fixture.name);
        let accepted = fixture.verdict == 0;
        assert_eq!(
            report.verdict,
            if accepted { jam::ACCEPT } else { jam::REJECT },
            "{}",
            fixture.name
        );
        if accepted {
            assert_eq!(report.id, fixture.input.statement.id().0);
            assert!(gas <= 150_000_000, "{gas} gas");
        }
    }
}

/// A proof longer than `MAX_PROOF_BYTES` is refused on the JAM-only host
/// before the guest allocates it or looks it up, in both of its modes; a
/// judgement's code is the one a venue reports natively.
#[test]
fn a_proof_too_long_is_refused_before_its_lookup() {
    let (program, _) = jam::program();
    let valid = load()
        .into_iter()
        .find(|fixture| fixture.name == "valid")
        .expect("the valid fixture");
    let long = vec![0; MAX_PROOF_BYTES + 1];
    let native = vos_statement::code(&valid.input.judge(&long));
    assert_eq!(
        native,
        Refusal::Proof(vos_pvm_final_verifier::Error::Length).code()
    );

    let (_, report) = jam::run(&program, &jam::judge_request(&valid.input), &long);
    assert_eq!(report.code, u64::from(native));
    assert_eq!(report.verdict, jam::REJECT);
    assert_eq!(report.gas[1], 0, "no lookup");

    let words = vos_pvm_final_verifier::Statement {
        program: valid.input.program.0,
        io_hash: valid.input.statement.io_hash(),
    }
    .words();
    let (_, report) = jam::run(
        &program,
        &jam::words_request(vos_statement::FORMAT, &words),
        &long,
    );
    assert_eq!(report.verdict, jam::UNDECODABLE, "{}", report.error);
    assert_eq!(report.gas[1], 0, "no lookup");
}

/// On the JAM-only host: each golden vector of `vos-anchor` decoded and its
/// digests computed by the guest, the pinned bytes; a vector cut short
/// refused.
#[test]
fn the_anchor_vectors_are_computed_on_the_jam_only_host_as_pinned() {
    let (program, _) = jam::program();
    let hex = |bytes: &[u8]| -> String { bytes.iter().map(|byte| format!("{byte:02x}")).collect() };
    for golden in vectors::golden() {
        let vector = golden.vector.encode();
        let (gas, report) = jam::run_payload(&program, jam::anchors_request(&vector), None);
        eprintln!("{}: {:.2}M gas", golden.name, gas as f64 / 1e6);
        assert_eq!(
            report.verdict,
            jam::ACCEPT,
            "{}: {}",
            golden.name,
            report.error
        );
        assert_eq!(hex(&report.digests), golden.digests, "{}", golden.name);
        assert_eq!(report.digests, golden.vector.digests().to_bytes());

        let short = jam::anchors_request(&vector[..vector.len() - 1]);
        let (_, report) = jam::run_payload(&program, short, None);
        assert_eq!(report.verdict, jam::BAD_PAYLOAD, "{}", golden.name);
    }
}
