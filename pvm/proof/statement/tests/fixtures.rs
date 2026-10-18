//! The golden fixtures (`proving.md` A.6, `pvm/proof/fixtures`) as the
//! venues judge them: natively, and on the JAM-only host by the venue's
//! refine program (`final-verify.elf`, built by `just check-no-std`); the
//! Wasm harness judges them with `judge` (`final-verifier/wasm/run`). Each
//! verdict is its fixture's: the same acceptance, or the same refusal's
//! class, and an accepted statement's id the same.

#[path = "support/jam.rs"]
mod jam;

use vos_statement::fixtures::{self, Fixture};
use vos_statement::model::judge_bytes;

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
