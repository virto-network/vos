//! The golden fixtures (`proving.md` A.6, `pvm/proof/fixtures`) as the
//! venues judge them: natively, and on the JAM-only host by the venue's
//! refine programs (`final-verify.elf`, linking format 39 alone, and
//! `final-verify-test.elf`, 28 beside it; built by `just check-no-std`); the
//! Wasm harness judges them with `judge` (`final-verifier/wasm/run`), its
//! production and test blobs alike. Each verdict is its fixture's under the
//! formats the build links (`Fixture::verdict_linking`): the same
//! acceptance, or the same refusal's class, and an accepted statement's id
//! the same. `vos-anchor`'s golden
//! vectors alike: each vector's digests the pinned bytes, by the same
//! program on the JAM-only host (natively, `vos-anchor`'s own test; in Wasm,
//! the harness's `anchors`).

#[path = "support/jam.rs"]
mod jam;

use vos_statement::Refusal;
use vos_statement::fixtures::{self, Fixture, RECORDED};
use vos_statement::model::judge_bytes;
use vos_statement::vos_anchor::vectors;
use vos_statement::vos_pvm_final_verifier::{self, MAX_PROOF_BYTES, masked};

/// The cases a venue accepts: under format 39, the rooted statement and the
/// rootless one; under 28, at the test venue.
const ACCEPTED: [&str; 3] = ["valid", "rootless", "format 28 at the test venue"];

fn load() -> Vec<Fixture> {
    let fixtures = fixtures::load(&fixtures::directory());
    let names: Vec<&str> = fixtures.iter().map(|f| f.name.as_str()).collect();
    for name in ACCEPTED.into_iter().chain([
        "tampered",
        "wrong program",
        "unanchored root",
        "prefix",
        "mid-way",
        "repeated",
        "unaccepted format",
        "format 28 at a production venue",
        "wrong io-hash",
        "another program than the pin",
        "another space",
        "the space",
        "rootless, another space",
        "rooted, of no space",
        "another venue's statement",
        "replayed at another venue",
        "a root's window",
        "a root",
        "the nonce",
        "migrated before a root's window",
        "registered after a root's window",
        "rooted, replayed past MaxRootAge",
        "rootless, replayed past MaxRootAge",
        "tampered, format 28 at the test venue",
        "accepted under 39, replayed under 28",
        "accepted under 28, replayed under 39",
    ]) {
        assert!(names.contains(&name), "the fixture {name:?}");
    }
    fixtures
}

/// Natively, linking both formats as the recorded build does: each
/// fixture's verdict, from its input and proof as the harnesses pass them;
/// only the valid ones accepted, with their statements' ids.
#[test]
fn every_fixture_is_judged_natively_as_recorded() {
    assert_eq!(vos_statement::LINKED, RECORDED);
    for fixture in load() {
        let verdict = judge_bytes(&fixture.bytes());
        let code = vos_statement::code(&verdict);
        eprintln!("{}: {code:#x} {verdict:?}", fixture.name);
        assert_eq!(code, fixture.verdict, "{}", fixture.name);
        assert_eq!(
            code == 0,
            ACCEPTED.contains(&fixture.name.as_str()),
            "{}",
            fixture.name
        );
        if let Ok(id) = verdict {
            assert_eq!(id, fixture.input.statement.id());
        }
    }
}

/// On the JAM-only host: each fixture's verdict, by the production guest
/// (format 39 alone: a statement of 28 refused as `Format`) and by the test
/// guest (28 beside it: the recorded verdict); its gas.
#[test]
fn every_fixture_is_judged_on_the_jam_only_host_as_recorded() {
    for (guest, (program, _), linked) in [
        ("production", jam::program(), &[masked::FORMAT][..]),
        ("test", jam::test_program(), RECORDED),
    ] {
        for fixture in load() {
            let expected = fixture.verdict_linking(linked);
            let request = jam::judge_request(&fixture.input);
            let (gas, report) = jam::run(&program, &request, &fixture.proof);
            eprintln!(
                "{guest}: {}: {:#x}, {:.1}M gas: {}",
                fixture.name,
                report.code,
                gas as f64 / 1e6,
                report.error
            );
            assert_eq!(
                report.code,
                u64::from(expected),
                "{guest}: {}",
                fixture.name
            );
            let accepted = expected == 0;
            assert_eq!(
                report.verdict,
                if accepted { jam::ACCEPT } else { jam::REJECT },
                "{guest}: {}",
                fixture.name
            );
            if accepted {
                assert_eq!(report.id, fixture.input.statement.id().0);
                assert!(gas <= 150_000_000, "{gas} gas");
            }
        }
    }
}

/// The production guest's program, linking format 39 alone, within JAM's
/// 4,000,000-byte bound on a service's code; its size beside 512 KiB and the
/// test guest's.
#[test]
fn the_production_program_fits_jams_code_bound() {
    let (program, elf) = jam::program();
    let (test, test_elf) = jam::test_program();
    eprintln!(
        "final-verify: program {} B (ELF {elf} B), {} 512 KiB; final-verify-test: program {} B \
         (ELF {test_elf} B)",
        program.len(),
        if program.len() <= 512 << 10 {
            "within"
        } else {
            "over"
        },
        test.len(),
    );
    assert!(program.len() <= 4_000_000, "{} bytes", program.len());
    assert!(program.len() < test.len(), "28's verifier is not linked");
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
        program: valid.input.pin.program.0,
        io_hash: valid.input.statement.io_hash(),
    }
    .words();
    let (_, report) = jam::run(&program, &jam::words_request(masked::FORMAT, &words), &long);
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
