//! The `balance` test actor's read at a window's cut: whether an account
//! held at least a threshold, the account public only as a salted
//! commitment. Run live at the cut on the agent's reference model,
//! re-traced, proved whole, wrapped under format 28 and masked under 39,
//! and judged at the model venue against the space's anchor.

use crate::common;
use crate::cut::{self, AGENT, Cut, INSTANCE, Rng, Venue, genesis, read_live, traced};

use vos_pvm_final_verifier::masked;
use vos_statement::{Pin, ProgramId, Statement};
use vos_testkit::programs::table_tag;
use vos_tree::{Blake2b, Hasher};
use vos_wire::Encode;
use vos_wire::abi::AttestError;
use vos_wire::ids::MapId;
use vos_wire::keys::{self, Transform};
use vos_wire::vos_anchor::{VenueId, space_id};

pub(crate) const ACCOUNT: [u8; 32] = [0xAC; 32];
const BALANCE: u64 = 5_000;
pub(crate) const SALT: [u8; 16] = [0x5A; 16];

/// The actor's commitment to `account` under `salt` (`balance::commitment`).
pub(crate) fn commitment(salt: &[u8; 16], account: &[u8; 32]) -> [u8; 32] {
    Blake2b.hash(b"vos/test/balance/account", &[salt, account])
}

/// An account's full row key in the actor's balances.
fn row(account: &[u8; 32]) -> Vec<u8> {
    let map = MapId {
        instance: INSTANCE,
        tag: table_tag("balances"),
        transform: Transform::Hashed,
    };
    keys::committed(&map, &Transform::Hashed.apply(account))
}

/// The balances at the cut: [`ACCOUNT`]'s among 256 others.
pub(crate) fn balances() -> Cut {
    let mut rng = Rng(0xba1a_0000);
    let others = (0..256)
        .map(|_| {
            let mut account = [0u8; 32];
            rng.fill(&mut account);
            (row(&account), rng.next().encode())
        })
        .collect();
    let known = vec![(row(&ACCOUNT), BALANCE.encode())];
    Cut::new(space_id(&genesis(1)), known, others, 8, true)
}

/// `at_least_at_cut` of `account` over `threshold`, its commitment `c`
/// opened by `salt`.
pub(crate) fn at_least(
    cut: &Cut,
    c: [u8; 32],
    threshold: u64,
    salt: [u8; 16],
    account: [u8; 32],
) -> cut::Live {
    read_live(
        cut,
        "balance",
        "at_least_at_cut",
        &((c, threshold), (salt, account)).encode(),
        |_| {},
    )
}

/// The statement names the account by its commitment alone: its public
/// arguments the reader's agent and instance, the commitment and the
/// threshold; its output whether the balance at the cut reached it; an
/// absent account holding nothing. Live ≡ traced.
#[test]
fn a_balance_is_stated_at_a_cut() {
    let cut = balances();
    let c = commitment(&SALT, &ACCOUNT);
    for (threshold, holds) in [(1_000, true), (BALANCE, true), (BALANCE + 1, false)] {
        let live = at_least(&cut, c, threshold, SALT, ACCOUNT);
        assert_eq!(live.output::<bool>(), Ok(holds), "{threshold}");
        let attest = live.attest();
        assert_eq!(
            attest.public_args,
            [(AGENT, INSTANCE).encode(), (c, threshold).encode()].concat()
        );
        assert_eq!(attest.roots, [cut.root()]);
        assert!(
            !attest
                .public_args
                .windows(ACCOUNT.len())
                .any(|window| window == ACCOUNT),
            "the account is not public"
        );
        let (kernel, _) = cut::kernel_of("balance", attest);
        traced(attest, &kernel);
    }
    let absent = [0xAD; 32];
    let live = at_least(&cut, commitment(&SALT, &absent), 1, SALT, absent);
    assert_eq!(live.output::<bool>(), Ok(false), "an absent account");
}

/// A commitment its salt and account do not open traps the kernel: another
/// salt, and another account's commitment.
#[test]
fn a_commitment_that_does_not_open_is_refused() {
    let cut = balances();
    let c = commitment(&SALT, &ACCOUNT);
    let live = at_least(&cut, c, 1_000, [0x5B; 16], ACCOUNT);
    assert_eq!(live.output::<bool>(), Err(AttestError::Failed));
    let other = commitment(&SALT, &[0xAE; 32]);
    let live = at_least(&cut, other, 1_000, SALT, ACCOUNT);
    assert_eq!(live.output::<bool>(), Err(AttestError::Failed));
}

/// The balance's statement proved whole, wrapped masked under format 39 and
/// accepted at the model venue holding the space's root anchored; another
/// threshold or commitment in its public arguments refused by the proof's
/// words.
#[test]
fn a_balance_is_accepted_at_the_model_venue() {
    let cut = balances();
    let c = commitment(&SALT, &ACCOUNT);
    let live = at_least(&cut, c, 1_000, SALT, ACCOUNT);
    let attest = live.attest().clone();
    let root = cut.root();
    let (blob, record) = cut::kernel_of("balance", &attest);
    let trace = traced(&attest, &blob);
    eprintln!(
        "balance: {} steps, {} compressions, witness input {} B",
        trace.side_note.steps.len(),
        trace.side_note.blake2b_calls.len(),
        attest.witness_input.len()
    );
    let (program, node, segments, mut totals) =
        cut::prove_whole("balance", &blob, &record, &trace, 1);
    let (_, _, proof) = common::wrap_root("balance", &program, &node, &mut totals.wrap);
    totals.report("balance");
    eprintln!("balance: {segments} segments");

    let program = ProgramId(program.id().0.map(|word| word.0));
    let statement = Statement {
        format: masked::FORMAT,
        program,
        space: cut.space,
        public_args: attest.public_args.clone(),
        output: attest.output.clone(),
        roots: attest.roots.clone(),
    };
    let venue = Venue::new(VenueId([0x7e; 32]), &[genesis(1)]);
    venue.venue.pin(Pin {
        program,
        venue_bound: false,
    });
    venue.anchor(&root).expect("anchored");
    let code = |statement: &Statement| {
        vos_venue::code(&vos_venue::VenueClient::submit(
            &venue.venue,
            statement,
            &proof,
        ))
    };
    let by_words = |code: u32| code == 0x108 || code == 0x109;
    let mut changed = statement.clone();
    let threshold = changed.public_args.len() - 8;
    changed.public_args[threshold] ^= 1;
    assert!(by_words(code(&changed)), "another threshold");
    let mut changed = statement.clone();
    changed.public_args[8] ^= 1;
    assert!(by_words(code(&changed)), "another commitment");
    assert_eq!(code(&statement), 0, "accepted");
}
