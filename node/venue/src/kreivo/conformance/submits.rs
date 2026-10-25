//! The submits' vectors: G6–G10, G12 and G13.

use parity_scale_codec::Encode;
use vos_statement::{RootRead, SpaceId, Statement};

use super::world::*;
use super::{Fixtures, Vector};
use crate::kreivo::mock::keys;
use crate::kreivo::mock::types::{
    Active, Call, Error, Handler, PAUSE_ANCHOR, PAUSE_REGISTER, PAUSE_SUBMIT, ProgramInfo,
};
use crate::kreivo::mock::{Chain, Origin, Payer};

pub(super) fn g6(fx: &Fixtures) -> Vector {
    let mut w = World::new(fx, false);
    w.begin();
    w.anchor_f();
    w.accept(AUTHORITY_F, F);
    let id = fx.statement().id().0;
    let expiry = vos_statement::seen_expiry(fx.statement(), &F_CLOCK);
    assert_eq!(
        w.chain.storage().get(&keys::seen(&id)),
        Some(&expiry.encode())
    );
    w.finish(
        "G6",
        "submit of the masked format-39 fixture: its two roots anchored, then Accepted { id }, \
         Seen[id] its newest root's B_w + MaxRootAge, the deposit held and released",
    )
}

/// G7's pre-state: the world, `F`'s two roots anchored.
pub fn g7_chain(fx: &Fixtures) -> Chain {
    let mut w = World::new(fx, false);
    w.anchor_f();
    w.chain
}

pub(super) fn g7(fx: &Fixtures) -> Vector {
    let mut w = World::new(fx, false);
    w.anchor_f();
    w.begin();
    let s = fx.statement();
    let proof = &fx.proof;
    let mut truncated = s.encode();
    truncated.pop();
    w.refused(truncated, proof.clone(), 1);
    let changed = |change: &dyn Fn(&mut Statement)| {
        let mut statement = s.clone();
        change(&mut statement);
        statement.encode()
    };
    w.refused(changed(&|s| s.format = 30), proof.clone(), 2);
    w.refused(changed(&|s| s.program.0[0] += 1), proof.clone(), 3);
    w.refused(
        changed(&|s| s.space = SpaceId([0xb2; 32])),
        proof.clone(),
        4,
    );
    let unanchored = RootRead {
        window: 40,
        root: root(0x40),
        ..s.roots[0]
    };
    w.refused(changed(&|s| s.roots[0] = unanchored), proof.clone(), 5);
    assert!(crate::proof_refused(fx.tampered_code));
    w.refused(s.encode(), fx.tampered.clone(), fx.tampered_code);
    // The activation windows: the fixture's own format and program stored,
    // but not active now.
    let format = vos_statement::vos_pvm_final_verifier::masked::FORMAT;
    let set_format = |from_ms, until_ms| Call::SetFormat {
        format,
        active: Active { from_ms, until_ms },
    };
    let set_program = |from_ms, until_ms| Call::SetProgram {
        program: fx.valid.program.0,
        info: Some(ProgramInfo {
            handler: Handler::Record,
            active: Active { from_ms, until_ms },
        }),
    };
    let (later, latest) = (NOW + 60_000, NOW + 120_000);
    w.call(Origin::Root, set_format(0, Some(NOW)), Expect::Ok);
    w.refused(s.encode(), proof.clone(), 2);
    w.call(Origin::Root, set_format(later, None), Expect::Ok);
    w.refused(s.encode(), proof.clone(), 2);
    w.at(later);
    w.call(Origin::Root, set_program(0, Some(later)), Expect::Ok);
    w.refused(s.encode(), proof.clone(), 3);
    w.call(Origin::Root, set_program(latest, None), Expect::Ok);
    w.refused(s.encode(), proof.clone(), 3);
    w.at(latest);
    w.accept(AUTHORITY_F, F);
    w.finish(
        "G7",
        "one mutant per refusal class, each Refused { code } and DepositForfeited: 1 (the \
         statement cut short), 2 (format 30), 3 (a program not in Programs), 4 (a space not its \
         roots'), 5 (a root not anchored), 0x1xx (the proof's byte flipped); 6 is G8's, its \
         deposit released. Then the statement itself against \
         activation windows: 2 while Formats[39].until_ms is now (retired), and while its \
         from_ms is past now; 3 while its program's until_ms is now, and while its from_ms is \
         past now; accepted once now reaches it",
    )
}

pub(super) fn g8(fx: &Fixtures) -> Vector {
    let mut w = World::new(fx, false);
    w.anchor_f();
    w.begin();
    w.accept(AUTHORITY_F, F);
    w.refused(fx.statement().encode(), fx.proof.clone(), 6);
    w.finish(
        "G8",
        "the same statement twice: Accepted, then Refused { 6 } with the deposit released",
    )
}

pub(super) fn g9(fx: &Fixtures) -> Vector {
    let mut w = World::new(fx, false);
    w.anchor_f();
    w.begin();
    // A statement of no root, of no space: venues judge rooted statements
    // alone.
    let rootless = Statement {
        space: SpaceId::NONE,
        roots: Vec::new(),
        ..fx.statement().clone()
    };
    w.refused(rootless.encode(), fx.proof.clone(), 4);
    w.accept(AUTHORITY_F, F);
    let past = F_CLOCK.boundary(42).unwrap() + vos_anchor::MAX_ROOT_AGE_MS + 1;
    w.at(past);
    // Before the cursor prunes them: the anchors are held but stale.
    w.refused(fx.statement().encode(), fx.proof.clone(), 5);
    w.on_idle();
    assert!(!w.has(&keys::seen(&fx.statement().id().0)));
    w.refused(fx.statement().encode(), fx.proof.clone(), 5);
    w.finish(
        "G9",
        "a statement of no root refused 4: venues judge rooted statements alone. A rooted one \
         accepted; at MaxRootAge + 1 past its newest root's B_w, resubmitted before on_idle \
         refused 5 (its anchors held but past MaxRootAge); on_idle prunes its Seen entry; \
         resubmitted, refused 5",
    )
}

pub(super) fn g10(fx: &Fixtures) -> Vector {
    let mut w = World::new(fx, false);
    // A space whose sovereign, once registered, cannot hold a deposit.
    let poor = genesis_of(0xc1);
    let constants = w.constants().clone();
    let free = constants.registration_deposit
        + constants.existential_deposit
        + constants.submit_deposit / 2;
    w.chain
        .set_account(constants.sovereign(&space_of(&poor)), funded(free));
    w.register(&poor, Expect::Ok);
    let add = Call::AddAuthority {
        space: space_of(&poor),
        who: AUTHORITY_2,
        anchor_key: None,
    };
    w.controller(add, Expect::Ok);
    w.begin();
    let s = fx.statement().encode();
    w.submit(
        AUTHORITY_2,
        space_of(&poor),
        s.clone(),
        fx.proof.clone(),
        Expect::Err(Error::InsufficientSovereignBalance),
    );
    w.submit(
        STRANGER,
        F,
        s.clone(),
        fx.proof.clone(),
        Expect::Err(Error::NotAuthority),
    );
    let pause = |flags| Call::SetPaused { flags };
    w.call(
        Origin::Signed(STRANGER),
        pause(PAUSE_SUBMIT),
        Expect::BadOrigin,
    );
    w.call(Origin::Emergency, pause(PAUSE_SUBMIT), Expect::Ok);
    w.submit(
        AUTHORITY_F,
        F,
        s,
        fx.proof.clone(),
        Expect::Err(Error::Paused),
    );
    let roots = fx.statement().roots.clone();
    w.anchor(
        AUTHORITY_F,
        F,
        roots[0].window,
        roots[0].root,
        KEY_F,
        Expect::Ok,
    );
    w.call(Origin::Emergency, pause(PAUSE_ANCHOR), Expect::Ok);
    w.anchor(
        AUTHORITY_F,
        F,
        roots[1].window,
        roots[1].root,
        KEY_F,
        Expect::Err(Error::Paused),
    );
    w.call(Origin::Emergency, pause(PAUSE_REGISTER), Expect::Ok);
    w.register(&b_genesis(), Expect::Err(Error::Paused));
    w.call(Origin::Root, pause(0), Expect::Ok);
    w.anchor(
        AUTHORITY_F,
        F,
        roots[1].window,
        roots[1].root,
        KEY_F,
        Expect::Ok,
    );
    w.register(&b_genesis(), Expect::Ok);
    w.finish(
        "G10",
        "a submit whose sovereign cannot hold the deposit (InsufficientSovereignBalance, nothing \
         moved); a non-authority's submit (NotAuthority); set_paused by a signed account (BadOrigin); \
         each pause flag, by the emergency origin, refusing its call (Paused): bit 0 submit, \
         bit 1 anchor, bit 2 register, each other call unpaused; cleared by Root",
    )
}

pub(super) fn g12(fx: &Fixtures) -> Vector {
    let mut w = World::new(fx, true);
    w.with_b(AUTHORITY_1, KEY_3);
    // `B`'s sovereign holds its fee and half a deposit.
    let sovereign = w.constants().sovereign(&b());
    let mut account = w.chain.account(&sovereign);
    account.free = w.constants().fee_bound + w.constants().submit_deposit / 2;
    w.chain.set_account(sovereign, account);
    w.begin();
    let garbage = vec![0];
    let outcome = w.submit(
        AUTHORITY_1,
        b(),
        garbage.clone(),
        Vec::new(),
        Expect::Payment,
    );
    assert_eq!(outcome.payer, None);
    let outcome = w.anchor(AUTHORITY_1, b(), 35, root(0x35), KEY_3, Expect::Ok);
    assert_eq!(outcome.payer, Some(Payer::Sovereign));
    let outcome = w.anchor(STRANGER, b(), 36, root(0x36), KEY_1, Expect::Ok);
    assert_eq!(outcome.payer, Some(Payer::Signer));
    let outcome = w.submit(AUTHORITY_F, F, garbage.clone(), Vec::new(), Expect::Ok);
    assert_eq!(outcome.payer, Some(Payer::Sovereign));
    let outcome = w.submit(
        STRANGER,
        F,
        garbage,
        Vec::new(),
        Expect::Err(Error::NotAuthority),
    );
    assert_eq!(outcome.payer, Some(Payer::Signer));
    w.finish(
        "G12",
        "fees, signs only: a submit whose sovereign cannot cover its fee and deposit refused in \
         validate (InvalidTransaction::Payment), nothing paid; an authority's anchor and submit \
         paid by the sovereign account, the authority unchanged; a non-authority's anchor and \
         submit paid by the signer",
    )
}

pub(super) fn g13(fx: &Fixtures) -> Vector {
    let mut w = World::new(fx, true);
    w.with_b(AUTHORITY_1, KEY_3);
    w.anchor_f();
    w.begin();
    let constants = w.constants().clone();
    let each = constants.submit_deposit + constants.fee_bound;
    assert_eq!(constants.default_spend_per_window, 8 * each);
    // Statements that do not decode: each refused 1, its deposit
    // forfeited, so each spends a fee and a deposit.
    for n in 0..8u8 {
        w.submit(AUTHORITY_1, b(), vec![n], Vec::new(), Expect::Ok);
    }
    let sovereign = constants.sovereign(&b());
    let before = w.chain.account(&sovereign);
    w.submit(AUTHORITY_1, b(), vec![8], Vec::new(), Expect::Payment);
    assert_eq!(w.chain.account(&sovereign), before, "untouched");
    // The next window, by the venue's time.
    let next = B_CLOCK.boundary(B_CLOCK.window(NOW).unwrap()).unwrap();
    w.at(next);
    w.submit(AUTHORITY_1, b(), vec![8], Vec::new(), Expect::Ok);
    let budget = Call::SetBudget {
        space: b(),
        max_spend_per_window: 2 * each,
    };
    w.controller(budget, Expect::Ok);
    w.submit(AUTHORITY_1, b(), vec![9], Vec::new(), Expect::Ok);
    w.submit(AUTHORITY_1, b(), vec![10], Vec::new(), Expect::Payment);
    // An accepted submit's deposit, released, is credited back: at one
    // submit and one fee a window, the accepted one leaves room for one
    // forfeiting submit, which without the credit would not fit.
    let budget = Call::SetBudget {
        space: b(),
        max_spend_per_window: each + constants.fee_bound,
    };
    w.controller(budget, Expect::Ok);
    w.at(B_CLOCK.boundary(B_CLOCK.window(next).unwrap()).unwrap());
    w.accept(AUTHORITY_1, b());
    w.submit(AUTHORITY_1, b(), vec![11], Vec::new(), Expect::Ok);
    w.submit(AUTHORITY_1, b(), vec![12], Vec::new(), Expect::Payment);
    w.finish(
        "G13",
        "the budget, fees: at 8 × (SubmitDeposit + FeeBound) a window, eight forfeiting \
         submits taken and the ninth refused in validate (InvalidTransaction::Payment; \
         OverBudget in the fallback), the sovereign untouched; the next window resets it; \
         set_budget to two submits' worth, the window's second taken and its third refused; \
         set_budget to SubmitDeposit + 2 × FeeBound, the next window's accepted submit, its \
         deposit credited back, leaving room for one forfeiting submit, and the next refused. \
         The model charges each fee at FeeBound, so eight fill the budget exactly",
    )
}
