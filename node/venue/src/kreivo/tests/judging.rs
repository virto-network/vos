use super::*;

/// Statements through the client, at the conformance vectors' world (`F`
/// with its two roots anchored): the fixture accepted, its repeat
/// accepted without a send, a tampered proof refused with its class, and
/// a format the venue does not accept refused before paying.
#[test]
fn statements_are_judged_through_the_client() {
    let fx = Fixtures::load();
    let chain = MockChain::new(g7_chain(&fx));
    let venue = KreivoVenue::over(
        chain.transport(Origin::Signed(AUTHORITY_F)),
        &[SpaceId(F)],
        SpaceId(F),
        options(),
    );
    let statement = fx.statement();
    assert_eq!(venue.submit(statement, &fx.proof), SubmitOutcome::Accepted);
    let sent = chain.sends().len();
    assert_eq!(
        venue.submit(statement, &fx.proof),
        SubmitOutcome::Accepted,
        "a repeat"
    );
    assert_eq!(chain.sends().len(), sent, "known accepted: not sent");
    let mut other = statement.clone();
    other.output.push(0);
    let refused = venue.submit(&other, &fx.proof);
    assert!(
        matches!(refused, SubmitOutcome::Refused(code) if crate::proof_refused(code)),
        "the proof refused against another statement: {refused:?}"
    );
    assert_eq!(
        venue.submit(statement, &fx.tampered),
        SubmitOutcome::Accepted,
        "known accepted, whatever the proof"
    );
    let mut format = statement.clone();
    format.format = 30;
    let sent = chain.sends().len();
    assert_eq!(
        venue.submit(&format, &fx.proof),
        SubmitOutcome::Refused(Refusal::Format.code())
    );
    assert_eq!(chain.sends().len(), sent, "refused before paying");
    assert!(
        venue
            .alerts()
            .iter()
            .all(|alert| !matches!(alert, Alert::Unexpected(_)))
    );
}

/// A tampered proof of a fresh statement is refused with its class, its
/// deposit forfeited, through the client.
#[test]
fn a_refused_proof_reports_its_class() {
    let fx = Fixtures::load();
    let chain = MockChain::new(g7_chain(&fx));
    let venue = KreivoVenue::over(
        chain.transport(Origin::Signed(AUTHORITY_F)),
        &[SpaceId(F)],
        SpaceId(F),
        options(),
    );
    assert_eq!(
        venue.submit(fx.statement(), &fx.tampered),
        SubmitOutcome::Refused(fx.tampered_code)
    );
    assert_eq!(
        venue.submit(fx.statement(), &fx.proof),
        SubmitOutcome::Accepted
    );
}

/// Every pallet error has its outcome (`spaces-pallet.md` §9), its code
/// kept, and a submit's events their outcome: `Refused { 6 }` accepted,
/// `Refused { 5 }` again later.
#[test]
fn every_error_and_refusal_is_mapped() {
    use Error::*;
    for error in (0..=u8::MAX).filter_map(Error::from_index) {
        let code = error as u32;
        let expected = match error {
            AlreadyAnchored => AnchorOutcome::Taken,
            WindowNotAfterLast | WindowTooOld | BadAnchorSignature | BadKind => {
                AnchorOutcome::Never(code)
            }
            NotAuthority | UnknownAnchorKey => AnchorOutcome::Unlisted(code),
            SpaceNotActive => AnchorOutcome::Stopped(code),
            _ => AnchorOutcome::NotYet,
        };
        assert_eq!(outcome_of(Some(error)), expected, "{error:?}");
    }
    assert_eq!(outcome_of(None), AnchorOutcome::NotYet);
    let id = vos_statement::StatementId([7; 32]);
    let refused = |code| Event::Refused {
        payer: [0; 32],
        statement_hash: [0; 32],
        code,
    };
    let accepted = Event::Accepted {
        id: id.0,
        program: [0; 8],
        space: [0; 32],
        payer: [0; 32],
        output_hash: [0; 32],
    };
    assert_eq!(judged(&[accepted], id), Some(SubmitOutcome::Accepted));
    assert_eq!(
        judged(&[refused(Refusal::Repeated.code())], id),
        Some(SubmitOutcome::Accepted)
    );
    assert_eq!(
        judged(&[refused(Refusal::Unanchored.code())], id),
        Some(SubmitOutcome::Retry(Refusal::Unanchored.code()))
    );
    for code in [1, 2, 3, 4, 0x101, 0x108] {
        assert_eq!(
            judged(&[refused(code)], id),
            Some(SubmitOutcome::Refused(code))
        );
    }
    assert_eq!(judged(&[], id), None);
}

/// The client's bound on one submit is what a submit holds at the design's
/// suggested values: its deposit and a fee's bound.
#[test]
fn a_submits_bound_is_its_deposit_and_fee() {
    let constants = Constants::kreivo(VENUE);
    assert_eq!(
        Options::default().per_submit,
        constants.submit_deposit + constants.fee_bound
    );
}
