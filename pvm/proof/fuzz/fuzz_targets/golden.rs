//! The golden wrap (`pvm/proof/fixtures`, the `valid` case): its proof's
//! bytes, the 24 public words it verifies against, and the oracle for a
//! proof a target finds accepted.

use std::sync::OnceLock;

use vos_final_verifier::PUBLIC_WORDS;

pub struct Golden {
    /// Its canonical encoding: postcard's, minimal varints. The mutation
    /// target's starting point, and what an accepted proof re-encodes to.
    pub proof: Vec<u8>,
    pub words: [u32; PUBLIC_WORDS],
}

impl Golden {
    /// The oracle for an accepted proof: it is the golden proof by value,
    /// its re-encoding the golden bytes.
    ///
    /// Not its bytes: postcard reads a varint in any length, so an accepted
    /// encoding may differ from the golden one (venues key on the
    /// statement's id for it). Not its statement: the verifier returns the
    /// words it was given, so that holds of any acceptance. A second proof
    /// of the golden words would be a part of the proof the transcript does
    /// not bind, which no mutation should find.
    pub fn assert_is_golden(&self, proof: &vos_final_verifier::WrapProof) {
        let bytes = postcard::to_allocvec(proof).expect("encodes");
        assert!(
            bytes == self.proof,
            "an accepted proof that is not the golden one"
        );
    }
}

pub fn golden() -> &'static Golden {
    static GOLDEN: OnceLock<Golden> = OnceLock::new();
    GOLDEN.get_or_init(|| {
        let fixtures = vos_statement::fixtures::load(&vos_statement::fixtures::directory());
        let valid = fixtures
            .into_iter()
            .find(|fixture| fixture.name == "valid")
            .expect("the valid fixture");
        let words = vos_final_verifier::Statement {
            program: valid.input.program.0,
            io_hash: valid.input.statement.io_hash(),
        }
        .words();
        vos_final_verifier::verify_bytes(&valid.proof, &words).expect("the golden wrap verifies");
        let decoded = vos_final_verifier::decode(&valid.proof).expect("decodes");
        assert_eq!(
            postcard::to_allocvec(&decoded).expect("encodes"),
            valid.proof,
            "the golden wrap's encoding is postcard's own"
        );
        Golden {
            proof: valid.proof,
            words,
        }
    })
}
