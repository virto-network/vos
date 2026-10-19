//! The golden wraps, the fixtures' (`pvm/proof/fixtures`): format 39's two
//! accepted statements' and format 28's: each its proof's bytes, the 24
//! public words it verifies against, and the oracle for a proof a target
//! finds accepted. Each target uses what it reads of it.

#![allow(dead_code)]

use std::sync::OnceLock;

use vos_pvm_final_verifier::PUBLIC_WORDS;

pub struct Golden {
    /// Its format.
    pub format: u32,
    /// Its canonical encoding: postcard's, minimal varints, for 28; the
    /// fixed layout, its one encoding, for 39. The mutation target's
    /// starting point, and what an accepted proof re-encodes to.
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
    pub fn assert_is_golden(&self, proof: &vos_pvm_final_verifier::WrapProof) {
        assert!(
            self.encode(proof).as_ref() == Some(&self.proof),
            "an accepted proof that is not the golden one"
        );
    }

    /// `proof` in the golden's format's encoding; `None` for a proof 39's
    /// layout cannot hold.
    pub fn encode(&self, proof: &vos_pvm_final_verifier::WrapProof) -> Option<Vec<u8>> {
        match self.format {
            vos_pvm_final_verifier::masked::FORMAT => vos_pvm_final_verifier::masked::encode(proof),
            _ => Some(postcard::to_allocvec(proof).expect("encodes")),
        }
    }

    /// The proof in `bytes` under the golden's format.
    pub fn decode(
        &self,
        bytes: &[u8],
    ) -> Result<vos_pvm_final_verifier::WrapProof, vos_pvm_final_verifier::Error> {
        vos_pvm_final_verifier::decode(self.format, vos_pvm_final_verifier::LINKED, bytes)
            .map(vos_pvm_final_verifier::Decoded::into_proof)
    }

    /// Verifies `proof` under the golden's format against its words.
    pub fn verify(&self, proof: vos_pvm_final_verifier::WrapProof) -> bool {
        match self.format {
            vos_pvm_final_verifier::masked::FORMAT => {
                vos_pvm_final_verifier::masked::verify(proof, &self.words).is_ok()
            }
            _ => vos_pvm_final_verifier::unmasked::verify(proof, &self.words).is_ok(),
        }
    }

    /// Verifies `bytes` under the golden's format against its words, the
    /// format the statement's, as a venue dispatches.
    pub fn verify_bytes(&self, bytes: &[u8]) -> bool {
        vos_pvm_final_verifier::verify(
            self.format,
            vos_pvm_final_verifier::LINKED,
            bytes,
            &self.words,
        )
        .is_ok()
    }
}

/// The golden of the fixture `name` (`pvm/proof/fixtures`): its proof, the
/// words its statement makes under its pin, checked to verify and to be its
/// format's own encoding.
fn of_fixture(name: &str) -> Golden {
    let fixtures = vos_statement::fixtures::load(&vos_statement::fixtures::directory());
    let fixture = fixtures
        .into_iter()
        .find(|fixture| fixture.name == name)
        .unwrap_or_else(|| panic!("the fixture {name:?}"));
    let format = fixture.input.statement.format;
    let words = vos_pvm_final_verifier::Statement {
        program: fixture.input.pin.program.0,
        io_hash: fixture.input.statement.io_hash(),
    }
    .words();
    let golden = Golden {
        format,
        proof: fixture.proof,
        words,
    };
    assert!(
        golden.verify_bytes(&golden.proof),
        "{name}: the golden verifies"
    );
    let decoded = golden.decode(&golden.proof).expect("decodes");
    assert_eq!(
        golden.encode(&decoded).as_ref(),
        Some(&golden.proof),
        "{name}: the golden's encoding is its format's own"
    );
    golden
}

/// The goldens: format 39's rooted statement (`valid`) and rootless one
/// (`rootless`), and format 28's (`format 28 at the test venue`).
pub fn goldens() -> &'static [Golden; 3] {
    static GOLDENS: OnceLock<[Golden; 3]> = OnceLock::new();
    GOLDENS.get_or_init(|| {
        [
            of_fixture("valid"),
            of_fixture("rootless"),
            of_fixture("format 28 at the test venue"),
        ]
    })
}
