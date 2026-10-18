//! The golden wrap (`pvm/proof/fixtures`, the `valid` case): its proof's
//! bytes and the 24 public words it verifies against.

use std::sync::OnceLock;

use vos_final_verifier::PUBLIC_WORDS;

pub struct Golden {
    /// The mutation target's starting point; the bytes target's corpus
    /// holds it as a file.
    #[allow(dead_code)]
    pub proof: Vec<u8>,
    pub words: [u32; PUBLIC_WORDS],
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
        Golden {
            proof: valid.proof,
            words,
        }
    })
}
