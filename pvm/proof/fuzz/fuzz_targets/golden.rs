//! The golden wraps: format 28's (`pvm/proof/fixtures`, the `valid` case)
//! and format 39's (the one-segment run's masked wrap, which
//! `vos-pvm-recair`'s masked wrap tests write under the workspace's
//! `target/tmp/wrap/one-segment-39.{proof,words}`): each its proof's bytes,
//! the 24 public words it verifies against, and the oracle for a proof a
//! target finds accepted. Each target uses what it reads of it.

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

pub fn golden() -> &'static Golden {
    static GOLDEN: OnceLock<Golden> = OnceLock::new();
    GOLDEN.get_or_init(|| {
        let fixtures = vos_statement::fixtures::load(&vos_statement::fixtures::directory());
        let valid = fixtures
            .into_iter()
            .find(|fixture| fixture.name == "valid")
            .expect("the valid fixture");
        let words = vos_pvm_final_verifier::Statement {
            program: valid.input.program.0,
            io_hash: valid.input.statement.io_hash(),
        }
        .words();
        vos_pvm_final_verifier::unmasked::verify_bytes(&valid.proof, &words)
            .expect("the golden wrap verifies");
        let decoded = vos_pvm_final_verifier::unmasked::decode(&valid.proof).expect("decodes");
        assert_eq!(
            postcard::to_allocvec(&decoded).expect("encodes"),
            valid.proof,
            "the golden wrap's encoding is postcard's own"
        );
        Golden {
            format: vos_pvm_final_verifier::unmasked::FORMAT,
            proof: valid.proof,
            words,
        }
    })
}

/// The format-39 golden: the one-segment run's masked wrap, as
/// `vos-pvm-recair`'s masked wrap tests write it (`cargo test -p
/// vos-pvm-recair --test recursion masked` first).
pub fn golden_39() -> &'static Golden {
    static GOLDEN: OnceLock<Golden> = OnceLock::new();
    GOLDEN.get_or_init(|| {
        let directory = masked_directory();
        let read = |extension: &str| {
            let path = directory.join(format!("one-segment-39.{extension}"));
            std::fs::read(&path).unwrap_or_else(|error| {
                panic!(
                    "{} ({error}): run `cargo test -p vos-pvm-recair --test recursion masked` \
                     first, with this `CARGO_TARGET_DIR` if the workspace's is elsewhere",
                    path.display()
                )
            })
        };
        let proof = read("proof");
        let bytes = read("words");
        let words: [u32; PUBLIC_WORDS] = core::array::from_fn(|i| {
            u32::from_le_bytes(bytes[4 * i..4 * i + 4].try_into().expect("a word"))
        });
        vos_pvm_final_verifier::masked::verify_bytes(&proof, &words)
            .expect("the golden masked wrap verifies");
        let decoded = vos_pvm_final_verifier::masked::decode(&proof).expect("decodes");
        assert_eq!(
            vos_pvm_final_verifier::masked::encode(&decoded),
            Some(proof.clone()),
            "the fixed layout is the one encoding"
        );
        Golden {
            format: vos_pvm_final_verifier::masked::FORMAT,
            proof,
            words,
        }
    })
}

/// Where `vos-pvm-recair`'s masked wrap tests write the format-39 golden:
/// `wrap` under the workspace's target directory's `tmp`, the workspace's
/// `target` unless `CARGO_TARGET_DIR` names another.
pub fn masked_directory() -> std::path::PathBuf {
    std::env::var_os("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../target"))
        .join("tmp/wrap")
}

/// Both goldens.
pub fn goldens() -> [&'static Golden; 2] {
    [golden(), golden_39()]
}
