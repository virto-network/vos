//! Separate verifier actor for the private-age producer.
//!
//! The gate consumes a portable package that was already produced and
//! accumulated. Verification never invokes the producer or generates a proof.

use private_age::{AgeClaim, IsAdult};
use vos::prelude::*;

#[actor]
pub struct AgeGate {
    admitted: u64,
}

#[messages]
impl AgeGate {
    fn new() -> Self {
        Self { admitted: 0 }
    }

    /// Admit a verified adult exactly once per producer invocation.
    ///
    /// Refine records the verification requirement. Guest Accumulate checks
    /// the producer binding, proof, receipt, and replay row atomically with
    /// this state update before the result becomes observable.
    #[msg]
    async fn admit(
        &mut self,
        package: Attestation<AgeClaim, IsAdult>,
        ctx: &mut Context<Self>,
    ) -> bool {
        let Ok(claim) = ctx.verify(package).from("private-age").once().await else {
            return false;
        };
        if !claim.adult {
            return false;
        }

        self.admitted = self.admitted.saturating_add(1);
        true
    }

    #[msg]
    fn admitted(&self) -> u64 {
        self.admitted
    }
}
