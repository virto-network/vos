//! Retry only the existing borrowed Shared startup recovery before publication.

use super::SharedAgentHostError;
use std::time::{Duration, Instant};

const SHARED_RECOVERY_ATTEMPT_BUDGET: Duration = Duration::from_secs(30);
const SHARED_RECOVERY_RETRY_CADENCE: Duration = Duration::from_millis(10);

/// Keep the caller's controller, System owner, signer and leases alive. The
/// callback is the same native recovery operation, not a store reopen or a new
/// authorization. Conflict and validation failures retain their fatal meaning.
///
/// This bounds scheduling between attempts, not execution inside an attempt:
/// nested consensus waits still require whole-recovery physical qualification.
pub(super) fn recover_shared_before_publication(
    mut recover: impl FnMut() -> Result<(), SharedAgentHostError>,
) -> Result<(), SharedAgentHostError> {
    let started = Instant::now();
    loop {
        match recover() {
            Err(error @ SharedAgentHostError::Unavailable) => {
                let Some(remaining) = SHARED_RECOVERY_ATTEMPT_BUDGET
                    .checked_sub(started.elapsed())
                    .filter(|remaining| !remaining.is_zero())
                else {
                    return Err(error);
                };
                std::thread::sleep(SHARED_RECOVERY_RETRY_CADENCE.min(remaining));
                if started.elapsed() >= SHARED_RECOVERY_ATTEMPT_BUDGET {
                    return Err(error);
                }
            }
            result => return result,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::shared_recovery::completed_management_manifest_for_test;
    use crate::agent::shared_recovery::management::completed_management_slot_for_test;
    use crate::service::wire::ServiceWire;

    #[test]
    fn shared_startup_retry_keeps_the_same_borrowed_source_and_signed_material() {
        // Genuine canonical signed custody, not fabricated application or
        // genesis approval. This tests the scheduling seam; the released
        // returning-Follower fixture must separately execute native recovery.
        let mut controller = completed_management_slot_for_test().registration().clone();
        let mut system = completed_management_manifest_for_test();
        let mut signer = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
        let identities = (
            (&mut controller as *mut _) as usize,
            (&mut system as *mut _) as usize,
            (&mut signer as *mut _) as usize,
        );
        let immutable = (controller.encode(), system.encode(), signer.to_bytes());
        let mut attempts = 0;
        recover_shared_before_publication(|| {
            attempts += 1;
            assert_eq!(
                (
                    (&mut controller as *mut _) as usize,
                    (&mut system as *mut _) as usize,
                    (&mut signer as *mut _) as usize,
                ),
                identities
            );
            assert_eq!(
                (controller.encode(), system.encode(), signer.to_bytes()),
                immutable
            );
            match attempts {
                1 => Err(SharedAgentHostError::Unavailable),
                2 => Err(SharedAgentHostError::Unavailable),
                _ => Ok(()),
            }
        })
        .unwrap();
        assert_eq!(attempts, 3);
    }

    #[test]
    fn shared_startup_retry_does_not_retry_conflict_or_validation_failure() {
        for error in [
            SharedAgentHostError::Conflict,
            SharedAgentHostError::ScopeMismatch,
            SharedAgentHostError::CorruptResidue,
            SharedAgentHostError::InvalidProvision,
            SharedAgentHostError::InvalidCatalog,
            SharedAgentHostError::CapacityExhausted,
        ] {
            let mut attempts = 0;
            assert_eq!(
                recover_shared_before_publication(|| {
                    attempts += 1;
                    Err(error)
                }),
                Err(error)
            );
            assert_eq!(attempts, 1);
        }
    }

    #[test]
    fn shared_startup_retry_preserves_later_fatal_failure_after_transient_progress() {
        let mut retained_progress = 0;
        assert_eq!(
            recover_shared_before_publication(|| {
                retained_progress += 1;
                match retained_progress {
                    1 => Err(SharedAgentHostError::Unavailable),
                    _ => Err(SharedAgentHostError::ScopeMismatch),
                }
            }),
            Err(SharedAgentHostError::ScopeMismatch)
        );
        assert_eq!(retained_progress, 2);
    }
}
