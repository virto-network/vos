//! Detached ordinary external maintenance; no public or image-path cutover.

use super::*;

impl SharedAgentHost {
    /// Reclaim only an exact installed, fixed-three ordinary external common
    /// checkpoint. System pending scopes and active transport remain excluded.
    pub(crate) fn compact_external_common_checkpoint(
        &mut self,
        agent: AgentId,
        limits: SharedAgentCompactionLimits,
    ) -> Result<SharedAgentCompaction, SharedAgentHostError> {
        let intent = self.require_external_archive_maintenance(agent)?;
        let outcome = self
            .agents
            .get_mut(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .compact_external_common_checkpoint(
                limits.max_binding_unlinks,
                super::super::journal_store::GcLimits {
                    max_index_nodes: limits.max_index_nodes,
                    max_marked_objects: limits.max_marked_objects,
                    max_marked_blobs: limits.max_marked_blobs,
                    max_scanned_files: limits.max_scanned_files,
                    max_scanned_bytes: limits.max_scanned_bytes,
                    max_unlinks_per_run: limits.max_unlinks,
                },
            )
            .map_err(map_driver_error)?;
        if self.require_external_archive_maintenance(agent)? != intent {
            return Err(SharedAgentHostError::CorruptResidue);
        }
        let journal = outcome.journal;
        Ok(SharedAgentCompaction {
            bindings_removed: outcome.bindings_removed,
            bindings_remaining: outcome.bindings_remaining,
            objects_removed: journal.map_or(0, |gc| gc.objects_removed),
            blobs_removed: journal.map_or(0, |gc| gc.blobs_removed),
            aliases_removed: journal.map_or(0, |gc| gc.aliases_removed),
            resumed: journal.is_some_and(|gc| gc.resumed),
            complete: outcome.bindings_remaining == 0 && journal.is_some_and(|gc| gc.complete),
        })
    }
}
