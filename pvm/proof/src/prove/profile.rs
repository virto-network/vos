//! The proving pipeline's timing breakdown.

/// Timing breakdown of the proving pipeline.
#[derive(Clone, Debug)]
pub struct ProveProfile {
    pub trace_gen: std::time::Duration,
    pub preprocess_commit: std::time::Duration,
    pub main_commit: std::time::Duration,
    pub interaction_gen: std::time::Duration,
    pub interaction_commit: std::time::Duration,
    pub stark_prove: std::time::Duration,
    pub log_sizes: Vec<u32>,
    pub total_main_columns: usize,
    pub total_interaction_columns: usize,
}

impl std::fmt::Display for ProveProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let total = self.trace_gen
            + self.preprocess_commit
            + self.main_commit
            + self.interaction_gen
            + self.interaction_commit
            + self.stark_prove;
        writeln!(
            f,
            "  trace_gen:          {:>10.2?}  ({:.0}%)",
            self.trace_gen,
            pct(self.trace_gen, total)
        )?;
        writeln!(
            f,
            "  preprocess_commit:  {:>10.2?}  ({:.0}%)",
            self.preprocess_commit,
            pct(self.preprocess_commit, total)
        )?;
        writeln!(
            f,
            "  main_commit:        {:>10.2?}  ({:.0}%)",
            self.main_commit,
            pct(self.main_commit, total)
        )?;
        writeln!(
            f,
            "  interaction_gen:    {:>10.2?}  ({:.0}%)",
            self.interaction_gen,
            pct(self.interaction_gen, total)
        )?;
        writeln!(
            f,
            "  interaction_commit: {:>10.2?}  ({:.0}%)",
            self.interaction_commit,
            pct(self.interaction_commit, total)
        )?;
        writeln!(
            f,
            "  stark_prove (FRI):  {:>10.2?}  ({:.0}%)",
            self.stark_prove,
            pct(self.stark_prove, total)
        )?;
        writeln!(f, "  total:              {total:>10.2?}")?;
        writeln!(f, "  log_sizes: {:?}", self.log_sizes)?;
        writeln!(
            f,
            "  main_cols: {}, interaction_cols: {}",
            self.total_main_columns, self.total_interaction_columns
        )?;
        Ok(())
    }
}

fn pct(part: std::time::Duration, total: std::time::Duration) -> f64 {
    100.0 * part.as_secs_f64() / total.as_secs_f64()
}
