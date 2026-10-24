//! The run's record: its lines, each package's attempts, and the times
//! they name.

use std::fmt::Write as _;

use vos_jam::{Attempt, Fate, Taken};
use vos_wire::package::slot_of;

use super::Testnet;

impl Testnet {
    /// A line of the record, printed as it is made.
    pub(super) fn note(&mut self, line: impl AsRef<str>) {
        println!("{}", line.as_ref());
        writeln!(self.record, "{}", line.as_ref()).expect("a string takes it");
    }

    /// Every attempt, with its fate and what `jamt` said of it.
    pub(super) fn note_attempts(&mut self, attempts: &[Attempt]) {
        for (at, attempt) in attempts.iter().enumerate() {
            let fate = match attempt.fate {
                Fate::Landed => "landed",
                Fate::Refused => {
                    "refused: the chain's root did not move before its window closed (see the testnet's errors)"
                }
                Fate::Overtaken => "overtaken: another package landed first, and was taken",
                Fate::Superseded => {
                    "superseded: an earlier attempt's package landed late, and was taken"
                }
            };
            self.note(format!(
                "  attempt {} at slot {} ({}): {fate}; jamt: {}",
                at + 1,
                slot_of(attempt.time),
                utc(attempt.time),
                attempt.submitted
            ));
        }
    }

    /// What `taken`'s package did, of `offered` inputs: the roots
    /// before and after it, its inputs and witness, what it left out,
    /// imported and exported, its work result, and its refine's gas,
    /// `gas_used` on the JAM-only host against what the builder gave.
    pub(super) fn note_package(
        &mut self,
        taken: &Taken,
        offered: usize,
        (before, after): ([u8; 32], [u8; 32]),
        gas_used: u64,
    ) {
        let Taken {
            prepared,
            encoded,
            exports,
            ..
        } = taken;
        let witness = &prepared.package.witness;
        self.note(format!(
            "  root {} -> {}",
            hex::encode(before),
            hex::encode(after)
        ));
        self.note(format!(
            "  {} of {offered} inputs; witness {} keys, {} ranges of {} rows; payload {} bytes",
            prepared.package.batch.inputs.len(),
            witness.keys.len(),
            witness.ranges.len(),
            witness
                .ranges
                .iter()
                .map(|range| range.rows.len())
                .sum::<usize>(),
            prepared.payload.len(),
        ));
        if !prepared.skipped.is_empty() {
            self.note(format!(
                "  left out, their pages gone from DA: workflows {:?}",
                prepared.skipped
            ));
        }
        self.note(format!(
            "  imports {}, exports {} ({} pages) at segment root {}",
            prepared.segments.len(),
            exports.segments,
            exports.pages,
            hex::encode(exports.root),
        ));
        self.note(format!(
            "  work result {} bytes, read back from DA: the one simulated, and the VOS node's, byte for byte",
            encoded.len()
        ));
        let simulations = match prepared.simulations {
            1 => "1 simulation".to_string(),
            count => format!("{count} simulations"),
        };
        self.note(format!(
            "  refine {gas_used} gas, measured on our JAM-only host (PolkaJam reports none); the builder gave {}: the batch's budget {}, {} for the package's own work, after {simulations}",
            prepared.gas, prepared.package.batch.budget, prepared.own,
        ));
    }

    /// Whether each package, the first among them, landed first time.
    pub(super) fn attempts_summary(&mut self) {
        let first = self.attempts.first().map(|(_, tries)| *tries);
        self.note(match first {
            Some(1) => "the first package landed at its first attempt".to_string(),
            Some(tries) => format!("the first package landed at attempt {tries}"),
            None => "no package landed".to_string(),
        });
        let retried: Vec<String> = self
            .attempts
            .iter()
            .filter(|(_, tries)| *tries > 1)
            .map(|(name, tries)| format!("{name} ({tries})"))
            .collect();
        self.note(if retried.is_empty() {
            format!(
                "every one of the {} packages landed at its first attempt",
                self.attempts.len()
            )
        } else {
            format!(
                "packages that took more than one attempt: {}",
                retried.join(", ")
            )
        });
    }
}

/// A time, in milliseconds since the Unix epoch, as its time of day in UTC.
fn utc(time: u64) -> String {
    let seconds = time / 1000 % 86_400;
    format!(
        "{:02}:{:02}:{:02}.{:03} UTC",
        seconds / 3600,
        seconds / 60 % 60,
        seconds % 60,
        time % 1000
    )
}
