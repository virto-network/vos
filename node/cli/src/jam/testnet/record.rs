//! The run's record: its lines, each package's attempts, and the times
//! they name.

use std::fmt::Write as _;

use vos_jam::chain::slot_of;
use vos_jam::{Attempt, Fate};

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
        self.note(match retried.is_empty() {
            true => format!(
                "every one of the {} packages landed at its first attempt",
                self.attempts.len()
            ),
            false => format!(
                "packages that took more than one attempt: {}",
                retried.join(", ")
            ),
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
