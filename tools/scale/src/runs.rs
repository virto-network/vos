//! A run's directory on the coordinator: one a run, named by its start
//! in UTC and an optional label, holding its inventory, the hosts' facts,
//! the samples, the drivers' records and the report. `current` names the
//! run the next command adds to.

use std::path::PathBuf;

use crate::inventory::Inventory;

pub struct Run {
    pub id: String,
    pub dir: PathBuf,
}

/// `seconds` since the Unix epoch as `YYYYMMDDTHHMMSSZ`.
pub fn stamp(seconds: u64) -> String {
    let (days, rest) = (seconds / 86_400, seconds % 86_400);
    // Days to a civil date, after Howard Hinnant's `civil_from_days`.
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
        rest / 3_600,
        rest / 60 % 60,
        rest % 60
    )
}

impl Run {
    /// A new run, which becomes the current one.
    pub fn new(inventory: &Inventory, label: Option<&str>) -> Result<Self, String> {
        let mut id = stamp(crate::now_ms() / 1_000);
        if let Some(label) = label {
            if !label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
            {
                return Err(format!(
                    "a label of letters, digits, '-', '_' and '.': {label}"
                ));
            }
            id = format!("{id}-{label}");
        }
        let runs = inventory.runs();
        let dir = runs.join(&id);
        std::fs::create_dir_all(&dir).map_err(|error| format!("{}: {error}", dir.display()))?;
        std::fs::copy(&inventory.path, dir.join("inventory.toml"))
            .map_err(|error| format!("{}: {error}", inventory.path.display()))?;
        std::fs::write(runs.join("current"), &id).map_err(|error| error.to_string())?;
        Ok(Self { id, dir })
    }

    /// The run named `id`, or the current one.
    pub fn open(inventory: &Inventory, id: Option<&str>) -> Result<Self, String> {
        let runs = inventory.runs();
        let id = match id {
            Some(id) => id.to_string(),
            None => std::fs::read_to_string(runs.join("current"))
                .map_err(|_| "no current run: `up` starts one".to_string())?
                .trim()
                .to_string(),
        };
        let dir = runs.join(&id);
        if !dir.is_dir() {
            return Err(format!("no run {}", dir.display()));
        }
        Ok(Self { id, dir })
    }

    pub fn file(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }
}

#[cfg(test)]
mod tests {
    use super::stamp;

    #[test]
    fn a_stamp_is_the_utc_time() {
        assert_eq!(stamp(0), "19700101T000000Z");
        assert_eq!(stamp(1_761_386_096), "20251025T095456Z");
        assert_eq!(stamp(951_782_400), "20000229T000000Z");
    }
}
