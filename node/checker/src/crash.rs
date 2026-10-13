//! The crash tests' rounds, on one directory: the test binary runs itself
//! as a child that writes in a loop and reports what it made durable,
//! kills it at a random moment, tears a tail of what it wrote as a power
//! loss could, and checks what reopens. A kill leaves the page cache
//! intact, so every write the child reported survives but for a tear.

use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime};

use crate::Random;

/// How a crash test's rounds go.
pub struct Rounds {
    /// The variable that makes the test binary the writer, naming its
    /// directory.
    pub writer: &'static str,
    pub rounds: usize,
    /// Rounds from this one on tear before reopening.
    pub torn_from: usize,
    /// What the writer prints before each index it reports.
    pub report: &'static str,
    /// How many reports are read before the kill: fewer than this, an
    /// exclusive bound, which must not be zero.
    pub reports: u64,
    /// How long after them the kill comes: less than this, an exclusive
    /// bound of a microsecond or more.
    pub kill_within: Duration,
}

/// A round, its writer killed, for the test to check.
pub struct Round<'a> {
    pub number: usize,
    pub dir: &'a Path,
    /// The last index the writer reported, if it reported any.
    pub reported: Option<u64>,
    /// Whether the round tore before reopening, as rounds from
    /// [`Rounds::torn_from`] on do: a tear may reach no data.
    pub torn: bool,
}

impl Rounds {
    /// The test binary's `main`: `writer` in the child, writing in its
    /// directory until killed; otherwise the rounds, on a seed of the
    /// clock, `tear` tearing the directory of a torn round (whether it
    /// tore any data) and `check` checking each round. Some torn round
    /// must tear data.
    pub fn run(
        &self,
        writer: impl FnOnce(&Path),
        mut tear: impl FnMut(usize, &Path, &mut Random) -> bool,
        mut check: impl FnMut(Round),
    ) {
        if let Ok(dir) = std::env::var(self.writer) {
            writer(Path::new(&dir));
            unreachable!("the writer writes until it is killed");
        }
        assert!(self.reports > 0, "some reports may be read");
        assert!(
            self.kill_within >= Duration::from_micros(1),
            "the kill may come a moment after them"
        );
        let dir = tempfile::tempdir().unwrap();
        let seed = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let mut random = Random(seed | 1);
        let mut tore = 0;
        for number in 0..self.rounds {
            let mut child = Command::new(std::env::current_exe().unwrap())
                .env(self.writer, dir.path())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
            let index = |line: String| -> u64 {
                line.strip_prefix(self.report)
                    .and_then(|index| index.parse().ok())
                    .unwrap_or_else(|| panic!("a report: {line}"))
            };
            let mut reported = None;
            for _ in 0..random.below(self.reports) {
                reported = Some(index(lines.next().unwrap().unwrap()));
            }
            let within = self.kill_within.as_micros() as u64;
            std::thread::sleep(Duration::from_micros(random.below(within)));
            child.kill().unwrap();
            child.wait().unwrap();
            // Lines the child printed before it died were durable too.
            for line in lines {
                reported = Some(index(line.unwrap()));
            }
            let torn = number >= self.torn_from;
            if torn && tear(number, dir.path(), &mut random) {
                tore += 1;
            }
            check(Round {
                number,
                dir: dir.path(),
                reported,
                torn,
            });
        }
        assert!(tore > 0, "no torn round reached data");
    }
}

/// Tear the newest file under `dir`, numbered by its name, with
/// `extension` if given or none: truncate its data by up to `most` bytes,
/// or zero up to its last `most` bytes of data. Whether it tore any.
/// Journals are preallocated, so the data ends before the file does.
pub fn tear(
    dir: &Path,
    extension: Option<&str>,
    most: u64,
    truncate: bool,
    random: &mut Random,
) -> bool {
    let mut files = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(path) = pending.pop() {
        for entry in std::fs::read_dir(&path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            let matches = match extension {
                Some(extension) => path.extension().is_some_and(|found| found == extension),
                None => path.extension().is_none(),
            };
            let Some(id) = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .and_then(|stem| stem.parse::<u64>().ok())
            else {
                continue;
            };
            if matches {
                files.push((id, path));
            }
        }
    }
    let Some((_, file)) = files.into_iter().max() else {
        return false;
    };
    let mut bytes = std::fs::read(&file).unwrap();
    let end = bytes
        .iter()
        .rposition(|&byte| byte != 0)
        .map_or(0, |at| at + 1);
    if end == 0 {
        return false;
    }
    let reach = 1 + random.below(most.min(end as u64)) as usize;
    if truncate {
        let handle = std::fs::OpenOptions::new().write(true).open(&file).unwrap();
        handle.set_len((end - reach) as u64).unwrap();
    } else {
        bytes[end - reach..end].fill(0);
        std::fs::write(&file, bytes).unwrap();
    }
    true
}
