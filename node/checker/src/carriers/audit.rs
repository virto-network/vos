//! The carriers of a run and the search: every needle of a kind a carrier's
//! reach admits, in one Aho–Corasick pass over each carrier.

use std::fmt;

use super::{Kind, Needles, Reach};

/// A carrier's bytes.
#[derive(Clone, Debug)]
pub struct Carrier {
    pub name: String,
    pub reach: Reach,
    pub bytes: Vec<u8>,
}

/// A needle found in a carrier.
#[derive(Clone, Debug)]
pub struct Finding {
    pub kind: Kind,
    pub needle: String,
    pub carrier: String,
    pub at: usize,
    /// The form found: 0 its bytes, then hex, `Debug`, or a number's forms.
    pub form: usize,
    /// The carrier's bytes around it, as text.
    pub context: String,
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} {} in {} at byte {} (form {}): {:?}",
            self.kind, self.needle, self.carrier, self.at, self.form, self.context
        )
    }
}

/// The carriers of a run, searched for its needles.
#[derive(Default)]
pub struct Audit {
    pub carriers: Vec<Carrier>,
    pub needles: Needles,
}

impl Audit {
    /// Add a carrier's bytes; an empty one is kept, so the report counts
    /// it.
    pub fn carrier(&mut self, name: impl Into<String>, reach: Reach, bytes: Vec<u8>) {
        self.carriers.push(Carrier {
            name: name.into(),
            reach,
            bytes,
        });
    }

    /// Every needle found in a carrier its kind reaches: the first place
    /// of each, in one pass over each carrier.
    pub fn findings(&self) -> Vec<Finding> {
        let mut findings = Vec::new();
        for reach in [Reach::Leaves, Reach::Recorded, Reach::Role] {
            let mut patterns: Vec<&[u8]> = Vec::new();
            let mut of: Vec<(usize, usize)> = Vec::new();
            for (index, needle) in self.needles.0.iter().enumerate() {
                if !needle.reaches(reach) {
                    continue;
                }
                for (form, bytes) in needle.forms(reach).enumerate() {
                    patterns.push(bytes);
                    of.push((index, form));
                }
            }
            if patterns.is_empty() {
                continue;
            }
            let automaton = aho_corasick::AhoCorasick::new(&patterns).expect("the needles");
            for carrier in self
                .carriers
                .iter()
                .filter(|carrier| carrier.reach == reach)
            {
                let mut found = vec![false; self.needles.0.len()];
                for hit in automaton.find_overlapping_iter(&carrier.bytes) {
                    let (index, form) = of[hit.pattern().as_usize()];
                    if found[index] || !whole(&carrier.bytes, hit.start(), hit.len()) {
                        continue;
                    }
                    found[index] = true;
                    let needle = &self.needles.0[index];
                    findings.push(Finding {
                        kind: needle.kind,
                        needle: needle.name.clone(),
                        carrier: carrier.name.clone(),
                        at: hit.start(),
                        form,
                        context: context(&carrier.bytes, hit.start(), hit.end()),
                    });
                }
            }
        }
        findings
    }

    /// What was searched: each carrier's reach and size, and the needles
    /// by kind.
    pub fn summary(&self) -> String {
        let mut out = String::new();
        for carrier in &self.carriers {
            out += &format!(
                "{:?} {}: {} bytes\n",
                carrier.reach,
                carrier.name,
                carrier.bytes.len()
            );
        }
        let mut kinds: Vec<Kind> = self.needles.0.iter().map(|needle| needle.kind).collect();
        kinds.sort();
        kinds.dedup();
        for kind in kinds {
            let count = self
                .needles
                .0
                .iter()
                .filter(|needle| needle.kind == kind)
                .count();
            out += &format!("{kind:?}: {count} needles\n");
        }
        out
    }

    /// Fails unless the run made needles of each of `kinds`, and each
    /// needle, put in a carrier that leaves, is found there: a run whose
    /// needles could not be found would pass the audit for nothing.
    pub fn assert_searchable(&self, kinds: &[Kind]) {
        for kind in kinds {
            assert!(
                self.needles.0.iter().any(|needle| needle.kind == *kind),
                "no {kind:?} needle"
            );
        }
        for needle in &self.needles.0 {
            let form = needle.forms(Reach::Leaves).next().expect("a form");
            let mut planted = Audit::default();
            planted.carrier("planted", Reach::Leaves, [b" ", &form[..], b" "].concat());
            planted.needles.0.push(needle.clone());
            assert_eq!(planted.findings().len(), 1, "{} is not found", needle.name);
        }
    }

    /// Fails unless `canary`, put through one of the run's capture paths,
    /// is in a carrier whose name starts with `carrier`: a capture that
    /// missed its path would pass the audit for nothing.
    pub fn assert_captured(&self, carrier: &str, canary: &[u8]) {
        let held = self.carriers.iter().any(|held| {
            held.name.starts_with(carrier)
                && held
                    .bytes
                    .windows(canary.len())
                    .any(|window| window == canary)
        });
        assert!(
            held,
            "the canary {:?} is in no carrier named {carrier:?}",
            String::from_utf8_lossy(canary)
        );
    }

    /// Fails, naming each finding, unless no carrier holds a needle.
    pub fn assert_clean(&self) {
        let findings = self.findings();
        assert!(
            findings.is_empty(),
            "{} needles found:\n{}",
            findings.len(),
            findings
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
}

/// The bytes of a line's length around `start..end`, as text.
fn context(bytes: &[u8], start: usize, end: usize) -> String {
    let from = start.saturating_sub(160);
    let to = (end + 160).min(bytes.len());
    String::from_utf8_lossy(&bytes[from..to]).into_owned()
}

/// Whether the match of `len` bytes at `at` is a whole run of digits in
/// `haystack`, or no run of digits at all.
fn whole(haystack: &[u8], at: usize, len: usize) -> bool {
    let digits = haystack[at..at + len].iter().all(u8::is_ascii_digit);
    !digits
        || (haystack
            .get(at.wrapping_sub(1))
            .is_none_or(|b| !b.is_ascii_digit())
            && haystack.get(at + len).is_none_or(|b| !b.is_ascii_digit()))
}
