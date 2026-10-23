//! The run's record: each verdict and measurement, printed and written to
//! `record.txt` in the run's directory as it is noted.

use std::io::Write;
use std::path::Path;

pub struct Record(std::fs::File);

impl Record {
    pub fn new(run: &Path) -> Self {
        Self(std::fs::File::create(run.join("record.txt")).expect("the record's file"))
    }

    pub fn note(&mut self, line: impl AsRef<str>) {
        let line = line.as_ref();
        println!("{line}");
        writeln!(self.0, "{line}").expect("the record written");
    }
}
