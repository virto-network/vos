//! Compiled code named in perf's map: this test binary turns the map on for
//! its whole process, so it holds this test alone.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::io::Write;
use std::sync::{Arc, Mutex};

use vos_pvm::perf_map;

/// A sink the test reads back.
#[derive(Clone, Default)]
struct Lines(Arc<Mutex<Vec<u8>>>);

impl Write for Lines {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn a_compile_names_the_region_its_code_occupies() {
    let lines = Lines::default();
    perf_map::enable_into(Box::new(lines.clone()));
    assert!(perf_map::enabled());
    // Two traps and an `ecalli`: any code will do.
    let code = vec![0u8, 10, 42, 0];
    let bitmask = vec![1u8, 1, 0, 1];
    let compiled = vos_pvm::recompiler::compile_code(&code, &bitmask, &[]).unwrap();
    let start = compiled.native_code.ptr as usize;
    let len = compiled.native_code.len;
    let written = String::from_utf8(lines.0.lock().unwrap().clone()).unwrap();
    let expected = format!("{start:x} {len:x} {}\n", perf_map::program_name(&code));
    assert!(
        written.contains(&expected),
        "{written:?} lacks {expected:?}"
    );
}
