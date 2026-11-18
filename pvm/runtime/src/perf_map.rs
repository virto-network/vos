//! Names for the code the recompiler compiles, in perf's map for JIT code
//! (`/tmp/perf-<pid>.map`: one `<start> <size> <name>` line a region, in
//! hex without `0x`), so a profile attributes guest time to the programs
//! it ran. Off unless a binary turns it on at start ([`enable`]); then each
//! `recompiler::compile_code` appends its lines, and programs are compiled
//! once each, as their preparation is cached. (The older inline compile of
//! `RecompiledPvm::new` names nothing.)
//!
//! A program whose functions were [`register`]ed is named a line a
//! function, with its compiled entry (`<program>:entry`) and its exit
//! sequences and stubs (`<program>:exits`) apart; any other, a line for the
//! whole program.
//!
//! Lines are only appended. A program whose code is unmapped (an evicted
//! one) and whose addresses a later compile reuses leaves an overlapping,
//! stale line behind: fine for a profile of a steady state.

use std::collections::HashMap;
use std::io::Write;
use std::sync::{Mutex, OnceLock, PoisonError};

/// Where lines go, once turned on.
static MAP: OnceLock<Mutex<Box<dyn Write + Send>>> = OnceLock::new();

/// Each registered program's functions, by its code's hash.
static FUNCTIONS: OnceLock<Mutex<Registered>> = OnceLock::new();

/// A program's functions: each one's first PVM instruction, and its name.
type Functions = Vec<(u32, String)>;

type Registered = HashMap<[u8; 32], Functions>;

/// Name compiled code in `/tmp/perf-<pid>.map` from now on: what perf reads
/// for this process. The file is emptied first, as a process that had this
/// pid before may have left one, and is not opened through a symbolic link.
pub fn enable() -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let path = format!("/tmp/perf-{}.map", std::process::id());
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    enable_into(Box::new(file));
    Ok(())
}

/// Name compiled code into `out` from now on. Only the first sink a process
/// is given is kept.
pub fn enable_into(out: Box<dyn Write + Send>) {
    let _ = MAP.set(Mutex::new(out));
}

/// Whether compiled code is named.
pub fn enabled() -> bool {
    MAP.get().is_some()
}

/// Name the `len` bytes of code at `start` `name`, if naming is on. A line
/// that cannot be written is dropped: the map is a debugging aid.
pub fn name(start: *const u8, len: usize, name: &str) {
    if let Some(map) = MAP.get() {
        let mut out = map.lock().unwrap_or_else(PoisonError::into_inner);
        let _ = write_line(&mut **out, start as usize, len, name);
    }
}

/// Name `code`'s functions when it is compiled: each one's first PVM
/// instruction, and its name.
pub fn register(code: &[u8], functions: Functions) {
    FUNCTIONS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(crate::precompile::blake2b_256(code), functions);
}

/// Name `code`, compiled to the `len` bytes at `start`: a line a function if
/// its functions were registered, else one line. `dispatch` maps each PVM
/// pc to its native offset, `panic` for a pc with no entry of its own.
pub fn name_program(code: &[u8], start: *const u8, len: usize, dispatch: &[i32], panic: i32) {
    let program = program_name(code);
    let functions = FUNCTIONS.get().and_then(|registered| {
        registered
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&crate::precompile::blake2b_256(code))
            .cloned()
    });
    match functions {
        Some(functions) => {
            for (from, to, function) in regions(&program, len, dispatch, panic, &functions) {
                name(start.wrapping_add(from), to - from, &function);
            }
        }
        None => name(start, len, &program),
    }
}

/// The native regions of a program compiled to `len` bytes, named: its
/// entry, each function from its first instruction's offset to the next
/// function's, and its exits from the end sentinel's offset to the end.
/// A function's first instruction is a basic-block start, which `dispatch`
/// maps; one that maps to `panic` (never a target) is named from the next
/// pc that does, and one with no own region goes into the one before.
pub fn regions(
    program: &str,
    len: usize,
    dispatch: &[i32],
    panic: i32,
    functions: &[(u32, String)],
) -> Vec<(usize, usize, String)> {
    let mapped = |pc: usize| {
        dispatch
            .get(pc..)?
            .iter()
            .find(|offset| **offset != panic)
            .map(|offset| *offset as usize)
    };
    // The end sentinel's entry: the body ends there, the exits begin.
    let body_end = dispatch
        .last()
        .filter(|offset| **offset != panic)
        .map_or(len, |offset| *offset as usize)
        .min(len);
    let mut starts: Vec<(usize, u32, &str)> = functions
        .iter()
        .filter_map(|(pc, name)| Some((mapped(*pc as usize)?, *pc, name.as_str())))
        .filter(|(offset, _, _)| *offset < body_end)
        .collect();
    // Two at one offset: an unmapped entry fell forward onto the next
    // function's, which is the offset's owner, the higher pc.
    starts.sort_by_key(|(offset, pc, _)| (*offset, std::cmp::Reverse(*pc)));
    starts.dedup_by_key(|(offset, _, _)| *offset);
    let starts: Vec<(usize, &str)> = starts
        .into_iter()
        .map(|(offset, _, name)| (offset, name))
        .collect();
    let mut regions = Vec::new();
    let first = starts.first().map_or(body_end, |(offset, _)| *offset);
    if first > 0 {
        regions.push((0, first, format!("{program}:entry")));
    }
    for (index, (from, name)) in starts.iter().enumerate() {
        let to = starts.get(index + 1).map_or(body_end, |(next, _)| *next);
        regions.push((*from, to, name.to_string()));
    }
    if body_end < len {
        regions.push((body_end, len, format!("{program}:exits")));
    }
    regions
}

/// A program's name in the map: the first 8 bytes of its code's hash, and
/// its code's length.
pub fn program_name(code: &[u8]) -> String {
    let hash = crate::precompile::blake2b_256(code);
    let hex: String = hash[..8].iter().map(|byte| format!("{byte:02x}")).collect();
    format!("pvm:{hex}:{}", code.len())
}

/// One line of the map, written whole in one write.
pub fn write_line(
    out: &mut dyn Write,
    start: usize,
    len: usize,
    name: &str,
) -> std::io::Result<()> {
    out.write_all(format!("{start:x} {len:x} {name}\n").as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_is_perf_s_format() {
        let mut out = Vec::new();
        write_line(
            &mut out,
            0x7f00_1234_5000,
            0x1a2b,
            "pvm:0011223344556677:4096",
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "7f0012345000 1a2b pvm:0011223344556677:4096\n"
        );
    }

    /// Functions take the native span from their first instruction's entry
    /// to the next function's; the program's entry and exits are apart,
    /// and a function whose entry is unmapped starts at the next mapped pc.
    #[test]
    fn functions_cover_the_body_in_order() {
        const PANIC: i32 = 900;
        // pcs 0..10 and the end sentinel at 10.
        let mut dispatch = vec![PANIC; 11];
        dispatch[0] = 0;
        dispatch[2] = 40;
        dispatch[5] = 120;
        dispatch[8] = 300;
        dispatch[10] = 800;
        let functions = vec![
            (5, "second".to_string()),
            (2, "first".to_string()),
            (4, "stray".to_string()), // unmapped: falls onto pc 5, which owns it
            (7, "third".to_string()), // unmapped: from pc 8
            (9, "dead".to_string()),  // unmapped to the end: none
        ];
        let regions = regions("pvm:p:10", 1000, &dispatch, PANIC, &functions);
        assert_eq!(
            regions,
            vec![
                (0, 40, "pvm:p:10:entry".to_string()),
                (40, 120, "first".to_string()),
                (120, 300, "second".to_string()),
                (300, 800, "third".to_string()),
                (800, 1000, "pvm:p:10:exits".to_string()),
            ]
        );
        // Every region inside the program, in order, without overlap.
        for pair in regions.windows(2) {
            assert_eq!(pair[0].1, pair[1].0);
        }
    }

    #[test]
    fn a_program_is_named_by_its_code() {
        let name = program_name(&[1, 2, 3]);
        assert!(name.starts_with("pvm:"), "{name}");
        assert!(name.ends_with(":3"), "{name}");
        assert_eq!(name.len(), "pvm:".len() + 16 + ":3".len());
        assert_ne!(name, program_name(&[1, 2, 4]));
    }
}
