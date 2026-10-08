//! Link a RISC-V service ELF into a Gray Paper 0.8.0 service code blob:
//! `E(↕metadata) ‖ standard program`.

use std::process::ExitCode;

/// Gray Paper natural encoding (appendix C).
fn encode_natural(value: u64, out: &mut Vec<u8>) {
    for extra in 0..8u32 {
        if value < 1u64 << (7 * (extra + 1)) {
            let high = (value >> (8 * extra)) as u8;
            out.push((0xffu16 << (8 - extra)) as u8 | high);
            out.extend_from_slice(&value.to_le_bytes()[..extra as usize]);
            return;
        }
    }
    out.push(0xff);
    out.extend_from_slice(&value.to_le_bytes());
}

fn encode_bytes(bytes: &[u8], out: &mut Vec<u8>) {
    encode_natural(bytes.len() as u64, out);
    out.extend_from_slice(bytes);
}

/// Conventional metadata, as shipped with PolkaJam's own services:
/// version 0, name, version, license, then a sequence of authors.
fn metadata(name: &str) -> Vec<u8> {
    let mut out = vec![0u8];
    encode_bytes(name.as_bytes(), &mut out);
    encode_bytes(b"0.1.0", &mut out);
    encode_bytes(b"AGPL-3.0-or-later", &mut out);
    encode_natural(1, &mut out);
    encode_bytes(b"VOS spike", &mut out);
    out
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let [_, elf_path, out_path, name] = args.as_slice() else {
        eprintln!("usage: sj-tool <service.elf> <out.jam> <name>");
        return ExitCode::FAILURE;
    };
    let elf = std::fs::read(elf_path).expect("read ELF");
    let program = match vos_pvm_compiler::link_elf_spi(&elf) {
        Ok(program) => program,
        Err(error) => {
            eprintln!("link failed: {error}");
            return ExitCode::FAILURE;
        }
    };
    let mut blob = Vec::new();
    encode_bytes(&metadata(name), &mut blob);
    blob.extend_from_slice(&program);
    std::fs::write(out_path, &blob).expect("write service blob");
    println!(
        "{out_path}: {} bytes (program {} bytes)",
        blob.len(),
        program.len()
    );
    ExitCode::SUCCESS
}
