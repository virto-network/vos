//! `cargo run -p vos-light --features release --example devices -- ELF DIR
//! NAME…`: the release artifacts of the device kernels `NAME…` of the
//! package whose ELF is `ELF`, each written to `DIR/NAME.device` in its
//! encoding ([`vos_light::release::Release`]): what an app embeds for the
//! stock kernels, `auth` and `owner` from the credential actor's ELF
//! (`just build-programs`).

use vos_wire::Encode;

fn main() -> Result<(), String> {
    let mut arguments = std::env::args().skip(1);
    let usage = "devices ELF DIR NAME…";
    let elf = arguments.next().ok_or(usage)?;
    let dir = std::path::PathBuf::from(arguments.next().ok_or(usage)?);
    let elf = std::fs::read(&elf).map_err(|error| format!("{elf}: {error}"))?;
    let names: Vec<String> = arguments.collect();
    if names.is_empty() {
        return Err(usage.into());
    }
    for name in names {
        let device = vos_light::release::device(&elf, &name)?;
        let path = dir.join(format!("{name}.device"));
        std::fs::write(&path, device.encode())
            .map_err(|error| format!("{}: {error}", path.display()))?;
        println!("{}: program {}", path.display(), hex(&device.id));
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
