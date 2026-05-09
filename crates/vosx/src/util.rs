//! Small process / formatting / I/O helpers shared across
//! `main`, `commands/*`, `network`, `hyperspace`, and `query`.

use std::path::Path;

/// Print an error to stderr and exit with status 1. Used for
/// any unrecoverable manifest, I/O, or CLI usage error — the
/// CLI itself doesn't do error chaining, every fatal path
/// converges here.
pub fn die(msg: &str) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(1);
}

/// Initialize the global tracing subscriber from `RUST_LOG`,
/// defaulting to `warn`. Idempotent — multiple calls are no-ops.
pub fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .try_init();
}

/// Read a file or `die`. Common abbreviation across all the
/// load_* helpers below.
pub fn load_file(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| die(&format!("reading {}: {e}", path.display())))
}

/// Load a PVM blob from disk. `.pvm` files are passed through
/// untouched; anything else is treated as an ELF and run
/// through the JAM transpiler. `die` on any failure.
pub fn load_blob(path: &Path) -> Vec<u8> {
    let data = load_file(path);
    match path.extension().and_then(|e| e.to_str()) {
        Some("pvm") => data,
        _ => grey_transpiler::link_elf(&data)
            .unwrap_or_else(|e| die(&format!("transpiling '{}': {e:?}", path.display()))),
    }
}

/// Read every byte from stdin. Used by `vosx run --payload -`.
pub fn read_stdin() -> Vec<u8> {
    use std::io::Read;
    let mut buf = Vec::new();
    std::io::stdin()
        .read_to_end(&mut buf)
        .unwrap_or_else(|e| die(&format!("stdin: {e}")));
    buf
}

/// Decode a `0xHEX` or bare-hex string into bytes, or `None`
/// if any character isn't a hex digit / the length is odd.
pub fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    let hex = hex.trim_start_matches("0x");
    (hex.len() % 2 == 0)
        .then(|| {
            (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
                .collect::<Option<Vec<_>>>()
        })
        .flatten()
}

/// Lower-hex 32-byte → 64-char string. Used for printing
/// replication-ids / DAG roots in operator output.
pub fn hex32(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for b in bytes {
        use core::fmt::Write;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

/// Format a `provides = [...]` tag for `vosx list` output, or
/// the empty string when the actor advertises no roles.
pub fn format_provides(provides: &[String]) -> String {
    if provides.is_empty() {
        String::new()
    } else {
        format!(" provides={provides:?}")
    }
}

/// Final exit handler shared by `vosx run`, `node`, and `start`.
/// `panics > 0` exits with status 1 so CI catches actor panics;
/// otherwise a `done` line + status 0.
pub fn exit_with_status(panics: u32) {
    if panics > 0 {
        eprintln!("\nvosx: {panics} panic(s)");
        std::process::exit(1);
    }
    eprintln!("\nvosx: done");
}

/// Print the actor metadata baked into an ELF — the actor's
/// declared messages and constructor params, recovered from
/// the `.vos_meta` section. Used by `vosx list` to render the
/// space's API surface.
pub fn print_actor_meta(name: &str, path: &Path, role: &str) {
    let Ok(data) = std::fs::read(path) else {
        println!("  {name} ({role}) — not built");
        return;
    };
    let Some(meta) = vos::metadata::from_elf(&data) else {
        println!("  {name} ({role}) — no metadata");
        return;
    };
    println!("  {} ({role}: {})", name, meta.actor_name);
    if !meta.constructor.is_empty() {
        let params: Vec<_> = meta
            .constructor
            .iter()
            .map(|f| format!("{}: {}", f.name, f.ty.replace(' ', "")))
            .collect();
        println!("    new({})", params.join(", "));
    }
    for msg in &meta.messages {
        let kind = if msg.is_query { "query" } else { "cmd" };
        let params: Vec<_> = msg
            .fields
            .iter()
            .map(|f| format!("{}: {}", f.name, f.ty.replace(' ', "")))
            .collect();
        if params.is_empty() {
            println!("    {kind} {}()", msg.name);
        } else {
            println!("    {kind} {}({})", msg.name, params.join(", "));
        }
    }
}
