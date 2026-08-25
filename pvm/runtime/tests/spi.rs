//! SPI parser conformance against a real GP service preimage.
//!
//! The `gp072_*` accumulate vectors store service code as a standard-program
//! blob (metadata prefix + GP memory layout). This test pulls the real
//! `test-service` preimage out of a shared vector and asserts the parser
//! recovers exactly the fields an independent byte-level decode found.

use vos_pvm::spi::parse_standard_program;

/// Extract the first service preimage blob from a gp072 accumulate input.
fn service_preimage() -> Vec<u8> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/",
        "accumulate_ready_queued_reports-1.input.gp072_tiny.json"
    );
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let json: serde_json::Value = serde_json::from_str(&text).expect("parse vector json");
    let hex = json["pre_state"]["accounts"][0]["data"]["preimage_blobs"][0]["blob"]
        .as_str()
        .expect("preimage blob hex");
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn parses_real_service_preimage() {
    let blob = service_preimage();
    let prog = parse_standard_program(&blob).expect("standard program parses");

    // Values independently decoded from the raw bytes:
    // E₃|o|=7360, E₃|w|=20, E₂z=2, E₃s=8192; code: jump_len=182, code_len=24792.
    assert_eq!(prog.ro_data.len(), 7360, "read-only data size");
    assert_eq!(prog.rw_data.len(), 20, "read-write data size");
    assert_eq!(prog.heap_pages, 2, "heap pages");
    assert_eq!(prog.stack_size, 8192, "stack size");
    assert_eq!(prog.code.jump_table.len(), 182, "jump table entries");
    assert_eq!(prog.code.code.len(), 24792, "code length");
    assert_eq!(
        prog.code.bitmask.len(),
        24792,
        "bitmask covers every code byte"
    );

    // The layout must fit the 32-bit address space with default (empty) args.
    let layout = prog.layout(&[]).expect("layout fits");
    assert_eq!(layout.ro.base, 1 << 16);
    assert!(layout.rw.base > layout.ro.base);
    assert_eq!(layout.registers[0], vos_pvm::PVM_HALT_ADDR);
}

/// The real service can be *started* under the kernel-free refine harness:
/// it runs deterministically up to its first hostcall (`ecalli 1`), which
/// surfaces as an undispatched `HostCall` exit for the embedder to handle.
#[test]
fn refine_harness_starts_real_service_preimage() {
    let blob = service_preimage();
    let inv = vos_pvm::refine::execute(&blob, &[], 10_000_000).expect("service preimage loads");
    assert_eq!(
        inv.exit,
        vos_pvm::ExitReason::HostCall(1),
        "the service's first act at the refine entry is hostcall 1"
    );
    // ro (2) + rw+heap (3) + stack (2) pages charge init gas; the prologue
    // consumed execution gas on top of that.
    let init_gas = 7 * vos_pvm::GAS_PER_PAGE;
    assert!(
        inv.gas_used > init_gas,
        "gas accounting: init charge plus execution (used {})",
        inv.gas_used
    );
    assert_eq!(inv.output(), None, "no output without a halt");
}

/// The flat and sparse memory representations are indistinguishable on the
/// real gp072 service: same first-hostcall exit, the same pinned gas
/// (10 702), the same register file, and the same logical memory around
/// every mapped region. This is the shape a 32-bit embedder (which
/// `MemoryModel::Auto` puts on the sparse path) executes.
#[test]
fn refine_flat_and_sparse_agree_on_real_service_preimage() {
    use vos_pvm::refine::MemoryModel;

    let blob = service_preimage();
    let f = vos_pvm::refine::execute_with(&blob, &[], 10_000_000, MemoryModel::Flat).expect("flat");
    let s =
        vos_pvm::refine::execute_with(&blob, &[], 10_000_000, MemoryModel::Sparse).expect("sparse");

    assert_eq!(f.exit, vos_pvm::ExitReason::HostCall(1));
    assert_eq!(s.exit, f.exit, "exit agrees");
    assert_eq!(f.gas_used, 10_702, "pinned gas for the service prologue");
    assert_eq!(s.gas_used, f.gas_used, "gas agrees");
    assert_eq!(s.registers, f.registers, "registers agree");
    assert_eq!(s.memory().span(), f.memory().span(), "spans agree");

    // Compare the logical image over every mapped region plus a page of
    // surrounding gap, via reads (representation-independent).
    let prog = parse_standard_program(&blob).expect("parses");
    let layout = prog.layout(&[]).expect("lays out");
    let span = f.memory().span();
    let page = 4096u64;
    for r in [layout.ro, layout.rw, layout.stack, layout.args] {
        if r.size == 0 {
            continue;
        }
        let start = r.base.saturating_sub(page);
        let end = (r.base + r.size + page).min(span);
        let mut bf = vec![0u8; (end - start) as usize];
        let mut bs = bf.clone();
        f.memory().read_bytes(start as u32, &mut bf);
        s.memory().read_bytes(start as u32, &mut bs);
        assert_eq!(bf, bs, "logical image diverges near {start:#x}");
    }
}
