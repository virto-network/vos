set shell := ["nu", "-c"]

# The pinning tests write their pins under `VOS_PINS=write` and hold them
# otherwise. No recipe inherits it: the recipes that write pins (`repin`,
# `repin-proof`, `fixtures`, each in no tier) set it on their own lines, so
# a `VOS_PINS=write` left in the caller's environment cannot turn a gate's
# check into a rewrite (`just check-tiers` holds the tiers to that).
unexport VOS_PINS

default:
    @just --list

# The gates are five tiers, each holding the one before it:
#
#   check ⊆ gate ⊆ ci ⊆ ci-full ⊆ slice-gate
#
# Each named for when it runs, by what it adds and the pins it holds.
# There is no hosted CI: "ci" names the pre-push hook's recipe.
# - `check`, after every edit (minutes, warm): formatting, the gates' own
#   tripwire, the workspace's lints and the fast tests. Holds the final
#   verifier's layout constants (format 39's).
# - `gate`, before each commit: `check`, the heavy test
#   targets (`tools/gates/heavy.toml`), the docs' tripwire, deny, the
#   builds without std, every guest and its blob, the leak checks, the
#   verifier kit and the fuzz corpora replayed and their reach. Holds
#   `blobs.lock`, the wrap's preprocessed root, the compiler's leaf tables
#   and the kit's lock.
# - `ci`, before a push (the pre-push hook, `just install-hooks`): `gate`
#   and every feature set's lints, the JAR check, the PVM vectors, the
#   bench's cross-host checks and the prover's library tests. Holds the
#   formats' bit counts (`COUNTS`).
# - `ci-full`, by hand before a release candidate (under a 12 GiB memory
#   cap): `ci` and the prover suites (`test-proof`: the forgery and
#   soundness gates, the leakage tests at a medium N), the bench's proving
#   tests and the fuzz targets a minute each. Holds `H_FOLD` and the
#   golden fixtures.
# - `slice-gate`, the full gate, by hand before a release: `ci-full` with
#   the leakage tests at their full N and the fuzz targets five minutes
#   each.
# A suite belongs to the lowest tier that can afford it; `just check-tiers`
# holds the recipes to that. `just test-changed` runs the tests a change
# touches. Outside every tier, on purpose: a release of the verifier kit
# (`vendor-verifier`).

# The fast suites' crates, which `check` and `gate` run.
core_crates := "-p vos-pvm -p vos-pvm-compiler -p vos-pvm-program -p vos-pvm-codec -p vos-pvm-codec-derive -p vos-pvm-proof-derive -p merkle-crdt -p vmls -p vos-net -p vraft -p vos-pvm-precompiles -p vos-pvm-poseidon2 -p vos-pvm-proof-verifier -p vos-abi -p vos-tree -p vos-pvm-recair-air -p vos-pvm-final-verifier -p vos-anchor -p vos-statement -p vos-statement-service --features vos-anchor/vectors,vos-statement/fixtures"

# A guest build for the PVM: the statement's target, its standard library
# built from source. Every guest and blob build sets `CARGO_INCREMENTAL` to
# 0: an incremental build, which the environment's `CARGO_INCREMENTAL=1`
# forces over the release profile, links other code, which the program ids
# and blob hashes pin and the transpiler may refuse.
guest_flags := "--target pvm/proof/statement/riscv64em-vos.json -Zbuild-std=core,alloc,compiler_builtins -Zbuild-std-features=compiler-builtins-mem"

# A venue guest of the workspace (`final-verify`,
# `statement-service`), built from `package` with `features`: its panic
# locations name the repository's sources from its root, and the
# registry's, the git checkouts' and the toolchain's under `/cargo` and
# `/rustc`, never this checkout's or this machine's paths, so its bytes are
# the same in every checkout (`blobs.lock`).
_venue-guest package bin features:
    let cargo = ($env.CARGO_HOME? | default ($env.HOME | path join .cargo)); \
        let sysroot = (rustc --print sysroot | str trim); \
        let remaps = [$"--remap-path-prefix=($env.PWD)/=" $"--remap-path-prefix=($cargo)=/cargo" \
        $"--remap-path-prefix=($sysroot)=/rustc"]; \
        with-env { CARGO_INCREMENTAL: "0", CARGO_ENCODED_RUSTFLAGS: ($remaps \
        | str join (char -u "1f")) } { cargo build -p {{package}} --release --features {{features}} --bin {{bin}} \
        {{guest_flags}} }

# The recursion AIR's prover tests and the device profile's, on its masked
# prover, four at a time: at every core at once the recursion suite passed
# 12 GiB, the limit the gates run under.
test-recair:
    cargo test -p vos-pvm-recair -p vos-pvm-device -- --test-threads=4 --skip wrap_files::

# Bench guests, built with the guest toolchain in `pvm/guest`.
build-bench-guests:
    with-env { CARGO_INCREMENTAL: "0" } { for guest in \
        [pvm/bench/guests/workflows pvm/bench/guests/actor pvm/bench/guests/agent pvm/bench/guests/hash-software \
        pvm/bench/guests/hash-precompile pvm/bench/guests/poseidon2 pvm/bench/guests/diverse] { do { cd $guest; \
        cargo build --release --target ../../../guest/riscv64em-vos.json } } }

# Cross-host checks that need the bench guests. The bench tests that prove
# run in `test-bench-proof`.
test-bench: build-bench-guests
    cargo test -p vos-pvm-bench

# Bench tests that prove end to end, one at a time. Memory-heavy.
test-bench-proof: build-bench-guests
    cargo test -p vos-pvm-bench --features prove --test diverse_proof --test precompile_tamper -- --test-threads=1

# Machine benches: snapshots of suspended workflows, and nested invocation.
bench: build-bench-guests
    cargo run --release -p vos-pvm-bench --bin snapshots
    cargo run --release -p vos-pvm-bench --bin nesting

# The segment bench (`pvm/proof/benches/segments.rs`): a kernel's run with
# precompiles cut into windows, then proved, each case in its own process
# for its peak memory. A proving run: on a host with the memory for it.
bench-segments:
    cargo bench -p vos-pvm-proof --bench segments --no-run
    cargo bench -p vos-pvm-proof --bench segments -- windows
    cargo bench -p vos-pvm-proof --bench segments -- prove

# Gray Paper 0.8.0 conformance vectors on the interpreter and the JIT.
vectors:
    cargo test -p vos-pvm --test pvm_vectors --test boundaries

# Prover integration suites, including the soundness gates behind
# `debug-internals`, the Poseidon2-M31 kernel's leaves on the recursion
# AIR, program identity, the recursion's seams, and the fixtures checked
# against their generator and judged in Wasm. The circuits' constants
# (`pvm/proof/src/constants.rs`) are recomputed with and without
# `debug-internals`.
# Memory-heavy: the library, `gates` and `isa` run two tests at a time, and
# `kernel`, whose proving runs each take several GiB, one at a time: each
# of its tests in a process of its own, as freed heap is not all returned
# between tests, so the recipe fits under a 12 GiB limit, e.g.
# `systemd-run --user --scope -p MemoryMax=12G -p MemorySwapMax=0 just test-proof`.
# They cover every admitted format, the Poseidon2-M31 segment format among
# them; the verifier's suite runs in `check`.
# Then the masking's heavy gates (`vos-pvm-recair`'s and `vos-pvm-device`'s
# `heavy-gates`): the
# leakage tests at a medium N (500 proofs a witness on the small circuit, 16
# on the real wrap, 64 a witness on the device segment; `LEAKAGE_N`,
# `LEAKAGE_WRAP_N` and `LEAKAGE_SEGMENT_N` set others, and `slice-gate` the
# full 2,000, 32 and 256), the masked acceptance above 2^16
# rows, and the final verifier's decode, verify and Wasm gates as the
# maximum over 12 seeds of the masked wrap (on the JAM-only host's
# `final-verify.elf`, built by `build-final-verify`, and `judge-wasm`'s blob),
# one test at a time, the device format's leakage gate (47's)
# among them. Last, the wrap files the suites wrote
# checked to be final wraps alone.
test-proof: build-final-verify judge-wasm
    cargo test -p vos-pvm-proof --features debug-internals --lib --bins --test gates --test isa --test pool -- --test-threads=2
    for test in (cargo test -p vos-pvm-proof --features debug-internals --test kernel -- --list --format terse \
        | lines | where {|line| $line ends-with ': test' } | each {|line| $line \
        | str replace ': test' '' }) { cargo test -p vos-pvm-proof --features debug-internals --test kernel $test -- \
        --exact --test-threads=1 }
    cargo test -p vos-pvm-proof --test kernel constants:: -- --test-threads=1
    cargo test -p vos-pvm-recair --features heavy-gates --test circuit --test recursion -- leakage heavy --test-threads=1
    cargo test -p vos-pvm-device --features heavy-gates --test device -- leakage heavy --test-threads=1
    cargo test -p vos-pvm-recair --test recursion wrap_files:: -- --test-threads=1

# The proving gates' counts only a proving run measures, written anew
# (`VOS_PINS=write`) after a change that moves format 39: the masked
# wrap's verify gas and Wasm instructions over seeds and at the fitted
# worst shape (`pvm/proof/counts.txt`). Under the 12 GiB limit
# `test-proof` names; in no tier, as `repin` is in none.
repin-proof: build-final-verify judge-wasm
    with-env { VOS_PINS: "write" } { cargo test -p vos-pvm-recair --features heavy-gates --test recursion masked::heavy::heavy_the_verify_gates_hold_over_seeds -- --exact --test-threads=1 }
    cargo test -p vos-pvm-recair --features heavy-gates --test recursion masked::heavy::heavy_the_verify_gates_hold_over_seeds -- --exact --test-threads=1
    git status --porcelain -- pvm/proof/counts.txt

# The golden fixtures (`pvm/proof/fixtures`) judged in Wasm, by the final
# verifier's blob built as a runtime builds it, under the PVF's semantics
# and the client's, every verdict the recorded one, as natively and on the
# JAM-only host (`vos-statement`'s fixtures test); and `vos-anchor`'s
# golden vectors computed by the blob, every digest the pinned bytes.
judge-wasm: build-wasm-blobs
    cd pvm/proof/final-verifier/wasm/run; cargo build --release --locked
    let run = "pvm/proof/final-verifier/wasm/run/target/release/vos-pvm-final-verifier-wasm-run"; \
        for task in [["judge" "pvm/proof/fixtures"] ["anchors"]] { for semantics in [pvf client] { \
        ^$run "pvm/proof/final-verifier/wasm/blob/target/wasm32-unknown-unknown/release/vos_pvm_final_verifier_wasm.wasm" \
        $semantics ...$task } }

# The final verifier's Wasm blob, built as a runtime builds it, from the
# fixed path (`_at-fixed-path`), `--locked` on its lock file (`just locks`).
build-wasm-blobs:
    just _at-fixed-path pvm/proof/final-verifier/wasm/blob --release --locked

# `cargo build` of the workspace at `dir` (from the repository's root) as
# if the checkout were at `/tmp/vos-checkout`, a symbolic link to it held
# under a lock for the build. Cargo hashes a package outside its
# workspace's root by its absolute path into its symbols, whose order
# lays out the program's code: built from the fixed path, a guest whose
# path dependencies lie outside its workspace is the same bytes from any
# checkout. The path is part of the blobs' bytes, so it cannot move to a
# per-user directory. What keeps another user from pointing the build at
# other sources, each checked, the build refused without it: `/tmp` is
# root's and sticky, so no other user can replace or remove this user's
# link or lock there, and the kernel follows no other user's symbolic
# link in it (`fs.protected_symlinks`), so the lock cannot be redirected;
# the link, once made, is this user's and names this checkout. On a host
# with other users, a `/tmp/vos-checkout` or lock another user made (who
# builds from it, or left it) blocks this user's builds, and the recipe
# names that user; build inside a private mount namespace that binds the
# checkout at the fixed path instead.
_at-fixed-path dir +args:
    #!/usr/bin/env bash
    set -euo pipefail
    fixed=/tmp/vos-checkout
    me=$(id -un)
    here=$(pwd -P)
    if [ "$(stat -c %U /tmp)" != root ] || [ ! -k /tmp ]; then echo "/tmp is not root's and sticky: another user could replace $fixed" >&2; exit 1; fi
    if [ "$(cat /proc/sys/fs/protected_symlinks)" != 1 ]; then echo "fs.protected_symlinks is off: another user's link could redirect $fixed.lock" >&2; exit 1; fi
    for entry in "$fixed.lock" "$fixed"; do
        if [ -e "$entry" ] || [ -L "$entry" ]; then
            owner=$(stat -c %U "$entry")
            if [ "$owner" != "$me" ]; then echo "$entry is $owner's, not $me's: another user builds from the fixed path on this host" >&2; exit 1; fi
        fi
    done
    exec 9>>"$fixed.lock"
    flock 9
    if [ -e "$fixed" ] && [ ! -L "$fixed" ]; then echo "$fixed is not a symbolic link" >&2; exit 1; fi
    ln -sfn "$here" "$fixed"
    if [ "$(stat -c %U "$fixed")" != "$me" ] || [ "$(readlink "$fixed")" != "$here" ]; then echo "$fixed is not this user's link to $here" >&2; exit 1; fi
    cd "{{dir}}"
    CARGO_INCREMENTAL=0 cargo build --manifest-path "$fixed/{{dir}}/Cargo.toml" {{args}}

# The proof fixtures under `pvm/proof/fixtures` (`proving.md` A.6), written
# anew by their generator, `pvm/proof/tests/kernel/fixtures.rs`: at a format bump,
# or a change of the AIR or a kernel's shape; a file the generator no longer
# makes is removed. `test-proof` refuses fixtures the generator does not
# make, byte for byte, and a directory holding any file but its.
fixtures:
    with-env { VOS_PINS: "write" } { cargo test -p vos-pvm-proof --test kernel fixtures::the_fixtures_are_the_generators }

# Formatting: the workspace's, and each crate's it excludes.
fmt-check:
    cargo fmt --all -- --check
    for manifest in ([pvm/bench/guests pvm/proof/fuzz pvm/proof/final-verifier/wasm] | each {|dir| glob $'($dir)/**/Cargo.toml' --exclude ['**/target/**'] } | flatten \
        | where {|manifest| open --raw $manifest \
        | str contains '[package]' }) { cargo fmt --manifest-path $manifest -- --check }

# The docs' links: none broken, and none from a public doc to a private
# item (vraft's with its simulator too, the `sim` feature); and the proof
# docs' tripwire (`tools/gates/docs.py`): no doc names deleted code as
# built, every path the audit map names exists, and SECURITY.md names
# every fuzz target.
doc-check:
    python3 -I tools/gates/docs.py
    with-env { RUSTDOCFLAGS: "-D rustdoc::broken_intra_doc_links -D rustdoc::private_intra_doc_links" } { cargo doc --workspace --no-deps --quiet }
    with-env { RUSTDOCFLAGS: "-D rustdoc::broken_intra_doc_links -D rustdoc::private_intra_doc_links" } { cargo doc -p vraft --features sim --no-deps --quiet }

clippy:
    cargo clippy --workspace --all-targets --quiet -- -D warnings
    cargo clippy -p vos-pvm-bench --features prove --all-targets --quiet -- -D warnings
    cargo clippy -p vos-pvm-proof --features debug-internals --all-targets --quiet -- -D warnings

# Fails on any JAR remnant in the PVM crates: its ISA and gas modes, opcodes,
# exits, capability surface, linker entry points, invocation kernel, CSR
# 0x800 marker and fixtures. The proof crate's own `kernel` module and a
# 0x800 rounding constant are not remnants.
jar-check:
    let hits = (rg -n --glob '!**/target/**' \
        'IsaMode|CapabilityManifest|\blink_elf\b|link_elf_with_argument_pages|run_with_vos_stubs|ECALL_VOS_|VOS_OBJECT_CAP|Opcode::Ecall\b|ExitReason::Ecall|ExitReason::Trap\b|vos_pvm::kernel::|InvocationKernel|vm_pool|JAR\\x02|\.gp072\.json|\bGasModel\b|\bPerInstruction\b|\bmem_cycles\b|Opcode::Sbrk|\bsbrk\(|(?i:csr\w*,? 0x800)\b|\(\d, 0x800\)|Some\(0x800\)' \
        pvm | complete); if ($hits.exit_code == 0) { print $hits.stdout; \
        error make { msg: "JAR remnants found" } } else { print "no JAR remnants" }

# The JAM statements service's program, `statement-service.elf`.
build-statement-service: (_venue-guest "vos-statement-service" "statement-service" "pvm-guest")

# The model venue's JAM refine program, the harnesses' (`final-verify.elf`):
# it links the model judge, whose pinned program and state its input
# carries, and is deployed nowhere.
build-final-verify: (_venue-guest "vos-statement" "final-verify" "pvm-guest")

# Every guest blob `blobs.lock` pins, its hash then its path from the
# repository's root: the venue's programs and the final verifier's Wasm
# blob. Each is hashed with its symbols and relocations stripped (the
# toolchain's `rust-objcopy`): an out-of-tree workspace's symbol names hash
# its path dependencies' absolute paths (cargo's `-C metadata`), so its
# symbol table differs between checkouts while its code does not. The Wasm
# blob, whose code that hash orders, is built from a fixed path
# (`_at-fixed-path`).
_blob-hashes:
    if ($env.CARGO_TARGET_DIR? | is-not-empty) { error make { \
        msg: "the blobs are hashed where the recipes build them: unset CARGO_TARGET_DIR" } }; \
        let fixed = ["target/riscv64em-vos/release/final-verify.elf" \
        "target/riscv64em-vos/release/statement-service.elf" \
        "pvm/proof/final-verifier/wasm/blob/target/wasm32-unknown-unknown/release/vos_pvm_final_verifier_wasm.wasm"]; \
        let sysroot = (rustc --print sysroot | str trim); \
        let objcopy = ($sysroot | path join lib rustlib (rustc -vV | lines | parse "host: {host}" \
        | get host.0) bin rust-objcopy); let stripped = (mktemp -t); \
        for path in $fixed { with-env { LD_LIBRARY_PATH: ($sysroot \
        | path join lib) } { ^$objcopy --strip-all $path $stripped }; \
        print $"(open --raw $stripped | hash sha256)  ($path)" }; rm $stripped

# The pinned blobs by role: `final-verify.elf` and the Wasm blob, the
# harnesses' programs, deployed nowhere, link the model judge
# (`vos-statement`'s `model-judge`, whose pinned program and state its
# input carries); `statement-service.elf`, the one deployed, links none
# (`_forbidden`'s `venue-model` rows); every other line of `blobs.lock` is an agent
# program (`programs.toml`) or a test actor, on the node side. A blob that
# joins the lock joins one of these, or fails here.
check-blob-roles:
    let judges = {|args| cargo tree ...($args | split row ' ') -e no-dev --target all -f '{p}|{f}' --prefix none | lines | any {|line| \
        let parts = ($line | str replace ' (*)' '' | split row '|'); \
        ($parts.0 | str starts-with 'vos-statement v') and ('model-judge' in ($parts.1? | default '' | split row ',')) } }; \
    for harness in ["-p vos-statement --features pvm-guest" "--manifest-path pvm/proof/final-verifier/wasm/blob/Cargo.toml"] { \
        if not (do $judges $harness) { error make { msg: $"cargo tree ($harness) links no model judge: a harness's blob no longer, its role changed" } } }; \
    let harnesses = [target/riscv64em-vos/release/final-verify.elf pvm/proof/final-verifier/wasm/blob/target/wasm32-unknown-unknown/release/vos_pvm_final_verifier_wasm.wasm]; \
    let deployed = [target/riscv64em-vos/release/statement-service.elf]; \
    let programs = (if ('programs.toml' | path exists) { open programs.toml | get program.elf } else { [] }); \
    let pinned = (open --raw blobs.lock | lines | where {|line| not ($line | str starts-with '#') and $line != '' } | each {|line| $line | split row '  ' | last }); \
    let unknown = ($pinned | where {|path| $path not-in ($harnesses ++ $deployed ++ $programs) and not ($path | str starts-with 'agent/test-actors/') }); \
    if ($unknown | is-not-empty) { error make { msg: $"blobs.lock pins blobs of no role: ($unknown | str join ', ')" } }; \
    print $"the pinned blobs by role: ($harnesses | length) harnesses' linking the model judge, ($deployed | length) deployed, ($pinned | length) in all"

# Every guest blob `blobs.lock` pins, built as `check` builds it.
build-blobs: build-final-verify build-statement-service build-wasm-blobs

# `blobs.lock` written anew from the blobs as built: after a change that
# moves one, which the lock's diff then shows.
blobs-lock: build-blobs
    {{_hashed}}; $built | prepend ["# Every pinned guest blob's SHA-256, its symbols and relocations stripped," \
        "# as `just build-blobs` builds it: `just blobs-lock` writes it, `just" \
        "# check-blobs` checks it (the justfile's `_blob-hashes` says which blobs)."] | str join "\n" | $in + "\n" \
        | save -f blobs.lock

# Every pin store written anew from this tree, in dependency order, after
# a change that moves a guest, a circuit or the lock file: one command at
# a merge, where two branches' pins are never merged by hand. On a tree
# whose pins are current it changes nothing.
# 1. the guests built, and `blobs.lock` (`blobs-lock`);
# 2. the circuits' constants, `pvm/proof/src/constants.rs` (the
#    recursion's circuits are built: minutes, and several GiB);
# 3. the golden fixtures, `pvm/proof/fixtures` (`fixtures`: it proves,
#    under the 12 GiB limit `test-proof` names), and the proving gates'
#    counts over them, `pvm/proof/counts.txt`: a statement judged
#    and refined on the JAM-only host, the one-segment masked wrap's verify
#    (the heavy gates' counts are a proving run's: `just repin-proof`);
# 4. the lock `check-kit` builds the kit on, `pvm/proof/kit/Cargo.lock`
#    (`kit-lock`).
# The known programs' ids in `pvm/proof/src/constants.rs` and the
# conformance vectors the kit carries (`tools/kreivo/conformance`) are
# the node side's to write, from the test actors and the reference mock.
# Before them, the side workspaces' lock files (`locks`), which the Wasm
# blob is built on.
# The pinning tests write under `VOS_PINS=write` what moved, and are run
# again without it, so a store a write did not settle fails here. Not
# written, on purpose: the final verifier's own constants
# (`pvm/proof/final-verifier/src/constants.rs`), a venue's verifying key,
# which a circuit change moves by hand; and the fuzz targets' replay
# corpora (`pvm/proof/fuzz/replay/*.tar`), which are kept, not
# generated. Last, the stores that moved are listed.
repin: locks blobs-lock
    with-env { VOS_PINS: "write" } { cargo test -p vos-pvm-proof --test kernel constants:: -- --test-threads=1 }
    rustfmt --edition 2024 pvm/proof/src/constants.rs
    cargo test -p vos-pvm-proof --test kernel constants:: -- --test-threads=1
    just fixtures
    with-env { VOS_PINS: "write" } { cargo test -p vos-statement --features fixtures --test fixtures every_fixture_is_judged_on_the_jam_only_host_as_recorded -- --exact }
    with-env { VOS_PINS: "write" } { cargo test -p vos-statement-service --test service a_140_kib_extrinsic_is_read_as_the_proof -- --exact }
    with-env { VOS_PINS: "write" } { cargo test -p vos-pvm-recair --test recursion masked::the_masked_wrap_verifies_on_the_jam_only_host -- --exact }
    just kit-lock
    let moved = (git status --porcelain -- blobs.lock pvm/proof/src/constants.rs pvm/proof/fixtures \
        pvm/proof/counts.txt pvm/proof/kit/Cargo.lock pvm/proof/final-verifier/wasm/blob/Cargo.lock \
        pvm/proof/fuzz/Cargo.lock | lines); \
        if ($moved | is-empty) { print "repin: every pin store is this tree's already" } else { print "repin: moved"; \
        $moved | each {|line| print $line }; null }

# The pinned blobs' hashes, `_blob-hashes`' lines; its failure fails the
# recipe that reads them.
_hashed := 'let hashed = (just _blob-hashes | complete); if $hashed.exit_code != 0 or ($hashed.stdout | is-empty) { print -e $hashed.stderr; error make { msg: "the guest blobs could not be hashed" } }; let built = ($hashed.stdout | lines)'

# Every pinned guest blob built and hashed, each its `blobs.lock` hash, and
# the lock naming every blob built: a change that moves a blob moves its
# line.
check-blobs: build-blobs check-blob-roles
    {{_hashed}}; let locked = (open --raw blobs.lock | lines | where {|line| not ($line | str starts-with "#") }); \
        let moved = ($built | where {|line| $line not-in $locked }); \
        let gone = ($locked | where {|line| $line not-in $built }); for line in $moved { print -e $"built: ($line)" }; \
        for line in $gone { print -e $"locked: ($line)" }; \
        if ($moved ++ $gone | is-not-empty) { error make { \
        msg: "the guest blobs are not blobs.lock's: `just repin` after a change that moves them" } }; \
        print $"every pinned guest blob is blobs.lock's: ($built | length) blobs"

# The gates' table: by gate, each build `cargo tree <args>` resolves (its
# normal and build edges, for every target). What a gate refuses in its
# builds is read from the manifests, beside what it names: a package's
# `[package.metadata.vos]` `test-features`, each of its test-only features
# with the gates that refuse it, and `test-package`, the gates that refuse
# the package itself. A feature named there that the package does not
# define, or a gate no row builds, fails here, so a renamed feature is
# never silently passed. Each package's enabled features (`{f}`) are
# compared whole, so one a feature enables through another is caught.
# `_forbidden <gate>...` resolves each build the gates name once, prints
# every feature enabled and package held, and fails on any, or when a
# build does not resolve.
_forbidden +gates:
    let table = [ \
        [gate args]; \
        [venue-model "--workspace"] \
        [venue-model "-p vos-statement-service --features pvm-guest"] \
        [seeded-masks "--workspace"] \
        [seeded-masks "--manifest-path pvm/proof/fuzz/Cargo.toml --locked"] \
        [seeded-masks "--manifest-path pvm/proof/final-verifier/wasm/run/Cargo.toml"] \
        [seeded-masks "--manifest-path pvm/proof/final-verifier/wasm/blob/Cargo.toml --locked"] \
        [debug-internals "--workspace"] \
        [debug-internals "-p vos-statement-service --features pvm-guest"] \
        [debug-internals "--manifest-path pvm/proof/final-verifier/wasm/run/Cargo.toml"] \
        [debug-internals "--manifest-path pvm/proof/final-verifier/wasm/blob/Cargo.toml --locked"] \
        [test-device-format "--workspace"] \
        [heap-peak "--workspace"] \
        [heap-peak "-p vos-statement --features pvm-guest"] \
        [heap-peak "-p vos-statement-service --features pvm-guest"] \
    ]; \
    let manifests = (cargo metadata --no-deps --format-version 1 | from json | get packages); \
    let features = ($manifests | each {|package| $package.metadata?.vos?."test-features"? | default {} \
        | transpose feature gates | each {|row| { package: $package.name, feature: $row.feature, gates: $row.gates, \
        defined: ($row.feature in ($package.features | columns)) } } } | flatten); \
    let packages = ($manifests | each {|package| $package.metadata?.vos?."test-package"? | default [] \
        | each {|gate| { package: $package.name, gate: $gate } } } | flatten); \
    let known = ($table.gate | uniq); \
    let stale = ($features | where not defined | each {|row| $"($row.package) declares no feature ($row.feature)" }) \
        ++ ($features | each {|row| $row.gates | where {|gate| $gate not-in $known } | each {|gate| $"($row.package)'s ($row.feature) names no gate ($gate)" } } | flatten) \
        ++ ($packages | where {|row| $row.gate not-in $known } | each {|row| $"($row.package) names no gate ($row.gate)" }) \
        ++ ($known | where {|gate| ($features | where {|row| $gate in $row.gates } | is-empty) and ($packages | where gate == $gate | is-empty) } \
        | each {|gate| $"no manifest names a feature or package the gate ($gate) refuses" }); \
    for failure in $stale { print -e $failure }; \
    if ($stale | is-not-empty) { error make { msg: "the manifests' test features and the gates' table disagree" } }; \
    let failures = ($table | where gate in [{{gates}}] | group-by args | items {|args, rows| \
        let refused = ($features | where {|row| $row.gates | any {|gate| $gate in $rows.gate } } | get feature | uniq); \
        let barred = ($packages | where gate in $rows.gate | get package | uniq); \
        let resolved = (cargo tree ...($args | split row ' ') -e no-dev --target all -f '{p}|{f}' --prefix none | complete); \
        if $resolved.exit_code != 0 { print -e $resolved.stderr; error make { msg: $"cargo tree ($args) failed" } }; \
        let tree = ($resolved.stdout | lines | each {|line| $line | str replace ' (*)' '' | split row '|' }); \
        let held = ($tree | each {|parts| $parts.0 | split row ' ' | first }); \
        let enabled = ($tree | each {|parts| $parts.1? | default '' | split row ',' } | flatten); \
        ($refused | where {|feature| $feature in $enabled } | each {|feature| $"cargo tree ($args) enables ($feature)" }) \
        ++ ($barred | where {|package| $package in $held } | each {|package| $"cargo tree ($args) holds ($package)" }) \
    } | flatten); \
    for failure in $failures { print -e $failure }; \
    if ($failures | is-not-empty) { error make { msg: "a production build enables a forbidden feature or holds a forbidden package" } }

# The proof crate's `debug-internals` does not imply `seeded-masks`.
_seeded-masks-unimplied:
    if (open pvm/proof/Cargo.toml | get features.debug-internals | any {|feature| $feature | str contains 'seeded-masks' }) { error make { msg: "debug-internals implies seeded masks" } }

# The venue rules are written once, in `vos_anchor::venue`: no venue's
# source outside its tests (the model judge and the JAM statements
# service here) holds the arithmetic of an anchor or registration rule: the root age, a
# window's boundary, a comparison with the last window anchored, the window
# lengths a venue registers, the key bounds and the small-order keys, or the
# strict signature check past the one verifier each venue hands the core;
# and each venue calls the core's rules. A tripwire on the rules'
# arithmetic, not a proof that no rule is restated: the clients' reads of a
# space's status and listed keys, which a re-founded space's anchoring
# keeps, are not flagged.
check-venue-rules:
    let roots = [pvm/proof/statement/src pvm/proof/statement/service/src]; \
    let markers = ['MAX_ROOT_AGE_MS' '\.boundary\(' 'verify_strict' 'SMALL_ORDER' 'small_order\(' 'registrable' \
        'MIN_LENGTH_MS' 'MAX_LENGTH_MS' 'MAX_FOUNDING_KEYS' '[<>]=?\s*last\b' '\blast\s*[<>]']; \
    let allowed = [[file marker]; [pvm/proof/statement/service/src/refine.rs verify_strict]]; \
    let sources = ($roots | each {|root| glob $"($root)/**/*.rs" } | flatten | each {|path| $path \
        | path relative-to $env.PWD } | where {|path| not ($path =~ '(^|/)(tests?|conformance)(/|\.rs$)') }); \
    let found = ($sources | each {|file| let code = (open --raw $file | lines \
        | take until {|line| $line =~ '^#\[cfg\(test\)\]' } | each {|line| $line | str replace -r '//.*$' '' } \
        | str join "\n" | str replace -a -r '(?m)^\s*(pub )?use [^;]*;' ''); \
        $markers | where {|marker| ($code =~ $marker) and not ($allowed \
        | any {|a| $a.file == $file and $a.marker == $marker }) } | each {|marker| $"($file) holds ($marker)" } } \
        | flatten); \
    let calls = [[file call]; [pvm/proof/statement/src/model.rs 'rules::anchored('] \
        [pvm/proof/statement/service/src/accumulate.rs 'rules::anchor('] \
        [pvm/proof/statement/service/src/accumulate.rs 'rules::register('] \
        [pvm/proof/statement/service/src/accumulate.rs 'rules::anchored('] \
        [pvm/proof/statement/service/src/refine.rs 'rules::registration('] \
        [pvm/proof/statement/service/src/accumulate.rs 'rules::add_key(']]; \
    let missing = ($calls | where {|row| not (open --raw $row.file | str contains $row.call) } | each {|row| $"($row.file) calls no ($row.call)" }); \
    for failure in ($found ++ $missing) { print -e $failure }; \
    if ($found ++ $missing | is-not-empty) { error make { msg: "an anchor rule lives outside vos_anchor::venue, or a venue does not call it" } }; \
    print $"the venue rules live in vos_anchor::venue alone: ($sources | length) files searched, ($calls | length) calls found"

# Every `check-no-*` gate below, each build resolved once, and two more
# of the table's: the model venue (`venue-model`: `vos-venue`'s `model`
# and Kreivo's mock, `kreivo-mock`, on no normal or build edge of any
# workspace member; `vos-statement`'s `model-judge` in neither the node,
# the `vos` binary nor the JAM statements service's program, which the
# development tools' harnesses link), and the guests' heap peak
# (`heap-peak`: `vos-statement`'s and the JAM statements service's, a
# measurement build's, in no workspace member's, the `vos` binary's with
# the prover nor the venues' guests' builds).
check-no-leaks: (_forbidden "venue-model" "seeded-masks" "debug-internals" "test-device-format" "heap-peak") _seeded-masks-unimplied
    print "no test seam, debug output, test device format, heap peak or model venue in a production build"

# The masked prover's test seams (`vos-pvm-recair`'s `seeded-masks`: the
# seeded randomness `MaskRng::Seeded` and the forced proof
# `prove_masked_unchecked`), the final verifier's (`other-pins`: the wrap
# verified under other pins, `masked::verify_with`) and the proof crate's
# (`chip-isolated`: a chip slice proved and verified alone) reach no
# production build: no normal or build edge
# of any workspace member, nor of the workspaces built apart (the fuzz
# targets, the final verifier's Wasm blob and its runner), enables
# it (the prover's tests enable it on a dev edge), and the proof crate's
# `debug-internals` does not imply it.
check-no-seeded-masks: (_forbidden "seeded-masks") _seeded-masks-unimplied
    print "no seeded masks in a production build"

# The debug outputs (`vos-pvm`'s and `vos-pvm-proof`'s `debug-internals`:
# the PVM's instruction trace, `VOS_PVM_DEBUG`'s registers and native code,
# `CPU_DUMP`, `CPU_EXPR_DUMP`, `VOS_PROOF_PROFILE`), which show a run's steps,
# registers and rows, and the carrier audit's seam (`vos-pvm-recair`'s
# `watch`), which hands a proof's internals out, reach no production
# build: no normal or build edge of any workspace member, nor of the final
# verifier's workspaces, enables the debug outputs, nor of any workspace
# member the seam.
check-no-debug-internals: (_forbidden "debug-internals")
    print "no debug outputs in a production build"

# The builds without std, for an embedded target on core and alloc
# alone, built from the toolchain's source. merkle-crdt, without its
# `std` feature. vraft, the Raft core, with and without its simulator
# (the `sim` feature). The proof verifier, which reads every admitted
# format, with the proof crate's verifier path under it: both are
# `no_std` crates, so a `std` path in either fails the build. The
# verifier builds for
# the same embedded target, where no dependency has std either, and for
# wasm32, the target of an on-chain verifier; the workspace's toolchain file
# installs wasm32.
# The final verifier, on the recursion AIR's bodies, the space's anchor
# types, and the statement's venue check over both, for the embedded
# target, for wasm32 with every nightly feature refused (their source
# builds on stable), and for the PVM
# with the standard library built from source, with the venue's JAM refine
# program, which `vos-pvm-recair`'s wrap tests and the fixtures' and the
# end-to-end tests run on the JAM-only host: `final-verify.elf`, the
# harness's refine program, linking format 39 and accepting nothing
# without a proof; and the JAM statements service's program,
# `statement-service.elf`, which its tests run on the JAM-only host,
# refine and accumulate. The guests' bins and the Wasm blob,
# crate roots the workspace's lints do not reach, are linted here under the
# verify path's denies. Last, every guest blob checked against
# `blobs.lock` (`check-blobs`).
check-no-std:
    cargo build -p merkle-crdt --no-default-features --target thumbv7em-none-eabihf -Zbuild-std=core,alloc
    cargo build -p vraft --target thumbv7em-none-eabihf -Zbuild-std=core,alloc
    cargo build -p vraft --features sim --target thumbv7em-none-eabihf -Zbuild-std=core,alloc
    cargo build -p vos-pvm-proof-verifier --target thumbv7em-none-eabihf -Zbuild-std=core,alloc
    cargo build -p vos-pvm-proof-verifier --target wasm32-unknown-unknown
    cargo build -p vos-pvm-final-verifier --target thumbv7em-none-eabihf -Zbuild-std=core,alloc
    with-env { RUSTFLAGS: "-Zallow-features=" } { cargo build -p vos-pvm-final-verifier --target wasm32-unknown-unknown --target-dir target/no-nightly-features }
    cargo build -p vos-anchor --target thumbv7em-none-eabihf -Zbuild-std=core,alloc
    with-env { RUSTFLAGS: "-Zallow-features=" } { cargo build -p vos-anchor --target wasm32-unknown-unknown --target-dir target/no-nightly-features }
    cargo build -p vos-statement --target thumbv7em-none-eabihf -Zbuild-std=core,alloc
    with-env { RUSTFLAGS: "-Zallow-features=" } { cargo build -p vos-statement --target wasm32-unknown-unknown --target-dir target/no-nightly-features }
    just build-final-verify
    cargo clippy -p vos-statement --release --features pvm-guest --bin final-verify {{guest_flags}} --quiet -- -D warnings
    just build-statement-service
    cargo clippy -p vos-statement-service --release --features pvm-guest --bin statement-service {{guest_flags}} --quiet -- -D warnings
    cd pvm/proof/final-verifier/wasm/blob; cargo clippy --release --locked --quiet -- -D warnings
    just check-blobs

# The verifier kit (`pvm/proof/kit/vos_kit.py`), which a chain's runtime
# vendors (Kreivo's `vendor/vos-verifier/`, `spaces-pallet.md` §3), written
# into `dir`: `vos-anchor`, `vos-statement`, `vos-pvm-final-verifier`,
# `vos-pvm-recair-air` and `vos-pvm-poseidon2` with concrete manifests (Stwo
# a git dependency at the pin, without default features; `pvm-guest` left
# in VOS), the golden fixtures, the conformance
# vectors and a `VENDOR` file naming the commit (and the tag) and the
# tree's hash. From the working tree, or from `rev`, a tag or a commit: a
# release vendors from a tag.
vendor-verifier dir rev="":
    if "{{rev}}" == "" { python3 -I pvm/proof/kit/vos_kit.py vendor {{dir}} } else { python3 -I pvm/proof/kit/vos_kit.py vendor {{dir}} --rev {{rev}} }

# A vendored kit checked against the commit its `VENDOR` names: the tree's
# hash, then the kit vendored anew from that commit by its own script, the
# fixtures and the conformance vectors with it, every file compared; here
# against this checkout, a kit vendored at a commit accepted. A consumer
# runs `pvm/proof/kit/vos-sync.sh`, copied outside its kit, which pins VOS's
# repository, refuses a kit of another tag than the one it expects and
# runs the tag's script, never the kit's own: `scripts/vos-sync.sh
# vendor/vos-verifier <tag>` (`spaces-pallet.md` §3.1).
vos-sync dir:
    python3 -I pvm/proof/kit/vos_kit.py sync {{dir}} --vos . --allow-untagged --scratch target/kit/scratch

# The kit as Kreivo builds it: vendored from the working tree into a
# workspace of its own, built alone and `--locked` (on the kit's lockfile,
# `pvm/proof/kit/Cargo.lock`) for `wasm32v1-none` on Kreivo's stable
# toolchain (1.94.1, the target installed as Kreivo's CI installs it), no
# `std` feature, model venue (`vos-statement`'s `model-judge`) or test seam
# (the final verifier's `other-pins`) enabled in any crate it links;
# `vos-statement`'s `fixtures`
# reader built for the host; and the sync check's own test
# (`pvm/proof/kit/check.py`): a one-byte change in a vendored file refused,
# the kit's own script never trusted, `VENDOR`'s tag required and checked.
check-kit: _kit-workspace
    cd target/kit/build; cargo +1.94.1 build --workspace --target wasm32v1-none --locked --quiet
    cd target/kit/build; let std = (cargo +1.94.1 tree --workspace -e normal --target wasm32v1-none -f '{p}|{f}' \
        --prefix none --locked | lines | where {|line| $line | split row '|' | last | split row ',' \
        | any {|feature| $feature in [std model-judge other-pins] } } | uniq); \
        if ($std | is-not-empty) { error make { msg: \
        $"std, the model venue or a test seam reaches the kit: ($std | str join ', ')" } } else { \
        print "no std feature, model venue or test seam in the kit's wasm32v1-none build" }
    cd target/kit/build; cargo +1.94.1 build -p vos-statement --features fixtures --locked --quiet
    python3 -I pvm/proof/kit/check.py --scratch target/kit/sync

# The kit's lockfile, after its crates' dependencies change: VOS's own
# lockfile, pruned to what the kit links.
kit-lock: _kit-workspace
    cp Cargo.lock target/kit/build/Cargo.lock
    cd target/kit/build; cargo +1.94.1 build --workspace --target wasm32v1-none --quiet
    cp target/kit/build/Cargo.lock pvm/proof/kit/Cargo.lock

# The side workspaces' lock files, after a dependency changes: the root's
# copied in, pruned by cargo to what each workspace links, kept, then held
# to the root's (`check-locks`). The Wasm blob's (whose bytes `blobs.lock`
# pins) and the prover's fuzz targets'; the blob's runner keeps its own,
# for wasmtime, a tool that is no part of the blob.
locks:
    for dir in [pvm/proof/final-verifier/wasm/blob pvm/proof/fuzz] { cp Cargo.lock $"($dir)/Cargo.lock"; cargo metadata --manifest-path $"($dir)/Cargo.toml" --format-version 1 | ignore }
    just check-locks

# Every package of the side workspaces' lock files, its name, version and
# source, the root lock's, but each workspace's own and the tools only it
# links (`tools/gates/locks.py`): the verifier's dependencies resolve to
# one version everywhere it is built.
check-locks:
    python3 -I tools/gates/locks.py check

_kit-workspace:
    if not ((do { rustup target list --installed --toolchain 1.94.1 } | complete).stdout | lines \
        | any {|target| $target == 'wasm32v1-none' }) { \
        rustup toolchain install 1.94.1 --profile minimal --target wasm32v1-none --no-self-update }
    rm -rf target/kit/build
    python3 -I pvm/proof/kit/vos_kit.py vendor target/kit/build/vendor/vos-verifier
    {workspace: {resolver: "3", members: (glob target/kit/build/vendor/vos-verifier/*/Cargo.toml \
        | each {|manifest| $manifest | path dirname | path relative-to ($env.PWD | path join target/kit/build) } \
        | sort)}, profile: {dev: {debug: false}}} | to toml | save -f target/kit/build/Cargo.toml
    cp pvm/proof/kit/Cargo.lock target/kit/build/Cargo.lock

# The fuzz targets, built apart with `cargo fuzz` (`pvm/proof/fuzz`):
# the final verifier on arbitrary bytes, on
# the golden wraps mutated, on format 39's layout past its header and on
# its queried parts reshaped within the layout's bounds; the statement's
# and the space's decoders and the venue's check; prove-then-verify on
# random programs; the device verifier on ingress's bytes and on the
# golden device proof mutated, under 47; the compiler's derive on ELF
# bytes; a standard program's parse and run on both backends; and the JAM
# statements service's refine on work items. A target's
# property is no panic and nothing accepted but a golden (a device proof:
# its one encoding).
# Each target's libFuzzer bounds where they are not the default's (an
# input of 256 KiB and a byte, 8 GiB, ten minutes an input): a device
# input up to an io-hash and a whole device proof (`MAX_PROOF_BYTES`), and
# an ELF as large under the memory and time derive is held to whatever the
# ELF claims.
_fuzz_limits := '{device_verify_bytes: [-max_len=1572896 -rss_limit_mb=8192 -timeout=600], derive_elf: [-max_len=1572896 -rss_limit_mb=512 -timeout=10]}'
_fuzz_default := '[-max_len=262145 -rss_limit_mb=8192 -timeout=600]'
proof_fuzz_targets := "final_verifier_bytes final_verifier_mutate statement_decode prove_verify_roundtrip masked_bytes masked_shape anchor_decode device_verify_bytes device_verify_mutate derive_elf program_blob service_item"

# Each target's checked-in corpus (`replay/<target>.tar` of
# `pvm/proof/fuzz`, unpacked into its `target/replay/` by `corpus.py`) run
# once, every input, optimized and without a sanitizer: no crash, within
# the memory `fuzz` gives a target (a kernel's segments proved take about
# 3 GB). `cargo
# run --example paths` there lists what each input reaches. `cargo fuzz`
# sets RUSTFLAGS, which replaces the host's `target-cpu=native`
# (`.cargo/config.toml`), so the recipes pass it again: without it the
# prover's SIMD falls back to its generic code, and one proof takes many
# minutes. `cargo fuzz` takes no `--locked`: `cargo fetch --locked` first
# refuses a lock file the build would change.
fuzz-replay:
    cd pvm/proof/fuzz; cargo fetch --locked
    cd pvm/proof/fuzz; python3 -I corpus.py unpack replay target/replay; \
        with-env { RUSTFLAGS: "-C target-cpu=native" } { for target in ("{{proof_fuzz_targets}}" \
        | split row ' ') { cargo fuzz run -O -s none --target-dir target/no-sanitizer $target \
        $"target/replay/($target)" -- -runs=0 -rss_limit_mb=8192 } }

# What each replay corpus reaches (`cargo run --example paths` in
# `pvm/proof/fuzz`), held to `pvm/proof/fuzz/reach.txt`: every verdict it
# lists for a target reached by one of the target's inputs at least, so a
# corpus that drifts off a check fails `gate`.
fuzz-reach:
    cd pvm/proof/fuzz; python3 -I corpus.py unpack replay target/replay; \
        with-env { RUSTFLAGS: "-C target-cpu=native" } { \
        cargo run --release --locked --target-dir target/no-sanitizer --example paths -- --expect reach.txt }

# The prover's replay corpora rebuilt from the goldens (but
# `prove_verify_roundtrip`'s, whose programs need no golden): each target
# seeded (`--example seed`), fuzzed `secs` seconds from its seeds and its
# replay corpus as `just fuzz` runs it (each under `_fuzz_limits`' bounds),
# then merged (`-merge=1`) into a new replay corpus of the inputs that add
# coverage, the old one's among them.
# It writes each `replay/<target>.tar` anew (`corpus.py pack`: the same
# inputs, the same bytes) and marks a new archive (`git add -N`), so a
# remote run's diff carries it; `just fuzz-reach` then lists what the new
# corpus reaches.
fuzz-refresh secs="120":
    cd pvm/proof/fuzz; cargo run --release --locked --example seed
    cd pvm/proof/fuzz; python3 -I corpus.py unpack replay target/replay; \
        with-env { RUSTFLAGS: "-C target-cpu=native" } { for target in ("{{proof_fuzz_targets}}" | split row ' ' \
        | where {|target| $target != "prove_verify_roundtrip" }) { let limits = ({{_fuzz_limits}} | get -o $target \
        | default {{_fuzz_default}}); mkdir $"corpus/($target)"; \
        cargo fuzz run -a $target $"corpus/($target)" $"target/replay/($target)" -- -max_total_time={{secs}} \
        -len_control=0 ...$limits; rm -rf $"target/merged/($target)"; mkdir $"target/merged/($target)"; \
        cargo fuzz run -a $target $"target/merged/($target)" $"corpus/($target)" $"target/replay/($target)" -- \
        -merge=1 ...$limits; python3 -I corpus.py pack $"target/merged/($target)" $"replay/($target).tar" } }
    git add -N pvm/proof/fuzz/replay

# Each target `secs` seconds from its corpus (a minute in `ci-full`, five in
# `slice-gate`: `just fuzz 300`), the prover's seeded from the fixtures and
# the anchor's vectors, the checked-in corpus beside it (unpacked into
# `target/replay/`): no crash. One at a
# time; the sanitized targets with debug assertions and overflow checks
# (`-a`), the prove target optimized and without a sanitizer, its proving
# too slow under either. A target with no corpus yet (none seeded, never
# run here) starts from an empty one beside its replay.
fuzz secs="60":
    cd pvm/proof/fuzz; cargo run --release --locked --example seed
    cd pvm/proof/fuzz; python3 -I corpus.py unpack replay target/replay; \
        with-env { RUSTFLAGS: "-C target-cpu=native" } { for target in ("{{proof_fuzz_targets}}" \
        | split row ' ') { let limits = ({{_fuzz_limits}} | get -o $target | default {{_fuzz_default}}); \
        mkdir $"corpus/($target)"; let build = if $target == "prove_verify_roundtrip" { \
        [-O -s none --target-dir target/no-sanitizer] } else { [-a] }; \
        cargo fuzz run ...$build $target $"corpus/($target)" $"target/replay/($target)" -- -max_total_time={{secs}} \
        -len_control=0 ...$limits } }

# The light check, after every edit, and the innermost tier: formatting,
# the gates' own tripwire, the replay archives' reader's refusals
# (`pvm/proof/fuzz/test_corpus.py`), the workspace's lints, and every test
# target of the fast suites' crates but the heavy ones (`tools/gates/heavy.toml`,
# each a binary past about 20 s): minutes, warm. It builds the guests its
# tests run, the venues' refine programs, and nothing else outside the
# workspace.
check: fmt-check check-tiers check-layers check-device-verifier build-final-verify build-statement-service
    python3 -I pvm/proof/fuzz/test_corpus.py
    cargo clippy --workspace --all-targets --quiet -- -D warnings
    cargo test {{core_crates}} ...(python3 -I tools/gates/tiers.py fast {{core_crates}} | split row ' ')
    cargo test -p vos-pvm-recair -p vos-pvm-device ...(python3 -I tools/gates/tiers.py fast -p vos-pvm-recair -p vos-pvm-device | split row ' ') -- --test-threads=4

# The commit gate, before each commit: `check`,
# then the docs' links, the dependencies' licences and advisories (`deny`),
# the side workspaces' lock files held to the root's (`check-locks`), the
# venue rules' tripwire, the builds without std
# with every guest built and its blob checked, the production builds'
# leaks, the verifier kit, the fuzz corpus replayed, the lints of the
# feature sets a change touches, and the heavy test targets and the doc
# tests of the fast suites' crates.
# Left to `just ci`: the PVM vectors, the bench and prover library tests,
# and the lints of other feature sets.
gate: check doc-check deny check-locks check-venue-rules check-no-std check-no-leaks check-kit fuzz-replay fuzz-reach
    cargo clippy -p vos-pvm-recair --no-default-features --lib --quiet -- -D warnings
    cargo clippy -p merkle-crdt --no-default-features --lib --quiet -- -D warnings
    cargo clippy -p vraft --lib --quiet -- -D warnings
    cargo test {{core_crates}} ...(python3 -I tools/gates/tiers.py heavy {{core_crates}} | split row ' ')
    cargo test {{core_crates}} --doc
    cargo test -p vos-pvm-recair -p vos-pvm-device ...(python3 -I tools/gates/tiers.py heavy -p vos-pvm-recair -p vos-pvm-device | split row ' ') -- --test-threads=4 --skip wrap_files::

# The tests a change touches (`tools/gates/tiers.py changed`): `cargo
# test` for the workspace's crates that differ from `base`, and those that
# depend on them; the fast test targets alone, or with `--heavy` the heavy
# ones too. The prover's own suites stay `ci`'s and above.
test-changed base="master" *flags="":
    python3 -I tools/gates/tiers.py changed {{base}} {{flags}}

# The workspace's dependencies (`deny.toml`, cargo-deny): every licence on
# the AGPL-compatible allowlist, no advisory of the RustSec database but
# those the file names with its reason, and no source but crates.io and
# the forks it lists. A crate held in two versions fails but those the
# file names with their reasons; yanked crates are warnings.
# The advisory database is fetched; without a network it is the cached one.
# Then the side workspaces' graphs, on their lock files: no advisory and no
# other source there either (the root's ignores that match nothing there
# allowed): the Wasm blob's and the fuzz targets' (`just locks`) and the
# bench guests'. The Wasm runner's is held to its sources alone: it pins
# wasmtime at the version a Polkadot client runs the blob under, which its
# measurements must match, whose advisories are that client's and reach no
# shipped code. The verifier
# kit's (`pvm/proof/kit/Cargo.lock`) is no workspace's here: it is the
# root's pruned to what the kit links (`kit-lock`), which the root's check
# holds.
deny:
    cargo deny check --hide-inclusion-graph
    for manifest in ([pvm/proof/final-verifier/wasm/blob/Cargo.toml pvm/proof/fuzz/Cargo.toml] \
        ++ (glob pvm/bench/guests/*/Cargo.toml --exclude ['**/target/**'] | path relative-to $env.PWD)) { \
        cargo deny --locked --manifest-path $manifest check --hide-inclusion-graph -A advisory-not-detected advisories \
        sources }
    cargo deny --locked --manifest-path pvm/proof/final-verifier/wasm/run/Cargo.toml check --hide-inclusion-graph sources

# The device verifier built alone, ingress's build (`vos-pvm-device`
# without its `prover` feature): it builds and lints clean, and its normal
# dependencies hold neither the prover (`vos-pvm-recair`), nor the runtime
# and its recompiler (`vos-pvm`), nor `rayon`.
check-device-verifier:
    cargo clippy -p vos-pvm-device --no-default-features --quiet -- -D warnings
    let crates = (cargo tree -p vos-pvm-device --no-default-features -e normal --prefix none \
        | lines | each {|line| $line | split row ' ' | first } | uniq); \
    let linked = ($crates | where {|name| $name in ["vos-pvm", "vos-pvm-recair", "rayon"] }); \
    if not ($linked | is-empty) { error make { msg: $"the device verifier links ($linked | str join ', ')" } }; \
    print "the device verifier links neither the prover, nor the runtime, nor rayon"

# The layers: a package under `pvm/` has no path dependency outside
# `pvm/`, on a normal, a build or a dev edge, so the PVM, its compiler,
# its prover and the actor ABI read, build and test alone. Git and registry
# dependencies (the Stwo fork) are allowed, and listed. Every package
# under `pvm/` is read, the
# workspaces built apart included (`cargo metadata` of each manifest).
check-layers:
    let manifests = (glob pvm/**/Cargo.toml --exclude ['**/target/**'] | where {|manifest| open --raw $manifest | str contains '[package]' }); \
    if ($manifests | is-empty) { error make { msg: "no package under pvm/" } }; \
    let packages = ($manifests | each {|manifest| cargo metadata --no-deps --offline --format-version 1 \
        --manifest-path $manifest | from json | get packages | where manifest_path == $manifest | first }); \
    let edges = ($packages | each {|package| $package.dependencies \
        | each {|dependency| { package: $package.name, dependency: $dependency.name, kind: ($dependency.kind \
        | default normal), path: ($dependency.path? | default "" | if ($in | is-empty) { "" } else { $in \
        | path relative-to $env.PWD }), source: ($dependency.source? | default "") } } } | flatten); \
    let local = ($edges | where path != ""); \
    let outside = ($local | where {|edge| not ($edge.path | str starts-with "pvm/") }); \
    print $"git crates allowed: ($edges | where {|edge| $edge.source | str starts-with 'git+' } | get dependency | uniq | str join ', ')"; \
    for edge in $outside { print -e $"($edge.package) -> ($edge.dependency) \(($edge.kind)\): ($edge.path) is outside pvm/" }; \
    if ($outside | is-not-empty) { error make { msg: "a package under pvm/ depends on a path outside pvm/" } }; \
    print $"no package under pvm/ depends on a path outside it: ($packages | length) packages, ($local | length) path edges"

# The gates' tripwire (`tools/gates/tiers.py`): the tiers nest, every test
# target of the workspace is run by `check` or listed heavy and run by
# `gate`, or run by a tier above; every workspace outside the root's is
# built or tested by a tier.
check-tiers:
    python3 -I tools/gates/tiers.py check

# Before a merge, and at the end of each planned stage of work: `gate`,
# and everything else but the prover suites: the lints of every feature
# set, the JAR check, the PVM vectors, the bench's cross-host checks, the
# statement's heap peak and the prover's library tests.
ci: gate clippy jar-check vectors test-bench
    cargo test -p vos-statement --features heap-peak --test heap
    cargo test -p vos-pvm-proof --lib

# The gate at a milestone: `ci` plus the prover suites, the soundness gates (the leakage tests at their medium N), the
# bench tests that prove and the fuzz targets a minute each. Run it under a 12 GiB limit, e.g.
# `systemd-run --user --scope -p MemoryMax=12G -p MemorySwapMax=0 just ci-full`.
# Run alone on the machine, its builds may take `CARGO_BUILD_JOBS` 8 to 12:
# the proving tests keep their own thread limits (`test-proof`'s
# `--test-threads`), so the peak stays under the cap.
ci-full: ci test-bench-proof test-proof (fuzz "60")

# The release gate, before a release: `ci-full`'s recipes, with the leakage tests at
# their full N (2,000 proofs a witness on the small circuit, 32 on the real
# wrap, 256 a witness on the device segment) and the fuzz targets five
# minutes each. Under the same limit.
slice-gate: ci test-bench-proof
    with-env { LEAKAGE_N: "2000", LEAKAGE_WRAP_N: "32", LEAKAGE_SEGMENT_N: "256" } { just test-proof }
    just fuzz 300

# Use the repository's hooks, which run only once this sets them: fmt and
# clippy before commits, `just ci` before pushes, on a push of HEAD from a
# tree that is HEAD alone (`.githooks/pre-push`).
install-hooks:
    git config core.hooksPath .githooks
