# vosx decoupling — retire hardcoded extension commands, metadata-driven CLI

Goal: `vosx` becomes a kernel CLI — space lifecycle, identity, one-shot `run`,
and a **generic metadata-driven dispatcher** — with **zero actor/extension
crate dependencies**. Extensions surface as subcommands dynamically from their
`.vos_meta` schemas; the client-side behaviors that hardcoded commands exist
for today (file I/O, streaming, long-running work, signing) become generic
*drivers* keyed off metadata, not per-extension Rust.

Execution model for this plan: work wave by wave, one commit per work item
(item IDs below), run the wave gate before moving on. Waves 1–2 fit one
session; waves 3 and 4 are each their own session. Read this whole file
first; then read the files listed in each item before editing them.

## Boot checklist (read before any edit)

- `vos/src/actors/metadata.rs` — the `.vos_meta` wire format. **Trailing-append
  evolvable**: every new section goes at the end; old decoders stop early and
  fields default. All metadata changes in this plan follow that discipline.
- `vosx/src/commands/dynamic.rs` — the dispatcher being promoted. Already has:
  schema-typed coercion (`apply_arg`), `key=@path` file reads, hex↔bytes,
  `#[msg(cli)]` filtering, return-type labels, universal `__stop`/`__describe`.
- `vos/vos-macros/src/lib.rs` — `#[actor]`/`#[messages]` emit `ActorMeta` +
  `encode::<4096>` (lines ~140, ~1002). `#[msg(cli)]` and `#[msg(role = X)]`
  parse at ~293–315.
- `vosx/src/main.rs` `should_dynamic_dispatch` (~line 330) — `BUILTIN_VERBS`
  list gates routing; every retired verb must be removed from it.
- `extensions/ai/src/lib.rs`, `extensions/prover/src/lib.rs` — the two
  hand-rolled async-job systems this plan unifies.
- House rules (repo-wide): no `#[ignore]` tests — fix or delete; comments are
  timeless (no phase/sprint narrative); `#[repr(u8)]` rkyv enums over const
  byte groups; if a pre-existing test breaks mid-task, fix it.

## Non-goals (explicitly out of scope)

- **Daemon split** (`vosx` vs `vos-daemon` binaries). Wave 4 moves daemon-role
  code *into `vos` the library*, which is the prep step; the binary split is a
  separate future plan.
- **zk pin end-state** (catalog stored in registry/CAS instead of local TOML;
  pin as a dev-extension pipeline). `vosx zk` stays a thin builtin for now —
  it already delegates all zkpvm work to the prover extension's
  `measure_catalog`.
- **Money-path changes**: nothing in clerk-ledger/clerk-bridge/clerk-settle,
  voucher protocol, or proving semantics changes. The prover's job-surface
  rename (2.3) is wire-shape only; its prove/verify logic is untouched.
- No backward-compat shims for renamed handlers: this is a pre-release,
  single-repo system. Migrate all callers in the same commit instead.

## Design decisions (locked — do not re-litigate)

1. **Builtin verbs after this plan**: `run`, `space`, `zk`, `whoami`,
   `help-schema`. Retired: `ai`, `dev`, `space console`. Everything else is
   dynamic dispatch.
2. **The typed `*Ref` façades buy no wire capability** — they emit the same
   `TAG_DYNAMIC` `Msg` as `invoke_dyn`. Client-side registry/chronos calls
   convert to dynamic invokes with reply types hosted in `vos`.
3. **System-actor protocol lives in `vos`**: the space-registry and chronos
   *wire types + constants + canonical encodings* move into `vos` (cycle-safe:
   both actor crates already depend on `vos` and re-import them). Verifier-side
   crypto (`verify_op_sig`) stays in the actor crates.
4. **Jobs are a wire convention + a `vos` helper, not an executor change**: a
   `#[msg(job)]` handler *is the begin* — it returns a `u64` job id and the
   extension answers reserved `job_poll`/`job_release` methods, backed by a
   `vos::jobs::JobQueue` state helper. How the work actually runs (worker
   thread like ai, tick-advance like prover) stays each extension's business.
5. **CLI-visible replies are self-describing**: `#[msg(cli)]` handlers return
   primitives, `vos::value::Args`-encoded records, or raw `Vec<u8>` labeled by
   the `returns` metadata. No consumer may need the extension's Rust structs
   to render a reply.
6. **Bundled ELF blobs are data, not deps** — `vosx/blobs/*.elf` +
   `build.rs` bundling stays; it never required the actor crates.

---

## Wave 1 — deletions + dispatcher gaps + metadata docs

### 1.1 Delete `space console` + the `vos-shell` dependency

- Delete `vosx/src/commands/space/console.rs` (~147 lines; the only coupling
  is a ~55-line `SpaceClient` trait adapter), the `Console` variant in
  `space/mod.rs`, and `vosx/tests/console_e2e.rs`.
- Drop `vos-shell` from `vosx/Cargo.toml`. Grep docs (`README.md`, `docs/`,
  `docs/`) for `space console` / `support/vos-shell` mentions and update.
- Do **not** delete the `vos-shell` crate itself (a future shell extension may
  reuse pieces); only unlink it from vosx. If it's a workspace member that now
  builds for nothing, leave it — out of scope.
- Gate: `cargo check -p vosx`; `cargo tree -p vosx -e normal | grep -c
  vos-shell` → 0.

### 1.2 Dispatcher input/output gaps

File: `vosx/src/commands/dynamic.rs`.

- `apply_arg`: add `ListU32` (schema ty `Vec<u32>`: comma-split parse) and
  `ListStr` (schema ty `Vec<String>`: comma-split). Escape hatch not needed —
  values with commas in strings can wait.
- `@-` reads stdin bytes (complement to `key=@path`).
- New global-ish flag `--out <path>` parsed in `parse_argv`: when set,
  `render_reply` writes a `Value::Bytes` reply raw to the file (byte-exact,
  like `dev show`'s `write_all` semantics) and prints the byte count + declared
  type to stderr. Non-bytes replies with `--out` write their text rendering.
- Unit tests alongside the existing `apply_arg`/`parse_argv` tests.

### 1.3 Metadata v2: doc strings + per-handler timeout

Files: `vos/src/actors/metadata.rs`, `vos/vos-macros/src/lib.rs`,
`vosx/src/commands/dynamic.rs`, `vosx/src/cli_cache.rs`.

- `MessageMeta` gains `doc: &'static str` and `timeout_ms: u32` (0 = default);
  `ActorMeta` gains `doc: &'static str`. Encoder appends, **in this order**,
  three new trailing sections after `returns`:
  1. per-message docs — `[count:u16][len:u16 bytes]*`, index-crossref like
     `returns`;
  2. actor doc — `[len:u16][bytes]`;
  3. per-message timeout_ms — `[count:u16][u32 LE]*`, index-crossref.
  Decoder fills `ParsedMessage.doc` / `ParsedMeta.doc` /
  `ParsedMessage.timeout_ms`, defaulting to empty/0 for old blobs. Add
  round-trip + old-blob-defaults tests mirroring the existing ones.
- Macro: capture `///` docs from each `#[msg]` method's `#[doc]` attributes
  (first paragraph is enough — join lines, truncate at the first blank line)
  and the actor struct's docs. Parse `#[msg(timeout_ms = N)]`.
  **Bump both `encode::<4096>` sites to `encode::<16384>`** — the emitted
  static is sized by the returned length (`[u8; ENCODED.1]`), so the buffer
  bump costs nothing in the binary; docs would overflow 4 KiB on doc-rich
  actors (messenger has 16 CLI methods).
- Dispatcher: `print_target_surface` prints the actor doc + first doc line per
  method; `print_method_surface` prints the full method doc. JSON variants
  gain `doc` fields. `invoke_dyn` honors `timeout_ms` when non-zero (use the
  existing `invoke_dyn_with_timeout`).
- `cli_cache.rs`: persist `doc` per method (additive TOML field, defaults
  empty on old caches) so `vosx --help` discovery shows one-liners.
- Gate: `cargo test -p vos metadata`; rebuild one PVM actor
  (`just build-registry`) and confirm `vosx <target> --help` shows docs
  against a live space (or via the existing meta-decode unit tests if no
  daemon in CI).

### Wave 1 gate

`cargo check -p vosx -p vos && cargo test -p vosx -p vos --lib` plus the
targeted tests above. `vosx --help` and dynamic dispatch smoke unchanged.

---

## Wave 2 — the job protocol + generic driver; retire `vosx ai generate`

### 2.1 `vos::jobs::JobQueue` + `#[msg(job)]`

- New module `vos/src/jobs.rs` (feature-light; must compile for extensions —
  `default-features = false, features = ["extension"]`). Provides
  `JobQueue` — rkyv-serializable state holding
  `{ id: u64, chunks: Vec<u8> (drained on poll), done: bool, error: String,
  released: bool }` entries + monotonic next-id. API:
  `begin() -> u64`, `push(id, &[u8])`, `finish(id)`, `fail(id, msg)`,
  `poll(id) -> (Vec<u8> data, bool done, String error)` (drains; a poll after
  terminal returns `done=true` + empty), `release(id) -> bool`, `prune()`.
  Unit-test the lifecycle (mirror `extensions/prover` `job_tests` style).
- Standard wire shape for `job_poll` replies: `vos::value::Args` with fields
  `data: Bytes`, `done: bool`, `error: Str` — this is exactly the ai
  extension's `GenerationChunk` shape today; reuse/blessing, not invention.
- Macro (`vos/vos-macros/src/lib.rs`): `#[msg(job)]` = the handler is a job
  *begin*: enforce return type `u64` (compile error otherwise), set a new
  per-message `mode` byte in metadata (new trailing section 4:
  `[count:u16][u8]*` index-crossref; `0 = sync`, `1 = job`). `ParsedMessage`
  gains `mode: u8`.
- Convention (documented in `extensions/AUTHORING.md`): an actor with any
  job-mode handler must expose `job_poll(job_id: u64) -> Vec<u8>` (the Args
  shape above) and `job_release(job_id: u64) -> u8`, typically delegating to
  its embedded `JobQueue`.

### 2.2 Generic job driver in the dispatcher

File: `vosx/src/commands/dynamic.rs` (+ small helpers).

- When the invoked method's metadata says `mode == job`: invoke it (gets
  `u64` id; `0` = refused → error), then loop `job_poll` at 100 ms
  (constants from `ai/generate.rs`: `POLL_INTERVAL`, `MAX_EMPTY_TICKS` ≈ 3 min
  wedge guard — lift them, delete there in 2.4):
  - text mode: stream `data` as lossy UTF-8 to stdout, flush per chunk;
  - `--out`: append raw bytes to the file;
  - JSON mode: collect until `done`, emit one object
    `{ "data": <utf8 or hex>, "error": ..., "chunks": n }`.
  - non-empty `error` at terminal → non-zero exit.
- On Ctrl-C/wedge-abort, best-effort `job_release` before exiting.

### 2.3 Migrate the prover extension

File: `extensions/prover/src/lib.rs`.

- Replace the hand-rolled `ProveJob` queue mechanics (`next_pending_index`,
  `job_status_of`, `job_result_of`, `release_job` and the `jobs`/`next_job_id`
  fields) with `JobQueue` + a retained per-job inputs list for pending work.
  `prove_chain_async` becomes `#[msg(job)] async fn prove_chain_job(...) ->
  u64` (or keep the name — executor's judgment; pick one and migrate ALL
  callers: grep `prove_chain_async|job_state|job_result|job_release` across
  `vos/tests/`, `actors/`, `extensions/`). `tick()` keeps advancing one job
  per tick (prover-specific execution strategy, unchanged), pushing the
  result via `queue.push(id, ..) + finish/fail`.
- Keep the `reply_to`/`reply_msg` callback (`ctx.tell`) — the federation flow
  uses it; jobs and callbacks coexist.
- `JobStatus` enum + `job_state` byte surface are superseded by `job_poll`'s
  `done`/`error` — delete them with their callers (memory note: JobStatus is
  wire-carried in persisted ProveJob; persisted-state compat is NOT required
  pre-release, but say so in the commit message).
- Gate: `cargo test -p prover-extension`; the async-jobs paths in
  `vos/tests/elf_integration.rs` (grep for the job tests) updated + green.

### 2.4 Migrate the ai extension + retire `vosx ai generate`

Files: `extensions/ai/src/lib.rs`, `extensions/ai/tests/e2e.rs`,
`vosx/src/commands/ai/*`.

- `begin_generate` → `#[msg(job, cli)] async fn generate(prompt, max_tokens)
  -> u64`; `poll_generation` → the standard `job_poll`; delete the old
  blocking `generate` (the driver's collect mode covers JSON consumers).
  Worker threads keep pushing chunks — now into the `JobQueue`
  (`push`/`finish`/`fail`) instead of `GenerationChunk` plumbing.
- Delete `vosx/src/commands/ai/generate.rs` + the `Ai` verb wiring for
  `generate` (keep `ai actor` compiling until Wave 3 removes the whole
  module; if `mod.rs` restructuring is annoying, retire the whole `ai` verb
  here and move `ai actor` retirement work into Wave 3's extension move —
  executor's judgment, but never ship a dangling verb).
- Remove `"ai"` from `BUILTIN_VERBS` when the verb goes.
- Migration UX check: `vosx ai generate prompt="hi" max_tokens=64` (dynamic
  path) streams tokens exactly as the old builtin did.
- Gate: `cargo test -p ai-extension` (adjust names), ai e2e updated.

### Wave 2 gate

All of: `cargo test -p vos --lib`, `-p prover-extension`, ai extension tests,
`cargo check -p vosx`. Behavioral: prover async e2e green; ai generate via
dynamic dispatch streams.

---

## Wave 3 — push orchestration into extensions; retire `dev` + `ai` verbs

### 3.1 `ai actor` moves into the ai extension

Files: `extensions/ai/src/lib.rs` (+ new module), delete
`vosx/src/commands/ai/` entirely.

- New `#[msg(job, cli)] async fn actor_change(project: u32, branch: String,
  prompt: String, apply: bool, max_tokens: u32) -> u64`. `project` is the
  dev-project instance ServiceId — the *client* resolves the name via
  `resolve_target` and passes the id (avoids adding name-resolution to the
  extension ctx; `ctx.ask_dispatch` to another local service is established —
  the dev extension already drives dev-project this way,
  `extensions/dev/src/lib.rs:24`).
- Move wholesale from `vosx/src/commands/ai/actor.rs`: branch-head resolution
  (head/`main` fallback), commit/blob reads, interesting-path filter +
  byte-cap truncation (`nearest_char_boundary`), `PROMPT_PREAMBLE` +
  `build_prompt`, the streaming loop (now: push model tokens into the job's
  chunk stream), and — most importantly — `parse_response`/`extract_path`
  **with all 14 unit tests**. Apply-mode writes
  (`open_change`/`put_blob`/`put_file_working`/`commit_change`) go through
  `ctx.ask_dispatch`. `ts_ms` via std time (native .so — fine).
- The job's chunk stream carries the generated text; the terminal chunk (or a
  final Args field) carries the apply summary (commit hash, files written,
  warnings). Keep warnings in-band, not lost.
- `default_ai_branch` needs the node prefix — pass it as an arg from the
  client (the dispatcher can't know it; simplest: make `branch` required and
  give the old default in the method doc) — executor picks, document in the
  method doc either way.
- Delete `vosx/src/commands/ai/`, the `Ai` verb, `"ai"` from
  `BUILTIN_VERBS` (if not already done in 2.4). Drop nothing from Cargo yet —
  `dev-project` goes in 3.3.

### 3.2 Richer dev-project/dev-extension replies (kill the N+1s)

Files: `actors/dev-project/src/*`, `extensions/dev/src/lib.rs`.

- dev-project (PVM actor) gains `#[msg(cli)] tree(commit: [u8;32]) -> Args`:
  per-file records (path, size, blob short-hash) — kills `dev show`'s
  N+1 `get_blob` size probes (`show.rs:259-272`, the code already asks for
  this in a comment).
- dev extension `compile` reply carries build success + artifact hash
  directly (today's `HashResult.status` conflates "recorded" with "build
  ok", forcing the CLI's second `get_commit` round-trip — `compile.rs:116-138`).
- dev-project `merge` reply gains `fast_forward: bool` + inline conflict
  records (kills the CLI's third round-trip + `extras.is_empty()`
  interpretation — `merge.rs:133-146`).
- `log` returns `ListStr` of hex hashes (kills the hand-rolled 32-byte
  splitter — `log.rs:44-49`).
- Replies use the Args-record convention (decision 5). If the macro doesn't
  yet support `-> vos::value::Args` returns, add it: encode via `.encode()`,
  metadata `returns = "Args"`, and teach `render_reply` to pretty-print
  Args-typed Bytes replies (key: value lines in text mode, object in JSON).
- **Rebuild gotcha**: dev-project is a PVM actor — rebuild via its justfile
  recipe (`cargo +nightly actor` pattern, see `justfile` build-msg-actors) and
  refresh `vosx/blobs/dev_project.elf` (add a `refresh-bundled-dev` recipe
  mirroring `refresh-bundled-registry`, justfile:97-105). Stale-ELF symptoms
  waste hours — rebuild FIRST when tests act stale.

### 3.3 Retire the `dev` verb

- Migration surface (document in README/book migration table):
  - `dev new` → `vosx space publish <elf-path-or-hash>` + `vosx space install
    <name> --in name=<x>` (both already exist; `publish` already resolves
    `BlobSource::Path`, `install.rs` already takes typed `--in` init args).
    Add a `--bundled dev-project` sugar to `space publish` that resolves the
    baked-in blob (`bundled::dev_project_elf()`), preserving the
    works-out-of-the-box flow. The publish-if-absent idempotency checks move
    into that path.
  - `dev compile|publish|log|show|merge` → `vosx dev compile project_id=…`
    etc. (the dev *extension* instance is named `dev` — verb shape barely
    changes; `show <file>` becomes `vosx <project> get_blob hash=… --out f.rs`
    or `tree`).
- Delete `vosx/src/commands/dev/`, the verb, `"dev"` from `BUILTIN_VERBS`;
  drop `dev-project` from `vosx/Cargo.toml`.
- Gate: `cargo tree -p vosx -e normal | grep -c dev-project` → 0.

### 3.4 Subsume `space call`

`space/call.rs` (132 lines) + `payload_codec.rs` (67) duplicate the dynamic
dispatcher with a worse arg surface. Replace `space call`'s implementation
with a forward into the dynamic path (or delete the verb with a migration
note — executor checks test usage: grep `space call` in `vosx/tests` and docs
first). Keep `payload_codec` only if something else imports it.

### Wave 3 gate

Full: `cargo check -p vosx && cargo test -p vosx`, dev extension + dev-project
tests, ai extension tests, `just build-actors` clean, and the e2e suites that
exercise dev/ai flows. `vosx --help` shows only kernel verbs + discovered
targets. README/book migration table updated.

---

## Wave 4 — system-actor protocol into `vos`; drop the last actor deps

### 4.1 `vos::registry` protocol module

Files: new `vos/src/registry.rs` (fold `vos/src/registry_canon.rs` into it),
`actors/space-registry/src/lib.rs`, `vosx/src/commands/space/*`.

- Move into `vos::registry`: rows (`ProgramRow`, `AgentRow`, `MemberRow`,
  `AuthGrantRow`, `ActorAclRow`), `Status`, the role/kind consts
  (`AUTH_ROLE_*`, `NODE_ROLE_*`, `MEMBER_KIND_*`, `PROOF_KIND_*`),
  `REGISTRY_OP_DOMAIN`, `OP_SIG_LEN`, `canonical_op_bytes`, `pack_auth`,
  `ed25519_pubkey_from_peer_id`, `binding_signed_bytes`. All derive only
  `vos::rkyv` — verified movable. **`verify_op_sig` stays in the actor**
  (verifier-side crypto; keeps its dep out of vos). The `op_sign.rs` test
  that uses it moves to the space-registry crate.
- space-registry imports these from `vos` and `pub use`s them (its public API
  unchanged). This **deletes** the `registry_canon` mirror + its drift-pin
  cross-check test (`registry_canon.rs:176`) — the mirror existed only
  because of the dependency cycle; moving the source of truth to vos ends it.
  `sign_catalog_op_on_relay` and the node wiring stay in vos, now calling the
  canonical fns directly.
- vosx: `DaemonClient`'s `registry()` Ref wrappers (`client.rs:336-630`)
  become `invoke_dyn` calls decoding `vos::registry` rows; the genesis driver
  in `space/new.rs:100-151` builds its gated ops with `canonical_op_bytes` +
  dynamic invokes instead of `SpaceRegistryRef::at`. Behavior-identical: the
  Ref emitted the same `TAG_DYNAMIC` Msg.
- Drop `space-registry` from `vosx/Cargo.toml`.
- **Caution**: `canonical_op_bytes` field order is consensus-critical for
  signed ops — the move must be byte-identical (keep the existing tests,
  moved, plus the registry e2e). Run the messaging/registry e2e suites.

### 4.2 chronos protocol + feeder into `vos`

Files: new `vos/src/chronos_feed.rs` (+ `vos::chronos` proto types),
`actors/chronos/src/*`, `vosx/src/commands/space/up.rs`.

- Move wire types/consts the feeder needs into `vos::chronos`:
  `AdvanceOutcome`, `Status`, `MAX_SLOT_JUMP`, `encode_committee`, the slot
  math consts (`CHRONOS_SLOT_MS`, `VOS_COMMON_ERA_MS` — locate in
  `actors/chronos/src/consts.rs`). chronos re-imports from vos (cycle-safe).
- Move `ChronosFeeder` (`up.rs:789-1209`, incl. `CaptureInvoker`) wholesale
  into `vos` behind the `network`+`storage` features; convert its `ChronosRef`
  calls to dynamic `Msg` invokes decoding `vos::chronos` types. The `vrf` dep
  moves `vosx → vos`. vosx keeps only the wiring: derive-seed + construct
  feeder + the 1 s `run_forever_with` cadence (or expose
  `VosNode::enable_chronos_feed(...)` — executor picks the smaller diff).
- Drop `chronos` and `vrf` from `vosx/Cargo.toml`.
- This is daemon-role code moving into the daemon *library* — the prep for a
  future vosx/vos-daemon binary split, not a semantic change. The feeder's
  protocol behavior (leader clamp, entropy skip, enrol/reveal idempotency)
  must not change; its unit-testable pieces keep their tests.

### 4.3 Generic operator-signing flow (replaces `messenger_register`)

Files: `vos/src/actors/metadata.rs`, `vos/vos-macros`, `actors/messenger/src/*`,
`vosx/src/commands/dynamic.rs`.

- Metadata trailing section 5: per-message bind spec — for a method declared
  `#[msg(cli, then_bind = "bind_identity")]`, record
  `(method, bind_method)`. Driver flow on invoking such a method: invoke it →
  reply is the challenge (**change messenger `register` to reply
  `Value::Bytes(mls_pubkey)`** instead of the `"mls_pubkey=<hex>"` string) →
  sign `vos::registry::binding_signed_bytes(challenge, operator_peer,
  space_id)` with the operator identity key → invoke `bind_method` with the
  conventional fields `peer_id`, `space_id`, `cert`. Delete the
  `messenger_register` special case (`dynamic.rs:107,166-215`).
- Messenger actor rebuild + its registration e2e updated (reply-shape
  change). Existing deployed bindings are not a concern pre-release.
- **Deferrable**: if messenger work is in flight elsewhere, this item may be
  skipped without blocking 4.1/4.2 — it removes the *last* hardcoded flow but
  is independent.

### Wave 4 / final gate

- `cargo tree -p vosx -e normal | grep -cE
  "space-registry|chronos|dev-project|vos-shell|vrf "` → 0, and no
  `workspace = true` deps in `vosx/Cargo.toml`.
- Full suites: `cargo test -p vosx -p vos` (note: `elf_integration` is heavy;
  federation paths document `RUST_MIN_STACK=268435456`), extension crates,
  messaging e2e (4.1 touches signed-op encoding paths), `just build-actors`.
- Smoke the whole kernel surface: `space new/up/install/publish/members/role`,
  `run`, `whoami`, `zk pin --help`, dynamic `--help` for ai/dev/prover/
  messenger targets.

## Follow-ups (not this plan)

- Daemon binary split (`vos-daemon`); vosx becomes pure client.
- zk pin catalog into the registry/CAS; pin as dev-extension pipeline;
  transpile-as-a-service question.
- `#[msg(job)]` queue generation fully in the macro (auto-embedding the
  `JobQueue` field) once a third consumer exists.
- Field-level docs (needs an attr syntax — fn params can't carry `///`).
- Per-extension timeout/policy in the space manifest.

## Command migration table (keep in README when waves land)

| Before | After |
|---|---|
| `vosx ai generate --space s --prompt p` | `vosx ai generate prompt=p [--space s]` |
| `vosx ai actor --project x --prompt p --apply` | `vosx ai actor_change project=<id> prompt=p apply=true` |
| `vosx dev new --name x` | `vosx space publish --bundled dev-project && vosx space install dev-project --name x --in name=x` |
| `vosx dev compile/publish/…` | `vosx dev compile …` (dynamic; same verb shape) |
| `vosx dev show --file f > f.rs` | `vosx <project> get_blob hash=… --out f.rs` / `vosx <project> tree commit=…` |
| `vosx space call <space> <agent> <m> …` | `vosx <agent> <m> k=v [--space s]` |
| `vosx space console` | removed (future shell extension) |
