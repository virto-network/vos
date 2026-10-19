# Slice 6: stale statements to fix in the design docs

Against `vos-core` at `31b7938e`. Paths are under `docs/design/`. Each item
names its place, the stale statement, and the replacement text or what it
waits on:
- **[now]:** applied at 6.0d;
- **[decision N]:** the plan's owner decision N, taken on 2026-10-19, so
  applied at 6.0d with the decision's outcome, which the item states;
- **[step 6.x]:** applied by that step, when what it describes is built.

Decision numbers are the plan's (draft 3). The plan's drafts folded in
Fable's review of draft 1 (the FRI mask at 8 columns, the rootless `Seen`
rule, the JAM proof transport) and the owner's decisions (time between
parties is the venue's; Kreivo is a spaces pallet the Kreivo teammate
builds from `spaces-pallet.md`, with a sovereign account per space and an
authorities map).

Numbers are the spikes' (`research/slice-6/` after 6.0d): spike 6a (the
masked wrap), 6b (the security tool), 6c (Kreivo), the design round on
roots and its review.

## `proving.md`

1. **Header, "Design, draft 5"** [step 6.22]. Draft 6, history line: "draft
   6 folds slice 6's spikes (6a–6c), its design round on roots and anchors,
   and Fable's review of it".
2. **§1, "a public JAM agent, later"** (l.29) [now]. Replace with "a JAM
   statements service, a dedicated service whose refine verifies and whose
   accumulate records (slice 6)".
3. **§3.2, "the whole input is capped at 4 MiB, a work result's cap"**
   (l.196) [now]. Replace with: "the caller's arguments are capped by
   `Limits::attest` (64 KiB on VOS, 2 KiB on JAM); a statement's served
   witness travels as a blob by hash, under `Limits::served` and the
   kernel's declared gas (slice 6); 4 MiB stays the ceiling of the
   kernel's whole input". **Amended by 6.0a** [step 6.13]: the served
   witness travels inline in the `Resume` input, under `Limits::served`
   (128 KiB on VOS, JAM's own) and the kernel's declared gas; the text
   applied at 6.0d (a blob by hash) is replaced with it.
4. **§3.5, "Masked with variant (c), in slice 6 … masking takes a new
   final format"** (l.361-362) [now]. Replace with: "Masked as format 39
   (variant (c), A.4): blowup 32, 24 queries, PoW 26, interaction PoW 8,
   fold step 3, a 2^6 last layer, affine DEEP batching; 146 / 82 (82.70)
   [model]. Format 28 stays a test format."
5. **§3.5, "Kreivo's host and VOS's precompile both serve Blake2b"**
   (l.365) [now]. Replace with: "VOS's `0x400` serves a Blake2b compression
   and Kreivo's host `blake2_256` the whole-message hash; JAM serves no hash
   (Gray Paper 0.8.0 has no hash host call), so a JAM verifier hashes in
   software. On Kreivo the host hash would shorten ref_time, but proof_size
   binds a block and length sets the fee."
6. **§3.5 "Cost [model]", "117–119M masked" and "2.2–4.9 GiB to prove"**
   (l.366-371) [now]. Replace the masked line with the measured masked
   wrap (spike 6a, shape A, postcard): "115.8–118.7M JAM gas (decode 19.9M,
   verify 95.8M), 45.2M Wasm instructions, 160–163 KB, 3.45 GiB of heap and
   11.6–15 s to prove [measured]; about 98M with format 39's fixed-layout
   decode [est]". Drop the 2.2–4.9 GiB projection (2.5 GiB measured
   unmasked).
7. **§3.5 "Built", "the levers left: a fixed-layout decode … and Blake2b
   through `0x400`, which needs a compression hook"** (l.380-382)
   [decision 4]. Replace with: "format 39 decodes a fixed layout; the
   Blake2b hook is deferred, a lever for when ref_time binds: nothing in
   slice 6 verifies as a PVM guest on a VOS host, and Kreivo's binding
   limit is proof_size".
8. **§3.6, the `public_args` comment, "the kernel's #[public] arguments"**
   (l.396) [step 6.13]. Add the rule: "the SCALE encodings, in order, of
   the venue (a venue-bound program), the reader `(AgentId, InstanceId)`
   (a `&self` method), and each `#[public]` argument".
9. **§3.6, "A kernel that does not state its roots … The window kernel is
   one, until the SDK puts …"** (l.443-448) [step 6.15]. Replace with: "the
   window kernel states its root since slice 6 (6.15): it reads at one
   anchored cut and carries the last settled state as a `#[public]`
   commitment".
10. **§3.6, the venue's check, "the format (accepted, and 28, the one the
    final verifier reads)"** (l.455-456) [step 6.5]. Replace with: "the
    format, in the venue's accepted set (production venues accept 39
    only); the program against the pin; the venue, for a venue-bound
    program; …". Add `Refusal::Venue` (`0x7`).
11. **§3.6, the crates** (l.502-518) [step 6.10, 6.19]. Add `vos-anchor`
    (`pvm/proof/anchor`: `SpaceId`, the genesis, the window clock, root
    kinds, anchors and their digests, no_std) and `vos-statement-service`
    (`pvm/proof/statement/service`, the JAM venue).
12. **§4's table, the wrap's row** (l.545) [now]. Keep 28's row, relabelled
    "the final wrap, unmasked (28; tests only)"; add "the final wrap,
    masked (39) | ≥ 100 / ≥ 80 | blowup 32 (log 5), 24 queries, PoW 26,
    plus interaction PoW 8; fold step 3, last layer 2^6; affine DEEP
    batching; variant (c) | 146 / 82 (82.70)".
13. **§4, the audit's scope** (l.582-597) [now]. Add "the masked wrap's
    transcript and R1–R4, and the lifted protocol under (c) (spike 6b §4)".
14. **§5, "Where: device proofs, and the final wrap"** (l.603-604) [now].
    Replace with: "Where: the final wrap (slice 6). Device proofs (slice 7)
    reuse it: the masking is generic over the component set and the
    channel."
15. **§5, items 2 and 3 (R2, R3)** (l.610-611) [now]. Item 2: "claimed
    sums blinded: one blinding QM31 a component on one row, through a
    `BlindRelation` drawn after `Gate`; the wrap's public sum is the 24
    words and `u`, so its boundary re-cut is trivial". Item 3: "the FRI
    mask's rank: under affine batching each of R's columns gets its own
    QM31 coefficient, so a 4-column R is singular about 2^-31 an attempt;
    R takes 8 columns, whose coefficients span M31^4 except with
    probability about 2^-155, with no prover check (the rank test runs on
    a small circuit only)". Item 1 adds: "the prover retries on R1's
    failure, a public event that leaks nothing".
16. **§5, after "The composition mode"** (l.618-620) [now]. Add the
    measured factors: "On the wrap (spike 6a): no re-LDE [measured]; the
    prover ×2.6–2.9 in time (the lifting rises to 22, and Blake2b Merkle
    hashing of the doubled leaf layer dominates), ×1.41 in memory; verify
    ×1.20, bytes ×1.31. Shape A's preprocessed root is format 28's."
17. **§6, Kreivo, "Its home: frame-contrib, to be confirmed in slice 6"**
    (l.671) [decision 9, 12]. Replace with: "`pallet-spaces`, in Kreivo,
    built by the Kreivo teammate from `spaces-pallet.md`, to replace
    pallet-communities later; the verifier stack vendored into Kreivo with
    a sync check against a VOS tag (VOS's kit, slice 6's 6.16);
    frame-contrib and crates.io later".
18. **§6, Kreivo, "Built-in handlers: `Record` … and `Credential`"**
    (l.668-670) [decision 10]. Replace with "`Record`; a `Credential`
    handler with slice 7's credential AIR; the Clerk's settlement handler
    with the Clerk. Every value-moving handler is two-sided or spends the
    submitting space's own escrow."
19. **§6, Kreivo, the registries and `submit`** (l.627-648) [decisions
    10–12; step 6.16]. Rewrite after `spaces-pallet.md`: a space registered
    from its genesis, with a **sovereign account** that holds the
    registration deposit and pays its authorities' fees and deposits; an
    **authorities map** of the nodes' own sr25519 accounts, each paired
    with its ed25519 anchor key, set by the controller (an `AccountId`);
    `submit` with a refundable deposit, released on acceptance or a
    repeat, forfeited on any other refusal; normal length and weight fees,
    paid by the sovereign account through `ChargeSpaceFee` within a
    spend budget per window; a registration that signs its first window;
    the
    venue-bound flag; the migration range; `MaxRootAge` (24 h) as the only
    age; anchors keyed by `(space, kind, window)`; "a proof's length counts
    as proof_size, so about 20 statements fit a block on one core"; **the
    repeat rule**: a rootless statement's `Seen` entry never expires, since
    it has no anchor whose age refuses a replay; **the node's Kreivo
    client**: the representative and the worker anchor and submit through
    a `VenueClient` signing with the node's own sr25519 key, which holds
    no balance. The weights and benchmarks are the teammate's.
20. **§6, "The JAM agent"** (l.672-675) [now]. Replace with: "**The JAM
    statements service** (slice 6): a dedicated service; refine verifies
    anchors' signatures and statements (about 100M gas a statement; a
    report's accumulate has 10M); accumulate holds the spaces, anchors and
    repeats, and records, checking an anchor's signer against the space's
    registered keys and keeping a rootless statement's `Seen` entry
    forever, as Kreivo does; accepted program ids are constants changed by
    redeploy; a proof rides in its work item's payload (or as a preimage,
    if 6.0b found the payload cannot carry it). An actor in the default agent
    cannot host it: `MAX_HANDLER_GAS` 100M, a 512 KiB program cap
    (538,683 B with both formats linked), 2 KiB messages, no preimage
    access." **Amended by 6.0b** [step 6.19]: the statement rides in its
    work item's payload and the proof as the item's extrinsic (JAM-NP CE
    133 caps a package at 204,802 B); the default agent cannot host it for
    `MAX_HANDLER_GAS` (118.7M against 100M) whatever its bytes (the
    masked-only verifier is 500,205 B, under 512 KiB). The text applied at
    6.0d is replaced with it.
21. **§7, "a few dozen more compressions per statement"** (l.682)
    [step 6.13]. Replace with 6.0a's measurement: the path 14
    compressions (+1 for `S_w`) and 590 B at 1,024 agents, a row 19.07
    compressions and 842 B [measured] (the estimate was about 13 and
    0.45 KB).
22. **§7, "Latency … The window length Kreivo runs is decided in slice 6"**
    (l.686-687) [decision 2]. Replace with: "windows are Unix time from the
    space's genesis, `w = ⌊(t − origin)/length⌋`, the clock frozen in the
    genesis; the length per space in [2, 60] minutes, default 10. **Time
    between parties is the venue's:** every expiry, timeout or exposure
    deadline between parties uses the venue's chain time, never a window
    number or the space's clock; the space's clock schedules only its own
    cuts, and a venue anchors only windows closed by its own clock
    (`w < now_w`). **Latency:** authorization across spaces is instant
    (the counterparty credits within its exposure cap); trustless
    settlement takes about `L/2 + D + t_prove + inclusion`, about 10
    minutes on average at L = 10; parallel proving is the lever below
    that."
23. **§7, "Root kinds: A JAM-deployed agent's maps are subtrees of one
    tree, so roots differ by host. A chain accepts only root kinds that are
    the same on both hosts."** (l.693-696) [decision 5]. Replace with:
    "Committed rows sit first in the keyspace, under `0x03`, so an agent's
    root is the same on both hosts: VOS's tree per agent equals JAM's node
    at `0x03`. `RootKind { Space = 0 }`; 1 is reserved for the Poseidon2
    kind (§8)."
24. **§7, new bullets** [decisions 1, 6, 7; step 6.14]: `SpaceId` (the
    genesis hash); the representative and `S_w`'s preimage; anchors signed
    by one registered node key; retention none past a cut and a request
    served at the next cut; spans by a carried commitment, not by an old
    root; "an anchor gives ordering and non-equivocation, not integrity".
25. **§10, the masking row** (l.799) [now]. Mark "measured (spike 6a):
    3.45 GiB of heap, 115.8–118.7M gas; the gate is 6.3–6.6". Add rows:
    the cut and held build under failover (6.12); the worker against the
    window cadence (6.18); the teammate's pallet against the conformance
    vectors (6.17); a deadline read from a space's clock; a forgery in the
    recursion AIR (6.8).
26. **§11, M2's row, "R1–R8 on the wrap and on device proofs … 6–8
    weeks"** (l.809) [now]. Replace with "R1–R8 on the final wrap, generic
    over components and channel for slice 7; format 39; 248-bit salts;
    leakage and soundness gates"; the estimates from the slice-6 plan
    (M2 about 8.5–13 engineer-weeks with the carried items, M3 about
    18.5–29 with the Kreivo kit and client; the pallet is the Kreivo
    teammate's), and the total recomputed. M3's row: "the Kreivo spaces
    pallet's design, the verifier kit and the node's client" in place of
    "the Kreivo pallet (P0 and P1)".
27. **§11, "production hardening (the audit, masking) is slice 6"**
    (l.819-820) [now]. Replace with "masking is slice 6; the external
    audit's timing is the owner's (`slice-5-progress.md`)".
28. **§12, "Deferred: Kreivo's window length (slice 6), and the pallet's
    home (slice 6)"** (l.851-852) [decisions 2, 9, 12]. Move each into the
    decisions taken, with their outcomes (items 17 and 22).
29. **A.4's table, 28's row "(unmasked until slice 6)"** (l.956) [now].
    "the final wrap, unmasked (tests only)"; add 39's row (blowup 5, 24,
    26, 3, 6, 8, affine; 100 / 80; 146 / 82; reserved, admitted at 6.4).
30. **A.4, "Masking the wrap (slice 6) changes its proofs, so it takes a
    new number or a bump of 28."** (l.980-981) [now]. Replace with:
    "Masking takes a new number, 39: a bump of 28 would break 'a number
    names one AIR and one set of parameters'. 40, spike 6a's blowup-64
    shape, is retired unregistered; 38 stays unassigned, the fixtures' 'a
    number no format holds'."
31. **A.4, the retired list** (l.982-986) [step 6.1, 6.9]. Add 40 and 36
    (decision 3), and drop 36's row from the table.
32. **A.5, "Slice 6 adds the window, then the final proof's hash."**
    (l.998) [step 6.13]. Replace with the record:
    `Attest { program, window, witness_input, output, public_args, roots }`,
    `witness_input` the arguments ‖ the served witness for an at-cut
    attest (6.0a: inline, not a blob by hash); the final proof's hash
    arrives as a `Proven { id, proof }` input.
33. **A.6, "slice 6's masked format adds the case the other way round"**
    (l.1050-1051) [step 6.5]. Replace with: "the transition runs both ways
    between 28 and 39 under the test policy; production venues accept 39
    alone", and list the adversarial cases (a field of the id or io-hash
    changed).
34. **A.6, "(about 1.2 MB)"** (l.1017-1018) [now]. Replace with "about 380
    KB, plus the segment fixtures".
35. **A.7, the wrap's row** (l.1070) [now]. Add the masked budget: "39: ≤
    8 GiB; 3.45 GiB of heap [measured]; ≤ 15 s, 11.6 s [measured]".

## `recursion-air.md`

1. **§0 item 7, "117–119M masked"** (l.71) [now]. Replace with "115.8–118.7M
   masked with postcard [measured, spike 6a], about 98M with format 39's
   fixed layout [est]".
2. **§7's table, "memory, time: … ×1.56–1.6 masked (c): 3.5–7.8 GiB"**
   (l.675) [now]. Replace the masked part with "masked (format 39):
   3.45 GiB of heap (×1.41), 11.6–15 s (×2.6–2.9) [measured]".
3. **§7's table, "JAM gas, masked: 117–119M (×1.37–1.40) projected"**
   (l.677) [now]. Replace with "115.8–118.7M (×1.21–1.24) [measured]; the
   toy's ×1.37–1.40 overestimated".
4. **§7's table, "proof: … 164–170 KB masked"** (l.678) [now]. Replace
   with "160–163 KB masked [measured]".
5. **§8, "through the host (VOS `0x400`, Kreivo's `blake2_256`) once the
   fork's hasher takes a compression hook (slice 6)"** (l.715-716)
   [decision 4]. Replace with the decision; state that JAM serves no hash.
6. **§8, "postcard's decode, 16.0M of its 96.4M gas, until a fixed-layout
   decode (slice 6"** (l.720-722) [step 6.4]. Replace with "format 28 keeps
   postcard (16.0M of 96.4M gas); format 39 decodes a fixed layout".
7. **§8, the masked verifier** [step 6.4]. Add: "format 39's verifier runs
   over `CommitmentSchemeVerifier::{commit, verify_values}`, never
   `core::verifier::verify` (whose composition split is hardcoded,
   DIVERGENCE-004), and names the two facts it leaves to Stwo, each pinned
   by the format (the tree widths, 57 / 381 / 48 / 20; the FRI round list
   `[3, 3, 3, 2]`); R has 8 columns, so it needs no rank check; a
   production venue links 39 alone; both formats linked are 538,683 B as a
   PVM program."
8. **§10, "production hardening (the audit, masking) is slice 6"**
   (l.807-808) [now]. As `proving.md` item 27.
9. **§11, R13, "Masking the wrap (slice 6) costs more than (c)'s ×1.6"**
   (l.828) [now]. Replace the measurement column with "spike 6a, measured:
   memory ×1.41 and gas ×1.21–1.24, within the gate; time ×2.6–2.9, above
   the toy's ×1.6, from Blake2b Merkle hashing at a lifting one level
   higher".
10. **§1.2, "masking variant (c) applies unchanged"** (l.129) [now]. Add:
    "its blinding columns live in a wrap-only variant (`MaskedEval`), never
    in the shared components, so format 32, `H_fold` and every program id
    stay as they are".

## `core-model.md`

1. **§9.2's table, the `#[attestable]` row** (l.642) [step 6.13]. "May
   write": "nothing (writes, 'the root after', are not built)"; "May read":
   "its arguments, and, as `&self`, committed fields through a served
   witness at an anchored window cut, its read set declared".
2. **§9.3, "Proofs are served against a map's last complete root"**
   (l.700) [step 6.12]. Add: "and, for a statement, against the agent root
   at a window cut, generated by the held build".
3. **§9.3, "An attest waits for the root at its window's version."**
   (l.704) [step 6.12]. Replace with: "A statement requested in window w
   reads at `cut(w)`: the builder holds at each pending cut, node-local
   `undo` rows keep values overwritten before the cut's build reads them,
   and the proofs are persisted with the cut. Nothing is kept past a cut."
4. **§9.3, "No global state root on VOS. Agents deployed on JAM keep one,
   over their whole keyspace."** (l.709-710) [decision 5]. Replace with:
   "Every agent has a root on both hosts: committed rows sit under `0x03`,
   VOS keeps one tree per agent over them, and that tree is the node at
   `0x03` of a JAM agent's whole-keyspace tree. A space has a root per
   window, built by its representative (`proving.md` §7)."
5. **§11.1, "Inputs (private): … delivered as witnesses (rows plus a
   `BatchProof` against `CommittedMap` roots)"** (l.888-891) [step 6.13].
   Replace with: "a served witness: the rows and one multiproof against the
   agent root at the cut, and the path to the space root".
6. **§11.1, "Outputs: public: the return value, the roots before and
   after, and the program hash; private: its writes …"** (l.892-896)
   [now]. Replace with: "public: the statement, its program id, space,
   `#[public]` arguments, output and the roots it read
   (`proving.md` §3.6); writes are not built".
7. **§11.1, "The agent records the program hash, the witness and the
   output"** (l.899-901) [step 6.13]. Replace with the record's fields
   (`proving.md` A.5).
8. **§11.1, "Proofs are content-addressed and attached to messages for
   other spaces or JAM."** (l.903-904) [step 6.18]. Replace with: "the
   space's prover worker proves each anchored statement and submits it to
   the space's venue".
9. **§11.1, "The settlement verifier takes 10.68M instructions and about
   29M gas … one segment (slice 1). A whole window needs aggregation"**
   (l.910-912) [now]. Replace with: "A window's segments fold into one
   final proof (slice 5): 96.4M JAM gas unmasked, about 116–119M masked
   with postcard [measured], verified in a JAM statements service's
   refine."
10. **§11.3, "Prover memory per segment ≈ 4.6 GiB + …", "Proving time ≈ 2 s
    plus 80 µs per step", "Proofs are about 0.6–0.9 MiB per segment"**
    (l.951-958) [now]. Mark as the S5 measurements of the retired formats
    and point to `proving.md` A.7 and `slice-5-progress.md` "Measured"
    (format 35: a class-1 segment 6.7–10.7 s at 4.79 GiB of heap).
11. **§11.4, "Not hiding. The pinned Stwo revision has no zero-knowledge
    masking"** (l.981-983) [step 6.6]. Replace with: "The final proof is
    masked (format 39, variant (c)); segment, leaf and fold proofs are not,
    and never leave the prover role."
12. **§11.4, "Witness-free verification is incomplete …
    `verify_refine_bundle_authenticated` … replay required"** (l.984-988)
    [decision 3]. Replace with: "A statement's final proof binds the whole
    run (its entry, its halt and its io-hash); the refine-bundle path
    (format 36) is retired, and deleted".
13. **§11.4, "The arguments are exposed by commitment"** (l.989-990) [now].
    Replace with: "No plain hash of private inputs leaves: the io-hash
    covers the public arguments, the output and the roots."
14. **§11.4, requirements 4–6** (l.1001-1012) [now]. Mark each met:
    4 by the statement and format 39; 5 by the shape per kernel and the
    padded fold shape; 6 by the recursion (slice 5).
15. **§12, "the builder is trusted for the batch's content until proofs
    (slice 5)"** (l.1069-1070) [now]. Replace with: "the builder is trusted
    for the batch's content; statements are verified by the statements
    service (slice 6), batches are not proved".
16. **§12, "Next: the per-space aggregate-balance agent … once the privacy
    track's aggregation exists"** (l.1151-1152) [now]. Replace with "the
    Clerk's settlement follows slice 6".
17. **§16, items 9–12** (l.1318-1325) [now]. Mark 9 and 12 done (masking in
    slice 6, aggregation in slice 5), 10 and 11 done by the statement and
    the shape per kernel.
18. **§18, Q6 and Q7** (l.1415-1417) [now]. Strike both, pointing to
    `proving.md` §5 and `recursion-air.md`.

## `identity-and-authority.md`

1. **§11, "its representative agent keeps a space-level root over its
   agents' roots, per window"** (l.408-410) [decisions 1, 2, 7; step 6.14].
   Add the design: windows of Unix time from the genesis; the
   representative's committed map keyed `(agent, kind, w)`, cut at
   `B_w + D`; `S_w`'s preimage.
2. **§11, "the space's own builder submits its space-level root"**
   (l.415-416) [decision 7]. Replace with: "the representative's leader
   signs the anchor with one registered node key and submits it to the
   space's one anchor venue: on Kreivo through the node's own sr25519
   authority account, the space's sovereign account paying
   (`spaces-pallet.md`; a budget per window bounds what a compromised
   node key can spend); or the JAM statements service". Add: "A venue
   anchors only a window its own clock has closed; every deadline between
   parties is the venue's time."
3. **§11, the cost: "an anchor is a work package per window per space, a
   few million gas; a claim verified on chain also pays its verifier,
   about 10.7M cycles for the settlement verifier measured in slice 1"**
   (l.418-421) [now]. Replace with: "on Kreivo an anchor is a ~170-byte
   extrinsic, a statement about 4 ms of ref_time unmasked [measured] and
   about 0.43 UNITS of length fee, plus a refundable deposit, all paid by
   the space's sovereign account; on JAM a statement is about 100M gas of
   refine".
4. **§11, "'this root is in the sequence' is a witnessed read in the
   representative agent's state"** (l.422-423) [now]. Add: "on JAM, later;
   on Kreivo the pallet stores the anchors".
5. **§11, "Masking (the pinned Stwo has none) therefore leads the prover
   track …, with hiding commitments for public outputs, fixed proof shapes
   and aggregation after it."** (l.432-434) [now]. Replace with: "The
   final proof is masked (format 39, slice 6); aggregation (the recursion)
   and fixed shapes came first, in slice 5."
6. **§8, "a pool on JAM verifies every spend in refine, about 10.7M cycles
   each today, so about 90 spends fit a package"** (l.343-345) [now].
   Replace with "a final proof costs about 100M gas of refine, so about 50
   fit a work package's 5e9".
7. **§12, "A registry agent on JAM"** (l.438-446) [decisions 9–12]. Add
   first: "Kreivo's `pallet-spaces` (`spaces-pallet.md`, built by the Kreivo
   teammate, to replace pallet-communities later) holds the first
   registry: spaces registered from their genesis, each with a sovereign
   account and a map of its authorities, formats and programs with a
   7-day delay under the Virto community; the JAM statements service holds
   its own; a JAM registry agent comes later." §12's "A space's own keys
   … rotate by a governance decision" gains: "on Kreivo, the controller
   (an `AccountId`) rotates the authorities and anchor keys".
8. **§14, "Postponed: … the device prover (§8)"** (l.511) and §15 (l.563)
   [now]. Replace "the device prover" with "the holder-side prover for
   personal spaces"; the credential AIR and the device profile are slice
   7's (`proving.md` §8).

## `research/slice-5/kreivo-pallet.md`

A research record: leave its body, and add a note at the top [now]: "The
built venue, slice 6's plan and `spaces-pallet.md` (the pallet's handoff
design, which replaces this note's pallet) supersede parts of this note:"
with these items.

1. **§1, Kreivo's facts** (e4b2af3, stable2603, velocity 12, 500 ms
   blocks): Kreivo master `87f8728` runs stable2606-2 from crates.io,
   velocity 3 (2 s blocks) with block bundling; one core gives about
   666 ms and 3.33 MiB a block.
2. **§2, the interface:** the built `Statement` is `{ format: u32, program:
   ProgramId ([u32; 8]), space, public_args, output, roots }`, with no
   `shape_class`; `io_digest` is the io-hash; the id is
   `H("vos/statement/v1" ‖ program ‖ space ‖ io_hash)`, without the format.
3. **§2, `RootKind { SpaceWindow = 0, Carried = 1 }`:** `{ Space = 0 }`,
   1 reserved for Poseidon2; `Carried` retired by the carried commitment
   [decision 6].
4. **§1 and §2, the check order's "the program taken from the proof"
   (modesto's):** the program id is the venue's pin, never the caller's or
   the proof's.
5. **§3, "Programs are tied to one format, since the id includes the
   channel" and §7's migration by new ids:** the program id covers the
   segment format, not the final one; a venue accepts final formats as a
   set.
6. **§4, the clock "RelaychainData's block number / WindowLength" and
   `AnchorGrace`:** Unix time from the space's genesis [decision 2];
   `MaxRootAge` alone.
7. **§4, "chain-bound attests read the agent root at the last window
   cut":** they read to the space root.
8. **§6, the 250 ms weight placeholder and `MaxProofLen = 512 KiB`:**
   3.99 ms measured unmasked on a laptop (×1.3–1.4 masked [est]);
   `MaxProofLen` 256 KiB; a proof's length counts as proof_size, so about
   20 a block on one core, and length sets the fee (about 0.43 UNITS a
   proof).
9. **§7, `PROOF_FORMAT_VERSION` 24/25 as a cargo feature:** formats are
   chosen at run time from the registry.
10. **§8, the toolchain and pin ("vos-core pins stwo e1286720"):** the pin
    is olanod/stwo `ab294189`; the stack builds on Kreivo's stable 1.94.1
    for `wasm32v1-none` with no change and adds 75.7 KiB compressed
    [measured, spike 6c].
11. **§9's table, "Blake2s: software in Wasm":** Blake2b-256; JAM serves no
    hash.
12. **§10 Q11, "P2: the Clerk handler (slice 6)":** the Clerk follows
    slice 6.
13. **The home, frame-contrib:** `pallet-spaces` in Kreivo, the verifier
    vendored with a sync check (decision 9); frame-contrib later.
14. **§3, the space registry (`register_space(space_id, binding,
    controller, anchor_keys)`, anchor keys signing directly) and §6's
    fees:** a space registered from its genesis with a sovereign account
    that pays; an authorities map of the nodes' sr25519 accounts paired
    with ed25519 anchor keys; a refundable deposit on `submit`
    (decisions 11, 12; `spaces-pallet.md`).
15. **§5's `Verified` expiry for every statement:** a rootless statement's
    `Seen` entry never expires.

## The Clerk's draft (`clerk-across-spaces.md`)

1. **The file's name and title, "Slice 6 (draft): the Clerk across
   spaces"; "written for slice 5 before the owner chose proving first; now
   slice 6's starting point"** [decision 15]. Rename to
   `clerk-across-spaces.md`, its slice number set when it is scheduled;
   title "The Clerk across spaces (draft)"; renumber its steps 5.x as C.x;
   the header: "**What changed since this draft:** proving came first
   (slices 5 and 6); slice 6 builds the statements, the space roots and
   anchors (Unix-time windows from the genesis, one venue per space), the
   carried commitment that replaces two-anchor reads, `&self` reads by a
   served witness, a JAM statements service and the design of Kreivo's
   spaces pallet. The steps below are re-read against them (items 2–14)."
2. **"What the survey found"** (l.14-29) [now]. Replace with: "Proving is
   built: the recursion folds a window into one final proof (slice 5;
   8,039 columns in the full segment AIR; 96.4M gas, 38M Wasm instructions
   unmasked); slice 6 masks it and builds roots, anchors, `&self` reads
   and the venues."
3. **"The split"** (l.31-35) and decision 1 (l.284) [now]. Replace with:
   "The owner chose proving first; the Clerk follows slice 6."
4. **"The condition: … reads are witnessed rows and paths; the roots are
   in the `Attest` record; the public output is fixed, including the rows
   commitment"** (l.52-56) [step 6.13]. Keep; the record is
   `proving.md` A.5's.
5. **"the witness channel (arguments are capped at 64 KiB)"** (l.58-60)
   and 5.4's "its witness channel lifts the 64 KiB argument cap"
   (l.209) [now]. Replace with: "the argument cap stays; a statement's
   rows arrive as a served witness by hash, under `Limits::served`".
   **Amended by 6.0a** [step 6.13]: "inline in the `Resume` input", not
   "by hash"; the text applied at 6.0d is replaced with it.
6. **5.0's spikes** (l.77-111) [now]. Mark done: a real segment on JAM
   (spike 4a: not viable; a final proof instead), masking (spikes 2, 6a),
   a window statement proved (spike 3, slice 5's 5.15).
7. **5.2, "`SpaceId`: the hash of the space's creation record, bound to its
   representative's service id on JAM, signed both ways"** (l.147-148)
   [decision 1]. Replace with: "`SpaceId` = the hash of the space's
   genesis (`vos-anchor`); a founding node key binds a controller at each
   venue." Add: "Counterparties anchor at the same venue; a pair on two
   venues settles once one migrates."
8. **5.4, "The cut: windows bound to the pair's sequence numbers" and
   "Anchors: … on a schedule taken from JAM's time through the builder's
   JAM node"** (l.175-186) [decisions 2, 6]. Replace with: "Windows are
   the space's Unix-time clock; the per-pair sequence cut lives in the
   pair's rows and the statement's output."
9. **5.4, "The carry-forward of past-anchor reads" and "Absence at a past
   anchor"** (l.187-198) [decision 6]. Replace with: "The handler keeps
   per (A, B, currency) a commitment to the last settled cumulative state;
   the kernel takes it as a `#[public]` argument, the old values
   privately, and reads the current rows at one anchored cut. No old tree
   or anchor is kept; the creation-window stamp is not needed."
10. **5.4, "Completeness of the journals"** (l.199-203) [decision 6, the
    Clerk's decision 4]. With the aggregate rows, a pair reads two rows;
    the range proof over journals is not needed.
11. **5.5, "The JAM agents" and "Registration stand-in: self-registration
    by first transfer"** (l.211-235) [decision 9]. Replace with:
    "Settlement on Kreivo first, a `ClerkSettle` handler in
    `pallet-spaces` (the Kreivo teammate's); the JAM statements service
    beside it. Spaces register at the venue from their genesis, with a
    sovereign account." Every value-moving handler two-sided (Fable's
    review of the design round, finding 9).
12. **5.6 and 5.7** (l.237-266) [now]. Mark done in slice 5 (5.7: the JAM
    limits, DA, the heap per invocation, the measurements, Ristretto
    removed).
13. **"Risks": "A real proof's verification may not fit JAM"; "Masking may
    need a Stwo move and a toolchain change"** (l.307-309) [now]. Retired:
    the final proof fits (96.4M gas); masking needed no Stwo move (spike
    6a).
14. **5.3's payments between spaces, 5.4's exposure cap and every
    deadline between spaces** [decision 2]. Add the rule: "a deadline
    between parties in different spaces (a payment's expiry, a timeout, an
    exposure deadline) is the venue's chain time, never a window number or
    a space's clock";
    and the latency: authorization instant, the counterparty crediting
    within its exposure cap; trustless settlement about
    `L/2 + D + t_prove + inclusion`.
