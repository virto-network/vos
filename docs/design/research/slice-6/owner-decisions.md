# Slice 6 owner decisions (2026-10-19)

1. SpaceId: genesis hash (a) — BLAKE2b("vos/space/id" ‖ SCALE(genesis)); clock frozen in genesis; no controller (bound per venue by a founding key).
2. Window clock: Unix time, fixed cadence (C3), length 2–60 min per space, default 10, close delay min(L/5, 2 min), MaxRootAge 24 h.
   - Owner asked about trust: ADD RULE to plan — any time logic between parties (expiries, timeouts, exposure deadlines) uses the venue's chain time (Kreivo timestamp / JAM slot), never a window number or the space's clock. The space's clock only schedules its own cuts; the venue bounds windows by its own clock.
   - Owner asked about cross-space latency: explain in plan — authorization instant, counterparty may credit within its exposure cap; trustless settlement ≈ L/2 + D + t_prove + inclusion (~10 min avg at L=10); parallel proving (not in slice 6) is the lever below that.
3. Format 36: retire it and delete the refine-bundle proving path; default prove + bench → 35.
4. Blake2b hook: defer (lever for when ref_time binds).
5. Agent root: committed rows under 0x03 (VOS agent root ≡ JAM node).
6. History: W1 + S3 — no tree history; carried per-pair commitment at the venue; RootKind { Space } only.
7. Space root: representative agent; anchors signed by one registered node key; controller rotates keys.
8. F2: migration ranges (rooted) + per-program venue_bound flag checked on public_args[0..32]; no vos/io/v2.
9. Pallet home: vendor verifier stack into Kreivo pallets/ with sync check vs VOS tag (c2); frame-contrib + crates.io later.
10. Governance: Virto community ProgramsOrigin + Root override, 7-day delay, EmergencyOrigin pause, signed submitters, Record only, rootless Seen never expires.
11. Fees: OWNER CHOSE (c) refundable deposit on submit (refunded on acceptance, forfeited on refusal) — NOT the recommended (b). Length + weight fees charged as normal on submit and anchor (no feeless anchors, no gas tank) unless owner says otherwise.
12. Node accounts — OWNER REDIRECTED (not a pick): the Kreivo pallet becomes a general "spaces pallet" that will REPLACE pallet-communities; each space gets a SOVEREIGN ACCOUNT at registration (the funded account that pays deposits); a map of current space AUTHORITIES (nodes' unique sr25519 keys) authorizes node-signed txs; alternatively nodes use pallet-pass (ssh key or other authenticator); maybe nodes stay ANONYMOUS and authenticate with a proof against the space. → research spaces-pallet-research.md running; reshapes 6.16/6.17/6.17b and decisions 10–12.
12a. Spaces pallet: NOT built in slice 6. Slice 6 prepares a handoff DESIGN of the spaces pallet (replaces communities later; sovereign account per space; authorities map; pallet-pass alt; anonymous-by-proof later) for a Kreivo teammate → stage/spaces-pallet-design.md.
12b. Kreivo scope in slice 6 = DESIGN + KIT ONLY: spaces-pallet design; verifier crates packaged for vendoring with the sync check; the node's Kreivo client tested against a MOCK of the designed interface. NO pallet code from us (no test-fixture pallet). Slice 6's on-chain end to end runs on the JAM service only; the Kreivo leg runs when the teammate's pallet exists. Decisions 9–11 (vendoring path, governance, deposit) become inputs to the design doc, not our build. Decision 12 (node accounts) is folded into the design: authorities map of node sr25519 keys; sovereign account pays.
13. Code-quality rest from slice 5: ALL in slice 6 (6.22 cleanup), not split.
14. External audit: scope frozen at M2 acceptance; engage after slice 6, before any value.
15. Rename slice-6-clerk.md → clerk-across-spaces.md (slice number set when scheduled), with a header noting what changed.
