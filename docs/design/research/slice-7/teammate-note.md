# To the Kreivo teammate: `pallet-spaces` v2

From the VOS owner, 2026-10-25, for sending as is.

VOS is simplifying the anchoring protocol that `spaces-pallet.md`
describes. A v2 of the design and its conformance vectors comes with VOS's
step 7.1, a few weeks from now. If you have started on the pallet, these
are the parts that change, so you can hold them until v2 lands:

1. **No migration.** Call 5 (`migrate`), `end_window`, errors 24 and 28,
   event 5 and vector G14 go. A space that changes venue registers again
   under a new genesis.
2. **No resume: equivocation ends a space for good.** Call 6 (`resume`),
   error 23, event 9 and the unblock-to-`Suspended` branch of
   `set_status` go. A second root for a window still stores the evidence,
   but the space's status becomes `Ended` (`SpaceStatus` index 3; index 1,
   `Suspended`, retired and never reused), its roots are refused from then
   on, and its record is never pruned (a tombstone). The registration
   deposit is released to the sovereign account on `Ended`, and the
   controller's `dispatch_as_sovereign` stays callable on an ended space,
   so its funds can leave (the existential deposit stays). G5 and G19
   change.
3. **Registration starts at the next window.** `register` no longer takes
   `start_window`: the founder signs `(venue, space, controller)` and the
   space anchors from the venue's next window. `BadStartWindow` goes; G1
   and G18 change.
4. **One anchor key per node, no rotation.** An authority is paired with
   its node's key; the "update replaces the paired key" semantics of
   `add_authority` go (a node key changes only by replacing the node:
   remove the authority, add the new one). §13's questions 2 and 12 are
   answered that way; G15 changes.
5. **Rooted statements only.** `ProgramInfo.venue_bound`, `Pin`'s flag and
   refusal 7 go; a statement naming `SpaceId::NONE` is refused (code 4);
   the "rootless `Seen` never expires" rule goes. G7, G9 and G11 change.
6. **The anchor rule as one function.** VOS adds a `no_std` module,
   `vos_anchor::venue`, holding the registration, anchor, anchored and
   freshness rules over a small state trait; the kit vendors it, and v2
   asks the pallet to call it over its storage rather than restate the
   rule.
7. **Strict ed25519.** Verify signatures as `verify_strict` does, or refuse
   small-order keys at `register` and `add_authority`; a vector pins it.

Unchanged: the sovereign account and its budget, deposits and fees,
`submit`'s check order, `Record`, formats and programs with their delay,
the pause, `on_idle`, the storage keys of the items that stay.

**Drops to expect:** v2 and the vectors at VOS's 7.1; at 7.8a the kit's
fixtures, the vectors' wrap hashes and lengths, and the vendored
`vos-pvm-recair-air` and `vos-pvm-final-verifier` sources (no pinned
program id moves); the kit's `vos-anchor` and
statement pieces and the blob hashes at 7.8b; the fixtures and program ids
once more at the slice's end (7.21), if VOS's node segment format changes
(no change to the pallet's code, only the vendored tree and the pinned
ids).
