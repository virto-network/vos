# Extensions

Native extensions connect VOS to host services. Application logic belongs in
signed actors; extensions should remain small capability adapters.

- `substrate/` — Kreivo-first Substrate light-client queries and externally
  signed V4 transaction submission.
- `prover/` — host-side PVM proof production and verification.

See [the extension guide](../docs/extensions.md).
