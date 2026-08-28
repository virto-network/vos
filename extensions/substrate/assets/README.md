# Bundled chain specifications

The extension embeds compressed, immutable light-client specifications so its
default network does not depend on a public JSON-RPC endpoint.

Source collection: `paritytech/chainspecs` commit
`2f380ac0cae8f45466b7c87503effff565b0dbde` (retrieved 2026-08-28).

- The base Kusama spec resolves the collection's relay-chain symlink through
  `paritytech/polkadot-sdk@bd646008920111d1dd5698dc73f45428f3227d31`, file
  `polkadot/node/service/chain-specs/kusama.json`.
- `kreivo-kusama.json.zst` resolves the Kreivo symlink through
  `virto-network/virto-node@e72e0120b5555c3af459d1439239797076ab10c7`, file
  `chain-spec-generator/src/spec/live/kreivo_kusama_chainspec.json`.

The upstream Kreivo file contains only a localhost bootnode. For the bundled
default, that single entry is replaced with the six public TCP addresses
reported by Kreivo's `system_localListenAddresses` RPC on 2026-08-28, all for
peer `12D3KooWP1mhED5zhk5ghkdYH1TSEVTVX2s2hSADz67oLfiYeeXF`. Its
`relay_chain` label is also normalized from `kusama` to the canonical Kusama
spec's `id`, `ksmcc3`: smoldot associates a parachain with a supplied relay
spec by exact chain-spec id. These are connectivity-only changes; genesis
storage and code substitutes are untouched. Operators can replace either
complete spec through extension init arguments, provided the parachain's
`relay_chain` and relay spec's `id` match.

The base Kusama spec starts smoldot at genesis. `kusama.json.zst` therefore
embeds the result of the official `https://kusama-rpc.polkadot.io`
`sync_state_genSyncSpec(true)` RPC fetched on 2026-08-28. It adds a finalized
GRANDPA/BABE light-client checkpoint at block 34,997,431,
`0x8a4c53dfefecac0bc14d9047801bc2b2136dbf2f0c09634cb4ea2ba2042a38b7`.
The checkpoint is immutable in this build and is authenticated forward by the
relay-chain consensus proof; the extension does not contact that RPC service
at runtime.

SHA-256:

```text
d09b0ce837e04ecc1f029fcd5efb41624557995af664b7313df57fdcd23e05fb  upstream kreivo_kusama_chainspec.json
b2412280b50c2f34de62f732e664073627bde66432518822f6c1c31bda601b5f  bundled Kreivo JSON before compression
7e69e6565e4be9430686ba5d39089b1a47d4ffa37de4472de7b39011f816a84a  kreivo-kusama.json.zst
f18574a1d43e5bc1d4ba0e469af22065321512240c77fdb26f33a32160711781  upstream Kusama JSON
7873274cbfbe6d59f698c2f9c470dc3b8075ed8723e17cf5d37503b302747c5c  sync_state_genSyncSpec JSON-RPC response
031478a882bf53d307de8aeab02596ce7d2da9c0a1cec3688a68d3df7b394b54  bundled Kusama sync-spec JSON
b18bacf0969acfb0723f7ea1d6bc8791e103fc9517e70950a3d9df4f2f03650e  kusama.json.zst
```
