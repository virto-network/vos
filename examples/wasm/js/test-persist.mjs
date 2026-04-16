// Smoke test for WASM state persistence.
// In Node (no IndexedDB) we use the in-memory fallback to prove the
// load/save plumbing works end-to-end. In a browser, IndexedDB is used.
//   node examples/wasm/js/test-persist.mjs

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { loadActor } from './vos.js';

const here = dirname(fileURLToPath(import.meta.url));
const wasmPath = join(
  here, '..', 'echo', 'target', 'wasm32-unknown-unknown', 'release', 'echo_wasm.wasm'
);
const wasmBytes = readFileSync(wasmPath);
const wasmBuf = wasmBytes.buffer.slice(
  wasmBytes.byteOffset, wasmBytes.byteOffset + wasmBytes.byteLength
);

// First session — start fresh, send 2 echoes.
{
  const actor = await loadActor(wasmBuf, {
    initArgs: { prefix: 'persist' },
    storageKey: 'echo-test',
  });
  const r1 = await actor.ask('echo', { text: 'one' });
  const r2 = await actor.ask('echo', { text: 'two' });
  console.log('session 1:', r1, '|', r2);
  if (r1 !== '[persist] echo #1: one') throw new Error(`got: ${r1}`);
  if (r2 !== '[persist] echo #2: two') throw new Error(`got: ${r2}`);
  actor.drop();
}

// Second session — should restore state, count starts at 2.
{
  const actor = await loadActor(wasmBuf, {
    // initArgs would normally re-seed the prefix, but with persisted
    // state present they're ignored (the load path takes over).
    initArgs: { prefix: 'persist' },
    storageKey: 'echo-test',
  });
  const r3 = await actor.ask('echo', { text: 'three' });
  console.log('session 2:', r3);
  if (r3 !== '[persist] echo #3: three')
    throw new Error(`expected count to resume at 3, got: ${r3}`);
  const count = await actor.ask('count');
  if (count !== 3) throw new Error(`count mismatch: ${count}`);
  actor.drop();
}

console.log('OK');
