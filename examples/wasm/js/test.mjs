// Quick smoke test for vos.js — loads echo-wasm and verifies metadata
// parsing. Runs in Node:
//   node examples/wasm/js/test.mjs

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { loadActor } from './vos.js';

const here = dirname(fileURLToPath(import.meta.url));
const wasmPath = join(
  here, '..', 'echo', 'target', 'wasm32-unknown-unknown', 'release', 'echo_wasm.wasm'
);

const wasmBytes = readFileSync(wasmPath);
const actor = await loadActor(wasmBytes.buffer.slice(
  wasmBytes.byteOffset, wasmBytes.byteOffset + wasmBytes.byteLength
));

const meta = actor.meta();
console.log('actor name:', meta.actor_name);
console.log('messages:', meta.messages.map(m => `${m.name}(${m.fields.map(f => f.name + ':' + f.ty).join(', ')}) ${m.is_query ? 'query' : 'cmd'}`));
console.log('constructor params:', meta.constructor.map(f => `${f.name}: ${f.ty}`));

// We don't have rkyv encoding in JS yet, so skip dispatch.
// The metadata roundtrip + WASM load is the smoke test.
actor.drop();
console.log('OK');
