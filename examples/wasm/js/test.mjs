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
const wasmBuf = wasmBytes.buffer.slice(
  wasmBytes.byteOffset, wasmBytes.byteOffset + wasmBytes.byteLength
);

// Load with init args (constructor takes a `prefix: String`)
const actor = await loadActor(wasmBuf, {
  initArgs: { prefix: 'wasm' },
});

const meta = actor.meta();
console.log('actor name:', meta.actor_name);
console.log('messages:', meta.messages.map(m => `${m.name}(${m.fields.map(f => f.name + ':' + f.ty).join(', ')}) ${m.is_query ? 'query' : 'cmd'}`));
console.log('constructor params:', meta.constructor.map(f => `${f.name}: ${f.ty}`));

// Dispatch real messages now that we have JS-side encoding.
const reply1 = await actor.ask('echo', { text: 'hello from JS' });
console.log('reply 1:', reply1);
const reply2 = await actor.ask('echo', { text: 'second message' });
console.log('reply 2:', reply2);
const count = await actor.ask('count');
console.log('count:', count);

if (reply1 !== '[wasm] echo #1: hello from JS') throw new Error(`unexpected reply: ${reply1}`);
if (reply2 !== '[wasm] echo #2: second message') throw new Error(`unexpected reply: ${reply2}`);
if (count !== 2) throw new Error(`unexpected count: ${count}`);

actor.drop();
console.log('OK');
