// Smoke test for the WASM fetcher actor — uses the loader's
// default onEffect handler which dispatches to the global fetch().
//   node examples/wasm/js/test-fetch.mjs

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { loadActor } from './vos.js';

const here = dirname(fileURLToPath(import.meta.url));
const wasmPath = join(
  here, '..', 'fetcher', 'target', 'wasm32-unknown-unknown', 'release', 'fetcher_wasm.wasm'
);

const wasmBytes = readFileSync(wasmPath);
const wasmBuf = wasmBytes.buffer.slice(
  wasmBytes.byteOffset, wasmBytes.byteOffset + wasmBytes.byteLength
);

const actor = await loadActor(wasmBuf);
const meta = actor.meta();
console.log('actor:', meta.actor_name);

// Get the HTTP status of example.com
const status = await actor.ask('status', { url: 'https://example.com' });
console.log('status:', status);
if (status !== 200) throw new Error(`expected 200, got ${status}`);

// Get the body
const body = await actor.ask('get', { url: 'https://example.com' });
console.log('body length:', body.length);
if (!body.includes('Example Domain')) throw new Error('body missing expected content');

actor.drop();
console.log('OK');
