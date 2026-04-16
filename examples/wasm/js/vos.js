// vos.js — minimal loader for VOS WASM actors.
//
// Single-file ES module, no build step. Load via:
//   <script type="module">
//     import { loadActor } from 'https://example.com/vos.js';
//   </script>
//
// Provides the host side of the poll-based async ABI defined in
// crates/vos-macros (vos_wasm_*).  The actor's WASM module exports
// a small set of functions; this loader drives them.

/**
 * Load a VOS WASM actor from a URL or ArrayBuffer.
 *
 * @param {string|Response|ArrayBuffer|Promise<Response>} source
 * @param {object} [options]
 * @param {Uint8Array} [options.initArgs] - rkyv-encoded init args
 * @param {object} [options.imports] - extra WebAssembly imports
 * @param {function} [options.onEffect] - async (effectBytes, instance) => resultBytes
 * @returns {Promise<VosActor>}
 */
export async function loadActor(source, options = {}) {
  const wasmInstance = await loadWasm(source, options.imports || {});
  return new VosActor(wasmInstance, options);
}

async function loadWasm(source, imports) {
  if (source instanceof ArrayBuffer || source instanceof Uint8Array) {
    const { instance } = await WebAssembly.instantiate(source, imports);
    return instance;
  }
  // URL or Response or Promise<Response>
  const response = typeof source === 'string'
    ? fetch(source)
    : Promise.resolve(source);

  if (typeof WebAssembly.instantiateStreaming === 'function') {
    const { instance } = await WebAssembly.instantiateStreaming(response, imports);
    return instance;
  }
  // Fallback for environments without instantiateStreaming (Node)
  const resolved = await response;
  const buf = await resolved.arrayBuffer();
  const { instance } = await WebAssembly.instantiate(buf, imports);
  return instance;
}

/**
 * A live WASM actor instance.
 *
 * Methods:
 *   meta()                  — parsed actor metadata (sync)
 *   dispatch(bytes)         — send a message, returns reply bytes (async)
 *   drop()                  — destroy the instance
 */
export class VosActor {
  constructor(wasmInstance, options) {
    this.exports = wasmInstance.exports;
    this.memory = wasmInstance.exports.memory;
    this.onEffect = options.onEffect || defaultEffectHandler;

    // Allocate state with optional init args
    const initArgs = options.initArgs || null;
    let argsPtr = 0, argsLen = 0;
    if (initArgs && initArgs.length > 0) {
      argsPtr = this.exports.vos_wasm_alloc(initArgs.length);
      this._writeBytes(argsPtr, initArgs);
      argsLen = initArgs.length;
    }
    this.state = this.exports.vos_wasm_create(argsPtr, argsLen);
    if (argsPtr) this.exports.vos_wasm_free(argsPtr, argsLen);
  }

  /**
   * Read the actor's metadata (parsed from the .vos_meta binary blob).
   * @returns {object} { actor_name, messages, constructor }
   */
  meta() {
    if (this._meta) return this._meta;
    const packed = this.exports.vos_wasm_meta();
    const { ptr, len } = unpackBuf(packed);
    if (!ptr || !len) return null;
    const bytes = this._readBytes(ptr, len);
    this._meta = parseMetadata(bytes);
    return this._meta;
  }

  /**
   * Dispatch a raw message (TAG_DYNAMIC-prefixed rkyv bytes) and
   * drive the poll loop until completion. Effects are fulfilled via
   * `options.onEffect`.
   *
   * @param {Uint8Array} msgBytes
   * @returns {Promise<Uint8Array>} reply bytes (rkyv-encoded Value)
   */
  async dispatch(msgBytes) {
    const msgPtr = this.exports.vos_wasm_alloc(msgBytes.length);
    this._writeBytes(msgPtr, msgBytes);
    this.exports.vos_wasm_dispatch(this.state, msgPtr, msgBytes.length);
    this.exports.vos_wasm_free(msgPtr, msgBytes.length);

    // Poll loop: handle pending effects, return when ready
    while (true) {
      const status = this.exports.vos_wasm_poll(this.state);
      if (status === 0) {
        // Ready — take the reply
        const packed = this.exports.vos_wasm_take_reply(this.state);
        if (packed === 0n || packed === 0) return new Uint8Array(0);
        const { ptr, len } = unpackBuf(packed);
        const reply = this._readBytes(ptr, len).slice(); // copy out
        this.exports.vos_wasm_free(ptr, len);
        return reply;
      }
      if (status === 1) {
        // Pending — read effect, fulfill, provide result
        const effPacked = this.exports.vos_wasm_pending_effect(this.state);
        const eff = effPacked === 0n || effPacked === 0
          ? new Uint8Array(0)
          : (() => {
              const { ptr, len } = unpackBuf(effPacked);
              return this._readBytes(ptr, len).slice();
            })();
        const result = await this.onEffect(eff, this);
        const resultBytes = result instanceof Uint8Array
          ? result
          : new Uint8Array(0);
        let resultPtr = 0;
        if (resultBytes.length > 0) {
          resultPtr = this.exports.vos_wasm_alloc(resultBytes.length);
          this._writeBytes(resultPtr, resultBytes);
        }
        this.exports.vos_wasm_provide_result(this.state, resultPtr, resultBytes.length);
        if (resultPtr) this.exports.vos_wasm_free(resultPtr, resultBytes.length);
        // Loop and re-poll
      } else {
        throw new Error(`vos: poll error status=${status}`);
      }
    }
  }

  /** Destroy the actor instance. */
  drop() {
    if (this.state) {
      this.exports.vos_wasm_drop(this.state);
      this.state = 0;
    }
  }

  // ── Internal helpers ──────────────────────────────────────────────

  _readBytes(ptr, len) {
    return new Uint8Array(this.memory.buffer, ptr, len);
  }

  _writeBytes(ptr, bytes) {
    new Uint8Array(this.memory.buffer, ptr, bytes.length).set(bytes);
  }
}

// Default effect handler: provides empty result (no-op).
// Override via options.onEffect to handle ask/fetch/etc.
function defaultEffectHandler(_eff, _actor) {
  return new Uint8Array(0);
}

// Unpack a u64 (high 32 = ptr, low 32 = len) from the WASM ABI.
// Note: WebAssembly returns BigInt for i64; we normalize to numbers.
function unpackBuf(packed) {
  const big = typeof packed === 'bigint' ? packed : BigInt(packed);
  const ptr = Number(big >> 32n) & 0xFFFFFFFF;
  const len = Number(big & 0xFFFFFFFFn);
  return { ptr, len };
}

// ── Metadata parser ──────────────────────────────────────────────────
//
// Decodes the .vos_meta binary format produced by vos::metadata::encode.
// Format:
//   [name_len:u16][name_bytes]
//   [msg_count:u16]
//     [msg_name_len:u16][msg_name_bytes]
//     [is_query:u8]
//     [field_count:u16]
//       [field_name_len:u16][field_name_bytes]
//       [field_ty_len:u16][field_ty_bytes]
//   [ctor_count:u16]
//     [ctor_name_len:u16][ctor_name_bytes]
//     [ctor_ty_len:u16][ctor_ty_bytes]

function parseMetadata(bytes) {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let pos = 0;
  const dec = new TextDecoder();

  function readU16() {
    const v = dv.getUint16(pos, true);
    pos += 2;
    return v;
  }
  function readStr() {
    const len = readU16();
    const s = dec.decode(new Uint8Array(bytes.buffer, bytes.byteOffset + pos, len));
    pos += len;
    return s;
  }
  function readField() {
    return { name: readStr(), ty: readStr() };
  }

  const actor_name = readStr();

  const msgCount = readU16();
  const messages = [];
  for (let i = 0; i < msgCount; i++) {
    const name = readStr();
    const is_query = dv.getUint8(pos) !== 0;
    pos += 1;
    const fieldCount = readU16();
    const fields = [];
    for (let j = 0; j < fieldCount; j++) fields.push(readField());
    messages.push({ name, is_query, fields });
  }

  let constructor = [];
  if (pos < bytes.length) {
    const ctorCount = readU16();
    for (let i = 0; i < ctorCount; i++) constructor.push(readField());
  }

  return { actor_name, messages, constructor };
}
