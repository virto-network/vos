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

  /**
   * Encode a high-level message into the wire format and dispatch it.
   * Convenience around `encodeMsg` + `dispatch` + `decodeValue`.
   *
   * @param {string} name - message handler name
   * @param {object} [args] - arg name → value, where value is a tagged
   *   { type: 'Str'|'U32'|..., val: ... } object or a primitive (auto-tagged)
   * @returns {Promise<any>} decoded reply
   */
  async ask(name, args = {}) {
    const msgBytes = this.encodeMsg(name, args);
    const replyBytes = await this.dispatch(msgBytes);
    if (replyBytes.length === 0) return null;
    return this.decodeValue(replyBytes);
  }

  /**
   * Encode a message (name + args) into the wire format ready for dispatch.
   * @returns {Uint8Array} TAG_DYNAMIC-prefixed rkyv-encoded Msg bytes
   */
  encodeMsg(name, args = {}) {
    const desc = encodeMsgDesc(name, args);
    const descPtr = this.exports.vos_wasm_alloc(desc.length);
    this._writeBytes(descPtr, desc);
    const packed = this.exports.vos_wasm_encode_msg(descPtr, desc.length);
    this.exports.vos_wasm_free(descPtr, desc.length);
    if (packed === 0n || packed === 0) {
      throw new Error(`vos: failed to encode msg "${name}"`);
    }
    const { ptr, len } = unpackBuf(packed);
    const bytes = this._readBytes(ptr, len).slice();
    this.exports.vos_wasm_free(ptr, len);
    return bytes;
  }

  /**
   * Decode rkyv-encoded Value bytes (e.g. a reply) into a JS value.
   * @param {Uint8Array} bytes
   * @returns {any} the decoded value (number, string, bool, etc.)
   */
  decodeValue(bytes) {
    if (bytes.length === 0) return null;
    const ptr = this.exports.vos_wasm_alloc(bytes.length);
    this._writeBytes(ptr, bytes);
    const packed = this.exports.vos_wasm_decode_value(ptr, bytes.length);
    this.exports.vos_wasm_free(ptr, bytes.length);
    if (packed === 0n || packed === 0) return null;
    const out = unpackBuf(packed);
    const desc = this._readBytes(out.ptr, out.len).slice();
    this.exports.vos_wasm_free(out.ptr, out.len);
    return decodeValueDesc(desc);
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

// ── Value description codec (matches vos::value::desc) ───────────────

const TAG_UNIT = 0, TAG_BOOL = 1, TAG_U8 = 2, TAG_U16 = 3,
      TAG_U32 = 4, TAG_U64 = 5, TAG_I32 = 6, TAG_I64 = 7,
      TAG_STR = 8, TAG_BYTES = 9, TAG_LIST_U32 = 10, TAG_LIST_STR = 11;

const ENCODER = new TextEncoder();
const DECODER = new TextDecoder();

/** Auto-tag a JS primitive into a {type, val} object. */
function autoTag(v) {
  if (v == null) return { type: 'Unit' };
  if (typeof v === 'object' && 'type' in v) return v;
  if (typeof v === 'boolean') return { type: 'Bool', val: v };
  if (typeof v === 'string') return { type: 'Str', val: v };
  if (typeof v === 'number') {
    if (Number.isInteger(v)) {
      if (v >= 0) {
        if (v <= 0xFF) return { type: 'U8', val: v };
        if (v <= 0xFFFF) return { type: 'U16', val: v };
        if (v <= 0xFFFFFFFF) return { type: 'U32', val: v };
      } else {
        if (v >= -0x80000000) return { type: 'I32', val: v };
      }
    }
    return { type: 'I64', val: BigInt(v) };
  }
  if (typeof v === 'bigint') return { type: 'U64', val: v };
  if (v instanceof Uint8Array) return { type: 'Bytes', val: v };
  if (Array.isArray(v)) {
    if (v.every(x => typeof x === 'number' && Number.isInteger(x) && x >= 0)) {
      return { type: 'ListU32', val: v };
    }
    if (v.every(x => typeof x === 'string')) {
      return { type: 'ListStr', val: v };
    }
  }
  throw new Error(`vos: cannot auto-tag value: ${v}`);
}

/** Encode a single tagged value into ValueDesc bytes (appending to writer). */
function writeValueDesc(w, tagged) {
  const t = tagged.type;
  const v = tagged.val;
  switch (t) {
    case 'Unit': w.u8(TAG_UNIT); break;
    case 'Bool': w.u8(TAG_BOOL); w.u8(v ? 1 : 0); break;
    case 'U8':   w.u8(TAG_U8);   w.u8(v); break;
    case 'U16':  w.u8(TAG_U16);  w.u16(v); break;
    case 'U32':  w.u8(TAG_U32);  w.u32(v); break;
    case 'U64':  w.u8(TAG_U64);  w.u64(BigInt(v)); break;
    case 'I32':  w.u8(TAG_I32);  w.i32(v); break;
    case 'I64':  w.u8(TAG_I64);  w.i64(BigInt(v)); break;
    case 'Str': {
      w.u8(TAG_STR);
      const bytes = ENCODER.encode(v);
      w.u32(bytes.length);
      w.bytes(bytes);
      break;
    }
    case 'Bytes':
      w.u8(TAG_BYTES);
      w.u32(v.length);
      w.bytes(v);
      break;
    case 'ListU32':
      w.u8(TAG_LIST_U32);
      w.u32(v.length);
      for (const x of v) w.u32(x);
      break;
    case 'ListStr':
      w.u8(TAG_LIST_STR);
      w.u32(v.length);
      for (const s of v) {
        const b = ENCODER.encode(s);
        w.u32(b.length);
        w.bytes(b);
      }
      break;
    default:
      throw new Error(`vos: unknown value type: ${t}`);
  }
}

/** Build the MsgDesc bytes for a name + args object. */
function encodeMsgDesc(name, args) {
  const w = new BinWriter();
  const nameBytes = ENCODER.encode(name);
  w.u32(nameBytes.length);
  w.bytes(nameBytes);
  const entries = Object.entries(args);
  w.u32(entries.length);
  for (const [k, v] of entries) {
    const kb = ENCODER.encode(k);
    w.u32(kb.length);
    w.bytes(kb);
    writeValueDesc(w, autoTag(v));
  }
  return w.toBytes();
}

/** Decode ValueDesc bytes into a JS value. */
function decodeValueDesc(bytes) {
  const r = new BinReader(bytes);
  return readValueDesc(r);
}

function readValueDesc(r) {
  const tag = r.u8();
  switch (tag) {
    case TAG_UNIT: return null;
    case TAG_BOOL: return r.u8() !== 0;
    case TAG_U8:   return r.u8();
    case TAG_U16:  return r.u16();
    case TAG_U32:  return r.u32();
    case TAG_U64:  return r.u64();
    case TAG_I32:  return r.i32();
    case TAG_I64:  return r.i64();
    case TAG_STR:  return DECODER.decode(r.bytes(r.u32()));
    case TAG_BYTES: {
      const len = r.u32();
      return new Uint8Array(r.bytes(len));
    }
    case TAG_LIST_U32: {
      const n = r.u32();
      const out = new Array(n);
      for (let i = 0; i < n; i++) out[i] = r.u32();
      return out;
    }
    case TAG_LIST_STR: {
      const n = r.u32();
      const out = new Array(n);
      for (let i = 0; i < n; i++) out[i] = DECODER.decode(r.bytes(r.u32()));
      return out;
    }
    default: throw new Error(`vos: unknown value tag: ${tag}`);
  }
}

// Tiny binary writers/readers for the wire format.
class BinWriter {
  constructor() { this.chunks = []; this.len = 0; }
  u8(v) { this.chunks.push(new Uint8Array([v & 0xFF])); this.len += 1; }
  u16(v) {
    const b = new Uint8Array(2);
    new DataView(b.buffer).setUint16(0, v, true);
    this.chunks.push(b); this.len += 2;
  }
  u32(v) {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, v, true);
    this.chunks.push(b); this.len += 4;
  }
  i32(v) {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setInt32(0, v, true);
    this.chunks.push(b); this.len += 4;
  }
  u64(v) {
    const b = new Uint8Array(8);
    new DataView(b.buffer).setBigUint64(0, BigInt(v), true);
    this.chunks.push(b); this.len += 8;
  }
  i64(v) {
    const b = new Uint8Array(8);
    new DataView(b.buffer).setBigInt64(0, BigInt(v), true);
    this.chunks.push(b); this.len += 8;
  }
  bytes(b) { this.chunks.push(b); this.len += b.length; }
  toBytes() {
    const out = new Uint8Array(this.len);
    let off = 0;
    for (const c of this.chunks) { out.set(c, off); off += c.length; }
    return out;
  }
}

class BinReader {
  constructor(bytes) {
    this.bytes_ = bytes;
    this.dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    this.pos = 0;
  }
  u8()  { const v = this.dv.getUint8(this.pos);    this.pos += 1; return v; }
  u16() { const v = this.dv.getUint16(this.pos, true); this.pos += 2; return v; }
  u32() { const v = this.dv.getUint32(this.pos, true); this.pos += 4; return v; }
  i32() { const v = this.dv.getInt32(this.pos, true);  this.pos += 4; return v; }
  u64() { const v = this.dv.getBigUint64(this.pos, true); this.pos += 8; return v; }
  i64() { const v = this.dv.getBigInt64(this.pos, true);  this.pos += 8; return v; }
  bytes(n) {
    const v = this.bytes_.subarray(this.pos, this.pos + n);
    this.pos += n;
    return v;
  }
}
