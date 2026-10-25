//! The venue's JAM refine program, shared by `final-verify` and
//! `final-verify-test` (`src/bin/final-verify.rs` describes it).

#[macro_use]
mod runtime;

use alloc::vec::Vec;
use core::arch::global_asm;
use core::cell::UnsafeCell;
use core::fmt::Write;

use runtime::{Cursor, HEAP, STACK_BYTES, Static, gas_left};
use vos_pvm_final_verifier::PUBLIC_WORDS;
use vos_statement::model::Input;
use vos_statement::vos_anchor::vectors::{Digests, Vector};
use vos_statement::{Admitted, Refusal, StatementId};

global_asm!(
    ".global _start",
    ".type _start, @function",
    "_start:",
    "mv s0, ra",
    "lla t0, VERIFY_STACK",
    "li t1, {size}",
    "add sp, t0, t1",
    "jal ra, verify_main",
    "mv ra, s0",
    "ret",
    size = const STACK_BYTES,
);

// ── Host calls ───────────────────────────────────────────────────────────

const FETCH: u64 = 2;
const HISTORICAL_LOOKUP: u64 = 7;
const FETCH_PAYLOAD: u64 = 13;
const NONE: u64 = u64::MAX;

// ── The verify ──────────────────────────────────────────────────────────

/// The payload's buffer: a judgement's input holds the statement.
const PAYLOAD_MAX: usize = 16 << 10;

/// The payload's modes, its first byte.
#[derive(Clone, Copy)]
#[repr(u8)]
enum Mode {
    Words = 0,
    Judge = 1,
    Anchors = 2,
}

impl Mode {
    const ALL: [Self; 3] = [Self::Words, Self::Judge, Self::Anchors];

    fn of(byte: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|&mode| mode as u8 == byte)
    }
}

/// The program's verdicts, `Report::verdict`.
#[derive(Clone, Copy)]
#[repr(u64)]
enum Verdict {
    Reject = 0,
    Accept = 1,
    BadPayload = 2,
    NoPreimage = 3,
    Undecodable = 4,
}

static PAYLOAD: Static<[u8; PAYLOAD_MAX]> = Static(UnsafeCell::new([0; PAYLOAD_MAX]));
static REPORT: Static<Report> = Static(UnsafeCell::new(Report::new()));

/// What the program returns.
#[repr(C)]
pub struct Report {
    verdict: u64,
    gas_start: u64,
    gas_after_lookup: u64,
    gas_after_decode: u64,
    gas_end: u64,
    proof_len: u64,
    peak_live: u64,
    high_water: u64,
    allocs: u64,
    error_len: u64,
    error: [u8; 192],
    /// A judgement's code (`vos_statement::code`).
    code: u64,
    /// An accepted statement's id.
    id: [u8; 32],
    /// A golden vector's digests.
    digests: [u8; Digests::BYTES],
}

impl Report {
    const fn new() -> Self {
        Self {
            verdict: u64::MAX,
            gas_start: 0,
            gas_after_lookup: 0,
            gas_after_decode: 0,
            gas_end: 0,
            proof_len: 0,
            peak_live: 0,
            high_water: 0,
            allocs: 0,
            error_len: 0,
            error: [0; 192],
            code: u64::MAX,
            id: [0; 32],
            digests: [0; Digests::BYTES],
        }
    }

    /// A judgement's verdict: its code, an accepted statement's id.
    fn judged(&mut self, verdict: Result<StatementId, Refusal>) -> Verdict {
        self.code = u64::from(vos_statement::code(&verdict));
        match verdict {
            Ok(id) => {
                self.id = id.0;
                Verdict::Accept
            }
            Err(refusal) => self.refuse(&refusal),
        }
    }

    /// `error`'s text, and the verdict [`Verdict::Reject`].
    fn refuse(&mut self, error: &dyn core::fmt::Display) -> Verdict {
        let mut cursor = Cursor {
            buf: &mut self.error,
            len: 0,
        };
        let _ = write!(cursor, "{error}");
        self.error_len = cursor.len as u64;
        Verdict::Reject
    }
}

#[repr(C)]
pub struct Output {
    address: u64,
    len: u64,
}

#[unsafe(no_mangle)]
extern "C" fn verify_main() -> Output {
    // SAFETY: single-threaded; the host reads the report after halt.
    let report = unsafe { &mut *REPORT.0.get() };
    report.gas_start = gas_left();
    report.verdict = verify(report) as u64;
    report.gas_end = gas_left();
    let state = HEAP.state();
    report.peak_live = state.peak_live as u64;
    report.high_water = HEAP.peak_top() as u64;
    report.allocs = state.allocs as u64;
    Output {
        address: report as *mut Report as u64,
        len: core::mem::size_of::<Report>() as u64,
    }
}

/// What the payload asks.
#[allow(clippy::large_enum_variant, reason = "one a run, never moved")]
enum Request {
    Words(u32, [u32; PUBLIC_WORDS]),
    Judge(Input),
}

/// What the proof is checked against: the words alone under a format, or a
/// judgement's statement its checks before the proof admitted.
enum Check {
    Words(u32, [u32; PUBLIC_WORDS]),
    Judge(Admitted),
}

/// The payload: its request, the proof's hash and its length.
fn request(mode: Mode, body: &[u8]) -> Option<(Request, [u8; 32], usize)> {
    let (request, rest) = match mode {
        Mode::Words => {
            let (format, body) = body.split_first_chunk::<4>()?;
            let (words, rest) = body.split_at_checked(4 * PUBLIC_WORDS)?;
            let (words, _) = words.as_chunks::<4>();
            let mut out = [0; PUBLIC_WORDS];
            for (word, bytes) in out.iter_mut().zip(words) {
                *word = u32::from_le_bytes(*bytes);
            }
            let words = out;
            (Request::Words(u32::from_le_bytes(*format), words), rest)
        }
        Mode::Judge => {
            let (input, used) = Input::decode_prefix(body).ok()?;
            (Request::Judge(input), body.get(used..)?)
        }
        Mode::Anchors => return None,
    };
    let [hash @ .., l0, l1, l2, l3] = <[u8; 36]>::try_from(rest).ok()?;
    Some((request, hash, u32::from_le_bytes([l0, l1, l2, l3]) as usize))
}

fn verify(report: &mut Report) -> Verdict {
    // SAFETY: single-threaded; nothing else borrows the payload buffer.
    let payload = unsafe { &mut *PAYLOAD.0.get() };
    let len = hostcall!(
        FETCH,
        [
            payload.as_mut_ptr() as u64,
            0,
            payload.len() as u64,
            FETCH_PAYLOAD,
            0,
            0
        ]
    );
    let Some(payload) = usize::try_from(len).ok().and_then(|len| payload.get(..len)) else {
        return Verdict::BadPayload;
    };
    let Some((mode, body)) = payload
        .split_first()
        .and_then(|(&mode, body)| Some((Mode::of(mode)?, body)))
    else {
        return Verdict::BadPayload;
    };
    if let Mode::Anchors = mode {
        return match Vector::decode(body) {
            Ok(vector) => {
                report.digests = vector.digests().to_bytes();
                Verdict::Accept
            }
            Err(error) => {
                report.refuse(&error);
                Verdict::BadPayload
            }
        };
    }
    let Some((request, hash, proof_len)) = request(mode, body) else {
        return Verdict::BadPayload;
    };
    report.proof_len = proof_len as u64;
    let check = match request {
        Request::Words(format, words) => Check::Words(format, words),
        Request::Judge(input) => match input.admit() {
            Ok(admitted) => Check::Judge(admitted),
            Err(refusal) => return report.judged(Err(refusal)),
        },
    };
    if proof_len > vos_pvm_final_verifier::MAX_PROOF_BYTES {
        let error = vos_pvm_final_verifier::Error::Length;
        return match check {
            Check::Words(..) => {
                report.refuse(&error);
                Verdict::Undecodable
            }
            Check::Judge(_) => report.judged(Err(Refusal::Proof(error))),
        };
    }

    let mut bytes: Vec<u8> = Vec::with_capacity(proof_len);
    let found = hostcall!(
        HISTORICAL_LOOKUP,
        [
            NONE,
            hash.as_ptr() as u64,
            bytes.as_mut_ptr() as u64,
            0,
            proof_len as u64,
            0
        ]
    );
    if found != proof_len as u64 {
        return Verdict::NoPreimage;
    }
    // SAFETY: the host wrote all `proof_len` bytes.
    unsafe { bytes.set_len(proof_len) };
    report.gas_after_lookup = gas_left();

    match check {
        Check::Words(format, words) => {
            let decoded = match vos_pvm_final_verifier::decode(
                format,
                vos_pvm_final_verifier::LINKED,
                &bytes,
            ) {
                Ok(decoded) => decoded,
                Err(error) => {
                    report.gas_after_decode = gas_left();
                    report.refuse(&error);
                    return Verdict::Undecodable;
                }
            };
            drop(bytes);
            report.gas_after_decode = gas_left();
            match decoded.verify(&words) {
                Ok(_) => Verdict::Accept,
                Err(error) => report.refuse(&error),
            }
        }
        Check::Judge(admitted) => report.judged(admitted.verify(&bytes)),
    }
}
