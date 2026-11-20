// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Nothing the facility shows or keeps carries the member's secrets. The
//! facility is driven as its own process serves the Binder interface
//! ([`Node`]), with prompts whose key's output `o` is known: an enrollment, a sign-in on the tree
//! its feed served (the member at a slot of its own), a payment, and the failures (a refused and a failed
//! source, a node whose time does not decode, a malformed request, another
//! origin's unreadable enrollment). Every form the chrome is handed, every
//! answer as the server is answered, the enrollment files and the process's stderr are searched for
//! `o`, the secret `s` (its 32 bytes, in hex, and each word's digits and
//! bytes), BLAKE2b's `w` and the nullifier's key; and
//! every heap block freed meanwhile is searched for `o`, `s`, `w` and the
//! nullifier's key.

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::Read as _;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use blake2::{Blake2b512, Digest as _};
use common::*;
use vos_facility::node::{Device, Prompts};
use vos_facility::{Enroll, Outcome, Pay, SignIn};

/// Freed blocks up to this size are searched: the facility's own buffers,
/// futures and tasks, not the prover's large traces, which hold `s`'s
/// words by design (`vos-light`'s SECURITY.md); the prover's smaller
/// buffers are told apart by their frames (`by_the_prover`).
const SEARCHED: usize = 16 << 10;

/// The secrets a freed block must not hold, and how many blocks did: in
/// `FOUND`, with the first such block's backtrace in `FIRST`, and in
/// `PROVER` those the device prover freed, which `vos-light`'s SECURITY.md
/// states are freed, not overwritten: the kernel's traced run (its trace
/// frames and the Poseidon2 states of its side note) and the recursion
/// builder's `Context`.
static SECRETS: OnceLock<Vec<(&'static str, [u8; 32])>> = OnceLock::new();
static FOUND: [AtomicUsize; 8] = [const { AtomicUsize::new(0) }; 8];
static FIRST: [OnceLock<String>; 8] = [const { OnceLock::new() }; 8];
static PROVER: [AtomicUsize; 8] = [const { AtomicUsize::new(0) }; 8];

/// Whether a free's backtrace is the device prover's (`vos-pvm-device`,
/// on `vos-pvm-recair`'s masked prover): a frame of either crate, or, since
/// an inlined frame names its function alone, a frame in their source
/// files.
fn by_the_prover(trace: &str) -> bool {
    [
        "vos_pvm_device::",
        "pvm/proof/device/src/",
        "vos_pvm_recair::",
        "pvm/proof/recair/src/",
    ]
    .iter()
    .any(|frame| trace.contains(frame))
}

static ARMED: AtomicBool = AtomicBool::new(false);

thread_local! {
    /// Set while a hit's backtrace is taken, which allocates.
    static TRACING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

struct Searching;

impl Searching {
    fn search(ptr: *const u8, size: usize) {
        if !ARMED.load(Ordering::Relaxed)
            || !(32..=SEARCHED).contains(&size)
            || TRACING.with(|tracing| tracing.get())
        {
            return;
        }
        let Some(secrets) = SECRETS.get() else {
            return;
        };
        // SAFETY: the block being freed, `size` bytes, still ours.
        let block = unsafe { std::slice::from_raw_parts(ptr, size) };
        for (index, (_, secret)) in secrets.iter().enumerate() {
            if contains(block, secret) {
                TRACING.with(|tracing| tracing.set(true));
                let trace = std::backtrace::Backtrace::force_capture().to_string();
                if by_the_prover(&trace) {
                    PROVER[index].fetch_add(1, Ordering::Relaxed);
                } else {
                    FOUND[index].fetch_add(1, Ordering::Relaxed);
                    let _ = FIRST[index].set(trace);
                }
                TRACING.with(|tracing| tracing.set(false));
            }
        }
    }
}

// SAFETY: the system's allocator, searching a block before it frees it.
unsafe impl GlobalAlloc for Searching {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        Self::search(ptr, layout.size());
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // Moved to a new block always, so the old one is searched as freed.
        let new_layout = unsafe { Layout::from_size_align_unchecked(new_size, layout.align()) };
        let new = unsafe { System.alloc(new_layout) };
        if !new.is_null() {
            unsafe { std::ptr::copy_nonoverlapping(ptr, new, layout.size().min(new_size)) };
            Self::search(ptr, layout.size());
            unsafe { System.dealloc(ptr, layout) };
        }
        new
    }
}

#[global_allocator]
static ALLOCATOR: Searching = Searching;

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack.len() >= needle.len()
        && haystack
            .windows(needle.len())
            .any(|window| window[0] == needle[0] && window == needle)
}

/// The phone's seed, and its keystore's output for the space: the first
/// key it makes, the enrollment's.
const SEED: u8 = 0x6b;

fn output() -> [u8; 32] {
    let alias = format!("vos.device.{}", SEED.wrapping_mul(16).wrapping_add(1));
    let key = vos_light::testing::hmac(&[SEED; 32], alias.as_bytes());
    vos_light::testing::hmac(&key, &vos_light::source_input(&HANDLE))
}

/// An answer's bytes as the server is answered: the outcome's CBOR, or the
/// refusal's code and message.
fn carried(answer: &Result<Outcome, Refusal>) -> Vec<u8> {
    match answer {
        Ok(outcome) => {
            let mut bytes = Vec::new();
            ciborium::ser::into_writer(&outcome.to_value(), &mut bytes).unwrap();
            bytes
        }
        Err(refusal) => format!("{}: {}", refusal.code.as_str(), refusal.message).into_bytes(),
    }
}

fn code(answer: &Result<Outcome, Refusal>) -> Option<Code> {
    answer.as_ref().err().map(|refusal| refusal.code)
}

/// The secret's words, as `vos_light::derive_secret` takes them from `o`.
fn secret_words(output: &[u8; 32]) -> ([u32; 8], [u8; 64]) {
    let mut hasher = Blake2b512::new();
    hasher.update(b"vos/device/secret/v1");
    hasher.update(HANDLE);
    hasher.update(output);
    let w: [u8; 64] = hasher.finalize().into();
    let words = core::array::from_fn(|i| {
        (u64::from_le_bytes(w[8 * i..8 * i + 8].try_into().unwrap()) % u64::from(tree::P)) as u32
    });
    (words, w)
}

/// Each form of a secret a carrier must not hold: `text` ones only where
/// short patterns cannot occur by chance (no proof bytes beside them).
struct Forbidden {
    long: Vec<(String, Vec<u8>)>,
    short: Vec<(String, Vec<u8>)>,
}

impl Forbidden {
    fn new(secrets: &[(&str, [u8; 32])], words: &[u32; 8]) -> Self {
        let mut long = Vec::new();
        for (name, bytes) in secrets
            .iter()
            .map(|(name, bytes)| (name.to_string(), *bytes))
        {
            long.push((name.clone(), bytes.to_vec()));
            long.push((format!("{name} in hex"), hex::encode(bytes).into_bytes()));
            long.push((
                format!("{name} in HEX"),
                hex::encode_upper(bytes).into_bytes(),
            ));
        }
        let mut short = Vec::new();
        for (index, word) in words.iter().enumerate() {
            short.push((
                format!("s word {index} digits"),
                word.to_string().into_bytes(),
            ));
            short.push((format!("s word {index} bytes"), word.to_le_bytes().to_vec()));
        }
        Self { long, short }
    }

    /// Whether `carrier` holds none, the short forms checked too when it
    /// is `text`.
    fn check(&self, carrier: &str, bytes: &[u8], text: bool) {
        for (name, pattern) in self
            .long
            .iter()
            .chain(if text { &self.short[..] } else { &[] })
        {
            assert!(!contains(bytes, pattern), "{carrier} carries {name}");
        }
    }
}

/// Stderr into a file while held: what any thread prints meanwhile. Shown
/// on the real stderr if the test fails while it is held.
struct Stderr {
    saved: i32,
    path: std::path::PathBuf,
}

impl Stderr {
    fn capture(path: &std::path::Path) -> Self {
        use std::os::fd::AsRawFd as _;
        let file = std::fs::File::create(path).unwrap();
        let saved = unsafe { libc::dup(2) };
        assert!(saved >= 0);
        assert!(unsafe { libc::dup2(file.as_raw_fd(), 2) } >= 0);
        Self {
            saved,
            path: path.to_owned(),
        }
    }

    fn restore(&mut self) -> Vec<u8> {
        if self.saved >= 0 {
            unsafe {
                libc::dup2(self.saved, 2);
                libc::close(self.saved);
            }
            self.saved = -1;
        }
        let mut bytes = Vec::new();
        if let Ok(mut file) = std::fs::File::open(&self.path) {
            let _ = file.read_to_end(&mut bytes);
        }
        bytes
    }

    fn release(mut self) -> Vec<u8> {
        self.restore()
    }
}

impl Drop for Stderr {
    fn drop(&mut self) {
        if self.saved >= 0 {
            let printed = self.restore();
            eprintln!("{}", String::from_utf8_lossy(&printed));
        }
    }
}

#[test]
fn nothing_the_facility_shows_or_keeps_carries_a_secret() {
    let output = output();
    let (words, w) = secret_words(&output);
    let secret = tree::digest(&words);
    let nf_key = tree::digest(&tree::compress(&tree::Tag::Nf.block(), &words));
    let w_halves: [[u8; 32]; 2] = [w[..32].try_into().unwrap(), w[32..].try_into().unwrap()];
    let secrets = vec![
        ("o", output),
        ("s", secret),
        ("w's first half", w_halves[0]),
        ("w's second half", w_halves[1]),
        ("the nullifier's key", nf_key),
    ];
    let forbidden = Forbidden::new(&secrets, &words);
    SECRETS.set(secrets.clone()).unwrap();

    // The tree: five members before this one, so its leaf is at slot 5.
    let world = world();
    for n in 0..5u8 {
        world.enroll(AGENT, &tree::digest(&[u32::from(n) + 1; 8]));
    }
    let directory = tempfile::tempdir().unwrap();
    let store = directory.path().join("credentials");
    let store_text = store.to_str().unwrap();
    let stderr_path = directory.path().join("stderr");
    let shown = Arc::new(Phone::new(SEED));
    let prompts = || Arc::clone(&shown) as Arc<dyn Prompts>;
    let mut answers = Vec::new();

    let stderr = Stderr::capture(&stderr_path);
    ARMED.store(true, Ordering::SeqCst);
    let node = node(&world, &store, Arc::clone(&shown) as Arc<dyn Device>);
    // The app in the foreground, as while s4 shows a session: the client
    // stays awake between calls, so the tree's reads go on between them.
    node.foreground(true);
    let session = node.open_session(gateway());

    // Enrollment, its digests the secret's.
    shown.will_confirm(&[]);
    shown.will_confirm(&[]);
    let enrolled = node
        .enroll(session, Enroll::read(&enrollment()).unwrap(), prompts())
        .unwrap();
    let member = enrolled.member;
    answers.push((
        "the enrollment's answer",
        carried(&Ok(Outcome::Enrolled(enrolled))),
    ));
    assert_eq!(
        member,
        tree::digest(&tree::compress(&tree::Tag::Member.block(), &words)),
        "the secret searched for is the facility's"
    );
    world.enroll(AGENT, &member);
    node.granted(session).unwrap();
    // Sign-ins on a session of their own: the enrolling one showed the
    // digests, and pays.
    let signing = node.open_session(gateway());
    node.granted(signing).unwrap();

    // A sign-in on the tree kept apart.
    let login = sign_in();
    let signed = loop {
        shown.will_confirm(&[]);
        match node.sign_in(signing, login.clone(), prompts()) {
            Err(refusal) if matches!(refusal.code, Code::NoPath | Code::Unclaimed) => {
                shown.confirms.lock().unwrap().clear();
                std::thread::sleep(Duration::from_millis(200));
            }
            signed => break signed.unwrap(),
        }
    };
    let (_, request) = world.last_credentialed();
    let claim =
        vos_wire::credentials::AuthClaim::decode_exact(&request.claim).expect("an auth claim");
    assert_eq!(
        claim.map_root,
        world.root(AGENT),
        "proved on the tree's newest root"
    );
    answers.push((
        "the sign-in's answer",
        carried(&Ok(Outcome::SignedIn(signed))),
    ));

    // A payment.
    let pay = Pay::read(&object(&[
        ("agent", Value::from(AGENT)),
        ("instance", Value::from(PAYMENTS)),
        ("method", Value::from("transfer")),
        ("payee", Value::from("shop")),
        ("amount", Value::from(20u64)),
    ]))
    .unwrap();
    shown.will_confirm(&["shop", "20"]);
    let paid = node.pay(session, pay.clone(), prompts()).map(Outcome::Paid);
    assert!(paid.is_ok());
    answers.push(("the payment's answer", carried(&paid)));

    // The failures.
    let mut failed = |name: &'static str, answer: Result<Outcome, Refusal>, expected: Code| {
        assert_eq!(code(&answer), Some(expected), "{name}");
        answers.push((name, carried(&answer)));
    };
    shown.decline(1);
    shown.will_confirm(&[]);
    failed(
        "a refused source",
        node.sign_in(signing, login.clone(), prompts())
            .map(Outcome::SignedIn),
        Code::Declined,
    );
    shown.fail(1);
    shown.will_confirm(&[]);
    failed(
        "a failed source",
        node.sign_in(signing, login.clone(), prompts())
            .map(Outcome::SignedIn),
        Code::Source,
    );
    // A session's reading of the node's clock is its own: a new one reads
    // the bad time.
    world.state.lock().unwrap().bad_time = true;
    let late = node.open_session(gateway());
    node.granted(late).unwrap();
    shown.will_confirm(&["shop", "21"]);
    failed(
        "a node's bad time",
        node.pay(late, pay, prompts()).map(Outcome::Paid),
        Code::Api,
    );
    world.state.lock().unwrap().bad_time = false;
    failed(
        "a malformed request",
        node.sign_in(
            signing,
            SignIn {
                method: "log in".into(),
                ..login
            },
            prompts(),
        )
        .map(Outcome::SignedIn),
        Code::Arguments,
    );
    // Another origin's enrollment, unreadable: its member digest, its file
    // and the directory stay on the device.
    let other_member = hex::encode([0x77; 32]);
    let kept = vos_facility::kept::Kept::open(&store).unwrap();
    let (_, row) = kept.raw(b"enrollment/").unwrap().remove(0);
    let member_at = row.windows(32).position(|window| window == member).unwrap();
    let mut corrupt = row.clone();
    corrupt[member_at..member_at + 32].copy_from_slice(&[0x77; 32]);
    corrupt.pop();
    let other = [b"enrollment/".as_slice(), &[0; 16]].concat();
    kept.write(&other, Some(corrupt)).unwrap();
    shown.will_confirm(&[]);
    let unreadable = node
        .enroll(session, Enroll::read(&enrollment()).unwrap(), prompts())
        .map(Outcome::Enrolled);
    assert_eq!(code(&unreadable), Some(Code::Store));
    let unreadable = carried(&unreadable);
    for (what, pattern) in [
        ("another origin's member digest", other_member.as_str()),
        ("the enrollments' directory", store_text),
        ("another origin's row", "00000000000000000000000000000000"),
    ] {
        assert!(
            !contains(&unreadable, pattern.as_bytes()),
            "an unreadable enrollment's error names {what}"
        );
    }
    answers.push(("an unreadable enrollment's error", unreadable));
    kept.write(&other, None).unwrap();
    drop(kept);

    node.close(session);
    drop(node);
    ARMED.store(false, Ordering::SeqCst);
    let printed = stderr.release();

    let held = |found: &[AtomicUsize; 8]| {
        secrets
            .iter()
            .zip(found)
            .map(|((name, _), found)| (*name, found.load(Ordering::SeqCst)))
            .filter(|(_, blocks)| *blocks > 0)
            .collect::<Vec<_>>()
    };
    let firsts = FIRST
        .iter()
        .zip(secrets.iter())
        .filter_map(|(first, (name, _))| first.get().map(|trace| format!("{name}:\n{trace}")))
        .collect::<Vec<_>>();
    assert_eq!(
        held(&FOUND),
        [],
        "freed heap blocks held secrets; each one's first free:\n{}",
        firsts.join("\n")
    );
    let prover = held(&PROVER);
    eprintln!("freed by the device prover: {prover:?}");
    // The prover's traced run holds `s`: its frees are attributed to it,
    // or the attribution matched nothing and proves nothing.
    assert!(
        prover.iter().any(|(name, _)| *name == "s"),
        "no free attributed to the device prover held `s`: {prover:?}"
    );
    forbidden.check("stderr", &printed, true);
    for (name, answer) in &answers {
        forbidden.check(name, answer, false);
    }
    let forms = shown.shown.lock().unwrap();
    assert!(forms.len() >= 5);
    for form in forms.iter() {
        forbidden.check("a chrome form", form.as_bytes(), true);
    }
    for path in std::fs::read_dir(&store)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_file())
    {
        let kept = std::fs::read(&path).unwrap();
        forbidden.check("a file of the store", &kept, true);
    }
    // The facility's database, row by row: what it keeps.
    let kept = vos_facility::kept::Kept::open(&store).unwrap();
    for (key, value) in kept.raw(b"").unwrap() {
        forbidden.check(
            "a row of the facility's database",
            &[key, value].concat(),
            true,
        );
    }
}
