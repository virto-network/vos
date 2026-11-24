//! The user and their phone's keys, in memory: what every test of the
//! personal space prompts.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use ed25519_dalek::{Signer as _, SigningKey};
use hmac::{Hmac, Mac as _};
use zeroize::Zeroizing;

use crate::space::{AdminKey, Approval, Card, Error, Prompts};

/// HMAC-SHA-256 of `input` under `key`: a keystore key's and a security
/// key's output.
pub fn hmac(key: &[u8; 32], input: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key).expect("any key length");
    mac.update(input);
    mac.finalize().into_bytes().into()
}

/// A user and their phone's keys, kept across the app's restarts as the
/// keystore keeps them: each keystore key its own HMAC key (another alias,
/// another secret; an alias never made, no key), one security key (its
/// discoverable credential a kit's), and the admin keys made behind the
/// biometric. It shows and writes down every kit, enters the words it was
/// given, approves what it is asked unless told to decline.
pub struct Phone {
    /// The seed every keystore key's secret derives from.
    pub source: [u8; 32],
    /// The keystore's aliases made so far.
    pub aliases: Mutex<HashSet<Vec<u8>>>,
    pub security_key: [u8; 32],
    pub admins: Mutex<HashMap<[u8; 32], SigningKey>>,
    made: Mutex<u8>,
    /// Every phrase shown, the newest last.
    pub phrases: Mutex<Vec<String>>,
    /// Why each kit shown in place of an earlier one was so.
    pub voids: Mutex<Vec<String>>,
    /// Every kit's card shown, the newest last.
    pub cards: Mutex<Vec<Card>>,
    /// The words to enter when asked.
    pub words: Mutex<Option<String>>,
    /// How many times the kit's words were asked.
    pub entered: Mutex<usize>,
    /// Every stage a flow said, by its byte, in order.
    pub stages: Mutex<Vec<u8>>,
    /// Every stage an operation said in words, for the client's chrome.
    pub said: Mutex<Vec<String>>,
    /// The admin key that signed last.
    pub signed: Mutex<Option<[u8; 32]>>,
    /// Every approval asked.
    pub approvals: Mutex<Vec<Approval>>,
    /// The prompts still to decline, counted down at each.
    pub declines: Mutex<usize>,
    /// The keystore keys' evaluations so far.
    pub uses: Mutex<usize>,
    /// The keystore keys' evaluations still to fail, counted down at each.
    pub failures: Mutex<usize>,
    /// Said at each keystore evaluation, before its output is handed over:
    /// a test's marker that a proof is about to start.
    pub evaluating: Mutex<Option<fn()>>,
    /// The answers to the app's other forms (a sign-in's, a payment's), in
    /// order: the values confirmed, or `None` declined; past the script,
    /// every form confirmed as it is filled.
    pub confirms: Mutex<VecDeque<Option<Vec<String>>>>,
    /// Every one of those forms, as the app showed it.
    pub shown: Mutex<Vec<String>>,
    /// Every pairing check shown or confirmed, the newest last.
    pub checks: Mutex<Vec<String>>,
    /// The next pairing check this phone is asked to confirm is declined.
    pub decline_check: Mutex<bool>,
    /// How long the user takes to compare a pairing's check.
    pub comparing: Mutex<std::time::Duration>,
    /// How long the user takes to write a new phrase down.
    pub writing: Mutex<std::time::Duration>,
    /// The next phrase shown is cancelled.
    pub decline_phrase: Mutex<bool>,
    /// The admin keys made from now on are software keys, as a keystore
    /// with no Ed25519 in its TEE makes them.
    pub software: Mutex<bool>,
    /// The process asking is dead ([`Phone::die`]): nothing is shown, made
    /// or signed for it.
    dead: AtomicBool,
}

impl Phone {
    /// The phone of `seed`: its keys drawn from it.
    pub fn new(seed: u8) -> Self {
        Self {
            source: [seed; 32],
            aliases: Mutex::new(HashSet::new()),
            security_key: [seed ^ 0x80; 32],
            admins: Mutex::new(HashMap::new()),
            made: Mutex::new(seed.wrapping_mul(16)),
            phrases: Mutex::new(Vec::new()),
            voids: Mutex::new(Vec::new()),
            cards: Mutex::new(Vec::new()),
            words: Mutex::new(None),
            entered: Mutex::new(0),
            stages: Mutex::new(Vec::new()),
            said: Mutex::new(Vec::new()),
            signed: Mutex::new(None),
            approvals: Mutex::new(Vec::new()),
            declines: Mutex::new(0),
            uses: Mutex::new(0),
            failures: Mutex::new(0),
            evaluating: Mutex::new(None),
            confirms: Mutex::new(VecDeque::new()),
            shown: Mutex::new(Vec::new()),
            checks: Mutex::new(Vec::new()),
            decline_check: Mutex::new(false),
            comparing: Mutex::new(std::time::Duration::ZERO),
            writing: Mutex::new(std::time::Duration::ZERO),
            decline_phrase: Mutex::new(false),
            software: Mutex::new(false),
            dead: AtomicBool::new(false),
        }
    }

    /// The process asking died: every prompt it makes from now on is
    /// declined unseen, every key it asks made or used refused, until
    /// [`Phone::live`] (the next process's).
    pub fn die(&self) {
        self.dead.store(true, Ordering::SeqCst);
    }

    /// The next process asks.
    pub fn live(&self) {
        self.dead.store(false, Ordering::SeqCst);
    }

    fn dead(&self) -> bool {
        self.dead.load(Ordering::SeqCst)
    }

    /// The last phrase shown.
    pub fn phrase(&self) -> String {
        self.phrases
            .lock()
            .unwrap()
            .last()
            .cloned()
            .expect("a phrase shown")
    }

    /// The words entered when the kit is asked.
    pub fn will_enter(&self, words: String) {
        *self.words.lock().unwrap() = Some(words);
    }

    /// The next `n` prompts declined.
    pub fn decline(&self, n: usize) {
        *self.declines.lock().unwrap() = n;
    }

    /// The next of the app's other forms confirmed with `values`.
    pub fn will_confirm(&self, values: &[&str]) {
        self.confirms.lock().unwrap().push_back(Some(
            values.iter().map(|value| (*value).to_owned()).collect(),
        ));
    }

    /// The answer to one of the app's other forms, `shown` as it showed
    /// it, its fields `filled`: the script's next, or `filled` confirmed.
    pub fn answer(&self, shown: String, filled: Vec<String>) -> Option<Vec<String>> {
        self.shown.lock().unwrap().push(shown);
        self.confirms
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Some(filled))
    }

    /// The next `n` keystore evaluations failed.
    pub fn fail(&self, n: usize) {
        *self.failures.lock().unwrap() = n;
    }

    pub fn admin_keys(&self) -> usize {
        self.admins.lock().unwrap().len()
    }

    pub fn signed_by(&self) -> [u8; 32] {
        self.signed.lock().unwrap().expect("an admin signature")
    }

    /// Whether this prompt is declined: every one a dead process asks.
    fn declines(&self) -> bool {
        if self.dead() {
            return true;
        }
        let mut left = self.declines.lock().unwrap();
        let declined = *left > 0;
        *left = left.saturating_sub(1);
        declined
    }

    fn next(&self) -> u8 {
        let mut made = self.made.lock().unwrap();
        *made = made.wrapping_add(1);
        *made
    }

    /// The phone of `seed` in another process of the same device: its
    /// keystore holds the first key the device made, as an enrollment in
    /// an earlier process made it.
    pub fn restarted(seed: u8) -> Self {
        let phone = Self::new(seed);
        let first = format!("vos.device.{}", seed.wrapping_mul(16).wrapping_add(1));
        phone.aliases.lock().unwrap().insert(first.into_bytes());
        phone
    }

    /// A new keystore key: its alias.
    pub fn new_alias(&self) -> Vec<u8> {
        let alias = format!("vos.device.{}", self.next()).into_bytes();
        self.aliases.lock().unwrap().insert(alias.clone());
        alias
    }

    /// The keystore key `alias`'s HMAC of `input`: none for an alias never
    /// made.
    pub fn keystore(&self, alias: &[u8], input: &[u8]) -> Result<[u8; 32], String> {
        if !self.aliases.lock().unwrap().contains(alias) {
            return Err("the Keystore holds no such key".into());
        }
        {
            let mut failures = self.failures.lock().unwrap();
            if *failures > 0 {
                *failures -= 1;
                return Err("the keystore failed".into());
            }
        }
        *self.uses.lock().unwrap() += 1;
        if let Some(said) = *self.evaluating.lock().unwrap() {
            said();
        }
        Ok(hmac(&hmac(&self.source, alias), input))
    }
}

impl Prompts for Phone {
    fn stage(&self, stage: crate::space::Stage) {
        self.stages.lock().unwrap().push(stage as u8);
    }

    fn show_phrase(&self, words: &str, card: &Card, void: Option<&str>) -> bool {
        if self.dead() {
            return false;
        }
        if let Some(void) = void {
            self.voids.lock().unwrap().push(void.to_owned());
        }
        assert_eq!(words.split(' ').count(), 24, "a phrase's 24 words");
        self.phrases.lock().unwrap().push(words.to_owned());
        self.cards.lock().unwrap().push(card.clone());
        std::thread::sleep(*self.writing.lock().unwrap());
        !std::mem::take(&mut *self.decline_phrase.lock().unwrap()) && !self.declines()
    }

    fn show_card(&self, card: &Card, void: Option<&str>) -> bool {
        if self.dead() {
            return false;
        }
        if let Some(void) = void {
            self.voids.lock().unwrap().push(void.to_owned());
        }
        self.cards.lock().unwrap().push(card.clone());
        !self.declines()
    }

    fn enter_phrase(&self) -> Option<Zeroizing<String>> {
        if self.dead() {
            return None;
        }
        *self.entered.lock().unwrap() += 1;
        if self.declines() {
            return None;
        }
        let words = self.words.lock().unwrap().clone().expect("words to enter");
        Some(Zeroizing::new(words))
    }

    fn approve_admin(&self, approval: &Approval) -> bool {
        if self.dead() {
            return false;
        }
        self.approvals.lock().unwrap().push(approval.clone());
        !self.declines()
    }

    fn confirm_pairing(&self, check: &str) -> bool {
        if self.dead() {
            return false;
        }
        self.checks.lock().unwrap().push(check.to_owned());
        std::thread::sleep(*self.comparing.lock().unwrap());
        !std::mem::take(&mut *self.decline_check.lock().unwrap())
    }

    fn show_pairing(&self, check: &str) -> bool {
        if self.dead() {
            return false;
        }
        self.checks.lock().unwrap().push(check.to_owned());
        true
    }

    fn create_source(&self) -> Result<Vec<u8>, Error> {
        if self.dead() {
            return Err(Error::Declined);
        }
        Ok(self.new_alias())
    }

    fn evaluate_source(
        &self,
        source: &[u8],
        input: &[u8; 32],
    ) -> Result<Zeroizing<[u8; 32]>, Error> {
        if self.declines() {
            return Err(Error::Declined);
        }
        self.keystore(source, input)
            .map(Zeroizing::new)
            .map_err(Error::Source)
    }

    fn create_kit_key(&self) -> Result<Vec<u8>, Error> {
        if self.dead() {
            return Err(Error::Declined);
        }
        Ok(vec![self.next(); 16])
    }

    fn kit_secret(&self, _id: &[u8], salt: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, Error> {
        if self.dead() {
            return Err(Error::Declined);
        }
        Ok(Zeroizing::new(hmac(&self.security_key, salt)))
    }

    fn create_admin(&self) -> Result<AdminKey, Error> {
        if self.dead() {
            return Err(Error::Declined);
        }
        let key = SigningKey::from_bytes(&[self.next(); 32]);
        let public = key.verifying_key().to_bytes();
        self.admins.lock().unwrap().insert(public, key);
        // Hardware-backed with verified boot, unless the phone makes
        // software keys.
        let hardware = !*self.software.lock().unwrap();
        Ok(AdminKey {
            key: public,
            hardware,
            verified_boot: hardware,
        })
    }

    fn sign_admin(&self, key: &[u8; 32], message: &[u8]) -> Result<[u8; 64], Error> {
        if self.declines() {
            return Err(Error::Declined);
        }
        let admins = self.admins.lock().unwrap();
        let admin = admins
            .get(key)
            .ok_or_else(|| Error::Source("no such key".into()))?;
        *self.signed.lock().unwrap() = Some(admin.verifying_key().to_bytes());
        Ok(admin.sign(message).to_bytes())
    }
}
