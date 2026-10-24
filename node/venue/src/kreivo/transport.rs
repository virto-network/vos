//! How the client reaches Kreivo ([`Transport`]), and how it sends one call
//! there ([`Sender`]): signed once with the signer's next nonce, sent, and
//! followed to inclusion; after a lost connection, or the pool calling it
//! stale, sent again as the same bytes, never re-signed with another nonce
//! while the first may still land, so a call is included at most once. It
//! is taken as landed only once the signer's nonce in the best block's
//! state passes it, never by the pool's count.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use super::calls::{AccountId, Event, Failure, read};

/// The chain could not be reached: whether a call sent landed is unknown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lost(pub String);

/// An extrinsic signed, ready to send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signed {
    /// Its bytes.
    pub bytes: Vec<u8>,
    /// The signer's nonce it takes.
    pub nonce: u64,
    /// The last block it can be included in: its era's end.
    pub until: u64,
}

/// An extrinsic included in the best chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Included {
    /// The block's number.
    pub block: u64,
    /// The spaces pallet's events it emitted, each its SCALE bytes from the
    /// event's index on.
    pub events: Vec<Vec<u8>>,
    /// Its `DispatchError`'s bytes, when it failed.
    pub failure: Option<Vec<u8>>,
}

/// Why the pool refused an extrinsic: it was never included.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Invalid {
    /// `InvalidTransaction::Payment`: the fee's payer cannot pay, or the
    /// space's spend budget for the window is spent.
    Payment,
    /// Its nonce is used.
    Stale,
    /// Its nonce is ahead of the signer's.
    Future,
    /// The call does not decode at the chain.
    Call,
    /// The envelope this client builds is not the chain's: an extension
    /// list it does not know.
    Envelope(String),
    Other(String),
}

/// Why sending failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SendError {
    Lost(Lost),
    Invalid(Invalid),
}

impl From<Lost> for SendError {
    fn from(lost: Lost) -> Self {
        Self::Lost(lost)
    }
}

/// Kreivo as one signer reaches it.
pub trait Transport: Send + Sync {
    /// The signer's account.
    fn account(&self) -> AccountId;
    /// The chain's genesis hash: Kreivo's venue id.
    fn genesis(&self) -> Result<[u8; 32], Lost>;
    /// The best block's number.
    fn best(&self) -> Result<u64, Lost>;
    /// The signer's next nonce to sign with: the best block's, past the
    /// signer's extrinsics in the pool.
    fn nonce(&self) -> Result<u64, Lost>;
    /// The signer's nonce in the best block's state (`System.Account`): past
    /// an extrinsic's only once one of that nonce is included.
    fn chain_nonce(&self) -> Result<u64, Lost>;
    /// `call`'s bytes signed with `nonce`, the envelope the chain's.
    fn sign(&self, call: &[u8], nonce: u64) -> Result<Signed, SendError>;
    /// Send `signed` and follow it until the best chain includes it.
    fn send(&self, signed: &Signed) -> Result<Included, SendError>;
    /// The raw value at `key`, at the best block.
    fn storage(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Lost>;
    /// The keys under `prefix`, at the best block.
    fn keys(&self, prefix: &[u8]) -> Result<Vec<Vec<u8>>, Lost>;
}

/// A call's outcome as the chain reported it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub block: u64,
    /// Its failure, when it failed: its writes and events dropped.
    pub failure: Option<Failure>,
    /// The spaces pallet's events.
    pub events: Vec<Event>,
    /// Events or a failure this client cannot read.
    pub unread: Vec<Vec<u8>>,
}

impl Outcome {
    fn of(included: Included) -> Self {
        let mut unread = Vec::new();
        let failure = included.failure.and_then(|bytes| {
            let failure = read_prefix::<Failure>(&bytes);
            if failure.is_none() {
                unread.push(bytes);
            }
            failure
        });
        let events = included
            .events
            .into_iter()
            .filter_map(|bytes| {
                let event = read::<Event>(&bytes);
                if event.is_none() {
                    unread.push(bytes);
                }
                event
            })
            .collect();
        Self {
            block: included.block,
            failure,
            events,
            unread,
        }
    }
}

/// `T` from the head of `bytes`: a `DispatchError` in `ExtrinsicFailed` is
/// followed by the dispatch's info.
fn read_prefix<T: parity_scale_codec::Decode>(bytes: &[u8]) -> Option<T> {
    T::decode(&mut &bytes[..]).ok()
}

/// What became of a call sent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Sent {
    /// Included, with its outcome.
    Included(Outcome),
    /// The signer's nonce passed it while its answer was lost: it landed,
    /// its outcome unread. The caller reads the state it changed.
    Landed,
}

/// Why a call was not sent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Unsent {
    /// The pool refused it.
    Invalid(Invalid),
    /// The client is stopping.
    Stopped,
}

/// A wait doubled after each failure, up to 32 times the first.
pub(crate) struct Backoff {
    first: Duration,
    wait: Duration,
}

impl Backoff {
    pub(crate) fn new(first: Duration) -> Self {
        Self { first, wait: first }
    }

    /// The wait now; the next one doubled.
    pub(crate) fn next(&mut self) -> Duration {
        let wait = self.wait;
        self.wait = (wait * 2).min(self.first * 32);
        wait
    }

    /// Back to the first wait.
    pub(crate) fn reset(&mut self) {
        self.wait = self.first;
    }
}

/// Sends calls for one signer, one at a time.
pub struct Sender {
    transport: Arc<dyn Transport>,
    /// Held across a call: the signer's nonces go one call at a time.
    calling: std::sync::Mutex<()>,
    /// The first wait after a lost connection, doubled up to 32 times it.
    backoff: Duration,
    stopping: AtomicBool,
}

impl Sender {
    pub fn new(transport: Arc<dyn Transport>, backoff: Duration) -> Self {
        Self {
            transport,
            calling: std::sync::Mutex::new(()),
            backoff,
            stopping: AtomicBool::new(false),
        }
    }

    pub fn transport(&self) -> &Arc<dyn Transport> {
        &self.transport
    }

    /// Stop: a call waiting on the chain gives up.
    pub fn stop(&self) {
        self.stopping.store(true, Ordering::SeqCst);
    }

    fn stopped(&self) -> bool {
        self.stopping.load(Ordering::SeqCst)
    }

    /// `read` until the chain answers, waiting longer after each loss.
    fn retry<R>(&self, mut read: impl FnMut() -> Result<R, Lost>) -> Result<R, Unsent> {
        let mut backoff = Backoff::new(self.backoff);
        loop {
            if self.stopped() {
                return Err(Unsent::Stopped);
            }
            match read() {
                Ok(value) => return Ok(value),
                Err(Lost(why)) => {
                    tracing::warn!(%why, "Kreivo is not reachable; trying again");
                    std::thread::sleep(backoff.next());
                }
            }
        }
    }

    fn sign(&self, call: &[u8], nonce: u64) -> Result<Signed, Unsent> {
        let mut backoff = Backoff::new(self.backoff);
        loop {
            if self.stopped() {
                return Err(Unsent::Stopped);
            }
            match self.transport.sign(call, nonce) {
                Ok(signed) => return Ok(signed),
                Err(SendError::Invalid(invalid)) => return Err(Unsent::Invalid(invalid)),
                Err(SendError::Lost(Lost(why))) => {
                    tracing::warn!(%why, "Kreivo is not reachable to sign; trying again");
                    std::thread::sleep(backoff.next());
                }
            }
        }
    }

    /// Send `call` (its pinned bytes) signed by this signer, and follow it
    /// until it is included or refused. After a lost answer, or a stale
    /// nonce, it reads the signer's nonce in the best block's state: past
    /// the call's, it landed; otherwise the same bytes go again, signed
    /// anew with the same nonce only once their era has ended, when they
    /// can no longer land. Calls go one at a time.
    pub fn call(&self, call: &[u8]) -> Result<Sent, Unsent> {
        let _calling = self
            .calling
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let nonce = self.retry(|| self.transport.nonce())?;
        let mut signed = self.sign(call, nonce)?;
        let mut backoff = Backoff::new(self.backoff);
        loop {
            match self.transport.send(&signed) {
                Ok(included) => return Ok(Sent::Included(Outcome::of(included))),
                Err(SendError::Invalid(Invalid::Stale)) => {
                    tracing::warn!(nonce, "a call's nonce is used; reading whether it landed");
                }
                Err(SendError::Invalid(invalid)) => return Err(Unsent::Invalid(invalid)),
                Err(SendError::Lost(Lost(why))) => {
                    tracing::warn!(%why, nonce, "a call's answer was lost; reading whether it landed");
                }
            }
            std::thread::sleep(backoff.next());
            if self.retry(|| self.transport.chain_nonce())? > nonce {
                return Ok(Sent::Landed);
            }
            if self.retry(|| self.transport.best())? > signed.until {
                signed = self.sign(call, nonce)?;
            }
        }
    }
}
