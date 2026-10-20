//! The client's transport over the mock ([`MockChain`]): each signer's
//! extrinsics are its nonce and its call's bytes, included one a block in
//! the order they arrive, each answered with its events and failure as
//! FRAME encodes them. `Timestamp.Now` and `System.Account` read as Kreivo
//! stores them. A pool holds what a test keeps from inclusion: the next
//! nonce to sign with counts it, the account's nonce does not. A test may
//! delay every send, lose a send's answer after it landed, drop a send
//! before it lands, or keep one in the pool; an extrinsic past its era is
//! refused as stale, as Kreivo refuses an ancient birth block.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use parity_scale_codec::{DecodeAll, Encode};

use super::types::AccountId;
use super::{Chain, Origin, Verdict, keys};
use crate::kreivo::transport::{Included, Invalid, Lost, SendError, Signed, Transport};

/// How many blocks a signed extrinsic is valid for: its era.
const ERA: u64 = 64;

/// What a test does to the next send.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// It lands, and its answer is lost.
    LoseAnswer,
    /// It is lost before it lands.
    Drop,
    /// It waits in the pool, its answer lost, until the test includes or
    /// drops the pool.
    Pool,
}

/// An extrinsic in the pool.
struct Pooled {
    origin: Origin,
    bytes: Vec<u8>,
    nonce: u64,
    until: u64,
}

struct Inner {
    chain: Chain,
    nonces: BTreeMap<AccountId, u64>,
    block: u64,
    pool: Vec<Pooled>,
    /// Every send's origin and call, in order, included or not.
    sends: Vec<(Origin, Vec<u8>)>,
    /// Every call included, by origin, in order.
    included: Vec<(Origin, Vec<u8>)>,
    faults: Vec<Fault>,
    latency: Duration,
}

impl Inner {
    fn nonce(&self, who: &AccountId) -> u64 {
        self.nonces.get(who).copied().unwrap_or(0)
    }

    /// Include `call` by `origin` at `nonce`: its outcome.
    fn include(
        &mut self,
        origin: Origin,
        nonce: u64,
        until: u64,
        call: Vec<u8>,
    ) -> Result<Included, SendError> {
        if let Origin::Signed(who) = origin {
            let next = self.nonce(&who);
            if nonce < next || self.block > until {
                return Err(SendError::Invalid(Invalid::Stale));
            }
            if nonce > next {
                return Err(SendError::Invalid(Invalid::Future));
            }
        }
        let outcome = self.chain.submit(origin, &call);
        let failure = match outcome.verdict {
            Verdict::Payment => return Err(SendError::Invalid(Invalid::Payment)),
            Verdict::Undecodable => return Err(SendError::Invalid(Invalid::Call)),
            Verdict::Ok => None,
            Verdict::Err(error) => Some(error.encode()),
        };
        if let Origin::Signed(who) = origin {
            *self.nonces.entry(who).or_default() += 1;
        }
        self.block += 1;
        self.included.push((origin, call));
        Ok(Included {
            block: self.block,
            events: outcome.events.iter().map(Encode::encode).collect(),
            failure,
        })
    }
}

/// The mock chain, shared by its signers' transports.
pub struct MockChain {
    inner: Mutex<Inner>,
    /// The chain's time, when it follows a clock rather than a test.
    clock: Option<Arc<dyn Fn() -> u64 + Send + Sync>>,
}

impl MockChain {
    pub fn new(chain: Chain) -> Arc<Self> {
        Self::with_clock(chain, None)
    }

    /// The chain, its time `clock`'s whenever it is read or a call lands.
    pub fn with_clock(
        chain: Chain,
        clock: Option<Arc<dyn Fn() -> u64 + Send + Sync>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner {
                chain,
                nonces: BTreeMap::new(),
                block: 1,
                pool: Vec::new(),
                sends: Vec::new(),
                included: Vec::new(),
                faults: Vec::new(),
                latency: Duration::ZERO,
            }),
            clock,
        })
    }

    fn inner(&self) -> MutexGuard<'_, Inner> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(clock) = &self.clock {
            inner.chain.set_now(clock());
        }
        inner
    }

    /// A transport that signs as `origin`.
    pub fn transport(self: &Arc<Self>, origin: Origin) -> Arc<MockTransport> {
        Arc::new(MockTransport {
            chain: Arc::clone(self),
            origin,
        })
    }

    /// Run `f` on the chain.
    pub fn with<R>(&self, f: impl FnOnce(&mut Chain) -> R) -> R {
        f(&mut self.inner().chain)
    }

    /// Every send's origin and call, included or not.
    pub fn sends(&self) -> Vec<(Origin, Vec<u8>)> {
        self.inner().sends.clone()
    }

    /// Every call included, with its origin.
    pub fn included(&self) -> Vec<(Origin, Vec<u8>)> {
        self.inner().included.clone()
    }

    /// Do `fault` to the next send.
    pub fn fault(&self, fault: Fault) {
        self.inner().faults.push(fault);
    }

    /// Delay every send by `latency`, as a block's wait does.
    pub fn set_latency(&self, latency: Duration) {
        self.inner().latency = latency;
    }

    /// End the current block, as time passing does: an era runs out.
    pub fn advance(&self, blocks: u64) {
        self.inner().block += blocks;
    }

    /// How many extrinsics wait in the pool.
    pub fn pooled(&self) -> usize {
        self.inner().pool.len()
    }

    /// Include the pool's extrinsics, by nonce, as a block author does;
    /// those past their era go.
    pub fn include_pool(&self) {
        let mut inner = self.inner();
        let mut pool = std::mem::take(&mut inner.pool);
        pool.sort_by_key(|pooled| pooled.nonce);
        for pooled in pool {
            let (nonce, call) = <(u64, Vec<u8>)>::decode_all(&mut &pooled.bytes[..])
                .expect("the pool holds what the transport signed");
            let _ = inner.include(pooled.origin, nonce, pooled.until, call);
        }
    }

    /// Drop the pool's extrinsics, as a pool does that lets them go.
    pub fn drop_pool(&self) {
        self.inner().pool.clear();
    }
}

/// One signer's transport over a [`MockChain`].
pub struct MockTransport {
    chain: Arc<MockChain>,
    origin: Origin,
}

impl Transport for MockTransport {
    fn account(&self) -> AccountId {
        match self.origin {
            Origin::Signed(who) => who,
            _ => [0; 32],
        }
    }

    fn genesis(&self) -> Result<[u8; 32], Lost> {
        Ok(self.chain.inner().chain.constants.venue.0)
    }

    fn best(&self) -> Result<u64, Lost> {
        Ok(self.chain.inner().block)
    }

    fn nonce(&self) -> Result<u64, Lost> {
        let inner = self.chain.inner();
        let who = self.account();
        let pooled = inner
            .pool
            .iter()
            .filter(|pooled| pooled.origin == self.origin)
            .count() as u64;
        Ok(inner.nonce(&who) + pooled)
    }

    fn chain_nonce(&self) -> Result<u64, Lost> {
        Ok(self.chain.inner().nonce(&self.account()))
    }

    fn sign(&self, call: &[u8], nonce: u64) -> Result<Signed, SendError> {
        Ok(Signed {
            bytes: (nonce, call).encode(),
            nonce,
            until: self.chain.inner().block + ERA,
        })
    }

    fn send(&self, signed: &Signed) -> Result<Included, SendError> {
        let latency = self.chain.inner().latency;
        std::thread::sleep(latency);
        let mut inner = self.chain.inner();
        let (nonce, call) = <(u64, Vec<u8>)>::decode_all(&mut &signed.bytes[..])
            .map_err(|_| SendError::Invalid(Invalid::Call))?;
        inner.sends.push((self.origin, call.clone()));
        if inner.pool.iter().any(|pooled| pooled.bytes == signed.bytes) {
            return Err(SendError::Lost(Lost("already in the pool".into())));
        }
        let fault = (!inner.faults.is_empty()).then(|| inner.faults.remove(0));
        match fault {
            Some(Fault::Drop) => Err(SendError::Lost(Lost("dropped before it landed".into()))),
            Some(Fault::Pool) => {
                inner.pool.push(Pooled {
                    origin: self.origin,
                    bytes: signed.bytes.clone(),
                    nonce,
                    until: signed.until,
                });
                Err(SendError::Lost(Lost("waiting in the pool".into())))
            }
            Some(Fault::LoseAnswer) => {
                inner.include(self.origin, nonce, signed.until, call)?;
                Err(SendError::Lost(Lost("the answer was lost".into())))
            }
            None => inner.include(self.origin, nonce, signed.until, call),
        }
    }

    fn storage(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Lost> {
        let inner = self.chain.inner();
        let account = [keys::twox128(b"System"), keys::twox128(b"Account")].concat();
        if key == [keys::twox128(b"Timestamp"), keys::twox128(b"Now")].concat() {
            return Ok(Some(inner.chain.now().encode()));
        }
        if let Some(who) = key
            .strip_prefix(&account[..])
            .and_then(|rest| <[u8; 32]>::try_from(rest.get(16..)?).ok())
        {
            let held = inner.chain.account(&who);
            let nonce = inner.nonces.get(&who).copied().unwrap_or(0) as u32;
            let info = (
                nonce,
                held.consumers,
                held.providers,
                0u32,
                held.free,
                held.held_registration + held.held_submit,
                0u128,
                0u128,
            );
            return Ok(Some(info.encode()));
        }
        Ok(inner.chain.storage().get(key).cloned())
    }

    fn keys(&self, prefix: &[u8]) -> Result<Vec<Vec<u8>>, Lost> {
        let inner = self.chain.inner();
        Ok(inner
            .chain
            .storage()
            .range(prefix.to_vec()..)
            .take_while(|(key, _)| key.starts_with(prefix))
            .map(|(key, _)| key.clone())
            .collect())
    }
}
