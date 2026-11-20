//! Pairing (`light-node.md` §3.8): a device of the group (the opener) and a
//! new device (the joiner) meet through a pairing slot's inbox at the
//! personal agent, over `Noise_XXpsk3_25519_ChaChaPoly_BLAKE2b`.
//!
//! - **The code** ([`Code`]): the opener opens a slot under its sync key
//!   ([`Opener::open`]: a random slot id and a slot key the agent admits
//!   for that slot alone) and shows a QR code of the home's handle and
//!   onions, the personal agent, the slot, its key and expiry, the opener's
//!   ephemeral key (the handshake's first message) and a 128-bit code. The
//!   code, the slot and the agent derive the handshake's pre-shared key,
//!   so the operators, who serve the slot's items and never see the QR,
//!   neither read the channel nor stand in for either side.
//! - **The handshake:** the joiner scans the code ([`Joiner::scan`]) and
//!   leaves the second message in the slot under the slot key; the opener
//!   answers with the third, which carries nothing.
//! - **The check:** both sides derive a six-digit check from the whole
//!   handshake's hash ([`check`]), the joiner showing it, the opener asking
//!   its user to confirm the joiner shows the same before it sends anything
//!   more ([`Opener::offer`]). Someone who photographed the QR and answered
//!   first holds a handshake of its own, which the third message ends: the
//!   user's new phone cannot read that message and shows no check, and the
//!   third is written after the second it answers, so no second is ground
//!   to a check the new phone shows.
//! - **The offer:** the opener's first message over the channel, its
//!   [`Offer`]: the home, which the joiner's "home" nullifier is of, and
//!   the user's other memberships, which it is enrolled in.
//! - **Over the channel:** the joiner sends its [`Hello`] (its keys, its
//!   nullifier, its key package, its handles in the offered spaces); the
//!   opener pairs it ([`crate::group::DeviceGroup::pair`]) and hands over
//!   the [`crate::group::Pairing`] (the log as it verified it, and the key
//!   archive with the naming secret and `R`), in as many items as it
//!   takes; the joiner acknowledges it by
//!   its hash. Only then does the opener make the commit adding the joiner,
//!   which closes the slot and deletes its items.
//!
//! Sans I/O: each side's caller puts the items it is given
//! ([`Put::arguments`], `Personal::put` to the slot, the opener under its
//! sync key, the joiner under the slot key) and hands each side the slot's
//! items it reads (`Personal::inbox`, every page of it: a handover of more
//! than a few items spans pages). A side lives in memory. A pairing cut
//! short (an error, the slot's expiry, the user's no, the opener's
//! restart) is started again from a new slot: the opener closes the old
//! one (`close_slot` of [`Opener::slot`]), and once it paired the joiner,
//! abandons the commit adding it ([`crate::group::DeviceGroup::abandon`]),
//! never sending it.
//!
//! *Known limits:* the pre-shared key enters at the third message, so a
//! joiner holding another code fails at the third message and the opener hears
//! nothing until the slot expires; a delayed admin's pairing (its add an
//! operation, its commit after the delay, past the slot's life) is not
//! built here: [`crate::group::DeviceGroup::pair`] makes a strong admin's
//! inline add.

use blake2::Blake2b;
use blake2::digest::Digest as _;
use blake2::digest::consts::{U16, U32};
use ed25519_dalek::SigningKey;
use vos_abi::ids::InstanceId;
use vos_abi::{Decode, Encode};
use vos_wire::books::{DeviceHandle, Space};
use vos_wire::credentials::Onion;
use vos_wire::personal::{Author, InboxItem, NewDevice, Recipient, Scope};
use zeroize::{Zeroize, Zeroizing};

use crate::group::Pairing;
use crate::home::Home;

/// The handshake's pattern.
const PATTERN: &str = "Noise_XXpsk3_25519_ChaChaPoly_BLAKE2b";

/// The code's bytes in the QR: its version first.
const VERSION: u8 = 1;
const PSK: &[u8] = b"vos/personal/pairing/psk";
const PROLOGUE: &[u8] = b"vos/personal/pairing/v1";
const ITEM: &[u8] = b"vos/personal/pairing/item";
const RECEIVED: &[u8] = b"vos/personal/pairing/received";
const CHECK: &[u8] = b"vos/personal/pairing/check";
/// A Noise message's bound, and an AEAD's tag.
const NOISE_MAX: usize = 65_535;
const TAG: usize = 16;
/// The handshake's first message: the opener's ephemeral key and the
/// tag of its empty payload, which the pre-shared key's mode encrypts.
const FIRST: usize = 32 + TAG;
/// The most bytes a handover takes: a full device set's log and an archive
/// of years of epochs fit many times over.
const MAX_HANDOVER: usize = 8 << 20;

/// What the QR code carries. Its `Debug` shows neither the slot key nor
/// the code.
#[derive(Clone, PartialEq, Eq, Encode, Decode)]
pub struct Code {
    /// The home's stable handle and its onions, each with the SSH host key
    /// the joiner pins.
    pub handle: [u8; 32],
    pub onions: Vec<Onion>,
    /// The personal agent, the identity its calls are signed for, and
    /// `Personal`'s instance in it.
    pub agent: u32,
    pub identity: [u8; 32],
    pub instance: InstanceId,
    pub slot: Scope,
    /// The slot key's ed25519 seed: the joiner's client key at the agent
    /// for the slot alone.
    pub key: [u8; 32],
    /// The slot's expiry, by the agent's batch time.
    pub expires: u64,
    /// The handshake's first message: the opener's ephemeral X25519 key,
    /// and its empty payload's tag.
    pub ephemeral: [u8; FIRST],
    pub code: [u8; 16],
}

impl core::fmt::Debug for Code {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Code")
            .field("agent", &self.agent)
            .field("slot", &self.slot)
            .field("expires", &self.expires)
            .finish_non_exhaustive()
    }
}

impl Drop for Code {
    fn drop(&mut self) {
        self.key.zeroize();
        self.code.zeroize();
    }
}

impl Code {
    /// The bytes the QR code shows.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        // Sized for the code and its onions, so no growth leaves a copy of
        // the slot key behind.
        let onions: usize = self.onions.len() * 64 + 5;
        let mut bytes = Vec::with_capacity(256 + onions);
        bytes.push(VERSION);
        self.encode_to(&mut bytes);
        Zeroizing::new(bytes)
    }

    /// The code a QR code showed; `None` for another version or bytes that
    /// do not decode.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        match bytes.split_first() {
            Some((&VERSION, rest)) => Self::decode_exact(rest),
            _ => None,
        }
    }

    /// The slot key, the joiner's client key at the agent.
    pub fn slot_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.key)
    }
}

/// A space the user is a member of, as the joining device needs it to
/// derive its secret there and confirm its enrollment: the space, its
/// handle, and its credential actor.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Membership {
    pub space: Space,
    pub handle: [u8; 32],
    pub agent: u32,
    pub identity: [u8; 32],
    pub credentials: InstanceId,
}

/// The opener's word in the handshake's last message: the home, and the
/// memberships the joiner is enrolled in at once (the chrome may defer
/// any).
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Offer {
    pub home: Home,
    pub memberships: Vec<Membership>,
}

/// The joiner's word over the channel: its keys (its "home" nullifier
/// among them), its key package, and its handle in each offered space.
/// Its `Debug` shows none of them: the nullifier links the device to its
/// agent.
#[derive(Clone, PartialEq, Eq, Encode, Decode)]
pub struct Hello {
    pub device: NewDevice,
    pub key_package: Vec<u8>,
    pub handles: Vec<(Space, DeviceHandle)>,
}

impl core::fmt::Debug for Hello {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Hello")
            .field("handles", &self.handles.len())
            .finish_non_exhaustive()
    }
}

/// An inbox item to leave in the slot: its id, its expiry (the slot's) and
/// its bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Put {
    pub slot: Scope,
    pub id: [u8; 16],
    pub expires: u64,
    pub bytes: Vec<u8>,
}

impl Put {
    /// `Personal::put`'s arguments.
    pub fn arguments(&self) -> Vec<u8> {
        (
            (Recipient::Slot(self.slot), self.id),
            (self.expires, self.bytes.clone()),
        )
            .encode()
    }
}

/// Why a pairing fails: it starts again with a new slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairError {
    /// The operating system gave no randomness.
    Random,
    /// A message did not authenticate: another code, or an item forged or
    /// replaced.
    Handshake,
    /// A message's plaintext does not decode, the handover is longer than
    /// its framed length, or a message exceeds a Noise message.
    Decode,
    /// The call is not this side's at this point of the pairing.
    Order,
    /// The handover's hash in the acknowledgement is not the one sent.
    Received,
}

impl core::fmt::Display for PairError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            PairError::Random => "the operating system gave no randomness",
            PairError::Handshake => "a pairing message did not authenticate",
            PairError::Decode => "a pairing message does not decode",
            PairError::Order => "not this side's step of the pairing",
            PairError::Received => "the handover acknowledged is not the one sent",
        })
    }
}

impl std::error::Error for PairError {}

impl From<snow::Error> for PairError {
    fn from(_: snow::Error) -> Self {
        PairError::Handshake
    }
}

/// The two sides, whose items' ids differ.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum Side {
    Opener = 0,
    Joiner = 1,
}

/// The id of `side`'s `n`th item in `slot`.
fn item_id(slot: &Scope, side: Side, n: u32) -> [u8; 16] {
    Blake2b::<U16>::new()
        .chain_update(ITEM)
        .chain_update(slot)
        .chain_update([side as u8])
        .chain_update(n.to_le_bytes())
        .finalize()
        .into()
}

fn psk(code: &[u8; 16], slot: &Scope, identity: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(
        Blake2b::<U32>::new()
            .chain_update(PSK)
            .chain_update(code)
            .chain_update(slot)
            .chain_update(identity)
            .finalize()
            .into(),
    )
}

fn prologue(slot: &Scope, identity: &[u8; 32]) -> Vec<u8> {
    [PROLOGUE, &identity[..], &slot[..]].concat()
}

fn received(handover: &[u8]) -> [u8; 32] {
    Blake2b::<U32>::new()
        .chain_update(RECEIVED)
        .chain_update(handover)
        .finalize()
        .into()
}

/// The six-digit check of a handshake whose hash is `hash`, as both sides
/// show it: `123 456`.
pub fn check(hash: &[u8]) -> String {
    let digest: [u8; 32] = Blake2b::<U32>::new()
        .chain_update(CHECK)
        .chain_update(hash)
        .finalize()
        .into();
    let n = u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]]) % 1_000_000;
    format!("{:03} {:03}", n / 1000, n % 1000)
}

fn random<const N: usize>() -> Result<[u8; N], PairError> {
    let mut bytes = [0; N];
    getrandom::getrandom(&mut bytes).map_err(|_| PairError::Random)?;
    Ok(bytes)
}

/// A handshake state for `slot` at the agent `identity` under `code`.
fn handshake(
    slot: &Scope,
    identity: &[u8; 32],
    code: &[u8; 16],
    initiator: bool,
) -> Result<snow::HandshakeState, PairError> {
    let params: snow::params::NoiseParams = PATTERN.parse().expect("the pattern parses");
    let builder = snow::Builder::new(params);
    let mut keypair = builder.generate_keypair()?;
    let private = Zeroizing::new(core::mem::take(&mut keypair.private));
    let psk = psk(code, slot, identity);
    let prologue = prologue(slot, identity);
    let builder = builder
        .local_private_key(&private)
        .psk(3, &psk[..])
        .prologue(&prologue);
    Ok(if initiator {
        builder.build_initiator()?
    } else {
        builder.build_responder()?
    })
}

/// The channel once the handshake is done: messages each side writes, in
/// order, and reads in its peer's order.
struct Channel {
    transport: snow::TransportState,
    /// The next item this side writes and the next of its peer's it reads.
    written: u32,
    read: u32,
}

impl Channel {
    fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, PairError> {
        let mut out = vec![0; plaintext.len() + TAG];
        let len = self.transport.write_message(plaintext, &mut out)?;
        out.truncate(len);
        Ok(out)
    }

    fn open(&mut self, message: &[u8]) -> Result<Zeroizing<Vec<u8>>, PairError> {
        let mut out = Zeroizing::new(vec![0; message.len()]);
        let len = self.transport.read_message(message, &mut out)?;
        out.truncate(len);
        Ok(out)
    }
}

/// The peer's item `n` among `items`: one in `slot`, by the peer.
fn find<'a>(items: &'a [InboxItem], slot: &Scope, peer: Side, n: u32) -> Option<&'a InboxItem> {
    let id = item_id(slot, peer, n);
    items.iter().find(|item| {
        item.id == id
            && item.item.to == Recipient::Slot(*slot)
            && match (peer, item.item.from) {
                (Side::Joiner, Author::Slot(from)) => from == *slot,
                (Side::Opener, Author::Device(_)) => true,
                _ => false,
            }
    })
}

/// The opener's part.
enum Opening {
    /// Its first message is in the code: waiting for the joiner's second.
    Shown(Box<snow::HandshakeState>),
    /// The handshake done, its check to confirm: then [`Opener::offer`].
    Checked(Channel),
    /// The offer sent: waiting for the joiner's hello.
    Offered(Channel),
    /// The hello read: the handover to send.
    Greeted(Channel),
    /// The handover sent, its hash: waiting for the acknowledgement.
    Handed(Channel, [u8; 32]),
    Done,
}

/// What the opener has read of the slot.
#[derive(Debug)]
pub enum Opened {
    /// Nothing new: read the slot again.
    Waiting,
    /// The joiner's second message read: leave `put`, the handshake's
    /// last message, in the slot; the user confirms the joiner shows
    /// `check`, then [`Opener::offer`].
    Check { check: String, put: Put },
    /// The joiner's hello: pair it, then [`Opener::hand_over`].
    Hello(Hello),
    /// The joiner holds the handover: make the commit adding it.
    Received,
}

/// The device that pairs another: its slot and its side of the channel.
pub struct Opener {
    /// The handshake's check, once it is done.
    check: Option<String>,
    slot: Scope,
    identity: [u8; 32],
    expires: u64,
    offer: Offer,
    item_bytes: usize,
    state: Opening,
}

/// The slot `Opener::open` draws: `Personal::open_slot`'s arguments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Slot {
    pub slot: Scope,
    pub key: [u8; 32],
}

impl Slot {
    pub fn arguments(&self) -> Vec<u8> {
        (self.slot, self.key).encode()
    }
}

/// The slot, its key and the code an opener draws: what its QR code
/// shows once the agent answers its `open_slot`.
pub struct Drawn {
    pub slot: Slot,
    seed: Zeroizing<[u8; 32]>,
    code: Zeroizing<[u8; 16]>,
    ephemeral: [u8; FIRST],
}

impl Opener {
    /// Draw a slot, its key and a code at the personal agent `identity`,
    /// and the handshake's first message; `offer` goes first over the
    /// channel, and
    /// the handover in items of at most `item_bytes` (the agent's
    /// policy's). Open the slot with [`Slot::arguments`], then show
    /// [`Opener::code`].
    pub fn open(
        identity: [u8; 32],
        offer: Offer,
        item_bytes: u32,
    ) -> Result<(Self, Drawn), PairError> {
        let slot: Scope = random()?;
        let seed = Zeroizing::new(random::<32>()?);
        let code = Zeroizing::new(random::<16>()?);
        let mut state = handshake(&slot, &identity, &code, true)?;
        let mut first = [0; FIRST];
        if state.write_message(&[], &mut first)? != first.len() {
            return Err(PairError::Handshake);
        }
        let key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        let opener = Self {
            check: None,
            slot,
            identity,
            expires: 0,
            offer,
            item_bytes: (item_bytes as usize).min(NOISE_MAX),
            state: Opening::Shown(Box::new(state)),
        };
        let drawn = Drawn {
            slot: Slot { slot, key },
            seed,
            code,
            ephemeral: first,
        };
        Ok((opener, drawn))
    }

    /// The QR code, once the agent opened the slot until `expires` (the
    /// batch time `open_slot` answered and the policy's `slot_ttl_ms`,
    /// [`crate::group::DeviceGroup::policy`]), every item's expiry; the
    /// home's `handle` and `onions`, and the agent `agent` with `Personal`
    /// at `instance`. Items are put only after it.
    pub fn code(
        &mut self,
        drawn: &Drawn,
        expires: u64,
        agent: u32,
        instance: InstanceId,
        onions: Vec<Onion>,
    ) -> Code {
        self.expires = expires;
        Code {
            handle: self.offer.home.handle,
            onions,
            agent,
            identity: self.identity,
            instance,
            slot: drawn.slot.slot,
            key: *drawn.seed,
            expires,
            ephemeral: drawn.ephemeral,
            code: *drawn.code,
        }
    }

    /// The slot, which a device closes when it gives up on a pairing.
    pub fn slot(&self) -> Scope {
        self.slot
    }

    /// The handshake's check, once it is done: what the user confirms the
    /// joiner shows before [`Opener::offer`].
    pub fn check(&self) -> Option<&str> {
        self.check.as_deref()
    }

    /// The offer, once the user confirmed the check: the item to leave in
    /// the slot.
    pub fn offer(&mut self) -> Result<Put, PairError> {
        let Opening::Checked(mut channel) = core::mem::replace(&mut self.state, Opening::Done)
        else {
            return Err(PairError::Order);
        };
        let offer = self.offer.encode();
        if offer.len() + TAG > NOISE_MAX.min(self.item_bytes) {
            return Err(PairError::Decode);
        }
        let sealed = channel.seal(&offer)?;
        let put = self.put(channel.written, sealed);
        channel.written += 1;
        self.state = Opening::Offered(channel);
        Ok(put)
    }

    fn put(&self, n: u32, bytes: Vec<u8>) -> Put {
        Put {
            slot: self.slot,
            id: item_id(&self.slot, Side::Opener, n),
            expires: self.expires,
            bytes,
        }
    }

    /// Read the slot's `items`: the next step, at most one a call.
    pub fn read(&mut self, items: &[InboxItem]) -> Result<Opened, PairError> {
        let state = core::mem::replace(&mut self.state, Opening::Done);
        let (state, opened) = self.step(state, items)?;
        self.state = state;
        if let Opened::Check { check, .. } = &opened {
            self.check = Some(check.clone());
        }
        Ok(opened)
    }

    fn step(&self, state: Opening, items: &[InboxItem]) -> Result<(Opening, Opened), PairError> {
        Ok(match state {
            Opening::Shown(mut handshake) => {
                let Some(item) = find(items, &self.slot, Side::Joiner, 0) else {
                    return Ok((Opening::Shown(handshake), Opened::Waiting));
                };
                let mut payload = vec![0; item.item.bytes.len()];
                handshake.read_message(&item.item.bytes, &mut payload)?;
                let mut third = vec![0; 32 + 48 + 2 * TAG];
                let len = handshake.write_message(&[], &mut third)?;
                third.truncate(len);
                let check = check(handshake.get_handshake_hash());
                let channel = Channel {
                    transport: handshake.into_transport_mode()?,
                    written: 1,
                    read: 1,
                };
                let put = self.put(0, third);
                (Opening::Checked(channel), Opened::Check { check, put })
            }
            state @ Opening::Checked(_) => (state, Opened::Waiting),
            Opening::Offered(mut channel) => {
                let Some(item) = find(items, &self.slot, Side::Joiner, channel.read) else {
                    return Ok((Opening::Offered(channel), Opened::Waiting));
                };
                let plain = channel.open(&item.item.bytes)?;
                let hello = Hello::decode_exact(&plain).ok_or(PairError::Decode)?;
                channel.read += 1;
                (Opening::Greeted(channel), Opened::Hello(hello))
            }
            Opening::Handed(mut channel, hash) => {
                let Some(item) = find(items, &self.slot, Side::Joiner, channel.read) else {
                    return Ok((Opening::Handed(channel, hash), Opened::Waiting));
                };
                let plain = channel.open(&item.item.bytes)?;
                if plain.as_slice() != hash {
                    return Err(PairError::Received);
                }
                (Opening::Done, Opened::Received)
            }
            state @ Opening::Greeted(_) => (state, Opened::Waiting),
            Opening::Done => return Err(PairError::Order),
        })
    }

    /// Hand `pairing` over, after the joiner's hello: the items to leave in
    /// the slot. The commit waits for [`Opened::Received`].
    pub fn hand_over(&mut self, pairing: &Pairing) -> Result<Vec<Put>, PairError> {
        let Opening::Greeted(mut channel) = core::mem::replace(&mut self.state, Opening::Done)
        else {
            return Err(PairError::Order);
        };
        let bytes = Zeroizing::new(pairing.to_bytes());
        let mut framed = Zeroizing::new((bytes.len() as u32).to_le_bytes().to_vec());
        framed.extend_from_slice(&bytes);
        let room = self.item_bytes.saturating_sub(TAG).max(1);
        let mut puts = Vec::new();
        for chunk in framed.chunks(room) {
            let sealed = channel.seal(chunk)?;
            puts.push(self.put(channel.written, sealed));
            channel.written += 1;
        }
        self.state = Opening::Handed(channel, received(&bytes));
        Ok(puts)
    }
}

/// The joiner's part.
enum Joining {
    /// Its second message sent: waiting for the third.
    Scanned(Box<snow::HandshakeState>),
    /// The handshake done, its check shown: waiting for the offer.
    Checked(Channel),
    /// The offer read: its hello to send.
    Offered(Channel),
    /// The hello sent: reading the handover, its length and what came.
    Greeted(Channel, Option<usize>, Zeroizing<Vec<u8>>),
    Done,
}

/// What the joiner has read of the slot.
pub enum Joined {
    /// Nothing new: read the slot again.
    Waiting,
    /// The handshake done: show its check while the opener's user
    /// confirms it, and read the slot again.
    Check(String),
    /// The opener's offer: send [`Joiner::hello`].
    Offer(Offer),
    /// The handover, whole: join with it
    /// ([`crate::group::DeviceGroup::join`]), and leave the
    /// acknowledgement in the slot.
    Handover(Box<Pairing>, Put),
}

impl core::fmt::Debug for Joined {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Joined::Waiting => f.write_str("Waiting"),
            Joined::Check(check) => f.debug_tuple("Check").field(check).finish(),
            Joined::Offer(offer) => f.debug_tuple("Offer").field(offer).finish(),
            Joined::Handover(..) => f.write_str("Handover(..)"),
        }
    }
}

/// The device being paired: its side of the channel.
pub struct Joiner {
    /// The handshake's check, once it is done.
    check: Option<String>,
    slot: Scope,
    expires: u64,
    state: Joining,
}

impl Joiner {
    /// Scan `code`: the handshake's second message, to leave in the slot
    /// under the code's slot key.
    pub fn scan(code: &Code) -> Result<(Self, Put), PairError> {
        let mut state = handshake(&code.slot, &code.identity, &code.code, false)?;
        let mut payload = [0; 0];
        state.read_message(&code.ephemeral, &mut payload)?;
        let mut second = vec![0; 32 + 48 + 2 * TAG];
        let len = state.write_message(&[], &mut second)?;
        second.truncate(len);
        let joiner = Self {
            check: None,
            slot: code.slot,
            expires: code.expires,
            state: Joining::Scanned(Box::new(state)),
        };
        let put = joiner.put(0, second);
        Ok((joiner, put))
    }

    fn put(&self, n: u32, bytes: Vec<u8>) -> Put {
        Put {
            slot: self.slot,
            id: item_id(&self.slot, Side::Joiner, n),
            expires: self.expires,
            bytes,
        }
    }

    /// The handshake's check, once it is done: what this device shows
    /// while the opener's user confirms it.
    pub fn check(&self) -> Option<&str> {
        self.check.as_deref()
    }

    /// Read the slot's `items`: the next step.
    pub fn read(&mut self, items: &[InboxItem]) -> Result<Joined, PairError> {
        let state = core::mem::replace(&mut self.state, Joining::Done);
        let (state, joined) = self.step(state, items)?;
        self.state = state;
        if let Joined::Check(check) = &joined {
            self.check = Some(check.clone());
        }
        Ok(joined)
    }

    fn step(&self, state: Joining, items: &[InboxItem]) -> Result<(Joining, Joined), PairError> {
        Ok(match state {
            Joining::Scanned(mut handshake) => {
                let Some(item) = find(items, &self.slot, Side::Opener, 0) else {
                    return Ok((Joining::Scanned(handshake), Joined::Waiting));
                };
                let mut payload = vec![0; item.item.bytes.len()];
                handshake.read_message(&item.item.bytes, &mut payload)?;
                let check = check(handshake.get_handshake_hash());
                let channel = Channel {
                    transport: handshake.into_transport_mode()?,
                    written: 1,
                    read: 1,
                };
                (Joining::Checked(channel), Joined::Check(check))
            }
            Joining::Checked(mut channel) => {
                let Some(item) = find(items, &self.slot, Side::Opener, channel.read) else {
                    return Ok((Joining::Checked(channel), Joined::Waiting));
                };
                let plain = channel.open(&item.item.bytes)?;
                let offer = Offer::decode_exact(&plain).ok_or(PairError::Decode)?;
                channel.read += 1;
                (Joining::Offered(channel), Joined::Offer(offer))
            }
            Joining::Greeted(mut channel, mut length, mut bytes) => loop {
                let Some(item) = find(items, &self.slot, Side::Opener, channel.read) else {
                    break (Joining::Greeted(channel, length, bytes), Joined::Waiting);
                };
                let plain = channel.open(&item.item.bytes)?;
                channel.read += 1;
                bytes.extend_from_slice(&plain);
                if length.is_none() && bytes.len() >= 4 {
                    let framed = u32::from_le_bytes(bytes[..4].try_into().expect("four bytes"));
                    let framed = framed as usize;
                    if framed > MAX_HANDOVER {
                        return Err(PairError::Decode);
                    }
                    length = Some(framed);
                    let mut whole = Zeroizing::new(Vec::with_capacity(framed));
                    whole.extend_from_slice(&bytes[4..]);
                    bytes = whole;
                }
                match length {
                    Some(length) if bytes.len() > length => return Err(PairError::Decode),
                    Some(length) if bytes.len() == length => {
                        let pairing = Pairing::from_bytes(&bytes).ok_or(PairError::Decode)?;
                        let ack = channel.seal(&received(&bytes))?;
                        let put = self.put(channel.written, ack);
                        break (Joining::Done, Joined::Handover(Box::new(pairing), put));
                    }
                    _ => {}
                }
            },
            state @ Joining::Offered(_) => (state, Joined::Waiting),
            Joining::Done => return Err(PairError::Order),
        })
    }

    /// This device's hello, after the offer: the item to leave in the slot.
    pub fn hello(&mut self, hello: &Hello) -> Result<Put, PairError> {
        let Joining::Offered(mut channel) = core::mem::replace(&mut self.state, Joining::Done)
        else {
            return Err(PairError::Order);
        };
        let bytes = hello.encode();
        if bytes.len() + TAG > NOISE_MAX {
            return Err(PairError::Decode);
        }
        let sealed = channel.seal(&bytes)?;
        let put = self.put(channel.written, sealed);
        channel.written += 1;
        self.state = Joining::Greeted(channel, None, Zeroizing::new(Vec::new()));
        Ok(put)
    }
}
