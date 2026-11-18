//! `vos-anchor`'s space id, venue id, window clock, root kind and root
//! read, as its own encoding writes them: an id's 32 bytes; the clock's
//! origin, then its length, each a little-endian `u64`; a kind's byte, an
//! unknown one refused; a root read's kind, space, window (eight bytes,
//! little-endian) and root.

use alloc::vec::Vec;

use vos_anchor::{RootKind, RootRead, SpaceId, VenueId, WindowClock};

use crate::{Decode, DecodeError, Encode};

impl Encode for SpaceId {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.0);
    }
}

impl Decode for SpaceId {
    fn decode(data: &[u8]) -> Result<(Self, usize), DecodeError> {
        <[u8; 32]>::decode(data).map(|(id, used)| (SpaceId(id), used))
    }
}

impl Encode for VenueId {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.0);
    }
}

impl Decode for VenueId {
    fn decode(data: &[u8]) -> Result<(Self, usize), DecodeError> {
        <[u8; 32]>::decode(data).map(|(id, used)| (VenueId(id), used))
    }
}

impl Encode for RootKind {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        buf.push(*self as u8);
    }
}

impl Decode for RootKind {
    fn decode(data: &[u8]) -> Result<(Self, usize), DecodeError> {
        let (byte, used) = u8::decode(data)?;
        let kind = RootKind::from_u8(byte).ok_or(DecodeError::InvalidDiscriminator(byte))?;
        Ok((kind, used))
    }
}

impl Encode for RootRead {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        RootRead::encode_to(self, buf);
    }
}

impl Decode for RootRead {
    fn decode(data: &[u8]) -> Result<(Self, usize), DecodeError> {
        let (kind, used) = RootKind::decode(data)?;
        let (space, more) = SpaceId::decode(&data[used..])?;
        let (window, window_len) = u64::decode(&data[used + more..])?;
        let at = used + more + window_len;
        let (root, root_len) = <[u8; 32]>::decode(&data[at..])?;
        Ok((
            RootRead {
                kind,
                space,
                window,
                root,
            },
            at + root_len,
        ))
    }
}

impl Encode for WindowClock {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        WindowClock::encode_to(self, buf);
    }
}

impl Decode for WindowClock {
    fn decode(data: &[u8]) -> Result<(Self, usize), DecodeError> {
        let (origin_ms, used) = u64::decode(data)?;
        let (length_ms, more) = u64::decode(&data[used..])?;
        Ok((
            WindowClock {
                origin_ms,
                length_ms,
            },
            used + more,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each encodes as `vos-anchor` encodes it, and decodes back.
    #[test]
    fn as_vos_anchor_encodes_them() {
        let space = SpaceId([7; 32]);
        assert_eq!(space.encode(), [7; 32]);
        assert_eq!(SpaceId::decode(&[7; 32]).unwrap(), (space, 32));
        let clock = WindowClock {
            origin_ms: 0x0102_0304_0506_0708,
            length_ms: 600_000,
        };
        let mut anchor = Vec::new();
        WindowClock::encode_to(&clock, &mut anchor);
        assert_eq!(Encode::encode(&clock), anchor);
        assert_eq!(WindowClock::decode(&anchor).unwrap(), (clock, 16));
        assert!(WindowClock::decode(&anchor[..15]).is_err());

        let venue = VenueId([9; 32]);
        assert_eq!(venue.encode(), [9; 32]);
        assert_eq!(VenueId::decode(&[9; 32]).unwrap(), (venue, 32));
        let read = RootRead {
            kind: RootKind::Space,
            space,
            window: 0x0a0b_0c0d,
            root: [3; 32],
        };
        let mut anchor = Vec::new();
        RootRead::encode_to(&read, &mut anchor);
        assert_eq!(Encode::encode(&read), anchor);
        assert_eq!(anchor.len(), RootRead::BYTES);
        assert_eq!(RootRead::decode(&anchor).unwrap(), (read, RootRead::BYTES));
        assert!(RootRead::decode(&anchor[..RootRead::BYTES - 1]).is_err());
    }

    /// One root kind is known; a root read of any other byte is refused.
    #[test]
    fn an_unknown_root_kind_is_refused() {
        assert_eq!(RootKind::Space.encode(), [0]);
        let mut bytes = Encode::encode(&RootRead {
            kind: RootKind::Space,
            space: SpaceId::NONE,
            window: 1,
            root: [0; 32],
        });
        for byte in 1..=u8::MAX {
            bytes[0] = byte;
            assert!(RootKind::decode(&[byte]).is_err());
            assert!(RootRead::decode(&bytes).is_err());
        }
    }
}
