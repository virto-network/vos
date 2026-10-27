//! The node's binary API (`docs/design/node-api.md`): length-framed
//! requests of a numbered kind, each answered by one frame, over a unix
//! socket or QUIC with mutual TLS. Every kind's body is sized from its
//! frame's header before a byte of it is read; operator kinds carry an
//! [`Operated`] envelope, signed for one node.

#[cfg(feature = "client")]
pub mod client;
mod frame;
mod operated;
#[cfg(feature = "quic")]
pub mod quic;

pub use frame::{Event, Frame, Framing, Header, MAX_ANSWER, Reader, Requests, error_frame, frame};
pub use operated::{CREDENTIALS, OPERATOR_DOMAIN, Operated, operator_message};

use scale::{Decode, Encode};
use vos_wire::abi::cap;

/// The most a request's body holds beyond its call's cap: its envelope.
pub const ENVELOPE: usize = 4096;
/// An agent's id ahead of a body that names one.
const AGENT: u32 = 4;
/// [`Operated`]'s bytes beside the inner body: the node 32, the key 32,
/// the nonce 16, the expiry 8, the inner body's length 4 and the
/// signature 64.
pub const OPERATED: u32 = 156;
/// A client request's body as the HTTP ingress takes it.
const REQUEST: u32 = (cap::REQUEST + ENVELOPE) as u32;
/// An install's body as the HTTP ingress takes it.
const INSTALL: u32 = (cap::MAX_ELF + ENVELOPE) as u32;
/// An operator read's inner body, at most: an agent, with room to spare.
const OPERATOR_READ: u32 = ENVELOPE as u32;
/// An install's body past this is large. A node holds few at once, from
/// every transport.
pub const LARGE: u32 = REQUEST + AGENT + OPERATED;
/// The most a credential proof holds, in any format: a device proof's
/// 1.5 MiB.
pub const MAX_CREDENTIAL_PROOF: usize = 3 << 19;
/// A credentialed call's body as HTTP takes it: the proof, the arguments'
/// cap and the envelope, less the agent's id a frame's body leads with.
pub const CREDENTIALED_HTTP: usize =
    MAX_CREDENTIAL_PROOF + cap::REQUEST + ENVELOPE - AGENT as usize;

/// The frame error's kind: an answer only, never a request.
pub const FRAME_ERROR: u16 = 0xffff;

/// A request's kind: its number, its body's limit, who may send it, and
/// whether a relay passes it on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum Kind {
    /// The node's key: `NodeId`.
    NodeKey = 0x0001,
    /// The node's clock, in milliseconds: a `u64`.
    Time = 0x0002,
    /// An agent's record and replicas: `Option<AgentInfo>`.
    AgentInfo = 0x0003,
    /// An installed instance's schema: `Option<Schema>`.
    Schema = 0x0004,
    Call = 0x0101,
    Query = 0x0102,
    Workflow = 0x0103,
    /// A call whose authority is a credential proof: no session, no
    /// signature.
    Credentialed = 0x0104,
    Stats = 0x0201,
    Status = 0x0202,
    CreateAgent = 0x0203,
    CreateRepresentative = 0x0204,
    Install = 0x0205,
    Replace = 0x0206,
    Grant = 0x0207,
    Reports = 0x0208,
}

impl Kind {
    pub const ALL: [Kind; 16] = [
        Kind::NodeKey,
        Kind::Time,
        Kind::AgentInfo,
        Kind::Schema,
        Kind::Call,
        Kind::Query,
        Kind::Workflow,
        Kind::Credentialed,
        Kind::Stats,
        Kind::Status,
        Kind::CreateAgent,
        Kind::CreateRepresentative,
        Kind::Install,
        Kind::Replace,
        Kind::Grant,
        Kind::Reports,
    ];

    /// The kind numbered `number`, if one is.
    pub fn from_u16(number: u16) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| *kind as u16 == number)
    }

    /// The most its body holds, in bytes: today's HTTP limit for its route
    /// plus the agent's id where it names one, and an operator's envelope;
    /// a credentialed call's, the largest proof's 1.5 MiB plus the
    /// arguments' cap and 4 KiB.
    pub fn limit(self) -> u32 {
        match self {
            Kind::NodeKey | Kind::Time => 0,
            Kind::AgentInfo => AGENT,
            Kind::Schema => 2 * AGENT,
            Kind::Call | Kind::Query | Kind::Workflow => REQUEST + AGENT,
            Kind::Credentialed => (CREDENTIALED_HTTP + AGENT as usize) as u32,
            Kind::Stats | Kind::Status => OPERATOR_READ + OPERATED,
            Kind::Install => INSTALL + AGENT + OPERATED,
            Kind::CreateAgent
            | Kind::CreateRepresentative
            | Kind::Replace
            | Kind::Grant
            | Kind::Reports => REQUEST + AGENT + OPERATED,
        }
    }

    /// Whether the gateway's `vos-api` subsystem relays it: the public
    /// reads, the node's time and queries.
    pub fn relayed(self) -> bool {
        matches!(
            self,
            Kind::NodeKey | Kind::Time | Kind::AgentInfo | Kind::Schema | Kind::Query
        )
    }

    /// Whether an operator key must sign it: the table says, not the
    /// number's range.
    pub fn operator(self) -> bool {
        matches!(
            self,
            Kind::Stats
                | Kind::Status
                | Kind::CreateAgent
                | Kind::CreateRepresentative
                | Kind::Install
                | Kind::Replace
                | Kind::Grant
                | Kind::Reports
        )
    }

    /// Whether the node records its nonce: an operator's command, which may
    /// not run twice. The operator's reads record none.
    pub fn records_nonce(self) -> bool {
        self.operator() && !matches!(self, Kind::Stats | Kind::Status)
    }
}

/// Why a frame was not taken: the body of a frame of kind
/// [`FRAME_ERROR`]. Every variant but [`FrameError::Unavailable`] closes
/// the QUIC stream, or the byte stream's connection, once written.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub enum FrameError {
    /// The body is past its kind's limit.
    #[codec(index = 0)]
    Oversize { limit: u32 },
    #[codec(index = 1)]
    UnknownKind,
    /// The length is shorter than the header, or the frame ended early.
    #[codec(index = 2)]
    Truncated,
    /// A relay does not pass this kind on.
    #[codec(index = 3)]
    NotRelayed,
    /// A relay's upstream gave no answer.
    #[codec(index = 4)]
    Unavailable,
}

impl FrameError {
    /// Whether the channel goes on after it: the framing is intact.
    pub fn keeps_open(self) -> bool {
        self == FrameError::Unavailable
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The table's limits, as the brief pins them.
    #[test]
    fn the_limits_are_the_briefs() {
        let limit = |kind: Kind| kind.limit();
        assert_eq!(limit(Kind::NodeKey), 0);
        assert_eq!(limit(Kind::Time), 0);
        assert_eq!(limit(Kind::AgentInfo), 4);
        assert_eq!(limit(Kind::Schema), 8);
        for kind in [Kind::Call, Kind::Query, Kind::Workflow] {
            assert_eq!(limit(kind), 69_636);
        }
        for kind in [Kind::Stats, Kind::Status] {
            assert_eq!(limit(kind), 4_252);
        }
        for kind in [
            Kind::CreateAgent,
            Kind::CreateRepresentative,
            Kind::Replace,
            Kind::Grant,
            Kind::Reports,
        ] {
            assert_eq!(limit(kind), 69_792);
        }
        assert_eq!(limit(Kind::Install), 67_113_120);
        assert_eq!(limit(Kind::Credentialed), 1_642_496);
        assert_eq!(CREDENTIALED_HTTP, 1_642_492);
        for kind in Kind::ALL {
            let large = matches!(kind, Kind::Install | Kind::Credentialed);
            assert_eq!(kind.limit() > LARGE, large, "{kind:?}");
        }
    }

    #[test]
    fn every_kind_is_its_number() {
        for kind in Kind::ALL {
            assert_eq!(Kind::from_u16(kind as u16), Some(kind));
        }
        assert_eq!(Kind::Credentialed as u16, 0x0104);
        for number in [0, FRAME_ERROR, 0x0005, 0x0105, 0x0209] {
            assert_eq!(Kind::from_u16(number), None, "{number:#06x}");
        }
        let relayed: Vec<Kind> = Kind::ALL.into_iter().filter(|k| k.relayed()).collect();
        assert_eq!(
            relayed,
            [
                Kind::NodeKey,
                Kind::Time,
                Kind::AgentInfo,
                Kind::Schema,
                Kind::Query
            ]
        );
        let nonces = Kind::ALL.into_iter().filter(|k| k.records_nonce()).count();
        assert_eq!(nonces, 6);
        let operators = Kind::ALL.into_iter().filter(|k| k.operator()).count();
        assert_eq!(operators, 8);
        assert!(Kind::Stats.operator() && !Kind::Stats.records_nonce());
        assert!(!Kind::Call.operator());
    }

    /// The frame error's encodings, pinned.
    #[test]
    fn frame_errors_are_pinned() {
        assert_eq!(
            FrameError::Oversize { limit: 0x0102_0304 }.encode(),
            [0, 4, 3, 2, 1]
        );
        assert_eq!(FrameError::UnknownKind.encode(), [1]);
        assert_eq!(FrameError::Truncated.encode(), [2]);
        assert_eq!(FrameError::NotRelayed.encode(), [3]);
        assert_eq!(FrameError::Unavailable.encode(), [4]);
        assert!(FrameError::Unavailable.keeps_open());
        use vos_wire::ingress::{OperatorRefusal, Rejection};
        let refusals = [
            (
                OperatorRefusal::Expiry { now: 1 },
                vec![10, 0, 1, 0, 0, 0, 0, 0, 0, 0],
            ),
            (OperatorRefusal::Replayed, vec![10, 1]),
            (OperatorRefusal::SocketOnly, vec![10, 2]),
            (OperatorRefusal::OtherNode, vec![10, 3]),
        ];
        for (refusal, bytes) in refusals {
            assert_eq!(Rejection::Operator(refusal).encode(), bytes);
        }
        assert!(!FrameError::Truncated.keeps_open());
    }
}
