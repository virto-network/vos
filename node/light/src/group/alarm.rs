//! Why a candidate was void, the alarms a device raises and what each asks
//! of the user, and the clock alarm.

use vos_abi::{Decode, Encode};
use vos_wire::personal::{DeviceId, Scope};

/// Why a candidate was void, as this device counted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Why {
    /// A device of the set nacked it: the chrome names it.
    Nack(DeviceId),
    /// The set confirmed two different `h`.
    Split,
    /// The window passed without the set complete.
    Timeout,
    /// The agent voided it before this device's count decided it.
    Agent,
    /// A regroup or a restore matured: a new group starts.
    Regroup,
}

/// What a device raises to its user. Kept in the store from the batch
/// that consumes its evidence until the chrome acknowledges it
/// ([`DeviceGroup::alarms`](super::DeviceGroup::alarms),
/// [`DeviceGroup::acknowledge`](super::DeviceGroup::acknowledge)).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Alarm {
    /// The log does not chain from what this device saw at `index`: a
    /// rollback or a fork. The device reads no further.
    #[codec(index = 0)]
    Log { index: u64 },
    /// A vote by `device`, of `epoch`'s logged set, does not verify against
    /// the candidate as this device's log holds it: the devices were shown
    /// two logs (a different confirming set), or the vote is forged.
    #[codec(index = 1)]
    SplitLog { epoch: u64, device: DeviceId },
    /// The log names this device absent from `epoch`'s confirming set
    /// though it made a call within the window.
    #[codec(index = 2)]
    NamedAbsent { epoch: u64, last_call: u64 },
    /// This device refused `epoch`'s candidate by `committer`: its evidence
    /// does not verify, its effect is not the matured operations', or its
    /// handshake does not process. It nacked, if it votes.
    #[codec(index = 3)]
    Refused { epoch: u64, committer: DeviceId },
    /// `epoch` was confirmed and this device cannot follow it: it could not
    /// process `committer`'s commit, or its `h` is not the confirmed one.
    #[codec(index = 4)]
    CannotFollow {
        epoch: u64,
        committer: DeviceId,
        remedy: Remedy,
    },
    /// The agent's verdict on `epoch` is not this device's count.
    #[codec(index = 5)]
    Verdict { epoch: u64 },
    /// The log's entry at `index` asserts a maturity its evidence does not
    /// support: no verified operation, or one whose delay had not passed
    /// with no verified second signature or resolution, or vetoed. It is
    /// ignored.
    #[codec(index = 6)]
    Unsigned { index: u64 },
    /// The device's clock and the agent's batch time disagree by `skew_ms`,
    /// more than an hour: the device acts as the log says.
    #[codec(index = 7)]
    Clock { skew_ms: u64 },
    /// The kit signed the operation at `index`: every device shows it for
    /// as long as it is open, and its user vetoes it or rotates the kit.
    #[codec(index = 8)]
    Kit { index: u64 },
    /// The agent's log head, `next`, is behind what this device read of
    /// it, or diverges from it there: a rollback.
    #[codec(index = 9)]
    Rollback { next: u64 },
    /// A writer's view of the log names `index` with a chain this device's
    /// log does not have there, or an index past what the agent serves this
    /// device: a split log.
    #[codec(index = 10)]
    View { index: u64 },
    /// An admin call of this device's that the agent took at `index` is not
    /// there: dropped, or replaced.
    #[codec(index = 11)]
    Dropped { index: u64 },
    /// A writer had read `scope` to `position`, and the agent serves this
    /// device less of it: a partition.
    #[codec(index = 12)]
    Partition { scope: Scope, position: u64 },
    /// The agent's page of `scope` skips `position`, which it numbered: an
    /// envelope withheld.
    #[codec(index = 13)]
    Withheld { scope: Scope, position: u64 },
    /// The envelope at `scope`'s `position` is sealed under an epoch before
    /// one the agent took earlier there: a push it should have refused.
    #[codec(index = 14)]
    Stale { scope: Scope, position: u64 },
    /// The node at `scope`'s `position` is not by a device of the set, or by
    /// a removed device past its frontier: refused.
    #[codec(index = 15)]
    Author { scope: Scope, position: u64 },
    /// This device's own envelope at `scope`'s `position` is gone: pushed
    /// again.
    #[codec(index = 16)]
    Deleted { scope: Scope, position: u64 },
    /// The agent named its log's head at `next` and, read again, served
    /// this device less of the log: entries withheld. The writers' views
    /// and this device's admin calls past what it was served count as
    /// unreached.
    #[codec(index = 18)]
    Unserved { next: u64 },
    /// The log's entry at `index` lowers a delay or a window of the device
    /// set's policy: refused, the policy's delays and windows kept. Only
    /// the claim's configuration sets them (`light-node.md` §3.5).
    #[codec(index = 19)]
    Policy { index: u64 },
}

/// What a device that cannot follow does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
#[repr(u8)]
pub enum Remedy {
    /// Pair again from another live device.
    #[codec(index = 0)]
    RePair = 0,
    /// No other live device to pair from: a regroup (§3.5).
    #[codec(index = 1)]
    Regroup = 1,
}

/// The clock alarm: the device's clock `local` against the agent's batch
/// time `agent`, both in milliseconds.
pub fn clock(local: u64, agent: u64) -> Option<Alarm> {
    let skew_ms = local.abs_diff(agent);
    (skew_ms > vos_wire::personal::HOUR_MS).then_some(Alarm::Clock { skew_ms })
}
