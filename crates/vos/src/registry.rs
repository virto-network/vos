//! Service registry — manages the lifecycle of VOS services.

use vos_abi::service::ServiceId;
use crate::actors::Mailbox;

/// State of a registered service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    /// Service has been registered but not yet invoked.
    Created,
    /// Service is running and can receive transfers.
    Running,
    /// Service is suspended mid-execution (yielded).
    Suspended,
    /// Service has stopped (cleanly or due to error).
    Stopped,
}

/// Status returned by service execution.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Ready = 0,
    Pending = 1,
    Done = 2,
    Error = 3,
}

/// A registered service entry.
pub struct ServiceEntry<Msg, const MAILBOX_CAP: usize> {
    pub id: ServiceId,
    pub state: ServiceState,
    pub mailbox: Mailbox<Msg, MAILBOX_CAP>,
}

/// Registry of services managed by the runtime.
pub struct ServiceRegistry<Msg, const N: usize, const MAILBOX_CAP: usize> {
    services: [Option<ServiceEntry<Msg, MAILBOX_CAP>>; N],
    count: u32,
}

impl<Msg, const N: usize, const MAILBOX_CAP: usize> Default
    for ServiceRegistry<Msg, N, MAILBOX_CAP>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<Msg, const N: usize, const MAILBOX_CAP: usize> ServiceRegistry<Msg, N, MAILBOX_CAP> {
    const NONE: Option<ServiceEntry<Msg, MAILBOX_CAP>> = None;

    pub const fn new() -> Self {
        Self {
            services: [Self::NONE; N],
            count: 0,
        }
    }

    /// Register a new service. Returns its ID, or `None` if full.
    pub fn register(&mut self) -> Option<ServiceId> {
        if self.count as usize >= N {
            return None;
        }
        // ID 0 is reserved for the supervisor
        self.count += 1;
        let id = ServiceId(self.count);
        let idx = (id.0 - 1) as usize;
        self.services[idx] = Some(ServiceEntry {
            id,
            state: ServiceState::Created,
            mailbox: Mailbox::new(),
        });
        Some(id)
    }

    pub fn get(&self, id: ServiceId) -> Option<&ServiceEntry<Msg, MAILBOX_CAP>> {
        let idx = id.0.checked_sub(1)? as usize;
        self.services.get(idx)?.as_ref()
    }

    pub fn get_mut(&mut self, id: ServiceId) -> Option<&mut ServiceEntry<Msg, MAILBOX_CAP>> {
        let idx = id.0.checked_sub(1)? as usize;
        self.services.get_mut(idx)?.as_mut()
    }

    pub fn update_state(&mut self, id: ServiceId, status: Status) {
        if let Some(entry) = self.get_mut(id) {
            entry.state = match status {
                Status::Ready => ServiceState::Running,
                Status::Pending => ServiceState::Suspended,
                Status::Done => ServiceState::Stopped,
                Status::Error => ServiceState::Stopped,
            };
        }
    }

    pub fn send(&mut self, target: ServiceId, msg: Msg) -> Result<(), Msg> {
        let entry = match self.get_mut(target) {
            Some(e) if e.state != ServiceState::Stopped => e,
            _ => return Err(msg),
        };
        entry.mailbox.push(msg)
    }

    pub fn tick(&mut self, mut f: impl FnMut(ServiceId, ServiceState, Option<&Msg>) -> Status) {
        for slot in self.services.iter_mut() {
            let Some(entry) = slot else { continue };
            match entry.state {
                ServiceState::Stopped | ServiceState::Created => continue,
                ServiceState::Suspended => {
                    let msg = entry.mailbox.pop();
                    let status = f(entry.id, entry.state, msg.as_ref());
                    entry.state = match status {
                        Status::Ready => ServiceState::Running,
                        Status::Pending => ServiceState::Suspended,
                        Status::Done | Status::Error => ServiceState::Stopped,
                    };
                }
                ServiceState::Running => {
                    if let Some(msg) = entry.mailbox.pop() {
                        let status = f(entry.id, entry.state, Some(&msg));
                        entry.state = match status {
                            Status::Ready => ServiceState::Running,
                            Status::Pending => ServiceState::Suspended,
                            Status::Done | Status::Error => ServiceState::Stopped,
                        };
                    }
                }
            }
        }
    }

    pub fn alive_count(&self) -> usize {
        self.services
            .iter()
            .filter(|s| {
                s.as_ref()
                    .is_some_and(|e| e.state != ServiceState::Stopped)
            })
            .count()
    }
}
