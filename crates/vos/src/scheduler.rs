//! Scheduler — drives the runtime's main loop.

use crate::registry::{ServiceRegistry, ServiceState, Status};
use crate::hostcall_handler::HostcallHandler;
use vos_abi::service::ServiceId;

/// Result of a scheduler tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TickResult {
    Progress,
    Idle,
    Done,
}

/// The scheduler drives service execution.
pub struct Scheduler<Msg, D, const N: usize, const MC: usize> {
    pub registry: ServiceRegistry<Msg, N, MC>,
    pub hostcalls: HostcallHandler,
    driver: D,
}

/// The driver trait — abstracts how the runtime calls into guest PVM programs.
pub trait Driver<Msg> {
    fn init(&mut self, id: ServiceId) -> Status;
    fn handle(&mut self, id: ServiceId, msg: &Msg) -> Status;
    fn poll(&mut self, id: ServiceId) -> Status;
    fn drop_service(&mut self, id: ServiceId);
    fn drain_sends(&mut self, _route: impl FnMut(ServiceId, Msg)) {}
}

impl<Msg, D: Driver<Msg>, const N: usize, const MC: usize> Scheduler<Msg, D, N, MC> {
    pub fn new(driver: D) -> Self {
        Self {
            registry: ServiceRegistry::new(),
            hostcalls: HostcallHandler::new(),
            driver,
        }
    }

    pub fn spawn(&mut self) -> Option<ServiceId> {
        let id = self.registry.register()?;
        let status = self.driver.init(id);
        self.registry.update_state(id, status);
        Some(id)
    }

    pub fn send(&mut self, target: ServiceId, msg: Msg) -> Result<(), Msg> {
        self.registry.send(target, msg)
    }

    pub fn tick(&mut self) -> TickResult {
        if self.registry.alive_count() == 0 {
            return TickResult::Done;
        }

        let mut progress = false;
        let driver = &mut self.driver;

        self.registry.tick(|id, state, msg| {
            let status = match (state, msg) {
                (_, Some(msg)) => driver.handle(id, msg),
                (ServiceState::Suspended, None) => driver.poll(id),
                _ => Status::Ready,
            };

            if status == Status::Done || status == Status::Error {
                driver.drop_service(id);
            }

            if status != Status::Ready || msg.is_some() {
                progress = true;
            }

            status
        });

        let driver = &mut self.driver;
        let registry = &mut self.registry;
        driver.drain_sends(|target, msg| {
            let _ = registry.send(target, msg);
            progress = true;
        });

        if progress {
            TickResult::Progress
        } else {
            TickResult::Idle
        }
    }

    pub fn driver(&self) -> &D {
        &self.driver
    }

    pub fn driver_mut(&mut self) -> &mut D {
        &mut self.driver
    }
}
