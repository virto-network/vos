//! A phone's [`Host`] in process: its requests over a Tor client whose
//! every stream is the [`World`]'s gateway, its proofs on a prover of its
//! own under the world's stock kernels, its enrollments as a test sets
//! them.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use vos_wire::credentials::Onion;

use super::{World, program};
use crate::route::{Purpose, Route, Routes};
use crate::space::{Enrolled, Error, Host, Proof};
use crate::tor::{Client, Config};
use crate::{DeviceProgram, Prover, ProverConfig, wire};

/// A phone's host over the world, its requests tagged with the phone's tag
/// ([`World::dial_as`]).
pub struct Reach {
    runtime: tokio::runtime::Runtime,
    client: Client,
    world: Arc<World>,
    prover: OnceLock<Prover>,
    programs: OnceLock<(DeviceProgram, DeviceProgram)>,
    /// The phone's enrollments in other spaces.
    pub enrollments: Mutex<Vec<Enrolled>>,
    /// How far the phone's clock runs ahead of the device's, in
    /// milliseconds.
    pub ahead: AtomicU64,
}

impl Reach {
    /// The host of the phone tagged `tag` in `world`.
    pub fn new(world: &Arc<World>, tag: u8) -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("a runtime");
        let client = {
            let _entered = runtime.enter();
            Client::new(world.dial_as(tag), Config::default())
        };
        Self {
            runtime,
            client,
            world: Arc::clone(world),
            prover: OnceLock::new(),
            programs: OnceLock::new(),
            enrollments: Mutex::new(Vec::new()),
            ahead: AtomicU64::new(0),
        }
    }

    /// The client its requests go through.
    pub fn client(&self) -> &Client {
        &self.client
    }

    fn prover(&self) -> &Prover {
        self.prover
            .get_or_init(|| Prover::new(ProverConfig::default()).expect("a prover"))
    }

    /// The stock kernels' programs: auth's, owner's.
    fn programs(&self) -> &(DeviceProgram, DeviceProgram) {
        self.programs.get_or_init(|| {
            (
                program(&self.world.stock.auth),
                program(&self.world.stock.owner),
            )
        })
    }
}

impl Host for Reach {
    fn request(
        &self,
        space: &[u8; 32],
        purpose: Purpose,
        request: &[u8],
    ) -> Result<Vec<u8>, String> {
        self.runtime
            .block_on(self.client.request(*space, purpose, request))
            .map(|(_, body)| body)
            .map_err(|error| error.to_string())
    }

    fn requests(
        &self,
        space: &[u8; 32],
        purpose: Purpose,
        requests: &[Vec<u8>],
    ) -> Vec<Result<Vec<u8>, String>> {
        self.runtime
            .block_on(self.client.requests(*space, purpose, requests))
            .into_iter()
            .map(|answer| answer.map(|(_, body)| body).map_err(|error| error.to_string()))
            .collect()
    }

    fn pin(&self, home: &[u8; 32], onions: &[Onion]) {
        let _entered = self.runtime.enter();
        self.client
            .set_space(*home, Routes::new(onions.to_vec(), None, true));
    }

    fn route(&self, space: &[u8; 32], purpose: Purpose) -> Route {
        self.client
            .routes(space)
            .and_then(|routes| routes.route(purpose).ok())
            .unwrap_or(Route::Clearnet)
    }

    fn prove(&self, proof: Proof) -> Result<Vec<u8>, Error> {
        let (auth, owner) = self.programs();
        let (call, proven) = match proof {
            Proof::Home {
                secret,
                witness,
                call,
            } => {
                let proven = self.prover().prove_home(&secret, &witness, &call, auth);
                (call, proven)
            }
            Proof::Owner { secret, call } => {
                let proven = self.prover().prove_owner(&secret, &call, owner);
                (call, proven)
            }
        };
        let proven = proven.map_err(|error| Error::Prove(error.to_string()))?;
        Ok(wire::credentialed(&call, &proven))
    }

    fn enrollments(&self) -> Result<Vec<Enrolled>, String> {
        Ok(self.enrollments.lock().unwrap().clone())
    }

    fn now(&self) -> u64 {
        super::wall() + self.ahead.load(Ordering::Relaxed)
    }
}
