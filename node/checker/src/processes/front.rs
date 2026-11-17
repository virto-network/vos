//! A gateway in front of the processes, on its own runtime.

use super::*;

/// A gateway on its own runtime, and what stops it.
pub struct Front {
    pub(super) target: Target,
    _stop: tokio::sync::oneshot::Sender<()>,
    runtime: tokio::runtime::Runtime,
}

impl Front {
    /// A gateway in front of the sockets of the nodes whose keys, in hex,
    /// are `keys` and whose data directories `data` names.
    pub(super) fn start(keys: &[String], data: impl Fn(usize) -> PathBuf) -> Self {
        let upstreams = keys
            .iter()
            .enumerate()
            .map(|(at, key)| {
                let mut node = [0u8; 32];
                hex::decode_to_slice(key, &mut node).unwrap();
                let socket = data(at + 1).join("api.sock");
                (node, format!("unix:{}", socket.display()))
            })
            .collect();
        Self::serve(upstreams, [0x9a; 32])
    }

    /// A gateway whose QUIC key's seed is `secret`, in front of the nodes
    /// `upstreams` names, each by its key and its API's address
    /// (`unix:/path` or `quic://host:port`), serving HTTP on a loopback
    /// port, no limit binding.
    pub fn serve(upstreams: Vec<([u8; 32], String)>, secret: [u8; 32]) -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let upstreams = upstreams
            .into_iter()
            .map(|(node, address)| {
                let address = vos_gateway::upstream::Address::parse(&address).unwrap();
                vos_gateway::upstream::Upstream::new(node, address, secret)
            })
            .collect();
        let gateway = std::sync::Arc::new(vos_gateway::Gateway::new(upstreams));
        let listener = runtime
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .unwrap();
        let address = listener.local_addr().unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        runtime.spawn(vos_gateway::front::serve(
            gateway,
            vos_gateway::limits::Limits::new(vos_gateway::limits::PerAddress {
                connections: 1024,
                rate: u32::MAX,
                burst: u32::MAX,
            }),
            listener,
            vos_gateway::front::Http {
                tls: None,
                connections: 1024,
            },
            async {
                let _ = stopped.await;
            },
        ));
        Self {
            target: Target::loopback(&format!("http://{address}")).unwrap(),
            _stop: stop,
            runtime,
        }
    }

    /// Its HTTP front, as a client reaches it.
    pub fn target(&self) -> &Target {
        &self.target
    }

    /// Runs `task` as one of the gateway's tasks, on its runtime's
    /// workers, to its end.
    pub fn run<T: Send + 'static>(
        &self,
        task: impl std::future::Future<Output = T> + Send + 'static,
    ) -> T {
        self.runtime
            .block_on(self.runtime.spawn(task))
            .expect("the task ends")
    }
}
