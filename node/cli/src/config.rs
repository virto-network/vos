//! `vos node run --config`: the node's settings from a TOML file, each
//! optional, over the defaults.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use vos_node::Config;

use crate::at;

/// The settings a node's TOML file may give.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    /// Executor threads for PVM work.
    executors: Option<usize>,
    /// Client requests an agent queues before a call answers busy.
    queue: Option<usize>,
    /// The most inputs in one batch.
    max_inputs: Option<usize>,
    /// The most argument bytes in one batch.
    max_bytes: Option<usize>,
    /// How long a leader waits for more inputs after the first.
    linger_ms: Option<u64>,
    /// The most connections the ingress holds open at once.
    ingress_connections: Option<usize>,
    /// A group's election timeout, drawn between its two ends.
    election_timeout_ms: Option<(u64, u64)>,
    /// How often a group's leader sends heartbeats.
    heartbeat_ms: Option<u64>,
    /// Where the node API's unix socket is made: `api.sock` in the data
    /// directory by default.
    api_socket: Option<PathBuf>,
    /// The socket file's mode: 0o660 by default, the node's user and
    /// group.
    api_socket_mode: Option<u32>,
    /// The most connections the node API holds open on each transport.
    api_connections: Option<usize>,
    /// The most requests in flight on one connection of the node API.
    api_in_flight: Option<usize>,
}

/// The node API's socket by default, in the data directory.
pub const API_SOCKET: &str = "api.sock";
/// The socket file's mode by default: the node's user and group.
const API_SOCKET_MODE: u32 = 0o660;

/// Where the node serves its API, as the file gives it.
#[derive(Debug, Default)]
pub struct Fronts {
    /// The socket's path, if not the default.
    pub api_socket: Option<PathBuf>,
    pub api_socket_mode: u32,
}

impl Settings {
    pub fn read(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(at(path))?;
        toml::from_str(&text).map_err(at(path))
    }

    /// Set what the file gives on `config`. Refused: an election timeout
    /// whose ends are out of order or that a heartbeat does not fit in, and
    /// a zero for a count of executors, queued requests, batch inputs or
    /// bytes, or connections.
    pub fn apply(self, config: &mut Config) -> Result<Fronts, String> {
        let set = |value: Option<usize>, field: &mut usize| *field = value.unwrap_or(*field);
        set(self.api_connections, &mut config.api_connections);
        set(self.api_in_flight, &mut config.api_in_flight);
        set(self.executors, &mut config.executors);
        set(self.queue, &mut config.queue);
        set(self.max_inputs, &mut config.max_inputs);
        set(self.max_bytes, &mut config.max_bytes);
        set(self.ingress_connections, &mut config.ingress_connections);
        if let Some(linger) = self.linger_ms {
            config.linger = Duration::from_millis(linger);
        }
        if let Some(timeout) = self.election_timeout_ms {
            config.election_timeout_ms = timeout;
        }
        if let Some(heartbeat) = self.heartbeat_ms {
            config.heartbeat_ms = heartbeat;
        }
        let (low, high) = config.election_timeout_ms;
        if low == 0 || low > high {
            return Err(format!("an election timeout of {low}..{high} ms"));
        }
        if config.heartbeat_ms == 0 || config.heartbeat_ms >= low {
            return Err(format!(
                "a heartbeat of {} ms, not under the election timeout's {low} ms",
                config.heartbeat_ms
            ));
        }
        for (name, value) in [
            ("executors", config.executors),
            ("queue", config.queue),
            ("max_inputs", config.max_inputs),
            ("max_bytes", config.max_bytes),
            ("ingress_connections", config.ingress_connections),
            ("api_connections", config.api_connections),
            ("api_in_flight", config.api_in_flight),
        ] {
            if value == 0 {
                return Err(format!("{name} of 0: a node takes no work"));
            }
        }
        let mode = self.api_socket_mode.unwrap_or(API_SOCKET_MODE);
        if mode & !0o777 != 0 {
            return Err(format!(
                "an api_socket_mode of {mode:#o}: a file mode is 0o777 at most"
            ));
        }
        Ok(Fronts {
            api_socket: self.api_socket,
            api_socket_mode: mode,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::Settings;
    use vos_node::Config;

    fn applied(text: &str) -> Result<Config, String> {
        let mut config = Config::new(Vec::new());
        toml::from_str::<Settings>(text)
            .map_err(|error| error.to_string())?
            .apply(&mut config)?;
        Ok(config)
    }

    #[test]
    fn a_file_sets_what_it_names_and_keeps_the_rest() {
        let config = applied(
            "executors = 3\nlinger_ms = 5\nelection_timeout_ms = [1000, 2000]\nheartbeat_ms = 200\n",
        )
        .unwrap();
        let defaults = Config::new(Vec::new());
        assert_eq!(config.executors, 3);
        assert_eq!(config.linger.as_millis(), 5);
        assert_eq!(config.election_timeout_ms, (1000, 2000));
        assert_eq!(config.heartbeat_ms, 200);
        assert_eq!(config.queue, defaults.queue);
        assert_eq!(config.ingress_connections, defaults.ingress_connections);
        assert!(applied("").is_ok());
        let fronts =
            toml::from_str::<Settings>("api_socket = \"/run/vos.sock\"\napi_socket_mode = 0o600\n")
                .unwrap()
                .apply(&mut Config::new(Vec::new()))
                .unwrap();
        assert_eq!(
            fronts.api_socket.as_deref(),
            Some(Path::new("/run/vos.sock"))
        );
        assert_eq!(fronts.api_socket_mode, 0o600);
        assert!(applied("api_socket_mode = 0o1777\n").is_err());
    }

    #[test]
    fn unknown_names_and_unsound_timings_are_refused() {
        assert!(applied("executor = 3\n").is_err());
        assert!(applied("election_timeout_ms = [3000, 1000]\n").is_err());
        assert!(applied("heartbeat_ms = 1500\n").is_err());
        for zero in [
            "executors",
            "queue",
            "max_inputs",
            "max_bytes",
            "ingress_connections",
            "api_connections",
            "api_in_flight",
        ] {
            let refused = applied(&format!("{zero} = 0\n")).err();
            assert!(refused.is_some_and(|error| error.contains(zero)), "{zero}");
        }
    }
}
