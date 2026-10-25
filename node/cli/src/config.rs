//! `vos node run --config`: the node's settings from a TOML file, each
//! optional, over the defaults.

use std::path::Path;
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
}

impl Settings {
    pub fn read(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(at(path))?;
        toml::from_str(&text).map_err(at(path))
    }

    /// Set what the file gives on `config`; an election timeout whose ends
    /// are out of order, or that a heartbeat does not fit in, is refused.
    pub fn apply(self, config: &mut Config) -> Result<(), String> {
        let set = |value: Option<usize>, field: &mut usize| *field = value.unwrap_or(*field);
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
        if config.executors == 0 {
            return Err("no executors".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
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
    }

    #[test]
    fn unknown_names_and_unsound_timings_are_refused() {
        assert!(applied("executor = 3\n").is_err());
        assert!(applied("election_timeout_ms = [3000, 1000]\n").is_err());
        assert!(applied("heartbeat_ms = 1500\n").is_err());
        assert!(applied("executors = 0\n").is_err());
    }
}
