//! What takes a run's carriers: a venue's client ([`Tapped`]) and each
//! venue's layout of what it is sent, the process's logs ([`Logs`]) and
//! standard error ([`Stderr`]), a node's files ([`directory`]) and its
//! store's rows ([`store`]).

use std::sync::{Arc, Mutex, OnceLock};

use vos_statement_service::item::Item;
use vos_venue::kreivo;
use vos_venue::vos_statement::{Statement, StatementId};
use vos_venue::{AnchorRefusal, Anchored, NotAccepted, Status, VenueClient};
use vos_wire::vos_anchor::{Anchor, RootRead, SpaceId, VenueId};

use super::{Audit, Reach, lock};

/// A venue's client, every anchor and submission it is sent kept: the
/// carriers a node sends its venue.
pub struct Tapped {
    inner: Arc<dyn VenueClient>,
    anchors: Mutex<Vec<Anchor>>,
    submitted: Mutex<Vec<(Statement, Vec<u8>)>>,
}

impl Tapped {
    pub fn new(inner: Arc<dyn VenueClient>) -> Self {
        Self {
            inner,
            anchors: Mutex::default(),
            submitted: Mutex::default(),
        }
    }

    /// The anchors sent so far.
    pub fn anchors(&self) -> Vec<Anchor> {
        lock(&self.anchors).clone()
    }

    /// The statements submitted so far, each with its final proof.
    pub fn submitted(&self) -> Vec<(Statement, Vec<u8>)> {
        lock(&self.submitted).clone()
    }

    /// Every carrier the venue was sent, in each venue's layout
    /// ([`anchor_carriers`], [`submission_carriers`]), into `audit`.
    pub fn carriers(&self, audit: &mut Audit) {
        for anchor in self.anchors() {
            for (name, bytes) in anchor_carriers(&anchor) {
                audit.carrier(
                    format!("window {}: {name}", anchor.window),
                    Reach::Leaves,
                    bytes,
                );
            }
        }
        for (statement, proof) in self.submitted() {
            for (name, bytes) in submission_carriers(&statement, &proof) {
                audit.carrier(name, Reach::Leaves, bytes);
            }
        }
    }
}

impl VenueClient for Tapped {
    fn id(&self) -> VenueId {
        self.inner.id()
    }

    fn anchor(&self, anchor: &Anchor) -> Result<Anchored, AnchorRefusal> {
        lock(&self.anchors).push(*anchor);
        self.inner.anchor(anchor)
    }

    fn submit(&self, statement: &Statement, proof: &[u8]) -> Result<StatementId, NotAccepted> {
        lock(&self.submitted).push((statement.clone(), proof.to_vec()));
        self.inner.submit(statement, proof)
    }

    fn anchored(&self, root: &RootRead) -> bool {
        self.inner.anchored(root)
    }

    fn anchor_keys(&self, space: &SpaceId) -> Vec<[u8; 32]> {
        self.inner.anchor_keys(space)
    }

    fn status(&self, space: &SpaceId) -> Status {
        self.inner.status(space)
    }

    fn time(&self) -> Option<u64> {
        self.inner.time()
    }

    fn unsettled(&self, space: &SpaceId) -> Vec<u64> {
        self.inner.unsettled(space)
    }
}

/// What a venue is sent for `anchor`, as each venue's client lays it out:
/// Kreivo's call and the JAM statements service's work item.
pub fn anchor_carriers(anchor: &Anchor) -> Vec<(String, Vec<u8>)> {
    vec![
        ("the anchor".into(), anchor.encode()),
        (
            "Kreivo's anchor call".into(),
            kreivo::calls::Call::anchor(anchor).bytes(),
        ),
        ("JAM's anchor item".into(), Item::Anchor(*anchor).encode()),
    ]
}

/// What a venue is sent for `statement` and its final `proof`: the
/// statement, the proof, Kreivo's call and JAM's work item and extrinsic.
pub fn submission_carriers(statement: &Statement, proof: &[u8]) -> Vec<(String, Vec<u8>)> {
    let encoded = statement.encode();
    vec![
        ("the statement".into(), encoded.clone()),
        ("the final proof".into(), proof.to_vec()),
        (
            "Kreivo's submit call".into(),
            kreivo::calls::Call::Submit {
                payer: [0; 32],
                statement: encoded.clone(),
                proof: proof.to_vec(),
            }
            .bytes(),
        ),
        ("JAM's submit item".into(), Item::Submit(encoded).encode()),
        ("JAM's submit extrinsic".into(), proof.to_vec()),
    ]
}

/// Every file under `dir`, read whole, in path order: what a node wrote
/// to its disk.
pub fn directory(dir: &std::path::Path) -> Vec<(String, Vec<u8>)> {
    let mut files = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else if let Ok(bytes) = std::fs::read(&path) {
                files.push((path.display().to_string(), bytes));
            }
        }
    }
    files.sort();
    files
}

/// Every key and value `store` holds, each partition's name before its
/// rows: the node's store as its logic reads it, however fjall compresses
/// its blocks on disk ([`directory`] reads the files as they are).
pub fn store(store: &vos_node::store::Fjall) -> Vec<u8> {
    let rows = store.dump().expect("the store's rows");
    let mut bytes = Vec::new();
    for (partition, key, value) in rows {
        bytes.extend_from_slice(partition.as_bytes());
        bytes.extend_from_slice(&key);
        bytes.extend_from_slice(&value);
    }
    bytes
}

/// The environment that turns every debug output on, in a build that has
/// them: a run under it shows the outputs [`DEBUG_OUTPUTS`](super::DEBUG_OUTPUTS) names unless
/// they are compiled out.
pub const DEBUG_ENVIRONMENT: [&str; 4] = [
    "GREY_PVM_DEBUG",
    "CPU_DUMP",
    "CPU_EXPR_DUMP",
    "ZKPVM_PROFILE",
];

/// The process's standard error, written to a file from [`Stderr::capture`]
/// until [`Stderr::finish`]: what a debug output prints there. The test
/// harness keeps its own capture of a test's prints unless run with
/// `--nocapture`.
pub struct Stderr {
    saved: i32,
    path: std::path::PathBuf,
}

impl Stderr {
    /// The process's standard error, from now on, into a new file in `dir`.
    pub fn capture(dir: &std::path::Path) -> Self {
        use std::os::fd::AsRawFd;
        let path = dir.join("stderr");
        let file = std::fs::File::create(&path).expect("the capture's file");
        // SAFETY: `dup` and `dup2` on the process's standard error and an
        // open file; the saved descriptor is restored by `finish`.
        let saved = unsafe { libc::dup(2) };
        assert!(saved >= 0, "standard error duplicated");
        assert!(
            unsafe { libc::dup2(file.as_raw_fd(), 2) } >= 0,
            "standard error redirected"
        );
        Self { saved, path }
    }

    /// Standard error restored: what was written to it meanwhile.
    pub fn finish(self) -> Vec<u8> {
        // SAFETY: the descriptor `capture` saved, put back.
        unsafe {
            libc::dup2(self.saved, 2);
            libc::close(self.saved);
        }
        std::fs::read(&self.path).unwrap_or_default()
    }
}

/// Every tracing event of the process, formatted, at every level.
#[derive(Clone, Default)]
pub struct Logs(Arc<Mutex<Vec<u8>>>);

impl Logs {
    /// The process's capture, installed as its global subscriber on the
    /// first call. Fails if another subscriber is installed already.
    pub fn install() -> Self {
        static LOGS: OnceLock<Logs> = OnceLock::new();
        LOGS.get_or_init(|| {
            let logs = Logs::default();
            let subscriber = tracing_subscriber::fmt()
                .with_max_level(tracing::Level::TRACE)
                .with_ansi(false)
                .without_time()
                .with_writer(logs.clone())
                .finish();
            tracing::subscriber::set_global_default(subscriber)
                .expect("the process's only subscriber");
            logs
        })
        .clone()
    }

    /// What was captured so far.
    pub fn bytes(&self) -> Vec<u8> {
        lock(&self.0).clone()
    }
}

impl std::io::Write for Logs {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        lock(&self.0).extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Logs {
    type Writer = Logs;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}
