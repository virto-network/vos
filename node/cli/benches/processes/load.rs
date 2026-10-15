//! The load: increments signed ahead or as they go, in plans of a session
//! each, sent over HTTP connections kept open by the driver, which paces
//! them and times them.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use ed25519_dalek::{Signer, SigningKey};
use smol::io::{AsyncReadExt, AsyncWriteExt};
use vos_node::client::Target;
use vos_wire::ids::{AgentId, MethodId, Session};
use vos_wire::ingress::{Call, Response, call_message};
use vos_wire::result::Outcome;
use vos_wire::{Decode, Encode};

use crate::nodes::{Cpu, Space, cpus, pin_thread};
use crate::{COUNTER, NODES, WARM};

/// The node leading each agent, by index.
pub type Leaders = HashMap<AgentId, usize>;

/// What the driver needs of an agent to sign its calls.
#[derive(Clone, Copy)]
pub struct Signed {
    pub agent: AgentId,
    pub identity: [u8; 32],
    increment: MethodId,
    pub value: MethodId,
}

pub fn signed(space: &Space, agent: AgentId) -> Signed {
    // At whichever node has applied its install.
    let until = Instant::now() + Duration::from_secs(30);
    let (info, schema) = loop {
        let served = space.processes.iter().find_map(|process| {
            let info = vos_node::client::agent_info(&process.target, agent).ok()??;
            let schema = vos_node::client::schema(&process.target, agent, COUNTER).ok()??;
            Some((info, schema))
        });
        if let Some(served) = served {
            break served;
        }
        assert!(
            Instant::now() < until,
            "agent {}'s schema is not served",
            agent.0
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    Signed {
        agent,
        identity: vos_node::identity(&info.record),
        increment: schema.method_id("increment").unwrap(),
        value: schema.method_id("value").unwrap(),
    }
}

/// One session's calls: the node it starts at, and each call's path and
/// body in order.
pub struct Plan {
    /// The agent whose counter its calls increment, if they do.
    pub counts: Option<AgentId>,
    pub node: usize,
    pub path: String,
    pub bodies: Bodies,
}

/// A plan's call bodies: signed before the run, or one at a time as it
/// goes, after each answer, for runs too long to sign ahead.
pub enum Bodies {
    Ready(std::vec::IntoIter<Vec<u8>>),
    Signing(Box<Signing>),
}

/// Calls signed as a plan goes, in a new session every `every` calls, as
/// clients come and go: session `number`, then `number + stride`, and so
/// on.
pub struct Signing {
    signed: Signed,
    number: u64,
    stride: u64,
    every: u64,
    key: SessionKey,
    /// The plan's next call, from 1, and its last.
    next: u64,
    last: u64,
}

impl Bodies {
    fn next(&mut self) -> Option<Vec<u8>> {
        match self {
            Bodies::Ready(bodies) => bodies.next(),
            Bodies::Signing(signing) => {
                if signing.next > signing.last {
                    return None;
                }
                let sequence = (signing.next - 1) % signing.every + 1;
                if sequence == 1 && signing.next > 1 {
                    signing.number += signing.stride;
                    signing.key = SessionKey::new(&signing.signed, signing.number);
                }
                signing.next += 1;
                Some(signing.key.sign(sequence))
            }
        }
    }
}

/// What signs a session's increments.
struct SessionKey {
    key: SigningKey,
    session: Session,
    identity: [u8; 32],
    increment: MethodId,
}

impl SessionKey {
    /// Session `number` at `signed`'s agent.
    fn new(signed: &Signed, number: u64) -> Self {
        let mut seed = [7u8; 32];
        seed[..8].copy_from_slice(&number.to_le_bytes());
        seed[8..12].copy_from_slice(&signed.agent.0.to_le_bytes());
        let key = SigningKey::from_bytes(&seed);
        let mut name = [0u8; 16];
        name[..8].copy_from_slice(&number.to_le_bytes());
        let session = Session {
            key: key.verifying_key().to_bytes(),
            name,
            t0: vos_node::wall_clock(),
        };
        Self {
            key,
            session,
            identity: signed.identity,
            increment: signed.increment,
        }
    }

    /// The increment at `sequence`, signed.
    fn sign(&self, sequence: u64) -> Vec<u8> {
        let arguments = 1u64.encode();
        let message = call_message(
            &self.identity,
            &self.session,
            sequence,
            COUNTER,
            self.increment,
            &arguments,
        );
        Call {
            session: self.session,
            sequence,
            instance: COUNTER,
            method: self.increment,
            arguments,
            signature: self.key.sign(&message).to_bytes(),
        }
        .encode()
    }
}

/// The session numbers every plan so far took: each plan's are new.
static SESSIONS: AtomicU64 = AtomicU64::new(0);

/// `count` session numbers no plan took before: the first of them.
pub fn new_sessions(count: u64) -> u64 {
    SESSIONS.fetch_add(count, Ordering::Relaxed)
}

/// `calls` increments in a new session `number` at `signed`'s agent,
/// signed now.
fn session_plan(signed: &Signed, number: u64, calls: usize, node: usize) -> Plan {
    let signer = SessionKey::new(signed, number);
    let bodies: Vec<Vec<u8>> = (1..=calls as u64)
        .map(|sequence| signer.sign(sequence))
        .collect();
    Plan {
        counts: Some(signed.agent),
        node,
        path: format!("/agents/{}/calls", signed.agent.0),
        bodies: Bodies::Ready(bodies.into_iter()),
    }
}

/// `calls` increments at `signed`'s agent, each signed as it goes, in
/// session `number` and then a new one every `every` calls, `stride`
/// apart.
pub fn signing_plan(
    signed: &Signed,
    (number, stride, every): (u64, u64, u64),
    calls: usize,
    node: usize,
) -> Plan {
    Plan {
        counts: Some(signed.agent),
        node,
        path: format!("/agents/{}/calls", signed.agent.0),
        bodies: Bodies::Signing(Box::new(Signing {
            signed: *signed,
            number,
            stride,
            every,
            key: SessionKey::new(signed, number),
            next: 1,
            last: calls as u64,
        })),
    }
}

/// Plans signed on the driver's threads at once.
fn sign_plans(jobs: Vec<(Signed, u64, usize, usize)>) -> Vec<Plan> {
    let threads = 4;
    let chunk = jobs.len().div_ceil(threads).max(1);
    std::thread::scope(|scope| {
        let handles: Vec<_> = jobs
            .chunks(chunk)
            .map(|jobs| {
                scope.spawn(move || {
                    jobs.iter()
                        .map(|(signed, number, calls, node)| {
                            session_plan(signed, *number, *calls, *node)
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|handle| handle.join().unwrap())
            .collect()
    })
}

/// New sessions spread over `agents`, `sessions` at each, each starting
/// at its agent's leader, with `calls` signed calls each.
pub fn plans(agents: &[Signed], leaders: &Leaders, sessions: u64, calls: usize) -> Vec<Plan> {
    let first = new_sessions(agents.len() as u64 * sessions);
    let spread = spread();
    let jobs = agents
        .iter()
        .flat_map(|signed| {
            (0..sessions).map(move |session| {
                let leader = leaders[&signed.agent];
                // Spread, each session goes to one of the space's nodes in
                // turn, which checks its calls' signatures and forwards
                // them to the leader, as clients spread over the replicas
                // would.
                let node = if spread {
                    (leader + session as usize) % NODES
                } else {
                    leader
                };
                (*signed, first + session, calls, node)
            })
        })
        .collect();
    sign_plans(jobs)
}

/// Whether sessions are spread over the nodes (`SPREAD=1`), rather than
/// sent to their agent's leader.
fn spread() -> bool {
    std::env::var("SPREAD").is_ok_and(|value| value == "1")
}

/// Signed calls for each session of a closed-loop run, all signed before
/// it: an even share of 400,000, a bound on the memory the calls take; at
/// most 4,000, about what one session sends in a run at a few milliseconds
/// a call (a faster machine may run a session out: counted as exhausted);
/// and 64 more for room.
pub fn closed_calls(sessions: u64) -> usize {
    (400_000 / sessions as usize).min(4_000) + 64
}

/// Calls per session an open-loop run of `measure` needs at `per_session`
/// a second, with room.
pub fn open_calls(per_session: f64, measure: Duration) -> usize {
    ((per_session * (WARM + measure).as_secs_f64()) * 1.2) as usize + 16
}

trait Stream: smol::io::AsyncRead + smol::io::AsyncWrite + Unpin + Send {}
impl<T: smol::io::AsyncRead + smol::io::AsyncWrite + Unpin + Send> Stream for T {}

/// HTTP/1.1 on a connection kept open.
struct Http {
    stream: Box<dyn Stream>,
    authority: String,
    buffer: Vec<u8>,
}

impl Http {
    async fn connect(target: &Target) -> std::io::Result<Self> {
        let tcp = smol::net::TcpStream::connect(target.authority()).await?;
        tcp.set_nodelay(true)?;
        let stream: Box<dyn Stream> = match target.tls() {
            Some((config, name)) => Box::new(
                futures_rustls::TlsConnector::from(config)
                    .connect(name, tcp)
                    .await?,
            ),
            None => Box::new(tcp),
        };
        Ok(Self {
            stream,
            authority: target.authority().to_string(),
            buffer: Vec::with_capacity(4096),
        })
    }

    async fn post(&mut self, path: &str, body: &[u8]) -> std::io::Result<Response> {
        let head = format!(
            "POST {path} HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\n\r\n",
            self.authority,
            body.len()
        );
        let mut request = Vec::with_capacity(head.len() + body.len());
        request.extend_from_slice(head.as_bytes());
        request.extend_from_slice(body);
        self.stream.write_all(&request).await?;
        self.stream.flush().await?;
        let invalid = |why: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, why);
        let mut chunk = [0u8; 8192];
        loop {
            let mut headers = [httparse::EMPTY_HEADER; 16];
            let mut response = httparse::Response::new(&mut headers);
            if let httparse::Status::Complete(head) = response
                .parse(&self.buffer)
                .map_err(|_| invalid("not HTTP"))?
            {
                let length = response
                    .headers
                    .iter()
                    .find(|header| header.name.eq_ignore_ascii_case("content-length"))
                    .and_then(|header| {
                        std::str::from_utf8(header.value)
                            .ok()?
                            .trim()
                            .parse::<usize>()
                            .ok()
                    })
                    .ok_or_else(|| invalid("no length"))?;
                while self.buffer.len() < head + length {
                    let read = self.stream.read(&mut chunk).await?;
                    if read == 0 {
                        return Err(invalid("closed"));
                    }
                    self.buffer.extend_from_slice(&chunk[..read]);
                }
                let answer = Response::decode(&self.buffer[head..head + length])
                    .map(|(answer, _)| answer)
                    .map_err(|_| invalid("no answer"));
                self.buffer.drain(..head + length);
                return answer;
            }
            let read = self.stream.read(&mut chunk).await?;
            if read == 0 {
                return Err(invalid("closed"));
            }
            self.buffer.extend_from_slice(&chunk[..read]);
        }
    }
}

/// What a run measured: each call's latency, and in an open loop its send
/// lag, for the calls scheduled in the timed window.
#[derive(Default)]
pub struct Samples {
    pub latencies: Vec<Duration>,
    pub lags: Vec<Duration>,
    pub failed: u64,
    /// The first answer that was not a call run to completion.
    pub first_failure: Option<String>,
    /// Calls in an open loop that waited for their session's previous call
    /// to be answered: the nodes, not the driver, held them.
    pub behind: u64,
    /// Calls answered after their window ended: a backlog past the knee,
    /// once more than the few in flight at its end.
    pub answered_after: u64,
    /// The latencies of the calls scheduled in the window's first quarter,
    /// and in its last: past the knee the backlog, and with it the
    /// latency, grows across the window.
    pub first_quarter: Vec<Duration>,
    pub last_quarter: Vec<Duration>,
    /// Sessions whose signed calls ran out before the window ended.
    pub exhausted: u64,
}

/// When calls go: back to back, or each at its scheduled time.
#[derive(Clone, Copy)]
pub enum Pace {
    Closed,
    /// One call every so long per session, the sessions staggered.
    Open(Duration),
}

/// Send one call until it is answered, following the leader: its answer,
/// or none once the run ends.
async fn call(
    space: &Space,
    http: &mut Option<Http>,
    node: &mut usize,
    path: &str,
    body: &[u8],
    until: Instant,
) -> Option<Response> {
    loop {
        if Instant::now() >= until + Duration::from_secs(10) {
            return None;
        }
        if http.is_none() {
            *http = Http::connect(&space.processes[*node].target).await.ok();
        }
        let Some(connection) = http.as_mut() else {
            smol::Timer::after(Duration::from_millis(10)).await;
            continue;
        };
        match connection.post(path, body).await {
            Ok(answer @ Response::Ran { .. }) => return Some(answer),
            Ok(Response::NotLeader {
                leader: Some(leader),
            }) => {
                if let Some(at) = space.by_url(&leader.address) {
                    *node = at;
                }
                *http = None;
            }
            Ok(
                Response::Busy
                | Response::Unavailable
                | Response::TimedOut
                | Response::NotLeader { .. },
            ) => {
                smol::Timer::after(Duration::from_millis(2)).await;
            }
            Ok(other) => return Some(other),
            Err(_) => {
                *http = None;
                smol::Timer::after(Duration::from_millis(10)).await;
            }
        }
    }
}

/// Run `plans` paced as `pace`, one load throughout, measuring the calls
/// scheduled in `windows` windows of `measure` back to back after the
/// warm-up, on the driver's executor: two threads, each on one of the
/// driver's first two cores. Each window's samples, and the CPU at its
/// edges.
pub fn drive(
    space: &Space,
    plans: Vec<Plan>,
    pace: Pace,
    measure: Duration,
    windows: usize,
) -> Vec<(Samples, (Cpu, Cpu))> {
    let samples: Mutex<Vec<Samples>> =
        Mutex::new((0..windows).map(|_| Samples::default()).collect());
    let edges_cpu = Mutex::new(Vec::new());
    let stop = AtomicBool::new(false);
    let executor = smol::Executor::new();
    let start = Instant::now() + Duration::from_millis(200);
    let first = start + WARM;
    let end = first + measure * windows as u32;
    // The window a call scheduled `from` counts in, if any.
    let window_of = move |from: Instant| {
        (from >= first && from < end).then(|| {
            (((from - first).as_secs_f64() / measure.as_secs_f64()) as usize).min(windows - 1)
        })
    };
    let count = plans.len() as u32;
    let cores: Vec<String> = cpus()
        .get(NODES)
        .map(|cpus| cpus.split(',').map(str::to_string).collect())
        .unwrap_or_default();
    std::thread::scope(|scope| {
        let edges_cpu = &edges_cpu;
        scope.spawn(move || {
            for edge in 0..=windows {
                let at = first + measure * edge as u32;
                std::thread::sleep(at.saturating_duration_since(Instant::now()));
                let cpu = Cpu::now(space);
                edges_cpu.lock().unwrap().push(cpu);
            }
        });
        for thread in 0..2 {
            let (executor, stop, core) = (&executor, &stop, cores.get(thread).cloned());
            scope.spawn(move || {
                if let Some(core) = core {
                    pin_thread(&core);
                }
                smol::block_on(executor.run(async {
                    while !stop.load(Ordering::Relaxed) {
                        smol::Timer::after(Duration::from_millis(20)).await;
                    }
                }));
            });
        }
        let tasks: Vec<_> = plans
            .into_iter()
            .enumerate()
            .map(|(at, plan)| {
                let samples = &samples;
                executor.spawn(async move {
                    let mut node = plan.node;
                    let mut http = None;
                    let mut mine: Vec<Samples> = (0..windows).map(|_| Samples::default()).collect();
                    let mut scheduled = start
                        + match pace {
                            Pace::Closed => Duration::ZERO,
                            Pace::Open(interval) => interval * at as u32 / count,
                        };
                    smol::Timer::at(scheduled).await;
                    let mut bodies = plan.bodies;
                    // When the session's previous call was answered: no
                    // call goes before it.
                    let mut previous = scheduled;
                    // Its increments run, in or out of the windows.
                    let mut ran = 0u64;
                    while scheduled < end {
                        // Signed, when it is signed as it goes, in the
                        // session's time between calls.
                        let Some(body) = bodies.next() else {
                            let window = if scheduled < first {
                                0
                            } else {
                                window_of(scheduled).unwrap_or(windows - 1)
                            };
                            mine[window].exhausted += 1;
                            break;
                        };
                        if let Pace::Open(_) = pace {
                            smol::Timer::at(scheduled).await;
                        }
                        let sent = Instant::now();
                        let from = match pace {
                            Pace::Closed => sent,
                            Pace::Open(_) => scheduled,
                        };
                        let answer =
                            call(space, &mut http, &mut node, &plan.path, &body, end).await;
                        let answered = Instant::now();
                        if matches!(
                            answer,
                            Some(Response::Ran {
                                outcome: Outcome::Done(_),
                                ..
                            })
                        ) {
                            ran += 1;
                        }
                        if let Some(window) = window_of(from) {
                            let opened = first + measure * window as u32;
                            if answered >= opened + measure {
                                mine[window].answered_after += 1;
                            }
                            let into = from - opened;
                            if into < measure / 4 {
                                mine[window].first_quarter.push(answered - from);
                            } else if into >= measure * 3 / 4 {
                                mine[window].last_quarter.push(answered - from);
                            }
                            let mine = &mut mine[window];
                            match answer {
                                Some(Response::Ran {
                                    outcome: Outcome::Done(_),
                                    ..
                                }) => {
                                    mine.latencies.push(answered - from);
                                    if let Pace::Open(_) = pace {
                                        // The driver's own lateness: past
                                        // the schedule and the previous
                                        // answer both.
                                        mine.lags.push(
                                            sent.saturating_duration_since(scheduled.max(previous)),
                                        );
                                        if previous > scheduled {
                                            mine.behind += 1;
                                        }
                                    }
                                }
                                other => {
                                    mine.failed += 1;
                                    mine.first_failure.get_or_insert(format!("{other:?}"));
                                }
                            }
                        }
                        previous = answered;
                        scheduled = match pace {
                            Pace::Closed => answered,
                            Pace::Open(interval) => scheduled + interval,
                        };
                    }
                    if let Some(agent) = plan.counts {
                        *space.ran.lock().unwrap().entry(agent).or_default() += ran;
                    }
                    let mut samples = samples.lock().unwrap();
                    for (samples, mine) in samples.iter_mut().zip(mine) {
                        samples.latencies.extend(mine.latencies);
                        samples.lags.extend(mine.lags);
                        samples.failed += mine.failed;
                        samples.exhausted += mine.exhausted;
                        samples.behind += mine.behind;
                        samples.answered_after += mine.answered_after;
                        samples.first_quarter.extend(mine.first_quarter);
                        samples.last_quarter.extend(mine.last_quarter);
                        if samples.first_failure.is_none() {
                            samples.first_failure = mine.first_failure;
                        }
                    }
                })
            })
            .collect();
        for task in tasks {
            smol::block_on(task);
        }
        stop.store(true, Ordering::Relaxed);
    });
    drop(executor);
    let edges = edges_cpu.into_inner().unwrap();
    let mut edges = edges.into_iter();
    let mut before = edges.next().unwrap_or_default();
    samples
        .into_inner()
        .unwrap()
        .into_iter()
        .map(|samples| {
            let after = edges.next().unwrap_or_default();
            let cpu = (std::mem::replace(&mut before, after.clone()), after);
            (samples, cpu)
        })
        .collect()
}
