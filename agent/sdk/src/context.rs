//! Handler and workflow contexts. A query's context reaches only
//! operations that read; a command's adds the ones that write; a
//! workflow's reaches its instance's state only through sections and
//! calls, and adds the awaits that pause it.

use core::cell::Cell;
use core::future::{IntoFuture, Ready, ready};
use core::marker::PhantomData;
use core::time::Duration;

use alloc::vec::Vec;

use vos_wire::abi::{AttestError, Failure};
use vos_wire::batch::Answer;
use vos_wire::ids::{AgentId, InstanceId, Principal, WorkflowId};
use vos_wire::result::Attested;
use vos_wire::{Decode, DecodeError, Encode, keys};

use crate::host;
use crate::state::{self, New, Tables};
use crate::table::Read;

/// A handler of an actor, as a message another actor can send.
pub trait Method: Encode {
    /// The actor that handles it.
    type Actor;
    const ID: u32;
    type Reply: Decode;
    type Error: Decode;
}

/// A `&self` handler: callable from queries too.
pub trait QueryMethod: Method {}

/// An `#[attestable]` method, run as its kernel.
pub trait AttestableMethod: Encode {
    type Actor;
    const ID: u32;
    type Output: Decode;
}

/// An `#[attestable]` `&self` method: run as its kernel at a window's cut,
/// on its instance's committed rows as they stood there
/// ([`Workflow::attest_at_cut`]).
pub trait AtCutMethod: Encode {
    type Actor;
    const ID: u32;
    type Output: Decode;
}

/// A `#[workflow]` method, routed in its actor's program and run as a
/// workflow: a request naming it starts one, answered with its id, and its
/// result is read by that id.
pub trait WorkflowMethod: Encode {
    type Actor;
    const ID: u32;
    type Output: Decode;
    type Error: Decode;
}

/// The error type of a handler that cannot fail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Never {}

impl Decode for Never {
    fn decode(_: &[u8]) -> Result<(Self, usize), DecodeError> {
        Err(DecodeError::InvalidDiscriminator(0))
    }
}

impl Encode for Never {
    fn encode_to(&self, _: &mut alloc::vec::Vec<u8>) {
        match *self {}
    }
}

/// An instance of actor `A` in this agent.
pub struct Ref<A> {
    pub instance: InstanceId,
    _actor: PhantomData<fn() -> A>,
}

impl<A> Ref<A> {
    pub const fn new(instance: InstanceId) -> Self {
        Self {
            instance,
            _actor: PhantomData,
        }
    }
}

impl<A> Clone for Ref<A> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<A> Copy for Ref<A> {}

/// Why a nested call returned an error. Any other failure of the callee
/// fails the whole step, so the caller never sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CallError<E> {
    /// The callee's own error.
    Failed(E),
    /// This instance lacks the callee's role; the callee did not run.
    Forbidden,
    /// The reply or error did not decode as the method's types.
    Undecodable,
}

fn decode<T: Decode>(bytes: &[u8]) -> Option<T> {
    T::decode(bytes).ok().map(|(value, _)| value)
}

fn outcome<R: Decode, E: Decode>(
    result: Result<alloc::vec::Vec<u8>, (u32, alloc::vec::Vec<u8>)>,
) -> Result<R, CallError<E>> {
    match result {
        Ok(reply) => decode(&reply).ok_or(CallError::Undecodable),
        Err((code, detail)) => match Failure::from_code(code) {
            Some(Failure::Handler) => {
                Err(decode(&detail).map_or(CallError::Undecodable, CallError::Failed))
            }
            Some(Failure::Forbidden) => Err(CallError::Forbidden),
            _ => Err(CallError::Undecodable),
        },
    }
}

/// What a handler's and a workflow's contexts read alike: the batch's time
/// and random bytes, and logs.
macro_rules! batch_reads {
    () => {
        /// The time of the batch, or for a query of the last applied one, in
        /// milliseconds since the Unix epoch.
        pub fn now(&self) -> u64 {
            host::now()
        }

        /// 32 bytes derived from the batch seed: the same on every replica.
        pub fn random(&self) -> [u8; 32] {
            host::random()
        }

        pub fn log(&self, level: Level, message: &str) {
            host::log(level as u8, message.as_bytes());
        }
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
    Trace = 4,
}

/// The context of a `&self` handler.
pub struct Query<A> {
    _actor: PhantomData<fn() -> A>,
}

impl<A> Query<A> {
    #[doc(hidden)]
    pub const fn new() -> Self {
        Self {
            _actor: PhantomData,
        }
    }

    /// Who invoked this handler: the calling instance, for a nested call.
    pub fn caller(&self) -> Principal {
        decode(&host::caller()).expect("the agent passes a principal")
    }

    /// This agent and instance.
    pub fn me(&self) -> (AgentId, InstanceId) {
        let (instance, agent) = host::self_id();
        (AgentId(agent), InstanceId(instance))
    }

    batch_reads!();

    /// Call a query of another instance of this agent.
    pub async fn call<M: QueryMethod>(
        &self,
        to: Ref<M::Actor>,
        message: M,
    ) -> Result<M::Reply, CallError<M::Error>> {
        outcome(host::call(to.instance.0, M::ID, &message.encode()))
    }
}

/// The context of a `&mut self` handler: everything a query has, and the
/// operations that write.
pub struct Command<A> {
    query: Query<A>,
}

impl<A> core::ops::Deref for Command<A> {
    type Target = Query<A>;

    fn deref(&self) -> &Query<A> {
        &self.query
    }
}

impl<A> Command<A> {
    #[doc(hidden)]
    pub const fn new() -> Self {
        Self {
            query: Query::new(),
        }
    }

    /// Call any handler of another instance of this agent. The callee runs
    /// nested and completes before this returns.
    pub async fn call<M: Method>(
        &mut self,
        to: Ref<M::Actor>,
        message: M,
    ) -> Result<M::Reply, CallError<M::Error>> {
        outcome(host::call(to.instance.0, M::ID, &message.encode()))
    }

    /// Send a message to an instance of any agent, delivered after this
    /// step commits.
    pub fn send<M: Method>(&mut self, agent: AgentId, to: Ref<M::Actor>, message: M) {
        host::send(agent.0, to.instance.0, M::ID, &message.encode());
    }

    /// Run one of this actor's attestable methods, as its kernel.
    pub async fn attest<M: AttestableMethod<Actor = A>>(
        &mut self,
        arguments: M,
    ) -> Result<M::Output, CallError<Never>> {
        match host::attest(M::ID, &arguments.encode()) {
            Ok(output) => decode(&output).ok_or(CallError::Undecodable),
            Err(_) => Err(CallError::Undecodable),
        }
    }
}

/// Why an await of another agent returned an error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequestError<E> {
    /// The callee's own error.
    Failed(E),
    /// The deadline passed before the answer came.
    TimedOut,
    /// The callee failed otherwise, or never ran: no such method or
    /// workflow, a role missing, a trap; the code says which.
    Refused(Failure),
    /// The answer did not decode as the method's types.
    Undecodable,
}

/// An answer, its failures as the awaited method's error.
fn awaited<E: Decode>(answer: &[u8]) -> Result<Answer, RequestError<E>> {
    let answer: Answer = decode(answer).ok_or(RequestError::Undecodable)?;
    match answer {
        Answer::Failed {
            code: Failure::Handler,
            detail,
        } => Err(decode(&detail).map_or(RequestError::Undecodable, RequestError::Failed)),
        Answer::Failed {
            code: Failure::TimedOut,
            ..
        } => Err(RequestError::TimedOut),
        Answer::Failed { code, .. } => Err(RequestError::Refused(code)),
        answer => Ok(answer),
    }
}

/// An answer that is a reply, decoded.
fn replied<T: Decode, E: Decode>(answer: &[u8]) -> Result<T, RequestError<E>> {
    match awaited::<E>(answer)? {
        Answer::Done(reply) => decode(&reply).ok_or(RequestError::Undecodable),
        _ => Err(RequestError::Undecodable),
    }
}

/// A deadline as the ABI takes it: milliseconds, at least one and at most
/// `u64::MAX`; 0 for the agent's default.
fn millis(within: Option<Duration>) -> u64 {
    within.map_or(0, |within| {
        u64::try_from(within.as_millis()).map_or(u64::MAX, |millis| millis.max(1))
    })
}

/// The context of a `#[workflow]`: its instance's state through sections,
/// calls to this agent's instances, messages, and the awaits of other
/// agents and timers at which it pauses. Every `.await` may pause: the code
/// between two of them runs atomically, its effects committing with the
/// snapshot taken at the next pause.
///
/// Code with no effect yet may pause anywhere: when the step's share of
/// the batch's gas is spent, the workflow is snapshotted and goes on in the
/// next batch, so a long computation needs no await. From its first effect
/// (a section, a call, a send, a request, a wait or the result) to its next
/// await, the code has the workflow's whole gas limit, and never pauses.
///
/// **Memory:** a workflow runs in its actor's program, on the whole heap
/// the actor configures, of which its handlers map the start. The pages it has written that differ from the
/// program's image are its snapshot, which every step restores: at most
/// [`crate::abi::cap::HELD_PAGES`] pages, 2.25 MiB, and a step that would
/// leave it more fails the workflow. Each page held costs every step its
/// restore, so a workflow keeps what it carries across pauses small.
///
/// **Sections** ([`Workflow::read`], [`Workflow::update`]) reach the state
/// of the instance the workflow runs for, its tables included, as the
/// instance itself. A section is synchronous: its closure can neither await
/// nor call, and the agent serves only the instance's rows, the time and
/// logs inside it, so a section never spans a pause. State is read afresh
/// in every section. A short computation on state belongs inside one
/// `update`, which reads and writes atomically; a long one cannot keep that
/// atomicity, since a unit that computes long must pause between its read
/// and its write, and so re-reads after the pause:
///
/// ```text
/// let order = ctx.read(|shop: &Shop| shop.orders.get(&id));
/// let priced = price(order).await; // a pause: state may change meanwhile
/// ctx.update(|shop: &mut Shop| {
///     if shop.orders.get(&id) == order {
///         shop.orders.insert(&id, &priced);
///     }
/// });
/// ```
pub struct Workflow<A> {
    /// This agent and instance, asked once: the workflow's memory keeps
    /// them across its pauses.
    me: Cell<Option<(AgentId, InstanceId)>>,
    _actor: PhantomData<fn() -> A>,
}

impl<A> Workflow<A> {
    #[doc(hidden)]
    pub const fn new() -> Self {
        Self {
            me: Cell::new(None),
            _actor: PhantomData,
        }
    }

    /// This agent, and the instance whose workflow this is.
    pub fn me(&self) -> (AgentId, InstanceId) {
        if let Some(me) = self.me.get() {
            return me;
        }
        let (instance, agent) = host::self_id();
        let me = (AgentId(agent), InstanceId(instance));
        self.me.set(Some(me));
        me
    }

    batch_reads!();

    /// Call any handler of an instance of this agent, as the workflow's
    /// instance. The callee runs nested and completes before this returns;
    /// the step may pause here once its share of the batch's gas is spent.
    pub async fn call<M: Method>(
        &mut self,
        to: Ref<M::Actor>,
        message: M,
    ) -> Result<M::Reply, CallError<M::Error>> {
        outcome(host::call(to.instance.0, M::ID, &message.encode()))
    }

    /// Send a message to an instance of any agent, delivered after this
    /// step commits.
    pub fn send<M: Method>(&mut self, agent: AgentId, to: Ref<M::Actor>, message: M) {
        host::send(agent.0, to.instance.0, M::ID, &message.encode());
    }

    /// Ask a handler of another agent's instance, and await its reply:
    /// the step ends here, and the workflow resumes once the reply comes,
    /// or the deadline passes ([`Request::within`]).
    pub fn request<M: Method>(
        &mut self,
        agent: AgentId,
        to: Ref<M::Actor>,
        message: M,
    ) -> Request<M> {
        Request {
            agent,
            instance: to.instance,
            message,
            within: None,
        }
    }

    /// Start a workflow of another agent's instance, and await its id,
    /// which [`Workflow::result`] then awaits the result by.
    pub fn start<M: WorkflowMethod>(
        &mut self,
        agent: AgentId,
        to: Ref<M::Actor>,
        arguments: M,
    ) -> Start<M> {
        Start {
            agent,
            instance: to.instance,
            arguments,
            within: None,
        }
    }

    /// Await the result of a workflow this one started at `agent`.
    pub fn result<M: WorkflowMethod>(
        &mut self,
        agent: AgentId,
        workflow: WorkflowId,
    ) -> Pending<M> {
        Pending {
            agent,
            workflow,
            within: None,
            _method: PhantomData,
        }
    }

    /// Pause until a batch at or past `time`, in milliseconds since the
    /// Unix epoch.
    pub async fn sleep_until(&mut self, time: u64) {
        host::sleep(time);
    }
}

impl<A: Tables + New> Workflow<A> {
    /// Read the workflow's instance's committed rows at the cut of the
    /// current window, through attestable `&self` method `call`: the rows
    /// [`AtCut::reads`] names are proved there, then served to the method's
    /// kernel, which checks them against the space's root and runs on them.
    /// Awaited, it pauses until the window's cut is built and closed, and
    /// returns the kernel's output, or why there is none
    /// ([`AttestError`]). The run is recorded as the step's attest, for a
    /// prover; the workflow's record never holds the served rows.
    pub fn attest_at_cut<M: AtCutMethod<Actor = A>>(&mut self, call: M) -> AtCut<A, M> {
        let (_, instance) = self.me();
        AtCut {
            instance,
            call,
            reads: Vec::new(),
            _actor: PhantomData,
        }
    }
}

impl<A: Encode + Decode + Tables + New> Workflow<A> {
    /// Read the state of the workflow's instance, its tables included, in
    /// a section: `f`'s result. A new instance's state when none is stored.
    /// It borrows the context whole, so `f` reaches nothing of it.
    pub fn read<R>(&mut self, f: impl FnOnce(&A) -> R) -> R {
        let (_, instance) = self.me();
        host::open(instance.0);
        let state = state::load::<A>();
        let result = f(&state);
        host::close();
        result
    }

    /// Read and change the state of the workflow's instance, its tables
    /// included, atomically in a section: `f`'s result. The state is
    /// written back if it changed; its tables' writes are `f`'s own.
    pub fn update<R>(&mut self, f: impl FnOnce(&mut A) -> R) -> R {
        let (_, instance) = self.me();
        host::open(instance.0);
        let mut state = state::load::<A>();
        let before = state.encode();
        let result = f(&mut state);
        state::save(&state, &before);
        host::close();
        result
    }
}

/// The deadline of an await, `within`, on each of its builders.
macro_rules! within {
    ($($builder:ident),*) => {$(
        impl<M> $builder<M> {
            /// The deadline, after this step's batch time; the agent's default
            /// otherwise.
            pub fn within(mut self, deadline: Duration) -> Self {
                self.within = Some(deadline);
                self
            }
        }
    )*};
}

within!(Request, Start, Pending);

/// A request of another agent, awaited.
#[must_use = "a request is sent when awaited"]
pub struct Request<M> {
    agent: AgentId,
    instance: InstanceId,
    message: M,
    within: Option<Duration>,
}

impl<M: Method> IntoFuture for Request<M> {
    type Output = Result<M::Reply, RequestError<M::Error>>;
    type IntoFuture = Ready<Self::Output>;

    fn into_future(self) -> Self::IntoFuture {
        let answer = host::request(
            self.agent.0,
            self.instance.0,
            M::ID,
            &self.message.encode(),
            millis(self.within),
        );
        ready(replied::<M::Reply, M::Error>(&answer))
    }
}

/// A start of another agent's workflow, awaited for its id.
#[must_use = "a start is sent when awaited"]
pub struct Start<M> {
    agent: AgentId,
    instance: InstanceId,
    arguments: M,
    within: Option<Duration>,
}

impl<M: WorkflowMethod> IntoFuture for Start<M> {
    type Output = Result<WorkflowId, RequestError<Never>>;
    type IntoFuture = Ready<Self::Output>;

    fn into_future(self) -> Self::IntoFuture {
        let answer = host::request(
            self.agent.0,
            self.instance.0,
            M::ID,
            &self.arguments.encode(),
            millis(self.within),
        );
        ready(match awaited::<Never>(&answer) {
            Ok(Answer::Started(workflow)) => Ok(workflow),
            Ok(_) => Err(RequestError::Undecodable),
            Err(error) => Err(error),
        })
    }
}

/// A read at a window's cut, awaited for its kernel's output.
#[must_use = "a read at a cut is asked when awaited"]
pub struct AtCut<A, M> {
    instance: InstanceId,
    call: M,
    reads: Vec<Read>,
    _actor: PhantomData<fn() -> A>,
}

impl<A: Tables + New, M> AtCut<A, M> {
    /// The rows the method reads, named by `f` through the actor's committed
    /// maps ([`crate::table::CommittedMap::read`]), in any order: the
    /// method's view answers these alone. A row named twice is refused
    /// ([`AttestError::Reads`]).
    pub fn reads(mut self, f: impl FnOnce(&A) -> Vec<Read>) -> Self {
        let mut maps = A::new();
        maps.bind_tables();
        self.reads = f(&maps);
        self
    }
}

impl<A, M: AtCutMethod> IntoFuture for AtCut<A, M> {
    type Output = Result<M::Output, AttestError>;
    type IntoFuture = Ready<Self::Output>;

    fn into_future(self) -> Self::IntoFuture {
        let rows: Result<Vec<Vec<u8>>, _> = self
            .reads
            .iter()
            .map(|read| keys::row(self.instance, read.rows, &read.key))
            .collect();
        let Ok(mut rows) = rows else {
            return ready(Err(AttestError::Reads));
        };
        rows.sort_unstable();
        let returned = host::attest_at(M::ID, &self.call.encode(), &rows.encode())
            .map_err(|code| AttestError::from_code(code).unwrap_or(AttestError::Undecodable))
            .and_then(|input| match decode::<Attested>(&input) {
                Some(Attested::Done(output)) => Ok(output),
                Some(Attested::Failed(error)) => Err(error),
                None => Err(AttestError::Undecodable),
            })
            .and_then(|output| decode::<M::Output>(&output).ok_or(AttestError::Undecodable));
        ready(returned)
    }
}

/// A wait for another agent's workflow's result.
#[must_use = "a wait is sent when awaited"]
pub struct Pending<M> {
    agent: AgentId,
    workflow: WorkflowId,
    within: Option<Duration>,
    _method: PhantomData<fn() -> M>,
}

impl<M: WorkflowMethod> IntoFuture for Pending<M> {
    type Output = Result<M::Output, RequestError<M::Error>>;
    type IntoFuture = Ready<Self::Output>;

    fn into_future(self) -> Self::IntoFuture {
        let answer = host::result(self.agent.0, self.workflow.0, millis(self.within));
        ready(replied::<M::Output, M::Error>(&answer))
    }
}
