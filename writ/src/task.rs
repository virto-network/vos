use crate::wasi::clocks::wall_clock::Datetime;
use crate::{State, TyDef, json, protocol::Protocol, storage::TaskStorage};
use std::ascii::Char;
use std::fmt;
use std::ops::{Deref, DerefMut};

type Error<S> = <<S as State>::Storage as TaskStorage<S>>::Error;

///
pub struct TaskName<const N: usize = 16>([Char; N]);
impl<const N: usize> TaskName<{ N }> {
    pub const fn from_str(name: &str) -> Self {
        let name = name.trim_ascii().as_bytes();
        let mut bytes = [Char::Space; N];
        let len = if name.len() < N { name.len() } else { N };
        let mut i = 0usize;
        while i < len {
            bytes[i] = name[i].as_ascii().expect("ascii char");
            i += 1;
        }
        TaskName(bytes)
    }
    pub const fn as_str(&self) -> &str {
        self.0.as_str().trim_ascii_end()
    }
}
impl<const N: usize> AsRef<str> for TaskName<{ N }> {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl From<&str> for TaskName {
    fn from(name: &str) -> Self {
        TaskName::from_str(name)
    }
}
impl fmt::Debug for TaskName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Task
/// ```
/// # use writ::{Task, Protocol::*, Action::*};
/// # async fn main() {
/// struct Foo(pub bool);
///
/// let task = if let Some(task) = Task::resume().await? { taks } else {
///     Task::<Foo>::init(|_| Foo(true)).await?
/// };
/// let protocol = Protocol::detect();
///
/// protocol.wait_for_actions(task.name(), async |action| {
///     match action {
///         Query(name, params) => task.run(name, pararms).await,
///         Command(name, params) => task.run_in_background(name, params).await,
///     }
/// }).await;
/// # }
/// ```
pub struct Task<S = json::Value> {
    name: TaskName,
    stats: Stats,
    state: S,
}

impl<S: State> Task<S> {
    pub const fn metadata() -> &'static Metadata {
        S::META
    }

    pub async fn init(init_fn: impl AsyncFnOnce(&Metadata) -> S) -> Result<Self, Error<S>> {
        Self::init_named(S::META.default_name.as_str(), init_fn).await
    }

    pub async fn init_named(
        name: impl AsRef<str>,
        init_fn: impl AsyncFnOnce(&Metadata) -> S,
    ) -> Result<Self, Error<S>> {
        let state = init_fn(Self::metadata()).await;
        let task = Task {
            name: name.as_ref().into(),
            stats: Stats::default(),
            state,
        };
        S::Storage::initialize(task.name.as_str()).await?;
        Ok(task)
    }

    pub async fn resume() -> Result<Option<Self>, Error<S>> {
        Self::resume_named(S::META.default_name.as_str()).await
    }

    pub async fn resume_named(name: impl AsRef<str>) -> Result<Option<Self>, Error<S>> {
        let name = name.as_ref();
        let Some((updated, state)) = S::Storage::restore(name).await? else {
            return Ok(None);
        };
        Ok(Some(Self {
            name: TaskName::from_str(name),
            stats: Stats {
                last_updated: Some(updated),
            },
            state,
        }))
    }

    pub async fn run(
        &self,
        _action_name: &str,
        _params: impl Iterator<Item = (&str, json::Value)>,
    ) -> Result<(), Error<S>> {
        todo!()
    }

    pub async fn run_in_background(
        &self,
        _action_name: &str,
        _params: impl Iterator<Item = (&str, json::Value)>,
    ) -> Result<(), Error<S>> {
        todo!()
    }

    async fn update(&self) -> Result<(), Error<S>> {
        S::Storage::update(self.name.as_ref(), &self.state).await
    }
}

impl<S> Task<S> {
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    pub async fn wait_for_action(&self, protocol: Protocol) {
        match protocol {
            Protocol::Simple => todo!(),
            Protocol::Nu => todo!(),
            Protocol::HttpRpc(_) => todo!(),
        }
    }
}

impl<S: State> fmt::Display for Task<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

impl<S> Deref for Task<S> {
    type Target = S;
    fn deref(&self) -> &Self::Target {
        &self.state
    }
}
impl<S> DerefMut for Task<S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.state
    }
}

///
#[derive(Debug, Default)]
pub struct Stats {
    pub last_updated: Option<Datetime>,
}

///
#[derive(Debug)]
pub struct Metadata {
    pub version: u16,
    pub default_name: TaskName,
    pub constructors: &'static [&'static TyDef],
    pub queries: &'static [&'static TyDef],
    pub commands: &'static [&'static TyDef],
}

impl Metadata {
    pub const fn simple_crud_task() -> Self {
        Self {
            version: 0,
            default_name: TaskName::from_str("crud"),
            constructors: &[],
            queries: &[],
            commands: &[],
        }
    }
}
