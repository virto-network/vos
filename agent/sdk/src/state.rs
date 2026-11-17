//! An actor's state as its handlers hold it: the struct of its handles,
//! each bound to its rows. The state itself is the rows.

/// Binds an actor's fields, each a handle on rows, to their tags.
/// `#[actor]` implements it.
pub trait Tables {
    fn bind_tables(&mut self);
}

/// What `#[actor(...)]` marks an actor as, which its program's schema
/// carries. `#[actor]` implements it.
pub trait Marked {
    /// `#[actor(credentials)]`: its agent's credential actor, whose ring
    /// the agent's auth guards read.
    const CREDENTIALS: bool;
    /// `#[actor(known_keys, onion_only)]`: what its agent's ingress asks of
    /// the requests it takes (`light-node.md` §3.3). An actor that asks
    /// known keys keeps them as the rows of its table `admitted`
    /// ([`vos_abi::schema::ADMITTED`]).
    const ADMISSION: vos_abi::schema::Admission;
}

/// The actor's struct, its handles unbound. `#[actor]` implements it, each
/// field its `Default`.
pub trait New {
    fn new() -> Self;
}

/// The view of an actor's state an attestable `&self` method reads: its
/// committed maps alone, each answering from the rows served at a window's
/// cut ([`crate::table::ServedMap`]). `#[actor]` generates it, as
/// `<Actor>View`.
pub trait View {
    /// The view over `served`, each map bound to its tag.
    fn served(served: &'static vos_abi::served::Served) -> Self;
}

/// The instance's state: the actor's struct, each handle bound to its
/// rows. It reads nothing: a handler pays for the rows it touches.
pub fn load<A: Tables + New>() -> A {
    let mut state = A::new();
    state.bind_tables();
    state
}
