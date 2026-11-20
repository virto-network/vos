//! The node's formats and the stock actors' messages: a refine's batch
//! ([`batch`]), the apply of its result ([`apply`]), a work package
//! ([`package`]), a node's ingress ([`ingress`]) and its peers' messages
//! ([`peer`]); and the messages of the credential actor ([`credentials`]),
//! the personal agent ([`personal`]), the homes ([`homes`]), the books
//! ([`books`]) and the ledger ([`payments`]). The actor ABI they are built on is `vos-abi`'s.
//!
//! Everything here is SCALE-coded with the workspace codec, the encoding JAM
//! uses.

#![no_std]

extern crate alloc;

/// The method ids of an actor's handlers, each a constant named after its
/// handler, and [`ALL`](personal::method::ALL) with their names: what host
/// code calls an actor with or compares a call's method to, each name held
/// to the built actor by the test that resolves it there (`vos-testkit`'s
/// `methods` test), so a handler renamed fails that test.
macro_rules! methods {
    ($($id:ident = $name:literal;)*) => {
        $(
            #[doc = concat!("`", $name, "`.")]
            pub const $id: vos_abi::ids::MethodId =
                vos_abi::ids::MethodId(vos_sdk_macros::method_id!($name));
        )*
        /// Every id above, by its handler's name.
        pub const ALL: &[(&str, vos_abi::ids::MethodId)] = &[$(($name, $id)),*];
    };
}

pub mod apply;
pub mod batch;
pub mod books;
pub mod credentials;
pub mod homes;
pub mod ingress;
pub mod package;
pub mod payments;
pub mod peer;
pub mod personal;

/// When a session's row in the due index is due: sessions are filed by the
/// bucket of their last activity, so one sweep collects many.
pub mod expiry;

/// The node's and the agent's defaults. Each is a constant, cheap to change.
pub mod defaults;
