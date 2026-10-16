//! The VOS actor SDK's macros.
//!
//! - `#[actor]` on the state struct: its encoding, which skips `Table` and
//!   `CommittedMap` fields, and each one's tag.
//! - `#[messages]` on the impl block: a message type per handler, the
//!   dispatcher, which routes to handlers and workflows alike, and the
//!   program's schema; and for each `#[attestable]` method, the entry its
//!   kernel is derived from.

mod actor;
mod messages;
mod names;

use proc_macro::TokenStream;
use proc_macro2::Span;
use syn::{Error, ItemImpl, ItemStruct, LitStr, Type, parse_macro_input};

use actor::actor_impl;
use messages::messages_impl;

pub(crate) fn last_segment(ty: &Type) -> Option<&syn::PathSegment> {
    match ty {
        Type::Path(path) => path.path.segments.last(),
        _ => None,
    }
}

pub(crate) fn is_named(ty: &Type, name: &str) -> bool {
    last_segment(ty).is_some_and(|segment| segment.ident == name)
}

/// The string value of `name = "..."` inside an attribute's arguments.
pub(crate) fn string_arg(meta: &syn::meta::ParseNestedMeta) -> syn::Result<String> {
    Ok(meta.value()?.parse::<LitStr>()?.value())
}

// ===== #[actor] =====

/// The actor's state: a struct whose encoding is stored under the instance,
/// and whose `Table` and `CommittedMap` fields are handles to rows stored
/// beside it.
///
/// A table's tag derives from its field's name, or from
/// `#[table(name = "...")]`, which keeps rows reachable when the field is
/// renamed. Its key transform is its type's.
#[proc_macro_attribute]
pub fn actor(attr: TokenStream, item: TokenStream) -> TokenStream {
    if !attr.is_empty() {
        return Error::new(Span::call_site(), "#[actor] takes no arguments")
            .to_compile_error()
            .into();
    }
    let input = parse_macro_input!(item as ItemStruct);
    actor_impl(input)
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

// ===== #[messages] =====

/// The handlers of an actor.
///
/// - **Messages:** each `#[msg]` method becomes a message type, with the
///   handler's arguments as fields, in a module named after the actor in
///   snake case, or as `#[messages(module = "...")]` names it;
///   `#[attestable]` and `#[workflow]` methods likewise.
/// - **The module** imports its parent's names, so argument types resolve
///   as they do beside the impl. A message type shadows a parent type of
///   the same name, so a handler must not be named after an argument type
///   (a `balance` handler beside a `Balance` argument).
/// - **Workflows** are routed in the actor's program as handlers are. A
///   `#[workflow]` takes no `self`: `ctx: &mut Workflow<Self>` if it uses
///   one, then its arguments.
/// - **Attestable methods** each run as their own kernel, derived at
///   install from the entry generated for them, `__vos_attest_<name>`.
///   `#[attestable(gas = N)]` sets the gas limit its kernel runs within on
///   a target that bounds kernels' BLAKE2b compressions, which its install
///   checks; it takes no role.
/// - **Options:** `#[msg(role = "...", gas = N)]`, the role a caller needs
///   and the handler's gas limit; `#[workflow(role = "...", gas = N)]`
///   alike, the role checked when it starts and the gas each step's.
/// - **Linearizable:** on a query, `#[msg(linearizable)]` always reads
///   after a read index, whatever consistency its client asks. That governs
///   the query a client names: a method it calls reads its snapshot.
/// - **A new instance's state:** the impl block must define
///   `fn new() -> Self`.
#[proc_macro_attribute]
pub fn messages(attr: TokenStream, item: TokenStream) -> TokenStream {
    let mut module = None;
    let parser = syn::meta::parser(|meta| {
        if meta.path.is_ident("module") {
            module = Some(string_arg(&meta)?);
            Ok(())
        } else {
            Err(meta.error("expected `module = \"...\"`"))
        }
    });
    parse_macro_input!(attr with parser);
    let input = parse_macro_input!(item as ItemImpl);
    messages_impl(input, module)
        .unwrap_or_else(Error::into_compile_error)
        .into()
}
