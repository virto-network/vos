//! `#[messages]`: a message type per handler, the dispatcher, the schema
//! and the attestable methods' entries.

use proc_macro2::{Span, TokenStream as Tokens};
use quote::{format_ident, quote};
use syn::spanned::Spanned;
use syn::{
    Attribute, Error, Expr, ExprLit, FnArg, Ident, ImplItem, ImplItemFn, ItemImpl, Lit, Meta, Pat,
    PathArguments, ReturnType, Type,
};
use vos_wire::abi::Kind;
use vos_wire::ids::MethodId;
use vos_wire::schema::{MethodSchema, Schema};

use crate::names::{Ids, snake, upper_camel};
use crate::{is_named, last_segment, string_arg};

struct Handler {
    method: ImplItemFn,
    name: String,
    id: u32,
    kind: Kind,
    options: Options,
    has_context: bool,
    arguments: Vec<(Ident, Type)>,
    reply: Type,
    error: Option<Type>,
}

impl Handler {
    /// Its arguments' names.
    fn names(&self) -> Vec<&Ident> {
        self.arguments.iter().map(|(name, _)| name).collect()
    }
}

/// `T` and `Some(E)` for `Result<T, E>`, else the type and `None`.
fn reply_and_error(output: &ReturnType) -> (Type, Option<Type>) {
    let ty: Type = match output {
        ReturnType::Default => syn::parse_quote!(()),
        ReturnType::Type(_, ty) => (**ty).clone(),
    };
    if let Some(segment) = last_segment(&ty)
        && segment.ident == "Result"
        && let PathArguments::AngleBracketed(arguments) = &segment.arguments
        && arguments.args.len() == 2
        && let (syn::GenericArgument::Type(ok), syn::GenericArgument::Type(err)) =
            (&arguments.args[0], &arguments.args[1])
    {
        return (ok.clone(), Some(err.clone()));
    }
    (ty, None)
}

/// A handler's options, from `#[msg(role = "...", gas = N, linearizable)]`.
#[derive(Default)]
struct Options {
    role: Option<String>,
    gas: Option<u64>,
    /// A query that always reads after a read index.
    linearizable: Option<Span>,
}

fn msg_options(attribute: &Attribute) -> syn::Result<Options> {
    let mut options = Options::default();
    if let Meta::List(_) = attribute.meta {
        attribute.parse_nested_meta(|meta| {
            if meta.path.is_ident("role") {
                options.role = Some(string_arg(&meta)?);
            } else if meta.path.is_ident("linearizable") {
                options.linearizable = Some(meta.path.span());
            } else if meta.path.is_ident("gas") {
                let Expr::Lit(ExprLit {
                    lit: Lit::Int(value),
                    ..
                }) = meta.value()?.parse::<Expr>()?
                else {
                    return Err(meta.error("expected an integer gas limit"));
                };
                options.gas = Some(value.base10_parse()?);
            } else {
                return Err(meta.error("expected `role = \"...\"`, `gas = N` or `linearizable`"));
            }
            Ok(())
        })?;
    }
    Ok(options)
}

/// The kind an attribute marks a method to run as, apart from a handler:
/// `#[attestable]` or `#[workflow]`.
fn mark(attribute: &Attribute) -> Option<Kind> {
    if attribute.path().is_ident("attestable") {
        Some(Kind::Attestable)
    } else if attribute.path().is_ident("workflow") {
        Some(Kind::Workflow)
    } else {
        None
    }
}

fn handler(
    mut method: ImplItemFn,
    attribute: &Attribute,
    marked: Option<Kind>,
    ids: &mut Ids,
) -> syn::Result<Handler> {
    let name = method.sig.ident.to_string();
    let options = msg_options(attribute)?;
    if marked == Some(Kind::Attestable)
        && (options.role.is_some() || options.linearizable.is_some())
    {
        return Err(Error::new(
            attribute.span(),
            "an #[attestable] method takes `gas = N` alone: it has no caller and reads no state",
        ));
    }
    let mut inputs = method.sig.inputs.iter();
    let kind = if let Some(kind) = marked {
        if let Some(FnArg::Receiver(receiver)) = method.sig.inputs.first() {
            return Err(Error::new(
                receiver.span(),
                if kind == Kind::Workflow {
                    "a #[workflow] takes no `self`: it holds only its own memory"
                } else {
                    "an #[attestable] method takes no `self`: it sees only its arguments"
                },
            ));
        }
        kind
    } else {
        match inputs.next() {
            Some(FnArg::Receiver(receiver)) if receiver.reference.is_some() => {
                if receiver.mutability.is_some() {
                    Kind::Command
                } else {
                    Kind::Query
                }
            }
            _ => {
                return Err(Error::new(
                    method.sig.span(),
                    "a #[msg] handler takes `&self` (a query) or `&mut self` (a command)",
                ));
            }
        }
    };
    if let Some(span) = options.linearizable
        && kind != Kind::Query
    {
        return Err(Error::new(
            span,
            "only a query (`&self`) is `linearizable`: what runs through the log already is",
        ));
    }
    let mut has_context = false;
    let mut arguments = Vec::new();
    for (index, input) in inputs.enumerate() {
        let FnArg::Typed(typed) = input else {
            unreachable!("only the first input can be a receiver");
        };
        if index == 0
            && let Type::Reference(reference) = &*typed.ty
            && ["Query", "Command", "Workflow"]
                .iter()
                .any(|context| is_named(&reference.elem, context))
        {
            let mutable = reference.mutability.is_some();
            let expected = match kind {
                Kind::Query => is_named(&reference.elem, "Query") && !mutable,
                Kind::Command => is_named(&reference.elem, "Command") && mutable,
                Kind::Workflow => is_named(&reference.elem, "Workflow") && mutable,
                Kind::Attestable => false,
            };
            if !expected {
                return Err(Error::new(
                    typed.ty.span(),
                    match kind {
                        Kind::Query => "a `&self` handler takes `&Query<Self>`",
                        Kind::Command => "a `&mut self` handler takes `&mut Command<Self>`",
                        Kind::Attestable => "an #[attestable] method takes no context",
                        Kind::Workflow => "a #[workflow] takes `&mut Workflow<Self>`",
                    },
                ));
            }
            has_context = true;
            continue;
        }
        let Pat::Ident(pattern) = &*typed.pat else {
            return Err(Error::new(
                typed.pat.span(),
                "handler arguments are plain names",
            ));
        };
        arguments.push((pattern.ident.clone(), (*typed.ty).clone()));
    }
    let (reply, error) = reply_and_error(&method.sig.output);
    if kind == Kind::Attestable && error.is_some() {
        return Err(Error::new(
            method.sig.output.span(),
            "an #[attestable] method cannot fail: return its output",
        ));
    }
    let id = ids.take("vos/method/", &name, method.sig.ident.span())?;
    method
        .attrs
        .retain(|attribute| !attribute.path().is_ident("msg") && mark(attribute).is_none());
    Ok(Handler {
        method,
        name,
        id,
        kind,
        options,
        has_context,
        arguments,
        reply,
        error,
    })
}

pub(crate) fn messages_impl(mut input: ItemImpl, module: Option<String>) -> syn::Result<Tokens> {
    let actor = match &*input.self_ty {
        Type::Path(path) if path.qself.is_none() => path
            .path
            .segments
            .last()
            .map(|segment| segment.ident.clone())
            .ok_or_else(|| Error::new(input.self_ty.span(), "expected the actor's type"))?,
        other => return Err(Error::new(other.span(), "expected the actor's type")),
    };
    let module = format_ident!("{}", module.unwrap_or_else(|| snake(&actor.to_string())));

    let mut ids = Ids::new("method");
    let mut handlers = Vec::new();
    let mut has_new = false;
    let mut items = Vec::new();
    for item in input.items.drain(..) {
        let ImplItem::Fn(method) = item else {
            items.push(item);
            continue;
        };
        if method.sig.ident == "new" && method.sig.inputs.is_empty() {
            has_new = true;
        }
        let marker = method
            .attrs
            .iter()
            .find(|attribute| attribute.path().is_ident("msg") || mark(attribute).is_some())
            .cloned();
        match marker {
            Some(attribute) => {
                let kind = mark(&attribute);
                let handler = handler(method, &attribute, kind, &mut ids)?;
                items.push(ImplItem::Fn(handler.method.clone()));
                handlers.push(handler);
            }
            None => items.push(ImplItem::Fn(method)),
        }
    }
    input.items = items;
    if !has_new {
        return Err(Error::new(
            input.self_ty.span(),
            "#[messages] needs `fn new() -> Self`, the state of a new instance",
        ));
    }

    let mut types = Vec::new();
    let mut arms = Vec::new();
    let mut entries = Vec::new();
    let mut attestables = Vec::new();
    let mut schema = Schema {
        methods: Vec::new(),
    };
    for handler in &handlers {
        let message = format_ident!("{}", upper_camel(&handler.name));
        let id = handler.id;
        let reply = &handler.reply;
        let fields = handler
            .arguments
            .iter()
            .map(|(name, ty)| quote!(pub #name: #ty));
        schema.methods.push(MethodSchema {
            id: MethodId(id),
            name: handler.name.clone().into_bytes(),
            kind: handler.kind,
            role: handler.options.role.clone().map(String::into_bytes),
            gas: handler.options.gas,
            linearizable: handler.options.linearizable.is_some(),
        });
        types.push(quote! {
            #[derive(::vos_sdk::Encode, ::vos_sdk::Decode)]
            pub struct #message {
                #(#fields,)*
            }
        });
        let error = handler
            .error
            .clone()
            .unwrap_or_else(|| syn::parse_quote!(::vos_sdk::context::Never));
        match handler.kind {
            Kind::Attestable => {
                types.push(quote! {
                    impl ::vos_sdk::context::AttestableMethod for #message {
                        type Actor = super::#actor;
                        const ID: u32 = #id;
                        type Output = #reply;
                    }
                });
                let (entry, attestable) = attestable_entry(handler, &actor, &module, &message);
                entries.push(entry);
                attestables.push(attestable);
            }
            Kind::Workflow => {
                types.push(quote! {
                    impl ::vos_sdk::context::WorkflowMethod for #message {
                        type Actor = super::#actor;
                        const ID: u32 = #id;
                        type Output = #reply;
                        type Error = #error;
                    }
                });
                arms.push(workflow_arm(handler, &actor, &message));
            }
            Kind::Command | Kind::Query => {
                types.push(quote! {
                    impl ::vos_sdk::context::Method for #message {
                        type Actor = super::#actor;
                        const ID: u32 = #id;
                        type Reply = #reply;
                        type Error = #error;
                    }
                });
                if handler.kind == Kind::Query {
                    types.push(quote! {
                        impl ::vos_sdk::context::QueryMethod for #message {}
                    });
                }
                arms.push(handler_arm(handler, &actor, &message));
            }
        }
    }

    let schema = schema.section();
    let schema_len = schema.len();
    let attestable_count = attestables.len();
    let impl_block = &input;
    Ok(quote! {
        #impl_block

        impl #actor {
            #(#entries)*
        }

        impl ::vos_sdk::state::New for #actor {
            fn new() -> Self {
                #actor::new()
            }
        }

        /// Messages to this actor, one per handler.
        pub mod #module {
            use super::*;

            #(#types)*

            /// Run the handler or the workflow `method` names on the
            /// invocation's arguments: the body of the program's entry
            /// point.
            pub fn dispatch(method: u32) {
                match method {
                    #(#arms)*
                    _ => ::core::panic!("unknown method"),
                }
            }

            /// The schema's section bytes; `vos_sdk::actor_program!` places
            /// them in `.vos_schema`, first in the program's read-only data.
            pub const SCHEMA: [u8; #schema_len] = [#(#schema),*];

            /// Each attestable method's entry, which
            /// `vos_sdk::actor_program!` places in `.vos_attest`.
            pub const ATTESTABLES: [::vos_sdk::runtime::Attestable; #attestable_count] =
                [#(#attestables),*];
        }
    })
}

/// An attestable method's entry, `__vos_attest_<name>`, the root its
/// kernel is derived from, and the entry's row in the program's table.
fn attestable_entry(
    handler: &Handler,
    actor: &Ident,
    module: &Ident,
    message: &Ident,
) -> (Tokens, Tokens) {
    let method = &handler.method.sig.ident;
    let id = handler.id;
    let names = handler.names();
    let entry = format_ident!("__vos_attest_{}", handler.name);
    let function = quote! {
        /// Run this method on its encoded arguments, `len` bytes at
        /// `arguments`, leaving its encoded output where the result
        /// says: the root of its kernel, the program derived from
        /// what this entry reaches.
        ///
        /// # Safety
        ///
        /// `arguments` must point at `len` readable bytes.
        #[doc(hidden)]
        #[inline(never)]
        pub unsafe extern "C" fn #entry(
            arguments: *const u8,
            len: u64,
        ) -> ::vos_sdk::runtime::Output {
            // SAFETY: the caller's contract.
            let input = unsafe { ::core::slice::from_raw_parts(arguments, len as usize) };
            let ::core::result::Result::Ok((#module::#message { #(#names),* }, _)) =
                <#module::#message as ::vos_sdk::Decode>::decode(input)
            else {
                ::core::panic!("undecodable arguments")
            };
            ::vos_sdk::runtime::Output::leak(::vos_sdk::Encode::encode(&Self::#method(
                #(#names),*
            )))
        }
    };
    let row = quote! {
        ::vos_sdk::runtime::Attestable {
            method: #id as u64,
            entry: super::#actor::#entry,
        }
    };
    (function, row)
}

/// A workflow's arm of the dispatcher: its arguments decoded, its context
/// made when it takes one, and its outcome passed to the agent.
fn workflow_arm(handler: &Handler, actor: &Ident, message: &Ident) -> Tokens {
    let method = &handler.method.sig.ident;
    let id = handler.id;
    let names = handler.names();
    let (context, argument) = if handler.has_context {
        (
            quote!(let mut context = ::vos_sdk::context::Workflow::<super::#actor>::new();),
            quote!(&mut context,),
        )
    } else {
        (quote!(), quote!())
    };
    let outcome = outcome(
        handler,
        quote!(super::#actor::#method(#argument #(#names),*)),
        quote!(),
    );
    quote! {
        #id => {
            let #message { #(#names),* } = ::vos_sdk::runtime::arguments::<#message>();
            #context
            #outcome
        }
    }
}

/// A handler's arm of the dispatcher: its message decoded, its instance's
/// state loaded, its outcome passed to the agent, and a command's state
/// saved when it replies.
fn handler_arm(handler: &Handler, actor: &Ident, message: &Ident) -> Tokens {
    let method = &handler.method.sig.ident;
    let id = handler.id;
    let names = handler.names();
    let context = match (handler.kind, handler.has_context) {
        (Kind::Query, true) => quote!(&::vos_sdk::context::Query::new(),),
        (Kind::Command, true) => quote!(&mut ::vos_sdk::context::Command::new(),),
        _ => quote!(),
    };
    let (state, save) = if handler.kind == Kind::Command {
        (
            quote! {
                let mut state = ::vos_sdk::state::load::<super::#actor>();
                let before = ::vos_sdk::Encode::encode(&state);
            },
            quote!(::vos_sdk::state::save(&state, &before);),
        )
    } else {
        (
            quote!(let state = ::vos_sdk::state::load::<super::#actor>();),
            quote!(),
        )
    };
    let outcome = outcome(
        handler,
        quote!(state.#method(#context #(message.#names),*)),
        save,
    );
    quote! {
        #id => {
            let message = ::vos_sdk::runtime::arguments::<#message>();
            #state
            #outcome
        }
    }
}

/// The method's `call`, run to completion when it is `async`: its reply,
/// after `save`, or its error, passed to the agent. A method that cannot
/// fail always replies.
fn outcome(handler: &Handler, call: Tokens, save: Tokens) -> Tokens {
    let call = if handler.method.sig.asyncness.is_some() {
        quote!(::vos_sdk::runtime::block_on(#call))
    } else {
        call
    };
    let result = if handler.error.is_some() {
        call
    } else {
        quote!(::core::result::Result::<_, ::vos_sdk::context::Never>::Ok(#call))
    };
    quote! {
        match #result {
            ::core::result::Result::Ok(reply) => {
                #save
                ::vos_sdk::host::reply(&::vos_sdk::Encode::encode(&reply));
            }
            ::core::result::Result::Err(error) => {
                ::vos_sdk::host::fail(&::vos_sdk::Encode::encode(&error));
            }
        }
    }
}
