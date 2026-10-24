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
    /// Which arguments are `#[public]`, by their position.
    public: Vec<bool>,
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

/// A handler's options, from `#[msg(role = "...", gas = N, linearizable)]`,
/// or an attestable method's, from `#[attestable(gas = N, venue_bound)]`.
#[derive(Default)]
struct Options {
    role: Option<String>,
    gas: Option<u64>,
    /// A query that always reads after a read index.
    linearizable: Option<Span>,
    /// An attestable method whose statements bind the venue that judges
    /// them: a leading `venue: VenueId` public argument.
    venue_bound: Option<Span>,
}

fn msg_options(attribute: &Attribute) -> syn::Result<Options> {
    let mut options = Options::default();
    if let Meta::List(_) = attribute.meta {
        attribute.parse_nested_meta(|meta| {
            if meta.path.is_ident("role") {
                options.role = Some(string_arg(&meta)?);
            } else if meta.path.is_ident("linearizable") {
                options.linearizable = Some(meta.path.span());
            } else if meta.path.is_ident("venue_bound") {
                options.venue_bound = Some(meta.path.span());
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
                return Err(meta.error(
                    "expected `role = \"...\"`, `gas = N`, `linearizable` or `venue_bound`",
                ));
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
            "an #[attestable] method takes `gas = N` and `venue_bound` alone: it has no caller",
        ));
    }
    if let Some(span) = options.venue_bound
        && marked != Some(Kind::Attestable)
    {
        return Err(Error::new(
            span,
            "only an #[attestable] method is `venue_bound`: its statements bind a venue",
        ));
    }
    let mut inputs = method.sig.inputs.iter();
    let mut reads = false;
    let kind = if let Some(kind) = marked {
        if let Some(FnArg::Receiver(receiver)) = method.sig.inputs.first() {
            if kind == Kind::Workflow {
                return Err(Error::new(
                    receiver.span(),
                    "a #[workflow] takes no `self`: it holds only its own memory",
                ));
            }
            if receiver.reference.is_none() || receiver.mutability.is_some() {
                return Err(Error::new(
                    receiver.span(),
                    "an #[attestable] method takes `&self` at most: it reads its instance's \
                     committed rows at a window's cut, and writes nothing",
                ));
            }
            reads = true;
            inputs.next();
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
    let Arguments {
        has_context,
        arguments,
        public,
    } = arguments(inputs, kind, &options)?;
    let (reply, error) = reply_and_error(&method.sig.output);
    if kind == Kind::Attestable && error.is_some() {
        return Err(Error::new(
            method.sig.output.span(),
            "an #[attestable] method cannot fail: return its output",
        ));
    }
    // An attestable method's kind says what its kernel returns, and whether
    // it reads at a window's cut.
    let kind = match kind {
        Kind::Attestable if reads => Kind::Reading,
        Kind::Attestable if options.venue_bound.is_some() || public.contains(&true) => {
            Kind::Stating
        }
        kind => kind,
    };
    let id = ids.take("vos/method/", &name, method.sig.ident.span())?;
    method
        .attrs
        .retain(|attribute| !attribute.path().is_ident("msg") && mark(attribute).is_none());
    for input in &mut method.sig.inputs {
        if let FnArg::Typed(typed) = input {
            typed
                .attrs
                .retain(|attribute| !attribute.path().is_ident("public"));
        }
    }
    Ok(Handler {
        method,
        name,
        id,
        kind,
        options,
        has_context,
        arguments,
        public,
        reply,
        error,
    })
}

/// A handler's arguments after its receiver, as [`handler`] reads them.
struct Arguments {
    /// Whether the first is its context.
    has_context: bool,
    arguments: Vec<(Ident, Type)>,
    /// Which arguments are `#[public]`, by their position.
    public: Vec<bool>,
}

/// The arguments `inputs` of a handler of `kind` (an attestable method's
/// before its kind is refined) with `options`: its context, if it takes
/// one, then its plain-named arguments.
fn arguments<'a>(
    inputs: impl Iterator<Item = &'a FnArg>,
    kind: Kind,
    options: &Options,
) -> syn::Result<Arguments> {
    let mut has_context = false;
    let mut arguments = Vec::new();
    let mut public = Vec::new();
    for (index, input) in inputs.enumerate() {
        let FnArg::Typed(typed) = input else {
            unreachable!("only the first input can be a receiver");
        };
        let marked_public = typed
            .attrs
            .iter()
            .find(|attribute| attribute.path().is_ident("public"));
        if let Some(attribute) = marked_public
            && kind != Kind::Attestable
        {
            return Err(Error::new(
                attribute.span(),
                "only an #[attestable] method's arguments are `#[public]`",
            ));
        }
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
                Kind::Attestable | Kind::Stating | Kind::Reading => false,
            };
            if !expected {
                return Err(Error::new(
                    typed.ty.span(),
                    match kind {
                        Kind::Query => "a `&self` handler takes `&Query<Self>`",
                        Kind::Command => "a `&mut self` handler takes `&mut Command<Self>`",
                        Kind::Attestable | Kind::Stating | Kind::Reading => {
                            "an #[attestable] method takes no context"
                        }
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
        if options.venue_bound.is_some() && pattern.ident == "venue" {
            return Err(Error::new(
                pattern.ident.span(),
                "a `venue_bound` method's leading argument is `venue`: name this one otherwise",
            ));
        }
        arguments.push((pattern.ident.clone(), (*typed.ty).clone()));
        public.push(marked_public.is_some());
    }
    Ok(Arguments {
        has_context,
        arguments,
        public,
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

    let view = format_ident!("{}View", actor);
    let mut ids = Ids::new("method");
    let mut handlers = Vec::new();
    let mut has_new = false;
    let mut items = Vec::new();
    // The attestable `&self` methods, which read through the actor's view.
    let mut viewed = Vec::new();
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
                if handler.kind == Kind::Reading {
                    viewed.push(handler.method.clone());
                } else {
                    items.push(ImplItem::Fn(handler.method.clone()));
                }
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

    let mut generated = Generated {
        types: Vec::new(),
        arms: Vec::new(),
        entries: Vec::new(),
        attestables: Vec::new(),
        schema: Schema {
            methods: Vec::new(),
        },
    };
    for handler in &handlers {
        generated.add(handler, &actor, &view, &module);
    }
    let Generated {
        types,
        arms,
        entries,
        attestables,
        schema,
    } = generated;

    let schema = schema.section();
    let schema_len = schema.len();
    let attestable_count = attestables.len();
    let impl_block = &input;
    let viewed = (!viewed.is_empty()).then(|| {
        quote! {
            impl #view {
                #(#viewed)*
            }
        }
    });
    Ok(quote! {
        #impl_block

        #viewed

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

/// The code `#[messages]` makes of its handlers, in their order.
struct Generated {
    /// The message types and their impls.
    types: Vec<Tokens>,
    /// The dispatcher's arms.
    arms: Vec<Tokens>,
    /// The attestable methods' entries, and their rows in the table.
    entries: Vec<Tokens>,
    attestables: Vec<Tokens>,
    schema: Schema,
}

impl Generated {
    /// `handler`'s message type, its schema entry, and its dispatcher arm
    /// or its attestable entry.
    fn add(&mut self, handler: &Handler, actor: &Ident, view: &Ident, module: &Ident) {
        let message = format_ident!("{}", upper_camel(&handler.name));
        let id = handler.id;
        let reply = &handler.reply;
        let venue = handler
            .options
            .venue_bound
            .map(|_| quote!(pub venue: ::vos_sdk::VenueId));
        let fields = venue.into_iter().chain(
            handler
                .arguments
                .iter()
                .map(|(name, ty)| quote!(pub #name: #ty)),
        );
        self.schema.methods.push(MethodSchema {
            id: MethodId(id),
            name: handler.name.clone().into_bytes(),
            kind: handler.kind,
            role: handler.options.role.clone().map(String::into_bytes),
            gas: handler.options.gas,
            linearizable: handler.options.linearizable.is_some(),
        });
        self.types.push(quote! {
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
            Kind::Attestable | Kind::Stating | Kind::Reading => {
                let method = if handler.kind == Kind::Reading {
                    quote!(AtCutMethod)
                } else {
                    quote!(AttestableMethod)
                };
                self.types.push(quote! {
                    impl ::vos_sdk::context::#method for #message {
                        type Actor = super::#actor;
                        const ID: u32 = #id;
                        type Output = #reply;
                    }
                });
                let (entry, attestable) = attestable_entry(handler, actor, view, module, &message);
                self.entries.push(entry);
                self.attestables.push(attestable);
            }
            Kind::Workflow => {
                self.types.push(quote! {
                    impl ::vos_sdk::context::WorkflowMethod for #message {
                        type Actor = super::#actor;
                        const ID: u32 = #id;
                        type Output = #reply;
                        type Error = #error;
                    }
                });
                self.arms.push(workflow_arm(handler, actor, &message));
            }
            Kind::Command | Kind::Query => {
                self.types.push(quote! {
                    impl ::vos_sdk::context::Method for #message {
                        type Actor = super::#actor;
                        const ID: u32 = #id;
                        type Reply = #reply;
                        type Error = #error;
                    }
                });
                if handler.kind == Kind::Query {
                    self.types.push(quote! {
                        impl ::vos_sdk::context::QueryMethod for #message {}
                    });
                }
                self.arms.push(handler_arm(handler, actor, &message));
            }
        }
    }
}

/// An attestable method's entry, `__vos_attest_<name>`, the root its
/// kernel is derived from, and the entry's row in the program's table.
///
/// A method that states no part beside its output, no venue, reader or
/// `#[public]` argument, returns its output alone. Any other returns its
/// statement's parts: the public arguments, the encodings of the venue, of
/// the reader `(AgentId, InstanceId)` and of each `#[public]` argument in
/// order; its output; and the roots it read. A `&self` method reads, after
/// its arguments, the rows served at a window's cut, which its prologue
/// checks against the space's root before the method runs on its view;
/// its row in the table marks it so, and its kernel reads that much more.
fn attestable_entry(
    handler: &Handler,
    actor: &Ident,
    view: &Ident,
    module: &Ident,
    message: &Ident,
) -> (Tokens, Tokens) {
    let method = &handler.method.sig.ident;
    let id = handler.id;
    let names = handler.names();
    let entry = format_ident!("__vos_attest_{}", handler.name);
    let body = if handler.kind != Kind::Attestable {
        parts_body(handler, view, module, message)
    } else {
        quote! {
            let ::core::result::Result::Ok((#module::#message { #(#names),* }, _)) =
                <#module::#message as ::vos_sdk::Decode>::decode(input)
            else {
                ::core::panic!("undecodable arguments")
            };
            let output = ::vos_sdk::Encode::encode(&Self::#method(#(#names),*));
            // SAFETY: the caller's contract.
            unsafe { ::vos_sdk::runtime::attested_output(output, io_hash) }
        }
    };
    let function = quote! {
        /// Run this method on its encoded arguments, `len` bytes at
        /// `arguments`, leaving its encoded output where the result
        /// says and its io-hash at `io_hash`: the root of its kernel,
        /// the program derived from what this entry reaches.
        ///
        /// # Safety
        ///
        /// `arguments` must point at `len` readable bytes, and `io_hash`
        /// at 32 writable ones.
        #[doc(hidden)]
        #[inline(never)]
        pub unsafe extern "C" fn #entry(
            arguments: *const u8,
            len: u64,
            io_hash: *mut [u8; 32],
        ) -> ::vos_sdk::runtime::Output {
            // SAFETY: the caller's contract.
            let input = unsafe { ::core::slice::from_raw_parts(arguments, len as usize) };
            #body
        }
    };
    let word = if handler.kind == Kind::Reading {
        quote!(#id as u64 | ::vos_sdk::runtime::READS_SERVED)
    } else {
        quote!(#id as u64)
    };
    let row = quote! {
        ::vos_sdk::runtime::Attestable {
            method: #word,
            entry: super::#actor::#entry,
        }
    };
    (function, row)
}

/// An attestable entry's body when its method states parts beside its
/// output: a venue, the reader or a `#[public]` argument.
fn parts_body(handler: &Handler, view: &Ident, module: &Ident, message: &Ident) -> Tokens {
    let method = &handler.method.sig.ident;
    let names = handler.names();
    let venue = handler.options.venue_bound.map(|_| quote!(venue,));
    let bound = handler
        .options
        .venue_bound
        .map(|_| quote!(::vos_sdk::Encode::encode_to(&venue, &mut public_args);));
    let publics = handler
        .arguments
        .iter()
        .zip(&handler.public)
        .filter(|(_, public)| **public)
        .map(|((name, _), _)| quote!(::vos_sdk::Encode::encode_to(&#name, &mut public_args);));
    let (served, reader, call, roots) = if handler.kind == Kind::Reading {
        (
            quote! {
                let served = ::vos_sdk::runtime::served(&input[used..]);
                let root = ::vos_sdk::runtime::verify_served(served);
                let view = <#view as ::vos_sdk::state::View>::served(served);
            },
            quote!(::vos_sdk::Encode::encode_to(&(served.agent, served.instance), &mut public_args);),
            quote!(view.#method(#(#names),*)),
            quote!(::vos_sdk::Vec::from([root])),
        )
    } else {
        (
            quote!(let _ = used;),
            quote!(),
            quote!(Self::#method(#(#names),*)),
            quote!(::vos_sdk::Vec::new()),
        )
    };
    quote! {
        let ::core::result::Result::Ok((#module::#message { #venue #(#names),* }, used)) =
            <#module::#message as ::vos_sdk::Decode>::decode(input)
        else {
            ::core::panic!("undecodable arguments")
        };
        #served
        let mut public_args = ::vos_sdk::Vec::new();
        #bound
        #reader
        #(#publics)*
        let output = ::vos_sdk::Encode::encode(&#call);
        // SAFETY: the caller's contract.
        unsafe { ::vos_sdk::runtime::attested(public_args, output, #roots, io_hash) }
    }
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
            ::vos_sdk::heap::whole_arena();
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
