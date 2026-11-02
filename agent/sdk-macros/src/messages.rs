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
use vos_wire::schema::{CredentialGuard, MAX_GUARD_NAME, MethodSchema, Schema};

use crate::names::{Ids, snake, upper_camel};
use crate::{is_named, last_segment, string_arg};

mod emit;
mod options;

use emit::*;
use options::*;

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
    /// Its auth guard's device kernel, by name, where the guard names one.
    guard_device: Option<(String, Span)>,
}

impl Handler {
    /// Its arguments' names.
    fn names(&self) -> Vec<&Ident> {
        self.arguments.iter().map(|(name, _)| name).collect()
    }
}

/// `T` for a device kernel's argument by reference, `&T`, which its entry
/// reads in place; `None` for an argument by value.
fn in_place(ty: &Type) -> Option<&Type> {
    match ty {
        Type::Reference(reference) => Some(&reference.elem),
        _ => None,
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

fn handler(
    mut method: ImplItemFn,
    attribute: &Attribute,
    marked: Option<Kind>,
    ids: &mut Ids,
) -> syn::Result<Handler> {
    let name = method.sig.ident.to_string();
    let mut options = msg_options(attribute)?;
    if marked == Some(Kind::Attestable)
        && (options.role.is_some() || options.linearizable.is_some())
    {
        return Err(Error::new(
            attribute.span(),
            "an #[attestable] method takes `gas = N`, `venue_bound` and `device` alone: it has \
             no caller",
        ));
    }
    if let (Some(span), Some(_)) = (options.device_kernel, options.venue_bound) {
        return Err(Error::new(
            span,
            "an #[attestable(device)] method is not `venue_bound`: no venue judges a device's \
             statement",
        ));
    }
    if let Some(span) = options.device_kernel
        && marked != Some(Kind::Attestable)
    {
        return Err(Error::new(
            span,
            "only an #[attestable] method is a device kernel: `device = \"...\"` names one \
             beside an auth guard",
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
            if let Some(span) = options.device_kernel {
                return Err(Error::new(
                    span,
                    "an #[attestable(device)] method takes no `self`: a device reads no root, \
                     and no node serves it rows",
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
    let guard_device = options.device.clone();
    guard(&mut options, kind)?;
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
        Kind::Attestable if options.device_kernel.is_some() => Kind::Device,
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
        guard_device,
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
                Kind::Attestable | Kind::Stating | Kind::Reading | Kind::Device => false,
            };
            if !expected {
                return Err(Error::new(
                    typed.ty.span(),
                    match kind {
                        Kind::Query => "a `&self` handler takes `&Query<Self>`",
                        Kind::Command => "a `&mut self` handler takes `&mut Command<Self>`",
                        Kind::Attestable | Kind::Stating | Kind::Reading | Kind::Device => {
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
        if let Type::Reference(reference) = &*typed.ty {
            if options.device_kernel.is_none() {
                return Err(Error::new(
                    typed.ty.span(),
                    "only an #[attestable(device)] method takes an argument by reference, read \
                     in place",
                ));
            }
            if reference.mutability.is_some() || reference.lifetime.is_some() {
                return Err(Error::new(
                    typed.ty.span(),
                    "a device kernel's argument by reference is `&T`, read in place for its run",
                ));
            }
            if arguments
                .iter()
                .any(|(_, ty): &(Ident, Type)| in_place(ty).is_none())
            {
                return Err(Error::new(
                    typed.ty.span(),
                    "a device kernel's arguments by reference come first, so each lies aligned \
                     where its witness input leaves it",
                ));
            }
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
    for (device, span) in handlers
        .iter()
        .filter_map(|handler| handler.guard_device.as_ref())
    {
        if !handlers
            .iter()
            .any(|handler| handler.name == *device && handler.kind == Kind::Device)
        {
            return Err(Error::new(
                *span,
                format!(
                    "`device = \"{device}\"` names no #[attestable(device)] method of this actor"
                ),
            ));
        }
    }

    let mut generated = Generated {
        types: Vec::new(),
        arms: Vec::new(),
        entries: Vec::new(),
        attestables: Vec::new(),
        schema: Schema {
            methods: Vec::new(),
            // The actor's mark, which `#[actor]` gives: both sections are
            // made, and it picks one.
            credentials: false,
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

    let marked = Schema {
        credentials: true,
        ..schema.clone()
    }
    .section();
    let plain = schema.section();
    let (plain_len, marked_len) = (plain.len(), marked.len());
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

            const SCHEMA_PLAIN: [u8; #plain_len] = [#(#plain),*];
            const SCHEMA_MARKED: [u8; #marked_len] = [#(#marked),*];
            const CREDENTIALS: bool = <super::#actor as ::vos_sdk::state::Marked>::CREDENTIALS;
            const SCHEMA_LEN: usize = if CREDENTIALS { #marked_len } else { #plain_len };

            /// The schema's section bytes; `vos_sdk::actor_program!` places
            /// them in `.vos_schema`, first in the program's read-only data.
            /// The actor's `#[actor(credentials)]` mark picks which.
            pub const SCHEMA: [u8; SCHEMA_LEN] =
                ::vos_sdk::runtime::schema_section(&SCHEMA_PLAIN, &SCHEMA_MARKED, CREDENTIALS);

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
        let fields = venue
            .into_iter()
            .chain(handler.arguments.iter().map(|(name, ty)| {
                let ty = in_place(ty).unwrap_or(ty);
                quote!(pub #name: #ty)
            }));
        self.schema.methods.push(MethodSchema {
            id: MethodId(id),
            name: handler.name.clone().into_bytes(),
            kind: handler.kind,
            role: handler.options.role.clone().map(String::into_bytes),
            gas: handler.options.gas,
            linearizable: handler.options.linearizable.is_some(),
            credential: handler
                .options
                .credential
                .as_ref()
                .map(|(guard, _)| Box::new(guard.clone())),
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
            Kind::Device => {
                // No `AttestableMethod`: no node attests a device kernel's
                // method, so a workflow's attest of one does not compile.
                let (entry, attestable) = attestable_entry(handler, actor, view, module, &message);
                self.entries.push(entry);
                self.attestables.push(attestable);
            }
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
