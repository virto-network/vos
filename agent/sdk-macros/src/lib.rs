//! The VOS actor SDK's macros.
//!
//! - `#[actor]` on the state struct: its encoding, which skips `Table`
//!   fields, and each table's tag.
//! - `#[messages]` on the impl block: a message type per handler, the
//!   dispatcher, the program's entry point and its schema.

use std::collections::BTreeMap;

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as Tokens};
use quote::{format_ident, quote};
use syn::spanned::Spanned;
use syn::{
    Attribute, Error, Expr, ExprLit, Fields, FnArg, ImplItem, ImplItemFn, ItemImpl, ItemStruct,
    Lit, LitStr, Meta, Pat, PathArguments, ReturnType, Type, parse_macro_input,
};
use vos_wire::abi::Kind;
use vos_wire::ids::MethodId;
use vos_wire::schema::{MethodSchema, Schema};

/// The first four bytes, big-endian, of BLAKE2b-256 over `domain` and
/// `name`.
fn derive_id(domain: &str, name: &str) -> u32 {
    let hash = Blake2b::<U32>::new()
        .chain_update(domain.as_bytes())
        .chain_update(name.as_bytes())
        .finalize();
    u32::from_be_bytes(hash[..4].try_into().expect("four bytes"))
}

/// Track derived ids: 0 is reserved and two names must not share one.
struct Ids {
    what: &'static str,
    seen: BTreeMap<u32, String>,
}

impl Ids {
    fn new(what: &'static str) -> Self {
        Self {
            what,
            seen: BTreeMap::new(),
        }
    }

    fn take(&mut self, domain: &str, name: &str, span: Span) -> syn::Result<u32> {
        let id = derive_id(domain, name);
        if id == 0 {
            return Err(Error::new(
                span,
                format!(
                    "{} `{name}` derives the reserved id 0; name it explicitly",
                    self.what
                ),
            ));
        }
        if let Some(other) = self.seen.insert(id, name.to_owned()) {
            return Err(Error::new(
                span,
                format!(
                    "{} `{name}` derives the same id as `{other}`; name one explicitly",
                    self.what
                ),
            ));
        }
        Ok(id)
    }
}

fn last_segment(ty: &Type) -> Option<&syn::PathSegment> {
    match ty {
        Type::Path(path) => path.path.segments.last(),
        _ => None,
    }
}

fn is_named(ty: &Type, name: &str) -> bool {
    last_segment(ty).is_some_and(|segment| segment.ident == name)
}

/// The string value of `name = "..."` inside an attribute's arguments.
fn string_arg(meta: &syn::meta::ParseNestedMeta) -> syn::Result<String> {
    Ok(meta.value()?.parse::<LitStr>()?.value())
}

// ===== #[actor] =====

/// The actor's state: a struct whose encoding is stored under the instance,
/// and whose `Table` fields are handles to rows stored beside it.
///
/// A table's tag derives from its field's name, or from
/// `#[table(name = "...")]`, which keeps rows reachable when the field is
/// renamed.
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

fn actor_impl(mut input: ItemStruct) -> syn::Result<Tokens> {
    let name = input.ident.clone();
    let Fields::Named(fields) = &mut input.fields else {
        return Err(Error::new(
            input.ident.span(),
            "#[actor] needs a struct with named fields",
        ));
    };
    let mut tags = Ids::new("table");
    let mut binds = Vec::new();
    for field in &mut fields.named {
        let ident = field.ident.clone().expect("named field");
        let mut table_name = None;
        let mut explicit = false;
        let mut kept: Vec<Attribute> = Vec::new();
        for attribute in field.attrs.drain(..) {
            if attribute.path().is_ident("table") {
                explicit = true;
                if let Meta::List(_) = attribute.meta {
                    attribute.parse_nested_meta(|meta| {
                        if meta.path.is_ident("name") {
                            table_name = Some(string_arg(&meta)?);
                            Ok(())
                        } else {
                            Err(meta.error("expected `name = \"...\"`"))
                        }
                    })?;
                }
            } else {
                kept.push(attribute);
            }
        }
        field.attrs = kept;
        if !(explicit || is_named(&field.ty, "Table")) {
            continue;
        }
        let table_name = table_name.unwrap_or_else(|| ident.to_string());
        let tag = tags.take("vos/table/", &table_name, field.span())?;
        field.attrs.push(syn::parse_quote!(#[codec(skip)]));
        binds.push(quote! {
            self.#ident = ::vos_sdk::table::Table::new(::vos_sdk::table::Tag(#tag));
        });
    }
    Ok(quote! {
        #[derive(::vos_sdk::Encode, ::vos_sdk::Decode)]
        #input

        impl ::vos_sdk::state::Tables for #name {
            fn bind_tables(&mut self) {
                #(#binds)*
            }
        }
    })
}

// ===== #[messages] =====

struct Handler {
    method: ImplItemFn,
    name: String,
    id: u32,
    kind: Kind,
    role: Option<String>,
    gas: Option<u64>,
    has_context: bool,
    arguments: Vec<(syn::Ident, Type)>,
    reply: Type,
    error: Option<Type>,
}

fn upper_camel(name: &str) -> String {
    name.split('_')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            let first = chars.next().expect("non-empty").to_ascii_uppercase();
            core::iter::once(first).chain(chars).collect::<String>()
        })
        .collect()
}

/// `Ledger` → `ledger`, `HttpServer` and `HTTPServer` → `http_server`.
fn snake(name: &str) -> String {
    let chars: Vec<char> = name.chars().collect();
    let mut out = String::new();
    for (index, &c) in chars.iter().enumerate() {
        if c.is_ascii_uppercase() && index > 0 {
            let previous = chars[index - 1];
            let next_lower = chars.get(index + 1).is_some_and(char::is_ascii_lowercase);
            if previous.is_ascii_lowercase()
                || previous.is_ascii_digit()
                || (previous.is_ascii_uppercase() && next_lower)
            {
                out.push('_');
            }
        }
        out.push(c.to_ascii_lowercase());
    }
    out
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

/// The handler's options from `#[msg(role = "...", gas = N)]`.
fn msg_options(attribute: &Attribute) -> syn::Result<(Option<String>, Option<u64>)> {
    let (mut role, mut gas) = (None, None);
    if let Meta::List(_) = attribute.meta {
        attribute.parse_nested_meta(|meta| {
            if meta.path.is_ident("role") {
                role = Some(string_arg(&meta)?);
            } else if meta.path.is_ident("gas") {
                let Expr::Lit(ExprLit {
                    lit: Lit::Int(value),
                    ..
                }) = meta.value()?.parse::<Expr>()?
                else {
                    return Err(meta.error("expected an integer gas limit"));
                };
                gas = Some(value.base10_parse()?);
            } else {
                return Err(meta.error("expected `role = \"...\"` or `gas = N`"));
            }
            Ok(())
        })?;
    }
    Ok((role, gas))
}

fn handler(
    mut method: ImplItemFn,
    attribute: &Attribute,
    attestable: bool,
    ids: &mut Ids,
) -> syn::Result<Handler> {
    let name = method.sig.ident.to_string();
    let (role, gas) = if attestable {
        (None, None)
    } else {
        msg_options(attribute)?
    };
    let mut inputs = method.sig.inputs.iter();
    let kind = if attestable {
        if let Some(FnArg::Receiver(receiver)) = method.sig.inputs.first() {
            return Err(Error::new(
                receiver.span(),
                "an #[attestable] method takes no `self`: it sees only its arguments",
            ));
        }
        Kind::Attestable
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
    let mut has_context = false;
    let mut arguments = Vec::new();
    for (index, input) in inputs.enumerate() {
        let FnArg::Typed(typed) = input else {
            unreachable!("only the first input can be a receiver");
        };
        if index == 0
            && let Type::Reference(reference) = &*typed.ty
            && (is_named(&reference.elem, "Query") || is_named(&reference.elem, "Command"))
        {
            let expected = match kind {
                Kind::Query => is_named(&reference.elem, "Query") && reference.mutability.is_none(),
                Kind::Command => {
                    is_named(&reference.elem, "Command") && reference.mutability.is_some()
                }
                Kind::Attestable => false,
            };
            if !expected {
                return Err(Error::new(
                    typed.ty.span(),
                    match kind {
                        Kind::Query => "a `&self` handler takes `&Query<Self>`",
                        Kind::Command => "a `&mut self` handler takes `&mut Command<Self>`",
                        Kind::Attestable => "an #[attestable] method takes no context",
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
    if attestable && error.is_some() {
        return Err(Error::new(
            method.sig.output.span(),
            "an #[attestable] method cannot fail: return its output",
        ));
    }
    let id = ids.take("vos/method/", &name, method.sig.ident.span())?;
    method.attrs.retain(|attribute| {
        !attribute.path().is_ident("msg") && !attribute.path().is_ident("attestable")
    });
    Ok(Handler {
        method,
        name,
        id,
        kind,
        role,
        gas,
        has_context,
        arguments,
        reply,
        error,
    })
}

/// The handlers of an actor. Each `#[msg]` method becomes a message type in
/// a module named after the actor in snake case, or as
/// `#[messages(module = "...")]` names it, with the handler's arguments as
/// fields; `#[attestable]` methods likewise, run as their own programs. The
/// module imports its parent's names, so argument types resolve as they do
/// beside the impl; a message type shadows a parent type of the same name,
/// so a handler must not be named after an argument type (a `balance`
/// handler beside a `Balance` argument). The impl block must define
/// `fn new() -> Self`, the state of a new instance.
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

fn messages_impl(mut input: ItemImpl, module: Option<String>) -> syn::Result<Tokens> {
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
            .find(|attribute| {
                attribute.path().is_ident("msg") || attribute.path().is_ident("attestable")
            })
            .cloned();
        match marker {
            Some(attribute) => {
                let attestable = attribute.path().is_ident("attestable");
                let handler = handler(method, &attribute, attestable, &mut ids)?;
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
    let mut attest_fns = Vec::new();
    let mut schema = Schema {
        methods: Vec::new(),
    };
    for handler in &handlers {
        let message = format_ident!("{}", upper_camel(&handler.name));
        let method = &handler.method.sig.ident;
        let id = handler.id;
        let reply = &handler.reply;
        let fields = handler
            .arguments
            .iter()
            .map(|(name, ty)| quote!(pub #name: #ty));
        let names: Vec<_> = handler.arguments.iter().map(|(name, _)| name).collect();
        schema.methods.push(MethodSchema {
            id: MethodId(id),
            name: handler.name.clone().into_bytes(),
            kind: handler.kind,
            role: handler.role.clone().map(String::into_bytes),
            gas: handler.gas,
        });
        types.push(quote! {
            #[derive(::vos_sdk::Encode, ::vos_sdk::Decode)]
            pub struct #message {
                #(#fields,)*
            }
        });
        if handler.kind == Kind::Attestable {
            types.push(quote! {
                impl ::vos_sdk::context::AttestableMethod for #message {
                    type Actor = super::#actor;
                    const ID: u32 = #id;
                    type Output = #reply;
                }
            });
            let entry = format_ident!("__vos_attest_{}", handler.name);
            attest_fns.push(quote! {
                /// Run this attestable method on encoded arguments; the
                /// entry of its own program.
                #[doc(hidden)]
                pub fn #entry(input: &[u8]) -> ::vos_sdk::Vec<u8> {
                    let ::core::result::Result::Ok((#module::#message { #(#names),* }, _)) =
                        <#module::#message as ::vos_sdk::Decode>::decode(input)
                    else {
                        ::core::panic!("undecodable arguments")
                    };
                    ::vos_sdk::Encode::encode(&Self::#method(#(#names),*))
                }
            });
            continue;
        }
        let error = handler
            .error
            .clone()
            .unwrap_or_else(|| syn::parse_quote!(::vos_sdk::context::Never));
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
        let context = match (handler.kind, handler.has_context) {
            (Kind::Query, true) => quote!(&::vos_sdk::context::Query::new(),),
            (Kind::Command, true) => quote!(&mut ::vos_sdk::context::Command::new(),),
            _ => quote!(),
        };
        let call = quote!(state.#method(#context #(message.#names),*));
        let call = if handler.method.sig.asyncness.is_some() {
            quote!(::vos_sdk::runtime::block_on(#call))
        } else {
            call
        };
        let outcome = if handler.error.is_some() {
            quote!(#call)
        } else {
            quote!(::core::result::Result::<_, ::vos_sdk::context::Never>::Ok(#call))
        };
        let state = if handler.kind == Kind::Command {
            quote!(let mut state = ::vos_sdk::state::load::<super::#actor>();)
        } else {
            quote!(let state = ::vos_sdk::state::load::<super::#actor>();)
        };
        let (before, save) = if handler.kind == Kind::Command {
            (
                quote!(let before = ::vos_sdk::Encode::encode(&state);),
                quote!(::vos_sdk::state::save(&state, &before);),
            )
        } else {
            (quote!(), quote!())
        };
        arms.push(quote! {
            #id => {
                let message = ::vos_sdk::runtime::arguments::<#message>();
                #state
                #before
                match #outcome {
                    ::core::result::Result::Ok(reply) => {
                        #save
                        ::vos_sdk::host::reply(&::vos_sdk::Encode::encode(&reply));
                    }
                    ::core::result::Result::Err(error) => {
                        ::vos_sdk::host::fail(&::vos_sdk::Encode::encode(&error));
                    }
                }
            }
        });
    }

    let schema = schema.section();
    let schema_len = schema.len();
    let impl_block = &input;
    Ok(quote! {
        #impl_block

        impl #actor {
            #(#attest_fns)*
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

            /// Run the handler `method` names on the invocation's
            /// arguments: the body of the program's entry point.
            pub fn dispatch(method: u32) {
                match method {
                    #(#arms)*
                    _ => ::core::panic!("unknown method"),
                }
            }

            /// The schema's section bytes; `vos_sdk::actor_program!` places
            /// them first in the program's read-only data.
            pub const SCHEMA: [u8; #schema_len] = [#(#schema),*];
        }
    })
}

#[cfg(test)]
mod tests {
    use super::snake;

    #[test]
    fn snake_case_keeps_acronyms_together() {
        assert_eq!(snake("Ledger"), "ledger");
        assert_eq!(snake("HttpServer"), "http_server");
        assert_eq!(snake("HTTPServer"), "http_server");
        assert_eq!(snake("Erc20Token"), "erc20_token");
    }
}
