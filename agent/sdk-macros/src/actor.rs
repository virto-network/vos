//! `#[actor]`: the state struct's encoding, its tables' tags, and the view
//! an attestable `&self` method reads: `<Actor>View`, its committed maps
//! alone, each a [`ServedMap`](vos_sdk::table::ServedMap) of the same keys,
//! values and transform, answering from the rows served at a window's cut.
//! Its plain fields and tables are not in it, so a method that reads one
//! does not compile.

use proc_macro2::TokenStream as Tokens;
use quote::{format_ident, quote};
use syn::spanned::Spanned;
use syn::{Attribute, Error, Fields, ItemStruct, Meta, PathArguments, Type};

use vos_wire::schema::ADMITTED;

use crate::names::Ids;
use crate::{is_named, string_arg};

/// What `#[actor(...)]` marks an actor as.
#[derive(Default)]
pub(crate) struct Marks {
    pub(crate) credentials: bool,
    pub(crate) known_keys: bool,
    pub(crate) onion_only: bool,
}

pub(crate) fn actor_impl(mut input: ItemStruct, marks: Marks) -> syn::Result<Tokens> {
    let Marks {
        credentials,
        known_keys,
        onion_only,
    } = marks;
    let name = input.ident.clone();
    let Fields::Named(fields) = &mut input.fields else {
        return Err(Error::new(
            input.ident.span(),
            "#[actor] needs a struct with named fields",
        ));
    };
    let mut tags = Ids::new("table");
    let mut binds = Vec::new();
    let mut views = Vec::new();
    let mut viewed = Vec::new();
    let mut admitted = false;
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
        if !(explicit || is_named(&field.ty, "Table") || is_named(&field.ty, "CommittedMap")) {
            continue;
        }
        let table_name = table_name.unwrap_or_else(|| ident.to_string());
        if known_keys && table_name == ADMITTED {
            if !admitted_table(&field.ty) {
                return Err(Error::new(
                    field.ty.span(),
                    "`known_keys` reads `admitted` as a `Table<[u8; 32], V>` of the default \
                     transform: ingress looks a key up by its 32 bytes",
                ));
            }
            admitted = true;
        }
        let tag = tags.take("vos/table/", &table_name, field.span())?;
        field.attrs.push(syn::parse_quote!(#[codec(skip)]));
        binds.push(quote! {
            self.#ident = ::vos_sdk::table::Bind::bound(::vos_sdk::table::Tag(#tag));
        });
        if is_named(&field.ty, "CommittedMap") {
            let vis = &field.vis;
            let ty = served_map(&field.ty);
            views.push(quote!(#vis #ident: #ty));
            viewed.push(quote! {
                #ident: ::vos_sdk::table::ServedMap::bound(::vos_sdk::table::Tag(#tag), served)
            });
        }
    }
    if known_keys && !admitted {
        return Err(Error::new(
            name.span(),
            "`known_keys` needs a table `admitted: Table<[u8; 32], V>`, whose rows ingress \
             reads as the admitted keys",
        ));
    }
    let vis = &input.vis;
    let view = format_ident!("{}View", name);
    let doc = format!(
        "The view of [`{name}`] an attestable `&self` method reads: its committed maps, \
         as served at a window's cut."
    );
    Ok(quote! {
        #[derive(::vos_sdk::Encode, ::vos_sdk::Decode)]
        #input

        impl ::vos_sdk::state::Marked for #name {
            const CREDENTIALS: bool = #credentials;
            const ADMISSION: ::vos_sdk::schema::Admission =
                ::vos_sdk::schema::Admission {
                    known_keys: #known_keys,
                    onion_only: #onion_only,
                };
        }

        impl ::vos_sdk::state::Tables for #name {
            fn bind_tables(&mut self) {
                #(#binds)*
            }
        }

        #[doc = #doc]
        #[allow(dead_code)]
        #vis struct #view {
            #(#views,)*
        }

        impl ::vos_sdk::state::View for #view {
            fn served(served: &'static ::vos_sdk::served::Served) -> Self {
                Self {
                    #(#viewed,)*
                }
            }
        }
    })
}

/// Whether `ty` is `Table<[u8; 32], V>`, of the default (hashed)
/// transform: the rows ingress reads for `known_keys`.
fn admitted_table(ty: &Type) -> bool {
    let Some(segment) = crate::last_segment(ty).filter(|segment| segment.ident == "Table") else {
        return false;
    };
    let PathArguments::AngleBracketed(arguments) = &segment.arguments else {
        return false;
    };
    let types: Vec<&Type> = arguments
        .args
        .iter()
        .filter_map(|argument| match argument {
            syn::GenericArgument::Type(ty) => Some(ty),
            _ => None,
        })
        .collect();
    let key = quote!([u8; 32]).to_string();
    match types.as_slice() {
        [first, _] => quote!(#first).to_string() == key,
        _ => false,
    }
}

/// A committed map's type as its view holds it: a `ServedMap` of the same
/// arguments.
fn served_map(ty: &Type) -> Type {
    let arguments = match ty {
        Type::Path(path) => path
            .path
            .segments
            .last()
            .map(|segment| segment.arguments.clone())
            .unwrap_or(PathArguments::None),
        _ => PathArguments::None,
    };
    syn::parse_quote!(::vos_sdk::table::ServedMap #arguments)
}
