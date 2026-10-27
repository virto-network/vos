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

use crate::names::Ids;
use crate::{is_named, string_arg};

pub(crate) fn actor_impl(mut input: ItemStruct, credentials: bool) -> syn::Result<Tokens> {
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
