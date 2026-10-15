//! `#[actor]`: the state struct's encoding and its tables' tags.

use proc_macro2::TokenStream as Tokens;
use quote::quote;
use syn::spanned::Spanned;
use syn::{Attribute, Error, Fields, ItemStruct, Meta};

use crate::names::Ids;
use crate::{is_named, string_arg};

pub(crate) fn actor_impl(mut input: ItemStruct) -> syn::Result<Tokens> {
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
        if !(explicit || is_named(&field.ty, "Table") || is_named(&field.ty, "CommittedMap")) {
            continue;
        }
        let table_name = table_name.unwrap_or_else(|| ident.to_string());
        let tag = tags.take("vos/table/", &table_name, field.span())?;
        field.attrs.push(syn::parse_quote!(#[codec(skip)]));
        binds.push(quote! {
            self.#ident = ::vos_sdk::table::Bind::bound(::vos_sdk::table::Tag(#tag));
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
