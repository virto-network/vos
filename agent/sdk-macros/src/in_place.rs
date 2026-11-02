//! `#[derive(InPlace)]`: a `#[repr(C)]` struct of in-place fields, read in
//! place and encoded as its bytes.

use proc_macro2::TokenStream as Tokens;
use quote::quote;
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::{Data, DeriveInput, Error, Fields, Meta, Token};

pub(crate) fn in_place_impl(input: DeriveInput) -> syn::Result<Tokens> {
    let name = &input.ident;
    if !input.generics.params.is_empty() {
        return Err(Error::new(
            input.generics.span(),
            "an in-place struct takes no generics",
        ));
    }
    let repr_c = input.attrs.iter().any(|attribute| {
        attribute.path().is_ident("repr")
            && attribute
                .parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
                .is_ok_and(|reprs| reprs.iter().any(|repr| repr.path().is_ident("C")))
    });
    if !repr_c {
        return Err(Error::new(
            name.span(),
            "an in-place struct is `#[repr(C)]`: its layout is its encoding",
        ));
    }
    let Data::Struct(data) = &input.data else {
        return Err(Error::new(name.span(), "only a struct is in place"));
    };
    let types: Vec<_> = match &data.fields {
        Fields::Named(fields) => fields.named.iter().map(|field| &field.ty).collect(),
        Fields::Unnamed(fields) => fields.unnamed.iter().map(|field| &field.ty).collect(),
        Fields::Unit => Vec::new(),
    };
    Ok(quote! {
        // SAFETY: `#[repr(C)]` of in-place fields, which the bounds below
        // check, no padding and an alignment of at most eight, which the
        // assertions check: every bit pattern is a value. Its encoding,
        // below, is its bytes.
        unsafe impl ::vos_sdk::p2::InPlace for #name
        where
            #(#types: ::vos_sdk::p2::InPlace,)*
        {
        }

        const _: () = ::core::assert!(
            ::core::mem::size_of::<#name>() == 0 #(+ ::core::mem::size_of::<#types>())*,
            "an in-place struct holds no padding"
        );

        const _: () = ::core::assert!(
            ::core::mem::align_of::<#name>() <= 8,
            "an in-place struct is aligned to eight bytes at most"
        );

        impl ::vos_sdk::Encode for #name {
            #[inline(always)]
            fn encode_to(&self, buf: &mut ::vos_sdk::Vec<u8>) {
                ::vos_sdk::p2::encode_in_place(self, buf)
            }
        }

        impl ::vos_sdk::Decode for #name {
            #[inline]
            fn decode(
                data: &[u8],
            ) -> ::core::result::Result<(Self, usize), ::vos_sdk::scale::DecodeError> {
                ::vos_sdk::p2::decode_in_place(data)
            }
        }
    })
}
