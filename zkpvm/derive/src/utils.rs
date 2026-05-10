use proc_macro_crate::FoundCrate;
use proc_macro2::{Span, TokenStream};
use quote::{ToTokens, format_ident, quote};

pub(crate) fn air_column_crate_include() -> TokenStream {
    match proc_macro_crate::crate_name("zkpvm") {
        Ok(FoundCrate::Itself) => quote! { crate },
        Ok(FoundCrate::Name(crate_name)) => format_ident!("{crate_name}").to_token_stream(),
        Err(e) => {
            let err = syn::Error::new(Span::call_site(), e).to_compile_error();
            quote!( #err )
        }
    }
}
