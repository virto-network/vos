use std::num::NonZeroU8;

use convert_case::{Case, Casing};
use proc_macro2::{Span, TokenStream};
use quote::{format_ident, quote};

use super::utils::air_column_crate_include;

const SIZE_FN_IDENT: &str = "const_size";
const OFFSET_FN_IDENT: &str = "const_offset";

struct ParsedVariant {
    ident: syn::Ident,
    size: usize,
    mask_next_row: bool,
}

pub fn generate_impl(input: TokenStream, preprocessed: bool) -> syn::Result<TokenStream> {
    let input: syn::ItemEnum = syn::parse2(input)?;
    sanitize_attrs(&input)?;
    let enum_ident = &input.ident;

    let variants = collect_variants(&input)?;

    let all_variants = all_variants_impl(&variants);
    let const_size_impl = const_size_impl(&variants);
    let (offset, const_offset_impl) = const_offset_impl(&variants);
    let mask_next_row_impl = mask_next_row_impl(&variants);

    let crate_ident: TokenStream = air_column_crate_include();
    let preprocessed_impl = if preprocessed {
        preprocessed_impl(&input, &variants, &crate_ident, enum_ident)?
    } else {
        TokenStream::new()
    };
    let row_impl = match string_attr(&input, "row")? {
        Some(row) if !preprocessed => row_impl(&variants, &crate_ident, enum_ident, &row),
        Some(_) => {
            return Err(syn::Error::new(
                Span::call_site(),
                "a row view is only derived for main-trace columns",
            ));
        }
        None => TokenStream::new(),
    };

    let size_fn_ident = format_ident!("{SIZE_FN_IDENT}");
    let offset_fn_ident = format_ident!("{OFFSET_FN_IDENT}");
    let column_impl = quote! {
        impl #enum_ident {
            #const_size_impl

            #const_offset_impl
        }

        impl #crate_ident::AirColumn for #enum_ident {
            const COLUMNS_NUM: usize = #offset;
            const ALL_VARIANTS: &'static [Self] = #all_variants;

            fn size(self) -> usize {
                Self::#size_fn_ident(self)
            }
            fn offset(self) -> usize {
                Self::#offset_fn_ident(self)
            }
            fn mask_next_row(self) -> bool {
                #mask_next_row_impl
            }
        }
    };
    Ok(quote! {
        #column_impl

        #preprocessed_impl

        #row_impl
    })
}

fn all_variants_impl(parsed_variants: &[ParsedVariant]) -> TokenStream {
    let ident_iter = parsed_variants.iter().map(|v| &v.ident);
    quote! {
        &[#(Self::#ident_iter,)*]
    }
}

fn const_size_impl(parsed_variants: &[ParsedVariant]) -> TokenStream {
    let size_fn_ident = format_ident!("{SIZE_FN_IDENT}");
    let ident_iter = parsed_variants.iter().map(|v| &v.ident);
    let size_iter = parsed_variants.iter().map(|v| v.size);
    quote! {
        #[doc = "Returns the number of actual columns used by this variant."]
        pub const fn #size_fn_ident(self) -> usize {
            match self {
                #( Self::#ident_iter => #size_iter, )*
            }
        }
    }
}

fn const_offset_impl(parsed_variants: &[ParsedVariant]) -> (usize, TokenStream) {
    let mut offset = 0usize;
    let offset_iter = parsed_variants.iter().map(|v| {
        let off = offset;
        offset += v.size;
        off
    });
    let offset_fn_ident = format_ident!("{OFFSET_FN_IDENT}");
    let ident_iter = parsed_variants.iter().map(|v| &v.ident);
    let const_offset_impl = quote! {
        #[doc = "Returns the starting offset index for a variant."]
        pub const fn #offset_fn_ident(self) -> usize {
            match self {
                #( Self::#ident_iter => #offset_iter, )*
            }
        }
    };
    (offset, const_offset_impl)
}

fn preprocessed_impl(
    input: &syn::ItemEnum,
    parsed_variants: &[ParsedVariant],
    crate_ident: &TokenStream,
    enum_ident: &syn::Ident,
) -> Result<TokenStream, syn::Error> {
    let prefix = string_attr(input, "preprocessed_prefix")?;
    let prefix = prefix.ok_or_else(|| {
        syn::Error::new(
            Span::call_site(),
            "preprocessed prefix attribute must be present",
        )
    })?;

    let ident_iter = parsed_variants.iter().map(|v| &v.ident);
    let size_iter = parsed_variants.iter().map(|v| v.size);
    let ids: Vec<String> = (ident_iter.clone())
        .zip(size_iter)
        .flat_map(|(ident, size)| {
            (0..size).map(|i| {
                let ident = ident.to_string().to_case(Case::Snake);
                format!("{prefix}_{ident}_{i}")
            })
        })
        .collect();
    Ok(quote! {
        impl #crate_ident::PreprocessedAirColumn for #enum_ident {
            const PREPROCESSED_IDS: &'static [&'static str] = &[#(#ids,)*];
        }
    })
}

/// The value of the enum-level attribute `#[name = "..."]`, if present.
fn string_attr(input: &syn::ItemEnum, name: &str) -> syn::Result<Option<String>> {
    let mut value = None;
    for attr in &input.attrs {
        if attr.path.get_ident().is_none_or(|ident| *ident != name) {
            continue;
        }
        let syn::Meta::NameValue(meta) = attr.parse_meta()? else {
            return Err(syn::Error::new_spanned(attr, "string literal is expected"));
        };
        let syn::Lit::Str(s) = meta.lit else {
            return Err(syn::Error::new_spanned(attr, "string literal is expected"));
        };
        if value.replace(s.value()).is_some() {
            return Err(syn::Error::new_spanned(
                attr,
                format!("repeating `{name}` attribute"),
            ));
        }
    }
    Ok(value)
}

/// A variant's field in the row view: its name in snake case, a word
/// boundary before an upper-case letter that follows a lower-case letter or
/// a digit, or that starts a word after an acronym (`ValRPartNZTimesIndH`
/// is `val_r_part_nz_times_ind_h`, `Is32Bit` is `is32_bit`, `IsRotateR64`
/// is `is_rotate_r64`).
fn field_name(ident: &syn::Ident) -> String {
    let chars: Vec<char> = ident.to_string().chars().collect();
    let mut name = String::new();
    for (i, &c) in chars.iter().enumerate() {
        let boundary = i > 0 && c.is_ascii_uppercase() && {
            let prev = chars[i - 1];
            let next = chars.get(i + 1);
            prev.is_ascii_lowercase()
                || prev.is_ascii_digit()
                || (prev.is_ascii_uppercase() && next.is_some_and(|n| n.is_ascii_lowercase()))
        };
        if boundary {
            name.push('_');
        }
        name.push(c.to_ascii_lowercase());
    }
    name
}

/// The row view `#[row = "Name"]` asks for: a struct `Name<F>` with every
/// column's values at the row, a field per variant (its `_next` twin for a
/// `mask_next_row` variant's next row), read once from a `TraceEval`.
fn row_impl(
    parsed_variants: &[ParsedVariant],
    crate_ident: &TokenStream,
    enum_ident: &syn::Ident,
    row: &str,
) -> TokenStream {
    let row_ident = format_ident!("{row}");
    let mut fields = Vec::new();
    let mut reads = Vec::new();
    let mut arms = Vec::new();
    for v in parsed_variants {
        let ident = &v.ident;
        let field = format_ident!("{}", field_name(ident));
        let size = v.size;
        let doc = format!("`{enum_ident}::{ident}`.");
        fields.push(quote! { #[doc = #doc] pub #field: [F; #size] });
        reads.push(quote! { #field: trace_eval.column_eval(#enum_ident::#ident) });
        arms.push(quote! { #enum_ident::#ident => &self.#field });
        if v.mask_next_row {
            let next = format_ident!("{}_next", field_name(ident));
            let doc = format!("`{enum_ident}::{ident}` on the next row.");
            fields.push(quote! { #[doc = #doc] pub #next: [F; #size] });
            reads.push(quote! { #next: trace_eval.column_eval_next_row(#enum_ident::#ident) });
        }
    }
    let doc = format!("The values of every `{enum_ident}` at a row, read once.");
    let trace = trace_row_impl(parsed_variants, crate_ident, enum_ident, row);
    quote! {
        #trace

        #[doc = #doc]
        pub struct #row_ident<F> {
            #(#fields,)*
        }

        impl<F: Clone> #row_ident<F> {
            /// The row `trace_eval` evaluates.
            pub fn new<P, E>(trace_eval: &#crate_ident::trace::eval::TraceEval<P, #enum_ident, E>) -> Self
            where
                P: #crate_ident::air_column::PreprocessedAirColumn,
                E: ::stwo_constraint_framework::EvalAtRow<F = F>,
            {
                Self {
                    #(#reads,)*
                }
            }

            /// The values of `column`.
            pub fn column(&self, column: #enum_ident) -> &[F] {
                match column {
                    #(#arms,)*
                }
            }
        }
    }
}

/// The row view over a component's main trace, `NameTrace<'a>`: every
/// column's finalized parts, a field per variant named as in the row view's
/// (no `_next` twins), for the interaction trace's prover-side reads.
fn trace_row_impl(
    parsed_variants: &[ParsedVariant],
    crate_ident: &TokenStream,
    enum_ident: &syn::Ident,
    row: &str,
) -> TokenStream {
    let trace_ident = format_ident!("{row}Trace");
    let mut fields = Vec::new();
    let mut reads = Vec::new();
    let mut arms = Vec::new();
    for v in parsed_variants {
        let ident = &v.ident;
        let field = format_ident!("{}", field_name(ident));
        let size = v.size;
        let doc = format!("`{enum_ident}::{ident}`'s parts.");
        fields.push(quote! {
            #[doc = #doc]
            pub #field: [#crate_ident::trace::component::FinalizedColumn<'a>; #size]
        });
        reads.push(quote! { #field: trace.original_base_column(#enum_ident::#ident) });
        arms.push(quote! { #enum_ident::#ident => &self.#field });
    }
    let doc = format!("Every `{enum_ident}`'s parts in a component's main trace, read once.");
    quote! {
        #[cfg(feature = "prover")]
        #[doc = #doc]
        pub struct #trace_ident<'a> {
            #(#fields,)*
        }

        #[cfg(feature = "prover")]
        impl<'a> #trace_ident<'a> {
            /// The columns of `trace`'s main trace.
            pub fn new(trace: &'a #crate_ident::trace::component::ComponentTrace) -> Self {
                Self {
                    #(#reads,)*
                }
            }

            /// The parts of `column`.
            pub fn column(&self, column: #enum_ident) -> &[#crate_ident::trace::component::FinalizedColumn<'a>] {
                match column {
                    #(#arms,)*
                }
            }
        }
    }
}

fn mask_next_row_impl(parsed_variants: &[ParsedVariant]) -> TokenStream {
    let mut ident_iter = parsed_variants
        .iter()
        .filter_map(|v| v.mask_next_row.then_some(&v.ident));
    if let Some(first) = ident_iter.next() {
        quote! {
            matches!(
                self,
                Self::#first #(| Self::#ident_iter)*
            )
        }
    } else {
        quote! { false }
    }
}

fn collect_variants(input: &syn::ItemEnum) -> syn::Result<Vec<ParsedVariant>> {
    let mut result = Vec::with_capacity(input.variants.len());
    for variant in input.variants.iter() {
        if !matches!(variant.fields, syn::Fields::Unit) {
            return Err(syn::Error::new_spanned(
                &variant.fields,
                "non-unit variants are disallowed",
            ));
        }

        let mut size = None;
        let mut mask_next_row = false;
        for attr in &variant.attrs {
            match attr.path.get_ident() {
                Some(ident) if *ident == "mask_next_row" => {
                    let syn::Meta::Path(_) = attr.parse_meta()? else {
                        return Err(syn::Error::new_spanned(attr, "invalid attribute"));
                    };
                    if mask_next_row {
                        return Err(syn::Error::new_spanned(
                            attr,
                            "repeating `mask_next_row` attribute",
                        ));
                    }
                    mask_next_row = true;
                    continue;
                }
                Some(ident) if *ident == "size" => {}
                Some(ident) if *ident == "preprocessed_prefix" => {
                    return Err(syn::Error::new_spanned(
                        attr,
                        "preprocessed prefix is only allowed on the enum definition level",
                    ));
                }
                _ => continue,
            }

            let syn::Meta::NameValue(meta) = attr.parse_meta()? else {
                return Err(syn::Error::new_spanned(attr, "integer value expected"));
            };
            if let syn::Lit::Int(i) = meta.lit {
                let value = i.base10_parse::<NonZeroU8>()?;
                if size.is_none() {
                    size = Some(value)
                } else {
                    return Err(syn::Error::new_spanned(attr, "repeating `size` attribute"));
                }
            } else {
                return Err(syn::Error::new_spanned(attr, "integer value expected"));
            }
        }
        let Some(size) = size else {
            return Err(syn::Error::new_spanned(
                variant,
                "size attribute must be present",
            ));
        };
        result.push(ParsedVariant {
            ident: variant.ident.clone(),
            size: size.get() as usize,
            mask_next_row,
        });
    }
    Ok(result)
}

fn sanitize_attrs(input: &syn::ItemEnum) -> syn::Result<()> {
    for attr in &input.attrs {
        if attr
            .path
            .get_ident()
            .is_some_and(|ident| *ident == "size" || *ident == "mask_next_row")
        {
            return Err(syn::Error::new_spanned(attr, "invalid attribute"));
        }
    }

    Ok(())
}
