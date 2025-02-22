use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse2, parse_macro_input, Attribute, ImplItem, Item, ItemImpl, ItemMod, Pat, PatIdent, Type,
};
use syn::{FnArg, Ident};

#[proc_macro_attribute]
pub fn bin(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as ItemMod);
    let mod_name = &input.ident;

    let content = input.content.expect("Module must have a body").1;

    let mut storage_struct = None;
    let mut impl_blocks = Vec::new();
    let mut tests = Vec::new();
    let mut methods = Vec::new();

    for item in content {
        match item {
            Item::Struct(s) => {
                if has_vos_attr(&s.attrs, "storage") {
                    let mut storage = s;
                    storage.attrs.retain(|attr| !is_vos_attr(attr));
                    storage_struct = Some(storage);
                }
            }
            Item::Impl(i) => {
                // Process impl block and its methods
                let processed_impl = process_impl_block(i, &mut methods);
                impl_blocks.push(processed_impl);
            }
            Item::Mod(m) => {
                if m.ident == "tests" {
                    tests.push(m);
                }
            }
            _ => {}
        }
    }

    let storage = storage_struct.expect("Contract must have a storage struct");
    let storage_name = &storage.ident;
    let bin_impl = impl_bin(mod_name, storage_name, &methods);

    let expanded = quote! {
        use vos::bin_prelude::*;
        pub mod #mod_name {
            use super::*;

            #storage

            #(#impl_blocks)*

            #bin_impl

            #(#tests)*
        }

        fn main() {
            logger::init();
            runtime::block_on(async {
                if let Err(e) = protocol::run::<#mod_name::#storage_name>(
                    ::std::env::args(),
                    io::stdin(),
                    io::stdout(),
                ).await {
                    log::error!("{e:?}");
                }
            });
        }
    };

    TokenStream::from(expanded)
}

struct MethodInfo {
    name: Ident,
    args: Vec<(Ident, Type)>,
}

fn impl_bin(module: &Ident, data: &Ident, methods: &[MethodInfo]) -> Option<ItemImpl> {
    let signatures = methods
        .iter()
        .map(|m| {
            let name = format!("{module} {}", m.name);
            let args = m.args.iter().map(|a| {
                let arg = a.0.to_string();
                quote! {
                    args.push(protocol::Flag {
                        long: #arg.into(),
                        short: None,
                        arg: None,
                        required: true,
                        desc: "".into(),
                        var_id: None,
                        default_value: None,
                    })
                }
            });

            quote! {{
                let mut args = Vec::new();
                { #(#args)* };
                sig.push(protocol::ActionSignature {
                    sig: protocol::SignatureDetail {
                        name: #name.into(),
                        description: String::new(),
                        extra_description: String::new(),
                        search_terms: Vec::new(),
                        required_positional: Vec::new(),
                        optional_positional: Vec::new(),
                        rest_positional: None,
                        named: args,
                        input_output_types: Vec::new(),
                        allow_variants_without_examples: true,
                        is_filter: false,
                        creates_scope: false,
                        allows_unknown_args: true,
                        category: protocol::Value::String("Misc".into()),
                    },
                    examples: Vec::new(),
                });
            }}
        })
        .collect::<Vec<_>>();
    let out = quote! {
        impl protocol::Bin for #data {
            fn signature() -> Vec<protocol::ActionSignature> {
                let mut sig = Vec::new();
                #(#signatures)*
                sig
            }
        }
    };
    parse2(out).ok()
}

fn process_impl_block(mut impl_block: ItemImpl, methods: &mut Vec<MethodInfo>) -> ItemImpl {
    // Process each method in the impl block
    impl_block.items = impl_block
        .items
        .into_iter()
        .map(|item| {
            if let ImplItem::Fn(mut method) = item {
                if has_vos_attr(&method.attrs, "message") {
                    method.attrs.retain(|a| !is_vos_attr(a));
                    let args = method
                        .sig
                        .inputs
                        .iter()
                        .filter_map(|arg| match arg {
                            FnArg::Receiver(_) => None,
                            FnArg::Typed(a) => {
                                if let Pat::Ident(PatIdent { ident, .. }) = &*a.pat {
                                    Some((ident.to_owned(), *a.ty.to_owned()))
                                } else {
                                    None
                                }
                            }
                        })
                        .collect();
                    methods.push(MethodInfo {
                        name: method.sig.ident.clone(),
                        args,
                    });
                    ImplItem::Fn(method)
                } else if has_vos_attr(&method.attrs, "constructor") {
                    method.attrs.retain(|a| !is_vos_attr(a));
                    ImplItem::Fn(method)
                } else {
                    // other.push(&method);
                    ImplItem::Fn(method)
                }
            } else {
                item
            }
        })
        .collect();
    impl_block
}

fn is_vos_attr(attr: &Attribute) -> bool {
    if let Some(ident) = attr.path().get_ident() {
        ident == "vos"
    } else {
        false
    }
}

fn has_vos_attr(attrs: &[Attribute], name: &str) -> bool {
    attrs.iter().any(|attr| {
        if let Some(ident) = attr.path().get_ident() {
            if ident == "vos" {
                if let Ok(meta) = attr.meta.require_list() {
                    let content = meta.tokens.to_string();
                    return content.contains(name);
                }
            }
        }
        false
    })
}
