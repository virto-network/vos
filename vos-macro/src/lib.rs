use proc_macro::TokenStream;
use quote::quote;
use syn::ImplItemFn;
use syn::{parse_macro_input, Attribute, ImplItem, Item, ItemImpl, ItemMod};

#[proc_macro_attribute]
pub fn bin(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as ItemMod);
    let mod_name = &input.ident;

    let content = input.content.expect("Module must have a body").1;

    let mut storage_struct = None;
    let mut impl_blocks = Vec::new();
    let mut tests = Vec::new();

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
                if let Some(processed_impl) = process_impl_block(i) {
                    impl_blocks.push(processed_impl);
                }
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

    let expanded = quote! {
        #[cfg_attr(not(feature = "std"), no_std)]
        pub mod #mod_name {
            #storage

            #(#impl_blocks)*

            #(#tests)*

            impl #storage_name {
                pub fn deploy() -> Self {
                    Self::new_default()
                }
            }
        }
    };

    TokenStream::from(expanded)
}

fn process_impl_block(mut impl_block: ItemImpl) -> Option<ItemImpl> {
    let mut has_contract_methods = false;

    // Process each method in the impl block
    impl_block.items = impl_block
        .items
        .into_iter()
        .map(|item| {
            if let ImplItem::Fn(method) = item {
                if has_vos_attr(&method.attrs, "message") {
                    has_contract_methods = true;
                    process_message_method(method)
                } else if has_vos_attr(&method.attrs, "constructor") {
                    has_contract_methods = true;
                    process_constructor_method(method)
                } else {
                    ImplItem::Fn(method)
                }
            } else {
                item
            }
        })
        .collect();

    if has_contract_methods {
        Some(impl_block)
    } else {
        None
    }
}

fn process_message_method(mut method: ImplItemFn) -> ImplItem {
    method.attrs.retain(|attr| !is_vos_attr(attr));
    ImplItem::Fn(method)
}

fn process_constructor_method(mut method: ImplItemFn) -> ImplItem {
    method.attrs.retain(|attr| !is_vos_attr(attr));
    ImplItem::Fn(method)
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
