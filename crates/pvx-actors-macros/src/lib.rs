//! Proc macros for `pvx-actors`.
//!
//! - `#[derive(Actor)]` — implements the `Actor` trait with default lifecycle hooks
//! - `#[messages]` — on an `impl` block, generates a message enum and `Message` impls

use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{parse_macro_input, DeriveInput, FnArg, ImplItem, ItemImpl, Pat, ReturnType};

/// Derive the `Actor` trait with defaults.
///
/// ```ignore
/// #[derive(Actor)]
/// struct Counter { count: i32 }
/// ```
///
/// Generates:
/// ```ignore
/// impl Actor for Counter {
///     type Error = ();
/// }
/// ```
///
/// Optionally specify the error type:
/// ```ignore
/// #[derive(Actor)]
/// #[actor(error = MyError)]
/// struct Counter { count: i32 }
/// ```
#[proc_macro_derive(Actor, attributes(actor))]
pub fn derive_actor(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    // Look for #[actor(error = Type)]
    let error_ty = input
        .attrs
        .iter()
        .find(|a| a.path().is_ident("actor"))
        .and_then(|a| {
            let mut ty = None;
            a.parse_nested_meta(|meta| {
                if meta.path.is_ident("error") {
                    let value = meta.value()?;
                    ty = Some(value.parse::<syn::Type>()?);
                }
                Ok(())
            })
            .ok();
            ty
        });

    let error_ty = error_ty
        .map(|t| quote! { #t })
        .unwrap_or_else(|| quote! { () });

    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let expanded = quote! {
        impl #impl_generics pvx_actors::Actor for #name #ty_generics #where_clause {
            type Error = #error_ty;
        }
    };

    expanded.into()
}

/// Attribute macro for impl blocks that generates message types and handlers.
///
/// Each method marked with `#[msg]` becomes:
/// 1. A public struct with the method's parameters as fields (with rkyv derives)
/// 2. A `Message<ThatStruct>` impl that delegates to the method body
///
/// An aggregated enum `{Actor}Msg` is generated containing all message variants
/// with rkyv derives and helper methods:
/// - `to_bytes(&self) -> AlignedVec` — serialize via rkyv
/// - `dispatch(bytes: &[u8], actor, ctx)` — zero-copy deserialize + deliver
/// - `is_query(&self) -> bool` — true for `&self` methods, false for `&mut self`
///
/// A `Mailbox`-compatible `deliver` method is generated for the enum.
#[proc_macro_attribute]
pub fn messages(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as ItemImpl);
    let actor_ty = &input.self_ty;

    // Extract the simple ident for naming the enum
    let actor_name = match actor_ty.as_ref() {
        syn::Type::Path(p) => p.path.segments.last().unwrap().ident.clone(),
        _ => panic!("#[messages] requires a simple type path"),
    };
    let enum_name = format_ident!("{}Msg", actor_name);
    let archived_enum_name = format_ident!("Archived{}Msg", actor_name);

    let mut msg_structs = Vec::new();
    let mut msg_impls = Vec::new();
    let mut enum_variants = Vec::new();
    let mut deliver_arms = Vec::new();
    let mut dispatch_arms = Vec::new();
    let mut is_query_arms = Vec::new();
    let mut passthrough_items = Vec::new();

    for item in &input.items {
        let ImplItem::Fn(method) = item else {
            passthrough_items.push(item.clone());
            continue;
        };

        // Check for #[msg] attribute
        let is_msg = method.attrs.iter().any(|a| a.path().is_ident("msg"));
        if !is_msg {
            passthrough_items.push(item.clone());
            continue;
        }

        let method_name = &method.sig.ident;
        let struct_name = format_ident!(
            "{}",
            to_pascal_case(&method_name.to_string())
        );

        // Detect &self vs &mut self
        let is_query = match method.sig.inputs.first() {
            Some(FnArg::Receiver(r)) => r.mutability.is_none(),
            _ => false,
        };

        // Collect parameters (skip self)
        let mut field_names = Vec::new();
        let mut field_types = Vec::new();
        for arg in method.sig.inputs.iter().skip(1) {
            // skip Context parameters (&Context<..> or &mut Context<..>)
            if let FnArg::Typed(pat_type) = arg {
                if is_context_type(pat_type.ty.as_ref()) {
                    continue;
                }
                if let Pat::Ident(pat) = pat_type.pat.as_ref() {
                    field_names.push(pat.ident.clone());
                    field_types.push(pat_type.ty.as_ref().clone());
                }
            }
        }

        // Determine reply type
        let reply_ty = match &method.sig.output {
            ReturnType::Default => quote! { () },
            ReturnType::Type(_, ty) => quote! { #ty },
        };

        // Generate the message struct with rkyv derives
        let msg_struct = if field_names.is_empty() {
            quote! {
                #[derive(
                    pvx_actors::rkyv::Archive,
                    pvx_actors::rkyv::Serialize,
                    pvx_actors::rkyv::Deserialize,
                )]
                #[rkyv(crate = pvx_actors::rkyv)]
                pub struct #struct_name;
            }
        } else {
            quote! {
                #[derive(
                    pvx_actors::rkyv::Archive,
                    pvx_actors::rkyv::Serialize,
                    pvx_actors::rkyv::Deserialize,
                )]
                #[rkyv(crate = pvx_actors::rkyv)]
                pub struct #struct_name {
                    #( pub #field_names: #field_types ),*
                }
            }
        };
        msg_structs.push(msg_struct);

        // Generate Message impl
        let body = &method.block;
        let field_binds = if field_names.is_empty() {
            quote! { let _ = msg; }
        } else {
            quote! { let #struct_name { #( #field_names ),* } = msg; }
        };

        let msg_impl = quote! {
            impl pvx_actors::Message<#struct_name> for #actor_name {
                type Reply = #reply_ty;
                async fn handle(
                    &mut self,
                    msg: #struct_name,
                    ctx: &mut pvx_actors::Context<Self>,
                ) -> Result<Self::Reply, Self::Error> {
                    #field_binds
                    Ok(#body)
                }
            }
        };
        msg_impls.push(msg_impl);

        // Enum variant
        enum_variants.push(quote! { #struct_name(#struct_name) });

        // Deliver arm
        deliver_arms.push(quote! {
            #enum_name::#struct_name(msg) => {
                let _ = <#actor_name as pvx_actors::Message<#struct_name>>::handle(actor, msg, ctx).await;
                pvx_actors::Yield::once().await;
            }
        });

        // Dispatch arm (deserialize from archived)
        dispatch_arms.push(quote! {
            #archived_enum_name::#struct_name(archived) => {
                let msg: #struct_name = pvx_actors::rkyv::deserialize::<#struct_name, pvx_actors::rkyv::rancor::Error>(archived).unwrap();
                let _ = <#actor_name as pvx_actors::Message<#struct_name>>::handle(actor, msg, ctx).await;
                pvx_actors::Yield::once().await;
            }
        });

        // is_query arm
        let query_val = is_query;
        is_query_arms.push(quote! {
            #enum_name::#struct_name(_) => #query_val
        });
    }

    // Generate the aggregated enum
    let aggregated_enum = quote! {
        #[derive(
            pvx_actors::rkyv::Archive,
            pvx_actors::rkyv::Serialize,
            pvx_actors::rkyv::Deserialize,
        )]
        #[rkyv(crate = pvx_actors::rkyv)]
        pub enum #enum_name {
            #( #enum_variants ),*
        }

        impl #enum_name {
            /// Dispatch this message to the actor's async handler.
            pub async fn deliver(self, actor: &mut #actor_name, ctx: &mut pvx_actors::Context<#actor_name>) {
                match self {
                    #( #deliver_arms )*
                }
            }

            /// Serialize this message to bytes.
            pub fn to_bytes(&self) -> pvx_actors::rkyv::util::AlignedVec {
                pvx_actors::rkyv::to_bytes::<pvx_actors::rkyv::rancor::Error>(self).unwrap()
            }

            /// Deserialize from bytes and dispatch to the actor's handler.
            ///
            /// # Safety
            /// The caller must ensure `bytes` were produced by `to_bytes` on a valid `#enum_name`.
            pub async unsafe fn dispatch(bytes: &[u8], actor: &mut #actor_name, ctx: &mut pvx_actors::Context<#actor_name>) {
                let archived = unsafe { pvx_actors::rkyv::access_unchecked::<#archived_enum_name>(bytes) };
                match archived {
                    #( #dispatch_arms )*
                }
            }

            /// Returns `true` if this message is a query (`&self` handler).
            pub fn is_query(&self) -> bool {
                match self {
                    #( #is_query_arms ),*
                }
            }
        }
    };

    // Re-emit the impl block with non-message methods preserved
    let passthrough_impl = if !passthrough_items.is_empty() {
        quote! {
            impl #actor_ty {
                #( #passthrough_items )*
            }
        }
    } else {
        quote! {}
    };

    let expanded = quote! {
        #( #msg_structs )*
        #aggregated_enum
        #( #msg_impls )*
        #passthrough_impl
    };

    expanded.into()
}

/// Check if a type is a reference to `Context` (either `&Context<..>` or `&mut Context<..>`).
fn is_context_type(ty: &syn::Type) -> bool {
    if let syn::Type::Reference(r) = ty {
        return match r.elem.as_ref() {
            syn::Type::Path(p) => p
                .path
                .segments
                .last()
                .is_some_and(|s| s.ident == "Context"),
            _ => false,
        };
    }
    false
}

fn to_pascal_case(s: &str) -> String {
    s.split('_')
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                None => String::new(),
                Some(c) => c.to_uppercase().chain(chars).collect(),
            }
        })
        .collect()
}
