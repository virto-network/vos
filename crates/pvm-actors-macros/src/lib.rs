//! Proc macros for `pvm-actors`.
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
        impl #impl_generics pvm_actors::Actor for #name #ty_generics #where_clause {
            type Error = #error_ty;
        }
    };

    expanded.into()
}

/// Attribute macro for impl blocks that generates message types and handlers.
///
/// Each method marked with `#[msg]` becomes:
/// 1. A public struct with the method's parameters as fields
/// 2. A `Message<ThatStruct>` impl that delegates to the method body
///
/// An aggregated enum `{Actor}Msg` is generated containing all message variants.
/// A `Mailbox`-compatible `deliver` method is generated for the enum.
///
/// # Example
///
/// ```ignore
/// #[messages]
/// impl Counter {
///     #[msg]
///     async fn increment(&mut self, amount: i32) -> i32 {
///         self.count += amount;
///         self.count
///     }
///
///     #[msg]
///     async fn reset(&mut self) {
///         self.count = 0;
///     }
/// }
/// ```
///
/// Generates:
/// ```ignore
/// pub struct Increment { pub amount: i32 }
/// pub struct Reset;
///
/// pub enum CounterMsg {
///     Increment(Increment),
///     Reset(Reset),
/// }
///
/// impl Message<Increment> for Counter { ... }
/// impl Message<Reset> for Counter { ... }
///
/// impl CounterMsg {
///     pub async fn deliver(self, actor: &mut Counter, ctx: &mut Context<Counter>) { ... }
/// }
/// ```
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

    let mut msg_structs = Vec::new();
    let mut msg_impls = Vec::new();
    let mut enum_variants = Vec::new();
    let mut deliver_arms = Vec::new();
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

        // Collect parameters (skip &mut self)
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

        // Generate the message struct
        let msg_struct = if field_names.is_empty() {
            quote! { pub struct #struct_name; }
        } else {
            quote! {
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
            impl pvm_actors::Message<#struct_name> for #actor_name {
                type Reply = #reply_ty;
                async fn handle(
                    &mut self,
                    msg: #struct_name,
                    ctx: &mut pvm_actors::Context<Self>,
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
                let _ = <#actor_name as pvm_actors::Message<#struct_name>>::handle(actor, msg, ctx).await;
                pvm_actors::Yield::once().await;
            }
        });
    }

    // Generate the aggregated enum
    let aggregated_enum = quote! {
        pub enum #enum_name {
            #( #enum_variants ),*
        }

        impl #enum_name {
            /// Dispatch this message to the actor's async handler.
            pub async fn deliver(self, actor: &mut #actor_name, ctx: &mut pvm_actors::Context<#actor_name>) {
                match self {
                    #( #deliver_arms )*
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
