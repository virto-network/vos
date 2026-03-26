//! Proc macros for `pvx-actors`.
//!
//! - `#[derive(Actor)]` — implements the `Actor` trait with default lifecycle hooks
//! - `#[messages]` — on an `impl` block, generates message types, dispatch, and `_start`

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

/// Attribute macro for impl blocks that generates message types, handlers,
/// and the actor entry point (`_start`).
///
/// ## Constructor
///
/// A `fn new(...) -> Self` method (without `#[msg]`) defines the constructor.
/// The executor sends constructor arguments as the first message when spawning.
///
/// ## Message handlers
///
/// Each method marked with `#[msg]` becomes:
/// 1. A public struct with the method's parameters as fields (with rkyv derives)
/// 2. A `Message<ThatStruct>` impl that delegates to the method body
///
/// An aggregated enum `{Actor}Msg` is generated with:
/// - `deliver(actor, ctx)` — dispatch to handler
/// - `to_bytes()` — serialize via rkyv
/// - `dispatch(bytes, actor, ctx)` — zero-copy deserialize + deliver
/// - `dispatch_sync(bytes, actor, ctx)` — sync wrapper using `block_on`
///
/// ## Generated `_start`
///
/// The macro generates the PVM entry point that runs the standard lifecycle:
/// yield → recv constructor → build actor → checkpoint → message loop.
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
    let actor_name_str = actor_name.to_string();

    let mut msg_structs = Vec::new();
    let mut msg_impls = Vec::new();
    let mut enum_variants = Vec::new();
    let mut deliver_arms = Vec::new();
    let mut dispatch_arms = Vec::new();
    let mut is_query_arms = Vec::new();
    let mut meta_messages: Vec<proc_macro2::TokenStream> = Vec::new();
    let mut passthrough_items = Vec::new();

    // Constructor info
    let mut ctor_method = None;

    for item in &input.items {
        let ImplItem::Fn(method) = item else {
            passthrough_items.push(item.clone());
            continue;
        };

        // Check for #[msg] attribute
        let is_msg = method.attrs.iter().any(|a| a.path().is_ident("msg"));

        // Detect constructor: fn new(...) -> Self (without #[msg])
        if !is_msg && method.sig.ident == "new" {
            ctor_method = Some(method.clone());
            passthrough_items.push(item.clone());
            continue;
        }

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

        // Deliver arm (no Yield — outer loop handles scheduling)
        deliver_arms.push(quote! {
            #enum_name::#struct_name(msg) => {
                let _ = <#actor_name as pvx_actors::Message<#struct_name>>::handle(actor, msg, ctx).await;
            }
        });

        // Dispatch arm (deserialize from archived, no Yield)
        dispatch_arms.push(quote! {
            #archived_enum_name::#struct_name(archived) => {
                let msg: #struct_name = pvx_actors::rkyv::deserialize::<#struct_name, pvx_actors::rkyv::rancor::Error>(archived).unwrap();
                let _ = <#actor_name as pvx_actors::Message<#struct_name>>::handle(actor, msg, ctx).await;
            }
        });

        // is_query arm
        let query_val = is_query;
        is_query_arms.push(quote! {
            #enum_name::#struct_name(_) => #query_val
        });

        // Metadata for this message
        let msg_name_str = method_name.to_string();
        let field_metas: Vec<_> = field_names
            .iter()
            .zip(field_types.iter())
            .map(|(name, ty)| {
                let name_str = name.to_string();
                let ty_str = quote!(#ty).to_string();
                quote! {
                    pvx_actors::metadata::FieldMeta {
                        name: #name_str,
                        ty: #ty_str,
                    }
                }
            })
            .collect();
        meta_messages.push(quote! {
            pvx_actors::metadata::MessageMeta {
                name: #msg_name_str,
                is_query: #query_val,
                fields: &[ #( #field_metas ),* ],
            }
        });
    }

    // --- Constructor: generate Init struct and _start ---

    let (init_struct, init_deserialize, ctor_call) = if let Some(ctor) = &ctor_method {
        // Collect constructor params (skip Context if present)
        let mut ctor_field_names = Vec::new();
        let mut ctor_field_types = Vec::new();
        for arg in &ctor.sig.inputs {
            if let FnArg::Typed(pat_type) = arg {
                if is_context_type(pat_type.ty.as_ref()) {
                    continue;
                }
                if let Pat::Ident(pat) = pat_type.pat.as_ref() {
                    ctor_field_names.push(pat.ident.clone());
                    ctor_field_types.push(pat_type.ty.as_ref().clone());
                }
            }
        }

        let init_struct_name = format_ident!("{}Init", actor_name);
        let archived_init_name = format_ident!("Archived{}Init", actor_name);

        let init_struct_def = if ctor_field_names.is_empty() {
            quote! {
                #[derive(
                    pvx_actors::rkyv::Archive,
                    pvx_actors::rkyv::Serialize,
                    pvx_actors::rkyv::Deserialize,
                )]
                #[rkyv(crate = pvx_actors::rkyv)]
                pub struct #init_struct_name;
            }
        } else {
            quote! {
                #[derive(
                    pvx_actors::rkyv::Archive,
                    pvx_actors::rkyv::Serialize,
                    pvx_actors::rkyv::Deserialize,
                )]
                #[rkyv(crate = pvx_actors::rkyv)]
                pub struct #init_struct_name {
                    #( pub #ctor_field_names: #ctor_field_types ),*
                }
            }
        };

        let deser = if ctor_field_names.is_empty() {
            quote! {
                let _ = __payload;
            }
        } else {
            quote! {
                let __archived = unsafe {
                    pvx_actors::rkyv::access_unchecked::<#archived_init_name>(__payload)
                };
                let #init_struct_name { #( #ctor_field_names ),* } =
                    pvx_actors::rkyv::deserialize::<#init_struct_name, pvx_actors::rkyv::rancor::Error>(__archived).unwrap();
            }
        };

        let call = quote! {
            #actor_name::new(#( #ctor_field_names ),*)
        };

        (init_struct_def, deser, call)
    } else {
        // No constructor — require Default
        let init_struct_def = quote! {};
        let deser = quote! { let _ = __payload; };
        let call = quote! { <#actor_name as Default>::default() };
        (init_struct_def, deser, call)
    };

    // Generate _start
    let start_fn = quote! {
        #[unsafe(no_mangle)]
        pub extern "C" fn _start() {
            pvx_actors::main_loop::<#actor_name>(
                |__payload| {
                    #init_deserialize
                    #ctor_call
                },
                |__payload, __actor, __ctx| {
                    pvx_actors::block_on(async {
                        unsafe { #enum_name::dispatch(__payload, __actor, __ctx).await; }
                    });
                },
            );
        }
    };

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

            /// Static metadata describing this actor's message interface.
            pub const META: pvx_actors::metadata::ActorMeta = pvx_actors::metadata::ActorMeta {
                actor_name: #actor_name_str,
                messages: &[ #( #meta_messages ),* ],
            };
        }
    };

    // Re-emit the impl block with non-message methods preserved (including new)
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
        #init_struct
        #( #msg_structs )*
        #aggregated_enum
        #( #msg_impls )*
        #passthrough_impl
        #start_fn
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
