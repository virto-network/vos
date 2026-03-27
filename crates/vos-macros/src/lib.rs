//! Proc macros for `vos`.
//!
//! - `#[actor]` — makes a struct a VOS actor with rkyv derives and Actor trait impl
//! - `#[messages]` — on an `impl` block, generates message types, dispatch, and `_start`

use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{parse_macro_input, FnArg, ImplItem, ItemImpl, ItemStruct, Pat, ReturnType};

/// Attribute macro that makes a struct a VOS actor.
///
/// Adds rkyv `Archive`/`Serialize`/`Deserialize` derives for state persistence
/// and implements the `Actor` trait with default lifecycle hooks.
///
/// ```ignore
/// #[actor]
/// struct Counter { count: i32 }
/// ```
///
/// Optionally specify the error type:
/// ```ignore
/// #[actor(error = MyError)]
/// struct Counter { count: i32 }
/// ```
#[proc_macro_attribute]
pub fn actor(attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as ItemStruct);
    let name = &input.ident;

    // Parse optional error type from #[actor(error = Type)]
    let error_ty = if attr.is_empty() {
        quote! { () }
    } else {
        let meta = syn::parse_macro_input!(attr as syn::Meta);
        match meta {
            syn::Meta::NameValue(nv) if nv.path.is_ident("error") => {
                let val = &nv.value;
                quote! { #val }
            }
            syn::Meta::List(list) => {
                let mut ty = None;
                let _ = list.parse_nested_meta(|meta| {
                    if meta.path.is_ident("error") {
                        let value = meta.value()?;
                        ty = Some(value.parse::<syn::Type>()?);
                    }
                    Ok(())
                });
                ty.map(|t| quote! { #t }).unwrap_or_else(|| quote! { () })
            }
            _ => quote! { () },
        }
    };

    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let vis = &input.vis;
    let attrs = &input.attrs;
    let fields = &input.fields;

    // Re-emit struct with rkyv derives injected
    let struct_def = match fields {
        syn::Fields::Named(f) => quote! {
            #( #attrs )*
            #[derive(
                vos::rkyv::Archive,
                vos::rkyv::Serialize,
                vos::rkyv::Deserialize,
            )]
            #[rkyv(crate = vos::rkyv)]
            #vis struct #name #impl_generics #where_clause #f
        },
        syn::Fields::Unit => quote! {
            #( #attrs )*
            #[derive(
                vos::rkyv::Archive,
                vos::rkyv::Serialize,
                vos::rkyv::Deserialize,
            )]
            #[rkyv(crate = vos::rkyv)]
            #vis struct #name #impl_generics #where_clause;
        },
        syn::Fields::Unnamed(f) => quote! {
            #( #attrs )*
            #[derive(
                vos::rkyv::Archive,
                vos::rkyv::Serialize,
                vos::rkyv::Deserialize,
            )]
            #[rkyv(crate = vos::rkyv)]
            #vis struct #name #impl_generics #f #where_clause;
        },
    };

    let expanded = quote! {
        #struct_def

        impl #impl_generics vos::Actor for #name #ty_generics #where_clause {
            type Error = #error_ty;
        }
    };

    expanded.into()
}

/// Attribute macro for impl blocks that generates message types, handlers,
/// and the actor entry point (`_start`).
///
/// ## Result type alias
///
/// The macro emits `type Result<T> = core::result::Result<T, <Actor as vos::Actor>::Error>`
/// so handlers can use `Result<T>` with `?` and the actor's error type is used automatically.
///
/// ## Constructor
///
/// A `fn new(...) -> Self` method (without `#[msg]`) defines the constructor.
///
/// ## Message handlers
///
/// Each method marked with `#[msg]` becomes a message type. Handlers can return:
/// - `T` — infallible, wrapped in `Ok(T)` automatically
/// - `Result<T>` — fallible, errors propagated to `on_error`
///
/// ## Generated `_start`
///
/// The macro generates the PVM entry point. Lifecycle:
/// read state from storage → dispatch all pending items → write state back → halt.
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

        // Determine reply type and whether handler returns Result
        let (reply_ty, returns_result) = match &method.sig.output {
            ReturnType::Default => (quote! { () }, false),
            ReturnType::Type(_, ty) => {
                if let Some(inner) = result_ok_type(ty) {
                    (quote! { #inner }, true)
                } else {
                    (quote! { #ty }, false)
                }
            }
        };

        // Generate the message struct with rkyv derives
        let msg_struct = if field_names.is_empty() {
            quote! {
                #[derive(
                    vos::rkyv::Archive,
                    vos::rkyv::Serialize,
                    vos::rkyv::Deserialize,
                )]
                #[rkyv(crate = vos::rkyv)]
                pub struct #struct_name;
            }
        } else {
            quote! {
                #[derive(
                    vos::rkyv::Archive,
                    vos::rkyv::Serialize,
                    vos::rkyv::Deserialize,
                )]
                #[rkyv(crate = vos::rkyv)]
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

        // If handler returns Result<T>, pass through directly; otherwise wrap in Ok()
        let handler_body = if returns_result {
            quote! {
                #field_binds
                #body
            }
        } else {
            quote! {
                #field_binds
                Ok(#body)
            }
        };

        let msg_impl = quote! {
            impl vos::Message<#struct_name> for #actor_name {
                type Reply = #reply_ty;
                async fn handle(
                    &mut self,
                    msg: #struct_name,
                    ctx: &mut vos::Context<Self>,
                ) -> core::result::Result<Self::Reply, Self::Error> {
                    #handler_body
                }
            }
        };
        msg_impls.push(msg_impl);

        // Enum variant
        enum_variants.push(quote! { #struct_name(#struct_name) });

        // Deliver arm
        deliver_arms.push(quote! {
            #enum_name::#struct_name(msg) => {
                match <#actor_name as vos::Message<#struct_name>>::handle(actor, msg, ctx).await {
                    Ok(_) => false,
                    Err(e) => vos::Actor::on_error(actor, &e),
                }
            }
        });

        // Dispatch arm (deserialize from archived)
        dispatch_arms.push(quote! {
            #archived_enum_name::#struct_name(archived) => {
                let msg: #struct_name = vos::rkyv::deserialize::<#struct_name, vos::rkyv::rancor::Error>(archived).unwrap();
                match <#actor_name as vos::Message<#struct_name>>::handle(actor, msg, ctx).await {
                    Ok(_) => false,
                    Err(e) => vos::Actor::on_error(actor, &e),
                }
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
                    vos::metadata::FieldMeta {
                        name: #name_str,
                        ty: #ty_str,
                    }
                }
            })
            .collect();
        meta_messages.push(quote! {
            vos::metadata::MessageMeta {
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
                    vos::rkyv::Archive,
                    vos::rkyv::Serialize,
                    vos::rkyv::Deserialize,
                )]
                #[rkyv(crate = vos::rkyv)]
                pub struct #init_struct_name;
            }
        } else {
            quote! {
                #[derive(
                    vos::rkyv::Archive,
                    vos::rkyv::Serialize,
                    vos::rkyv::Deserialize,
                )]
                #[rkyv(crate = vos::rkyv)]
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
                    vos::rkyv::access_unchecked::<#archived_init_name>(__payload)
                };
                let #init_struct_name { #( #ctor_field_names ),* } =
                    vos::rkyv::deserialize::<#init_struct_name, vos::rkyv::rancor::Error>(__archived).unwrap();
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

    let archived_actor_name = format_ident!("Archived{}", actor_name);

    // Generate _start entry point with save/load closures for state persistence
    let start_fn = quote! {
        extern crate alloc;

        /// Result type alias using this actor's error type.
        #[allow(dead_code)]
        type Result<T> = core::result::Result<T, <#actor_name as vos::Actor>::Error>;

        #[allow(unused_imports)]
        use vos::{print, println, eprint, eprintln};
        #[allow(unused_imports)]
        use alloc::{boxed::Box, format, string::String, vec, vec::Vec};

        #[unsafe(no_mangle)]
        pub extern "C" fn _start() {
            vos::main_loop::<#actor_name>(
                |__payload| {
                    #init_deserialize
                    #ctor_call
                },
                |__payload, __actor, __ctx| -> bool {
                    vos::block_on(async {
                        unsafe { #enum_name::dispatch(__payload, __actor, __ctx).await }
                    })
                },
                |__actor| {
                    let bytes = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(__actor).unwrap();
                    bytes.to_vec()
                },
                |__bytes| {
                    let archived = unsafe {
                        vos::rkyv::access_unchecked::<#archived_actor_name>(__bytes)
                    };
                    vos::rkyv::deserialize::<#actor_name, vos::rkyv::rancor::Error>(archived).unwrap()
                },
            );
        }
    };

    // Generate the aggregated enum
    let aggregated_enum = quote! {
        #[derive(
            vos::rkyv::Archive,
            vos::rkyv::Serialize,
            vos::rkyv::Deserialize,
        )]
        #[rkyv(crate = vos::rkyv)]
        pub enum #enum_name {
            #( #enum_variants ),*
        }

        impl #enum_name {
            /// Dispatch this message to the actor. Returns `true` if the actor
            /// should stop processing further messages (i.e. `on_error` returned `true`).
            pub async fn deliver(self, actor: &mut #actor_name, ctx: &mut vos::Context<#actor_name>) -> bool {
                match self {
                    #( #deliver_arms )*
                }
            }

            pub fn to_bytes(&self) -> vos::rkyv::util::AlignedVec {
                vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(self).unwrap()
            }

            /// Deserialize and dispatch a message from bytes. Returns `true` if the
            /// actor should stop processing further messages.
            pub async unsafe fn dispatch(bytes: &[u8], actor: &mut #actor_name, ctx: &mut vos::Context<#actor_name>) -> bool {
                let archived = unsafe { vos::rkyv::access_unchecked::<#archived_enum_name>(bytes) };
                match archived {
                    #( #dispatch_arms )*
                }
            }

            pub fn is_query(&self) -> bool {
                match self {
                    #( #is_query_arms ),*
                }
            }

            pub const META: vos::metadata::ActorMeta = vos::metadata::ActorMeta {
                actor_name: #actor_name_str,
                messages: &[ #( #meta_messages ),* ],
            };
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

/// If `ty` is `Result<T>` or `Result<T, E>`, return the `T`.
fn result_ok_type(ty: &syn::Type) -> Option<syn::Type> {
    let syn::Type::Path(p) = ty else { return None };
    let seg = p.path.segments.last()?;
    if seg.ident != "Result" {
        return None;
    }
    let syn::PathArguments::AngleBracketed(args) = &seg.arguments else {
        return None;
    };
    match args.args.first()? {
        syn::GenericArgument::Type(t) => Some(t.clone()),
        _ => None,
    }
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
