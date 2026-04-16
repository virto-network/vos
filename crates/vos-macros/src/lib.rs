//! Proc macros for `vos`.
//!
//! - `#[actor]` — rkyv derives + `impl Actor for X` using conventions
//! - `#[messages]` — message types, dispatch enum, entry points

use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{parse_macro_input, FnArg, ImplItem, ItemImpl, ItemStruct, Pat, ReturnType};

/// Makes a struct a VOS actor.
///
/// 1. Adds rkyv `Archive`/`Serialize`/`Deserialize` derives
/// 2. Generates `impl Actor for X` with:
///    - `create` → calls `Self::new()`
///    - `dispatch` → forwards to `{Name}Msg::dispatch` (from `#[messages]`)
///    - `encode`/`decode` → rkyv via [`vos::rkyv_encode`]/[`vos::rkyv_decode`]
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
///
/// ## Without this macro
///
/// If you need custom construction (e.g. init payload), skip `#[actor]` and
/// implement `Actor` manually. You still use `#[messages]` for the dispatch enum.
#[proc_macro_attribute]
pub fn actor(attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as ItemStruct);
    let name = &input.ident;
    let msg_enum = format_ident!("{}Msg", name);

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
            type Message = #msg_enum;

            fn create() -> Self {
                Self::__vos_create()
            }

            async fn on_start(
                &mut self,
                ctx: &mut vos::Context<Self>,
            ) -> core::result::Result<(), #error_ty> {
                self.__vos_on_start(ctx).await
            }

            fn dispatch(
                &mut self,
                msg: Self::Message,
                ctx: &mut vos::Context<Self>,
            ) -> vos::RunResult<bool> {
                vos::try_poll(async {
                    msg.deliver(self, ctx).await
                })
            }
        }
    };

    expanded.into()
}

/// Generates message types, dispatch enum, and PVM entry points from an impl block.
///
/// ## Constructor
///
/// A `fn new(...) -> Self` method (without `#[msg]`) is preserved as an inherent method.
///
/// ## Message handlers
///
/// Each method marked with `#[msg]` becomes a message type. Handlers can return:
/// - `T` — infallible, wrapped in `Ok(T)` automatically
/// - `Result<T>` — fallible, errors propagated to `on_error`
///
/// ## Generated items
///
/// - `{Name}Msg` enum with rkyv derives
/// - `Message<T>` trait impls for each handler
/// - `_start` / `accumulate` PVM entry points
/// - `.vos_meta` section with actor metadata
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
    let actor_name_str = actor_name.to_string();

    let mut msg_structs = Vec::new();
    let mut msg_impls = Vec::new();
    let mut enum_variants = Vec::new();
    let mut deliver_arms = Vec::new();
    let mut is_query_arms = Vec::new();
    let mut from_msg_arms = Vec::new();
    let mut meta_messages: Vec<proc_macro2::TokenStream> = Vec::new();
    let mut passthrough_items = Vec::new();
    let mut constructor_params: Vec<(syn::Ident, syn::Type)> = Vec::new();
    let mut has_start_handler = false;
    let mut start_returns_result = false;

    for item in &input.items {
        let ImplItem::Fn(method) = item else {
            passthrough_items.push(item.clone());
            continue;
        };

        let is_msg = method.attrs.iter().any(|a| a.path().is_ident("msg"));

        if !is_msg {
            // Detect constructor and extract its typed parameters
            if method.sig.ident == "new" {
                for arg in &method.sig.inputs {
                    if let FnArg::Typed(pat_type) = arg {
                        if is_context_type(pat_type.ty.as_ref()) {
                            continue;
                        }
                        if let Pat::Ident(pat) = pat_type.pat.as_ref() {
                            constructor_params.push((
                                pat.ident.clone(),
                                pat_type.ty.as_ref().clone(),
                            ));
                        }
                    }
                }
            }
            passthrough_items.push(item.clone());
            continue;
        }

        let method_name = &method.sig.ident;
        if method_name == "start" {
            has_start_handler = true;
            start_returns_result = match &method.sig.output {
                ReturnType::Default => false,
                ReturnType::Type(_, ty) => result_ok_type(ty).is_some(),
            };
        }
        let struct_name = format_ident!(
            "{}",
            to_pascal_case(&method_name.to_string())
        );

        // Detect &self vs &mut self
        let is_query = match method.sig.inputs.first() {
            Some(FnArg::Receiver(r)) => r.mutability.is_none(),
            _ => false,
        };

        // Collect parameters (skip self, skip Context)
        let mut field_names = Vec::new();
        let mut field_types = Vec::new();
        for arg in method.sig.inputs.iter().skip(1) {
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

        // Determine output type and whether handler returns Result
        let (output_ty, returns_result) = match &method.sig.output {
            ReturnType::Default => (quote! { () }, false),
            ReturnType::Type(_, ty) => {
                if result_ok_type(ty).is_some() {
                    (quote! { #ty }, true)
                } else {
                    (quote! { #ty }, false)
                }
            }
        };

        // Generate the message struct with rkyv derives.
        // Only Archive + Deserialize — messages are decoded from
        // incoming bytes, never serialized by user code. The enum
        // also only needs Archive + Deserialize since self-scheduling
        // uses dynamic Msg via ctx.tell() instead of typed encoding.
        let msg_struct = if field_names.is_empty() {
            quote! {
                #[derive(
                    vos::rkyv::Archive,
                    vos::rkyv::Deserialize,
                )]
                #[rkyv(crate = vos::rkyv)]
                pub struct #struct_name;
            }
        } else {
            quote! {
                #[derive(
                    vos::rkyv::Archive,
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

        let handler_body = quote! {
            #field_binds
            #body
        };

        let msg_impl = quote! {
            impl vos::Message<#struct_name> for #actor_name {
                type Output = #output_ty;
                #[allow(unreachable_code)]
                async fn handle(
                    &mut self,
                    msg: #struct_name,
                    ctx: &mut vos::Context<Self>,
                ) -> Self::Output {
                    #handler_body
                }
            }
        };
        msg_impls.push(msg_impl);

        // Enum variant
        enum_variants.push(quote! { #struct_name(#struct_name) });

        // Deliver arm — different code for infallible vs fallible handlers
        let deliver_arm = if returns_result {
            quote! {
                #enum_name::#struct_name(msg) => {
                    match <#actor_name as vos::Message<#struct_name>>::handle(actor, msg, ctx).await {
                        Ok(reply) => {
                            ctx.__set_reply(reply.into());
                            false
                        }
                        Err(e) => vos::Actor::on_error(actor, &e),
                    }
                }
            }
        } else {
            quote! {
                #enum_name::#struct_name(msg) => {
                    let reply = <#actor_name as vos::Message<#struct_name>>::handle(actor, msg, ctx).await;
                    ctx.__set_reply(reply.into());
                    false
                }
            }
        };
        deliver_arms.push(deliver_arm);

        // is_query arm
        let query_val = is_query;
        is_query_arms.push(quote! {
            #enum_name::#struct_name(_) => #query_val
        });

        // Metadata
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

        // Dynamic from_msg arm
        let from_msg_body = if field_names.is_empty() {
            quote! { Some(#enum_name::#struct_name(#struct_name)) }
        } else {
            let extractions: Vec<_> = field_names.iter().zip(field_types.iter()).map(|(name, ty)| {
                let name_str = name.to_string();
                let accessor = type_to_accessor(ty);
                quote! {
                    let #name: #ty = msg.args.#accessor(#name_str)?;
                }
            }).collect();
            quote! {
                #( #extractions )*
                Some(#enum_name::#struct_name(#struct_name { #( #field_names ),* }))
            }
        };
        from_msg_arms.push(quote! {
            #msg_name_str => { #from_msg_body }
        });
    }

    // Constructor field metadata
    let ctor_field_metas: Vec<_> = constructor_params.iter().map(|(name, ty)| {
        let name_str = name.to_string();
        let ty_str = quote!(#ty).to_string();
        quote! {
            vos::metadata::FieldMeta {
                name: #name_str,
                ty: #ty_str,
            }
        }
    }).collect();

    // Generate the aggregated enum
    let aggregated_enum = quote! {
        #[derive(
            vos::rkyv::Archive,
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

            pub fn is_query(&self) -> bool {
                match self {
                    #( #is_query_arms ),*
                }
            }

            /// Convert a dynamic message to this typed enum.
            /// Returns `None` if the message name or argument types don't match.
            pub fn from_msg(msg: &vos::value::Msg) -> Option<Self> {
                match msg.name.as_str() {
                    #( #from_msg_arms )*
                    _ => None,
                }
            }
        }

        impl vos::value::FromDynamic for #enum_name {
            fn from_dynamic(msg: &vos::value::Msg) -> Option<Self> {
                Self::from_msg(msg)
            }
        }

        impl #enum_name {
            pub const META: vos::metadata::ActorMeta = vos::metadata::ActorMeta {
                actor_name: #actor_name_str,
                messages: &[ #( #meta_messages ),* ],
                constructor: &[ #( #ctor_field_metas ),* ],
            };
        }
    };

    // Generate __vos_create() — reads init args from storage if constructor has params
    let vos_create = if constructor_params.is_empty() {
        quote! {
            fn __vos_create() -> Self {
                Self::new()
            }
        }
    } else {
        let extractions: Vec<_> = constructor_params.iter().map(|(name, ty)| {
            let name_str = name.to_string();
            let accessor = type_to_accessor(ty);
            quote! {
                let #name: #ty = args.#accessor(#name_str)
                    .expect(concat!("missing init arg '", #name_str, "'"));
            }
        }).collect();
        let names: Vec<_> = constructor_params.iter().map(|(n, _)| n).collect();
        // PVM service path reads init args from storage. Worker/WASM
        // builds receive args via __vos_create_with_args; bare create()
        // is an error there.
        quote! {
            fn __vos_create() -> Self {
                #[cfg(feature = "service")]
                {
                    let args: vos::value::Args = vos::lifecycle::load(vos::lifecycle::INIT_KEY)
                        .expect("actor init args not found in storage");
                    #( #extractions )*
                    return Self::new(#( #names ),*);
                }
                #[cfg(not(feature = "service"))]
                panic!(
                    "actor has constructor parameters — workers and WASM \
                     must be created with init args (see vos_worker_create / \
                     vos_wasm_create with non-null args)"
                );
            }
        }
    };

    // Generate __vos_create_with_args — for workers, reads init args from provided bytes
    let vos_create_with_args = if constructor_params.is_empty() {
        quote! {
            fn __vos_create_with_args(_args_bytes: &[u8]) -> Self {
                Self::new()
            }
        }
    } else {
        let extractions: Vec<_> = constructor_params.iter().map(|(name, ty)| {
            let name_str = name.to_string();
            let accessor = type_to_accessor(ty);
            quote! {
                let #name: #ty = args.#accessor(#name_str)
                    .expect(concat!("missing init arg '", #name_str, "'"));
            }
        }).collect();
        let names: Vec<_> = constructor_params.iter().map(|(n, _)| n).collect();
        quote! {
            fn __vos_create_with_args(args_bytes: &[u8]) -> Self {
                let args: vos::value::Args = vos::Decode::decode(args_bytes);
                #( #extractions )*
                Self::new(#( #names ),*)
            }
        }
    };

    // Generate __vos_on_start — forwards to start handler if defined, else no-op
    let vos_on_start = if has_start_handler {
        // The start handler is a Message<Start> impl. Call it directly.
        // If it returns Result, map Ok to Ok(()) and propagate Err.
        // If it returns (), just wrap in Ok(()).
        if start_returns_result {
            quote! {
                async fn __vos_on_start(
                    &mut self,
                    ctx: &mut vos::Context<Self>,
                ) -> core::result::Result<(), <Self as vos::Actor>::Error> {
                    <Self as vos::Message<Start>>::handle(self, Start, ctx).await?;
                    Ok(())
                }
            }
        } else {
            quote! {
                async fn __vos_on_start(
                    &mut self,
                    ctx: &mut vos::Context<Self>,
                ) -> core::result::Result<(), <Self as vos::Actor>::Error> {
                    <Self as vos::Message<Start>>::handle(self, Start, ctx).await;
                    Ok(())
                }
            }
        }
    } else {
        quote! {
            async fn __vos_on_start(
                &mut self,
                _ctx: &mut vos::Context<Self>,
            ) -> core::result::Result<(), <Self as vos::Actor>::Error> {
                Ok(())
            }
        }
    };

    // Re-emit the impl block with non-message methods + __vos_create + __vos_on_start
    let passthrough_impl = quote! {
        impl #actor_ty {
            #vos_create
            #vos_create_with_args
            #vos_on_start
            #( #passthrough_items )*
        }
    };

    // Preamble — always emitted
    let preamble = quote! {
        extern crate alloc;

        /// Result type alias using this actor's error type.
        #[allow(dead_code)]
        type Result<T> = core::result::Result<T, <#actor_name as vos::Actor>::Error>;

        #[allow(unused_imports)]
        use alloc::{boxed::Box, format, string::String, vec, vec::Vec};

        const _VOS_META_ENCODED: ([u8; 4096], usize) =
            vos::metadata::encode::<4096>(&#enum_name::META);
    };

    // PVM entry points — only when targeting PVM
    let pvm_entries = quote! {
        #[cfg(feature = "pvm")]
        #[allow(unused_imports)]
        use vos::{print, println, eprint, eprintln};

        // PC=0 entry — JAM refine.
        #[cfg(feature = "pvm")]
        #[unsafe(no_mangle)]
        pub extern "C" fn _start() {
            vos::run_refine_entry::<#actor_name>();
        }

        // PC=5 entry — JAM accumulate.
        #[cfg(feature = "pvm")]
        #[unsafe(no_mangle)]
        pub extern "C" fn accumulate() {
            vos::run_accumulate_entry::<#actor_name>();
        }

        #[cfg(feature = "pvm")]
        #[used]
        static _KEEP_ACCUMULATE: unsafe extern "C" fn() = accumulate;

        #[cfg(feature = "pvm")]
        #[unsafe(link_section = ".vos_meta")]
        #[used]
        static _VOS_META: [u8; _VOS_META_ENCODED.1] = {
            let (src, len) = _VOS_META_ENCODED;
            let mut out = [0u8; _VOS_META_ENCODED.1];
            let mut i = 0;
            while i < len { out[i] = src[i]; i += 1; }
            out
        };
    };

    // Worker entry points — native .so plugins (poll-based async ABI)
    let worker_entries = quote! {
        #[cfg(feature = "worker")]
        mod __vos_worker {
            use super::*;
            use core::future::Future;
            use core::pin::Pin;

            /// Persistent worker state: actor + context + in-flight future.
            /// One dispatch at a time per instance.
            struct WorkerState {
                actor: #actor_name,
                ctx: vos::Context<#actor_name>,
                in_flight: Option<Pin<Box<dyn Future<Output = bool>>>>,
            }

            static _VOS_WORKER_META: [u8; _VOS_META_ENCODED.1] = {
                let (src, len) = _VOS_META_ENCODED;
                let mut out = [0u8; _VOS_META_ENCODED.1];
                let mut i = 0;
                while i < len { out[i] = src[i]; i += 1; }
                out
            };

            #[unsafe(no_mangle)]
            pub extern "C" fn vos_worker_meta(
                out_ptr: *mut *const u8,
                out_len: *mut usize,
            ) {
                unsafe {
                    *out_ptr = _VOS_WORKER_META.as_ptr();
                    *out_len = _VOS_WORKER_META.len();
                }
            }

            #[unsafe(no_mangle)]
            pub extern "C" fn vos_worker_create(
                args_ptr: *const u8,
                args_len: usize,
            ) -> *mut () {
                use vos::Actor as _;
                let mut actor = if args_ptr.is_null() || args_len == 0 {
                    <#actor_name as vos::Actor>::create()
                } else {
                    let args_bytes = unsafe {
                        core::slice::from_raw_parts(args_ptr, args_len)
                    };
                    #actor_name::__vos_create_with_args(args_bytes)
                };
                let mut ctx = vos::Context::<#actor_name>::new(
                    vos::actors::context::ServiceId(0),
                );
                // Run on_start to completion (blocking).
                let _ = vos::run_blocking(actor.on_start(&mut ctx));
                let state = Box::new(WorkerState {
                    actor,
                    ctx,
                    in_flight: None,
                });
                Box::into_raw(state) as *mut ()
            }

            #[unsafe(no_mangle)]
            pub extern "C" fn vos_worker_dispatch(
                state: *mut (),
                msg_ptr: *const u8,
                msg_len: usize,
            ) {
                let ws = unsafe { &mut *(state as *mut WorkerState) };
                let raw = unsafe { core::slice::from_raw_parts(msg_ptr, msg_len) };

                // Decode: TAG_DYNAMIC prefix → dynamic Msg → typed enum
                let msg = if !raw.is_empty() && raw[0] == vos::value::TAG_DYNAMIC {
                    let dynamic: vos::value::Msg = vos::Decode::decode(&raw[1..]);
                    match <#enum_name as vos::value::FromDynamic>::from_dynamic(&dynamic) {
                        Some(m) => m,
                        None => return, // poll will return error
                    }
                } else {
                    vos::Decode::decode(raw)
                };

                // Create the handler future. Uses raw pointers because
                // the future borrows actor+ctx from the same WorkerState.
                // SAFETY: WorkerState is heap-allocated and never moved
                // while a future is in flight. Single-threaded.
                let actor_ptr = &mut ws.actor as *mut #actor_name;
                let ctx_ptr = &mut ws.ctx as *mut vos::Context<#actor_name>;
                let future: Pin<Box<dyn Future<Output = bool>>> = Box::pin(async move {
                    let actor = unsafe { &mut *actor_ptr };
                    let ctx = unsafe { &mut *ctx_ptr };
                    msg.deliver(actor, ctx).await
                });
                ws.in_flight = Some(future);
            }

            #[unsafe(no_mangle)]
            pub extern "C" fn vos_worker_poll(
                state: *mut (),
            ) -> vos::worker::WorkerPollResult {
                let ws = unsafe { &mut *(state as *mut WorkerState) };
                let Some(future) = ws.in_flight.as_mut() else {
                    return vos::worker::WorkerPollResult::error(
                        vos::worker::POLL_ERR_NO_FUTURE,
                    );
                };

                // Poll the future once
                let waker = vos::__worker::noop_waker();
                let mut cx = core::task::Context::from_waker(&waker);
                match future.as_mut().poll(&mut cx) {
                    core::task::Poll::Ready(_stop) => {
                        ws.in_flight = None;
                        let reply_bytes = ws.ctx.take_reply_bytes();
                        if reply_bytes.is_empty() {
                            vos::worker::WorkerPollResult::ready_empty()
                        } else {
                            vos::worker::WorkerPollResult::ready(reply_bytes)
                        }
                    }
                    core::task::Poll::Pending => {
                        vos::worker::WorkerPollResult::pending()
                    }
                }
            }

            #[unsafe(no_mangle)]
            pub extern "C" fn vos_worker_pending_effect(
                state: *mut (),
                out_ptr: *mut *const u8,
                out_len: *mut usize,
            ) {
                let ws = unsafe { &mut *(state as *mut WorkerState) };
                // Peek — pointer valid until next dispatch/poll
                if let Some(request) = ws.ctx.peek_host_io_request() {
                    unsafe {
                        *out_ptr = request.as_ptr();
                        *out_len = request.len();
                    }
                } else {
                    unsafe {
                        *out_ptr = core::ptr::null();
                        *out_len = 0;
                    }
                }
            }

            #[unsafe(no_mangle)]
            pub extern "C" fn vos_worker_provide_result(
                state: *mut (),
                ptr: *const u8,
                len: usize,
            ) {
                let ws = unsafe { &mut *(state as *mut WorkerState) };
                let result = if ptr.is_null() || len == 0 {
                    Vec::new()
                } else {
                    unsafe { core::slice::from_raw_parts(ptr, len) }.to_vec()
                };
                ws.ctx.set_host_io_result(result);
            }

            #[unsafe(no_mangle)]
            pub extern "C" fn vos_worker_drop(state: *mut ()) {
                if !state.is_null() {
                    unsafe { drop(Box::from_raw(state as *mut WorkerState)) };
                }
            }

            #[unsafe(no_mangle)]
            pub extern "C" fn vos_worker_free(ptr: *mut u8, len: usize, cap: usize) {
                if !ptr.is_null() && cap > 0 {
                    unsafe { drop(Vec::from_raw_parts(ptr, len, cap)) };
                }
            }
        }
    };

    // WASM entry points — for browser / WASI hosts.
    //
    // WASM is 32-bit and lacks multi-value returns in many toolchains,
    // so we pack two u32s (ptr + len) into a u64 for "buffer" returns:
    //   high 32 bits = ptr, low 32 bits = len
    //
    // The host (JS/WASI) drives the poll loop just like the worker host,
    // reading effects from WASM linear memory directly.
    let wasm_entries = quote! {
        #[cfg(feature = "wasm")]
        mod __vos_wasm {
            use super::*;
            use core::future::Future;
            use core::pin::Pin;

            /// Persistent WASM actor state: actor + context + in-flight future.
            /// Mirrors the worker model — one dispatch at a time.
            ///
            /// `last_reply` holds the bytes from the most recent Ready poll
            /// so the host can read them via `vos_wasm_take_reply`.
            struct WasmState {
                actor: #actor_name,
                ctx: vos::Context<#actor_name>,
                in_flight: Option<Pin<Box<dyn Future<Output = bool>>>>,
                last_reply: Option<Vec<u8>>,
            }

            static _VOS_WASM_META: [u8; _VOS_META_ENCODED.1] = {
                let (src, len) = _VOS_META_ENCODED;
                let mut out = [0u8; _VOS_META_ENCODED.1];
                let mut i = 0;
                while i < len { out[i] = src[i]; i += 1; }
                out
            };

            /// Pack (ptr, len) into a u64 for returning across the WASM ABI.
            #[inline]
            fn pack_buf(ptr: u32, len: u32) -> u64 {
                ((ptr as u64) << 32) | (len as u64)
            }

            /// Returns metadata bytes as packed (ptr, len).
            #[unsafe(no_mangle)]
            pub extern "C" fn vos_wasm_meta() -> u64 {
                pack_buf(
                    _VOS_WASM_META.as_ptr() as u32,
                    _VOS_WASM_META.len() as u32,
                )
            }

            /// Allocate a buffer in WASM memory. Used by the host to write
            /// init args / messages / I/O results before passing pointers
            /// to other functions. Caller must free via `vos_wasm_free`.
            #[unsafe(no_mangle)]
            pub extern "C" fn vos_wasm_alloc(size: u32) -> u32 {
                let mut buf: Vec<u8> = Vec::with_capacity(size as usize);
                // SAFETY: capacity is at least size; bytes are uninitialized
                // but the host writes to them before reading.
                unsafe { buf.set_len(size as usize); }
                let ptr = buf.as_mut_ptr() as u32;
                core::mem::forget(buf);
                ptr
            }

            /// Free a buffer previously returned by `vos_wasm_alloc` or
            /// `vos_wasm_take_reply`.
            #[unsafe(no_mangle)]
            pub extern "C" fn vos_wasm_free(ptr: u32, size: u32) {
                if ptr != 0 && size > 0 {
                    unsafe {
                        drop(Vec::from_raw_parts(
                            ptr as *mut u8,
                            size as usize,
                            size as usize,
                        ));
                    }
                }
            }

            /// Create a new actor instance. `args_ptr` may be 0 (no init args).
            /// Returns the state pointer (opaque handle).
            #[unsafe(no_mangle)]
            pub extern "C" fn vos_wasm_create(args_ptr: u32, args_len: u32) -> u32 {
                use vos::Actor as _;
                let mut actor = if args_ptr == 0 || args_len == 0 {
                    <#actor_name as vos::Actor>::create()
                } else {
                    let args_bytes = unsafe {
                        core::slice::from_raw_parts(args_ptr as *const u8, args_len as usize)
                    };
                    #actor_name::__vos_create_with_args(args_bytes)
                };
                let mut ctx = vos::Context::<#actor_name>::new(
                    vos::actors::context::ServiceId(0),
                );
                let _ = vos::run_blocking(actor.on_start(&mut ctx));
                let state = Box::new(WasmState {
                    actor,
                    ctx,
                    in_flight: None,
                    last_reply: None,
                });
                Box::into_raw(state) as u32
            }

            /// Start dispatching a message. Caller must drive with `vos_wasm_poll`.
            #[unsafe(no_mangle)]
            pub extern "C" fn vos_wasm_dispatch(state: u32, msg_ptr: u32, msg_len: u32) {
                let ws = unsafe { &mut *(state as *mut WasmState) };
                let raw = unsafe {
                    core::slice::from_raw_parts(msg_ptr as *const u8, msg_len as usize)
                };

                let msg = if !raw.is_empty() && raw[0] == vos::value::TAG_DYNAMIC {
                    let dynamic: vos::value::Msg = vos::Decode::decode(&raw[1..]);
                    match <#enum_name as vos::value::FromDynamic>::from_dynamic(&dynamic) {
                        Some(m) => m,
                        None => return,
                    }
                } else {
                    vos::Decode::decode(raw)
                };

                let actor_ptr = &mut ws.actor as *mut #actor_name;
                let ctx_ptr = &mut ws.ctx as *mut vos::Context<#actor_name>;
                let future: Pin<Box<dyn Future<Output = bool>>> = Box::pin(async move {
                    let actor = unsafe { &mut *actor_ptr };
                    let ctx = unsafe { &mut *ctx_ptr };
                    msg.deliver(actor, ctx).await
                });
                ws.in_flight = Some(future);
            }

            /// Poll the in-flight handler once.
            /// Returns: 0 = Ready, 1 = Pending, -1 = no future, -2 = decode error
            #[unsafe(no_mangle)]
            pub extern "C" fn vos_wasm_poll(state: u32) -> i32 {
                let ws = unsafe { &mut *(state as *mut WasmState) };
                let Some(future) = ws.in_flight.as_mut() else {
                    return -1;
                };
                let waker = vos::__worker::noop_waker();
                let mut cx = core::task::Context::from_waker(&waker);
                match future.as_mut().poll(&mut cx) {
                    core::task::Poll::Ready(_stop) => {
                        ws.in_flight = None;
                        let reply = ws.ctx.take_reply_bytes();
                        ws.last_reply = if reply.is_empty() { None } else { Some(reply) };
                        0
                    }
                    core::task::Poll::Pending => 1,
                }
            }

            /// Take the reply bytes from the last Ready poll. Returns
            /// packed (ptr, len) — caller owns the buffer and must free
            /// via `vos_wasm_free(ptr, len)`.
            ///
            /// Returns 0 if no reply is available.
            #[unsafe(no_mangle)]
            pub extern "C" fn vos_wasm_take_reply(state: u32) -> u64 {
                let ws = unsafe { &mut *(state as *mut WasmState) };
                match ws.last_reply.take() {
                    Some(bytes) => {
                        // Shrink to exact size so cap == len for free
                        let mut bytes = bytes;
                        bytes.shrink_to_fit();
                        let len = bytes.len();
                        let ptr = bytes.as_mut_ptr();
                        core::mem::forget(bytes);
                        pack_buf(ptr as u32, len as u32)
                    }
                    None => 0,
                }
            }

            /// Read the pending host I/O request. Returns packed (ptr, len)
            /// into worker memory — pointer valid until next dispatch/poll.
            /// Returns 0 if no pending effect.
            #[unsafe(no_mangle)]
            pub extern "C" fn vos_wasm_pending_effect(state: u32) -> u64 {
                let ws = unsafe { &mut *(state as *mut WasmState) };
                match ws.ctx.peek_host_io_request() {
                    Some(bytes) => pack_buf(bytes.as_ptr() as u32, bytes.len() as u32),
                    None => 0,
                }
            }

            /// Provide the result for the pending host I/O request.
            #[unsafe(no_mangle)]
            pub extern "C" fn vos_wasm_provide_result(state: u32, ptr: u32, len: u32) {
                let ws = unsafe { &mut *(state as *mut WasmState) };
                let result = if ptr == 0 || len == 0 {
                    Vec::new()
                } else {
                    unsafe {
                        core::slice::from_raw_parts(ptr as *const u8, len as usize)
                    }.to_vec()
                };
                ws.ctx.set_host_io_result(result);
            }

            /// Drop the actor instance.
            #[unsafe(no_mangle)]
            pub extern "C" fn vos_wasm_drop(state: u32) {
                if state != 0 {
                    unsafe { drop(Box::from_raw(state as *mut WasmState)) };
                }
            }

            /// Encode a JS-friendly MsgDesc into a TAG_DYNAMIC-prefixed
            /// rkyv-encoded Msg, ready to pass to `vos_wasm_dispatch`.
            ///
            /// Returns packed (ptr, len). Caller frees via `vos_wasm_free`.
            /// Returns 0 on decode error.
            #[unsafe(no_mangle)]
            pub extern "C" fn vos_wasm_encode_msg(desc_ptr: u32, desc_len: u32) -> u64 {
                if desc_ptr == 0 || desc_len == 0 { return 0; }
                let desc = unsafe {
                    core::slice::from_raw_parts(desc_ptr as *const u8, desc_len as usize)
                };
                let Some(msg) = vos::value::desc::decode_msg(desc) else {
                    return 0;
                };
                use vos::Encode;
                let encoded = msg.encode();
                let mut out: Vec<u8> = Vec::with_capacity(1 + encoded.len());
                out.push(vos::value::TAG_DYNAMIC);
                out.extend_from_slice(&encoded);
                out.shrink_to_fit();
                let len = out.len();
                let ptr = out.as_mut_ptr();
                core::mem::forget(out);
                pack_buf(ptr as u32, len as u32)
            }

            /// Encode an ArgsDesc into rkyv-encoded `Args` bytes, ready
            /// to pass to `vos_wasm_create` as init args.
            ///
            /// Returns packed (ptr, len). Caller frees via `vos_wasm_free`.
            /// Returns 0 on decode error.
            #[unsafe(no_mangle)]
            pub extern "C" fn vos_wasm_encode_args(desc_ptr: u32, desc_len: u32) -> u64 {
                if desc_ptr == 0 || desc_len == 0 { return 0; }
                let desc = unsafe {
                    core::slice::from_raw_parts(desc_ptr as *const u8, desc_len as usize)
                };
                let Some(args) = vos::value::desc::decode_args(desc) else {
                    return 0;
                };
                use vos::Encode;
                let mut encoded = args.encode();
                encoded.shrink_to_fit();
                let len = encoded.len();
                let ptr = encoded.as_mut_ptr();
                core::mem::forget(encoded);
                pack_buf(ptr as u32, len as u32)
            }

            /// Decode a rkyv-encoded Value into the JS-friendly ValueDesc format.
            ///
            /// Returns packed (ptr, len). Caller frees via `vos_wasm_free`.
            /// Returns 0 on empty input or decode error.
            #[unsafe(no_mangle)]
            pub extern "C" fn vos_wasm_decode_value(value_ptr: u32, value_len: u32) -> u64 {
                if value_ptr == 0 || value_len == 0 { return 0; }
                let bytes = unsafe {
                    core::slice::from_raw_parts(value_ptr as *const u8, value_len as usize)
                };
                let value: vos::value::Value = vos::Decode::decode(bytes);
                let mut out = vos::value::desc::encode_value(&value);
                out.shrink_to_fit();
                let len = out.len();
                let ptr = out.as_mut_ptr();
                core::mem::forget(out);
                pack_buf(ptr as u32, len as u32)
            }
        }
    };

    let expanded = quote! {
        #( #msg_structs )*
        #aggregated_enum
        #( #msg_impls )*
        #passthrough_impl
        #preamble
        #pvm_entries
        #worker_entries
        #wasm_entries
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

/// Map a Rust type to the corresponding `InitArgs` accessor method.
fn type_to_accessor(ty: &syn::Type) -> proc_macro2::TokenStream {
    let ty_str = quote!(#ty).to_string().replace(' ', "");
    match ty_str.as_str() {
        "u32" => quote! { get_u32 },
        "u64" => quote! { get_u64 },
        "i32" => quote! { get_i32 },
        "bool" => quote! { get_bool },
        "String" => quote! { get_str },
        "Vec<u8>" => quote! { get_bytes },
        "Vec<u32>" => quote! { get_list_u32 },
        _ => {
            let msg = format!("unsupported constructor param type for init args: {ty_str}");
            quote! { compile_error!(#msg) }
        }
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
