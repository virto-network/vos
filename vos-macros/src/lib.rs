//! Proc macros for `vos`.
//!
//! - `#[actor]` — rkyv derives + `impl Actor for X` using conventions
//! - `#[messages]` — message types, dispatch enum, entry points

use proc_macro::TokenStream;
use quote::{ToTokens, format_ident, quote};
use syn::{FnArg, ImplItem, ItemImpl, ItemStruct, Pat, ReturnType, parse_macro_input};

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
/// ## Determinism
///
/// PVM actors are deterministic by construction — their `Context`
/// has no `fetch` / `host_call` / other I/O methods at all. External
/// I/O lives in workers (build the same actor crate with the
/// `worker` feature on, and [`vos::ExtensionCtx`] unlocks `ctx.fetch`).
/// PVM actors that need external data route through workers via
/// `ctx.ask` / `ctx.tell` so each reply is captured in the
/// CRDT/Raft replay log.
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

    // Parse optional attributes:
    //   #[actor]                       — defaults to `Error = ()`, kind = Actor
    //   #[actor(error = Type)]         — custom error type for Actor::Error
    //   #[actor(kind = "service")]     — opt into Service-mode (long-running)
    //   #[actor(caps = ["net.tcp.bind", ...])] — declarative capability list
    let parsed = parse_actor_attrs(attr);
    let error_ty = parsed.error_ty;
    let kind_byte = parsed.kind_byte;
    let caps_lits = parsed.caps;

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

    // PVM entry-point block — emitted only on riscv64 actor builds
    // with the `bin` feature on. Same shape `pvm_main!` used to
    // produce; lives here so the user's lib.rs needs neither a
    // `pvm_main!()` invocation nor a separate `main.rs`. The
    // helper symbols (`__VOS_ACTOR_META_ENCODED`,
    // `_KEEP_ACCUMULATE`) are named with leading underscores /
    // a `__VOS_` prefix so they don't shadow anything in the
    // user's module.
    let pvm_entries = quote! {
        #[cfg(all(target_arch = "riscv64", feature = "bin"))]
        #[unsafe(no_mangle)]
        pub extern "C" fn _start() {
            vos::run_refine_entry::<#name>();
        }

        #[cfg(all(target_arch = "riscv64", feature = "bin"))]
        #[unsafe(no_mangle)]
        pub extern "C" fn accumulate() {
            vos::run_accumulate_entry::<#name>();
        }

        #[cfg(all(target_arch = "riscv64", feature = "bin"))]
        #[used]
        static _KEEP_ACCUMULATE: unsafe extern "C" fn() = accumulate;

        #[cfg(all(target_arch = "riscv64", feature = "bin"))]
        const __VOS_ACTOR_META_ENCODED: ([u8; 4096], usize) =
            vos::metadata::encode::<4096>(
                &<<#name as vos::Actor>::Message>::META,
            );

        #[cfg(all(target_arch = "riscv64", feature = "bin"))]
        #[unsafe(link_section = ".vos_meta")]
        #[used]
        static _VOS_META: [u8; __VOS_ACTOR_META_ENCODED.1] = {
            let (src, len) = __VOS_ACTOR_META_ENCODED;
            let mut out = [0u8; __VOS_ACTOR_META_ENCODED.1];
            let mut i = 0;
            while i < len { out[i] = src[i]; i += 1; }
            out
        };
    };

    let expanded = quote! {
        #struct_def

        impl #impl_generics vos::Actor for #name #ty_generics #where_clause {
            type Error = #error_ty;
            type Message = #msg_enum;

            // Phase 2 — extension kind discriminant; defaulted on the
            // trait, overridden here from `#[actor(kind = "...")]`.
            const KIND_BYTE: u8 = #kind_byte;

            // Phase 6 — capability declarations. Empty by default;
            // overridden from `#[actor(caps = [...])]`.
            const CAPS: &'static [&'static str] = &[ #( #caps_lits ),* ];

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
                // Pass `deliver`'s future to `try_poll` directly. Wrapping
                // it in an `async {}` block compiles to a second state
                // machine that holds `deliver`'s state machine plus its
                // own resume slot — doubling the on-stack frame for no
                // semantic gain. Actors with large async handlers
                // (branchy `match` or `if/else if` chains) overflow the
                // PVM's 64 KiB stack on warm-restart specifically because
                // the warm path already adds two more frames beyond the
                // cold-start `on_start` path; this redundancy is what
                // pushes them over the edge.
                vos::try_poll(msg.deliver(self, ctx))
            }
        }

        #pvm_entries
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
    // One entry per `#[msg]`: the data the host-Client emission
    // (gated on vos's `std` feature inside `__vos_emit_host_client!`)
    // needs to generate a typed method per message — the wire
    // name and the unwrapped success type.
    let mut client_methods: Vec<ClientMethodInfo> = Vec::new();
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
                            constructor_params
                                .push((pat.ident.clone(), pat_type.ty.as_ref().clone()));
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
        let struct_name = format_ident!("{}", to_pascal_case(&method_name.to_string()));

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

        // Detect `Option<T>` in the handler's return type (after
        // unwrapping `Result<T, E>` if applicable). When present,
        // we serialize replies via rkyv into `Value::Bytes` —
        // empty for `None`, populated for `Some(v)`. The
        // generated client at the other end recognises this
        // shape and turns it back into `Option<T>`.
        let raw_ret = match &method.sig.output {
            ReturnType::Default => None,
            ReturnType::Type(_, ty) => Some(ty.as_ref().clone()),
        };
        let success_after_result = match &raw_ret {
            None => None,
            Some(t) => match result_ok_type(t) {
                Some(inner) => Some(inner),
                None => Some(t.clone()),
            },
        };
        let option_inner = success_after_result.as_ref().and_then(option_inner_type);

        // Reply-encoding step: how to convert the handler's
        // returned value into the `Value` we hand to
        // `ctx.__set_reply`. Three shapes, in order:
        //
        // 1. `Option<T>` — match Some/None, rkyv-encode T into
        //    `Value::Bytes` (empty for None).
        // 2. Primitives / strings / `Vec<u8|u32|String>` — these
        //    all impl `Into<Value>` already, so `reply.into()`.
        // 3. Anything else — assume a user rkyv-able struct and
        //    encode into `Value::Bytes`.
        let reply_to_value = if option_inner.is_some() {
            quote! {
                {
                    let __reply = reply;
                    match __reply {
                        None => vos::value::Value::Bytes(alloc::vec::Vec::new()),
                        Some(v) => {
                            let bytes = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&v)
                                .expect("rkyv encode")
                                .to_vec();
                            vos::value::Value::Bytes(bytes)
                        }
                    }
                }
            }
        } else {
            let ty_str = success_after_result
                .as_ref()
                .map(|t| quote!(#t).to_string().replace(' ', ""))
                .unwrap_or_else(|| "()".to_string());
            const PRIMITIVES: &[&str] = &[
                "()",
                "bool",
                "u8",
                "u16",
                "u32",
                "u64",
                "i32",
                "i64",
                "String",
                "Vec<u8>",
                "Vec<u32>",
                "Vec<String>",
            ];
            if PRIMITIVES.contains(&ty_str.as_str()) {
                quote! { reply.into() }
            } else {
                quote! {
                    {
                        let bytes = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&reply)
                            .expect("rkyv encode")
                            .to_vec();
                        vos::value::Value::Bytes(bytes)
                    }
                }
            }
        };

        // Deliver arm — different code for infallible vs fallible handlers
        let deliver_arm = if returns_result {
            quote! {
                #enum_name::#struct_name(msg) => {
                    match <#actor_name as vos::Message<#struct_name>>::handle(actor, msg, ctx).await {
                        Ok(reply) => {
                            ctx.__set_reply(#reply_to_value);
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
                    ctx.__set_reply(#reply_to_value);
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
            let extractions: Vec<_> = field_names
                .iter()
                .zip(field_types.iter())
                .map(|(name, ty)| {
                    let name_str = name.to_string();
                    let accessor = type_to_accessor(ty);
                    quote! {
                        let #name: #ty = msg.args.#accessor(#name_str)?;
                    }
                })
                .collect();
            quote! {
                #( #extractions )*
                Some(#enum_name::#struct_name(#struct_name { #( #field_names ),* }))
            }
        };
        from_msg_arms.push(quote! {
            #msg_name_str => { #from_msg_body }
        });

        // Stash data for the host-Client emission below. The
        // wire name is the original snake_case method ident; the
        // success type unwraps `Result<T, E>` to `T` (clients
        // surface the `Result` in their own `ClientError`-shaped
        // return type).
        let success_ty = match &method.sig.output {
            ReturnType::Default => None,
            ReturnType::Type(_, ty) => match result_ok_type(ty) {
                Some(inner) => {
                    if matches!(&inner, syn::Type::Tuple(t) if t.elems.is_empty()) {
                        None
                    } else {
                        Some(inner)
                    }
                }
                None => {
                    if matches!(ty.as_ref(), syn::Type::Tuple(t) if t.elems.is_empty()) {
                        None
                    } else {
                        Some(ty.as_ref().clone())
                    }
                }
            },
        };
        let client_args: Vec<(syn::Ident, syn::Type)> = field_names
            .iter()
            .cloned()
            .zip(field_types.iter().cloned())
            .collect();
        client_methods.push(ClientMethodInfo {
            wire_name: method_name.clone(),
            args: client_args,
            success_ty,
        });
    }

    // Constructor field metadata
    let ctor_field_metas: Vec<_> = constructor_params
        .iter()
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
            ///
            /// The return is a heap-boxed `Pin<Box<dyn Future>>` rather than
            /// a bare `async fn` future. The bare form's auto-generated state
            /// machine is sized to fit the **largest** arm (so it can hold any
            /// handler's future across an await), which on warm-restart stacks
            /// alongside `dispatch`'s own future and the caller's frame —
            /// large branchy handlers (e.g. `if/else if/else` chains) overflow
            /// the PVM's 64 KiB stack at frame allocation, faulting at
            /// `0xfffffff8`. Boxing moves the per-arm future onto the heap
            /// so only a fat pointer rides the stack; one extra alloc per
            /// dispatch is cheap relative to the failure mode.
            pub fn deliver<'a>(
                self,
                actor: &'a mut #actor_name,
                ctx: &'a mut vos::Context<#actor_name>,
            ) -> ::core::pin::Pin<vos::__alloc::boxed::Box<
                dyn ::core::future::Future<Output = bool> + 'a,
            >> {
                vos::__alloc::boxed::Box::pin(async move {
                    match self {
                        #( #deliver_arms )*
                    }
                })
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
                // The kind byte lives on the Actor trait — Phase 2's
                // #[actor(kind = "service")] sets it via the `KIND_BYTE`
                // associated const override.
                kind: <#actor_ty as vos::Actor>::KIND_BYTE,
                // Phase 6 — declared capability tokens. Defaults to
                // empty on the trait; overridden by #[actor(caps = [...])].
                caps: <#actor_ty as vos::Actor>::CAPS,
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
        let extractions: Vec<_> = constructor_params
            .iter()
            .map(|(name, ty)| {
                let name_str = name.to_string();
                let accessor = type_to_accessor(ty);
                quote! {
                    let #name: #ty = args.#accessor(#name_str)
                        .expect(concat!("missing init arg '", #name_str, "'"));
                }
            })
            .collect();
        let names: Vec<_> = constructor_params.iter().map(|(n, _)| n).collect();
        // PVM service path reads init args from storage. Worker/WASM
        // builds receive args via __vos_create_with_args; bare create()
        // is an error there.
        //
        // The cfg gate is target-based, not feature-based: every PVM
        // actor crate is built for `riscv64`, the service feature is
        // enabled on `vos` (not on the user crate). A previous version
        // checked `cfg(feature = "service")` against the *user* crate
        // — which never has that feature — and `__vos_create` always
        // hit the panic branch.
        quote! {
            fn __vos_create() -> Self {
                #[cfg(target_arch = "riscv64")]
                {
                    let args: vos::value::Args = vos::lifecycle::load(vos::lifecycle::INIT_KEY)
                        .expect("actor init args not found in storage");
                    #( #extractions )*
                    return Self::new(#( #names ),*);
                }
                #[cfg(not(target_arch = "riscv64"))]
                panic!(
                    "actor has constructor parameters — workers and WASM \
                     must be created with init args (see vos_extension_create / \
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
        let extractions: Vec<_> = constructor_params
            .iter()
            .map(|(name, ty)| {
                let name_str = name.to_string();
                let accessor = type_to_accessor(ty);
                quote! {
                    let #name: #ty = args.#accessor(#name_str)
                        .expect(concat!("missing init arg '", #name_str, "'"));
                }
            })
            .collect();
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

    // Preamble — always emitted. Worker/WASM entry blocks below
    // reference `_VOS_META_ENCODED` to embed the actor's metadata
    // into their respective `.vos_meta`-shaped exports. The PVM
    // entries (auto-emitted by `#[actor]`) compute their own meta.
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

    // PVM entry points (`_start`, `accumulate`, `.vos_meta`) are
    // auto-emitted by the `#[actor]` macro itself, gated on
    // `cfg(all(target_arch = "riscv64", feature = "bin"))` so:
    //   - host / worker / wasm builds skip them (different arch),
    //   - cross-actor lib deps skip them (`bin` feature off).
    // The user's lib.rs no longer needs `pvm_main!()`; one
    // `#[actor]` is the whole story.
    let pvm_entries = quote! {};

    // Worker entry points — native .so plugins (poll-based async ABI).
    //
    // The decl-macro itself is gated on vos's `worker` feature
    // (expands to nothing when worker glue isn't relevant for
    // this build target). Inside its expansion, the `vos_extension_*`
    // extern fns are further gated on the user crate's `bin`
    // feature, so cross-actor lib deps don't collide on those
    // symbols at link time. The `Extension` impl and
    // `ExtensionCtx` use stay unconditional so handler bodies can
    // reach `ctx.fetch` / etc. regardless.
    let worker_entries = quote! {
        vos::__vos_emit_worker_glue!(#actor_name, #enum_name);
    };

    // WASM cdylib entry points (`vos_wasm_*` extern fns). Same
    // bin-gating shape as worker_entries — the gate lives inside
    // the decl-macro so the surrounding scope sees the right
    // symbols regardless of `bin`.
    let wasm_entries = quote! {
        vos::__vos_emit_wasm_glue!(#actor_name, #enum_name);
    };

    // ── Unified Ref emission ────────────────────────────────────
    //
    // `{Actor}Ref` is the typed reference for both call sites:
    //
    //   - inside a PVM actor handler, with `ctx` as the invoker
    //     (`Context<A>: Invoker`),
    //   - from host code, with `&node` as the invoker (gated on
    //     vos's `std` feature where `&VosNode: Invoker` lives).
    //
    // Holds only a `ServiceId`, no_std + dep-free. Each method
    // takes `&mut impl Invoker` as its first parameter. Methods
    // are `async`; host callers wrap them with `vos::block_on`.
    let ref_struct_name = format_ident!("{}Ref", actor_name);
    let ref_methods_emit: Vec<proc_macro2::TokenStream> = client_methods
        .iter()
        .map(|m| {
            let method_ident = &m.wire_name;
            let wire_name = m.wire_name.to_string();
            let arg_decls: Vec<proc_macro2::TokenStream> = m
                .args
                .iter()
                .map(|(n, t)| {
                    quote! { #n: #t }
                })
                .collect();
            let with_calls: Vec<proc_macro2::TokenStream> = m
                .args
                .iter()
                .map(|(n, _)| {
                    let n_str = n.to_string();
                    quote! { .with(#n_str, #n) }
                })
                .collect();
            let return_ty: proc_macro2::TokenStream = match &m.success_ty {
                None => quote! { () },
                Some(t) => quote! { #t },
            };
            let value_ident = format_ident!("__value");
            let decode = client_decode_body(&m.success_ty, &value_ident);
            quote! {
                pub async fn #method_ident<__I: vos::actors::client::Invoker>(
                    &self,
                    __inv: &mut __I,
                    #( #arg_decls ),*
                ) -> core::result::Result<#return_ty, vos::actors::client::ClientError> {
                    use vos::Encode;
                    let __msg = vos::value::Msg::new(#wire_name)
                        #( #with_calls )*;
                    let __encoded = __msg.encode();
                    let mut __payload = alloc::vec::Vec::with_capacity(1 + __encoded.len());
                    __payload.push(vos::value::TAG_DYNAMIC);
                    __payload.extend_from_slice(&__encoded);
                    let #value_ident: vos::value::Value =
                        __inv.invoke(self.target, __payload).await?;
                    #decode
                }
            }
        })
        .collect();

    let ref_emission = quote! {
        #[derive(Copy, Clone)]
        pub struct #ref_struct_name {
            target: vos::abi::service::ServiceId,
        }

        impl #ref_struct_name {
            /// Bind to an explicit `ServiceId`. Cheap; copy freely.
            pub const fn at(target: vos::abi::service::ServiceId) -> Self {
                Self { target }
            }

            /// The `ServiceId` this ref points at.
            pub const fn id(&self) -> vos::abi::service::ServiceId {
                self.target
            }

            #( #ref_methods_emit )*
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
        #ref_emission
    };

    expanded.into()
}

/// Check if a type is a reference to `Context` or `PureContext`
/// (either `&Context<..>` / `&mut Context<..>`).
fn is_context_type(ty: &syn::Type) -> bool {
    if let syn::Type::Reference(r) = ty {
        return match r.elem.as_ref() {
            syn::Type::Path(p) => p
                .path
                .segments
                .last()
                .is_some_and(|s| s.ident == "Context" || s.ident == "PureContext"),
            _ => false,
        };
    }
    false
}

/// Parsed `#[actor(...)]` attribute payload.
struct ActorAttrs {
    /// Token stream for the actor's `Error` associated type — `()`
    /// when not specified.
    error_ty: proc_macro2::TokenStream,
    /// Encoded kind byte that lands in the `.vos_meta` blob — 0 for
    /// `Actor` (the default), 1 for `Service`.
    kind_byte: u8,
    /// Declared capability tokens (Phase 6). Each element is a
    /// string literal that goes into the `Actor::CAPS` slice.
    caps: Vec<String>,
}

/// Parse `#[actor(...)]` attributes.
///
/// Recognised keys:
/// - `error = Type` — custom Actor::Error type (default `()`)
/// - `kind = "actor" | "service"` — extension kind discriminant
///   (default `"actor"`). `"service"` opts into the long-running
///   shape introduced in Phase 3; in Phase 2 this byte is recorded
///   in metadata but the loader still treats every extension as
///   `Actor`.
fn parse_actor_attrs(attr: TokenStream) -> ActorAttrs {
    let default_err = quote! { () };
    let mut out = ActorAttrs {
        error_ty: default_err.clone(),
        kind_byte: 0,
        caps: Vec::new(),
    };
    if attr.is_empty() {
        return out;
    }
    let Ok(meta) = syn::parse::<syn::Meta>(attr) else {
        return out;
    };
    match meta {
        syn::Meta::NameValue(nv) if nv.path.is_ident("error") => {
            let val = &nv.value;
            out.error_ty = quote! { #val };
        }
        syn::Meta::NameValue(nv) if nv.path.is_ident("kind") => {
            if let syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(s),
                ..
            }) = &nv.value
            {
                out.kind_byte = parse_kind_str(&s.value());
            }
        }
        syn::Meta::List(list) => {
            let _ = list.parse_nested_meta(|meta| {
                if meta.path.is_ident("error") {
                    let value = meta.value()?;
                    out.error_ty = value.parse::<syn::Type>()?.to_token_stream();
                } else if meta.path.is_ident("kind") {
                    let value = meta.value()?;
                    let lit: syn::LitStr = value.parse()?;
                    out.kind_byte = parse_kind_str(&lit.value());
                } else if meta.path.is_ident("caps") {
                    // `caps = ["net.tcp.bind", ...]`
                    let value = meta.value()?;
                    let arr: syn::ExprArray = value.parse()?;
                    for elem in &arr.elems {
                        if let syn::Expr::Lit(syn::ExprLit {
                            lit: syn::Lit::Str(s),
                            ..
                        }) = elem
                        {
                            out.caps.push(s.value());
                        }
                    }
                }
                Ok(())
            });
        }
        _ => {}
    }
    out
}

fn parse_kind_str(s: &str) -> u8 {
    match s {
        "actor" => 0,
        "service" => 1,
        _ => 0, // unknown → fall back to actor; macro doesn't fail
                // at compile time so that older toolchains still
                // build crates that name future kinds.
    }
}

/// If `ty` is `Option<T>`, return the inner `T`. Otherwise `None`.
fn option_inner_type(ty: &syn::Type) -> Option<syn::Type> {
    let syn::Type::Path(p) = ty else { return None };
    let seg = p.path.segments.last()?;
    if seg.ident != "Option" {
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

/// Per-message data captured from the `#[messages] impl` block,
/// used by the host-side client emission. The dispatch path
/// uses its own per-message data; this is purely for the
/// generated `{Actor}Client` struct.
struct ClientMethodInfo {
    /// Wire name (snake_case ident from the original handler).
    wire_name: syn::Ident,
    /// Args excluding `self` and `Context<Self>`.
    args: Vec<(syn::Ident, syn::Type)>,
    /// Handler's success type — `T` if the handler returns `T`,
    /// or the inner `T` if the handler returns `Result<T, E>`.
    /// `None` means unit.
    success_ty: Option<syn::Type>,
}

/// Emit the body of a generated client method's reply-decoding
/// step. `value_ident` is the local that holds the
/// already-decoded `vos::value::Value`. The body is an
/// expression returning `Result<#success_ty, ClientError>`.
fn client_decode_body(
    success_ty: &Option<syn::Type>,
    value_ident: &syn::Ident,
) -> proc_macro2::TokenStream {
    use quote::ToTokens;
    let Some(ty) = success_ty else {
        return quote! { Ok(()) };
    };

    // `Option<T>`: the actor encodes `None` as
    // `Value::Bytes(empty)` (or `Value::Unit`) and `Some(v)` as
    // `Value::Bytes(rkyv-encoded v)`. Mirror that on decode.
    if let Some(inner) = option_inner_type(ty) {
        return quote! {
            match #value_ident {
                vos::value::Value::Unit => Ok(None),
                vos::value::Value::Bytes(b) if b.is_empty() => Ok(None),
                vos::value::Value::Bytes(b) => {
                    let mut av = vos::rkyv::util::AlignedVec::<16>::with_capacity(b.len());
                    av.extend_from_slice(&b);
                    let archived = unsafe {
                        vos::rkyv::access_unchecked::<<#inner as vos::rkyv::Archive>::Archived>(&av)
                    };
                    vos::rkyv::deserialize::<#inner, vos::rkyv::rancor::Error>(archived)
                        .map(Some)
                        .map_err(|_| vos::actors::client::ClientError::Decode)
                }
                other => Err(vos::actors::client::ClientError::UnexpectedReply(
                    alloc::format!("{:?}", other))),
            }
        };
    }

    let ty_str = ty.to_token_stream().to_string().replace(' ', "");
    match ty_str.as_str() {
        "()" => quote! { Ok(()) },
        "bool" => quote! {
            #value_ident.as_bool().ok_or_else(||
                vos::actors::client::ClientError::UnexpectedReply(
                    alloc::format!("{:?}", #value_ident)))
        },
        "u8" => quote! {
            #value_ident.as_u8().ok_or_else(||
                vos::actors::client::ClientError::UnexpectedReply(
                    alloc::format!("{:?}", #value_ident)))
        },
        "u16" => quote! {
            #value_ident.as_u16().ok_or_else(||
                vos::actors::client::ClientError::UnexpectedReply(
                    alloc::format!("{:?}", #value_ident)))
        },
        "u32" => quote! {
            #value_ident.as_u32().ok_or_else(||
                vos::actors::client::ClientError::UnexpectedReply(
                    alloc::format!("{:?}", #value_ident)))
        },
        "u64" => quote! {
            #value_ident.as_u64().ok_or_else(||
                vos::actors::client::ClientError::UnexpectedReply(
                    alloc::format!("{:?}", #value_ident)))
        },
        "i32" => quote! {
            #value_ident.as_i32().ok_or_else(||
                vos::actors::client::ClientError::UnexpectedReply(
                    alloc::format!("{:?}", #value_ident)))
        },
        "i64" => quote! {
            #value_ident.as_i64().ok_or_else(||
                vos::actors::client::ClientError::UnexpectedReply(
                    alloc::format!("{:?}", #value_ident)))
        },
        "String" => quote! {
            #value_ident.as_str().map(alloc::string::String::from).ok_or_else(||
                vos::actors::client::ClientError::UnexpectedReply(
                    alloc::format!("{:?}", #value_ident)))
        },
        "Vec<u8>" => quote! {
            match #value_ident {
                vos::value::Value::Bytes(b) => Ok(b),
                other => Err(vos::actors::client::ClientError::UnexpectedReply(
                    alloc::format!("{:?}", other))),
            }
        },
        "Vec<u32>" => quote! {
            #value_ident.as_list_u32().map(|s| s.to_vec()).ok_or_else(||
                vos::actors::client::ClientError::UnexpectedReply(
                    alloc::format!("{:?}", #value_ident)))
        },
        "Vec<String>" => quote! {
            #value_ident.as_list_str().map(|s| s.to_vec()).ok_or_else(||
                vos::actors::client::ClientError::UnexpectedReply(
                    alloc::format!("{:?}", #value_ident)))
        },
        // Anything else: assume rkyv-encoded inside Value::Bytes.
        _ => quote! {
            match #value_ident {
                vos::value::Value::Bytes(b) => {
                    let mut av = vos::rkyv::util::AlignedVec::<16>::with_capacity(b.len());
                    av.extend_from_slice(&b);
                    let archived = unsafe {
                        vos::rkyv::access_unchecked::<<#ty as vos::rkyv::Archive>::Archived>(&av)
                    };
                    vos::rkyv::deserialize::<#ty, vos::rkyv::rancor::Error>(archived)
                        .map_err(|_| vos::actors::client::ClientError::Decode)
                }
                other => Err(vos::actors::client::ClientError::UnexpectedReply(
                    alloc::format!("{:?}", other))),
            }
        },
    }
}

/// Map a Rust type to the corresponding `InitArgs` accessor method.
fn type_to_accessor(ty: &syn::Type) -> proc_macro2::TokenStream {
    let ty_str = quote!(#ty).to_string().replace(' ', "");
    match ty_str.as_str() {
        "u8" => quote! { get_u8 },
        "u16" => quote! { get_u16 },
        "u32" => quote! { get_u32 },
        "u64" => quote! { get_u64 },
        "i32" => quote! { get_i32 },
        "i64" => quote! { get_i64 },
        "bool" => quote! { get_bool },
        "String" => quote! { get_str },
        "Vec<u8>" => quote! { get_bytes },
        "Vec<u32>" => quote! { get_list_u32 },
        "Vec<String>" => quote! { get_list_str },
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
