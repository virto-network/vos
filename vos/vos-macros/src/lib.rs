//! Proc macros for `vos`.
//!
//! - `#[actor]` — rkyv derives + `impl Actor for X` using conventions
//! - `#[messages]` — message types, dispatch enum, entry points

use proc_macro::TokenStream;
use quote::{ToTokens, format_ident, quote};
use syn::spanned::Spanned;
use syn::visit_mut::VisitMut;
use syn::{FnArg, ImplItem, ItemImpl, ItemStruct, Pat, ReturnType, parse_macro_input};

const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x100000001b3;

fn fingerprint_bytes(hash: &mut u64, bytes: &[u8]) {
    for byte in bytes {
        *hash ^= u64::from(*byte);
        *hash = hash.wrapping_mul(FNV_PRIME);
    }
}

fn fingerprint_frame(hash: &mut u64, bytes: &[u8]) {
    fingerprint_bytes(hash, &(bytes.len() as u64).to_le_bytes());
    fingerprint_bytes(hash, bytes);
}

fn fingerprint_literal(hash: &mut u64, literal: proc_macro2::Literal) {
    let original = literal.to_string();
    let tokens = proc_macro2::TokenStream::from(proc_macro2::TokenTree::Literal(literal));
    let Ok(literal) = syn::parse2::<syn::Lit>(tokens) else {
        fingerprint_bytes(hash, &[0xff]);
        fingerprint_frame(hash, original.as_bytes());
        return;
    };

    match literal {
        syn::Lit::Str(value) => {
            fingerprint_bytes(hash, &[0]);
            fingerprint_frame(hash, value.value().as_bytes());
            fingerprint_frame(hash, value.suffix().as_bytes());
        }
        syn::Lit::ByteStr(value) => {
            fingerprint_bytes(hash, &[1]);
            fingerprint_frame(hash, &value.value());
            fingerprint_frame(hash, value.suffix().as_bytes());
        }
        syn::Lit::CStr(value) => {
            fingerprint_bytes(hash, &[2]);
            fingerprint_frame(hash, value.value().as_bytes_with_nul());
            fingerprint_frame(hash, value.suffix().as_bytes());
        }
        syn::Lit::Byte(value) => {
            fingerprint_bytes(hash, &[3, value.value()]);
            fingerprint_frame(hash, value.suffix().as_bytes());
        }
        syn::Lit::Char(value) => {
            fingerprint_bytes(hash, &[4]);
            fingerprint_bytes(hash, &(value.value() as u32).to_le_bytes());
            fingerprint_frame(hash, value.suffix().as_bytes());
        }
        syn::Lit::Int(value) => {
            fingerprint_bytes(hash, &[5]);
            fingerprint_frame(hash, value.base10_digits().as_bytes());
            fingerprint_frame(hash, value.suffix().as_bytes());
        }
        syn::Lit::Float(value) => {
            fingerprint_bytes(hash, &[6]);
            fingerprint_frame(hash, value.base10_digits().as_bytes());
            fingerprint_frame(hash, value.suffix().as_bytes());
        }
        syn::Lit::Bool(value) => fingerprint_bytes(hash, &[7, u8::from(value.value())]),
        syn::Lit::Verbatim(value) => {
            fingerprint_bytes(hash, &[0xff]);
            fingerprint_frame(hash, value.to_string().as_bytes());
        }
        _ => {
            fingerprint_bytes(hash, &[0xff]);
            fingerprint_frame(hash, original.as_bytes());
        }
    }
}

/// Hash a token tree structurally: whitespace, spans, and rustc's pretty
/// printer never enter the fingerprint. Delimiters and punctuation spacing do,
/// because they distinguish otherwise-ambiguous Rust syntax.
fn fingerprint_tokens(hash: &mut u64, tokens: proc_macro2::TokenStream) {
    use proc_macro2::{Delimiter, Spacing, TokenTree};

    for token in tokens {
        match token {
            TokenTree::Group(group) => {
                fingerprint_bytes(hash, &[0]);
                fingerprint_bytes(
                    hash,
                    &[match group.delimiter() {
                        Delimiter::Parenthesis => 0,
                        Delimiter::Brace => 1,
                        Delimiter::Bracket => 2,
                        Delimiter::None => 3,
                    }],
                );
                fingerprint_tokens(hash, group.stream());
                fingerprint_bytes(hash, &[0xff]);
            }
            TokenTree::Ident(ident) => {
                fingerprint_bytes(hash, &[1]);
                fingerprint_frame(hash, ident.to_string().as_bytes());
            }
            TokenTree::Punct(punct) => {
                fingerprint_bytes(hash, &[2]);
                fingerprint_bytes(hash, &(punct.as_char() as u32).to_le_bytes());
                fingerprint_bytes(
                    hash,
                    &[match punct.spacing() {
                        Spacing::Alone => 0,
                        Spacing::Joint => 1,
                    }],
                );
            }
            TokenTree::Literal(literal) => {
                fingerprint_bytes(hash, &[3]);
                fingerprint_literal(hash, literal);
            }
        }
    }
}

fn fingerprint_relevant_attrs(hash: &mut u64, attrs: &[syn::Attribute]) {
    for attr in attrs.iter().filter(|attr| {
        let path = attr.path();
        path.is_ident("rkyv")
            || path.is_ident("repr")
            || path.is_ident("cfg")
            || path.is_ident("cfg_attr")
            || path.is_ident("storage")
            || path.is_ident("crdt")
    }) {
        fingerprint_bytes(hash, &[0xa0]);
        fingerprint_tokens(hash, attr.meta.to_token_stream());
    }
}

/// Canonical fingerprint of the direct archived state schema.
///
/// This deliberately excludes the struct's name, visibility, documentation,
/// lint attributes, spans, and formatting. Field kind/order/name/type and the
/// attributes that can alter compiled/archive representation or framework
/// persistence remain part of the contract. Nested named types still require
/// an explicit state-version bump when their representation changes.
fn state_schema_fingerprint(input: &ItemStruct) -> u64 {
    let mut hash = FNV_OFFSET_BASIS;
    fingerprint_frame(&mut hash, b"vos/state-schema/v1");
    fingerprint_relevant_attrs(&mut hash, &input.attrs);

    // Generic parameter declarations are part of the type vocabulary used by
    // field types. Bounds and where clauses do not change the archived fields,
    // so hash the parameter kind/name (and const parameter type) only.
    for param in &input.generics.params {
        match param {
            syn::GenericParam::Lifetime(param) => {
                fingerprint_bytes(&mut hash, &[0xb0]);
                fingerprint_frame(&mut hash, param.lifetime.ident.to_string().as_bytes());
            }
            syn::GenericParam::Type(param) => {
                fingerprint_bytes(&mut hash, &[0xb1]);
                fingerprint_frame(&mut hash, param.ident.to_string().as_bytes());
            }
            syn::GenericParam::Const(param) => {
                fingerprint_bytes(&mut hash, &[0xb2]);
                fingerprint_frame(&mut hash, param.ident.to_string().as_bytes());
                fingerprint_tokens(&mut hash, param.ty.to_token_stream());
                if let Some(default) = &param.default {
                    fingerprint_bytes(&mut hash, &[1]);
                    fingerprint_tokens(&mut hash, default.to_token_stream());
                } else {
                    fingerprint_bytes(&mut hash, &[0]);
                }
            }
        }
    }

    match &input.fields {
        syn::Fields::Named(fields) => {
            fingerprint_bytes(&mut hash, &[0xc0]);
            for field in &fields.named {
                fingerprint_bytes(&mut hash, &[0xc1]);
                fingerprint_relevant_attrs(&mut hash, &field.attrs);
                fingerprint_frame(
                    &mut hash,
                    field
                        .ident
                        .as_ref()
                        .expect("named field")
                        .to_string()
                        .as_bytes(),
                );
                fingerprint_tokens(&mut hash, field.ty.to_token_stream());
            }
        }
        syn::Fields::Unnamed(fields) => {
            fingerprint_bytes(&mut hash, &[0xc2]);
            for field in &fields.unnamed {
                fingerprint_bytes(&mut hash, &[0xc3]);
                fingerprint_relevant_attrs(&mut hash, &field.attrs);
                fingerprint_tokens(&mut hash, field.ty.to_token_stream());
            }
        }
        syn::Fields::Unit => fingerprint_bytes(&mut hash, &[0xc4]),
    }
    hash
}

/// First paragraph of a doc comment: the `#[doc = "..."]` text joined
/// with spaces (each line trimmed), stopping at the first blank line.
/// Empty string when the item is undocumented. Feeds `ActorMeta.doc`
/// and per-message `MessageMeta.doc` in the `.vos_meta` blob so
/// `vosx <target>` help can show one-liners without the actor's Rust
/// source.
///
/// Works for both `///` line comments (one `#[doc]` attr per line) and
/// block `/** … */` / explicit multi-line `#[doc = "…"]` (one attr with
/// interior newlines): the blank-line break fires on interior newlines
/// too, and a leading `*` block-comment decoration is dropped.
fn first_doc_paragraph(attrs: &[syn::Attribute]) -> String {
    let mut lines: Vec<String> = Vec::new();
    for attr in attrs {
        if !attr.path().is_ident("doc") {
            continue;
        }
        let syn::Meta::NameValue(nv) = &attr.meta else {
            continue;
        };
        let syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Str(s),
            ..
        }) = &nv.value
        else {
            continue;
        };
        let value = s.value();
        // Split on interior newlines so a block `/** … */` comment or a
        // multi-line `#[doc = "…"]` breaks at the first blank line exactly
        // like consecutive `///` lines. `value.lines()` yields nothing for
        // an empty attr — the blank `///` case — so handle that after.
        let mut saw_line = false;
        for raw in value.lines() {
            saw_line = true;
            // Trim, then drop a leading `*` block-comment decoration
            // (` * text` → `text`, a bare ` *` separator → empty).
            let line = raw.trim();
            let line = line.strip_prefix('*').unwrap_or(line).trim();
            if line.is_empty() {
                if lines.is_empty() {
                    continue;
                }
                return lines.join(" ");
            }
            lines.push(line.to_string());
        }
        // An empty `///` attr (a blank line between `///` blocks) yields no
        // lines above; it is itself the paragraph break once we have content.
        if !saw_line && !lines.is_empty() {
            return lines.join(" ");
        }
    }
    lines.join(" ")
}

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
/// Stateful native extensions should declare a persisted-state version and
/// bump it whenever a nested archived type changes incompatibly:
/// ```ignore
/// #[actor(state_version = 1)]
/// struct Counter { config: CounterConfig }
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
    let mut input = parse_macro_input!(item as ItemStruct);
    let parsed = match parse_actor_attrs(attr.into()) {
        Ok(parsed) => parsed,
        Err(error) => return error.to_compile_error().into(),
    };
    // Validation and code generation strip framework-owned field attributes;
    // retain the declared form for the persistence fingerprint.
    let state_schema = input.clone();
    let state_fields = match prepare_state_fields(&mut input, parsed.crdt) {
        Ok(fields) => fields,
        Err(error) => return error.to_compile_error().into(),
    };
    let storage_fields = extract_storage_fields(&mut input);
    let name = &input.ident;
    let msg_enum = format_ident!("{}Msg", name);

    // Parse optional attributes:
    //   #[actor]                       — defaults to `Error = ()`
    //   #[actor(error = Type)]         — custom error type for Actor::Error
    // A proof exists only for the witness-delivered, refine-pure Task
    // shape — `provable` on anything else is a category error, not a
    // flag to ignore.
    if parsed.provable && parsed.task_buf.is_none() {
        return syn::Error::new(
            proc_macro2::Span::call_site(),
            "#[actor(provable)] requires `task`: a provable actor is a \
             witness-delivered Task — write #[actor(task, provable)]",
        )
        .to_compile_error()
        .into();
    }
    if parsed.agent && parsed.task_buf.is_some() {
        return syn::Error::new(
            proc_macro2::Span::call_site(),
            "#[actor(agent)] and #[actor(task)] select different execution ABIs",
        )
        .to_compile_error()
        .into();
    }
    let agent_actor = parsed.agent;
    let error_ty = parsed.error_ty;
    let provable = parsed.provable;
    let role_ty = parsed.role_ty;
    let default_role = parsed.default_role;
    let space_role_map = parsed.space_role_map;
    let crdt = parsed.crdt;
    let state_version = parsed.state_version;

    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let vis = &input.vis;
    let attrs = &input.attrs;
    // First paragraph of the struct's `///` doc → `Actor::DOC` → the
    // actor-level line in `.vos_meta` (shown by `vosx <target>` help).
    let actor_doc = first_doc_paragraph(&input.attrs);
    let fields = &input.fields;
    let state_fingerprint = state_schema_fingerprint(&state_schema);
    // `VOSXST02` snapshots written before the canonical schema encoder used
    // quote's display rendering. Keep this exact declaration-specific value as
    // a one-way migration path; all newly-written snapshots use the canonical
    // fingerprint above.
    let legacy_state_shape = quote! { #name #impl_generics #fields }.to_string();
    let mut legacy_state_fingerprint = FNV_OFFSET_BASIS;
    fingerprint_bytes(&mut legacy_state_fingerprint, legacy_state_shape.as_bytes());

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
        syn::Fields::Unnamed(_) => {
            unreachable!("prepare_state_fields rejects tuple actor structs")
        }
    };

    // PVM entry-point block — emitted only on riscv64 actor builds
    // with the `bin` feature on. The macro emits the single refine
    // entry (`_start`, PC=0) here, so the user's lib.rs needs neither
    // a `pvm_main!()` invocation nor a separate `main.rs`. The helper
    // symbol `__VOS_ACTOR_META_ENCODED` carries a `__VOS_` prefix so
    // it doesn't shadow anything in the user's module.
    //
    // For `#[actor(task)]` blobs, `_start` is the witness-delivered
    // task entry instead, and a `__VOS_WITNESS` buffer is emitted for
    // the invoker (and the prover) to patch `(state, msg)` into — the
    // same symbol/patching convention as `vos::zk::witness_buffer!`.
    let entry = match parsed.task_buf {
        Some(task_buf) => quote! {
            #[cfg(all(target_arch = "riscv64", feature = "bin"))]
            #[unsafe(no_mangle)]
            static mut __VOS_WITNESS: [u8; #task_buf] = [0u8; #task_buf];

            #[cfg(all(target_arch = "riscv64", feature = "bin"))]
            #[unsafe(no_mangle)]
            pub extern "C" fn _start() {
                vos::run_task_entry::<#name>(
                    ::core::ptr::addr_of!(__VOS_WITNESS) as *const u8,
                    #task_buf,
                );
            }
        },
        None => quote! {
            #[cfg(all(target_arch = "riscv64", feature = "bin"))]
            #[unsafe(no_mangle)]
            pub extern "C" fn _start(a0: u64, a1: u64, a2: u64, a3: u64) {
                vos::run_actor_entry::<#name>(a0, a1, a2, a3);
            }
        },
    };
    let agent_field_metas = state_fields.fields.iter().map(|field| {
        let name = field.ident.to_string();
        let ty = &field.ty;
        let persistence = field.persistence.tokens();
        quote! {
            vos::agent::schema::FieldMeta {
                name: #name,
                // Source spelling alone lets two modules reuse an alias name
                // for different codecs. Include its declaration context in
                // the signed layout identity. Explicit state migration is
                // still required when the meaning of that named codec changes.
                codec: concat!(module_path!(), "::", stringify!(#ty)),
                persistence: #persistence,
            }
        }
    });
    let agent_entry_kind = if parsed.task_buf.is_some() {
        quote! { vos::agent::schema::ExecutionEntryKind::Task }
    } else if agent_actor {
        quote! { vos::agent::schema::ExecutionEntryKind::AgentActor }
    } else {
        quote! { vos::agent::schema::ExecutionEntryKind::ServiceActor }
    };
    let agent_uses_storage = !storage_fields.is_empty();
    let pvm_entries = quote! {
        #entry

        #[cfg(all(target_arch = "riscv64", feature = "bin"))]
        const __VOS_ACTOR_META_ENCODED: ([u8; 16384], usize) =
            vos::metadata::encode::<16384>(
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

        #[cfg(all(target_arch = "riscv64", feature = "bin"))]
        const __VOS_AGENT_SCHEMA_ENCODED: ([u8; 16384], usize) =
            vos::agent::schema::encode_with_entry::<16384>(
                &vos::agent::schema::SchemaMeta {
                    uses_storage: #agent_uses_storage,
                    fields: &[ #( #agent_field_metas ),* ],
                    methods: <#msg_enum>::AGENT_METHODS,
                },
                #agent_entry_kind,
            );

        #[cfg(all(target_arch = "riscv64", feature = "bin"))]
        #[unsafe(link_section = ".vos_agent")]
        #[used]
        static _VOS_AGENT_SCHEMA: [u8; __VOS_AGENT_SCHEMA_ENCODED.1] = {
            let (src, len) = __VOS_AGENT_SCHEMA_ENCODED;
            let mut out = [0u8; __VOS_AGENT_SCHEMA_ENCODED.1];
            let mut i = 0;
            while i < len { out[i] = src[i]; i += 1; }
            out
        };
    };

    // `#[storage]` fields: point each handle at its key prefix after
    // every create/decode. Handles archive as units, so this is the
    // only place the prefix exists — actors without storage fields get
    // the trait's default no-op.
    let init_storage = if storage_fields.is_empty() {
        quote! {}
    } else {
        let inits = storage_fields.iter().map(|f| {
            let ident = &f.ident;
            let lit = syn::LitByteStr::new(&f.prefix, proc_macro2::Span::call_site());
            match &f.domains {
                Some((leaf, node)) => {
                    let leaf =
                        syn::LitByteStr::new(leaf.as_bytes(), proc_macro2::Span::call_site());
                    let node =
                        syn::LitByteStr::new(node.as_bytes(), proc_macro2::Span::call_site());
                    quote! { self.#ident.__init_with_domains(#lit, #leaf, #node); }
                }
                None => quote! { self.#ident.__init(#lit); },
            }
        });
        quote! {
            #[doc(hidden)]
            fn __init_storage(&mut self) {
                #( #inits )*
            }
        }
    };

    let init_crdt_fields = if state_fields.merge.is_empty() {
        quote! {}
    } else {
        let actor_name = name.to_string();
        let inits = state_fields.merge.iter().map(|ident| {
            let field_name = ident.to_string();
            quote! {
                vos::crdt::Field::__vos_init(&mut self.#ident, #actor_name, #field_name);
            }
        });
        quote! {
            #[doc(hidden)]
            fn __init_crdt_fields(&mut self) {
                #( #inits )*
            }
        }
    };

    let merge_crdt = if state_fields.merge.is_empty() {
        quote! {}
    } else {
        let merge_fields = state_fields.merge.iter().map(|ident| {
            quote! { merged.#ident.merge(&other.#ident)?; }
        });
        let check_constants = state_fields.constants.iter().map(|ident| {
            quote! {
                if vos::Encode::encode(&self.#ident) != vos::Encode::encode(&other.#ident) {
                    return core::result::Result::Err(vos::crdt::Error::ConstMismatch);
                }
            }
        });
        quote! {
            #[doc(hidden)]
            fn __merge_crdt(
                &mut self,
                other: &Self,
            ) -> core::result::Result<(), vos::crdt::Error> {
                #( #check_constants )*
                let mut merged = <Self as vos::Decode>::decode(&vos::Encode::encode(self));
                #( #merge_fields )*
                *self = merged;
                <Self as vos::Actor>::__init_crdt_fields(self);
                core::result::Result::Ok(())
            }
        }
    };

    let lane_fields = |lane: PersistencePlan| {
        state_fields
            .fields
            .iter()
            .filter(|field| field.persistence == lane)
            .map(|field| field.ident.clone())
            .collect::<Vec<_>>()
    };
    let linear_fields = lane_fields(PersistencePlan::Linear);
    let merge_fields = lane_fields(PersistencePlan::Merge);
    let local_fields = lane_fields(PersistencePlan::Local);
    let mut view_generics = input.generics.clone();
    view_generics.params.insert(
        0,
        syn::GenericParam::Lifetime(syn::parse_quote!('__vos_agent_view)),
    );
    let (view_impl_generics, view_ty_generics, view_where_clause) = view_generics.split_for_impl();
    let lane_view = |suffix: &str,
                     mutable: &[PersistencePlan],
                     immutable: &[PersistencePlan],
                     shared_receiver: bool| {
        let view_name = format_ident!("__Vos{}{}View", name, suffix);
        let selected = state_fields
            .fields
            .iter()
            .filter(|field| {
                mutable.contains(&field.persistence) || immutable.contains(&field.persistence)
            })
            .collect::<Vec<_>>();
        let declarations = selected.iter().map(|field| {
            let ident = &field.ident;
            let ty = &field.ty;
            if mutable.contains(&field.persistence) {
                quote! { #ident: &'__vos_agent_view mut #ty }
            } else {
                quote! { #ident: &'__vos_agent_view #ty }
            }
        });
        let initializers = selected.iter().map(|field| {
            let ident = &field.ident;
            if mutable.contains(&field.persistence) {
                quote! { #ident: &mut actor.#ident }
            } else {
                quote! { #ident: &actor.#ident }
            }
        });
        let receiver = if shared_receiver {
            quote! { &'__vos_agent_view #name #ty_generics }
        } else {
            quote! { &'__vos_agent_view mut #name #ty_generics }
        };
        let marker = if shared_receiver {
            quote! { core::marker::PhantomData<&'__vos_agent_view #name #ty_generics> }
        } else {
            quote! { core::marker::PhantomData<&'__vos_agent_view mut #name #ty_generics> }
        };
        quote! {
            #[doc(hidden)]
            struct #view_name #view_generics {
                #( #declarations, )*
                __marker: #marker,
            }

            impl #view_impl_generics #view_name #view_ty_generics #view_where_clause {
                #[doc(hidden)]
                fn __new(actor: #receiver) -> Self {
                    Self {
                        #( #initializers, )*
                        __marker: core::marker::PhantomData,
                    }
                }
            }
        }
    };
    let agent_lane_views = agent_actor
        .then(|| {
            [
                lane_view(
                    "SharedQuery",
                    &[],
                    &[
                        PersistencePlan::Linear,
                        PersistencePlan::Merge,
                        PersistencePlan::Constant,
                    ],
                    true,
                ),
                lane_view(
                    "LocalQuery",
                    &[],
                    &[
                        PersistencePlan::Linear,
                        PersistencePlan::Merge,
                        PersistencePlan::Local,
                        PersistencePlan::Constant,
                    ],
                    true,
                ),
                lane_view(
                    "Linear",
                    &[PersistencePlan::Linear],
                    &[PersistencePlan::Merge, PersistencePlan::Constant],
                    false,
                ),
                lane_view(
                    "Merge",
                    &[PersistencePlan::Merge],
                    &[PersistencePlan::Constant],
                    false,
                ),
                lane_view(
                    "Local",
                    &[PersistencePlan::Local],
                    &[
                        PersistencePlan::Linear,
                        PersistencePlan::Merge,
                        PersistencePlan::Constant,
                    ],
                    false,
                ),
            ]
        })
        .into_iter()
        .flatten();
    let load_lane = |argument: &syn::Ident, fields: &[syn::Ident]| {
        let count = fields.len() as u16;
        quote! {
            if let Some(bytes) = #argument.filter(|bytes| !bytes.is_empty()) {
                let mut reader = vos::lifecycle::AgentLaneReader::new(bytes, #count)?;
                #( actor.#fields = reader.read()?; )*
                if !reader.finish() {
                    return None;
                }
            }
        }
    };
    let linear_argument = format_ident!("linear");
    let merge_argument = format_ident!("merge");
    let local_argument = format_ident!("local");
    let load_linear = load_lane(&linear_argument, &linear_fields);
    let load_merge = load_lane(&merge_argument, &merge_fields);
    let load_local = load_lane(&local_argument, &local_fields);
    let save_lane = |fields: &[syn::Ident]| {
        let count = fields.len() as u16;
        quote! {
            let mut writer = vos::lifecycle::AgentLaneWriter::new(#count);
            #( writer.push(&self.#fields); )*
            writer.finish()
        }
    };
    let save_linear = save_lane(&linear_fields);
    let save_merge = save_lane(&merge_fields);
    let save_local = save_lane(&local_fields);
    let agent_state = quote! {
        #[doc(hidden)]
        fn __load_agent_state(
            #linear_argument: Option<&[u8]>,
            #merge_argument: Option<&[u8]>,
            #local_argument: Option<&[u8]>,
        ) -> Option<Self> {
            let mut actor = Self::create();
            #load_linear
            #load_merge
            #load_local
            <Self as vos::Actor>::__init_storage(&mut actor);
            <Self as vos::Actor>::__init_crdt_fields(&mut actor);
            Some(actor)
        }

        #[doc(hidden)]
        fn __save_agent_lane(
            &self,
            lane: vos::agent::StateLane,
        ) -> alloc::vec::Vec<u8> {
            match lane {
                vos::agent::StateLane::Linear => { #save_linear }
                vos::agent::StateLane::Merge => { #save_merge }
                vos::agent::StateLane::Local => { #save_local }
            }
        }
    };

    // `#[storage(committed)]` fields: fold their SMT roots (declaration
    // order — part of the upgrade contract) with the state-blob hash
    // into the composite root `anchor_kind 0x02` anchors. Actors with
    // no committed fields keep the trait default (`None` → 0x01).
    let committed: Vec<&syn::Ident> = storage_fields
        .iter()
        .filter(|f| f.committed)
        .map(|f| &f.ident)
        .collect();
    let committed_root = if committed.is_empty() {
        quote! {}
    } else {
        quote! {
            #[doc(hidden)]
            const COMMITTED: bool = true;

            #[doc(hidden)]
            fn __committed_root(&self, state_hash: &[u8; 32]) -> Option<[u8; 32]> {
                Some(vos::zk::state::composite_fold(
                    state_hash,
                    [ #( self.#committed.root() ),* ],
                ))
            }
        }
    };
    let default_mutation_mode = state_fields.default_mutation_mode.tokens();
    let agent_message_assert = agent_actor.then(|| {
        quote! {
            const _: () = {
                fn __vos_require_agent_messages<T: vos::agent::schema::AgentMessageSet>() {}
                let _ = __vos_require_agent_messages::<#msg_enum> as fn();
            };
        }
    });

    let expanded = quote! {
        #struct_def

        #( #agent_lane_views )*

        impl #impl_generics vos::Actor for #name #ty_generics #where_clause {
            type Error = #error_ty;
            type Message = #msg_enum;

            #[doc(hidden)]
            const AGENT_ACTOR_SOURCE: bool = #agent_actor;

            // Per-agent ACL framework — sentinel defaults so
            // actors that haven't declared their own `Role` enum
            // keep compiling. `NoRoles::Any` admits every check;
            // Actors opt in via
            // `#[actor(role = MyRole, default_role = ...,
            // space_role_map = ...)]`.
            type Role = #role_ty;
            const DEFAULT_ROLE: <Self as vos::Actor>::Role = #default_role;
            const SPACE_ROLE_MAP: vos::SpaceRoleMap<<Self as vos::Actor>::Role> = #space_role_map;

            // Provable-program publication mark; defaulted false on
            // the trait, set by `#[actor(task, provable)]`.
            const PROVABLE: bool = #provable;

            // One-line actor description from the struct's `///` doc.
            const DOC: &'static str = #actor_doc;

            const CRDT: bool = #crdt;

            const STATE_SCHEMA_VERSION: u64 = #state_version;
            const STATE_SCHEMA_FINGERPRINT: u64 = #state_fingerprint;
            const STATE_SCHEMA_LEGACY_FINGERPRINTS: &'static [u64] = &[#legacy_state_fingerprint];

            #[doc(hidden)]
            const DEFAULT_MUTATION_MODE: vos::agent::MethodMode = #default_mutation_mode;

            fn create() -> Self {
                Self::__vos_create()
            }

            #init_storage

            #init_crdt_fields

            #merge_crdt

            #agent_state

            #committed_root

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

        #agent_message_assert

        #pvm_entries
    };

    expanded.into()
}

fn path_is_self(expression: &syn::Expr) -> bool {
    matches!(
        expression,
        syn::Expr::Path(path)
            if path.qself.is_none()
                && path.path.leading_colon.is_none()
                && path.path.segments.len() == 1
                && path.path.segments[0].ident == "self"
    )
}

fn tokens_contain_self(tokens: proc_macro2::TokenStream) -> bool {
    use proc_macro2::TokenTree;

    tokens.into_iter().any(|token| match token {
        TokenTree::Ident(ident) => ident == "self",
        TokenTree::Group(group) => tokens_contain_self(group.stream()),
        TokenTree::Punct(_) | TokenTree::Literal(_) => false,
    })
}

/// Rewrite an explicit agent handler onto the mode-specific field view.
///
/// A field place becomes `(*__vos_agent_lane_view.field)`, so an immutable
/// view field is rejected by rustc when used as an assignment target. Bare
/// `self` and helper-method receivers become the view itself; helpers must be
/// written against an explicit view API rather than regaining the full actor.
struct AgentLaneBodyRewriter {
    error: Option<syn::Error>,
}

impl VisitMut for AgentLaneBodyRewriter {
    fn visit_expr_mut(&mut self, expression: &mut syn::Expr) {
        match expression {
            syn::Expr::Field(field) if path_is_self(&field.base) => {
                let member = field.member.clone();
                *expression = syn::parse_quote!((*__vos_agent_lane_view.#member));
            }
            syn::Expr::Path(path)
                if path.qself.is_none()
                    && path.path.leading_colon.is_none()
                    && path.path.segments.len() == 1
                    && path.path.segments[0].ident == "self" =>
            {
                path.path.segments[0].ident =
                    syn::Ident::new("__vos_agent_lane_view", path.path.segments[0].ident.span());
            }
            syn::Expr::Macro(expression_macro) => {
                if tokens_contain_self(expression_macro.mac.tokens.clone()) {
                    self.error.get_or_insert_with(|| {
                        syn::Error::new_spanned(
                            expression_macro,
                            "explicit agent handlers cannot hide `self` lane access inside a macro; move the field access outside the macro",
                        )
                    });
                }
            }
            _ => syn::visit_mut::visit_expr_mut(self, expression),
        }
    }
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
/// - `_start` PVM entry point (PC=0, refine)
/// - `.vos_meta` section with actor metadata
#[proc_macro_attribute]
pub fn messages(attr: TokenStream, item: TokenStream) -> TokenStream {
    let (emit_extension_reference, agent_messages) = if attr.is_empty() {
        (false, false)
    } else {
        let mode = parse_macro_input!(attr as syn::Ident);
        if mode == "extension" {
            (true, false)
        } else if mode == "agent" {
            (false, true)
        } else {
            return syn::Error::new_spanned(
                mode,
                "expected #[messages], #[messages(agent)], or #[messages(extension)]",
            )
            .to_compile_error()
            .into();
        }
    };
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
    let mut attested_method_impls = Vec::new();
    let mut enum_variants = Vec::new();
    let mut deliver_arms = Vec::new();
    let mut is_query_arms = Vec::new();
    let mut from_msg_arms = Vec::new();
    let mut meta_messages: Vec<proc_macro2::TokenStream> = Vec::new();
    // Method names declared with `#[msg(cli)]`. Emitted into the
    // `ActorMeta.cli_methods` list and (via the trailing-append
    // section in the binary meta blob) cross-referenced by the
    // decoder to set `ParsedMessage.exposed_to_cli`.
    let mut cli_method_names: Vec<proc_macro2::TokenStream> = Vec::new();
    // One arm per `#[msg(role = X)]` variant for the
    // emitted `required_role(&self) -> Option<u8>` method. Other
    // variants emit a `None` arm so the dispatch boundary skips
    // the role check.
    let mut required_role_arms: Vec<proc_macro2::TokenStream> = Vec::new();
    let mut attested_arms: Vec<proc_macro2::TokenStream> = Vec::new();
    let mut required_space_role_arms: Vec<proc_macro2::TokenStream> = Vec::new();
    let mut required_capability_arms: Vec<proc_macro2::TokenStream> = Vec::new();
    let mut agent_method_metas: Vec<proc_macro2::TokenStream> = Vec::new();
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

        let msg_attr = method.attrs.iter().find(|a| a.path().is_ident("msg"));
        let is_msg = msg_attr.is_some();
        // Parse `#[msg(...)]` arguments. Two shapes recognised:
        //
        //   #[msg(cli)]          — bare ident; exposes handler to
        //                          the vosx CLI dispatcher.
        //   #[msg(role = EXPR)]  — requires the caller's effective
        //                          role to be `>=` EXPR before the
        //                          handler runs. EXPR is parsed as
        //                          a syn::Expr so paths like
        //                          `MyRole::Maintainer` work.
        //
        // Unknown keys are tolerated (their fallthrough arm returns Ok) so
        // future attrs land without breaking older actors — but a malformed
        // value on a KNOWN key (an out-of-range `timeout_ms`, a `role` that
        // isn't an expression) fails loudly with a compile error rather than
        // silently defaulting.
        let mut exposed_to_cli = false;
        let mut role_expr: Option<syn::Expr> = None;
        let mut space_role_expr: Option<syn::Expr> = None;
        let mut capability: Option<syn::LitStr> = None;
        let mut is_attested = false;
        let mut execution_mode: Option<syn::Ident> = None;
        // `#[msg(timeout_ms = N)]` — per-handler invoke timeout in ms
        // (0 = client default), recorded in `.vos_meta` so the dispatcher
        // waits long enough for a legitimately slow handler.
        let mut timeout_ms: u32 = 0;
        // `#[msg(job)]` — the handler is a long-running job *begin*: it must
        // return a `u64` job id (enforced below), and gets `mode = 1` in
        // `.vos_meta` so the dispatcher drives poll → stream → release.
        let mut is_job = false;
        // Only `#[msg(...)]` with parenthesized args is parsed; bare `#[msg]`
        // has none (and `parse_nested_meta` would error on the missing parens).
        if let Some(attr) = msg_attr
            && matches!(attr.meta, syn::Meta::List(_))
        {
            if let Err(e) = attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("cli") {
                    exposed_to_cli = true;
                    return Ok(());
                }
                if meta.path.is_ident("job") {
                    is_job = true;
                    return Ok(());
                }
                if meta.path.is_ident("attested") {
                    is_attested = true;
                    return Ok(());
                }
                for name in [
                    "query",
                    "linearizable",
                    "local_query",
                    "linear",
                    "merge",
                    "local",
                ] {
                    if meta.path.is_ident(name) {
                        if execution_mode.is_some() {
                            return Err(meta.error("select exactly one actor execution mode"));
                        }
                        execution_mode = Some(syn::Ident::new(name, meta.path.span()));
                        return Ok(());
                    }
                }
                if meta.path.is_ident("role") {
                    let value = meta.value()?;
                    let expr: syn::Expr = value.parse()?;
                    role_expr = Some(expr);
                    return Ok(());
                }
                if meta.path.is_ident("timeout_ms") {
                    let value = meta.value()?;
                    let lit: syn::LitInt = value.parse()?;
                    timeout_ms = lit.base10_parse()?;
                    return Ok(());
                }
                if meta.path.is_ident("space_role") {
                    let value = meta.value()?;
                    let expr: syn::Expr = value.parse()?;
                    space_role_expr = Some(expr);
                    return Ok(());
                }
                if meta.path.is_ident("capability") {
                    let value = meta.value()?;
                    let name: syn::LitStr = value.parse()?;
                    if !valid_capability_name(&name.value()) {
                        return Err(syn::Error::new_spanned(
                            name,
                            "capability must be 1..=128 lowercase ASCII characters: [a-z][a-z0-9._-]*",
                        ));
                    }
                    capability = Some(name);
                    return Ok(());
                }
                Ok(())
            }) {
                return e.to_compile_error().into();
            }
        }

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

        if is_attested && is_job {
            return syn::Error::new_spanned(
                &method.sig,
                "#[msg(attested)] must complete in one execution slice and cannot be #[msg(job)]",
            )
            .to_compile_error()
            .into();
        }
        if capability.is_some() && (role_expr.is_some() || space_role_expr.is_some()) {
            return syn::Error::new_spanned(
                &method.sig,
                "#[msg(capability = \"...\")] cannot be combined with role or space_role",
            )
            .to_compile_error()
            .into();
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
        let explicit_execution_mode = execution_mode.is_some();
        let effective_lane_view_mode = agent_messages
            .then(|| {
                execution_mode
                    .as_ref()
                    .map(ToString::to_string)
                    .or_else(|| is_query.then(|| "query".to_owned()))
            })
            .flatten();
        let agent_lane_view = effective_lane_view_mode.as_deref().map(|mode| {
            let suffix = match mode {
                "query" | "linearizable" => "SharedQuery",
                "local_query" => "LocalQuery",
                "linear" => "Linear",
                "merge" => "Merge",
                "local" => "Local",
                _ => unreachable!("execution modes were validated while parsing"),
            };
            format_ident!("__Vos{}{}View", actor_name, suffix)
        });
        let agent_execution_mode = match execution_mode.as_ref().map(ToString::to_string) {
            Some(mode) if mode == "query" && is_query => {
                quote! { vos::agent::MethodMode::Query }
            }
            Some(mode) if mode == "linearizable" && is_query => {
                quote! { vos::agent::MethodMode::LinearizableQuery }
            }
            Some(mode) if mode == "local_query" && is_query => {
                quote! { vos::agent::MethodMode::LocalQuery }
            }
            Some(mode) if mode == "linear" && !is_query => {
                quote! { vos::agent::MethodMode::Linear }
            }
            Some(mode) if mode == "merge" && !is_query => {
                quote! { vos::agent::MethodMode::Merge }
            }
            Some(mode) if mode == "local" && !is_query => {
                quote! { vos::agent::MethodMode::Local }
            }
            Some(_) => {
                return syn::Error::new_spanned(
                    &method.sig,
                    "query/linearizable modes require &self; linear/merge/local modes require &mut self",
                )
                .to_compile_error()
                .into();
            }
            None if is_query => quote! { vos::agent::MethodMode::Query },
            None => quote! { <#actor_name as vos::Actor>::DEFAULT_MUTATION_MODE },
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
                pub struct #struct_name;
            }
        } else {
            quote! {
                pub struct #struct_name {
                    #( pub #field_names: #field_types ),*
                }
            }
        };
        msg_structs.push(msg_struct);

        // Generate Message impl
        let mut body = method.block.clone();
        if agent_lane_view.is_some() {
            let mut rewriter = AgentLaneBodyRewriter { error: None };
            rewriter.visit_block_mut(&mut body);
            if let Some(error) = rewriter.error {
                return error.to_compile_error().into();
            }
        }
        let field_binds = if field_names.is_empty() {
            quote! { let _ = msg; }
        } else {
            quote! { let #struct_name { #( #field_names ),* } = msg; }
        };

        let handler_body = if let Some(view) = agent_lane_view {
            quote! {
                #field_binds
                #[allow(unused_mut)]
                let mut __vos_agent_lane_view = #view::__new(self);
                #body
            }
        } else {
            quote! {
                #field_binds
                #body
            }
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
        // the canonical reply uses an explicit discriminant inside
        // `Value::Bytes`: `[0]` for `None`, `[1] ++ rkyv(T)` for `Some`.
        // The tag is required because rkyv encodes zero-sized values to zero
        // bytes, so an empty/non-empty convention is not injective.
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

        // Canonical return-type string for the schema (`Result<T, E>`
        // already unwrapped to `T` by `success_after_result`; unit /
        // no-return renders `()`). Mirrors the reply-encoding branch so
        // the label matches what actually lands on the wire.
        let returns_str = success_after_result
            .as_ref()
            .map(ty_string)
            .unwrap_or_else(|| "()".to_string());

        // A `#[msg(job)]` handler is a job *begin* — it must return a `u64`
        // job id (or `Result<u64, _>`, already unwrapped above) for the
        // dispatcher's job driver to poll on.
        if is_job && returns_str != "u64" {
            return syn::Error::new_spanned(
                &method.sig,
                "#[msg(job)] handler must return u64 (the job id)",
            )
            .to_compile_error()
            .into();
        }

        // Reply-encoding step: how to convert the handler's
        // returned value into the `Value` we hand to
        // `ctx.__set_reply`. Three shapes, in order:
        //
        // 1. `Option<T>` — match Some/None and emit the tagged canonical
        //    `Value::Bytes` representation described above.
        // 2. Primitives / strings / `Vec<u8|u32|String>` — these
        //    all impl `Into<Value>` already, so `reply.into()`.
        // 3. Anything else — assume a user rkyv-able struct and
        //    encode into `Value::Bytes`.
        let reply_to_value = if option_inner.is_some() {
            quote! {
                {
                    let __reply = reply;
                    match __reply {
                        None => vos::value::Value::Bytes(alloc::vec![0]),
                        Some(v) => {
                            let bytes = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&v)
                                .expect("rkyv encode")
                                .to_vec();
                            let mut tagged = alloc::vec::Vec::with_capacity(1 + bytes.len());
                            tagged.push(1);
                            tagged.extend_from_slice(&bytes);
                            vos::value::Value::Bytes(tagged)
                        }
                    }
                }
            }
        } else if success_after_result.as_ref().is_some_and(is_byte_array) {
            // `[u8; N]` return → raw bytes, symmetric with the arg path.
            quote! { vos::value::Value::Bytes(reply.to_vec()) }
        } else {
            let ty_str = success_after_result
                .as_ref()
                .map(ty_string)
                .unwrap_or_else(|| "()".to_string());
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

        if is_attested {
            let claim_ty: syn::Type = success_after_result
                .clone()
                .unwrap_or_else(|| syn::parse_quote!(()));
            let claim_to_value = if option_inner.is_some() {
                quote! {
                    match claim {
                        None => vos::value::Value::Bytes(alloc::vec![0]),
                        Some(value) => {
                            let bytes = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(value)
                                .expect("rkyv encode")
                                .to_vec();
                            let mut tagged = alloc::vec::Vec::with_capacity(1 + bytes.len());
                            tagged.push(1);
                            tagged.extend_from_slice(&bytes);
                            vos::value::Value::Bytes(tagged)
                        }
                    }
                }
            } else if success_after_result.as_ref().is_some_and(is_byte_array) {
                quote! { vos::value::Value::Bytes(claim.to_vec()) }
            } else if PRIMITIVES.contains(&returns_str.as_str()) {
                quote! { (*claim).clone().into() }
            } else {
                quote! {
                    {
                        let bytes = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(claim)
                            .expect("rkyv encode")
                            .to_vec();
                        vos::value::Value::Bytes(bytes)
                    }
                }
            };
            let claim_value_ident = format_ident!("__claim_value");
            let decode_claim = client_decode_body(&Some(claim_ty.clone()), &claim_value_ident);
            let method_name = method_name.to_string();
            attested_method_impls.push(quote! {
                impl vos::AttestedMethod<#claim_ty> for #struct_name {
                    const METHOD: &'static str = #method_name;

                    fn claim_wire(claim: &#claim_ty) -> alloc::vec::Vec<u8> {
                        let value: vos::value::Value = #claim_to_value;
                        vos::Encode::encode(&value)
                    }

                    fn decode_claim_wire(wire: &[u8]) -> Option<#claim_ty> {
                        let #claim_value_ident =
                            <vos::value::Value as vos::Decode>::try_decode(wire)?;
                        (#decode_claim).ok()
                    }
                }
            });
        }

        // Pre-dispatch role check. Emitted at the very top
        // of the arm so it runs *before* the user's handler can
        // observe `msg`. On refusal the actor flags the dispatch
        // as forbidden via Context::__mark_forbidden; lifecycle's
        // exit_status then emits STATUS_FORBIDDEN end-to-end
        // (PVM -> runtime.last_status -> host envelope).
        // `__mark_forbidden + return false` is short and
        // side-effect-free so a refused call leaves no trace
        // behind beyond the wire status.
        let actor_role_check = if let Some(role) = &role_expr {
            quote! {
                if !ctx.has_role_byte(
                    <<#actor_name as vos::Actor>::Role as vos::RoleByte>::as_byte(#role)
                ) {
                    ctx.__mark_forbidden();
                    return false;
                }
            }
        } else {
            quote! {}
        };
        let space_role_check = if let Some(role) = &space_role_expr {
            quote! {
                if !ctx.has_space_role(#role) {
                    ctx.__mark_forbidden();
                    return false;
                }
            }
        } else {
            quote! {}
        };
        let capability_check = if let Some(name) = &capability {
            quote! {
                if !ctx.has_capability(vos::CapabilityId::named(#name)) {
                    ctx.__mark_forbidden();
                    return false;
                }
            }
        } else {
            quote! {}
        };
        let role_check = quote! {
            #actor_role_check
            #space_role_check
            #capability_check
        };

        // Stash a `required_role()` arm for this variant. The
        // emitted enum gets a single `match` that returns
        // `Some(byte)` for role-gated handlers and `None`
        // otherwise, mirroring the existing `is_query` shape.
        let required_role_arm = if let Some(role) = &role_expr {
            quote! {
                #enum_name::#struct_name(_) => Some(
                    <<#actor_name as vos::Actor>::Role as vos::RoleByte>::as_byte(#role)
                )
            }
        } else {
            quote! { #enum_name::#struct_name(_) => None }
        };
        required_role_arms.push(required_role_arm);
        attested_arms.push(quote! {
            #enum_name::#struct_name(_) => #is_attested
        });
        let required_space_role_arm = if let Some(role) = &space_role_expr {
            quote! {
                #enum_name::#struct_name(_) => Some((#role).as_u8())
            }
        } else {
            quote! { #enum_name::#struct_name(_) => None }
        };
        required_space_role_arms.push(required_space_role_arm);
        let required_capability_arm = if let Some(name) = &capability {
            quote! {
                #enum_name::#struct_name(_) => Some(vos::CapabilityId::named(#name))
            }
        } else {
            quote! { #enum_name::#struct_name(_) => None }
        };
        required_capability_arms.push(required_capability_arm);

        // Deliver arm — different code for infallible vs fallible handlers
        let deliver_arm = if returns_result {
            quote! {
                #enum_name::#struct_name(msg) => {
                    #role_check
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
                    #role_check
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
        agent_method_metas.push(quote! {
            vos::agent::schema::MethodMeta {
                name: #msg_name_str,
                mode: #agent_execution_mode,
                explicit: #explicit_execution_mode,
            }
        });
        // First paragraph of the handler's `///` doc → MessageMeta.doc.
        let method_doc = first_doc_paragraph(&method.attrs);
        // Dispatch mode byte: 1 for `#[msg(job)]`, else 0 (sync).
        let mode_byte: u8 = if is_job { 1 } else { 0 };
        let field_metas: Vec<_> = field_names
            .iter()
            .zip(field_types.iter())
            .map(|(name, ty)| {
                let name_str = name.to_string();
                // Whitespace-free so `[u8; 32]` records as `[u8;32]` and
                // `Vec < u8 >` as `Vec<u8>` — the CLI, worker, and
                // OpenAPI renderer all match against this canonical form.
                let ty_str = ty_string(ty);
                quote! {
                    vos::metadata::FieldMeta {
                        name: #name_str,
                        ty: #ty_str,
                    }
                }
            })
            .collect();
        let space_role_meta = if let Some(role) = &space_role_expr {
            quote! { Some((#role).as_u8()) }
        } else {
            quote! { None }
        };
        let actor_role_meta = if let Some(role) = &role_expr {
            // Actor role enums are wire discriminants (`#[repr(u8)]`). The
            // metadata blob is a const, so it cannot call the non-const
            // `RoleByte::as_byte` trait method used by runtime dispatch.
            quote! { Some((#role) as u8) }
        } else {
            quote! { None }
        };
        let capability_meta = if let Some(name) = &capability {
            quote! { Some(#name) }
        } else {
            quote! { None }
        };
        meta_messages.push(quote! {
            vos::metadata::MessageMeta {
                name: #msg_name_str,
                is_query: #query_val,
                fields: &[ #( #field_metas ),* ],
                returns: #returns_str,
                doc: #method_doc,
                timeout_ms: #timeout_ms,
                mode: #mode_byte,
                attested: #is_attested,
                space_role: #space_role_meta,
                actor_role: #actor_role_meta,
                capability: #capability_meta,
            }
        });
        if exposed_to_cli {
            cli_method_names.push(quote! { #msg_name_str });
        }

        // Dynamic from_msg arm
        let from_msg_body = if field_names.is_empty() {
            quote! { Some(#enum_name::#struct_name(#struct_name)) }
        } else {
            let extractions: Vec<_> = field_names
                .iter()
                .zip(field_types.iter())
                .map(|(name, ty)| from_msg_arg(name, ty))
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
            attested: is_attested,
        });
    }

    // A `fn new(args: &[u8])` constructor receives the raw init-args
    // blob verbatim (see `is_byte_slice`). It owns its own parsing, so
    // it has no named init fields to surface in meta and bypasses the
    // per-param `.expect()` extraction below.
    let raw_args_ctor = constructor_params.len() == 1 && is_byte_slice(&constructor_params[0].1);

    // Constructor field metadata
    let ctor_field_metas: Vec<_> = if raw_args_ctor {
        Vec::new()
    } else {
        constructor_params
            .iter()
            .map(|(name, ty)| {
                let name_str = name.to_string();
                let ty_str = ty_string(ty);
                quote! {
                    vos::metadata::FieldMeta {
                        name: #name_str,
                        ty: #ty_str,
                    }
                }
            })
            .collect()
    };

    // An impl with no `#[msg]` handlers has no messages, so all the
    // arm vectors are empty and the aggregated enum would be zero-variant. A
    // zero-variant enum can't derive rkyv (`#[repr]` is unsupported on it,
    // E0084) and can't be matched (`match self {}` is non-exhaustive against a
    // `&Self`, E0004). Inject a single never-constructed placeholder variant so
    // the `Message` type is well-formed. It is unreachable in practice:
    // `from_msg` never yields it (its `_ => None` catch-all covers every wire
    // message), and a transport instance is driven via `conn_new`, never
    // `deliver`. (Actor/service extensions always have ≥1 handler, so this
    // branch is only a well-formed placeholder.)
    if enum_variants.is_empty() {
        enum_variants.push(quote! {
            #[doc(hidden)]
            __VosNoMessages
        });
        deliver_arms.push(quote! {
            #enum_name::__VosNoMessages => ::core::unreachable!(
                "deliver on an actor with no message handlers"
            )
        });
        is_query_arms.push(quote! {
            #enum_name::__VosNoMessages => false
        });
        required_role_arms.push(quote! {
            #enum_name::__VosNoMessages => ::core::option::Option::None
        });
        attested_arms.push(quote! {
            #enum_name::__VosNoMessages => false
        });
        required_space_role_arms.push(quote! {
            #enum_name::__VosNoMessages => ::core::option::Option::None
        });
        required_capability_arms.push(quote! {
            #enum_name::__VosNoMessages => ::core::option::Option::None
        });
    }

    let agent_message_marker = agent_messages.then(|| {
        quote! {
            impl vos::agent::schema::AgentMessageSet for #enum_name {}
            const _: () = assert!(
                <#actor_ty as vos::Actor>::AGENT_ACTOR_SOURCE,
                "#[messages(agent)] requires #[actor(agent)] on the actor type",
            );
        }
    });

    // Generate the aggregated enum
    let aggregated_enum = quote! {
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

            /// Role byte required to invoke this variant.
            /// `Some(b)` for handlers annotated with
            /// `#[msg(role = X)]` (the byte decodes against
            /// the actor's `Role` enum); `None` for handlers
            /// without an explicit annotation (open by default).
            /// The macro-emitted `deliver` already enforces this
            /// check before dispatching; the method is exposed
            /// for introspection (e.g. CLI help, audit tooling).
            pub fn required_role(&self) -> Option<u8> {
                match self {
                    #( #required_role_arms ),*
                }
            }

            /// Whether this handler requires a proof-bearing single-slice
            /// transition before guest Accumulate may commit it.
            pub fn is_attested(&self) -> bool {
                match self {
                    #( #attested_arms ),*
                }
            }

            /// Direct minimum space role declared on this handler.
            pub fn required_space_role(&self) -> Option<u8> {
                match self {
                    #( #required_space_role_arms ),*
                }
            }

            /// Stable space capability declared on this handler.
            pub fn required_capability(&self) -> Option<vos::CapabilityId> {
                match self {
                    #( #required_capability_arms ),*
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

        #agent_message_marker

        impl #enum_name {
            #[doc(hidden)]
            pub const AGENT_METHODS: &'static [vos::agent::schema::MethodMeta] =
                &[ #( #agent_method_metas ),* ];

            pub const META: vos::metadata::ActorMeta = vos::metadata::ActorMeta {
                actor_name: #actor_name_str,
                messages: &[ #( #meta_messages ),* ],
                constructor: &[ #( #ctor_field_metas ),* ],
                // CLI dispatch surface — names of handlers marked
                // `#[msg(cli)]`. Emitted into the trailing
                // `cli_methods` section of the binary blob; the
                // decoder uses it to set `ParsedMessage.exposed_to_cli`.
                // The `vosx <ext> <cmd>` dispatcher filters by this
                // when extending clap subcommands.
                cli_methods: &[ #( #cli_method_names ),* ],
                // Actor-level doc — the struct's `///` first paragraph,
                // threaded through the Actor trait (defaulted empty).
                doc: <#actor_ty as vos::Actor>::DOC,
                // Only `#[actor(crdt)]` programs may select CRDT storage.
                crdt: <#actor_ty as vos::Actor>::CRDT,
                // Provable-program mark — set on the Actor trait by
                // `#[actor(task, provable)]`, defaulted false.
                provable: <#actor_ty as vos::Actor>::PROVABLE,
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
    } else if raw_args_ctor {
        // Raw-args constructor: the no-args create path (a manifest entry
        // with no `init = {}`, so the host hands a null/empty arg blob) is
        // valid — hand `new` an EMPTY slice so it applies its own defaults.
        // (Panicking here would unwind out of the `extern "C"`
        // `vos_extension_create` boundary and abort the whole daemon.)
        quote! {
            fn __vos_create() -> Self {
                Self::new(&[])
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
        // The cfg gate is target-based: every PVM actor crate is built for
        // `riscv64`, while the service feature belongs to `vos`, not the user
        // crate.
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
    } else if raw_args_ctor {
        // Hand the raw init-args blob straight to `new(args: &[u8])`.
        quote! {
            fn __vos_create_with_args(args_bytes: &[u8]) -> Self {
                Self::new(args_bytes)
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

        const _VOS_META_ENCODED: ([u8; 16384], usize) =
            vos::metadata::encode::<16384>(&#enum_name::META);
    };

    // PVM entry points (`_start`, `.vos_meta`) are
    // auto-emitted by the `#[actor]` macro itself, gated on
    // `cfg(all(target_arch = "riscv64", feature = "bin"))` so:
    //   - host / worker / wasm builds skip them (different arch),
    //   - cross-actor lib deps skip them (`bin` feature off).
    // The user's lib.rs does not need a separate `pvm_main!()`; one
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
    // `{Actor}Ref` is a typed namespace and compile-time relationship between
    // an actor state and its generated handle. Handles always bind a complete
    // ActorId; route-only application references do not exist.
    let ref_struct_name = format_ident!("{}Ref", actor_name);
    let handle_methods_emit: Vec<proc_macro2::TokenStream> = client_methods
        .iter()
        .map(|m| {
            let method_ident = &m.wire_name;
            let wire_name = m.wire_name.to_string();
            let arg_decls: Vec<proc_macro2::TokenStream> =
                m.args.iter().map(|(n, t)| quote! { #n: #t }).collect();
            let with_calls: Vec<proc_macro2::TokenStream> =
                m.args.iter().map(|(n, t)| ref_arg_with(n, t)).collect();
            let return_ty: proc_macro2::TokenStream = match &m.success_ty {
                None => quote! { () },
                Some(t) => quote! { #t },
            };
            let method_marker = format_ident!("{}", to_pascal_case(&m.wire_name.to_string()));
            let value_ident = format_ident!("__value");
            let decode = client_decode_body(&m.success_ty, &value_ident);
            if m.attested {
                quote! {
                    pub async fn #method_ident(
                        &mut self,
                        #( #arg_decls ),*
                    ) -> core::result::Result<
                        vos::Attestation<#return_ty, #method_marker>,
                        vos::actors::client::ClientError,
                    >
                    where
                        __I: vos::actors::client::AttestationInvoker,
                    {
                        use vos::Encode;
                        let __msg = vos::value::Msg::new(#wire_name)
                            #( #with_calls )*;
                        let __encoded = __msg.encode();
                        let mut __payload = alloc::vec::Vec::with_capacity(1 + __encoded.len());
                        __payload.push(vos::value::TAG_DYNAMIC);
                        __payload.extend_from_slice(&__encoded);
                        let vos::actors::client::AttestedInvocationResult {
                            value: __value,
                            producer_name: __producer_name,
                            producer: __producer,
                            statement: __statement,
                            trace: __trace,
                            proof: __proof,
                        } = self.invoker
                            .invoke_actor_attested(self.target, __payload)
                            .await?;
                        let __claim_wire = vos::Encode::encode(&__value);
                        let __preview: #return_ty = (#decode)?;
                        vos::Attestation::__from_runtime_wire(
                            __producer_name,
                            __producer,
                            __statement,
                            __trace,
                            __claim_wire,
                            __preview,
                            __proof,
                        )
                        .map_err(vos::actors::client::ClientError::InvalidAttestation)
                    }
                }
            } else {
                quote! {
                    pub async fn #method_ident(
                        &mut self,
                        #( #arg_decls ),*
                    ) -> core::result::Result<#return_ty, vos::actors::client::ClientError> {
                        use vos::Encode;
                        let __msg = vos::value::Msg::new(#wire_name)
                            #( #with_calls )*;
                        let __encoded = __msg.encode();
                        let mut __payload = alloc::vec::Vec::with_capacity(1 + __encoded.len());
                        __payload.push(vos::value::TAG_DYNAMIC);
                        __payload.extend_from_slice(&__encoded);
                        let #value_ident: vos::value::Value = self
                            .invoker
                            .invoke_actor(self.target, __payload)
                            .await?;
                        #decode
                    }
                }
            }
        })
        .collect();
    // Native extensions expose the same ordinary message methods but bind to
    // an installed instance name and the dedicated ExtensionInvoker transport.
    // Attested methods intentionally remain actor-only: native host I/O cannot
    // produce the deterministic service proof contract.
    let extension_handle_methods_emit: Vec<proc_macro2::TokenStream> = if emit_extension_reference {
        client_methods
            .iter()
            .filter(|method| !method.attested)
            .map(|m| {
                let method_ident = &m.wire_name;
                let wire_name = m.wire_name.to_string();
                let arg_decls: Vec<proc_macro2::TokenStream> =
                    m.args.iter().map(|(n, t)| quote! { #n: #t }).collect();
                let with_calls: Vec<proc_macro2::TokenStream> =
                    m.args.iter().map(|(n, t)| ref_arg_with(n, t)).collect();
                let return_ty: proc_macro2::TokenStream = match &m.success_ty {
                    None => quote! { () },
                    Some(t) => quote! { #t },
                };
                let value_ident = format_ident!("__value");
                let decode = client_decode_body(&m.success_ty, &value_ident);
                quote! {
                    pub async fn #method_ident(
                        &mut self,
                        #( #arg_decls ),*
                    ) -> core::result::Result<#return_ty, vos::actors::client::ClientError> {
                        use vos::Encode;
                        let __msg = vos::value::Msg::new(#wire_name)
                            #( #with_calls )*;
                        let __encoded = __msg.encode();
                        let mut __payload = alloc::vec::Vec::with_capacity(1 + __encoded.len());
                        __payload.push(vos::value::TAG_DYNAMIC);
                        __payload.extend_from_slice(&__encoded);
                        let #value_ident: vos::value::Value = self
                            .invoker
                            .invoke_extension(self.target.clone(), __payload)
                            .await?;
                        #decode
                    }
                }
            })
            .collect()
    } else {
        Vec::new()
    };
    let handle_struct_name = format_ident!("{}Handle", actor_name);
    let extension_handle_struct_name = format_ident!("{}ExtensionHandle", actor_name);

    let extension_ref_emission = emit_extension_reference.then(|| {
        quote! {
            pub struct #extension_handle_struct_name<
                'a,
                __I: vos::actors::client::ExtensionInvoker,
            > {
                target: alloc::string::String,
                invoker: &'a mut __I,
            }

            impl<'a, __I: vos::actors::client::ExtensionInvoker>
                #extension_handle_struct_name<'a, __I>
            {
                /// Node-local installed instance name carried by this handle.
                pub fn extension_name(&self) -> &str {
                    &self.target
                }

                #( #extension_handle_methods_emit )*
            }

            impl vos::actors::client::ExtensionReference for #ref_struct_name {
                type Handle<'a, __I: vos::actors::client::ExtensionInvoker + 'a> =
                    #extension_handle_struct_name<'a, __I>;

                fn bind_extension<'a, __I: vos::actors::client::ExtensionInvoker + 'a>(
                    target: alloc::string::String,
                    invoker: &'a mut __I,
                ) -> Self::Handle<'a, __I> {
                    #extension_handle_struct_name {
                        target,
                        invoker,
                    }
                }
            }
        }
    });

    let ref_emission = quote! {
        #[derive(Copy, Clone)]
        pub struct #ref_struct_name;

        pub struct #handle_struct_name<'a, __I: vos::actors::client::Invoker> {
            target: vos::ActorId,
            invoker: &'a mut __I,
        }

        impl<'a, __I: vos::actors::client::Invoker> #handle_struct_name<'a, __I> {
            /// Canonical identity carried by an application-facing handle.
            pub const fn actor_id(&self) -> vos::ActorId {
                self.target
            }

            #( #handle_methods_emit )*
        }

        impl vos::actors::client::ActorReference for #ref_struct_name {
            type Handle<'a, __I: vos::actors::client::Invoker + 'a> =
                #handle_struct_name<'a, __I>;

            fn bind<'a, __I: vos::actors::client::Invoker + 'a>(
                target: vos::ActorId,
                invoker: &'a mut __I,
            ) -> Self::Handle<'a, __I> {
                #handle_struct_name {
                    target,
                    invoker,
                }
            }
        }

        #extension_ref_emission

        impl vos::actors::client::ActorReferenceFor<#actor_name> for #ref_struct_name {}
    };

    let expanded = quote! {
        #( #msg_structs )*
        #aggregated_enum
        #( #msg_impls )*
        #( #attested_method_impls )*
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

/// `true` for a `&[u8]` constructor parameter. A `fn new(args: &[u8])`
/// receives the **raw** init-args blob verbatim (not a single
/// `vos::value::Args` field), letting an extension parse its own
/// optional/defaulted config without the named-param path's
/// `.expect("missing init arg")` (every named param must be present).
/// Useful for extensions whose init format is application-defined.
fn is_byte_slice(ty: &syn::Type) -> bool {
    if let syn::Type::Reference(r) = ty
        && let syn::Type::Slice(s) = r.elem.as_ref()
        && let syn::Type::Path(p) = s.elem.as_ref()
    {
        return p.path.is_ident("u8");
    }
    false
}

/// Parsed `#[actor(...)]` attribute payload.
struct ActorAttrs {
    /// Token stream for the actor's `Error` associated type — `()`
    /// when not specified.
    error_ty: proc_macro2::TokenStream,
    /// Token stream for the actor's `Role` associated type
    /// (e.g. `MyRole`). `vos::NoRoles` when not specified, which
    /// makes the actor opt out of RBAC.
    role_ty: proc_macro2::TokenStream,
    /// Token stream for `Actor::DEFAULT_ROLE` (the value
    /// applied when no grant resolves). `vos::NoRoles::Any` when
    /// not specified.
    default_role: proc_macro2::TokenStream,
    /// Token stream for `Actor::SPACE_ROLE_MAP` (a const
    /// SpaceRoleMap<Self::Role>). Defaults to vos::NO_ROLES_MAP.
    space_role_map: proc_macro2::TokenStream,
    /// `Some(buffer_size)` when the actor is a **Task** blob
    /// (`#[actor(task)]` / `#[actor(task = N)]`): `_start` becomes the
    /// witness-delivered task entry and a `__VOS_WITNESS` buffer of
    /// that many bytes is emitted for the invoker (and the prover) to
    /// patch `(state, msg)` into.
    task_buf: Option<usize>,
    /// Standard agent actor execution ABI (`#[actor(agent)]`). This is an
    /// explicit source-level choice rather than an inference from Cargo
    /// features, which the proc macro cannot observe reliably.
    agent: bool,
    /// Explicit CRDT source model (`#[actor(crdt)]`).
    crdt: bool,
    /// `#[actor(task, provable)]` — publish this Task as a provable
    /// program: sets `Actor::PROVABLE`, which lands as the `.vos_meta`
    /// provable flag. Valid
    /// only with `task`; the macro rejects it otherwise.
    provable: bool,
    /// Explicit persisted-state contract version. Direct fields are also
    /// fingerprinted automatically; this covers changes inside nested types.
    state_version: u64,
}

/// Pull `#[storage]` / `#[storage(prefix = "…")]` off the state
/// struct's named fields, returning `(field, key-prefix-bytes)` per
/// storage field. The attribute must be stripped here — nothing else
/// declares it, so leaving it in the re-emitted struct is a compile
/// error by design (it only means something on an `#[actor]` struct).
///
/// The default prefix is `s/<field>/`; pass an explicit
/// `prefix = "…"` to pin it across a field rename (the prefix names
/// the rows — changing it orphans them).
/// One `#[storage]` field: its ident, key prefix, whether it is
/// `committed` (folds into the `anchor_kind 0x02` composite root),
/// and optional application-owned SMT hash domains (for trees whose
/// roots are pinned outside vos — clerk-ledger ↔ cipher-clerk).
struct StorageField {
    ident: syn::Ident,
    prefix: Vec<u8>,
    committed: bool,
    domains: Option<(String, String)>,
}

fn extract_storage_fields(input: &mut ItemStruct) -> Vec<StorageField> {
    let mut out: Vec<StorageField> = Vec::new();
    let syn::Fields::Named(named) = &mut input.fields else {
        return out;
    };
    for field in named.named.iter_mut() {
        type StorageAttribute = (Option<String>, bool, Option<String>, Option<String>);
        let mut storage: Option<StorageAttribute> = None;
        field.attrs.retain(|attr| {
            if !attr.path().is_ident("storage") {
                return true;
            }
            let mut custom = None;
            let mut committed = false;
            let mut leaf_domain = None;
            let mut node_domain = None;
            if matches!(attr.meta, syn::Meta::List(_)) {
                let parsed = attr.parse_nested_meta(|meta| {
                    if meta.path.is_ident("prefix") {
                        let lit: syn::LitStr = meta.value()?.parse()?;
                        custom = Some(lit.value());
                        Ok(())
                    } else if meta.path.is_ident("committed") {
                        committed = true;
                        Ok(())
                    } else if meta.path.is_ident("leaf_domain") {
                        let lit: syn::LitStr = meta.value()?.parse()?;
                        leaf_domain = Some(lit.value());
                        Ok(())
                    } else if meta.path.is_ident("node_domain") {
                        let lit: syn::LitStr = meta.value()?.parse()?;
                        node_domain = Some(lit.value());
                        Ok(())
                    } else {
                        Err(meta.error(
                            "expected `prefix = \"…\"`, `committed`, \
                             `leaf_domain = \"…\"`, or `node_domain = \"…\"`",
                        ))
                    }
                });
                if let Err(e) = parsed {
                    panic!("#[storage]: {e}");
                }
            }
            storage = Some((custom, committed, leaf_domain, node_domain));
            false
        });
        if let Some((custom, committed, leaf_domain, node_domain)) = storage {
            let ident = field.ident.clone().expect("named field");
            let prefix = custom.unwrap_or_else(|| format!("s/{ident}/"));
            assert!(
                !prefix.is_empty() && !prefix.starts_with("__vos_"),
                "#[storage] prefix {prefix:?} collides with the framework keyspace",
            );
            assert!(
                out.iter().all(|f| f.prefix != prefix.as_bytes()),
                "#[storage] prefix {prefix:?} is used by two fields",
            );
            let domains = match (leaf_domain, node_domain) {
                (Some(l), Some(n)) => Some((l, n)),
                (None, None) => None,
                _ => panic!(
                    "#[storage]: leaf_domain and node_domain must be given together \
                     (field `{ident}`)"
                ),
            };
            assert!(
                domains.is_none() || committed,
                "#[storage]: custom SMT domains only apply to `committed` fields \
                 (field `{ident}`)"
            );
            out.push(StorageField {
                ident,
                prefix: prefix.into_bytes(),
                committed,
                domains,
            });
        }
    }
    out
}

/// Parse `#[actor(...)]` attributes.
///
/// Recognised keys:
/// - `error = Type` — custom Actor::Error type (default `()`)
/// - `state_version = N` — explicit nested persisted-state schema version
fn parse_actor_attrs(attr: proc_macro2::TokenStream) -> syn::Result<ActorAttrs> {
    use syn::Token;
    use syn::parse::Parser;
    use syn::punctuated::Punctuated;

    let default_err = quote! { () };
    let mut out = ActorAttrs {
        error_ty: default_err.clone(),
        role_ty: quote! { vos::NoRoles },
        default_role: quote! { vos::NoRoles::Any },
        space_role_map: quote! { vos::NO_ROLES_MAP },
        task_buf: None,
        agent: false,
        crdt: false,
        provable: false,
        state_version: 0,
    };
    if attr.is_empty() {
        return Ok(out);
    }

    // Proc-macro attribute body is the tokens inside the parens,
    // possibly comma-separated. Parse as a Punctuated<Meta, ,>
    // so multi-arg forms like
    // `#[actor(role = X, default_role = Y, ...)]` work — a bare
    // `syn::parse::<syn::Meta>` only handles a single arg.
    let metas: Punctuated<syn::Meta, Token![,]> =
        Punctuated::<syn::Meta, Token![,]>::parse_terminated.parse2(attr)?;

    for meta in metas {
        match meta {
            syn::Meta::NameValue(nv) if nv.path.is_ident("error") => {
                let val = &nv.value;
                out.error_ty = quote! { #val };
            }
            syn::Meta::NameValue(nv) if nv.path.is_ident("role") => {
                // `role = MyRole` overrides `type Role`.
                let val = &nv.value;
                out.role_ty = quote! { #val };
            }
            syn::Meta::NameValue(nv) if nv.path.is_ident("default_role") => {
                let val = &nv.value;
                out.default_role = quote! { #val };
            }
            syn::Meta::NameValue(nv) if nv.path.is_ident("space_role_map") => {
                let val = &nv.value;
                out.space_role_map = quote! { #val };
            }
            syn::Meta::NameValue(nv) if nv.path.is_ident("state_version") => {
                let syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Int(version),
                    ..
                }) = &nv.value
                else {
                    return Err(syn::Error::new_spanned(
                        &nv.value,
                        "`state_version` must be an integer literal",
                    ));
                };
                out.state_version = version.base10_parse::<u64>()?;
            }
            // Task blob: `task` (default 16 KiB witness buffer) or
            // `task = N` for a custom size. The buffer bounds the
            // provable `state ‖ msg` — see the work-result contract's
            // proving ceilings; large state belongs to SMT anchors,
            // not a bigger buffer.
            syn::Meta::Path(p) if p.is_ident("task") => {
                out.task_buf = Some(DEFAULT_TASK_BUF);
            }
            syn::Meta::Path(p) if p.is_ident("agent") => {
                out.agent = true;
            }
            syn::Meta::Path(p) if p.is_ident("crdt") => {
                out.crdt = true;
            }
            syn::Meta::NameValue(nv) if nv.path.is_ident("task") => {
                let syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Int(n),
                    ..
                }) = &nv.value
                else {
                    return Err(syn::Error::new_spanned(
                        &nv.value,
                        "`task` buffer size must be an integer literal",
                    ));
                };
                out.task_buf = Some(n.base10_parse::<usize>()?);
            }
            // Publication mark for the pin/verify tooling; validated
            // against `task` in `actor()` after parsing.
            syn::Meta::Path(p) if p.is_ident("provable") => {
                out.provable = true;
            }
            unsupported => {
                return Err(syn::Error::new_spanned(
                    unsupported,
                    "unsupported #[actor] option; expected `error = Type`, \
                     `role = Type`, `default_role = Role`, \
                     `space_role_map = MAP`, `state_version = N`, `task`, \
                     `task = N`, `agent`, `crdt`, or `provable`",
                ));
            }
        }
    }
    Ok(out)
}

/// Persistence plan emitted into the signed `.vos_agent` schema.
#[derive(Default)]
struct StateFieldPlan {
    fields: Vec<StateField>,
    merge: Vec<syn::Ident>,
    constants: Vec<syn::Ident>,
    default_mutation_mode: MethodModePlan,
}

struct StateField {
    ident: syn::Ident,
    ty: syn::Type,
    persistence: PersistencePlan,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PersistencePlan {
    Linear,
    Merge,
    Local,
    Constant,
    Skipped,
}

impl PersistencePlan {
    fn tokens(self) -> proc_macro2::TokenStream {
        match self {
            Self::Linear => quote! {
                vos::agent::FieldPersistence::State(vos::agent::StateLane::Linear)
            },
            Self::Merge => quote! {
                vos::agent::FieldPersistence::State(vos::agent::StateLane::Merge)
            },
            Self::Local => quote! {
                vos::agent::FieldPersistence::State(vos::agent::StateLane::Local)
            },
            Self::Constant => quote! { vos::agent::FieldPersistence::Constant },
            Self::Skipped => quote! { vos::agent::FieldPersistence::Skipped },
        }
    }
}

#[derive(Clone, Copy, Default)]
enum MethodModePlan {
    #[default]
    Linear,
    Merge,
    Local,
}

impl MethodModePlan {
    fn tokens(self) -> proc_macro2::TokenStream {
        match self {
            Self::Linear => quote! { vos::agent::MethodMode::Linear },
            Self::Merge => quote! { vos::agent::MethodMode::Merge },
            Self::Local => quote! { vos::agent::MethodMode::Local },
        }
    }
}

/// Strip and validate field persistence annotations. Plain fields select the
/// linear lane, `crdt::*` fields select the merge lane, and `#[state(local)]`
/// selects replica-local state. An existing `#[rkyv(with = ...::Skip)]` is the
/// service/extension spelling of the same transient-state contract as
/// `#[state(skip)]`; both are omitted from agent lanes. Constants and skipped
/// fields are not mutable durable lanes.
fn has_rkyv_skip(field: &syn::Field) -> bool {
    field.attrs.iter().any(|attr| {
        let syn::Meta::List(list) = &attr.meta else {
            return false;
        };
        if !list.path.is_ident("rkyv") {
            return false;
        }
        let Ok(items) = list.parse_args_with(
            syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
        ) else {
            return false;
        };
        items.iter().any(|item| {
            let syn::Meta::NameValue(value) = item else {
                return false;
            };
            if !value.path.is_ident("with") {
                return false;
            }
            let syn::Expr::Path(path) = &value.value else {
                return false;
            };
            path.path
                .segments
                .last()
                .is_some_and(|segment| segment.ident == "Skip")
        })
    })
}

fn prepare_state_fields(input: &mut ItemStruct, is_crdt: bool) -> syn::Result<StateFieldPlan> {
    let syn::Fields::Named(named) = &mut input.fields else {
        if !matches!(input.fields, syn::Fields::Unit) {
            return Err(syn::Error::new_spanned(
                &input.fields,
                "#[actor] tuple structs are unsupported: use named fields so every persisted field has an explicit signed lane codec, or a unit struct for a stateless actor",
            ));
        }
        return Ok(StateFieldPlan::default());
    };

    let mut plan = StateFieldPlan::default();
    let mut has_linear = false;
    let mut has_merge = false;
    let mut has_local = false;
    for field in &mut named.named {
        let is_storage = field
            .attrs
            .iter()
            .any(|attr| attr.path().is_ident("storage"));
        if is_storage {
            if let Some(attribute) = field
                .attrs
                .iter()
                .find(|attr| attr.path().is_ident("state") || attr.path().is_ident("crdt"))
            {
                return Err(syn::Error::new_spanned(
                    attribute,
                    "#[storage] handles live outside agent state lanes and cannot also use #[state(...)] or #[crdt(...)]",
                ));
            }
            continue;
        }
        let mut is_const = false;
        let rkyv_skip = has_rkyv_skip(field);
        let mut is_skip = rkyv_skip;
        let mut is_local = false;
        let mut is_merge = false;
        let mut is_linear = false;
        let mut crdt_attr = None;
        let mut state_attr = None;
        field.attrs.retain(|attr| {
            if attr.path().is_ident("crdt") {
                crdt_attr = Some(attr.clone());
                false
            } else if attr.path().is_ident("state") {
                state_attr = Some(attr.clone());
                false
            } else {
                true
            }
        });

        if let Some(attr) = &crdt_attr {
            if !is_crdt {
                return Err(syn::Error::new_spanned(
                    attr,
                    "#[crdt(...)] fields require #[actor(crdt)]",
                ));
            }
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("const") {
                    is_const = true;
                    Ok(())
                } else if meta.path.is_ident("skip") {
                    is_skip = true;
                    Ok(())
                } else {
                    Err(meta.error("expected #[crdt(const)] or #[crdt(skip)]"))
                }
            })?;
            if is_const && is_skip {
                return Err(syn::Error::new_spanned(
                    &field.ty,
                    "a CRDT field cannot be both const and skip",
                ));
            }
        }

        if let Some(attr) = &state_attr {
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("local") {
                    is_local = true;
                    Ok(())
                } else if meta.path.is_ident("merge") {
                    is_merge = true;
                    Ok(())
                } else if meta.path.is_ident("linear") {
                    is_linear = true;
                    Ok(())
                } else if meta.path.is_ident("const") {
                    is_const = true;
                    Ok(())
                } else if meta.path.is_ident("skip") {
                    is_skip = true;
                    Ok(())
                } else {
                    Err(meta.error(
                        "expected #[state(linear)], #[state(merge)], #[state(local)], #[state(const)], or #[state(skip)]",
                    ))
                }
            })?;
            if usize::from(is_linear)
                + usize::from(is_merge)
                + usize::from(is_local)
                + usize::from(is_const)
                + usize::from(is_skip)
                != 1
            {
                return Err(syn::Error::new_spanned(
                    &field.ty,
                    "a state field must select exactly one persistence class",
                ));
            }
        }

        if crdt_attr.is_some() && state_attr.is_some() {
            return Err(syn::Error::new_spanned(
                &field.ty,
                "use one field persistence annotation, not both #[crdt(...)] and #[state(...)]",
            ));
        }
        if is_skip && !rkyv_skip {
            field
                .attrs
                .push(syn::parse_quote!(#[rkyv(with = vos::rkyv::with::Skip)]));
        }

        if is_crdt
            && !is_const
            && !is_skip
            && !is_merge
            && !is_linear
            && !is_crdt_field_type(&field.ty)
        {
            let name = field
                .ident
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_else(|| "field".into());
            return Err(syn::Error::new_spanned(
                &field.ty,
                format!(
                    "plain mutable field `{name}` has no convergent merge rule; use crdt::Counter for additive changes, crdt::Value<T> when one assignment should be visible, crdt::Map for independently editable keys, crdt::Set for membership, crdt::List/crdt::Text for sequences, or mark derived data #[crdt(skip)]",
                ),
            ));
        }

        let ident = field.ident.clone().expect("named actor field");
        let persistence = if is_skip {
            PersistencePlan::Skipped
        } else if is_const {
            plan.constants.push(ident.clone());
            PersistencePlan::Constant
        } else if is_local {
            has_local = true;
            PersistencePlan::Local
        } else if is_merge || (!is_linear && is_crdt_field_type(&field.ty)) {
            has_merge = true;
            plan.merge.push(ident.clone());
            PersistencePlan::Merge
        } else {
            has_linear = true;
            PersistencePlan::Linear
        };
        plan.fields.push(StateField {
            ident,
            ty: field.ty.clone(),
            persistence,
        });
    }

    plan.default_mutation_mode = if has_merge && !has_linear && !has_local {
        MethodModePlan::Merge
    } else if has_local && !has_linear && !has_merge {
        MethodModePlan::Local
    } else {
        MethodModePlan::Linear
    };
    Ok(plan)
}

fn is_crdt_field_type(ty: &syn::Type) -> bool {
    let syn::Type::Path(path) = ty else {
        return false;
    };
    let mut segments = path.path.segments.iter().rev();
    let Some(kind) = segments.next() else {
        return false;
    };
    let is_known = matches!(
        kind.ident.to_string().as_str(),
        "Value" | "Map" | "Set" | "List" | "Text" | "Counter"
    );
    is_known
        && segments
            .next()
            .is_some_and(|segment| segment.ident == "crdt")
}

#[cfg(test)]
mod agent_schema_tests {
    use super::*;

    #[test]
    fn explicit_lanes_override_syntactic_type_classification() {
        let mut actor: ItemStruct = syn::parse_quote! {
            struct Mixed {
                #[state(merge)]
                merge: CustomMergeCodec,
                #[state(linear)]
                linear: some::crdt::Counter,
            }
        };
        let plan = prepare_state_fields(&mut actor, false).unwrap();
        assert_eq!(plan.fields.len(), 2);
        assert_eq!(plan.fields[0].persistence, PersistencePlan::Merge);
        assert_eq!(plan.fields[1].persistence, PersistencePlan::Linear);
    }

    #[test]
    fn only_qualified_crdt_types_are_inferred_as_merge_state() {
        let qualified: syn::Type = syn::parse_quote!(some::crdt::Counter);
        let direct: syn::Type = syn::parse_quote!(Counter);
        let unrelated: syn::Type = syn::parse_quote!(other::Counter);
        assert!(is_crdt_field_type(&qualified));
        assert!(!is_crdt_field_type(&direct));
        assert!(!is_crdt_field_type(&unrelated));
    }

    #[test]
    fn storage_handles_are_not_agent_lane_fields() {
        let mut actor: ItemStruct = syn::parse_quote! {
            struct Stored {
                #[storage(prefix = "items/")]
                items: vos::StorageMap<String, String>,
                count: u64,
            }
        };
        let plan = prepare_state_fields(&mut actor, false).unwrap();
        assert_eq!(plan.fields.len(), 1);
        assert_eq!(plan.fields[0].ident, "count");
        assert!(
            actor
                .fields
                .iter()
                .next()
                .unwrap()
                .attrs
                .iter()
                .any(|attr| attr.path().is_ident("storage"))
        );
    }

    #[test]
    fn storage_handles_cannot_claim_a_second_persistence_class() {
        let mut actor: ItemStruct = syn::parse_quote! {
            struct Stored {
                #[storage]
                #[state(linear)]
                items: vos::StorageMap<String, String>,
            }
        };
        assert!(prepare_state_fields(&mut actor, false).is_err());
    }

    #[test]
    fn existing_rkyv_skip_is_a_transient_agent_field_without_duplicate_attrs() {
        let mut actor: ItemStruct = syn::parse_quote! {
            struct NativeExtension {
                durable: u64,
                #[rkyv(with = vos::rkyv::with::Skip)]
                runtime: NativeRuntime,
            }
        };
        let plan = prepare_state_fields(&mut actor, false).unwrap();
        assert_eq!(plan.fields.len(), 2);
        assert_eq!(plan.fields[0].persistence, PersistencePlan::Linear);
        assert_eq!(plan.fields[1].persistence, PersistencePlan::Skipped);
        let runtime = actor.fields.iter().nth(1).unwrap();
        assert_eq!(
            runtime
                .attrs
                .iter()
                .filter(|attr| attr.path().is_ident("rkyv"))
                .count(),
            1
        );
    }

    #[test]
    fn tuple_actor_state_is_rejected_instead_of_silently_omitted() {
        let mut actor: ItemStruct = syn::parse_quote! {
            struct Coordinates(u64, u64);
        };
        let error = match prepare_state_fields(&mut actor, false) {
            Ok(_) => panic!("tuple actor state was accepted"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("tuple structs are unsupported"));
    }

    #[test]
    fn unit_actor_is_an_explicit_zero_field_state_shape() {
        let mut actor: ItemStruct = syn::parse_quote! {
            struct Health;
        };
        let plan = prepare_state_fields(&mut actor, false).unwrap();
        assert!(plan.fields.is_empty());
        assert!(plan.merge.is_empty());
        assert!(plan.constants.is_empty());
    }
}

/// Default `__VOS_WITNESS` capacity for `#[actor(task)]` blobs.
const DEFAULT_TASK_BUF: usize = 16 * 1024;

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
    /// Whether the generated handle must return a proved package instead of
    /// exposing the decoded reply directly.
    attested: bool,
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
        return quote! {
            Ok::<(), vos::actors::client::ClientError>(())
        };
    };

    // `Option<T>`: the actor encodes `None` as `Value::Bytes([0])` and
    // `Some(v)` as `Value::Bytes([1] ++ rkyv(v))`. The explicit tag keeps
    // zero-sized values injective.
    if let Some(inner) = option_inner_type(ty) {
        return quote! {
            match #value_ident {
                vos::value::Value::Bytes(b) if b.as_slice() == [0] => Ok(None),
                vos::value::Value::Bytes(b) if b.first() == Some(&1) => {
                    let payload = &b[1..];
                    let mut av =
                        vos::rkyv::util::AlignedVec::<16>::with_capacity(payload.len());
                    av.extend_from_slice(payload);
                    // The reply is peer-supplied and crosses a trust
                    // boundary (another node / space produced it), so it
                    // is validated rather than trusted: `rkyv::access`
                    // checks alignment, bounds, pointer windows, and (via
                    // bytecheck) per-type invariants. A corrupted or
                    // version-skewed archive returns `Decode` here instead
                    // of the UB `access_unchecked` would invite. AlignedVec<16>
                    // supplies the alignment `access` requires.
                    match vos::rkyv::access::<
                        <#inner as vos::rkyv::Archive>::Archived,
                        vos::rkyv::rancor::Error,
                    >(&av) {
                        Ok(archived) => vos::rkyv::deserialize::<#inner, vos::rkyv::rancor::Error>(archived)
                            .map(Some)
                            .map_err(|_| vos::actors::client::ClientError::Decode),
                        Err(_) => Err(vos::actors::client::ClientError::Decode),
                    }
                }
                other => Err(vos::actors::client::ClientError::UnexpectedReply(
                    alloc::format!("{:?}", other))),
            }
        };
    }

    // `[u8; N]` reply → raw bytes, length-checked into the array.
    if is_byte_array(ty) {
        return quote! {
            match #value_ident {
                vos::value::Value::Bytes(b) => <#ty>::try_from(b.as_slice())
                    .map_err(|_| vos::actors::client::ClientError::Decode),
                other => Err(vos::actors::client::ClientError::UnexpectedReply(
                    alloc::format!("{:?}", other))),
            }
        };
    }

    let ty_str = ty.to_token_stream().to_string().replace(' ', "");
    match ty_str.as_str() {
        "()" => quote! {
            Ok::<(), vos::actors::client::ClientError>(())
        },
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
                    // Checked access — see the Option<T> arm above for why
                    // a peer-supplied reply must be validated, not trusted.
                    match vos::rkyv::access::<
                        <#ty as vos::rkyv::Archive>::Archived,
                        vos::rkyv::rancor::Error,
                    >(&av) {
                        Ok(archived) => vos::rkyv::deserialize::<#ty, vos::rkyv::rancor::Error>(archived)
                            .map_err(|_| vos::actors::client::ClientError::Decode),
                        Err(_) => Err(vos::actors::client::ClientError::Decode),
                    }
                }
                other => Err(vos::actors::client::ClientError::UnexpectedReply(
                    alloc::format!("{:?}", other))),
            }
        },
    }
}

/// Scalar / collection types that map directly onto a `Value` variant:
/// they impl `Into<Value>` (sender side) and have a typed `Args`
/// accessor (receiver side). Everything else travels rkyv-encoded
/// inside `Value::Bytes`. `()` is here for the reply path (a unit
/// return encodes as `Value::Unit`); it never appears as an argument.
/// Both the `#[msg]` argument path and the reply path branch on this
/// one list so the two sides can never disagree about what is a
/// primitive.
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

/// Canonical, whitespace-free rendering of a type (`Vec<u8>`, not
/// `Vec < u8 >`). Used everywhere a type is matched against a string.
fn ty_string(ty: &syn::Type) -> String {
    quote!(#ty).to_string().replace(' ', "")
}

/// `true` if `ty` is one of the [`PRIMITIVES`] that convert straight
/// to a `Value` variant via `Into<Value>`.
fn is_primitive_ty(ty: &syn::Type) -> bool {
    PRIMITIVES.contains(&ty_string(ty).as_str())
}

/// `true` if `ty` is a fixed-size byte array `[u8; N]`. These travel as
/// raw `Value::Bytes` of exactly `N` bytes (not rkyv-wrapped), so a
/// hex / `@file` CLI argument maps straight onto them, the reply reads
/// back symmetrically, and the length can be validated at the edge —
/// the natural shape for ids, roots, hashes, and public keys.
fn is_byte_array(ty: &syn::Type) -> bool {
    let syn::Type::Array(arr) = ty else {
        return false;
    };
    matches!(arr.elem.as_ref(), syn::Type::Path(p) if p.path.is_ident("u8"))
}

/// The typed `Args` accessor for a whitelisted scalar argument type,
/// or `None` for types that travel rkyv-encoded (custom structs,
/// `Vec<[u8; 32]>`, …). Drives the `from_msg` extraction.
fn whitelist_accessor(ty: &syn::Type) -> Option<proc_macro2::TokenStream> {
    Some(match ty_string(ty).as_str() {
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
        _ => return None,
    })
}

/// The `from_msg` extraction statement for one `#[msg]` argument —
/// `let <name>: <ty> = <expr>;`. Whitelisted scalars read through the
/// typed `Args` accessor; any other type is decoded from rkyv
/// `Value::Bytes` via checked `from_bytes`. Every failure mode (missing
/// arg, wrong `Value` variant, decode failure) yields `None` from
/// `from_msg` through `?`, so a malformed dynamic message is rejected
/// rather than mis-dispatched.
fn from_msg_arg(name: &syn::Ident, ty: &syn::Type) -> proc_macro2::TokenStream {
    let name_str = name.to_string();
    if is_attestation_type(ty) {
        return quote! {
            let #name: #ty = <#ty>::from_portable_bytes(
                msg.args.get(#name_str)?.as_bytes()?,
            )
            .ok()?;
        };
    }
    if let Some(accessor) = whitelist_accessor(ty) {
        return quote! { let #name: #ty = msg.args.#accessor(#name_str)?; };
    }
    if is_byte_array(ty) {
        // Raw bytes → fixed array; a length mismatch yields `None`.
        return quote! {
            let #name: #ty = <#ty>::try_from(msg.args.get(#name_str)?.as_bytes()?).ok()?;
        };
    }
    quote! {
        let #name: #ty = vos::rkyv::from_bytes::<#ty, vos::rkyv::rancor::Error>(
            msg.args.get(#name_str)?.as_bytes()?,
        )
        .ok()?;
    }
}

/// The `Msg::with(name, value)` call that encodes one `{Actor}Ref`
/// argument. Whitelisted scalars pass through their `Into<Value>`
/// impl; any other type is rkyv-encoded into `Value::Bytes`, the exact
/// inverse of [`from_msg_arg`]. The wire shape for whitelisted types is
/// unchanged, so callers written against the old scalar-only surface
/// keep working.
fn ref_arg_with(name: &syn::Ident, ty: &syn::Type) -> proc_macro2::TokenStream {
    let name_str = name.to_string();
    if is_attestation_type(ty) {
        return quote! {
            .with(
                #name_str,
                vos::value::Value::Bytes(
                    #name
                        .to_portable_bytes()
                        .expect("portable attestation exceeds the VOS wire limit"),
                ),
            )
        };
    }
    if is_primitive_ty(ty) {
        return quote! { .with(#name_str, #name) };
    }
    if is_byte_array(ty) {
        return quote! { .with(#name_str, vos::value::Value::Bytes(#name.to_vec())) };
    }
    quote! {
        .with(
            #name_str,
            vos::value::Value::Bytes(
                vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&#name)
                    .expect("rkyv encode")
                    .to_vec(),
            ),
        )
    }
}

fn is_attestation_type(ty: &syn::Type) -> bool {
    let syn::Type::Path(path) = ty else {
        return false;
    };
    if path.qself.is_some() {
        return false;
    }
    let segments = &path.path.segments;
    let explicitly_vos = matches!(
        (segments.first(), segments.last()),
        (Some(first), Some(last))
            if first.ident == "vos"
                && last.ident == "Attestation"
                && (segments.len() == 2 || segments.len() == 3)
    );
    if !explicitly_vos {
        return false;
    }
    let Some(last) = segments.last() else {
        return false;
    };
    let syn::PathArguments::AngleBracketed(arguments) = &last.arguments else {
        return false;
    };
    arguments.args.len() == 2
        && arguments
            .args
            .iter()
            .all(|argument| matches!(argument, syn::GenericArgument::Type(_)))
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

fn valid_capability_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 128
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(byte))
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

#[cfg(test)]
mod doc_tests {
    use super::{
        first_doc_paragraph, is_attestation_type, parse_actor_attrs, state_schema_fingerprint,
        valid_capability_name,
    };
    use quote::quote;

    fn attrs(src: &str) -> Vec<syn::Attribute> {
        syn::parse_str::<syn::ItemStruct>(src).unwrap().attrs
    }

    #[test]
    fn joins_lines_until_first_blank() {
        let a = attrs("/// First line.\n/// Second line.\n///\n/// A later paragraph.\nstruct X;");
        assert_eq!(first_doc_paragraph(&a), "First line. Second line.");
    }

    #[test]
    fn single_line_doc() {
        let a = attrs("/// Enqueue a prove job.\nstruct X;");
        assert_eq!(first_doc_paragraph(&a), "Enqueue a prove job.");
    }

    #[test]
    fn empty_when_undocumented() {
        let a = attrs("struct X;");
        assert_eq!(first_doc_paragraph(&a), "");
    }

    #[test]
    fn ignores_non_doc_attrs() {
        let a = attrs("/// Doc.\n#[derive(Debug)]\nstruct X;");
        assert_eq!(first_doc_paragraph(&a), "Doc.");
    }

    #[test]
    fn stops_at_interior_blank_line_in_single_attr() {
        // An explicit multi-line `#[doc]` (or a block comment) is one attr
        // with interior newlines — the blank line must still break.
        let a = attrs("#[doc = \" First para.\\n\\n Second para.\"]\nstruct X;");
        assert_eq!(first_doc_paragraph(&a), "First para.");
    }

    #[test]
    fn block_comment_strips_star_and_stops_at_blank() {
        let a = attrs("/**\n * First line.\n * still first.\n *\n * Second para.\n */\nstruct X;");
        assert_eq!(first_doc_paragraph(&a), "First line. still first.");
    }

    #[test]
    fn portable_attestation_detection_requires_the_vos_type_and_two_type_arguments() {
        let ty = |source| syn::parse_str::<syn::Type>(source).unwrap();
        assert!(is_attestation_type(&ty("vos::Attestation<Claim, Method>")));
        assert!(is_attestation_type(&ty(
            "vos::attestation::Attestation<Claim, Method>"
        )));
        assert!(!is_attestation_type(&ty("Attestation<Claim, Method>")));
        assert!(!is_attestation_type(&ty(
            "application::Attestation<Claim, Method>"
        )));
        assert!(!is_attestation_type(&ty("vos::Attestation<Claim>")));
        assert!(!is_attestation_type(&ty("vos::Attestation")));
    }
    #[test]
    fn capability_names_are_stable_lowercase_identifiers() {
        assert!(valid_capability_name("agent.invoke"));
        assert!(valid_capability_name("agent-create.local_2"));
        assert!(!valid_capability_name(""));
        assert!(!valid_capability_name("Agent.invoke"));
        assert!(!valid_capability_name("2agent.invoke"));
        assert!(!valid_capability_name("agent/invoke"));
        assert!(!valid_capability_name(&"a".repeat(129)));
    }

    #[test]
    fn state_fingerprint_ignores_non_schema_source_details() {
        let first: syn::ItemStruct = syn::parse_quote! {
            /// Documentation is not persisted.
            pub struct PublicName {
                #[allow(dead_code)]
                pub value: Vec<u8>,
            }
        };
        let second: syn::ItemStruct = syn::parse_quote! {
            #[allow(non_camel_case_types)]
            struct renamed {
                value: Vec < u8 >,
            }
        };

        assert_eq!(
            state_schema_fingerprint(&first),
            state_schema_fingerprint(&second)
        );
    }

    #[test]
    fn state_fingerprint_tracks_direct_archive_schema() {
        let base: syn::ItemStruct = syn::parse_quote! {
            struct State { first: u8, second: u16 }
        };
        let reordered: syn::ItemStruct = syn::parse_quote! {
            struct State { second: u16, first: u8 }
        };
        let changed_type: syn::ItemStruct = syn::parse_quote! {
            struct State { first: u8, second: u32 }
        };
        let archive_attr: syn::ItemStruct = syn::parse_quote! {
            struct State {
                first: u8,
                #[rkyv(with = Adapter)]
                second: u16,
            }
        };
        let storage_attr: syn::ItemStruct = syn::parse_quote! {
            struct State {
                first: u8,
                #[storage(prefix = "different/")]
                second: u16,
            }
        };
        let fingerprint = state_schema_fingerprint(&base);

        assert_ne!(fingerprint, state_schema_fingerprint(&reordered));
        assert_ne!(fingerprint, state_schema_fingerprint(&changed_type));
        assert_ne!(fingerprint, state_schema_fingerprint(&archive_attr));
        assert_ne!(fingerprint, state_schema_fingerprint(&storage_attr));
    }

    #[test]
    fn state_fingerprint_normalizes_equivalent_integer_literals() {
        let decimal: syn::ItemStruct = syn::parse_quote! {
            struct State { bytes: [u8; 16] }
        };
        let hexadecimal: syn::ItemStruct = syn::parse_quote! {
            struct State { bytes: [u8; 0x10] }
        };
        let separated: syn::ItemStruct = syn::parse_quote! {
            struct State { bytes: [u8; 1_6] }
        };

        let expected = state_schema_fingerprint(&decimal);
        assert_eq!(expected, state_schema_fingerprint(&hexadecimal));
        assert_eq!(expected, state_schema_fingerprint(&separated));
    }

    #[test]
    fn actor_attributes_reject_typos_and_malformed_values() {
        assert!(parse_actor_attrs(quote!(state_verison = 1)).is_err());
        assert!(parse_actor_attrs(quote!(state_version = CURRENT)).is_err());
        assert!(parse_actor_attrs(quote!(task = "large")).is_err());
        assert!(parse_actor_attrs(quote!(task,, crdt)).is_err());

        let parsed = parse_actor_attrs(quote!(task = 4096, crdt, state_version = 2))
            .expect("valid actor attributes");
        assert_eq!(parsed.task_buf, Some(4096));
        assert!(parsed.crdt);
        assert_eq!(parsed.state_version, 2);
    }
}
