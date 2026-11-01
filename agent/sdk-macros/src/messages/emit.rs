//! The code each handler generates: its dispatch arms and entry bodies.

use super::*;

/// An attestable method's entry, `__vos_attest_<name>`, the root its
/// kernel is derived from, and the entry's row in the program's table.
///
/// A method that states no part beside its output, no venue, reader or
/// `#[public]` argument, returns its output alone. Any other returns its
/// statement's parts: the public arguments, the encodings of the venue, of
/// the reader `(AgentId, InstanceId)` and of each `#[public]` argument in
/// order; its output; and the roots it read. A `&self` method reads, after
/// its arguments, the rows served at a window's cut, which its prologue
/// checks against the space's root before the method runs on its view;
/// its row in the table marks it so, and its kernel reads that much more.
pub(super) fn attestable_entry(
    handler: &Handler,
    actor: &Ident,
    view: &Ident,
    module: &Ident,
    message: &Ident,
) -> (Tokens, Tokens) {
    let method = &handler.method.sig.ident;
    let id = handler.id;
    let names = handler.names();
    let entry = format_ident!("__vos_attest_{}", handler.name);
    let body = if handler.kind == Kind::Device {
        device_body(handler, module, message)
    } else if handler.kind != Kind::Attestable {
        parts_body(handler, view, module, message)
    } else {
        quote! {
            let ::core::result::Result::Ok((#module::#message { #(#names),* }, _)) =
                <#module::#message as ::vos_sdk::Decode>::decode(input)
            else {
                ::core::panic!("undecodable arguments")
            };
            let output = ::vos_sdk::Encode::encode(&Self::#method(#(#names),*));
            // SAFETY: the caller's contract.
            unsafe { ::vos_sdk::runtime::attested_output(output, io_hash) }
        }
    };
    let function = quote! {
        /// Run this method on its encoded arguments, `len` bytes at
        /// `arguments`, leaving its encoded output where the result
        /// says and its io-hash at `io_hash`: the root of its kernel,
        /// the program derived from what this entry reaches.
        ///
        /// # Safety
        ///
        /// `arguments` must point at `len` readable bytes, and `io_hash`
        /// at 32 writable ones.
        #[doc(hidden)]
        #[inline(never)]
        pub unsafe extern "C" fn #entry(
            arguments: *const u8,
            len: u64,
            io_hash: *mut [u8; 32],
        ) -> ::vos_sdk::runtime::Output {
            // SAFETY: the caller's contract.
            let input = unsafe { ::core::slice::from_raw_parts(arguments, len as usize) };
            #body
        }
    };
    let word = match handler.kind {
        Kind::Reading => quote!(#id as u64 | ::vos_sdk::runtime::READS_SERVED),
        Kind::Device => quote!(#id as u64 | ::vos_sdk::runtime::DEVICE),
        _ => quote!(#id as u64),
    };
    let row = quote! {
        ::vos_sdk::runtime::Attestable {
            method: #word,
            entry: super::#actor::#entry,
        }
    };
    (function, row)
}

/// A device kernel's entry's body: its parts written once, in place, and
/// their io-hash the Poseidon2 one ([`vos_sdk::device::DeviceReturn`]),
/// whatever parts it states.
pub(super) fn device_body(handler: &Handler, module: &Ident, message: &Ident) -> Tokens {
    let method = &handler.method.sig.ident;
    let names = handler.names();
    let publics = handler
        .arguments
        .iter()
        .zip(&handler.public)
        .filter(|(_, public)| **public)
        .map(|((name, _), _)| quote!(::vos_sdk::Encode::encode_to(&#name, parts.public_args());));
    quote! {
        let ::core::result::Result::Ok((#module::#message { #(#names),* }, _)) =
            <#module::#message as ::vos_sdk::Decode>::decode(input)
        else {
            ::core::panic!("undecodable arguments")
        };
        let mut parts = ::vos_sdk::device::DeviceReturn::new();
        #(#publics)*
        let output = Self::#method(#(#names),*);
        ::vos_sdk::Encode::encode_to(&output, parts.output());
        // SAFETY: the caller's contract.
        unsafe { parts.end(io_hash) }
    }
}

/// An attestable entry's body when its method states parts beside its
/// output: a venue, the reader or a `#[public]` argument.
pub(super) fn parts_body(
    handler: &Handler,
    view: &Ident,
    module: &Ident,
    message: &Ident,
) -> Tokens {
    let method = &handler.method.sig.ident;
    let names = handler.names();
    let venue = handler.options.venue_bound.map(|_| quote!(venue,));
    let bound = handler
        .options
        .venue_bound
        .map(|_| quote!(::vos_sdk::Encode::encode_to(&venue, &mut public_args);));
    let publics = handler
        .arguments
        .iter()
        .zip(&handler.public)
        .filter(|(_, public)| **public)
        .map(|((name, _), _)| quote!(::vos_sdk::Encode::encode_to(&#name, &mut public_args);));
    let (served, reader, call, roots) = if handler.kind == Kind::Reading {
        (
            quote! {
                let served = ::vos_sdk::runtime::served(&input[used..]);
                let root = ::vos_sdk::runtime::verify_served(served);
                let view = <#view as ::vos_sdk::state::View>::served(served);
            },
            quote!(::vos_sdk::Encode::encode_to(&(served.agent, served.instance), &mut public_args);),
            quote!(view.#method(#(#names),*)),
            quote!(::vos_sdk::Vec::from([root])),
        )
    } else {
        (
            quote!(let _ = used;),
            quote!(),
            quote!(Self::#method(#(#names),*)),
            quote!(::vos_sdk::Vec::new()),
        )
    };
    quote! {
        let ::core::result::Result::Ok((#module::#message { #venue #(#names),* }, used)) =
            <#module::#message as ::vos_sdk::Decode>::decode(input)
        else {
            ::core::panic!("undecodable arguments")
        };
        #served
        let mut public_args = ::vos_sdk::Vec::new();
        #bound
        #reader
        #(#publics)*
        let output = ::vos_sdk::Encode::encode(&#call);
        // SAFETY: the caller's contract.
        unsafe { ::vos_sdk::runtime::attested(public_args, output, #roots, io_hash) }
    }
}

/// A workflow's arm of the dispatcher: its arguments decoded, its context
/// made when it takes one, and its outcome passed to the agent.
pub(super) fn workflow_arm(handler: &Handler, actor: &Ident, message: &Ident) -> Tokens {
    let method = &handler.method.sig.ident;
    let id = handler.id;
    let names = handler.names();
    let (context, argument) = if handler.has_context {
        (
            quote!(let mut context = ::vos_sdk::context::Workflow::<super::#actor>::new();),
            quote!(&mut context,),
        )
    } else {
        (quote!(), quote!())
    };
    let outcome = outcome(
        handler,
        quote!(super::#actor::#method(#argument #(#names),*)),
        quote!(),
    );
    quote! {
        #id => {
            ::vos_sdk::heap::whole_arena();
            let #message { #(#names),* } = ::vos_sdk::runtime::arguments::<#message>();
            #context
            #outcome
        }
    }
}

/// A handler's arm of the dispatcher: its message decoded, its instance's
/// state loaded, its outcome passed to the agent, and a command's state
/// saved when it replies.
pub(super) fn handler_arm(handler: &Handler, actor: &Ident, message: &Ident) -> Tokens {
    let method = &handler.method.sig.ident;
    let id = handler.id;
    let names = handler.names();
    let context = match (handler.kind, handler.has_context) {
        (Kind::Query, true) => quote!(&::vos_sdk::context::Query::new(),),
        (Kind::Command, true) => quote!(&mut ::vos_sdk::context::Command::new(),),
        _ => quote!(),
    };
    let (state, save) = if handler.kind == Kind::Command {
        (
            quote! {
                let mut state = ::vos_sdk::state::load::<super::#actor>();
                let before = ::vos_sdk::Encode::encode(&state);
            },
            quote!(::vos_sdk::state::save(&state, &before);),
        )
    } else {
        (
            quote!(let state = ::vos_sdk::state::load::<super::#actor>();),
            quote!(),
        )
    };
    let outcome = outcome(
        handler,
        quote!(state.#method(#context #(message.#names),*)),
        save,
    );
    quote! {
        #id => {
            let message = ::vos_sdk::runtime::arguments::<#message>();
            #state
            #outcome
        }
    }
}

/// The method's `call`, run to completion when it is `async`: its reply,
/// after `save`, or its error, passed to the agent. A method that cannot
/// fail always replies.
pub(super) fn outcome(handler: &Handler, call: Tokens, save: Tokens) -> Tokens {
    let call = if handler.method.sig.asyncness.is_some() {
        quote!(::vos_sdk::runtime::block_on(#call))
    } else {
        call
    };
    let result = if handler.error.is_some() {
        call
    } else {
        quote!(::core::result::Result::<_, ::vos_sdk::context::Never>::Ok(#call))
    };
    quote! {
        match #result {
            ::core::result::Result::Ok(reply) => {
                #save
                ::vos_sdk::host::reply(&::vos_sdk::Encode::encode(&reply));
            }
            ::core::result::Result::Err(error) => {
                ::vos_sdk::host::fail(&::vos_sdk::Encode::encode(&error));
            }
        }
    }
}
