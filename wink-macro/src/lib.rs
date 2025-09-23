use proc_macro::{Span, TokenStream};
use quote::quote;
use syn::{
    parse2, parse_macro_input, spanned::Spanned, Attribute, FnArg, Ident, ImplItem, Item,
    ItemConst, ItemImpl, ItemMod, LitStr, Pat, PatIdent, ReturnType, Type, TypePath,
};

#[proc_macro_attribute]
pub fn bin(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as ItemMod);
    let mod_name = &input.ident;
    let mut content = input.content.expect("Module must have a body").1;

    let mut methods = Vec::new();
    let storage_name = {
        let mut storage_struct = None;
        if let Err(e) = content.iter_mut().try_for_each(|item| {
            match item {
                Item::Struct(ty) => {
                    if has_wink_attr(&ty.attrs, "storage") {
                        if storage_struct.is_none() {
                            ty.attrs.retain(|attr| !is_wink_attr(attr));
                            storage_struct = Some(ty);
                        } else {
                            return Err(syn::Error::new(
                                ty.span(),
                                "Multiple storage items declared",
                            ));
                        }
                    }
                }
                Item::Impl(i) => process_impl_block(i, &mut methods)?,
                _ => {}
            };
            Ok(())
        }) {
            return e.into_compile_error().into();
        }
        storage_struct.expect("foo").ident.clone()
    };

    let metadata = metadata(mod_name, &methods);
    let bin_impl = impl_bin(mod_name, &storage_name, &methods);

    let expanded = quote! {
        pub mod #mod_name {
            use wink::prelude::*;
            #(#content)*
        }

        #bin_impl

        #metadata

        async fn __main(args: wink::Arguments) {
            let mgr = __bin::get_manager();
            match wink::RunMode::from_args(args) {
                Some(wink::RunMode::Nu) => wink::run_nu_plugin(mgr).await,
                Some(wink::RunMode::StandAloneHttp(port)) => wink::http::run_server(port, mgr).await,
                _ => {}
            };
        }

        fn main() {
            wink::logger::init();
            wink::run(|s|
                s.must_spawn(embassy_task(wink::Arguments::from_env()))
            );

            fn embassy_task(args: wink::Arguments) -> wink::executor::SpawnToken<impl Sized> {
                trait _EmbassyInternalTaskTrait {
                    type Fut: ::core::future::Future + 'static;
                    fn construct(args: wink::Arguments) -> Self::Fut;
                }
                impl _EmbassyInternalTaskTrait for () {
                    type Fut = impl core::future::Future + 'static;
                    fn construct(args: wink::Arguments) -> Self::Fut {
                        __main(args)
                    }
                }
                static POOL: wink::executor::raw::TaskPool<<() as _EmbassyInternalTaskTrait>::Fut, 1> =
                    wink::executor::raw::TaskPool::new();
                unsafe { POOL._spawn_async_fn(move || <() as _EmbassyInternalTaskTrait>::construct(args)) }
            }
        }

    };

    TokenStream::from(expanded)
}

struct MethodInfo {
    name: Ident,
    args: Vec<(Ident, Type)>,
    doc: Option<String>,
    is_async: bool,
    returns_result: bool,
}

fn metadata(mod_name: &Ident, methods: &[MethodInfo]) -> syn::ItemMod {
    let (idents, cmds) = methods
        .iter()
        .map(|m| {
            let args = m.args.iter().map(|(id, ty)| {
                let name = id.to_string();
                quote!(wink::Arg {
                    name: #name,
                    ty: stringify!(#ty),
                })
            });
            let name = m.name.to_string();
            let name_up = Ident::new(&name.to_uppercase(), Span::mixed_site().into());
            let desc = m.doc.clone().unwrap_or_default();
            let const_cmd = parse2::<ItemConst>(quote! {
                const #name_up: wink::Cmd = wink::Cmd {
                    name: #name,
                    desc: #desc,
                    args: &[#(#args),*],
                };
            })
            .expect("const");
            (name_up, const_cmd)
        })
        .unzip::<_, _, Vec<_>, Vec<_>>();
    let name = mod_name.to_string();
    parse2(quote! {
        mod __meta {
            use std::sync::OnceLock;

            #(#cmds)*
            pub const CMDS: &[&wink::Cmd] = &[#(&#idents),*];
            static NU_SIGNATURE: OnceLock<Vec<wink::protocol::CmdSignature>> = OnceLock::new();
            pub fn signature() -> &'static [wink::protocol::CmdSignature] {
                let sig = NU_SIGNATURE.get_or_init(||  wink::to_nu_signature(#name, CMDS));
                sig.as_slice()
            }
        }
    })
    .expect("meta mod")
}

fn impl_bin(mod_name: &Ident, data: &Ident, methods: &[MethodInfo]) -> syn::ItemMod {
    let cmds = methods
        .iter()
        .map(|m| {
            let name = m.name.clone();
            let cmd = LitStr::new(&format!("{name}"), Span::mixed_site().into());
            let wait = if m.is_async {
                quote!( .await )
            } else {
                quote!()
            };
            let result = if m.returns_result {
                quote!( .map_err(|e| format!("{e:?}"))? )
            } else {
                quote!()
            };
            let args = m.args.iter().enumerate().map(|(i, (_, ty))| {
                quote! {
                    #ty::try_from(args.remove(#i)).expect("supported type"),
                }
            });
            quote! {
                #cmd => Ok(Box::new(self.#name(#(#args)*)#wait #result) as Box<dyn Serialize>),
            }
        })
        .collect::<Vec<_>>();

    parse2(quote! {
        mod __bin {
            use std::future::Future;
            use wink::prelude::Serialize;

            pub static BIN_MANAGER: std::sync::OnceLock<Manager> = std::sync::OnceLock::new();
            pub fn get_manager() -> &'static Manager {
                BIN_MANAGER.get_or_init(|| Manager)
            }

            pub struct Manager;
            impl wink::protocol::BinManager for &Manager {
                type Bin = super::#mod_name::#data;
                fn bin_signature() -> &'static [wink::protocol::CmdSignature] {
                    super::__meta::signature()
                }
                async fn get_bin(&self) -> Result<Self::Bin, impl wink::io::Error> {
                    // TODO
                    Ok::<_, std::io::Error>(Default::default())
                }
                async fn save_bin(&mut self, bin: Self::Bin) -> Result<(), impl wink::io::Error> {
                    // TODO
                    Ok::<_, std::io::Error>(())
                }
            }

            impl wink::protocol::Bin for super::#mod_name::#data {
                async fn call(
                    &mut self,
                    cmd: &str,
                    mut args: Vec<wink::protocol::NuType>
                ) -> Result<Box<dyn Serialize>, String> {
                    match cmd {
                        #(#cmds)*
                        _ => Err("Not Found".into()),
                    }
                }
            }
        }
    })
    .expect("impl bin")
}

fn process_impl_block(impl_block: &mut ItemImpl, methods: &mut Vec<MethodInfo>) -> syn::Result<()> {
    // Process each method in the impl block to extract needed data
    for item in impl_block.items.iter_mut() {
        if let ImplItem::Fn(ref mut method) = item {
            if has_wink_attr(&method.attrs, "message") {
                method.attrs.retain(|a| !is_wink_attr(a));

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
                    .collect::<Vec<_>>();

                let extract_doc = |a: &syn::Attribute| {
                    if let syn::Expr::Lit(syn::ExprLit {
                        lit: syn::Lit::Str(doc),
                        ..
                    }) = &a.meta.require_name_value().unwrap().value
                    {
                        doc.value().trim().into()
                    } else {
                        unreachable!()
                    }
                };
                let doc = method
                    .attrs
                    .iter()
                    .find(|a| a.path().is_ident("doc"))
                    .map(extract_doc);

                methods.push(MethodInfo {
                    name: method.sig.ident.clone(),
                    args,
                    doc,
                    is_async: method.sig.asyncness.is_some(),
                    returns_result: has_result_return(&method.sig.output),
                });
            } else if has_wink_attr(&method.attrs, "constructor") {
                method.attrs.retain(|a| !is_wink_attr(a));
            }
        }
    }
    Ok(())
}

fn is_wink_attr(attr: &Attribute) -> bool {
    if let Some(ident) = attr.path().get_ident() {
        ident == "wink"
    } else {
        false
    }
}

fn has_wink_attr(attrs: &[Attribute], name: &str) -> bool {
    attrs.iter().any(|attr| {
        if let Some(ident) = attr.path().get_ident() {
            if ident == "wink" {
                if let Ok(meta) = attr.meta.require_list() {
                    let content = meta.tokens.to_string();
                    return content.contains(name);
                }
            }
        }
        false
    })
}

fn has_result_return(return_type: &ReturnType) -> bool {
    match return_type {
        ReturnType::Default => false,
        ReturnType::Type(_, ty) => is_ty_one_of(ty, ["Result"]),
    }
}
fn is_ty_one_of<const N: usize>(ty: &Type, allowed: [&str; N]) -> bool {
    if let Type::Path(TypePath { path, .. }) = ty {
        if let Some(segment) = path.segments.last() {
            return allowed.into_iter().any(|ty| segment.ident == ty);
        }
    }
    false
}
