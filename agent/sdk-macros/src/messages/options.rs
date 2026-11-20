//! A handler's `#[msg(..)]` options, parsed and checked.

use super::*;

/// A handler's options, from `#[msg(role = "...", gas = N, linearizable)]`
/// or `#[msg(merge, gas = N)]`,
/// or an attestable method's, from `#[attestable(gas = N, venue_bound,
/// device, reference = path, headroom = k)]`.
#[derive(Default)]
pub(super) struct Options {
    pub(super) role: Option<String>,
    pub(super) gas: Option<u64>,
    /// A query that always reads after a read index.
    pub(super) linearizable: Option<Span>,
    /// An attestable method whose statements bind the venue that judges
    /// them: a leading `venue: VenueId` public argument.
    pub(super) venue_bound: Option<Span>,
    /// `credential = Auth("name")` or `credential = Owner`; a `proven = k`
    /// guard once its kernel is resolved.
    pub(super) credential: Option<(CredentialGuard, Span)>,
    /// `proven = k`: the device kernel the handler's proofs are of, this
    /// actor's or a stock kernel, resolved once every handler is read.
    pub(super) proven: Option<(String, Span)>,
    /// An attestable method that is a device kernel, `device`.
    pub(super) device_kernel: Option<Span>,
    /// A device kernel's reference run, `reference = path`: the function
    /// giving its reference arguments, a public, valid witness.
    pub(super) reference: Option<syn::Path>,
    /// A device kernel's headroom, `headroom = k`: each log size of its
    /// program raised by `k` over its reference run's.
    pub(super) headroom: Option<(u8, Span)>,
    /// An auth guard that admits each nullifier once, `once`.
    pub(super) once: Option<Span>,
    /// A merge handler, `merge`.
    pub(super) merge: Option<Span>,
}

/// `Auth("name")` or `Owner`, a guard's value.
pub(super) fn credential_arg(meta: &syn::meta::ParseNestedMeta) -> syn::Result<CredentialGuard> {
    let expected = || meta.error("expected `credential = Auth(\"name\")` or `credential = Owner`");
    match meta.value()?.parse::<Expr>()? {
        Expr::Path(path) if path.path.is_ident("Owner") => Ok(CredentialGuard::Owner),
        Expr::Call(call) => {
            let Expr::Path(function) = &*call.func else {
                return Err(expected());
            };
            if !function.path.is_ident("Auth") || call.args.len() != 1 {
                return Err(expected());
            }
            let Some(Expr::Lit(ExprLit {
                lit: Lit::Str(name),
                ..
            })) = call.args.first()
            else {
                return Err(expected());
            };
            let name = name.value().into_bytes();
            if !(1..=MAX_GUARD_NAME).contains(&name.len()) {
                return Err(meta.error(format!(
                    "an auth guard's name takes 1 to {MAX_GUARD_NAME} bytes"
                )));
            }
            Ok(CredentialGuard::Auth { name, once: false })
        }
        _ => Err(expected()),
    }
}

pub(super) fn msg_options(attribute: &Attribute) -> syn::Result<Options> {
    let mut options = Options::default();
    if let Meta::List(_) = attribute.meta {
        attribute.parse_nested_meta(|meta| {
            if meta.path.is_ident("role") {
                options.role = Some(string_arg(&meta)?);
            } else if meta.path.is_ident("linearizable") {
                options.linearizable = Some(meta.path.span());
            } else if meta.path.is_ident("venue_bound") {
                options.venue_bound = Some(meta.path.span());
            } else if meta.path.is_ident("credential") {
                let span = meta.path.span();
                options.credential = Some((credential_arg(&meta)?, span));
            } else if meta.path.is_ident("proven") {
                if options.proven.is_some() {
                    return Err(meta.error("`proven = k` given twice"));
                }
                let span = meta.path.span();
                let kernel = meta.value()?.parse::<Ident>()?;
                options.proven = Some((kernel.to_string(), span));
            } else if meta.path.is_ident("device") {
                if options.device_kernel.is_some() {
                    return Err(meta.error("`device` given twice"));
                }
                options.device_kernel = Some(meta.path.span());
            } else if meta.path.is_ident("reference") {
                if options.reference.is_some() {
                    return Err(meta.error("`reference = ...` given twice"));
                }
                options.reference = Some(meta.value()?.parse::<syn::Path>()?);
            } else if meta.path.is_ident("headroom") {
                if options.headroom.is_some() {
                    return Err(meta.error("`headroom = k` given twice"));
                }
                let span = meta.path.span();
                let Expr::Lit(ExprLit {
                    lit: Lit::Int(value),
                    ..
                }) = meta.value()?.parse::<Expr>()?
                else {
                    return Err(meta.error("expected an integer headroom"));
                };
                let headroom: u8 = value.base10_parse()?;
                if headroom > vos_abi::records::MAX_HEADROOM {
                    return Err(meta.error(format!(
                        "a device kernel's headroom is at most {}",
                        vos_abi::records::MAX_HEADROOM
                    )));
                }
                options.headroom = Some((headroom, span));
            } else if meta.path.is_ident("once") {
                options.once = Some(meta.path.span());
            } else if meta.path.is_ident("merge") {
                options.merge = Some(meta.path.span());
            } else if meta.path.is_ident("gas") {
                let Expr::Lit(ExprLit {
                    lit: Lit::Int(value),
                    ..
                }) = meta.value()?.parse::<Expr>()?
                else {
                    return Err(meta.error("expected an integer gas limit"));
                };
                options.gas = Some(value.base10_parse()?);
            } else {
                return Err(meta.error(
                    "expected `role = \"...\"`, `gas = N`, `linearizable`, `merge`, \
                     `venue_bound`, `device`, `reference = path`, `headroom = k`, \
                     `credential = ...`, `proven = k` or `once`",
                ));
            }
            Ok(())
        })?;
    }
    Ok(options)
}

/// A handler's guard, `once` folded in: only a command takes one, with no
/// role and not linearizable; `once` only beside an auth guard, and
/// `credential` and `proven` not together. A `proven` guard's kernel is
/// resolved later ([`resolve`]).
pub(super) fn guard(options: &mut Options, kind: Kind) -> syn::Result<()> {
    let span = match (&options.credential, &options.proven) {
        (Some(_), Some((_, span))) => {
            return Err(Error::new(
                *span,
                "a handler takes `credential = ...` or `proven = k`, not both",
            ));
        }
        (Some((_, span)), None) | (None, Some((_, span))) => *span,
        (None, None) => {
            if let Some(span) = options.once {
                return Err(Error::new(
                    span,
                    "`once` goes with `credential = Auth(\"...\")`",
                ));
            }
            return Ok(());
        }
    };
    if kind != Kind::Command || options.role.is_some() || options.linearizable.is_some() {
        return Err(Error::new(
            span,
            "a guard sits on a `&mut self` #[msg] handler alone, with no role and not \
             `linearizable`: the proof is its caller's authority",
        ));
    }
    match &mut options.credential {
        Some((CredentialGuard::Auth { once, .. }, _)) => *once = options.once.take().is_some(),
        _ => {
            if let Some(span) = options.once {
                return Err(Error::new(
                    span,
                    "`once` goes with `credential = Auth(\"...\")` alone",
                ));
            }
        }
    }
    Ok(())
}

/// The guard `proven = kernel` names, given `devices`, this actor's device
/// kernels by name: this actor's kernel of that name. A stock kernel's
/// guard is `credential = Auth("name")` or `credential = Owner`.
pub(super) fn resolve(kernel: &str, span: Span, devices: &[&str]) -> syn::Result<CredentialGuard> {
    if devices.contains(&kernel) {
        return Ok(CredentialGuard::Kernel {
            name: kernel.as_bytes().to_vec(),
        });
    }
    match kernel {
        vos_abi::schema::stock::OWNER => Err(Error::new(
            span,
            "the stock `owner` kernel's guard is `credential = Owner`",
        )),
        vos_abi::schema::stock::AUTH => Err(Error::new(
            span,
            "the stock `auth` kernel proves a pseudonym in a scope: name it, \
             `credential = Auth(\"name\")`",
        )),
        _ => Err(Error::new(
            span,
            format!(
                "`proven = {kernel}` names no #[attestable(device)] method of this actor, and no \
                 stock kernel"
            ),
        )),
    }
}

/// The kind an attribute marks a method to run as, apart from a handler:
/// `#[attestable]` or `#[workflow]`.
pub(super) fn mark(attribute: &Attribute) -> Option<Kind> {
    if attribute.path().is_ident("attestable") {
        Some(Kind::Attestable)
    } else if attribute.path().is_ident("workflow") {
        Some(Kind::Workflow)
    } else {
        None
    }
}
