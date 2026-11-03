//! A handler's `#[msg(..)]` options, parsed and checked.

use super::*;

/// A handler's options, from `#[msg(role = "...", gas = N, linearizable)]`,
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
    /// `credential = Auth("name")` or `credential = Owner`.
    pub(super) credential: Option<(CredentialGuard, Span)>,
    /// An auth guard's device kernel, `device = "..."`.
    pub(super) device: Option<(String, Span)>,
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
            Ok(CredentialGuard::Auth {
                name,
                device: None,
                once: false,
            })
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
            } else if meta.path.is_ident("device") {
                let span = meta.path.span();
                if meta.input.peek(syn::Token![=]) {
                    if options.device.is_some() {
                        return Err(meta.error("`device = \"...\"` given twice"));
                    }
                    options.device = Some((string_arg(&meta)?, span));
                } else {
                    if options.device_kernel.is_some() {
                        return Err(meta.error("`device` given twice"));
                    }
                    options.device_kernel = Some(span);
                }
            } else if meta.path.is_ident("reference") {
                if options.reference.is_some() {
                    return Err(meta.error("`reference = ...` given twice"));
                }
                options.reference = Some(meta.value()?.parse::<syn::Path>()?);
            } else if meta.path.is_ident("headroom") {
                let span = meta.path.span();
                let Expr::Lit(ExprLit {
                    lit: Lit::Int(value),
                    ..
                }) = meta.value()?.parse::<Expr>()?
                else {
                    return Err(meta.error("expected an integer headroom"));
                };
                let headroom: u8 = value.base10_parse()?;
                if headroom > vos_wire::records::MAX_HEADROOM {
                    return Err(meta.error(format!(
                        "a device kernel's headroom is at most {}",
                        vos_wire::records::MAX_HEADROOM
                    )));
                }
                options.headroom = Some((headroom, span));
            } else if meta.path.is_ident("once") {
                options.once = Some(meta.path.span());
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
                    "expected `role = \"...\"`, `gas = N`, `linearizable`, `venue_bound`, \
                     `device`, `reference = path`, `headroom = k`, `credential = ...`, \
                     `device = \"...\"` or `once`",
                ));
            }
            Ok(())
        })?;
    }
    Ok(options)
}

/// A handler's credential guard, its `device` and `once` folded in: only
/// a command takes one, with no role and not linearizable; `device` and
/// `once` only beside an auth guard.
pub(super) fn guard(options: &mut Options, kind: Kind) -> syn::Result<()> {
    let Some((guard, span)) = &mut options.credential else {
        if let Some(span) = options
            .device
            .as_ref()
            .map(|(_, span)| *span)
            .or(options.once)
        {
            return Err(Error::new(
                span,
                "`device` and `once` go with `credential = Auth(\"...\")`",
            ));
        }
        return Ok(());
    };
    if kind != Kind::Command || options.role.is_some() || options.linearizable.is_some() {
        return Err(Error::new(
            *span,
            "a credential guard sits on a `&mut self` #[msg] handler alone, with no role and not \
             `linearizable`: the proof is its caller's authority",
        ));
    }
    match guard {
        CredentialGuard::Auth { device, once, .. } => {
            *device = options.device.take().map(|(name, _)| name.into_bytes());
            *once = options.once.take().is_some();
        }
        CredentialGuard::Owner => {
            if let Some(span) = options
                .device
                .as_ref()
                .map(|(_, span)| *span)
                .or(options.once)
            {
                return Err(Error::new(
                    span,
                    "`device` and `once` go with `credential = Auth(\"...\")`, not `Owner`",
                ));
            }
        }
    }
    Ok(())
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
