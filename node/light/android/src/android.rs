// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The facility's JNI, which the app's `:vos` process calls
//! (`team.virto.s4.vos.VosNode`): each native method one operation of one
//! of the Binder interfaces it serves (s4's `IVosNode`, the facility's own
//! `IVosPersonal`), its request and result the interfaces' parcelables
//! (`s4_credential_contract::java`, [`crate::personal::contract`]), a
//! refusal written into the operation's `out Refusal`, its result then null
//! (or false, or 0). The client's prompts are the `IVosPrompts` it lent the
//! operation, called back through Binder; the device's kinds are
//! `VosNode.kinds()`.
//!
//! Every native method is one entry of the one [`natives!`] table, which
//! the tests hold the Java classes' `native` declarations to (`NATIVES`).
//! Nothing here unwinds into the JVM: a panic is a refusal of
//! [`Code::Failed`].

use std::os::fd::FromRawFd as _;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use crate::personal::{Claim, Home, KitKind, Membership, Refused, contract};
use jni::errors::LogErrorAndDefault;
use jni::objects::{Global, JByteArray, JClass, JLongArray, JObject, JObjectArray, JString};
use jni::sys::{jboolean, jbyte, jint, jlong};
use jni::{Env, EnvUnowned, JValue, JavaVM, jni_sig, jni_str};
use s4_credential_contract::java::{self, JavaError, Parcel};
use s4_credential_contract::{Answer, Code, Form, Gateway, KeyAnswer, Refusal};

use crate::node::{Device, Node, Prompts};
use crate::source::Kind;
use crate::{Enroll, EnrolledSpace, JobRun, Pay, SignIn, StreamTarget, refused};

static VM: OnceLock<JavaVM> = OnceLock::new();

/// The process's `VosNode`, which each flow's stage is handed to
/// (`VosNode.stage`): a sign-in's or a payment's to its announcing prompts,
/// a personal flow's to the screens' watcher.
static VOS_NODE: OnceLock<Global<JObject<'static>>> = OnceLock::new();

fn failed(error: impl std::fmt::Display) -> Refusal {
    refused(Code::Failed, error.to_string())
}

/// `call` on this thread, attached to the VM.
fn attached<T>(call: impl FnOnce(&mut Env<'_>) -> Result<T, Refusal>) -> Result<T, Refusal> {
    let vm = VM.get().ok_or_else(|| failed("the facility is not open"))?;
    vm.attach_current_thread(|env| -> Result<Result<T, Refusal>, jni::errors::Error> {
        Ok(call(env))
    })
    .map_err(failed)?
}

/// The prompts a client lent an operation: its `IVosPrompts`, across
/// Binder. A client gone, or a prompt that fails, declines.
struct Lent {
    prompts: Global<JObject<'static>>,
}

/// A key's answer, or the failure the call threw: a client gone, say.
fn key_answer(
    env: &mut Env<'_>,
    answer: jni::errors::Result<JObject<'_>>,
) -> Result<KeyAnswer, Refusal> {
    match answer {
        Ok(answer) => Ok(KeyAnswer::from_java(env, &answer)?),
        Err(_) => Ok(KeyAnswer::Failed(java::refusal(env).message)),
    }
}

impl Prompts for Lent {
    fn confirm(&self, form: Form) -> Answer {
        attached(|env| {
            let form = form.to_java(env)?;
            let answer = env
                .call_method(
                    &self.prompts,
                    jni_str!("confirm"),
                    jni_sig!("(Lteam/virto/s4/vos/Form;)Lteam/virto/s4/vos/Answer;"),
                    &[JValue::Object(&form)],
                )
                .and_then(|answer| answer.l());
            match answer {
                Ok(answer) => Ok(Answer::from_java(env, &answer)?),
                Err(_) => {
                    java::refusal(env);
                    Ok(Answer::Declined)
                }
            }
        })
        .unwrap_or(Answer::Declined)
    }

    fn create_key(&self, kind: Kind) -> KeyAnswer {
        attached(|env| {
            let answer = env
                .call_method(
                    &self.prompts,
                    jni_str!("createKey"),
                    jni_sig!("(B)Lteam/virto/s4/vos/KeyResult;"),
                    &[JValue::Byte(kind as i8)],
                )
                .and_then(|answer| answer.l());
            key_answer(env, answer)
        })
        .unwrap_or_else(|refusal| KeyAnswer::Failed(refusal.message))
    }

    fn evaluate_key(&self, kind: Kind, key: &[u8], input: &[u8; 32]) -> KeyAnswer {
        attached(|env| {
            let key = env.byte_array_from_slice(key).map_err(failed)?;
            let input = env.byte_array_from_slice(input).map_err(failed)?;
            let answer = env
                .call_method(
                    &self.prompts,
                    jni_str!("evaluateKey"),
                    jni_sig!("(B[B[B)Lteam/virto/s4/vos/KeyResult;"),
                    &[
                        JValue::Byte(kind as i8),
                        JValue::Object(&key),
                        JValue::Object(&input),
                    ],
                )
                .and_then(|answer| answer.l());
            key_answer(env, answer)
        })
        .unwrap_or_else(|refusal| KeyAnswer::Failed(refusal.message))
    }

    fn sign_key(&self, kind: Kind, key: &[u8], message: &[u8]) -> KeyAnswer {
        attached(|env| {
            let key = env.byte_array_from_slice(key).map_err(failed)?;
            let message = env.byte_array_from_slice(message).map_err(failed)?;
            let answer = env
                .call_method(
                    &self.prompts,
                    jni_str!("signKey"),
                    jni_sig!("(B[B[B)Lteam/virto/s4/vos/KeyResult;"),
                    &[
                        JValue::Byte(kind as i8),
                        JValue::Object(&key),
                        JValue::Object(&message),
                    ],
                )
                .and_then(|answer| answer.l());
            key_answer(env, answer)
        })
        .unwrap_or_else(|refusal| KeyAnswer::Failed(refusal.message))
    }

    fn stage(&self, stage: crate::personal::Stage) {
        let Some(node) = VOS_NODE.get() else {
            return;
        };
        let _ = attached(|env| {
            env.call_method(
                &**node,
                jni_str!("stage"),
                jni_sig!("(Lteam/virto/s4/vos/IVosPrompts;B)V"),
                &[JValue::Object(&self.prompts), JValue::Byte(stage as i8)],
            )
            .map(drop)
            .map_err(|_| java::refusal(env))
        });
    }
}

/// The device, as `VosNode` reads it in this process.
struct JavaDevice {
    node: Global<JObject<'static>>,
}

impl Device for JavaDevice {
    fn kinds(&self) -> Vec<Kind> {
        attached(|env| {
            env.call_method(&self.node, jni_str!("kinds"), jni_sig!("()I"), &[])
                .and_then(|mask| mask.i())
                .map_err(|_| java::refusal(env))
        })
        .map_or_else(|_| Vec::new(), |mask| Kind::of_mask(mask as u32))
    }
}

/// What an operation refuses with, written into its `out` parcelable:
/// s4's `Refusal`, or a personal flow's `Refused`.
trait Written: From<Refusal> {
    fn write_into(&self, env: &mut Env<'_>, object: &JObject<'_>) -> java::Result<()>;
}

impl Written for Refusal {
    fn write_into(&self, env: &mut Env<'_>, object: &JObject<'_>) -> java::Result<()> {
        Refusal::write_into(self, env, object)
    }
}

impl Written for Refused {
    fn write_into(&self, env: &mut Env<'_>, object: &JObject<'_>) -> java::Result<()> {
        Refused::write_into(self, env, object)
    }
}

/// `operation`'s answer; a refusal written into `refused` (the operation's
/// `out Refusal` or `out Refused`, or null when it has none) with the
/// default answered.
fn answer<'l, T: Default, R: Written>(
    env: &mut Env<'l>,
    refused_into: &JObject<'_>,
    operation: impl FnOnce(&mut Env<'l>) -> Result<T, R>,
) -> T {
    let refusal = match catch_unwind(AssertUnwindSafe(|| operation(env))) {
        Ok(Ok(value)) => return value,
        Ok(Err(refusal)) => refusal,
        Err(_) => R::from(refused(Code::Failed, "the facility failed")),
    };
    env.exception_clear();
    if !refused_into.is_null() && refusal.write_into(env, refused_into).is_err() {
        env.exception_clear();
    }
    T::default()
}

/// The process's facility, which `nativeOpen` opens once and never frees.
static NODE: OnceLock<Node> = OnceLock::new();

fn node() -> Result<&'static Node, Refusal> {
    NODE.get().ok_or_else(|| failed("no facility"))
}

fn prompts(env: &mut Env<'_>, prompts: &JObject<'_>) -> Result<Arc<dyn Prompts>, Refusal> {
    if prompts.is_null() {
        return Err(refused(Code::Arguments, "an operation is lent its prompts"));
    }
    Ok(Arc::new(Lent {
        prompts: env.new_global_ref(prompts).map_err(failed)?,
    }))
}

fn made<'l, P: Parcel, E: From<Refusal>>(env: &mut Env<'l>, value: &P) -> Result<JObject<'l>, E> {
    value
        .to_java(env)
        .map_err(|error: JavaError| E::from(failed(error)))
}

/// `items` as a new array of their parcelable `element`.
fn array<'l, P: Parcel, E: From<Refusal>>(
    env: &mut Env<'l>,
    element: &JClass<'l>,
    items: &[P],
) -> Result<JObjectArray<'l>, E> {
    let array = env
        .new_object_array(items.len() as i32, element, JObject::null())
        .map_err(failed)?;
    for (index, item) in items.iter().enumerate() {
        let item = made::<P, Refusal>(env, item)?;
        array.set_element(env, index, &item).map_err(failed)?;
    }
    Ok(array)
}

fn bytes(env: &mut Env<'_>, array: &JByteArray<'_>) -> Result<Vec<u8>, Refusal> {
    if array.is_null() {
        return Err(refused(Code::Arguments, "a null byte array"));
    }
    env.convert_byte_array(array).map_err(failed)
}

fn longs(env: &mut Env<'_>, array: &JLongArray<'_>) -> Result<Vec<i64>, Refusal> {
    if array.is_null() {
        return Err(refused(Code::Arguments, "a null array"));
    }
    let mut values = vec![0; array.len(env).map_err(failed)?];
    array.get_region(env, 0, &mut values).map_err(failed)?;
    Ok(values)
}

fn word(value: jlong) -> Result<u32, Refusal> {
    u32::try_from(value).map_err(|_| refused(Code::Arguments, "past 32 bits"))
}

fn kit(byte: jbyte) -> Result<KitKind, Refusal> {
    KitKind::from_byte(byte as u8).ok_or_else(|| refused(Code::Arguments, "no such kit kind"))
}

/// The native methods of `VosNode`, each `fn` named as its Java method
/// (its JNI symbol `VosNode`'s), its arguments, its answer and its body,
/// given the environment and the facility. An `op` takes the operation's
/// `out Refusal` last, which a refusal is written into, and a `personal`
/// one its `out Refused`; a `quiet` one takes none; a `bare` one is not
/// given the facility either. Statements after
/// `take` run first, before the environment is reached. `NATIVES` lists
/// every symbol and its Java arity.
macro_rules! natives {
    ($(
        $(#[$doc:meta])*
        $mode:ident fn $name:ident($($argument:ident: $ty:ty),* $(,)?) -> $answer:ty
        $(, take { let $taken:ident = $value:expr; })?,
        |$env:ident $(, $node:ident)?| $body:block
    )*) => {
        $(
            natives!(@$mode $(#[$doc])* $name($($argument: $ty),*) -> $answer
                [$(let $taken = $value;)?] |$env $(, $node)?| $body);
        )*

        /// Every native method: its JNI symbol and its Java arity.
        #[cfg(test)]
        const NATIVES: &[(&str, usize)] = &[
            $((natives!(@symbol $name), natives!(@arity $mode $($argument)*)),)*
        ];
    };
    (@symbol $name:ident) => { concat!("Java_team_virto_s4_vos_VosNode_", stringify!($name)) };
    (@arity op $($argument:ident)*) => { 1 $(+ natives!(@one $argument))* };
    (@arity personal $($argument:ident)*) => { 1 $(+ natives!(@one $argument))* };
    (@arity quiet $($argument:ident)*) => { 0 $(+ natives!(@one $argument))* };
    (@arity bare $($argument:ident)*) => { 0 $(+ natives!(@one $argument))* };
    (@one $argument:ident) => { 1 };
    (@op $($rest:tt)*) => { natives!(@fn [refused Refusal] $($rest)*); };
    (@personal $($rest:tt)*) => { natives!(@fn [refused Refused] $($rest)*); };
    (@quiet $($rest:tt)*) => { natives!(@fn [] $($rest)*); };
    (@bare $($rest:tt)*) => { natives!(@fn [] $($rest)*); };
    (@refused) => { &JObject::null() };
    (@refused $refused:ident) => { &$refused };
    (@error) => { Refusal };
    (@error $error:ty) => { $error };
    (@fn [$($refused:ident $error:ty)?]
     $(#[$doc:meta])* $name:ident($($argument:ident: $ty:ty),*) -> $answer:ty
     [$($take:tt)*] |$env:ident $(, $node:ident)?| $body:block) => {
        $(#[$doc])*
        #[allow(non_snake_case)]
        #[unsafe(export_name = natives!(@symbol $name))]
        pub extern "system" fn $name<'l>(
            mut unowned: EnvUnowned<'l>,
            _class: JClass<'l>,
            $($argument: $ty,)*
            $($refused: JObject<'l>,)?
        ) -> $answer {
            $($take)*
            unowned
                .with_env(|env| -> jni::errors::Result<$answer> {
                    Ok(answer(env, natives!(@refused $($refused)?), |$env| -> Result<_, natives!(@error $($error)?)> {
                        $(let $node = node()?;)?
                        $body
                    }))
                })
                .resolve::<LogErrorAndDefault>()
        }
    };
}

natives! {
    /// The facility whose enrollments are kept under `directory`, arti's
    /// state under `tor`, the app's parcelables loaded through `loader`,
    /// the device read from `device` (the `VosNode`): opened once for the
    /// process, never freed, an open after it the same facility; false when
    /// it does not open.
    bare fn nativeOpen(
        directory: JString<'l>,
        tor: JString<'l>,
        loader: JObject<'l>,
        device: JObject<'l>,
    ) -> jboolean,
    |env| {
        if NODE.get().is_some() {
            return Ok(true);
        }
        let directory = PathBuf::from(directory.try_to_string(env).map_err(failed)?);
        let tor = PathBuf::from(tor.try_to_string(env).map_err(failed)?);
        let _ = VM.set(env.get_java_vm().map_err(failed)?);
        java::init(env, &loader).map_err(failed)?;
        java::load(env, &loader, contract::REGISTRY).map_err(failed)?;
        let _ = VOS_NODE.set(env.new_global_ref(&device).map_err(failed)?);
        let device = Arc::new(JavaDevice {
            node: env.new_global_ref(&device).map_err(failed)?,
        });
        let node = Node::open(directory, tor, device).map_err(failed)?;
        NODE.set(node).map_err(|_| failed("the facility is open already"))?;
        Ok(true)
    }

    quiet fn nativeSupported() -> jboolean, |_env, node| {
        Ok(node.supported())
    }

    quiet fn nativeWarm(thrifty: jboolean) -> (), |_env, node| {
        node.warm(thrifty);
        Ok(())
    }

    op fn nativeOpenSession(gateway: JObject<'l>) -> jlong, |env, node| {
        let gateway = Gateway::from_java(env, &gateway)?;
        Ok(node.open_session(gateway) as jlong)
    }

    op fn nativeGranted(session: jlong) -> jboolean, |_env, node| {
        node.granted(session as u64)?;
        Ok(true)
    }

    quiet fn nativeClose(session: jlong) -> (), |_env, node| {
        node.close(session as u64);
        Ok(())
    }

    op fn nativeEnroll(
        session: jlong,
        request: JObject<'l>,
        lent: JObject<'l>,
    ) -> JObject<'l>,
    |env, node| {
        let request = Enroll::from_java(env, &request)?;
        let lent = prompts(env, &lent)?;
        let enrolled = node.enroll(session as u64, request, lent)?;
        made(env, &enrolled)
    }

    op fn nativeSignIn(
        session: jlong,
        request: JObject<'l>,
        lent: JObject<'l>,
    ) -> JObject<'l>,
    |env, node| {
        let request = SignIn::from_java(env, &request)?;
        let lent = prompts(env, &lent)?;
        let signed = node.sign_in(session as u64, request, lent)?;
        made(env, &signed)
    }

    op fn nativePay(
        session: jlong,
        request: JObject<'l>,
        lent: JObject<'l>,
    ) -> JObject<'l>,
    |env, node| {
        let request = Pay::from_java(env, &request)?;
        let lent = prompts(env, &lent)?;
        let paid = node.pay(session as u64, request, lent)?;
        made(env, &paid)
    }

    op fn nativeRefresh(session: jlong) -> jboolean, |_env, node| {
        node.refresh(session as u64)?;
        Ok(true)
    }

    op fn nativeSync() -> JObject<'l>, |env, node| {
        let synced = node.sync()?;
        made(env, &synced)
    }

    op fn nativeEnrollments(element: JClass<'l>) -> JObjectArray<'l>, |env, node| {
        let all: Vec<EnrolledSpace> = node.enrollments()?;
        array(env, &element, &all)
    }

    op fn nativeRuns(element: JClass<'l>) -> JObjectArray<'l>, |env, node| {
        let all: Vec<JobRun> = node.runs()?;
        array(env, &element, &all)
    }

    /// s4's screen session with the target's gateway, carried between the
    /// UI's end of a socket pair, `descriptor` (owned from here), and that
    /// gateway's SSH port: the SSH host key the space pinned for that port,
    /// or none (an empty array) for an onion service first contacted.
    op fn nativeScreens(
        gateway: JObject<'l>,
        descriptor: jint,
    ) -> JByteArray<'l>,
    // SAFETY: the binder's descriptor, detached for this call alone.
    take { let end = (descriptor >= 0).then(|| unsafe { std::os::fd::OwnedFd::from_raw_fd(descriptor) }); },
    |env, node| {
        let end = end.ok_or_else(|| crate::refused(Code::Arguments, "no socket pair's end"))?;
        let gateway = StreamTarget::from_java(env, &gateway)?;
        let host_key = node.screens(gateway, end)?;
        env.byte_array_from_slice(host_key.as_ref().map_or(&[][..], |key| &key[..]))
            .map_err(failed)
    }

    op fn nativeSyncPersonal() -> JObject<'l>, |env, node| {
        let synced = node.sync_personal()?;
        made(env, &synced)
    }

    op fn nativeForeground(foreground: jboolean) -> jboolean, |_env, node| {
        node.foreground(foreground);
        Ok(true)
    }

    op fn nativeCloseAll(sessions: JLongArray<'l>) -> jboolean, |env, node| {
        let sessions: Vec<u64> = longs(env, &sessions)?.into_iter().map(|session| session as u64).collect();
        node.close_all(&sessions);
        Ok(true)
    }

    op fn nativeBridges(lines: JObjectArray<'l>) -> jboolean, |env, node| {
        let mut all = Vec::new();
        for index in 0..lines.len(env).map_err(failed)? {
            let line = lines.get_element(env, index).map_err(failed)?;
            let line = JString::cast_local(env, line).map_err(failed)?;
            all.push(line.try_to_string(env).map_err(failed)?);
        }
        node.bridges(all)?;
        Ok(true)
    }

    op fn nativeBootstrap() -> jboolean, |_env, node| {
        node.bootstrap()?;
        Ok(true)
    }

    op fn nativeOptOut(space: JByteArray<'l>, out: jboolean) -> jboolean, |env, node| {
        let space: [u8; 32] = bytes(env, &space)?
            .try_into()
            .map_err(|_| refused(Code::Arguments, "a space's handle is 32 bytes"))?;
        node.opt_out(space, out)?;
        Ok(true)
    }

    op fn nativeClearnet(host_key: JByteArray<'l>) -> jboolean, |env, node| {
        let host_key: [u8; 32] = bytes(env, &host_key)?
            .try_into()
            .map_err(|_| refused(Code::Arguments, "an SSH host key is 32 bytes"))?;
        node.clearnet(host_key)?;
        Ok(true)
    }

    personal fn nativeClaim(request: JObject<'l>, lent: JObject<'l>) -> JObject<'l>, |env, node| {
        let request = Claim::from_java(env, &request)?;
        let lent = prompts(env, &lent)?;
        let claimed = node.personal()?.claim(&*lent, request)?;
        made(env, &claimed)
    }

    personal fn nativePairOffer(lent: JObject<'l>) -> JObject<'l>, |env, node| {
        let lent = prompts(env, &lent)?;
        let code = node.personal()?.pair_offer(&*lent)?;
        made(env, &code)
    }

    personal fn nativePairAwait(lent: JObject<'l>) -> JObject<'l>, |env, node| {
        let lent = prompts(env, &lent)?;
        let paired = node.personal()?.pair_await(&*lent)?;
        made(env, &paired)
    }

    personal fn nativePairCancel() -> jboolean, |_env, node| {
        node.space()?.pair_cancel();
        Ok(true)
    }

    personal fn nativePairJoin(code: JByteArray<'l>, label: JString<'l>, lent: JObject<'l>) -> JObject<'l>, |env, node| {
        let code = zeroize::Zeroizing::new(bytes(env, &code)?);
        let label = label.try_to_string(env).map_err(failed)?;
        let lent = prompts(env, &lent)?;
        let paired = node.personal()?.pair_join(&*lent, &code, &label)?;
        made(env, &paired)
    }

    personal fn nativeMemberships(element: JClass<'l>) -> JObjectArray<'l>, |env, node| {
        let all = node.space()?.memberships()?;
        array(env, &element, &all)
    }

    personal fn nativeEnrollDevice(membership: JObject<'l>, lent: JObject<'l>) -> jboolean, |env, node| {
        let membership = Membership::from_java(env, &membership)?;
        let lent = prompts(env, &lent)?;
        node.personal()?.enroll_device(&*lent, membership)?;
        Ok(true)
    }

    personal fn nativeConfirmDevice(membership: JObject<'l>, lent: JObject<'l>) -> jboolean, |env, node| {
        let membership = Membership::from_java(env, &membership)?;
        let lent = prompts(env, &lent)?;
        node.personal()?.confirm_device(&*lent, membership)?;
        Ok(true)
    }

    personal fn nativeDropEnrollment(membership: JObject<'l>) -> jboolean, |env, node| {
        let membership = Membership::from_java(env, &membership)?;
        node.space()?.drop_enrollment(membership)?;
        Ok(true)
    }

    personal fn nativeRevoke(device: jlong, lent: JObject<'l>) -> jint, |env, node| {
        let lent = prompts(env, &lent)?;
        Ok(node.personal()?.revoke(&*lent, word(device)?)? as jint)
    }

    personal fn nativeDevices(element: JClass<'l>) -> JObjectArray<'l>, |env, node| {
        let all = node.personal()?.devices()?;
        array(env, &element, &all)
    }

    personal fn nativeOperations(element: JClass<'l>) -> JObjectArray<'l>, |env, node| {
        let all = node.space()?.operations()?;
        array(env, &element, &all)
    }

    personal fn nativeRemove(device: jlong, lent: JObject<'l>) -> JObject<'l>, |env, node| {
        let lent = prompts(env, &lent)?;
        let posted = node.personal()?.remove(&*lent, word(device)?)?;
        made(env, &posted)
    }

    personal fn nativeVeto(index: jlong, lent: JObject<'l>) -> JObject<'l>, |env, node| {
        let lent = prompts(env, &lent)?;
        let posted = node.personal()?.veto(&*lent, index as u64)?;
        made(env, &posted)
    }

    personal fn nativeCosign(index: jlong, lent: JObject<'l>) -> JObject<'l>, |env, node| {
        let lent = prompts(env, &lent)?;
        let posted = node.personal()?.cosign(&*lent, index as u64)?;
        made(env, &posted)
    }

    personal fn nativeResolve(index: jlong, upheld: jboolean, lent: JObject<'l>) -> JObject<'l>, |env, node| {
        let lent = prompts(env, &lent)?;
        let posted = node.personal()?.resolve(&*lent, index as u64, upheld)?;
        made(env, &posted)
    }

    personal fn nativeRotateKit(kind: jbyte, lent: JObject<'l>) -> JObject<'l>, |env, node| {
        let lent = prompts(env, &lent)?;
        let posted = node.personal()?.rotate_kit(&*lent, kit(kind)?)?;
        made(env, &posted)
    }

    personal fn nativeReplaceAdmin(kind: jbyte, lent: JObject<'l>) -> JObject<'l>, |env, node| {
        let lent = prompts(env, &lent)?;
        let posted = node.personal()?.replace_admin(&*lent, kit(kind)?)?;
        made(env, &posted)
    }

    personal fn nativeAdminOffer(lent: JObject<'l>) -> JByteArray<'l>, |env, node| {
        let lent = prompts(env, &lent)?;
        let offer = node.personal()?.admin_offer(&*lent)?;
        Ok(env.byte_array_from_slice(&offer).map_err(failed)?)
    }

    personal fn nativeReplaceAdminOf(code: JByteArray<'l>, lent: JObject<'l>) -> JObject<'l>, |env, node| {
        let code = bytes(env, &code)?;
        let lent = prompts(env, &lent)?;
        let posted = node.personal()?.replace_admin_of(&*lent, &code)?;
        made(env, &posted)
    }

    personal fn nativeRegroup(lent: JObject<'l>) -> JObject<'l>, |env, node| {
        let lent = prompts(env, &lent)?;
        let posted = node.personal()?.regroup(&*lent)?;
        made(env, &posted)
    }

    personal fn nativeUpdate(lent: JObject<'l>) -> jboolean, |env, node| {
        let lent = prompts(env, &lent)?;
        node.personal()?.update(&*lent)?;
        Ok(true)
    }

    personal fn nativeCommitRemovals(lent: JObject<'l>) -> jint, |env, node| {
        let lent = prompts(env, &lent)?;
        let revoked = node.personal()?.commit_removals(&*lent)?;
        Ok(revoked as jint)
    }

    /// The restore screen's sitting opened: the kit its flows enter held.
    quiet fn nativeKitHold() -> (), |_env, node| {
        if let Ok(space) = node.space() {
            space.hold_kit();
        }
        Ok(())
    }

    /// The sitting closed: the kit it held, if any, zeroized.
    quiet fn nativeKitForget() -> (), |_env, node| {
        if let Ok(space) = node.space() {
            space.forget_kit();
        }
        Ok(())
    }

    personal fn nativeRestore(request: JObject<'l>, old: jbyte, lent: JObject<'l>) -> JObject<'l>, |env, node| {
        let request = Claim::from_java(env, &request)?;
        let lent = prompts(env, &lent)?;
        let posted = node.personal()?.restore(&*lent, request, kit(old)?)?;
        made(env, &posted)
    }

    personal fn nativeKitView(home: JObject<'l>, kind: jbyte, lent: JObject<'l>) -> JObject<'l>, |env, node| {
        let home = Home::from_java(env, &home)?;
        let lent = prompts(env, &lent)?;
        let view = node.personal()?.kit_view(&*lent, home, kit(kind)?)?;
        made(env, &view)
    }

    personal fn nativeRemoveByKit(home: JObject<'l>, kind: jbyte, device: jlong, lent: JObject<'l>) -> JObject<'l>, |env, node| {
        let home = Home::from_java(env, &home)?;
        let lent = prompts(env, &lent)?;
        let posted = node.personal()?.remove_by_kit(&*lent, home, kit(kind)?, word(device)?)?;
        made(env, &posted)
    }

    personal fn nativeResolveByKit(home: JObject<'l>, kind: jbyte, index: jlong, upheld: jboolean, lent: JObject<'l>) -> JObject<'l>, |env, node| {
        let home = Home::from_java(env, &home)?;
        let lent = prompts(env, &lent)?;
        let index = u64::try_from(index).map_err(|_| refused(Code::Arguments, "a negative log index"))?;
        let posted = node.personal()?.resolve_by_kit(&*lent, home, kit(kind)?, index, upheld)?;
        made(env, &posted)
    }

    personal fn nativeRestored(kind: jbyte, lent: JObject<'l>) -> JObject<'l>, |env, node| {
        let lent = prompts(env, &lent)?;
        let claimed = node.personal()?.restored(&*lent, kit(kind)?)?;
        made(env, &claimed)
    }

    personal fn nativeMoveHome(request: JObject<'l>, lent: JObject<'l>) -> JObject<'l>, |env, node| {
        let request = Claim::from_java(env, &request)?;
        let lent = prompts(env, &lent)?;
        let claimed = node.personal()?.move_home(&*lent, request)?;
        made(env, &claimed)
    }

    personal fn nativeStatus() -> JObject<'l>, |env, node| {
        let status = node.status()?;
        made(env, &status)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::Path;

    use super::NATIVES;

    /// JNI's escape of a name's part: `_` is `_1`.
    fn mangle(part: &str) -> String {
        part.replace('_', "_1")
    }

    fn sources(directory: &Path, into: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                sources(&path, into);
            } else if path
                .extension()
                .is_some_and(|extension| extension == "java")
            {
                into.push(path);
            }
        }
    }

    /// Every `native` method the AAR's classes declare: its JNI symbol and
    /// its arity.
    fn declared() -> BTreeMap<String, usize> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("aar/src/main/java");
        let mut files = Vec::new();
        sources(&root, &mut files);
        let mut natives = BTreeMap::new();
        for file in files {
            let source = std::fs::read_to_string(&file).unwrap();
            let package = source
                .split_once("package ")
                .and_then(|(_, rest)| rest.split_once(';'))
                .map(|(package, _)| package.trim().to_owned())
                .unwrap();
            let class = file.file_stem().unwrap().to_str().unwrap().to_owned();
            let mut rest = source.as_str();
            while let Some(at) = rest.find(" static native ") {
                rest = &rest[at + " static native ".len()..];
                let (signature, after) = rest.split_once(')').unwrap();
                let (head, parameters) = signature.split_once('(').unwrap();
                let method = head.split_whitespace().last().unwrap();
                let arity = match parameters.trim() {
                    "" => 0,
                    parameters => parameters.split(',').count(),
                };
                let symbol = format!(
                    "Java_{}_{}_{}",
                    package.split('.').map(mangle).collect::<Vec<_>>().join("_"),
                    mangle(&class),
                    mangle(method)
                );
                natives.insert(symbol, arity);
                rest = after;
            }
        }
        natives
    }

    #[test]
    fn every_native_method_declared_is_one_of_the_table() {
        let declared = declared();
        let table: BTreeMap<String, usize> = NATIVES
            .iter()
            .map(|(symbol, arity)| ((*symbol).to_owned(), *arity))
            .collect();
        assert!(!declared.is_empty(), "no native method was read");
        assert_eq!(declared, table);
    }
}
