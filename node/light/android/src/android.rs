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

use std::os::fd::{FromRawFd as _, IntoRawFd as _};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use crate::personal::{Claim, KitKind, Membership, contract};
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

/// `operation`'s answer; a refusal written into `refused` (the operation's
/// `out Refusal`, or null when it has none) with the default answered.
fn answer<'l, T: Default>(
    env: &mut Env<'l>,
    refused_into: &JObject<'_>,
    operation: impl FnOnce(&mut Env<'l>) -> Result<T, Refusal>,
) -> T {
    let refusal = match catch_unwind(AssertUnwindSafe(|| operation(env))) {
        Ok(Ok(value)) => return value,
        Ok(Err(refusal)) => refusal,
        Err(_) => refused(Code::Failed, "the facility failed"),
    };
    env.exception_clear();
    if !refused_into.is_null() && refusal.write_into(env, refused_into).is_err() {
        env.exception_clear();
    }
    T::default()
}

/// # Safety
/// `node` is one `nativeOpen` made.
unsafe fn node<'a>(node: jlong) -> Result<&'a Node, Refusal> {
    // SAFETY: as the caller promised; a node lives as long as its process.
    unsafe { (node as *const Node).as_ref() }.ok_or_else(|| failed("no facility"))
}

fn prompts(env: &mut Env<'_>, prompts: &JObject<'_>) -> Result<Arc<dyn Prompts>, Refusal> {
    if prompts.is_null() {
        return Err(refused(Code::Arguments, "an operation is lent its prompts"));
    }
    Ok(Arc::new(Lent {
        prompts: env.new_global_ref(prompts).map_err(failed)?,
    }))
}

fn made<'l, P: Parcel>(env: &mut Env<'l>, value: &P) -> Result<JObject<'l>, Refusal> {
    value.to_java(env).map_err(|error: JavaError| failed(error))
}

/// `items` as a new array of their parcelable `element`.
fn array<'l, P: Parcel>(
    env: &mut Env<'l>,
    element: &JClass<'l>,
    items: &[P],
) -> Result<JObjectArray<'l>, Refusal> {
    let array = env
        .new_object_array(items.len() as i32, element, JObject::null())
        .map_err(failed)?;
    for (index, item) in items.iter().enumerate() {
        let item = made(env, item)?;
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

/// A descriptor answered to Java: -1 for none.
#[repr(transparent)]
pub struct Descriptor(jint);

impl Default for Descriptor {
    fn default() -> Self {
        Self(-1)
    }
}

/// The native methods, each `fn` its JNI symbol, its arguments after the
/// facility's handle, its answer and its body, given the environment and
/// the facility. An `op` takes the operation's `out Refusal` last, which a
/// refusal is written into; a `quiet` one takes none; a `bare` one takes no
/// handle either. Statements after `take` run first, before the
/// environment is reached. `NATIVES` lists every symbol and its Java
/// arity.
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
            $((stringify!($name), natives!(@arity $mode $($argument)*)),)*
        ];
    };
    (@arity op $($argument:ident)*) => { 2 $(+ natives!(@one $argument))* };
    (@arity quiet $($argument:ident)*) => { 1 $(+ natives!(@one $argument))* };
    (@arity bare $($argument:ident)*) => { 0 $(+ natives!(@one $argument))* };
    (@one $argument:ident) => { 1 };
    (@op $(#[$doc:meta])* $name:ident($($argument:ident: $ty:ty),*) -> $answer:ty
     [$($take:tt)*] |$env:ident, $node:ident| $body:block) => {
        $(#[$doc])*
        #[unsafe(no_mangle)]
        pub extern "system" fn $name<'l>(
            mut unowned: EnvUnowned<'l>,
            _class: JClass<'l>,
            handle: jlong,
            $($argument: $ty,)*
            refused: JObject<'l>,
        ) -> $answer {
            $($take)*
            unowned
                .with_env(|env| -> jni::errors::Result<$answer> {
                    Ok(answer(env, &refused, |$env| {
                        // SAFETY: the handle `nativeOpen` answered.
                        let $node = unsafe { node(handle) }?;
                        $body
                    }))
                })
                .resolve::<LogErrorAndDefault>()
        }
    };
    (@quiet $(#[$doc:meta])* $name:ident($($argument:ident: $ty:ty),*) -> $answer:ty
     [$($take:tt)*] |$env:ident, $node:ident| $body:block) => {
        $(#[$doc])*
        #[unsafe(no_mangle)]
        pub extern "system" fn $name<'l>(
            mut unowned: EnvUnowned<'l>,
            _class: JClass<'l>,
            handle: jlong,
            $($argument: $ty,)*
        ) -> $answer {
            $($take)*
            unowned
                .with_env(|env| -> jni::errors::Result<$answer> {
                    Ok(answer(env, &JObject::null(), |$env| {
                        // SAFETY: the handle `nativeOpen` answered.
                        let $node = unsafe { node(handle) }?;
                        $body
                    }))
                })
                .resolve::<LogErrorAndDefault>()
        }
    };
    (@bare $(#[$doc:meta])* $name:ident($($argument:ident: $ty:ty),*) -> $answer:ty
     [$($take:tt)*] |$env:ident| $body:block) => {
        $(#[$doc])*
        #[unsafe(no_mangle)]
        pub extern "system" fn $name<'l>(
            mut unowned: EnvUnowned<'l>,
            _class: JClass<'l>,
            $($argument: $ty,)*
        ) -> $answer {
            $($take)*
            unowned
                .with_env(|env| -> jni::errors::Result<$answer> {
                    Ok(answer(env, &JObject::null(), |$env| $body))
                })
                .resolve::<LogErrorAndDefault>()
        }
    };
}

natives! {
    /// The facility whose enrollments are kept under `directory`, arti's
    /// state under `tor`, the app's parcelables loaded through `loader`,
    /// the device read from `device` (the `VosNode`): its handle, never
    /// freed; 0 when it does not open.
    bare fn Java_team_virto_s4_vos_VosNode_nativeOpen(
        directory: JString<'l>,
        tor: JString<'l>,
        loader: JObject<'l>,
        device: JObject<'l>,
    ) -> jlong,
    |env| {
        let directory = PathBuf::from(directory.try_to_string(env).map_err(failed)?);
        let tor = PathBuf::from(tor.try_to_string(env).map_err(failed)?);
        let _ = VM.set(env.get_java_vm().map_err(failed)?);
        java::init(env, &loader).map_err(failed)?;
        java::load(env, &loader, contract::REGISTRY).map_err(failed)?;
        let device = Arc::new(JavaDevice {
            node: env.new_global_ref(&device).map_err(failed)?,
        });
        let node = Node::open(directory, tor, device).map_err(failed)?;
        Ok(Box::into_raw(Box::new(node)) as jlong)
    }

    quiet fn Java_team_virto_s4_vos_VosNode_nativeSupported() -> jboolean, |_env, node| {
        Ok(node.supported())
    }

    quiet fn Java_team_virto_s4_vos_VosNode_nativeWarm(thrifty: jboolean) -> (), |_env, node| {
        node.warm(thrifty);
        Ok(())
    }

    op fn Java_team_virto_s4_vos_VosNode_nativeOpenSession(gateway: JObject<'l>) -> jlong, |env, node| {
        let gateway = Gateway::from_java(env, &gateway)?;
        Ok(node.open_session(gateway) as jlong)
    }

    op fn Java_team_virto_s4_vos_VosNode_nativeGranted(session: jlong) -> jboolean, |_env, node| {
        node.granted(session as u64)?;
        Ok(true)
    }

    quiet fn Java_team_virto_s4_vos_VosNode_nativeClose(session: jlong) -> (), |_env, node| {
        node.close(session as u64);
        Ok(())
    }

    op fn Java_team_virto_s4_vos_VosNode_nativeEnroll(
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

    op fn Java_team_virto_s4_vos_VosNode_nativeSignIn(
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

    op fn Java_team_virto_s4_vos_VosNode_nativePay(
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

    op fn Java_team_virto_s4_vos_VosNode_nativeRefresh(session: jlong) -> jboolean, |_env, node| {
        node.refresh(session as u64)?;
        Ok(true)
    }

    op fn Java_team_virto_s4_vos_VosNode_nativeSync() -> JObject<'l>, |env, node| {
        let synced = node.sync()?;
        made(env, &synced)
    }

    op fn Java_team_virto_s4_vos_VosNode_nativeEnrollments(element: JClass<'l>) -> JObjectArray<'l>, |env, node| {
        let all: Vec<EnrolledSpace> = node.enrollments()?;
        array(env, &element, &all)
    }

    op fn Java_team_virto_s4_vos_VosNode_nativeRuns(element: JClass<'l>) -> JObjectArray<'l>, |env, node| {
        let all: Vec<JobRun> = node.runs()?;
        array(env, &element, &all)
    }

    /// A stream to the target, served into one end of a socket pair: the
    /// other end's descriptor, which the caller owns; -1 when refused.
    op fn Java_team_virto_s4_vos_VosNode_nativeOpenStream(target: JObject<'l>) -> Descriptor, |env, node| {
        let target = StreamTarget::from_java(env, &target)?;
        let theirs = node.open_stream(target)?;
        Ok(Descriptor(theirs.into_raw_fd()))
    }

    /// s4's screen session with the target's gateway, carried between the
    /// UI's end of a socket pair, `descriptor` (owned from here), and that
    /// gateway's SSH port: the SSH host key the space pinned for that port.
    op fn Java_team_virto_s4_vos_VosNode_nativeScreens(
        gateway: JObject<'l>,
        descriptor: jint,
    ) -> JByteArray<'l>,
    // SAFETY: the binder's descriptor, detached for this call alone.
    take { let end = (descriptor >= 0).then(|| unsafe { std::os::fd::OwnedFd::from_raw_fd(descriptor) }); },
    |env, node| {
        let end = end.ok_or_else(|| crate::refused(Code::Arguments, "no socket pair's end"))?;
        let gateway = StreamTarget::from_java(env, &gateway)?;
        let host_key = node.screens(gateway, end)?;
        env.byte_array_from_slice(&host_key).map_err(failed)
    }

    op fn Java_team_virto_s4_vos_VosNode_nativeSyncPersonal() -> JObject<'l>, |env, node| {
        let synced = node.sync_personal()?;
        made(env, &synced)
    }

    op fn Java_team_virto_s4_vos_VosNode_nativeForeground(foreground: jboolean) -> jboolean, |_env, node| {
        node.foreground(foreground);
        Ok(true)
    }

    op fn Java_team_virto_s4_vos_VosNode_nativeCloseAll(sessions: JLongArray<'l>) -> jboolean, |env, node| {
        let sessions: Vec<u64> = longs(env, &sessions)?.into_iter().map(|session| session as u64).collect();
        node.close_all(&sessions);
        Ok(true)
    }

    op fn Java_team_virto_s4_vos_VosNode_nativeBridges(lines: JObjectArray<'l>) -> jboolean, |env, node| {
        let mut all = Vec::new();
        for index in 0..lines.len(env).map_err(failed)? {
            let line = lines.get_element(env, index).map_err(failed)?;
            let line = JString::cast_local(env, line).map_err(failed)?;
            all.push(line.try_to_string(env).map_err(failed)?);
        }
        node.bridges(all)?;
        Ok(true)
    }

    op fn Java_team_virto_s4_vos_VosNode_nativeBootstrap() -> jboolean, |_env, node| {
        node.bootstrap()?;
        Ok(true)
    }

    op fn Java_team_virto_s4_vos_VosNode_nativeOptOut(space: JByteArray<'l>, out: jboolean) -> jboolean, |env, node| {
        let space: [u8; 32] = bytes(env, &space)?
            .try_into()
            .map_err(|_| refused(Code::Arguments, "a space's handle is 32 bytes"))?;
        node.opt_out(space, out)?;
        Ok(true)
    }

    op fn Java_team_virto_s4_vos_VosNode_nativeClearnet(host_key: JByteArray<'l>) -> jboolean, |env, node| {
        let host_key: [u8; 32] = bytes(env, &host_key)?
            .try_into()
            .map_err(|_| refused(Code::Arguments, "an SSH host key is 32 bytes"))?;
        node.clearnet(host_key)?;
        Ok(true)
    }

    op fn Java_team_virto_s4_vos_VosNode_nativeClaim(request: JObject<'l>, lent: JObject<'l>) -> JObject<'l>, |env, node| {
        let request = Claim::from_java(env, &request)?;
        let lent = prompts(env, &lent)?;
        let claimed = node.personal()?.claim(&*lent, request)?;
        made(env, &claimed)
    }

    op fn Java_team_virto_s4_vos_VosNode_nativePairOffer(lent: JObject<'l>) -> JObject<'l>, |env, node| {
        let lent = prompts(env, &lent)?;
        let code = node.personal()?.pair_offer(&*lent)?;
        made(env, &code)
    }

    op fn Java_team_virto_s4_vos_VosNode_nativePairAwait(lent: JObject<'l>) -> JObject<'l>, |env, node| {
        let lent = prompts(env, &lent)?;
        let paired = node.personal()?.pair_await(&*lent)?;
        made(env, &paired)
    }

    op fn Java_team_virto_s4_vos_VosNode_nativePairCancel() -> jboolean, |_env, node| {
        node.space()?.pair_cancel();
        Ok(true)
    }

    op fn Java_team_virto_s4_vos_VosNode_nativePairJoin(code: JByteArray<'l>, label: JString<'l>, lent: JObject<'l>) -> JObject<'l>, |env, node| {
        let code = zeroize::Zeroizing::new(bytes(env, &code)?);
        let label = label.try_to_string(env).map_err(failed)?;
        let lent = prompts(env, &lent)?;
        let paired = node.personal()?.pair_join(&*lent, &code, &label)?;
        made(env, &paired)
    }

    op fn Java_team_virto_s4_vos_VosNode_nativeMemberships(element: JClass<'l>) -> JObjectArray<'l>, |env, node| {
        let all = node.space()?.memberships()?;
        array(env, &element, &all)
    }

    op fn Java_team_virto_s4_vos_VosNode_nativeEnrollDevice(membership: JObject<'l>, lent: JObject<'l>) -> jboolean, |env, node| {
        let membership = Membership::from_java(env, &membership)?;
        let lent = prompts(env, &lent)?;
        node.personal()?.enroll_device(&*lent, membership)?;
        Ok(true)
    }

    op fn Java_team_virto_s4_vos_VosNode_nativeConfirmDevice(membership: JObject<'l>, lent: JObject<'l>) -> jboolean, |env, node| {
        let membership = Membership::from_java(env, &membership)?;
        let lent = prompts(env, &lent)?;
        node.personal()?.confirm_device(&*lent, membership)?;
        Ok(true)
    }

    op fn Java_team_virto_s4_vos_VosNode_nativeDropEnrollment(membership: JObject<'l>) -> jboolean, |env, node| {
        let membership = Membership::from_java(env, &membership)?;
        node.space()?.drop_enrollment(membership)?;
        Ok(true)
    }

    op fn Java_team_virto_s4_vos_VosNode_nativeRevoke(device: jlong, lent: JObject<'l>) -> jint, |env, node| {
        let lent = prompts(env, &lent)?;
        Ok(node.personal()?.revoke(&*lent, word(device)?)? as jint)
    }

    op fn Java_team_virto_s4_vos_VosNode_nativeDevices(element: JClass<'l>) -> JObjectArray<'l>, |env, node| {
        let all = node.personal()?.devices()?;
        array(env, &element, &all)
    }

    op fn Java_team_virto_s4_vos_VosNode_nativeOperations(element: JClass<'l>) -> JObjectArray<'l>, |env, node| {
        let all = node.space()?.operations()?;
        array(env, &element, &all)
    }

    op fn Java_team_virto_s4_vos_VosNode_nativeRemove(device: jlong, lent: JObject<'l>) -> JObject<'l>, |env, node| {
        let lent = prompts(env, &lent)?;
        let posted = node.personal()?.remove(&*lent, word(device)?)?;
        made(env, &posted)
    }

    op fn Java_team_virto_s4_vos_VosNode_nativeVeto(index: jlong, lent: JObject<'l>) -> JObject<'l>, |env, node| {
        let lent = prompts(env, &lent)?;
        let posted = node.personal()?.veto(&*lent, index as u64)?;
        made(env, &posted)
    }

    op fn Java_team_virto_s4_vos_VosNode_nativeCosign(index: jlong, lent: JObject<'l>) -> JObject<'l>, |env, node| {
        let lent = prompts(env, &lent)?;
        let posted = node.personal()?.cosign(&*lent, index as u64)?;
        made(env, &posted)
    }

    op fn Java_team_virto_s4_vos_VosNode_nativeResolve(index: jlong, upheld: jboolean, lent: JObject<'l>) -> JObject<'l>, |env, node| {
        let lent = prompts(env, &lent)?;
        let posted = node.personal()?.resolve(&*lent, index as u64, upheld)?;
        made(env, &posted)
    }

    op fn Java_team_virto_s4_vos_VosNode_nativeRotateKit(kind: jbyte, lent: JObject<'l>) -> JObject<'l>, |env, node| {
        let lent = prompts(env, &lent)?;
        let posted = node.personal()?.rotate_kit(&*lent, kit(kind)?)?;
        made(env, &posted)
    }

    op fn Java_team_virto_s4_vos_VosNode_nativeReplaceAdmin(kind: jbyte, lent: JObject<'l>) -> JObject<'l>, |env, node| {
        let lent = prompts(env, &lent)?;
        let posted = node.personal()?.replace_admin(&*lent, kit(kind)?)?;
        made(env, &posted)
    }

    op fn Java_team_virto_s4_vos_VosNode_nativeAdminOffer(lent: JObject<'l>) -> JByteArray<'l>, |env, node| {
        let lent = prompts(env, &lent)?;
        let offer = node.personal()?.admin_offer(&*lent)?;
        env.byte_array_from_slice(&offer).map_err(failed)
    }

    op fn Java_team_virto_s4_vos_VosNode_nativeReplaceAdminOf(code: JByteArray<'l>, lent: JObject<'l>) -> JObject<'l>, |env, node| {
        let code = bytes(env, &code)?;
        let lent = prompts(env, &lent)?;
        let posted = node.personal()?.replace_admin_of(&*lent, &code)?;
        made(env, &posted)
    }

    op fn Java_team_virto_s4_vos_VosNode_nativeRegroup(remove: JLongArray<'l>, lent: JObject<'l>) -> JObject<'l>, |env, node| {
        let remove = longs(env, &remove)?.into_iter().map(word).collect::<Result<Vec<_>, _>>()?;
        let lent = prompts(env, &lent)?;
        let posted = node.personal()?.regroup(&*lent, remove)?;
        made(env, &posted)
    }

    op fn Java_team_virto_s4_vos_VosNode_nativeUpdate(lent: JObject<'l>) -> jboolean, |env, node| {
        let lent = prompts(env, &lent)?;
        node.personal()?.update(&*lent)?;
        Ok(true)
    }

    op fn Java_team_virto_s4_vos_VosNode_nativeRenew(lent: JObject<'l>) -> jboolean, |env, node| {
        let lent = prompts(env, &lent)?;
        node.personal()?.renew(&*lent)?;
        Ok(true)
    }

    op fn Java_team_virto_s4_vos_VosNode_nativeRestore(request: JObject<'l>, old: jbyte, lent: JObject<'l>) -> JObject<'l>, |env, node| {
        let request = Claim::from_java(env, &request)?;
        let lent = prompts(env, &lent)?;
        let posted = node.personal()?.restore(&*lent, request, kit(old)?)?;
        made(env, &posted)
    }

    op fn Java_team_virto_s4_vos_VosNode_nativeRestored(kind: jbyte, lent: JObject<'l>) -> JObject<'l>, |env, node| {
        let lent = prompts(env, &lent)?;
        let claimed = node.personal()?.restored(&*lent, kit(kind)?)?;
        made(env, &claimed)
    }

    op fn Java_team_virto_s4_vos_VosNode_nativeMoveHome(request: JObject<'l>, lent: JObject<'l>) -> JObject<'l>, |env, node| {
        let request = Claim::from_java(env, &request)?;
        let lent = prompts(env, &lent)?;
        let moved = node.personal()?.move_home(&*lent, request)?;
        made(env, &moved)
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
