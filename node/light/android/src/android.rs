// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The facility's JNI, which the app's `:vos` process calls
//! (`team.virto.s4.vos.VosNode`): each native method one operation of the
//! Binder interface, its request and result the interface's parcelables
//! (`s4_credential_contract::java`), a refusal written into the operation's
//! `out Refusal`, its result then null (or false, or 0). The client's prompts
//! are the `IVosPrompts` it lent the operation, called back through
//! Binder; the device's kinds are `VosNode.kinds()`.
//!
//! Nothing here unwinds into the JVM: a panic is a refusal of
//! [`Code::Failed`].

use std::os::fd::IntoRawFd as _;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use jni::errors::LogErrorAndDefault;
use jni::objects::{Global, JByteArray, JClass, JLongArray, JObject, JObjectArray, JString};
use jni::sys::{jboolean, jbyte, jint, jlong};
use jni::{Env, EnvUnowned, JValue, JavaVM, jni_sig, jni_str};
use s4_credential_contract::java::{self, JavaError, Parcel};
use s4_credential_contract::personal::{Claim, KitKind, Membership};
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
/// `node` is one [`Java_team_virto_s4_vos_VosNode_nativeOpen`] made.
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

/// The facility whose enrollments are kept under `directory`, arti's state
/// under `tor`, the app's parcelables loaded through `loader`, the device
/// read from `device` (the `VosNode`): its handle, never freed; 0 when it
/// does not open.
#[unsafe(no_mangle)]
pub extern "system" fn Java_team_virto_s4_vos_VosNode_nativeOpen<'l>(
    mut unowned: EnvUnowned<'l>,
    _class: JClass<'l>,
    directory: JString<'l>,
    tor: JString<'l>,
    loader: JObject<'l>,
    device: JObject<'l>,
) -> jlong {
    unowned
        .with_env(|env| -> jni::errors::Result<jlong> {
            Ok(answer(env, &JObject::null(), |env| {
                let directory = PathBuf::from(directory.try_to_string(env).map_err(failed)?);
                let tor = PathBuf::from(tor.try_to_string(env).map_err(failed)?);
                let _ = VM.set(env.get_java_vm().map_err(failed)?);
                java::init(env, &loader).map_err(failed)?;
                let device = Arc::new(JavaDevice {
                    node: env.new_global_ref(&device).map_err(failed)?,
                });
                let node = Node::open(directory, tor, device).map_err(failed)?;
                Ok(Box::into_raw(Box::new(node)) as jlong)
            }))
        })
        .resolve::<LogErrorAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_team_virto_s4_vos_VosNode_nativeSupported<'l>(
    mut unowned: EnvUnowned<'l>,
    _class: JClass<'l>,
    handle: jlong,
) -> jboolean {
    unowned
        .with_env(|env| -> jni::errors::Result<jboolean> {
            // SAFETY: the handle `nativeOpen` answered.
            Ok(answer(env, &JObject::null(), |_| {
                Ok(unsafe { node(handle) }?.supported())
            }))
        })
        .resolve::<LogErrorAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_team_virto_s4_vos_VosNode_nativeWarm<'l>(
    mut unowned: EnvUnowned<'l>,
    _class: JClass<'l>,
    handle: jlong,
    thrifty: jboolean,
) {
    unowned
        .with_env(|env| -> jni::errors::Result<()> {
            // SAFETY: the handle `nativeOpen` answered.
            answer(env, &JObject::null(), |_| {
                unsafe { node(handle) }?.warm(thrifty);
                Ok(())
            });
            Ok(())
        })
        .resolve::<LogErrorAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_team_virto_s4_vos_VosNode_nativeOpenSession<'l>(
    mut unowned: EnvUnowned<'l>,
    _class: JClass<'l>,
    handle: jlong,
    gateway: JObject<'l>,
    refused: JObject<'l>,
) -> jlong {
    unowned
        .with_env(|env| -> jni::errors::Result<jlong> {
            Ok(answer(env, &refused, |env| {
                let gateway = Gateway::from_java(env, &gateway)?;
                // SAFETY: the handle `nativeOpen` answered.
                Ok(unsafe { node(handle) }?.open_session(gateway) as jlong)
            }))
        })
        .resolve::<LogErrorAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_team_virto_s4_vos_VosNode_nativeGranted<'l>(
    mut unowned: EnvUnowned<'l>,
    _class: JClass<'l>,
    handle: jlong,
    session: jlong,
    refused: JObject<'l>,
) -> jboolean {
    unowned
        .with_env(|env| -> jni::errors::Result<jboolean> {
            Ok(answer(env, &refused, |_| {
                // SAFETY: the handle `nativeOpen` answered.
                unsafe { node(handle) }?.granted(session as u64)?;
                Ok(true)
            }))
        })
        .resolve::<LogErrorAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_team_virto_s4_vos_VosNode_nativeClose<'l>(
    mut unowned: EnvUnowned<'l>,
    _class: JClass<'l>,
    handle: jlong,
    session: jlong,
) {
    unowned
        .with_env(|env| -> jni::errors::Result<()> {
            answer(env, &JObject::null(), |_| {
                // SAFETY: the handle `nativeOpen` answered.
                unsafe { node(handle) }?.close(session as u64);
                Ok(())
            });
            Ok(())
        })
        .resolve::<LogErrorAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_team_virto_s4_vos_VosNode_nativeEnroll<'l>(
    mut unowned: EnvUnowned<'l>,
    _class: JClass<'l>,
    handle: jlong,
    session: jlong,
    request: JObject<'l>,
    lent: JObject<'l>,
    refused: JObject<'l>,
) -> JObject<'l> {
    unowned
        .with_env(|env| -> jni::errors::Result<JObject<'l>> {
            Ok(answer(env, &refused, |env| {
                let request = Enroll::from_java(env, &request)?;
                let lent = prompts(env, &lent)?;
                // SAFETY: the handle `nativeOpen` answered.
                let enrolled = unsafe { node(handle) }?.enroll(session as u64, request, lent)?;
                made(env, &enrolled)
            }))
        })
        .resolve::<LogErrorAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_team_virto_s4_vos_VosNode_nativeSignIn<'l>(
    mut unowned: EnvUnowned<'l>,
    _class: JClass<'l>,
    handle: jlong,
    session: jlong,
    request: JObject<'l>,
    lent: JObject<'l>,
    refused: JObject<'l>,
) -> JObject<'l> {
    unowned
        .with_env(|env| -> jni::errors::Result<JObject<'l>> {
            Ok(answer(env, &refused, |env| {
                let request = SignIn::from_java(env, &request)?;
                let lent = prompts(env, &lent)?;
                // SAFETY: the handle `nativeOpen` answered.
                let signed = unsafe { node(handle) }?.sign_in(session as u64, request, lent)?;
                made(env, &signed)
            }))
        })
        .resolve::<LogErrorAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_team_virto_s4_vos_VosNode_nativePay<'l>(
    mut unowned: EnvUnowned<'l>,
    _class: JClass<'l>,
    handle: jlong,
    session: jlong,
    request: JObject<'l>,
    lent: JObject<'l>,
    refused: JObject<'l>,
) -> JObject<'l> {
    unowned
        .with_env(|env| -> jni::errors::Result<JObject<'l>> {
            Ok(answer(env, &refused, |env| {
                let request = Pay::from_java(env, &request)?;
                let lent = prompts(env, &lent)?;
                // SAFETY: the handle `nativeOpen` answered.
                let paid = unsafe { node(handle) }?.pay(session as u64, request, lent)?;
                made(env, &paid)
            }))
        })
        .resolve::<LogErrorAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_team_virto_s4_vos_VosNode_nativeRefresh<'l>(
    mut unowned: EnvUnowned<'l>,
    _class: JClass<'l>,
    handle: jlong,
    session: jlong,
    refused: JObject<'l>,
) -> jboolean {
    unowned
        .with_env(|env| -> jni::errors::Result<jboolean> {
            Ok(answer(env, &refused, |_| {
                // SAFETY: the handle `nativeOpen` answered.
                unsafe { node(handle) }?.refresh(session as u64)?;
                Ok(true)
            }))
        })
        .resolve::<LogErrorAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_team_virto_s4_vos_VosNode_nativeSync<'l>(
    mut unowned: EnvUnowned<'l>,
    _class: JClass<'l>,
    handle: jlong,
    refused: JObject<'l>,
) -> JObject<'l> {
    unowned
        .with_env(|env| -> jni::errors::Result<JObject<'l>> {
            Ok(answer(env, &refused, |env| {
                // SAFETY: the handle `nativeOpen` answered.
                let synced = unsafe { node(handle) }?.sync()?;
                made(env, &synced)
            }))
        })
        .resolve::<LogErrorAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_team_virto_s4_vos_VosNode_nativeEnrollments<'l>(
    mut unowned: EnvUnowned<'l>,
    _class: JClass<'l>,
    handle: jlong,
    element: JClass<'l>,
    refused: JObject<'l>,
) -> JObjectArray<'l> {
    unowned
        .with_env(|env| -> jni::errors::Result<JObjectArray<'l>> {
            Ok(answer(env, &refused, |env| {
                // SAFETY: the handle `nativeOpen` answered.
                let all: Vec<EnrolledSpace> = unsafe { node(handle) }?.enrollments()?;
                let array = env
                    .new_object_array(all.len() as i32, &element, JObject::null())
                    .map_err(failed)?;
                for (index, enrolled) in all.iter().enumerate() {
                    let item = made(env, enrolled)?;
                    array.set_element(env, index, &item).map_err(failed)?;
                }
                Ok(array)
            }))
        })
        .resolve::<LogErrorAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_team_virto_s4_vos_VosNode_nativeRuns<'l>(
    mut unowned: EnvUnowned<'l>,
    _class: JClass<'l>,
    handle: jlong,
    element: JClass<'l>,
    refused: JObject<'l>,
) -> JObjectArray<'l> {
    unowned
        .with_env(|env| -> jni::errors::Result<JObjectArray<'l>> {
            Ok(answer(env, &refused, |env| {
                // SAFETY: the handle `nativeOpen` answered.
                let all: Vec<JobRun> = unsafe { node(handle) }?.runs()?;
                let array = env
                    .new_object_array(all.len() as i32, &element, JObject::null())
                    .map_err(failed)?;
                for (index, run) in all.iter().enumerate() {
                    let item = made(env, run)?;
                    array.set_element(env, index, &item).map_err(failed)?;
                }
                Ok(array)
            }))
        })
        .resolve::<LogErrorAndDefault>()
}

/// A stream to the target, served into one end of a socket pair: the
/// other end's descriptor, which the caller owns; -1 when refused.
#[unsafe(no_mangle)]
pub extern "system" fn Java_team_virto_s4_vos_VosNode_nativeOpenStream<'l>(
    mut unowned: EnvUnowned<'l>,
    _class: JClass<'l>,
    handle: jlong,
    target: JObject<'l>,
    refused: JObject<'l>,
) -> jint {
    unowned
        .with_env(|env| -> jni::errors::Result<jint> {
            let fd = answer(env, &refused, |env| {
                let target = StreamTarget::from_java(env, &target)?;
                // SAFETY: the handle `nativeOpen` answered.
                let theirs = unsafe { node(handle) }?.open_stream(target)?;
                Ok(Some(theirs.into_raw_fd()))
            });
            Ok(fd.unwrap_or(-1))
        })
        .resolve::<LogErrorAndDefault>()
}

/// s4's screen session with the target's gateway, carried between the
/// UI's end of a socket pair, `descriptor` (owned from here), and that
/// gateway's SSH port: the SSH host key the space pinned for that port.
#[unsafe(no_mangle)]
pub extern "system" fn Java_team_virto_s4_vos_VosNode_nativeScreens<'l>(
    mut unowned: EnvUnowned<'l>,
    _class: JClass<'l>,
    handle: jlong,
    gateway: JObject<'l>,
    descriptor: jint,
    refused: JObject<'l>,
) -> JByteArray<'l> {
    use std::os::fd::{FromRawFd as _, OwnedFd};
    // SAFETY: the binder's descriptor, detached for this call alone.
    let end = (descriptor >= 0).then(|| unsafe { OwnedFd::from_raw_fd(descriptor) });
    unowned
        .with_env(|env| -> jni::errors::Result<JByteArray<'l>> {
            Ok(answer(env, &refused, |env| {
                let end =
                    end.ok_or_else(|| crate::refused(Code::Arguments, "no socket pair's end"))?;
                let gateway = StreamTarget::from_java(env, &gateway)?;
                // SAFETY: the handle `nativeOpen` answered.
                let host_key = unsafe { node(handle) }?.screens(gateway, end)?;
                env.byte_array_from_slice(&host_key).map_err(failed)
            }))
        })
        .resolve::<LogErrorAndDefault>()
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

/// A native method of `VosNode` taking the facility's handle, then
/// `arguments`, then the operation's `out Refusal`: `body` its answer,
/// given the environment and the facility.
macro_rules! native {
    ($(#[$doc:meta])* $name:ident($($argument:ident: $ty:ty),*) -> $answer:ty,
     |$env:ident, $node:ident| $body:block) => {
        $(#[$doc])*
        #[unsafe(no_mangle)]
        pub extern "system" fn $name<'l>(
            mut unowned: EnvUnowned<'l>,
            _class: JClass<'l>,
            handle: jlong,
            $($argument: $ty,)*
            refused: JObject<'l>,
        ) -> $answer {
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
}

native!(Java_team_virto_s4_vos_VosNode_nativeSyncPersonal() -> JObject<'l>, |env, node| {
    let synced = node.sync_personal()?;
    made(env, &synced)
});

native!(Java_team_virto_s4_vos_VosNode_nativeForeground(foreground: jboolean) -> jboolean, |_env, node| {
    node.foreground(foreground);
    Ok(true)
});

native!(Java_team_virto_s4_vos_VosNode_nativeCloseAll(sessions: JLongArray<'l>) -> jboolean, |env, node| {
    let sessions: Vec<u64> = longs(env, &sessions)?.into_iter().map(|session| session as u64).collect();
    node.close_all(&sessions);
    Ok(true)
});

native!(Java_team_virto_s4_vos_VosNode_nativeBridges(lines: JObjectArray<'l>) -> jboolean, |env, node| {
    let mut all = Vec::new();
    for index in 0..lines.len(env).map_err(failed)? {
        let line = lines.get_element(env, index).map_err(failed)?;
        let line = JString::cast_local(env, line).map_err(failed)?;
        all.push(line.try_to_string(env).map_err(failed)?);
    }
    node.bridges(all)?;
    Ok(true)
});

native!(Java_team_virto_s4_vos_VosNode_nativeBootstrap() -> jboolean, |_env, node| {
    node.bootstrap()?;
    Ok(true)
});

native!(Java_team_virto_s4_vos_VosNode_nativeOptOut(space: JByteArray<'l>, out: jboolean) -> jboolean, |env, node| {
    let space: [u8; 32] = bytes(env, &space)?
        .try_into()
        .map_err(|_| refused(Code::Arguments, "a space's handle is 32 bytes"))?;
    node.opt_out(space, out)?;
    Ok(true)
});

native!(Java_team_virto_s4_vos_VosNode_nativeClearnet(host_key: JByteArray<'l>) -> jboolean, |env, node| {
    let host_key: [u8; 32] = bytes(env, &host_key)?
        .try_into()
        .map_err(|_| refused(Code::Arguments, "an SSH host key is 32 bytes"))?;
    node.clearnet(host_key)?;
    Ok(true)
});

native!(Java_team_virto_s4_vos_VosNode_nativeClaim(request: JObject<'l>, lent: JObject<'l>) -> JObject<'l>, |env, node| {
    let request = Claim::from_java(env, &request)?;
    let lent = prompts(env, &lent)?;
    let claimed = node.claim(request, &*lent)?;
    made(env, &claimed)
});

native!(Java_team_virto_s4_vos_VosNode_nativePairOffer(lent: JObject<'l>) -> JObject<'l>, |env, node| {
    let lent = prompts(env, &lent)?;
    let code = node.pair_offer(&*lent)?;
    made(env, &code)
});

native!(Java_team_virto_s4_vos_VosNode_nativePairAwait(lent: JObject<'l>) -> JObject<'l>, |env, node| {
    let lent = prompts(env, &lent)?;
    let paired = node.pair_await(&*lent)?;
    made(env, &paired)
});

native!(Java_team_virto_s4_vos_VosNode_nativePairCancel() -> jboolean, |_env, node| {
    node.pair_cancel()?;
    Ok(true)
});

native!(Java_team_virto_s4_vos_VosNode_nativePairJoin(code: JByteArray<'l>, label: JString<'l>, lent: JObject<'l>) -> JObject<'l>, |env, node| {
    let code = zeroize::Zeroizing::new(bytes(env, &code)?);
    let label = label.try_to_string(env).map_err(failed)?;
    let lent = prompts(env, &lent)?;
    let paired = node.pair_join(&code, &label, &*lent)?;
    made(env, &paired)
});

native!(Java_team_virto_s4_vos_VosNode_nativeMemberships(element: JClass<'l>) -> JObjectArray<'l>, |env, node| {
    let all = node.memberships()?;
    array(env, &element, &all)
});

native!(Java_team_virto_s4_vos_VosNode_nativeEnrollDevice(membership: JObject<'l>, lent: JObject<'l>) -> jboolean, |env, node| {
    let membership = Membership::from_java(env, &membership)?;
    let lent = prompts(env, &lent)?;
    node.enroll_device(membership, &*lent)?;
    Ok(true)
});

native!(Java_team_virto_s4_vos_VosNode_nativeConfirmDevice(membership: JObject<'l>, lent: JObject<'l>) -> jboolean, |env, node| {
    let membership = Membership::from_java(env, &membership)?;
    let lent = prompts(env, &lent)?;
    node.confirm_device(membership, &*lent)?;
    Ok(true)
});

native!(Java_team_virto_s4_vos_VosNode_nativeDropEnrollment(membership: JObject<'l>) -> jboolean, |env, node| {
    let membership = Membership::from_java(env, &membership)?;
    node.drop_enrollment(membership)?;
    Ok(true)
});

native!(Java_team_virto_s4_vos_VosNode_nativeRevoke(device: jlong, lent: JObject<'l>) -> jint, |env, node| {
    let lent = prompts(env, &lent)?;
    Ok(node.revoke(word(device)?, &*lent)? as jint)
});

native!(Java_team_virto_s4_vos_VosNode_nativeDevices(element: JClass<'l>) -> JObjectArray<'l>, |env, node| {
    let all = node.devices()?;
    array(env, &element, &all)
});

native!(Java_team_virto_s4_vos_VosNode_nativeOperations(element: JClass<'l>) -> JObjectArray<'l>, |env, node| {
    let all = node.operations()?;
    array(env, &element, &all)
});

native!(Java_team_virto_s4_vos_VosNode_nativeRemove(device: jlong, lent: JObject<'l>) -> JObject<'l>, |env, node| {
    let lent = prompts(env, &lent)?;
    let posted = node.remove(word(device)?, &*lent)?;
    made(env, &posted)
});

native!(Java_team_virto_s4_vos_VosNode_nativeVeto(index: jlong, lent: JObject<'l>) -> JObject<'l>, |env, node| {
    let lent = prompts(env, &lent)?;
    let posted = node.veto(index as u64, &*lent)?;
    made(env, &posted)
});

native!(Java_team_virto_s4_vos_VosNode_nativeCosign(index: jlong, lent: JObject<'l>) -> JObject<'l>, |env, node| {
    let lent = prompts(env, &lent)?;
    let posted = node.cosign(index as u64, &*lent)?;
    made(env, &posted)
});

native!(Java_team_virto_s4_vos_VosNode_nativeResolve(index: jlong, upheld: jboolean, lent: JObject<'l>) -> JObject<'l>, |env, node| {
    let lent = prompts(env, &lent)?;
    let posted = node.resolve(index as u64, upheld, &*lent)?;
    made(env, &posted)
});

native!(Java_team_virto_s4_vos_VosNode_nativeRotateKit(kind: jbyte, lent: JObject<'l>) -> JObject<'l>, |env, node| {
    let lent = prompts(env, &lent)?;
    let posted = node.rotate_kit(kit(kind)?, &*lent)?;
    made(env, &posted)
});

native!(Java_team_virto_s4_vos_VosNode_nativeReplaceAdmin(kind: jbyte, lent: JObject<'l>) -> JObject<'l>, |env, node| {
    let lent = prompts(env, &lent)?;
    let posted = node.replace_admin(kit(kind)?, &*lent)?;
    made(env, &posted)
});

native!(Java_team_virto_s4_vos_VosNode_nativeAdminOffer(lent: JObject<'l>) -> JByteArray<'l>, |env, node| {
    let lent = prompts(env, &lent)?;
    let offer = node.admin_offer(&*lent)?;
    env.byte_array_from_slice(&offer).map_err(failed)
});

native!(Java_team_virto_s4_vos_VosNode_nativeReplaceAdminOf(code: JByteArray<'l>, lent: JObject<'l>) -> JObject<'l>, |env, node| {
    let code = bytes(env, &code)?;
    let lent = prompts(env, &lent)?;
    let posted = node.replace_admin_of(&code, &*lent)?;
    made(env, &posted)
});

native!(Java_team_virto_s4_vos_VosNode_nativeRegroup(remove: JLongArray<'l>, lent: JObject<'l>) -> JObject<'l>, |env, node| {
    let remove = longs(env, &remove)?.into_iter().map(word).collect::<Result<Vec<_>, _>>()?;
    let lent = prompts(env, &lent)?;
    let posted = node.regroup(remove, &*lent)?;
    made(env, &posted)
});

native!(Java_team_virto_s4_vos_VosNode_nativeUpdate(lent: JObject<'l>) -> jboolean, |env, node| {
    let lent = prompts(env, &lent)?;
    node.update(&*lent)?;
    Ok(true)
});

native!(Java_team_virto_s4_vos_VosNode_nativeRenew(lent: JObject<'l>) -> jboolean, |env, node| {
    let lent = prompts(env, &lent)?;
    node.renew(&*lent)?;
    Ok(true)
});

native!(Java_team_virto_s4_vos_VosNode_nativeRestore(request: JObject<'l>, old: jbyte, lent: JObject<'l>) -> JObject<'l>, |env, node| {
    let request = Claim::from_java(env, &request)?;
    let lent = prompts(env, &lent)?;
    let posted = node.restore(request, kit(old)?, &*lent)?;
    made(env, &posted)
});

native!(Java_team_virto_s4_vos_VosNode_nativeRestored(kind: jbyte, lent: JObject<'l>) -> JObject<'l>, |env, node| {
    let lent = prompts(env, &lent)?;
    let claimed = node.restored(kit(kind)?, &*lent)?;
    made(env, &claimed)
});

native!(Java_team_virto_s4_vos_VosNode_nativeMoveHome(request: JObject<'l>, lent: JObject<'l>) -> JObject<'l>, |env, node| {
    let request = Claim::from_java(env, &request)?;
    let lent = prompts(env, &lent)?;
    let moved = node.move_home(request, &*lent)?;
    made(env, &moved)
});
