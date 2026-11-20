// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.s4.vos;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.BatteryManager;
import android.os.Binder;
import android.os.Build;
import android.os.IBinder;
import android.os.ParcelFileDescriptor;
import android.os.PowerManager;
import android.os.Process;
import android.os.RemoteException;
import android.os.SystemClock;
import android.util.Log;
import java.io.File;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import team.virto.vos.personal.ClaimRequest;
import team.virto.vos.personal.Claimed;
import team.virto.vos.personal.Device;
import team.virto.vos.personal.Home;
import team.virto.vos.personal.IVosPersonal;
import team.virto.vos.personal.KitView;
import team.virto.vos.personal.Membership;
import team.virto.vos.personal.Notice;
import team.virto.vos.personal.PairCode;
import team.virto.vos.personal.Paired;
import team.virto.vos.personal.PersonalStatus;
import team.virto.vos.personal.Posted;
import team.virto.vos.personal.Refused;
import team.virto.vos.personal.Synced;

/**
 * The VOS facility in the app's own {@code :vos} process: {@code libvos_facility.so}, opened once
 * for the process, and the two interfaces it serves: s4's {@link IVosNode}, which s4's client
 * calls, and the facility's own {@link IVosPersonal}, which its screens call. The prover's
 * memory, the secrets a proof takes and the gateway connections stay in this process, so the UI's
 * death touches no proof or sync, and this process's death leaves the UI running.
 *
 * <p>Any component of this process reaches the facility through {@link #get}: the bound {@link
 * VosNodeService} the UI calls, and the background job ({@link SyncWorker}), which runs {@link
 * #sync} here with no UI at all. Opening the facility schedules the job.
 *
 * <p>The store is in the app's credential-encrypted storage ({@code getNoBackupFilesDir}), which
 * Android opens at the first unlock after boot and keeps open while the screen is locked: the job
 * runs on what the store holds and no key behind a prompt. The app is not direct-boot aware, so no
 * job runs before that first unlock.
 *
 * <p>Every request leaves over Tor: one Tor runtime for the process, its state in {@code
 * files/tor} (outside every backup, as all of {@code files} is), dormant while the app is in the
 * background and woken around each job.
 */
public final class VosNode {
  /** The facility's library. */
  static final String LIBRARY = "vos_facility";

  private static final String TAG = "vos.node";
  private static final int KEYSTORE = 1;
  private static final int SECURITY_KEY = 2;
  /** The battery level at or below which, unplugged, the device saves power. */
  private static final int LOW_BATTERY_PERCENT = 20;

  private static VosNode node;

  private final Context context;
  private final long handle;
  private final IVosNode.Stub binder = new Served();
  private final IVosPersonal.Stub personal = new Personal();
  /** The sessions each UI token opened, closed when its process dies or it releases them. */
  private final Map<IBinder, Set<Long>> held = new HashMap<>();
  /** The token each UI process last held, by its pid. */
  private final Map<Integer, IBinder> tokens = new HashMap<>();
  /** When each session was granted, by the monotonic clock: how long it was open, the logs say. */
  private final Map<Long, Long> grants = new java.util.concurrent.ConcurrentHashMap<>();

  /** The process's facility, opened on first use. */
  public static synchronized VosNode get(Context context) {
    if (node == null) {
      node = new VosNode(context.getApplicationContext());
    }
    return node;
  }

  private VosNode(Context context) {
    this.context = context;
    System.loadLibrary(LIBRARY);
    File store = new File(context.getNoBackupFilesDir(), "credentials");
    File tor = new File(context.getFilesDir(), "tor");
    handle =
        nativeOpen(
            store.getAbsolutePath(), tor.getAbsolutePath(), VosNode.class.getClassLoader(), this);
    if (handle == 0) {
      throw new IllegalStateException("the VOS facility did not open");
    }
    Refusal refused = new Refusal();
    EnrolledSpace[] kept = nativeEnrollments(handle, EnrolledSpace.class, refused);
    // A store that does not read is said, not thrown: the facility still
    // serves what does not need it, and the UI hears why the rest refuse.
    Log.i(
        TAG,
        "store opened: "
            + (kept == null ? "unreadable (" + refused.message + ")" : kept.length + " enrollments"));
    nativeWarm(handle, thrifty());
    Background.schedule(context);
  }

  /** s4's interface, as this process serves it. */
  IVosNode binder() {
    return binder;
  }

  /** The facility's own interface, as this process serves it. */
  IVosPersonal personal() {
    return personal;
  }

  /** Only this app's own processes are served. */
  private static void caller() {
    if (Binder.getCallingUid() != Process.myUid()) {
      throw new SecurityException("the VOS facility serves this app alone");
    }
  }

  /**
   * One pass of the facility's sync: the background job's, in this process, whoever asked for it,
   * its notices posted ({@link Notices}). Null when it refuses, {@code refused} then filled.
   */
  public Synced sync(Refusal refused) {
    Log.i(TAG, "sync started");
    Synced synced = nativeSync(handle, refused);
    if (synced == null) {
      Log.i(TAG, "sync refused: " + refused.message);
      return null;
    }
    Log.i(
        TAG,
        "sync done: "
            + synced.synced
            + " of "
            + synced.enrollments
            + " synced, "
            + synced.failed
            + " failed"
            + why(synced));
    Notices.post(context, synced);
    return synced;
  }

  /** Why a sync's failures failed, after a colon; nothing when none did. */
  private static String why(Synced synced) {
    return synced.failures == null || synced.failures.isEmpty() ? "" : ": " + synced.failures;
  }

  /**
   * One pass of the personal space's job: its own schedule, its own isolation group, its notices
   * posted. Null when it refuses, {@code refused} then filled.
   */
  public Synced syncPersonal(Refusal refused) {
    Log.i(TAG, "personal sync started");
    Synced synced = nativeSyncPersonal(handle, refused);
    if (synced == null) {
      Log.i(TAG, "personal sync refused: " + refused.message);
      return null;
    }
    Log.i(TAG, "personal sync done: " + synced.failed + " failed" + why(synced));
    Notices.post(context, synced);
    return synced;
  }

  /** Bootstrap Tor now: false when it refuses, {@code refused} naming why. */
  public boolean bootstrap(Refusal refused) {
    return nativeBootstrap(handle, refused);
  }

  /** The background job's last runs, the latest last; null when refused. */
  public JobRun[] runs(Refusal refused) {
    return nativeRuns(handle, JobRun.class, refused);
  }

  /** The secret sources' kinds this device offers, as a mask: called by the library. */
  int kinds() {
    if (Build.VERSION.SDK_INT < 30) {
      return 0;
    }
    PackageManager packages = context.getPackageManager();
    boolean securityKeyReachable =
        packages.hasSystemFeature(PackageManager.FEATURE_USB_HOST)
            || packages.hasSystemFeature(PackageManager.FEATURE_NFC);
    return KEYSTORE | (securityKeyReachable ? SECURITY_KEY : 0);
  }

  /**
   * Whether the device saves power: its power-save mode, or a low battery not charging. The
   * facility then computes no kernel's program when it opens; enrollment and a grant still do.
   */
  private boolean thrifty() {
    PowerManager power = context.getSystemService(PowerManager.class);
    if (power != null && power.isPowerSaveMode()) {
      return true;
    }
    BatteryManager battery = context.getSystemService(BatteryManager.class);
    if (battery == null || battery.isCharging()) {
      return false;
    }
    int percent = battery.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY);
    return percent > 0 && percent <= LOW_BATTERY_PERCENT;
  }

  /** The session {@code session} opened by the calling process, closed with its token. */
  private void opened(long session) {
    synchronized (held) {
      IBinder token = tokens.get(Binder.getCallingPid());
      if (token != null && held.containsKey(token)) {
        held.get(token).add(session);
      }
    }
  }

  private void closed(long session) {
    synchronized (held) {
      for (Set<Long> sessions : held.values()) {
        sessions.remove(session);
      }
    }
  }

  /** Every session {@code token}'s process opened, closed; the token watched no more. */
  private void released(IBinder token) {
    Set<Long> sessions;
    synchronized (held) {
      sessions = held.remove(token);
      tokens.values().remove(token);
    }
    if (sessions == null || sessions.isEmpty()) {
      return;
    }
    long[] closing = new long[sessions.size()];
    int at = 0;
    for (long session : sessions) {
      closing[at++] = session;
    }
    Log.i(TAG, "closing " + closing.length + " sessions of a released UI");
    nativeCloseAll(handle, closing, new Refusal());
  }

  /** s4's interface, for this app's own processes alone. */
  private final class Served extends IVosNode.Stub {
    @Override
    public void hold(IBinder client) {
      caller();
      int pid = Binder.getCallingPid();
      synchronized (held) {
        if (held.containsKey(client)) {
          return;
        }
        held.put(client, new HashSet<>());
        tokens.put(pid, client);
      }
      try {
        client.linkToDeath(() -> released(client), 0);
      } catch (RemoteException dead) {
        released(client);
      }
    }

    @Override
    public void release(IBinder client) {
      caller();
      released(client);
    }

    @Override
    public boolean supported() {
      caller();
      return nativeSupported(handle);
    }

    @Override
    public long open(Gateway gateway, Refusal refused) {
      caller();
      long session = nativeOpenSession(handle, gateway, refused);
      if (session != 0) {
        opened(session);
      }
      return session;
    }

    @Override
    public boolean granted(long session, Refusal refused) {
      caller();
      grants.put(session, SystemClock.elapsedRealtime());
      Log.i(TAG, "session granted");
      return nativeGranted(handle, session, refused);
    }

    @Override
    public void close(long session) {
      caller();
      grants.remove(session);
      closed(session);
      nativeClose(handle, session);
    }

    @Override
    public Enrolled enroll(
        long session, EnrollRequest request, IVosPrompts prompts, Refusal refused) {
      caller();
      return nativeEnroll(handle, session, request, prompts, refused);
    }

    @Override
    public SignedIn signIn(
        long session, SignInRequest request, IVosPrompts prompts, Refusal refused) {
      caller();
      Announced announced = announced(prompts, "sign-in", grants.get(session));
      SignedIn signed = nativeSignIn(handle, session, request, announced, refused);
      Log.i(
          TAG,
          signed == null
              ? "sign-in refused: " + refused.code + Announced.at(announced)
              : "sign-in done: proved in " + signed.provingMs + " ms" + Announced.at(announced));
      return signed;
    }

    @Override
    public Paid pay(long session, PayRequest request, IVosPrompts prompts, Refusal refused) {
      caller();
      Announced announced = announced(prompts, "payment", grants.get(session));
      Paid paid = nativePay(handle, session, request, announced, refused);
      Log.i(
          TAG,
          paid == null
              ? "payment refused: " + refused.code + Announced.at(announced)
              : "payment done: proved in " + paid.provingMs + " ms" + Announced.at(announced));
      return paid;
    }

    @Override
    public boolean refresh(long session, Refusal refused) {
      caller();
      return nativeRefresh(handle, session, refused);
    }

    @Override
    public void foreground(boolean foreground) {
      caller();
      nativeForeground(handle, foreground, new Refusal());
    }

    @Override
    public EnrolledSpace[] enrollments(Refusal refused) {
      caller();
      return nativeEnrollments(handle, EnrolledSpace.class, refused);
    }

    @Override
    public JobRun[] runs(Refusal refused) {
      caller();
      return VosNode.this.runs(refused);
    }

    @Override
    public byte[] screens(StreamTarget gateway, ParcelFileDescriptor end, Refusal refused) {
      try {
        caller();
      } catch (RuntimeException refusedCaller) {
        closeQuietly(end);
        throw refusedCaller;
      }
      if (end == null) {
        refused.code = ErrorCode.ARGUMENTS;
        refused.message = "the screens need the UI's end of a socket pair";
        return null;
      }
      // The light node owns the descriptor from here, and closes it with the session.
      return nativeScreens(handle, gateway, end.detachFd(), refused);
    }

    @Override
    public boolean clearnet(byte[] hostKey, Refusal refused) {
      caller();
      return nativeClearnet(handle, hostKey, refused);
    }
  }

  /** The facility's own interface, for this app's own processes alone. */
  private final class Personal extends IVosPersonal.Stub {
    @Override
    public Synced sync(Refusal refused) {
      caller();
      return VosNode.this.sync(refused);
    }

    @Override
    public Synced syncPersonal(Refusal refused) {
      caller();
      return VosNode.this.syncPersonal(refused);
    }

    @Override
    public boolean bridges(String[] lines, Refusal refused) {
      caller();
      return nativeBridges(handle, lines, refused);
    }

    @Override
    public boolean bootstrap(Refusal refused) {
      caller();
      return nativeBootstrap(handle, refused);
    }

    @Override
    public boolean optOut(byte[] space, boolean optedOut, Refusal refused) {
      caller();
      return nativeOptOut(handle, space, optedOut, refused);
    }

    @Override
    public PersonalStatus status(Refused refused) {
      caller();
      return nativeStatus(handle, refused);
    }

    @Override
    public Claimed claim(ClaimRequest request, IVosPrompts prompts, Refused refused) {
      caller();
      return nativeClaim(handle, request, prompts, refused);
    }

    @Override
    public PairCode pairOffer(IVosPrompts prompts, Refused refused) {
      caller();
      return nativePairOffer(handle, prompts, refused);
    }

    @Override
    public Paired pairAwait(IVosPrompts prompts, Refused refused) {
      caller();
      return nativePairAwait(handle, prompts, refused);
    }

    @Override
    public void pairCancel() {
      caller();
      nativePairCancel(handle, new Refused());
    }

    @Override
    public Paired pairJoin(byte[] code, String label, IVosPrompts prompts, Refused refused) {
      caller();
      return nativePairJoin(handle, code, label, prompts, refused);
    }

    @Override
    public Membership[] memberships(Refused refused) {
      caller();
      return nativeMemberships(handle, Membership.class, refused);
    }

    @Override
    public boolean enrollDevice(Membership membership, IVosPrompts prompts, Refused refused) {
      caller();
      return nativeEnrollDevice(handle, membership, prompts, refused);
    }

    @Override
    public boolean confirmDevice(Membership membership, IVosPrompts prompts, Refused refused) {
      caller();
      return nativeConfirmDevice(handle, membership, prompts, refused);
    }

    @Override
    public boolean dropEnrollment(Membership membership, Refused refused) {
      caller();
      return nativeDropEnrollment(handle, membership, refused);
    }

    @Override
    public int revoke(long device, IVosPrompts prompts, Refused refused) {
      caller();
      return nativeRevoke(handle, device, prompts, refused);
    }

    @Override
    public Device[] devices(Refused refused) {
      caller();
      return nativeDevices(handle, Device.class, refused);
    }

    @Override
    public Notice[] operations(Refused refused) {
      caller();
      return nativeOperations(handle, Notice.class, refused);
    }

    @Override
    public Posted remove(long device, IVosPrompts prompts, Refused refused) {
      caller();
      return nativeRemove(handle, device, prompts, refused);
    }

    @Override
    public Posted veto(long index, IVosPrompts prompts, Refused refused) {
      caller();
      return nativeVeto(handle, index, prompts, refused);
    }

    @Override
    public Posted cosign(long index, IVosPrompts prompts, Refused refused) {
      caller();
      return nativeCosign(handle, index, prompts, refused);
    }

    @Override
    public Posted resolve(long index, boolean upheld, IVosPrompts prompts, Refused refused) {
      caller();
      return nativeResolve(handle, index, upheld, prompts, refused);
    }

    @Override
    public Posted rotateKit(byte kit, IVosPrompts prompts, Refused refused) {
      caller();
      return nativeRotateKit(handle, kit, prompts, refused);
    }

    @Override
    public Posted replaceAdmin(byte kit, IVosPrompts prompts, Refused refused) {
      caller();
      return nativeReplaceAdmin(handle, kit, prompts, refused);
    }

    @Override
    public byte[] adminOffer(IVosPrompts prompts, Refused refused) {
      caller();
      return nativeAdminOffer(handle, prompts, refused);
    }

    @Override
    public Posted replaceAdminOf(byte[] code, IVosPrompts prompts, Refused refused) {
      caller();
      return nativeReplaceAdminOf(handle, code, prompts, refused);
    }

    @Override
    public Posted regroup(IVosPrompts prompts, Refused refused) {
      caller();
      return nativeRegroup(handle, prompts, refused);
    }

    @Override
    public boolean update(IVosPrompts prompts, Refused refused) {
      caller();
      return nativeUpdate(handle, prompts, refused);
    }

    @Override
    public Posted restore(ClaimRequest request, byte old, IVosPrompts prompts, Refused refused) {
      caller();
      return nativeRestore(handle, request, old, prompts, refused);
    }

    @Override
    public KitView kitView(Home home, byte kit, IVosPrompts prompts, Refused refused) {
      caller();
      return nativeKitView(handle, home, kit, prompts, refused);
    }

    @Override
    public Posted removeByKit(
        Home home, byte kit, long device, IVosPrompts prompts, Refused refused) {
      caller();
      return nativeRemoveByKit(handle, home, kit, device, prompts, refused);
    }

    @Override
    public Posted resolveByKit(
        Home home, byte kit, long index, boolean upheld, IVosPrompts prompts, Refused refused) {
      caller();
      return nativeResolveByKit(handle, home, kit, index, upheld, prompts, refused);
    }

    @Override
    public Claimed restored(byte kit, IVosPrompts prompts, Refused refused) {
      caller();
      return nativeRestored(handle, kit, prompts, refused);
    }

    @Override
    public Claimed moveHome(ClaimRequest request, IVosPrompts prompts, Refused refused) {
      caller();
      return nativeMoveHome(handle, request, prompts, refused);
    }
  }

  /**
   * The UI's prompts, saying when a key was used (the proof starts then, with nothing more asked of
   * the UI), and logging each stage of a sign-in or a payment with the milliseconds since it was
   * asked: the form shown and answered, the key asked and answered, then done. A late form is the
   * reads before it; a gap from the form's answer to the key's ask is the node's time read; a long
   * wait from the key's answer to done, past the proof, is the send. Nothing of the form's values
   * or the key's output is logged.
   */
  private static final class Announced extends IVosPrompts.Stub {
    private final IVosPrompts prompts;
    private final String what;
    private final long start = SystemClock.elapsedRealtime();
    /** The last stage's time, since the start. */
    private volatile long last;

    Announced(IVosPrompts prompts, String what, Long granted) {
      this.prompts = prompts;
      this.what = what;
      Log.i(
          TAG,
          what
              + " started"
              + (granted == null ? "" : ", the session open " + (start - granted) + " ms"));
    }

    private void stage(String stage) {
      long now = SystemClock.elapsedRealtime() - start;
      Log.i(TAG, what + " " + stage + " at +" + now + " ms (+" + (now - last) + ")");
      last = now;
    }

    /** The end's time, for the done or refused line. */
    static String at(Announced announced) {
      if (announced == null) {
        return "";
      }
      long now = SystemClock.elapsedRealtime() - announced.start;
      return " at +" + now + " ms (+" + (now - announced.last) + " since the last stage)";
    }

    @Override
    public Answer confirm(Form form) throws RemoteException {
      stage("form shown");
      Answer answer = prompts.confirm(form);
      stage("form answered");
      return answer;
    }

    @Override
    public KeyResult createKey(byte kind) throws RemoteException {
      return prompts.createKey(kind);
    }

    @Override
    public KeyResult signKey(byte kind, byte[] key, byte[] message) throws RemoteException {
      return prompts.signKey(kind, key, message);
    }

    @Override
    public KeyResult evaluateKey(byte kind, byte[] key, byte[] input) throws RemoteException {
      stage("key asked");
      KeyResult result = prompts.evaluateKey(kind, key, input);
      stage("key answered");
      if (result != null && result.status == KeyStatus.DONE) {
        Log.i(TAG, "proof started");
      }
      return result;
    }
  }

  private static Announced announced(IVosPrompts prompts, String what, Long granted) {
    return prompts == null ? null : new Announced(prompts, what, granted);
  }

  private static native long nativeOpen(
      String store, String tor, ClassLoader loader, VosNode device);

  private static native boolean nativeSupported(long handle);

  private static native void nativeWarm(long handle, boolean thrifty);

  private static native long nativeOpenSession(long handle, Gateway gateway, Refusal refused);

  private static native boolean nativeGranted(long handle, long session, Refusal refused);

  private static native void nativeClose(long handle, long session);

  private static native Enrolled nativeEnroll(
      long handle, long session, EnrollRequest request, IVosPrompts prompts, Refusal refused);

  private static native SignedIn nativeSignIn(
      long handle, long session, SignInRequest request, IVosPrompts prompts, Refusal refused);

  private static native Paid nativePay(
      long handle, long session, PayRequest request, IVosPrompts prompts, Refusal refused);

  private static native boolean nativeRefresh(long handle, long session, Refusal refused);

  private static native Synced nativeSync(long handle, Refusal refused);

  private static native EnrolledSpace[] nativeEnrollments(
      long handle, Class<EnrolledSpace> element, Refusal refused);

  private static native JobRun[] nativeRuns(
      long handle, Class<JobRun> element, Refusal refused);

  private static void closeQuietly(ParcelFileDescriptor descriptor) {
    if (descriptor == null) {
      return;
    }
    try {
      descriptor.close();
    } catch (java.io.IOException ignored) {
      // Closing a descriptor no one reads.
    }
  }

  private static native byte[] nativeScreens(
      long handle, StreamTarget gateway, int descriptor, Refusal refused);

  private static native boolean nativeClearnet(long handle, byte[] hostKey, Refusal refused);

  private static native Synced nativeSyncPersonal(long handle, Refusal refused);

  private static native boolean nativeForeground(long handle, boolean foreground, Refusal refused);

  private static native boolean nativeCloseAll(long handle, long[] sessions, Refusal refused);

  private static native boolean nativeBridges(long handle, String[] lines, Refusal refused);

  private static native boolean nativeBootstrap(long handle, Refusal refused);

  private static native boolean nativeOptOut(
      long handle, byte[] space, boolean optedOut, Refusal refused);

  private static native Claimed nativeClaim(
      long handle, ClaimRequest request, IVosPrompts prompts, Refused refused);

  private static native PairCode nativePairOffer(
      long handle, IVosPrompts prompts, Refused refused);

  private static native Paired nativePairAwait(long handle, IVosPrompts prompts, Refused refused);

  private static native boolean nativePairCancel(long handle, Refused refused);

  private static native Paired nativePairJoin(
      long handle, byte[] code, String label, IVosPrompts prompts, Refused refused);

  private static native Membership[] nativeMemberships(
      long handle, Class<Membership> element, Refused refused);

  private static native boolean nativeEnrollDevice(
      long handle, Membership membership, IVosPrompts prompts, Refused refused);

  private static native boolean nativeConfirmDevice(
      long handle, Membership membership, IVosPrompts prompts, Refused refused);

  private static native boolean nativeDropEnrollment(
      long handle, Membership membership, Refused refused);

  private static native int nativeRevoke(
      long handle, long device, IVosPrompts prompts, Refused refused);

  private static native Device[] nativeDevices(long handle, Class<Device> element, Refused refused);

  private static native Notice[] nativeOperations(
      long handle, Class<Notice> element, Refused refused);

  private static native Posted nativeRemove(
      long handle, long device, IVosPrompts prompts, Refused refused);

  private static native Posted nativeVeto(
      long handle, long index, IVosPrompts prompts, Refused refused);

  private static native Posted nativeCosign(
      long handle, long index, IVosPrompts prompts, Refused refused);

  private static native Posted nativeResolve(
      long handle, long index, boolean upheld, IVosPrompts prompts, Refused refused);

  private static native Posted nativeRotateKit(
      long handle, byte kit, IVosPrompts prompts, Refused refused);

  private static native Posted nativeReplaceAdmin(
      long handle, byte kit, IVosPrompts prompts, Refused refused);

  private static native byte[] nativeAdminOffer(
      long handle, IVosPrompts prompts, Refused refused);

  private static native Posted nativeReplaceAdminOf(
      long handle, byte[] code, IVosPrompts prompts, Refused refused);

  private static native Posted nativeRegroup(long handle, IVosPrompts prompts, Refused refused);

  private static native KitView nativeKitView(
      long handle, Home home, byte kit, IVosPrompts prompts, Refused refused);

  private static native Posted nativeRemoveByKit(
      long handle, Home home, byte kit, long device, IVosPrompts prompts, Refused refused);

  private static native Posted nativeResolveByKit(
      long handle,
      Home home,
      byte kit,
      long index,
      boolean upheld,
      IVosPrompts prompts,
      Refused refused);

  private static native boolean nativeUpdate(long handle, IVosPrompts prompts, Refused refused);

  private static native Posted nativeRestore(
      long handle, ClaimRequest request, byte old, IVosPrompts prompts, Refused refused);

  private static native Claimed nativeRestored(
      long handle, byte kit, IVosPrompts prompts, Refused refused);

  private static native Claimed nativeMoveHome(
      long handle, ClaimRequest request, IVosPrompts prompts, Refused refused);

  private static native PersonalStatus nativeStatus(long handle, Refused refused);
}
