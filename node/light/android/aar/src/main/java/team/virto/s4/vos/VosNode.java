// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.s4.vos;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.BatteryManager;
import android.os.Binder;
import android.os.Build;
import android.os.IBinder;
import android.os.Parcel;
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
  /** The uid each transaction of the two interfaces comes from. */
  private final Callers callers;
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
    this.callers = Binder::getCallingUid;
    System.loadLibrary(LIBRARY);
    File store = new File(context.getNoBackupFilesDir(), "credentials");
    File tor = new File(context.getFilesDir(), "tor");
    if (!nativeOpen(
        store.getAbsolutePath(), tor.getAbsolutePath(), VosNode.class.getClassLoader(), this)) {
      throw new IllegalStateException("the VOS facility did not open");
    }
    Refusal refused = new Refusal();
    EnrolledSpace[] kept = nativeEnrollments(EnrolledSpace.class, refused);
    // A store that does not read is said, not thrown: the facility still
    // serves what does not need it, and the UI hears why the rest refuse.
    Log.i(
        TAG,
        "store opened: "
            + (kept == null ? "unreadable (" + refused.message + ")" : kept.length + " enrollments"));
    nativeWarm(thrifty());
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

  /** A facility that opened nothing, its transactions' uid read from {@code callers}. */
  VosNode(Callers callers) {
    this.context = null;
    this.callers = callers;
  }

  /** Where a transaction's uid is read. */
  interface Callers {
    int uid();
  }

  /**
   * Only this app's own processes are served: each interface's every transaction, whatever its
   * code, refused before its dispatch when it comes from another uid.
   */
  private void caller() {
    if (callers.uid() != Process.myUid()) {
      throw new SecurityException("the VOS facility serves this app alone");
    }
  }

  /**
   * One pass of the facility's sync: the background job's, in this process, whoever asked for it,
   * its notices posted ({@link Notices}). Null when it refuses, {@code refused} then filled.
   */
  public Synced sync(Refusal refused) {
    Log.i(TAG, "sync started");
    Synced synced = nativeSync(refused);
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
    Synced synced = nativeSyncPersonal(refused);
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
    return nativeBootstrap(refused);
  }

  /** The background job's last runs, the latest last; null when refused. */
  public JobRun[] runs(Refusal refused) {
    return nativeRuns(JobRun.class, refused);
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
    nativeCloseAll(closing, new Refusal());
  }

  /** s4's interface, for this app's own processes alone. */
  private final class Served extends IVosNode.Stub {
    @Override
    public boolean onTransact(int code, Parcel data, Parcel reply, int flags)
        throws RemoteException {
      caller();
      return super.onTransact(code, data, reply, flags);
    }

    @Override
    public void hold(IBinder client) {
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
      released(client);
    }

    @Override
    public boolean supported() {
      return nativeSupported();
    }

    @Override
    public long open(Gateway gateway, Refusal refused) {
      long session = nativeOpenSession(gateway, refused);
      if (session != 0) {
        opened(session);
      }
      return session;
    }

    @Override
    public boolean granted(long session, Refusal refused) {
      grants.put(session, SystemClock.elapsedRealtime());
      Log.i(TAG, "session granted");
      return nativeGranted(session, refused);
    }

    @Override
    public void close(long session) {
      grants.remove(session);
      closed(session);
      nativeClose(session);
    }

    @Override
    public Enrolled enroll(
        long session, EnrollRequest request, IVosPrompts prompts, Refusal refused) {
      return nativeEnroll(session, request, prompts, refused);
    }

    @Override
    public SignedIn signIn(
        long session, SignInRequest request, IVosPrompts prompts, Refusal refused) {
      Announced announced = announced(prompts, "sign-in", grants.get(session));
      SignedIn signed = nativeSignIn(session, request, announced, refused);
      Log.i(
          TAG,
          signed == null
              ? "sign-in refused: " + refused.code + Announced.at(announced)
              : "sign-in done: proved in " + signed.provingMs + " ms" + Announced.at(announced));
      return signed;
    }

    @Override
    public Paid pay(long session, PayRequest request, IVosPrompts prompts, Refusal refused) {
      Announced announced = announced(prompts, "payment", grants.get(session));
      Paid paid = nativePay(session, request, announced, refused);
      Log.i(
          TAG,
          paid == null
              ? "payment refused: " + refused.code + Announced.at(announced)
              : "payment done: proved in " + paid.provingMs + " ms" + Announced.at(announced));
      return paid;
    }

    @Override
    public boolean refresh(long session, Refusal refused) {
      return nativeRefresh(session, refused);
    }

    @Override
    public void foreground(boolean foreground) {
      nativeForeground(foreground, new Refusal());
    }

    @Override
    public EnrolledSpace[] enrollments(Refusal refused) {
      return nativeEnrollments(EnrolledSpace.class, refused);
    }

    @Override
    public JobRun[] runs(Refusal refused) {
      return VosNode.this.runs(refused);
    }

    @Override
    public byte[] screens(StreamTarget gateway, ParcelFileDescriptor end, Refusal refused) {
      if (end == null) {
        refused.code = ErrorCode.ARGUMENTS;
        refused.message = "the screens need the UI's end of a socket pair";
        return null;
      }
      // The light node owns the descriptor from here, and closes it with the session.
      return nativeScreens(gateway, end.detachFd(), refused);
    }

    @Override
    public boolean clearnet(byte[] hostKey, Refusal refused) {
      return nativeClearnet(hostKey, refused);
    }
  }

  /** The facility's own interface, for this app's own processes alone. */
  private final class Personal extends IVosPersonal.Stub {
    @Override
    public boolean onTransact(int code, Parcel data, Parcel reply, int flags)
        throws RemoteException {
      caller();
      return super.onTransact(code, data, reply, flags);
    }

    @Override
    public Synced sync(Refusal refused) {
      return VosNode.this.sync(refused);
    }

    @Override
    public Synced syncPersonal(Refusal refused) {
      return VosNode.this.syncPersonal(refused);
    }

    @Override
    public boolean bridges(String[] lines, Refusal refused) {
      return nativeBridges(lines, refused);
    }

    @Override
    public boolean bootstrap(Refusal refused) {
      return nativeBootstrap(refused);
    }

    @Override
    public boolean optOut(byte[] space, boolean optedOut, Refusal refused) {
      return nativeOptOut(space, optedOut, refused);
    }

    @Override
    public PersonalStatus status(Refused refused) {
      return nativeStatus(refused);
    }

    @Override
    public Claimed claim(ClaimRequest request, IVosPrompts prompts, Refused refused) {
      return nativeClaim(request, prompts, refused);
    }

    @Override
    public PairCode pairOffer(IVosPrompts prompts, Refused refused) {
      return nativePairOffer(prompts, refused);
    }

    @Override
    public Paired pairAwait(IVosPrompts prompts, Refused refused) {
      return nativePairAwait(prompts, refused);
    }

    @Override
    public void pairCancel() {
      nativePairCancel(new Refused());
    }

    @Override
    public Paired pairJoin(byte[] code, String label, IVosPrompts prompts, Refused refused) {
      return nativePairJoin(code, label, prompts, refused);
    }

    @Override
    public Membership[] memberships(Refused refused) {
      return nativeMemberships(Membership.class, refused);
    }

    @Override
    public boolean enrollDevice(Membership membership, IVosPrompts prompts, Refused refused) {
      return nativeEnrollDevice(membership, prompts, refused);
    }

    @Override
    public boolean confirmDevice(Membership membership, IVosPrompts prompts, Refused refused) {
      return nativeConfirmDevice(membership, prompts, refused);
    }

    @Override
    public boolean dropEnrollment(Membership membership, Refused refused) {
      return nativeDropEnrollment(membership, refused);
    }

    @Override
    public int revoke(long device, IVosPrompts prompts, Refused refused) {
      return nativeRevoke(device, prompts, refused);
    }

    @Override
    public Device[] devices(Refused refused) {
      return nativeDevices(Device.class, refused);
    }

    @Override
    public Notice[] operations(Refused refused) {
      return nativeOperations(Notice.class, refused);
    }

    @Override
    public Posted remove(long device, IVosPrompts prompts, Refused refused) {
      return nativeRemove(device, prompts, refused);
    }

    @Override
    public Posted veto(long index, IVosPrompts prompts, Refused refused) {
      return nativeVeto(index, prompts, refused);
    }

    @Override
    public Posted cosign(long index, IVosPrompts prompts, Refused refused) {
      return nativeCosign(index, prompts, refused);
    }

    @Override
    public Posted resolve(long index, boolean upheld, IVosPrompts prompts, Refused refused) {
      return nativeResolve(index, upheld, prompts, refused);
    }

    @Override
    public Posted rotateKit(byte kit, IVosPrompts prompts, Refused refused) {
      return nativeRotateKit(kit, prompts, refused);
    }

    @Override
    public Posted replaceAdmin(byte kit, IVosPrompts prompts, Refused refused) {
      return nativeReplaceAdmin(kit, prompts, refused);
    }

    @Override
    public byte[] adminOffer(IVosPrompts prompts, Refused refused) {
      return nativeAdminOffer(prompts, refused);
    }

    @Override
    public Posted replaceAdminOf(byte[] code, IVosPrompts prompts, Refused refused) {
      return nativeReplaceAdminOf(code, prompts, refused);
    }

    @Override
    public Posted regroup(IVosPrompts prompts, Refused refused) {
      return nativeRegroup(prompts, refused);
    }

    @Override
    public boolean update(IVosPrompts prompts, Refused refused) {
      return nativeUpdate(prompts, refused);
    }

    @Override
    public Posted restore(ClaimRequest request, byte old, IVosPrompts prompts, Refused refused) {
      return nativeRestore(request, old, prompts, refused);
    }

    @Override
    public KitView kitView(Home home, byte kit, IVosPrompts prompts, Refused refused) {
      return nativeKitView(home, kit, prompts, refused);
    }

    @Override
    public Posted removeByKit(
        Home home, byte kit, long device, IVosPrompts prompts, Refused refused) {
      return nativeRemoveByKit(home, kit, device, prompts, refused);
    }

    @Override
    public Posted resolveByKit(
        Home home, byte kit, long index, boolean upheld, IVosPrompts prompts, Refused refused) {
      return nativeResolveByKit(home, kit, index, upheld, prompts, refused);
    }

    @Override
    public Claimed restored(byte kit, IVosPrompts prompts, Refused refused) {
      return nativeRestored(kit, prompts, refused);
    }

    @Override
    public Claimed moveHome(ClaimRequest request, IVosPrompts prompts, Refused refused) {
      return nativeMoveHome(request, prompts, refused);
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

  private static native boolean nativeOpen(
      String store, String tor, ClassLoader loader, VosNode device);

  private static native boolean nativeSupported();

  private static native void nativeWarm(boolean thrifty);

  private static native long nativeOpenSession(Gateway gateway, Refusal refused);

  private static native boolean nativeGranted(long session, Refusal refused);

  private static native void nativeClose(long session);

  private static native Enrolled nativeEnroll(long session, EnrollRequest request, IVosPrompts prompts, Refusal refused);

  private static native SignedIn nativeSignIn(long session, SignInRequest request, IVosPrompts prompts, Refusal refused);

  private static native Paid nativePay(long session, PayRequest request, IVosPrompts prompts, Refusal refused);

  private static native boolean nativeRefresh(long session, Refusal refused);

  private static native Synced nativeSync(Refusal refused);

  private static native EnrolledSpace[] nativeEnrollments(Class<EnrolledSpace> element, Refusal refused);

  private static native JobRun[] nativeRuns(Class<JobRun> element, Refusal refused);

  private static native byte[] nativeScreens(StreamTarget gateway, int descriptor, Refusal refused);

  private static native boolean nativeClearnet(byte[] hostKey, Refusal refused);

  private static native Synced nativeSyncPersonal(Refusal refused);

  private static native boolean nativeForeground(boolean foreground, Refusal refused);

  private static native boolean nativeCloseAll(long[] sessions, Refusal refused);

  private static native boolean nativeBridges(String[] lines, Refusal refused);

  private static native boolean nativeBootstrap(Refusal refused);

  private static native boolean nativeOptOut(byte[] space, boolean optedOut, Refusal refused);

  private static native Claimed nativeClaim(ClaimRequest request, IVosPrompts prompts, Refused refused);

  private static native PairCode nativePairOffer(IVosPrompts prompts, Refused refused);

  private static native Paired nativePairAwait(IVosPrompts prompts, Refused refused);

  private static native boolean nativePairCancel(Refused refused);

  private static native Paired nativePairJoin(byte[] code, String label, IVosPrompts prompts, Refused refused);

  private static native Membership[] nativeMemberships(Class<Membership> element, Refused refused);

  private static native boolean nativeEnrollDevice(Membership membership, IVosPrompts prompts, Refused refused);

  private static native boolean nativeConfirmDevice(Membership membership, IVosPrompts prompts, Refused refused);

  private static native boolean nativeDropEnrollment(Membership membership, Refused refused);

  private static native int nativeRevoke(long device, IVosPrompts prompts, Refused refused);

  private static native Device[] nativeDevices(Class<Device> element, Refused refused);

  private static native Notice[] nativeOperations(Class<Notice> element, Refused refused);

  private static native Posted nativeRemove(long device, IVosPrompts prompts, Refused refused);

  private static native Posted nativeVeto(long index, IVosPrompts prompts, Refused refused);

  private static native Posted nativeCosign(long index, IVosPrompts prompts, Refused refused);

  private static native Posted nativeResolve(long index, boolean upheld, IVosPrompts prompts, Refused refused);

  private static native Posted nativeRotateKit(byte kit, IVosPrompts prompts, Refused refused);

  private static native Posted nativeReplaceAdmin(byte kit, IVosPrompts prompts, Refused refused);

  private static native byte[] nativeAdminOffer(IVosPrompts prompts, Refused refused);

  private static native Posted nativeReplaceAdminOf(byte[] code, IVosPrompts prompts, Refused refused);

  private static native Posted nativeRegroup(IVosPrompts prompts, Refused refused);

  private static native KitView nativeKitView(Home home, byte kit, IVosPrompts prompts, Refused refused);

  private static native Posted nativeRemoveByKit(Home home, byte kit, long device, IVosPrompts prompts, Refused refused);

  private static native Posted nativeResolveByKit(Home home,
      byte kit,
      long index,
      boolean upheld,
      IVosPrompts prompts,
      Refused refused);

  private static native boolean nativeUpdate(IVosPrompts prompts, Refused refused);

  private static native Posted nativeRestore(ClaimRequest request, byte old, IVosPrompts prompts, Refused refused);

  private static native Claimed nativeRestored(byte kit, IVosPrompts prompts, Refused refused);

  private static native Claimed nativeMoveHome(ClaimRequest request, IVosPrompts prompts, Refused refused);

  private static native PersonalStatus nativeStatus(Refused refused);
}
