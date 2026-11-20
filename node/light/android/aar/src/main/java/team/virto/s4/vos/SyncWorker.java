// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.s4.vos;

import android.app.KeyguardManager;
import android.app.usage.UsageStatsManager;
import android.content.Context;
import android.net.TrafficStats;
import android.os.Build;
import android.os.PowerManager;
import android.os.Process;
import android.os.SystemClock;
import android.util.Log;
import androidx.annotation.NonNull;
import androidx.work.Worker;
import androidx.work.WorkerParameters;
import team.virto.vos.personal.Synced;

/**
 * The background jobs, run by WorkManager in {@code :vos} with no UI process: one pass of the
 * facility's sync ({@link VosNode#sync}), or of the personal space's ({@link
 * VosNode#syncPersonal}), each posting its notices. Its line in {@code
 * logcat -s vos.job} is the record of the run: its length, the bytes the app's uid read and wrote
 * meanwhile and those the pass's own connections did, the standby bucket, and whether the device
 * was idle and locked.
 */
public final class SyncWorker extends Worker {
  static final String TAG = "vos.job";

  public SyncWorker(@NonNull Context context, @NonNull WorkerParameters parameters) {
    super(context, parameters);
  }

  @NonNull
  @Override
  public Result doWork() {
    Context context = getApplicationContext();
    int uid = Process.myUid();
    long rx = TrafficStats.getUidRxBytes(uid);
    long tx = TrafficStats.getUidTxBytes(uid);
    long started = SystemClock.elapsedRealtime();
    boolean personal = getInputData().getBoolean(Background.PART, false);
    String job = personal ? "personal job" : "job";
    Log.i(TAG, job + " started: " + state(context) + ", attempt " + getRunAttemptCount());
    Refusal refused = new Refusal();
    VosNode node = VosNode.get(context);
    Synced synced = personal ? node.syncPersonal(refused) : node.sync(refused);
    long millis = SystemClock.elapsedRealtime() - started;
    long down = TrafficStats.getUidRxBytes(uid) - rx;
    long up = TrafficStats.getUidTxBytes(uid) - tx;
    if (personal && (synced != null || refused.code != ErrorCode.NOT_ENROLLED)) {
      paused(context, node, synced == null || synced.failed > 0);
    }
    if (synced == null) {
      Log.i(TAG, job + " refused in " + millis + " ms: " + refused.code + " " + refused.message);
      return Result.success();
    }
    Log.i(
        TAG,
        job + " done in "
            + millis
            + " ms: uid rx "
            + down
            + " B tx "
            + up
            + " B, pass down "
            + synced.bytesDown
            + " B up "
            + synced.bytesUp
            + " B, "
            + synced.synced
            + " of "
            + synced.enrollments
            + " synced, "
            + synced.failed
            + " failed, "
            + synced.notices.length
            + " notices, "
            + state(context));
    // A failed pass is the next period's to retry: the job is periodic.
    return Result.success();
  }

  /**
   * The personal space's backup paused or not: after a pass that did not finish, Tor's bootstrap
   * names why (a network that blocks Tor, a wrong clock), posted until a pass finishes.
   */
  private static void paused(Context context, VosNode node, boolean unfinished) {
    if (!unfinished) {
      Notices.resumed(context);
      return;
    }
    Refusal refused = new Refusal();
    if (node.bootstrap(refused)) {
      Notices.resumed(context);
    } else {
      Notices.paused(context, refused.message);
    }
  }

  @Override
  public void onStopped() {
    String reason = Build.VERSION.SDK_INT >= 31 ? " (reason " + getStopReason() + ")" : "";
    Log.i(TAG, "job stopped by the system" + reason);
  }

  /** The standby bucket, and whether the device is idle and locked. */
  static String state(Context context) {
    StringBuilder state = new StringBuilder();
    if (Build.VERSION.SDK_INT >= 28) {
      UsageStatsManager usage = context.getSystemService(UsageStatsManager.class);
      state.append("bucket ").append(usage == null ? -1 : usage.getAppStandbyBucket());
    } else {
      state.append("bucket ?");
    }
    PowerManager power = context.getSystemService(PowerManager.class);
    state.append(", idle ").append(power != null && power.isDeviceIdleMode());
    state.append(", exempt ")
        .append(power != null && power.isIgnoringBatteryOptimizations(context.getPackageName()));
    KeyguardManager keyguard = context.getSystemService(KeyguardManager.class);
    state.append(", locked ").append(keyguard != null && keyguard.isDeviceLocked());
    return state.toString();
  }
}
