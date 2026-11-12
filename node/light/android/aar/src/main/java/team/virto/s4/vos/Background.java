// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.s4.vos;

import android.content.Context;
import androidx.work.Constraints;
import androidx.work.Data;
import androidx.work.ExistingPeriodicWorkPolicy;
import androidx.work.NetworkType;
import androidx.work.PeriodicWorkRequest;
import androidx.work.WorkManager;
import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;

/**
 * The background job's schedule, made in {@code :vos}: a periodic job at Android's floor of 15
 * minutes, when a network is up. Android runs it late or not at all in the "rare" and "restricted"
 * standby buckets, after a force-stop until the app is opened, and under some OEMs' battery
 * managers; the UI then recommends the battery-optimization exemption.
 *
 * <p>Two jobs, each on its own schedule: the spaces' ({@link #WORK}: each enrollment's tree from
 * its feed) and the personal space's ({@link #PERSONAL}: the device group's pass at the personal
 * agent), whose traffic goes on circuits of its own, so the two never line up.
 */
public final class Background {
  /** The job's unique name. */
  public static final String WORK = "vos.sync";

  /** The personal space's job's unique name. */
  public static final String PERSONAL = "vos.personal";

  /** The job's input: whether it is the personal space's. */
  static final String PART = "personal";

  /** The job's period, Android's floor. */
  public static final long PERIOD_MINUTES = 15;

  /** The personal space's job's window at the end of each period, Android's floor. */
  static final long PERSONAL_FLEX_MINUTES = 5;

  private Background() {}

  /** Schedule the job, keeping the schedule already made. */
  static void schedule(Context context) {
    WorkManager work = WorkManager.getInstance(context);
    work.enqueueUniquePeriodicWork(WORK, ExistingPeriodicWorkPolicy.KEEP, request(false));
    work.enqueueUniquePeriodicWork(PERSONAL, ExistingPeriodicWorkPolicy.KEEP, request(true));
  }

  /**
   * The job's request. The personal space's starts at a drawn offset into the period and runs in
   * a narrower window of it, so it does not follow the spaces' job by a fixed delay.
   */
  private static PeriodicWorkRequest request(boolean personal) {
    PeriodicWorkRequest.Builder builder =
        personal
            ? new PeriodicWorkRequest.Builder(
                    SyncWorker.class,
                    PERIOD_MINUTES,
                    TimeUnit.MINUTES,
                    PERSONAL_FLEX_MINUTES,
                    TimeUnit.MINUTES)
                .setInitialDelay(
                    new SecureRandom().nextInt((int) TimeUnit.MINUTES.toSeconds(PERIOD_MINUTES)),
                    TimeUnit.SECONDS)
            : new PeriodicWorkRequest.Builder(SyncWorker.class, PERIOD_MINUTES, TimeUnit.MINUTES);
    return builder
        .setConstraints(
            new Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
        .setInputData(new Data.Builder().putBoolean(PART, personal).build())
        .build();
  }
}
