// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.s4.vos;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.service.notification.StatusBarNotification;
import android.util.Log;
import java.util.HashSet;
import java.util.Set;
import team.virto.vos.R;
import team.virto.vos.personal.Notice;
import team.virto.vos.personal.Pending;
import team.virto.vos.personal.PersonalActivity;
import team.virto.vos.personal.Synced;
import team.virto.vos.personal.Words;

/**
 * The background job's local notifications, posted in {@code :vos}: one for each notice a pass
 * raises, alerting when it is fresh, left as it is while it stands, and withdrawn once no pass
 * raises it. No push service is involved: the device polls (no token is given to any space).
 */
final class Notices {
  private static final String CHANNEL = "vos.pending";
  /** The tag every notice's notification is posted under. */
  private static final String TAG = "vos.pending";
  /** The tag of the one "backup paused" notification. */
  private static final String PAUSED = "vos.paused";

  private Notices() {}

  /** The notification service, the notices' channel made; null when there is none. */
  private static NotificationManager manager(Context context) {
    NotificationManager manager = context.getSystemService(NotificationManager.class);
    if (manager != null && Build.VERSION.SDK_INT >= 26) {
      NotificationChannel channel =
          new NotificationChannel(
              CHANNEL,
              context.getString(R.string.vos_pending_channel),
              NotificationManager.IMPORTANCE_DEFAULT);
      channel.setDescription(context.getString(R.string.vos_pending_channel_description));
      manager.createNotificationChannel(channel);
    }
    return manager;
  }

  /**
   * The personal space's backup paused, Tor's bootstrap refused for {@code why} (a network that
   * blocks Tor, a wrong clock): posted once, its tap opening the bridges' screen.
   */
  static void paused(Context context, String why) {
    NotificationManager manager = manager(context);
    if (manager == null) {
      return;
    }
    String text = context.getString(R.string.vos_paused_text, why);
    Intent open =
        new Intent(context, PersonalActivity.class)
            .putExtra(PersonalActivity.OPEN, PersonalActivity.NETWORK);
    manager.notify(
        PAUSED,
        0,
        builder(context, 1, open)
            .setContentTitle(context.getString(R.string.vos_paused_title))
            .setContentText(text)
            .setStyle(new Notification.BigTextStyle().bigText(text))
            .build());
    Log.i(SyncWorker.TAG, "backup paused: " + why);
  }

  /** Tor connects again: the "backup paused" notification withdrawn. */
  static void resumed(Context context) {
    NotificationManager manager = context.getSystemService(NotificationManager.class);
    if (manager != null) {
      manager.cancel(PAUSED, 0);
    }
  }

  /** Mirror `synced`'s notices: fresh ones posted, those no longer raised withdrawn. */
  static void post(Context context, Synced synced) {
    NotificationManager manager = manager(context);
    if (manager == null) {
      return;
    }
    if (Build.VERSION.SDK_INT >= 24 && !manager.areNotificationsEnabled()) {
      Log.w(SyncWorker.TAG, synced.notices.length + " notices, notifications off");
    }
    Set<Integer> raised = new HashSet<>();
    long now = System.currentTimeMillis();
    for (Notice notice : synced.notices) {
      int id = id(notice);
      raised.add(id);
      if (!notice.fresh) {
        continue;
      }
      manager.notify(TAG, id, notification(context, notice));
      Log.i(
          SyncWorker.TAG,
          "notice "
              + notice.pending
              + " at "
              + notice.index
              + " posted at "
              + now
              + " (device clock)"
              + (notice.at > 0 ? ", the log took it at " + notice.at + " (agent clock)" : ""));
    }
    if (Build.VERSION.SDK_INT >= 23) {
      for (StatusBarNotification shown : manager.getActiveNotifications()) {
        if (TAG.equals(shown.getTag()) && !raised.contains(shown.getId())) {
          manager.cancel(TAG, shown.getId());
        }
      }
    }
  }

  /** A notice's notification id: what it is and where. */
  private static int id(Notice notice) {
    int id = 31 * notice.pending + (int) (notice.index ^ (notice.index >>> 32));
    return 31 * (31 * id + notice.alarm) + (int) notice.by + (notice.byKit ? 1 << 30 : 0);
  }

  /**
   * A notification of the channel, opening {@code open} (its pending intent the {@code request}th:
   * one for the notices, one for the pause, so neither's extras replace the other's).
   */
  @SuppressWarnings("deprecation") // API 23-25 require the pre-channel Builder constructor.
  private static Notification.Builder builder(Context context, int request, Intent open) {
    PendingIntent content =
        PendingIntent.getActivity(
            context,
            request,
            open,
            PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
    Notification.Builder builder =
        Build.VERSION.SDK_INT >= 26
            ? new Notification.Builder(context, CHANNEL)
            : new Notification.Builder(context);
    return builder
        .setSmallIcon(R.drawable.vos_notice)
        .setContentIntent(content)
        .setAutoCancel(true)
        .setOnlyAlertOnce(true);
  }

  /** A notice's notification, opening the personal space's screens. */
  private static Notification notification(Context context, Notice notice) {
    // An alarm in its own words; an operation's kind as the notification channel words it, who
    // signed it after.
    String text =
        notice.pending == Pending.ALARM
            ? Words.notice(notice)
            : context.getString(text(notice.pending)) + Words.signer(notice);
    return builder(context, 0, new Intent(context, PersonalActivity.class))
        .setContentTitle(context.getString(R.string.vos_pending_title))
        .setContentText(text)
        .setStyle(new Notification.BigTextStyle().bigText(text))
        .build();
  }

  private static int text(byte pending) {
    switch (pending) {
      case Pending.ADD:
        return R.string.vos_pending_add;
      case Pending.REMOVE:
        return R.string.vos_pending_remove;
      case Pending.REPLACE:
        return R.string.vos_pending_replace;
      case Pending.ROTATE:
        return R.string.vos_pending_rotate;
      case Pending.REGROUP:
        return R.string.vos_pending_regroup;
      case Pending.RESTORE:
        return R.string.vos_pending_restore;
      case Pending.RESTORING:
        return R.string.vos_pending_restoring;
      case Pending.REMOVED:
        return R.string.vos_pending_removed;
      case Pending.STUCK:
        return R.string.vos_pending_stuck;
      case Pending.COMMIT:
        return R.string.vos_pending_commit;
      case Pending.RESEAL:
        return R.string.vos_pending_reseal;
      case Pending.UNFINISHED:
        return R.string.vos_pending_unfinished;
      default:
        return R.string.vos_pending_alarm;
    }
  }
}
