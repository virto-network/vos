// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.vos.personal;

import android.content.Context;
import android.os.Bundle;
import android.os.RemoteException;
import android.os.SystemClock;
import team.virto.s4.FacilityProbe;
import team.virto.s4.vos.Refusal;

/**
 * The facility's own ops of s4's debug probe ({@code VosProbe}, which hands them here through the
 * application's meta-data), over {@link IVosPersonal}:
 *
 * <ul>
 *   <li>{@code -e op sync -e count N}: N passes of the spaces' job, each one's result or failure,
 *       the binding waited for again after a failure;
 *   <li>{@code -e op personal -e count N}: N passes of the personal space's job.
 * </ul>
 */
public final class Probe implements FacilityProbe {
  @Override
  public boolean run(Context context, String op, Bundle arguments, Say say) {
    if (!op.equals("sync") && !op.equals("personal")) {
      return false;
    }
    Binding binding = new Binding(context);
    try {
      int count = Integer.parseInt(arguments.getString("count", "1"));
      for (int pass = 1; pass <= count; pass++) {
        sync(binding, op.equals("personal"), pass, say);
      }
    } finally {
      binding.close();
    }
    return true;
  }

  private static void sync(Binding binding, boolean personal, int pass, Say say) {
    long started = SystemClock.elapsedRealtime();
    try {
      Refusal refused = new Refusal();
      IVosPersonal facility = binding.personal();
      Synced synced = personal ? facility.syncPersonal(refused) : facility.sync(refused);
      if (synced == null) {
        say.line("sync " + pass + ": refused " + refused.code + " " + refused.message);
        return;
      }
      say.line(
          "sync "
              + pass
              + ": "
              + synced.synced
              + " of "
              + synced.enrollments
              + " synced, "
              + synced.failed
              + " failed, "
              + (SystemClock.elapsedRealtime() - started)
              + " ms, down "
              + synced.bytesDown
              + " B up "
              + synced.bytesUp
              + " B, "
              + synced.notices.length
              + " notices");
    } catch (RemoteException | RuntimeException gone) {
      say.line("sync " + pass + ": failed: " + gone);
    }
  }
}
