// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.s4.vos;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import team.virto.vos.personal.Binding;

/**
 * The bound service the app reaches the VOS facility through, declared in the {@code :vos}
 * process and not exported: s4's {@link IVosNode}, or the facility's own {@link
 * team.virto.vos.personal.IVosPersonal} for an intent of its action ({@link Binding#ACTION}). It
 * lives while the app is bound to it, and the process for a while after, as Android keeps a cached
 * process.
 */
public final class VosNodeService extends Service {
  @Override
  public IBinder onBind(Intent intent) {
    VosNode node = VosNode.get(this);
    if (Binding.ACTION.equals(intent.getAction())) {
      return node.personal().asBinder();
    }
    return node.binder().asBinder();
  }
}
