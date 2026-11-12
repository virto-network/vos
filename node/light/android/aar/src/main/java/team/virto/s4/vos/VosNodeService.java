// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.s4.vos;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;

/**
 * The bound service the UI reaches the VOS facility through, declared in the {@code :vos}
 * process and not exported: {@link IVosNode}. It lives while the UI is bound to it, and the
 * process for a while after, as Android keeps a cached process.
 */
public final class VosNodeService extends Service {
  @Override
  public IBinder onBind(Intent intent) {
    return VosNode.get(this).binder().asBinder();
  }
}
