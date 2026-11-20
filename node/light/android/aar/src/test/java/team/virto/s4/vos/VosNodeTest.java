// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.s4.vos;

import static org.junit.Assert.assertThrows;

import android.os.IBinder;
import org.junit.Test;
import team.virto.vos.personal.IVosPersonal;

public class VosNodeTest {
  /** Another app's uid: the host's android.jar answers 0 for this process's. */
  private static final int FOREIGN = 10_123;

  /** The codes tried: every method's of both interfaces, those past them, and the descriptor's. */
  private static int[] codes() {
    int[] codes = new int[129];
    for (int at = 0; at < 128; at++) {
      codes[at] = IBinder.FIRST_CALL_TRANSACTION + at;
    }
    codes[128] = IBinder.INTERFACE_TRANSACTION;
    return codes;
  }

  @Test
  public void anotherAppsTransactionsAreRefusedBeforeTheirDispatch() {
    VosNode node = new VosNode(() -> FOREIGN);
    IVosNode.Stub served = (IVosNode.Stub) node.binder();
    IVosPersonal.Stub personal = (IVosPersonal.Stub) node.personal();
    for (int code : codes()) {
      assertThrows(SecurityException.class, () -> served.onTransact(code, null, null, 0));
      assertThrows(SecurityException.class, () -> personal.onTransact(code, null, null, 0));
    }
  }
}
