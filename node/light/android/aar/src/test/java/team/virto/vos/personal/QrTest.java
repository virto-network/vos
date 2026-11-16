// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.vos.personal;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import com.google.zxing.common.BitMatrix;
import org.junit.Test;

public final class QrTest {
  /** A frame's luminance holding {@code text}'s code, each module {@code scale} pixels. */
  private static byte[] frame(String text, int scale, int[] size) {
    BitMatrix modules = Qr.matrix(text);
    int side = modules.getWidth() * scale;
    byte[] luminance = new byte[side * side];
    for (int y = 0; y < side; y++) {
      for (int x = 0; x < side; x++) {
        luminance[y * side + x] = modules.get(x / scale, y / scale) ? 0 : (byte) 0xff;
      }
    }
    size[0] = side;
    return luminance;
  }

  @Test
  public void aPairingCodesQrReadsBack() {
    // A pairing code's size with two onions.
    byte[] code = new byte[400];
    for (int i = 0; i < code.length; i++) {
      code[i] = (byte) (i * 37);
    }
    String text = Codes.pair(code);
    int[] side = new int[1];
    byte[] luminance = frame(text, 4, side);
    assertEquals(text, Qr.read(luminance, side[0], side[0]));
  }

  @Test
  public void aBlankFrameReadsNothing() {
    byte[] blank = new byte[200 * 200];
    java.util.Arrays.fill(blank, (byte) 0xff);
    assertNull(Qr.read(blank, 200, 200));
  }
}
