// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.vos.personal;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;
import team.virto.s4.vos.Onion;

public final class CodesTest {
  private static byte[] filled(int value) {
    byte[] bytes = new byte[32];
    java.util.Arrays.fill(bytes, (byte) value);
    return bytes;
  }

  private static Home home(int onions) {
    Home home = new Home();
    home.space = filled(1);
    home.handle = filled(2);
    home.agent = 0xfffffffeL;
    home.identity = filled(3);
    home.homes = 3;
    home.credentials = 1;
    home.onions = new Onion[onions];
    for (int i = 0; i < onions; i++) {
      home.onions[i] = new Onion();
      home.onions[i].key = filled(0x10 + i);
      home.onions[i].sshHostKey = filled(0x80 + i);
    }
    return home;
  }

  @Test
  public void aHomesCodeReadsBack() {
    Home home = home(2);
    String code = Codes.home(home);
    assertTrue(code.startsWith(Codes.HOME));
    assertEquals(Codes.HOME.length() + 2 * (109 + 2 * 64), code.length());
    // Pasted with its case changed and broken over lines.
    Home read = Codes.home(" " + code.toLowerCase().replace("0101", "01\n01") + "\n");
    assertArrayEquals(home.space, read.space);
    assertArrayEquals(home.handle, read.handle);
    assertEquals(home.agent, read.agent);
    assertArrayEquals(home.identity, read.identity);
    assertEquals(home.homes, read.homes);
    assertEquals(home.credentials, read.credentials);
    assertEquals(2, read.onions.length);
    assertArrayEquals(home.onions[1].key, read.onions[1].key);
    assertArrayEquals(home.onions[1].sshHostKey, read.onions[1].sshHostKey);
  }

  @Test
  public void anythingElseIsNoHome() {
    String code = Codes.home(home(1));
    assertNull(Codes.home(""));
    assertNull(Codes.home((String) null));
    assertNull(Codes.home(code.substring(Codes.HOME.length())));
    assertNull(Codes.home(code.substring(0, code.length() - 2)));
    assertNull(Codes.home(code + "00"));
    assertNull(Codes.home(code.substring(0, code.length() - 1) + "G"));
    assertNull(Codes.home(Codes.home(home(0))));
    assertNull(Codes.home(Codes.home(home(Codes.MAX_ONIONS + 1))));
    assertNull(Codes.home(Codes.pair(new byte[] {1, 2, 3})));
  }

  @Test
  public void aPairingCodeReadsBack() {
    byte[] code = {0, 1, (byte) 0xab, (byte) 0xff};
    assertEquals("VOSPAIR1:0001ABFF", Codes.pair(code));
    assertArrayEquals(code, Codes.pair("vospair1:0001abff"));
    assertNull(Codes.pair("VOSPAIR1:"));
    assertNull(Codes.pair(Codes.home(home(1))));
  }

  @Test
  public void anAdminKeysOfferReadsBackWithItsCheck() {
    byte[] offer = new byte[Codes.ADMIN_LENGTH];
    offer[3] = 2;
    for (int i = 0; i < 32; i++) {
      offer[4 + i] = (byte) (0xa0 + i);
    }
    offer[36] = 3;
    String text = Codes.admin(offer);
    assertTrue(text.startsWith("VOSADMN1:00000002A0A1"));
    assertArrayEquals(offer, Codes.admin(text.toLowerCase(java.util.Locale.ROOT)));
    assertEquals("a0a1a2a3a4a5a6a7", Codes.adminCheck(offer));
    assertNull(Codes.admin("VOSADMN1:0001"));
    assertNull("unsigned", Codes.admin(Codes.admin(java.util.Arrays.copyOf(offer, 37))));
    offer[36] = 4;
    assertNull(Codes.admin(Codes.admin(offer)));
    assertNull(Codes.admin(Codes.pair(offer)));
  }
}
