// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.vos.personal;

import java.io.ByteArrayOutputStream;
import java.util.Locale;
import team.virto.s4.vos.Onion;

/**
 * The texts the screens show, scan and paste: a home's code (what its operator publishes: the
 * home as a device reaches it), a pairing's code (the bytes {@code pairOffer} answers), and a new
 * admin key's offer (the bytes {@code adminOffer} answers: device ‖ key ‖ flags ‖ the device's
 * sync-key signature, which {@code replaceAdminOf} checks). Each is
 * a prefix and upper-case hex, which a QR code carries in its alphanumeric mode; read back, case
 * and whitespace are ignored.
 *
 * <p>A home's code is {@code space ‖ handle ‖ agent ‖ identity ‖ homes ‖ credentials ‖ n ‖ n ×
 * (onion key ‖ SSH host key)}: 32-byte keys, the three ids as big-endian u32s, {@code n} one byte
 * from 1 to {@link #MAX_ONIONS}.
 */
public final class Codes {
  public static final String HOME = "VOSHOME1:";
  public static final String PAIR = "VOSPAIR1:";
  public static final String ADMIN = "VOSADMN1:";
  /** An admin key's offer: the device (u32), its new key, a flags byte, a signature. */
  public static final int ADMIN_LENGTH = 4 + 32 + 1 + 64;
  /** The onions a home pins at most, as the facility bounds them. */
  public static final int MAX_ONIONS = 16;

  private static final int KEY = 32;

  private Codes() {}

  /** The home's code. */
  public static String home(Home home) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.write(home.space, 0, KEY);
    out.write(home.handle, 0, KEY);
    u32(out, home.agent);
    out.write(home.identity, 0, KEY);
    u32(out, home.homes);
    u32(out, home.credentials);
    out.write(home.onions.length);
    for (Onion onion : home.onions) {
      out.write(onion.key, 0, KEY);
      out.write(onion.sshHostKey, 0, KEY);
    }
    return HOME + hex(out.toByteArray());
  }

  /** The home a code names; null for anything else. */
  public static Home home(String text) {
    byte[] bytes = unhex(text, HOME);
    if (bytes == null || bytes.length < 3 * KEY + 12 + 1) {
      return null;
    }
    int at = 0;
    Home home = new Home();
    home.space = slice(bytes, at, KEY);
    at += KEY;
    home.handle = slice(bytes, at, KEY);
    at += KEY;
    home.agent = u32(bytes, at);
    at += 4;
    home.identity = slice(bytes, at, KEY);
    at += KEY;
    home.homes = u32(bytes, at);
    at += 4;
    home.credentials = u32(bytes, at);
    at += 4;
    int count = bytes[at++] & 0xff;
    if (count < 1 || count > MAX_ONIONS || bytes.length != at + count * 2 * KEY) {
      return null;
    }
    home.onions = new Onion[count];
    for (int i = 0; i < count; i++) {
      Onion onion = new Onion();
      onion.key = slice(bytes, at, KEY);
      onion.sshHostKey = slice(bytes, at + KEY, KEY);
      at += 2 * KEY;
      home.onions[i] = onion;
    }
    return home;
  }

  /** A pairing code's text, for its QR code and its copy. */
  public static String pair(byte[] code) {
    return PAIR + hex(code);
  }

  /** The pairing code's bytes a text holds; null for anything else. */
  public static byte[] pair(String text) {
    byte[] bytes = unhex(text, PAIR);
    return bytes == null || bytes.length == 0 ? null : bytes;
  }

  /** An admin key's offer's text, for its QR code and its copy. */
  public static String admin(byte[] offer) {
    return ADMIN + hex(offer);
  }

  /** The admin key's offer a text holds; null for anything else. */
  public static byte[] admin(String text) {
    byte[] bytes = unhex(text, ADMIN);
    return bytes == null || bytes.length != ADMIN_LENGTH || (bytes[36] & 0xff) >= 4
        ? null
        : bytes;
  }

  /** The key check both devices show: the new key's first 8 bytes, lower-case hex. */
  public static String adminCheck(byte[] offer) {
    return lowerHex(slice(offer, 4, 8));
  }

  /** Lower-case hex, as the kit's card shows a home's handle. */
  public static String lowerHex(byte[] bytes) {
    return hex(bytes).toLowerCase(Locale.ROOT);
  }

  static String hex(byte[] bytes) {
    char[] digits = "0123456789ABCDEF".toCharArray();
    StringBuilder out = new StringBuilder(bytes.length * 2);
    for (byte b : bytes) {
      out.append(digits[(b >> 4) & 0xf]).append(digits[b & 0xf]);
    }
    return out.toString();
  }

  /** The bytes after {@code prefix} in {@code text}, whitespace and case ignored. */
  static byte[] unhex(String text, String prefix) {
    if (text == null) {
      return null;
    }
    String plain = text.replaceAll("\\s+", "").toUpperCase(Locale.ROOT);
    if (!plain.startsWith(prefix)) {
      return null;
    }
    String digits = plain.substring(prefix.length());
    if (digits.length() % 2 != 0) {
      return null;
    }
    byte[] bytes = new byte[digits.length() / 2];
    for (int i = 0; i < bytes.length; i++) {
      int high = Character.digit(digits.charAt(2 * i), 16);
      int low = Character.digit(digits.charAt(2 * i + 1), 16);
      if (high < 0 || low < 0) {
        return null;
      }
      bytes[i] = (byte) (high << 4 | low);
    }
    return bytes;
  }

  private static byte[] slice(byte[] bytes, int at, int length) {
    byte[] out = new byte[length];
    System.arraycopy(bytes, at, out, 0, length);
    return out;
  }

  private static void u32(ByteArrayOutputStream out, long value) {
    for (int shift = 24; shift >= 0; shift -= 8) {
      out.write((int) (value >>> shift) & 0xff);
    }
  }

  private static long u32(byte[] bytes, int at) {
    long value = 0;
    for (int i = 0; i < 4; i++) {
      value = value << 8 | (bytes[at + i] & 0xff);
    }
    return value;
  }
}
