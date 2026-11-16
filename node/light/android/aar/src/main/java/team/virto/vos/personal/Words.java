// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.vos.personal;

import team.virto.s4.vos.ErrorCode;

/** What the screens say of the facility's values: plain words, no Android in them. */
public final class Words {
  private static final long MINUTE = 60_000;
  private static final long HOUR = 60 * MINUTE;
  private static final long DAY = 24 * HOUR;

  /** The characters a device's label takes besides letters and digits. */
  private static final String LABEL_SIGNS = " ._-";
  /** A label's most characters, as the facility bounds it. */
  public static final int MAX_LABEL = 64;

  private Words() {}

  /** A device's standing, as {@code Device.standing} holds it. */
  public static String standing(byte standing) {
    switch (standing) {
      case 0:
        return "in probation";
      case 1:
        return "active";
      case 2:
        return "removed";
      case 3:
        return "dropped";
      default:
        return "unknown standing " + standing;
    }
  }

  /** When something happened, {@code at} by the agent's clock, against the device's {@code now}. */
  public static String ago(long at, long now) {
    if (at <= 0) {
      return "never";
    }
    long since = now - at;
    if (since < MINUTE) {
      return "just now";
    }
    return span(since) + " ago";
  }

  /** How long until {@code at}, against {@code now}. */
  public static String until(long at, long now) {
    long left = at - now;
    return left <= 0 ? "now" : "in " + span(left);
  }

  private static String span(long ms) {
    if (ms < HOUR) {
      return Math.max(1, ms / MINUTE) + " min";
    }
    if (ms < DAY) {
      return ms / HOUR + " h";
    }
    return ms / DAY + " d";
  }

  /** What an operation open, or a notice, is. */
  public static String pending(byte pending) {
    switch (pending) {
      case Pending.ADD:
        return "A device is being added";
      case Pending.REMOVE:
        return "A device is being removed";
      case Pending.REPLACE:
        return "A device's admin key is being replaced";
      case Pending.ROTATE:
        return "The recovery kit is being replaced";
      case Pending.REGROUP:
        return "The devices are being regrouped";
      case Pending.RESTORE:
        return "A restore by the kit removes every device";
      case Pending.RESTORING:
        return "A restore is pending: rotate your recovery kit";
      case Pending.REMOVED:
        return "This device was removed";
      case Pending.RENEW:
        return "The yearly re-proof is due";
      case Pending.STUCK:
        return "This device cannot follow the others: pair it again";
      default:
        return "The sync found something wrong";
    }
  }

  /** Whether an operation's detail says it is contested, as the facility words it. */
  public static boolean contested(String detail) {
    return detail != null && detail.endsWith(", contested");
  }

  /** A refusal's words: its message, or its code when it has none. */
  public static String refusal(int code, String message) {
    if (message != null && !message.isEmpty()) {
      return message;
    }
    switch (code) {
      case ErrorCode.DECLINED:
        return "declined";
      case ErrorCode.NOT_ENROLLED:
        return "this device holds no personal space";
      case ErrorCode.API:
        return "the home did not answer";
      default:
        return "refused (" + code + ")";
    }
  }

  /** A device's label as the facility takes it, from any text: the default the screens fill. */
  public static String label(String text) {
    StringBuilder out = new StringBuilder();
    for (char c : (text == null ? "" : text).toCharArray()) {
      boolean plain =
          (c >= 'a' && c <= 'z')
              || (c >= 'A' && c <= 'Z')
              || (c >= '0' && c <= '9')
              || LABEL_SIGNS.indexOf(c) >= 0;
      out.append(plain ? c : ' ');
    }
    String label = out.toString().trim().replaceAll(" +", " ");
    if (label.length() > MAX_LABEL) {
      label = label.substring(0, MAX_LABEL).trim();
    }
    return label.isEmpty() ? "phone" : label;
  }

  /** The first and last eight hex digits of a handle, to tell homes and spaces apart. */
  public static String shortHex(byte[] bytes) {
    String hex = Codes.lowerHex(bytes);
    return hex.length() <= 16 ? hex : hex.substring(0, 8) + "…" + hex.substring(hex.length() - 8);
  }
}
