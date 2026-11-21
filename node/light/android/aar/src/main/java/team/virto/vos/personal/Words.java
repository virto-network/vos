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

  /** The standing of a device removed, as {@code Device.standing} holds it. */
  public static final byte REMOVED = 2;

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

  /**
   * When an open operation takes effect, after its words: a contested one waits for a resolution,
   * whatever its maturity.
   */
  public static String when(Notice notice, long now) {
    if (notice.contested) {
      return ": it waits for a resolution";
    }
    return notice.matures > 0 ? ", it takes effect " + until(notice.matures, now) : "";
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
        return "Your recovery kit opened a restore, which this phone stopped: if you did not"
            + " open it, rotate your kit";
      case Pending.REMOVED:
        return "This device was removed";
      case Pending.STUCK:
        return "This device cannot follow the others: remove it from another, then pair it again";
      case Pending.COMMIT:
        return "A removed device still holds your keys until you commit: commit now";
      case Pending.RESEAL:
        return "Your recovery kit must be sealed again: commit now";
      case Pending.UNFINISHED:
        return "The last sync after your change did not finish: the next sync finishes it";
      default:
        return "The sync found something wrong";
    }
  }

  /** What a notice is: its kind, who signed it, and whether it is contested; an alarm's words. */
  public static String notice(Notice notice) {
    if (notice.pending == Pending.ALARM) {
      return alarm(notice.alarm, notice.index) + remedy(notice.remedy);
    }
    return pending(notice.pending) + signer(notice);
  }

  /** Who signed an operation's notice, and whether it is contested; nothing for other kinds. */
  public static String signer(Notice notice) {
    if (notice.byKit) {
      return " (by the kit)";
    }
    if (notice.pending <= Pending.RESTORE) {
      return " (by device " + notice.by + (notice.contested ? ", contested" : "") + ")";
    }
    return "";
  }

  /** An alarm's words, {@code at} its place (a log index, an epoch, a position, a skew in s). */
  public static String alarm(byte alarm, long at) {
    switch (alarm) {
      case Alarm.LOG:
        return "The log does not chain at entry " + at;
      case Alarm.SPLIT_LOG:
        return "A vote on epoch " + at + " is of another log";
      case Alarm.NAMED_ABSENT:
        return "Epoch " + at + " names this device absent though it called";
      case Alarm.REFUSED:
        return "This device refused epoch " + at;
      case Alarm.CANNOT_FOLLOW:
        return "This device cannot follow epoch " + at;
      case Alarm.VERDICT:
        return "The agent's verdict on epoch " + at + " is not this device's";
      case Alarm.UNSIGNED:
        return "Log entry " + at + " matures with no evidence";
      case Alarm.CLOCK:
        return "This device's clock is " + at + " s off the agent's";
      case Alarm.KIT:
        return "The recovery kit signed operation " + at + ": veto it, or rotate the kit";
      case Alarm.ROLLBACK:
        return "The agent's log went back to " + at;
      case Alarm.VIEW:
        return "A device saw log entry " + at + " otherwise";
      case Alarm.DROPPED:
        return "This device's call at " + at + " is not in the log";
      case Alarm.PARTITION:
        return "The agent serves less than a device read, at " + at;
      case Alarm.WITHHELD:
        return "The agent withheld an envelope at " + at;
      case Alarm.STALE:
        return "An envelope at " + at + " is sealed under a past epoch";
      case Alarm.AUTHOR:
        return "An envelope at " + at + " is by no device of the set";
      case Alarm.DELETED:
        return "This device's envelope at " + at + " was gone: pushed again";
      case Alarm.UNSERVED:
        return "The agent named its log's head at " + at + " and served less of it";
      case Alarm.POLICY:
        return "Log entry " + at + " lowers the device set's delays: refused";
      default:
        return "An alarm (" + alarm + ")";
    }
  }

  /** What an alarm's remedy asks, after its words; nothing when it has none. */
  public static String remedy(byte remedy) {
    switch (remedy) {
      case Remedy.RE_PAIR:
        return ": pair this phone again from another of your devices";
      case Remedy.REGROUP:
        return ": no other device to pair from, regroup";
      default:
        return "";
    }
  }

  /** Where the personal space is. */
  public static String phase(byte phase) {
    switch (phase) {
      case Phase.NONE:
        return "This phone holds no personal space";
      case Phase.CLAIMING:
        return "A claim is under way: claim at its home again to finish it";
      case Phase.JOINING:
        return "Paired: waiting to be added";
      case Phase.HELD:
        return "Your personal space";
      case Phase.RESTORING:
        return "A restore is under way";
      case Phase.REMOVED:
        return "This phone is out of your personal space: pair it again";
      case Phase.STUCK:
        return "This phone cannot follow your devices: pair it again, or regroup";
      case Phase.NEEDS_REPAIR:
        return "This phone's personal space needs repair: clear the app's data, then claim or pair";
      default:
        return "Unknown (" + phase + ")";
    }
  }

  /** What a flow is doing at {@code stage}, while it runs. */
  public static String stage(byte stage) {
    switch (stage) {
      case Stage.REACHING:
        return "Reaching your home…";
      case Stage.PROVING:
        return "Proving your device…";
      case Stage.WRITING_KIT:
        return "Writing your kit…";
      case Stage.JOINING:
        return "Joining…";
      case Stage.SCANNED:
      case Stage.CHECKED:
      case Stage.HANDING_OVER:
      case Stage.APPROVING:
        return pairing(stage, true);
      case Stage.SENDING:
        return "Sending…";
      default:
        return "Working…";
    }
  }

  /**
   * A pairing's steps on either phone, those done ticked and the one under way said: scan, check,
   * the keys handed over, the new device approved (by this phone's admin key on the {@code
   * opener}, on the other phone on the new one), done.
   */
  public static String pairing(byte stage, boolean opener) {
    int at;
    switch (stage) {
      case Stage.SCANNED:
        at = 1;
        break;
      case Stage.CHECKED:
      case Stage.HANDING_OVER:
        at = 2;
        break;
      case Stage.APPROVING:
        at = 3;
        break;
      case Stage.JOINING:
        at = 4;
        break;
      default:
        at = 0;
    }
    String[] steps = {
      "scan",
      "check",
      "handing over your keys",
      opener ? "approve it with your admin key" : "approve on the other phone",
      "done"
    };
    StringBuilder line = new StringBuilder();
    for (int i = 0; i < steps.length; i++) {
      if (i > 0) {
        line.append(" · ");
      }
      line.append(steps[i]).append(i < at ? " ✓" : i == at ? "…" : "");
    }
    return line.toString();
  }

  /**
   * A kit no personal space at the home holds: the home's code to check, by its handle, or the
   * kit's being an older one.
   */
  public static String noAgentForKit(byte[] handle) {
    return "no personal space at that home holds this kit: check the home's code (it is "
        + shortHex(handle)
        + "), or that these are your newest kit's words";
  }

  /** A personal sync that did not finish, with its reasons; empty when it finished. */
  public static String failed(String failures) {
    return failures == null || failures.isEmpty()
        ? ""
        : "The last sync did not finish: " + failures + ". It runs again later.";
  }

  /** Tor as the facility last found it. */
  public static String tor(byte tor, String why) {
    switch (tor) {
      case Tor.CONNECTED:
        return "Tor connected";
      case Tor.BLOCKED:
        return "Tor blocked" + (why == null || why.isEmpty() ? "" : ": " + why);
      default:
        return "Tor starting";
    }
  }

  /** Why a personal operation was refused, in words, its detail after when it has one. */
  public static String why(Refused refused) {
    String said = whyWords(refused);
    return refused.detail == null || refused.detail.isEmpty() || said.endsWith(refused.detail)
        ? said
        : said + " (" + refused.detail + ")";
  }

  private static String whyWords(Refused refused) {
    switch (refused.why) {
      case Why.NO_SPACE:
        return "this phone holds no personal space";
      case Why.ALREADY_HELD:
        return "this phone holds a personal space already";
      case Why.HOLDS_KEYS:
        return "this phone holds a personal space's keys already: restore or pair it";
      case Why.CLAIM_ELSEWHERE:
        return "a claim at another home is under way: claim there again to finish it";
      case Why.AT_THAT_HOME:
        return "your personal space is at that home already";
      case Why.NO_RESTORE:
        return "no restore is under way";
      case Why.NO_PAIRING:
        return "no pairing is under way";
      case Why.NEEDS_REPAIR:
        return "this phone's personal space needs repair";
      case Why.DECLINED:
        return "declined";
      case Why.CANCELLED:
        return "cancelled";
      case Why.NOT_A_KIT:
        return "that is not a recovery kit";
      case Why.WRONG_KIT:
        return "that kit is not this personal space's";
      case Why.NOT_A_PAIRING_CODE:
        return "that is not a pairing code";
      case Why.NOT_AN_OFFER:
        return "that is not an admin-key code";
      case Why.STALE_OFFER:
        return "that admin-key code is not signed by its device, or is stale";
      case Why.OWN_KEY:
        return "a device does not sign its own key's replacement";
      case Why.NOT_IN_SET:
        return "that device is not in the set";
      case Why.DELAYED_ADMIN:
        return "this phone's admin key is not kept in hardware: open the pairing on a phone"
            + " whose key is";
      case Why.SOURCE:
        // The source's own words name the key, the phone's or a security key, when they can.
        if (refused.detail == null || refused.detail.isEmpty()) {
          return "the key failed";
        }
        return refused.detail.contains("key") || refused.detail.startsWith("no answer from you")
            ? refused.detail
            : "the key failed: " + refused.detail;
      case Why.NO_OPEN_CLAIM:
        return "that home serves no claim";
      case Why.OPEN_CLAIM_REFUSED:
        return "that home refused to open a claim";
      case Why.NO_AGENT_TO_GIVE:
        return "that home has no personal agent to give";
      case Why.NO_AGENT_FOR_KIT:
        return "no personal space at that home holds this kit";
      case Why.HOLDS_AGENT_THERE:
        return "this phone holds an agent at that home already";
      case Why.UNKNOWN_AGENT:
        return "that home does not know the agent";
      case Why.NO_LEAF:
        return "the space is not read yet: try again";
      case Why.HOME_REFUSED:
        return "the home refused";
      case Why.UPDATE:
        return "update the app: this proof's format is retired";
      case Why.REJECTED:
        return "the proof was rejected";
      case Why.AGENT_REFUSED:
        return "your personal agent refused";
      case Why.NOT_TAKEN_YET:
      case Why.NOT_JOINED_YET:
      case Why.COMMIT_VOID:
      case Why.COMMITTED_MEANWHILE:
        return "not yet: try again";
      case Why.AWAITS_VOTES:
        return "waiting for your other devices";
      case Why.UNDECIDED:
        return "your devices have not decided yet";
      case Why.SLOT_EXPIRED:
        return "the pairing's code expired";
      case Why.PAIRING_DECLINED:
        return "the pairing was declined on your other device";
      case Why.IN_SET_ALREADY:
        return "this phone is in that personal space already";
      case Why.NOT_IN_AGENT_SET:
        return "your personal agent does not hold this phone";
      case Why.REGROUPED:
        return "device " + refused.device + " regrouped: pair this phone again";
      case Why.NOT_ENROLLED:
        return "this phone is not enrolled there";
      case Why.NOTHING_OWED:
        return "nothing is owed there";
      case Why.SPENT:
        return "that enrollment was used";
      case Why.REGISTRAR_REFUSED:
        return "the space refused";
      case Why.UNREACHABLE:
        return "not reached over Tor";
      case Why.PROVE:
        return "the proof failed";
      case Why.STORE:
        return "this phone's storage failed";
      case Why.ARGUMENTS:
        return "not a request the facility takes";
      default:
        return refused.detail == null || refused.detail.isEmpty()
            ? "the facility failed"
            : refused.detail;
    }
  }

  /** One of the facility's own refusals ({@code code}, {@code message}) filled into {@code into}. */
  public static void refused(int code, String message, Refused into) {
    switch (code) {
      case ErrorCode.DECLINED:
        into.why = Why.DECLINED;
        break;
      case ErrorCode.NOT_ENROLLED:
        into.why = Why.NOT_ENROLLED;
        break;
      case ErrorCode.API:
        into.why = Why.UNREACHABLE;
        break;
      case ErrorCode.STORE:
        into.why = Why.STORE;
        break;
      case ErrorCode.ARGUMENTS:
        into.why = Why.ARGUMENTS;
        break;
      case ErrorCode.SOURCE:
        into.why = Why.SOURCE;
        break;
      case ErrorCode.PROVE:
        into.why = Why.PROVE;
        break;
      default:
        into.why = Why.FAILED;
    }
    into.detail = message == null ? "" : message;
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
