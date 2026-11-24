// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.vos.personal;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;
import team.virto.s4.vos.ErrorCode;

public final class WordsTest {
  private static final long NOW = 1_800_000_000_000L;

  @Test
  public void timesReadPlainly() {
    assertEquals("never", Words.ago(0, NOW));
    assertEquals("just now", Words.ago(NOW - 5_000, NOW));
    assertEquals("5 min ago", Words.ago(NOW - 5 * 60_000, NOW));
    assertEquals("3 h ago", Words.ago(NOW - 3 * 3_600_000, NOW));
    assertEquals("2 d ago", Words.ago(NOW - 2 * 86_400_000L, NOW));
    assertEquals("in 2 min", Words.until(NOW + 2 * 60_000, NOW));
    assertEquals("now", Words.until(NOW - 1, NOW));
  }

  @Test
  public void aLabelIsOneTheFacilityTakes() {
    assertEquals("Pixel 9 Pro", Words.label("Pixel 9 Pro"));
    assertEquals("FP6 a b", Words.label("FP6 (a/b)"));
    assertEquals("phone", Words.label("…"));
    assertEquals("phone", Words.label(null));
    StringBuilder longer = new StringBuilder();
    for (int i = 0; i < 100; i++) {
      longer.append('x');
    }
    assertEquals(Words.MAX_LABEL, Words.label(longer.toString()).length());
  }

  @Test
  public void aContestIsReadFromTheDetail() {
    Notice notice = new Notice();
    notice.pending = Pending.REMOVE;
    notice.by = 2;
    notice.contested = true;
    assertEquals("A device is being removed (by device 2, contested)", Words.notice(notice));
    notice.byKit = true;
    assertEquals(
        "A device is being removed (by the kit: if you did not sign it, rotate your kit, and veto"
            + " it while you can)",
        Words.notice(notice));
    Notice alarm = new Notice();
    alarm.pending = Pending.ALARM;
    alarm.alarm = Alarm.CANNOT_FOLLOW;
    alarm.index = 3;
    alarm.remedy = Remedy.REGROUP;
    assertEquals(
        "This device cannot follow epoch 3: no other device to pair from, regroup",
        Words.notice(alarm));
    Refused regrouped = new Refused();
    regrouped.why = Why.REGROUPED;
    regrouped.device = 4;
    assertEquals("device 4 regrouped: pair this phone again", Words.why(regrouped));
    Refused theirs = new Refused();
    Words.refused(ErrorCode.DECLINED, "", theirs);
    assertEquals(Why.DECLINED, theirs.why);
  }

  @Test
  public void aRefusalSaysWhy() {
    assertEquals("the slot expired", Words.refusal(ErrorCode.REFUSED, "the slot expired"));
    assertEquals("declined", Words.refusal(ErrorCode.DECLINED, ""));
    assertEquals("refused (13)", Words.refusal(ErrorCode.REFUSED, null));
  }

  @Test
  public void aFlowSaysWhereItIs() {
    assertEquals("Writing your kit…", Words.stage(Stage.WRITING_KIT));
    assertEquals(
        "scan ✓ · check ✓ · handing over your keys… · approve on the other phone · done",
        Words.pairing(Stage.HANDING_OVER, false));
    assertEquals(
        "scan ✓ · check ✓ · handing over your keys ✓ · approve it with your admin key… · done",
        Words.pairing(Stage.APPROVING, true));
    assertEquals("", Words.failed(""));
    assertEquals(
        "The last sync did not finish: not reached over Tor. It runs again later.",
        Words.failed("not reached over Tor"));
    byte[] handle = new byte[32];
    assertTrue(Words.noAgentForKit(handle).contains("(it is 00000000…00000000)"));
  }

  @Test
  public void aHandleIsShortened() {
    byte[] handle = new byte[32];
    handle[0] = (byte) 0xab;
    handle[31] = (byte) 0xcd;
    assertEquals("ab000000…000000cd", Words.shortHex(handle));
  }

  private static Device device(long id, String label, boolean removed, boolean me) {
    Device device = new Device();
    device.id = id;
    device.label = label;
    device.removed = removed;
    device.me = me;
    return device;
  }

  @Test
  public void devicesOfOneLabelAreToldApart() {
    Device[] devices = {
      device(0, "Fairphone 6", true, false),
      device(1, "Pixel", false, false),
      device(2, "Fairphone 6", false, true),
    };
    String[] names = Words.names(devices);
    assertEquals("An earlier Fairphone 6 (device 0)", names[0]);
    assertEquals("Pixel", names[1]);
    assertEquals("Fairphone 6 (this phone)", names[2]);
  }

  @Test
  public void aRemovalNamesThisPhoneAndSaysWhenItTookEffect() {
    Device[] devices = {device(1, "Pixel", false, true), device(2, "Fairphone 6", false, false)};
    Notice removal = new Notice();
    removal.pending = Pending.REMOVE;
    removal.by = 2;
    removal.target = 1;
    removal.targeted = true;
    removal.matures = NOW - 2 * 60_000;
    assertEquals(
        "This phone is being removed (by Fairphone 6)", Words.notice(removal, devices));
    assertTrue(Words.tookEffect(removal, NOW));
    assertTrue(Words.when(removal, NOW).contains("took effect"));
    removal.matures = NOW - 1;
    assertFalse("a clock a little fast hides no veto", Words.tookEffect(removal, NOW));
  }

  @Test
  public void theKitsAlarmNamesNoOperationNumber() {
    assertFalse(Words.alarm(Alarm.KIT, 14).contains("14"));
  }
}
