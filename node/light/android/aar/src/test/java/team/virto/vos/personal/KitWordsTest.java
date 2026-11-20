// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.vos.personal;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import android.content.pm.ApplicationInfo;
import org.junit.Test;

public final class KitWordsTest {
  /** BIP39's 256-bit test vector of all-zero entropy: its checksum word is "art". */
  private static final String ZEROS =
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
          + " abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
          + " abandon abandon art";

  @Test
  public void aPhraseChecksOut() {
    assertNull(KitWords.problem(ZEROS, true));
    assertNull(KitWords.problem("  " + ZEROS.toUpperCase() + "\n", true));
    assertEquals(ZEROS, KitWords.normalized(" " + ZEROS.replace(" ", "   ") + " "));
  }

  @Test
  public void theBadWordIsNamed() {
    String typo = ZEROS.replaceFirst("abandon abandon abandon abandon abandon abandon abandon "
        + "abandon", "abandon abandon abandon abandon abandon abandon abandon abandn");
    assertEquals("word 8 'abandn' is not a recovery-kit word", KitWords.problem(typo, true));
    // While typed: the word under way is not judged until it starts no kit word.
    assertNull(KitWords.problem("abandon aba", false));
    assertEquals(
        "word 2 'abq' starts no recovery-kit word", KitWords.problem("abandon abq", false));
    assertEquals(
        "word 1 'abq' is not a recovery-kit word", KitWords.problem("abq abandon", false));
  }

  @Test
  public void aWrongValidWordIsCaughtByTheChecksum() {
    String swapped = ZEROS.replace(" art", " zoo");
    assertEquals(
        "the words are all kit words but do not check out: look for one written wrong",
        KitWords.problem(swapped, true));
    assertEquals("23 words: a recovery phrase is 24", KitWords.problem(
        ZEROS.substring(ZEROS.indexOf(' ') + 1), true));
  }

  @Test
  public void theListCompletesWhatIsTyped() {
    assertArrayEquals(new String[0], KitWords.completions("ab"));
    assertArrayEquals(new String[] {"abandon"}, KitWords.completions("aba"));
    assertArrayEquals(
        new String[] {"absent", "absorb", "abstract", "absurd"}, KitWords.completions("abs"));
    assertArrayEquals(new String[0], KitWords.completions("abandon zo"));
    assertArrayEquals(new String[] {"zoo"}, KitWords.completions("abandon zoo"));
    assertArrayEquals(new String[0], KitWords.completions("abandon zoo "));
    assertEquals("abandon zoo ", KitWords.complete("abandon zo", "zoo"));
    assertTrue(KitWords.known("zoo"));
    assertFalse(KitWords.known("zo"));
    assertNull(KitWords.wordProblem(" Zoo "));
    assertEquals("'zo' is not a recovery-kit word", KitWords.wordProblem("zo"));
  }

  @Test
  public void onlyADebuggableBuildIsCaptured() {
    assertTrue(PersonalActivity.secured(0));
    assertFalse(PersonalActivity.secured(ApplicationInfo.FLAG_DEBUGGABLE));
  }
}
