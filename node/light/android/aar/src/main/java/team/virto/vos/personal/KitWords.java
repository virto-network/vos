// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.vos.personal;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/**
 * A recovery phrase's words as they are typed: each checked against the kit's list (BIP39's
 * English, {@code kit-words.txt}, held to the facility's in its tests), the list's words that
 * complete what is typed, and the phrase's checksum once all 24 are known. What it says names a
 * word and its place, for the screen alone: nothing of it leaves the UI. Plain Java, no Android in
 * it.
 */
public final class KitWords {
  /** The facility's form a kit's words are entered in ({@code personal::ENTER_PHRASE}). */
  public static final String ENTER = "Enter your recovery phrase";
  /** The facility's form asking two of a new phrase's words back ({@code CHECK_PHRASE}). */
  public static final String CHECK = "Check your recovery phrase";

  /** A phrase's words. */
  public static final int COUNT = 24;
  /** The letters typed before the list completes them. */
  public static final int COMPLETE_FROM = 3;
  /** The most completions offered at once. */
  public static final int COMPLETIONS = 4;

  private static final String[] LIST = load();

  private KitWords() {}

  private static String[] load() {
    List<String> words = new ArrayList<>();
    try (InputStream in = KitWords.class.getResourceAsStream("kit-words.txt")) {
      if (in == null) {
        throw new IllegalStateException("the kit's word list is not packaged");
      }
      BufferedReader lines = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
      for (String line = lines.readLine(); line != null; line = lines.readLine()) {
        if (!line.isEmpty()) {
          words.add(line);
        }
      }
    } catch (IOException failed) {
      throw new IllegalStateException("the kit's word list does not read", failed);
    }
    if (words.size() != 2048) {
      throw new IllegalStateException("the kit's word list has " + words.size() + " words");
    }
    return words.toArray(new String[0]);
  }

  /** The words of {@code text}, lower case, as the facility reads them. */
  public static String[] words(String text) {
    String trimmed = text == null ? "" : text.trim().toLowerCase(Locale.ROOT);
    return trimmed.isEmpty() ? new String[0] : trimmed.split("\\s+");
  }

  /** {@code text} as the facility takes it: its words, lower case, one space between. */
  public static String normalized(String text) {
    return String.join(" ", words(text));
  }

  /** Whether {@code word} is one of the kit's. */
  public static boolean known(String word) {
    return Arrays.binarySearch(LIST, word) >= 0;
  }

  /**
   * The kit's words that start with what is typed of the last word of {@code text}, at most
   * {@link #COMPLETIONS}, once {@link #COMPLETE_FROM} letters are; none while the last word is
   * finished (a space after it) or shorter.
   */
  public static String[] completions(String text) {
    String typed = typing(text);
    if (typed.length() < COMPLETE_FROM) {
      return new String[0];
    }
    int at = Arrays.binarySearch(LIST, typed);
    int first = at >= 0 ? at : -at - 1;
    List<String> found = new ArrayList<>();
    for (int i = first; i < LIST.length && found.size() < COMPLETIONS; i++) {
      if (!LIST[i].startsWith(typed)) {
        break;
      }
      found.add(LIST[i]);
    }
    return found.toArray(new String[0]);
  }

  /** What is typed of the word under way: none after a space. */
  private static String typing(String text) {
    if (text == null || text.isEmpty() || Character.isWhitespace(text.charAt(text.length() - 1))) {
      return "";
    }
    String[] all = words(text);
    return all.length == 0 ? "" : all[all.length - 1];
  }

  /** {@code text} with the word under way replaced by {@code word}, and a space after it. */
  public static String complete(String text, String word) {
    String typed = typing(text);
    String kept = text.substring(0, text.length() - typed.length());
    return kept + word + " ";
  }

  /**
   * What is wrong with {@code text} as a phrase, or null when nothing is yet: an unknown word
   * named by its place (the word under way only once {@code done}), then, once {@code done}, a
   * count other than {@link #COUNT}, then a checksum that does not hold.
   */
  public static String problem(String text, boolean done) {
    String[] all = words(text);
    boolean typingLast = !done && !typing(text).isEmpty();
    for (int i = 0; i < all.length; i++) {
      boolean underWay = typingLast && i == all.length - 1;
      if (!underWay && !known(all[i])) {
        return "word " + (i + 1) + " '" + all[i] + "' is not a recovery-kit word";
      }
      if (underWay && completions(text).length == 0 && all[i].length() >= COMPLETE_FROM) {
        return "word " + (i + 1) + " '" + all[i] + "' starts no recovery-kit word";
      }
    }
    if (!done) {
      return null;
    }
    if (all.length != COUNT) {
      return all.length + " words: a recovery phrase is " + COUNT;
    }
    if (!checksum(all)) {
      return "the words are all kit words but do not check out: look for one written wrong";
    }
    return null;
  }

  /** Whether one word, a check's, is a kit word: null when it is, else why not. */
  public static String wordProblem(String text) {
    String[] all = words(text);
    if (all.length != 1) {
      return all.length == 0 ? "enter the word" : "one word here";
    }
    return known(all[0]) ? null : "'" + all[0] + "' is not a recovery-kit word";
  }

  /** Whether {@code words}, each a kit word, hold their checksum: SHA-256's first byte. */
  static boolean checksum(String[] words) {
    boolean[] bits = new boolean[words.length * 11];
    for (int i = 0; i < words.length; i++) {
      int index = Arrays.binarySearch(LIST, words[i]);
      for (int j = 0; j < 11; j++) {
        bits[i * 11 + j] = ((index >> (10 - j)) & 1) == 1;
      }
    }
    int entropyBytes = words.length / 3 * 4;
    byte[] entropy = new byte[entropyBytes];
    for (int i = 0; i < entropyBytes; i++) {
      for (int j = 0; j < 8; j++) {
        if (bits[i * 8 + j]) {
          entropy[i] |= (byte) (1 << (7 - j));
        }
      }
    }
    try {
      byte[] check = MessageDigest.getInstance("SHA-256").digest(entropy);
      boolean holds = true;
      for (int i = 0; i < entropyBytes / 4; i++) {
        boolean bit = (check[i / 8] & (1 << (7 - (i % 8)))) != 0;
        holds &= bit == bits[entropyBytes * 8 + i];
      }
      Arrays.fill(check, (byte) 0);
      return holds;
    } catch (NoSuchAlgorithmException absent) {
      throw new IllegalStateException(absent);
    } finally {
      Arrays.fill(bits, false);
      Arrays.fill(entropy, (byte) 0);
    }
  }
}
