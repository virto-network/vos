// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.vos.personal;

import android.content.ClipData;
import android.content.ClipDescription;
import android.content.ClipboardManager;
import android.os.Build;
import android.os.PersistableBundle;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.LinearLayout;

/**
 * Pairing: on a device of the personal space, its code shown as a QR code (and copied, for a
 * device with no camera) while the facility waits for the new device, cancellable; on the new
 * device, the code scanned (or pasted) and joined, this phone named. A device that moved home with
 * the others pairs again here too. Both phones say the pairing's steps as they pass (scan, check,
 * the keys handed over, the approval, done); once paired, the memberships it left are offered at
 * once, one prompt each.
 */
final class PairScreen extends Screen {
  /** The device that shows the code, or the one that scans it. */
  private final boolean opener;

  private PairCode code;
  private boolean copied;
  private String pasted = "";
  private String label = Words.label(Build.MODEL);

  PairScreen(PersonalActivity app, boolean opener) {
    super(app);
    this.opener = opener;
  }

  @Override
  String title() {
    return opener ? "Pair a new device" : "Join from another device";
  }

  @Override
  void shown() {
    if (opener && code == null) {
      offer();
    }
  }

  @Override
  String stage(byte stage) {
    return Words.pairing(stage, opener);
  }

  @Override
  void build(LinearLayout into) {
    if (opener) {
      offered(into);
    } else {
      joining(into);
    }
  }

  // ----- the device that shows the code -----

  private void offer() {
    app.run(
        "Opening a pairing slot…",
        (personal, prompts, refused) -> personal.pairOffer(prompts, refused),
        (PairCode offered) -> {
          code = offered;
          redraw();
          await();
        },
        null,
        true,
        refused -> {
          app.refused(refused);
          app.close();
        });
  }

  private void offered(LinearLayout into) {
    if (code == null) {
      into.addView(text("Opening a pairing slot…"));
      return;
    }
    into.addView(
        text(
            "On the new device, open the app's personal space, choose \"Join from another "
                + "device\" and scan this code. Show it to no one else: whoever scans it first "
                + "joins."));
    String text = Codes.pair(code.code);
    ImageView qr = new ImageView(app);
    qr.setImageBitmap(Qr.bitmap(text, app.dp(300)));
    qr.setAdjustViewBounds(true);
    into.addView(qr);
    into.addView(
        text("The slot closes " + Words.until(code.expiresMs, System.currentTimeMillis()) + "."));
    into.addView(button("Copy the code instead", v -> copy(text)));
  }

  /** Wait for the new device, the screen covered, cancellable. */
  private void await() {
    app.run(
        Words.pairing((byte) 0, true),
        (personal, prompts, refused) -> personal.pairAwait(prompts, refused),
        (Paired paired) -> {
          forget();
          app.home();
          String joined = "Paired: device " + paired.device + " joined your personal space.";
          if (paired.memberships > 0) {
            memberships(joined, paired.memberships);
          } else {
            app.say(joined);
          }
        },
        (personal, prompts, refused) -> {
          personal.pairCancel();
          return null;
        },
        false,
        refused -> {
          // The slot is gone with the wait: its code no longer shown or held.
          forget();
          app.refused(refused);
          app.close();
        });
  }

  /** The code copied, if it was, cleared from the clipboard: it is a bearer secret. */
  private void forget() {
    if (copied && Build.VERSION.SDK_INT >= 28) {
      app.getSystemService(ClipboardManager.class).clearPrimaryClip();
    }
    copied = false;
  }

  private void copy(String text) {
    copied = true;
    ClipboardManager clipboard = app.getSystemService(ClipboardManager.class);
    ClipData clip = ClipData.newPlainText("pairing code", text);
    if (Build.VERSION.SDK_INT >= 33) {
      PersistableBundle extras = new PersistableBundle();
      extras.putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true);
      clip.getDescription().setExtras(extras);
    }
    clipboard.setPrimaryClip(clip);
  }

  /**
   * The memberships a pairing left on the phone that showed the code, offered right after it: the
   * new device enrolled in each, in one flow, one prompt each; left for Devices, changes and keys
   * when the user waits.
   */
  private void memberships(String paired, int count) {
    app.ask(
        "Paired",
        paired
            + " Memberships to finish: enroll it in your "
            + count
            + " other space(s) now, by this phone's proof there; or later, from Devices, changes"
            + " and keys.",
        "Now",
        () ->
            app.run(
                "Enrolling the new device…",
                (personal, prompts, refused) -> {
                  Membership[] owed = personal.memberships(refused);
                  if (owed == null) {
                    return null;
                  }
                  int done = 0;
                  for (Membership membership : owed) {
                    boolean made =
                        membership.owed == Owed.ENROLL
                            ? personal.enrollDevice(membership, prompts, refused)
                            : personal.confirmDevice(membership, prompts, refused);
                    if (!made) {
                      return null;
                    }
                    done++;
                  }
                  return done;
                },
                (Integer done) -> app.say("Done in " + done + " space(s).")));
  }

  // ----- the new device -----

  private void joining(LinearLayout into) {
    into.addView(
        text(
            "On a device of your personal space, choose \"Pair a new device\", then scan its "
                + "code here."));
    into.addView(heading("This phone's name"));
    EditText name = kept(field("Its name on your other devices", label, false), t -> label = t);
    into.addView(name);
    into.addView(button("Scan the code", v -> app.scan(this::join)));
    into.addView(heading("Or paste it"));
    EditText paste = kept(field(Codes.PAIR + "…", pasted, true), t -> pasted = t);
    into.addView(paste);
    into.addView(button("Join", v -> join(pasted)));
  }

  private void join(String text) {
    byte[] scanned = Codes.pair(text);
    if (scanned == null) {
      app.say("This is not a pairing code.");
      return;
    }
    String name = label.trim();
    app.ask(
        "Join this personal space?",
        "A personal space this phone holds now is left for good: what this phone keeps of "
            + "it is deleted, and its other devices should remove this one.",
        "Join",
        () -> joined(scanned, name));
  }

  private void joined(byte[] scanned, String name) {
    app.run(
        Words.pairing(Stage.SCANNED, false),
        (personal, prompts, refused) -> personal.pairJoin(scanned, name, prompts, refused),
        (Paired paired) -> {
          app.home();
          String joined = "Paired: this phone is device " + paired.device + " of your space.";
          app.say(
              joined
                  + (paired.memberships > 0
                      ? " Memberships to finish: once your other phone enrolled it in your "
                          + paired.memberships
                          + " other space(s), enroll this phone in each from its gateway, then"
                          + " confirm it from Devices, changes and keys."
                      : ""));
        },
        (personal, prompts, refused) -> {
          personal.pairCancel();
          return null;
        });
  }
}
