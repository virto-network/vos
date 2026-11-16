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
 * the others pairs again here too.
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
        "Waiting for the new device to scan the code…",
        (personal, prompts, refused) -> personal.pairAwait(prompts, refused),
        (Paired paired) -> {
          forget();
          app.home();
          app.say(
              "Device "
                  + paired.device
                  + " joined your personal space."
                  + (paired.memberships > 0
                      ? " Enroll it in your "
                          + paired.memberships
                          + " other space(s) from Devices, changes and keys."
                      : ""));
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
    app.run(
        "Joining your personal space…",
        (personal, prompts, refused) -> personal.pairJoin(scanned, name, prompts, refused),
        (Paired paired) -> {
          app.home();
          app.say(
              "This phone joined your personal space as device "
                  + paired.device
                  + "."
                  + (paired.memberships > 0
                      ? " Confirm its "
                          + paired.memberships
                          + " membership(s) from Devices, changes and keys."
                      : "")
                  + " Its membership at your home is made in the background within a few "
                  + "hours, at a random time, so the home cannot tell it is this pairing's.");
        },
        (personal, prompts, refused) -> {
          personal.pairCancel();
          return null;
        });
  }
}
