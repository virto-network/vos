// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.vos.personal;

import android.widget.EditText;
import android.widget.ImageView;
import android.widget.LinearLayout;

/**
 * An admin key replaced by another device: on the phone whose key it is, the new key made and its
 * offer shown as a QR code with its key check; on another seasoned device of the set, the offer
 * scanned (or pasted) and the replacement signed by its admin key. The new key signs from the end
 * of its probation.
 */
final class AdminKeyScreen extends Screen {
  /** The phone whose key is replaced, or the device that signs. */
  private final boolean offering;

  private byte[] offer;
  private String pasted = "";

  AdminKeyScreen(PersonalActivity app, boolean offering) {
    super(app);
    this.offering = offering;
  }

  @Override
  String title() {
    return offering ? "New admin key, by another device" : "Approve another device's admin key";
  }

  @Override
  void shown() {
    if (offering && offer == null) {
      app.run(
          "Making this phone's new admin key…",
          (personal, prompts, refused) -> personal.adminOffer(prompts, refused),
          (byte[] made) -> {
            offer = made;
            redraw();
          },
          null,
          false,
          refused -> {
            app.refused(refused);
            app.close();
          });
    }
  }

  @Override
  void build(LinearLayout into) {
    if (!offering) {
      approving(into);
      return;
    }
    if (offer == null) {
      into.addView(text("Making this phone's new admin key…"));
      return;
    }
    into.addView(
        text(
            "On another of your devices, seasoned in your personal space, open \"Devices, "
                + "changes and keys\", choose \"Approve another device's admin key\" and scan "
                + "this code. Check that it shows the same key check. This phone's new key signs "
                + "once its probation ends."));
    String text = Codes.admin(offer);
    ImageView qr = new ImageView(app);
    qr.setImageBitmap(Qr.bitmap(text, app.dp(300)));
    qr.setAdjustViewBounds(true);
    into.addView(qr);
    into.addView(heading("Key check"));
    into.addView(mono(Codes.adminCheck(offer)));
  }

  private void approving(LinearLayout into) {
    into.addView(
        text(
            "On the phone whose admin key is replaced, choose \"New admin key, by another "
                + "device\", then scan its code here. Approve only if both show the same key "
                + "check."));
    into.addView(button("Scan the code", v -> app.scan(this::approve)));
    into.addView(heading("Or paste it"));
    EditText paste = kept(field(Codes.ADMIN + "…", pasted, true), t -> pasted = t);
    into.addView(paste);
    into.addView(button("Approve", v -> approve(pasted)));
  }

  private void approve(String text) {
    byte[] scanned = Codes.admin(text);
    if (scanned == null) {
      app.say("This is not an admin key's code.");
      return;
    }
    app.run(
        "Signing the replacement…",
        (personal, prompts, refused) -> personal.replaceAdminOf(scanned, prompts, refused),
        (Posted posted) -> {
          app.close();
          app.say(
              "Done: your personal agent took it (log entry "
                  + posted.index
                  + "). The new key signs once its probation ends.");
        });
  }
}
