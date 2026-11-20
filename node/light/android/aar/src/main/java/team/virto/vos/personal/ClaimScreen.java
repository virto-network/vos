// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.vos.personal;

import android.os.Build;
import android.widget.EditText;
import android.widget.LinearLayout;

/**
 * The claim: a personal agent at a home (its code pasted or scanned), with a recovery kit of the
 * kind chosen, this phone named to the person's other devices. The facility shows the kit with
 * its card (the home's handle and onions) in its own form.
 */
final class ClaimScreen extends Screen {
  private String code = "";
  private String label = Words.label(Build.MODEL);
  private byte kit = KitKind.PHRASE;

  ClaimScreen(PersonalActivity app) {
    super(app);
  }

  @Override
  String title() {
    return "Back up this phone";
  }

  @Override
  void build(LinearLayout into) {
    into.addView(
        text(
            "A home keeps your personal space, sealed so that its operators read nothing of it. "
                + "Your recovery kit restores it there if every device is lost."));
    into.addView(heading("The home"));
    HomeField home = new HomeField(into, code, text -> code = text);
    into.addView(heading("This phone's name"));
    EditText name = kept(field("Its name on your other devices", label, false), text -> label = text);
    into.addView(name);
    into.addView(heading("Your recovery kit"));
    KitChoice choice = new KitChoice(this, kit, kind -> kit = kind);
    into.addView(choice.group);
    into.addView(
        button(
            "Back up",
            v -> {
              Home at = home.home();
              if (at != null) {
                claim(at);
              }
            }));
  }

  private void claim(Home home) {
    ClaimRequest request = new ClaimRequest();
    request.home = home;
    request.kit = kit;
    request.label = label.trim();
    app.run(
        "Backing up at the home: about a minute…",
        (personal, prompts, refused) -> personal.claim(request, prompts, refused),
        (Claimed claimed) -> {
          app.home();
          app.say(
              "Backed up. This phone is device "
                  + claimed.device
                  + " of your personal space, at agent "
                  + claimed.agent
                  + ". Keep your kit and its card apart from this phone.");
        });
  }
}
