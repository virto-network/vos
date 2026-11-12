// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.s4.personal;

import android.os.Build;
import android.widget.LinearLayout;
import team.virto.s4.vos.ClaimRequest;
import team.virto.s4.vos.Home;
import team.virto.s4.vos.KitKind;
import team.virto.s4.vos.Moved;

/**
 * A move home: the personal space carried to another home, with a new kit of the kind chosen
 * (its card names the new home); the other devices pair again with this one after it.
 */
final class MoveScreen extends Screen {
  private String code = "";
  private byte kit = KitKind.PHRASE;

  MoveScreen(PersonalActivity app) {
    super(app);
  }

  @Override
  String title() {
    return "Move home";
  }

  @Override
  void build(LinearLayout into) {
    into.addView(
        text(
            "Your personal space moves to another home, sealed as before. Your old home keeps a "
                + "signed notice for your other devices, which then pair again with this phone."));
    into.addView(heading("The new home"));
    HomeField home = new HomeField(into, code, text -> code = text);
    into.addView(heading("The new home's recovery kit"));
    into.addView(new KitChoice(this, kit, kind -> kit = kind).group);
    into.addView(
        button(
            "Move",
            v -> {
              Home at = home.home();
              if (at != null) {
                app.ask(
                    "Move home",
                    "Your personal space moves to home " + Words.shortHex(at.handle) + ".",
                    "Move",
                    () -> move(at));
              }
            }));
  }

  private void move(Home home) {
    ClaimRequest request = new ClaimRequest();
    request.home = home;
    request.kit = kit;
    // The device keeps the name it has; the request's is only checked.
    request.label = Words.label(Build.MODEL);
    app.run(
        "Moving your personal space: the open claim's work takes about a minute…",
        (node, prompts, refused) -> node.moveHome(request, prompts, refused),
        (Moved moved) -> {
          app.home();
          app.say(
              "Moved: "
                  + moved.carried
                  + " sealed envelope(s) carried to the new home. On each of your other devices, "
                  + "pair again from this phone.");
        });
  }
}
