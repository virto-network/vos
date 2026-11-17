// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.vos.personal;

import android.os.Build;
import android.widget.LinearLayout;

/**
 * A move home: this phone leaves its home and backs up at another, with a new kit of the kind
 * chosen (its card names the new home); nothing is carried, and the other devices pair again with
 * this one after it.
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
            "This phone leaves your home and backs up at another, sealed as before: your devices "
                + "write their books there again, and nothing else is carried. Then pair each of "
                + "your other devices again with this phone."));
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
        (personal, prompts, refused) -> personal.moveHome(request, prompts, refused),
        (Claimed claimed) -> {
          app.home();
          app.say("Moved. On each of your other devices, pair again from this phone.");
        });
  }
}
