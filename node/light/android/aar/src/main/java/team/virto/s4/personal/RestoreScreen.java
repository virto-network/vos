// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.s4.personal;

import android.os.Build;
import android.widget.LinearLayout;
import team.virto.s4.vos.ClaimRequest;
import team.virto.s4.vos.Claimed;
import team.virto.s4.vos.Home;
import team.virto.s4.vos.KitKind;
import team.virto.s4.vos.Posted;

/**
 * A restore from the recovery kit, in two steps: opened at the home the kit's card names (a new
 * kit made for it), it matures after the kit's delay unless a device of the set answers; then
 * finished with the same kit entered again, the personal space read back.
 */
final class RestoreScreen extends Screen {
  private String code = "";
  private String label = Words.label(Build.MODEL);
  private byte old = KitKind.PHRASE;
  private byte next = KitKind.PHRASE;

  RestoreScreen(PersonalActivity app) {
    super(app);
  }

  @Override
  String title() {
    return "Restore from a recovery kit";
  }

  @Override
  void build(LinearLayout into) {
    into.addView(
        text(
            "Every device lost: your kit restores your personal space at its home. The restore "
                + "waits for the kit's delay, so a device of yours can still stop one it did not "
                + "ask for; then finish it here."));
    into.addView(heading("1. Open the restore"));
    into.addView(text("The home your kit's card names: check its handle against the card."));
    HomeField home = new HomeField(into, code, text -> code = text);
    into.addView(text("This phone's name"));
    into.addView(kept(field("Its name on your other devices", label, false), t -> label = t));
    into.addView(text("The kit you have"));
    into.addView(new KitChoice(this, old, kind -> old = kind).group);
    into.addView(text("Your new kit, made for the restored space"));
    into.addView(new KitChoice(this, next, kind -> next = kind).group);
    into.addView(
        button(
            "Open the restore",
            v -> {
              Home at = home.home();
              if (at != null) {
                open(at);
              }
            }));
    into.addView(heading("2. Finish it"));
    into.addView(
        text("Once the delay passed: enter the kit you opened it with again (chosen above)."));
    into.addView(button("Finish the restore", v -> finish()));
  }

  private void open(Home home) {
    ClaimRequest request = new ClaimRequest();
    request.home = home;
    request.kit = next;
    request.label = label.trim();
    byte kit = old;
    app.run(
        "Opening the restore at the home…",
        (node, prompts, refused) -> node.restore(request, kit, prompts, refused),
        (Posted posted) ->
            app.say(
                "The restore is open (log entry "
                    + posted.index
                    + "). It matures after your kit's delay unless one of your devices answers "
                    + "that it is alive. Then finish it here with the same kit."));
  }

  private void finish() {
    byte kit = old;
    app.run(
        "Reading your personal space back…",
        (node, prompts, refused) -> node.restored(kit, prompts, refused),
        (Claimed claimed) -> {
          app.home();
          app.say("Restored. This phone is device " + claimed.device + " of your personal space.");
        });
  }
}
