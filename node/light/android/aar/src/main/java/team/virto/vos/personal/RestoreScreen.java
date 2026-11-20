// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.vos.personal;

import android.os.Build;
import android.widget.LinearLayout;

/**
 * A restore from the recovery kit, in two steps: opened at the home the kit's card names (a new
 * kit made for it), it matures after the kit's delay unless a device of the set answers; then
 * finished with the same kit entered again, the personal space read back. A lost phone left on
 * answers every restore: the kit reads the device set, removes that phone (it matures after the
 * kit's delay, and its background sync cannot veto it) and resolves a contest, from this install.
 */
final class RestoreScreen extends Screen {
  private String code = "";
  private String label = Words.label(Build.MODEL);
  private byte old = KitKind.PHRASE;
  private byte next = KitKind.PHRASE;
  private KitView view;

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
    into.addView(heading("A lost phone answers the restore"));
    into.addView(
        text(
            "A lost phone left on answers every restore by itself. Read your devices with the kit "
                + "(chosen above), remove that phone with the kit, and open the restore again once "
                + "its removal matured."));
    into.addView(
        button(
            "Read the devices with the kit",
            v -> {
              Home at = home.home();
              if (at != null) {
                read(at);
              }
            }));
    if (view == null) {
      return;
    }
    for (Device device : view.devices) {
      into.addView(
          text(
              device.label
                  + ": "
                  + Words.standing(device.standing)
                  // Its standing says it when it is removed.
                  + (device.removed && device.standing != Words.REMOVED
                      ? ", its removal matured"
                      : "")));
      if (!device.removed) {
        into.addView(
            button(
                "Remove " + device.label + " with the kit",
                v -> {
                  Home at = home.home();
                  if (at != null) {
                    remove(at, device);
                  }
                }));
      }
    }
    for (Notice notice : view.operations) {
      into.addView(text(Words.notice(notice)));
      if (notice.contested) {
        into.addView(
            buttons(
                button("Uphold it with the kit", v -> resolve(home.home(), notice.index, true)),
                button("Drop it with the kit", v -> resolve(home.home(), notice.index, false))));
      }
    }
  }

  private void read(Home home) {
    byte kit = old;
    app.run(
        "Reading your devices with the kit…",
        (personal, prompts, refused) -> personal.kitView(home, kit, prompts, refused),
        (KitView read) -> {
          view = read;
          redraw();
        });
  }

  private void remove(Home home, Device device) {
    byte kit = old;
    app.run(
        "Removing " + device.label + " with the kit…",
        (personal, prompts, refused) -> personal.removeByKit(home, kit, device.id, prompts, refused),
        (Posted posted) ->
            app.say(
                device.label
                    + "'s removal is open (log entry "
                    + posted.index
                    + "). It matures after your kit's delay; then open the restore again."));
  }

  private void resolve(Home home, long index, boolean upheld) {
    if (home == null) {
      return;
    }
    byte kit = old;
    app.run(
        "Resolving the contest with the kit…",
        (personal, prompts, refused) ->
            personal.resolveByKit(home, kit, index, upheld, prompts, refused),
        (Posted posted) -> app.say("Resolved (log entry " + posted.index + ")."));
  }

  private void open(Home home) {
    ClaimRequest request = new ClaimRequest();
    request.home = home;
    request.kit = next;
    request.label = label.trim();
    byte kit = old;
    app.run(
        "Opening the restore at the home…",
        (personal, prompts, refused) -> personal.restore(request, kit, prompts, refused),
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
        (personal, prompts, refused) -> personal.restored(kit, prompts, refused),
        (Claimed claimed) -> {
          app.home();
          app.say("Restored. This phone is device " + claimed.device + " of your personal space.");
        });
  }
}
