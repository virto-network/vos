// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.vos.personal;

import android.os.Build;
import android.widget.LinearLayout;

/**
 * A restore from the recovery kit, laid out as its steps, only the next one's button shown: the
 * home and the kit (both kept once this phone knows them: a restore under way, or the device set
 * it holds), the restore opened (a new kit made for it), the kit's delay waited out unless a device
 * of the set answers, then the restore finished. A lost phone left on answers every restore: the
 * kit reads the device set, removes that phone (it matures after the kit's delay, and its
 * background sync cannot veto it) and resolves a contest, from this install. The kit is entered
 * once for the screen's life: {@code :vos} holds it between its flows (at most ten minutes, wiped
 * when the screen closes or the app goes to the background).
 */
final class RestoreScreen extends Screen {
  /** Whether it opened on the kit's reading of the devices (a contest only the kit resolves). */
  private final boolean byKit;

  private PersonalStatus status;
  private String code = "";
  private String label = Words.label(Build.MODEL);
  private byte old = KitKind.PHRASE;
  private byte next = KitKind.PHRASE;
  /** Whether the user asked to remove a lost phone first. */
  private boolean lost;
  private KitView view;
  /** The home's code field, while this phone knows no home. */
  private HomeField homeField;
  /** The screen drawn again once the restore's delay passed, so its finish is offered then. */
  private final Runnable matured = this::redraw;
  /** The view the redraw is posted on. */
  private LinearLayout drawn;

  RestoreScreen(PersonalActivity app) {
    this(app, false);
  }

  RestoreScreen(PersonalActivity app, boolean byKit) {
    super(app);
    this.byKit = byKit;
    this.lost = byKit;
  }

  @Override
  String title() {
    return byKit ? "Your recovery kit" : "Restore from a recovery kit";
  }

  @Override
  void shown() {
    app.holdKit();
    app.read(
        (personal, prompts, refused) -> personal.status(refused),
        read -> {
          status = read;
          if (read.kitKnown) {
            old = read.kit;
          }
          redraw();
        },
        refused -> redraw());
  }

  @Override
  void started() {
    // Back from the background, the sitting is opened anew: the kit is entered again.
    app.holdKit();
  }

  @Override
  void closed() {
    unschedule();
    app.forgetKit();
  }

  @Override
  void left() {
    unschedule();
  }

  @Override
  void resumed() {
    // Back on the screen, it is drawn as the time is now.
    redraw();
  }

  private void unschedule() {
    if (drawn != null) {
      drawn.removeCallbacks(matured);
    }
  }

  /** The home this phone knows: its restore's, or its personal space's; null when none. */
  private Home known() {
    if (status == null || status.home == null || status.home.onions == null) {
      return null;
    }
    return status.home.onions.length == 0 ? null : status.home;
  }

  private boolean restoring() {
    return status != null && status.phase == Phase.RESTORING;
  }

  @Override
  void build(LinearLayout into) {
    if (status == null) {
      into.addView(text("Reading…"));
      return;
    }
    into.addView(
        text(
            byKit
                ? "Your kit reads your devices and resolves what they cannot: enter it once here."
                : "Every device lost: your kit restores your personal space at its home. The "
                    + "restore waits for the kit's delay, so a device of yours can still stop one "
                    + "it did not ask for."));
    Home home = homeStep(into);
    if (lost) {
      devicesStep(into, home);
      return;
    }
    if (!restoring()) {
      into.addView(heading("2. Open the restore"));
      into.addView(
          status.delayed
              ? warning(
                  "This phone's admin key is not kept in hardware: restored here, your personal"
                      + " space can pair no new device from it. To pair your other devices, "
                      + "restore on a phone whose admin key is kept in hardware.")
              : text(
                  "Restore on a phone that keeps its admin key in hardware (an Ed25519 key in "
                      + "its secure hardware, Android 13 or later): one that does not pairs no "
                      + "new device, and with no other device left none could."));
      into.addView(
          text(
              "Opening the restore makes a new recovery kit for the restored space: its words are"
                  + " shown once, and two of them asked back. It replaces your old kit once this"
                  + " phone shows \"Restored\"."));
      into.addView(text("This phone's name"));
      into.addView(kept(field("Its name on your other devices", label, false), t -> label = t));
      into.addView(text("Your new kit, made for the restored space"));
      into.addView(new KitChoice(this, next, kind -> next = kind).group);
      into.addView(
          button(
              "Open the restore",
              v -> {
                Home at = home != null ? home : homeField.home();
                if (at != null) {
                  open(at);
                }
              }));
      into.addView(
          text("A lost phone of yours left on answers every restore: remove it with the kit first."));
      into.addView(
          button(
              "Remove a lost phone first",
              v -> {
                lost = true;
                redraw();
              }));
      return;
    }
    into.addView(heading("2. Opened ✓"));
    if (status.delayed) {
      into.addView(
          warning(
              "This phone's admin key is not kept in hardware: once restored, it pairs no new "
                  + "device. To pair your other devices, restore on a phone whose key is."));
    }
    into.addView(
        text(
            "Keep your old kit until this phone shows \"Restored\": the new one restores nothing "
                + "before then, nor if the restore is cancelled."));
    into.addView(
        text(
            "If opening it was cut short, or a device of yours answered that it is alive, open it "
                + "again: the kit resumes it, or opens a new one."));
    into.addView(
        buttons(
            button(
                "Open the restore again",
                v -> {
                  Home at = home != null ? home : homeField == null ? null : homeField.home();
                  if (at != null) {
                    open(at);
                  }
                }),
            button(
                "Remove a lost phone first",
                v -> {
                  lost = true;
                  redraw();
                })));
    long now = System.currentTimeMillis();
    boolean ripe = status.matures > 0 && status.matures <= now;
    into.addView(heading("3. Wait for the kit's delay" + (ripe ? " ✓" : "")));
    unschedule();
    if (!ripe) {
      into.addView(
          text(
              status.matures > 0
                  ? "It takes effect " + Words.when(status.matures, now) + ", unless one of "
                      + "your devices answers that it is alive: then this screen offers to "
                      + "finish it. Should a device stop it, finishing says so."
                  : "The home has not shown its delay yet: try finishing it; if it is too early, "
                      + "the home says so."));
      if (status.matures > 0) {
        drawn = into;
        into.postDelayed(matured, status.matures - now + 1_000);
      }
    }
    into.addView(heading("4. Finish it"));
    if (ripe || status.matures == 0) {
      into.addView(button("Finish the restore", v -> finish()));
    }
  }

  /** The first step: the home and the kit, shown as kept when this phone knows them. */
  private Home homeStep(LinearLayout into) {
    Home home = known();
    into.addView(heading("1. Your home and your kit"));
    if (home != null) {
      into.addView(text("Home " + Words.shortHex(home.handle) + ": check it against your card."));
    } else {
      into.addView(text("The home your kit's card names: check its handle against the card."));
      homeField = new HomeField(into, code, text -> code = text);
    }
    // The kit a restore under way was opened with is the one its finish takes; any other kit's
    // kind is offered again, defaulted to the one this phone last knew.
    if (status.kitKnown && restoring()) {
      into.addView(
          text(
              "Your kit: "
                  + (old == KitKind.SECURITY_KEY ? "your security key" : "your recovery phrase")));
    } else {
      into.addView(text("The kit you have"));
      into.addView(new KitChoice(this, old, kind -> old = kind).group);
    }
    return home;
  }

  /** The kit's reading of the devices, and its removal of a lost phone or resolution of a contest. */
  private void devicesStep(LinearLayout into, Home known) {
    into.addView(heading("2. Your devices, read with the kit"));
    if (view == null) {
      into.addView(
          button(
              "Read the devices with the kit",
              v -> {
                Home at = home(known);
                if (at != null) {
                  read(at);
                }
              }));
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
                  Home at = home(known);
                  if (at != null) {
                    app.ask(
                        "Remove " + device.label,
                        "Your kit signs its removal: it matures after your kit's delay unless "
                            + device.label
                            + " vetoes it.",
                        "Remove",
                        () -> remove(at, device));
                  }
                }));
      }
    }
    for (Notice notice : view.operations) {
      into.addView(
          text(
              Words.notice(notice, view.devices)
                  + Words.when(notice, System.currentTimeMillis())));
      if (notice.contested) {
        into.addView(
            buttons(
                button("Uphold it with the kit", v -> resolving(home(known), notice, true)),
                button("Drop it with the kit", v -> resolving(home(known), notice, false))));
      }
    }
    if (!byKit) {
      into.addView(
          text("Once the lost phone's removal matured (the kit's delay), open the restore."));
      into.addView(
          button(
              "Back to the restore",
              v -> {
                lost = false;
                redraw();
              }));
    }
  }

  private Home home(Home known) {
    return known != null ? known : homeField == null ? null : homeField.home();
  }

  /** A refusal said, a kit no space at the home holds with the home's handle to check. */
  private void refused(Home home, Refused refused) {
    if (refused.why == Why.NO_AGENT_FOR_KIT && home != null) {
      app.say("Not done: " + Words.noAgentForKit(home.handle) + ".");
      return;
    }
    app.refused(refused);
  }

  private void read(Home home) {
    byte kit = old;
    app.run(
        "Reading your devices with the kit…",
        (personal, prompts, refused) -> personal.kitView(home, kit, prompts, refused),
        (KitView read) -> {
          view = read;
          redraw();
        },
        null,
        true,
        refused -> refused(home, refused));
  }

  private void remove(Home home, Device device) {
    byte kit = old;
    app.run(
        "Removing " + device.label + " with the kit…",
        (personal, prompts, refused) -> personal.removeByKit(home, kit, device.id, prompts, refused),
        (Posted posted) -> {
          app.say(
              device.label
                  + "'s removal is open. It matures after your kit's delay; then open the "
                  + "restore.");
          read(home);
        },
        null,
        true,
        refused -> refused(home, refused));
  }

  /** A contest resolved by the kit, at once, once the user confirms it. */
  private void resolving(Home home, Notice notice, boolean upheld) {
    app.ask(
        upheld ? "Uphold it" : "Drop it",
        Words.notice(notice)
            + ": your kit signs that it is "
            + (upheld ? "upheld" : "dropped")
            + ", which takes effect at once.",
        upheld ? "Uphold" : "Drop",
        () -> resolve(home, notice.index, upheld));
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
        (Posted posted) -> {
          app.say("Resolved.");
          read(home);
        },
        null,
        true,
        refused -> refused(home, refused));
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
        (Posted posted) -> {
          app.say(
              "The restore is open. It matures after your kit's delay unless one of your "
                  + "devices answers that it is alive; then finish it here.");
          shown();
        },
        null,
        true,
        refused -> {
          refused(home, refused);
          shown();
        });
  }

  private void finish() {
    byte kit = old;
    Home home = known();
    app.run(
        "Reading your personal space back over Tor (several seconds), then your biometric is"
            + " asked…",
        (personal, prompts, refused) -> personal.restored(kit, prompts, refused),
        (Claimed claimed) -> {
          app.home();
          app.say("Restored. This phone is device " + claimed.device + " of your personal space.");
        },
        null,
        true,
        refused -> {
          refused(home, refused);
          shown();
        });
  }
}
