// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.vos.personal;

import android.widget.LinearLayout;

/**
 * The device set: each device's standing and last call, a phone retired (removed, then its
 * memberships revoked), the changes open (veto, cosign, a contest resolved), the memberships a
 * pairing left, the recovery kit's rotation, this phone's admin key replaced, a regroup, a commit
 * now, and this phone leaving the space. Each change is the admin key's, behind its strong
 * biometric. Read from the agent when shown and on each return to the app, never on a timer.
 */
final class DevicesScreen extends Screen {
  private Device[] devices;
  private Notice[] open;
  private Membership[] owed;
  private String unread;

  DevicesScreen(PersonalActivity app) {
    super(app);
  }

  @Override
  String title() {
    return "Devices, changes and keys";
  }

  @Override
  void shown() {
    reload();
  }

  @Override
  void started() {
    reload();
  }

  private void reload() {
    app.read(
        (personal, prompts, refused) -> {
          Device[] read = personal.devices(refused);
          if (read == null) {
            return null;
          }
          Notice[] operations = personal.operations(refused);
          Membership[] memberships = operations == null ? null : personal.memberships(refused);
          return memberships == null ? null : new Object[] {read, operations, memberships};
        },
        read -> {
          devices = (Device[]) read[0];
          open = (Notice[]) read[1];
          owed = (Membership[]) read[2];
          unread = null;
          redraw();
        },
        refused -> {
          unread = Words.why(refused);
          redraw();
        });
  }

  @Override
  void build(LinearLayout into) {
    into.addView(button("Read again", v -> reload()));
    if (unread != null) {
      into.addView(warning("Not read: " + unread));
    }
    if (devices == null) {
      into.addView(text(unread == null ? "Reading…" : ""));
      return;
    }
    devices(into);
    operations(into);
    memberships(into);
    keys(into);
  }

  private void devices(LinearLayout into) {
    into.addView(heading("Devices"));
    long now = System.currentTimeMillis();
    for (Device device : devices) {
      into.addView(
          text(
              device.label
                  + (device.me ? " (this phone)" : "")
                  + "\n"
                  + Words.standing(device.standing)
                  + (device.removed ? ", its removal matured" : "")
                  + ", admin key "
                  + (device.strong ? "strong" : "weak")
                  + ", last call at your agent "
                  + Words.ago(device.seen, now)));
      if (device.me) {
        // Left alone, no other device would commit it: a move or a regroup is the way.
        if (!device.removed && others() > 0) {
          if (device.standing == 0) {
            // On probation its admin key signs nothing, its own removal neither.
            into.addView(
                text(
                    "This phone can leave once its probation ends; until then another of your"
                        + " devices retires it."));
          } else {
            into.addView(button("Leave this personal space", v -> leave(device)));
          }
        }
        continue;
      }
      if (device.removed) {
        into.addView(button("Revoke it in your other spaces", v -> revoke(device)));
      } else {
        into.addView(button("Retire this device", v -> retire(device)));
      }
    }
    into.addView(
        button(
            "Regroup on this phone alone",
            v ->
                app.ask(
                    "Regroup",
                    "Every other device is removed and this phone starts a new group alone. Once"
                        + " it matures, tap Commit now here; then pair each other device again"
                        + " from this phone.",
                    "Regroup",
                    this::regroup)));
  }

  private void operations(LinearLayout into) {
    into.addView(heading("Changes open"));
    if (open.length == 0) {
      into.addView(text("None."));
    }
    long now = System.currentTimeMillis();
    for (Notice notice : open) {
      into.addView(text(Words.notice(notice) + Words.when(notice, now)));
      if (notice.contested && notice.kitOnly) {
        into.addView(
            text(
                "Too few of your devices can resolve this contest: only your recovery kit can."
                    + " Open the kit's screen, read the devices with the kit, then uphold or drop"
                    + " it there."));
        into.addView(
            button("Resolve it with the kit", v -> app.open(new RestoreScreen(app, true))));
      } else if (notice.contested && notice.cannotResolve) {
        into.addView(
            text(
                "This phone cannot resolve it (it is one of its targets, or not yet a seasoned"
                    + " strong device): your other devices do, or your recovery kit."));
      } else if (notice.contested) {
        into.addView(
            buttons(
                button("Uphold it", v -> posted("Upholding…", notice, true)),
                button("Drop it", v -> posted("Dropping…", notice, false))));
      } else {
        into.addView(
            buttons(
                button("Veto", v -> veto(notice)),
                button("Approve now", v -> cosign(notice))));
      }
    }
  }

  private void memberships(LinearLayout into) {
    if (owed.length == 0) {
      return;
    }
    into.addView(heading("Memberships to finish"));
    for (Membership membership : owed) {
      boolean enroll = membership.owed == Owed.ENROLL;
      into.addView(
          text(
              (enroll ? "Enroll your new device in space " : "Confirm this phone in space ")
                  + Words.shortHex(membership.space)));
      into.addView(
          buttons(
              button(
                  enroll ? "Enroll it" : "Confirm",
                  v ->
                      app.run(
                          enroll ? "Enrolling the device…" : "Confirming…",
                          (personal, prompts, refused) ->
                              (enroll
                                      ? personal.enrollDevice(membership, prompts, refused)
                                      : personal.confirmDevice(membership, prompts, refused))
                                  ? Boolean.TRUE
                                  : null,
                          done -> reload())),
              button(
                  "Give it up",
                  v ->
                      app.run(
                          "Giving it up…",
                          (personal, prompts, refused) ->
                              personal.dropEnrollment(membership, refused) ? Boolean.TRUE : null,
                          done -> reload()))));
    }
  }

  private void keys(LinearLayout into) {
    into.addView(heading("Recovery kit and admin key"));
    into.addView(
        text(
            "A new kit replaces yours once its delay passes, unless one of your devices vetoes "
                + "it. A new admin key for this phone is signed by your kit, or by another "
                + "seasoned device of yours."));
    into.addView(
        buttons(
            button("New kit: a phrase", v -> rotate(KitKind.PHRASE)),
            button("New kit: a security key", v -> rotate(KitKind.SECURITY_KEY))));
    into.addView(
        buttons(
            button("New admin key, by the phrase", v -> replaceAdmin(KitKind.PHRASE)),
            button("New admin key, by the key", v -> replaceAdmin(KitKind.SECURITY_KEY))));
    into.addView(
        buttons(
            button(
                "New admin key, by another device",
                v -> app.open(new AdminKeyScreen(app, true))),
            button(
                "Approve another device's admin key",
                v -> app.open(new AdminKeyScreen(app, false)))));
    into.addView(
        button(
            "Commit now",
            v ->
                app.run(
                    "Committing: removals carried, this phone's leaf updated…",
                    (personal, prompts, refused) ->
                        personal.update(prompts, refused) ? Boolean.TRUE : null,
                    done -> {
                      app.say("Committed.");
                      reload();
                    })));
  }

  // ----- the admin key's calls -----

  private void retire(Device device) {
    app.ask(
        "Retire " + device.label,
        "It is removed from your personal space once the removal's delay passes, unless it "
            + "vetoes. Then revoke it in your other spaces from here.",
        "Retire",
        () ->
            app.run(
                "Removing " + device.label + "…",
                (personal, prompts, refused) -> personal.remove(device.id, prompts, refused),
                this::taken));
  }

  /** The other devices of the set not removed. */
  private int others() {
    int others = 0;
    for (Device device : devices) {
      others += !device.me && !device.removed ? 1 : 0;
    }
    return others;
  }

  /** This phone's own removal, signed by its own admin key: the other devices commit it. */
  private void leave(Device device) {
    app.ask(
        "Leave this personal space",
        "This phone signs its own removal. Your other devices finish it: once the removal's"
            + " delay passes, one of them commits it (its notice asks), and from then on this"
            + " phone gets none of the space's new keys and reads none of its changes; pairing it"
            + " again or restoring clears what it kept. Until then"
            + " another device can still veto it.",
        "Leave",
        () ->
            app.run(
                "Signing this phone's removal…",
                (personal, prompts, refused) -> personal.remove(device.id, prompts, refused),
                (Posted posted) -> {
                  app.say(
                      "Your removal is open: your other devices commit it once its delay"
                          + " passes.");
                  reload();
                }));
  }

  private void revoke(Device device) {
    app.run(
        "Revoking " + device.label + " in your other spaces…",
        (personal, prompts, refused) -> {
          int revoked = personal.revoke(device.id, prompts, refused);
          return refused.why == Why.NONE ? revoked : null;
        },
        (Integer revoked) -> app.say("Revoked in " + revoked + " space(s)."));
  }

  private void veto(Notice notice) {
    app.run(
        "Vetoing…",
        (personal, prompts, refused) -> personal.veto(notice.index, prompts, refused),
        this::taken);
  }

  private void cosign(Notice notice) {
    app.run(
        "Approving…",
        (personal, prompts, refused) -> personal.cosign(notice.index, prompts, refused),
        this::taken);
  }

  private void posted(String doing, Notice notice, boolean upheld) {
    app.run(
        doing,
        (personal, prompts, refused) -> personal.resolve(notice.index, upheld, prompts, refused),
        this::taken);
  }

  private void rotate(byte kit) {
    app.run(
        "Making your new kit…",
        (personal, prompts, refused) -> personal.rotateKit(kit, prompts, refused),
        this::taken);
  }

  private void replaceAdmin(byte kit) {
    app.run(
        "Replacing this phone's admin key…",
        (personal, prompts, refused) -> personal.replaceAdmin(kit, prompts, refused),
        this::taken);
  }

  private void regroup() {
    app.run(
        "Regrouping…",
        (personal, prompts, refused) -> personal.regroup(prompts, refused),
        this::taken);
  }

  private void taken(Posted posted) {
    app.say("Done: your personal agent took it (log entry " + posted.index + ").");
    reload();
  }
}
