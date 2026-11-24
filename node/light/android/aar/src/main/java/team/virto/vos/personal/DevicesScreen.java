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
    String[] names = Words.names(devices);
    for (int at = 0; at < devices.length; at++) {
      Device device = devices[at];
      into.addView(
          text(
              names[at]
                  + (device.me ? " (this phone)" : "")
                  + "\n"
                  + Words.standing(device.standing)
                  + (device.removed ? ", its removal matured" : removal(device, now))
                  + ", admin key "
                  + (device.strong ? "strong" : "weak")
                  + ", last call at your agent "
                  + Words.ago(device.seen, now)));
      if (device.me) {
        // Alone, no other device would commit it: a restore with the kit replaces it instead.
        if (!device.removed && others() > 0) {
          into.addView(button("Leave this personal space", v -> leave()));
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

  /** An open removal of {@code device}, as its row says it; empty when none. */
  private String removal(Device device, long now) {
    for (Notice notice : open) {
      if (notice.pending == Pending.REMOVE && notice.targeted && notice.target == device.id) {
        return Words.tookEffect(notice, now)
            ? ", removed: out once a commit carries it"
            : ", being removed: it takes effect " + Words.when(notice.matures, now);
      }
    }
    return "";
  }

  private void operations(LinearLayout into) {
    into.addView(heading("Changes open"));
    if (open.length == 0) {
      into.addView(text("None."));
    }
    long now = System.currentTimeMillis();
    for (Notice notice : open) {
      into.addView(text(Words.notice(notice, devices) + Words.when(notice, now)));
      if (Words.tookEffect(notice, now)) {
        // Nothing vetoes or approves it now: only the commit is left, offered below.
        continue;
      }
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
      String space = Words.space(membership);
      if (!enroll && !membership.enrolled) {
        // Confirmed by this phone's own enrollment there, which it does not hold yet.
        into.addView(
            text(
                "Confirm this phone in "
                    + space
                    + ": enroll this phone in that space first (from its gateway, as you"
                    + " enrolled your other device), then confirm it here."));
        into.addView(button("Give it up", v -> giveUp(membership)));
        continue;
      }
      into.addView(
          text((enroll ? "Enroll your new device in " : "Confirm this phone in ") + space));
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
              button("Give it up", v -> giveUp(membership))));
    }
  }

  private void giveUp(Membership membership) {
    app.run(
        "Giving it up…",
        (personal, prompts, refused) ->
            personal.dropEnrollment(membership, refused) ? Boolean.TRUE : null,
        done -> reload());
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
      // A device whose add is undecided is no other live one: void, it leaves the set.
      others += !device.me && !device.removed && !device.adding ? 1 : 0;
    }
    return others;
  }

  /** This phone's own removal, signed by its admin key: the other devices commit it. */
  private void leave() {
    app.ask(
        "Leave this personal space",
        "This phone removes itself from your personal space now. Your other devices finish it:"
            + " the next one you open asks you to commit it. This phone keeps nothing of the"
            + " space: its copy of your data, its keys to it and its recovery state are cleared,"
            + " and its admin key signs nothing your agent takes. Committing it also ends this"
            + " phone's memberships in every other space: its sign-ins there stop working. To come"
            + " back, pair it again from another of your devices.",
        "Leave",
        () ->
            app.run(
                "Signing this phone's removal…",
                (personal, prompts, refused) ->
                    personal.leave(prompts, refused) ? Boolean.TRUE : null,
                done -> app.left()));
  }

  private void revoke(Device device) {
    app.run(
        "Revoking " + device.label + " in your other spaces…",
        (personal, prompts, refused) -> {
          int revoked = personal.revoke(device.id, prompts, refused);
          return refused.why == Why.NONE ? revoked : null;
        },
        (Integer revoked) ->
            app.say(
                revoked == 0
                    ? device.label + " is in no other space your personal space records: nothing to"
                        + " revoke."
                    : "Revoked in " + revoked + " space(s)."));
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
