// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.vos.personal;

import android.widget.LinearLayout;

/**
 * The personal space at a glance, from its status: without one, the ways to get one (back this
 * phone up, join from another device, restore from the kit); a flow under way, the way to finish
 * it; with one, its devices, what waits for the user, Tor's state ("backup paused" on a network
 * that blocks it), why the last sync did not finish, and every flow; removed from it, the two ways
 * back in. Read again on each return to the app and after each background pass.
 */
final class OverviewScreen extends Screen {
  /** The personal space's status: unknown until read. */
  private PersonalStatus status;
  private Device[] devices;
  private String unread;

  OverviewScreen(PersonalActivity app) {
    super(app);
  }

  @Override
  String title() {
    return "Personal space";
  }

  @Override
  void shown() {
    reload();
  }

  @Override
  void started() {
    reload();
  }

  @Override
  void passed() {
    reload();
  }

  private void reload() {
    app.read(
        (personal, prompts, refused) -> personal.status(refused),
        read -> {
          status = read;
          unread = null;
          redraw();
          if (holds()) {
            readDevices();
          }
        },
        refused -> {
          status = null;
          unread = Words.why(refused);
          redraw();
        });
  }

  /**
   * Whether the phone holds a group its devices are listed from: not while it joins, its sync key
   * not yet admitted.
   */
  private boolean holds() {
    return status != null
        && (status.phase == Phase.HELD
            || status.phase == Phase.REMOVED
            || status.phase == Phase.STUCK);
  }

  private void readDevices() {
    app.read(
        (personal, prompts, refused) -> personal.devices(refused),
        read -> {
          devices = read;
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
    if (status == null) {
      into.addView(text(unread == null ? "Reading…" : "Not read: " + unread));
      into.addView(button("Try again", v -> reload()));
      return;
    }
    if (status.tor == Tor.BLOCKED) {
      into.addView(warning("Backup paused: " + Words.tor(status.tor, status.torWhy)));
      into.addView(
          text(
              "Your devices do not sync while Tor cannot connect. On a network that blocks Tor, "
                  + "add bridges."));
    } else {
      into.addView(text(Words.tor(status.tor, status.torWhy) + "."));
    }
    into.addView(button("Tor and bridges", v -> app.open(new NetworkScreen(app))));
    if (status.failed != null && !status.failed.isEmpty()) {
      into.addView(warning(Words.failed(status.failed)));
    }
    long now = System.currentTimeMillis();
    switch (status.phase) {
      case Phase.NONE:
        none(into);
        return;
      case Phase.NEEDS_REPAIR:
        into.addView(warning(Words.phase(status.phase)));
        if (status.repair != null && !status.repair.isEmpty()) {
          into.addView(text(status.repair));
        }
        return;
      case Phase.CLAIMING:
        into.addView(warning(Words.phase(status.phase)));
        into.addView(button("Finish the claim", v -> app.open(new ClaimScreen(app))));
        return;
      case Phase.RESTORING:
        into.addView(
            warning(
                Words.phase(status.phase)
                    + (status.matures > 0
                        ? ": it takes effect " + Words.until(status.matures, now)
                        : "")
                    + "."));
        into.addView(button("Finish the restore", v -> app.open(new RestoreScreen(app))));
        return;
      case Phase.REMOVED:
        into.addView(warning(Words.phase(status.phase)));
        into.addView(
            text(
                "Pair it again from another of your devices, or, with none left, restore your "
                    + "personal space with your recovery kit."));
        into.addView(button("Pair again", v -> app.open(new PairScreen(app, false))));
        into.addView(button("Restore with your kit", v -> app.open(new RestoreScreen(app))));
        return;
      case Phase.STUCK:
        into.addView(warning(Words.phase(status.phase)));
        into.addView(
            button("Pair this phone again", v -> app.open(new PairScreen(app, false))));
        break;
      case Phase.JOINING:
        into.addView(text(Words.phase(status.phase)));
        into.addView(button("Sync now", v -> sync()));
        return;
      default:
        break;
    }
    into.addView(heading("Your devices"));
    if (devices == null) {
      into.addView(text(unread == null ? "Reading your devices…" : "Not read: " + unread));
    } else {
      for (Device device : devices) {
        into.addView(
            text(
                device.label
                    + (device.me ? " (this phone)" : "")
                    + ": "
                    + Words.standing(device.standing)
                    + ", last call at your agent "
                    + Words.ago(device.seen, now)));
      }
    }
    if (status.owed > 0) {
      into.addView(warning(status.owed + " membership(s) of your other spaces wait for you."));
    }
    boolean owed = false;
    boolean removals = false;
    for (Notice notice : status.standing) {
      into.addView(warning(Words.notice(notice)));
      owed |= notice.pending == Pending.COMMIT || notice.pending == Pending.RESEAL;
      removals |= notice.pending == Pending.COMMIT;
    }
    if (owed) {
      boolean revoking = removals;
      into.addView(
          button(
              revoking ? "Commit now, and revoke it in your other spaces" : "Commit now",
              v -> commit(revoking)));
    }
    into.addView(button("Devices, changes and keys", v -> app.open(new DevicesScreen(app))));
    into.addView(button("Pair a new device", v -> app.open(new PairScreen(app, true))));
    into.addView(button("Sync now", v -> sync()));
    into.addView(button("Move home", v -> app.open(new MoveScreen(app))));
    into.addView(
        button(
            "Pair again after a move or a regroup (scan the code of a device there)",
            v -> app.open(new PairScreen(app, false))));
  }

  private void none(LinearLayout into) {
    into.addView(
        text(
            "This phone holds no personal space. Back it up at a home, join the personal space "
                + "of another of your devices, or restore it from your recovery kit."));
    into.addView(button("Back up this phone", v -> app.open(new ClaimScreen(app))));
    into.addView(
        button("Join from another device", v -> app.open(new PairScreen(app, false))));
    into.addView(button("Restore from a recovery kit", v -> app.open(new RestoreScreen(app))));
  }

  /**
   * The commit a notice asks for, behind the biometric; for a matured removal, the device it
   * carries out revoked in your other spaces in the same flow, one prompt a signature.
   */
  private void commit(boolean revoking) {
    if (!revoking) {
      app.run(
          "Committing: the kit sealed again…",
          (personal, prompts, refused) -> personal.update(prompts, refused) ? Boolean.TRUE : null,
          done -> {
            app.say("Committed.");
            reload();
          });
      return;
    }
    app.run(
        "Committing, then revoking the removed device in your other spaces…",
        (personal, prompts, refused) -> {
          int revoked = personal.commitRemovals(prompts, refused);
          return refused.why == Why.NONE ? revoked : null;
        },
        (Integer revoked) -> {
          app.say(
              "Committed"
                  + (revoked > 0 ? ", and revoked in " + revoked + " other space(s)." : "."));
          reload();
        },
        null,
        true,
        refused -> {
          reload();
          if (refused.why != Why.DECLINED && refused.why != Why.CANCELLED) {
            app.ask(
                "Not done",
                Words.why(refused)
                    + ". A commit already made stays; a revoke left is done from Devices.",
                "Open Devices",
                () -> app.open(new DevicesScreen(app)));
          }
        });
  }

  /** One pass now; what it found (and why it did not finish) read back as the status. */
  private void sync() {
    app.run(
        "Syncing your personal space…",
        PersonalActivity.own((personal, refused) -> personal.syncPersonal(refused)),
        (Synced synced) -> reload());
  }
}
