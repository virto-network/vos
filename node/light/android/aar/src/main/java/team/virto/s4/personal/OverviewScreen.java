// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.s4.personal;

import android.widget.LinearLayout;
import team.virto.s4.vos.Device;
import team.virto.s4.vos.ErrorCode;
import team.virto.s4.vos.Notice;
import team.virto.s4.vos.Refusal;
import team.virto.s4.vos.Synced;

/**
 * The personal space at a glance: without one, the ways to get one (back this phone up, join from
 * another device, restore from the kit); with one, its devices, what waits for the user, Tor's
 * state ("backup paused" on a network that blocks it), and every flow.
 */
final class OverviewScreen extends Screen {
  /** Whether the device holds a personal space: unknown until read. */
  private Boolean holds;
  private Device[] devices;
  private Notice[] open;
  private Notice[] raised;
  private String unread;
  /** Tor's bootstrap refused, and why: backup paused. */
  private String paused;
  private boolean torRead;
  /** A read of Tor's state under way. */
  private boolean torReading;

  OverviewScreen(PersonalActivity app) {
    super(app);
  }

  @Override
  String title() {
    return "Personal space";
  }

  @Override
  void shown() {
    // The device set's operations open are read on the device: whether it holds a space.
    app.read(
        (node, prompts, refused) -> node.operations(refused),
        operations -> {
          holds = true;
          open = operations;
          redraw();
          readDevices();
        },
        refused -> {
          holds = refused.code == ErrorCode.NOT_ENROLLED ? false : null;
          unread = holds == null ? Words.refusal(refused.code, refused.message) : null;
          redraw();
        });
    if (!torRead) {
      readTor();
    }
  }

  private void readDevices() {
    app.read(
        (node, prompts, refused) -> node.devices(refused),
        read -> {
          devices = read;
          unread = null;
          redraw();
        },
        refused -> {
          unread = Words.refusal(refused.code, refused.message);
          redraw();
        });
  }

  /** Tor's state, on its own thread: a bootstrap waits for the network. */
  private void readTor() {
    if (torReading) {
      return;
    }
    torReading = true;
    new Thread(
            () -> {
              Refusal refused = new Refusal();
              boolean up;
              try {
                up = team.virto.s4.VosClient.get(app).node().bootstrap(refused);
              } catch (android.os.RemoteException | RuntimeException gone) {
                up = false;
                refused.message = "the facility stopped";
              }
              boolean working = up;
              app.runOnUiThread(
                  () -> {
                    torRead = true;
                    torReading = false;
                    paused = working ? null : Words.refusal(refused.code, refused.message);
                    redraw();
                  });
            },
            "vos.tor")
        .start();
  }

  @Override
  void build(LinearLayout into) {
    if (!torRead) {
      into.addView(text("Tor: starting…"));
    } else if (paused != null) {
      into.addView(warning("Backup paused: " + paused));
      into.addView(
          text(
              "Your devices do not sync while Tor cannot connect. On a network that blocks Tor, "
                  + "add bridges."));
    } else {
      into.addView(text("Tor: connected."));
    }
    into.addView(button("Tor and bridges", v -> app.open(new NetworkScreen(app))));
    if (holds == null) {
      into.addView(text(unread == null ? "Reading…" : "Not read: " + unread));
      into.addView(button("Try again", v -> shown()));
      return;
    }
    if (!holds) {
      none(into);
      return;
    }
    into.addView(heading("Your devices"));
    if (devices == null) {
      into.addView(text(unread == null ? "Reading your devices…" : "Not read: " + unread));
    } else {
      long now = System.currentTimeMillis();
      for (Device device : devices) {
        into.addView(
            text(
                device.label
                    + (device.me ? " (this phone)" : "")
                    + ": "
                    + Words.standing(device.standing)
                    + ", last sync "
                    + Words.ago(device.seen, now)));
      }
    }
    if (open != null && open.length > 0) {
      into.addView(warning(open.length + " change(s) to your devices wait for you."));
    }
    if (raised != null) {
      for (Notice notice : raised) {
        into.addView(
            warning(
                Words.pending(notice.pending)
                    + (notice.detail.isEmpty() ? "" : " (" + notice.detail + ")")));
      }
    }
    into.addView(button("Devices, changes and keys", v -> app.open(new DevicesScreen(app))));
    into.addView(button("Pair a new device", v -> app.open(new PairScreen(app, true))));
    into.addView(button("Sync now", v -> sync()));
    into.addView(button("Yearly re-proof", v -> renew()));
    into.addView(button("Move home", v -> app.open(new MoveScreen(app))));
    into.addView(
        button(
            "Pair again after a move (scan the moved device's code)",
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

  private void sync() {
    app.run(
        "Syncing your personal space…",
        (node, prompts, refused) -> node.syncPersonal(refused),
        (Synced synced) -> {
          raised = synced.notices;
          shown();
          if (synced.failed > 0) {
            app.say("The sync did not finish: " + synced.failed + " failed. It runs again later.");
          }
        });
  }

  private void renew() {
    app.run(
        "Re-proving at your home…",
        (node, prompts, refused) -> node.renew(prompts, refused) ? Boolean.TRUE : null,
        done -> app.say("Re-proved at your home for another year, this phone's leaf updated."));
  }
}
