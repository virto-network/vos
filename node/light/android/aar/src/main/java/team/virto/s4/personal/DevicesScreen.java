// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.s4.personal;

import android.widget.CheckBox;
import android.widget.LinearLayout;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import team.virto.s4.vos.Device;
import team.virto.s4.vos.KitKind;
import team.virto.s4.vos.Membership;
import team.virto.s4.vos.Notice;
import team.virto.s4.vos.Owed;
import team.virto.s4.vos.Posted;

/**
 * The device set: each device's standing and last sync, a phone retired (removed, then its
 * memberships revoked), the changes open (veto, cosign, a contest resolved), the memberships a
 * pairing left, the recovery kit's rotation, this phone's admin key replaced, a regroup, and a
 * commit now. Each change is the admin key's, behind its strong biometric.
 */
final class DevicesScreen extends Screen {
  private Device[] devices;
  private Notice[] open;
  private Membership[] owed;
  private String unread;
  private final Set<Long> regrouped = new HashSet<>();

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

  private void reload() {
    app.read(
        (node, prompts, refused) -> {
          Device[] read = node.devices(refused);
          if (read == null) {
            return null;
          }
          Notice[] operations = node.operations(refused);
          Membership[] memberships = operations == null ? null : node.memberships(refused);
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
          unread = Words.refusal(refused.code, refused.message);
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
                  + ", last sync "
                  + Words.ago(device.seen, now)));
      if (device.me) {
        continue;
      }
      CheckBox pick = check("In a regroup, leave it out", regrouped.contains(device.id));
      pick.setOnCheckedChangeListener(
          (box, checked) -> {
            if (checked) {
              regrouped.add(device.id);
            } else {
              regrouped.remove(device.id);
            }
          });
      into.addView(pick);
      if (device.removed) {
        into.addView(button("Revoke it in your other spaces", v -> revoke(device)));
      } else {
        into.addView(button("Retire this device", v -> retire(device)));
      }
    }
    into.addView(
        button(
            "Regroup without the devices left out",
            v -> {
              if (regrouped.isEmpty()) {
                app.say("Tick the devices to leave out first.");
                return;
              }
              app.ask(
                  "Regroup",
                  "The devices left out are removed and your other devices start a new group."
                      + " Once it matures, each device you keep hands this phone its key"
                      + " package when it syncs (Sync now there, or its background job);"
                      + " then tap Commit now here.",
                  "Regroup",
                  this::regroup);
            }));
  }

  private void operations(LinearLayout into) {
    into.addView(heading("Changes open"));
    if (open.length == 0) {
      into.addView(text("None."));
    }
    long now = System.currentTimeMillis();
    for (Notice notice : open) {
      into.addView(
          text(
              Words.pending(notice.pending)
                  + (notice.detail.isEmpty() ? "" : " (" + notice.detail + ")")
                  + (notice.matures > 0
                      ? ", it takes effect " + Words.until(notice.matures, now)
                      : "")));
      if (Words.contested(notice.detail)) {
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
                          (node, prompts, refused) ->
                              (enroll
                                      ? node.enrollDevice(membership, prompts, refused)
                                      : node.confirmDevice(membership, prompts, refused))
                                  ? Boolean.TRUE
                                  : null,
                          done -> reload())),
              button(
                  "Give it up",
                  v ->
                      app.run(
                          "Giving it up…",
                          (node, prompts, refused) ->
                              node.dropEnrollment(membership, refused) ? Boolean.TRUE : null,
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
                    (node, prompts, refused) -> node.update(prompts, refused) ? Boolean.TRUE : null,
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
                (node, prompts, refused) -> node.remove(device.id, prompts, refused),
                this::taken));
  }

  private void revoke(Device device) {
    app.run(
        "Revoking " + device.label + " in your other spaces…",
        (node, prompts, refused) -> {
          int revoked = node.revoke(device.id, prompts, refused);
          return refused.code == 0 ? revoked : null;
        },
        (Integer revoked) -> app.say("Revoked in " + revoked + " space(s)."));
  }

  private void veto(Notice notice) {
    app.run(
        "Vetoing…", (node, prompts, refused) -> node.veto(notice.index, prompts, refused), this::taken);
  }

  private void cosign(Notice notice) {
    app.run(
        "Approving…",
        (node, prompts, refused) -> node.cosign(notice.index, prompts, refused),
        this::taken);
  }

  private void posted(String doing, Notice notice, boolean upheld) {
    app.run(
        doing,
        (node, prompts, refused) -> node.resolve(notice.index, upheld, prompts, refused),
        this::taken);
  }

  private void rotate(byte kit) {
    app.run(
        "Making your new kit…",
        (node, prompts, refused) -> node.rotateKit(kit, prompts, refused),
        this::taken);
  }

  private void replaceAdmin(byte kit) {
    app.run(
        "Replacing this phone's admin key…",
        (node, prompts, refused) -> node.replaceAdmin(kit, prompts, refused),
        this::taken);
  }

  private void regroup() {
    long[] remove = new long[regrouped.size()];
    List<Long> ids = new ArrayList<>(regrouped);
    for (int i = 0; i < remove.length; i++) {
      remove[i] = ids.get(i);
    }
    app.run(
        "Regrouping…",
        (node, prompts, refused) -> node.regroup(remove, prompts, refused),
        posted -> {
          regrouped.clear();
          taken(posted);
        });
  }

  private void taken(Posted posted) {
    app.say("Done: your personal agent took it (log entry " + posted.index + ").");
    reload();
  }
}
