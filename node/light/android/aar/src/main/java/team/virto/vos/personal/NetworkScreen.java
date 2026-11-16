// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.vos.personal;

import android.widget.EditText;
import android.widget.LinearLayout;
import java.util.ArrayList;
import java.util.List;
import team.virto.s4.VosClient;
import team.virto.s4.vos.EnrolledSpace;
import team.virto.s4.vos.Refusal;
import team.virto.vos.R;

/**
 * Tor and the network: whether Tor connects (backup paused when it does not, with why: a wrong
 * clock, a bridge that does not answer, a network that blocks Tor), the bridges pasted for a
 * network that blocks it, and each space's opt-out of Tor for its key-signed calls, behind its
 * plain warning. The personal space and every anonymous call stay on Tor whatever is chosen.
 */
final class NetworkScreen extends Screen {
  private String bridges = "";
  private String state;
  private EnrolledSpace[] spaces;

  NetworkScreen(PersonalActivity app) {
    super(app);
  }

  @Override
  String title() {
    return "Tor and bridges";
  }

  @Override
  void shown() {
    check();
    app.read(
        // The enrollments are s4's interface's, through s4's binding.
        (personal, prompts, refused) -> VosClient.get(app).enrollments(refused),
        read -> {
          spaces = read;
          redraw();
        },
        refused -> {
          spaces = new EnrolledSpace[0];
          redraw();
        });
  }

  /** Bootstrap Tor now: its state, or the refusal that pauses the backup. */
  private void check() {
    state = "Connecting to Tor…";
    redraw();
    // Uncovered: the bridges' field stays usable while Tor tries.
    app.read(
        (personal, prompts, refused) -> personal.bootstrap(refused) ? Boolean.TRUE : null,
        done -> {
          state = "Tor is connected: your devices sync.";
          redraw();
        },
        this::paused);
  }

  private void paused(Refusal refused) {
    state = "Backup paused: " + Words.refusal(refused.code, refused.message);
    redraw();
  }

  @Override
  void build(LinearLayout into) {
    if (state != null) {
      into.addView(state.startsWith("Backup paused") ? warning(state) : text(state));
    }
    into.addView(button("Try again", v -> check()));
    into.addView(heading("Bridges"));
    into.addView(
        text(
            "On a network that blocks Tor, paste plain bridge lines (\"Bridge <address:port> "
                + "<fingerprint>\"), one a line. Without any, Tor uses its public relays."));
    EditText lines = kept(field("Bridge lines", bridges, true), text -> bridges = text);
    into.addView(lines);
    into.addView(
        buttons(
            button("Use these bridges", v -> bridges(split(bridges))),
            button("Use the public relays", v -> bridges(new String[0]))));
    into.addView(heading("Spaces off Tor"));
    if (spaces == null) {
      into.addView(text("Reading your spaces…"));
      return;
    }
    if (spaces.length == 0) {
      into.addView(text("No space this phone is enrolled in."));
      return;
    }
    into.addView(text(app.getString(R.string.vos_opt_out_warning)));
    for (EnrolledSpace space : spaces) {
      into.addView(
          text(
              space.host
                  + ":"
                  + space.port
                  + " ("
                  + Words.shortHex(space.handle)
                  + "): its signed calls "
                  + (space.optedOut ? "off Tor" : "on Tor")));
      into.addView(
          space.optedOut
              ? button("Put it back on Tor", v -> optOut(space, false))
              : button(
                  "Take it off Tor",
                  v ->
                      app.ask(
                          "Take this space off Tor?",
                          app.getString(R.string.vos_opt_out_warning),
                          "Take it off Tor",
                          () -> optOut(space, true))));
    }
  }

  private static String[] split(String text) {
    List<String> lines = new ArrayList<>();
    for (String line : text.split("\n")) {
      if (!line.trim().isEmpty()) {
        lines.add(line.trim());
      }
    }
    return lines.toArray(new String[0]);
  }

  private void bridges(String[] lines) {
    app.run(
        lines.length == 0 ? "Connecting through the public relays…" : "Connecting through bridges…",
        (personal, prompts, refused) -> personal.bridges(lines, refused) ? Boolean.TRUE : null,
        done -> {
          state = "Tor is connected: your devices sync.";
          redraw();
        },
        null,
        true,
        this::paused);
  }

  private void optOut(EnrolledSpace space, boolean out) {
    app.run(
        out ? "Taking the space off Tor…" : "Putting the space back on Tor…",
        (personal, prompts, refused) ->
            personal.optOut(space.handle, out, refused) ? Boolean.TRUE : null,
        done -> {
          space.optedOut = out;
          redraw();
        },
        null,
        true,
        refused -> {
          app.refused(refused);
          redraw();
        });
  }
}
