// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.s4.personal;

import android.app.AlertDialog;
import android.graphics.Typeface;
import android.text.InputType;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import team.virto.s4.VosPrompts;
import team.virto.s4.vos.Answer;
import team.virto.s4.vos.Form;
import team.virto.s4.vos.Row;

/**
 * The facility's forms over the personal space's screens, the app's own chrome: shown whole (its
 * rows as they are, its fields pre-filled, its notice apart), never screenshotted, answered by one
 * of its choices or declined. Asked on a Binder thread, which waits for the user.
 */
final class FormDialog implements VosPrompts.Forms {
  /** How long a form waits for the user: the operation holds the personal space meanwhile. */
  private static final long ANSWER_MINUTES = 10;

  private final PersonalActivity activity;
  private final Set<CompletableFuture<Answer>> open = new HashSet<>();
  private final List<AlertDialog> shown = new ArrayList<>();

  FormDialog(PersonalActivity activity) {
    this.activity = activity;
  }

  @Override
  public Answer confirm(Form form) {
    CompletableFuture<Answer> answer = new CompletableFuture<>();
    synchronized (open) {
      open.add(answer);
    }
    activity.runOnUiThread(() -> show(form, answer));
    try {
      return answer.get(ANSWER_MINUTES, TimeUnit.MINUTES);
    } catch (TimeoutException late) {
      activity.runOnUiThread(this::dismissShown);
      return declined();
    } catch (InterruptedException interrupted) {
      Thread.currentThread().interrupt();
      return declined();
    } catch (ExecutionException failed) {
      return declined();
    } finally {
      synchronized (open) {
        open.remove(answer);
      }
    }
  }

  /** The activity is going: every form open declined. */
  void dismissAll() {
    synchronized (open) {
      for (CompletableFuture<Answer> answer : open) {
        answer.complete(declined());
      }
    }
    dismissShown();
  }

  private void dismissShown() {
    for (AlertDialog dialog : new ArrayList<>(shown)) {
      dialog.dismiss();
    }
    shown.clear();
  }

  private void show(Form form, CompletableFuture<Answer> answer) {
    if (activity.isFinishing() || activity.isDestroyed()) {
      answer.complete(declined());
      return;
    }
    LinearLayout body = new LinearLayout(activity);
    body.setOrientation(LinearLayout.VERTICAL);
    int pad = activity.dp(20);
    body.setPadding(pad, activity.dp(8), pad, 0);
    if (form.detail != null && !form.detail.isEmpty()) {
      body.addView(text(form.detail, false));
    }
    for (Row row : form.rows) {
      TextView label = text(row.label, false);
      label.setTypeface(Typeface.DEFAULT_BOLD);
      label.setPadding(0, activity.dp(6), 0, 0);
      body.addView(label);
      body.addView(text(row.value, true));
    }
    List<EditText> fields = new ArrayList<>();
    for (Row row : form.fields) {
      EditText field = new EditText(activity);
      field.setHint(row.label);
      field.setText(row.value);
      field.setInputType(
          InputType.TYPE_CLASS_TEXT
              | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
              | InputType.TYPE_TEXT_FLAG_MULTI_LINE
              | InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD);
      body.addView(text(row.label, false));
      body.addView(field);
      fields.add(field);
    }
    if (form.notice != null && !form.notice.isEmpty()) {
      TextView notice = text(form.notice, false);
      notice.setTextColor(0xFFFFB74D);
      notice.setTypeface(Typeface.DEFAULT_BOLD);
      notice.setPadding(0, activity.dp(12), 0, 0);
      body.addView(notice);
    }
    String[] choices = form.choices.length == 0 ? new String[] {"Confirm"} : form.choices;
    AlertDialog[] dialog = new AlertDialog[1];
    for (int i = 1; i < choices.length; i++) {
      int choice = i;
      Button extra = new Button(activity);
      extra.setText(choices[i]);
      extra.setAllCaps(false);
      extra.setOnClickListener(
          v -> {
            answer.complete(confirmed(choice, fields));
            dialog[0].dismiss();
          });
      body.addView(extra);
    }
    ScrollView scroll = new ScrollView(activity);
    scroll.addView(body);
    dialog[0] =
        new AlertDialog.Builder(activity)
            .setTitle(form.title)
            .setView(scroll)
            .setCancelable(false)
            .setPositiveButton(choices[0], (d, which) -> answer.complete(confirmed(0, fields)))
            .setNegativeButton("Cancel", (d, which) -> answer.complete(declined()))
            .create();
    dialog[0].setOnDismissListener(d -> shown.remove(dialog[0]));
    dialog[0].getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
    shown.add(dialog[0]);
    dialog[0].show();
  }

  private TextView text(String value, boolean mono) {
    TextView view = new TextView(activity);
    view.setText(value);
    view.setTextSize(mono ? 14 : 15);
    if (mono) {
      view.setTypeface(Typeface.MONOSPACE);
    }
    return view;
  }

  private static Answer confirmed(int choice, List<EditText> fields) {
    Answer answer = new Answer();
    answer.confirmed = true;
    answer.choice = choice;
    answer.values = new String[fields.size()];
    for (int i = 0; i < fields.size(); i++) {
      answer.values[i] = fields.get(i).getText().toString();
      fields.get(i).getText().clear();
    }
    return answer;
  }

  private static Answer declined() {
    Answer answer = new Answer();
    answer.confirmed = false;
    answer.values = new String[0];
    return answer;
  }
}
