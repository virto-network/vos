// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.vos.personal;

import android.graphics.Typeface;
import android.text.Editable;
import android.text.InputType;
import android.text.TextWatcher;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.TextView;

/**
 * One screen of the personal space: its views, built anew on each {@link #redraw}, and the
 * operations it starts through its {@link PersonalActivity}.
 */
abstract class Screen {
  final PersonalActivity app;
  private LinearLayout into;

  Screen(PersonalActivity app) {
    this.app = app;
  }

  abstract String title();

  /** The screen's views, into {@code into}. */
  abstract void build(LinearLayout into);

  /** Shown: load what it shows. */
  void shown() {}

  /** Left, or the activity paused: release what it holds (the camera). */
  void left() {}

  /** The activity resumed with this screen shown. */
  void resumed() {}

  /** A permission the screen asked for was answered. */
  void permitted(boolean granted) {}

  final void attach(LinearLayout into) {
    this.into = into;
    into.removeAllViews();
    build(into);
  }

  /** Build the screen anew, if it is the one shown. */
  final void redraw() {
    if (into != null && app.showing(this)) {
      attach(into);
    }
  }

  // ----- views -----

  final TextView heading(String text) {
    TextView view = text(text);
    view.setTextSize(18);
    view.setTypeface(Typeface.DEFAULT_BOLD);
    view.setPadding(0, app.dp(16), 0, app.dp(4));
    return view;
  }

  final TextView text(String text) {
    TextView view = new TextView(app);
    view.setText(text);
    view.setTextSize(15);
    view.setTextIsSelectable(true);
    view.setPadding(0, app.dp(4), 0, app.dp(4));
    return view;
  }

  final TextView mono(String text) {
    TextView view = text(text);
    view.setTypeface(Typeface.MONOSPACE);
    view.setTextSize(13);
    return view;
  }

  /** A warning, set apart. */
  final TextView warning(String text) {
    TextView view = text(text);
    view.setTextColor(0xFFFFB74D);
    view.setTypeface(Typeface.DEFAULT_BOLD);
    return view;
  }

  final Button button(String label, View.OnClickListener click) {
    Button button = new Button(app);
    button.setText(label);
    button.setAllCaps(false);
    button.setOnClickListener(click);
    return button;
  }

  /** A row of buttons, sharing its width. */
  final LinearLayout buttons(Button... buttons) {
    LinearLayout row = new LinearLayout(app);
    row.setOrientation(LinearLayout.HORIZONTAL);
    for (Button button : buttons) {
      row.addView(
          button, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1));
    }
    return row;
  }

  /** Where a field's text is kept, so the screen built anew shows it again. */
  interface Keep {
    void keep(String text);
  }

  /** {@code field}, its text kept by {@code keep} as it changes. */
  static EditText kept(EditText field, Keep keep) {
    field.addTextChangedListener(
        new TextWatcher() {
          @Override
          public void beforeTextChanged(CharSequence text, int start, int count, int after) {}

          @Override
          public void onTextChanged(CharSequence text, int start, int before, int count) {}

          @Override
          public void afterTextChanged(Editable text) {
            keep.keep(text.toString());
          }
        });
    return field;
  }

  /** A text field: no suggestions learned from it. */
  final EditText field(String hint, String value, boolean lines) {
    EditText field = new EditText(app);
    field.setHint(hint);
    field.setText(value);
    int type = InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS;
    if (lines) {
      type |= InputType.TYPE_TEXT_FLAG_MULTI_LINE;
      field.setMinLines(3);
    } else {
      field.setSingleLine(true);
    }
    field.setInputType(type);
    return field;
  }

  interface KeepKind {
    void keep(byte kind);
  }

  /** A choice of kit kind, the phrase first, kept by {@code keep} as it changes. */
  static final class KitChoice {
    final RadioGroup group;
    private final RadioButton phrase;

    KitChoice(Screen screen, byte initial, KeepKind keep) {
      group = new RadioGroup(screen.app);
      phrase = new RadioButton(screen.app);
      phrase.setText("A recovery phrase: 24 words you write down");
      phrase.setId(View.generateViewId());
      RadioButton key = new RadioButton(screen.app);
      key.setText(
          "A separate hardware security key (FIDO2, plugged in by USB or held to NFC, with its"
              + " PIN), not this phone's own: its card you write down");
      key.setId(View.generateViewId());
      group.addView(phrase);
      group.addView(key);
      group.check(initial == KitKind.SECURITY_KEY ? key.getId() : phrase.getId());
      group.setOnCheckedChangeListener((g, id) -> keep.keep(kind()));
    }

    byte kind() {
      return group.getCheckedRadioButtonId() == phrase.getId()
          ? KitKind.PHRASE
          : KitKind.SECURITY_KEY;
    }
  }

  /** A home's code field, with its scan and what the code names. */
  final class HomeField {
    final EditText code;
    private final TextView named;

    HomeField(LinearLayout into, String value, Keep keep) {
      code = kept(field("The home's code (" + Codes.HOME + "…)", value, true), keep);
      named = mono("");
      into.addView(code);
      into.addView(
          buttons(
              button("Scan the home's code", v -> app.scan(text -> set(text))),
              button("Check", v -> show())));
      into.addView(named);
      show();
    }

    private void set(String text) {
      code.setText(text);
      show();
    }

    private void show() {
      String text = code.getText().toString();
      if (text.trim().isEmpty()) {
        named.setText("");
        return;
      }
      Home home = Codes.home(text);
      named.setText(
          home == null
              ? "This is not a home's code."
              : "Home " + Codes.lowerHex(home.handle) + "\n" + home.onions.length + " onion(s)");
    }

    /** The home named, or null after saying why. */
    Home home() {
      Home home = Codes.home(code.getText().toString());
      if (home == null) {
        app.say("Enter or scan the home's code first.");
      }
      return home;
    }
  }
}
