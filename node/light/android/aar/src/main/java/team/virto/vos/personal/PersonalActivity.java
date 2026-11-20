// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.vos.personal;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.graphics.Typeface;
import android.os.Binder;
import android.os.Bundle;
import android.os.RemoteException;
import android.util.Log;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import team.virto.s4.KeySources;
import team.virto.s4.VosClient;
import team.virto.s4.VosPrompts;
import team.virto.s4.vos.Refusal;

/**
 * The personal space's screens, over the {@code :vos} facility's own operations ({@link
 * IVosPersonal}, bound for the activity's life):
 * every operation runs off the main thread, one at a time, with the prompts it is lent (its forms
 * in {@link FormDialog}, its keys behind their own prompts in {@link KeySources}), and released
 * when it returns or the screen gives it up. The facility tells it each flow's stage, said over the
 * screen while the flow runs, and each background pass, after which the screen shown reads again.
 * Its windows are never captured in a release build; a debuggable one's are, for its screenshots.
 */
public final class PersonalActivity extends Activity {
  static final String TAG = "vos.personal";
  /** The intent's extra naming the screen to open: {@link #NETWORK} or none. */
  public static final String OPEN = "open";
  public static final String NETWORK = "network";

  private static final int CAMERA = 1;

  private final ExecutorService worker = Executors.newSingleThreadExecutor();
  /** The facility's quick calls (its watcher, the sitting), in order, beside every operation. */
  private final ExecutorService quick = Executors.newSingleThreadExecutor();
  private final Deque<Screen> back = new ArrayDeque<>();
  private Binding binding;
  private KeySources keys;
  private FormDialog forms;
  private Screen shown;
  private LinearLayout content;
  private TextView title;
  private View busy;
  private TextView busyText;
  private Button busyCancel;
  private boolean resumed;
  /** The operation under way's cancel, which back presses too; null when it has none. */
  private Runnable cancelling;
  /** The same cancel, sent when the activity goes while the operation runs. */
  private Runnable cancelOnDestroy;
  /** Whether the restore screen's sitting is open in {@code :vos}. */
  private boolean sitting;

  /** What {@code :vos} tells the screens: a stage of the flow under way, a pass ended. */
  private final IVosWatcher.Stub watcher =
      new IVosWatcher.Stub() {
        @Override
        public void stage(byte stage) {
          runOnUiThread(
              () -> {
                // A stage after its flow ended is dropped.
                if (!isDestroyed() && busy.getVisibility() == View.VISIBLE && shown != null) {
                  busyText.setText(shown.stage(stage));
                }
              });
        }

        @Override
        public void passed() {
          runOnUiThread(
              () -> {
                if (!isDestroyed() && shown != null && busy.getVisibility() != View.VISIBLE) {
                  shown.passed();
                }
              });
        }
      };

  /** One operation of the facility, its prompts lent, its refusal filled when it refuses. */
  interface Call<T> {
    T call(IVosPersonal personal, VosPrompts prompts, Refused refused) throws RemoteException;
  }

  /** One of the facility's own operations (the syncs, Tor), which refuse with s4's refusal. */
  interface Own<T> {
    T call(IVosPersonal personal, Refusal refused) throws RemoteException;
  }

  /** {@code own} as a {@link Call}: its refusal's code and message as a {@link Refused}. */
  static <T> Call<T> own(Own<T> own) {
    return (personal, prompts, refused) -> {
      Refusal theirs = new Refusal();
      T result = own.call(personal, theirs);
      if (theirs.code != 0) {
        Words.refused(theirs.code, theirs.message, refused);
      }
      return result;
    };
  }

  interface Done<T> {
    void done(T result);
  }

  @Override
  protected void onCreate(Bundle state) {
    super.onCreate(state);
    secure(this, getWindow());
    binding = new Binding(this);
    binding.bind();
    keys = new KeySources(this);
    forms = new FormDialog(this);
    FrameLayout root = new FrameLayout(this);
    root.setBackgroundColor(0xFF111510);
    ScrollView scroll = new ScrollView(this);
    LinearLayout page = new LinearLayout(this);
    page.setOrientation(LinearLayout.VERTICAL);
    page.setPadding(dp(16), dp(16), dp(16), dp(32));
    title = new TextView(this);
    title.setTextSize(22);
    title.setTypeface(Typeface.DEFAULT_BOLD);
    page.addView(title);
    content = new LinearLayout(this);
    content.setOrientation(LinearLayout.VERTICAL);
    page.addView(content);
    scroll.addView(page);
    root.addView(scroll);
    root.addView(busyOverlay());
    setContentView(root);
    open(new OverviewScreen(this));
    if (NETWORK.equals(getIntent().getStringExtra(OPEN))) {
      open(new NetworkScreen(this));
    }
  }

  @Override
  protected void onNewIntent(Intent intent) {
    super.onNewIntent(intent);
    if (NETWORK.equals(intent.getStringExtra(OPEN))) {
      open(new NetworkScreen(this));
    }
  }

  private View busyOverlay() {
    LinearLayout overlay = new LinearLayout(this);
    overlay.setOrientation(LinearLayout.VERTICAL);
    overlay.setGravity(Gravity.CENTER);
    overlay.setBackgroundColor(0xE0111510);
    overlay.setClickable(true);
    overlay.setPadding(dp(32), dp(32), dp(32), dp(32));
    overlay.addView(new ProgressBar(this));
    busyText = new TextView(this);
    busyText.setTextSize(16);
    busyText.setGravity(Gravity.CENTER);
    busyText.setPadding(0, dp(16), 0, dp(16));
    overlay.addView(busyText);
    busyCancel = new Button(this);
    busyCancel.setText("Cancel");
    busyCancel.setAllCaps(false);
    overlay.addView(busyCancel);
    overlay.setVisibility(View.GONE);
    busy = overlay;
    return overlay;
  }

  @Override
  protected void onStart() {
    super.onStart();
    VosClient.get(this).started();
    background(personal -> personal.watch(watcher));
  }

  @Override
  protected void onStop() {
    // The app in the background: the kit a restore holds is wiped, entered again on return.
    forgetKit();
    VosClient.get(this).stopped();
    super.onStop();
  }

  @Override
  protected void onResume() {
    super.onResume();
    resumed = true;
    keys.onResume();
    if (shown != null) {
      shown.resumed();
    }
  }

  @Override
  protected void onPause() {
    resumed = false;
    keys.onPause();
    if (shown != null) {
      shown.left();
    }
    super.onPause();
  }

  @Override
  protected void onDestroy() {
    // A wait the screen started ends with it, so it holds the personal space no longer.
    if (cancelOnDestroy != null) {
      cancelOnDestroy.run();
    }
    forms.dismissAll();
    keys.close();
    forgetKit();
    worker.shutdown();
    quick.shutdown();
    try {
      // The sitting's close delivered before the binding goes.
      quick.awaitTermination(2, TimeUnit.SECONDS);
    } catch (InterruptedException interrupted) {
      Thread.currentThread().interrupt();
    }
    binding.close();
    super.onDestroy();
  }

  /** Whether a build whose application flags are {@code flags} keeps its screens from capture. */
  static boolean secured(int flags) {
    return (flags & ApplicationInfo.FLAG_DEBUGGABLE) == 0;
  }

  /**
   * {@code window} kept from screenshots and the recents' preview, unless the app is a debuggable
   * build, whose personal-space screens are captured for its screenshots.
   */
  static void secure(Context context, Window window) {
    if (secured(context.getApplicationInfo().flags)) {
      window.addFlags(WindowManager.LayoutParams.FLAG_SECURE);
    }
  }

  /** One call of the facility's own interface off the main thread, beside every operation. */
  interface Quick {
    void call(IVosPersonal personal) throws RemoteException;
  }

  private void background(Quick call) {
    if (quick.isShutdown()) {
      return;
    }
    quick.execute(
        () -> {
          try {
            call.call(binding.personal());
          } catch (RemoteException | RuntimeException gone) {
            Log.w(TAG, "not delivered to the facility: " + gone);
          }
        });
  }

  /**
   * The restore screen's sitting opened in {@code :vos}: the kit its flows enter held there for
   * the next, until {@link #forgetKit}, this process's death, or ten minutes after its entry.
   */
  void holdKit() {
    if (sitting) {
      return;
    }
    sitting = true;
    Binder token = new Binder();
    background(personal -> personal.kitHold(token));
  }

  /** The sitting closed, the kit it held wiped in {@code :vos}. */
  void forgetKit() {
    if (!sitting) {
      return;
    }
    sitting = false;
    background(IVosPersonal::kitForget);
  }

  @Override
  @SuppressWarnings("deprecation") // The platform Activity's back, on every API level the app runs.
  public void onBackPressed() {
    if (busy.getVisibility() == View.VISIBLE) {
      // An operation runs: back cancels it if it can be, and leaves nothing under it.
      if (cancelling != null && busyCancel.isEnabled()) {
        cancelling.run();
      }
      return;
    }
    if (back.isEmpty()) {
      super.onBackPressed();
      return;
    }
    shown.left();
    shown.closed();
    show(back.pop());
  }

  @Override
  public void onRequestPermissionsResult(int code, String[] permissions, int[] results) {
    if (code == CAMERA && shown != null) {
      shown.permitted(results.length > 0 && results[0] == 0);
    }
  }

  // ----- navigation -----

  /** Open {@code screen} over the one shown. */
  void open(Screen screen) {
    if (shown != null) {
      shown.left();
      back.push(shown);
    }
    show(screen);
  }

  /** Close the screen shown, back to the one under it. */
  void close() {
    onBackPressed();
  }

  /** Back to the screen under the one shown, whatever runs meanwhile. */
  void pop() {
    if (back.isEmpty()) {
      finish();
      return;
    }
    shown.left();
    shown.closed();
    show(back.pop());
  }

  /** Replace the screen shown, keeping the ones under it. */
  void replace(Screen screen) {
    if (shown != null) {
      shown.left();
      shown.closed();
    }
    show(screen);
  }

  /** Back to the first screen, shown anew. */
  void home() {
    if (shown != null) {
      shown.left();
      shown.closed();
    }
    for (Screen under : back) {
      under.closed();
    }
    back.clear();
    show(new OverviewScreen(this));
  }

  private void show(Screen screen) {
    shown = screen;
    title.setText(screen.title());
    screen.attach(content);
    screen.shown();
    if (resumed) {
      screen.resumed();
    }
  }

  boolean showing(Screen screen) {
    return shown == screen && !isDestroyed();
  }

  /** Scan a QR code; {@code then} takes its text. */
  void scan(ScanScreen.Scanned then) {
    open(new ScanScreen(this, then));
  }

  void askCamera() {
    requestPermissions(new String[] {android.Manifest.permission.CAMERA}, CAMERA);
  }

  // ----- operations -----

  /**
   * Run {@code call} off the main thread with prompts lent to it, the screen covered meanwhile
   * by {@code doing}; {@code done} takes its result on the main thread, or the refusal is said.
   */
  <T> void run(String doing, Call<T> call, Done<T> done) {
    run(doing, call, done, null);
  }

  /**
   * As {@link #run(String, Call, Done)}, cancellable while it runs: {@code cancel} (off the main
   * thread) asks the facility to stop, and the operation's prompts are released at once.
   */
  <T> void run(String doing, Call<T> call, Done<T> done, Call<Void> cancel) {
    run(doing, call, done, cancel, true);
  }

  /**
   * As {@link #run(String, Call, Done, Call)}, the screen left visible under a bar at its foot
   * unless {@code covered}: a pairing's code stays on screen while the facility waits.
   */
  <T> void run(String doing, Call<T> call, Done<T> done, Call<Void> cancel, boolean covered) {
    run(doing, call, done, cancel, covered, this::refused);
  }

  /** As the others, its refusal (a cancel's, a decline's) taken by {@code refusedThen}. */
  <T> void run(
      String doing,
      Call<T> call,
      Done<T> done,
      Call<Void> cancel,
      boolean covered,
      Done<Refused> refusedThen) {
    VosPrompts prompts = new VosPrompts(keys, forms);
    busy.setLayoutParams(
        covered
            ? new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT)
            : new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.WRAP_CONTENT,
                Gravity.BOTTOM));
    cancelling = cancel == null ? null : busyCancel::performClick;
    busyText.setText(doing);
    busyCancel.setVisibility(cancel == null ? View.GONE : View.VISIBLE);
    busyCancel.setEnabled(true);
    busyCancel.setOnClickListener(
        v -> {
          busyCancel.setEnabled(false);
          busyText.setText("Cancelling…");
          // The prompts stay lent: the facility ends the operation itself.
          deliver(cancel, prompts);
        });
    cancelOnDestroy = cancel == null ? null : () -> deliver(cancel, prompts);
    busy.setVisibility(View.VISIBLE);
    worker.execute(
        () -> {
          Refused refused = new Refused();
          T result = null;
          try {
            IVosPersonal personal = binding.personal();
            // Told again each time: a `:vos` started anew knows no watcher.
            personal.watch(watcher);
            result = call.call(personal, prompts, refused);
          } catch (RemoteException | RuntimeException error) {
            Log.w(TAG, doing + " failed", error);
            refused.why = Why.FAILED;
            refused.detail = "the facility stopped: " + error.getMessage();
          } finally {
            prompts.release();
          }
          T answered = refused.why != Why.NONE ? null : result;
          runOnUiThread(
              () -> {
                if (isDestroyed()) {
                  return;
                }
                busy.setVisibility(View.GONE);
                cancelling = null;
                cancelOnDestroy = null;
                if (answered == null) {
                  refusedThen.done(refused);
                } else {
                  done.done(answered);
                }
              });
        });
  }

  /** The facility's own interface, waited for while {@code :vos} starts; off the main thread. */
  IVosPersonal personal() throws RemoteException {
    return binding.personal();
  }

  /**
   * Send {@code cancel} to the facility off the main thread, on the interface bound now: the
   * activity may close its binding meanwhile.
   */
  private void deliver(Call<Void> cancel, VosPrompts prompts) {
    IVosPersonal bound = binding.current();
    new Thread(
            () -> {
              try {
                cancel.call(bound != null ? bound : binding.personal(), prompts, new Refused());
              } catch (RemoteException | RuntimeException gone) {
                Log.w(TAG, "cancel not delivered: " + gone);
              }
            },
            "vos.cancel")
        .start();
  }

  /** Read {@code call} off the main thread, uncovered; {@code done} takes its result or null. */
  <T> void read(Call<T> call, Done<T> done, Done<Refused> refusedThen) {
    worker.execute(
        () -> {
          Refused refused = new Refused();
          T result = null;
          try {
            result = call.call(binding.personal(), null, refused);
          } catch (RemoteException | RuntimeException error) {
            refused.why = Why.FAILED;
            refused.detail = "the facility stopped: " + error.getMessage();
          }
          T answered = refused.why != Why.NONE ? null : result;
          runOnUiThread(
              () -> {
                if (isDestroyed()) {
                  return;
                }
                if (answered == null) {
                  refusedThen.done(refused);
                } else {
                  done.done(answered);
                }
              });
        });
  }

  /** Say a refusal, quietly when the user declined. */
  void refused(Refused refused) {
    if (refused.why == Why.DECLINED || refused.why == Why.CANCELLED) {
      return;
    }
    new AlertDialog.Builder(this)
        .setTitle("Not done")
        .setMessage(Words.why(refused))
        .setPositiveButton("OK", null)
        .show();
  }

  void say(String message) {
    new AlertDialog.Builder(this).setMessage(message).setPositiveButton("OK", null).show();
  }

  /** Ask before {@code then}. */
  void ask(String title, String message, String yes, Runnable then) {
    new AlertDialog.Builder(this)
        .setTitle(title)
        .setMessage(message)
        .setPositiveButton(yes, (dialog, which) -> then.run())
        .setNegativeButton("Cancel", null)
        .show();
  }

  int dp(int value) {
    return (int)
        TypedValue.applyDimension(
            TypedValue.COMPLEX_UNIT_DIP, value, getResources().getDisplayMetrics());
  }
}
