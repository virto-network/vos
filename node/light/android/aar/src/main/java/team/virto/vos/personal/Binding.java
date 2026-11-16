// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.vos.personal;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.IBinder;
import android.os.RemoteException;
import android.util.Log;
import team.virto.s4.vos.VosNodeService;

/**
 * A binding to the facility's own interface in {@code :vos} ({@link IVosPersonal}), held from
 * {@link #bind} to {@link #close}, after which it never binds again: the personal space's screens
 * hold one for the activity's life, the debug probe for its run. When {@code :vos} dies Android
 * starts it again for the binding (or, when the binding itself died, this binds again); an
 * operation under way then fails with a {@link RemoteException}.
 */
public final class Binding implements ServiceConnection {
  /** The intent action {@code VosNodeService} serves {@link IVosPersonal} for. */
  public static final String ACTION = "team.virto.vos.personal.IVosPersonal";

  private static final String TAG = "vos.personal";
  /** How long an operation waits for {@code :vos} to be bound. */
  private static final long BIND_MS = 10_000;

  private final Context context;
  private IVosPersonal personal;
  private boolean bound;
  private boolean closed;

  public Binding(Context context) {
    this.context = context.getApplicationContext();
  }

  /** Bind, unless bound or closed. */
  public synchronized void bind() {
    if (bound || closed) {
      return;
    }
    Intent intent = new Intent(context, VosNodeService.class).setAction(ACTION);
    bound = context.bindService(intent, this, Context.BIND_AUTO_CREATE);
    if (!bound) {
      Log.w(TAG, "the VOS facility's service did not bind");
    }
  }

  /** Drop the binding for good: a later {@link #personal} refuses, and nothing binds again. */
  public synchronized void close() {
    closed = true;
    unbind();
    notifyAll();
  }

  private synchronized void unbind() {
    if (!bound) {
      return;
    }
    bound = false;
    personal = null;
    context.unbindService(this);
  }

  /** The interface as it is bound now, without waiting: null when it is not. */
  public synchronized IVosPersonal current() {
    return personal;
  }

  /** The interface, waited for while {@code :vos} starts; never on the main thread. */
  public synchronized IVosPersonal personal() throws RemoteException {
    if (closed) {
      throw new RemoteException("the binding to the VOS facility is closed");
    }
    bind();
    long until = System.currentTimeMillis() + BIND_MS;
    while (personal == null) {
      long left = until - System.currentTimeMillis();
      if (left <= 0) {
        throw new RemoteException("the VOS facility is not bound");
      }
      if (closed) {
        throw new RemoteException("the binding to the VOS facility is closed");
      }
      try {
        wait(left);
      } catch (InterruptedException interrupted) {
        Thread.currentThread().interrupt();
        throw new RemoteException("interrupted waiting for the VOS facility");
      }
    }
    return personal;
  }

  @Override
  public synchronized void onServiceConnected(ComponentName name, IBinder service) {
    personal = IVosPersonal.Stub.asInterface(service);
    notifyAll();
  }

  @Override
  public synchronized void onServiceDisconnected(ComponentName name) {
    personal = null;
    Log.w(TAG, "the VOS facility's process stopped");
  }

  @Override
  public void onBindingDied(ComponentName name) {
    // A dead binding is never connected again: bind anew.
    synchronized (this) {
      if (!bound || closed) {
        return;
      }
      unbind();
      bind();
    }
  }
}
