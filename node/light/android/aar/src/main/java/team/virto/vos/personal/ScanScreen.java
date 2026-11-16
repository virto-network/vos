// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.vos.personal;

import android.Manifest;
import android.content.pm.PackageManager;
import android.graphics.ImageFormat;
import android.graphics.SurfaceTexture;
import android.hardware.camera2.CameraAccessException;
import android.hardware.camera2.CameraCaptureSession;
import android.hardware.camera2.CameraCharacteristics;
import android.hardware.camera2.CameraDevice;
import android.hardware.camera2.CameraManager;
import android.hardware.camera2.CaptureRequest;
import android.hardware.camera2.params.StreamConfigurationMap;
import android.media.Image;
import android.media.ImageReader;
import android.os.Handler;
import android.os.HandlerThread;
import android.util.Log;
import android.util.Size;
import android.view.Surface;
import android.view.TextureView;
import android.widget.LinearLayout;
import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * A QR code scanned with the back camera (camera2, its frames' luminance read by ZXing); the
 * first code read goes to the screen that asked, and the camera closes when the screen is left or
 * the activity paused.
 */
final class ScanScreen extends Screen {
  /** What takes the scanned text, on the main thread. */
  interface Scanned {
    void scanned(String text);
  }

  /** The frame size asked for: enough for a dense code held near. */
  private static final int WIDTH = 1280;
  private static final int HEIGHT = 720;

  private final Scanned then;
  private HandlerThread thread;
  private Handler handler;
  private CameraDevice camera;
  private CameraCaptureSession session;
  private ImageReader reader;
  private TextureView preview;
  private Size size;
  private boolean done;
  private String problem;
  /** Stopped since the camera was asked for: a camera or session that opens late is closed. */
  private volatile boolean stopped;

  ScanScreen(PersonalActivity app, Scanned then) {
    super(app);
    this.then = then;
  }

  @Override
  String title() {
    return "Scan a code";
  }

  @Override
  void build(LinearLayout into) {
    if (problem != null) {
      into.addView(warning(problem));
      into.addView(text("Paste the code instead: go back and use the field for it."));
      return;
    }
    into.addView(text("Hold the code in the frame."));
    preview = new TextureView(app);
    int width = app.getResources().getDisplayMetrics().widthPixels - app.dp(32);
    // The sensor's frames are landscape; on a portrait screen the preview stands upright.
    into.addView(preview, new LinearLayout.LayoutParams(width, width * WIDTH / HEIGHT));
  }

  @Override
  void resumed() {
    if (done || problem != null) {
      return;
    }
    if (app.checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
      app.askCamera();
      return;
    }
    start();
  }

  @Override
  void permitted(boolean granted) {
    if (granted) {
      start();
    } else {
      problem = "The camera was not allowed.";
      redraw();
    }
  }

  @Override
  void left() {
    stop();
  }

  private void start() {
    if (camera != null || preview == null) {
      return;
    }
    if (preview.isAvailable()) {
      open(preview.getSurfaceTexture());
      return;
    }
    preview.setSurfaceTextureListener(
        new TextureView.SurfaceTextureListener() {
          @Override
          public void onSurfaceTextureAvailable(SurfaceTexture texture, int width, int height) {
            open(texture);
          }

          @Override
          public void onSurfaceTextureSizeChanged(SurfaceTexture texture, int width, int height) {}

          @Override
          public boolean onSurfaceTextureDestroyed(SurfaceTexture texture) {
            stop();
            return true;
          }

          @Override
          public void onSurfaceTextureUpdated(SurfaceTexture texture) {}
        });
  }

  private void open(SurfaceTexture texture) {
    if (camera != null || thread != null) {
      return;
    }
    stopped = false;
    CameraManager cameras = app.getSystemService(CameraManager.class);
    try {
      String id = back(cameras);
      if (id == null) {
        fail("This device has no camera.");
        return;
      }
      StreamConfigurationMap map =
          cameras
              .getCameraCharacteristics(id)
              .get(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP);
      size = closest(map.getOutputSizes(ImageFormat.YUV_420_888));
      thread = new HandlerThread("vos.scan");
      thread.start();
      handler = new Handler(thread.getLooper());
      reader =
          ImageReader.newInstance(size.getWidth(), size.getHeight(), ImageFormat.YUV_420_888, 2);
      reader.setOnImageAvailableListener(this::frame, handler);
      texture.setDefaultBufferSize(size.getWidth(), size.getHeight());
      Surface shown = new Surface(texture);
      cameras.openCamera(
          id,
          new CameraDevice.StateCallback() {
            @Override
            public void onOpened(CameraDevice opened) {
              synchronized (ScanScreen.this) {
                if (stopped) {
                  opened.close();
                  return;
                }
                camera = opened;
              }
              session(opened, shown);
            }

            @Override
            public void onDisconnected(CameraDevice gone) {
              gone.close();
              camera = null;
            }

            @Override
            public void onError(CameraDevice failed, int error) {
              failed.close();
              camera = null;
              app.runOnUiThread(() -> fail("The camera did not open (" + error + ")."));
            }
          },
          handler);
    } catch (CameraAccessException | SecurityException | IllegalArgumentException error) {
      fail("The camera did not open: " + error.getMessage());
    }
  }

  @SuppressWarnings("deprecation") // The session API every level from 23 has.
  private void session(CameraDevice opened, Surface shown) {
    try {
      opened.createCaptureSession(
          Arrays.asList(shown, reader.getSurface()),
          new CameraCaptureSession.StateCallback() {
            @Override
            public void onConfigured(CameraCaptureSession configured) {
              synchronized (ScanScreen.this) {
                if (stopped) {
                  configured.close();
                  return;
                }
                session = configured;
              }
              try {
                CaptureRequest.Builder request =
                    opened.createCaptureRequest(CameraDevice.TEMPLATE_PREVIEW);
                request.addTarget(shown);
                request.addTarget(reader.getSurface());
                request.set(
                    CaptureRequest.CONTROL_AF_MODE,
                    CaptureRequest.CONTROL_AF_MODE_CONTINUOUS_PICTURE);
                configured.setRepeatingRequest(request.build(), null, handler);
              } catch (CameraAccessException | IllegalStateException error) {
                Log.w(PersonalActivity.TAG, "the scan's frames stopped", error);
              }
            }

            @Override
            public void onConfigureFailed(CameraCaptureSession failed) {
              app.runOnUiThread(() -> fail("The camera did not start."));
            }
          },
          handler);
    } catch (CameraAccessException | IllegalStateException error) {
      app.runOnUiThread(() -> fail("The camera did not start: " + error.getMessage()));
    }
  }

  /** One frame: its luminance plane read for a code, on the camera's thread. */
  private void frame(ImageReader from) {
    Image image;
    try {
      image = from.acquireLatestImage();
    } catch (IllegalStateException closed) {
      return;
    }
    if (image == null || stopped) {
      if (image != null) {
        image.close();
      }
      return;
    }
    String text;
    try {
      int width = image.getWidth();
      int height = image.getHeight();
      Image.Plane plane = image.getPlanes()[0];
      ByteBuffer buffer = plane.getBuffer();
      int stride = plane.getRowStride();
      byte[] luminance = new byte[width * height];
      for (int row = 0; row < height; row++) {
        buffer.position(row * stride);
        buffer.get(luminance, row * width, width);
      }
      text = Qr.read(luminance, width, height);
    } catch (IllegalStateException closed) {
      // The reader closed under the frame: the scan stopped.
      return;
    } finally {
      image.close();
    }
    if (text != null) {
      app.runOnUiThread(() -> scanned(text));
    }
  }

  private void scanned(String text) {
    if (done) {
      return;
    }
    done = true;
    stop();
    // The screen that asked takes the text before it is shown again.
    then.scanned(text);
    if (app.showing(this)) {
      app.pop();
    }
  }

  private void fail(String why) {
    stop();
    problem = why;
    redraw();
  }

  private synchronized void stop() {
    stopped = true;
    if (session != null) {
      session.close();
      session = null;
    }
    if (camera != null) {
      camera.close();
      camera = null;
    }
    if (reader != null) {
      reader.close();
      reader = null;
    }
    if (thread != null) {
      thread.quitSafely();
      thread = null;
    }
  }

  private static String back(CameraManager cameras) throws CameraAccessException {
    String[] ids = cameras.getCameraIdList();
    for (String id : ids) {
      Integer facing = cameras.getCameraCharacteristics(id).get(CameraCharacteristics.LENS_FACING);
      if (facing != null && facing == CameraCharacteristics.LENS_FACING_BACK) {
        return id;
      }
    }
    return ids.length > 0 ? ids[0] : null;
  }

  /** The frame size nearest {@link #WIDTH} by {@link #HEIGHT}. */
  private static Size closest(Size[] sizes) {
    Size best = sizes[0];
    for (Size candidate : sizes) {
      long off =
          Math.abs((long) candidate.getWidth() * candidate.getHeight() - (long) WIDTH * HEIGHT);
      long bestOff = Math.abs((long) best.getWidth() * best.getHeight() - (long) WIDTH * HEIGHT);
      if (off < bestOff) {
        best = candidate;
      }
    }
    return best;
  }
}
