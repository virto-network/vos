// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.s4.personal;

import android.graphics.Bitmap;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.BinaryBitmap;
import com.google.zxing.DecodeHintType;
import com.google.zxing.EncodeHintType;
import com.google.zxing.PlanarYUVLuminanceSource;
import com.google.zxing.ReaderException;
import com.google.zxing.Result;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.common.HybridBinarizer;
import com.google.zxing.qrcode.QRCodeReader;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;
import java.util.EnumMap;
import java.util.Map;

/** QR codes through ZXing's core: one drawn from a text, and one read from a camera frame. */
final class Qr {
  private Qr() {}

  /** The modules of {@code text}'s QR code, a margin of four around them. */
  static BitMatrix matrix(String text) {
    Map<EncodeHintType, Object> hints = new EnumMap<>(EncodeHintType.class);
    hints.put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.M);
    hints.put(EncodeHintType.MARGIN, 4);
    try {
      return new QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, 0, 0, hints);
    } catch (WriterException tooLong) {
      throw new IllegalArgumentException("no QR code holds this text", tooLong);
    }
  }

  /** {@code text}'s QR code, black on white, about {@code size} pixels square. */
  static Bitmap bitmap(String text, int size) {
    BitMatrix modules = matrix(text);
    int scale = Math.max(1, size / modules.getWidth());
    int side = modules.getWidth() * scale;
    int[] pixels = new int[side * side];
    for (int y = 0; y < side; y++) {
      for (int x = 0; x < side; x++) {
        pixels[y * side + x] = modules.get(x / scale, y / scale) ? 0xFF000000 : 0xFFFFFFFF;
      }
    }
    return Bitmap.createBitmap(pixels, side, side, Bitmap.Config.ARGB_8888);
  }

  /** The text of a QR code in a frame's luminance plane, or null when none is read. */
  static String read(byte[] luminance, int width, int height) {
    PlanarYUVLuminanceSource source =
        new PlanarYUVLuminanceSource(luminance, width, height, 0, 0, width, height, false);
    Map<DecodeHintType, Object> hints = new EnumMap<>(DecodeHintType.class);
    hints.put(DecodeHintType.TRY_HARDER, Boolean.TRUE);
    try {
      BinaryBitmap bitmap = new BinaryBitmap(new HybridBinarizer(source));
      Result result = new QRCodeReader().decode(bitmap, hints);
      return result.getText();
    } catch (ReaderException none) {
      return null;
    }
  }
}
