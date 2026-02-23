package com.google.tsunami.plugins.detectors.cves.cve202421181;

import java.nio.ByteBuffer;

public class Utils {
  public static byte[] hexStringToByteArray(String s) {
    int len = s.length();
    byte[] data = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
      data[i / 2] =
          (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
    }
    return data;
  }

  public static int arrayIndexOf(byte[] array, byte[] subsequence) {
    /*
    Finds a sequence of bytes in an array. Returns -1 when not found.
     */
    int index = -1;
    for (int i = 0; i < array.length - subsequence.length + 1; ++i) {
      boolean found = true;
      for (int j = 0; j < subsequence.length; ++j) {
        if (array[i + j] != subsequence[j]) {
          found = false;
          break;
        }
      }
      if (found) {
        index = i;
        break;
      }
    }
    return index;
  }

  public static int calcBytesToAlign(int initialPos) {
    if (initialPos % 4 == 0) {
      // Already aligned
      return 0;
    }
    int alignedPos = 4 * ((initialPos / 4) + 1);
    return alignedPos - initialPos;
  }

  public static void alignByteBuf(ByteBuffer byteBuf) {
    int initialPos = byteBuf.position();
    int bytesToDiscard = calcBytesToAlign(initialPos);

    // Check that there are only NULL bytes. If not, abort.
    for (int i = 0; i < bytesToDiscard; i++) {
      byte b = byteBuf.get();
      if (b != (byte) 0) {
        // Tried to discard bytes to align buffer but there was deta in there, abort and restore
        // previous position
        byteBuf.position(initialPos);
        return;
      }
    }
  }
}
