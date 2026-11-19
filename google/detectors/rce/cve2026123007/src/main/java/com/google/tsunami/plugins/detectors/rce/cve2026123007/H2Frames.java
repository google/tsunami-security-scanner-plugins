/*
 * Copyright 2026 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.google.tsunami.plugins.detectors.rce.cve2026123007;

import static java.nio.charset.StandardCharsets.US_ASCII;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Optional;

/** Low-level RFC 9113 HTTP/2 frame codec shared by {@link H2FlowControlProbe} and unit tests. */
final class H2Frames {
  private static final byte[] clientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".getBytes(US_ASCII);

  static final int FRAME_HEADER_LEN = 9;

  static final int TYPE_DATA = 0x00;
  static final int TYPE_HEADERS = 0x01;
  static final int TYPE_RST_STREAM = 0x03;
  static final int TYPE_SETTINGS = 0x04;
  static final int TYPE_PING = 0x06;
  static final int TYPE_GOAWAY = 0x07;
  static final int TYPE_WINDOW_UPDATE = 0x08;
  static final int TYPE_CONTINUATION = 0x09;

  static final int FLAG_ACK = 0x01;
  static final int FLAG_END_STREAM = 0x01;
  static final int FLAG_END_HEADERS = 0x04;
  static final int FLAG_PADDED = 0x08;
  static final int FLAG_PRIORITY = 0x20;

  static final long ERR_FLOW_CONTROL = 0x03L;
  static final long ERR_REFUSED_STREAM = 0x07L;

  static final int SETTING_HEADER_TABLE_SIZE = 0x0001;
  static final int SETTING_MAX_CONCURRENT_STREAMS = 0x0003;
  static final int SETTING_INITIAL_WINDOW_SIZE = 0x0004;
  static final int SETTING_MAX_FRAME_SIZE = 0x0005;
  static final int SETTING_NO_PRIORITIES = 0x0009;

  record FrameHeader(int length, int type, int flags, int streamId) {}

  static void writeClientPreface(ByteArrayOutputStream out) {
    out.writeBytes(clientPreface);
  }

  static byte[] clientPrefaceCopy() {
    return clientPreface.clone();
  }

  static Optional<FrameHeader> readNextFrameHeader(InputStream in) throws IOException {
    byte[] hdr = in.readNBytes(FRAME_HEADER_LEN);
    if (hdr.length < FRAME_HEADER_LEN) {
      return Optional.empty();
    }
    return Optional.of(decodeFrameHeader(hdr));
  }

  static FrameHeader decodeFrameHeader(byte[] hdr) {
    int length = ((hdr[0] & 0xff) << 16) | ((hdr[1] & 0xff) << 8) | (hdr[2] & 0xff);
    int type = hdr[3] & 0xff;
    int flags = hdr[4] & 0xff;
    int streamId = (int) (readUint32(hdr, 5) & 0x7fffffffL);
    return new FrameHeader(length, type, flags, streamId);
  }

  static void writeFrame(
      ByteArrayOutputStream out, int type, int flags, int streamId, byte[] payload) {
    int len = payload.length;
    out.write((len >>> 16) & 0xff);
    out.write((len >>> 8) & 0xff);
    out.write(len & 0xff);
    out.write(type & 0xff);
    out.write(flags & 0xff);
    int sid = streamId & 0x7fffffff;
    out.write((sid >>> 24) & 0xff);
    out.write((sid >>> 16) & 0xff);
    out.write((sid >>> 8) & 0xff);
    out.write(sid & 0xff);
    out.writeBytes(payload);
  }

  static void writeSettingsFrame(
      ByteArrayOutputStream out, long headerTableSize, long initialWindowSize) {
    byte[] p = new byte[12];
    writeUint16(p, 0, SETTING_HEADER_TABLE_SIZE);
    writeUint32(p, 2, headerTableSize);
    writeUint16(p, 6, SETTING_INITIAL_WINDOW_SIZE);
    writeUint32(p, 8, initialWindowSize);
    writeFrame(out, TYPE_SETTINGS, 0, 0, p);
  }

  static void writeWindowUpdateFrame(ByteArrayOutputStream out, int streamId, long increment) {
    byte[] p = new byte[4];
    writeUint32(p, 0, increment & 0x7fffffffL);
    writeFrame(out, TYPE_WINDOW_UPDATE, 0, streamId, p);
  }

  static void writePingFrame(ByteArrayOutputStream out, boolean ack, byte[] data8) {
    writeFrame(out, TYPE_PING, ack ? FLAG_ACK : 0, 0, data8);
  }

  static void writeHeadersFrame(
      ByteArrayOutputStream out, int streamId, byte[] headerBlock, boolean endStream) {
    int flags = FLAG_END_HEADERS | (endStream ? FLAG_END_STREAM : 0);
    writeFrame(out, TYPE_HEADERS, flags, streamId, headerBlock);
  }

  static int readUint16(byte[] b, int off) {
    return ((b[off] & 0xff) << 8) | (b[off + 1] & 0xff);
  }

  static long readUint32(byte[] b, int off) {
    return ((long) (b[off] & 0xff) << 24)
        | ((long) (b[off + 1] & 0xff) << 16)
        | ((long) (b[off + 2] & 0xff) << 8)
        | (long) (b[off + 3] & 0xff);
  }

  static void writeUint16(byte[] b, int off, int val) {
    b[off] = (byte) (val >>> 8);
    b[off + 1] = (byte) val;
  }

  static void writeUint32(byte[] b, int off, long val) {
    b[off] = (byte) (val >>> 24);
    b[off + 1] = (byte) (val >>> 16);
    b[off + 2] = (byte) (val >>> 8);
    b[off + 3] = (byte) val;
  }

  private H2Frames() {}
}
