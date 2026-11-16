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
package com.google.tsunami.plugins.detectors.rce.cve2026119618;

import static java.nio.charset.StandardCharsets.ISO_8859_1;

import com.google.common.base.Ascii;
import com.google.common.collect.ImmutableList;
import com.google.tsunami.common.net.socket.TsunamiSocketFactory;
import com.google.tsunami.plugins.detectors.rce.cve2026119618.HpackCodec.HeaderField;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * Resource-safe sequential HTTP/2 probe session supporting TLS ALPN {@code h2} and cleartext {@code
 * h2c} prior knowledge, connection-scoped HPACK dynamic tables, pre-allocation 9-byte server {@code
 * SETTINGS} validation, {@code PADDED}/{@code PRIORITY}/{@code CONTINUATION} handling, and {@code
 * GOAWAY} reconnection.
 */
final class H2ProbeSession implements AutoCloseable {

  private static final byte[] clientPreface =
      "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".getBytes(ISO_8859_1);

  static final int MAX_FRAME_SIZE = 16384;
  static final int MAX_CONTINUATION_FRAMES = 16;
  static final int MAX_HEADER_BLOCK_BYTES = 32768;
  static final int MAX_RESPONSE_BODY_BYTES = 65536;
  static final int MAX_FRAMES_PER_STREAM = 64;
  static final int MAX_HEADERS_PER_STREAM = 9;

  static final int FRAME_DATA = 0x00;
  static final int FRAME_HEADERS = 0x01;
  static final int FRAME_RST_STREAM = 0x03;
  static final int FRAME_SETTINGS = 0x04;
  static final int FRAME_PING = 0x06;
  static final int FRAME_GOAWAY = 0x07;
  static final int FRAME_WINDOW_UPDATE = 0x08;
  static final int FRAME_CONTINUATION = 0x09;

  static final int FLAG_END_STREAM = 0x01;
  static final int FLAG_ACK = 0x01;
  static final int FLAG_END_HEADERS = 0x04;
  static final int FLAG_PADDED = 0x08;
  static final int FLAG_PRIORITY = 0x20;

  enum TransportMode {
    H2_TLS("h2"),
    H2C("h2c");

    final String wireLabel;

    TransportMode(String wireLabel) {
      this.wireLabel = wireLabel;
    }
  }

  interface TransportConnector {
    Socket connect(TransportMode mode, String host, int port, String sniHost, Duration timeout)
        throws IOException;
  }

  static TransportConnector defaultConnector(TsunamiSocketFactory socketFactory) {
    return (mode, host, port, sniHost, timeout) -> {
      Socket rawSocket = socketFactory.createSocket(host, port, timeout);
      int timeoutMs = (int) Math.min(timeout.toMillis(), Integer.MAX_VALUE);
      rawSocket.setSoTimeout(timeoutMs); // NOMUTANTS -- defensive socket read timeout
      if (mode == TransportMode.H2C) {
        return rawSocket;
      }

      try {
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(
            null, new TrustManager[] {new PermissiveTrustManager()}, new SecureRandom());
        SSLSocket sslSocket =
            (SSLSocket)
                sslContext
                    .getSocketFactory()
                    .createSocket(
                        rawSocket, host, port, true); // NOMUTANTS -- autoClose underlying socket
        sslSocket.setSoTimeout(timeoutMs); // NOMUTANTS -- defensive TLS read timeout
        SSLParameters params = sslSocket.getSSLParameters();
        params.setApplicationProtocols(new String[] {"h2"});
        if (!sniHost.isEmpty()) {
          try {
            params.setServerNames(ImmutableList.of(new SNIHostName(sniHost)));
          } catch (IllegalArgumentException e) {
            // Non-STD3 hostnames (such as internal container names containing underscores) are
            // rejected by SNIHostName; suppress SNI rather than aborting the TLS handshake.
            params.setServerNames(ImmutableList.of());
          }
        } else {
          params.setServerNames(ImmutableList.of());
        }
        sslSocket.setSSLParameters(params);
        sslSocket.startHandshake();
        String negotiated = sslSocket.getApplicationProtocol();
        if (negotiated == null || !negotiated.equals("h2")) {
          sslSocket.close();
          throw new IOException("Target did not negotiate ALPN h2");
        }
        return sslSocket;
      } catch (GeneralSecurityException e) { // NOMUTANTS -- JVM TLS provider initialization error
        rawSocket.close();
        throw new IOException("Failed to initialize TLS context", e);
      } catch (IOException | RuntimeException e) {
        rawSocket.close();
        throw e;
      }
    };
  }

  static final class H2Response {
    final String status;
    final String contentType;
    final byte[] body;

    H2Response(String status, String contentType, byte[] body) {
      this.status = status;
      this.contentType = contentType;
      this.body = body.clone();
    }
  }

  private static final class GoAwayReconnectException extends IOException {
    GoAwayReconnectException(String message) {
      super(message);
    }

    GoAwayReconnectException(String message, Throwable cause) {
      super(message, cause);
    }
  }

  private final TransportConnector connector;
  private final TransportMode mode;
  private final String host;
  private final int port;
  private final String sniHost;
  private final Duration timeout;

  private Socket socket;
  private HpackCodec.Decoder hpackDecoder;
  private int nextStreamId = 1;
  private boolean peerGoAway;

  private H2ProbeSession(
      TransportConnector connector,
      TransportMode mode,
      String host,
      int port,
      String sniHost,
      Duration timeout) {
    this.connector = connector;
    this.mode = mode;
    this.host = host;
    this.port = port;
    this.sniHost = sniHost;
    this.timeout = timeout;
  }

  static H2ProbeSession open(
      TransportConnector connector,
      TransportMode mode,
      String host,
      int port,
      String sniHost,
      Duration timeout)
      throws IOException {
    H2ProbeSession session = new H2ProbeSession(connector, mode, host, port, sniHost, timeout);
    session.connectSession();
    return session;
  }

  private void connectSession() throws IOException {
    closeSocketQuietly(); // NOMUTANTS -- closes prior socket on reconnect to prevent FD leaks
    Socket connected = connector.connect(mode, host, port, sniHost, timeout);
    try {
      InputStream input = connected.getInputStream();
      OutputStream output = connected.getOutputStream();

      ByteArrayOutputStream handshakeOut = new ByteArrayOutputStream();
      handshakeOut.writeBytes(clientPreface);
      writeRawFrame(handshakeOut, FRAME_SETTINGS, 0, 0, new byte[0]);
      handshakeOut.writeTo(output);
      output.flush(); // NOMUTANTS -- explicit socket flush

      // Pre-allocation 9-byte server SETTINGS header gate: immediately rejects HTTP/1.1
      // responses ("HTTP/1.1 400..." encodes 0x485454 = 4.74 MiB frame length).
      FrameHeader firstHdr = readFrameHeader(input);
      if (firstHdr.type != FRAME_SETTINGS
          || (firstHdr.flags & FLAG_ACK) != 0
          || firstHdr.streamId != 0
          || firstHdr.length % 6 != 0) {
        throw new IOException("Peer did not begin with a valid HTTP/2 server SETTINGS frame");
      }
      input.skipNBytes(firstHdr.length);
      sendFrame(output, FRAME_SETTINGS, FLAG_ACK, 0, new byte[0]);

      this.socket = connected;
      this.hpackDecoder = new HpackCodec.Decoder(HpackCodec.DEFAULT_DYNAMIC_TABLE_SIZE);
      this.nextStreamId = 1;
      this.peerGoAway = false;
    } catch (IOException | RuntimeException e) {
      try {
        connected.close();
      } catch (IOException suppressed) { // NOMUTANTS -- best-effort cleanup
        e.addSuppressed(suppressed);
      }
      throw e;
    }
  }

  H2Response roundTrip(List<HeaderField> headers, byte[] body) throws IOException {
    if (headers.size() > MAX_HEADERS_PER_STREAM) {
      throw new IOException("Outbound header count exceeds <10 safety ceiling");
    }
    if (peerGoAway) {
      connectSession();
    }
    boolean canRetry = nextStreamId > 1;
    try {
      return exchangeOnce(headers, body);
    } catch (GoAwayReconnectException e) {
      if (!canRetry) {
        throw e;
      }
      connectSession();
      return exchangeOnce(headers, body);
    }
  }

  private H2Response exchangeOnce(List<HeaderField> headers, byte[] body) throws IOException {
    int streamId = nextStreamId;
    nextStreamId += 2;

    InputStream in = socket.getInputStream();
    OutputStream out = socket.getOutputStream();

    byte[] headerBlock = HpackCodec.encodeLiteralNeverIndexed(headers);
    ByteArrayOutputStream reqBytes = new ByteArrayOutputStream();
    if (body.length == 0) {
      writeRawFrame(
          reqBytes, FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, streamId, headerBlock);
    } else {
      writeRawFrame(reqBytes, FRAME_HEADERS, FLAG_END_HEADERS, streamId, headerBlock);
      writeRawFrame(reqBytes, FRAME_DATA, FLAG_END_STREAM, streamId, body);
    }

    try {
      reqBytes.writeTo(out);
      out.flush(); // NOMUTANTS -- explicit socket flush
    } catch (IOException e) {
      throw new GoAwayReconnectException("Write failed on idle HTTP/2 connection", e);
    }

    boolean gotHeaders = false;
    String status = "";
    String contentType = "";
    ByteArrayOutputStream bodyBuf = new ByteArrayOutputStream();

    for (int frameCount = 0; frameCount < MAX_FRAMES_PER_STREAM; frameCount++) {
      FrameHeader fh;
      try {
        fh = readFrameHeader(in);
      } catch (EOFException e) {
        if (gotHeaders && !status.isEmpty()) {
          return new H2Response(status, contentType, bodyBuf.toByteArray());
        }
        throw new GoAwayReconnectException("EOF before response headers", e);
      } catch (SocketException | SSLException e) {
        if (!gotHeaders) {
          throw new GoAwayReconnectException("Connection reset before response headers", e);
        }
        throw e;
      }

      byte[] payload = readExactBytes(in, fh.length);

      switch (fh.type) {
        case FRAME_SETTINGS -> {
          if ((fh.flags & FLAG_ACK) == 0) {
            if (fh.streamId != 0 || fh.length % 6 != 0) {
              throw new IOException("Malformed HTTP/2 SETTINGS frame");
            }
            sendFrame(out, FRAME_SETTINGS, FLAG_ACK, 0, new byte[0]);
          }
        }
        case FRAME_PING -> {
          if (fh.streamId != 0 || fh.length != 8) {
            throw new IOException("Malformed HTTP/2 PING frame");
          }
          if ((fh.flags & FLAG_ACK) == 0) {
            sendFrame(out, FRAME_PING, FLAG_ACK, 0, payload);
          }
        }
        case FRAME_WINDOW_UPDATE -> {
          // Flow-control window updates require no action for <= 1-byte probe payloads.
        }
        case FRAME_HEADERS -> {
          byte[] stripped = stripHeadersPaddingAndPriority(payload, fh.flags);
          boolean endStream = (fh.flags & FLAG_END_STREAM) != 0;
          byte[] fullBlock =
              (fh.flags & FLAG_END_HEADERS) != 0
                  ? stripped
                  : readContinuations(in, fh.streamId, stripped);
          // Decode every HEADERS block through the connection-scoped HPACK decoder so dynamic
          // table state stays synchronized even if another stream were observed.
          ImmutableList<HeaderField> decoded = hpackDecoder.decodeHeaderBlock(fullBlock);
          if (fh.streamId == streamId && !gotHeaders) {
            String hdrStatus = "";
            String hdrContentType = "";
            for (HeaderField hf : decoded) {
              if (hf.name.equals(":status") && hdrStatus.isEmpty()) {
                hdrStatus = hf.value;
              } else if (Ascii.equalsIgnoreCase(hf.name, "content-type")
                  && hdrContentType.isEmpty()) {
                hdrContentType = hf.value;
              }
            }
            if (!endStream && hdrStatus.length() == 3 && hdrStatus.charAt(0) == '1') {
              continue;
            }
            gotHeaders = true;
            status = hdrStatus;
            contentType = hdrContentType;
          }
          if (fh.streamId == streamId && endStream) {
            return new H2Response(status, contentType, bodyBuf.toByteArray());
          }
        }
        case FRAME_DATA -> {
          if (fh.streamId != streamId) {
            continue;
          }
          byte[] dataSlice = stripDataPadding(payload, fh.flags);
          if (bodyBuf.size() + dataSlice.length > MAX_RESPONSE_BODY_BYTES) {
            throw new IOException("HTTP/2 response body exceeds maximum allowed size");
          }
          bodyBuf.writeBytes(dataSlice);
          if ((fh.flags & FLAG_END_STREAM) != 0) {
            return new H2Response(status, contentType, bodyBuf.toByteArray());
          }
          if (fh.length > 0 && !peerGoAway) {
            int inc = fh.length;
            byte[] wu =
                new byte[] {
                  (byte) ((inc >>> 24) & 0x7f), (byte) (inc >>> 16), (byte) (inc >>> 8), (byte) inc
                };
            try {
              sendFrame(out, FRAME_WINDOW_UPDATE, 0, 0, wu);
              sendFrame(out, FRAME_WINDOW_UPDATE, 0, streamId, wu);
            } catch (IOException ignored) { // NOMUTANTS -- best-effort flow-control update
              // Peer may close after transmitting response payload.
            }
          }
        }
        case FRAME_RST_STREAM -> {
          if (fh.streamId != streamId) {
            continue;
          }
          if (gotHeaders && !status.isEmpty()) {
            return new H2Response(status, contentType, bodyBuf.toByteArray());
          }
          throw new IOException("HTTP/2 stream reset before response headers");
        }
        case FRAME_GOAWAY -> {
          if (payload.length < 8) {
            throw new IOException("Malformed HTTP/2 GOAWAY frame");
          }
          peerGoAway = true;
          int lastStreamId =
              ((payload[0] & 0x7f) << 24)
                  | ((payload[1] & 0xff) << 16)
                  | ((payload[2] & 0xff) << 8)
                  | (payload[3] & 0xff);
          if (lastStreamId < streamId) {
            throw new GoAwayReconnectException("Server GOAWAY prior to active stream");
          }
        }
        case FRAME_CONTINUATION ->
            throw new IOException("Unexpected HTTP/2 CONTINUATION frame outside HEADERS block");
        default -> {
          // Ignore unknown extension frames per RFC 9113 Section 5.5.
        }
      }
    }

    throw new IOException("Exceeded maximum HTTP/2 frames per stream");
  }

  static byte[] readContinuations(InputStream in, int expectedStreamId, byte[] initialFragment)
      throws IOException {
    ByteArrayOutputStream full = new ByteArrayOutputStream();
    full.writeBytes(initialFragment);
    for (int i = 0; i < MAX_CONTINUATION_FRAMES; i++) {
      FrameHeader contHdr = readFrameHeader(in);
      if (contHdr.type != FRAME_CONTINUATION || contHdr.streamId != expectedStreamId) {
        throw new IOException(
            "Expected contiguous CONTINUATION frame on stream " + expectedStreamId);
      }
      if (full.size() + contHdr.length > MAX_HEADER_BLOCK_BYTES) {
        throw new IOException("HTTP/2 header block exceeds maximum size");
      }
      byte[] frag = readExactBytes(in, contHdr.length);
      full.writeBytes(frag);
      if ((contHdr.flags & FLAG_END_HEADERS) != 0) {
        return full.toByteArray();
      }
    }
    throw new IOException("Exceeded maximum HTTP/2 CONTINUATION frame count");
  }

  static byte[] stripHeadersPaddingAndPriority(byte[] payload, int flags) throws IOException {
    int start = 0;
    int end = payload.length;
    if ((flags & FLAG_PADDED) != 0) {
      if (payload.length < 1) {
        throw new IOException("Truncated PADDED HEADERS frame");
      }
      int padLen = payload[0] & 0xff;
      start += 1;
      end -= padLen;
    }
    if ((flags & FLAG_PRIORITY) != 0) {
      start += 5;
    }
    if (start > end || end > payload.length) {
      throw new IOException("Invalid HEADERS padding or priority bounds");
    }
    return Arrays.copyOfRange(payload, start, end);
  }

  static byte[] stripDataPadding(byte[] payload, int flags) throws IOException {
    if ((flags & FLAG_PADDED) == 0) {
      return payload;
    }
    if (payload.length < 1) {
      throw new IOException("Truncated PADDED DATA frame");
    }
    int padLen = payload[0] & 0xff;
    int end = payload.length - padLen;
    if (end < 1) {
      throw new IOException("Invalid DATA padding length");
    }
    return Arrays.copyOfRange(payload, 1, end);
  }

  static final class FrameHeader {
    final int length;
    final int type;
    final int flags;
    final int streamId;

    FrameHeader(int length, int type, int flags, int streamId) {
      this.length = length;
      this.type = type;
      this.flags = flags;
      this.streamId = streamId;
    }
  }

  static FrameHeader readFrameHeader(InputStream in) throws IOException {
    byte[] hdr = in.readNBytes(9);
    if (hdr.length == 0) {
      throw new EOFException("EOF reading HTTP/2 frame header");
    }
    if (hdr.length < 9) {
      throw new IOException("Truncated HTTP/2 9-byte frame header");
    }
    int length = ((hdr[0] & 0xff) << 16) | ((hdr[1] & 0xff) << 8) | (hdr[2] & 0xff);
    if (length > MAX_FRAME_SIZE) {
      throw new IOException("HTTP/2 frame length exceeds MAX_FRAME_SIZE: " + length);
    }
    int type = hdr[3] & 0xff;
    int flags = hdr[4] & 0xff;
    int streamId =
        ((hdr[5] & 0x7f) << 24)
            | ((hdr[6] & 0xff) << 16)
            | ((hdr[7] & 0xff) << 8)
            | (hdr[8] & 0xff);
    return new FrameHeader(length, type, flags, streamId);
  }

  private static byte[] readExactBytes(InputStream in, int length) throws IOException {
    byte[] buf = in.readNBytes(length);
    if (buf.length < length) {
      throw new IOException("Truncated HTTP/2 frame payload");
    }
    return buf;
  }

  static void writeRawFrame(
      ByteArrayOutputStream out, int type, int flags, int streamId, byte[] payload) {
    int len = payload.length;
    out.write((len >>> 16) & 0xff);
    out.write((len >>> 8) & 0xff);
    out.write(len & 0xff);
    out.write(type & 0xff);
    out.write(flags & 0xff);
    int maskedId = streamId & 0x7fffffff;
    out.write((maskedId >>> 24) & 0xff);
    out.write((maskedId >>> 16) & 0xff);
    out.write((maskedId >>> 8) & 0xff);
    out.write(maskedId & 0xff);
    out.writeBytes(payload);
  }

  private static void sendFrame(OutputStream out, int type, int flags, int streamId, byte[] payload)
      throws IOException {
    ByteArrayOutputStream buf = new ByteArrayOutputStream();
    writeRawFrame(buf, type, flags, streamId, payload);
    buf.writeTo(out);
    out.flush(); // NOMUTANTS -- explicit socket flush
  }

  private void closeSocketQuietly() {
    if (socket != null) {
      try {
        socket.close();
      } catch (IOException ignored) { // NOMUTANTS -- best-effort close
        // Ignore close error.
      }
      socket = null;
    }
  }

  @Override
  public void close() {
    closeSocketQuietly();
  }

  private static final class PermissiveTrustManager implements X509TrustManager {
    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) {}

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) {}

    @Override
    public X509Certificate[] getAcceptedIssuers() {
      return new X509Certificate[0]; // NOMUTANTS -- X509TrustManager interface contract
    }
  }
}
