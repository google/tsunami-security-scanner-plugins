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
package com.google.tsunami.plugins.detectors.rce.dask;

import static com.google.common.base.Preconditions.checkNotNull;
import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Ascii;
import com.google.common.base.Splitter;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.net.HostAndPort;
import com.google.tsunami.common.net.socket.TsunamiSocketFactory;
import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.function.LongSupplier;

/**
 * Pure-Java binary client for the Dask Distributed Comm protocol over TCP/TLS and RFC 6455
 * WebSocket transports.
 */
final class DaskCommClient {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private static final int MAX_FRAME_BYTES = 512 * 1024;
  private static final int MAX_TOTAL_REPLY_BYTES = 2 * 1024 * 1024;
  private static final int MAX_FRAMES_COUNT = 16;
  private static final int MAX_WS_FRAMES_PER_MESSAGE = 64;
  private static final int MAX_MSGPACK_DEPTH = 16;
  private static final int MAX_COLLECTION_SIZE = 4096;
  private static final int MAX_WS_HEADER_BYTES = 16 * 1024;
  private static final int MAX_WORKER_ADDR_BYTES = 4096;

  // MsgPack map: {"compression": nil, "python": [3, 10, 0], "pickle-protocol": 4}
  private static final byte[] commHandshakeFrame =
      new byte[] {
        (byte) 0x83,
        (byte) 0xab,
        'c',
        'o',
        'm',
        'p',
        'r',
        'e',
        's',
        's',
        'i',
        'o',
        'n',
        (byte) 0xc0,
        (byte) 0xa6,
        'p',
        'y',
        't',
        'h',
        'o',
        'n',
        (byte) 0x93,
        0x03,
        0x0a,
        0x00,
        (byte) 0xaf,
        'p',
        'i',
        'c',
        'k',
        'l',
        'e',
        '-',
        'p',
        'r',
        'o',
        't',
        'o',
        'c',
        'o',
        'l',
        0x04
      };

  // MsgPack map: {"op": "identity", "reply": true}
  private static final byte[] identityRequestFrame =
      new byte[] {
        (byte) 0x82,
        (byte) 0xa2,
        'o',
        'p',
        (byte) 0xa8,
        'i',
        'd',
        'e',
        'n',
        't',
        'i',
        't',
        'y',
        (byte) 0xa5,
        'r',
        'e',
        'p',
        'l',
        'y',
        (byte) 0xc3
      };

  // Pickle protocol 2 representation of Python stdlib operator.add
  private static final byte[] operatorAddPickle =
      new byte[] {
        (byte) 0x80,
        0x02,
        'c',
        'o',
        'p',
        'e',
        'r',
        'a',
        't',
        'o',
        'r',
        '\n',
        'a',
        'd',
        'd',
        '\n',
        'q',
        0x00,
        '.'
      };

  // Pickle protocol 2 representation of empty dict {}
  private static final byte[] emptyKwargsPickle =
      new byte[] {(byte) 0x80, 0x02, '}', 'q', 0x00, '.'};

  private final TsunamiSocketFactory socketFactory;
  private final Duration timeout;
  private final SecureRandom secureRandom = new SecureRandom();

  DaskCommClient(TsunamiSocketFactory socketFactory, Duration timeout) {
    this.socketFactory = checkNotNull(socketFactory);
    this.timeout = checkNotNull(timeout);
  }

  sealed interface ProbeOutcome {
    default Optional<CommResult> result() {
      return Optional.empty();
    }

    record Vulnerable(CommResult commResult) implements ProbeOutcome {
      public Vulnerable {
        checkNotNull(commResult);
      }

      @Override
      public Optional<CommResult> result() {
        return Optional.of(commResult);
      }
    }

    enum NonVulnerable implements ProbeOutcome {
      CONFIRMED_DASK_NOT_VULNERABLE,
      NOT_DASK
    }
  }

  record CommResult(
      String commAddress,
      String daemonType,
      String daemonId,
      String handler,
      int operandA,
      int operandB,
      long computedSum) {}

  private record DaemonIdentity(
      String type, String id, Optional<String> workerTarget, Optional<String> nannyWorkerTarget) {}

  interface FrameTransport {
    void writeFrames(List<byte[]> frames) throws IOException;

    /**
     * Reads one or more Dask Comm frames; throws {@link IOException} if the frame count is <= 0.
     */
    List<byte[]> readFrames() throws IOException;
  }

  ProbeOutcome probeTcp(String host, int port, boolean useTls, int a, int b) {
    String commAddress = HostAndPort.fromParts(host, port).toString();
    try (Socket socket = openSocket(host, port, useTls)) {
      InputStream in = new BufferedInputStream(new DeadlineInputStream(socket, timeout), 8192);
      OutputStream out = socket.getOutputStream();
      return runCommSession(new TcpFrameTransport(in, out), commAddress, a, b);
    } catch (IOException e) {
      logger.atFine().withCause(e).log( // NOMUTANTS -- diagnostic logging
          "Dask TCP Comm probe to %s failed.", commAddress);
      return ProbeOutcome.NonVulnerable.NOT_DASK;
    }
  }

  Optional<CommResult> probeWebSocket(
      String host, int port, String wsPath, boolean useTls, int a, int b) {
    String authority = HostAndPort.fromParts(host, port).toString();
    try (Socket socket = openSocket(host, port, useTls)) {
      BufferedInputStream in =
          new BufferedInputStream(new DeadlineInputStream(socket, timeout), 8192);
      OutputStream out = socket.getOutputStream();
      if (!performWebSocketUpgrade(in, out, authority, wsPath)) {
        return Optional.empty();
      }
      return runCommSession(new WebSocketFrameTransport(in, out, secureRandom), authority, a, b)
          .result();
    } catch (IOException e) {
      logger.atFine().withCause(e).log( // NOMUTANTS -- diagnostic logging
          "Dask WebSocket Comm probe to %s failed.", authority);
      return Optional.empty();
    }
  }

  @VisibleForTesting
  static final class DeadlineInputStream extends FilterInputStream {
    private final Socket socket;
    private final LongSupplier nanoClock;
    private final long deadlineNanos;

    DeadlineInputStream(Socket socket, Duration timeout) throws IOException {
      this(socket, timeout, System::nanoTime);
    }

    @VisibleForTesting
    DeadlineInputStream(Socket socket, Duration timeout, LongSupplier nanoClock)
        throws IOException {
      super(socket.getInputStream());
      this.socket = socket;
      this.nanoClock = checkNotNull(nanoClock);
      this.deadlineNanos = this.nanoClock.getAsLong() + timeout.toNanos();
    }

    private void applyRemainingTimeout() throws IOException {
      long remainingMillis = Duration.ofNanos(deadlineNanos - nanoClock.getAsLong()).toMillis();
      if (remainingMillis <= 0) {
        throw new SocketTimeoutException("Dask Comm session deadline exceeded");
      }
      socket.setSoTimeout((int) Math.min(remainingMillis, Integer.MAX_VALUE));
    }

    @Override
    public int read() throws IOException {
      applyRemainingTimeout();
      return super.read();
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
      applyRemainingTimeout();
      return super.read(b, off, len);
    }
  }

  // Compose createSocket + wrapWithSsl instead of createSslSocket so plainSocket is closed if SSL
  // wrapping or startHandshake() throws (DefaultTsunamiSocketFactory.createSslSocket does not close
  // plainSocket on failure).
  private Socket openSocket(String host, int port, boolean useTls) throws IOException {
    Socket plainSocket = socketFactory.createSocket(host, port, timeout);
    if (!useTls) {
      return plainSocket;
    }
    try {
      return socketFactory.wrapWithSsl(plainSocket, host, port, /* autoClose= */ true);
    } catch (Throwable t) {
      try (plainSocket) {
        throw t;
      }
    }
  }

  @VisibleForTesting
  boolean performWebSocketUpgrade(InputStream in, OutputStream out, String authority, String wsPath)
      throws IOException {
    byte[] nonce = new byte[16];
    secureRandom.nextBytes(nonce);
    String wsKey = Base64.getEncoder().encodeToString(nonce);
    String normalizedPath = (wsPath.isEmpty() || wsPath.charAt(0) != '/') ? "/" + wsPath : wsPath;

    String request =
        "GET "
            + normalizedPath
            + " HTTP/1.1\r\n"
            + "Host: "
            + authority
            + "\r\n"
            + "Upgrade: websocket\r\n"
            + "Connection: Upgrade\r\n"
            + "Sec-WebSocket-Key: "
            + wsKey
            + "\r\n"
            + "Sec-WebSocket-Version: 13\r\n\r\n";
    out.write(request.getBytes(US_ASCII));
    out.flush(); // NOMUTANTS -- explicit socket flush

    String headers = readHttpHeaderBlock(in);
    if (!headers.startsWith("HTTP/1.1 101")) {
      return false;
    }

    boolean hasUpgradeWebsocket = false;
    boolean hasConnectionUpgrade = false;
    boolean hasAcceptKey = false;
    for (String line : Splitter.on("\r\n").split(headers)) {
      int colon = line.indexOf(':');
      if (colon == -1) {
        continue;
      }
      String headerName = Ascii.toLowerCase(line.substring(0, colon).trim());
      String headerVal = line.substring(colon + 1).trim();
      switch (headerName) {
        case "upgrade" -> {
          if (Ascii.equalsIgnoreCase(headerVal, "websocket")) {
            hasUpgradeWebsocket = true;
          }
        }
        case "connection" -> {
          for (String token : headerVal.split(",", -1)) {
            if (Ascii.equalsIgnoreCase(token.trim(), "upgrade")) {
              hasConnectionUpgrade = true;
              break;
            }
          }
        }
        case "sec-websocket-accept" -> {
          if (!headerVal.isEmpty()) {
            hasAcceptKey = true;
          }
        }
        default -> {}
      }
    }
    return hasUpgradeWebsocket && hasConnectionUpgrade && hasAcceptKey;
  }

  private static String readHttpHeaderBlock(InputStream in) throws IOException {
    ByteArrayOutputStream buf = new ByteArrayOutputStream(256);
    // NOMUTANTS(AOR): Any valid HTTP/1.1 101 header starts with 'H', which resets matched to 0.
    int matched = 0;
    while (buf.size() < MAX_WS_HEADER_BYTES) {
      int b = in.read();
      if (b < 0) {
        return "";
      }
      buf.write(b);
      if ((matched == 1 && b == '\n')
          || (matched == 2 && b == '\r')
          || (matched == 3 && b == '\n')) {
        matched++;
        if (matched == 4) {
          return buf.toString(US_ASCII);
        }
      } else {
        matched = (b == '\r') ? 1 : 0;
      }
    }
    return "";
  }

  private static ProbeOutcome runCommSession(
      FrameTransport transport, String commAddress, int a, int b) throws IOException {
    // Step 1: Exchange Dask Comm binary handshake.
    transport.writeFrames(ImmutableList.of(commHandshakeFrame));
    List<byte[]> hsFrames = transport.readFrames();
    if (hsFrames.size() != 1 || !isValidHandshakeReply(hsFrames.get(0))) {
      return ProbeOutcome.NonVulnerable.NOT_DASK;
    }

    // Once Step 1 confirms binary Dask Comm framing (which HTTP/WebSocket servers do not emit),
    // any subsequent I/O failure or blocked/oversized reply indicates a confirmed Dask port
    // so raw TCP callers do not fall back to sending HTTP GET bytes.
    try {
      // Step 2: Query {"op": "identity", "reply": true} to verify a live Dask Scheduler or Worker
      // and reject echo servers.
      transport.writeFrames(ImmutableList.of(identityRequestFrame));
      List<byte[]> idFrames = transport.readFrames();
      Optional<DaemonIdentity> daemonInfo = parseIdentityReply(idFrames.get(0));
      if (daemonInfo.isEmpty()) {
        return ProbeOutcome.NonVulnerable.CONFIRMED_DASK_NOT_VULNERABLE;
      }
      String daemonType = daemonInfo.get().type();
      String daemonId = daemonInfo.get().id();

      // Step 3: Non-destructive active arithmetic evaluation via operator.add(a, b).
      long expectedSum = (long) a + (long) b;
      byte[] argsPickle = buildArgsTuplePickle(a, b);
      if (!Objects.equals(daemonType, "Scheduler")) {
        transport.writeFrames(
            ImmutableList.of(
                buildRunOpFrame("run", operatorAddPickle, argsPickle, emptyKwargsPickle)));
        List<byte[]> replyFrames = transport.readFrames();
        if (verifyDirectRunReply(replyFrames, expectedSum)) {
          return new ProbeOutcome.Vulnerable(
              new CommResult(commAddress, daemonType, daemonId, "run", a, b, expectedSum));
        }
        return ProbeOutcome.NonVulnerable.CONFIRMED_DASK_NOT_VULNERABLE;
      }

      transport.writeFrames(
          ImmutableList.of(
              buildRunOpFrame("run_function", operatorAddPickle, argsPickle, emptyKwargsPickle)));
      List<byte[]> runFnFrames = transport.readFrames();
      if (verifyDirectRunReply(runFnFrames, expectedSum)) {
        return new ProbeOutcome.Vulnerable(
            new CommResult(commAddress, daemonType, daemonId, "run_function", a, b, expectedSum));
      }

      transport.writeFrames(
          ImmutableList.of(
              buildBroadcastRunFrame(
                  operatorAddPickle,
                  argsPickle,
                  emptyKwargsPickle,
                  /* targetNanny= */ false,
                  daemonInfo.get().workerTarget())));
      List<byte[]> bcastFrames = transport.readFrames();
      if (verifyBroadcastRunReply(bcastFrames, expectedSum)) {
        return new ProbeOutcome.Vulnerable(
            new CommResult(commAddress, daemonType, daemonId, "broadcast(run)", a, b, expectedSum));
      }

      transport.writeFrames(
          ImmutableList.of(
              buildBroadcastRunFrame(
                  operatorAddPickle,
                  argsPickle,
                  emptyKwargsPickle,
                  /* targetNanny= */ true,
                  daemonInfo.get().nannyWorkerTarget())));
      List<byte[]> nannyBcastFrames = transport.readFrames();
      if (verifyBroadcastRunReply(nannyBcastFrames, expectedSum)) {
        return new ProbeOutcome.Vulnerable(
            new CommResult(
                commAddress, daemonType, daemonId, "broadcast(nanny_run)", a, b, expectedSum));
      }
      return ProbeOutcome.NonVulnerable.CONFIRMED_DASK_NOT_VULNERABLE;
    } catch (IOException e) {
      logger.atFine().withCause(e).log( // NOMUTANTS -- diagnostic logging
          "Confirmed Dask endpoint on %s rejected, exceeded reply limits, or closed connection"
              + " during probe.",
          commAddress);
      return ProbeOutcome.NonVulnerable.CONFIRMED_DASK_NOT_VULNERABLE;
    }
  }

  private static final class TcpFrameTransport implements FrameTransport {
    private final InputStream in;
    private final OutputStream out;

    TcpFrameTransport(InputStream in, OutputStream out) {
      this.in = in;
      this.out = out;
    }

    @Override
    public void writeFrames(List<byte[]> frames) throws IOException {
      long totalPayload = 0;
      for (byte[] f : frames) {
        totalPayload += f.length;
      }
      long nFrames = frames.size();
      long nosplitBytes = 8L * (1L + nFrames) + totalPayload;

      ByteBuffer hdr = ByteBuffer.allocate((int) (16 + 8 * nFrames)).order(ByteOrder.LITTLE_ENDIAN);
      hdr.putLong(nosplitBytes);
      hdr.putLong(nFrames);
      for (byte[] f : frames) {
        hdr.putLong(f.length);
      }
      out.write(hdr.array());
      for (byte[] f : frames) {
        out.write(f);
      }
      out.flush(); // NOMUTANTS -- explicit socket flush
    }

    @Override
    public List<byte[]> readFrames() throws IOException {
      ByteBuffer hdr = ByteBuffer.wrap(readExact(in, 16)).order(ByteOrder.LITTLE_ENDIAN);
      long nosplitBytes = hdr.getLong();
      long nFrames = hdr.getLong();
      if (nFrames <= 0
          || nFrames > MAX_FRAMES_COUNT
          || nosplitBytes <= 0
          || nosplitBytes > (long) MAX_TOTAL_REPLY_BYTES + 8L * (1L + MAX_FRAMES_COUNT)) {
        throw new IOException("Invalid Dask TCP frame count or header size");
      }

      ByteBuffer lensBuf =
          ByteBuffer.wrap(readExact(in, (int) (nFrames * 8))).order(ByteOrder.LITTLE_ENDIAN);
      int[] lengths = new int[(int) nFrames];
      long sumLengths = 0;
      for (int i = 0; i < nFrames; i++) {
        long fLen = lensBuf.getLong();
        if (fLen < 0 || fLen > MAX_FRAME_BYTES || sumLengths + fLen > MAX_TOTAL_REPLY_BYTES) {
          throw new IOException("Dask TCP frame exceeds bounds");
        }
        lengths[i] = (int) fLen;
        sumLengths += fLen;
      }
      if (nosplitBytes != 8L * (1L + nFrames) + sumLengths) {
        throw new IOException("Mismatched Dask TCP frames_nosplit_nbytes prefix");
      }

      List<byte[]> frames = new ArrayList<>((int) nFrames);
      for (int len : lengths) {
        frames.add(readExact(in, len));
      }
      return frames;
    }
  }

  @VisibleForTesting
  static final class WebSocketFrameTransport implements FrameTransport {
    private final InputStream in;
    private final OutputStream out;
    private final SecureRandom rng;

    WebSocketFrameTransport(InputStream in, OutputStream out, SecureRandom rng) {
      this.in = in;
      this.out = out;
      this.rng = rng;
    }

    @Override
    public void writeFrames(List<byte[]> frames) throws IOException {
      byte[] countBytes =
          ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(frames.size()).array();
      writeWsBinaryMessage(countBytes);
      for (byte[] frame : frames) {
        writeWsBinaryMessage(frame);
      }
      out.flush(); // NOMUTANTS -- explicit socket flush
    }

    @Override
    public List<byte[]> readFrames() throws IOException {
      byte[] countMsg = readWsBinaryMessage(MAX_FRAME_BYTES);
      if (countMsg.length != 8) {
        throw new IOException("Invalid Dask WS frame count payload");
      }
      long nFrames = ByteBuffer.wrap(countMsg).order(ByteOrder.LITTLE_ENDIAN).getLong();
      if (nFrames <= 0 || nFrames > MAX_FRAMES_COUNT) {
        throw new IOException("Dask WS frame count out of bounds");
      }
      List<byte[]> frames = new ArrayList<>((int) nFrames);
      int remainingReplyBytes = MAX_TOTAL_REPLY_BYTES;
      for (int i = 0; i < nFrames; i++) {
        byte[] frame = readWsBinaryMessage(Math.min(MAX_FRAME_BYTES, remainingReplyBytes));
        remainingReplyBytes -= frame.length;
        frames.add(frame);
      }
      return frames;
    }

    private void writeWsBinaryMessage(byte[] payload) throws IOException {
      byte[] maskKey = new byte[4];
      rng.nextBytes(maskKey);

      // NOMUTANTS(AOR): Initial buffer capacity hint only; output bytes match.
      ByteArrayOutputStream frame = new ByteArrayOutputStream(payload.length + 10);
      frame.write(0x82); // FIN=1, binary opcode 0x2
      if (payload.length < 126) {
        frame.write(0x80 | payload.length);
      } else {
        frame.write(0x80 | 126);
        frame.write((payload.length >> 8) & 0xff);
        frame.write(payload.length & 0xff);
      }
      frame.write(maskKey);
      for (int i = 0; i < payload.length; i++) {
        frame.write(payload[i] ^ maskKey[i & 3]);
      }
      frame.writeTo(out);
    }

    private byte[] readWsBinaryMessage(int maxBytes) throws IOException {
      ByteArrayOutputStream assembled = new ByteArrayOutputStream();
      boolean expectingContinuation = false;

      for (int frameCount = 0; frameCount < MAX_WS_FRAMES_PER_MESSAGE; frameCount++) {
        byte[] hdr = readExact(in, 2);
        boolean fin = (hdr[0] & 0x80) != 0;
        int opcode = hdr[0] & 0x0f;
        boolean masked = (hdr[1] & 0x80) != 0;
        long payLen = hdr[1] & 0x7f;

        if (payLen == 126) {
          byte[] ext = readExact(in, 2);
          payLen = ((ext[0] & 0xffL) << 8) | (ext[1] & 0xffL);
        } else if (payLen == 127) {
          payLen = ByteBuffer.wrap(readExact(in, 8)).order(ByteOrder.BIG_ENDIAN).getLong();
        }
        if (payLen < 0 || payLen > maxBytes || assembled.size() + payLen > maxBytes) {
          throw new IOException("WebSocket payload exceeds maximum frame size");
        }

        byte[] maskKey = masked ? readExact(in, 4) : new byte[0];
        byte[] chunk = readExact(in, (int) payLen);
        if (masked) {
          for (int i = 0; i < chunk.length; i++) {
            chunk[i] = (byte) (chunk[i] ^ maskKey[i & 3]);
          }
        }

        switch (opcode) {
          case 0x09, 0x0a -> {
            // Ignore ping/pong control frames.
          }
          case 0x08 -> throw new IOException("WebSocket closed by peer");
          case 0x02 -> {
            if (expectingContinuation) {
              throw new IOException("Unexpected WebSocket binary opcode during continuation");
            }
            assembled.write(chunk);
            if (fin) {
              return assembled.toByteArray();
            }
            expectingContinuation = true;
          }
          case 0x00 -> {
            if (!expectingContinuation) {
              throw new IOException("Unexpected uninitiated WebSocket continuation frame");
            }
            assembled.write(chunk);
            if (fin) {
              return assembled.toByteArray();
            }
          }
          default -> throw new IOException("Unsupported WebSocket opcode: " + opcode);
        }
      }
      throw new IOException("WebSocket message exceeded maximum frame count");
    }
  }

  private static byte[] readExact(InputStream in, int length) throws IOException {
    byte[] data = in.readNBytes(length);
    if (data.length != length) {
      throw new EOFException("Unexpected EOF while reading Dask frame");
    }
    return data;
  }

  private static byte[] buildArgsTuplePickle(int a, int b) {
    ByteBuffer buf = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
    buf.put((byte) 0x80);
    buf.put((byte) 0x02);
    buf.put((byte) 'J');
    buf.putInt(a);
    buf.put((byte) 'J');
    buf.putInt(b);
    buf.put((byte) 0x86); // TUPLE2
    buf.put((byte) 'q');
    buf.put((byte) 0x00);
    buf.put((byte) '.');
    return buf.array();
  }

  private static byte[] buildRunOpFrame(String op, byte[] fnPkl, byte[] argsPkl, byte[] kwargsPkl) {
    ByteArrayOutputStream out = new ByteArrayOutputStream(128);
    out.write(0x86); // fixmap(6)
    writeMpStr(out, "op");
    writeMpStr(out, op);
    writeMpStr(out, "function");
    writeMpBin8(out, fnPkl);
    writeMpStr(out, "args");
    writeMpBin8(out, argsPkl);
    writeMpStr(out, "kwargs");
    writeMpBin8(out, kwargsPkl);
    writeMpStr(out, "wait");
    out.write(0xc3);
    writeMpStr(out, "reply");
    out.write(0xc3);
    return out.toByteArray();
  }

  private static byte[] buildBroadcastRunFrame(
      byte[] fnPkl,
      byte[] argsPkl,
      byte[] kwargsPkl,
      boolean targetNanny,
      Optional<String> targetWorker) {
    ByteArrayOutputStream out = new ByteArrayOutputStream(192);
    int topEntries = 3 + (targetNanny ? 1 : 0) + (targetWorker.isPresent() ? 1 : 0);
    out.write(0x80 | topEntries);
    writeMpStr(out, "op");
    writeMpStr(out, "broadcast");
    writeMpStr(out, "msg");
    out.write(0x85); // fixmap(5)
    writeMpStr(out, "op");
    writeMpStr(out, "run");
    writeMpStr(out, "function");
    writeMpBin8(out, fnPkl);
    writeMpStr(out, "args");
    writeMpBin8(out, argsPkl);
    writeMpStr(out, "kwargs");
    writeMpBin8(out, kwargsPkl);
    writeMpStr(out, "wait");
    out.write(0xc3);
    if (targetWorker.isPresent()) {
      writeMpStr(out, "workers");
      out.write(0x91); // fixarray(1)
      writeMpStr(out, targetWorker.get());
    }
    if (targetNanny) {
      writeMpStr(out, "nanny");
      out.write(0xc3);
    }
    writeMpStr(out, "reply");
    out.write(0xc3);
    return out.toByteArray();
  }

  @VisibleForTesting
  static void writeMpStr(ByteArrayOutputStream out, String s) {
    byte[] raw = s.getBytes(UTF_8);
    if (raw.length <= 31) {
      out.write(0xa0 | raw.length);
    } else if (raw.length <= 255) {
      out.write(0xd9);
      out.write(raw.length);
    } else if (raw.length <= 65535) {
      out.write(0xda);
      out.write((raw.length >> 8) & 0xff);
      out.write(raw.length & 0xff);
    } else {
      throw new IllegalArgumentException("MsgPack string exceeds 65535 bytes: " + raw.length);
    }
    out.writeBytes(raw);
  }

  private static void writeMpBin8(ByteArrayOutputStream out, byte[] b) {
    out.write(0xc4);
    out.write(b.length);
    out.writeBytes(b);
  }

  private static boolean isValidHandshakeReply(byte[] frame) {
    Optional<Object> decoded = decodeMsgPack(frame);
    if (decoded.isEmpty() || !(decoded.get() instanceof Map<?, ?> map)) {
      return false;
    }
    return map.get("pickle-protocol") instanceof Long;
  }

  private static Optional<DaemonIdentity> parseIdentityReply(byte[] frame) {
    Optional<Object> decoded = decodeMsgPack(frame);
    if (decoded.isEmpty() || !(decoded.get() instanceof Map<?, ?> map)) {
      return Optional.empty();
    }
    if (!(map.get("type") instanceof String daemonType)
        || !(map.get("id") instanceof String daemonId)
        || daemonId.trim().isEmpty()) {
      return Optional.empty();
    }
    Optional<String> workerTarget = Optional.empty();
    Optional<String> nannyWorkerTarget = Optional.empty();
    if (map.get("workers") instanceof Map<?, ?> workersMap) {
      for (Map.Entry<?, ?> entry : workersMap.entrySet()) {
        String workerAddr = String.valueOf(entry.getKey());
        if (workerAddr.isEmpty() || workerAddr.getBytes(UTF_8).length > MAX_WORKER_ADDR_BYTES) {
          continue;
        }
        if (workerTarget.isEmpty()) {
          workerTarget = Optional.of(workerAddr);
        }
        if (nannyWorkerTarget.isEmpty()
            && entry.getValue() instanceof Map<?, ?> workerInfo
            && workerInfo.get("nanny") instanceof String nannyAddr
            && !nannyAddr.isEmpty()) {
          nannyWorkerTarget = Optional.of(workerAddr);
        }
        if (workerTarget.isPresent() && nannyWorkerTarget.isPresent()) {
          break; // NOMUTANTS -- early-exit optimization once both targets are found
        }
      }
    }
    if (nannyWorkerTarget.isEmpty()) {
      nannyWorkerTarget = workerTarget;
    }
    return switch (daemonType) {
      case "Scheduler", "Worker", "CUDAWorker", "Nanny" ->
          Optional.of(new DaemonIdentity(daemonType, daemonId, workerTarget, nannyWorkerTarget));
      default -> Optional.empty();
    };
  }

  private enum WorkerResultMatch {
    MATCHED,
    NEEDS_SUBFRAME,
    NO_MATCH
  }

  private static boolean verifyDirectRunReply(List<byte[]> frames, long expectedSum) {
    if (frames.isEmpty()) {
      return false;
    }
    Optional<Object> decoded = decodeMsgPack(frames.get(0));
    if (decoded.isEmpty() || !(decoded.get() instanceof Map<?, ?> map)) {
      return false;
    }
    WorkerResultMatch match = classifyWorkerStatusMap(map, expectedSum);
    return match == WorkerResultMatch.MATCHED
        || (match == WorkerResultMatch.NEEDS_SUBFRAME
            && anySubFrameMatchesSum(frames.subList(1, frames.size()), expectedSum));
  }

  @VisibleForTesting
  static boolean verifyBroadcastRunReply(List<byte[]> frames, long expectedSum) {
    if (frames.isEmpty()) {
      return false;
    }
    Optional<Object> decoded = decodeMsgPack(frames.get(0));
    if (decoded.isEmpty() || !(decoded.get() instanceof Map<?, ?> outer)) {
      return false;
    }
    boolean needsSubFrame = false;
    for (Object entry : outer.values()) {
      if (!(entry instanceof Map<?, ?> workerMap)) {
        continue;
      }
      WorkerResultMatch match = classifyWorkerStatusMap(workerMap, expectedSum);
      if (match == WorkerResultMatch.MATCHED) {
        return true;
      }
      if (match == WorkerResultMatch.NEEDS_SUBFRAME) {
        needsSubFrame = true;
      }
    }
    return needsSubFrame && anySubFrameMatchesSum(frames.subList(1, frames.size()), expectedSum);
  }

  private static boolean anySubFrameMatchesSum(List<byte[]> subFrames, long expectedSum) {
    for (byte[] sf : subFrames) {
      OptionalLong parsed = extractSubFramePickleInt64(sf);
      if (parsed.isPresent() && parsed.getAsLong() == expectedSum) {
        return true;
      }
    }
    return false;
  }

  private static WorkerResultMatch classifyWorkerStatusMap(Map<?, ?> map, long expectedSum) {
    if (!Objects.equals(map.get("status"), "OK")) {
      return WorkerResultMatch.NO_MATCH;
    }
    Object resVal = map.get("result");
    if (resVal instanceof Long directInt) {
      return directInt == expectedSum ? WorkerResultMatch.MATCHED : WorkerResultMatch.NO_MATCH;
    }
    if (resVal instanceof byte[] directBytes) {
      OptionalLong parsed = parsePickleInt64(directBytes);
      return parsed.isPresent() && parsed.getAsLong() == expectedSum
          ? WorkerResultMatch.MATCHED
          : WorkerResultMatch.NO_MATCH;
    }
    if (!(resVal instanceof Map<?, ?> resMap)) {
      return WorkerResultMatch.NO_MATCH;
    }
    if (resMap.get("__Pickled__") instanceof byte[] pickledBytes) {
      OptionalLong parsed = parsePickleInt64(pickledBytes);
      return parsed.isPresent() && parsed.getAsLong() == expectedSum
          ? WorkerResultMatch.MATCHED
          : WorkerResultMatch.NO_MATCH;
    }
    return (resMap.containsKey("__Serialized__") || resMap.containsKey("__Pickled__"))
        ? WorkerResultMatch.NEEDS_SUBFRAME
        : WorkerResultMatch.NO_MATCH;
  }

  private static OptionalLong extractSubFramePickleInt64(byte[] sf) {
    OptionalLong direct = parsePickleInt64(sf);
    if (direct.isPresent()) {
      return direct;
    }
    Optional<Object> decoded = decodeMsgPack(sf);
    if (decoded.isEmpty() || !(decoded.get() instanceof Map<?, ?> subHeader)) {
      return OptionalLong.empty();
    }
    if (!(subHeader.get("pickled-obj") instanceof byte[] pickledObj)) {
      return OptionalLong.empty();
    }
    return parsePickleInt64(pickledObj);
  }

  @VisibleForTesting
  static OptionalLong parsePickleInt64(byte[] data) {
    int pos = 0;
    if (pos < data.length && (data[pos] & 0xff) == 0x80) { // PROTO
      pos += 2;
      if (pos > data.length) {
        return OptionalLong.empty();
      }
    }
    if (pos < data.length && (data[pos] & 0xff) == 0x95) { // FRAME (protocol >= 4)
      pos += 9;
      if (pos > data.length) {
        return OptionalLong.empty();
      }
    }
    if (pos >= data.length) {
      return OptionalLong.empty();
    }

    long val;
    int opcode = data[pos] & 0xff;
    switch (opcode) {
      case 'J' -> {
        if (pos + 5 > data.length) {
          return OptionalLong.empty();
        }
        val = ByteBuffer.wrap(data, pos + 1, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
        pos += 5;
      }
      case 'I' -> {
        int start = pos + 1;
        int nl = start;
        while (nl < data.length && data[nl] != '\n') {
          nl++;
        }
        String text = new String(data, start, nl - start, US_ASCII);
        if (text.endsWith("L")) {
          text = text.substring(0, text.length() - 1);
        }
        try {
          val = Long.parseLong(text);
        } catch (NumberFormatException e) {
          return OptionalLong.empty();
        }
        pos = nl + 1;
      }
      case 0x8a -> { // LONG1
        if (pos + 2 > data.length) {
          return OptionalLong.empty();
        }
        int n = data[pos + 1] & 0xff;
        if (n <= 0 || n > 8 || pos + 2 + n > data.length) {
          return OptionalLong.empty();
        }
        long u = 0;
        for (int i = 0; i < n; i++) {
          u |= (data[pos + 2 + i] & 0xffL) << (8 * i);
        }
        if (n < 8 && (data[pos + 1 + n] & 0x80) != 0) {
          u |= -1L << (8 * n);
        }
        val = u;
        pos += 2 + n;
      }
      default -> {
        return OptionalLong.empty();
      }
    }

    while (pos < data.length) {
      int nextOp = data[pos] & 0xff;
      switch (nextOp) {
        case 0x94 -> pos++;
        case 'q' -> pos += 2;
        case 'r' -> pos += 5;
        case '.' -> {
          return pos + 1 == data.length ? OptionalLong.of(val) : OptionalLong.empty();
        }
        default -> {
          return OptionalLong.empty();
        }
      }
    }
    return OptionalLong.empty();
  }

  @VisibleForTesting
  static Optional<Object> decodeMsgPack(byte[] data) {
    MpReader reader = new MpReader(data);
    try {
      return Optional.of(reader.readValue(0));
    } catch (IOException e) {
      return Optional.empty();
    }
  }

  private static final class MpReader {
    private static final Object NIL_SENTINEL = new Object();
    private final byte[] data;
    private int pos;

    MpReader(byte[] data) {
      this.data = data;
    }

    int readU8() throws IOException {
      if (pos >= data.length) {
        throw new EOFException();
      }
      return data[pos++] & 0xff;
    }

    void skipN(int n) throws IOException {
      if (n < 0 || pos + n > data.length) {
        throw new EOFException();
      }
      pos += n;
    }

    byte[] readN(int n) throws IOException {
      if (n < 0 || pos + n > data.length) {
        throw new EOFException();
      }
      byte[] slice = new byte[n];
      System.arraycopy(data, pos, slice, 0, n);
      pos += n;
      return slice;
    }

    Object readValue(int depth) throws IOException {
      if (depth > MAX_MSGPACK_DEPTH) {
        throw new IOException("MsgPack max depth exceeded");
      }
      int tag = readU8();
      if (tag <= 0x7f) {
        return (long) tag;
      }
      if (tag >= 0xe0) {
        return (long) ((byte) tag);
      }
      if (tag >= 0x80 && tag <= 0x8f) {
        return readMap(tag & 0x0f, depth);
      }
      if (tag >= 0x90 && tag <= 0x9f) {
        return readArray(tag & 0x0f, depth);
      }
      if (tag >= 0xa0 && tag <= 0xbf) {
        return new String(readN(tag & 0x1f), UTF_8);
      }

      return switch (tag) {
        case 0xc0 -> NIL_SENTINEL;
        case 0xc2 -> false;
        case 0xc3 -> true;
        case 0xc4 -> readN(readU8());
        case 0xd9 -> new String(readN(readU8()), UTF_8);
        case 0xc5 -> readN(readU16());
        case 0xda -> new String(readN(readU16()), UTF_8);
        case 0xc6 -> readN(readBoundedLen32());
        case 0xdb -> new String(readN(readBoundedLen32()), UTF_8);
        case 0xca -> {
          skipN(4);
          yield 0.0d;
        }
        case 0xcb -> {
          skipN(8);
          yield 0.0d;
        }
        case 0xcc -> (long) readU8();
        case 0xcd -> (long) readU16();
        case 0xce -> Integer.toUnsignedLong(ByteBuffer.wrap(readN(4)).getInt());
        case 0xd0 -> (long) ((byte) readU8());
        case 0xd1 -> (long) ByteBuffer.wrap(readN(2)).getShort();
        case 0xd2 -> (long) ByteBuffer.wrap(readN(4)).getInt();
        case 0xcf, 0xd3 -> ByteBuffer.wrap(readN(8)).getLong();
        case 0xdc -> readArray(readU16(), depth);
        case 0xdd -> readArray(readBoundedCollectionLen32(), depth);
        case 0xde -> readMap(readU16(), depth);
        case 0xdf -> readMap(readBoundedCollectionLen32(), depth);
        case 0xd4, 0xd5, 0xd6, 0xd7, 0xd8 -> {
          skipN(1 + (1 << (tag - 0xd4)));
          yield NIL_SENTINEL;
        }
        case 0xc7 -> {
          skipN(1 + readU8());
          yield NIL_SENTINEL;
        }
        case 0xc8 -> {
          skipN(1 + readU16());
          yield NIL_SENTINEL;
        }
        case 0xc9 -> {
          skipN(1 + readBoundedLen32());
          yield NIL_SENTINEL;
        }
        default -> throw new IOException("Unsupported MsgPack tag: " + tag);
      };
    }

    private int readU16() throws IOException {
      byte[] b = readN(2);
      return ((b[0] & 0xff) << 8) | (b[1] & 0xff);
    }

    private int readBoundedLen32() throws IOException {
      long len = Integer.toUnsignedLong(ByteBuffer.wrap(readN(4)).getInt());
      if (len > MAX_FRAME_BYTES) {
        throw new IOException("MsgPack payload exceeds limit");
      }
      return (int) len;
    }

    private int readBoundedCollectionLen32() throws IOException {
      long len = Integer.toUnsignedLong(ByteBuffer.wrap(readN(4)).getInt());
      if (len > MAX_COLLECTION_SIZE) {
        throw new IOException("MsgPack collection exceeds limit");
      }
      return (int) len;
    }

    private List<Object> readArray(int count, int depth) throws IOException {
      if (count > MAX_COLLECTION_SIZE) {
        throw new IOException("MsgPack array exceeds limit");
      }
      List<Object> list = new ArrayList<>(count);
      for (int i = 0; i < count; i++) {
        list.add(readValue(depth + 1));
      }
      return list;
    }

    private Map<String, Object> readMap(int count, int depth) throws IOException {
      if (count > MAX_COLLECTION_SIZE) {
        throw new IOException("MsgPack map exceeds limit");
      }
      Map<String, Object> map = new LinkedHashMap<>();
      for (int i = 0; i < count; i++) {
        Object k = readValue(depth + 1);
        Object v = readValue(depth + 1);
        map.put(String.valueOf(k), v);
      }
      return map;
    }
  }
}
