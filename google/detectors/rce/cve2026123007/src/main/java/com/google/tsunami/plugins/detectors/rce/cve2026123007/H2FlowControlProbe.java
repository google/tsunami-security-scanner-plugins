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

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Strings.isNullOrEmpty;
import static com.google.common.collect.Comparators.max;
import static com.google.common.collect.Comparators.min;
import static java.nio.charset.StandardCharsets.ISO_8859_1;
import static java.nio.charset.StandardCharsets.US_ASCII;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Ascii;
import com.google.common.base.Ticker;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.net.HostAndPort;
import com.google.common.net.InetAddresses;
import com.google.tsunami.common.net.socket.TsunamiSocketFactory;
import com.google.tsunami.plugins.detectors.rce.cve2026123007.H2Frames.FrameHeader;
import com.google.tsunami.plugins.detectors.rce.cve2026123007.HpackDecoder.HeaderField;
import com.google.tsunami.plugins.detectors.rce.cve2026123007.HpackDecoder.HpackException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.BitSet;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Consumer;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * Bounded, non-destructive HTTP/2 framing and Stream 0 {@code WINDOW_UPDATE} differential verifier
 * for NGINX {@code CVE-2026-123007}.
 */
final class H2FlowControlProbe {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private static final byte[] scannerUserAgent = "TsunamiSecurityScanner".getBytes(US_ASCII);
  private static final byte[] identityBytes = "identity".getBytes(US_ASCII);

  static final long NGINX_MAX_FRAME_SIZE = 16777215L;
  static final long NGINX_CONN_WINDOW_DELTA = 2147418112L;
  static final long NGINX_MAX_WINDOW = 0x7fffffffL;

  private static final long H2_INITIAL_WINDOW_BYTES = 65_535L;
  private static final int SMALL_RECV_BUF_BYTES = 2304;
  @VisibleForTesting static final int STAGE2_RECV_BUF_BYTES = 32 * 1024;
  private static final int LARGE_RECV_BUF_BYTES = 4 * 1024 * 1024;
  // Cap static candidates at 64 KiB so every queued response fits completely within NGINX's
  // default output_buffers (2 * 32 KiB = 65,536 bytes) when sendfile is inactive over TLS h2.
  static final int MAX_STATIC_BODY_BYTES = 65536;
  private static final int MAX_FRAME_PAYLOAD_BYTES = MAX_STATIC_BODY_BYTES + 1024;
  static final int DISCOVERY_STREAM_WIN = MAX_STATIC_BODY_BYTES + 1;
  private static final int DISCOVERY_CONN_WIN_DELTA = 4 * 1024 * 1024;
  private static final int MAX_HEADER_BLOCK_BYTES = 32768;
  private static final int MAX_CONTINUATION_FRAMES = 16;
  private static final int MAX_EFFECTIVE_CONCURRENT = 256;
  private static final int MAX_SAFE_REFUSED_CAP = 96;
  private static final int MIN_ZERO_REFUSED_SLACK = 8;
  private static final int MAX_BATCH_STREAMS = 64;
  private static final int MAX_BURST_STREAMS = 940;
  private static final int MAX_LADDER_STEP = 80;
  // Cap initial ladder attempts so MAX_CONCURRENT_STREAMS=1 endpoints cannot trigger hundreds of
  // retries (at most one additional overshoot-recovery attempt may be inserted at runtime).
  private static final int MAX_LADDER_ATTEMPTS = 16;
  private static final long MIN_HIGH_CONCURRENCY_TARGET_BYTES = 131_072L;
  private static final long PARKED_TARGET_QUEUED_BYTES = 2L * 1024L * 1024L;
  private static final long EXTENDED_PARKED_TARGET_QUEUED_BYTES = 2_560_000L;
  private static final long EXTENDED_CONCURRENCY_THRESHOLD = 4096L;
  private static final int SMALL_BODY_PARK_THRESHOLD_BYTES = 1024;
  private static final long PARKED_CONCURRENCY_HEADROOM = 16L;
  private static final int MIN_PARKED_STREAMS = 64;
  private static final int MAX_PARKED_STREAMS = 2048;
  private static final int EXTENDED_MAX_PARKED_STREAMS = 6000;
  static final int PARK_SYNC_BATCH_STREAMS = 256;
  private static final int MAX_PARK_SYNC_FRAMES = 24576;
  private static final int MAX_DRAIN_FRAMES = 32768;
  private static final int MAX_HOST_CHARS = 253;
  private static final Duration MAX_ADAPTIVE_PRE_DRAIN_DELAY = Duration.ofMillis(250);
  private static final Duration MIN_SOCKET_TIMEOUT = Duration.ofMillis(1);
  private static final Duration MAX_SOCKET_TIMEOUT = Duration.ofMillis(Integer.MAX_VALUE);

  private static final int HPACK_GET_INDEXED = 0x82;
  private static final int HPACK_SCHEME_HTTP_INDEXED = 0x86;
  private static final int HPACK_SCHEME_HTTPS_INDEXED = 0x87;
  private static final int HPACK_AUTHORITY_INC_INDEX = 0x41;
  private static final int HPACK_AUTHORITY_WITHOUT_INDEX = 0x01;
  private static final int HPACK_PATH_INC_INDEX = 0x44;
  private static final int HPACK_PATH_WITHOUT_INDEX = 0x04;
  private static final int HPACK_ACCEPT_ENCODING_INC_INDEX = 0x50; // 0x40 | 16 (static index 16)
  private static final int HPACK_USER_AGENT_INC_INDEX = 0x7a; // 0x40 | 58 (static index 58)
  private static final int HPACK_LITERAL_NAME_PREFIX = 0x0f;
  private static final int HPACK_ACCEPT_ENCODING_NAME_SUFFIX = 0x01; // static index 16 = 15 + 1
  private static final int HPACK_USER_AGENT_NAME_SUFFIX = 0x2b; // static index 58 = 15 + 43
  // FIFO dynamic indices after Stream 1 incrementally indexes :authority (1st -> 65), :path (2nd ->
  // 64), accept-encoding (3rd -> 63), and user-agent (4th -> 62).
  private static final byte HPACK_DYN_AUTHORITY_INDEXED = (byte) (0x80 | 65);
  private static final byte HPACK_DYN_PATH_INDEXED = (byte) (0x80 | 64);
  private static final byte HPACK_DYN_ACCEPT_ENCODING_INDEXED = (byte) (0x80 | 63);
  private static final byte HPACK_DYN_USER_AGENT_INDEXED = (byte) (0x80 | 62);

  private static final ImmutableList<String> STATIC_EXTENSIONS =
      ImmutableList.of(".js", ".css", ".html", ".htm", ".svg", ".png", ".ico", ".txt", ".woff2");

  private static final ImmutableList<String> NON_NGINX_SERVERS =
      ImmutableList.of(
          "apache", "envoy", "cloudflare", "caddy", "haproxy", "iis", "jetty", "tomcat", "gws");

  record ProbeMatch(
      String transport,
      String authority,
      String path,
      int settingsPayloadLen,
      long maxStreams,
      int bodyLen,
      int burstStreams,
      int refusedStreams,
      long windowIncrement) {
    String formatDetailText() {
      String scheme = transport.equals("h2") ? "https" : "http";
      return String.format(
          "Verified unpatched NGINX ngx_http_v2 flow-control window validation over HTTP/2 (%s) at"
              + " %s://%s%s (settings_len=%d, max_concurrent_streams=%d, static_body_bytes=%d,"
              + " burst_streams=%d, tail_refused_streams=%d, stream0_window_update=%d accepted"
              + " with queued DATA frames in h2c->last_out and verified by pre/post/liveness PING"
              + " ACKs).",
          transport,
          scheme,
          authority,
          path,
          settingsPayloadLen,
          maxStreams,
          bodyLen,
          burstStreams,
          refusedStreams,
          windowIncrement);
    }
  }

  record ProbeOutcome(Status status, Optional<ProbeMatch> match) {
    enum Status {
      MATCHED,
      NOT_VULNERABLE,
      FAST_PROTOCOL_MISMATCH,
      IO_OR_TIMEOUT
    }

    static ProbeOutcome matched(ProbeMatch match) {
      return new ProbeOutcome(Status.MATCHED, Optional.of(match));
    }

    static ProbeOutcome notVulnerable() {
      return new ProbeOutcome(Status.NOT_VULNERABLE, Optional.empty());
    }

    static ProbeOutcome fastProtocolMismatch() {
      return new ProbeOutcome(Status.FAST_PROTOCOL_MISMATCH, Optional.empty());
    }

    static ProbeOutcome ioOrTimeout() {
      return new ProbeOutcome(Status.IO_OR_TIMEOUT, Optional.empty());
    }
  }

  private record DiscoveryResult(
      int settingsPayloadLen,
      long maxStreams,
      int bodyLen,
      String path,
      boolean fastMismatch,
      Optional<InetAddress> validatedAddress,
      Duration discoveryRtt) {
    static DiscoveryResult empty(boolean fastMismatch) {
      return new DiscoveryResult(0, 0, 0, "", fastMismatch, Optional.empty(), Duration.ZERO);
    }
  }

  private record StreamDiscoveryResp(
      ImmutableList<HeaderField> headers, int bodyLen, String sampleHtml) {}

  private record DiscoveryFetch(Optional<StreamDiscoveryResp> resp, boolean excludedIntermediary) {}

  private record AttemptResult(
      int refusedCount,
      int acceptedBeforeRefused,
      boolean isContiguousTail,
      boolean canRetryOvershoot,
      boolean sawFlowControlGoAway,
      boolean gotPingA,
      boolean gotPingB,
      boolean gotPingC,
      long prePingBDataBytes,
      long windowIncrement) {}

  private static final class RawFrame {
    private final FrameHeader header;
    private final byte[] payload;

    RawFrame(FrameHeader header, byte[] payload) {
      this.header = header;
      this.payload = payload;
    }

    FrameHeader header() {
      return header;
    }

    byte[] payload() {
      return payload;
    }
  }

  @FunctionalInterface
  private interface Phase2SessionAction {
    AttemptResult run(Socket rawSocket, InputStream in, OutputStream out) throws IOException;
  }

  private record Phase2Context(
      boolean useTls,
      String dialHost,
      String sniHost,
      int port,
      String authority,
      DiscoveryResult disc,
      Duration effectivePreDrain) {
    byte[] buildFirstRequestHeaders() {
      return buildGetHeaders(useTls, authority, disc.path(), /* indexDynamicHeaders= */ true);
    }

    byte[] buildSubsequentRequestHeaders() {
      return buildCompactSubsequentHeaders(useTls);
    }

    ProbeMatch toMatch(int burstStreams, int refusedStreams, long windowIncrement) {
      return new ProbeMatch(
          useTls ? "h2" : "h2c",
          authority,
          disc.path(),
          disc.settingsPayloadLen(),
          disc.maxStreams(),
          disc.bodyLen(),
          burstStreams,
          refusedStreams,
          windowIncrement);
    }
  }

  private final TsunamiSocketFactory socketFactory;
  private final Duration timeout;
  private final Duration interBatchDelay;
  private final Duration preDrainDelay;
  private final SecureRandom secureRandom;
  private final SSLSocketFactory alpnSslSocketFactory;
  private final Ticker ticker;
  private final Consumer<Duration> sleeper;

  H2FlowControlProbe(TsunamiSocketFactory socketFactory, Duration timeout) {
    this(socketFactory, timeout, Duration.ofMillis(20), Duration.ofMillis(15), new SecureRandom());
  }

  @VisibleForTesting
  H2FlowControlProbe(
      TsunamiSocketFactory socketFactory,
      Duration timeout,
      Duration interBatchDelay,
      Duration preDrainDelay,
      SecureRandom secureRandom) {
    this(
        socketFactory,
        timeout,
        interBatchDelay,
        preDrainDelay,
        secureRandom,
        createPermissiveSslSocketFactory(checkNotNull(secureRandom)));
  }

  @VisibleForTesting
  H2FlowControlProbe(
      TsunamiSocketFactory socketFactory,
      Duration timeout,
      Duration interBatchDelay,
      Duration preDrainDelay,
      SecureRandom secureRandom,
      SSLSocketFactory alpnSslSocketFactory) {
    this(
        socketFactory,
        timeout,
        interBatchDelay,
        preDrainDelay,
        secureRandom,
        alpnSslSocketFactory,
        Ticker.systemTicker(),
        H2FlowControlProbe::defaultSleep);
  }

  @VisibleForTesting
  H2FlowControlProbe(
      TsunamiSocketFactory socketFactory,
      Duration timeout,
      Duration interBatchDelay,
      Duration preDrainDelay,
      SecureRandom secureRandom,
      SSLSocketFactory alpnSslSocketFactory,
      Ticker ticker,
      Consumer<Duration> sleeper) {
    this.socketFactory = checkNotNull(socketFactory);
    this.timeout = checkNotNull(timeout);
    this.interBatchDelay = checkNotNull(interBatchDelay);
    this.preDrainDelay = checkNotNull(preDrainDelay);
    this.secureRandom = checkNotNull(secureRandom);
    this.alpnSslSocketFactory = checkNotNull(alpnSslSocketFactory);
    this.ticker = checkNotNull(ticker);
    this.sleeper = checkNotNull(sleeper);
  }

  ProbeOutcome probeCleartextH2c(
      String dialHost, int port, String authority, ImmutableList<String> crawledPaths) {
    return runTwoPhaseProbe(
        /* useTls= */ false, dialHost, /* sniHost= */ "", port, authority, crawledPaths);
  }

  ProbeOutcome probeTlsH2(
      String dialHost,
      String sniHost,
      int port,
      String authority,
      ImmutableList<String> crawledPaths) {
    return runTwoPhaseProbe(/* useTls= */ true, dialHost, sniHost, port, authority, crawledPaths);
  }

  @VisibleForTesting
  Duration computeEffectivePreDrainDelay(Duration discoveryRtt) {
    if (!preDrainDelay.isPositive()) {
      return Duration.ZERO;
    }
    Duration cappedRtt = min(discoveryRtt, MAX_ADAPTIVE_PRE_DRAIN_DELAY);
    return max(cappedRtt, preDrainDelay);
  }

  static boolean isValidAuthorityHost(String host) {
    if (isNullOrEmpty(host) || host.length() > MAX_HOST_CHARS) {
      return false;
    }
    for (int i = 0; i < host.length(); i++) {
      char c = host.charAt(i);
      if (c <= 0x20 || c >= 0x7f) {
        return false;
      }
    }
    return true;
  }

  static String formatAuthority(String host, int port, boolean useTls) {
    boolean defaultPort = useTls ? port == 443 : port == 80;
    if (defaultPort) {
      return host.indexOf(':') >= 0 && !host.startsWith("[") ? "[" + host + "]" : host;
    }
    return HostAndPort.fromParts(host, port).toString();
  }

  static Optional<String> extractSafeLocalPath(String rawUrl) {
    if (isNullOrEmpty(rawUrl) || rawUrl.startsWith("//")) {
      return Optional.empty();
    }
    URI uri;
    try {
      uri = URI.create(rawUrl);
    } catch (IllegalArgumentException e) {
      return Optional.empty();
    }
    String scheme = uri.getScheme();
    if (scheme != null
        && !Ascii.equalsIgnoreCase(scheme, "http")
        && !Ascii.equalsIgnoreCase(scheme, "https")) {
      return Optional.empty();
    }
    String rawPath = uri.getRawPath();
    if (isNullOrEmpty(rawPath)
        || !rawPath.startsWith("/")
        || rawPath.startsWith("//")
        || rawPath.length() > 200) {
      return Optional.empty();
    }
    for (int i = 0; i < rawPath.length(); i++) {
      char c = rawPath.charAt(i);
      if (c <= 0x20 || c >= 0x7f) {
        return Optional.empty();
      }
    }
    return Optional.of(rawPath);
  }

  static Optional<String> extractSafeLocalPathForAuthority(String rawUrl, String authority) {
    Optional<String> pathOpt = extractSafeLocalPath(rawUrl);
    if (pathOpt.isEmpty()) {
      return Optional.empty();
    }
    URI uri = URI.create(rawUrl);
    String rawAuth = uri.getRawAuthority();
    if (!isNullOrEmpty(rawAuth) && !isNullOrEmpty(authority)) {
      String urlHost;
      String targetHost;
      try {
        urlHost = HostAndPort.fromString(rawAuth).getHost();
        targetHost = HostAndPort.fromString(authority).getHost();
      } catch (IllegalArgumentException e) {
        return Optional.empty();
      }
      if (!Ascii.equalsIgnoreCase(urlHost, targetHost)) {
        return Optional.empty();
      }
    }
    return pathOpt;
  }

  static boolean hasStaticExtension(String path) {
    String lower = Ascii.toLowerCase(path);
    for (String ext : STATIC_EXTENSIONS) {
      if (lower.endsWith(ext)) {
        return true;
      }
    }
    return false;
  }

  // Socket.setSoTimeout and Socket.connect treat 0 as infinite timeout and reject negative values;
  // clamp to [1, Integer.MAX_VALUE] ms without overflowing Duration.toMillis().
  @VisibleForTesting
  static int clampSocketTimeoutMillis(Duration timeout) {
    if (timeout.compareTo(MIN_SOCKET_TIMEOUT) <= 0) {
      return 1;
    }
    if (timeout.compareTo(MAX_SOCKET_TIMEOUT) >= 0) {
      return Integer.MAX_VALUE;
    }
    return (int) timeout.toMillis();
  }

  private ProbeOutcome runTwoPhaseProbe(
      boolean useTls,
      String dialHost,
      String sniHost,
      int port,
      String authority,
      ImmutableList<String> crawledPaths) {
    Optional<DiscoveryResult> discOpt =
        discoverEndpoint(useTls, dialHost, sniHost, port, authority, crawledPaths);
    if (discOpt.isEmpty()) {
      return ProbeOutcome.ioOrTimeout();
    }
    DiscoveryResult disc = discOpt.get();
    if (disc.fastMismatch()) {
      return ProbeOutcome.fastProtocolMismatch();
    }
    if (disc.bodyLen() <= 0) {
      return ProbeOutcome.notVulnerable();
    }

    Duration effectivePreDrain = computeEffectivePreDrainDelay(disc.discoveryRtt());
    Phase2Context ctx =
        new Phase2Context(useTls, dialHost, sniHost, port, authority, disc, effectivePreDrain);
    if (disc.maxStreams() > MAX_EFFECTIVE_CONCURRENT) {
      return runHighConcurrencyProbe(ctx);
    }

    // Keep refused tail streams within [1, min(effM, 96)] and total streams <= 940:
    // >= 1 refused stream proves active concurrency saturation, refused <= effM keeps
    // unpatched h2c->send_window + wuIncrement <= 0x7fffffff, and capping at 96 / 940
    // stays below NGINX's refused_streams (max(concurrent_streams, 100)) and default
    // keepalive_requests (1000) connection-close thresholds.
    int effM = (int) Math.min(disc.maxStreams(), MAX_EFFECTIVE_CONCURRENT);
    int maxSafeRefused = Math.min(effM, MAX_SAFE_REFUSED_CAP);
    int step = Math.max(1, Math.min(MAX_LADDER_STEP, maxSafeRefused));
    int halfWin = Math.max(1, maxSafeRefused / 2);
    int startN = effM + halfWin;

    List<Integer> ladder = new ArrayList<>();
    for (int n = startN; n <= MAX_BURST_STREAMS && ladder.size() < MAX_LADDER_ATTEMPTS; n += step) {
      ladder.add(n);
    }

    boolean targetedRetryDone = false;
    for (int idx = 0; idx < ladder.size(); idx++) {
      int nStreams = ladder.get(idx);
      Optional<AttemptResult> attemptOpt = executeFlowControlAttempt(ctx, effM, nStreams);
      if (attemptOpt.isEmpty()) {
        return ProbeOutcome.ioOrTimeout();
      }
      AttemptResult attempt = attemptOpt.get();

      if (attempt.isContiguousTail()
          && attempt.refusedCount() >= 1
          && attempt.refusedCount() <= maxSafeRefused) {
        if (attempt.gotPingA() && attempt.gotPingB() && attempt.gotPingC()) {
          long maxPrePingBData = (long) (nStreams - effM) * disc.bodyLen();
          if (attempt.prePingBDataBytes() < maxPrePingBData) {
            return ProbeOutcome.matched(
                ctx.toMatch(nStreams, attempt.refusedCount(), attempt.windowIncrement()));
          }
          // Flushed DATA bytes before PING(ACK, B) consumed >= (nStreams - effM)*bodyLen
          // (e.g. limit_req error responses or partial multi-stream chunks), so patched
          // NGINX could have accepted wuIncrement within 0x7fffffff; step to a larger burst.
          continue;
        }
        return ProbeOutcome.notVulnerable();
      }

      if (attempt.canRetryOvershoot()
          && attempt.refusedCount() > maxSafeRefused
          && !targetedRetryDone) {
        targetedRetryDone = true;
        int accepted = Math.max(effM, attempt.acceptedBeforeRefused());
        int retryN = accepted + halfWin;
        if (retryN <= MAX_BURST_STREAMS) {
          ladder.add(idx + 1, retryN);
          continue;
        }
      }

      if (attempt.sawFlowControlGoAway() || !(attempt.gotPingA() && attempt.gotPingB())) {
        return ProbeOutcome.notVulnerable();
      }
    }
    return ProbeOutcome.notVulnerable();
  }

  private ProbeOutcome runHighConcurrencyProbe(Phase2Context ctx) {
    DiscoveryResult disc = ctx.disc();
    // When MAX_CONCURRENT_STREAMS > 256 (e.g. 1000 or 10000), NGINX's default keepalive_requests
    // (1000) closes the connection before REFUSED_STREAM can be reached. Validate directly against
    // queued last_out bytes without requiring REFUSED_STREAM:
    // - Grant initConnWin = max(65535, nStreams * bodyLen) and send wuIncrement = 0x7fffffff -
    //   initConnWin + maxPrePingBData where maxPrePingBData = (nStreams - slack) * bodyLen.
    // - On patched NGINX, send_window + send_queued == initConnWin - S (invariantly across all
    //   stream outcomes), so patched NGINX rejects wuIncrement whenever S < maxPrePingBData.
    //   Enforcing prePingBDataBytes < maxPrePingBData guarantees S <= prePingBDataBytes <
    //   maxPrePingBData (zero false positives even if all DATA flushes before PING(ACK, B)).
    int maxBurst = (int) Math.min(disc.maxStreams(), MAX_BURST_STREAMS);
    int firstBurst =
        (int)
            Math.min(
                maxBurst,
                Math.max(
                    (long) MAX_EFFECTIVE_CONCURRENT,
                    Math.ceilDiv(MIN_HIGH_CONCURRENCY_TARGET_BYTES, disc.bodyLen())));
    ImmutableList<Integer> burstCandidates =
        (firstBurst < maxBurst)
            ? ImmutableList.of(firstBurst, maxBurst)
            : ImmutableList.of(firstBurst);

    for (int nStreams : burstCandidates) {
      int slack = Math.max(MIN_ZERO_REFUSED_SLACK, Math.min(nStreams / 8, MAX_SAFE_REFUSED_CAP));
      long maxPrePingBData = (long) (nStreams - slack) * disc.bodyLen();
      Optional<AttemptResult> attemptOpt =
          executeHighConcurrencyBurstAttempt(ctx, nStreams, maxPrePingBData);
      if (attemptOpt.isEmpty()) {
        return ProbeOutcome.ioOrTimeout();
      }
      AttemptResult attempt = attemptOpt.get();
      boolean validRefused =
          attempt.refusedCount() == 0
              || (attempt.isContiguousTail() && attempt.refusedCount() <= slack);
      if (!attempt.sawFlowControlGoAway()
          && validRefused
          && attempt.gotPingA()
          && attempt.gotPingB()
          && attempt.gotPingC()) {
        if (attempt.prePingBDataBytes() < maxPrePingBData) {
          return ProbeOutcome.matched(
              ctx.toMatch(nStreams, attempt.refusedCount(), attempt.windowIncrement()));
        }
        continue;
      }
      return ProbeOutcome.notVulnerable();
    }

    // Fallback for L4 TCP proxies whose client-read pause or larger backend SO_SNDBUF absorbed the
    // multi-flight burst: park streams in h2c->waiting while draining initial responses cleanly so
    // downstream proxy buffers are empty, then release all parked streams and validate Stream 0
    // WINDOW_UPDATE inside a single 60-byte atomic record.
    int drainStreams = (int) (H2_INITIAL_WINDOW_BYTES / disc.bodyLen()) + 1;
    if (drainStreams > MAX_PARKED_STREAMS) {
      return ProbeOutcome.notVulnerable();
    }
    ImmutableList<Integer> parkCandidates =
        buildParkCandidates(disc.maxStreams(), drainStreams, disc.bodyLen());

    for (int parkStreams : parkCandidates) {
      int slackStreams =
          Math.max(MIN_ZERO_REFUSED_SLACK, Math.min(parkStreams / 8, MAX_SAFE_REFUSED_CAP));
      long remFirstBytes = (long) drainStreams * disc.bodyLen() - H2_INITIAL_WINDOW_BYTES;
      long triggerWin = remFirstBytes + (long) parkStreams * disc.bodyLen();
      long maxPrePingBData = triggerWin - (long) slackStreams * disc.bodyLen();

      Optional<AttemptResult> parkedOpt =
          executeParkedAtomicAttempt(ctx, drainStreams, parkStreams, triggerWin, maxPrePingBData);
      if (parkedOpt.isEmpty()) {
        return ProbeOutcome.ioOrTimeout();
      }
      AttemptResult parked = parkedOpt.get();
      if (!parked.sawFlowControlGoAway()
          && parked.refusedCount() == 0
          && parked.gotPingA()
          && parked.gotPingB()
          && parked.gotPingC()) {
        if (parked.prePingBDataBytes() < maxPrePingBData) {
          return ProbeOutcome.matched(
              ctx.toMatch(
                  drainStreams + parkStreams, /* refusedStreams= */ 0, parked.windowIncrement()));
        }
        continue;
      }
      return ProbeOutcome.notVulnerable();
    }
    return ProbeOutcome.notVulnerable();
  }

  private static ImmutableList<Integer> buildParkCandidates(
      long maxStreams, int drainStreams, int bodyLen) {
    long stdMaxOpen = Math.min(maxStreams - PARKED_CONCURRENCY_HEADROOM, MAX_PARKED_STREAMS);
    int stdDesired =
        (int)
            Math.min(
                stdMaxOpen,
                Math.max(
                    (long) MAX_EFFECTIVE_CONCURRENT,
                    Math.ceilDiv(PARKED_TARGET_QUEUED_BYTES, bodyLen)));
    // Keep the initial Stage-2 total stream count <= MAX_BURST_STREAMS (940) so endpoints with
    // NGINX's default keepalive_requests (1000) do not emit GOAWAY(NO_ERROR) during Phase A; step
    // up to larger parked counts only if the keepalive-safe release flushes completely without
    // GOAWAY.
    int keepaliveSafe = Math.min(stdDesired, MAX_BURST_STREAMS - drainStreams);
    ImmutableList.Builder<Integer> candidates = ImmutableList.builder();
    if (keepaliveSafe >= MIN_PARKED_STREAMS && keepaliveSafe < stdDesired) {
      candidates.add(keepaliveSafe);
    }
    candidates.add(stdDesired);
    if (maxStreams >= EXTENDED_CONCURRENCY_THRESHOLD && bodyLen < SMALL_BODY_PARK_THRESHOLD_BYTES) {
      long extMaxOpen =
          Math.min(maxStreams - PARKED_CONCURRENCY_HEADROOM, EXTENDED_MAX_PARKED_STREAMS);
      int extDesired =
          (int) Math.min(extMaxOpen, Math.ceilDiv(EXTENDED_PARKED_TARGET_QUEUED_BYTES, bodyLen));
      if (extDesired > stdDesired) { // NOMUTANTS -- defensive monotonicity guard if thresholds tune
        candidates.add(extDesired);
      }
    }
    return candidates.build();
  }

  private Optional<DiscoveryResult> discoverEndpoint(
      boolean useTls,
      String dialHost,
      String sniHost,
      int port,
      String authority,
      ImmutableList<String> crawledPaths) {
    List<String> candidates = new ArrayList<>(crawledPaths);
    candidates.add("/");
    String fallback404 = "/" + nextHex(6);

    try (Socket rawSocket = socketFactory.createSocket(dialHost, port, timeout);
        Socket tlsSocket =
            useTls ? openAlpnTlsSocket(rawSocket, sniHost, port).orElse(null) : null) {
      if (useTls && tlsSocket == null) {
        return Optional.of(DiscoveryResult.empty(false));
      }
      Optional<InetAddress> validatedAddress = Optional.ofNullable(rawSocket.getInetAddress());
      Socket transportSocket = useTls ? tlsSocket : rawSocket;
      InputStream in = transportSocket.getInputStream();
      OutputStream out = transportSocket.getOutputStream();

      byte[] greetNonce = nextNonce8();
      String firstPath = candidates.get(0);
      ByteArrayOutputStream flight = new ByteArrayOutputStream();
      H2Frames.writeClientPreface(flight);
      H2Frames.writeSettingsFrame(flight, 4096, DISCOVERY_STREAM_WIN);
      H2Frames.writeWindowUpdateFrame(flight, 0, DISCOVERY_CONN_WIN_DELTA);
      H2Frames.writePingFrame(flight, /* ack= */ false, greetNonce);
      H2Frames.writeHeadersFrame(
          flight,
          1,
          buildGetHeaders(useTls, authority, firstPath, /* indexDynamicHeaders= */ true),
          /* endStream= */ true);
      long greetStartNanos = ticker.read();
      flight.writeTo(out);
      out.flush();

      byte[] rawHdr1;
      try {
        rawHdr1 = in.readNBytes(H2Frames.FRAME_HEADER_LEN);
      } catch (SocketTimeoutException e) {
        return Optional.empty();
      } catch (IOException e) {
        return Optional.of(DiscoveryResult.empty(true));
      }
      if (rawHdr1.length < H2Frames.FRAME_HEADER_LEN) {
        return Optional.of(DiscoveryResult.empty(true));
      }
      FrameHeader fh1 = H2Frames.decodeFrameHeader(rawHdr1);
      if (fh1.type() != H2Frames.TYPE_SETTINGS
          || fh1.flags() != 0
          || fh1.streamId() != 0
          || (fh1.length() != 18 && fh1.length() != 24)) {
        return Optional.of(DiscoveryResult.empty(fh1.type() != H2Frames.TYPE_SETTINGS));
      }
      byte[] settingsPayload = in.readNBytes(fh1.length());
      if (settingsPayload.length < fh1.length()) {
        return Optional.of(DiscoveryResult.empty(false));
      }
      Optional<Long> maxStreamsOpt = parseNginxSettingsPayload(settingsPayload);
      if (maxStreamsOpt.isEmpty()) {
        return Optional.of(DiscoveryResult.empty(false));
      }
      long maxStreams = maxStreamsOpt.get();

      // NGINX ngx_http_v2_init() immediately follows its server SETTINGS frame with a 4-byte
      // Stream 0 WINDOW_UPDATE of NGX_HTTP_V2_MAX_WINDOW - 65535 (2147418112).
      Optional<FrameHeader> fh2Opt = H2Frames.readNextFrameHeader(in);
      if (fh2Opt.isEmpty()) {
        return Optional.of(DiscoveryResult.empty(false));
      }
      FrameHeader fh2 = fh2Opt.get();
      if (fh2.type() != H2Frames.TYPE_WINDOW_UPDATE || fh2.streamId() != 0 || fh2.length() != 4) {
        return Optional.of(DiscoveryResult.empty(false));
      }
      byte[] wu2Payload = in.readNBytes(4);
      if (wu2Payload.length < 4
          || (H2Frames.readUint32(wu2Payload, 0) & 0x7fffffffL) != NGINX_CONN_WINDOW_DELTA) {
        return Optional.of(DiscoveryResult.empty(false));
      }

      HpackDecoder hpackDec = new HpackDecoder();
      Optional<StreamDiscoveryResp> resp1Opt =
          readDiscoveryStream(in, hpackDec, 1, Optional.of(greetNonce));
      if (resp1Opt.isEmpty() || isExcludedNonNginxServer(resp1Opt.get().headers())) {
        return Optional.of(DiscoveryResult.empty(false));
      }
      Duration discoveryRtt = Duration.ofNanos(Math.max(0L, ticker.read() - greetStartNanos));
      StreamDiscoveryResp resp1 = resp1Opt.get();

      int nextStreamId = 3;
      if (resp1.bodyLen() >= 8192 && resp1.bodyLen() <= MAX_STATIC_BODY_BYTES) {
        DiscoveryFetch check =
            sendDiscoveryGet(in, out, hpackDec, useTls, authority, firstPath, nextStreamId);
        nextStreamId += 2;
        if (check.excludedIntermediary()) {
          return Optional.of(DiscoveryResult.empty(false));
        }
        if (check.resp().isPresent() && check.resp().get().bodyLen() == resp1.bodyLen()) {
          return Optional.of(
              new DiscoveryResult(
                  fh1.length(),
                  maxStreams,
                  resp1.bodyLen(),
                  firstPath,
                  false,
                  validatedAddress,
                  discoveryRtt));
        }
      }

      for (String assetPath : extractHtmlAssetPaths(resp1.sampleHtml(), authority, 2)) {
        if (!candidates.contains(assetPath)) {
          candidates.add(assetPath);
        }
      }
      candidates.add(fallback404);

      String bestPath = "";
      int bestLen = 0;
      if (resp1.bodyLen() > 0 && resp1.bodyLen() < 8192) {
        DiscoveryFetch check =
            sendDiscoveryGet(in, out, hpackDec, useTls, authority, firstPath, nextStreamId);
        nextStreamId += 2;
        if (check.excludedIntermediary()) {
          return Optional.of(DiscoveryResult.empty(false));
        }
        if (check.resp().isPresent() && check.resp().get().bodyLen() == resp1.bodyLen()) {
          bestPath = firstPath;
          bestLen = resp1.bodyLen();
        }
      }

      for (int i = 1; i < candidates.size(); i++) {
        if (bestLen >= 8192) {
          break;
        }
        String cand = candidates.get(i);
        DiscoveryFetch fetch1 =
            sendDiscoveryGet(in, out, hpackDec, useTls, authority, cand, nextStreamId);
        nextStreamId += 2;
        if (fetch1.excludedIntermediary()) {
          return Optional.of(DiscoveryResult.empty(false));
        }
        if (fetch1.resp().isEmpty()) {
          break;
        }
        int candLen = fetch1.resp().get().bodyLen();
        if (candLen <= bestLen || candLen > MAX_STATIC_BODY_BYTES) {
          continue;
        }
        DiscoveryFetch fetch2 =
            sendDiscoveryGet(in, out, hpackDec, useTls, authority, cand, nextStreamId);
        nextStreamId += 2;
        if (fetch2.excludedIntermediary()) {
          return Optional.of(DiscoveryResult.empty(false));
        }
        if (fetch2.resp().isPresent() && fetch2.resp().get().bodyLen() == candLen) {
          bestPath = cand;
          bestLen = candLen;
        }
      }

      return Optional.of(
          new DiscoveryResult(
              fh1.length(), maxStreams, bestLen, bestPath, false, validatedAddress, discoveryRtt));
    } catch (IOException | HpackException e) {
      logger.atFine().withCause(e).log( // NOMUTANTS -- diagnostic logging
          "Phase 1 HTTP/2 discovery failed on %s:%d.", dialHost, port);
      return Optional.empty();
    }
  }

  private DiscoveryFetch sendDiscoveryGet(
      InputStream in,
      OutputStream out,
      HpackDecoder hpackDec,
      boolean useTls,
      String authority,
      String path,
      int streamId)
      throws IOException, HpackException {
    ByteArrayOutputStream req = new ByteArrayOutputStream();
    H2Frames.writeHeadersFrame(
        req,
        streamId,
        buildGetHeaders(useTls, authority, path, /* indexDynamicHeaders= */ false),
        /* endStream= */ true);
    req.writeTo(out);
    out.flush();
    Optional<StreamDiscoveryResp> respOpt =
        readDiscoveryStream(in, hpackDec, streamId, Optional.empty());
    if (respOpt.isPresent() && isExcludedNonNginxServer(respOpt.get().headers())) {
      return new DiscoveryFetch(Optional.empty(), true);
    }
    return new DiscoveryFetch(respOpt, false);
  }

  private Optional<AttemptResult> executeFlowControlAttempt(
      Phase2Context ctx, int effM, int nStreams) {
    DiscoveryResult disc = ctx.disc();
    // With pre-SYN SO_RCVBUF clamped to 2304 bytes so accepted DATA frames stay queued
    // in h2c->last_out:
    // - Unpatched NGINX deducts A = nStreams - refusedCount streams from send_window,
    //   so send_window + wuIncrement = 0x7fffffff + (refusedCount - effM)*bodyLen <= 0x7fffffff
    //   whenever refusedCount <= effM (accepted without GOAWAY).
    // - Patched NGINX (commit e27f5fa84fe6) includes queued last_out bytes (effM*bodyLen),
    //   so send_window + send_queued + wuIncrement = 0x7fffffff + refusedCount*bodyLen > 0x7fffffff
    //   for all refusedCount >= 1, rejecting the frame with GOAWAY(FLOW_CONTROL_ERROR).
    long initStreamWin = Math.max(H2_INITIAL_WINDOW_BYTES, disc.bodyLen());
    long targetConnWin = (long) nStreams * disc.bodyLen();
    long initConnWin = Math.max(H2_INITIAL_WINDOW_BYTES, targetConnWin);
    long wuIncrement = NGINX_MAX_WINDOW - initConnWin + (long) (nStreams - effM) * disc.bodyLen();

    return runPhase2Session(
        ctx,
        SMALL_RECV_BUF_BYTES,
        wuIncrement,
        "Phase 2 flow-control attempt",
        (rawSocket, in, out) -> {
          writeBurstPreface(out, initStreamWin, targetConnWin);

          byte[] hdr1 = ctx.buildFirstRequestHeaders();
          byte[] hdrc = ctx.buildSubsequentRequestHeaders();
          byte[] nonceA = nextNonce8();
          byte[] nonceB = nextNonce8();
          byte[] nonceC = nextNonce8();

          int batchLimit = Math.max(1, Math.min(MAX_BATCH_STREAMS, effM));
          int sent = 0;
          while (sent < nStreams) {
            int batch = Math.min(batchLimit, nStreams - sent);
            ByteArrayOutputStream batchBuf = new ByteArrayOutputStream();
            for (int j = 0; j < batch; j++) {
              int sid = 1 + 2 * (sent + j);
              H2Frames.writeHeadersFrame(
                  batchBuf, sid, sid == 1 ? hdr1 : hdrc, /* endStream= */ true);
            }
            sent += batch;
            if (sent == nStreams) {
              H2Frames.writePingFrame(batchBuf, /* ack= */ false, nonceA);
              H2Frames.writeWindowUpdateFrame(batchBuf, 0, wuIncrement);
              H2Frames.writePingFrame(batchBuf, /* ack= */ false, nonceB);
            }
            try {
              batchBuf.writeTo(out);
              out.flush();
            } catch (IOException e) {
              break;
            }
            if (sent < nStreams) {
              sleepQuietly(interBatchDelay);
            }
          }

          return settleAndDrainVerification(
              rawSocket,
              in,
              out,
              ctx.effectivePreDrain(),
              nStreams,
              nonceA,
              nonceB,
              nonceC,
              wuIncrement);
        });
  }

  private Optional<AttemptResult> executeHighConcurrencyBurstAttempt(
      Phase2Context ctx, int nStreams, long maxPrePingBData) {
    DiscoveryResult disc = ctx.disc();
    long initStreamWin = Math.max(H2_INITIAL_WINDOW_BYTES, disc.bodyLen());
    long targetConnWin = (long) nStreams * disc.bodyLen();
    long initConnWin = Math.max(H2_INITIAL_WINDOW_BYTES, targetConnWin);
    long wuIncrement = NGINX_MAX_WINDOW - initConnWin + maxPrePingBData;

    return runPhase2Session(
        ctx,
        SMALL_RECV_BUF_BYTES,
        wuIncrement,
        "High-concurrency burst attempt",
        (rawSocket, in, out) -> {
          writeBurstPreface(out, initStreamWin, targetConnWin);

          byte[] hdr1 = ctx.buildFirstRequestHeaders();
          byte[] hdrc = ctx.buildSubsequentRequestHeaders();
          byte[] nonceA = nextNonce8();
          byte[] nonceB = nextNonce8();
          byte[] nonceC = nextNonce8();

          // Send all nStreams back-to-back without inter-batch sleeps so early responses cannot
          // drain out of h2c->last_out across high-RTT links before the trailing WINDOW_UPDATE
          // arrives.
          ByteArrayOutputStream burstBuf = new ByteArrayOutputStream();
          for (int i = 0; i < nStreams; i++) {
            int sid = 1 + 2 * i;
            H2Frames.writeHeadersFrame(
                burstBuf, sid, sid == 1 ? hdr1 : hdrc, /* endStream= */ true);
            if (burstBuf.size() >= 8192) {
              try {
                burstBuf.writeTo(out);
                out.flush();
              } catch (IOException e) {
                break;
              }
              burstBuf.reset();
            }
          }
          H2Frames.writePingFrame(burstBuf, /* ack= */ false, nonceA);
          H2Frames.writeWindowUpdateFrame(burstBuf, 0, wuIncrement);
          H2Frames.writePingFrame(burstBuf, /* ack= */ false, nonceB);
          try {
            burstBuf.writeTo(out);
            out.flush();
          } catch (IOException ignored) {
            // Proceed to drain any server GOAWAY or partial frames already in flight.
          }

          return settleAndDrainVerification(
              rawSocket,
              in,
              out,
              ctx.effectivePreDrain(),
              nStreams,
              nonceA,
              nonceB,
              nonceC,
              wuIncrement);
        });
  }

  private Optional<AttemptResult> runPhase2Session(
      Phase2Context ctx,
      int recvBufBytes,
      long wuIncrement,
      String attemptLabel,
      Phase2SessionAction action) {
    try (Socket rawSocket =
        connectConfiguredSocket(
            ctx.dialHost(), ctx.disc().validatedAddress(), ctx.port(), recvBufBytes)) {
      if (!ctx.useTls()) {
        return Optional.of(
            action.run(rawSocket, rawSocket.getInputStream(), rawSocket.getOutputStream()));
      }
      Optional<Socket> tlsOpt = openAlpnTlsSocket(rawSocket, ctx.sniHost(), ctx.port());
      if (tlsOpt.isEmpty()) {
        return Optional.of(emptyAttempt(wuIncrement));
      }
      try (Socket tlsSocket = tlsOpt.get()) {
        return Optional.of(
            action.run(rawSocket, tlsSocket.getInputStream(), tlsSocket.getOutputStream()));
      }
    } catch (IOException e) {
      logger.atFine().withCause(e).log( // NOMUTANTS -- diagnostic logging
          "%s failed on %s:%d.", attemptLabel, ctx.dialHost(), ctx.port());
      return Optional.empty();
    }
  }

  private void writeBurstPreface(OutputStream out, long initStreamWin, long targetConnWin)
      throws IOException {
    ByteArrayOutputStream pre = new ByteArrayOutputStream();
    H2Frames.writeClientPreface(pre);
    H2Frames.writeSettingsFrame(pre, 4096, initStreamWin);
    if (targetConnWin > H2_INITIAL_WINDOW_BYTES) {
      H2Frames.writeWindowUpdateFrame(pre, 0, targetConnWin - H2_INITIAL_WINDOW_BYTES);
    }
    pre.writeTo(out);
    out.flush();
    sleepQuietly(interBatchDelay.dividedBy(2));
  }

  private AttemptResult settleAndDrainVerification(
      Socket rawSocket,
      InputStream in,
      OutputStream out,
      Duration effectivePreDrain,
      int totalStreams,
      byte[] nonceA,
      byte[] nonceB,
      byte[] nonceC,
      long wuIncrement) {
    sleepQuietly(effectivePreDrain);
    widenReceiveBufferQuietly(rawSocket);
    return drainVerificationFrames(in, out, totalStreams, nonceA, nonceB, nonceC, wuIncrement);
  }

  private Optional<AttemptResult> executeParkedAtomicAttempt(
      Phase2Context ctx, int drainStreams, int parkStreams, long triggerWin, long maxPrePingBData) {
    DiscoveryResult disc = ctx.disc();
    long wuIncrement = NGINX_MAX_WINDOW - triggerWin + maxPrePingBData;
    int totalStreams = drainStreams + parkStreams;

    return runPhase2Session(
        ctx,
        STAGE2_RECV_BUF_BYTES,
        wuIncrement,
        "Parked-stream atomic attempt",
        (rawSocket, in, out) -> {
          // Phase A: Open pre-SYN with STAGE2_RECV_BUF_BYTES (32 KiB) so active batch reads drain
          // the initial 65,535 bytes cleanly without advertising a multi-megabyte client TCP
          // receive window during Phase B, while avoiding any post-connect SO_RCVBUF shrink.
          ByteArrayOutputStream pre = new ByteArrayOutputStream();
          H2Frames.writeClientPreface(pre);
          H2Frames.writeSettingsFrame(pre, 4096, Math.max(H2_INITIAL_WINDOW_BYTES, disc.bodyLen()));
          pre.writeTo(out);
          out.flush();

          if (!parkStreamsInWaiting(
              in,
              out,
              ctx.buildFirstRequestHeaders(),
              ctx.buildSubsequentRequestHeaders(),
              totalStreams,
              disc.bodyLen())) {
            return emptyAttempt(wuIncrement);
          }

          // Phase B: Emit [WINDOW_UPDATE(triggerWin), PING(A), WINDOW_UPDATE(wuIncrement),
          // PING(B)] as a single 60-byte atomic record so all parked streams wake synchronously in
          // the same read pass before downstream proxies pause client reads;
          // settleAndDrainVerification then widens SO_RCVBUF to LARGE_RECV_BUF_BYTES only after the
          // pre-drain settle window.
          byte[] nonceA = nextNonce8();
          byte[] nonceB = nextNonce8();
          byte[] nonceC = nextNonce8();
          ByteArrayOutputStream atomic = new ByteArrayOutputStream(64);
          H2Frames.writeWindowUpdateFrame(atomic, 0, triggerWin);
          H2Frames.writePingFrame(atomic, /* ack= */ false, nonceA);
          H2Frames.writeWindowUpdateFrame(atomic, 0, wuIncrement);
          H2Frames.writePingFrame(atomic, /* ack= */ false, nonceB);
          atomic.writeTo(out);
          out.flush();

          return settleAndDrainVerification(
              rawSocket,
              in,
              out,
              ctx.effectivePreDrain(),
              totalStreams,
              nonceA,
              nonceB,
              nonceC,
              wuIncrement);
        });
  }

  private boolean parkStreamsInWaiting(
      InputStream in, OutputStream out, byte[] hdr1, byte[] hdrc, int totalStreams, int bodyLen)
      throws IOException {
    BitSet initialHeadersSeen = new BitSet(totalStreams);
    BitSet endedStreamsSeen = new BitSet(totalStreams);
    int headersSeen = 0;
    int endStreamsSeen = 0;
    long phaseADataBytes = 0L;
    int syncFramesRead = 0;
    int sent = 0;
    long phaseAStartNanos = ticker.read();
    long maxPhaseANanos = computeMaxDrainNanos();

    while (sent < totalStreams) {
      int batch = Math.min(PARK_SYNC_BATCH_STREAMS, totalStreams - sent);
      byte[] syncNonce = nextNonce8();
      ByteArrayOutputStream batchBuf = new ByteArrayOutputStream();
      for (int j = 0; j < batch; j++) {
        int sid = 1 + 2 * (sent + j);
        H2Frames.writeHeadersFrame(batchBuf, sid, sid == 1 ? hdr1 : hdrc, /* endStream= */ true);
      }
      sent += batch;
      H2Frames.writePingFrame(batchBuf, /* ack= */ false, syncNonce);
      batchBuf.writeTo(out);
      out.flush();

      boolean gotSyncPing = false;
      long expectedBatchDataBytes = Math.min(H2_INITIAL_WINDOW_BYTES, (long) sent * bodyLen);
      // NGINX queues PING(ACK) ahead of unblocked stream HEADERS/DATA frames and defers
      // decrementing h2c->processing until queued stream DATA flushes. Drain each batch's
      // expected HEADERS and DATA bytes before sending the next batch so cumulative streams
      // never overrun MAX_CONCURRENT_STREAMS, while finishing early if all sent streams already
      // ended (e.g. header-only 429/503 responses) to avoid blocking on SO_TIMEOUT.
      while (!(gotSyncPing
          && ((headersSeen >= sent && phaseADataBytes >= expectedBatchDataBytes)
              || endStreamsSeen >= sent))) {
        if (syncFramesRead >= MAX_PARK_SYNC_FRAMES
            || ticker.read() - phaseAStartNanos >= maxPhaseANanos) {
          return false;
        }
        Optional<RawFrame> frameOpt = readBoundedFrame(in);
        if (frameOpt.isEmpty()) {
          return false;
        }
        syncFramesRead++;
        FrameHeader fh = frameOpt.get().header();
        byte[] payload = frameOpt.get().payload();
        switch (fh.type()) {
          case H2Frames.TYPE_HEADERS -> {
            headersSeen += markClientStreamSeen(initialHeadersSeen, fh.streamId(), totalStreams);
            if ((fh.flags() & H2Frames.FLAG_END_STREAM) != 0) {
              endStreamsSeen += markClientStreamSeen(endedStreamsSeen, fh.streamId(), totalStreams);
            }
          }
          case H2Frames.TYPE_DATA -> {
            phaseADataBytes += fh.length();
            if ((fh.flags() & H2Frames.FLAG_END_STREAM) != 0) {
              endStreamsSeen += markClientStreamSeen(endedStreamsSeen, fh.streamId(), totalStreams);
            }
            if (phaseADataBytes > H2_INITIAL_WINDOW_BYTES) {
              return false;
            }
          }
          case H2Frames.TYPE_PING -> {
            if ((fh.flags() & H2Frames.FLAG_ACK) != 0 && Arrays.equals(payload, syncNonce)) {
              gotSyncPing = true;
            }
          }
          case H2Frames.TYPE_RST_STREAM, H2Frames.TYPE_GOAWAY -> {
            return false;
          }
          default -> {}
        }
      }
    }

    return headersSeen >= totalStreams && phaseADataBytes == H2_INITIAL_WINDOW_BYTES;
  }

  private static int markClientStreamSeen(BitSet seen, int sid, int totalStreams) {
    if (sid <= 0 || (sid & 1) == 0) {
      return 0;
    }
    int streamIdx = (sid - 1) >>> 1;
    if (streamIdx >= totalStreams || seen.get(streamIdx)) {
      return 0;
    }
    seen.set(streamIdx);
    return 1;
  }

  private static Optional<RawFrame> readBoundedFrame(InputStream in) throws IOException {
    Optional<FrameHeader> fhOpt = H2Frames.readNextFrameHeader(in);
    if (fhOpt.isEmpty()) {
      return Optional.empty();
    }
    FrameHeader fh = fhOpt.get();
    if (fh.length() > MAX_FRAME_PAYLOAD_BYTES) {
      return Optional.empty();
    }
    byte[] payload = in.readNBytes(fh.length());
    if (payload.length < fh.length()) {
      return Optional.empty();
    }
    return Optional.of(new RawFrame(fh, payload));
  }

  private static AttemptResult emptyAttempt(long wuIncrement) {
    return new AttemptResult(0, 0, false, false, false, false, false, false, 0L, wuIncrement);
  }

  private static void widenReceiveBufferQuietly(Socket rawSocket) {
    try {
      rawSocket.setReceiveBufferSize(LARGE_RECV_BUF_BYTES); // NOMUTANTS -- kernel drain speed hint
    } catch (IOException ignored) {
      // Non-fatal on custom socket implementations.
    }
  }

  private long computeMaxDrainNanos() {
    return Duration.ofMillis(clampSocketTimeoutMillis(timeout)).multipliedBy(2).toNanos();
  }

  private AttemptResult drainVerificationFrames(
      InputStream in,
      OutputStream out,
      int nStreams,
      byte[] nonceA,
      byte[] nonceB,
      byte[] nonceC,
      long wuIncrement) {
    List<Integer> refusedSids = new ArrayList<>();
    boolean sawFlowControlGoAway = false;
    boolean gotA = false;
    boolean gotB = false;
    boolean gotC = false;
    long prePingBDataBytes = 0L;
    long drainStartNanos = ticker.read();
    long maxDrainNanos = computeMaxDrainNanos();

    for (int frameCount = 0; frameCount < MAX_DRAIN_FRAMES; frameCount++) {
      if (ticker.read() - drainStartNanos >= maxDrainNanos) {
        break;
      }
      try {
        Optional<RawFrame> frameOpt = readBoundedFrame(in);
        if (frameOpt.isEmpty()) {
          break;
        }
        FrameHeader fh = frameOpt.get().header();
        byte[] payload = frameOpt.get().payload();
        switch (fh.type()) {
          case H2Frames.TYPE_DATA -> {
            if (!gotB) {
              prePingBDataBytes += fh.length();
            }
          }
          case H2Frames.TYPE_RST_STREAM -> {
            if (payload.length == 4
                && H2Frames.readUint32(payload, 0) == H2Frames.ERR_REFUSED_STREAM) {
              refusedSids.add(fh.streamId());
            }
          }
          case H2Frames.TYPE_GOAWAY -> {
            if (payload.length >= 8
                && H2Frames.readUint32(payload, 4) == H2Frames.ERR_FLOW_CONTROL) {
              sawFlowControlGoAway = true;
            }
            return finalizeAttempt(
                refusedSids,
                nStreams,
                sawFlowControlGoAway,
                gotA,
                gotB,
                gotC,
                prePingBDataBytes,
                wuIncrement);
          }
          case H2Frames.TYPE_PING -> {
            if ((fh.flags() & H2Frames.FLAG_ACK) != 0 && payload.length == 8) {
              if (Arrays.equals(payload, nonceA)) {
                gotA = true;
              } else if (Arrays.equals(payload, nonceB)) {
                if (!gotB) {
                  gotB = true;
                  ByteArrayOutputStream pingC = new ByteArrayOutputStream();
                  H2Frames.writePingFrame(pingC, /* ack= */ false, nonceC);
                  pingC.writeTo(out);
                  out.flush();
                }
              } else if (Arrays.equals(payload, nonceC)) {
                gotC = true;
                return finalizeAttempt(
                    refusedSids,
                    nStreams,
                    sawFlowControlGoAway,
                    gotA,
                    gotB,
                    gotC,
                    prePingBDataBytes,
                    wuIncrement);
              }
            }
          }
          default -> {}
        }
      } catch (IOException e) {
        break;
      }
    }

    return finalizeAttempt(
        refusedSids,
        nStreams,
        sawFlowControlGoAway,
        gotA,
        gotB,
        gotC,
        prePingBDataBytes,
        wuIncrement);
  }

  private Socket connectConfiguredSocket(
      String host, Optional<InetAddress> validatedAddress, int port, int recvBufBytes)
      throws IOException {
    if (validatedAddress.isEmpty()) {
      Socket connected = socketFactory.createSocket(host, port, timeout);
      connected.setReceiveBufferSize(recvBufBytes); // NOMUTANTS -- kernel buffer hint
      return connected;
    }
    InetAddress pinnedAddress = validatedAddress.get();
    Socket unconnected = socketFactory.createUnconnectedSocket();
    if (unconnected == null) {
      Socket connected = socketFactory.createSocket(pinnedAddress, port, timeout);
      connected.setReceiveBufferSize(recvBufBytes); // NOMUTANTS -- kernel buffer hint
      return connected;
    }
    try {
      int timeoutMillis = clampSocketTimeoutMillis(timeout);
      unconnected.setSoTimeout(timeoutMillis); // NOMUTANTS -- defensive read timeout
      unconnected.setTcpNoDelay(true); // NOMUTANTS -- latency optimization
      unconnected.setReceiveBufferSize(recvBufBytes); // NOMUTANTS -- pre-SYN SO_RCVBUF hint
      unconnected.connect(new InetSocketAddress(pinnedAddress, port), timeoutMillis);
      return unconnected;
    } catch (Throwable t) {
      try (unconnected) {
        throw t;
      }
    }
  }

  private Optional<Socket> openAlpnTlsSocket(Socket rawSocket, String sniHost, int port)
      throws IOException {
    // TsunamiSocketFactory.wrapWithSsl invokes startHandshake() immediately before returning,
    // preventing ALPN ("h2") and SNI SSLParameters from being applied prior to ClientHello.
    SSLSocket sslSocket =
        (SSLSocket)
            alpnSslSocketFactory.createSocket(rawSocket, sniHost, port, /* autoClose= */ false);
    try {
      sslSocket.setSoTimeout(
          clampSocketTimeoutMillis(timeout)); // NOMUTANTS -- defensive TLS read timeout
      SSLParameters params = sslSocket.getSSLParameters();
      params.setApplicationProtocols(new String[] {"h2"});
      params.setServerNames(
          extractValidSniServerName(sniHost).map(ImmutableList::of).orElse(ImmutableList.of()));
      sslSocket.setSSLParameters(params);
      sslSocket.startHandshake();
      if (!Objects.equals(sslSocket.getApplicationProtocol(), "h2")) {
        sslSocket.close();
        return Optional.empty();
      }
      return Optional.of(sslSocket);
    } catch (Throwable t) {
      try (sslSocket) {
        throw t;
      }
    }
  }

  private static Optional<SNIServerName> extractValidSniServerName(String host) {
    if (isNullOrEmpty(host) || InetAddresses.isInetAddress(host)) {
      return Optional.empty();
    }
    if (host.startsWith("[") && host.endsWith("]")) {
      return Optional.empty();
    }
    try {
      return Optional.of(new SNIHostName(host));
    } catch (IllegalArgumentException e) {
      return Optional.empty();
    }
  }

  private static AttemptResult finalizeAttempt(
      List<Integer> refusedSids,
      int nStreams,
      boolean sawFlowControlGoAway,
      boolean gotA,
      boolean gotB,
      boolean gotC,
      long prePingBDataBytes,
      long wuIncrement) {
    int r = refusedSids.size();
    if (r < 1 || r > nStreams) {
      return new AttemptResult(
          r,
          0,
          false,
          false,
          sawFlowControlGoAway,
          gotA,
          gotB,
          gotC,
          prePingBDataBytes,
          wuIncrement);
    }
    Collections.sort(refusedSids);
    int firstSid = refusedSids.get(0);
    int maxSid = 2 * nStreams - 1;
    if (firstSid < 1 || (firstSid & 1) == 0 || refusedSids.get(r - 1) > maxSid) {
      return new AttemptResult(
          r,
          0,
          false,
          false,
          sawFlowControlGoAway,
          gotA,
          gotB,
          gotC,
          prePingBDataBytes,
          wuIncrement);
    }
    for (int k = 0; k < r; k++) {
      if (refusedSids.get(k) != firstSid + 2 * k) {
        return new AttemptResult(
            r,
            0,
            false,
            false,
            sawFlowControlGoAway,
            gotA,
            gotB,
            gotC,
            prePingBDataBytes,
            wuIncrement);
      }
    }
    int acceptedBeforeRefused = (firstSid - 1) / 2;
    boolean contiguousTail = (refusedSids.get(r - 1) == maxSid);
    return new AttemptResult(
        r,
        acceptedBeforeRefused,
        contiguousTail,
        /* canRetryOvershoot= */ true,
        sawFlowControlGoAway,
        gotA,
        gotB,
        gotC,
        prePingBDataBytes,
        wuIncrement);
  }

  /**
   * Matches NGINX {@code ngx_http_v2_init()}'s exact server greeting {@code SETTINGS} payload: 3
   * entries (18 bytes: {@code MAX_CONCURRENT_STREAMS}, {@code INITIAL_WINDOW_SIZE}, {@code
   * MAX_FRAME_SIZE=16777215}) or 4 entries (24 bytes: plus {@code NO_PRIORITIES=1}). Entry order is
   * intentionally enforced to exclude non-NGINX HTTP/2 stacks before Phase 2 burst probing.
   */
  private static Optional<Long> parseNginxSettingsPayload(byte[] payload) {
    int id0 = H2Frames.readUint16(payload, 0);
    long val0 = H2Frames.readUint32(payload, 2);
    int id1 = H2Frames.readUint16(payload, 6);
    long val1 = H2Frames.readUint32(payload, 8);
    int id2 = H2Frames.readUint16(payload, 12);
    long val2 = H2Frames.readUint32(payload, 14);

    if (id0 != H2Frames.SETTING_MAX_CONCURRENT_STREAMS || val0 <= 0) {
      return Optional.empty();
    }
    if (id1 != H2Frames.SETTING_INITIAL_WINDOW_SIZE || val1 > NGINX_MAX_WINDOW) {
      return Optional.empty();
    }
    if (id2 != H2Frames.SETTING_MAX_FRAME_SIZE || val2 != NGINX_MAX_FRAME_SIZE) {
      return Optional.empty();
    }
    if (payload.length == 24) {
      int id3 = H2Frames.readUint16(payload, 18);
      long val3 = H2Frames.readUint32(payload, 20);
      if (id3 != H2Frames.SETTING_NO_PRIORITIES || val3 != 1L) {
        return Optional.empty();
      }
    }
    return Optional.of(val0);
  }

  private Optional<StreamDiscoveryResp> readDiscoveryStream(
      InputStream in, HpackDecoder hpackDec, int targetSid, Optional<byte[]> wantPing)
      throws IOException, HpackException {
    ImmutableList<HeaderField> headers = ImmutableList.of();
    int bodyLen = 0;
    ByteArrayOutputStream sample = new ByteArrayOutputStream();
    boolean gotEnd = false;
    boolean gotPing = wantPing.isEmpty();
    long streamStartNanos = ticker.read();
    long maxStreamNanos = computeMaxDrainNanos();

    for (int i = 0; i < 512; i++) {
      if (gotEnd && gotPing) {
        return Optional.of(new StreamDiscoveryResp(headers, bodyLen, sample.toString(ISO_8859_1)));
      }
      if (ticker.read() - streamStartNanos >= maxStreamNanos) {
        return Optional.empty();
      }
      Optional<RawFrame> frameOpt = readBoundedFrame(in);
      if (frameOpt.isEmpty()) {
        return Optional.empty();
      }
      FrameHeader fh = frameOpt.get().header();
      byte[] payload = frameOpt.get().payload();

      switch (fh.type()) {
        case H2Frames.TYPE_PING -> {
          if ((fh.flags() & H2Frames.FLAG_ACK) != 0
              && wantPing.isPresent()
              && Arrays.equals(payload, wantPing.get())) {
            gotPing = true;
          }
        }
        case H2Frames.TYPE_HEADERS -> {
          ImmutableList<HeaderField> decoded =
              decodeHeadersWithContinuations(in, hpackDec, fh, payload);
          if (fh.streamId() == targetSid) {
            headers =
                headers.isEmpty()
                    ? decoded
                    : ImmutableList.<HeaderField>builder().addAll(headers).addAll(decoded).build();
            if ((fh.flags() & H2Frames.FLAG_END_STREAM) != 0) {
              gotEnd = true;
            }
          }
        }
        case H2Frames.TYPE_DATA -> {
          if (fh.streamId() == targetSid) {
            int dataOffset = 0;
            int dataLen = payload.length;
            if ((fh.flags() & H2Frames.FLAG_PADDED) != 0) {
              if (payload.length == 0) {
                return Optional.empty();
              }
              int padLen = payload[0] & 0xff;
              if (padLen >= payload.length) {
                return Optional.empty();
              }
              dataOffset = 1;
              dataLen = payload.length - 1 - padLen;
            }
            bodyLen += dataLen;
            if (sample.size() < 8192 && dataLen > 0) {
              int take = Math.min(dataLen, 8192 - sample.size());
              sample.write(payload, dataOffset, take);
            }
            if (bodyLen > MAX_STATIC_BODY_BYTES || (fh.flags() & H2Frames.FLAG_END_STREAM) != 0) {
              gotEnd = true;
            }
          }
        }
        case H2Frames.TYPE_RST_STREAM, H2Frames.TYPE_GOAWAY -> {
          return Optional.empty();
        }
        default -> {}
      }
    }
    return Optional.empty();
  }

  private static ImmutableList<HeaderField> decodeHeadersWithContinuations(
      InputStream in, HpackDecoder hpackDec, FrameHeader fh, byte[] payload)
      throws IOException, HpackException {
    int offset = 0;
    int end = payload.length;
    if ((fh.flags() & H2Frames.FLAG_PADDED) != 0) {
      if (payload.length == 0) {
        throw new HpackException("Empty padded HEADERS frame.");
      }
      int padLen = payload[0] & 0xff;
      offset = 1;
      end -= padLen;
    }
    if ((fh.flags() & H2Frames.FLAG_PRIORITY) != 0) {
      offset += 5;
    }
    if (offset > end) {
      throw new HpackException("Invalid HEADERS padding or priority bounds.");
    }
    if (end - offset > MAX_HEADER_BLOCK_BYTES) {
      throw new HpackException("HEADERS block exceeds maximum size.");
    }

    ByteArrayOutputStream block = new ByteArrayOutputStream();
    block.write(payload, offset, end - offset);
    boolean endHeaders = (fh.flags() & H2Frames.FLAG_END_HEADERS) != 0;

    for (int cont = 0; cont < MAX_CONTINUATION_FRAMES && !endHeaders; cont++) {
      FrameHeader next =
          H2Frames.readNextFrameHeader(in)
              .orElseThrow(() -> new HpackException("Truncated CONTINUATION header."));
      if (next.type() != H2Frames.TYPE_CONTINUATION
          || next.streamId() != fh.streamId()
          || block.size() + next.length() > MAX_HEADER_BLOCK_BYTES) {
        throw new HpackException("Invalid CONTINUATION frame.");
      }
      byte[] contBytes = in.readNBytes(next.length());
      if (contBytes.length < next.length()) {
        throw new HpackException("Truncated CONTINUATION payload.");
      }
      block.write(contBytes);
      endHeaders = (next.flags() & H2Frames.FLAG_END_HEADERS) != 0;
    }
    if (!endHeaders) {
      throw new HpackException("Missing END_HEADERS flag.");
    }
    return hpackDec.decode(block.toByteArray());
  }

  private static boolean isExcludedNonNginxServer(ImmutableList<HeaderField> headers) {
    for (HeaderField hf : headers) {
      String name = Ascii.toLowerCase(hf.name());
      String val = Ascii.toLowerCase(hf.value().trim());
      switch (name) {
        case "via" -> {
          if (!val.isEmpty()) {
            return true;
          }
        }
        case "server" -> {
          if (val.contains("awselb")) {
            return true;
          }
          if (!val.isEmpty() && !val.contains("nginx") && !val.contains("openresty")) {
            for (String nonNginx : NON_NGINX_SERVERS) {
              if (val.contains(nonNginx)) {
                return true;
              }
            }
          }
        }
        case "set-cookie" -> {
          if (val.startsWith("awsalb=")
              || val.startsWith("awsalbcors=")
              || val.startsWith("awsalbtg=")
              || val.startsWith("awsalbtgcors=")) {
            return true;
          }
        }
        default -> {}
      }
    }
    return false;
  }

  private static ImmutableList<String> extractHtmlAssetPaths(
      String html, String authority, int limit) {
    Set<String> found = new LinkedHashSet<>();
    for (String attr : ImmutableList.of("href=\"", "src=\"", "href='", "src='")) {
      String rem = html;
      char quote = attr.charAt(attr.length() - 1);
      while (found.size() < limit) {
        int idx = rem.indexOf(attr);
        if (idx < 0) {
          break;
        }
        rem = rem.substring(idx + attr.length());
        int end = rem.indexOf(quote);
        if (end < 0) {
          break;
        }
        Optional<String> safe = extractSafeLocalPathForAuthority(rem.substring(0, end), authority);
        rem = rem.substring(end + 1);
        if (safe.isPresent() && !safe.get().equals("/") && hasStaticExtension(safe.get())) {
          found.add(safe.get());
        }
      }
    }
    return ImmutableList.copyOf(found);
  }

  private static byte[] buildGetHeaders(
      boolean httpsScheme, String authority, String path, boolean indexDynamicHeaders) {
    ByteArrayOutputStream buf = new ByteArrayOutputStream();
    buf.write(HPACK_GET_INDEXED);
    buf.write(httpsScheme ? HPACK_SCHEME_HTTPS_INDEXED : HPACK_SCHEME_HTTP_INDEXED);
    buf.write(indexDynamicHeaders ? HPACK_AUTHORITY_INC_INDEX : HPACK_AUTHORITY_WITHOUT_INDEX);
    writeHpackAscii(buf, authority.getBytes(US_ASCII));
    buf.write(indexDynamicHeaders ? HPACK_PATH_INC_INDEX : HPACK_PATH_WITHOUT_INDEX);
    writeHpackAscii(buf, path.getBytes(US_ASCII));
    // accept-encoding: identity prevents gzip/br compression from altering DATA byte counts.
    if (indexDynamicHeaders) {
      buf.write(HPACK_ACCEPT_ENCODING_INC_INDEX);
    } else {
      buf.write(HPACK_LITERAL_NAME_PREFIX);
      buf.write(HPACK_ACCEPT_ENCODING_NAME_SUFFIX);
    }
    writeHpackAscii(buf, identityBytes);
    if (indexDynamicHeaders) {
      buf.write(HPACK_USER_AGENT_INC_INDEX);
    } else {
      buf.write(HPACK_LITERAL_NAME_PREFIX);
      buf.write(HPACK_USER_AGENT_NAME_SUFFIX);
    }
    writeHpackAscii(buf, scannerUserAgent);
    return buf.toByteArray();
  }

  /**
   * Builds a 6-byte purely indexed subsequent burst {@code GET} header block referencing the FIFO
   * dynamic table entries populated on Stream 1 by {@link #buildGetHeaders}: {@code :authority}
   * ({@code 65}), {@code :path} ({@code 64}), {@code accept-encoding: identity} ({@code 63}, so
   * response {@code DATA} byte counts remain uncompressed), and {@code user-agent} ({@code 62}, so
   * NGINX rules rejecting empty {@code User-Agent} headers treat all burst streams identically).
   */
  private static byte[] buildCompactSubsequentHeaders(boolean httpsScheme) {
    return new byte[] {
      (byte) HPACK_GET_INDEXED,
      (byte) (httpsScheme ? HPACK_SCHEME_HTTPS_INDEXED : HPACK_SCHEME_HTTP_INDEXED),
      HPACK_DYN_AUTHORITY_INDEXED,
      HPACK_DYN_PATH_INDEXED,
      HPACK_DYN_ACCEPT_ENCODING_INDEXED,
      HPACK_DYN_USER_AGENT_INDEXED
    };
  }

  private static void writeHpackAscii(ByteArrayOutputStream buf, byte[] raw) {
    int n = raw.length;
    if (n < 127) {
      buf.write(n);
      buf.writeBytes(raw);
      return;
    }
    buf.write(127);
    n -= 127;
    while (n >= 128) {
      buf.write((n & 0x7f) | 0x80);
      n >>>= 7;
    }
    buf.write(n);
    buf.writeBytes(raw);
  }

  private byte[] nextNonce8() {
    byte[] b = new byte[8];
    secureRandom.nextBytes(b);
    return b;
  }

  private String nextHex(int numBytes) {
    byte[] b = new byte[numBytes];
    secureRandom.nextBytes(b);
    StringBuilder sb = new StringBuilder(numBytes * 2);
    for (byte v : b) {
      sb.append(Character.forDigit((v >>> 4) & 0x0f, 16));
      sb.append(Character.forDigit(v & 0x0f, 16));
    }
    return sb.toString();
  }

  private void sleepQuietly(Duration d) {
    if (!d.isPositive()) {
      return;
    }
    sleeper.accept(d);
  }

  private static void defaultSleep(Duration d) {
    try {
      Thread.sleep(d);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }

  @VisibleForTesting
  static SSLSocketFactory createPermissiveSslSocketFactory(SecureRandom random) {
    try {
      SSLContext sslContext = SSLContext.getInstance("TLS");
      sslContext.init(null, new TrustManager[] {new PermissiveTrustManager()}, random);
      return sslContext.getSocketFactory();
    } catch (GeneralSecurityException e) { // NOMUTANTS -- defensive JCA initialization guard
      throw new IllegalStateException("Failed to initialize TLS context for HTTP/2 probe.", e);
    }
  }

  private static final class PermissiveTrustManager implements X509TrustManager {
    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) {}

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) {}

    @Override
    public X509Certificate[] getAcceptedIssuers() {
      return new X509Certificate[0];
    }
  }
}
