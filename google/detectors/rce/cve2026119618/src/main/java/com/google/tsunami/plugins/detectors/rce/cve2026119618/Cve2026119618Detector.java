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

import static com.google.common.base.Preconditions.checkNotNull;
import static java.nio.charset.StandardCharsets.ISO_8859_1;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Ascii;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.flogger.GoogleLogger;
import com.google.common.io.BaseEncoding;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.socket.TsunamiSocketFactory;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.ForServiceName;
import com.google.tsunami.plugin.annotations.ForWebService;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.plugins.detectors.rce.cve2026119618.H2ProbeSession.H2Response;
import com.google.tsunami.plugins.detectors.rce.cve2026119618.H2ProbeSession.TransportConnector;
import com.google.tsunami.plugins.detectors.rce.cve2026119618.H2ProbeSession.TransportMode;
import com.google.tsunami.plugins.detectors.rce.cve2026119618.HpackCodec.HeaderField;
import com.google.tsunami.plugins.detectors.rce.cve2026119618.TraceEchoParser.EndpointTarget;
import com.google.tsunami.plugins.detectors.rce.cve2026119618.TraceEchoParser.ParsedTraceEcho;
import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TextData;
import com.google.tsunami.proto.TransportProtocol;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.io.IOException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.util.Arrays;
import java.util.Optional;
import java.util.function.Supplier;
import javax.inject.Inject;

/**
 * A {@link VulnDetector} that detects the Apache HTTP Server {@code mod_http2} {@code
 * assign_headers()} race condition and heap memory corruption RCE vulnerability (CVE-2026-119618).
 *
 * <p>Safety invariant: Every probe is executed sequentially on a single stream at a time with
 * strictly fewer than 10 headers (6 headers on Stream 1, 7 on Stream 3, and 6 on Stream 5), staying
 * well within {@code mod_http2}'s pre-allocated 10-element {@code apr_table_t} capacity on the
 * {@code c1} connection pool so zero unsynchronized pool reallocations or concurrent mutations can
 * occur.
 *
 * <p>Service-routing note: In {@code PluginManager}, combining {@link ForWebService} with {@link
 * ForServiceName} evaluates {@code hasServiceNameMatch || hasWebServiceMatch} (and allows unnamed
 * services through to {@link #detect}, where {@link #isSupportedService} enforces standard web-port
 * gating on {@code ""}/{@code "unknown"}/{@code "ssl/unknown"}/{@code "tcpwrapped"}).
 */
@ForWebService
@ForServiceName({
  "https-alt",
  "ssl/https-alt",
  "http over ssl",
  "ssl/unknown",
  "unknown",
  "tcpwrapped"
})
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "Cve2026119618Detector",
    version = "0.1",
    description =
        "Detects the Apache HTTP Server mod_http2 assign_headers() race condition RCE"
            + " vulnerability (CVE-2026-119618).",
    author = "Tsunami Security Scanner",
    bootstrapModule = Cve2026119618DetectorBootstrapModule.class)
public final class Cve2026119618Detector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  @VisibleForTesting static final String VULN_REPORT_PUBLISHER = "GOOGLE";
  @VisibleForTesting static final String VULN_REPORT_ID = "CVE-2026-119618";

  @VisibleForTesting
  static final String VULN_REPORT_TITLE =
      "Apache HTTP Server mod_http2 assign_headers() Race Condition RCE (CVE-2026-119618)";

  @VisibleForTesting
  static final String VULN_DESCRIPTION =
      "Apache HTTP Server versions 2.4.55 through 2.4.70 (and standalone mod_h2 versions 2.0.8"
          + " through 2.0.42) with HTTP/2 (h2 or h2c) enabled contain a race condition in"
          + " mod_http2's assign_headers() function (modules/http2/h2_request.c). For body-less"
          + " HTTP/2 requests carrying a Content-Type header without Content-Length,"
          + " assign_headers() writes a synthesized 'Content-Length: 0' header into the shared"
          + " connection-pool table (req->headers) after cloning the request-private table"
          + " (r->headers_in), enabling concurrent worker threads to corrupt the heap allocator."
          + " Exploitability has been proven: Apache's crash-tolerant multi-worker architecture"
          + " allows unlimited attempts to probe and align heap state and pivot RIP to ROP gadgets"
          + " in libc or httpd to achieve unauthenticated Remote Code Execution.";

  @VisibleForTesting
  static final String VULN_RECOMMENDATION =
      "Upgrade Apache HTTP Server to version 2.4.71 or later (or apply your Linux distribution's"
          + " security update backporting commit 824beab9b9424d6cfb29595248fdbf6c3dddeab1). If"
          + " immediate patching is not possible, disable HTTP/2 by removing 'h2' and 'h2c' from"
          + " all Protocols directives.";

  @VisibleForTesting
  static final String DETECTION_EVIDENCE_DESCRIPTION =
      "HTTP/2 assign_headers() causal-ablation verification evidence.";

  private static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(5);
  private static final int DEFAULT_HTTP_PORT = 80;
  private static final int DEFAULT_HTTPS_PORT = 443;
  private static final int MAX_CRAWLED_FALLBACKS = 2;

  private static final String PROBE_HEADER_WIRE_NAME = "x-tsunami-probe";
  private static final String PROBE_HEADER_CAMEL_NAME = "X-Tsunami-Probe";
  private static final String PROBE_CONTENT_TYPE_VAL = "text/plain";
  private static final byte[] emptyBody = new byte[0];
  private static final byte[] traceBodyBytes = "x".getBytes(ISO_8859_1);

  private static final ImmutableSet<String> EXTRA_HTTP_SERVICE_NAMES =
      ImmutableSet.of("https-alt", "ssl/https-alt", "http over ssl");

  private static final ImmutableSet<String> PORT_GATED_SERVICE_NAMES =
      ImmutableSet.of("", "unknown", "ssl/unknown", "tcpwrapped");

  private static final ImmutableSet<Integer> STANDARD_WEB_PORTS =
      ImmutableSet.of(80, 443, 8008, 8080, 8088, 8443);

  private static final SecureRandom SECURE_RANDOM = new SecureRandom();

  private final Clock utcClock;
  private final TransportConnector connector;
  private final Duration timeout;
  private final Supplier<String> nonceSupplier;

  @Inject
  Cve2026119618Detector(@UtcClock Clock utcClock, TsunamiSocketFactory socketFactory) {
    this(
        utcClock,
        H2ProbeSession.defaultConnector(checkNotNull(socketFactory)),
        DEFAULT_TIMEOUT,
        Cve2026119618Detector::randomHexNonce);
  }

  @VisibleForTesting
  Cve2026119618Detector(
      Clock utcClock,
      TransportConnector connector,
      Duration timeout,
      Supplier<String> nonceSupplier) {
    this.utcClock = checkNotNull(utcClock);
    this.connector = checkNotNull(connector);
    this.timeout = checkNotNull(timeout);
    this.nonceSupplier = checkNotNull(nonceSupplier);
  }

  @Override
  public ImmutableList<Vulnerability> getAdvisories() {
    return ImmutableList.of(
        Vulnerability.newBuilder()
            .setMainId(
                VulnerabilityId.newBuilder()
                    .setPublisher(VULN_REPORT_PUBLISHER)
                    .setValue(VULN_REPORT_ID))
            .addRelatedId(
                VulnerabilityId.newBuilder().setPublisher("CVE").setValue("CVE-2026-119618"))
            .setSeverity(Severity.CRITICAL)
            .setTitle(VULN_REPORT_TITLE)
            .setDescription(VULN_DESCRIPTION)
            .setRecommendation(VULN_RECOMMENDATION)
            .build());
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    checkNotNull(targetInfo);
    checkNotNull(matchedServices);

    DetectionReportList.Builder reports = DetectionReportList.newBuilder();
    for (NetworkService service : matchedServices) {
      if (!isSupportedService(service)) {
        continue;
      }
      detectService(targetInfo, service).ifPresent(reports::addDetectionReports);
    }
    return reports.build();
  }

  private Optional<DetectionReport> detectService(TargetInfo targetInfo, NetworkService service) {
    ImmutableList<TransportMode> transports = preferredTransports(service);
    int defaultPort =
        transports.get(0) == TransportMode.H2_TLS ? DEFAULT_HTTPS_PORT : DEFAULT_HTTP_PORT;

    Optional<EndpointTarget> targetOpt =
        TraceEchoParser.resolveEndpointTarget(service.getNetworkEndpoint(), defaultPort);
    if (targetOpt.isEmpty()) {
      return Optional.empty();
    }
    EndpointTarget target = targetOpt.get();
    ImmutableList<String> candidatePaths =
        TraceEchoParser.extractCandidatePaths(service, MAX_CRAWLED_FALLBACKS);

    for (TransportMode mode : transports) {
      try {
        Optional<DetectionEvidence> evOpt = probeTransport(mode, target, candidatePaths);
        if (evOpt.isPresent()) {
          return Optional.of(buildDetectionReport(targetInfo, service, evOpt.get()));
        }
      } catch (IOException e) {
        logger.atFine().withCause(e).log( // NOMUTANTS -- diagnostic logging
            "HTTP/2 %s probe on %s:%s did not match", mode.wireLabel, target.dialHost, target.port);
      }
    }
    return Optional.empty();
  }

  @VisibleForTesting
  static boolean isSupportedService(NetworkService service) {
    TransportProtocol tp = service.getTransportProtocol();
    if (tp != TransportProtocol.TRANSPORT_PROTOCOL_UNSPECIFIED && tp != TransportProtocol.TCP) {
      return false;
    }
    if (NetworkServiceUtils.isWebService(service)) {
      return true;
    }
    String name = Ascii.toLowerCase(service.getServiceName().trim());
    if (EXTRA_HTTP_SERVICE_NAMES.contains(name)) {
      return true;
    }
    if (PORT_GATED_SERVICE_NAMES.contains(name)) {
      return STANDARD_WEB_PORTS.contains(service.getNetworkEndpoint().getPort().getPortNumber());
    }
    return false;
  }

  @VisibleForTesting
  static ImmutableList<TransportMode> preferredTransports(NetworkService service) {
    String name = Ascii.toLowerCase(service.getServiceName().trim());
    int port = service.getNetworkEndpoint().getPort().getPortNumber();
    boolean tlsFirst =
        !service.getSupportedSslVersionsList().isEmpty()
            || name.contains("https")
            || name.contains("ssl")
            || port == 443
            || port == 8443;
    if (tlsFirst) {
      return ImmutableList.of(TransportMode.H2_TLS, TransportMode.H2C);
    }
    return ImmutableList.of(TransportMode.H2C, TransportMode.H2_TLS);
  }

  private Optional<DetectionEvidence> probeTransport(
      TransportMode mode, EndpointTarget target, ImmutableList<String> candidatePaths)
      throws IOException {
    try (H2ProbeSession session =
        H2ProbeSession.open(
            connector, mode, target.dialHost, target.port, target.sniHost, timeout)) {
      String scheme = mode == TransportMode.H2_TLS ? "https" : "http";
      String authority = target.authorityForMode(mode);

      for (String reqPath : candidatePaths) {
        ProbeStepResult step = probeCandidatePath(session, mode, scheme, authority, reqPath);
        if (step.evidence.isPresent()) {
          return step.evidence;
        }
        if (step.stopPaths) {
          return Optional.empty();
        }
      }
    }
    return Optional.empty();
  }

  private ProbeStepResult probeCandidatePath(
      H2ProbeSession session, TransportMode mode, String scheme, String authority, String reqPath)
      throws IOException {
    // Stream 1 (Differential assign_headers() Probe):
    // Body-less (END_STREAM) TRACE with lowercase content-type and random canary header,
    // omitting content-length (6 total headers < 10 APR table slots).
    String nonce1 = nonceSupplier.get();
    H2Response resp1 =
        session.roundTrip(
            traceHeaders(scheme, authority, reqPath, nonce1, PROBE_CONTENT_TYPE_VAL, ""),
            emptyBody);
    // TraceEnable Off is server-wide in Apache core; abort immediately without probing
    // fallback crawled paths.
    if (resp1.status.equals("405") || resp1.status.equals("501")) {
      return ProbeStepResult.STOP_EMPTY;
    }
    if (!resp1.status.equals("200")) {
      return ProbeStepResult.CONTINUE_NEXT_PATH;
    }
    if (!TraceEchoParser.isMessageHttpContentType(resp1.contentType)) {
      return ProbeStepResult.STOP_EMPTY;
    }
    Optional<ParsedTraceEcho> echo1Opt = TraceEchoParser.parseTraceEcho(resp1.body);
    if (echo1Opt.isEmpty()) {
      return ProbeStepResult.STOP_EMPTY;
    }
    ParsedTraceEcho echo1 = echo1Opt.get();
    if (!matchesApacheH2TraceBase(echo1, reqPath, authority, nonce1)
        || !echo1.hasExactCaseHeader("Content-Type", PROBE_CONTENT_TYPE_VAL)
        || echo1.hasHeaderIgnoreCase("Content-Length")) {
      return ProbeStepResult.STOP_EMPTY;
    }

    // Stream 3 (Explicit Content-Length: 0 Positive Control):
    // Confirms r->headers_in echoes Content-Length: 0 when explicitly supplied, ruling out
    // mod_headers "RequestHeader unset Content-Length" on patched servers.
    String nonce2 = nonceSupplier.get();
    H2Response resp2 =
        session.roundTrip(
            traceHeaders(scheme, authority, reqPath, nonce2, PROBE_CONTENT_TYPE_VAL, "0"),
            emptyBody);
    if (!resp2.status.equals("200")
        || !TraceEchoParser.isMessageHttpContentType(resp2.contentType)) {
      return ProbeStepResult.STOP_EMPTY;
    }
    Optional<ParsedTraceEcho> echo2Opt = TraceEchoParser.parseTraceEcho(resp2.body);
    if (echo2Opt.isEmpty()) {
      return ProbeStepResult.STOP_EMPTY;
    }
    ParsedTraceEcho echo2 = echo2Opt.get();
    if (!matchesApacheH2TraceBase(echo2, reqPath, authority, nonce2)
        || !echo2.hasExactCaseHeader("Content-Length", "0")) {
      return ProbeStepResult.STOP_EMPTY;
    }

    // Stream 5 (Apache ap_send_http_trace 1-Byte Body Control):
    // Under default TraceEnable on, Apache rejects TRACE bodies with 413; under TraceEnable
    // extended, Apache returns 200 message/http with Content-Length: 1 and echoes the 1-byte
    // body after the blank header terminator.
    String nonce3 = nonceSupplier.get();
    H2Response resp3 =
        session.roundTrip(
            traceHeaders(scheme, authority, reqPath, nonce3, "", "1"), traceBodyBytes);
    Optional<String> stream5Summary = verifyStream5BodyControl(resp3, reqPath, authority, nonce3);
    if (stream5Summary.isEmpty()) {
      return ProbeStepResult.STOP_EMPTY;
    }

    return ProbeStepResult.found(
        new DetectionEvidence(mode, authority, reqPath, stream5Summary.get()));
  }

  private static ImmutableList<HeaderField> traceHeaders(
      String scheme,
      String authority,
      String reqPath,
      String nonce,
      String contentType,
      String contentLength) {
    ImmutableList.Builder<HeaderField> hdrs =
        ImmutableList.<HeaderField>builderWithExpectedSize(7)
            .add(new HeaderField(":method", "TRACE"))
            .add(new HeaderField(":scheme", scheme))
            .add(new HeaderField(":authority", authority))
            .add(new HeaderField(":path", reqPath));
    if (!contentType.isEmpty()) {
      hdrs.add(new HeaderField("content-type", contentType));
    }
    if (!contentLength.isEmpty()) {
      hdrs.add(new HeaderField("content-length", contentLength));
    }
    return hdrs.add(new HeaderField(PROBE_HEADER_WIRE_NAME, nonce)).build();
  }

  private static final class ProbeStepResult {
    static final ProbeStepResult STOP_EMPTY = new ProbeStepResult(true);
    static final ProbeStepResult CONTINUE_NEXT_PATH = new ProbeStepResult(false);

    final Optional<DetectionEvidence> evidence;
    boolean stopPaths;

    private ProbeStepResult(boolean stopPaths) {
      this.evidence = Optional.empty();
      this.stopPaths = stopPaths;
    }

    private ProbeStepResult(DetectionEvidence ev) {
      this.evidence = Optional.of(ev);
    }

    static ProbeStepResult found(DetectionEvidence ev) {
      return new ProbeStepResult(ev);
    }
  }

  private static boolean matchesApacheH2TraceBase(
      ParsedTraceEcho echo, String reqPath, String authority, String nonce) {
    String expectedReqLine = "TRACE " + reqPath + " HTTP/2.0";
    if (!echo.requestLine.equals(expectedReqLine)) {
      return false;
    }
    if (!echo.hasExactCaseHeader("Host", authority)) {
      return false;
    }
    return echo.hasExactCaseHeader(PROBE_HEADER_CAMEL_NAME, nonce);
  }

  private static Optional<String> verifyStream5BodyControl(
      H2Response resp, String reqPath, String authority, String nonce) {
    if (resp.status.equals("413")) {
      return Optional.of("HTTP 413 (TraceEnable on)");
    }
    if (!resp.status.equals("200") || !TraceEchoParser.isMessageHttpContentType(resp.contentType)) {
      return Optional.empty();
    }
    Optional<ParsedTraceEcho> echoOpt = TraceEchoParser.parseTraceEcho(resp.body);
    if (echoOpt.isEmpty()) {
      return Optional.empty();
    }
    ParsedTraceEcho echo = echoOpt.get();
    if (!matchesApacheH2TraceBase(echo, reqPath, authority, nonce)
        || !echo.hasExactCaseHeader("Content-Length", "1")
        || !Arrays.equals(echo.body, traceBodyBytes)) {
      return Optional.empty();
    }
    return Optional.of("HTTP 200 echoed 1-byte body (TraceEnable extended)");
  }

  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo, NetworkService service, DetectionEvidence ev) {
    String scheme = ev.mode == TransportMode.H2_TLS ? "https" : "http";
    String detailText =
        String.format(
            "Verified unpatched Apache mod_http2 assign_headers() over HTTP/2 (%s) at"
                + " %s://%s%s: Stream 1 omitted synthesized 'Content-Length: 0' in r->headers_in,"
                + " Stream 3 confirmed explicit 'Content-Length: 0' preservation, and Stream 5"
                + " confirmed ap_send_http_trace body handling (%s).",
            ev.mode.wireLabel, scheme, ev.authority, ev.path, ev.stream5Info);

    AdditionalDetail evidence =
        AdditionalDetail.newBuilder()
            .setDescription(DETECTION_EVIDENCE_DESCRIPTION)
            .setTextData(TextData.newBuilder().setText(detailText))
            .build();

    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(service)
        .setDetectionTimestamp(Timestamps.fromMillis(utcClock.instant().toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(getAdvisories().get(0).toBuilder().addAdditionalDetails(evidence).build())
        .build();
  }

  @VisibleForTesting
  static String randomHexNonce() {
    byte[] bytes = new byte[8];
    SECURE_RANDOM.nextBytes(bytes);
    return BaseEncoding.base16().lowerCase().encode(bytes);
  }

  private static final class DetectionEvidence {
    final TransportMode mode;
    final String authority;
    final String path;
    final String stream5Info;

    DetectionEvidence(TransportMode mode, String authority, String path, String stream5Info) {
      this.mode = mode;
      this.authority = authority;
      this.path = path;
      this.stream5Info = stream5Info;
    }
  }
}
