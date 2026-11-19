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
import static com.google.common.base.Strings.isNullOrEmpty;
import static com.google.tsunami.common.net.http.HttpRequest.get;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Ascii;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.flogger.GoogleLogger;
import com.google.common.net.HostAndPort;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkEndpointUtils;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.common.net.socket.TsunamiSocketFactory;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.ForServiceName;
import com.google.tsunami.plugin.annotations.ForWebService;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.plugins.detectors.rce.dask.DaskCommClient.CommResult;
import com.google.tsunami.plugins.detectors.rce.dask.DaskCommClient.ProbeOutcome;
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
import java.net.URI;
import java.net.URISyntaxException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.Set;
import java.util.function.IntSupplier;
import javax.inject.Inject;

/**
 * A {@link VulnDetector} that detects exposed unauthenticated Dask Distributed and NVIDIA RAPIDS
 * ({@code dask-cuda}) cluster endpoints allowing remote code execution.
 */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "DaskUnauthenticatedRceDetector",
    version = "0.1",
    description =
        "Detects exposed unauthenticated Dask Distributed and NVIDIA RAPIDS cluster endpoints"
            + " allowing remote code execution.",
    author = "Tsunami Security Scanner",
    bootstrapModule = DaskUnauthenticatedRceDetectorBootstrapModule.class)
@ForWebService
@ForServiceName({
  "msgclnt",
  "msgsrvr",
  "dask",
  "dask-scheduler",
  "dask-worker",
  "dask-nanny",
  "unknown",
  "ssl/msgclnt",
  "ssl/msgsrvr",
  "ssl/dask",
  "ssl/dask-scheduler",
  "ssl/dask-worker",
  "ssl/dask-nanny",
  "ssl/unknown",
  "tcpwrapped",
  "ssl/tcpwrapped"
})
public final class DaskUnauthenticatedRceDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  @VisibleForTesting static final String VULNERABILITY_REPORT_PUBLISHER = "GOOGLE";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_ID = "DASK_DISTRIBUTED_UNAUTHENTICATED_RCE";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_TITLE =
      "Exposed Unauthenticated Dask Distributed Cluster RCE";

  @VisibleForTesting
  static final String VULN_DESCRIPTION =
      "The target exposes an unauthenticated Dask Distributed (or NVIDIA RAPIDS dask-cuda) cluster"
          + " RPC endpoint (or a Dask Bokeh dashboard advertising a reachable unauthenticated"
          + " scheduler RPC endpoint) that permits arbitrary Python code execution via the"
          + " 'run_function', 'broadcast', or 'run' Comm RPC handlers without TLS"
          + " client-certificate authentication.";

  @VisibleForTesting
  static final String RECOMMENDATION =
      "Restrict network access to Dask Scheduler (default TCP 8786) and Dashboard (default HTTP"
          + " 8787) ports using firewall rules or private cluster networking, enforce mutual TLS"
          + " authentication ('distributed.comm.require-encryption: true' with"
          + " 'distributed.comm.tls.ca-file' and node certificates), and block arbitrary"
          + " code-execution RPC handlers ('distributed.scheduler.blocked-handlers: [broadcast,"
          + " feed, run, run_function]', 'distributed.worker.blocked-handlers: [run]', and"
          + " 'distributed.nanny.blocked-handlers: [run]').";

  private static final int DEFAULT_SCHEDULER_PORT = 8786;
  private static final int DEFAULT_DASHBOARD_PORT = 8787;
  private static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(5);
  private static final int MIN_PROBE_OPERAND = 10_000_000;
  private static final int OPERAND_SPAN = 40_000_000;

  private static final ImmutableSet<String> RAW_COMM_SERVICE_NAMES =
      ImmutableSet.of(
          "",
          "msgclnt",
          "msgsrvr",
          "dask",
          "dask-scheduler",
          "dask-worker",
          "dask-nanny",
          "unknown",
          "ssl/msgclnt",
          "ssl/msgsrvr",
          "ssl/dask",
          "ssl/dask-scheduler",
          "ssl/dask-worker",
          "ssl/dask-nanny",
          "ssl/unknown");

  private final Clock utcClock;
  private final HttpClient httpClient;
  private final DaskCommClient commClient;
  private final IntSupplier operandSupplier;

  @Inject
  DaskUnauthenticatedRceDetector(
      @UtcClock Clock utcClock, HttpClient httpClient, TsunamiSocketFactory socketFactory) {
    this(
        utcClock,
        httpClient,
        new DaskCommClient(checkNotNull(socketFactory), DEFAULT_TIMEOUT),
        createSecureOperandSupplier());
  }

  @VisibleForTesting
  DaskUnauthenticatedRceDetector(
      Clock utcClock,
      HttpClient httpClient,
      DaskCommClient commClient,
      IntSupplier operandSupplier) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(false).build();
    this.commClient = checkNotNull(commClient);
    this.operandSupplier = checkNotNull(operandSupplier);
  }

  @VisibleForTesting
  static IntSupplier createSecureOperandSupplier() {
    SecureRandom rng = new SecureRandom();
    // NOMUTANTS(AOR): Uniform 90M SecureRandom span; +/-1 shift is unobservable.
    return () -> MIN_PROBE_OPERAND + rng.nextInt(OPERAND_SPAN);
  }

  @Override
  public ImmutableList<Vulnerability> getAdvisories() {
    return ImmutableList.of(buildBaseVulnerability());
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log( // NOMUTANTS -- diagnostic logging
        "DaskUnauthenticatedRceDetector starts detecting.");

    ImmutableSet.Builder<HostAndPort> matchedTcpEndpoints = ImmutableSet.builder();
    for (NetworkService service : matchedServices) {
      TransportProtocol tp = service.getTransportProtocol();
      if (tp == TransportProtocol.TCP || tp == TransportProtocol.TRANSPORT_PROTOCOL_UNSPECIFIED) {
        HostAndPort ep = NetworkEndpointUtils.toHostAndPort(service.getNetworkEndpoint());
        if (ep.hasPort()) {
          matchedTcpEndpoints.add(
              HostAndPort.fromParts(resolveEndpointHost(service, ep), ep.getPort()));
        }
      }
    }

    List<NetworkService> orderedServices = new ArrayList<>();
    for (NetworkService service : matchedServices) {
      if (isSupportedService(service) && !NetworkServiceUtils.isWebService(service)) {
        orderedServices.add(service);
      }
    }
    for (NetworkService service : matchedServices) {
      if (isSupportedService(service) && NetworkServiceUtils.isWebService(service)) {
        orderedServices.add(service);
      }
    }

    ScanContext scanContext = new ScanContext(targetInfo, matchedTcpEndpoints.build());
    DetectionReportList.Builder reports = DetectionReportList.newBuilder();
    for (NetworkService service : orderedServices) {
      checkService(scanContext, service).ifPresent(reports::addDetectionReports);
    }
    return reports.build();
  }

  @VisibleForTesting
  static boolean isSupportedService(NetworkService service) {
    TransportProtocol tp = service.getTransportProtocol();
    if (tp != TransportProtocol.TCP && tp != TransportProtocol.TRANSPORT_PROTOCOL_UNSPECIFIED) {
      return false;
    }
    if (NetworkServiceUtils.isWebService(service)) {
      return true;
    }
    int port = service.getNetworkEndpoint().getPort().getPortNumber();
    if (port == DEFAULT_SCHEDULER_PORT || port == DEFAULT_DASHBOARD_PORT) {
      return true;
    }
    String serviceName = Ascii.toLowerCase(service.getServiceName().trim());
    return RAW_COMM_SERVICE_NAMES.contains(serviceName);
  }

  private Optional<DetectionReport> checkService(ScanContext scanContext, NetworkService service) {
    HostAndPort endpoint = NetworkEndpointUtils.toHostAndPort(service.getNetworkEndpoint());
    String host = resolveEndpointHost(service, endpoint);
    if (NetworkServiceUtils.isWebService(service)) {
      boolean webTls = !NetworkServiceUtils.isPlainHttp(service);
      HostAndPort directEndpoint =
          HostAndPort.fromParts(host, endpoint.getPortOrDefault(webTls ? 443 : 80));
      return probeWebCandidate(scanContext, service, directEndpoint, webTls);
    }

    int port = endpoint.getPortOrDefault(DEFAULT_SCHEDULER_PORT);
    HostAndPort directEndpoint = HostAndPort.fromParts(host, port);
    if (scanContext.isCompleted(directEndpoint)) {
      return Optional.empty();
    }
    String svcName = Ascii.toLowerCase(service.getServiceName().trim());
    boolean useTls = service.getSupportedSslVersionsCount() > 0 || svcName.startsWith("ssl/");
    int a = operandSupplier.getAsInt();
    int b = operandSupplier.getAsInt();
    switch (commClient.probeTcp(host, port, useTls, a, b)) {
      case ProbeOutcome.Vulnerable(CommResult commResult) -> {
        return Optional.of(recordDetection(scanContext, service, directEndpoint, commResult, ""));
      }
      case ProbeOutcome.NonVulnerable.CONFIRMED_DASK_NOT_VULNERABLE -> {
        scanContext.markCompleted(directEndpoint);
        return Optional.empty();
      }
      case ProbeOutcome.NonVulnerable.NOT_DASK -> {} // Fall through to Web/WS probes.
    }

    // Fallback when Nmap labeled Dashboard (8787 / msgsrvr) or WS Comm (8786 / msgclnt) without
    // web service recognition.
    String baseName = svcName.startsWith("ssl/") ? svcName.substring(4) : svcName;
    if (port == DEFAULT_DASHBOARD_PORT || baseName.equals("msgsrvr")) {
      return probeWebCandidate(scanContext, service, directEndpoint, useTls);
    }
    if (port == DEFAULT_SCHEDULER_PORT
        || baseName.equals("msgclnt")
        || baseName.startsWith("dask")) {
      return commClient
          .probeWebSocket(
              host, port, "/", useTls, operandSupplier.getAsInt(), operandSupplier.getAsInt())
          .map(res -> recordDetection(scanContext, service, directEndpoint, res, ""));
    }
    return Optional.empty();
  }

  private Optional<DetectionReport> probeWebCandidate(
      ScanContext scanContext, NetworkService service, HostAndPort directEndpoint, boolean useTls) {
    if (scanContext.isCompleted(directEndpoint)) {
      return Optional.empty();
    }
    String host = directEndpoint.getHost();
    int port = directEndpoint.getPort();
    String appPath = extractAppRootPath(service);
    ImmutableList<String> wsPaths =
        appPath.equals("/") ? ImmutableList.of("/") : ImmutableList.of(appPath, "/");
    for (String wsPath : wsPaths) {
      Optional<CommResult> wsResult =
          commClient.probeWebSocket(
              host, port, wsPath, useTls, operandSupplier.getAsInt(), operandSupplier.getAsInt());
      if (wsResult.isPresent()) {
        return Optional.of(
            recordDetection(scanContext, service, directEndpoint, wsResult.get(), ""));
      }
    }

    return discoverDashboardComm(service, useTls, appPath)
        .flatMap(dash -> probeAdvertisedDashboardTarget(scanContext, service, host, appPath, dash));
  }

  private Optional<DetectionReport> probeAdvertisedDashboardTarget(
      ScanContext scanContext,
      NetworkService service,
      String host,
      String appPath,
      DashboardTarget dash) {
    HostAndPort advEndpoint = HostAndPort.fromParts(host, dash.port());
    if (scanContext.isCompleted(advEndpoint)) {
      return Optional.empty();
    }
    if (!scanContext.isAdvertisedPortInScope(advEndpoint)) {
      logger.atFine().log( // NOMUTANTS -- diagnostic logging
          "Skipping Dask Dashboard advertised port %d on %s outside matchedServices and default"
              + " scheduler port %d.",
          dash.port(), host, DEFAULT_SCHEDULER_PORT);
      return Optional.empty();
    }

    if (dash.scheme().equals("ws") || dash.scheme().equals("wss")) {
      String wsPath = dash.wsPath();
      if (!wsPath.equals("/") && !wsPath.equals(appPath)) {
        logger.atFine().log( // NOMUTANTS -- diagnostic logging
            "Skipping Dask Dashboard advertised WebSocket path '%s' outside '/' and '%s'.",
            wsPath, appPath);
        return Optional.empty();
      }
      return commClient
          .probeWebSocket(
              host,
              dash.port(),
              wsPath,
              dash.scheme().equals("wss"),
              operandSupplier.getAsInt(),
              operandSupplier.getAsInt())
          .map(res -> recordDetection(scanContext, service, advEndpoint, res, dash.identityUrl()));
    }

    return switch (commClient.probeTcp(
        host,
        dash.port(),
        /* useTls= */ false,
        operandSupplier.getAsInt(),
        operandSupplier.getAsInt())) {
      case ProbeOutcome.Vulnerable(CommResult commResult) ->
          Optional.of(
              recordDetection(scanContext, service, advEndpoint, commResult, dash.identityUrl()));
      case ProbeOutcome.NonVulnerable.CONFIRMED_DASK_NOT_VULNERABLE -> {
        scanContext.markCompleted(advEndpoint);
        yield Optional.empty();
      }
      case ProbeOutcome.NonVulnerable.NOT_DASK -> Optional.empty();
    };
  }

  private DetectionReport recordDetection(
      ScanContext scanContext,
      NetworkService service,
      HostAndPort endpointKey,
      CommResult commResult,
      String discoveryUrl) {
    scanContext.markCompleted(endpointKey);
    return buildDetectionReport(scanContext.targetInfo(), service, commResult, discoveryUrl);
  }

  private static String resolveEndpointHost(NetworkService service, HostAndPort endpoint) {
    String ip = service.getNetworkEndpoint().getIpAddress().getAddress().trim();
    return ip.isEmpty() ? endpoint.getHost() : ip;
  }

  @VisibleForTesting
  static String extractAppRootPath(NetworkService service) {
    String appRoot = service.getServiceContext().getWebServiceContext().getApplicationRoot().trim();
    if (appRoot.startsWith("http://") || appRoot.startsWith("https://")) {
      try {
        String rawPath = new URI(appRoot).getRawPath();
        appRoot = (rawPath == null) ? "" : rawPath;
      } catch (URISyntaxException e) {
        // Retain raw appRoot when URI parsing fails.
      }
    }
    return normalizeRootPath(appRoot);
  }

  private static String normalizeRootPath(String path) {
    int start = 0;
    while (start < path.length() && path.charAt(start) == '/') {
      start++;
    }
    int end = path.length();
    while (end > start && path.charAt(end - 1) == '/') {
      end--;
    }
    return "/" + path.substring(start, end);
  }

  @VisibleForTesting
  record DashboardTarget(String scheme, int port, String wsPath, String identityUrl) {}

  private Optional<DashboardTarget> discoverDashboardComm(
      NetworkService service, boolean useTls, String appPath) {
    String scheme = useTls ? "https" : "http";
    String authority = NetworkEndpointUtils.toUriAuthority(service.getNetworkEndpoint());
    if (!useTls && authority.endsWith(":80")) {
      authority = authority.substring(0, authority.length() - 3);
    } else if (useTls && authority.endsWith(":443")) {
      authority = authority.substring(0, authority.length() - 4);
    }

    ImmutableList<String> prefixes =
        appPath.equals("/") ? ImmutableList.of("") : ImmutableList.of(appPath, "");
    for (String prefix : prefixes) {
      String identityUrl = scheme + "://" + authority + prefix + "/json/identity.json";
      Optional<DashboardTarget> parsed = fetchDashboardIdentityUrl(service, identityUrl);
      if (parsed.isPresent()) {
        return parsed;
      }
    }
    return Optional.empty();
  }

  private Optional<DashboardTarget> fetchDashboardIdentityUrl(
      NetworkService service, String identityUrl) {
    HttpResponse response;
    try {
      response =
          httpClient.send(
              get(identityUrl)
                  .setHeaders(HttpHeaders.builder().addHeader("Connection", "close").build())
                  .build(),
              service);
    } catch (IOException e) {
      logger.atFine().withCause(e).log( // NOMUTANTS -- diagnostic logging
          "Dashboard identity request to '%s' failed.", identityUrl);
      return Optional.empty();
    }

    if (response.status() != HttpStatus.OK || response.bodyString().isEmpty()) {
      return Optional.empty();
    }
    return parseDashboardIdentityJson(response.bodyString().get(), identityUrl);
  }

  @VisibleForTesting
  static Optional<DashboardTarget> parseDashboardIdentityJson(String body, String identityUrl) {
    JsonObject root;
    try {
      JsonElement elem = JsonParser.parseString(body);
      if (!elem.isJsonObject()) {
        return Optional.empty();
      }
      root = elem.getAsJsonObject();
    } catch (JsonParseException e) {
      return Optional.empty();
    }

    String type = getJsonString(root, "type");
    String id = getJsonString(root, "id");
    String address = getJsonString(root, "address");
    if (!Objects.equals(type, "Scheduler") || id.trim().isEmpty() || address.isEmpty()) {
      return Optional.empty();
    }

    URI parsed;
    try {
      parsed = new URI(address);
    } catch (URISyntaxException e) {
      return Optional.empty();
    }
    if (parsed.getScheme() == null) {
      return Optional.empty();
    }
    String scheme = Ascii.toLowerCase(parsed.getScheme());
    if (!scheme.equals("tcp") && !scheme.equals("ws") && !scheme.equals("wss")) {
      return Optional.empty();
    }
    OptionalInt port = extractUriPort(parsed);
    if (port.isEmpty()) {
      return Optional.empty();
    }
    String wsPath = normalizeRootPath(parsed.getRawPath());
    return Optional.of(new DashboardTarget(scheme, port.getAsInt(), wsPath, identityUrl));
  }

  private static OptionalInt extractUriPort(URI parsed) {
    String rawAuthority = parsed.getRawAuthority();
    if (isNullOrEmpty(rawAuthority)) {
      return OptionalInt.empty();
    }
    String hostPort = rawAuthority.substring(rawAuthority.lastIndexOf('@') + 1);
    try {
      HostAndPort parsedHp = HostAndPort.fromString(hostPort);
      if (!parsedHp.getHost().isEmpty() && parsedHp.hasPort() && parsedHp.getPort() >= 1) {
        return OptionalInt.of(parsedHp.getPort());
      }
      return OptionalInt.empty();
    } catch (IllegalArgumentException e) {
      return OptionalInt.empty();
    }
  }

  private static String getJsonString(JsonObject obj, String key) {
    if (!obj.has(key) || !obj.get(key).isJsonPrimitive()) {
      return "";
    }
    return obj.get(key).getAsString();
  }

  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo, NetworkService service, CommResult result, String dashboardUrl) {
    String evidence =
        String.format(
            "Verified unauthenticated Dask %s (%s) code execution on %s via %s RPC handler:"
                + " operator.add(%d, %d) returned %d.",
            result.daemonType(),
            result.daemonId(),
            result.commAddress(),
            result.handler(),
            result.operandA(),
            result.operandB(),
            result.computedSum());
    if (!dashboardUrl.isEmpty()) {
      evidence =
          String.format("Discovered via exposed Dask Dashboard %s. %s", dashboardUrl, evidence);
    }

    Vulnerability vuln =
        buildBaseVulnerability().toBuilder()
            .addAdditionalDetails(
                AdditionalDetail.newBuilder()
                    .setDescription("Verified unauthenticated Dask Distributed RPC code execution")
                    .setTextData(TextData.newBuilder().setText(evidence)))
            .build();

    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(service)
        .setDetectionTimestamp(Timestamps.fromMillis(utcClock.instant().toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(vuln)
        .build();
  }

  private static Vulnerability buildBaseVulnerability() {
    return Vulnerability.newBuilder()
        .setMainId(
            VulnerabilityId.newBuilder()
                .setPublisher(VULNERABILITY_REPORT_PUBLISHER)
                .setValue(VULNERABILITY_REPORT_ID))
        .setSeverity(Severity.CRITICAL)
        .setTitle(VULNERABILITY_REPORT_TITLE)
        .setDescription(VULN_DESCRIPTION)
        .setRecommendation(RECOMMENDATION)
        .build();
  }

  private static final class ScanContext {
    private final TargetInfo targetInfo;
    private final ImmutableSet<HostAndPort> matchedTcpEndpoints;
    private final Set<HostAndPort> completedCommEndpoints = new HashSet<>();

    ScanContext(TargetInfo targetInfo, ImmutableSet<HostAndPort> matchedTcpEndpoints) {
      this.targetInfo = targetInfo;
      this.matchedTcpEndpoints = matchedTcpEndpoints;
    }

    TargetInfo targetInfo() {
      return targetInfo;
    }

    boolean isCompleted(HostAndPort endpoint) {
      return completedCommEndpoints.contains(endpoint);
    }

    void markCompleted(HostAndPort endpoint) {
      completedCommEndpoints.add(endpoint);
    }

    boolean isAdvertisedPortInScope(HostAndPort endpoint) {
      return endpoint.getPort() == DEFAULT_SCHEDULER_PORT || matchedTcpEndpoints.contains(endpoint);
    }
  }
}
