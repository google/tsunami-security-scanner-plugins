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
import static com.google.common.collect.ImmutableList.toImmutableList;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.net.HostAndPort;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkEndpointUtils;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.socket.TsunamiSocketFactory;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.ForWebService;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.plugins.detectors.rce.cve2026123007.H2FlowControlProbe.ProbeMatch;
import com.google.tsunami.plugins.detectors.rce.cve2026123007.H2FlowControlProbe.ProbeOutcome;
import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.CrawlResult;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkEndpoint;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TextData;
import com.google.tsunami.proto.TransportProtocol;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.time.Clock;
import java.time.Duration;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;
import javax.inject.Inject;

/**
 * A {@link VulnDetector} that detects unpatched NGINX {@code ngx_http_v2} servers vulnerable to the
 * queued-frame flow-control window validation bypass and heap buffer overflow ({@code
 * CVE-2026-123007}).
 *
 * <p>Detection is strictly non-destructive: the probe never sends {@code RST_STREAM} frames and
 * closes connections cleanly after draining so {@code ngx_http_v2_finalize_connection} clears
 * {@code stream->queued} without triggering any window refund or worker crash.
 */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "Cve2026123007Detector",
    version = "0.1",
    description =
        "Detects NGINX HTTP/2 servers (1.9.5 through 1.30.6 and 1.31.0 through 1.31.8) vulnerable"
            + " to the queued-frame Stream 0 WINDOW_UPDATE validation bypass and heap buffer"
            + " overflow (CVE-2026-123007).",
    author = "Tsunami Team (tsunami-dev@google.com)",
    bootstrapModule = Cve2026123007DetectorBootstrapModule.class)
@ForWebService
public final class Cve2026123007Detector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(8);
  private static final int MAX_CRAWLED_CANDIDATES = 3;

  private final Clock utcClock;
  private final H2FlowControlProbe probe;

  @Inject
  Cve2026123007Detector(@UtcClock Clock utcClock, TsunamiSocketFactory socketFactory) {
    this(
        utcClock,
        new H2FlowControlProbe(
            socketFactory,
            socketFactory.getDefaultReadTimeout().isPositive()
                ? socketFactory.getDefaultReadTimeout()
                : DEFAULT_TIMEOUT));
  }

  @VisibleForTesting
  Cve2026123007Detector(Clock utcClock, H2FlowControlProbe probe) {
    this.utcClock = checkNotNull(utcClock);
    this.probe = checkNotNull(probe);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log( // NOMUTANTS -- diagnostic logging
        "Cve2026123007Detector starts detecting.");
    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(Cve2026123007Detector::isSupportedService)
                .flatMap(service ->
                    probeService(service).stream()
                        .map(match -> buildDetectionReport(targetInfo, service, match)))
                .collect(toImmutableList()))
        .build();
  }

  @Override
  public ImmutableList<Vulnerability> getAdvisories() {
    return ImmutableList.of(buildBaseVulnerability());
  }

  @VisibleForTesting
  static boolean isSupportedService(NetworkService service) {
    TransportProtocol tp = service.getTransportProtocol();
    if (tp != TransportProtocol.TCP && tp != TransportProtocol.TRANSPORT_PROTOCOL_UNSPECIFIED) {
      return false;
    }
    if (!NetworkServiceUtils.isWebService(service)) {
      return false;
    }
    NetworkEndpoint endpoint = service.getNetworkEndpoint();
    if (!NetworkEndpointUtils.hasPort(endpoint)) {
      return false;
    }
    int port = endpoint.getPort().getPortNumber();
    return port > 0 && port <= NetworkEndpointUtils.MAX_PORT_NUMBER;
  }

  private Optional<ProbeMatch> probeService(NetworkService service) {
    NetworkEndpoint endpoint = service.getNetworkEndpoint();
    HostAndPort hostAndPort;
    try {
      hostAndPort = NetworkEndpointUtils.toHostAndPort(endpoint);
    } catch (IllegalArgumentException e) {
      logger.atFine().withCause(e).log( // NOMUTANTS -- diagnostic logging
          "Skipping service with malformed network endpoint.");
      return Optional.empty();
    }

    String authorityHost = hostAndPort.getHost();
    int port = endpoint.getPort().getPortNumber();
    if (!H2FlowControlProbe.isValidAuthorityHost(authorityHost)) {
      logger.atFine().log( // NOMUTANTS -- diagnostic logging
          "Skipping service with invalid authority host '%s'.", authorityHost);
      return Optional.empty();
    }

    String dialHost =
        !endpoint.getIpAddress().getAddress().isEmpty()
            ? endpoint.getIpAddress().getAddress()
            : authorityHost;
    if (!H2FlowControlProbe.isValidAuthorityHost(dialHost)) {
      logger.atFine().log( // NOMUTANTS -- diagnostic logging
          "Skipping service with invalid dial host '%s'.", dialHost);
      return Optional.empty();
    }
    ImmutableList<String> crawledPaths = extractCrawledCandidatePaths(service);

    if (!NetworkServiceUtils.isPlainHttp(service)) {
      String tlsAuthority =
          H2FlowControlProbe.formatAuthority(authorityHost, port, /* useTls= */ true);
      return probe.probeTlsH2(dialHost, authorityHost, port, tlsAuthority, crawledPaths).match();
    }

    String h2cAuthority =
        H2FlowControlProbe.formatAuthority(authorityHost, port, /* useTls= */ false);
    ProbeOutcome h2cOutcome = probe.probeCleartextH2c(dialHost, port, h2cAuthority, crawledPaths);
    if (h2cOutcome.match().isPresent()) {
      return h2cOutcome.match();
    }

    // Custom-port TLS HTTP/2 listeners sometimes reach VulnDetectors without SSL fingerprint
    // metadata (e.g. when Nmap version/SSL scripts were skipped); retry over TLS ALPN "h2" when
    // the cleartext h2c preface triggers an immediate non-timeout protocol rejection or EOF.
    if (h2cOutcome.status() == ProbeOutcome.Status.FAST_PROTOCOL_MISMATCH) {
      String tlsAuthority =
          H2FlowControlProbe.formatAuthority(authorityHost, port, /* useTls= */ true);
      return probe.probeTlsH2(dialHost, authorityHost, port, tlsAuthority, crawledPaths).match();
    }
    return Optional.empty();
  }

  private static ImmutableList<String> extractCrawledCandidatePaths(NetworkService service) {
    if (!service.getServiceContext().hasWebServiceContext()) {
      return ImmutableList.of();
    }
    Set<String> paths = new LinkedHashSet<>();
    for (CrawlResult cr :
        service.getServiceContext().getWebServiceContext().getCrawlResultsList()) {
      Optional<String> safePath =
          H2FlowControlProbe.extractSafeLocalPath(cr.getCrawlTarget().getUrl());
      if (safePath.isPresent()
          && !safePath.get().equals("/")
          && H2FlowControlProbe.hasStaticExtension(safePath.get())) {
        paths.add(safePath.get());
        if (paths.size() >= MAX_CRAWLED_CANDIDATES) {
          break;
        }
      }
    }
    return ImmutableList.copyOf(paths);
  }

  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo, NetworkService service, ProbeMatch match) {
    Vulnerability vuln =
        buildBaseVulnerability().toBuilder()
            .addAdditionalDetails(
                AdditionalDetail.newBuilder()
                    .setDescription(
                        "Non-destructive NGINX HTTP/2 queued-frame Stream 0 WINDOW_UPDATE"
                            + " verification evidence")
                    .setTextData(TextData.newBuilder().setText(match.formatDetailText())))
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
        .setMainId(VulnerabilityId.newBuilder().setPublisher("GOOGLE").setValue("CVE-2026-123007"))
        .addRelatedId(VulnerabilityId.newBuilder().setPublisher("CVE").setValue("CVE-2026-123007"))
        .setSeverity(Severity.CRITICAL)
        .setTitle(
            "NGINX HTTP/2 Queued-Frame Flow-Control Window Validation Bypass Heap Buffer Overflow"
                + " (CVE-2026-123007)")
        .setDescription(
            "NGINX Open Source versions 1.9.5 through 1.30.6 and 1.31.0 through 1.31.8 (and"
                + " unpatched NGINX Plus and distribution builds) with HTTP/2 enabled fail to"
                + " account for unsent DATA frame bytes queued in h2c->last_out when validating"
                + " connection-level Stream 0 WINDOW_UPDATE increments in"
                + " ngx_http_v2_state_window_update(). Under TCP send-buffer backpressure, an"
                + " unauthenticated remote attacker can replenish h2c->send_window to"
                + " NGX_HTTP_V2_MAX_WINDOW while DATA frames remain queued and then cancel those"
                + " streams, pushing h2c->send_window past 0x7fffffff and triggering integer"
                + " wrap-around and heap buffer overflow in worker memory.")
        .setRecommendation(
            "Upgrade NGINX Open Source to version 1.30.7 or later (stable) or 1.31.9 or later"
                + " (mainline), upgrade NGINX Plus to a fixed release per F5 advisory K000164058,"
                + " or apply your OS distribution security update containing commit"
                + " e27f5fa84fe6e98505e70bc543b748747dad0a3b. If immediate patching is not"
                + " possible, disable direct HTTP/2 termination ('http2 off;').")
        .build();
  }
}
