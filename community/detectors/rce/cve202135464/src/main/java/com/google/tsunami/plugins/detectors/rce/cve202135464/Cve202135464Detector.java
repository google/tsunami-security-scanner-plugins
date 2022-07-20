/*
 * Copyright 2021 Google LLC
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
package com.google.tsunami.plugins.detectors.rce.cve202135464;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.get;

import com.google.common.base.Ascii;
import com.google.common.base.Charsets;
import com.google.common.base.Stopwatch;
import com.google.common.base.Ticker;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.io.Resources;
import com.google.common.net.HttpHeaders;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.plugins.detectors.rce.cve202135464.Cve202135464DetectorBootstrapModule.StopwatchTicker;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import javax.inject.Inject;

/** A {@link VulnDetector} plugin that detects CVE-2021-35464. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "Forgerock AM/OpenAM CVE-2021-35464 Detector",
    version = "0.1",
    description =
        "Plugin detects an unauthenticated java deserialization remote code execution"
            + "vulnerability in OpenAM before 14.6.3 and ForgeRock AM before 7.0 (CVE-2021-35464).",
    author = "0xtavi",
    bootstrapModule = Cve202135464DetectorBootstrapModule.class)
public final class Cve202135464Detector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final String QUERY_STRING =
      "openam/oauth2/..;/ccversion/Version?jato.pageSession=";
  private static final long PAYLOAD_SLEEP_DURATION_SECONDS = 5;

  private final Clock utcClock;
  private final HttpClient httpClient;
  private final Ticker ticker;

  private String serializedBase64RCEPayload = null;

  @Inject
  Cve202135464Detector(
      @UtcClock Clock utcClock, @StopwatchTicker Ticker ticker, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.ticker = ticker;
    this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(false).build();
    try {
      this.serializedBase64RCEPayload =
          Resources.toString(Resources.getResource(this.getClass(), "payload.b64"), Charsets.UTF_8);
    } catch (IOException e) {
      logger.atSevere().withCause(e).log(
          "Should never happen. Couldn't load payload resource file.");
    }
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Cve202135464Detector starts detecting.");
    checkNotNull(serializedBase64RCEPayload);

    DetectionReportList detectionReports =
        DetectionReportList.newBuilder()
            .addAllDetectionReports(
                matchedServices.stream()
                    .filter(NetworkServiceUtils::isWebService)
                    .filter(this::isServiceVulnerable)
                    .map(networkService -> buildDetectionReport(targetInfo, networkService))
                    .collect(toImmutableList()))
            .build();

    logger.atInfo().log(
        "Cve202135464Detector finished, detected '%d' vulns.",
        detectionReports.getDetectionReportsCount());
    return detectionReports;
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    String targetUri =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + QUERY_STRING;

    Stopwatch stopwatch = Stopwatch.createStarted(ticker);
    try {
      HttpResponse httpResponse =
          httpClient.send(
              get(targetUri + serializedBase64RCEPayload).withEmptyHeaders().build(),
              networkService);
      stopwatch.stop();

      if (httpResponse.status().code() != 302) {
        return false;
      }

      if (!Ascii.toLowerCase(httpResponse.headers().get(HttpHeaders.LOCATION).orElse(""))
          .contains("/openam/base/aminvalidurl")) {
        return false;
      }

      long stageSeconds = stopwatch.elapsed().getSeconds();
      if (stageSeconds >= PAYLOAD_SLEEP_DURATION_SECONDS) {
        return true;
      }
      return false;
    } catch (IOException e) {
      logger.atSevere().withCause(e).log("Cve202135464Detector: Unable to query %s.", targetUri);
      return false;
    }
  }

  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo, NetworkService vulnerableNetworkService) {
    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(vulnerableNetworkService)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder()
                        .setPublisher("TSUNAMI_COMMUNITY")
                        .setValue("CVE_2021_35464"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Pre-auth RCE in OpenAM 14.6.3/ForgeRock AM 7.0 (CVE-2021-35464)")
                .setDescription(
                    "OpenAM server before 14.6.3 and ForgeRock AM server before 7.0 have"
                        + "a Java deserialization vulnerability in the jato.pageSession"
                        + "parameter on multiple pages. The exploitation does not require"
                        + "authentication, and remote code execution can be triggered by"
                        + "sending a single crafted /ccversion/* request to the server."
                        + "The vulnerability exists due to the usage of Sun ONE Application"
                        + "Framework (JATO) found in versions of Java 8 or earlier. The issue"
                        + "was fixed in commit a267913b97002228c2df45f849151e9c373bc47f from"
                        + "OpenIdentityPlatform/OpenAM:master.")
                .setRecommendation(
                    "Block access to the ccversion endpoint using a reverse proxy or"
                        + "other method like disabling VersionServlet mapping in web.xml."
                        + "Update OpenAM to version 14.6.4 and ForgeRockAM to version 7.1"))
        .build();
  }
}
