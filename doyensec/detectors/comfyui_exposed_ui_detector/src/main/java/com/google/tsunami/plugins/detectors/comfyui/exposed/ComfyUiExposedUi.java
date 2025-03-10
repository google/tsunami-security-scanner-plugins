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

package com.google.tsunami.plugins.detectors.comfyui.exposed;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
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
import java.time.Clock;
import java.time.Instant;
import java.util.regex.Pattern;
import javax.inject.Inject;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;

/** A Tsunami plugin that detects an exposed instance of ComfyUI. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "ComfyUI_exposedUI",
    version = "0.1",
    description = "This plugin detects an exposed instance of ComfyUI.",
    author = "Savino Sisco (savio@doyensec.com), Leonardo Giovannini (leonardo@doyensec.com)",
    bootstrapModule = ComfyUiExposedUiBootstrapModule.class)
public final class ComfyUiExposedUi implements VulnDetector {
  @VisibleForTesting static final String VULNERABILITY_REPORT_PUBLISHER = "TSUNAMI_COMMUNITY";

  @VisibleForTesting static final String VULNERABILITY_REPORT_TITLE = "ComfyUI Exposed UI";

  static final String VULNERABILITY_REPORT_DESCRIPTION =
      "The scanner detected an exposed ComfyUI instance.";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_RECOMMENDATION = "Segregate the ComfyUI instance.";

  @VisibleForTesting static final String MANAGER_VERSION_ENDPOINT = "api/manager/version";

  @VisibleForTesting static final String STATS_ENDPOINT = "api/system_stats";

  @VisibleForTesting
  static final Pattern VERSION_PATTERN = Pattern.compile("^V\\d+\\.\\d+\\.\\d+$");

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private final Clock utcClock;
  private final HttpClient httpClient;

  @Inject
  ComfyUiExposedUi(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient);
  }

  // This is the main entry point of VulnDetector.
  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("ComfyUI Exposed UI starts detecting.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(NetworkServiceUtils::isWebService)
                .filter(this::isComfyUi)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  /*
   * Fingerprint phase for ComfyUI.
   * This detects the service and the version
   */
  private boolean isComfyUi(NetworkService networkService) {
    String rootUrl = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    try {
      // Check web page title first
      String targetUri = rootUrl;
      HttpRequest req =
          HttpRequest.get(targetUri)
              .setHeaders(HttpHeaders.builder().addHeader("Accept", "application/json").build())
              .build();
      HttpResponse response;
      response = this.httpClient.send(req, networkService);
      Document doc = Jsoup.parse(response.bodyString().get());
      String title = doc.title();
      if (!title.contains("ComfyUI")) {
        return false;
      }

      // Check the system_stats endpoint
      targetUri = rootUrl + STATS_ENDPOINT;
      req = HttpRequest.get(targetUri).withEmptyHeaders().build();
      response = this.httpClient.send(req, networkService);
      // Check if devices[0]["name"] is present
      try {
        if (response.bodyJson().isEmpty()
            || response
                .bodyJson()
                .get()
                .getAsJsonObject()
                .get("devices")
                .getAsJsonArray()
                .get(0)
                .getAsJsonObject()
                .get("name")
                .getAsString()
                .isEmpty()) {
          return false;
        }
      } catch (NullPointerException | IllegalStateException | IndexOutOfBoundsException e) {
        return false;
      }
      logger.atInfo().log("ComfyUI Detected. Attempting to find version numbers.");

      // Check if the Comfy version is available (not present on older versions)
      try {
        String comfyUiVersion =
            response
                .bodyJson()
                .get()
                .getAsJsonObject()
                .get("system")
                .getAsJsonObject()
                .get("comfyui_version")
                .getAsString();
        if (!comfyUiVersion.isEmpty()) {
          logger.atInfo().log("ComfyUI version: %s", comfyUiVersion);
        }
      } catch (NullPointerException | IllegalStateException | IndexOutOfBoundsException e) {
        // Do nothing, it's ok if the version is not there
      }

      // Checking if ComfyUI Manager is available (not present on older versions)
      targetUri = rootUrl + MANAGER_VERSION_ENDPOINT;
      req = HttpRequest.get(targetUri).withEmptyHeaders().build();
      response = this.httpClient.send(req, networkService);
      if (response.status() == HttpStatus.OK
          && VERSION_PATTERN.matcher(response.bodyString().orElse("")).find()) {
        logger.atInfo().log("ComfyUI Manager version: %s", response.bodyString().get());
      }
    } catch (IOException e) {
      return false;
    }
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
                    VulnerabilityId.newBuilder().setPublisher(VULNERABILITY_REPORT_PUBLISHER))
                .setSeverity(Severity.CRITICAL)
                .setTitle(VULNERABILITY_REPORT_TITLE)
                .setDescription(VULNERABILITY_REPORT_DESCRIPTION)
                .setRecommendation(VULNERABILITY_REPORT_RECOMMENDATION))
        .build();
  }
}
