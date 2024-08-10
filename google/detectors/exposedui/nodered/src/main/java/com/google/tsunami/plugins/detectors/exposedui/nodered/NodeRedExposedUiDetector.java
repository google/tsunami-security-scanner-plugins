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
package com.google.tsunami.plugins.detectors.exposedui.nodered;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.get;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpResponse;
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
import javax.inject.Inject;

/** A {@link VulnDetector} that detects exposed NodeRED instances. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "NodeRedExposedUiDetector",
    version = "0.1",
    description = "Detects exposed NodeRED instances",
    author = "Pierre Precourt (pprecourt@google.com)",
    bootstrapModule = NodeRedExposedUiDetectorBootstrapModule.class)
public final class NodeRedExposedUiDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  private final HttpClient httpClient;

  @Inject
  NodeRedExposedUiDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient).modify().build();
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Starting detection: exposed NodeRED instances");
    DetectionReportList detectionReports =
        DetectionReportList.newBuilder()
            .addAllDetectionReports(
                matchedServices.stream()
                    .filter(NetworkServiceUtils::isWebService)
                    .filter(this::isServiceVulnerable)
                    .map(networkService -> buildDetectionReport(targetInfo, networkService))
                    .collect(toImmutableList()))
            .build();

    logger.atInfo().log(
        "NodeRedExposedUiDetector finished, detected '%d' vulns.",
        detectionReports.getDetectionReportsCount());
    return detectionReports;
  }

  /*
   * Checks if the settings are accessible. The /settings page will either return a JSON content or
   * a permission denied error depending on the configuration for authentication.
   * Because /settings can be a pretty common endpoint, we want to ensure that this is a rednode
   * instance whilst not really performing JSON parsing hence the pattern matching instead.
   */
  private boolean settingsAreAccessible(NetworkService networkService) {
    String targetUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + "settings";

    try {
      HttpResponse response = httpClient.send(get(targetUri).withEmptyHeaders().build());

      return response.status().isSuccess()
          && response
              .bodyString()
              .map(
                  body ->
                      body.contains("\"httpNodeRoot\"")
                          && body.contains("\"version\"")
                          && body.contains("\"workflow\""))
              .orElse(false);
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", targetUri);
      return false;
    }
  }

  private boolean isNodeRedInstance(NetworkService networkService) {
    String targetUri =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + "/red/tours/welcome.js";

    try {
      HttpResponse response = httpClient.send(get(targetUri).withEmptyHeaders().build());

      return response.status().isSuccess()
          && response.bodyString().map(body -> body.contains("Welcome to Node-RED")).orElse(false);
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", targetUri);
      return false;
    }
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    return isNodeRedInstance(networkService) && settingsAreAccessible(networkService);
  }

  private DetectionReport buildDetectionReport(
      TargetInfo scannedTarget, NetworkService vulnerableNetworkService) {
    return DetectionReport.newBuilder()
        .setTargetInfo(scannedTarget)
        .setNetworkService(vulnerableNetworkService)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder()
                        .setPublisher("GOOGLE")
                        .setValue("NODERED_EXPOSED_UI"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Exposed NodeRED instance")
                .setRecommendation(
                    "Configure authentication or ensure the NodeRED instance is not exposed to the"
                        + " network. See"
                        + " https://nodered.org/docs/user-guide/runtime/securing-node-red for"
                        + " details")
                .setDescription(
                    "NodeRED instance is exposed and can be used to compromise the system."))
        .build();
  }
}
