/*
 * Copyright 2022 Google LLC
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

package com.google.tsunami.plugins.detectors.directorytraversal.cve20213223;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.get;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.gson.JsonSyntaxException;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TextData;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import javax.inject.Inject;

/** NodeRedDashboardDirectoryTraversalDetector plugin. */
// PluginInfo tells Tsunami scanning engine basic information about the plugin.
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "NodeRedDashboardDirectoryTraversalDetector",
    version = "0.1",
    description = "This plugin detects directory traversal vulnerability in Node-RED-Dashboard.",
    author = "Tsunami Team (tsunami-dev@google.com)",
    bootstrapModule = NodeRedDashboardDirectoryTraversalDetectorBootstrapModule.class)
public final class NodeRedDashboardDirectoryTraversalDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  private final HttpClient httpClient;

  // All the utility dependencies of the plugin must be injected through the constructor of the
  // detector. Here the UtcClock is provided by the scanner.
  @Inject
  NodeRedDashboardDirectoryTraversalDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(false).build();
  }

  // Main entry point of VulnDetector. Both parameters will be populated by the scanner.
  // targetInfo contains the general information about the scan target.
  // matchedServices parameter contains all exposed network services on the scan target.
  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("NodeRedDashboardDirectoryTraversalDetector starts detecting.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(NetworkServiceUtils::isWebService)
                // Check individual NetworkService whether it is vulnerable.
                .filter(this::isServiceVulnerable)
                // Build DetectionReport message for vulnerable services.
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  // Checks whether a given network service is vulnerable.
  private boolean isServiceVulnerable(NetworkService networkService) {
    String targetUri =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + "ui_base/js/..%2f";
    try {
      logger.atInfo().log("Node-RED starts checking for target URI: '%s'.", targetUri);

      HttpResponse response =
          httpClient.send(get(targetUri).withEmptyHeaders().build(), networkService);

      // If accessing targetUri does not give not found error, then returns true
      return response.status().isSuccess()
          && response.bodyString().get().contains("Welcome to the Node-RED Dashboard");
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", targetUri);
      return false;
    } catch (JsonSyntaxException e) {
      logger.atWarning().withCause(e).log(
          "JSON syntax error occurred parsing response for target URI: '%s'.", targetUri);
      return false;
    }
  }

  // This builds the DetectionReport message for a specific vulnerable network service.
  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo, NetworkService vulnerableNetworkService) {
    TextData details =
        TextData.newBuilder()
            .setText(
                String.format(
                    "Node-RED-Dashboard before 2.26.2 allows %s directory traversal to read files.",
                    NetworkServiceUtils.buildWebApplicationRootUrl(vulnerableNetworkService)
                        + "ui_base/js/..%2f"))
            .build();
    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(vulnerableNetworkService)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder().setPublisher("GOOGLE").setValue("CVE_2021_3223"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Node-RED-Dashboard directory traversal vulnerability")
                .setDescription("Directory Traversal vulnerability in exposed Node-RED-Dashboard")
                .setRecommendation("Upgrade node-red-dashboard to version 2.26.2 or greater.")
                .addAdditionalDetails(AdditionalDetail.newBuilder().setTextData(details)))
        .build();
  }
}
