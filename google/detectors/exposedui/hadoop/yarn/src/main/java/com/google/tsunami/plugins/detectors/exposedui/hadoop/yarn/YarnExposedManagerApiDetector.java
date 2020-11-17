/*
 * Copyright 2020 Google LLC
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
package com.google.tsunami.plugins.detectors.exposedui.hadoop.yarn;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.get;
import static com.google.tsunami.common.net.http.HttpRequest.post;

import com.google.common.base.Ascii;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.gson.JsonElement;
import com.google.gson.JsonSyntaxException;
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

/**
 * A {@link VulnDetector} that detects exposed and unauthenticated Hadoop Yarn ResourceManager API.
 */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "YarnExposedManagerApiDetector",
    version = "0.1",
    description =
        "This detector checks whether the ResourceManager API of Hadoop Yarn is exposed and allows"
            + " unauthenticated code execution.",
    author = "Tsunami Team (tsunami-dev@google.com)",
    bootstrapModule = YarnExposedManagerApiDetectorBootstrapModule.class)
public final class YarnExposedManagerApiDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final String VULN_ID = "HADOOP_YARN_UNAUTHENTICATED_RESOURCE_MANAGER_API";

  private final Clock utcClock;
  private final HttpClient httpClient;

  @Inject
  public YarnExposedManagerApiDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(false).build();
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Starting unauthenticated Apache Yarn ResourceManager API detection");

    DetectionReportList detectionReports =
        DetectionReportList.newBuilder()
            .addAllDetectionReports(
                matchedServices.stream()
                    .filter(NetworkServiceUtils::isWebService)
                    .filter(this::isUnauthenticatedYarnManager)
                    .filter(this::isServiceVulnerable)
                    .map(networkService -> buildDetectionReport(targetInfo, networkService))
                    .collect(toImmutableList()))
            .build();

    logger.atInfo().log(
        "YarnExposedManagerApiDetector finished, detected '%d' vulns.",
        detectionReports.getDetectionReportsCount());
    return detectionReports;
  }

  private boolean isUnauthenticatedYarnManager(NetworkService networkService) {
    // Unauthenticated Yarn always identifies user as "dr.who".
    String clusterInfoUrl =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + "cluster/cluster";
    try {
      HttpResponse response =
          httpClient.send(get(clusterInfoUrl).withEmptyHeaders().build(), networkService);
      return response.status().isSuccess()
          && response
              .bodyString()
              .map(Ascii::toLowerCase)
              .map(
                  body ->
                      body.contains("hadoop")
                          && body.contains("resourcemanager")
                          && body.contains("logged in as: dr.who"))
              .orElse(false);
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query Hadoop Yarn cluster info page.");
      return false;
    }
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    String targetUri =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService)
            + "ws/v1/cluster/apps/new-application";
    logger.atInfo().log("Trying creating a new application on target '%s'", targetUri);
    try {
      HttpResponse response =
          httpClient.send(post(targetUri).withEmptyHeaders().build(), networkService);
      return response.status().isSuccess()
          && response
              .bodyJson()
              .map(YarnExposedManagerApiDetector::bodyContainsApplicationId)
              .orElse(false);
    } catch (IOException e) {
      logger.atWarning().withCause(e).log(
          "Error creating new Hadoop application on target '%s'", targetUri);
      return false;
    } catch (JsonSyntaxException e) {
      logger.atInfo().log(
          "Hadoop Yarn NewApplication API response cannot be parsed as valid json. Maybe targeting"
              + " an unexpected service?");
      return false;
    }
  }

  private static boolean bodyContainsApplicationId(JsonElement responseBody) {
    if (!responseBody.isJsonObject()) {
      logger.atInfo().log(
          "Hadoop Yarn NewApplication API didn't respond with an expected json format.");
      return false;
    }
    if (!responseBody.getAsJsonObject().has("application-id")) {
      logger.atInfo().log(
          "Hadoop Yarn NewApplication API response didn't contain application-id. Service not"
              + " vulnerable.");
      return false;
    }

    logger.atInfo().log(
        "Plugin successfully created a new Hadoop application '%s' on scan target!",
        responseBody.getAsJsonObject().getAsJsonPrimitive("application-id").getAsString());
    // TODO(b/147455448): perform an out-of-band call on the target to verify.
    // Send POST to /ws/v1/cluster/apps with payload:
    // {
    //   "application-id": "application-id-from-response-body",
    //   "application-name": "tsunami-out-of-band",
    //   "am-container-spec": {
    //       "commands": {
    //           "command": "nslookup scanner.out.of.band.target"
    //       }
    //   },
    //   "application-type": "YARN"
    // }
    return true;
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
                .setMainId(VulnerabilityId.newBuilder().setPublisher("GOOGLE").setValue(VULN_ID))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Hadoop Yarn Unauthenticated ResourceManager API")
                // TODO(b/147455448): determine CVSS score.
                .setDescription(
                    "Hadoop Yarn ResourceManager controls the computation and storage resources of"
                        + " a Hadoop cluster. Unauthenticated ResourceManager API allows any"
                        + " remote users to create and execute arbitrary applications on the"
                        + " host."))
        .build();
  }
}
