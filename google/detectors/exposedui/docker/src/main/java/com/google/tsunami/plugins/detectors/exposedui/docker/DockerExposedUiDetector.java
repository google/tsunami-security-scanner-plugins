/*
 * Copyright 2023 Google LLC
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
package com.google.tsunami.plugins.detectors.exposedui.docker;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.get;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Ascii;
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
import java.util.ArrayList;
import java.util.List;
import javax.inject.Inject;

/** A {@link VulnDetector} that detects an unauthenticated Docker API. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "DockerExposedUiDetector",
    version = "0.1",
    description = "This detector checks whether the Docker API is exposed",
    author = "Manuel Karl (m.karl@tu-braunschweig.de) & Marius Musch (m.musch@tu-braunschweig.de)",
    bootstrapModule = DockerExposedUiDetectorBootstrapModule.class)
public final class DockerExposedUiDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  @VisibleForTesting
  static final String DESCRIPTION =
      "Docker API is not password or token protected. Attackers can use the API to access existing"
          + " containers or launch new containers.";

  @VisibleForTesting
  static final String FINDING_RECOMMENDATION_TEXT =
      "Docker API should be configured to only accept requests from specific IP addresses (0.0.0.0"
          + " should not be allowed). Check"
          + " https://docs.docker.com/engine/reference/commandline/dockerd/#daemon-socket-option to"
          + " add fine-grained allow list for your dockerd service.";

  private final Clock utcClock;
  private final HttpClient httpClient;
  private final List<AdditionalDetail> additionalDetails = new ArrayList<>();

  @Inject
  DockerExposedUiDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient).modify().build();
  }

  @Override
  public ImmutableList<Vulnerability> getAdvisories() {
    return ImmutableList.of(
        Vulnerability.newBuilder()
            .setMainId(
                VulnerabilityId.newBuilder().setPublisher("GOOGLE").setValue("DOCKER_EXPOSED_UI"))
            .setSeverity(Severity.CRITICAL)
            .setTitle("Docker API Exposed Ui")
            .setDescription(DESCRIPTION)
            .setRecommendation(FINDING_RECOMMENDATION_TEXT)
            .addAllAdditionalDetails(additionalDetails)
            .build());
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Starting exposed ui detection for Docker API");
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
        "DockerExposedUiDetector finished, detected '%d' vulns.",
        detectionReports.getDetectionReportsCount());
    return detectionReports;
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    String targetUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + "version";
    try {
      HttpResponse response = httpClient.send(get(targetUri).withEmptyHeaders().build());
      if (response.status().isSuccess() && response.bodyString().isPresent()) {
        String bodyString = Ascii.toLowerCase(response.bodyString().get());
        if (!bodyString.contains("minapiversion") || !bodyString.contains("kernelversion")) {
          return false;
        }
        additionalDetails.add(
            AdditionalDetail.newBuilder()
                .setTextData(TextData.newBuilder().setText(response.bodyString().get()))
                .build());
        return true;
      }
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", targetUri);
    }
    return false;
  }

  private DetectionReport buildDetectionReport(
      TargetInfo scannedTarget, NetworkService vulnerableNetworkService) {
    return DetectionReport.newBuilder()
        .setTargetInfo(scannedTarget)
        .setNetworkService(vulnerableNetworkService)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(this.getAdvisories().get(0))
        .build();
  }
}
