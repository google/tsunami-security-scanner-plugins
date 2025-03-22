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
package com.google.tsunami.plugins.detectors.exposedui.flowise;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpRequest;
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

/** A {@link VulnDetector} that detects an exposed Flowise UI installation. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "FlowiseExposedUiDetector",
    version = "0.1",
    description = "This detector checks whether a Flowise UI installation is exposed.",
    author = "yuradoc (yuradoc.research@gmail.com)",
    bootstrapModule = FlowiseExposedUiDetectorBootstrapModule.class)
public final class FlowiseExposedUiDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  private final HttpClient httpClient;

  @Inject
  FlowiseExposedUiDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(false).build();
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("FlowiseExposedUiDetector starts detecting.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(NetworkServiceUtils::isWebService)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    String targetUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    String targetApiUri = targetUri + "api/v1/apikey";

    HttpResponse response;
    try {
      // plain GET request to check Flowise UI availability.
      response = httpClient.send(HttpRequest.get(targetUri).withEmptyHeaders().build(), networkService);
      if (!(response.bodyString().isPresent() && response.bodyString().get().contains("Flowise"))) {
        return false;
      }

      // Main request that performs vulnerability check.
      response =
          httpClient.send(
              HttpRequest.get(targetApiUri)
                  .setHeaders(HttpHeaders.builder().addHeader("x-request-from", "internal").build())
                  .build(),
              networkService);
      return response.status().code() != 401;
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query Flowise.");
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
                    VulnerabilityId.newBuilder()
                        .setPublisher("TSUNAMI_COMMUNITY")
                        .setValue("FLOWISE_UI_EXPOSED"))
                .setSeverity(Severity.HIGH)
                .setTitle("Flowise UI Exposed")
                .setDescription("Flowise UI instance is exposed without proper authentication.")
                .setRecommendation(
                    "Secure the Flowise UI by implementing proper authentication.\n"
                        + "Consider restricting access to trusted networks only.")
                .addAdditionalDetails(
                    AdditionalDetail.newBuilder()
                        .setTextData(
                            TextData.newBuilder()
                                .setText(
                                    String.format(
                                        "The Flowise UI instance at %s is exposed without proper"
                                            + " authentication.",
                                        NetworkServiceUtils.buildWebApplicationRootUrl(
                                            vulnerableNetworkService))))))
        .build();
  }
}
