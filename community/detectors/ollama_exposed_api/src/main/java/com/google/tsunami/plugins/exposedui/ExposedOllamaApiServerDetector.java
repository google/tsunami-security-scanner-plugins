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

package com.google.tsunami.plugins.exposedui;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.tsunami.common.net.http.HttpRequest.get;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.net.http.HttpStatus;
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
import javax.inject.Inject;

/** A VulnDetector plugin for Exposed Ollama API Server. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "Exposed Ollama API Server Detector",
    version = "0.1",
    description =
        "This detector checks for a publicly exposed Ollama REST API which can be abused by an"
            + " attacker for management tasks.",
    author = "timoles",
    bootstrapModule = ExposedOllamaApiServerDetectorModule.class)
@ForWebService
public final class ExposedOllamaApiServerDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  private final HttpClient httpClient;

  @VisibleForTesting
  static final String RECOMMENDATION =
      "Don't expose the Ollama Rest API to unauthorized users. According to the official"
          + " documentation access to the API server must be restricted through a reverse proxy"
          + " which implements necessary authentication checks.";

  @Inject
  ExposedOllamaApiServerDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(true).build();
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {

    DetectionReportList.Builder detectionReport = DetectionReportList.newBuilder();
    matchedServices.stream()
        .filter(NetworkServiceUtils::isWebService)
        .filter(this::isOllamaApi)
        .forEach(
            networkService -> {
              if (isServiceVulnerableCheckResponse(networkService)) {
                detectionReport.addDetectionReports(
                    buildDetectionReport(targetInfo, networkService));
              }
            });
    return detectionReport.build();
  }

  public boolean isOllamaApi(NetworkService networkService) {
    logger.atInfo().log("Probing Ollama API landing page");

    var ollamaApiLandingPageUrl = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    try {
      HttpResponse landingPageResponse =
          this.httpClient.send(get(ollamaApiLandingPageUrl).withEmptyHeaders().build());
      if (!(landingPageResponse.status() == HttpStatus.OK
          && landingPageResponse.bodyString().isPresent())) {
        return false;
      }

      if (landingPageResponse.bodyString().get().contains("Ollama is running")) {
        return true;
      }

    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", ollamaApiLandingPageUrl);
      return false;
    }

    return false;
  }

  @Override
  public ImmutableList<Vulnerability> getAdvisories() {
    return ImmutableList.of(
        Vulnerability.newBuilder()
            .setMainId(
                VulnerabilityId.newBuilder()
                    .setPublisher("TSUNAMI_COMMUNITY")
                    .setValue("OLLAMA_API_SERVER_EXPOSED"))
            .setSeverity(Severity.HIGH)
            .setTitle("Exposed Ollama API Server")
            .setDescription(
                "An Ollama API server is exposed to the network. This was confirmed by"
                    + " investigating the API response for typical response artifacts. "
                    + " An attacker can abuse an exposed API server to, for example,"
                    + " download or modify existing LLM models, or misuse resources by"
                    + " using the LLM chat functionality.")
            .setRecommendation(RECOMMENDATION)
            .build());
  }

  private boolean isServiceVulnerableCheckResponse(NetworkService networkService) {

    var psUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + "api/ps";
    try {
      // Minimize false-positives by checking if we can access the models endpoint
      HttpResponse psApiResponse =
          httpClient.send(get(psUri).withEmptyHeaders().build(), networkService);
      if (psApiResponse.status() != HttpStatus.OK || psApiResponse.bodyString().isEmpty()) {
        return false;
      }
      if (psApiResponse.bodyString().get().contains("{\"models\":")) {
        return true;
      }

    } catch (RuntimeException | IOException e) {
      logger.atWarning().withCause(e).log("Request to target %s failed", psUri);
      return false;
    }
    return false;
  }

  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo, NetworkService vulnerableNetworkService) {
    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(vulnerableNetworkService)
        .setDetectionTimestamp(Timestamps.fromMillis(utcClock.instant().toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(this.getAdvisories().get(0))
        .build();
  }
}
