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
package com.google.tsunami.plugins.detectors.rce.tomcat.ghostcat;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;
import static com.google.common.collect.ImmutableList.toImmutableList;

import com.google.auto.value.AutoValue;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.flogger.GoogleLogger;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.plugins.detectors.rce.tomcat.ghostcat.ajp.AjpConnection;
import com.google.tsunami.plugins.detectors.rce.tomcat.ghostcat.ajp.AjpResponse;
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
import java.util.Optional;
import javax.inject.Inject;

/** A {@link VulnDetector} that detects the Ghostcat vulnerability. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "GhostcatVulnDetector",
    version = "0.1",
    description = "This detector checks for exposed AJP connectors we can interact with.",
    author = "Tsunami Team (tsunami-dev@google.com)",
    bootstrapModule = GhostcatVulnDetectorBootstrapModule.class)
public final class GhostcatVulnDetector implements VulnDetector {
  private static final ImmutableSet<Integer> VALID_STATUS_CODES = ImmutableSet.of(200, 404, 500);
  private static final String REQ_URI = "/xxxxx.jsp";
  private static final String PATH = "/WEB-INF/web.xml";

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  private final AjpConnection.Factory connectionFactory;

  @Inject
  GhostcatVulnDetector(@UtcClock Clock utcClock, AjpConnection.Factory connectionFactory) {
    this.utcClock = checkNotNull(utcClock);
    this.connectionFactory = checkNotNull(connectionFactory);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Starting Ghostcat vulnerability detection.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(GhostcatVulnDetector::isAjpService)
                .map(this::checkEndpointForNetworkService)
                .filter(EndpointProbingResult::isVulnerable)
                .map(probingResult -> buildDetectionReport(targetInfo, probingResult))
                .collect(toImmutableList()))
        .build();
  }

  private static boolean isAjpService(NetworkService networkService) {
    return NetworkServiceUtils.getServiceName(networkService).startsWith("ajp");
  }

  private EndpointProbingResult checkEndpointForNetworkService(NetworkService networkService) {
    try {
      String ip = networkService.getNetworkEndpoint().getIpAddress().getAddress();
      int port = networkService.getNetworkEndpoint().getPort().getPortNumber();
      AjpResponse response = connectionFactory.create(ip, port).performGhostcat(REQ_URI, PATH);
      logger.atInfo().log(
          "Got %s from %s:%d: %s",
          response.getStatusCode(), ip, port, formatAjpResponse(response));
      // Check if the connector is willing to disclose information
      if (!VALID_STATUS_CODES.contains(response.getStatusCode())) {
        return EndpointProbingResult.invulnerableForNetworkService(networkService);
      }
      return EndpointProbingResult.builder()
          .setIsVulnerable(true)
          .setNetworkService(networkService)
          .setAjpResponse(response)
          .build();
    } catch (IOException e) {
      logger.atInfo().withCause(e).log("Unable to communicate with AJP connector.");
      return EndpointProbingResult.invulnerableForNetworkService(networkService);
    }
  }

  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo, EndpointProbingResult endpointProbingResult) {
    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(endpointProbingResult.networkService())
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            Vulnerability.newBuilder()
                .setMainId(VulnerabilityId.newBuilder().setPublisher("GOOGLE").setValue("GHOSTCAT"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Apache Tomcat AJP File Read/Inclusion Vulnerability")
                .setDescription(
                    "Apache Tomcat is an open source web server and servlet container developed by"
                        + " the Apache Software Foundation Apache Tomcat fixed a vulnerability"
                        + " (CVE-2020-1938) that allows an attacker to read any webapps files. If"
                        + " the Tomcat instance supports file uploads, the vulnerability could"
                        + " also be leveraged to achieve remote code execution.")
                .setRecommendation("Install the latest security patches for Apache Tomcat.")
                .addAdditionalDetails(buildAdditionalDetail(endpointProbingResult)))
        .build();
  }

  private static AdditionalDetail buildAdditionalDetail(EndpointProbingResult probingResult) {
    checkState(probingResult.ajpResponse().isPresent());
    AjpResponse response = probingResult.ajpResponse().get();
    return AdditionalDetail.newBuilder()
        .setTextData(TextData.newBuilder().setText(formatAjpResponse(response)))
        .build();
  }

  private static String formatAjpResponse(AjpResponse response) {
    return String.format(
        "Status code: %d\nStatus message: %s\nHeaders: %s\n%s content: %s\n",
        response.getStatusCode(),
        response.getStatusMessage(),
        response.getHeaders(),
        PATH,
        response.getBodyAsString());
  }

  @AutoValue
  abstract static class EndpointProbingResult {
    abstract boolean isVulnerable();
    abstract NetworkService networkService();
    abstract Optional<AjpResponse> ajpResponse();

    static Builder builder() {
      return new AutoValue_GhostcatVulnDetector_EndpointProbingResult.Builder();
    }

    static EndpointProbingResult invulnerableForNetworkService(NetworkService networkService) {
      return builder().setIsVulnerable(false).setNetworkService(networkService).build();
    }

    @AutoValue.Builder
    abstract static class Builder {
      abstract Builder setIsVulnerable(boolean value);
      abstract Builder setNetworkService(NetworkService value);
      abstract Builder setAjpResponse(AjpResponse response);

      abstract EndpointProbingResult build();
    }
  }
}
