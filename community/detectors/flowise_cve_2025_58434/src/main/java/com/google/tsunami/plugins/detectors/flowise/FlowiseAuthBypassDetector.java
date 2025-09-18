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

package com.google.tsunami.plugins.detectors.flowise;

import static com.google.common.base.Preconditions.checkNotNull;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.protobuf.ByteString;
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
import com.google.tsunami.proto.DetectionReportList.Builder;
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

/** A {@link VulnDetector} that detects Flowise authentication bypass vulnerability. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "FlowiseAuthBypassDetector",
    version = "0.1",
    description =
        "This detector checks whether a Flowise installation is vulnerable to "
            + "CVE-2025-58434 (authentication bypass).",
    author = "DeVampKid",
    bootstrapModule = FlowiseAuthBypassDetectorBootstrapModule.class)
public final class FlowiseAuthBypassDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  private final HttpClient httpClient;

  @VisibleForTesting
  static final String RECOMMENDATION =
      "Please update your Flowise instance to version 3.0.6 and higher."
          + " Ensure proper authentication is enforced on the forgot-password endpoint.";

  @VisibleForTesting
  static final ImmutableList<String> EMAILS_TO_TEST =
      ImmutableList.of("admin@admin.com", "test@example.com", "user@domain.com");

  @Inject
  FlowiseAuthBypassDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(false).build();
  }

  @Override
  public ImmutableList<Vulnerability> getAdvisories() {
    return ImmutableList.of(
        Vulnerability.newBuilder()
            .setMainId(VulnerabilityId.newBuilder().setPublisher("CVE").setValue("CVE_2025_58434"))
            .setSeverity(Severity.HIGH)
            .setTitle("Flowise Authentication Bypass (CVE-2025-58434)")
            .setDescription(
                "Flowise instance is vulnerable to authentication bypass via the forgot-password"
                    + " endpoint, allowing unauthorized account creation and credential retrieval.")
            .setRecommendation(RECOMMENDATION)
            .build());
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("FlowiseAuthBypassDetector starts detecting.");

    Builder detectionReport = DetectionReportList.newBuilder();
    matchedServices.stream()
        .filter(NetworkServiceUtils::isWebService)
        .filter(this::isFlowiseService)
        .forEach(
            networkService -> {
              Optional<String> vulnerableAccountEmail = isServiceVulnerable(networkService);
              vulnerableAccountEmail.ifPresent(
                  testedAccountEmail ->
                      detectionReport.addDetectionReports(
                          buildDetectionReport(targetInfo, networkService, testedAccountEmail)));
            });
    return detectionReport.build();
  }

  private boolean isFlowiseService(NetworkService networkService) {
    String targetUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);

    try {
      HttpResponse response =
          httpClient.send(HttpRequest.get(targetUri).withEmptyHeaders().build(), networkService);
      return response.bodyString().isPresent()
          && response
              .bodyString()
              .get()
              .contains("<title>Flowise - Build AI Agents, Visually</title>");
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query Flowise for fingerprinting.");
      return false;
    }
  }

  private Optional<String> isServiceVulnerable(NetworkService networkService) {
    String targetUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);

    // Try each email in the test list
    for (String testEmail : EMAILS_TO_TEST) {
      HttpResponse response;
      try {
        String forgotPasswordUri = targetUri + "api/v1/account/forgot-password";
        String forgotPayload = String.format("{\"user\":{\"email\":\"%s\"}}", testEmail);
        response =
            httpClient.send(
                HttpRequest.post(forgotPasswordUri)
                    .setHeaders(
                        HttpHeaders.builder().addHeader("Content-Type", "application/json").build())
                    .setRequestBody(ByteString.copyFromUtf8(forgotPayload))
                    .build(),
                networkService);
        if (response.status().code() != 201) {
          continue;
        }
        if (response.bodyString().isPresent()
            && response.bodyString().get().contains("\"credential\"")
            && response.bodyString().get().contains("\"tempToken\"")
            && response.bodyString().get().contains("\"tokenExpiry\"")) {
          return Optional.of(testEmail);
        }
      } catch (IOException e) {
        logger.atWarning().withCause(e).log(
            "Unable to query Flowise for vulnerability check with email: " + testEmail);
      }
    }

    return Optional.empty();
  }

  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo, NetworkService vulnerableNetworkService, String testedAccountEmail) {
    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(vulnerableNetworkService)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            getAdvisories().getFirst().toBuilder()
                .addAdditionalDetails(
                    AdditionalDetail.newBuilder()
                        .setTextData(
                            TextData.newBuilder()
                                .setText(
                                    String.format(
                                        "The Flowise instance at %s is vulnerable to authentication"
                                            + " bypass (CVE-2025-58434). A password reset token was"
                                            + " successfully obtained for the account %s.",
                                        NetworkServiceUtils.buildWebApplicationRootUrl(
                                            vulnerableNetworkService),
                                        testedAccountEmail)))))
        .build();
  }
}
