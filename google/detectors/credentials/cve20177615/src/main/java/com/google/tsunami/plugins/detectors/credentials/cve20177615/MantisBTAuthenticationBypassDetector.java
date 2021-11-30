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
package com.google.tsunami.plugins.detectors.credentials.cve20177615;

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
import java.util.Optional;
import java.util.regex.Pattern;
import javax.inject.Inject;

/**
 * A {@link VulnDetector} that detects MantisBT authentication bypass vulnerability (CVE-2017-7615).
 *
 * <p>MantisBT through 2.3.0 allows arbitrary password reset and unauthenticated admin access via an
 * empty confirm_hash value to verify.php.
 */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "MantisBTAuthenticationBypassDetector",
    version = "0.1",
    description = "Tsunami detector plugin for MantisBT authentication bypass (CVE-2017-7615).",
    author = "Tsunami Team (tsunami-dev@google.com)",
    bootstrapModule = MantisBTAuthenticationBypassDetectorBootstrapModule.class)
public final class MantisBTAuthenticationBypassDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  // HTML title field returned by MantisBT's verify.php.
  private static final String MANTISBT_TITLE = "<title>MantisBT</title>";
  // HTML form hidden update token field returned by MantisBT's verfiry.php.
  private static final Pattern UPDATE_TOKEN_PATTERN =
      Pattern.compile(
          "<input type=\"hidden\" name=\"account_update_token\" value=\"[a-zA-Z0-9_-]+\"/>");

  private final Clock utcClock;
  private final HttpClient httpClient;

  @Inject
  MantisBTAuthenticationBypassDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Starting authentication bypass (CVE-2017-7615) detection for MantisBT.");
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
        "MantisBTAuthenticationBypassDetector finished, detected '%d' vulns.",
        detectionReports.getDetectionReportsCount());
    return detectionReports;
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    String targetUri =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService)
            + "verify.php?id=1&confirm_hash=";

    try {
      // This is a blocking call.
      HttpResponse response =
          httpClient.send(get(targetUri).withEmptyHeaders().build(), networkService);
      Optional<String> body = response.bodyString();
      if (body.isPresent()
          && body.get().contains(MANTISBT_TITLE)
          && UPDATE_TOKEN_PATTERN.matcher(body.get()).find()) {
        return true;
      } else {
        return false;
      }
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", targetUri);
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
                    VulnerabilityId.newBuilder().setPublisher("GOOGLE").setValue("CVE_2017_7615"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("MantisBT Authentication Bypass (CVE-2017-7615)")
                .setDescription(
                    "MantisBT through 2.3.0 allows arbitrary password reset and unauthenticated"
                        + " admin access via an empty confirm_hash value to verify.php."))
        .build();
  }
}
