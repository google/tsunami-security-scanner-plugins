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
package com.google.tsunami.plugins.detectors.cves.cve202129441;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.net.HttpHeaders.USER_AGENT;
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
import javax.inject.Inject;

/** A {@link VulnDetector} that detects the CVE-2021-29441 vulnerability. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "CVE202129441VulnDetector",
    version = "0.1",
    description =
        "Nacos is a platform designed for dynamic service discovery and configuration and service"
            + " management. In Nacos before version 1.4.1, when configured to use authentication"
            + " (-Dnacos.core.auth.enabled=true) Nacos uses the AuthFilter servlet filter to"
            + " enforce authentication. This filter has a backdoor that enables Nacos servers to"
            + " bypass this filter and therefore skip authentication checks. This mechanism relies"
            + " on the user-agent HTTP header so it can be easily spoofed. This issue may allow any"
            + " user to carry out any administrative tasks on the Nacos server.",
    author = "hh-hunter",
    bootstrapModule = Cve202129441DetectorBootstrapModule.class)
public final class Cve202129441VulnDetector implements VulnDetector {

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final String CHECK_VUL_PATH = "nacos/v1/auth/users/?pageNo=1&pageSize=9";

  @VisibleForTesting static final String DETECTION_STRING = "pageItems";
  @VisibleForTesting
  static final String VULN_DESCRIPTION =
      "Nacos is a platform designed for dynamic service discovery and configuration"
          + " and service management. In Nacos before version 1.4.1, when configured"
          + " to use authentication (-Dnacos.core.auth.enabled=true) Nacos uses the"
          + " AuthFilter servlet filter to enforce authentication. This filter has a"
          + " backdoor that enables Nacos servers to bypass this filter and therefore"
          + " skip authentication checks. This mechanism relies on the user-agent"
          + " HTTP header so it can be easily spoofed. This issue may allow any user"
          + " to carry out any administrative tasks on the Nacos server.";

  private final HttpClient httpClient;
  private final Clock utcClock;

  @Inject
  Cve202129441VulnDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.httpClient = checkNotNull(httpClient);
    this.utcClock = checkNotNull(utcClock);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("CVE-2921-29441 starts detecting.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(Cve202129441VulnDetector::isWebServiceOrUnknownService)
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
                  .setHeaders(HttpHeaders.builder().addHeader(USER_AGENT, "Nacos-Server").build())
                  .build(),
              networkService);

      if (httpResponse.status().code() == 200
          && httpResponse.bodyString().get().contains(DETECTION_STRING)) {
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
                        .setValue("CVE_2021_29441"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("CVE-2021-29441 Nacos Authentication Bypass Via Backdoor")
                .setRecommendation(
                    "Configure nacos.core.auth.enabled to true, upgrade nacos to the latest"
                        + " version, configure custom authentication key-value pair information")
                .setDescription(VULN_DESCRIPTION))
        .build();
  }

  private static boolean isWebServiceOrUnknownService(NetworkService networkService) {
    return networkService.getServiceName().isEmpty()
        || NetworkServiceUtils.isWebService(networkService)
        || NetworkServiceUtils.getServiceName(networkService).equals("unknown");
  }

  private static String buildTargetUrl(NetworkService networkService) {
    StringBuilder targetUrlBuilder = new StringBuilder();
    if (NetworkServiceUtils.isWebService(networkService)) {
      targetUrlBuilder.append(NetworkServiceUtils.buildWebApplicationRootUrl(networkService));
    } else {
      // Assume the service uses HTTP protocol when the scanner cannot identify the actual service.
      targetUrlBuilder
          .append("http://")
          .append(toUriAuthority(networkService.getNetworkEndpoint()))
          .append("/");
    }
    targetUrlBuilder.append(CHECK_VUL_PATH);
    return targetUrlBuilder.toString();
  }
}
