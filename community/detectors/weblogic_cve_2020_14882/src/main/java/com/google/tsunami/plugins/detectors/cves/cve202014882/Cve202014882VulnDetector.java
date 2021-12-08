/*
 * Copyright 2021 Google LLC
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
package com.google.tsunami.plugins.detectors.cves.cve202014882;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.net.HttpHeaders.COOKIE;
import static com.google.common.net.HttpHeaders.SET_COOKIE;
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
import java.util.Optional;
import javax.inject.Inject;

/** A {@link VulnDetector} that detects the CVE-2020-14882 vulnerability. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "Cve202014882VulnDetector",
    version = "0.1",
    description =
        "Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware"
            + " (component: Console). Supported versions that are affected are 10.3.6.0.0,"
            + " 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability"
            + " allows unauthenticated attacker with network access via HTTP to compromise Oracle"
            + " WebLogic Server. Successful attacks of this vulnerability can result in takeover of"
            + " Oracle WebLogic Server",
    author = "thiscodecc",
    bootstrapModule = Cve202014882DetectorBootstrapModule.class)
public class Cve202014882VulnDetector implements VulnDetector {

  @VisibleForTesting
  static final String DETECTION_STRING = "/console/jsp/common/warnuserlockheld.jsp";

  @VisibleForTesting static final String DETECTION_COOKIE = "ADMINCONSOLESESSION";
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final String CHECK_VUL_PATH =
      "console/css/%252e%252e%252fconsole.portal?_nfpb=true&_pageLabel=HomePage1";
  private final HttpClient httpClient;
  private final Clock utcClock;

  @Inject
  Cve202014882VulnDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(false).build();
    this.utcClock = checkNotNull(utcClock);
  }

  private static boolean isWebServiceOrUnknownService(NetworkService networkService) {
    return networkService.getServiceName().isEmpty()
        || NetworkServiceUtils.isWebService(networkService)
        || NetworkServiceUtils.getServiceName(networkService).equals("unknown");
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Cve202014882VulnDetector starts detecting.");
    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(Cve202014882VulnDetector::isWebServiceOrUnknownService)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    String targetUri =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + CHECK_VUL_PATH;
    try {
      HttpResponse httpResponse =
          httpClient.send(get(targetUri).withEmptyHeaders().build(), networkService);
      // Solve the WebLogic http 302 redirection problem.
      Optional<String> cookie = httpResponse.headers().get(SET_COOKIE);
      if (httpResponse.status().code() == 302
          && cookie.isPresent()
          && cookie.get().contains(DETECTION_COOKIE)) {
        httpResponse =
            httpClient.send(
                get(targetUri)
                    .withEmptyHeaders()
                    .setHeaders(HttpHeaders.builder().addHeader(COOKIE, cookie.get()).build())
                    .build(),
                networkService);
      }
      if (httpResponse.status().code() == 200
          && httpResponse.bodyString().isPresent()
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
                        .setValue("CVE_2020_14882"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("CVE-2020-14882: Weblogic management console permission bypass")
                .setDescription(
                    "Vulnerability in the Oracle WebLogic Server product of Oracle Fusion"
                        + " Middleware (component: Console). Supported versions that are affected"
                        + " are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0."
                        + " Easily exploitable vulnerability allows unauthenticated attacker with"
                        + " network access via HTTP to compromise Oracle WebLogic Server."
                        + " Successful attacks of this vulnerability can result in takeover of"
                        + " Oracle WebLogic Server")
                .setRecommendation(
                    "Go to the oracle official website to download the latest weblogic patch."))
        .build();
  }
}
