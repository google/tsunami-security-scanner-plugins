/*
 * Copyright 2022 Google LLC
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
package com.google.tsunami.plugins.detectors.jira;

import com.google.common.annotations.VisibleForTesting;
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
import com.google.tsunami.proto.*;

import javax.inject.Inject;
import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import java.util.Optional;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.net.HttpHeaders.SET_COOKIE;
import static com.google.tsunami.common.data.NetworkEndpointUtils.toUriAuthority;
import static com.google.tsunami.common.net.http.HttpRequest.get;

/** A {@link VulnDetector} that detects the CVE-2022-0540 vulnerability. Reading */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "Cve20220540VulnDetector",
    version = "0.1",
    description =
        "A vulnerability in Jira Seraph allows a remote, unauthenticated attacker to bypass"
            + " authentication by sending a specially crafted HTTP request. This affects Atlassian"
            + " Jira Server and Data Center versions before 8.13.18, versions 8.14.0 and later"
            + " before 8.20.6, and versions 8.21.0 and later before 8.22.0. This also affects"
            + " Atlassian Jira Service Management Server and Data Center versions before 4.13.18,"
            + " versions 4.14.0 and later before 4.20.6, and versions 4.21.0 and later before"
            + " 4.22.0.",
    author = "thiscodecc",
    bootstrapModule = Cve20220540DetectorBootstrapModule.class)
public final class Cve20220540VulnDetector implements VulnDetector {

  @VisibleForTesting static final String DETECTION_COOKIE = "atlassian.xsrf.token";
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final String CHECK_VUL_PATH = "secure/PerformOAuth2Authorization.jspa;";
  private final HttpClient httpClient;
  private final Clock utcClock;

  @Inject
  Cve20220540VulnDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(false).build();
    this.utcClock = checkNotNull(utcClock);
  }

  private static boolean isWebServiceOrUnknownService(NetworkService networkService) {
    return networkService.getServiceName().isEmpty()
        || NetworkServiceUtils.isWebService(networkService);
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

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Cve20220540VulnDetector starts detecting.");
    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(Cve20220540VulnDetector::isWebServiceOrUnknownService)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    String targetUri = buildTargetUrl(networkService);
    try {
      HttpResponse httpResponse =
          httpClient.send(get(targetUri).withEmptyHeaders().build(), networkService);
      Optional<String> cookie = httpResponse.headers().get(SET_COOKIE);
      if (httpResponse.status().code() == 200
          && cookie.isPresent()
          && cookie.get().contains(DETECTION_COOKIE)) {
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
                        .setValue("CVE_2022_0540"))
                .setSeverity(Severity.CRITICAL)
                .setTitle(
                    "CVE-2022-0540: unauthenticated attacker to bypass authentication by sending a"
                        + " specially crafted HTTP request")
                .setDescription(
                    "A vulnerability in Jira Seraph allows a remote, unauthenticated attacker to"
                        + " bypass authentication by sending a specially crafted HTTP request. This"
                        + " affects Atlassian Jira Server and Data Center versions before 8.13.18,"
                        + " versions 8.14.0 and later before 8.20.6, and versions 8.21.0 and later"
                        + " before 8.22.0. This also affects Atlassian Jira Service Management"
                        + " Server and Data Center versions before 4.13.18, versions 4.14.0 and"
                        + " later before 4.20.6, and versions 4.21.0 and later before 4.22.0")
                .setRecommendation("Upgrade Jira to the latest version"))
        .build();
  }
}
