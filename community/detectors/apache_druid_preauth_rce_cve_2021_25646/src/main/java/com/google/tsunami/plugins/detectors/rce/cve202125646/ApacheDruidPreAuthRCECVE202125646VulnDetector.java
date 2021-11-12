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
package com.google.tsunami.plugins.detectors.rce.cve202125646;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.data.NetworkEndpointUtils.toUriAuthority;
import static com.google.tsunami.common.net.http.HttpRequest.post;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.io.Resources;
import com.google.common.net.MediaType;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpHeaders;
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
import java.util.regex.Pattern;
import javax.inject.Inject;

/**
 * A {@link VulnDetector} that detects the CVE-2021-25646 vulnerability.
 */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "ApacheDruidPreAuthRCECVE202125646VulnDetector",
    version = "1.0",
    description = "This detector checks for Apache Druid <= 0.20.0 CVE-2021-25646 "
        + "Pre-Auth RCE vulnerability.",
    author = "threedr3am (qiaoer1320@gmail.com)",
    bootstrapModule = ApacheDruidPreAuthRCECVE202125646VulnDetectorBootstrapModule.class
)
public class ApacheDruidPreAuthRCECVE202125646VulnDetector implements VulnDetector {

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final String CHECK_VUL_PATH = "druid/indexer/v1/sampler";
  private static final Pattern VULNERABILITY_RESPONSE_PATTERN = Pattern.compile(
      "uid=.+?gid=.+?groups=.+?");

  private final Clock utcClock;
  private final HttpClient httpClient;
  private final String payloadString;

  @Inject
  ApacheDruidPreAuthRCECVE202125646VulnDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient);
    String payloadString;
    try {
      payloadString = Resources.toString(
          Resources.getResource(this.getClass(), "payloadString.json"), UTF_8);
    } catch (IOException e) {
      throw new AssertionError("Couldn't load payload resource file.", e);
    }
    this.payloadString = payloadString;
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(this::isWebServiceOrUnknownService)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  private boolean isWebServiceOrUnknownService(NetworkService networkService) {
    return networkService.getServiceName().isEmpty()
        || NetworkServiceUtils.isWebService(networkService)
        || NetworkServiceUtils.getServiceName(networkService).equals("unknown");
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    HttpHeaders httpHeaders = HttpHeaders.builder()
        .addHeader(com.google.common.net.HttpHeaders.CONTENT_TYPE, MediaType.JSON_UTF_8.toString())
        .build();

    ByteString requestBody = ByteString.copyFromUtf8(payloadString);
    String targetUri = buildTargetUrl(networkService);
    try {
      HttpResponse response = httpClient.send(
          post(targetUri).setHeaders(httpHeaders).setRequestBody(requestBody).build(),
          networkService);
      if (response.status() == HttpStatus.OK && response.bodyString().isPresent()) {
        String responseBody = response.bodyString().get();
        if (VULNERABILITY_RESPONSE_PATTERN.matcher(responseBody).find()) {
          return true;
        }
      }
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", targetUri);
    }
    return false;
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

  public DetectionReport buildDetectionReport(
      TargetInfo targetInfo, NetworkService vulnerableNetworkService) {
    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(vulnerableNetworkService)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder().setPublisher("TSUNAMI_COMMUNITY")
                        .setValue("CVE_2021_25646"))
                .setSeverity(Severity.HIGH)
                .setTitle("Apache Druid Pre-Auth RCE vulnerability (CVE-2021-25646)")
                .setDescription(
                    "Apache Druid includes the ability to execute user-provided JavaScript code "
                        + "embedded in various types of requests. "
                        + "This functionality is intended for use in high-trust environments, "
                        + "and is disabled by default. "
                        + "However, in Druid 0.20.0 and earlier, it is possible for an "
                        + "authenticated user "
                        + "to send a specially-crafted request that forces Druid to run "
                        + "user-provided "
                        + "JavaScript code for that request, regardless of server configuration. "
                        + "This can be leveraged to execute code on the target machine with the "
                        + "privileges of the Druid server process."
                        + "https://nvd.nist.gov/vuln/detail/CVE-2021-25646")
                .setRecommendation("Update 0.20.1 released, or later released.")
        )
        .build();
  }
}
