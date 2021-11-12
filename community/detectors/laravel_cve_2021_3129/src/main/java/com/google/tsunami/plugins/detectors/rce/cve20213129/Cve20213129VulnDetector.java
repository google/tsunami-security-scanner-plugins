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
package com.google.tsunami.plugins.detectors.rce.cve20213129;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.net.HttpHeaders.ACCEPT;
import static com.google.common.net.HttpHeaders.CONTENT_TYPE;

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
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.ForWebService;
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

/** A {@link VulnDetector} that detects the CVE-2021-3129 vulnerability. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "Cve20213129VulnDetector",
    version = "0.1",
    description =
        "This plugin detects Laravel (Version <= 8.4.2) running in debug mode, while using Ignition"
            + " (Version <= v2.5.1). Such instances are vulnerable to an unauthenticated remote"
            + " code execution vulnerability (CVE-2021-3129), due to unsafe user input handling.",
    author = "Timo Mueller (work@mtimo.de)",
    bootstrapModule = Cve20213129VulnDetectorBootstrapModule.class)

@ForWebService
public final class Cve20213129VulnDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final String QUERY_PATH = "_ignition/execute-solution";
  private static final String QUERY_PAYLOAD =
      "{\"solution\":"
          + " \"Facade\\\\Ignition\\\\Solutions\\\\MakeViewVariableOptionalSolution\",\"parameters\":"
          + " {\"variableName\": \"cve20213129_tsunami\", \"viewFile\":"
          + " \"phar://Tsunami_iDontExist\"}}";
  private static final CharSequence DETECTION_STRING =
      "file_get_contents(phar://Tsunami_iDontExist";

  private final HttpClient httpClient;
  private final Clock utcClock;

  @Inject
  Cve20213129VulnDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Cve20213129VulnDetector starts detecting.");

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
    String targetUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + QUERY_PATH;
    try {
      HttpResponse httpResponse =
          httpClient.send(
              HttpRequest.post(targetUri)
                  .setHeaders(
                      HttpHeaders.builder()
                          .addHeader(CONTENT_TYPE, MediaType.JSON_UTF_8.toString())
                          .addHeader(ACCEPT, MediaType.JSON_UTF_8.toString())
                          .build())
                  .setRequestBody(ByteString.copyFromUtf8(QUERY_PAYLOAD))
                  .build(),
              networkService);
      return httpResponse.bodyString().orElseGet(() -> "").contains(DETECTION_STRING);
    } catch (IOException e) {
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
                        .setValue("CVE_2021_3129"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("CVE-2021-3129: Unauthenticated RCE in Laravel using Debug Mode")
                .setDescription(
                    "Ignition before 2.5.2, as used in Laravel, allows unauthenticated remote"
                        + " attackers to execute arbitrary code because of insecure usage of"
                        + " file_get_contents() and file_put_contents(). This is exploitable on"
                        + " sites using debug mode with Laravel before 8.4.3")
                .setRecommendation(
                    "Update Laravel to at least version 8.4.3, and facade/ignition to at least"
                        + " version 2.5.2.For production systems it is advised to disable debug"
                        + " mode within the Laravel configuration."))
        .build();
  }
}
