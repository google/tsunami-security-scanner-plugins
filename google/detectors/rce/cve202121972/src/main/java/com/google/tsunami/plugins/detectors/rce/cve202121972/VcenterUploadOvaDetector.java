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
package com.google.tsunami.plugins.detectors.rce.cve202121972;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.post;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
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
import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TextData;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import javax.inject.Inject;

/**
 * A {@link VulnDetector} that detects exposed vCenter OVA Upload endpoints vulnerable to RCE
 * (CVE-2021-21972). If the application has a /ui/vropspluginui/rest/services/uploadova endpoint
 * that returns 405, the application is assumed to be vulnerable.
 */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "VcenterUploadOvaDetector",
    version = "0.1",
    description = "Detects CVE-2021-21972, upload OVA RCE in vCenter.",
    author = "Tsunami Team (tsunami-dev@google.com)",
    bootstrapModule = VcenterUploadOvaDetectorBootstrapModule.class)
public final class VcenterUploadOvaDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  private final HttpClient httpClient;

  @Inject
  VcenterUploadOvaDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(false).build();
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Starting VcenterUploadOva RCE detection.");
    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(NetworkServiceUtils::isWebService)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  /** Checks if a {@link NetworkService} has a vCenter upload OVA endpoint that returns 405. */
  private boolean isServiceVulnerable(NetworkService networkService) {
    String targetUri =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService)
            + "ui/vropspluginui/rest/services/uploadova";
    try {
      // This is a blocking call.
      HttpResponse response =
          httpClient.send(
              post(targetUri)
                  .setHeaders(
                      HttpHeaders.builder()
                          .addHeader("User-Agent", "Mozilla/5.0 (compatible; vCenter)")
                          .build())
                  .build());
      if (response.status().code() == HttpStatus.INTERNAL_SERVER_ERROR.code()
          && response.bodyString().isPresent()) {
        return response.bodyString().get().contains("uploadFile");
      }
      return false;
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", targetUri);
      return false;
    }
  }

  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo, NetworkService vulnerableNetworkService) {
    TextData details =
        TextData.newBuilder()
            .setText(
                String.format(
                    "The vCenter UploadOva endpoint %s is vulnerable to CVE-2021-1972.",
                    NetworkServiceUtils.buildWebApplicationRootUrl(vulnerableNetworkService)
                        + "ui/vropspluginui/rest/services/uploadova"))
            .build();
    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(vulnerableNetworkService)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder().setPublisher("GOOGLE").setValue("CVE_2021_21972"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("vCenter OVA Upload RCE")
                .setDescription(
                    "The vSphere Client (HTML5) contains a remote code execution vulnerability in a"
                        + " vCenter Server plugin. A malicious actor with network access to port"
                        + " 443 may exploit this issue to execute commands with unrestricted"
                        + " privileges on the underlying operating system that hosts vCenter"
                        + " Server. This affects VMware vCenter Server (7.x before 7.0 U1c, 6.7"
                        + " before 6.7 U3l and 6.5 before 6.5 U3n) and VMware Cloud Foundation (4.x"
                        + " before 4.2 and 3.x before 3.10.1.2).")
                .setRecommendation(
                    "To remediate CVE-2021-21972 apply the updates listed in the 'Fixed Version'"
                        + " column of the 'Response Matrix' below to affected deployments.\n"
                        + "\n"
                        + "Please see"
                        + " https://www.vmware.com/security/advisories/VMSA-2021-0002.html for the"
                        + " Response Matrix and the remediation instructions.")
                .addAdditionalDetails(AdditionalDetail.newBuilder().setTextData(details)))
        .build();
  }
}
