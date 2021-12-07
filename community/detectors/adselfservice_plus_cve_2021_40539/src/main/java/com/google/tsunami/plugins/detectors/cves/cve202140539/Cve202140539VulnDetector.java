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
package com.google.tsunami.plugins.detectors.cves.cve202140539;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.net.HttpHeaders.CONTENT_TYPE;
import static com.google.tsunami.common.data.NetworkEndpointUtils.toUriAuthority;
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

/** A {@link VulnDetector} that detects the CVE-2021-40539 vulnerability. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "CVE202140539VulnDetector",
    version = "0.1",
    description = Cve202140539VulnDetector.VULN_DESCRIPTION,
    author = "hh-hunter",
    bootstrapModule = Cve202140539DetectorBootstrapModule.class)
public final class Cve202140539VulnDetector implements VulnDetector {

  @VisibleForTesting
  static final String DETECTION_STRING = "<script type=\"text/javascript\">var d = new Date();";

  @VisibleForTesting
  static final String VULN_DESCRIPTION =
      "Zoho ManageEngine ADSelfService Plus version 6113 and prior is vulnerable to REST API "
          + "authentication bypass with resultant remote code execution.";

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private static final String VUL_PATH = "./RestAPI/LogonCustomization";

  private static final String POST_DATA = "methodToCall=previewMobLogo";

  private final HttpClient httpClient;

  private final Clock utcClock;

  @Inject
  Cve202140539VulnDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.httpClient = checkNotNull(httpClient);
    this.utcClock = checkNotNull(utcClock);
  }

  private static boolean isWebServiceOrUnknownService(NetworkService networkService) {
    return networkService.getServiceName().isEmpty()
        || NetworkServiceUtils.isWebService(networkService)
        || NetworkServiceUtils.getServiceName(networkService).equals("sun-answerbook");
  }

  private static StringBuilder buildTarget(NetworkService networkService) {
    StringBuilder targetUrlBuilder = new StringBuilder();
    if (NetworkServiceUtils.isWebService(networkService)) {
      targetUrlBuilder.append(NetworkServiceUtils.buildWebApplicationRootUrl(networkService));
    } else {
      targetUrlBuilder
          .append("http://")
          .append(toUriAuthority(networkService.getNetworkEndpoint()))
          .append("/");
    }
    targetUrlBuilder.append(VUL_PATH);
    return targetUrlBuilder;
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("CVE-2921-40539 starts detecting.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(Cve202140539VulnDetector::isWebServiceOrUnknownService)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    String targetVulnerabilityUrl = buildTarget(networkService).toString();
    try {
      HttpResponse httpResponse =
          httpClient.sendAsIs(
              post(targetVulnerabilityUrl)
                  .setHeaders(
                      HttpHeaders.builder()
                          .addHeader(CONTENT_TYPE, MediaType.FORM_DATA.toString())
                          .build())
                  .setRequestBody(ByteString.copyFromUtf8(POST_DATA))
                  .build());
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
                        .setValue("CVE_2021_40539"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("CVE-2021-40539 ADSelfService Plus REST API Authentication Bypass (RCE)")
                .setRecommendation(
                    "1. Disconnect the affected system from your network.\n2. Back up the "
                        + "ADSelfService Plus database using these steps.\n3. Format the "
                        + "compromised machine. \n4. Download and install ADSelfService Plus. \n"
                        + "5. Restore the backup and start the server.\n6. Once the server is up "
                        + "and running, update ADSelfService Plus to the latest build, 6114, using"
                        + " the service pack.\n7. Check for unauthorized access or use of accounts."
                        + " Also, check for any evidences of lateral movement from the compromised"
                        + " machine to other machines. If there are any indications of compromised"
                        + " Active Directory accounts, initiate password reset for those accounts.")
                .setDescription(VULN_DESCRIPTION))
        .build();
  }
}
