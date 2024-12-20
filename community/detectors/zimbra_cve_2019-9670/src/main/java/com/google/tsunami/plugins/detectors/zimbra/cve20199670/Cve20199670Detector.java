/*
 * Copyright 2024 Google LLC
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
package com.google.tsunami.plugins.detectors.zimbra.cve20199670;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
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
import java.util.UUID;
import javax.inject.Inject;

/** A {@link VulnDetector} that detects CVE-2019-9670. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "CVE-2019-9670 Detector",
    version = "0.1",
    description = "Detects CVE-2019-9670 XXE vulnerability in Synacor Zimbra Collaboration Suite.",
    author = "Leonardo Tamiano (leonardo.tamiano@mindedsecurity.com)",
    bootstrapModule = Cve20199670DetectorBootstrapModule.class)
public final class Cve20199670Detector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  @VisibleForTesting static final String VULNERABILITY_REPORT_PUBLISHER = "TSUNAMI_COMMUNITY";
  @VisibleForTesting static final String VULNERABILITY_REPORT_ID = "CVE_2019-9670";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_TITLE = "Synacor Zimbra XXE CVE-2019-9670";

  @VisibleForTesting
  static final String VULN_DESCRIPTION =
      "The mailboxd component of Synacor Zimbra Collaboration Suite, in versions from 8.5 to"
          + " 8.7.11p10, is vulnerable to an XML External Entity injection (XXE). The vulnerability"
          + " is found in the autodiscover feature, available to unauthenticated users through the"
          + " endpoint /Autodiscover/Autodiscover.xml. The vulnerability allows malicious actors to"
          + " extract sensitive files from the system and can be chained with another"
          + " vulnerability (CVE-2019-9621) in order to obtain an unauthenticated RCE."
          + " Specifically, by using the XXE (CVE-2019-9670) it is possible to read a configuration"
          + " file that contains an LDAP password for the zimbra account. The zimbra credentials"
          + " are then used to get a user authentication cookie with an AuthRequest message. Using"
          + " the user cookie, a SSRF (CVE-2019-9621) in the Proxy Servlet is used to proxy an"
          + " AuthRequest with the zimbra credentials to the admin port to retrieve an admin"
          + " cookie. After gaining an admin cookie the Client Upload servlet is used to upload a"
          + " JSP webshell that can be triggered from the web server to obtain RCE.";

  @VisibleForTesting
  static final String RECOMMENDATION =
      "Upgrade to non-vulnerable versions of Synacor Zimbra Collaboration Suite such as 8.7.11p14"
          + " or later versions such as 8.8.x, 9.x and 10.x.";

  @VisibleForTesting static final String TEST_STRING = String.format("%s", UUID.randomUUID());

  @VisibleForTesting
  static final String ERROR_MSG = "Error 503 Requested response schema not available";

  @VisibleForTesting
  static final String ZIMBRA_FINGERPRING = "Zimbra Collaboration Suite Web Client";

  private static final String PAYLOAD_TEMPLATE_REFLECTED =
      "<?xml version=\"1.0\" ?>\n"
          + "<!DOCTYPE foo [<!ENTITY xxe \"%s\"> ]>\n"
          + "<Request>\n"
          + "<EMailAddress>email</EMailAddress>\n"
          + "<AcceptableResponseSchema>&xxe;</AcceptableResponseSchema>\n"
          + "</Request>";

  private static final String AUTODISCOVER_PATH = "Autodiscover/Autodiscover.xml";

  private final Clock utcClock;
  private final HttpClient httpClient;

  @Inject
  Cve20199670Detector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(false).build();
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Starting CVE-2019-9670 RCE detection.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(NetworkServiceUtils::isWebService)
                .filter(this::isZimbra)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  private boolean isZimbra(NetworkService networkService) {
    boolean isZimbra = false;

    // Check presence of zimbra fingerpring in root
    String targetUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    try {
      HttpRequest request = HttpRequest.get(targetUri).withEmptyHeaders().build();
      HttpResponse response = response = this.httpClient.send(request, networkService);
      isZimbra =
          (response.status().code() == 200)
              && response.bodyString().map(body -> body.contains(ZIMBRA_FINGERPRING)).orElse(false);
    } catch (IOException e) {
      return false;
    }

    // Check presence of autodiscover endpoint
    targetUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + AUTODISCOVER_PATH;
    try {
      HttpRequest request = HttpRequest.get(targetUri).withEmptyHeaders().build();
      HttpResponse response = response = this.httpClient.send(request, networkService);
      isZimbra = isZimbra && (response.status().code() == 200);
    } catch (IOException e) {
      return false;
    }

    return isZimbra;
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    boolean isVulnerable = false;

    String targetUri =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + AUTODISCOVER_PATH;
    String reflectedPayload = String.format(PAYLOAD_TEMPLATE_REFLECTED, TEST_STRING);
    HttpRequest request =
        HttpRequest.post(targetUri)
            .setHeaders(HttpHeaders.builder().addHeader("Content-Type", "application/xml").build())
            .setRequestBody(ByteString.copyFromUtf8(reflectedPayload))
            .build();
    try {
      HttpResponse response = httpClient.send(request, networkService);
      isVulnerable =
          (response.status().code() == 503)
              && response
                  .bodyString()
                  // To decrease false positive rate, match also with specific error message
                  .map(body -> (body.contains(TEST_STRING) && body.contains(ERROR_MSG)))
                  .orElse(false);
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Request to target '%s' failed", targetUri);
      return false;
    }

    return isVulnerable;
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
                        .setPublisher(VULNERABILITY_REPORT_PUBLISHER)
                        .setValue(VULNERABILITY_REPORT_ID))
                .setSeverity(Severity.CRITICAL)
                .setTitle(VULNERABILITY_REPORT_TITLE)
                .setDescription(VULN_DESCRIPTION)
                .setRecommendation(RECOMMENDATION))
        .build();
  }
}
