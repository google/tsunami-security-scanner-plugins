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

package com.google.tsunami.plugins.detectors.cve.cve202226148;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
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
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.inject.Inject;

/** A Tsunami plugin that detects Zabbix password disclosure in Grafana web services. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "CredentialsDisclosureInGrafanaZabbixIntegrationDetector",
    version = "0.1",
    description = "This plugin detects Zabbix password disclosure in Grafana web services.",
    author = "Alessandro Versari (alessandroversari1@gmail.com)",
    bootstrapModule = CredentialsDisclosureInGrafanaZabbixIntegrationDetectorBootstrapModule.class)
public final class CredentialsDisclosureInGrafanaZabbixIntegrationDetector implements VulnDetector {

  @VisibleForTesting static final String VULNERABILITY_REPORT_PUBLISHER = "TSUNAMI_COMMUNITY";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_ID = "GRAFANA_ZABBIX_CREDENTIAL_DISCLOSURE";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_TITLE = "Grafana zabbix credential disclosure";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_DESCRIPTION =
      "The scanner detected a credentials disclosure vulnerability in Grafana.Improper"
          + " configuration allows attackers to retrieve Zabbix credentials from the Grafana web"
          + " interface.\n"
          + "Details on the scanner logic:\n"
          + "Attempts to access Grafana anonymously and inspect the HTML for exposed Zabbix"
          + " credentials.";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_RECOMMENDATION =
      "In the Grafana configuration use `sercureJsonData` instead of `jsonData` to store the Zabbix"
          + " datasource's password and optionally disable anonymous access to Grafana";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_DETAILS =
      "Attacker can view the Zabbix credentials inspecting the Granafana's welcome page without"
          + " being authenticated";

  Severity vulnSeverity = Severity.CRITICAL;

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  private final HttpClient httpClient;

  private static final Pattern ZABBIX_PASSWORD_PATTERN =
      Pattern.compile("\"jsonData\"\\s*:\\s*\\{.*?\"password\"\\s*:\\s*\"");

  // these are the potential paths where the Zabbix password could be disclosed
  @VisibleForTesting
  static final ImmutableList<String> VULNERABLE_PATHS =
      ImmutableList.of("/login?redirect=%2F", "/login", "/", "/?orgId=1");

  private static final String GRAFANA_SERVICE_NAME = "Grafana";

  @Inject
  CredentialsDisclosureInGrafanaZabbixIntegrationDetector(
      @UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient);
  }

  @Override
  public ImmutableList<Vulnerability> getAdvisories() {
    return ImmutableList.of(
        Vulnerability.newBuilder()
            .setMainId(
                VulnerabilityId.newBuilder()
                    .setPublisher(VULNERABILITY_REPORT_PUBLISHER)
                    .setValue(VULNERABILITY_REPORT_ID))
            .addRelatedId(
                VulnerabilityId.newBuilder().setPublisher("CVE").setValue("CVE-2022-26148"))
            .setSeverity(vulnSeverity)
            .setTitle(VULNERABILITY_REPORT_TITLE)
            .setDescription(VULNERABILITY_REPORT_DESCRIPTION)
            .setRecommendation(VULNERABILITY_REPORT_RECOMMENDATION)
            .addAdditionalDetails(
                AdditionalDetail.newBuilder()
                    .setTextData(TextData.newBuilder().setText(VULNERABILITY_REPORT_DETAILS)))
            .build());
  }

  // This is the main entry point of VulnDetector
  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log(
        "CredentialsDisclosureInGrafanaZabbixIntegrationDetector starts detecting.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(NetworkServiceUtils::isWebService)
                .filter(this::isGrafanaOrUnknownSoftware)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  private boolean isGrafanaOrUnknownSoftware(NetworkService networkService) {
    var software = networkService.getServiceContext().getWebServiceContext().getSoftware();

    return (software.getName().equals(GRAFANA_SERVICE_NAME) || software.getName().isEmpty());
  }

  /*
    Check presence of the Zabbix password inside the html response

    Typical response:
    HTTP/2 200 OK
    <!DOCTYPE html>
    <html lang="en">
      [...]
      <script>
          window.grafanaBootData = {
              user : {...},
              settings : {... "jsonData": {"password": "zabbixPassword", ...} ...}
              navTree : {...}
          }
          [..]
      </script>
      [...]
    </html>
  */
  private boolean isServiceVulnerable(NetworkService networkService) {
    for (String path : VULNERABLE_PATHS) {
      String targetUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + path;

      logger.atInfo().log("Checking Grafana endpoint '%s'", targetUri);

      HttpRequest req =
          HttpRequest.get(targetUri).setHeaders(HttpHeaders.builder().build()).build();

      try {
        HttpResponse response = this.httpClient.send(req, networkService);
        if (response.status().code() == HttpStatus.OK.code()
            && response.bodyString().map(this::containsDisclosedCredentials).orElse(false)) {
          logger.atInfo().log("Zabbix credentials disclosed at '%s'", targetUri);
          return true; // Vulnerable if any path discloses credentials
        }
      } catch (IOException e) {
        logger.atWarning().withCause(e).log("Failed to query '%s'.", targetUri);
      }
    }

    logger.atInfo().log("Unable to detect Zabbix credentials in any tested paths.");
    return false;
  }

  // returns true if the Zabbix credentials are present in the body
  private boolean containsDisclosedCredentials(String body) {
    Matcher matcher = ZABBIX_PASSWORD_PATTERN.matcher(body);
    return matcher.find();
  }

  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo, NetworkService vulnerableNetworkService) {
    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(vulnerableNetworkService)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(getAdvisories().get(0))
        .build();
  }
}
