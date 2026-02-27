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

package com.google.tsunami.plugins.rce.dolphinscheduler;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.tsunami.common.net.http.HttpRequest.get;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.util.concurrent.Uninterruptibles;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkEndpointUtils;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.ForWebService;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.plugin.payload.NotImplementedException;
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
import java.util.regex.Pattern;
import javax.inject.Inject;

/**
 * A {@link VulnDetector} that identifies Apache DolphinScheduler instances with an exposed Java
 * Gateway using default credentials.
 *
 * <p>Apache DolphinScheduler is an open-source distributed workflow scheduler. It uses a Java
 * Gateway (based on Py4j) for Python SDK communication, which has a default authentication token
 * when deployed via Docker. If the Java Gateway is exposed with default credentials, attackers can
 * execute arbitrary tasks (e.g., Shell, Python), leading to remote code execution (RCE).
 */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "ApacheDolphinSchedulerExposedJavaGatewayDetector",
    version = "0.1",
    description =
        "This detector identifies Apache DolphinScheduler instances with an exposed Java Gateway"
            + " using default credentials, which could lead to remote code execution (RCE).",
    author = "TSUNAMI_COMMUNITY",
    bootstrapModule = ApacheDolphinSchedulerExposedJavaGatewayDetectorModule.class)
@ForWebService
public final class ApacheDolphinSchedulerExposedJavaGatewayDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  @VisibleForTesting static final String VULNERABILITY_REPORT_PUBLISHER = "TSUNAMI_COMMUNITY";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_ID = "DOLPHINSCHEDULER_EXPOSED_JAVA_GATEWAY";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_TITLE = "Apache DolphinScheduler Exposed Java Gateway";

  @VisibleForTesting
  static final String VULN_DESCRIPTION =
      "Apache DolphinScheduler's Java Gateway (Py4j) is exposed with default credentials. The Java"
          + " Gateway uses a default auth token when deployed via the official Docker image"
          + " (apache/dolphinscheduler-standalone-server). When exposed, attackers can authenticate"
          + " and submit workflows with Shell or Python tasks, leading to remote code execution"
          + " (RCE) on the DolphinScheduler worker nodes.";

  @VisibleForTesting
  static final String RECOMMENDATION =
      "1. Change the default auth token by setting PYDS_JAVA_GATEWAY_AUTH_TOKEN environment "
          + "variable to a strong, unique value when deploying DolphinScheduler.\n"
          + "2. Restrict network access to the Java Gateway port (default 25333) - it should "
          + "only be accessible from trusted clients that need to submit workflows.\n"
          + "3. Do not expose the Java Gateway to the public internet. Refer to the configuration "
          + "guide: https://dolphinscheduler.apache.org/python/main/config.html";

  /** Default auth token from Docker deployment (apache/dolphinscheduler-standalone-server). */
  @VisibleForTesting
  static final String DEFAULT_AUTH_TOKEN = "jwUDzpLsNKEFER4*a8gruBH_GsAurNxU7A@Xc";

  /** Default Java Gateway port (Py4j). */
  @VisibleForTesting static final int JAVA_GATEWAY_PORT = 25333;

  @VisibleForTesting
  static final Pattern DOLPHINSCHEDULER_PATTERN =
      Pattern.compile("dolphinscheduler|DolphinScheduler", Pattern.CASE_INSENSITIVE);

  /** Time to wait for RCE callback after executing payload. */
  @VisibleForTesting static final int OOB_SLEEP_DURATION_SECS = 5;

  private final Clock utcClock;
  private final HttpClient httpClient;
  private final PayloadGenerator payloadGenerator;

  @Inject
  ApacheDolphinSchedulerExposedJavaGatewayDetector(
      @UtcClock Clock utcClock, HttpClient httpClient, PayloadGenerator payloadGenerator) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(true).build();
    this.payloadGenerator = checkNotNull(payloadGenerator);
  }

  @Override
  public ImmutableList<Vulnerability> getAdvisories() {
    return ImmutableList.of(
        Vulnerability.newBuilder()
            .setMainId(
                VulnerabilityId.newBuilder()
                    .setPublisher(VULNERABILITY_REPORT_PUBLISHER)
                    .setValue(VULNERABILITY_REPORT_ID))
            .setSeverity(Severity.CRITICAL)
            .setTitle(VULNERABILITY_REPORT_TITLE)
            .setDescription(VULN_DESCRIPTION)
            .setRecommendation(RECOMMENDATION)
            .build());
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("ApacheDolphinSchedulerExposedJavaGatewayDetector starts detecting.");

    DetectionReportList.Builder detectionReport = DetectionReportList.newBuilder();
    matchedServices.stream()
        .filter(NetworkServiceUtils::isWebService)
        .filter(this::isDolphinScheduler)
        .filter(this::isVulnerable)
        .forEach(
            networkService ->
                detectionReport.addDetectionReports(
                    buildDetectionReport(targetInfo, networkService)));
    return detectionReport.build();
  }

  private boolean isDolphinScheduler(NetworkService networkService) {
    logger.atInfo().log("Probing for DolphinScheduler web UI.");
    String rootUrl = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    if (!rootUrl.endsWith("/")) {
      rootUrl += "/";
    }

    // DolphinScheduler UI can be at /dolphinscheduler or root (standalone uses 12345)
    String[] paths = {"", "dolphinscheduler", "dolphinscheduler/ui", "dolphinscheduler/ui/login"};
    for (String path : paths) {
      String targetUrl = rootUrl + path;
      try {
        HttpResponse response =
            httpClient.send(get(targetUrl).withEmptyHeaders().build(), networkService);
        if (response.status() == HttpStatus.OK && response.bodyString().isPresent()) {
          String body = response.bodyString().get();
          if (DOLPHINSCHEDULER_PATTERN.matcher(body).find()) {
            logger.atInfo().log("Found DolphinScheduler at %s", targetUrl);
            return true;
          }
        }
      } catch (IOException e) {
        logger.atFine().withCause(e).log("Unable to query '%s'", targetUrl);
      }
    }

    logger.atFine().log("DolphinScheduler not detected at %s", rootUrl);
    return false;
  }

  private boolean isVulnerable(NetworkService networkService) {
    Payload payload = getTsunamiCallbackHttpPayload();
    if (payload == null || !payload.getPayloadAttributes().getUsesCallbackServer()) {
      logger.atWarning().log("Tsunami callback server is not setup for this environment.");
      return false;
    }

    String host = getHostFromNetworkService(networkService);
    if (host == null || host.isEmpty()) {
      logger.atWarning().log("Could not extract host from network service.");
      return false;
    }

    Py4jGatewayClient py4jClient =
        new Py4jGatewayClient(host, JAVA_GATEWAY_PORT, DEFAULT_AUTH_TOKEN);

    try {
      String payloadString = payload.getPayload();
      if (py4jClient.authenticate()) {
        py4jClient.runShellScript(payloadString);
      } else {
        logger.atInfo().log("Failed to authenticate with Java Gateway.");
        return false;
      }
      logger.atInfo().log("Waiting for RCE callback.");
      Uninterruptibles.sleepUninterruptibly(Duration.ofSeconds(OOB_SLEEP_DURATION_SECS));
      return payload.checkIfExecuted();
    } catch (Exception e) {
      logger.atWarning().withCause(e).log(
          "Failed to verify RCE via Java Gateway: %s", e.getMessage());
      return false;
    }
  }

  private Payload getTsunamiCallbackHttpPayload() {
    try {
      return payloadGenerator.generate(
          PayloadGeneratorConfig.newBuilder()
              .setVulnerabilityType(PayloadGeneratorConfig.VulnerabilityType.BLIND_RCE)
              .setInterpretationEnvironment(
                  PayloadGeneratorConfig.InterpretationEnvironment.LINUX_SHELL)
              .setExecutionEnvironment(
                  PayloadGeneratorConfig.ExecutionEnvironment.EXEC_INTERPRETATION_ENVIRONMENT)
              .build());
    } catch (NotImplementedException n) {
      logger.atWarning().withCause(n).log("Failed to generate payload.");
      return null;
    }
  }

  private String getHostFromNetworkService(NetworkService networkService) {
    var endpoint = networkService.getNetworkEndpoint();
    if (NetworkEndpointUtils.hasHostname(endpoint)) {
      return endpoint.getHostname().getName();
    }
    if (endpoint.hasIpAddress()) {
      return endpoint.getIpAddress().getAddress();
    }
    return null;
  }

  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo, NetworkService vulnerableNetworkService) {
    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(vulnerableNetworkService)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(getAdvisories().getFirst())
        .build();
  }
}
