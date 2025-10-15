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

package com.google.tsunami.plugins.rce.flyteconsole;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.tsunami.common.net.http.HttpRequest.get;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.protobuf.util.Timestamps;
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
import com.google.tsunami.proto.DetectionReportList.Builder;
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
import java.util.regex.Pattern;
import javax.inject.Inject;

/** A VulnDetector plugin for Exposed Flyte Console Server. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "Exposed Flyte Console Detector",
    version = "0.1",
    description =
        "This detector identifies instances of exposed Flyte Console, "
            + "which could potentially allow for remote code execution (RCE).",
    author = "hayageek",
    bootstrapModule = ExposedFlyteConsoleDetectorModule.class)
@ForWebService
public final class ExposedFlyteConsoleDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  @VisibleForTesting static final String VULNERABILITY_REPORT_PUBLISHER = "TSUNAMI_COMMUNITY";
  @VisibleForTesting static final String VULNERABILITY_REPORT_ID = "FLYTE_CONSOLE_EXPOSED";

  @VisibleForTesting static final String VULNERABILITY_REPORT_TITLE = "Exposed Flyte Console";

  @VisibleForTesting
  static final String VULN_DESCRIPTION =
      "An exposed Flyte Console can lead to severe security risks, "
          + "including unauthorized access and potential remote code execution (RCE). "
          + "Ensure that access controls and security measures are properly configured "
          + "to prevent exploitation. Please refer to the remediation guidance section "
          + "below for mitigation strategies.";

  @VisibleForTesting
  static final String RECOMMENDATION =
      "Please disable public access to your flyte console instance.";

  @VisibleForTesting
  private static final Pattern VULNERABILITY_RESPONSE_PATTERN = Pattern.compile("<title>Flyte");

  @VisibleForTesting FlyteProtoClient flyteClient = new FlyteProtoClient();

  private static final int MAX_TIMEOUT_FOR_RCE_IN_SECS = 180;
  private final Clock utcClock;
  private final HttpClient httpClient;
  private final PayloadGenerator payloadGenerator;

  @Inject
  ExposedFlyteConsoleDetector(
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

    Builder detectionReport = DetectionReportList.newBuilder();
    matchedServices.stream()
        .filter(NetworkServiceUtils::isWebService)
        .filter(this::isFlyteConsole)
        .forEach(
            networkService -> {
              if (isVulnerable(networkService)) {
                detectionReport.addDetectionReports(
                    buildDetectionReport(
                        targetInfo,
                        networkService,
                        "Flyte Console is misconfigured and can be accessed publicly, potentially"
                            + " leading to Remote Code Execution (RCE). Tsunami security scanner"
                            + " confirmed this by sending an HTTP request with a test connection"
                            + " API and receiving the corresponding callback on the tsunami"
                            + " callback server.",
                        Severity.CRITICAL));
              }
            });
    return detectionReport.build();
  }

  public boolean isFlyteConsole(NetworkService networkService) {
    logger.atInfo().log("probing flyte console home page ");
    String rootUrl = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    var consolePageUrl = String.format("%s%s", rootUrl, "console");
    try {
      HttpResponse loginResponse =
          this.httpClient.send(get(consolePageUrl).withEmptyHeaders().build());
      if ((loginResponse.status() == HttpStatus.OK && loginResponse.bodyString().isPresent())) {
        String responseBody = loginResponse.bodyString().get();
        if (VULNERABILITY_RESPONSE_PATTERN.matcher(responseBody).find()) {
          return true;
        }
      }

    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", consolePageUrl);
    }
    logger.atWarning().log("unable to find flight console ");

    return false;
  }

  private boolean isVulnerable(NetworkService networkService) {
    Payload payload = getTsunamiCallbackHttpPayload();
    if (payload == null || !payload.getPayloadAttributes().getUsesCallbackServer()) {
      logger.atWarning().log("Tsunami callback server is not setup for this environment.");
      return false;
    }

    String rootUrl = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    try {

      // Set the URL and build the client.
      flyteClient.buildService(rootUrl);

      // Run the RCE and check the status in loop, until MAX_TIMEOUT_FOR_RCE_IN_SECS
      String payloadString = payload.getPayload();
      flyteClient.runShellScript(payloadString, MAX_TIMEOUT_FOR_RCE_IN_SECS);

      return payload.checkIfExecuted();
    } catch (Exception e) {
      logger.atWarning().withCause(e).log("Failed to send request.%s", e.getMessage());
      return false;
    }
  }

  private Payload getTsunamiCallbackHttpPayload() {
    try {
      return this.payloadGenerator.generate(
          PayloadGeneratorConfig.newBuilder()
              .setVulnerabilityType(PayloadGeneratorConfig.VulnerabilityType.REFLECTIVE_RCE)
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

  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo,
      NetworkService vulnerableNetworkService,
      String description,
      Severity severity) {
    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(vulnerableNetworkService)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(this.getAdvisories().getFirst())
        .build();
  }
}
