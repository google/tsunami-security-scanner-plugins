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
package com.google.tsunami.plugins.detectors.exposedui.pytorchserve;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
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
import java.time.Clock;
import java.time.Instant;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.inject.Inject;

/**
 * A Pytorch Serve API Exposure VulnDetector plugin that uses the Tsunami callback server to verify
 * that the API allows model uploads.
 */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "PytorchServeExposedApiDetector",
    version = "0.1",
    description = "This is a Tsunami plugin that detects if the Pytorch Serve API is exposed",
    author = "Tsunami Team (tsunami-dev@google.com)",
    bootstrapModule = PytorchServeExposedApiDetectorBootstrapModule.class)
@ForWebService
public final class PytorchServeExposedApiDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  private final HttpClient httpClient;
  private final PayloadGenerator payloadGenerator;
  @VisibleForTesting static final String VULNERABILITY_REPORT_PUBLISHER = "GOOGLE";
  @VisibleForTesting static final String VULNERABILITY_REPORT_ID = "PYTORCH_EXPOSED_UI";
  private static final Pattern URI_REGEX = Pattern.compile("curl (.*)");

  @VisibleForTesting static final String VULNERABILITY_REPORT_TITLE = "Pytorch Exposed API";

  @VisibleForTesting
  static final String VULN_DESCRIPTION =
      "Exposed API allows anonymous users to upload arbitrary ML models.";

  @VisibleForTesting
  static final String RECOMMENDATION =
      "Please use firewalls or bind the service only to local network";

  @Inject
  PytorchServeExposedApiDetector(
      @UtcClock Clock utcClock, HttpClient httpClient, PayloadGenerator payloadGenerator) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(false).build();
    this.payloadGenerator = checkNotNull(payloadGenerator);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("ExampleVulnDetectorWithPayload starts detecting.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  private boolean isServiceVulnerable(NetworkService networkService) {

    PayloadGeneratorConfig config =
        PayloadGeneratorConfig.newBuilder()
            .setVulnerabilityType(PayloadGeneratorConfig.VulnerabilityType.REFLECTIVE_RCE)
            .setInterpretationEnvironment(
                PayloadGeneratorConfig.InterpretationEnvironment.LINUX_SHELL)
            .setExecutionEnvironment(
                PayloadGeneratorConfig.ExecutionEnvironment.EXEC_INTERPRETATION_ENVIRONMENT)
            .build();

    Payload payload = this.payloadGenerator.generate(config);

    if (!payload.getPayloadAttributes().getUsesCallbackServer()) {
      return false;
    }
    Matcher m = URI_REGEX.matcher(payload.getPayload());
    if (!m.find()) {
      return false;
    }

    String targetUri =
        String.format(
            "%smodels?url=http://%s/%s",
            NetworkServiceUtils.buildWebApplicationRootUrl(networkService),
            m.group(1),
            Long.toHexString(Double.doubleToLongBits(Math.random())));
    logger.atInfo().log("PytorchServeApiExposedui targetUri: %s", targetUri);
    HttpRequest req = HttpRequest.post(targetUri).withEmptyHeaders().build();

    try {
      HttpResponse res = this.httpClient.send(req, networkService);
      return payload.checkIfExecuted(res.bodyBytes());
    } catch (IOException e) {
      return false;
    }
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
