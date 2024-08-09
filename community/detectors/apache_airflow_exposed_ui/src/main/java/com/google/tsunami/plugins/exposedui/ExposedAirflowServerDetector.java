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

package com.google.tsunami.plugins.exposedui;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.tsunami.common.net.http.HttpRequest.get;
import static com.google.tsunami.common.net.http.HttpRequest.post;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.util.concurrent.Uninterruptibles;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkEndpointUtils;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.ForWebService;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.plugin.payload.NotImplementedException;
import com.google.tsunami.plugin.payload.Payload;
import com.google.tsunami.plugin.payload.PayloadGenerator;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionReportList.Builder;
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
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.inject.Inject;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

/** A VulnDetector plugin for Exposed Apache Airflow Server. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "Exposed Apache Airflow Server Detector",
    version = "0.1",
    description =
        "This detector checks for occurrences of exposed apache airflow server installations.",
    author = "am0o0",
    bootstrapModule = ExposedAirflowServerDetectorModule.class)
@ForWebService
public final class ExposedAirflowServerDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  private final HttpClient httpClient;
  private final PayloadGenerator payloadGenerator;

  @Inject
  ExposedAirflowServerDetector(
      @UtcClock Clock utcClock, HttpClient httpClient, PayloadGenerator payloadGenerator) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(true).build();
    this.payloadGenerator = checkNotNull(payloadGenerator);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {

    Builder detectionReport = DetectionReportList.newBuilder();
    matchedServices.stream()
        .filter(NetworkServiceUtils::isWebService)
        .filter(this::isApacheAirflow)
        .forEach(
            networkService -> {
              if (isServiceVulnerableCheckOutOfBandCallback(networkService)) {
                detectionReport.addDetectionReports(
                    buildDetectionReport(
                        targetInfo,
                        networkService,
                        "Apache Airflow Server is misconfigured and can be accessed publicly,"
                            + " Tsunami security scanner confirmed this by sending an HTTP request"
                            + " with test connection API and receiving the corresponding callback"
                            + " on tsunami callback server",
                        Severity.CRITICAL));
              } else if (isServiceVulnerableCheckResponse(networkService)) {
                detectionReport.addDetectionReports(
                    buildDetectionReport(
                        targetInfo,
                        networkService,
                        "Apache Airflow Server is misconfigured and can be accessed "
                            + "publicly, We confirmed this by checking API endpoint and matching "
                            + "the responses with our pattern",
                        Severity.HIGH));
              }
            });
    return detectionReport.build();
  }

  public boolean isApacheAirflow(NetworkService networkService) {
    logger.atInfo().log("probing apache airflow login page - custom fingerprint phase");

    var uriAuthority = NetworkEndpointUtils.toUriAuthority(networkService.getNetworkEndpoint());
    var loginPageUrl = String.format("http://%s/%s", uriAuthority, "login");
    try {
      HttpResponse loginResponse =
          this.httpClient.send(get(loginPageUrl).withEmptyHeaders().build());
      if (!(loginResponse.status() == HttpStatus.OK && loginResponse.bodyString().isPresent())) {
        return false;
      }
      Document doc = Jsoup.parse(loginResponse.bodyString().get());
      if (!Objects.equals(doc.title(), "Sign In - Airflow")) {
        return false;
      }
      for (Element anchor : doc.getElementsByTag("a")) {
        if (anchor.attr("href").equals("https://airflow.apache.org")
            && Objects.equals(anchor.text(), "Airflow Website")) {
          return true;
        }
      }
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", loginPageUrl);
    }
    return false;
  }

  private boolean isServiceVulnerableCheckOutOfBandCallback(NetworkService networkService) {
    var payload = getTsunamiCallbackHttpPayload();
    if (payload == null || !payload.getPayloadAttributes().getUsesCallbackServer()) {
      logger.atWarning().log("Tsunami callback server is not setup for this environment.");
      return false;
    }

    String rootUrl = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    try {
      String payloadString = payload.getPayload();
      String payloadWithoutProtocol;
      // I noticed that there are two types of SSRF payload, one the payload exists as a
      // subdomain and other exists as an http path
      if (payloadString.contains("http://") || payloadString.contains("https://")) {
        Matcher m = Pattern.compile("https?://(.*)").matcher(payloadString);
        if (!m.find()) {
          return false;
        }
        payloadWithoutProtocol = m.group(1);
      } else {
        payloadWithoutProtocol = payloadString;
      }
      String body =
          "{\"connection_id\":\"tsunami\",\"conn_type\":\"http\",\"host\":\"SSRF_PAYLOAD\",\"extra\":\"{}\"}"
              .replace("SSRF_PAYLOAD", payloadWithoutProtocol);
      this.httpClient.send(
          post(rootUrl + "api/v1/connections/test")
              .setHeaders(
                  HttpHeaders.builder().addHeader("Content-Type", "application/json").build())
              .setRequestBody(ByteString.copyFromUtf8(body))
              .build(),
          networkService);

      Uninterruptibles.sleepUninterruptibly(Duration.ofSeconds(2));
      return payload.checkIfExecuted();
    } catch (IOException | RuntimeException e) {
      logger.atWarning().withCause(e).log("Failed to send request.");
      return false;
    }
  }

  private boolean isServiceVulnerableCheckResponse(NetworkService networkService) {
    String rootUrl = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    try {
      HttpResponse dags =
          this.httpClient.send(
              get(rootUrl + "api/v1/dags").withEmptyHeaders().build(), networkService);
      if (dags.bodyString().isEmpty()) {
        return false;
      }
      JsonObject response = JsonParser.parseString(dags.bodyString().get()).getAsJsonObject();
      return response.has("total_entries") && response.has("dags");
    } catch (IllegalStateException | IOException | JsonSyntaxException e) {
      return false;
    }
  }

  private Payload getTsunamiCallbackHttpPayload() {
    try {
      return this.payloadGenerator.generate(
          PayloadGeneratorConfig.newBuilder()
              .setVulnerabilityType(PayloadGeneratorConfig.VulnerabilityType.SSRF)
              .setInterpretationEnvironment(
                  PayloadGeneratorConfig.InterpretationEnvironment.INTERPRETATION_ANY)
              .setExecutionEnvironment(PayloadGeneratorConfig.ExecutionEnvironment.EXEC_ANY)
              .build());
    } catch (NotImplementedException n) {
      return null;
    }
  }

  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo,
      NetworkService vulnerableNetworkService,
      String description,
      Severity severity) {
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
                        .setValue("APACHE_AIRFLOW_SERVER_EXPOSED"))
                .setSeverity(severity)
                .setTitle("Exposed Apache Airflow Server")
                .setDescription(description)
                .setRecommendation("Please disable public access to your apache airflow instance."))
        .build();
  }
}
