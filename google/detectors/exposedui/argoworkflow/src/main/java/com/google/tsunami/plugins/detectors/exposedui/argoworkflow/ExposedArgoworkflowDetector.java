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
package com.google.tsunami.plugins.detectors.exposedui.argoworkflow;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.data.NetworkEndpointUtils.toUriAuthority;
import static com.google.tsunami.common.net.http.HttpRequest.get;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.flogger.GoogleLogger;
import com.google.gson.JsonSyntaxException;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
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
import javax.inject.Inject;

/** A {@link VulnDetector} that detects exposed Argoworkflow instances. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,

    // name of the plugin
    name = "ExposedArgoworkflowDetector",
    version = "0.1",

    // detailed description of the plugin
    description =
        "This plugin detects exposed and misconfigured ArgoWorkflow instances."
            + "Exposed Argo Workflow instances allow attackers to access kubernetes clusters."
            + "Attackers can change parameters of clusters and possibly compromise it.",
    author = "Shivangi Goel (goelshivangi@google.com)",
    bootstrapModule = ExposedArgoworkflowDetectorBootstrapModule.class)
public final class ExposedArgoworkflowDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  private final HttpClient httpClient;

  @Inject
  ExposedArgoworkflowDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(false).build();
  }

  private static final ImmutableSet<String> HTTP_EQUIVALENT_SERVICE_NAMES =
      ImmutableSet.of(
          "",
          "unknown", // nmap could not determine the service name, we try to exploit anyway.
          "ssl/cpudpencap");

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Starting exposed Argo Workflow instances detection.");
    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                // filter services which are in scope
                .filter(this::isInScopeService)
                // check if the services are vulnerable
                .filter(this::isServiceVulnerable)
                // Build a DetectionReport when the web service is vulnerable.
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
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

  private boolean isArgoWorkflowExposed(HttpResponse response) {
    boolean flag = response.toString().contains("managedNamespace");
    logger.atInfo().log("Is unauthorized content exposed: %s", flag);
    return flag;
  }

  /** Checks if a {@link NetworkService} has a misconfigured ArgoWorkflow instances exposed. */
  private boolean isServiceVulnerable(NetworkService networkService) {

    // the target URL of the target is built
    String rootUri = buildRootUri(networkService);

    String targetUri = rootUri + "api/v1/info";
    logger.atInfo().log("targetUri is %s", targetUri);
    try {
      // This is a blocking call.
      HttpResponse response =
          httpClient.send(get(targetUri).withEmptyHeaders().build(), networkService);
      logger.atInfo().log("the response is %s", response);
      return response.status().isSuccess() && isArgoWorkflowExposed(response);
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", targetUri);
      return false;
    } catch (JsonSyntaxException e) {
      logger.atWarning().withCause(e).log(
          "JSON syntax error occurred parsing response for target URI: '%s'.", targetUri);
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
        .setVulnerability(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder()
                        .setPublisher("GOOGLE")
                        .setValue("ARGOWORKFLOW_INSTANCE_EXPOSED"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("ArgoWorkflow instance Exposed")
                .setDescription(
                    "Argo Workflow instance is misconfigured."
                        + "The instance is not authenticated."
                        + "All workflows can be accessed by public and therefore can be modified."
                        + "Results in instance being compromised."))
        .build();
  }
}
