package com.google.tsunami.plugins.detectors.goanywhere;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.post;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
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
import com.google.tsunami.plugin.payload.Payload;
import com.google.tsunami.plugin.payload.PayloadGenerator;
import com.google.tsunami.proto.*;
import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import javax.inject.Inject;

/** A {@link VulnDetector} that detects the CVE-2022-0540 vulnerability. Reading */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    author = "SuperX (SuperX.SIR@proton.me)",
    name = "Cve20230669VulnDetector",
    version = "0.1",
    description =
        "GoAnywhere MFT up to version 7.11 suffers from a pre-authentication command injection vulnerability in the License "
            + "Response Servlet due to deserializing an arbitrary attacker-controlled object."
    bootstrapModule = Cve20230669DetectorBootstrapModule.class)
public class Cve20230669VulnDetector implements VulnDetector {

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final String LICENSE_URL = "goanywhere/lic/accept";
  private static final String COMMAND_HEADER = "x-protect";
  private final HttpClient httpClient;
  private final Clock utcClock;
  private final PayloadGenerator payloadGenerator;

  @Inject
  Cve20230669VulnDetector(
      @UtcClock Clock utcClock, HttpClient httpClient, PayloadGenerator payloadGenerator) {
    this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(false).build();
    this.utcClock = checkNotNull(utcClock);
    this.payloadGenerator = checkNotNull(payloadGenerator);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("CVE-2023-0669 starts detecting.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(NetworkServiceUtils::isWebService)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    PayloadGeneratorConfig config =
        PayloadGeneratorConfig.newBuilder()
            .setVulnerabilityType(PayloadGeneratorConfig.VulnerabilityType.BLIND_RCE)
            .setInterpretationEnvironment(
                PayloadGeneratorConfig.InterpretationEnvironment.LINUX_SHELL)
            .setExecutionEnvironment(
                PayloadGeneratorConfig.ExecutionEnvironment.EXEC_INTERPRETATION_ENVIRONMENT)
            .build();

    if (!payloadGenerator.isCallbackServerEnabled()) {
      logger.atInfo().log("Callback server disabled but required for this detector.");
      return false;
    }

    Payload payload = this.payloadGenerator.generate(config);
    String commandToInject = String.format("%s", payload.getPayload());
    String licenseUrl =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + LICENSE_URL;

    try {
      HttpResponse httpResponse =
          httpClient.send(
              post(licenseUrl)
                  .setHeaders(
                      HttpHeaders.builder()
                          .addHeader(
                              "Content-Type",
                              "application/x-www-form-urlencoded; " + "charset=UTF-8")
                          .addHeader(COMMAND_HEADER, commandToInject)
                          .build())
                  .setRequestBody(ByteString.copyFromUtf8(deserialized))
                  .build(),
              networkService);
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Request to target %s failed", networkService);
    }
    return payload.checkIfExecuted();
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
                        .setValue("CVE-2023-0669"))
                .addRelatedId(
                    VulnerabilityId.newBuilder().setPublisher("CVE").setValue("CVE-2023-0669"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("CVE-2023-0669: GoAnywhere MFT RCE vulnerability")
                .setDescription(
                    "GoAnywhere MFT suffers from a pre-authentication command injection "
                        + "vulnerability in the License Response Servlet due to deserializing"
                        + " an arbitrary attacker-controlled object. All versions prior to 7.1.1 are affected.")
                .setRecommendation(
                    "Update GoAnywhere MFT to version 7.1.2 or later."))
        .build();
  }
}
