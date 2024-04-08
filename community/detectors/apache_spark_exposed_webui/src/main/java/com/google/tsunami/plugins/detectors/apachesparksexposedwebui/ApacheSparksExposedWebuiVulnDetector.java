package com.google.tsunami.plugins.detectors.apachesparksexposedwebui;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.get;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
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
import com.google.tsunami.plugin.payload.PayloadGenerator;
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
import java.util.regex.Pattern;
import javax.inject.Inject;

/** A Tsunami plugin for detecting an exposed Apache Spark Web UI. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "ApacheSparksExposedWebuiVulnDetector",
    version = "0.1",
    description =
        "This plugin detects an exposed Apache Spark Web UI which discloses information about the"
            + " Apache Spark environment and its' tasks.",
    author = "Timo Mueller (work@mtimo.de)",
    bootstrapModule = ApacheSparksExposedWebuiVulnDetectorBootstrapModule.class)
public final class ApacheSparksExposedWebuiVulnDetector implements VulnDetector {

  private final Clock utcClock;
  private final HttpClient httpClient;
  private final PayloadGenerator payloadGenerator;
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private static final Pattern VULNERABILITY_RESPONSE_PATTERN_TENTATIVE =
      Pattern.compile("<title>Spark ");
  private static final Pattern VULNERABILITY_RESPONSE_PATTERN_CONFIRMATION =
      Pattern.compile("onClick=\"collapseTable\\('collapse-aggregated-");

  @Inject
  ApacheSparksExposedWebuiVulnDetector(
      @UtcClock Clock utcClock, HttpClient httpClient, PayloadGenerator payloadGenerator) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient);
    this.payloadGenerator = checkNotNull(payloadGenerator);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("ApacheSparksExposedWebuiVulnDetector starts detecting.");

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
    String targetUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);

    try {
      HttpResponse response =
          httpClient.send(
              get(targetUri)
                  .setHeaders(
                      HttpHeaders.builder().addHeader("User-Agent", "TSUNAMI_SCANNER").build())
                  .build(),
              networkService);
      if (response.status() == HttpStatus.OK && response.bodyString().isPresent()) {
        String responseBody = response.bodyString().get();
        if (VULNERABILITY_RESPONSE_PATTERN_TENTATIVE.matcher(responseBody).find()
            && VULNERABILITY_RESPONSE_PATTERN_CONFIRMATION.matcher(responseBody).find()) {
          return true;
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
                        .setValue("Apache_Spark_Exposed_WebUI"))
                .setSeverity(Severity.MEDIUM)
                .setTitle(
                    "Exposed Apache Spark UI which discloses information about the Apache Spark"
                        + " environment and its' tasks.")
                .setDescription(
                    "An exposed Apache Spark Web UI provides attackers information about the Apache"
                        + " Spark UI and its' tasks. The disclosed information might leak other"
                        + " configured Apache Spark nodes and the output of previously run tasks."
                        + " Depending on the task, the output might contain sensitive information"
                        + " which was logged during the task execution.")
                .setRecommendation(
                    "Don't expose the Apache Spark Web UI to unauthenticated attackers."))
        .build();
  }
}
