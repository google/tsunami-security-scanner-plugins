package com.google.tsunami.plugins.detectors.nacos.authbypass;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.post;

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
 * A {@link VulnDetector} that detects the CVE-2021-29441 vulnerability.
 */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "NacosAuthBypassVulnDetector",
    version = "1.0",
    description = "This detector checks for Alibaba Nacos CVE-2021-29441 User-Agent "
        + "authentication bypass vulnerability.",
    author = "threedr3am (qiaoer1320@gmail.com)",
    bootstrapModule = NacosAuthBypassCVE202129441VulnDetectorBootstrapModule.class
)
public class NacosAuthBypassCVE202129441VulnDetector implements VulnDetector {

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  private final HttpClient httpClient;

  @Inject
  NacosAuthBypassCVE202129441VulnDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
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
        .addHeader(com.google.common.net.HttpHeaders.USER_AGENT, "Nacos-Server")
        .build();

    String targetUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService)
        + "nacos/v1/cs/configs?dataId=nacos.cfg.dataIdfoo&group=foo&content=helloWorld";
    try {
      HttpResponse response = httpClient.send(
          post(targetUri).withEmptyHeaders().setHeaders(httpHeaders).build(),
          networkService);
      if (response.status() == HttpStatus.OK && response.bodyString().isPresent()
          && response.bodyString().get().contains("true")) {
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
                        .setValue("CVE_2021_29441"))
                .setSeverity(Severity.HIGH)
                .setTitle("Alibaba-Nacos User-Agent authentication bypass vulnerability")
                .setDescription(
                    "This detector checks for Alibaba Nacos CVE-2021-29441 User-Agent "
                        + "authentication bypass vulnerability."
                        + "When the nacos version is less than or equal to 1.4.0, when accessing "
                        + "the http endpoint, "
                        + "adding the User-Agent: Nacos-Server header can bypass the "
                        + "authentication restriction and access any http endpoint."
                        + "https://github.com/alibaba/nacos/issues/4593 "
                        + "https://github.com/alibaba/nacos/pull/4703 "
                        + "https://github.com/advisories/GHSA-36hp-jr8h-556f "
                        + "https://nvd.nist.gov/vuln/detail/CVE-2021-29441 ")
                .setRecommendation("Update 1.4.1 released, or later released.")
        )
        .build();
  }
}
