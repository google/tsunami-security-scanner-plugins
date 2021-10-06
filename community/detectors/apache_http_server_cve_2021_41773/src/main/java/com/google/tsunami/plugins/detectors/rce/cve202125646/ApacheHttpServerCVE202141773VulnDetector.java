package com.google.tsunami.plugins.detectors.rce.cve202125646;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.get;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.inject.Inject;
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
import java.util.Optional;

/**
 * A {@link VulnDetector} that detects the CVE-2021-41773 vulnerability.
 */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "ApacheHttpServerCVE202141773VulnDetector",
    version = "1.0",
    description = "This detector checks for Apache HTTP Server 2.4.49 Path traversal and "
        + "disclosure vulnerability.",
    author = "threedr3am (qiaoer1320@gmail.com)",
    bootstrapModule = ApacheHttpServerCVE202141773VulnDetectorBootstrapModule.class
)
public class ApacheHttpServerCVE202141773VulnDetector implements VulnDetector {

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  private final HttpClient httpClient;

  @Inject
  ApacheHttpServerCVE202141773VulnDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
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
    String targetUri =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + "cgi-bin/.%2e/";
    try {
      HttpResponse response = httpClient.send(get(targetUri).withEmptyHeaders().build(),
          networkService);
      Optional<String> server = response.headers().get("Server");
      Optional<String> body = response.bodyString();
      if (server.isPresent() && server.get().contains("Apache/2.4.49") && body.isPresent()
          && !body.get().contains("You don't have permission to access this resource.")) {
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
                        .setValue("CVE_2021_41773"))
                .setSeverity(Severity.HIGH)
                .setTitle("Apache HTTP Server 2.4.49 Path traversal and disclosure vulnerability")
                .setDescription(
                    "A flaw was found in a change made to path normalization in Apache HTTP Server "
                        + "2.4.49. An attacker could use a path traversal attack to map URLs to "
                        + "files outside the expected document root."
                        + "If files outside of the document root "
                        + "are not protected by \"require all denied\" these requests can succeed. "
                        + "Additionally this flaw could leak the source of interpreted files "
                        + "like CGI scripts."
                        + "This issue is known to be exploited in the wild."
                        + "This issue only affects Apache 2.4.49 and not earlier versions."
                        + "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41773 "
                        + "https://httpd.apache.org/security/vulnerabilities_24.html")
                .setRecommendation("Update 2.4.50 released.")
        )
        .build();
  }
}
