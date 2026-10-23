/*
 * Copyright 2026 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.google.tsunami.plugins.detectors.rce.php2shell;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.post;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Ascii;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.flogger.GoogleLogger;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.ForWebService;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.proto.CrawlResult;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Clock;
import java.util.Optional;
import javax.inject.Inject;

/**
 * A {@link VulnDetector} that detects PHP2Shell RCE (CVE-2026-109618 / CVE-2026-109619).
 *
 * <p>This detector sends a non-destructive ~300-byte multipart POST with {@code Cookie:
 * PHPSESSID=tsunami/invalid_sid_<ts>} and {@code PHP_SESSION_UPLOAD_PROGRESS}. Unpatched PHP fails
 * {@code php_session_initialize()} during {@code PHP Request Startup} (before user PHP code runs)
 * and unconditionally calls {@code php_session_flush(1)}, emitting both {@code is too long or
 * contains illegal characters} and {@code Failed to write session data}. Patched PHP returns early
 * without calling {@code php_session_flush(1)}.
 */
@ForWebService
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "PHP2Shell RCE Detector",
    version = "1.0",
    description =
        "Detects PHP core RCE vulnerabilities (CVE-2026-109618 and CVE-2026-109619) caused by"
            + " out-of-memory error-handling bailout corruption and session.upload_progress stale"
            + " global state.",
    author = "Tsunami Team",
    bootstrapModule = Php2ShellDetectorBootstrapModule.class)
public final class Php2ShellDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  @VisibleForTesting static final String VULNERABILITY_REPORT_PUBLISHER = "GOOGLE";
  @VisibleForTesting static final String VULNERABILITY_REPORT_ID = "CVE-2026-109618";
  @VisibleForTesting static final String VULNERABILITY_REPORT_TITLE = "PHP Core RCE (PHP2Shell)";

  @VisibleForTesting
  static final String VULN_DESCRIPTION =
      "PHP versions 5.4 through 8.5.11 are vulnerable to an unauthenticated Remote Code Execution"
          + " flaw caused by out-of-memory error-handling bailout corruption (CVE-2026-109618) and"
          + " stale global state in session.upload_progress (CVE-2026-109619).";

  @VisibleForTesting
  static final String RECOMMENDATION =
      "Upgrade PHP runtime to patched versions (8.5.12, 8.4.27, 8.3.36, 8.2.35) or disable"
          + " 'session.upload_progress.enabled = 0' in php.ini.";

  @VisibleForTesting
  static final ImmutableList<String> CANDIDATE_PATHS =
      ImmutableList.of("", "index.php", "public/index.php", "web/index.php", "wp-login.php");

  @VisibleForTesting
  static final String STAGE1_INVALID_SID_WARNING = "is too long or contains illegal characters";

  @VisibleForTesting
  static final String STAGE1_FAILED_FLUSH_WARNING = "Failed to write session data";

  private final Clock utcClock;
  private final HttpClient httpClient;

  @Inject
  Php2ShellDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(false).build();
  }

  @Override
  public ImmutableList<Vulnerability> getAdvisories() {
    return ImmutableList.of(
        Vulnerability.newBuilder()
            .setMainId(
                VulnerabilityId.newBuilder()
                    .setPublisher(VULNERABILITY_REPORT_PUBLISHER)
                    .setValue(VULNERABILITY_REPORT_ID))
            .addRelatedId(
                VulnerabilityId.newBuilder().setPublisher("CVE").setValue("CVE-2026-109618"))
            .addRelatedId(
                VulnerabilityId.newBuilder().setPublisher("CVE").setValue("CVE-2026-109619"))
            .setSeverity(Severity.CRITICAL)
            .setTitle(VULNERABILITY_REPORT_TITLE)
            .setDescription(VULN_DESCRIPTION)
            .setRecommendation(RECOMMENDATION)
            .build());
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Starting PHP2Shell detection.");

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
    for (String targetUrl : getTargetUrls(networkService)) {
      if (isTargetUrlVulnerable(networkService, targetUrl)) {
        return true;
      }
    }
    return false;
  }

  private boolean isTargetUrlVulnerable(NetworkService networkService, String targetUrl) {
    return isStage1InvalidSidFlushVulnerable(networkService, targetUrl);
  }

  private boolean isStage1InvalidSidFlushVulnerable(
      NetworkService networkService, String targetUrl) {
    Optional<HttpResponse> stage1Response = sendStage1InvalidSidProbe(networkService, targetUrl);
    if (stage1Response.isEmpty()) {
      return false;
    }

    String body = stage1Response.get().bodyString().orElse("");
    if (body.contains(STAGE1_INVALID_SID_WARNING) && body.contains(STAGE1_FAILED_FLUSH_WARNING)) {
      logger.atInfo().log(
          "PHP2Shell Stage 1 confirmed unpatched rfc1867 startup session flush on '%s'", targetUrl);
      return true;
    }
    return false;
  }

  private ImmutableSet<String> getTargetUrls(NetworkService networkService) {
    ImmutableSet.Builder<String> targetUrls = ImmutableSet.builder();
    for (CrawlResult crawlResult :
        networkService.getServiceContext().getWebServiceContext().getCrawlResultsList()) {
      String crawledUrl = crawlResult.getCrawlTarget().getUrl();
      try {
        URI uri = new URI(crawledUrl);
        if (uri.getPath() != null && Ascii.toLowerCase(uri.getPath()).endsWith(".php")) {
          targetUrls.add(crawledUrl);
          break;
        }
      } catch (URISyntaxException e) {
        logger.atFine().withCause(e).log("Failed to parse crawled URL '%s'", crawledUrl);
      }
    }
    String rootUrl = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    CANDIDATE_PATHS.forEach(subpath -> targetUrls.add(rootUrl + subpath));
    return targetUrls.build();
  }

  private Optional<HttpResponse> sendStage1InvalidSidProbe(
      NetworkService networkService, String targetUrl) {
    String boundary = "----TsunamiPhp2ShellBoundary" + utcClock.instant().toEpochMilli();

    String multipartBody =
        "--"
            + boundary
            + "\r\n"
            + "Content-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n"
            + "tsunami\r\n"
            + "--"
            + boundary
            + "\r\n"
            + "Content-Disposition: form-data; name=\"file\"; filename=\"tsunami.txt\"\r\n"
            + "Content-Type: text/plain\r\n\r\n"
            + "TSUNAMI_PROBE\r\n"
            + "--"
            + boundary
            + "--\r\n";

    try {
      return Optional.of(
          httpClient.send(
              post(targetUrl)
                  .setHeaders(
                      HttpHeaders.builder()
                          .addHeader("Content-Type", "multipart/form-data; boundary=" + boundary)
                          .addHeader("Connection", "keep-alive")
                          .addHeader(
                              "Cookie",
                              "PHPSESSID=tsunami/invalid_sid_" + utcClock.instant().toEpochMilli())
                          .build())
                  .setRequestBody(ByteString.copyFromUtf8(multipartBody))
                  .build(),
              networkService));
    } catch (IOException e) {
      logger.atFine().withCause(e).log(
          "HTTP exception while sending PHP2Shell Stage 1 request to '%s'", targetUrl);
      return Optional.empty();
    }
  }

  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo, NetworkService vulnerableNetworkService) {
    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(vulnerableNetworkService)
        .setDetectionTimestamp(Timestamps.fromMillis(utcClock.instant().toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(getAdvisories().get(0))
        .build();
  }
}
