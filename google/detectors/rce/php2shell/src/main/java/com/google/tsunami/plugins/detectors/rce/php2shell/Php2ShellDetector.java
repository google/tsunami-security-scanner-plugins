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
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.inject.Inject;

/**
 * A {@link VulnDetector} that detects PHP2Shell RCE (CVE-2026-109618 / CVE-2026-109619).
 *
 * <p>Detection runs in two stages:
 *
 * <ul>
 *   <li><b>Stage 1 (Startup Flush Warning Check):</b> Sends a non-destructive ~300-byte multipart
 *       POST with {@code Cookie: PHPSESSID=tsunami/invalid_sid_<ts>} and {@code
 *       PHP_SESSION_UPLOAD_PROGRESS}. Unpatched PHP fails {@code php_session_initialize()} during
 *       {@code PHP Request Startup} and calls {@code php_session_flush(1)}, emitting both {@code is
 *       too long or contains illegal characters} and {@code Failed to write session data}. Patched
 *       PHP returns early without calling {@code php_session_flush(1)}.
 *   <li><b>Stage 2 (Upload-Progress Session Cookie Differential + Version Check):</b> For servers
 *       with {@code display_startup_errors = Off} that disclose an unpatched PHP 8.2+ version
 *       ({@code 8.2.0..8.2.34}, {@code 8.3.0..8.3.35}, {@code 8.4.0..8.4.26}, {@code
 *       8.5.0..8.5.11}) via {@code phpinfo()}, {@code X-Powered-By}, or {@code Server}, sends a
 *       control multipart POST (without {@code PHP_SESSION_UPLOAD_PROGRESS}) and a marker multipart
 *       POST (with {@code PHP_SESSION_UPLOAD_PROGRESS}) using {@code Cookie: PHPSESSID=} to verify
 *       that {@code session.upload_progress} emits an additional {@code Set-Cookie: PHPSESSID}
 *       header.
 * </ul>
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
          + " stale global state in session.upload_progress (CVE-2026-109619). This detector"
          + " confirms that the PHP session.upload_progress RFC1867 handler is reachable"
          + " unauthenticated and verifies patch status via either the unpatched startup"
          + " session-flush warning or a disclosed PHP version below the fixed release (8.2.35,"
          + " 8.3.36, 8.4.27, 8.5.12). Note: When startup errors are disabled, vendor OS packages"
          + " that backport the fix without updating the disclosed PHP version number are still"
          + " reported if session.upload_progress remains enabled.";

  @VisibleForTesting
  static final String RECOMMENDATION =
      "Upgrade PHP runtime to patched versions (8.5.12, 8.4.27, 8.3.36, 8.2.35) or disable"
          + " 'session.upload_progress.enabled = 0' in php.ini. If using an OS vendor package that"
          + " backports the fix without changing the PHP version string, set"
          + " 'session.upload_progress.enabled = 0' or 'expose_php = Off' in php.ini.";

  @VisibleForTesting
  static final ImmutableList<String> CANDIDATE_PATHS =
      ImmutableList.of("", "index.php", "public/index.php", "web/index.php", "wp-login.php");

  @VisibleForTesting
  static final String STAGE1_INVALID_SID_WARNING = "is too long or contains illegal characters";

  @VisibleForTesting
  static final String STAGE1_FAILED_FLUSH_WARNING = "Failed to write session data";

  private static final Pattern PHP_INFO_VERSION_PATTERN =
      Pattern.compile("(?i)<h1 class=.p.>php version (\\d+(?:\\.\\d+)*)");

  private static final Pattern PHP_X_POWERED_BY_VERSION_PATTERN =
      Pattern.compile("(?i)^\\s*php/?(\\d+(?:\\.\\d+)*)");

  private static final Pattern PHP_SERVER_VERSION_PATTERN =
      Pattern.compile("(?i)php/(\\d+(?:\\.\\d+)*)");

  private static final Pattern ANY_PHPSESSID_COOKIE_PATTERN =
      Pattern.compile("(?i)(?:^|;\\s*)PHPSESSID=[A-Za-z0-9,-]+");

  private static final Pattern VALID_PHPSESSID_COOKIE_PATTERN =
      Pattern.compile("(?i)(?:^|;\\s*)PHPSESSID=[A-Za-z0-9,-]{22,256}");

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
    if (isStage1InvalidSidFlushVulnerable(networkService, targetUrl)) {
      return true;
    }

    return isStage2UploadProgressCookieDifferentialVulnerable(networkService, targetUrl);
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

  private boolean isStage2UploadProgressCookieDifferentialVulnerable(
      NetworkService networkService, String targetUrl) {
    Optional<HttpResponse> controlResponse = sendStage2ControlProbe(networkService, targetUrl);
    if (controlResponse.isEmpty()) {
      return false;
    }

    Optional<HttpResponse> markerResponse = sendStage2MarkerProbe(networkService, targetUrl);
    if (markerResponse.isEmpty() || markerResponse.get().status().code() >= 500) {
      return false;
    }

    int controlCookieCount =
        countMatchingSetCookieHeaders(controlResponse.get(), ANY_PHPSESSID_COOKIE_PATTERN);
    int markerValidCookieCount =
        countMatchingSetCookieHeaders(markerResponse.get(), VALID_PHPSESSID_COOKIE_PATTERN);

    boolean cookieDifferentialMatched =
        controlCookieCount < 2
            && (markerValidCookieCount >= 2
                || (controlCookieCount == 0 && markerValidCookieCount >= 1));

    if (cookieDifferentialMatched && hasDisclosedUnpatchedPhpVersion(markerResponse.get())) {
      logger.atInfo().log(
          "PHP2Shell Stage 2 confirmed upload_progress session cookie differential with unpatched"
              + " PHP version on '%s'",
          targetUrl);
      return true;
    }
    return false;
  }

  private static int countMatchingSetCookieHeaders(HttpResponse response, Pattern pattern) {
    int count = 0;
    for (String cookieHeader : response.headers().getAll("Set-Cookie")) {
      if (pattern.matcher(cookieHeader).find()) {
        count++;
      }
    }
    return count;
  }

  private static boolean hasDisclosedUnpatchedPhpVersion(HttpResponse response) {
    Optional<String> disclosedVersion = extractDisclosedPhpVersion(response);
    return disclosedVersion.isPresent() && isUnpatchedPhpVersion(disclosedVersion.get());
  }

  /**
   * Extracts the disclosed PHP version following precedence: {@code phpinfo()} body &gt; {@code
   * X-Powered-By} header &gt; {@code Server} header.
   */
  private static Optional<String> extractDisclosedPhpVersion(HttpResponse response) {
    String body = response.bodyString().orElse("");
    Matcher phpInfoMatcher = PHP_INFO_VERSION_PATTERN.matcher(body);
    if (phpInfoMatcher.find()) {
      return Optional.of(phpInfoMatcher.group(1));
    }

    for (String xpb : response.headers().getAll("X-Powered-By")) {
      Matcher xpbMatcher = PHP_X_POWERED_BY_VERSION_PATTERN.matcher(xpb);
      if (xpbMatcher.find()) {
        return Optional.of(xpbMatcher.group(1));
      }
    }

    for (String server : response.headers().getAll("Server")) {
      Matcher srvMatcher = PHP_SERVER_VERSION_PATTERN.matcher(server);
      if (srvMatcher.find()) {
        return Optional.of(srvMatcher.group(1));
      }
    }

    return Optional.empty();
  }

  /**
   * Returns true if the version is in the unpatched PHP 8.2+ range ({@code 8.2.0 <= v < 8.2.35},
   * {@code 8.3.0 <= v < 8.3.36}, {@code 8.4.0 <= v < 8.4.27}, or {@code 8.5.0 <= v < 8.5.12}).
   */
  @VisibleForTesting
  static boolean isUnpatchedPhpVersion(String versionStr) {
    String[] parts = versionStr.split("\\.");
    if (parts.length < 2) {
      return false;
    }
    try {
      int major = Integer.parseInt(parts[0]);
      int minor = Integer.parseInt(parts[1]);
      int patch = parts.length >= 3 ? Integer.parseInt(parts[2]) : 0;

      if (major != 8) {
        return false;
      }
      switch (minor) {
        case 2:
          return patch < 35;
        case 3:
          return patch < 36;
        case 4:
          return patch < 27;
        case 5:
          return patch < 12;
        default:
          return false;
      }
    } catch (NumberFormatException e) {
      return false;
    }
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

  private Optional<HttpResponse> sendStage2ControlProbe(
      NetworkService networkService, String targetUrl) {
    String boundary = "----TsunamiPhp2ShellControl" + utcClock.instant().toEpochMilli();

    String multipartBody =
        "--"
            + boundary
            + "\r\n"
            + "Content-Disposition: form-data; name=\"file\"; filename=\"tsunami.txt\"\r\n"
            + "Content-Type: application/octet-stream\r\n\r\n"
            + "X\r\n"
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
                          .addHeader("Connection", "close")
                          .addHeader("Cookie", "PHPSESSID=")
                          .build())
                  .setRequestBody(ByteString.copyFromUtf8(multipartBody))
                  .build(),
              networkService));
    } catch (IOException e) {
      logger.atFine().withCause(e).log(
          "HTTP exception while sending PHP2Shell Stage 2 control request to '%s'", targetUrl);
      return Optional.empty();
    }
  }

  private Optional<HttpResponse> sendStage2MarkerProbe(
      NetworkService networkService, String targetUrl) {
    String boundary = "----TsunamiPhp2ShellMarker" + utcClock.instant().toEpochMilli();

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
            + "Content-Type: application/octet-stream\r\n\r\n"
            + "X\r\n"
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
                          .addHeader("Connection", "close")
                          .addHeader("Cookie", "PHPSESSID=")
                          .build())
                  .setRequestBody(ByteString.copyFromUtf8(multipartBody))
                  .build(),
              networkService));
    } catch (IOException e) {
      logger.atFine().withCause(e).log(
          "HTTP exception while sending PHP2Shell Stage 2 marker request to '%s'", targetUrl);
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
