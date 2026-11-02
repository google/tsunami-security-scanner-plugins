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
import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.CrawlResult;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.HttpHeader;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TextData;
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
 * <p>Verification uses a zero-side-effect behavioral differential in {@code ext/session/session.c}
 * during {@code PHP Request Startup}:
 *
 * <ol>
 *   <li><b>Probe (with {@code PHP_SESSION_UPLOAD_PROGRESS}):</b> Sends a minimal multipart POST
 *       supplying an illegal session ID ({@code tsunami/invalid_sid_<ts>}) in both the {@code
 *       Cookie} header and a multipart form field alongside {@code PHP_SESSION_UPLOAD_PROGRESS} and
 *       a 1-byte file part. Because {@code /} and {@code _} are rejected by session ID validation,
 *       {@code php_session_initialize()} aborts without creating or modifying any session record on
 *       disk. Unpatched PHP ({@code 5.4.0} through {@code 8.2.34}, {@code 8.3.35}, {@code 8.4.26},
 *       {@code 8.5.11}) ignores the {@code FAILURE} return value in {@code
 *       php_session_rfc1867_update()} / {@code php_session_rfc1867_cleanup()} and calls {@code
 *       php_session_flush(1)}, emitting both the startup invalid-SID warning and {@code Failed to
 *       write session data ... in Unknown on line 0}. Patched PHP releases and OS vendor backports
 *       either return early without calling {@code php_session_flush(1)} or disable {@code
 *       session.upload_progress} entirely.
 *   <li><b>Causal-Ablation Control (without {@code PHP_SESSION_UPLOAD_PROGRESS}):</b> Whenever a
 *       response matches the unpatched startup flush warning signature, sends an identical control
 *       request omitting only the {@code PHP_SESSION_UPLOAD_PROGRESS} field and verifies that the
 *       startup flush warning disappears, ruling out static pages or request-reflection endpoints.
 * </ol>
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
      "PHP versions 5.4 through 8.5.11 (prior to 8.2.35, 8.3.36, 8.4.27, and 8.5.12) are"
          + " vulnerable to unauthenticated Remote Code Execution caused by out-of-memory"
          + " error-handling bailout corruption during input variable registration"
          + " (CVE-2026-109618) combined with uncleaned cross-request global state in"
          + " session.upload_progress (CVE-2026-109619). This detector non-destructively verifies"
          + " that the PHP session.upload_progress RFC1867 startup handler is reachable and"
          + " executes the unpatched session-flush code path when session initialization fails.";

  @VisibleForTesting
  static final String RECOMMENDATION =
      "Upgrade PHP to a patched release (8.5.12+, 8.4.27+, 8.3.36+, 8.2.35+, or the corresponding"
          + " OS vendor security update). As a temporary mitigation for the unauthenticated"
          + " session.upload_progress exploitation vector (CVE-2026-109619), set"
          + " 'session.upload_progress.enabled = 0' in php.ini; upgrading PHP is still required"
          + " to fully remediate CVE-2026-109618.";

  @VisibleForTesting
  static final String ADDITIONAL_DETAIL_DESCRIPTION =
      "Verified unpatched PHP session.upload_progress startup session flush.";

  @VisibleForTesting
  static final ImmutableList<String> CANDIDATE_PATHS =
      ImmutableList.of("", "index.php", "public/index.php", "web/index.php", "wp-login.php");

  private static final String DEFAULT_PHP_SESSION_NAME = "PHPSESSID";
  private static final int MAX_CRAWLED_PHP_URLS = 3;
  private static final int MAX_EVIDENCE_WARNING_LENGTH = 512;

  private static final String INVALID_SID_SUBSTRING = "is too long or contains illegal characters";
  private static final String FAILED_FLUSH_SUBSTRING = "Failed to write session data";

  /**
   * Matches the PHP Request Startup (PHP 8.0+) or Unknown (PHP 5.4-7.4) warning emitted on line 0
   * when {@code mod_files} rejects our illegal session ID during {@code php_session_initialize()}.
   */
  private static final Pattern STARTUP_INVALID_SID_WARNING_PATTERN =
      Pattern.compile(
          "(?i)Warning(?:<[^>]*>)*:\\s*(?:<[^>]*>)*(?:PHP Request Startup|Unknown)"
              + "[^\\r\\n]{0,1024}?is too long or contains illegal characters"
              + "[^\\r\\n]{0,1024}?in (?:<[^>]*>)*Unknown(?:<[^>]*>)*"
              + " on line (?:<[^>]*>)*0(?:<[^>]*>)*");

  /**
   * Matches the PHP Request Startup (PHP 8.0+) or Unknown (PHP 5.4-7.4) warning emitted on line 0
   * when unpatched {@code php_session_rfc1867_update()} / {@code php_session_rfc1867_cleanup()}
   * ignores {@code php_session_initialize() == FAILURE} and calls {@code php_session_flush(1)}.
   */
  private static final Pattern STARTUP_FAILED_FLUSH_WARNING_PATTERN =
      Pattern.compile(
          "(?i)Warning(?:<[^>]*>)*:\\s*(?:<[^>]*>)*(?:PHP Request Startup|Unknown)"
              + "[^\\r\\n]{0,1024}?Failed to write session data"
              + "[^\\r\\n]{0,1024}?in (?:<[^>]*>)*Unknown(?:<[^>]*>)*"
              + " on line (?:<[^>]*>)*0(?:<[^>]*>)*");

  private static final Pattern HTML_TAG_PATTERN = Pattern.compile("<[^>]*>");

  private static final Pattern CUSTOM_SESSION_COOKIE_PATTERN =
      Pattern.compile("^\\s*([A-Za-z_][A-Za-z0-9_]{0,63})=([A-Za-z0-9,-]{22,256})(?:\\s*;|$)");

  private static final ImmutableSet<String> IGNORED_COOKIE_NAMES =
      ImmutableSet.of(
          "PHPSESSID",
          "JSESSIONID",
          "ASPSESSIONID",
          "CFID",
          "CFTOKEN",
          "AWSALB",
          "AWSALBCORS",
          "GCLB",
          "__CF_BM",
          "_CFUVID",
          "SERVERID",
          "XSRF_TOKEN",
          "CSRF_TOKEN",
          "CSRFTOKEN");

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
                .map(this::probeService)
                .flatMap(Optional::stream)
                .map(result -> buildDetectionReport(targetInfo, result))
                .collect(toImmutableList()))
        .build();
  }

  private Optional<VerificationResult> probeService(NetworkService networkService) {
    Optional<String> crawledCustomSessionName = extractCustomSessionNameFromCrawl(networkService);
    for (String targetUrl : getTargetUrls(networkService)) {
      Optional<VerificationResult> result =
          probeTargetUrl(networkService, targetUrl, crawledCustomSessionName);
      if (result.isPresent()) {
        return result;
      }
    }
    return Optional.empty();
  }

  private Optional<VerificationResult> probeTargetUrl(
      NetworkService networkService, String targetUrl, Optional<String> crawledCustomSessionName) {
    Optional<HttpResponse> defaultProbeResponse =
        sendMultipartProbe(
            networkService, targetUrl, DEFAULT_PHP_SESSION_NAME, /* includeUploadProgress= */ true);
    if (defaultProbeResponse.isEmpty()) {
      return Optional.empty();
    }

    Optional<VerificationResult> defaultResult =
        verifyStartupFlushDifferential(
            networkService, targetUrl, DEFAULT_PHP_SESSION_NAME, defaultProbeResponse.get());
    if (defaultResult.isPresent()) {
      return defaultResult;
    }

    Optional<String> customSessionName =
        extractCustomSessionNameFromHeaders(
                defaultProbeResponse.get().headers().getAll("Set-Cookie"))
            .or(() -> crawledCustomSessionName);
    if (customSessionName.isEmpty()) {
      return Optional.empty();
    }

    Optional<HttpResponse> customProbeResponse =
        sendMultipartProbe(
            networkService, targetUrl, customSessionName.get(), /* includeUploadProgress= */ true);
    if (customProbeResponse.isEmpty()) {
      return Optional.empty();
    }
    return verifyStartupFlushDifferential(
        networkService, targetUrl, customSessionName.get(), customProbeResponse.get());
  }

  private Optional<VerificationResult> verifyStartupFlushDifferential(
      NetworkService networkService,
      String targetUrl,
      String sessionName,
      HttpResponse probeResponse) {
    String probeBody = probeResponse.bodyString().orElse("");
    Optional<String> matchedFlushWarning = extractMatchedStartupFlushWarning(probeBody);
    if (matchedFlushWarning.isEmpty()) {
      return Optional.empty();
    }

    Optional<HttpResponse> controlResponse =
        sendMultipartProbe(
            networkService, targetUrl, sessionName, /* includeUploadProgress= */ false);
    if (controlResponse.isEmpty()) {
      return Optional.empty();
    }

    String controlBody = controlResponse.get().bodyString().orElse("");
    if (extractMatchedStartupFlushWarning(controlBody).isPresent()) {
      logger.atFine().log(
          "Ignoring non-differential startup warning text on '%s' (present without"
              + " PHP_SESSION_UPLOAD_PROGRESS).",
          targetUrl);
      return Optional.empty();
    }

    logger.atInfo().log(
        "PHP2Shell verified unpatched session.upload_progress startup session flush on '%s'"
            + " (session parameter '%s').",
        targetUrl, sessionName);
    return Optional.of(
        new VerificationResult(networkService, targetUrl, sessionName, matchedFlushWarning.get()));
  }

  private static Optional<String> extractMatchedStartupFlushWarning(String body) {
    if (!body.contains(INVALID_SID_SUBSTRING) || !body.contains(FAILED_FLUSH_SUBSTRING)) {
      return Optional.empty();
    }
    if (!STARTUP_INVALID_SID_WARNING_PATTERN.matcher(body).find()) {
      return Optional.empty();
    }
    Matcher flushMatcher = STARTUP_FAILED_FLUSH_WARNING_PATTERN.matcher(body);
    if (!flushMatcher.find()) {
      return Optional.empty();
    }
    String sanitizedWarning =
        HTML_TAG_PATTERN
            .matcher(flushMatcher.group())
            .replaceAll("")
            .replace("&quot;", "\"")
            .trim();
    if (sanitizedWarning.length() > MAX_EVIDENCE_WARNING_LENGTH) {
      sanitizedWarning = sanitizedWarning.substring(0, MAX_EVIDENCE_WARNING_LENGTH);
    }
    return Optional.of(sanitizedWarning);
  }

  private static Optional<String> extractCustomSessionNameFromCrawl(NetworkService networkService) {
    for (CrawlResult crawlResult :
        networkService.getServiceContext().getWebServiceContext().getCrawlResultsList()) {
      ImmutableList.Builder<String> setCookies = ImmutableList.builder();
      for (HttpHeader header : crawlResult.getResponseHeadersList()) {
        if (Ascii.equalsIgnoreCase(header.getKey(), "Set-Cookie")) {
          setCookies.add(header.getValue());
        }
      }
      Optional<String> candidate = extractCustomSessionNameFromHeaders(setCookies.build());
      if (candidate.isPresent()) {
        return candidate;
      }
    }
    return Optional.empty();
  }

  private static Optional<String> extractCustomSessionNameFromHeaders(Iterable<String> setCookies) {
    for (String cookieHeader : setCookies) {
      Matcher matcher = CUSTOM_SESSION_COOKIE_PATTERN.matcher(cookieHeader);
      if (matcher.find()) {
        String cookieName = matcher.group(1);
        if (!IGNORED_COOKIE_NAMES.contains(Ascii.toUpperCase(cookieName))) {
          return Optional.of(cookieName);
        }
      }
    }
    return Optional.empty();
  }

  private ImmutableSet<String> getTargetUrls(NetworkService networkService) {
    ImmutableSet.Builder<String> targetUrls = ImmutableSet.builder();
    int addedCrawledPhpUrls = 0;
    for (CrawlResult crawlResult :
        networkService.getServiceContext().getWebServiceContext().getCrawlResultsList()) {
      if (addedCrawledPhpUrls >= MAX_CRAWLED_PHP_URLS) {
        break;
      }
      if (crawlResult.getResponseCode() == 404) {
        continue;
      }
      String crawledUrl = crawlResult.getCrawlTarget().getUrl();
      if (isPhpUrl(crawledUrl)) {
        targetUrls.add(crawledUrl);
        addedCrawledPhpUrls++;
      }
    }
    if (addedCrawledPhpUrls == 0) {
      for (CrawlResult crawlResult :
          networkService.getServiceContext().getWebServiceContext().getCrawlResultsList()) {
        String crawledUrl = crawlResult.getCrawlTarget().getUrl();
        if (isPhpUrl(crawledUrl)) {
          targetUrls.add(crawledUrl);
          break;
        }
      }
    }
    String rootUrl = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    CANDIDATE_PATHS.forEach(subpath -> targetUrls.add(rootUrl + subpath));
    return targetUrls.build();
  }

  private boolean isPhpUrl(String candidateUrl) {
    try {
      URI uri = new URI(candidateUrl);
      return uri.getPath() != null && Ascii.toLowerCase(uri.getPath()).endsWith(".php");
    } catch (URISyntaxException e) {
      logger.atFine().withCause(e).log("Failed to parse crawled URL '%s'", candidateUrl);
      return false;
    }
  }

  private Optional<HttpResponse> sendMultipartProbe(
      NetworkService networkService,
      String targetUrl,
      String sessionName,
      boolean includeUploadProgress) {
    long timestampMillis = utcClock.instant().toEpochMilli();
    String boundary = "----TsunamiPhp2ShellBoundary" + timestampMillis;
    String invalidSid = "tsunami/invalid_sid_" + timestampMillis;

    StringBuilder multipartBody = new StringBuilder();
    multipartBody
        .append("--")
        .append(boundary)
        .append("\r\n")
        .append("Content-Disposition: form-data; name=\"")
        .append(sessionName)
        .append("\"\r\n\r\n")
        .append(invalidSid)
        .append("\r\n");
    if (includeUploadProgress) {
      multipartBody
          .append("--")
          .append(boundary)
          .append("\r\n")
          .append("Content-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n")
          .append("tsunami\r\n");
    }
    multipartBody
        .append("--")
        .append(boundary)
        .append("\r\n")
        .append("Content-Disposition: form-data; name=\"file\"; filename=\"tsunami.txt\"\r\n")
        .append("Content-Type: text/plain\r\n\r\n")
        .append("X\r\n")
        .append("--")
        .append(boundary)
        .append("--\r\n");

    try {
      return Optional.of(
          httpClient.send(
              post(targetUrl)
                  .setHeaders(
                      HttpHeaders.builder()
                          .addHeader("Content-Type", "multipart/form-data; boundary=" + boundary)
                          .addHeader("Connection", "close")
                          .addHeader("Cookie", sessionName + "=" + invalidSid)
                          .build())
                  .setRequestBody(ByteString.copyFromUtf8(multipartBody.toString()))
                  .build(),
              networkService));
    } catch (IOException e) {
      logger.atFine().withCause(e).log(
          "HTTP exception while sending PHP2Shell verification request to '%s'", targetUrl);
      return Optional.empty();
    }
  }

  private DetectionReport buildDetectionReport(TargetInfo targetInfo, VerificationResult result) {
    String detailText =
        String.format(
            "Vulnerable endpoint: %s\nSession parameter: %s\nMatched startup warning: %s",
            result.targetUrl, result.sessionName, result.matchedWarning);
    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(result.networkService)
        .setDetectionTimestamp(Timestamps.fromMillis(utcClock.instant().toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            getAdvisories().get(0).toBuilder()
                .addAdditionalDetails(
                    AdditionalDetail.newBuilder()
                        .setDescription(ADDITIONAL_DETAIL_DESCRIPTION)
                        .setTextData(TextData.newBuilder().setText(detailText))))
        .build();
  }

  private static final class VerificationResult {
    final NetworkService networkService;
    final String targetUrl;
    final String sessionName;
    final String matchedWarning;

    VerificationResult(
        NetworkService networkService,
        String targetUrl,
        String sessionName,
        String matchedWarning) {
      this.networkService = networkService;
      this.targetUrl = targetUrl;
      this.sessionName = sessionName;
      this.matchedWarning = matchedWarning;
    }
  }
}
