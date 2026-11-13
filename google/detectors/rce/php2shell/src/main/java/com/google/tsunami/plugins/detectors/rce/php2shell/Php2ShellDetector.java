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
import static com.google.common.base.Strings.isNullOrEmpty;
import static com.google.common.base.Strings.nullToEmpty;
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
import com.google.tsunami.common.net.http.HttpStatus;
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
import java.util.LinkedHashSet;
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
 *       supplying an illegal, overlong session ID ({@code tsunami/invalid_sid_<ts>_<padding>},
 *       &gt;250 bytes) in both the {@code Cookie} header and a multipart form field alongside
 *       {@code PHP_SESSION_UPLOAD_PROGRESS} and a 1-byte file part. Because {@code /} and {@code _}
 *       are rejected by {@code mod_files} session ID validation and keys exceeding 250 bytes fail
 *       {@code memcached}/{@code memcache} {@code s_read} ({@code MEMC_RES_KEY_TOO_BIG}), {@code
 *       php_session_initialize()} aborts without creating or modifying any session record.
 *       Unpatched PHP ({@code 5.4.0} through {@code 8.2.34}, {@code 8.3.35}, {@code 8.4.26}, {@code
 *       8.5.11}) ignores the {@code FAILURE} return value in {@code php_session_rfc1867_update()} /
 *       {@code php_session_rfc1867_cleanup()} and calls {@code php_session_flush(1)}, emitting both
 *       the startup initialization failure warning and {@code Failed to write session data ... in
 *       Unknown on line 0}. Patched PHP releases and OS vendor backports either return early
 *       without calling {@code php_session_flush(1)} or disable {@code session.upload_progress}
 *       entirely.
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
      ImmutableList.of("index.php", "", "public/index.php", "web/index.php", "wp-login.php");

  private static final String DEFAULT_PHP_SESSION_NAME = "PHPSESSID";
  // Padded past 250 bytes so healthy memcached/memcache save handlers reject the key in s_read
  // (MEMC_RES_KEY_TOO_BIG) without creating a session entry, while '/' and '_' immediately fail
  // mod_files validation (ps_files_valid_key).
  private static final String INVALID_SID_PADDING = "a".repeat(240);
  private static final int MAX_CRAWLED_PHP_URLS = 3;
  // Cap extensionless front-controller fallbacks (at most 1 route when 0 .php URLs were crawled)
  // and speculative crawl-cookie retries (at most 2 live non-redirect/non-404 endpoints) to keep
  // additional HTTP requests to a strict minimum.
  private static final int MAX_CRAWLED_EXTENSIONLESS_HTML_URLS = 1;
  private static final int MAX_CRAWLED_SESSION_RETRIES = 2;
  private static final int MAX_CUSTOM_SESSION_COOKIES_PER_SOURCE = 3;
  private static final int MAX_EVIDENCE_WARNING_LENGTH = 512;

  private static final String INVALID_SID_SUBSTRING = "is too long or contains illegal characters";
  private static final String FAILED_READ_SUBSTRING = "Failed to read session data";
  private static final String FAILED_PATH_SUBSTRING = "Failed to create session data file path";
  private static final String FAILED_INIT_SUBSTRING = "Failed to initialize storage module";
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
   * when {@code php_session_initialize()} fails in {@code s_read} or {@code s_open} (for example,
   * when {@code memcached}/{@code memcache} rejects the &gt;250-byte session key in {@code s_read},
   * when {@code redis} or custom handlers fail {@code s_open}/{@code s_read} on an unreachable or
   * misconfigured backend, or when {@code mod_files} fails path creation on a {@code
   * session.save_path} directory-depth prefix; note that healthy {@code redis} backends accept
   * arbitrary key characters in {@code s_read} and regenerate invalid IDs via {@code s_create_sid}
   * when {@code session.use_strict_mode = 1}).
   */
  private static final Pattern STARTUP_FAILED_INIT_WARNING_PATTERN =
      Pattern.compile(
          "(?i)Warning(?:<[^>]*>)*:\\s*(?:<[^>]*>)*(?:PHP Request Startup|Unknown)"
              + "[^\\r\\n]{0,1024}?(?:Failed to read session data"
              + "|Failed to create session data file path"
              + "|Failed to initialize storage module)"
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

  // PHP's OnUpdateName in ext/session/session.c permits hyphens in php.ini/.htaccess session.name
  // (e.g., "__Host-PHPSESSID" or "app-session"), and both Cookie parsing and rfc1867
  // MULTIPART_EVENT_FORMDATA match hyphenated PS(session_name) verbatim. Broaden the value class
  // to cover URL-encoded (e.g., %2C), double-quoted, or custom _, ., and ~ session identifiers.
  private static final Pattern CUSTOM_SESSION_COOKIE_PATTERN =
      Pattern.compile(
          "^\\s*([A-Za-z_][A-Za-z0-9_-]{0,63})=\"?([A-Za-z0-9,_%.~-]{8,256})\"?(?:\\s*;|$)");

  // Matched after normalizing '-' to '_' and uppercasing so hyphenated non-PHP CSRF, framework,
  // and load-balancer cookies (e.g., "XSRF-TOKEN", "CSRF-TOKEN", "__cf_bm") never trigger extra
  // retry requests.
  private static final ImmutableSet<String> IGNORED_COOKIE_NAMES =
      ImmutableSet.of(
          "PHPSESSID",
          "JSESSIONID",
          "ASPSESSIONID",
          "CFID",
          "CFTOKEN",
          "AWSALB",
          "AWSALBCORS",
          "AWSALBTG",
          "AWSALBTGCORS",
          "GCLB",
          "__CF_BM",
          "_CFUVID",
          "CF_CLEARANCE",
          "SERVERID",
          "XSRF_TOKEN",
          "CSRF_TOKEN",
          "CSRFTOKEN",
          "_CSRF",
          "LARAVEL_SESSION");

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
    ImmutableSet<String> crawledCustomSessionNames =
        extractCustomSessionNamesFromCrawl(networkService);
    int remainingCrawledSessionRetries = MAX_CRAWLED_SESSION_RETRIES;
    for (String targetUrl : getTargetUrls(networkService)) {
      Optional<HttpResponse> defaultProbeResponse =
          sendMultipartProbe(
              networkService,
              targetUrl,
              DEFAULT_PHP_SESSION_NAME,
              /* includeUploadProgress= */ true);
      if (defaultProbeResponse.isEmpty()) {
        continue;
      }

      Optional<VerificationResult> defaultResult =
          verifyStartupFlushDifferential(
              networkService, targetUrl, DEFAULT_PHP_SESSION_NAME, defaultProbeResponse.get());
      if (defaultResult.isPresent()) {
        return defaultResult;
      }

      HttpStatus status = defaultProbeResponse.get().status();
      // Prefer custom session cookies emitted directly by this endpoint. Only fall back to
      // crawl-discovered cookies on live non-redirect, non-404/405 responses (capped per service)
      // so dead fallback paths, static 405s, and HTTP/front-controller redirects do not multiply
      // probe traffic.
      ImmutableSet<String> endpointCustomSessionNames =
          extractCustomSessionNamesFromHeaders(
              defaultProbeResponse.get().headers().getAll("Set-Cookie"));
      for (String customSessionName : endpointCustomSessionNames) {
        Optional<HttpResponse> customProbeResponse =
            sendMultipartProbe(
                networkService, targetUrl, customSessionName, /* includeUploadProgress= */ true);
        if (customProbeResponse.isEmpty()) {
          continue;
        }
        Optional<VerificationResult> customResult =
            verifyStartupFlushDifferential(
                networkService, targetUrl, customSessionName, customProbeResponse.get());
        if (customResult.isPresent()) {
          return customResult;
        }
      }

      if (!crawledCustomSessionNames.isEmpty()
          && remainingCrawledSessionRetries > 0
          && status != HttpStatus.NOT_FOUND
          && status != HttpStatus.METHOD_NOT_ALLOWED
          && !status.isRedirect()) {
        for (String crawledSessionName : crawledCustomSessionNames) {
          if (endpointCustomSessionNames.contains(crawledSessionName)) {
            continue;
          }
          if (remainingCrawledSessionRetries <= 0) {
            break;
          }
          remainingCrawledSessionRetries--;
          Optional<HttpResponse> customProbeResponse =
              sendMultipartProbe(
                  networkService, targetUrl, crawledSessionName, /* includeUploadProgress= */ true);
          if (customProbeResponse.isEmpty()) {
            continue;
          }
          Optional<VerificationResult> customResult =
              verifyStartupFlushDifferential(
                  networkService, targetUrl, crawledSessionName, customProbeResponse.get());
          if (customResult.isPresent()) {
            return customResult;
          }
        }
      }
    }
    return Optional.empty();
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
    if (!body.contains(FAILED_FLUSH_SUBSTRING)) {
      return Optional.empty();
    }
    boolean hasInitFailureSubstring =
        body.contains(INVALID_SID_SUBSTRING)
            || body.contains(FAILED_READ_SUBSTRING)
            || body.contains(FAILED_PATH_SUBSTRING)
            || body.contains(FAILED_INIT_SUBSTRING);
    if (!hasInitFailureSubstring) {
      return Optional.empty();
    }
    boolean hasStartupInitWarning =
        STARTUP_INVALID_SID_WARNING_PATTERN.matcher(body).find()
            || STARTUP_FAILED_INIT_WARNING_PATTERN.matcher(body).find();
    if (!hasStartupInitWarning) {
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

  private static ImmutableSet<String> extractCustomSessionNamesFromCrawl(
      NetworkService networkService) {
    ImmutableList.Builder<String> setCookies = ImmutableList.builder();
    for (CrawlResult crawlResult :
        networkService.getServiceContext().getWebServiceContext().getCrawlResultsList()) {
      for (HttpHeader header : crawlResult.getResponseHeadersList()) {
        if (Ascii.equalsIgnoreCase(header.getKey(), "Set-Cookie")) {
          setCookies.add(header.getValue());
        }
      }
    }
    return extractCustomSessionNamesFromHeaders(setCookies.build());
  }

  private static ImmutableSet<String> extractCustomSessionNamesFromHeaders(
      Iterable<String> setCookies) {
    LinkedHashSet<String> customNames = new LinkedHashSet<>();
    for (String cookieHeader : setCookies) {
      Matcher matcher = CUSTOM_SESSION_COOKIE_PATTERN.matcher(cookieHeader);
      if (matcher.find()) {
        String cookieName = matcher.group(1);
        String normalizedName = Ascii.toUpperCase(cookieName).replace('-', '_');
        if (!IGNORED_COOKIE_NAMES.contains(normalizedName)) {
          customNames.add(cookieName);
          if (customNames.size() >= MAX_CUSTOM_SESSION_COOKIES_PER_SOURCE) {
            break;
          }
        }
      }
    }
    return ImmutableSet.copyOf(customNames);
  }

  private ImmutableSet<String> getTargetUrls(NetworkService networkService) {
    ImmutableSet.Builder<String> targetUrls = ImmutableSet.builder();
    int addedCrawledPhpUrls = 0;
    for (CrawlResult crawlResult :
        networkService.getServiceContext().getWebServiceContext().getCrawlResultsList()) {
      if (addedCrawledPhpUrls >= MAX_CRAWLED_PHP_URLS) {
        break;
      }
      if (crawlResult.getResponseCode() == HttpStatus.NOT_FOUND.code()) {
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
          addedCrawledPhpUrls++;
          break;
        }
      }
    }
    String rootUrl = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    CANDIDATE_PATHS.forEach(subpath -> targetUrls.add(rootUrl + subpath));

    // Frameworks using front-controller URL rewriting (e.g., RewriteRule / FallbackResource routes
    // such as /users/login) expose no .php URLs during crawling. Because HttpClient disables
    // redirect-following so 301/302 responses do not turn multipart POSTs into bodyless GETs,
    // web-server root redirects or buffered redirect handlers on CANDIDATE_PATHS may never reach
    // PHP. When no .php URL was crawled, append at most 1 same-origin 200 OK HTML extensionless
    // route after CANDIDATE_PATHS so standard servers incur 0 extra requests.
    if (addedCrawledPhpUrls == 0) {
      int addedExtensionlessUrls = 0;
      for (CrawlResult crawlResult :
          networkService.getServiceContext().getWebServiceContext().getCrawlResultsList()) {
        if (addedExtensionlessUrls >= MAX_CRAWLED_EXTENSIONLESS_HTML_URLS) {
          break;
        }
        if (isExtensionlessHtmlCrawlResult(crawlResult, rootUrl)) {
          targetUrls.add(crawlResult.getCrawlTarget().getUrl());
          addedExtensionlessUrls++;
        }
      }
    }
    return targetUrls.build();
  }

  private boolean isExtensionlessHtmlCrawlResult(CrawlResult crawlResult, String rootUrl) {
    if (crawlResult.getResponseCode() != HttpStatus.OK.code() || !hasHtmlContentType(crawlResult)) {
      return false;
    }
    String crawledUrl = crawlResult.getCrawlTarget().getUrl();
    if (!crawledUrl.startsWith(rootUrl)) {
      return false;
    }
    try {
      URI uri = new URI(crawledUrl);
      URI rootUri = new URI(rootUrl);
      String path = uri.getPath();
      if (isNullOrEmpty(path) || path.equals("/") || path.equals(rootUri.getPath())) {
        return false;
      }
      String lastSegment = path.substring(path.lastIndexOf('/') + 1);
      return !lastSegment.contains(".");
    } catch (URISyntaxException e) {
      logger.atFine().withCause(e).log("Failed to parse crawled URL '%s'", crawledUrl);
      return false;
    }
  }

  private static boolean hasHtmlContentType(CrawlResult crawlResult) {
    String contentType = crawlResult.getContentType();
    if (contentType.isEmpty()) {
      for (HttpHeader header : crawlResult.getResponseHeadersList()) {
        if (Ascii.equalsIgnoreCase(header.getKey(), "Content-Type")) {
          contentType = header.getValue();
          break;
        }
      }
    }
    String normalized = Ascii.toLowerCase(contentType.trim());
    return normalized.startsWith("text/html") || normalized.startsWith("application/xhtml+xml");
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
    String invalidSid = "tsunami/invalid_sid_" + timestampMillis + "_" + INVALID_SID_PADDING;

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

    String requestUrl = stripSessionQueryParam(targetUrl, sessionName);
    try {
      return Optional.of(
          httpClient.send(
              post(requestUrl)
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
          "HTTP exception while sending PHP2Shell verification request to '%s'", requestUrl);
      return Optional.empty();
    }
  }

  private static String stripSessionQueryParam(String targetUrl, String sessionName) {
    try {
      URI uri = new URI(targetUrl);
      String rawQuery = uri.getRawQuery();
      if (isNullOrEmpty(rawQuery)) {
        return targetUrl;
      }
      StringBuilder filteredQuery = new StringBuilder();
      boolean removed = false;
      for (String param : rawQuery.split("&", -1)) {
        int eqIdx = param.indexOf('=');
        String key = eqIdx >= 0 ? param.substring(0, eqIdx) : param;
        if (Ascii.equalsIgnoreCase(key, sessionName)) {
          removed = true;
          continue;
        }
        if (filteredQuery.length() > 0) {
          filteredQuery.append('&');
        }
        filteredQuery.append(param);
      }
      if (!removed) {
        return targetUrl;
      }
      return uri.getScheme()
          + "://"
          + uri.getRawAuthority()
          + nullToEmpty(uri.getRawPath())
          + (filteredQuery.length() > 0 ? "?" + filteredQuery : "")
          + (uri.getRawFragment() != null ? "#" + uri.getRawFragment() : "");
    } catch (URISyntaxException e) {
      return targetUrl;
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
