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
package com.google.tsunami.plugins.detectors.rce.cve2026111497outbound;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.UrlUtils.removeTrailingSlashes;
import static com.google.tsunami.common.net.http.HttpRequest.get;
import static com.google.tsunami.common.net.http.HttpRequest.post;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Ascii;
import com.google.common.base.CharMatcher;
import com.google.common.base.Splitter;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Sets;
import com.google.common.flogger.GoogleLogger;
import com.google.common.xml.XmlEscapers;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpRequest;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.TcsClient;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.ForWebService;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.plugin.payload.PayloadSecretGenerator;
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
import java.io.InterruptedIOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.inject.Inject;

/**
 * A {@link VulnDetector} that detects the Google Brotli decoder out-of-bounds write RCE
 * vulnerability (CVE-2026-111497) exposed via outbound HTTP fetches using the Tsunami Callback
 * Server (TCS).
 *
 * <p>Unlike servers that decompress incoming {@code Content-Encoding: br} request bodies (covered
 * by {@code Cve2026111497Detector}), this detector covers web applications whose unauthenticated
 * endpoints fetch an attacker-supplied URL and automatically decompress {@code Content-Encoding:
 * br} HTTP responses through an unpatched {@code libbrotlidec} (1.0.3 through 1.2.0):
 *
 * <ul>
 *   <li><b>Multi-CMS XML-RPC {@code pingback.ping}</b> (WordPress, Drupal, b2evolution,
 *       Serendipity, DokuWiki, Movable Type, TikiWiki): Supports both retrying HTTP transports
 *       (such as WordPress {@code WpOrg\Requests\Transport\Curl}, which retries a second {@code
 *       GET} with {@code Accept-Encoding: none} attributed to {@code no_br_cbid} whenever {@code
 *       libbrotlidec} rejects a stream) and non-retrying {@code libcurl}/Guzzle clients (verified
 *       via strict unmasked XML-RPC fault-code differentials between valid decompression and
 *       decompression failure).
 *   <li><b>Next.js Image Optimizer ({@code /_next/image})</b>: When remote image URLs are allowed,
 *       Next.js fetches {@code url} via Node.js {@code fetch()} ({@code undici}), which advertises
 *       {@code Accept-Encoding: gzip, deflate, br} and decompresses {@code Content-Encoding: br}
 *       streams via {@code node:zlib} ({@code libbrotlidec}) before validating the image {@code
 *       Content-Type} (returning {@code 400 Bad Request} when Brotli decompression succeeds vs.
 *       {@code 500}/{@code 502} when Brotli decompression fails).
 * </ul>
 */
@ForWebService
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "Cve2026111497OutboundDetector",
    version = "0.1",
    description =
        "This detector checks for the Google Brotli decoder out-of-bounds write RCE vulnerability"
            + " (CVE-2026-111497) exposed via outbound HTTP fetches such as CMS XML-RPC"
            + " pingback.ping and Next.js /_next/image.",
    author = "Tsunami Security Scanner",
    bootstrapModule = Cve2026111497OutboundDetectorBootstrapModule.class)
public final class Cve2026111497OutboundDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  @VisibleForTesting static final String VULNERABILITY_REPORT_PUBLISHER = "GOOGLE";
  @VisibleForTesting static final String VULNERABILITY_REPORT_ID = "CVE-2026-111497-OUTBOUND";
  @VisibleForTesting static final String RELATED_CVE_ID = "CVE-2026-111497";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_TITLE =
      "Outbound HTTP Client Google Brotli Decoder RCE (CVE-2026-111497)";

  @VisibleForTesting
  static final String VULN_DESCRIPTION =
      "The target web application exposes an unauthenticated outbound HTTP fetch endpoint (such as"
          + " CMS XML-RPC 'pingback.ping' in WordPress, Drupal, b2evolution, Serendipity, DokuWiki,"
          + " Movable Type, or TikiWiki, or Next.js '/_next/image') backed by a Google Brotli"
          + " decoder library (libbrotlidec 1.0.3 through 1.2.0) vulnerable to CVE-2026-111497."
          + " When the endpoint fetches a remote URL, its HTTP client (e.g., libcurl/Guzzle with"
          + " CURLOPT_ENCODING enabled or Node.js undici fetch) advertises 'br' in Accept-Encoding"
          + " and streams 'Content-Encoding: br' HTTP responses directly into"
          + " BrotliDecoderDecompressStream. In unpatched Brotli decoders, a compressed metablock"
          + " with NBLTYPESD == 1 and more than 16,777,216 explicit-distance commands causes"
          + " BrotliDecoderDecompressStream to copy unread input bytes past the 8-byte s->buffer"
          + " union into adjacent BrotliDecoderState fields, enabling unauthenticated Remote Code"
          + " Execution (RCE) inside the server worker.";

  @VisibleForTesting
  static final String RECOMMENDATION =
      "Upgrade the system Brotli library (libbrotli1) to version 1.2.1 or a patched distribution"
          + " package (such as Debian libbrotli1 >= 1.1.0-2+deb13u1) and restart PHP-FPM/Apache,"
          + " or upgrade Node.js to 22.23.4+, 24.15.0+, or 25.8.0+ for Next.js deployments. As"
          + " defense-in-depth, block unauthenticated XML-RPC 'pingback.ping' endpoints at the web"
          + " server or WAF, and restrict Next.js 'images.remotePatterns' / 'images.domains' to"
          + " trusted origins.";

  @VisibleForTesting static final String PRESET_BROTLI_VALID = "brotli_valid";
  @VisibleForTesting static final String PRESET_BROTLI_INVALID = "brotli_invalid";
  @VisibleForTesting static final String PRESET_BROTLI_CVE_2026_111497 = "brotli_cve_2026_111497";

  @VisibleForTesting
  static final String DETECTION_EVIDENCE_DESCRIPTION = "CVE-2026-111497 detection evidence";

  private static final int MAX_CRAWLED_CMS_ROOTS = 3;
  private static final int MAX_XPINGBACK_URLS = 3;
  private static final int MAX_CANDIDATE_POSTS = 4;
  private static final int MAX_CONSECUTIVE_TIMEOUTS = 2;
  private static final int SECRET_BYTES = 16;
  private static final int MAX_SERVER_HEADER_LENGTH = 64;

  // XML-RPC fault codes returned by pingback.ping implementations:
  // - By default since WordPress 3.6.1, core registers the 'xmlrpc_pingback_error' filter
  //   (wp-includes/default-filters.php), which normalizes all non-48 pingback fault codes to 0.
  // - Unmasked WordPress, Drupal, b2evolution, Serendipity, DokuWiki Linkback, Movable Type, and
  //   TikiWiki return standard Pingback 1.0 post-fetch fault codes after the source URL fetch
  //   completes: 16 (source URI could not be fetched / empty body / decompression error),
  //   17 (source document does not contain a link to target post), or 32 (target URI invalid or
  //   HTML <title> missing).
  private static final int FAULT_DEFAULT_MASKED = 0;
  private static final int FAULT_SOURCE_NOT_FOUND = 16;
  private static final int FAULT_TARGET_LINK_MISSING = 17;
  private static final int FAULT_TITLE_MISSING = 32;

  private static final CharMatcher QUERY_OR_FRAGMENT_MATCHER = CharMatcher.anyOf("?#");
  private static final CharMatcher NON_PRINTABLE_ASCII_MATCHER =
      CharMatcher.inRange(' ', '~').negate();

  private static final String DOKUWIKI_LINKBACK_PINGBACK_PREFIX =
      "/lib/plugins/linkback/exe/pingback.php/";

  private static final ImmutableList<String> CMS_SUBPATH_MARKERS =
      ImmutableList.of(
          "/wp-content/",
          "/wp-includes/",
          "/wp-admin/",
          "/wp-json/",
          "/wp-login.php",
          // Longer framework-internal XML-RPC suffixes must precede "/xmlrpc.php" so indexOf
          // strips the enclosing framework directory ("/xmlsrv/xmlrpc.php") rather than matching
          // only the trailing "/xmlrpc.php" suffix.
          "/xmlsrv/xmlrpc.php",
          "/xmlrpc.php",
          "/sites/default/",
          "/sites/all/",
          // "/core/modules/" must precede "/modules/" so Drupal 8-11 core module assets resolve to
          // the Drupal root rather than ".../core/".
          "/core/misc/",
          "/core/modules/",
          "/core/themes/",
          "/core/assets/",
          "/modules/",
          "/services/xmlrpc",
          "/comment.php",
          "/serendipity.css",
          "/serendipity_admin.php",
          "/mt-static/",
          "/mt-xmlrpc.cgi",
          "/tiki-index.php",
          "/tiki-xmlrpc.php");

  private static final ImmutableList<String> XPINGBACK_ROOT_MARKERS =
      ImmutableList.<String>builder().add("/lib/plugins/").addAll(CMS_SUBPATH_MARKERS).build();

  /**
   * Candidate XML-RPC / Pingback relative paths probed under each discovered CMS root to cover
   * WordPress, Drupal, b2evolution, Serendipity, Movable Type, and TikiWiki. DokuWiki's Linkback
   * plugin ({@code lib/plugins/linkback/exe/pingback.php/{id}}) and custom pingback routes are
   * discovered from same-origin {@code X-Pingback} response headers on crawled pages.
   */
  private static final ImmutableList<String> CMS_ROOT_XMLRPC_PATHS =
      ImmutableList.of(
          // Standard XML-RPC endpoint for WordPress, Drupal (xmlrpc/pingback module), and Xoops.
          "xmlrpc.php",
          // Drupal Services module XML-RPC endpoint when clean URLs are enabled.
          "services/xmlrpc",
          // b2evolution XML-RPC pingback server endpoint.
          "xmlsrv/xmlrpc.php",
          // Serendipity (s9y) core XML-RPC pingback receiver.
          "comment.php?type=pingback",
          // Movable Type CGI XML-RPC pingback endpoint.
          "mt-xmlrpc.cgi",
          // TikiWiki CMS Groupware XML-RPC endpoint.
          "tiki-xmlrpc.php");

  /**
   * Common un-crawled CMS subdirectory installation paths for WordPress and Drupal, probed only
   * under the base web application root ({@code rootUrl}) rather than nested under crawled CMS
   * subpaths.
   */
  private static final ImmutableList<String> ROOT_ONLY_SUBDIR_XMLRPC_PATHS =
      ImmutableList.of(
          "wordpress/xmlrpc.php",
          "wp/xmlrpc.php",
          "blog/xmlrpc.php",
          "drupal/xmlrpc.php",
          "cms/xmlrpc.php");

  private static final ImmutableSet<String> STATIC_ASSET_EXTENSIONS =
      ImmutableSet.of(
          ".css", ".js", ".mjs", ".map", ".ico", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp",
          ".woff", ".woff2", ".ttf", ".eot", ".otf", ".pdf", ".zip", ".xml", ".json", ".txt");

  private static final ImmutableList<String> NON_POST_PATH_MARKERS =
      ImmutableList.of(
          "/wp-admin",
          "/wp-login.php",
          "/wp-json",
          "/wp-content",
          "/wp-includes",
          "xmlrpc",
          "/comment.php",
          "/feed.php",
          "/rss.php",
          "/feed/",
          "/user/login",
          "/user/register",
          "/user/password",
          "/tiki-login",
          "/tiki-admin",
          "/lib/exe/",
          "/lib/plugins/",
          "/admin/",
          "/_next/");

  private static final ImmutableSet<String> NON_POST_ACTION_VALUES =
      ImmutableSet.of(
          "login",
          "logout",
          "register",
          "lostpassword",
          "retrievepassword",
          "resetpass",
          "admin",
          "edit");

  private static final ImmutableSet<String> FEED_FORMAT_VALUES =
      ImmutableSet.of("feed", "rss", "rss2", "atom", "rdf");

  private static final ImmutableSet<HttpStatus> NEXT_IMAGE_DECOMPRESSION_FAILURE_STATUSES =
      Sets.immutableEnumSet(HttpStatus.INTERNAL_SERVER_ERROR, HttpStatus.BAD_GATEWAY);

  private static final Pattern HOME_PAGE_LINK_PATTERN =
      Pattern.compile("<homePageLink>\\s*([^<\\s]+)\\s*</homePageLink>", Pattern.CASE_INSENSITIVE);

  private static final Pattern RSS_ITEM_PATTERN =
      Pattern.compile("<item>(.*?)</item>", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);

  private static final Pattern RSS_LINK_PATTERN =
      Pattern.compile("<link>\\s*([^<\\s]+)\\s*</link>", Pattern.CASE_INSENSITIVE);

  private static final Pattern XMLRPC_FAULT_CODE_PATTERN =
      Pattern.compile(
          "<name>\\s*faultCode\\s*</name>\\s*<value>\\s*<int>\\s*(-?\\d+)\\s*</int>\\s*</value>",
          Pattern.CASE_INSENSITIVE | Pattern.DOTALL);

  private static final ByteString LIST_METHODS_BODY =
      ByteString.copyFromUtf8(
          "<?xml version=\"1.0\"?><methodCall><methodName>system.listMethods</methodName>"
              + "<params></params></methodCall>");

  private final Clock utcClock;
  private final HttpClient httpClient;
  private final TcsClient tcsClient;
  private final PayloadSecretGenerator secretGenerator;

  @Inject
  Cve2026111497OutboundDetector(
      @UtcClock Clock utcClock,
      HttpClient httpClient,
      TcsClient tcsClient,
      PayloadSecretGenerator secretGenerator) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(false).build();
    this.tcsClient = checkNotNull(tcsClient);
    this.secretGenerator = checkNotNull(secretGenerator);
  }

  @Override
  public ImmutableList<Vulnerability> getAdvisories() {
    return ImmutableList.of(
        Vulnerability.newBuilder()
            .setMainId(
                VulnerabilityId.newBuilder()
                    .setPublisher(VULNERABILITY_REPORT_PUBLISHER)
                    .setValue(VULNERABILITY_REPORT_ID))
            .addRelatedId(VulnerabilityId.newBuilder().setPublisher("CVE").setValue(RELATED_CVE_ID))
            .setSeverity(Severity.CRITICAL)
            .setTitle(VULNERABILITY_REPORT_TITLE)
            .setDescription(VULN_DESCRIPTION)
            .setRecommendation(RECOMMENDATION)
            .build());
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Cve2026111497OutboundDetector starts detecting.");

    if (!tcsClient.isCallbackServerEnabled()) {
      logger.atWarning().log(
          "Tsunami callback server is not enabled; skipping Cve2026111497OutboundDetector.");
      return DetectionReportList.getDefaultInstance();
    }

    ImmutableList<NetworkService> webServices =
        matchedServices.stream()
            .filter(NetworkServiceUtils::isWebService)
            .collect(toImmutableList());
    if (webServices.isEmpty()) {
      return DetectionReportList.getDefaultInstance();
    }

    DetectionReportList.Builder reports = DetectionReportList.newBuilder();
    for (NetworkService service : webServices) {
      if (Thread.currentThread().isInterrupted()) {
        break;
      }
      checkService(service)
          .ifPresent(
              evidence ->
                  reports.addDetectionReports(buildDetectionReport(targetInfo, service, evidence)));
    }
    return reports.build();
  }

  private Optional<AdditionalDetail> checkService(NetworkService service) {
    ImmutableList<XmlRpcTarget> xmlRpcTargets = discoverXmlRpcTargets(service);
    if (Thread.currentThread().isInterrupted()) {
      return Optional.empty();
    }
    Optional<AdditionalDetail> xmlRpcEvidence = findVulnerableXmlRpcTarget(service, xmlRpcTargets);
    if (xmlRpcEvidence.isPresent() || Thread.currentThread().isInterrupted()) {
      return xmlRpcEvidence;
    }
    return findVulnerableNextJsImageTarget(service);
  }

  private Optional<AdditionalDetail> findVulnerableXmlRpcTarget(
      NetworkService service, ImmutableList<XmlRpcTarget> xmlRpcTargets) {
    PhaseTimeoutTracker pingbackTimeouts =
        new PhaseTimeoutTracker("XML-RPC pingback verification", MAX_CONSECUTIVE_TIMEOUTS);
    for (XmlRpcTarget xmlRpcTarget : xmlRpcTargets) {
      if (Thread.currentThread().isInterrupted() || pingbackTimeouts.isExhausted()) {
        break;
      }
      for (String postUrl : xmlRpcTarget.candidatePostUrls()) {
        if (Thread.currentThread().isInterrupted() || pingbackTimeouts.isExhausted()) {
          break;
        }
        ProbeResult result =
            probePostVulnerability(service, xmlRpcTarget.xmlRpcUrl(), postUrl, pingbackTimeouts);
        if (result.outcome() == StepOutcome.VULNERABLE && result.evidence().isPresent()) {
          logger.atInfo().log(
              "Confirmed CVE-2026-111497 via XML-RPC pingback on '%s' (post '%s')",
              xmlRpcTarget.xmlRpcUrl(), postUrl);
          return result.evidence();
        }
        if (result.outcome() == StepOutcome.PATCHED_OR_NON_BROTLI) {
          // Callback reached TCS from this XML-RPC instance and proved it is patched or does not
          // decompress Brotli; no need to re-test additional posts on the same instance.
          break;
        }
      }
    }
    return Optional.empty();
  }

  private ProbeResult probePostVulnerability(
      NetworkService service,
      String xmlRpcUrl,
      String targetPostUrl,
      PhaseTimeoutTracker timeoutTracker) {
    // Step 1: Valid RFC 7932 Brotli control (57 bytes). Expect 'br' interaction and no fallback.
    CallbackProbeStep valid1 = createProbeStep(PRESET_BROTLI_VALID);
    Optional<PingbackCallResult> v1Resp =
        sendPingbackCall(service, xmlRpcUrl, valid1.sourceUri(), targetPostUrl, timeoutTracker);
    if (v1Resp.isEmpty()) {
      return ProbeResult.ofOutcome(StepOutcome.NO_CALLBACK_REACHED);
    }
    boolean v1SawBr = tcsClient.hasOobLog(valid1.brSecret());
    boolean v1SawNoBr = tcsClient.hasOobLog(valid1.noBrSecret());
    if (!v1SawBr && !v1SawNoBr) {
      return ProbeResult.ofOutcome(StepOutcome.NO_CALLBACK_REACHED);
    }
    if (!v1SawBr || v1SawNoBr) {
      return ProbeResult.ofOutcome(StepOutcome.PATCHED_OR_NON_BROTLI);
    }

    // Step 2: Invalid Brotli control (57 bytes). Expect 'br' interaction, and check whether the
    // outbound HTTP client also retries with Accept-Encoding: none (as in WordPress WpOrg\Requests)
    // or aborts directly without retrying (as in Drupal Guzzle or raw libcurl).
    CallbackProbeStep invalid1 = createProbeStep(PRESET_BROTLI_INVALID);
    Optional<PingbackCallResult> i1Resp =
        sendPingbackCall(service, xmlRpcUrl, invalid1.sourceUri(), targetPostUrl, timeoutTracker);
    if (i1Resp.isEmpty() || !tcsClient.hasOobLog(invalid1.brSecret())) {
      return ProbeResult.ofOutcome(StepOutcome.PATCHED_OR_NON_BROTLI);
    }
    boolean clientRetriesWithoutBr = tcsClient.hasOobLog(invalid1.noBrSecret());

    Optional<Integer> validFault = v1Resp.get().faultCode();
    Optional<Integer> invalidFault = i1Resp.get().faultCode();
    if (validFault.isEmpty()
        || invalidFault.isEmpty()
        || !isAllowedControlFaultPair(
            validFault.get(), invalidFault.get(), clientRetriesWithoutBr)) {
      return ProbeResult.ofOutcome(StepOutcome.PATCHED_OR_NON_BROTLI);
    }
    int validFaultCode = validFault.get();
    int invalidFaultCode = invalidFault.get();

    // Step 3: Zero-side-effect CVE-2026-111497 bitstream.
    // Unpatched Brotli (1.0.3 .. 1.2.0): full stream consumed ('br' recorded), 0 'none' retries,
    // and XML-RPC fault code matches valid decompression.
    // Patched Brotli (1.0.10, 1.1.1, 1.2.1, Debian 1.1.0-2+deb13u1): either triggers the 'none'
    // retry (when clientRetriesWithoutBr == true) or returns fault 16 (when false).
    CallbackProbeStep probe = createProbeStep(PRESET_BROTLI_CVE_2026_111497);
    Optional<PingbackCallResult> p1Resp =
        sendPingbackCall(service, xmlRpcUrl, probe.sourceUri(), targetPostUrl, timeoutTracker);
    if (p1Resp.isEmpty()
        || p1Resp.get().faultCode().isEmpty()
        || !hasExpectedCallbacks(probe, /* expectNoBrRetry= */ false)
        || p1Resp.get().faultCode().get() != validFaultCode) {
      return ProbeResult.ofOutcome(StepOutcome.PATCHED_OR_NON_BROTLI);
    }
    int probeFaultCode = p1Resp.get().faultCode().get();

    // Step 4: Post-probe health and determinism verification with both 57-byte controls.
    CallbackProbeStep valid2 = createProbeStep(PRESET_BROTLI_VALID);
    Optional<PingbackCallResult> v2Resp =
        sendPingbackCall(service, xmlRpcUrl, valid2.sourceUri(), targetPostUrl, timeoutTracker);
    CallbackProbeStep invalid2 = createProbeStep(PRESET_BROTLI_INVALID);
    Optional<PingbackCallResult> i2Resp =
        sendPingbackCall(service, xmlRpcUrl, invalid2.sourceUri(), targetPostUrl, timeoutTracker);
    if (v2Resp.isEmpty()
        || i2Resp.isEmpty()
        || !hasExpectedCallbacks(valid2, /* expectNoBrRetry= */ false)
        || !hasExpectedCallbacks(invalid2, /* expectNoBrRetry= */ clientRetriesWithoutBr)
        || !v2Resp.get().faultCode().equals(validFault)
        || !i2Resp.get().faultCode().equals(invalidFault)) {
      return ProbeResult.ofOutcome(StepOutcome.PATCHED_OR_NON_BROTLI);
    }

    return ProbeResult.vulnerable(
        buildPingbackAdditionalDetail(
            xmlRpcUrl,
            targetPostUrl,
            validFaultCode,
            invalidFaultCode,
            probeFaultCode,
            v1Resp.get().serverHeader()));
  }

  @VisibleForTesting
  static boolean isAllowedControlFaultPair(
      int validFault, int invalidFault, boolean clientRetriesWithoutBr) {
    // Masked fault codes (0, 0) from WordPress's default 'xmlrpc_pingback_error' filter are ONLY
    // safe when the HTTP transport actively retries failed Brotli streams with Accept-Encoding:
    // none (recording noBrSecret on invalid1). For non-retrying libcurl/Guzzle clients, TCS
    // records brSecret right before streaming the 93-byte PROBE_TAIL in Step 3, so distinguishing
    // unpatched from patched decoders requires an unmasked post-decompression fault differential
    // (fault 32 or 17 on valid decompression vs. fault 16 on decompression error).
    if (clientRetriesWithoutBr
        && validFault == FAULT_DEFAULT_MASKED
        && invalidFault == FAULT_DEFAULT_MASKED) {
      return true;
    }
    return (validFault == FAULT_TITLE_MISSING || validFault == FAULT_TARGET_LINK_MISSING)
        && invalidFault == FAULT_SOURCE_NOT_FOUND;
  }

  private boolean hasExpectedCallbacks(CallbackProbeStep step, boolean expectNoBrRetry) {
    return tcsClient.hasOobLog(step.brSecret())
        && tcsClient.hasOobLog(step.noBrSecret()) == expectNoBrRetry;
  }

  private CallbackProbeStep createProbeStep(String responsePreset) {
    String brSecret = secretGenerator.generate(SECRET_BYTES);
    String noBrSecret = secretGenerator.generate(SECRET_BYTES);
    String brCallbackUri = tcsClient.getCallbackUri(brSecret);
    String noBrCallbackUri = tcsClient.getCallbackUri(noBrSecret);
    String noBrCbid = noBrCallbackUri.substring(noBrCallbackUri.lastIndexOf('/') + 1);
    String sourceUri = brCallbackUri + "?response=" + responsePreset + "&no_br_cbid=" + noBrCbid;
    return new CallbackProbeStep(brSecret, noBrSecret, sourceUri);
  }

  private ImmutableList<XmlRpcTarget> discoverXmlRpcTargets(NetworkService service) {
    String rootUrl = NetworkServiceUtils.buildWebApplicationRootUrl(service);
    ImmutableList.Builder<PingbackEndpointCandidate> candidates = ImmutableList.builder();

    // 1. First inspect same-origin X-Pingback endpoints advertised in crawled response headers
    // (such as DokuWiki Linkback lib/plugins/linkback/exe/pingback.php/{id}, Serendipity
    // comment.php?type=pingback&entry_id={id}, or custom WordPress XML-RPC paths).
    candidates.addAll(extractXPingbackCandidates(service, rootUrl));

    // 2. Probe standard CMS XML-RPC paths under each discovered CMS root, and probe the 5 guessed
    // subdirectory paths only under the base rootUrl.
    for (String cmsRootUrl : getCandidateCmsRoots(service, rootUrl)) {
      for (String relativeXmlRpcPath : CMS_ROOT_XMLRPC_PATHS) {
        candidates.add(
            new PingbackEndpointCandidate(
                cmsRootUrl + relativeXmlRpcPath,
                cmsRootUrl,
                /* supportsRsdHome= */ relativeXmlRpcPath.equals("xmlrpc.php"),
                /* allowXmlFaultWithoutRsd= */ relativeXmlRpcPath.equals(
                    "comment.php?type=pingback"),
                /* preferredPostUrl= */ Optional.empty()));
      }
      if (cmsRootUrl.equals(rootUrl)) {
        for (String subdirXmlRpcPath : ROOT_ONLY_SUBDIR_XMLRPC_PATHS) {
          String effectiveRootUrl =
              rootUrl
                  + subdirXmlRpcPath.substring(
                      0, subdirXmlRpcPath.length() - "xmlrpc.php".length());
          candidates.add(
              new PingbackEndpointCandidate(
                  rootUrl + subdirXmlRpcPath,
                  effectiveRootUrl,
                  /* supportsRsdHome= */ true,
                  /* allowXmlFaultWithoutRsd= */ false,
                  /* preferredPostUrl= */ Optional.empty()));
        }
      }
    }

    ImmutableList.Builder<XmlRpcTarget> targets = ImmutableList.builder();
    Set<String> seenXmlRpcUrls = new LinkedHashSet<>();
    PhaseTimeoutTracker discoveryTimeouts =
        new PhaseTimeoutTracker("XML-RPC discovery", MAX_CONSECUTIVE_TIMEOUTS);
    for (PingbackEndpointCandidate candidate : candidates.build()) {
      if (Thread.currentThread().isInterrupted() || discoveryTimeouts.isExhausted()) {
        break;
      }
      if (!seenXmlRpcUrls.add(candidate.xmlRpcUrl())) {
        continue;
      }
      Optional<String> homeUrlOpt =
          verifyXmlRpcPingbackEndpoint(service, candidate, discoveryTimeouts);
      if (homeUrlOpt.isEmpty()) {
        continue;
      }
      ImmutableList<String> postUrls =
          discoverCandidatePostUrls(service, candidate, homeUrlOpt.get(), discoveryTimeouts);
      if (!postUrls.isEmpty()) {
        targets.add(new XmlRpcTarget(candidate.xmlRpcUrl(), postUrls));
      }
    }
    return targets.build();
  }

  private ImmutableList<PingbackEndpointCandidate> extractXPingbackCandidates(
      NetworkService service, String rootUrl) {
    URI rootUri;
    try {
      rootUri = new URI(rootUrl);
    } catch (URISyntaxException e) {
      return ImmutableList.of();
    }

    Map<String, PingbackEndpointCandidate> candidates = new LinkedHashMap<>();
    for (CrawlResult crawlResult :
        service.getServiceContext().getWebServiceContext().getCrawlResultsList()) {
      String rawCrawledUrl = crawlResult.getCrawlTarget().getUrl();
      for (HttpHeader header : crawlResult.getResponseHeadersList()) {
        if (!Ascii.equalsIgnoreCase(header.getKey(), "X-Pingback")) {
          continue;
        }
        Optional<String> normalizedPingbackOpt =
            normalizeSameOriginPingbackUrl(header.getValue(), rawCrawledUrl, rootUri, rootUrl);
        if (normalizedPingbackOpt.isEmpty()) {
          continue;
        }
        String pingbackUrl = normalizedPingbackOpt.get();
        String strippedPingbackUrl = stripQueryAndFragment(pingbackUrl);
        boolean supportsRsdHome =
            strippedPingbackUrl.endsWith("/xmlrpc.php")
                && !strippedPingbackUrl.endsWith("/xmlsrv/xmlrpc.php");
        String effectiveRootUrl = deriveCmsRootFromPingbackUrl(pingbackUrl, rootUrl);
        Optional<String> preferredPostUrl =
            resolvePreferredPostForPingback(crawlResult, pingbackUrl, effectiveRootUrl);
        PingbackEndpointCandidate existing = candidates.get(pingbackUrl);
        if (existing == null) {
          if (candidates.size() >= MAX_XPINGBACK_URLS) {
            continue;
          }
          candidates.put(
              pingbackUrl,
              new PingbackEndpointCandidate(
                  pingbackUrl,
                  effectiveRootUrl,
                  supportsRsdHome,
                  /* allowXmlFaultWithoutRsd= */ true,
                  preferredPostUrl));
        } else if (existing.preferredPostUrl().isEmpty() && preferredPostUrl.isPresent()) {
          candidates.put(
              pingbackUrl,
              new PingbackEndpointCandidate(
                  pingbackUrl,
                  effectiveRootUrl,
                  supportsRsdHome,
                  /* allowXmlFaultWithoutRsd= */ true,
                  preferredPostUrl));
        }
      }
    }
    return ImmutableList.copyOf(candidates.values());
  }

  private static Optional<String> resolvePreferredPostForPingback(
      CrawlResult crawlResult, String pingbackUrl, String effectiveRootUrl) {
    String defaultHome = removeTrailingSlashes(effectiveRootUrl);
    if (isEligiblePostCrawlResult(crawlResult)) {
      String cleanedPageUrl = stripFragment(crawlResult.getCrawlTarget().getUrl());
      if (isCandidatePostCrawlUrl(cleanedPageUrl, effectiveRootUrl, defaultHome)) {
        return Optional.of(cleanedPageUrl);
      }
    }
    String strippedPingbackUrl = stripQueryAndFragment(pingbackUrl);
    int linkbackIdx =
        Ascii.toLowerCase(strippedPingbackUrl).indexOf(DOKUWIKI_LINKBACK_PINGBACK_PREFIX);
    if (linkbackIdx >= 0) {
      String pageId =
          strippedPingbackUrl.substring(linkbackIdx + DOKUWIKI_LINKBACK_PINGBACK_PREFIX.length());
      if (!pageId.isEmpty()) {
        return Optional.of(effectiveRootUrl + "doku.php?id=" + pageId);
      }
    }
    return Optional.empty();
  }

  private static String deriveCmsRootFromPingbackUrl(String pingbackUrl, String rootUrl) {
    String withoutQuery = stripQueryAndFragment(pingbackUrl);
    String lowerUrl = Ascii.toLowerCase(withoutQuery);
    for (String marker : XPINGBACK_ROOT_MARKERS) {
      int idx = lowerUrl.indexOf(marker);
      if (idx >= rootUrl.length() - 1) {
        return withoutQuery.substring(0, idx + 1);
      }
    }
    return rootUrl;
  }

  @VisibleForTesting
  static Optional<String> normalizeSameOriginPingbackUrl(
      String rawHeaderValue, String rawCrawledUrl, URI rootUri, String rootUrl) {
    String trimmed = rawHeaderValue.trim();
    if (trimmed.isEmpty()) {
      return Optional.empty();
    }
    try {
      URI parsed = new URI(trimmed);
      URI resolved;
      if (parsed.isAbsolute()) {
        resolved = parsed;
      } else if (parsed.getRawAuthority() != null) {
        resolved = new URI(rootUri.getScheme() + ":" + trimmed);
      } else {
        URI baseUri = rootUri;
        if (rawCrawledUrl.startsWith(rootUrl)) {
          try {
            URI crawledUri = new URI(stripFragment(rawCrawledUrl));
            if (isSameOrigin(crawledUri, rootUri)) {
              baseUri = crawledUri;
            }
          } catch (URISyntaxException ignored) {
            // Fall back to rootUri.
          }
        }
        resolved = baseUri.resolve(parsed);
      }
      if (!isSameOrigin(resolved, rootUri)) {
        return Optional.empty();
      }
      URI normalizedPathUri = resolved.normalize();
      String rawPath = normalizedPathUri.getRawPath();
      if (rawPath == null
          || rawPath.isEmpty()
          || !rawPath.startsWith("/")
          || rawPath.equals("/..")
          || rawPath.startsWith("/../")) {
        return Optional.empty();
      }
      StringBuilder canonical =
          new StringBuilder()
              .append(rootUri.getScheme())
              .append("://")
              .append(rootUri.getRawAuthority())
              .append(rawPath);
      if (normalizedPathUri.getRawQuery() != null) {
        canonical.append('?').append(normalizedPathUri.getRawQuery());
      }
      String canonicalUrl = canonical.toString();
      return canonicalUrl.startsWith(rootUrl) ? Optional.of(canonicalUrl) : Optional.empty();
    } catch (URISyntaxException | IllegalArgumentException e) {
      return Optional.empty();
    }
  }

  private static boolean isSameOrigin(URI candidate, URI origin) {
    return candidate.getScheme() != null
        && Ascii.equalsIgnoreCase(candidate.getScheme(), origin.getScheme())
        && candidate.getUserInfo() == null
        && candidate.getHost() != null
        && Ascii.equalsIgnoreCase(candidate.getHost(), origin.getHost())
        && getEffectivePort(candidate) == getEffectivePort(origin);
  }

  private static int getEffectivePort(URI uri) {
    if (uri.getPort() != -1) {
      return uri.getPort();
    }
    if (Ascii.equalsIgnoreCase("http", uri.getScheme())) {
      return 80;
    }
    if (Ascii.equalsIgnoreCase("https", uri.getScheme())) {
      return 443;
    }
    return -1;
  }

  private ImmutableList<String> getCandidateCmsRoots(NetworkService service, String rootUrl) {
    Set<String> roots = new LinkedHashSet<>();
    roots.add(rootUrl);

    for (CrawlResult crawlResult :
        service.getServiceContext().getWebServiceContext().getCrawlResultsList()) {
      if (roots.size() >= 1 + MAX_CRAWLED_CMS_ROOTS) {
        break;
      }
      String crawledUrl = stripQueryAndFragment(crawlResult.getCrawlTarget().getUrl());
      if (!crawledUrl.startsWith(rootUrl)) {
        continue;
      }
      String lowerUrl = Ascii.toLowerCase(crawledUrl);
      for (String marker : CMS_SUBPATH_MARKERS) {
        int idx = lowerUrl.indexOf(marker);
        if (idx >= rootUrl.length() - 1) {
          roots.add(crawledUrl.substring(0, idx + 1));
          break;
        }
      }
    }
    return ImmutableList.copyOf(roots);
  }

  private static String stripQueryAndFragment(String url) {
    int cutIdx = QUERY_OR_FRAGMENT_MATCHER.indexIn(url);
    return cutIdx >= 0 ? url.substring(0, cutIdx) : url;
  }

  private static String stripFragment(String url) {
    int hashIdx = url.indexOf('#');
    return hashIdx >= 0 ? url.substring(0, hashIdx) : url;
  }

  /**
   * Verifies whether {@code xmlRpcUrl} is an active XML-RPC endpoint that supports {@code
   * pingback.ping}, returning the resolved site home URL (without trailing slash) if supported.
   *
   * <p>Evaluates {@code system.listMethods} outcomes as follows:
   *
   * <ul>
   *   <li>{@link MethodListStatus#UNAVAILABLE}: {@code system.listMethods} either succeeded and
   *       omitted {@code pingback.ping} or did not return an XML-RPC response; immediately skip the
   *       endpoint without polling TCS even if RSD or {@code X-Pingback} is present.
   *   <li>{@link MethodListStatus#PINGBACK_LISTED}: {@code pingback.ping} is advertised; optionally
   *       check RSD on WordPress/Drupal {@code xmlrpc.php} to extract custom {@code <homePageLink>}
   *       if valid, otherwise use {@code effectiveRootUrl}.
   *   <li>{@link MethodListStatus#XMLRPC_FAULT}: the endpoint returned a valid XML-RPC {@code
   *       <fault>} response to {@code system.listMethods} (e.g., dedicated Pingback 1.0 handlers
   *       like Serendipity {@code comment.php?type=pingback}, {@code X-Pingback} receivers, or
   *       WordPress security plugins blocking introspection); check RSD / 405 banner, or accept
   *       {@code effectiveRootUrl} when {@code allowXmlFaultWithoutRsd} is set.
   *   <li>{@link MethodListStatus#HTTP_BLOCKED}: HTTP 401/403 on {@code system.listMethods}; fall
   *       back to RSD or {@code IXR_Server}'s GET banner on {@code ?rsd} / {@code &rsd}.
   * </ul>
   */
  private Optional<String> verifyXmlRpcPingbackEndpoint(
      NetworkService service,
      PingbackEndpointCandidate candidate,
      PhaseTimeoutTracker timeoutTracker) {
    String xmlRpcUrl = candidate.xmlRpcUrl();
    String effectiveRootUrl = candidate.effectiveRootUrl();
    MethodListStatus methodStatus = querySystemListMethods(service, xmlRpcUrl, timeoutTracker);
    if (methodStatus == MethodListStatus.UNAVAILABLE) {
      return Optional.empty();
    }
    String defaultHomeUrl = removeTrailingSlashes(effectiveRootUrl);
    if (methodStatus == MethodListStatus.PINGBACK_LISTED) {
      // NOMUTANTS -- Skipping RSD GET on non-xmlrpc.php endpoints is a request-count optimization;
      // checkXmlRpcRsd falls back to defaultHomeUrl when RSD is absent.
      if (candidate.supportsRsdHome()) {
        return Optional.of(
            checkXmlRpcRsd(service, xmlRpcUrl, effectiveRootUrl, timeoutTracker)
                .orElse(defaultHomeUrl));
      }
      return Optional.of(defaultHomeUrl);
    }
    Optional<String> rsdHome = checkXmlRpcRsd(service, xmlRpcUrl, effectiveRootUrl, timeoutTracker);
    if (rsdHome.isPresent()) {
      return rsdHome;
    }
    if (methodStatus == MethodListStatus.XMLRPC_FAULT && candidate.allowXmlFaultWithoutRsd()) {
      return Optional.of(defaultHomeUrl);
    }
    return Optional.empty();
  }

  private MethodListStatus querySystemListMethods(
      NetworkService service, String xmlRpcUrl, PhaseTimeoutTracker timeoutTracker) {
    Optional<HttpResponse> responseOpt =
        sendHttpRequest(
            post(xmlRpcUrl)
                .setHeaders(HttpHeaders.builder().addHeader("Content-Type", "text/xml").build())
                .setRequestBody(LIST_METHODS_BODY)
                .build(),
            service,
            timeoutTracker);
    if (responseOpt.isEmpty()) {
      return MethodListStatus.UNAVAILABLE;
    }
    HttpResponse response = responseOpt.get();
    String body = response.bodyString().orElse("");
    if (response.status() == HttpStatus.OK && body.contains("<methodResponse>")) {
      if (body.contains("<string>pingback.ping</string>")) {
        return MethodListStatus.PINGBACK_LISTED;
      }
      if (body.contains("<fault>")) {
        return MethodListStatus.XMLRPC_FAULT;
      }
    }
    if (response.status() == HttpStatus.FORBIDDEN || response.status() == HttpStatus.UNAUTHORIZED) {
      return MethodListStatus.HTTP_BLOCKED;
    }
    return MethodListStatus.UNAVAILABLE;
  }

  /**
   * Checks {@code GET <xmlRpcUrl>?rsd} (or {@code &rsd} when {@code xmlRpcUrl} already contains a
   * query string) to confirm an XML-RPC RSD document (or {@code IXR_Server}'s POST-only banner when
   * RSD output is suppressed) and extract an absolute {@code http}/{@code https} {@code
   * <homePageLink>} if present.
   */
  private Optional<String> checkXmlRpcRsd(
      NetworkService service,
      String xmlRpcUrl,
      String effectiveRootUrl,
      PhaseTimeoutTracker timeoutTracker) {
    String rsdUrl = xmlRpcUrl + (xmlRpcUrl.contains("?") ? "&rsd" : "?rsd");
    String defaultHomeUrl = removeTrailingSlashes(effectiveRootUrl);
    Optional<HttpResponse> responseOpt =
        sendHttpRequest(get(rsdUrl).withEmptyHeaders().build(), service, timeoutTracker);
    if (responseOpt.isEmpty()) {
      return Optional.empty();
    }
    HttpResponse response = responseOpt.get();
    String body = response.bodyString().orElse("");
    if (response.status() == HttpStatus.OK
        && (body.contains("<rsd") || body.contains("<engineName>"))) {
      Matcher matcher = HOME_PAGE_LINK_PATTERN.matcher(body);
      if (matcher.find()) {
        String candidateHomeUrl =
            removeTrailingSlashes(stripFragment(unescapeXmlText(matcher.group(1).trim())));
        if (isValidAbsoluteHttpHomeUrl(candidateHomeUrl)) {
          return Optional.of(candidateHomeUrl);
        }
      }
      return Optional.of(defaultHomeUrl);
    }
    if ((response.status() == HttpStatus.METHOD_NOT_ALLOWED || response.status() == HttpStatus.OK)
        && body.contains("XML-RPC server accepts POST requests only.")) {
      return Optional.of(defaultHomeUrl);
    }
    return Optional.empty();
  }

  @VisibleForTesting
  static boolean isValidAbsoluteHttpHomeUrl(String url) {
    if (url.isEmpty()) {
      return false;
    }
    try {
      URI uri = new URI(url);
      String scheme = uri.getScheme();
      return scheme != null
          && (Ascii.equalsIgnoreCase("http", scheme) || Ascii.equalsIgnoreCase("https", scheme))
          && uri.getUserInfo() == null
          && uri.getHost() != null
          && uri.getRawQuery() == null;
    } catch (URISyntaxException e) {
      return false;
    }
  }

  private ImmutableList<String> discoverCandidatePostUrls(
      NetworkService service,
      PingbackEndpointCandidate candidate,
      String homeUrl,
      PhaseTimeoutTracker timeoutTracker) {
    String cmsRootUrl = candidate.effectiveRootUrl();
    boolean prioritizePreferredPostFirst = !candidate.supportsRsdHome();
    Set<String> postUrls = new LinkedHashSet<>();

    if (prioritizePreferredPostFirst) {
      candidate.preferredPostUrl().ifPresent(postUrls::add);
    }
    int countBeforeRest = postUrls.size();

    // 1. Query WP REST API (/wp-json/wp/v2/posts), which explicitly exposes ping_status == "open".
    String restPostsUrl = cmsRootUrl + "wp-json/wp/v2/posts?per_page=5";
    Optional<HttpResponse> restResponse =
        sendHttpRequest(get(restPostsUrl).withEmptyHeaders().build(), service, timeoutTracker);
    if (restResponse.isPresent() && restResponse.get().status() == HttpStatus.OK) {
      restResponse
          .get()
          .bodyString()
          .ifPresent(
              body -> {
                for (String postLink : extractRestApiOpenPingPosts(body)) {
                  if (postUrls.size() >= MAX_CANDIDATE_POSTS - 2) {
                    break;
                  }
                  postUrls.add(postLink);
                }
              });
    }

    // 2. If REST API did not yield open-pingback posts, fall back to WordPress/CMS RSS2 feed
    // (?feed=rss2) and Drupal default RSS feed (rss.xml).
    if (postUrls.size() == countBeforeRest) {
      int countBeforeRss = postUrls.size();
      for (String rssSubpath : ImmutableList.of("?feed=rss2", "rss.xml")) {
        if (postUrls.size() > countBeforeRss
            || Thread.currentThread().isInterrupted()
            || timeoutTracker.isExhausted()) {
          break;
        }
        String rssUrl = cmsRootUrl + rssSubpath;
        Optional<HttpResponse> rssResponse =
            sendHttpRequest(get(rssUrl).withEmptyHeaders().build(), service, timeoutTracker);
        if (rssResponse.isPresent() && rssResponse.get().status() == HttpStatus.OK) {
          rssResponse
              .get()
              .bodyString()
              .ifPresent(
                  body -> {
                    for (String rssLink : extractRssPostLinks(body)) {
                      if (postUrls.size() >= MAX_CANDIDATE_POSTS - 2) {
                        break;
                      }
                      postUrls.add(rssLink);
                    }
                  });
        }
      }
    }

    if (!prioritizePreferredPostFirst && postUrls.size() < MAX_CANDIDATE_POSTS - 2) {
      candidate.preferredPostUrl().ifPresent(postUrls::add);
    }

    // 3. Include dynamic 200 GET crawled content URLs under the CMS root (for DokuWiki,
    // Serendipity, Movable Type, TikiWiki, query-routed CMS posts, or custom permalinks),
    // reserving slots for canonical CMS fallbacks.
    for (CrawlResult crawlResult :
        service.getServiceContext().getWebServiceContext().getCrawlResultsList()) {
      if (postUrls.size() >= MAX_CANDIDATE_POSTS - 2) {
        break;
      }
      if (!isEligiblePostCrawlResult(crawlResult)) {
        continue;
      }
      String candidateUrl = stripFragment(crawlResult.getCrawlTarget().getUrl());
      if (isCandidatePostCrawlUrl(candidateUrl, cmsRootUrl, homeUrl)) {
        postUrls.add(candidateUrl);
      }
    }

    // 4. Always include canonical CMS post fallbacks: <homeUrl>/?p=1 (WordPress/b2evolution/s9y
    // default post) and <homeUrl>/node/1 (Drupal default first node).
    if (postUrls.size() < MAX_CANDIDATE_POSTS) {
      postUrls.add(homeUrl + "/?p=1");
    }
    if (postUrls.size() < MAX_CANDIDATE_POSTS) {
      postUrls.add(homeUrl + "/node/1");
    }

    return ImmutableList.copyOf(postUrls);
  }

  private static boolean isEligiblePostCrawlResult(CrawlResult crawlResult) {
    return Ascii.equalsIgnoreCase(crawlResult.getCrawlTarget().getHttpMethod(), "GET")
        && crawlResult.getResponseCode() == HttpStatus.OK.code();
  }

  @VisibleForTesting
  static boolean isCandidatePostCrawlUrl(String crawledUrl, String cmsRootUrl, String homeUrl) {
    String withoutFragment = stripFragment(crawledUrl);
    if (withoutFragment.endsWith("?")) {
      withoutFragment = withoutFragment.substring(0, withoutFragment.length() - 1);
    }
    boolean underHome =
        !homeUrl.isEmpty()
            && (withoutFragment.startsWith(homeUrl + "/")
                || withoutFragment.startsWith(homeUrl + "?"));
    if (!withoutFragment.startsWith(cmsRootUrl) && !underHome) {
      return false;
    }
    if (withoutFragment.equals(cmsRootUrl)
        || withoutFragment.equals(homeUrl)
        || withoutFragment.equals(homeUrl + "/")) {
      return false;
    }
    URI uri;
    try {
      uri = new URI(withoutFragment);
    } catch (URISyntaxException e) {
      return false;
    }
    String path = uri.getPath();
    String rawQuery = uri.getRawQuery();
    if (path == null || (path.isEmpty() && (rawQuery == null || rawQuery.isEmpty()))) {
      return false;
    }
    String lowerPath = Ascii.toLowerCase(path);
    for (String marker : NON_POST_PATH_MARKERS) {
      if (lowerPath.contains(marker)) {
        return false;
      }
    }
    if (lowerPath.endsWith("/admin") || lowerPath.endsWith("/feed")) {
      return false;
    }
    int lastSlashIdx = lowerPath.lastIndexOf('/');
    String fileName = lastSlashIdx >= 0 ? lowerPath.substring(lastSlashIdx + 1) : lowerPath;
    int dotIdx = fileName.lastIndexOf('.');
    if (dotIdx >= 0 && STATIC_ASSET_EXTENSIONS.contains(fileName.substring(dotIdx))) {
      return false;
    }
    if (rawQuery != null && isNonPostQuery(rawQuery)) {
      return false;
    }
    return true;
  }

  private static boolean isNonPostQuery(String rawQuery) {
    String lowerQuery = Ascii.toLowerCase(rawQuery);
    for (String param : Splitter.on('&').omitEmptyStrings().split(lowerQuery)) {
      int eqIdx = param.indexOf('=');
      String key = eqIdx >= 0 ? param.substring(0, eqIdx) : param;
      String value = eqIdx >= 0 ? param.substring(eqIdx + 1) : "";
      if (key.equals("feed")
          || key.equals("rest_route")
          || key.equals("rsd")
          || key.equals("replytocom")) {
        return true;
      }
      if (key.equals("do") && !value.isEmpty() && !value.equals("show")) {
        return true;
      }
      if ((key.equals("action") || key.equals("disp")) && NON_POST_ACTION_VALUES.contains(value)) {
        return true;
      }
      if (key.equals("q")) {
        String normalizedRoute = CharMatcher.is('/').trimLeadingFrom(value.replace("%2f", "/"));
        if (normalizedRoute.equals("user")
            || normalizedRoute.startsWith("user/")
            || normalizedRoute.equals("admin")
            || normalizedRoute.startsWith("admin/")
            || normalizedRoute.equals("rss.xml")
            || normalizedRoute.endsWith("/feed")) {
          return true;
        }
      }
      if ((key.equals("format") || key.equals("type")) && FEED_FORMAT_VALUES.contains(value)) {
        return true;
      }
    }
    return false;
  }

  private static ImmutableList<String> extractRestApiOpenPingPosts(String jsonBody) {
    ImmutableList.Builder<String> links = ImmutableList.builder();
    try {
      JsonElement root = JsonParser.parseString(jsonBody);
      if (!root.isJsonArray()) {
        return ImmutableList.of();
      }
      JsonArray array = root.getAsJsonArray();
      int count = 0;
      for (JsonElement element : array) {
        if (count >= MAX_CANDIDATE_POSTS - 2) {
          break;
        }
        if (!element.isJsonObject()) {
          continue;
        }
        JsonObject postObj = element.getAsJsonObject();
        JsonElement pingStatus = postObj.get("ping_status");
        if (pingStatus != null
            && !pingStatus.isJsonNull()
            && (!pingStatus.isJsonPrimitive()
                || !Ascii.equalsIgnoreCase(pingStatus.getAsString(), "open"))) {
          continue;
        }
        JsonElement linkElement = postObj.get("link");
        if (linkElement != null && linkElement.isJsonPrimitive()) {
          String link = linkElement.getAsString().trim();
          if (!link.isEmpty()) {
            links.add(link);
            count++;
          }
        }
      }
    } catch (JsonParseException e) {
      logger.atFine().withCause(e).log("Failed to parse WP REST posts JSON response");
    }
    return links.build();
  }

  private static ImmutableList<String> extractRssPostLinks(String rssBody) {
    ImmutableList.Builder<String> links = ImmutableList.builder();
    Matcher itemMatcher = RSS_ITEM_PATTERN.matcher(rssBody);
    int count = 0;
    while (itemMatcher.find() && count < MAX_CANDIDATE_POSTS - 2) {
      Matcher linkMatcher = RSS_LINK_PATTERN.matcher(itemMatcher.group(1));
      if (linkMatcher.find()) {
        String link = unescapeXmlText(linkMatcher.group(1).trim());
        if (!link.isEmpty()) {
          links.add(link);
          count++;
        }
      }
    }
    return links.build();
  }

  private Optional<PingbackCallResult> sendPingbackCall(
      NetworkService service,
      String xmlRpcUrl,
      String sourceUri,
      String targetUri,
      PhaseTimeoutTracker timeoutTracker) {
    String xml =
        "<?xml version=\"1.0\"?><methodCall><methodName>pingback.ping</methodName><params>"
            + "<param><value><string>"
            + XmlEscapers.xmlContentEscaper().escape(sourceUri)
            + "</string></value></param>"
            + "<param><value><string>"
            + XmlEscapers.xmlContentEscaper().escape(targetUri)
            + "</string></value></param>"
            + "</params></methodCall>";
    Optional<HttpResponse> responseOpt =
        sendHttpRequest(
            post(xmlRpcUrl)
                .setHeaders(HttpHeaders.builder().addHeader("Content-Type", "text/xml").build())
                .setRequestBody(ByteString.copyFromUtf8(xml))
                .build(),
            service,
            timeoutTracker);
    if (responseOpt.isEmpty()) {
      return Optional.empty();
    }
    HttpResponse response = responseOpt.get();
    String body = response.bodyString().orElse("");
    if (response.status() != HttpStatus.OK || !body.contains("<methodResponse>")) {
      return Optional.empty();
    }
    return Optional.of(
        new PingbackCallResult(extractFaultCode(body), response.headers().get("Server")));
  }

  /**
   * Probes Next.js Image Optimizer endpoints ({@code /_next/image?url=<tcs_url>&w=64&q=75}) for
   * outbound {@code undici}/{@code node:zlib} Brotli decompression vulnerable to CVE-2026-111497.
   *
   * <p>When Next.js fetches a remote image URL via {@code fetch()} ({@code undici}), Node.js
   * streams {@code Content-Encoding: br} responses through {@code libbrotlidec} (even on plain
   * {@code http://} callback URLs where {@code undici} sends {@code User-Agent: node} and {@code
   * Accept-Encoding: gzip, deflate}) before validating the response {@code Content-Type}:
   *
   * <ul>
   *   <li>When Brotli decompression succeeds ({@code brotli_valid} and {@code
   *       brotli_cve_2026_111497} on unpatched Node.js), Next.js inspects the decompressed response
   *       with {@code Content-Type: text/plain} and returns {@code 400 Bad Request} ("The requested
   *       resource isn't a valid image").
   *   <li>When Brotli decompression fails ({@code brotli_invalid}, or {@code
   *       brotli_cve_2026_111497} on patched Node.js), {@code undici} throws {@code TypeError:
   *       fetch failed} ({@code Z_BROTLI_DECOMPRESSION_FAILED}), causing {@code /_next/image} to
   *       return {@code 500 Internal Server Error} or {@code 502 Bad Gateway}.
   * </ul>
   */
  private Optional<AdditionalDetail> findVulnerableNextJsImageTarget(NetworkService service) {
    PhaseTimeoutTracker nextJsTimeouts =
        new PhaseTimeoutTracker("Next.js /_next/image", MAX_CONSECUTIVE_TIMEOUTS);
    for (String nextImageEndpoint : getCandidateNextJsImageEndpoints(service)) {
      if (Thread.currentThread().isInterrupted() || nextJsTimeouts.isExhausted()) {
        break;
      }
      Optional<AdditionalDetail> evidence =
          probeNextJsImageEndpoint(service, nextImageEndpoint, nextJsTimeouts);
      if (evidence.isPresent()) {
        logger.atInfo().log(
            "Confirmed CVE-2026-111497 via Next.js Image Optimizer on '%s'", nextImageEndpoint);
        return evidence;
      }
    }
    return Optional.empty();
  }

  private ImmutableList<String> getCandidateNextJsImageEndpoints(NetworkService service) {
    String rootUrl = NetworkServiceUtils.buildWebApplicationRootUrl(service);
    Set<String> endpoints = new LinkedHashSet<>();
    endpoints.add(rootUrl + "_next/image");

    for (CrawlResult crawlResult :
        service.getServiceContext().getWebServiceContext().getCrawlResultsList()) {
      if (endpoints.size() >= 1 + MAX_CRAWLED_CMS_ROOTS) {
        break;
      }
      String crawledUrl = stripQueryAndFragment(crawlResult.getCrawlTarget().getUrl());
      if (!crawledUrl.startsWith(rootUrl)) {
        continue;
      }
      int idx = Ascii.toLowerCase(crawledUrl).indexOf("/_next/");
      if (idx >= rootUrl.length() - 1) {
        endpoints.add(crawledUrl.substring(0, idx + 1) + "_next/image");
      }
    }
    return ImmutableList.copyOf(endpoints);
  }

  private Optional<AdditionalDetail> probeNextJsImageEndpoint(
      NetworkService service, String nextImageEndpoint, PhaseTimeoutTracker timeoutTracker) {
    // Step 1: Valid RFC 7932 Brotli control (57 bytes). Expect TCS 'br' callback and 400 status.
    CallbackProbeStep valid1 = createProbeStep(PRESET_BROTLI_VALID);
    Optional<HttpResponse> v1Resp =
        sendNextJsImageRequest(service, nextImageEndpoint, valid1, timeoutTracker);
    if (v1Resp.isEmpty()
        || v1Resp.get().status() != HttpStatus.BAD_REQUEST
        || !hasExpectedCallbacks(valid1, /* expectNoBrRetry= */ false)) {
      return Optional.empty();
    }

    // Step 2: Invalid Brotli control (57 bytes). Expect TCS 'br' callback and 500/502 status.
    CallbackProbeStep invalid1 = createProbeStep(PRESET_BROTLI_INVALID);
    Optional<HttpResponse> i1Resp =
        sendNextJsImageRequest(service, nextImageEndpoint, invalid1, timeoutTracker);
    if (i1Resp.isEmpty()
        || !NEXT_IMAGE_DECOMPRESSION_FAILURE_STATUSES.contains(i1Resp.get().status())
        || !hasExpectedCallbacks(invalid1, /* expectNoBrRetry= */ false)) {
      return Optional.empty();
    }
    HttpStatus invalidStatus = i1Resp.get().status();

    // Step 3: Zero-side-effect CVE-2026-111497 bitstream.
    CallbackProbeStep probe = createProbeStep(PRESET_BROTLI_CVE_2026_111497);
    Optional<HttpResponse> p1Resp =
        sendNextJsImageRequest(service, nextImageEndpoint, probe, timeoutTracker);
    if (p1Resp.isEmpty()
        || p1Resp.get().status() != HttpStatus.BAD_REQUEST
        || !hasExpectedCallbacks(probe, /* expectNoBrRetry= */ false)) {
      return Optional.empty();
    }

    // Step 4: Post-probe health and determinism verification with both 57-byte controls.
    CallbackProbeStep valid2 = createProbeStep(PRESET_BROTLI_VALID);
    Optional<HttpResponse> v2Resp =
        sendNextJsImageRequest(service, nextImageEndpoint, valid2, timeoutTracker);
    CallbackProbeStep invalid2 = createProbeStep(PRESET_BROTLI_INVALID);
    Optional<HttpResponse> i2Resp =
        sendNextJsImageRequest(service, nextImageEndpoint, invalid2, timeoutTracker);
    if (v2Resp.isEmpty()
        || i2Resp.isEmpty()
        || v2Resp.get().status() != HttpStatus.BAD_REQUEST
        || i2Resp.get().status() != invalidStatus
        || !hasExpectedCallbacks(valid2, /* expectNoBrRetry= */ false)
        || !hasExpectedCallbacks(invalid2, /* expectNoBrRetry= */ false)) {
      return Optional.empty();
    }

    return Optional.of(
        buildNextJsImageAdditionalDetail(
            nextImageEndpoint,
            /* validStatus= */ HttpStatus.BAD_REQUEST.code(),
            /* invalidStatus= */ invalidStatus.code(),
            /* probeStatus= */ HttpStatus.BAD_REQUEST.code(),
            v1Resp.get().headers().get("Server")));
  }

  private Optional<HttpResponse> sendNextJsImageRequest(
      NetworkService service,
      String nextImageEndpoint,
      CallbackProbeStep step,
      PhaseTimeoutTracker timeoutTracker) {
    String encodedSourceUri = URLEncoder.encode(step.sourceUri(), UTF_8);
    String requestUrl = nextImageEndpoint + "?url=" + encodedSourceUri + "&w=64&q=75";
    return sendHttpRequest(
        get(requestUrl)
            .setHeaders(HttpHeaders.builder().addHeader("Accept", "image/webp,*/*").build())
            .build(),
        service,
        timeoutTracker);
  }

  private Optional<HttpResponse> sendHttpRequest(
      HttpRequest request, NetworkService service, PhaseTimeoutTracker timeoutTracker) {
    if (Thread.currentThread().isInterrupted() || timeoutTracker.isExhausted()) {
      return Optional.empty();
    }
    try {
      HttpResponse response = httpClient.send(request, service);
      timeoutTracker.onResponse();
      return Optional.of(response);
    } catch (InterruptedIOException e) {
      // Catch InterruptedIOException (superclass of SocketTimeoutException and thrown directly by
      // OkHttp's AsyncTimeout on call timeouts); only count it as a network timeout when the
      // scanner thread itself was not interrupted.
      if (!Thread.currentThread().isInterrupted()) {
        timeoutTracker.onTimeout(request.url());
      }
      logger.atFine().withCause(e).log(
          "HTTP timeout or interruption while sending %s to '%s'", request.method(), request.url());
      return Optional.empty();
    } catch (IOException e) {
      logger.atFine().withCause(e).log(
          "HTTP exception while sending %s to '%s'", request.method(), request.url());
      return Optional.empty();
    }
  }

  private static Optional<Integer> extractFaultCode(String xmlBody) {
    Matcher matcher = XMLRPC_FAULT_CODE_PATTERN.matcher(xmlBody);
    if (!matcher.find()) {
      return Optional.empty();
    }
    try {
      return Optional.of(Integer.parseInt(matcher.group(1)));
    } catch (NumberFormatException e) {
      return Optional.empty();
    }
  }

  private static String unescapeXmlText(String input) {
    return input
        .replace("&#038;", "&")
        .replace("&#38;", "&")
        .replace("&#x26;", "&")
        .replace("&#X26;", "&")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&");
  }

  private static AdditionalDetail buildPingbackAdditionalDetail(
      String xmlRpcUrl,
      String targetPostUrl,
      int validFaultCode,
      int invalidFaultCode,
      int probeFaultCode,
      Optional<String> serverHeader) {
    StringBuilder evidence =
        new StringBuilder()
            .append("Vulnerable endpoint: ")
            .append(xmlRpcUrl)
            .append(" (signal=tcs_pingback_differential, post=")
            .append(targetPostUrl)
            .append(", valid_fault=")
            .append(validFaultCode)
            .append(", invalid_fault=")
            .append(invalidFaultCode)
            .append(", probe_fault=")
            .append(probeFaultCode);
    appendSanitizedServerHeader(evidence, serverHeader);
    evidence.append(')');
    return AdditionalDetail.newBuilder()
        .setDescription(DETECTION_EVIDENCE_DESCRIPTION)
        .setTextData(TextData.newBuilder().setText(evidence.toString()))
        .build();
  }

  private static AdditionalDetail buildNextJsImageAdditionalDetail(
      String nextImageEndpoint,
      int validStatus,
      int invalidStatus,
      int probeStatus,
      Optional<String> serverHeader) {
    StringBuilder evidence =
        new StringBuilder()
            .append("Vulnerable endpoint: ")
            .append(nextImageEndpoint)
            .append(" (signal=tcs_nextjs_image_differential, valid_status=")
            .append(validStatus)
            .append(", invalid_status=")
            .append(invalidStatus)
            .append(", probe_status=")
            .append(probeStatus);
    appendSanitizedServerHeader(evidence, serverHeader);
    evidence.append(')');
    return AdditionalDetail.newBuilder()
        .setDescription(DETECTION_EVIDENCE_DESCRIPTION)
        .setTextData(TextData.newBuilder().setText(evidence.toString()))
        .build();
  }

  private static void appendSanitizedServerHeader(
      StringBuilder evidence, Optional<String> serverHeader) {
    serverHeader
        .map(Cve2026111497OutboundDetector::sanitizeServerHeader)
        .filter(server -> !server.isEmpty())
        .ifPresent(server -> evidence.append(", server=").append(server));
  }

  private static String sanitizeServerHeader(String server) {
    String cleaned = NON_PRINTABLE_ASCII_MATCHER.replaceFrom(server, ' ').trim();
    return Ascii.truncate(cleaned, MAX_SERVER_HEADER_LENGTH, "...");
  }

  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo, NetworkService vulnerableNetworkService, AdditionalDetail evidence) {
    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(vulnerableNetworkService)
        .setDetectionTimestamp(Timestamps.fromMillis(utcClock.instant().toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(getAdvisories().get(0).toBuilder().addAdditionalDetails(evidence).build())
        .build();
  }

  private static final class PhaseTimeoutTracker {
    private final String phaseName;
    private final int maxConsecutiveTimeouts;
    private int consecutiveTimeouts = 0;

    PhaseTimeoutTracker(String phaseName, int maxConsecutiveTimeouts) {
      this.phaseName = phaseName;
      this.maxConsecutiveTimeouts = maxConsecutiveTimeouts;
    }

    void onResponse() {
      consecutiveTimeouts = 0;
    }

    void onTimeout(String lastUrl) {
      consecutiveTimeouts++;
      if (consecutiveTimeouts == maxConsecutiveTimeouts) {
        logger.atWarning().log(
            "Aborting %s phase after %d consecutive HTTP timeouts (last URL: '%s')",
            phaseName, consecutiveTimeouts, lastUrl);
      }
    }

    boolean isExhausted() {
      return consecutiveTimeouts >= maxConsecutiveTimeouts;
    }
  }

  private enum MethodListStatus {
    PINGBACK_LISTED,
    XMLRPC_FAULT,
    HTTP_BLOCKED,
    UNAVAILABLE
  }

  private enum StepOutcome {
    NO_CALLBACK_REACHED,
    PATCHED_OR_NON_BROTLI,
    VULNERABLE
  }

  private record ProbeResult(StepOutcome outcome, Optional<AdditionalDetail> evidence) {
    static ProbeResult ofOutcome(StepOutcome outcome) {
      return new ProbeResult(outcome, Optional.empty());
    }

    static ProbeResult vulnerable(AdditionalDetail evidence) {
      return new ProbeResult(StepOutcome.VULNERABLE, Optional.of(evidence));
    }
  }

  private record CallbackProbeStep(String brSecret, String noBrSecret, String sourceUri) {}

  private record PingbackCallResult(Optional<Integer> faultCode, Optional<String> serverHeader) {}

  private record PingbackEndpointCandidate(
      String xmlRpcUrl,
      String effectiveRootUrl,
      boolean supportsRsdHome,
      boolean allowXmlFaultWithoutRsd,
      Optional<String> preferredPostUrl) {}

  private record XmlRpcTarget(String xmlRpcUrl, ImmutableList<String> candidatePostUrls) {}
}
