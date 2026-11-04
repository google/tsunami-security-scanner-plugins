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
package com.google.tsunami.plugins.detectors.rce.wordpress.cve2026111497;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.UrlUtils.removeTrailingSlashes;
import static com.google.tsunami.common.net.http.HttpRequest.get;
import static com.google.tsunami.common.net.http.HttpRequest.post;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Ascii;
import com.google.common.base.CharMatcher;
import com.google.common.collect.ImmutableList;
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
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TextData;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.io.IOException;
import java.time.Clock;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.inject.Inject;

/**
 * A {@link VulnDetector} that detects the Google Brotli decoder out-of-bounds write RCE
 * vulnerability (CVE-2026-111497) exposed via WordPress's unauthenticated {@code xmlrpc.php} {@code
 * pingback.ping} endpoint using the Tsunami Callback Server (TCS).
 *
 * <p>Unlike servers that decompress incoming {@code Content-Encoding: br} request bodies (covered
 * by {@code Cve2026111497Detector}), WordPress's {@code pingback.ping} handler invokes {@code
 * wp_safe_remote_get()} through {@code WpOrg\Requests\Transport\Curl} with {@code CURLOPT_ENCODING
 * = ""}, causing {@code libcurl} to advertise {@code Accept-Encoding: deflate, gzip, br, zstd} on
 * outbound HTTP fetches and stream {@code Content-Encoding: br} responses directly into {@code
 * libbrotlidec} inside the PHP worker process. Whenever {@code libbrotlidec} rejects a stream
 * ({@code CURLE_BAD_CONTENT_ENCODING}), {@code Curl.php} immediately retries a second {@code GET}
 * with {@code CURLOPT_ENCODING = "none"} ({@code Accept-Encoding: none}), which TCS attributes to
 * {@code no_br_cbid} while serving safe built-in Brotli presets on the primary callback ID.
 */
@ForWebService
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "WordPressXmlRpcCve2026111497Detector",
    version = "0.1",
    description =
        "This detector checks for the Google Brotli decoder out-of-bounds write RCE vulnerability"
            + " (CVE-2026-111497) exposed via WordPress xmlrpc.php pingback.ping.",
    author = "Tsunami Security Scanner",
    bootstrapModule = WordPressXmlRpcCve2026111497DetectorBootstrapModule.class)
public final class WordPressXmlRpcCve2026111497Detector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  @VisibleForTesting static final String VULNERABILITY_REPORT_PUBLISHER = "GOOGLE";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_ID = "CVE-2026-111497-WORDPRESS-XMLRPC";

  @VisibleForTesting static final String RELATED_CVE_ID = "CVE-2026-111497";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_TITLE =
      "WordPress XML-RPC Pingback Google Brotli Decoder RCE (CVE-2026-111497)";

  @VisibleForTesting
  static final String VULN_DESCRIPTION =
      "The target WordPress installation exposes an unauthenticated XML-RPC 'pingback.ping'"
          + " endpoint backed by a libcurl/libbrotlidec library (Brotli 1.0.3 through 1.2.0)"
          + " vulnerable to CVE-2026-111497. When 'pingback.ping' verifies a source URL,"
          + " WordPress's WpOrg\\Requests\\Transport\\Curl transport sets CURLOPT_ENCODING to \"\","
          + " causing libcurl to advertise 'br' in Accept-Encoding and stream 'Content-Encoding:"
          + " br' HTTP responses directly into BrotliDecoderDecompressStream prior to PHP's 150 KB"
          + " decompressed response-size check. In unpatched Brotli decoders, a compressed"
          + " metablock with NBLTYPESD == 1 and more than 16,777,216 explicit-distance commands"
          + " causes BrotliDecoderDecompressStream to copy unread input bytes past the 8-byte"
          + " s->buffer union into adjacent BrotliDecoderState fields, enabling unauthenticated"
          + " Remote Code Execution (RCE) inside the PHP/web server worker.";

  @VisibleForTesting
  static final String RECOMMENDATION =
      "Upgrade the system Brotli library (libbrotli1) to version 1.2.1 or a patched distribution"
          + " package (such as Debian libbrotli1 >= 1.1.0-2+deb13u1, included in official Docker"
          + " wordpress:7.1.4+ images rebuilt on or after 2026-10-28), and restart PHP-FPM/Apache."
          + " As defense-in-depth, block access to /xmlrpc.php at the web server or WAF, or"
          + " explicitly unset 'pingback.ping' via the 'xmlrpc_methods' filter (note that filtering"
          + " 'xmlrpc_enabled' to false alone does not disable unauthenticated 'pingback.ping').";

  @VisibleForTesting static final String PRESET_BROTLI_VALID = "brotli_valid";
  @VisibleForTesting static final String PRESET_BROTLI_INVALID = "brotli_invalid";
  @VisibleForTesting static final String PRESET_BROTLI_CVE_2026_111497 = "brotli_cve_2026_111497";

  @VisibleForTesting
  static final String DETECTION_EVIDENCE_DESCRIPTION = "CVE-2026-111497 detection evidence";

  private static final int MAX_CRAWLED_WP_ROOTS = 3;
  private static final int MAX_CANDIDATE_POSTS = 3;
  private static final int SECRET_BYTES = 16;
  private static final int MAX_SERVER_HEADER_LENGTH = 64;

  // XML-RPC fault codes returned by wp_xmlrpc_server::pingback_ping:
  // - By default since WordPress 3.6.1, core registers the 'xmlrpc_pingback_error' filter
  //   (wp-includes/default-filters.php), which normalizes all non-48 pingback fault codes to 0.
  // - When a plugin removes that filter, pingback_ping returns raw post-fetch fault codes after
  //   wp_safe_remote_get() completes: 16 (empty body or transport error), 17 (link to target post
  //   missing), or 32 (HTML <title> tag missing).
  // - Pre-fetch errors (such as 33 = pingbacks closed or 48 = already registered) return before
  //   wp_safe_remote_get() and never trigger the TCS callbacks verified in Steps 1 and 2.
  private static final int FAULT_DEFAULT_MASKED = 0;
  private static final int FAULT_SOURCE_NOT_FOUND = 16;
  private static final int FAULT_TARGET_LINK_MISSING = 17;
  private static final int FAULT_TITLE_MISSING = 32;

  private static final CharMatcher QUERY_OR_FRAGMENT_MATCHER = CharMatcher.anyOf("?#");
  private static final CharMatcher NON_PRINTABLE_ASCII_MATCHER =
      CharMatcher.inRange(' ', '~').negate();

  private static final ImmutableList<String> WP_SUBPATH_MARKERS =
      ImmutableList.of(
          "/wp-content/",
          "/wp-includes/",
          "/wp-admin/",
          "/wp-json/",
          "/wp-login.php",
          "/xmlrpc.php");

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
  WordPressXmlRpcCve2026111497Detector(
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
    logger.atInfo().log("WordPressXmlRpcCve2026111497Detector starts detecting.");

    if (!tcsClient.isCallbackServerEnabled()) {
      logger.atWarning().log(
          "Tsunami callback server is not enabled; skipping WordPressXmlRpcCve2026111497Detector.");
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
      ImmutableList<WordPressXmlRpcTarget> wpTargets = discoverWordPressTargets(service);
      findVulnerableWordPressTarget(service, wpTargets)
          .ifPresent(
              evidence ->
                  reports.addDetectionReports(buildDetectionReport(targetInfo, service, evidence)));
    }
    return reports.build();
  }

  private Optional<AdditionalDetail> findVulnerableWordPressTarget(
      NetworkService service, ImmutableList<WordPressXmlRpcTarget> wpTargets) {
    for (WordPressXmlRpcTarget wpTarget : wpTargets) {
      for (String postUrl : wpTarget.candidatePostUrls()) {
        ProbeResult result = probePostVulnerability(service, wpTarget.xmlRpcUrl(), postUrl);
        if (result.outcome() == StepOutcome.VULNERABLE && result.evidence().isPresent()) {
          logger.atInfo().log(
              "Confirmed CVE-2026-111497 via WordPress XML-RPC pingback on '%s' (post '%s')",
              wpTarget.xmlRpcUrl(), postUrl);
          return result.evidence();
        }
        if (result.outcome() == StepOutcome.PATCHED_OR_NON_BROTLI) {
          // Callback reached TCS from this WordPress instance and proved it is patched or does
          // not decompress Brotli; no need to re-test additional posts on the same instance.
          break;
        }
      }
    }
    return Optional.empty();
  }

  private ProbeResult probePostVulnerability(
      NetworkService service, String xmlRpcUrl, String targetPostUrl) {
    // Step 1: Valid RFC 7932 Brotli control (57 bytes). Expect 'br' interaction and no fallback.
    CallbackProbeStep valid1 = createProbeStep(PRESET_BROTLI_VALID);
    Optional<PingbackCallResult> v1Resp =
        sendPingbackCall(service, xmlRpcUrl, valid1.sourceUri(), targetPostUrl);
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

    // Step 2: Invalid Brotli control (57 bytes). Expect 'br' interaction followed by 'none' retry.
    CallbackProbeStep invalid1 = createProbeStep(PRESET_BROTLI_INVALID);
    Optional<PingbackCallResult> i1Resp =
        sendPingbackCall(service, xmlRpcUrl, invalid1.sourceUri(), targetPostUrl);
    if (i1Resp.isEmpty() || !hasExpectedCallbacks(invalid1, /* expectNoBrRetry= */ true)) {
      return ProbeResult.ofOutcome(StepOutcome.PATCHED_OR_NON_BROTLI);
    }

    // Require a valid XML-RPC fault code pair for both controls:
    // - Default WordPress (with core's 'xmlrpc_pingback_error' filter enabled) returns fault 0 for
    //   all non-48 pingback errors after wp_safe_remote_get() completes.
    // - Unmasked WordPress (when a plugin removes 'xmlrpc_pingback_error') returns fault 32 (or
    //   17) for valid1 (53-byte HTML without <title>) and fault 16 for invalid1 (empty body on the
    //   Accept-Encoding: none retry).
    Optional<Integer> validFault = v1Resp.get().faultCode();
    Optional<Integer> invalidFault = i1Resp.get().faultCode();
    if (validFault.isEmpty()
        || invalidFault.isEmpty()
        || !isAllowedControlFaultPair(validFault.get(), invalidFault.get())) {
      return ProbeResult.ofOutcome(StepOutcome.PATCHED_OR_NON_BROTLI);
    }
    int validFaultCode = validFault.get();
    int invalidFaultCode = invalidFault.get();

    // Step 3: Zero-side-effect CVE-2026-111497 bitstream.
    // Unpatched Brotli (1.0.3 .. 1.2.0): full stream consumed ('br' recorded), 0 'none' retries,
    // and XML-RPC fault code matches valid decompression.
    // Patched Brotli (1.0.10, 1.1.1, 1.2.1, Debian 1.1.0-2+deb13u1): 'none' retry recorded.
    CallbackProbeStep probe = createProbeStep(PRESET_BROTLI_CVE_2026_111497);
    Optional<PingbackCallResult> p1Resp =
        sendPingbackCall(service, xmlRpcUrl, probe.sourceUri(), targetPostUrl);
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
        sendPingbackCall(service, xmlRpcUrl, valid2.sourceUri(), targetPostUrl);
    CallbackProbeStep invalid2 = createProbeStep(PRESET_BROTLI_INVALID);
    Optional<PingbackCallResult> i2Resp =
        sendPingbackCall(service, xmlRpcUrl, invalid2.sourceUri(), targetPostUrl);
    if (v2Resp.isEmpty()
        || i2Resp.isEmpty()
        || !hasExpectedCallbacks(valid2, /* expectNoBrRetry= */ false)
        || !hasExpectedCallbacks(invalid2, /* expectNoBrRetry= */ true)
        || !v2Resp.get().faultCode().equals(validFault)
        || !i2Resp.get().faultCode().equals(invalidFault)) {
      return ProbeResult.ofOutcome(StepOutcome.PATCHED_OR_NON_BROTLI);
    }

    return ProbeResult.vulnerable(
        buildAdditionalDetail(
            xmlRpcUrl,
            targetPostUrl,
            validFaultCode,
            invalidFaultCode,
            probeFaultCode,
            v1Resp.get().serverHeader()));
  }

  @VisibleForTesting
  static boolean isAllowedControlFaultPair(int validFault, int invalidFault) {
    if (validFault == FAULT_DEFAULT_MASKED && invalidFault == FAULT_DEFAULT_MASKED) {
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

  private ImmutableList<WordPressXmlRpcTarget> discoverWordPressTargets(NetworkService service) {
    ImmutableList.Builder<WordPressXmlRpcTarget> targets = ImmutableList.builder();
    for (String wpRootUrl : getCandidateWordPressRoots(service)) {
      Optional<String> homeUrlOpt = checkXmlRpcRsd(service, wpRootUrl);
      if (homeUrlOpt.isEmpty()) {
        continue;
      }
      String xmlRpcUrl = wpRootUrl + "xmlrpc.php";
      if (!supportsPingbackMethod(service, xmlRpcUrl)) {
        continue;
      }
      ImmutableList<String> postUrls =
          discoverCandidatePostUrls(service, wpRootUrl, homeUrlOpt.get());
      if (!postUrls.isEmpty()) {
        targets.add(new WordPressXmlRpcTarget(xmlRpcUrl, postUrls));
      }
    }
    return targets.build();
  }

  private ImmutableList<String> getCandidateWordPressRoots(NetworkService service) {
    String rootUrl = NetworkServiceUtils.buildWebApplicationRootUrl(service);
    Set<String> roots = new LinkedHashSet<>();
    roots.add(rootUrl);

    for (CrawlResult crawlResult :
        service.getServiceContext().getWebServiceContext().getCrawlResultsList()) {
      if (roots.size() >= 1 + MAX_CRAWLED_WP_ROOTS) {
        break;
      }
      String crawledUrl = stripQueryAndFragment(crawlResult.getCrawlTarget().getUrl());
      if (!crawledUrl.startsWith(rootUrl)) {
        continue;
      }
      String lowerUrl = Ascii.toLowerCase(crawledUrl);
      for (String marker : WP_SUBPATH_MARKERS) {
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

  /**
   * Checks {@code GET <wpRootUrl>xmlrpc.php?rsd} to confirm a WordPress XML-RPC endpoint and
   * extract {@code get_option('home')} from {@code <homePageLink>}, falling back to {@code
   * IXR_Server}'s 405 banner when RSD output is suppressed.
   */
  private Optional<String> checkXmlRpcRsd(NetworkService service, String wpRootUrl) {
    String rsdUrl = wpRootUrl + "xmlrpc.php?rsd";
    try {
      HttpResponse response = httpClient.send(get(rsdUrl).withEmptyHeaders().build(), service);
      String body = response.bodyString().orElse("");
      if (response.status() == HttpStatus.OK
          && body.contains("<engineName>WordPress</engineName>")) {
        Matcher matcher = HOME_PAGE_LINK_PATTERN.matcher(body);
        if (matcher.find()) {
          return Optional.of(removeTrailingSlashes(unescapeXmlText(matcher.group(1).trim())));
        }
        return Optional.of(removeTrailingSlashes(wpRootUrl));
      }
      if (response.status() == HttpStatus.METHOD_NOT_ALLOWED
          && body.contains("XML-RPC server accepts POST requests only.")) {
        return Optional.of(removeTrailingSlashes(wpRootUrl));
      }
    } catch (IOException e) {
      logger.atFine().withCause(e).log("Failed to query WordPress RSD at '%s'", rsdUrl);
    }
    return Optional.empty();
  }

  private boolean supportsPingbackMethod(NetworkService service, String xmlRpcUrl) {
    try {
      HttpResponse response =
          httpClient.send(
              post(xmlRpcUrl)
                  .setHeaders(HttpHeaders.builder().addHeader("Content-Type", "text/xml").build())
                  .setRequestBody(LIST_METHODS_BODY)
                  .build(),
              service);
      if (response.status() != HttpStatus.OK) {
        return false;
      }
      String body = response.bodyString().orElse("");
      return body.contains("<string>pingback.ping</string>")
          && body.contains("<string>wp.getUsersBlogs</string>");
    } catch (IOException e) {
      logger.atFine().withCause(e).log(
          "Failed to query system.listMethods on WordPress XML-RPC '%s'", xmlRpcUrl);
      return false;
    }
  }

  private ImmutableList<String> discoverCandidatePostUrls(
      NetworkService service, String wpRootUrl, String homeUrl) {
    Set<String> postUrls = new LinkedHashSet<>();

    // 1. Query WP REST API (/wp-json/wp/v2/posts), which explicitly exposes ping_status == "open".
    String restPostsUrl = wpRootUrl + "wp-json/wp/v2/posts?per_page=5";
    try {
      HttpResponse response =
          httpClient.send(get(restPostsUrl).withEmptyHeaders().build(), service);
      if (response.status() == HttpStatus.OK) {
        response.bodyString().ifPresent(body -> postUrls.addAll(extractRestApiOpenPingPosts(body)));
      }
    } catch (IOException e) {
      logger.atFine().withCause(e).log("Failed to query WP REST posts at '%s'", restPostsUrl);
    }

    // 2. If REST API did not yield open-pingback posts, fall back to RSS2 feed (?feed=rss2).
    if (postUrls.isEmpty()) {
      String rssUrl = wpRootUrl + "?feed=rss2";
      try {
        HttpResponse response = httpClient.send(get(rssUrl).withEmptyHeaders().build(), service);
        if (response.status() == HttpStatus.OK) {
          response.bodyString().ifPresent(body -> postUrls.addAll(extractRssPostLinks(body)));
        }
      } catch (IOException e) {
        logger.atFine().withCause(e).log("Failed to query WP RSS2 feed at '%s'", rssUrl);
      }
    }

    // 3. Always include <homeUrl>/?p=1 ("Hello world!" default post, resolved directly via query
    // regex in wp_xmlrpc_server::pingback_ping regardless of permalink settings).
    if (postUrls.size() < MAX_CANDIDATE_POSTS) {
      postUrls.add(homeUrl + "/?p=1");
    }

    return ImmutableList.copyOf(postUrls);
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
        if (count >= MAX_CANDIDATE_POSTS) {
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
    while (itemMatcher.find() && count < MAX_CANDIDATE_POSTS) {
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
      NetworkService service, String xmlRpcUrl, String sourceUri, String targetUri) {
    String xml =
        "<?xml version=\"1.0\"?><methodCall><methodName>pingback.ping</methodName><params>"
            + "<param><value><string>"
            + XmlEscapers.xmlContentEscaper().escape(sourceUri)
            + "</string></value></param>"
            + "<param><value><string>"
            + XmlEscapers.xmlContentEscaper().escape(targetUri)
            + "</string></value></param>"
            + "</params></methodCall>";
    try {
      HttpResponse response =
          httpClient.send(
              post(xmlRpcUrl)
                  .setHeaders(HttpHeaders.builder().addHeader("Content-Type", "text/xml").build())
                  .setRequestBody(ByteString.copyFromUtf8(xml))
                  .build(),
              service);
      String body = response.bodyString().orElse("");
      if (response.status() != HttpStatus.OK || !body.contains("<methodResponse>")) {
        return Optional.empty();
      }
      return Optional.of(
          new PingbackCallResult(extractFaultCode(body), response.headers().get("Server")));
    } catch (IOException e) {
      logger.atFine().withCause(e).log(
          "HTTP exception while calling pingback.ping on '%s'", xmlRpcUrl);
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

  private static AdditionalDetail buildAdditionalDetail(
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
    serverHeader
        .map(WordPressXmlRpcCve2026111497Detector::sanitizeServerHeader)
        .filter(server -> !server.isEmpty())
        .ifPresent(server -> evidence.append(", server=").append(server));
    evidence.append(')');
    return AdditionalDetail.newBuilder()
        .setDescription(DETECTION_EVIDENCE_DESCRIPTION)
        .setTextData(TextData.newBuilder().setText(evidence.toString()))
        .build();
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

  private record WordPressXmlRpcTarget(String xmlRpcUrl, ImmutableList<String> candidatePostUrls) {}
}
