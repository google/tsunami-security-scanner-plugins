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
package com.google.tsunami.plugins.detectors.rce.cve2026111497;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.post;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Sets;
import com.google.common.flogger.GoogleLogger;
import com.google.common.io.BaseEncoding;
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
 * A {@link VulnDetector} that detects the Google Brotli decoder out-of-bounds write RCE
 * vulnerability (CVE-2026-111497).
 *
 * <p>Detection uses a zero-side-effect, false-positive-free 4-step differential protocol:
 *
 * <ol>
 *   <li><b>Step 1 (Valid Brotli Control)</b>: Sends a 191-byte valid RFC 7932 Brotli stream ({@code
 *       Content-Encoding: br}, {@code Content-Type: application/json}) consisting exclusively of
 *       7-bit ASCII bytes ({@code < 0x80}, opening byte <code>'P'</code> = {@code 0x50}) that
 *       decompresses to a 175-byte multi-protocol JSON object (<code>{\r\n
 *       \n\t"tsunami_brotli_check_7f9a2b":    "tsunami_brotli_check_7f9a2b","query":"{tsunami_brotli_check_7f9a2b}","jsonrpc":"2.0","id":
 *       1,  "method":"tsunami_brotli_check_7f9a2b"}</code>, with 4 spaces after the first colon and
 *       2 spaces before {@code "method"} so every uncompressed metablock header byte stays {@code <
 *       0x80}). Every occurrence of the canary is split across uncompressed metablocks so the
 *       contiguous string {@code tsunami_brotli_check_7f9a2b} never appears in the raw compressed
 *       request bytes.
 *   <li><b>Step 2 (Invalid Brotli Control)</b>: Sends a 191-byte invalid Brotli stream consisting
 *       of printable 7-bit ASCII (<code>{tsunami_brotli_invalid_control_...}</code>, matching the
 *       exact wire length of Step 1) whose opening byte (<code>'{'</code> = {@code 0x7b})
 *       immediately fails RFC 7932 Section 9.2 padding validation ({@code
 *       BROTLI_DECODER_ERROR_FORMAT_PADDING_2}) in any Brotli decoder while also failing raw
 *       non-Brotli JSON/XML syntax parsing identically to Step 1's raw compressed bytes. Verifies
 *       that the target actively decompresses {@code Content-Encoding: br} and discriminates valid
 *       vs. invalid Brotli (via decompressed canary reflection on any status code or decompression
 *       error status code differential). If the endpoint does not decompress {@code
 *       Content-Encoding: br}, detection aborts immediately without sending the probe.
 *   <li><b>Step 3 (CVE-2026-111497 Zero-Side-Effect Probe)</b>: Sends a crafted Brotli stream with
 *       {@code NBLTYPESD == 1} and {@code 16,777,217} commands using static dictionary transform
 *       {@code OmitLast7} (producing 0 output bytes for the first {@code 16,777,216} commands while
 *       keeping {@code s->pos == 0}), followed by the {@code 16,777,217}th command and a 32-byte
 *       zero-filled metadata metablock that preserves {@code s->pos == 0} across all arbitrary TCP
 *       chunk splits. Unpatched Brotli ({@code 1.0.3 .. 1.2.0}) ignores the {@code BROTLI_FALSE}
 *       return from {@code DecodeDistanceBlockSwitch}, underflows {@code s->block_length[2]} to
 *       {@code 0xFFFFFFFF}, and finishes decompressing the exact same 175-byte JSON payload as Step
 *       1. Patched Brotli ({@code 1.0.10}, {@code 1.1.1}, {@code 1.2.1}) immediately aborts at the
 *       {@code 16,777,217}th command with {@code BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH} ({@code
 *       -17}) and 0 output bytes.
 *   <li><b>Step 4 (Post-Probe Health &amp; Determinism Verification)</b>: Re-sends the 191-byte
 *       Step 1 and Step 2 controls to confirm that the service remains healthy and that the
 *       differential is deterministic.
 * </ol>
 */
@ForWebService
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "Cve2026111497Detector",
    version = "0.1",
    description =
        "This detector checks for the Google Brotli decoder out-of-bounds write RCE vulnerability"
            + " (CVE-2026-111497).",
    author = "Tsunami Security Scanner",
    bootstrapModule = Cve2026111497DetectorBootstrapModule.class)
public final class Cve2026111497Detector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  @VisibleForTesting static final String VULNERABILITY_REPORT_PUBLISHER = "GOOGLE";
  @VisibleForTesting static final String VULNERABILITY_REPORT_ID = "CVE-2026-111497";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_TITLE =
      "Google Brotli Decoder Out-of-Bounds Write RCE (CVE-2026-111497)";

  @VisibleForTesting
  static final String VULN_DESCRIPTION =
      "The target HTTP service decompresses 'Content-Encoding: br' request bodies using a version"
          + " of the Google Brotli library (1.0.3 through 1.2.0) vulnerable to CVE-2026-111497. In"
          + " unpatched Brotli decoders, when a compressed metablock declares a single distance"
          + " block type (NBLTYPESD == 1) and executes more than 16,777,216 commands with explicit"
          + " distances, s->block_length[2] reaches 0 and invokes DecodeDistanceBlockSwitch."
          + " Unpatched Brotli returns BROTLI_FALSE when max_block_type <= 1: on the fast path"
          + " (safe == 0), the return value is ignored and s->block_length[2] underflows to"
          + " 0xFFFFFFFF; on the slow path (safe == 1), BROTLI_FALSE is misinterpreted as"
          + " BROTLI_DECODER_NEEDS_MORE_INPUT, causing BrotliDecoderDecompressStream to copy unread"
          + " input bytes past the 8-byte s->buffer union into adjacent BrotliDecoderState fields"
          + " (s->buffer_length, s->pos, s->ringbuffer), enabling unauthenticated Remote Code"
          + " Execution (RCE).";

  @VisibleForTesting
  static final String RECOMMENDATION =
      "Upgrade the Brotli library to version 1.2.1 (or backported 1.1.1 / 1.0.10). For Node.js"
          + " applications, upgrade to Node.js 22.23.4+, 24.15.0+, or 25.8.0+. As an immediate"
          + " mitigation, reject or strip 'Content-Encoding: br' on incoming HTTP requests at the"
          + " reverse proxy or WAF layer.";

  @VisibleForTesting static final String DECOMPRESSED_CANARY = "tsunami_brotli_check_7f9a2b";

  /**
   * 191-byte valid RFC 7932 Brotli stream (composed solely of 7-bit UTF-8 safe bytes {@code <
   * 0x80}, opening byte <code>'P'</code> = {@code 0x50}) that decompresses to the 175-byte
   * multi-protocol JSON payload (with 4 spaces after the first colon and 2 spaces before {@code
   * "method"} so every uncompressed metablock header byte stays {@code < 0x80}): <code>{\r\n
   * \n\t"tsunami_brotli_check_7f9a2b":    "tsunami_brotli_check_7f9a2b","query":"{tsunami_brotli_check_7f9a2b}","jsonrpc":"2.0","id":
   * 1,  "method":"tsunami_brotli_check_7f9a2b"}</code>. Placing {@link #DECOMPRESSED_CANARY} as the
   * first property key and inside GraphQL {@code query} and JSON-RPC {@code method} fields elicits
   * canary reflection in strict schema, unknown-field, and GraphQL validation errors, while
   * splitting every canary instance across uncompressed metablocks ensures {@link
   * #DECOMPRESSED_CANARY} never appears contiguously in the raw compressed bytes.
   */
  @VisibleForTesting
  static final ByteString VALID_BROTLI_CONTROL =
      ByteString.copyFrom(
          BaseEncoding.base16()
              .lowerCase()
              .decode(
                  "5001107b0d0a200a09227473756e616d695f62726f746c695f080108"
                      + "636865636b5f376639613262223a20202020227473756e616d695f62726f746c695f200108"
                      + "636865636b5f376639613262222c227175657279223a227b7473756e616d695f62726f746c"
                      + "080208695f636865636b5f3766396132627d222c226a736f6e727063223a22322e3022"
                      + "2c226964223a20312c2020226d6574686f64223a227473756e616d695f62726f746c780008"
                      + "695f636865636b5f376639613262227d03"));

  /**
   * 191-byte invalid Brotli stream consisting of printable 7-bit ASCII (matching the exact 191-byte
   * length of {@link #VALID_BROTLI_CONTROL}) whose opening byte (<code>'{'</code> = {@code 0x7b}:
   * {@code WBITS = 21}, {@code ISLAST = 1}, {@code ISLASTEMPTY = 1}, non-zero padding bit 6)
   * immediately fails RFC 7932 Section 9.2 padding validation ({@code
   * BROTLI_DECODER_ERROR_FORMAT_PADDING_2}) in any Brotli decoder. Subsequent bytes intentionally
   * omit JSON quotes so that non-Brotli endpoints ignoring {@code Content-Encoding: br} fail raw
   * JSON/XML syntax parsing symmetrically on both {@link #VALID_BROTLI_CONTROL} and {@link
   * #INVALID_BROTLI_CONTROL}.
   */
  @VisibleForTesting
  static final ByteString INVALID_BROTLI_CONTROL =
      ByteString.copyFromUtf8(
          Strings.padEnd("{tsunami_brotli_invalid_control_", VALID_BROTLI_CONTROL.size() - 1, '_')
              + "}");

  /**
   * 17-byte header for the CVE-2026-111497 probe: {@code WBITS = 16} + 0-length metadata metablock
   * 0 (aligning to byte 1 with {@code s->pos == 0}) + compressed metablock 1 header ({@code MLEN =
   * 6}, {@code NBLTYPESL = 1}, {@code NBLTYPESI = 2} with initial {@code block_length[1] =
   * 16,777,217}, {@code NBLTYPESD = 1} with implicit {@code block_length[2] = 16,777,216}, 1-symbol
   * command tree {@code cmd 130}, 1-symbol distance tree {@code code 223}).
   */
  @VisibleForTesting
  static final ByteString PROBE_HEADER =
      ByteString.copyFrom(
          BaseEncoding.base16().lowerCase().decode("0c28002082c8ffffff260880102404896f"));

  /**
   * Number of zero bytes in the middle of the CVE-2026-111497 probe ({@code 16,777,216} commands *
   * 11 bits / 8 = {@code 23,068,672} bytes). Each command executes static dictionary transform 48
   * ({@code OmitLast7}) on a 4-byte word, outputting 0 bytes and decrementing {@code
   * s->block_length[2]} from {@code 16,777,216} down to {@code 0}.
   */
  @VisibleForTesting static final int PROBE_MIDDLE_ZERO_LEN = 23_068_672;

  /**
   * 221-byte tail for the CVE-2026-111497 probe: Command #16,777,217 ({@code extra = 353},
   * outputting <code>{\r\n \n\t</code>), followed by a 32-byte zero-filled metadata metablock
   * (ensuring {@code s->pos == 0} and {@code s->max_distance == 0} remain unchanged even under
   * arbitrary TCP packet splits), followed by five split uncompressed metablocks reconstructing the
   * exact same 175-byte multi-protocol JSON payload as {@link #VALID_BROTLI_CONTROL} and the final
   * empty metablock {@code 0x03}.
   */
  @VisibleForTesting
  static final ByteString PROBE_TAIL =
      ByteString.copyFrom(
          BaseEncoding.base16()
              .lowerCase()
              .decode(
                  "61b13e000000000000000000000000000000000000000000000000000000000000000000"
                      + "780008227473756e616d695f62726f746c695f080108"
                      + "636865636b5f376639613262223a20202020227473756e616d695f62726f746c695f200108"
                      + "636865636b5f376639613262222c227175657279223a227b7473756e616d695f62726f746c"
                      + "080208695f636865636b5f3766396132627d222c226a736f6e727063223a22322e3022"
                      + "2c226964223a20312c2020226d6574686f64223a227473756e616d695f62726f746c780008"
                      + "695f636865636b5f376639613262227d03"));

  private static final int MAX_CRAWLED_URLS = 3;

  /**
   * Fallback HTTP POST paths probed when Tsunami's web crawler does not discover a vulnerable
   * endpoint in {@code WebServiceContext.getCrawlResultsList()}.
   *
   * <p>IMPORTANT: Because Tsunami's HTML crawler only follows {@code GET} links in HTML pages and
   * rarely discovers JSON {@code POST} API routes (and returns no crawl results at all on headless
   * REST/GraphQL/RPC services or SPAs), {@code CANDIDATE_PATHS} are in practice the ONLY paths
   * tested against most targets.
   *
   * <p>These top 10 paths are selected to cover both middleware routing architectures in vulnerable
   * systems (Node.js/Express/Fastify/Next.js/NestJS/Apollo/tRPC, Bun, Python, and Envoy):
   *
   * <ul>
   *   <li><b>Prefix- or globally-mounted decompression middleware</b> (e.g., Express {@code
   *       app.use(express.json())} or {@code app.use('/api', express.json(), router)}, Envoy HTTP
   *       Brotli decompressor filter): Decompresses {@code Content-Encoding: br} before leaf route
   *       matching, so probing the mount prefix ({@code ""}, {@code "api"}, {@code "api/v1"},
   *       {@code "trpc"}) triggers the differential (e.g., 404 on valid Brotli vs. 400 on invalid
   *       Brotli) even without knowing any application-specific leaf route.
   *   <li><b>Route-first decompression frameworks</b> (e.g., Fastify with {@code @fastify/compress}
   *       {@code preParsing} hooks, Apollo Server, Next.js/NestJS controllers): Only decompress
   *       when an exact registered {@code POST} route matches, covered by the most common
   *       unauthenticated JSON {@code POST} endpoints ({@code "graphql"}, {@code "api/graphql"},
   *       {@code "login"}, {@code "api/login"}, {@code "auth/login"}, {@code "webhook"}).
   * </ul>
   *
   * <p>Non-decompressing paths abort after Step 1 or Step 2 (1-2 requests of 191 bytes each) and
   * never send the Step 3 probe, keeping the scan overhead negligible.
   */
  // TODO(b/352283036): Review candidate paths later to see if this list improves detection rate.
  private static final ImmutableList<String> CANDIDATE_PATHS =
      ImmutableList.of(
          "",
          "graphql",
          "api",
          "api/v1",
          "api/graphql",
          "trpc",
          "login",
          "api/login",
          "auth/login",
          "webhook");

  private static final ImmutableSet<HttpStatus> POST_DECOMPRESSION_STATUSES =
      Sets.immutableEnumSet(
          HttpStatus.FOUND,
          HttpStatus.SEE_OTHER,
          HttpStatus.UNAUTHORIZED,
          HttpStatus.FORBIDDEN,
          HttpStatus.NOT_FOUND,
          HttpStatus.METHOD_NOT_ALLOWED);

  private static final ImmutableSet<HttpStatus> DECOMPRESSION_FAILURE_STATUSES =
      Sets.immutableEnumSet(
          HttpStatus.BAD_REQUEST,
          HttpStatus.UNPROCESSABLE_ENTITY,
          HttpStatus.INTERNAL_SERVER_ERROR);

  private final Clock utcClock;
  private final HttpClient httpClient;

  @Inject
  Cve2026111497Detector(@UtcClock Clock utcClock, HttpClient httpClient) {
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
                VulnerabilityId.newBuilder().setPublisher("CVE").setValue(VULNERABILITY_REPORT_ID))
            .setSeverity(Severity.CRITICAL)
            .setTitle(VULNERABILITY_REPORT_TITLE)
            .setDescription(VULN_DESCRIPTION)
            .setRecommendation(RECOMMENDATION)
            .build());
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Cve2026111497Detector starts detecting.");

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
      if (isEndpointVulnerable(networkService, targetUrl)) {
        return true;
      }
    }
    return false;
  }

  private boolean isEndpointVulnerable(NetworkService networkService, String targetUrl) {
    // Step 1: Send small (191-byte) valid RFC 7932 Brotli control payload.
    Optional<HttpResponse> validControlOpt =
        sendBrotliRequest(networkService, targetUrl, VALID_BROTLI_CONTROL);
    if (validControlOpt.isEmpty()) {
      return false;
    }
    HttpResponse validControl = validControlOpt.get();
    if (!containsCanary(validControl) && !isPostDecompressionStatus(validControl.status())) {
      return false;
    }

    // Step 2: Send small (191-byte) invalid Brotli control payload to verify active decompression.
    Optional<HttpResponse> invalidControlOpt =
        sendBrotliRequest(networkService, targetUrl, INVALID_BROTLI_CONTROL);
    if (invalidControlOpt.isEmpty()) {
      return false;
    }
    HttpResponse invalidControl = invalidControlOpt.get();

    // Because DECOMPRESSED_CANARY is split across uncompressed metablocks in VALID_BROTLI_CONTROL,
    // its contiguous presence in validControl proves RFC 7932 decompression occurred even when
    // downstream schema/GraphQL/type validation returns 400 or 422.
    boolean canaryReflected =
        validControl.status() != HttpStatus.HTTP_STATUS_UNSPECIFIED
            && containsCanary(validControl)
            && !containsCanary(invalidControl);
    boolean statusDifferential =
        isValidVsInvalidStatusDifferential(validControl.status(), invalidControl.status());
    if (!canaryReflected && !statusDifferential) {
      return false;
    }

    // Step 3: Send the zero-side-effect CVE-2026-111497 Brotli probe.
    Optional<HttpResponse> probeResponseOpt =
        sendBrotliRequest(networkService, targetUrl, Holder.CVE_2026_111497_PROBE);
    if (probeResponseOpt.isEmpty()) {
      return false;
    }
    HttpResponse probeResponse = probeResponseOpt.get();
    if (probeResponse.status() != validControl.status()
        || (canaryReflected && !containsCanary(probeResponse))) {
      return false;
    }

    // Step 4: Post-probe health and determinism verification using the 191-byte controls.
    Optional<HttpResponse> validVerifyOpt =
        sendBrotliRequest(networkService, targetUrl, VALID_BROTLI_CONTROL);
    if (validVerifyOpt.isEmpty()) {
      return false;
    }
    Optional<HttpResponse> invalidVerifyOpt =
        sendBrotliRequest(networkService, targetUrl, INVALID_BROTLI_CONTROL);
    if (invalidVerifyOpt.isEmpty()) {
      return false;
    }
    HttpResponse validVerify = validVerifyOpt.get();
    HttpResponse invalidVerify = invalidVerifyOpt.get();

    if (validVerify.status() != validControl.status()
        || invalidVerify.status() != invalidControl.status()) {
      return false;
    }
    if (canaryReflected
        && (!containsCanary(validVerify) || containsCanary(invalidVerify))) {
      return false;
    }

    logger.atInfo().log("Confirmed CVE-2026-111497 vulnerable Brotli decoder on '%s'", targetUrl);
    return true;
  }

  private static boolean containsCanary(HttpResponse response) {
    return response.bodyString().orElse("").contains(DECOMPRESSED_CANARY);
  }

  private static boolean isPostDecompressionStatus(HttpStatus status) {
    // Reverse proxies, input filters, and global middleware (e.g., Apache mod_brotli, Envoy HTTP
    // decompressor filter, Express body-parser) decompress the request stream before downstream
    // authentication, ACLs, login redirects, or route/method matching; when Brotli decompression
    // succeeds, downstream handlers commonly return 2xx, 302/303, 401, 403, 404, or 405, whereas
    // decompression failure aborts earlier with 400, 422, or 500.
    return status.isSuccess() || POST_DECOMPRESSION_STATUSES.contains(status);
  }

  private static boolean isValidVsInvalidStatusDifferential(
      HttpStatus validStatus, HttpStatus invalidStatus) {
    return isPostDecompressionStatus(validStatus)
        && DECOMPRESSION_FAILURE_STATUSES.contains(invalidStatus);
  }

  private ImmutableSet<String> getTargetUrls(NetworkService networkService) {
    String rootUrl = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    ImmutableSet.Builder<String> targetUrls = ImmutableSet.builder();
    int crawledCount = 0;
    for (CrawlResult crawlResult :
        networkService.getServiceContext().getWebServiceContext().getCrawlResultsList()) {
      if (crawledCount >= MAX_CRAWLED_URLS) {
        break;
      }
      String crawledUrl = crawlResult.getCrawlTarget().getUrl();
      try {
        URI uri = new URI(crawledUrl);
        URI normalizedUri =
            new URI(
                uri.getScheme(),
                uri.getAuthority(),
                uri.getPath(),
                uri.getQuery(),
                /* fragment= */ null);
        String normalizedUrl = normalizedUri.toString();
        if (normalizedUrl.startsWith(rootUrl)) {
          targetUrls.add(normalizedUrl);
          crawledCount++;
        }
      } catch (URISyntaxException e) {
        logger.atFine().withCause(e).log("Failed to parse crawled URL '%s'", crawledUrl);
      }
    }
    CANDIDATE_PATHS.forEach(subpath -> targetUrls.add(rootUrl + subpath));
    return targetUrls.build();
  }

  private Optional<HttpResponse> sendBrotliRequest(
      NetworkService networkService, String targetUrl, ByteString brotliBody) {
    try {
      return Optional.of(
          httpClient.send(
              post(targetUrl)
                  .setHeaders(
                      HttpHeaders.builder()
                          .addHeader("Content-Encoding", "br")
                          .addHeader("Content-Type", "application/json")
                          .addHeader("Accept", "application/json, text/plain, */*")
                          .build())
                  .setRequestBody(brotliBody)
                  .build(),
              networkService));
    } catch (IOException e) {
      logger.atFine().withCause(e).log(
          "HTTP exception while sending Brotli request to '%s'", targetUrl);
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

  /** Lazy holder for the CVE-2026-111497 probe payload. */
  @VisibleForTesting
  static final class Holder {
    static final ByteString CVE_2026_111497_PROBE = buildProbePayload();

    static ByteString buildProbePayload() {
      ByteString zeroChunk64k = ByteString.copyFrom(new byte[65_536]);
      int numChunks = PROBE_MIDDLE_ZERO_LEN / 65_536;
      ByteString result = PROBE_HEADER;
      for (int i = 0; i < numChunks; i++) {
        result = result.concat(zeroChunk64k);
      }
      return result.concat(PROBE_TAIL);
    }

    private Holder() {}
  }
}
