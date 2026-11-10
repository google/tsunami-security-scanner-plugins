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

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.Truth.assertWithMessage;
import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forIp;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forIpAndPort;

import com.google.common.base.Ascii;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.io.ByteStreams;
import com.google.common.net.InetAddresses;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.inject.Guice;
import com.google.inject.Injector;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.callbackserver.common.CbidProcessor;
import com.google.tsunami.callbackserver.common.Sha3CbidGenerator;
import com.google.tsunami.callbackserver.common.UrlParser;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.net.http.HttpMethod;
import com.google.tsunami.common.net.http.HttpRequest;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.plugin.TcsClient;
import com.google.tsunami.plugin.payload.PayloadSecretGenerator;
import com.google.tsunami.plugin.payload.testing.FakePayloadGeneratorModule;
import com.google.tsunami.plugin.payload.testing.PayloadTestHelper;
import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.CrawlResult;
import com.google.tsunami.proto.CrawlTarget;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.HttpHeader;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.ServiceContext;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TextData;
import com.google.tsunami.proto.TransportProtocol;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import com.google.tsunami.proto.WebServiceContext;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import okio.Buffer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link Cve2026111497OutboundDetector}. */
@RunWith(JUnit4.class)
public final class Cve2026111497OutboundDetectorTest {
  private static final Pattern XMLRPC_STRING_PARAM_PATTERN =
      Pattern.compile("<param>\\s*<value>\\s*<string>(.*?)</string>\\s*</value>\\s*</param>");

  private static final ByteString VALID_CONTROL_BYTES =
      ByteString.copyFrom(new byte[] {0x40, 0x03, 0x10, 'o', 'k', 0x03});
  private static final ByteString INVALID_CONTROL_BYTES =
      ByteString.copyFrom(new byte[] {'{', 'b', 'a', 'd', '}'});
  private static final ByteString PROBE_BYTES =
      ByteString.copyFrom(new byte[] {0x0c, 0x28, 0x00, 0x03});

  private static final int VALID_FIRST_BYTE = Byte.toUnsignedInt(VALID_CONTROL_BYTES.byteAt(0));
  private static final int INVALID_FIRST_BYTE = Byte.toUnsignedInt(INVALID_CONTROL_BYTES.byteAt(0));
  private static final int PROBE_FIRST_BYTE = Byte.toUnsignedInt(PROBE_BYTES.byteAt(0));

  private static final int FAULT_PINGBACK_SOURCE_NOT_FOUND = 16;
  private static final int FAULT_PINGBACK_TARGET_LINK_MISSING = 17;
  private static final int FAULT_PINGBACK_TITLE_MISSING = 32;
  private static final int FAULT_PINGBACK_CLOSED = 33;
  private static final InetAddress LOOPBACK_ADDRESS = InetAddresses.forString("127.0.0.1");

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2026-10-29T00:00:00.00Z"));
  private final OkHttpClient callbackHttpClient =
      new OkHttpClient.Builder().followRedirects(false).build();

  private MockWebServer mockWebServer;
  private MockWebServer mockCallbackServer;

  @Before
  public void setUp() throws IOException {
    mockWebServer = new MockWebServer();
    mockWebServer.start(LOOPBACK_ADDRESS, 0);

    mockCallbackServer = new MockWebServer();
    mockCallbackServer.setDispatcher(new SimulatedTcsDispatcher());
    mockCallbackServer.start(LOOPBACK_ADDRESS, 0);
  }

  @After
  public void tearDownMockWebServer() throws IOException {
    if (mockWebServer != null) {
      mockWebServer.shutdown();
    }
  }

  @After
  public void tearDownMockCallbackServer() throws IOException {
    if (mockCallbackServer != null) {
      mockCallbackServer.shutdown();
    }
  }

  @Test
  public void getAdvisories_whenCalled_returnsOutboundMainIdAndRelatedCveId() {
    Cve2026111497OutboundDetector detector = createDetector();

    ImmutableList<Vulnerability> advisories = detector.getAdvisories();

    assertThat(advisories)
        .containsExactly(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder()
                        .setPublisher("GOOGLE")
                        .setValue("CVE-2026-111497-OUTBOUND"))
                .addRelatedId(
                    VulnerabilityId.newBuilder().setPublisher("CVE").setValue("CVE-2026-111497"))
                .setSeverity(Severity.CRITICAL)
                .setTitle(Cve2026111497OutboundDetector.VULNERABILITY_REPORT_TITLE)
                .setDescription(Cve2026111497OutboundDetector.VULN_DESCRIPTION)
                .setRecommendation(Cve2026111497OutboundDetector.RECOMMENDATION)
                .build());
  }

  @Test
  public void detect_whenCallbackServerDisabled_skipsWithoutSendingRequests() {
    Cve2026111497OutboundDetector detector = createDetectorWithoutCallbackServer();

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(mockWebServer.getRequestCount()).isEqualTo(0);
    assertThat(mockCallbackServer.getRequestCount()).isEqualTo(0);
  }

  @Test
  public void detect_whenVulnerableWordPressInstance_reportsVulnerability() {
    String postUrl = baseServerUrl() + "/2026/10/hello-world/";
    String restJson =
        "[{\"link\":{},\"ping_status\":[]},"
            + "{\"link\":\""
            + postUrl
            + "\",\"ping_status\":\"closed\"},"
            + "{\"link\":\""
            + postUrl
            + "\",\"ping_status\":\"open\"}]";
    SimulatedWordPressDispatcher wpDispatcher =
        SimulatedWordPressDispatcher.builder(baseServerUrl(), callbackHttpClient)
            .setClientMode(ClientMode.VULNERABLE_BROTLI)
            .setRestPostsJson(restJson)
            .setOpenPingbackPostUrls(ImmutableSet.of(postUrl))
            .build();
    mockWebServer.setDispatcher(wpDispatcher);
    Cve2026111497OutboundDetector detector = createDetector();
    TargetInfo target = createTargetInfo();
    NetworkService service = createNetworkService();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                "Vulnerable endpoint: "
                    + baseServerUrl()
                    + "/xmlrpc.php (signal=tcs_pingback_differential, post="
                    + postUrl
                    + ", valid_fault=32, invalid_fault=16, probe_fault=32)"));
    assertThat(wpDispatcher.pingbackSourceUris()).hasSize(5);
    assertThat(wpDispatcher.probeFetches()).isEqualTo(1);
  }

  @Test
  public void detect_whenDefaultWordPressNormalizesFaultCodesToZero_reportsVulnerability() {
    String postUrl = baseServerUrl() + "/?p=1";
    SimulatedWordPressDispatcher wpDispatcher =
        SimulatedWordPressDispatcher.builder(baseServerUrl(), callbackHttpClient)
            .setClientMode(ClientMode.VULNERABLE_BROTLI)
            .setMaskFaultCodes(true)
            .setServerHeader("Apache/2.4.66 (Debian)")
            .setOpenPingbackPostUrls(ImmutableSet.of(postUrl))
            .build();
    mockWebServer.setDispatcher(wpDispatcher);
    Cve2026111497OutboundDetector detector = createDetector();
    TargetInfo target = createTargetInfo();
    NetworkService service = createNetworkService();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                "Vulnerable endpoint: "
                    + baseServerUrl()
                    + "/xmlrpc.php (signal=tcs_pingback_differential, post="
                    + postUrl
                    + ", valid_fault=0, invalid_fault=0, probe_fault=0,"
                    + " server=Apache/2.4.66 (Debian))"));
    assertThat(wpDispatcher.pingbackSourceUris()).hasSize(5);
    assertThat(wpDispatcher.probeFetches()).isEqualTo(1);
  }

  @Test
  public void
      detect_whenServerHeaderContainsControlCharsAndExceedsMaxLength_sanitizesAndTruncatesInEvidence() {
    String postUrl = baseServerUrl() + "/?p=1";
    String rawServerHeader =
        "  envoy/1.30.0\t\t\t(custom-build-identifier-0123456789-abcdefghijklmnopqrstuvwxyz)  ";
    String expectedSanitizedServer =
        "envoy/1.30.0   (custom-build-identifier-0123456789-abcdefghij...";
    SimulatedWordPressDispatcher wpDispatcher =
        SimulatedWordPressDispatcher.builder(baseServerUrl(), callbackHttpClient)
            .setClientMode(ClientMode.VULNERABLE_BROTLI)
            .setServerHeader(rawServerHeader)
            .setOpenPingbackPostUrls(ImmutableSet.of(postUrl))
            .build();
    mockWebServer.setDispatcher(wpDispatcher);
    Cve2026111497OutboundDetector detector = createDetector();
    TargetInfo target = createTargetInfo();
    NetworkService service = createNetworkService();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                "Vulnerable endpoint: "
                    + baseServerUrl()
                    + "/xmlrpc.php (signal=tcs_pingback_differential, post="
                    + postUrl
                    + ", valid_fault=32, invalid_fault=16, probe_fault=32, server="
                    + expectedSanitizedServer
                    + ")"));
  }

  @Test
  public void detect_whenServerHeaderIsBlankAfterSanitization_omitsServerFieldFromEvidence() {
    String postUrl = baseServerUrl() + "/?p=1";
    SimulatedWordPressDispatcher wpDispatcher =
        SimulatedWordPressDispatcher.builder(baseServerUrl(), callbackHttpClient)
            .setClientMode(ClientMode.VULNERABLE_BROTLI)
            .setServerHeader(" \t   \t ")
            .setOpenPingbackPostUrls(ImmutableSet.of(postUrl))
            .build();
    mockWebServer.setDispatcher(wpDispatcher);
    Cve2026111497OutboundDetector detector = createDetector();
    TargetInfo target = createTargetInfo();
    NetworkService service = createNetworkService();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                "Vulnerable endpoint: "
                    + baseServerUrl()
                    + "/xmlrpc.php (signal=tcs_pingback_differential, post="
                    + postUrl
                    + ", valid_fault=32, invalid_fault=16, probe_fault=32)"));
  }

  @Test
  public void detect_whenControlFaultCodesAreUnexpected_reportsEmpty() {
    String postUrl = baseServerUrl() + "/?p=1";
    SimulatedWordPressDispatcher wpDispatcher =
        SimulatedWordPressDispatcher.builder(baseServerUrl(), callbackHttpClient)
            .setClientMode(ClientMode.VULNERABLE_BROTLI_PRIVATE_CALLBACK_RETRY_BLOCKED)
            .setOpenPingbackPostUrls(ImmutableSet.of(postUrl))
            .build();
    mockWebServer.setDispatcher(wpDispatcher);
    Cve2026111497OutboundDetector detector = createDetector();

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    // Aborts after Step 2 when valid and invalid controls both return unmasked fault 16.
    assertThat(wpDispatcher.pingbackSourceUris()).hasSize(2);
    assertThat(wpDispatcher.probeFetches()).isEqualTo(0);
  }

  @Test
  public void isAllowedControlFaultPair_enforcesExpectedMaskedAndUnmaskedCombinations() {
    assertThat(
            Cve2026111497OutboundDetector.isAllowedControlFaultPair(
                0, 0, /* clientRetriesWithoutBr= */ true))
        .isTrue();
    assertThat(
            Cve2026111497OutboundDetector.isAllowedControlFaultPair(
                0, 0, /* clientRetriesWithoutBr= */ false))
        .isFalse();
    assertThat(
            Cve2026111497OutboundDetector.isAllowedControlFaultPair(
                FAULT_PINGBACK_TITLE_MISSING,
                FAULT_PINGBACK_SOURCE_NOT_FOUND,
                /* clientRetriesWithoutBr= */ true))
        .isTrue();
    assertThat(
            Cve2026111497OutboundDetector.isAllowedControlFaultPair(
                FAULT_PINGBACK_TITLE_MISSING,
                FAULT_PINGBACK_SOURCE_NOT_FOUND,
                /* clientRetriesWithoutBr= */ false))
        .isTrue();
    assertThat(
            Cve2026111497OutboundDetector.isAllowedControlFaultPair(
                FAULT_PINGBACK_TARGET_LINK_MISSING,
                FAULT_PINGBACK_SOURCE_NOT_FOUND,
                /* clientRetriesWithoutBr= */ false))
        .isTrue();
    assertThat(
            Cve2026111497OutboundDetector.isAllowedControlFaultPair(
                0, FAULT_PINGBACK_SOURCE_NOT_FOUND, /* clientRetriesWithoutBr= */ true))
        .isFalse();
    assertThat(
            Cve2026111497OutboundDetector.isAllowedControlFaultPair(
                FAULT_PINGBACK_SOURCE_NOT_FOUND, 0, /* clientRetriesWithoutBr= */ true))
        .isFalse();
    assertThat(
            Cve2026111497OutboundDetector.isAllowedControlFaultPair(
                FAULT_PINGBACK_SOURCE_NOT_FOUND,
                FAULT_PINGBACK_SOURCE_NOT_FOUND,
                /* clientRetriesWithoutBr= */ false))
        .isFalse();
    assertThat(
            Cve2026111497OutboundDetector.isAllowedControlFaultPair(
                FAULT_PINGBACK_TITLE_MISSING,
                FAULT_PINGBACK_TITLE_MISSING,
                /* clientRetriesWithoutBr= */ false))
        .isFalse();
    assertThat(
            Cve2026111497OutboundDetector.isAllowedControlFaultPair(
                FAULT_PINGBACK_CLOSED,
                FAULT_PINGBACK_SOURCE_NOT_FOUND,
                /* clientRetriesWithoutBr= */ false))
        .isFalse();
    assertThat(
            Cve2026111497OutboundDetector.isAllowedControlFaultPair(
                48, 48, /* clientRetriesWithoutBr= */ true))
        .isFalse();
  }

  @Test
  public void detect_whenPatchedWordPressRejectsProbeAndRetriesWithNone_reportsEmpty() {
    String postUrl = baseServerUrl() + "/2026/10/hello-world/";
    SimulatedWordPressDispatcher wpDispatcher =
        SimulatedWordPressDispatcher.builder(baseServerUrl(), callbackHttpClient)
            .setClientMode(ClientMode.PATCHED_BROTLI)
            .setRestPostsJson("[{\"link\":\"" + postUrl + "\",\"ping_status\":\"open\"}]")
            .setOpenPingbackPostUrls(ImmutableSet.of(postUrl, baseServerUrl() + "/?p=1"))
            .build();
    mockWebServer.setDispatcher(wpDispatcher);
    Cve2026111497OutboundDetector detector = createDetector();

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    // Stops immediately at Step 3 on the first post without re-testing fallback posts or Step 4.
    assertThat(wpDispatcher.pingbackSourceUris()).hasSize(3);
    assertThat(wpDispatcher.probeFetches()).isEqualTo(1);
  }

  @Test
  public void detect_whenSlowTargetTimesOutAtTailReturningFault16WithoutRetry_reportsEmpty() {
    String postUrl = baseServerUrl() + "/?p=1";
    SimulatedWordPressDispatcher wpDispatcher =
        SimulatedWordPressDispatcher.builder(baseServerUrl(), callbackHttpClient)
            .setClientMode(ClientMode.TIMEOUT_ON_PROBE_WITHOUT_RETRY)
            .setOpenPingbackPostUrls(ImmutableSet.of(postUrl))
            .build();
    mockWebServer.setDispatcher(wpDispatcher);
    Cve2026111497OutboundDetector detector = createDetector();

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(wpDispatcher.pingbackSourceUris()).hasSize(3);
  }

  @Test
  public void detect_whenNonWordPressServerReturns404OnRsd_makesSingleGetAndNeverPollsTcs() {
    List<String> requestedPaths = Collections.synchronizedList(new ArrayList<>());
    mockWebServer.setDispatcher(
        new Dispatcher() {
          @Override
          public MockResponse dispatch(RecordedRequest request) {
            if (request.getPath() != null) {
              requestedPaths.add(request.getPath());
            }
            return new MockResponse()
                .setResponseCode(HttpStatus.NOT_FOUND.code())
                .setBody("Not Found");
          }
        });
    Cve2026111497OutboundDetector detector = createDetector();

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    // 11 XML-RPC system.listMethods POSTs (6 CMS root paths + 5 root-only subdir paths; 404 skips
    // ?rsd) + 1 GET /_next/image = 12
    assertThat(mockWebServer.getRequestCount()).isEqualTo(12);
    assertThat(requestedPaths).contains("/comment.php?type=pingback");
    assertThat(requestedPaths).containsNoneOf("/lib/exe/xmlrpc.php", "/serendipity_xmlrpc.php");
    assertThat(mockCallbackServer.getRequestCount()).isEqualTo(0);
  }

  @Test
  public void detect_whenPingbackDisabledInSystemListMethods_neverPollsTcs() {
    SimulatedWordPressDispatcher wpDispatcher =
        SimulatedWordPressDispatcher.builder(baseServerUrl(), callbackHttpClient)
            .setPingbackMethodListed(false)
            .build();
    mockWebServer.setDispatcher(wpDispatcher);
    Cve2026111497OutboundDetector detector = createDetector();

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(wpDispatcher.pingbackSourceUris()).isEmpty();
    assertThat(mockCallbackServer.getRequestCount()).isEqualTo(0);
  }

  @Test
  public void detect_whenWordPressTransportDoesNotSupportBrotli_abortsAtStep1WithoutProbe() {
    String postUrl = baseServerUrl() + "/?p=1";
    SimulatedWordPressDispatcher wpDispatcher =
        SimulatedWordPressDispatcher.builder(baseServerUrl(), callbackHttpClient)
            .setClientMode(ClientMode.NO_BROTLI_SUPPORT)
            .setOpenPingbackPostUrls(ImmutableSet.of(postUrl))
            .build();
    mockWebServer.setDispatcher(wpDispatcher);
    Cve2026111497OutboundDetector detector = createDetector();

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(wpDispatcher.pingbackSourceUris()).hasSize(1);
    assertThat(wpDispatcher.probeFetches()).isEqualTo(0);
  }

  @Test
  public void detect_whenProxyIgnoresContentEncodingAndNeverRetriesInvalidControl_skipsProbe() {
    String postUrl = baseServerUrl() + "/?p=1";
    SimulatedWordPressDispatcher wpDispatcher =
        SimulatedWordPressDispatcher.builder(baseServerUrl(), callbackHttpClient)
            .setClientMode(ClientMode.PROXY_IGNORING_CONTENT_ENCODING)
            .setOpenPingbackPostUrls(ImmutableSet.of(postUrl))
            .build();
    mockWebServer.setDispatcher(wpDispatcher);
    Cve2026111497OutboundDetector detector = createDetector();

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(wpDispatcher.pingbackSourceUris()).hasSize(2);
    assertThat(wpDispatcher.probeFetches()).isEqualTo(0);
  }

  @Test
  public void
      detect_whenRsdSuppressedWith405AndRestApiDisabled_fallsBackToRss2AndUnescapesEntities() {
    String rssPostUrl = baseServerUrl() + "/?post_type=post&p=5";
    String encodedRssPostUrl = baseServerUrl() + "/?post_type=post&#038;p=5";
    SimulatedWordPressDispatcher wpDispatcher =
        SimulatedWordPressDispatcher.builder(baseServerUrl(), callbackHttpClient)
            .setRsdReturns405Banner(true)
            .setRestApiEnabled(false)
            .setRssFeedXml(
                "<?xml version=\"1.0\"?><rss version=\"2.0\"><channel>"
                    + "<title>Blog</title><link>"
                    + baseServerUrl()
                    + "</link>"
                    + "<item><title>Post</title><link>"
                    + encodedRssPostUrl
                    + "</link></item>"
                    + "</channel></rss>")
            .setClientMode(ClientMode.VULNERABLE_BROTLI)
            .setOpenPingbackPostUrls(ImmutableSet.of(rssPostUrl))
            .build();
    mockWebServer.setDispatcher(wpDispatcher);
    Cve2026111497OutboundDetector detector = createDetector();
    TargetInfo target = createTargetInfo();
    NetworkService service = createNetworkService();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                "Vulnerable endpoint: "
                    + baseServerUrl()
                    + "/xmlrpc.php (signal=tcs_pingback_differential, post="
                    + rssPostUrl
                    + ", valid_fault=32, invalid_fault=16, probe_fault=32)"));
    assertThat(wpDispatcher.pingbackTargetUris()).contains(rssPostUrl);
  }

  @Test
  public void
      detect_whenFirstPostHasPingbacksClosed_fallsBackToDefaultHelloWorldPostAndReportsVuln() {
    String closedPostUrl = baseServerUrl() + "/2026/10/closed-pingbacks/";
    String defaultHelloWorldUrl = baseServerUrl() + "/?p=1";
    SimulatedWordPressDispatcher wpDispatcher =
        SimulatedWordPressDispatcher.builder(baseServerUrl(), callbackHttpClient)
            .setRestPostsJson("[{\"link\":\"" + closedPostUrl + "\",\"ping_status\":\"open\"}]")
            .setClientMode(ClientMode.VULNERABLE_BROTLI)
            .setOpenPingbackPostUrls(ImmutableSet.of(defaultHelloWorldUrl))
            .build();
    mockWebServer.setDispatcher(wpDispatcher);
    Cve2026111497OutboundDetector detector = createDetector();
    TargetInfo target = createTargetInfo();
    NetworkService service = createNetworkService();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                "Vulnerable endpoint: "
                    + baseServerUrl()
                    + "/xmlrpc.php (signal=tcs_pingback_differential, post="
                    + defaultHelloWorldUrl
                    + ", valid_fault=32, invalid_fault=16, probe_fault=32)"));
    assertThat(wpDispatcher.pingbackTargetUris().get(0)).isEqualTo(closedPostUrl);
    assertThat(wpDispatcher.pingbackTargetUris().get(1)).isEqualTo(defaultHelloWorldUrl);
  }

  @Test
  public void
      detect_whenWordPressInstalledUnderCrawledSubpath_ignoresQueryMarkersAndFindsSubpath() {
    String wpSubRoot = baseServerUrl() + "/blog";
    String subPostUrl = wpSubRoot + "/?p=1";
    String redirectWithMarkerInQuery =
        baseServerUrl() + "/sso?redirect_to=" + wpSubRoot + "/wp-login.php";
    String crawledAssetUrl = wpSubRoot + "/wp-content/themes/twentytwentyfive/style.css?ver=1.0";
    SimulatedWordPressDispatcher wpDispatcher =
        SimulatedWordPressDispatcher.builder(wpSubRoot, callbackHttpClient)
            .setMountPathPrefix("/blog")
            .setClientMode(ClientMode.VULNERABLE_BROTLI)
            .setOpenPingbackPostUrls(ImmutableSet.of(subPostUrl))
            .build();
    mockWebServer.setDispatcher(wpDispatcher);
    Cve2026111497OutboundDetector detector = createDetector();
    TargetInfo target = createTargetInfo();
    NetworkService service =
        createNetworkService().toBuilder()
            .setServiceContext(
                ServiceContext.newBuilder()
                    .setWebServiceContext(
                        WebServiceContext.newBuilder()
                            .addCrawlResults(
                                CrawlResult.newBuilder()
                                    .setCrawlTarget(
                                        CrawlTarget.newBuilder()
                                            .setUrl(redirectWithMarkerInQuery)
                                            .setHttpMethod("GET")))
                            .addCrawlResults(
                                CrawlResult.newBuilder()
                                    .setCrawlTarget(
                                        CrawlTarget.newBuilder()
                                            .setUrl(crawledAssetUrl)
                                            .setHttpMethod("GET")))))
            .build();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                "Vulnerable endpoint: "
                    + wpSubRoot
                    + "/xmlrpc.php (signal=tcs_pingback_differential, post="
                    + subPostUrl
                    + ", valid_fault=32, invalid_fault=16, probe_fault=32)"));
  }

  @Test
  public void detect_whenPostProbeStep4InvalidControlFailsDeterminism_reportsEmpty() {
    String postUrl = baseServerUrl() + "/?p=1";
    SimulatedWordPressDispatcher wpDispatcher =
        SimulatedWordPressDispatcher.builder(baseServerUrl(), callbackHttpClient)
            .setClientMode(ClientMode.INCONSISTENT_STEP4)
            .setOpenPingbackPostUrls(ImmutableSet.of(postUrl))
            .build();
    mockWebServer.setDispatcher(wpDispatcher);
    Cve2026111497OutboundDetector detector = createDetector();

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(wpDispatcher.pingbackSourceUris()).hasSize(5);
  }

  @Test
  public void detect_whenPingbackDisabledInSystemListMethodsEvenWith405BannerOnRsd_neverPollsTcs() {
    SimulatedWordPressDispatcher wpDispatcher =
        SimulatedWordPressDispatcher.builder(baseServerUrl(), callbackHttpClient)
            .setPingbackMethodListed(false)
            .setRsdReturns405Banner(true)
            .build();
    mockWebServer.setDispatcher(wpDispatcher);
    Cve2026111497OutboundDetector detector = createDetector();

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(wpDispatcher.pingbackSourceUris()).isEmpty();
    assertThat(mockCallbackServer.getRequestCount()).isEqualTo(0);
  }

  @Test
  public void
      detect_whenHardenedWordPressBlocksSystemListMethodsWith403_fallsBackToRsdAndReportsVuln() {
    String postUrl = baseServerUrl() + "/?p=1";
    SimulatedWordPressDispatcher wpDispatcher =
        SimulatedWordPressDispatcher.builder(baseServerUrl(), callbackHttpClient)
            .setSystemListMethodsResponseStatus(HttpStatus.FORBIDDEN.code())
            .setClientMode(ClientMode.VULNERABLE_BROTLI)
            .setOpenPingbackPostUrls(ImmutableSet.of(postUrl))
            .build();
    mockWebServer.setDispatcher(wpDispatcher);
    Cve2026111497OutboundDetector detector = createDetector();
    TargetInfo target = createTargetInfo();
    NetworkService service = createNetworkService();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                "Vulnerable endpoint: "
                    + baseServerUrl()
                    + "/xmlrpc.php (signal=tcs_pingback_differential, post="
                    + postUrl
                    + ", valid_fault=32, invalid_fault=16, probe_fault=32)"));
  }

  @Test
  public void
      detect_whenHardenedWordPressReturnsXmlFaultOnSystemListMethodsAnd405Banner_reportsVuln() {
    String postUrl = baseServerUrl() + "/?p=1";
    SimulatedWordPressDispatcher wpDispatcher =
        SimulatedWordPressDispatcher.builder(baseServerUrl(), callbackHttpClient)
            .setSystemListMethodsReturnsXmlFault(true)
            .setRsdReturns405Banner(true)
            .setClientMode(ClientMode.VULNERABLE_BROTLI)
            .setOpenPingbackPostUrls(ImmutableSet.of(postUrl))
            .build();
    mockWebServer.setDispatcher(wpDispatcher);
    Cve2026111497OutboundDetector detector = createDetector();
    TargetInfo target = createTargetInfo();
    NetworkService service = createNetworkService();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                "Vulnerable endpoint: "
                    + baseServerUrl()
                    + "/xmlrpc.php (signal=tcs_pingback_differential, post="
                    + postUrl
                    + ", valid_fault=32, invalid_fault=16, probe_fault=32)"));
  }

  @Test
  public void detect_whenDrupalServicesXmlRpcWithRssXmlAndNonRetryingClient_reportsVulnerability() {
    String drupalNodeUrl = baseServerUrl() + "/node/42";
    SimulatedWordPressDispatcher drupalDispatcher =
        SimulatedWordPressDispatcher.builder(baseServerUrl(), callbackHttpClient)
            .setXmlRpcRelativePath("/services/xmlrpc")
            .setRsdEnabled(false)
            .setIncludeWpGetUsersBlogs(false)
            .setRestApiEnabled(false)
            .setRssFeedPath("/rss.xml")
            .setRssFeedXml(
                "<?xml version=\"1.0\"?><rss version=\"2.0\"><channel>"
                    + "<title>Drupal Site</title><link>"
                    + baseServerUrl()
                    + "</link>"
                    + "<item><title>Story</title><link>"
                    + drupalNodeUrl
                    + "</link></item>"
                    + "</channel></rss>")
            .setRetryWithNoneOnFailure(false)
            .setClientMode(ClientMode.VULNERABLE_BROTLI)
            .setOpenPingbackPostUrls(ImmutableSet.of(drupalNodeUrl))
            .build();
    mockWebServer.setDispatcher(drupalDispatcher);
    Cve2026111497OutboundDetector detector = createDetector();
    TargetInfo target = createTargetInfo();
    NetworkService service = createNetworkService();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                "Vulnerable endpoint: "
                    + baseServerUrl()
                    + "/services/xmlrpc (signal=tcs_pingback_differential, post="
                    + drupalNodeUrl
                    + ", valid_fault=32, invalid_fault=16, probe_fault=32)"));
    assertThat(drupalDispatcher.pingbackSourceUris()).hasSize(5);
    assertThat(drupalDispatcher.probeFetches()).isEqualTo(1);
  }

  @Test
  public void
      detect_whenDrupalRootXmlRpcFallsBackToNode1WithFault17Differential_reportsVulnerability() {
    String drupalDefaultNode = baseServerUrl() + "/node/1";
    SimulatedWordPressDispatcher drupalDispatcher =
        SimulatedWordPressDispatcher.builder(baseServerUrl(), callbackHttpClient)
            .setXmlRpcRelativePath("/xmlrpc.php")
            .setRsdEnabled(false)
            .setIncludeWpGetUsersBlogs(false)
            .setRestApiEnabled(false)
            .setRetryWithNoneOnFailure(false)
            .setValidSuccessFaultCode(FAULT_PINGBACK_TARGET_LINK_MISSING)
            .setClientMode(ClientMode.VULNERABLE_BROTLI)
            .setOpenPingbackPostUrls(ImmutableSet.of(drupalDefaultNode))
            .build();
    mockWebServer.setDispatcher(drupalDispatcher);
    Cve2026111497OutboundDetector detector = createDetector();
    TargetInfo target = createTargetInfo();
    NetworkService service = createNetworkService();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                "Vulnerable endpoint: "
                    + baseServerUrl()
                    + "/xmlrpc.php (signal=tcs_pingback_differential, post="
                    + drupalDefaultNode
                    + ", valid_fault=17, invalid_fault=16, probe_fault=17)"));
    assertThat(drupalDispatcher.pingbackTargetUris()).contains(drupalDefaultNode);
  }

  @Test
  public void detect_whenNonWordPressCmsCandidatePathsAdvertisePingback_reportsVulnerability() {
    ImmutableList<String> nonWordPressPaths =
        ImmutableList.of(
            "/xmlsrv/xmlrpc.php",
            "/comment.php?type=pingback",
            "/mt-xmlrpc.cgi",
            "/tiki-xmlrpc.php");
    for (String xmlRpcPath : nonWordPressPaths) {
      String crawledArticleUrl = baseServerUrl() + "/articles/welcome";
      SimulatedWordPressDispatcher cmsDispatcher =
          SimulatedWordPressDispatcher.builder(baseServerUrl(), callbackHttpClient)
              .setXmlRpcRelativePath(xmlRpcPath)
              .setRsdEnabled(false)
              .setIncludeWpGetUsersBlogs(false)
              .setRestApiEnabled(false)
              .setRetryWithNoneOnFailure(false)
              .setClientMode(ClientMode.VULNERABLE_BROTLI)
              .setOpenPingbackPostUrls(ImmutableSet.of(crawledArticleUrl))
              .build();
      mockWebServer.setDispatcher(cmsDispatcher);
      Cve2026111497OutboundDetector detector = createDetector();
      TargetInfo target = createTargetInfo();
      NetworkService service =
          createNetworkService().toBuilder()
              .setServiceContext(
                  ServiceContext.newBuilder()
                      .setWebServiceContext(
                          WebServiceContext.newBuilder()
                              .addCrawlResults(
                                  CrawlResult.newBuilder()
                                      .setResponseCode(HttpStatus.OK.code())
                                      .setCrawlTarget(
                                          CrawlTarget.newBuilder()
                                              .setUrl(crawledArticleUrl)
                                              .setHttpMethod("GET")))))
              .build();

      DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

      assertThat(reports.getDetectionReportsList())
          .containsExactly(
              buildExpectedDetectionReport(
                  target,
                  service,
                  "Vulnerable endpoint: "
                      + baseServerUrl()
                      + xmlRpcPath
                      + " (signal=tcs_pingback_differential, post="
                      + crawledArticleUrl
                      + ", valid_fault=32, invalid_fault=16, probe_fault=32)"));
    }
  }

  @Test
  public void
      detect_whenCrawledDokuWikiLinkbackXPingbackHeaderAndBlockedListMethodsFallsBackTo405Banner_reportsVuln() {
    String wikiPostUrl = baseServerUrl() + "/wiki/doku.php?id=start";
    String linkbackPath = "/lib/plugins/linkback/exe/pingback.php/start";
    String linkbackUrl = baseServerUrl() + "/wiki" + linkbackPath;
    SimulatedWordPressDispatcher dokuDispatcher =
        SimulatedWordPressDispatcher.builder(baseServerUrl() + "/wiki", callbackHttpClient)
            .setMountPathPrefix("/wiki")
            .setXmlRpcRelativePath(linkbackPath)
            .setSystemListMethodsResponseStatus(HttpStatus.FORBIDDEN.code())
            .setRsdReturns405Banner(true)
            .setRestApiEnabled(false)
            .setRetryWithNoneOnFailure(false)
            .setClientMode(ClientMode.VULNERABLE_BROTLI)
            .setOpenPingbackPostUrls(ImmutableSet.of(wikiPostUrl))
            .build();
    mockWebServer.setDispatcher(dokuDispatcher);
    Cve2026111497OutboundDetector detector = createDetector();
    TargetInfo target = createTargetInfo();
    NetworkService service =
        createNetworkService().toBuilder()
            .setServiceContext(
                ServiceContext.newBuilder()
                    .setWebServiceContext(
                        WebServiceContext.newBuilder()
                            .addCrawlResults(
                                CrawlResult.newBuilder()
                                    .setResponseCode(HttpStatus.OK.code())
                                    .setCrawlTarget(
                                        CrawlTarget.newBuilder()
                                            .setUrl(wikiPostUrl)
                                            .setHttpMethod("GET"))
                                    .addResponseHeaders(
                                        HttpHeader.newBuilder()
                                            .setKey("X-Pingback")
                                            .setValue(linkbackUrl)))))
            .build();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                "Vulnerable endpoint: "
                    + linkbackUrl
                    + " (signal=tcs_pingback_differential, post="
                    + wikiPostUrl
                    + ", valid_fault=32, invalid_fault=16, probe_fault=32)"));
  }

  @Test
  public void detect_whenNonRetryingClientHasPatchedBrotliReturningFault16OnProbe_reportsEmpty() {
    String postUrl = baseServerUrl() + "/node/1";
    SimulatedWordPressDispatcher cmsDispatcher =
        SimulatedWordPressDispatcher.builder(baseServerUrl(), callbackHttpClient)
            .setXmlRpcRelativePath("/services/xmlrpc")
            .setRsdEnabled(false)
            .setIncludeWpGetUsersBlogs(false)
            .setRestApiEnabled(false)
            .setRetryWithNoneOnFailure(false)
            .setClientMode(ClientMode.PATCHED_BROTLI)
            .setOpenPingbackPostUrls(ImmutableSet.of(postUrl))
            .build();
    mockWebServer.setDispatcher(cmsDispatcher);
    Cve2026111497OutboundDetector detector = createDetector();

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    // 1 call on closed fallback /?p=1 + 3 calls (valid, invalid, probe) on /node/1 = 4
    assertThat(cmsDispatcher.pingbackSourceUris()).hasSize(4);
    assertThat(cmsDispatcher.probeFetches()).isEqualTo(1);
  }

  @Test
  public void detect_whenNonRetryingClientMasksAllFaultCodesToZero_abortsAtStep2WithoutProbe() {
    String postUrl = baseServerUrl() + "/?p=1";
    SimulatedWordPressDispatcher cmsDispatcher =
        SimulatedWordPressDispatcher.builder(baseServerUrl(), callbackHttpClient)
            .setMaskFaultCodes(true)
            .setRetryWithNoneOnFailure(false)
            .setClientMode(ClientMode.VULNERABLE_BROTLI)
            .setOpenPingbackPostUrls(ImmutableSet.of(postUrl))
            .build();
    mockWebServer.setDispatcher(cmsDispatcher);
    Cve2026111497OutboundDetector detector = createDetector();

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(cmsDispatcher.pingbackSourceUris()).hasSize(2);
    assertThat(cmsDispatcher.probeFetches()).isEqualTo(0);
  }

  @Test
  public void detect_whenVulnerableNextJsImageOptimizer_reportsVulnerability() {
    SimulatedNextJsImageDispatcher nextDispatcher =
        SimulatedNextJsImageDispatcher.builder(callbackHttpClient)
            .setMode(NextJsMode.VULNERABLE)
            .setInvalidStreamStatusCode(HttpStatus.INTERNAL_SERVER_ERROR.code())
            .build();
    mockWebServer.setDispatcher(nextDispatcher);
    Cve2026111497OutboundDetector detector = createDetector();
    TargetInfo target = createTargetInfo();
    NetworkService service = createNetworkService();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                "Vulnerable endpoint: "
                    + baseServerUrl()
                    + "/_next/image (signal=tcs_nextjs_image_differential,"
                    + " valid_status=400, invalid_status=500, probe_status=400)"));
    assertThat(nextDispatcher.fetchedSourceUris()).hasSize(5);
    assertThat(nextDispatcher.probeFetches()).isEqualTo(1);
  }

  @Test
  public void
      detect_whenVulnerableNextJsUnderCrawledSubpathReturns502OnInvalid_reportsVulnerability() {
    SimulatedNextJsImageDispatcher nextDispatcher =
        SimulatedNextJsImageDispatcher.builder(callbackHttpClient)
            .setMountPathPrefix("/app")
            .setMode(NextJsMode.VULNERABLE)
            .setInvalidStreamStatusCode(HttpStatus.BAD_GATEWAY.code())
            .setServerHeader("Vercel")
            .build();
    mockWebServer.setDispatcher(nextDispatcher);
    Cve2026111497OutboundDetector detector = createDetector();
    TargetInfo target = createTargetInfo();
    NetworkService service =
        createNetworkService().toBuilder()
            .setServiceContext(
                ServiceContext.newBuilder()
                    .setWebServiceContext(
                        WebServiceContext.newBuilder()
                            .addCrawlResults(
                                CrawlResult.newBuilder()
                                    .setCrawlTarget(
                                        CrawlTarget.newBuilder()
                                            .setUrl(
                                                baseServerUrl()
                                                    + "/app/_next/static/chunks/main.js")
                                            .setHttpMethod("GET")))))
            .build();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                "Vulnerable endpoint: "
                    + baseServerUrl()
                    + "/app/_next/image (signal=tcs_nextjs_image_differential,"
                    + " valid_status=400, invalid_status=502, probe_status=400, server=Vercel)"));
    assertThat(nextDispatcher.fetchedSourceUris()).hasSize(5);
    assertThat(nextDispatcher.probeFetches()).isEqualTo(1);
  }

  @Test
  public void detect_whenPatchedNextJsImageOptimizerRejectsProbeWith500Or502_reportsEmpty() {
    for (int errorStatus :
        ImmutableList.of(HttpStatus.INTERNAL_SERVER_ERROR.code(), HttpStatus.BAD_GATEWAY.code())) {
      SimulatedNextJsImageDispatcher nextDispatcher =
          SimulatedNextJsImageDispatcher.builder(callbackHttpClient)
              .setMode(NextJsMode.PATCHED)
              .setInvalidStreamStatusCode(errorStatus)
              .build();
      mockWebServer.setDispatcher(nextDispatcher);
      Cve2026111497OutboundDetector detector = createDetector();

      DetectionReportList reports =
          detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

      assertThat(reports.getDetectionReportsList()).isEmpty();
      assertThat(nextDispatcher.fetchedSourceUris()).hasSize(3);
      assertThat(nextDispatcher.probeFetches()).isEqualTo(1);
    }
  }

  @Test
  public void
      detect_whenNextJsImageOptimizerRejectsExternalUrlDomainWithoutFetchingTcs_abortsAtStep1() {
    SimulatedNextJsImageDispatcher nextDispatcher =
        SimulatedNextJsImageDispatcher.builder(callbackHttpClient)
            .setMode(NextJsMode.DOMAIN_RESTRICTED_NO_FETCH)
            .build();
    mockWebServer.setDispatcher(nextDispatcher);
    Cve2026111497OutboundDetector detector = createDetector();

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(nextDispatcher.fetchedSourceUris()).isEmpty();
    assertThat(nextDispatcher.probeFetches()).isEqualTo(0);
  }

  @Test
  public void
      detect_whenNextJsImageFetchesInvalidControlWithoutDecompressingAndReturns400_abortsAtStep2() {
    SimulatedNextJsImageDispatcher nextDispatcher =
        SimulatedNextJsImageDispatcher.builder(callbackHttpClient)
            .setMode(NextJsMode.NO_DECOMPRESSION_ALWAYS_400)
            .build();
    mockWebServer.setDispatcher(nextDispatcher);
    Cve2026111497OutboundDetector detector = createDetector();

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(nextDispatcher.fetchedSourceUris()).hasSize(2);
    assertThat(nextDispatcher.probeFetches()).isEqualTo(0);
  }

  @Test
  public void detect_whenNextJsImageReturns500OnInvalidControlWithoutFetchingTcs_abortsAtStep2() {
    SimulatedNextJsImageDispatcher nextDispatcher =
        SimulatedNextJsImageDispatcher.builder(callbackHttpClient)
            .setMode(NextJsMode.STEP2_NO_FETCH_500)
            .build();
    mockWebServer.setDispatcher(nextDispatcher);
    Cve2026111497OutboundDetector detector = createDetector();

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(nextDispatcher.fetchedSourceUris()).hasSize(1);
    assertThat(nextDispatcher.probeFetches()).isEqualTo(0);
  }

  @Test
  public void detect_whenNextJsImageStep4ValidControlFailsDeterminism_reportsEmpty() {
    SimulatedNextJsImageDispatcher nextDispatcher =
        SimulatedNextJsImageDispatcher.builder(callbackHttpClient)
            .setMode(NextJsMode.INCONSISTENT_STEP4_VALID_500)
            .build();
    mockWebServer.setDispatcher(nextDispatcher);
    Cve2026111497OutboundDetector detector = createDetector();

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(nextDispatcher.fetchedSourceUris()).hasSize(5);
    assertThat(nextDispatcher.probeFetches()).isEqualTo(1);
  }

  @Test
  public void detect_whenNextJsImageStep4InvalidControlReturns400_reportsEmpty() {
    SimulatedNextJsImageDispatcher nextDispatcher =
        SimulatedNextJsImageDispatcher.builder(callbackHttpClient)
            .setMode(NextJsMode.INCONSISTENT_STEP4_INVALID_400)
            .build();
    mockWebServer.setDispatcher(nextDispatcher);
    Cve2026111497OutboundDetector detector = createDetector();

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(nextDispatcher.fetchedSourceUris()).hasSize(5);
    assertThat(nextDispatcher.probeFetches()).isEqualTo(1);
  }

  @Test
  public void detect_whenNextJsImageStep4InvalidControlDriftsFrom500To502_reportsEmpty() {
    SimulatedNextJsImageDispatcher nextDispatcher =
        SimulatedNextJsImageDispatcher.builder(callbackHttpClient)
            .setMode(NextJsMode.INCONSISTENT_STEP4_INVALID_STATUS_DRIFT)
            .setInvalidStreamStatusCode(HttpStatus.INTERNAL_SERVER_ERROR.code())
            .build();
    mockWebServer.setDispatcher(nextDispatcher);
    Cve2026111497OutboundDetector detector = createDetector();

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(nextDispatcher.fetchedSourceUris()).hasSize(5);
    assertThat(nextDispatcher.probeFetches()).isEqualTo(1);
  }

  @Test
  public void
      detect_whenDrupalSubpathHasCoreModulesAsset_resolvesDrupalRootInsteadOfCoreAndSkipsNestedSubdirs() {
    String drupalSubRoot = baseServerUrl() + "/portal";
    String coreModuleCss =
        drupalSubRoot + "/core/modules/system/css/components/align.module.css?v=10.3";
    String rootCoreModuleCss = baseServerUrl() + "/core/modules/user/user.module.css";
    String drupalPostUrl = drupalSubRoot + "/node/7";
    SimulatedWordPressDispatcher drupalDispatcher =
        SimulatedWordPressDispatcher.builder(drupalSubRoot, callbackHttpClient)
            .setMountPathPrefix("/portal")
            .setXmlRpcRelativePath("/xmlrpc.php")
            .setRsdEnabled(false)
            .setIncludeWpGetUsersBlogs(false)
            .setRestApiEnabled(false)
            .setRetryWithNoneOnFailure(false)
            .setClientMode(ClientMode.VULNERABLE_BROTLI)
            .setOpenPingbackPostUrls(ImmutableSet.of(drupalPostUrl))
            .build();
    mockWebServer.setDispatcher(drupalDispatcher);
    Cve2026111497OutboundDetector detector = createDetector();
    TargetInfo target = createTargetInfo();
    NetworkService service =
        createNetworkService().toBuilder()
            .setServiceContext(
                ServiceContext.newBuilder()
                    .setWebServiceContext(
                        WebServiceContext.newBuilder()
                            .addCrawlResults(
                                CrawlResult.newBuilder()
                                    .setResponseCode(HttpStatus.OK.code())
                                    .setCrawlTarget(
                                        CrawlTarget.newBuilder()
                                            .setUrl(rootCoreModuleCss)
                                            .setHttpMethod("GET")))
                            .addCrawlResults(
                                CrawlResult.newBuilder()
                                    .setResponseCode(HttpStatus.OK.code())
                                    .setCrawlTarget(
                                        CrawlTarget.newBuilder()
                                            .setUrl(coreModuleCss)
                                            .setHttpMethod("GET")))
                            .addCrawlResults(
                                CrawlResult.newBuilder()
                                    .setResponseCode(HttpStatus.OK.code())
                                    .setCrawlTarget(
                                        CrawlTarget.newBuilder()
                                            .setUrl(drupalPostUrl)
                                            .setHttpMethod("GET")))))
            .build();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                "Vulnerable endpoint: "
                    + drupalSubRoot
                    + "/xmlrpc.php (signal=tcs_pingback_differential, post="
                    + drupalPostUrl
                    + ", valid_fault=32, invalid_fault=16, probe_fault=32)"));
    assertThat(drupalDispatcher.requestedPaths())
        .containsNoneOf(
            "/core/xmlrpc.php",
            "/portal/core/xmlrpc.php",
            "/portal/wordpress/xmlrpc.php",
            "/portal/wp/xmlrpc.php",
            "/portal/blog/xmlrpc.php",
            "/portal/drupal/xmlrpc.php",
            "/portal/cms/xmlrpc.php");
  }

  @Test
  public void
      detect_whenWordPressInstalledInUncrawledSubdirectory_resolvesSubdirRootAndReportsVuln() {
    String wpSubdirRoot = baseServerUrl() + "/wordpress";
    String subdirPostUrl = wpSubdirRoot + "/?p=1";
    SimulatedWordPressDispatcher wpDispatcher =
        SimulatedWordPressDispatcher.builder(wpSubdirRoot, callbackHttpClient)
            .setMountPathPrefix("/wordpress")
            .setClientMode(ClientMode.VULNERABLE_BROTLI)
            .setOpenPingbackPostUrls(ImmutableSet.of(subdirPostUrl))
            .build();
    mockWebServer.setDispatcher(wpDispatcher);
    Cve2026111497OutboundDetector detector = createDetector();
    TargetInfo target = createTargetInfo();
    NetworkService service = createNetworkService();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                "Vulnerable endpoint: "
                    + wpSubdirRoot
                    + "/xmlrpc.php (signal=tcs_pingback_differential, post="
                    + subdirPostUrl
                    + ", valid_fault=32, invalid_fault=16, probe_fault=32)"));
    assertThat(wpDispatcher.requestedPaths()).contains("/wordpress/wp-json/wp/v2/posts?per_page=5");
  }

  @Test
  public void
      detect_whenSerendipityCommentPingbackReturnsXmlFaultOnListMethods_usesAmpersandRsdAndReportsVuln() {
    String s9yEntryUrl = baseServerUrl() + "/archives/1-Hello.html";
    SimulatedWordPressDispatcher s9yDispatcher =
        SimulatedWordPressDispatcher.builder(baseServerUrl(), callbackHttpClient)
            .setXmlRpcRelativePath("/comment.php?type=pingback")
            .setSystemListMethodsReturnsXmlFault(true)
            .setRsdEnabled(false)
            .setIncludeWpGetUsersBlogs(false)
            .setRestApiEnabled(false)
            .setRetryWithNoneOnFailure(false)
            .setClientMode(ClientMode.VULNERABLE_BROTLI)
            .setOpenPingbackPostUrls(ImmutableSet.of(s9yEntryUrl))
            .build();
    mockWebServer.setDispatcher(s9yDispatcher);
    Cve2026111497OutboundDetector detector = createDetector();
    TargetInfo target = createTargetInfo();
    NetworkService service =
        createNetworkService().toBuilder()
            .setServiceContext(
                ServiceContext.newBuilder()
                    .setWebServiceContext(
                        WebServiceContext.newBuilder()
                            .addCrawlResults(
                                CrawlResult.newBuilder()
                                    .setResponseCode(HttpStatus.OK.code())
                                    .setCrawlTarget(
                                        CrawlTarget.newBuilder()
                                            .setUrl(s9yEntryUrl)
                                            .setHttpMethod("GET")))))
            .build();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                "Vulnerable endpoint: "
                    + baseServerUrl()
                    + "/comment.php?type=pingback (signal=tcs_pingback_differential, post="
                    + s9yEntryUrl
                    + ", valid_fault=32, invalid_fault=16, probe_fault=32)"));
    assertThat(s9yDispatcher.requestedPaths()).contains("/comment.php?type=pingback&rsd");
    assertThat(s9yDispatcher.requestedPaths()).doesNotContain("/comment.php?type=pingback?rsd");
  }

  @Test
  public void
      detect_whenDokuWikiRootPageAdvertisesRelativeLinkbackXPingback_derivesPostFromPageId() {
    String linkbackRelativeHeader = "lib/plugins/linkback/exe/pingback.php/wiki:welcome";
    String linkbackPath = "/lib/plugins/linkback/exe/pingback.php/wiki:welcome";
    String expectedLinkbackUrl = baseServerUrl() + "/wiki" + linkbackPath;
    String expectedDerivedPostUrl = baseServerUrl() + "/wiki/doku.php?id=wiki:welcome";
    SimulatedWordPressDispatcher dokuDispatcher =
        SimulatedWordPressDispatcher.builder(baseServerUrl() + "/wiki", callbackHttpClient)
            .setMountPathPrefix("/wiki")
            .setXmlRpcRelativePath(linkbackPath)
            .setSystemListMethodsReturnsXmlFault(true)
            .setRsdEnabled(false)
            .setRestApiEnabled(false)
            .setRetryWithNoneOnFailure(false)
            .setClientMode(ClientMode.VULNERABLE_BROTLI)
            .setOpenPingbackPostUrls(ImmutableSet.of(expectedDerivedPostUrl))
            .build();
    mockWebServer.setDispatcher(dokuDispatcher);
    Cve2026111497OutboundDetector detector = createDetector();
    TargetInfo target = createTargetInfo();
    NetworkService service =
        createNetworkService().toBuilder()
            .setServiceContext(
                ServiceContext.newBuilder()
                    .setWebServiceContext(
                        WebServiceContext.newBuilder()
                            .addCrawlResults(
                                CrawlResult.newBuilder()
                                    .setResponseCode(HttpStatus.OK.code())
                                    .setCrawlTarget(
                                        CrawlTarget.newBuilder()
                                            .setUrl(baseServerUrl() + "/wiki/")
                                            .setHttpMethod("GET"))
                                    .addResponseHeaders(
                                        HttpHeader.newBuilder()
                                            .setKey("x-pingback")
                                            .setValue("  " + linkbackRelativeHeader + "  ")))))
            .build();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                "Vulnerable endpoint: "
                    + expectedLinkbackUrl
                    + " (signal=tcs_pingback_differential, post="
                    + expectedDerivedPostUrl
                    + ", valid_fault=32, invalid_fault=16, probe_fault=32)"));
  }

  @Test
  public void normalizeSameOriginPingbackUrl_rejectsCrossOriginPortSchemeUserInfoAndTraversal()
      throws Exception {
    URI httpRootUri = new URI("http://example.com/app/");
    String httpRootUrl = "http://example.com/app/";

    assertThat(
            Cve2026111497OutboundDetector.normalizeSameOriginPingbackUrl(
                "http://evil.example.org/app/xmlrpc.php",
                "http://example.com/app/page",
                httpRootUri,
                httpRootUrl))
        .isEmpty();
    assertThat(
            Cve2026111497OutboundDetector.normalizeSameOriginPingbackUrl(
                "http://example.com:8080/app/xmlrpc.php",
                "http://example.com/app/page",
                httpRootUri,
                httpRootUrl))
        .isEmpty();
    assertThat(
            Cve2026111497OutboundDetector.normalizeSameOriginPingbackUrl(
                "https://example.com/app/xmlrpc.php",
                "http://example.com/app/page",
                httpRootUri,
                httpRootUrl))
        .isEmpty();
    assertThat(
            Cve2026111497OutboundDetector.normalizeSameOriginPingbackUrl(
                "http://user:pass@example.com/app/xmlrpc.php",
                "http://example.com/app/page",
                httpRootUri,
                httpRootUrl))
        .isEmpty();
    assertThat(
            Cve2026111497OutboundDetector.normalizeSameOriginPingbackUrl(
                "http://example.com/app/../../outside/xmlrpc.php",
                "http://example.com/app/page",
                httpRootUri,
                httpRootUrl))
        .isEmpty();
    assertThat(
            Cve2026111497OutboundDetector.normalizeSameOriginPingbackUrl(
                "http://example.com/other/xmlrpc.php",
                "http://example.com/app/page",
                httpRootUri,
                httpRootUrl))
        .isEmpty();
    assertThat(
            Cve2026111497OutboundDetector.normalizeSameOriginPingbackUrl(
                "   ", "http://example.com/app/page", httpRootUri, httpRootUrl))
        .isEmpty();

    assertThat(
            Cve2026111497OutboundDetector.normalizeSameOriginPingbackUrl(
                "http://EXAMPLE.COM:80/app/comment.php?type=pingback#frag",
                "http://example.com/app/page",
                httpRootUri,
                httpRootUrl))
        .hasValue("http://example.com/app/comment.php?type=pingback");
    assertThat(
            Cve2026111497OutboundDetector.normalizeSameOriginPingbackUrl(
                "//example.com/app/custom-pingback",
                "http://example.com/app/page",
                httpRootUri,
                httpRootUrl))
        .hasValue("http://example.com/app/custom-pingback");
  }

  @Test
  public void
      detect_whenCrawlResultsContainUntrustedXPingbackHeaders_ignoresThemWithoutContactingCrossPort()
          throws IOException {
    try (MockWebServer crossPortServer = new MockWebServer()) {
      crossPortServer.start(LOOPBACK_ADDRESS, 0);
      crossPortServer.setDispatcher(
          new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
              return new MockResponse().setResponseCode(HttpStatus.OK.code());
            }
          });
      mockWebServer.setDispatcher(
          new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
              return new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code());
            }
          });

      NetworkService service =
          createNetworkService().toBuilder()
              .setServiceContext(
                  ServiceContext.newBuilder()
                      .setWebServiceContext(
                          WebServiceContext.newBuilder()
                              .addCrawlResults(
                                  CrawlResult.newBuilder()
                                      .setResponseCode(HttpStatus.OK.code())
                                      .setCrawlTarget(
                                          CrawlTarget.newBuilder()
                                              .setUrl(baseServerUrl() + "/page")
                                              .setHttpMethod("GET"))
                                      .addResponseHeaders(
                                          HttpHeader.newBuilder()
                                              .setKey("X-Pingback")
                                              .setValue(
                                                  "http://127.0.0.1:"
                                                      + crossPortServer.getPort()
                                                      + "/xmlrpc.php"))
                                      .addResponseHeaders(
                                          HttpHeader.newBuilder()
                                              .setKey("X-Pingback")
                                              .setValue(
                                                  "https://127.0.0.1:"
                                                      + mockWebServer.getPort()
                                                      + "/xmlrpc.php"))
                                      .addResponseHeaders(
                                          HttpHeader.newBuilder()
                                              .setKey("X-Pingback")
                                              .setValue("http://evil.invalid/xmlrpc.php")))))
              .build();

      DetectionReportList reports =
          createDetector().detect(createTargetInfo(), ImmutableList.of(service));

      assertThat(reports.getDetectionReportsList()).isEmpty();
      assertThat(crossPortServer.getRequestCount()).isEqualTo(0);
    }
  }

  @Test
  public void
      detect_whenXmlRpcDiscoveryTimesOutConsecutively_breaksDiscoveryPhaseAndStillDetectsNextJs() {
    SimulatedNextJsImageDispatcher nextDispatcher =
        SimulatedNextJsImageDispatcher.builder(callbackHttpClient)
            .setMode(NextJsMode.VULNERABLE)
            .setInvalidStreamStatusCode(HttpStatus.INTERNAL_SERVER_ERROR.code())
            .build();
    mockWebServer.setDispatcher(nextDispatcher);
    AtomicInteger timedOutPostCount = new AtomicInteger();
    Cve2026111497OutboundDetector detector =
        createDetectorWithTimeoutRule(
            request -> {
              if (request.method() == HttpMethod.POST) {
                timedOutPostCount.incrementAndGet();
                return true;
              }
              return false;
            });
    TargetInfo target = createTargetInfo();
    NetworkService service =
        createNetworkService().toBuilder()
            .setServiceContext(
                ServiceContext.newBuilder()
                    .setWebServiceContext(
                        WebServiceContext.newBuilder()
                            .addCrawlResults(
                                CrawlResult.newBuilder()
                                    .setResponseCode(HttpStatus.OK.code())
                                    .setCrawlTarget(
                                        CrawlTarget.newBuilder()
                                            .setUrl(baseServerUrl() + "/portal/wp-login.php")
                                            .setHttpMethod("GET")))))
            .build();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    // Stops XML-RPC discovery after 2 consecutive POST timeouts instead of stalling across all
    // roots/paths, and proceeds to detect Next.js /_next/image with a fresh phase timeout tracker.
    assertThat(timedOutPostCount.get()).isEqualTo(2);
    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                "Vulnerable endpoint: "
                    + baseServerUrl()
                    + "/_next/image (signal=tcs_nextjs_image_differential,"
                    + " valid_status=400, invalid_status=500, probe_status=400)"));
  }

  @Test
  public void
      detect_whenXmlRpcPingbackCallsTimeOutConsecutively_breaksPingbackPhaseAndStillDetectsNextJs() {
    SimulatedWordPressDispatcher wpDispatcher =
        SimulatedWordPressDispatcher.builder(baseServerUrl(), callbackHttpClient)
            .setRestPostsJson(
                "[{\"link\":\""
                    + baseServerUrl()
                    + "/post-1\",\"ping_status\":\"open\"},{\"link\":\""
                    + baseServerUrl()
                    + "/post-2\",\"ping_status\":\"open\"}]")
            .build();
    SimulatedNextJsImageDispatcher nextDispatcher =
        SimulatedNextJsImageDispatcher.builder(callbackHttpClient)
            .setMode(NextJsMode.VULNERABLE)
            .setInvalidStreamStatusCode(HttpStatus.INTERNAL_SERVER_ERROR.code())
            .build();
    mockWebServer.setDispatcher(
        new Dispatcher() {
          @Override
          public MockResponse dispatch(RecordedRequest request) {
            String path = request.getPath();
            if (path != null && path.startsWith("/_next/image?")) {
              return nextDispatcher.dispatch(request);
            }
            return wpDispatcher.dispatch(request);
          }
        });

    AtomicInteger timedOutPingbackCount = new AtomicInteger();
    Cve2026111497OutboundDetector detector =
        createDetectorWithTimeoutRule(
            request -> {
              if (request.method() == HttpMethod.POST
                  && request
                      .requestBody()
                      .map(body -> body.toStringUtf8().contains("<methodName>pingback.ping"))
                      .orElse(false)) {
                timedOutPingbackCount.incrementAndGet();
                return true;
              }
              return false;
            });
    TargetInfo target = createTargetInfo();
    NetworkService service = createNetworkService();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    // Stops XML-RPC pingback probing after 2 consecutive pingback timeouts (despite 4 candidate
    // posts) and still verifies Next.js /_next/image.
    assertThat(timedOutPingbackCount.get()).isEqualTo(2);
    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                "Vulnerable endpoint: "
                    + baseServerUrl()
                    + "/_next/image (signal=tcs_nextjs_image_differential,"
                    + " valid_status=400, invalid_status=500, probe_status=400)"));
  }

  @Test
  public void detect_whenSingleTimeoutIsFollowedByHttpResponse_resetsConsecutiveTimeoutCounter() {
    SimulatedWordPressDispatcher wpDispatcher =
        SimulatedWordPressDispatcher.builder(baseServerUrl() + "/wordpress", callbackHttpClient)
            .setMountPathPrefix("/wordpress")
            .setClientMode(ClientMode.VULNERABLE_BROTLI)
            .setOpenPingbackPostUrls(ImmutableSet.of(baseServerUrl() + "/wordpress/?p=1"))
            .build();
    mockWebServer.setDispatcher(wpDispatcher);
    Cve2026111497OutboundDetector detector =
        createDetectorWithTimeoutRule(
            request ->
                request.url().endsWith("/xmlrpc.php")
                    && !request.url().endsWith("/wordpress/xmlrpc.php")
                    && (request.url().equals(baseServerUrl() + "/xmlrpc.php")
                        || request.url().equals(baseServerUrl() + "/xmlsrv/xmlrpc.php")));
    TargetInfo target = createTargetInfo();
    NetworkService service = createNetworkService();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    // Non-consecutive timeouts (separated by 404 responses on /services/xmlrpc, etc.) reset the
    // phase counter and still discover /wordpress/xmlrpc.php.
    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                "Vulnerable endpoint: "
                    + baseServerUrl()
                    + "/wordpress/xmlrpc.php (signal=tcs_pingback_differential, post="
                    + baseServerUrl()
                    + "/wordpress/?p=1, valid_fault=32, invalid_fault=16, probe_fault=32)"));
  }

  @Test
  public void detect_whenThreadInterrupted_honorsInterruptionWithoutProbingNextJs() {
    SimulatedNextJsImageDispatcher nextDispatcher =
        SimulatedNextJsImageDispatcher.builder(callbackHttpClient)
            .setMode(NextJsMode.VULNERABLE)
            .build();
    mockWebServer.setDispatcher(nextDispatcher);
    Cve2026111497OutboundDetector detector = createDetector();

    Thread.currentThread().interrupt();
    try {
      DetectionReportList reports =
          detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

      assertThat(reports.getDetectionReportsList()).isEmpty();
      assertThat(mockWebServer.getRequestCount()).isEqualTo(0);
      assertThat(nextDispatcher.fetchedSourceUris()).isEmpty();
    } finally {
      Thread.interrupted();
    }
  }

  @Test
  public void isValidAbsoluteHttpHomeUrl_enforcesAbsoluteHttpOrHttpsHostWithoutUserInfoOrQuery() {
    assertThat(Cve2026111497OutboundDetector.isValidAbsoluteHttpHomeUrl("http://example.com"))
        .isTrue();
    assertThat(
            Cve2026111497OutboundDetector.isValidAbsoluteHttpHomeUrl(
                "https://example.com:8443/blog"))
        .isTrue();
    assertThat(Cve2026111497OutboundDetector.isValidAbsoluteHttpHomeUrl("")).isFalse();
    assertThat(Cve2026111497OutboundDetector.isValidAbsoluteHttpHomeUrl("/")).isFalse();
    assertThat(Cve2026111497OutboundDetector.isValidAbsoluteHttpHomeUrl("/blog")).isFalse();
    assertThat(Cve2026111497OutboundDetector.isValidAbsoluteHttpHomeUrl("//example.com/blog"))
        .isFalse();
    assertThat(Cve2026111497OutboundDetector.isValidAbsoluteHttpHomeUrl("ftp://example.com"))
        .isFalse();
    assertThat(Cve2026111497OutboundDetector.isValidAbsoluteHttpHomeUrl("http:///missing-host"))
        .isFalse();
    assertThat(
            Cve2026111497OutboundDetector.isValidAbsoluteHttpHomeUrl(
                "http://user@example.com/blog"))
        .isFalse();
    assertThat(Cve2026111497OutboundDetector.isValidAbsoluteHttpHomeUrl("http://example.com/?p=1"))
        .isFalse();
  }

  @Test
  public void
      isCandidatePostCrawlUrl_enforcesHomeBoundariesPreservesQueryPostsAndExcludesNonPosts() {
    assertThat(
            Cve2026111497OutboundDetector.isCandidatePostCrawlUrl(
                "http://example.com/blog-archive/post",
                "http://example.com/wp/",
                "http://example.com/blog"))
        .isFalse();
    assertThat(
            Cve2026111497OutboundDetector.isCandidatePostCrawlUrl(
                "http://example.com:8080/post", "http://example.com/wp/", "http://example.com"))
        .isFalse();
    assertThat(
            Cve2026111497OutboundDetector.isCandidatePostCrawlUrl(
                "http://example.com.attacker.test/post",
                "http://example.com/wp/",
                "http://example.com"))
        .isFalse();
    assertThat(
            Cve2026111497OutboundDetector.isCandidatePostCrawlUrl(
                "http://example.com/blog/hello-world",
                "http://example.com/wp/",
                "http://example.com/blog"))
        .isTrue();
    assertThat(
            Cve2026111497OutboundDetector.isCandidatePostCrawlUrl(
                "http://example.com?p=42", "http://example.com/wp/", "http://example.com"))
        .isTrue();

    String rootUrl = "http://example.com/";
    String homeUrl = "http://example.com";
    for (String validQueryPostUrl :
        ImmutableList.of(
            "http://example.com/?q=node/42",
            "http://example.com/?id=start",
            "http://example.com/?p=42",
            "http://example.com/doku.php?id=start&do=show")) {
      assertWithMessage("validQueryPostUrl=%s", validQueryPostUrl)
          .that(
              Cve2026111497OutboundDetector.isCandidatePostCrawlUrl(
                  validQueryPostUrl, rootUrl, homeUrl))
          .isTrue();
    }

    for (String excludedUrl :
        ImmutableList.of(
            "http://example.com/#section",
            "http://example.com/?",
            "http://example.com/wp-admin/options",
            "http://example.com/user/login",
            "http://example.com/feed/",
            "http://example.com/?feed=rss2",
            "http://example.com/?rest_route=/wp/v2/posts",
            "http://example.com/?rsd",
            "http://example.com/?p=42&replytocom=5",
            "http://example.com/doku.php?id=start&do=login",
            "http://example.com/doku.php?id=start&do=admin",
            "http://example.com/?action=login",
            "http://example.com/?disp=admin",
            "http://example.com/?q=user",
            "http://example.com/?q=user/login",
            "http://example.com/?q=%2Fuser%2Flogin",
            "http://example.com/?q=admin",
            "http://example.com/?q=/admin/config",
            "http://example.com/?q=rss.xml",
            "http://example.com/?q=taxonomy/term/1/feed",
            "http://example.com/?format=rss",
            "http://example.com/?type=atom")) {
      assertWithMessage("excludedUrl=%s", excludedUrl)
          .that(
              Cve2026111497OutboundDetector.isCandidatePostCrawlUrl(excludedUrl, rootUrl, homeUrl))
          .isFalse();
    }
  }

  @Test
  public void detect_whenRsdHomePageLinkIsRelativeOrSchemeLess_fallsBackToEffectiveRootUrl() {
    String validPostUrl = baseServerUrl() + "/?p=1";
    for (String invalidRsdHomeLink : ImmutableList.of("/", "/blog", "//example.com/blog")) {
      SimulatedWordPressDispatcher wpDispatcher =
          SimulatedWordPressDispatcher.builder(invalidRsdHomeLink, callbackHttpClient)
              .setRestApiEnabled(false)
              .setClientMode(ClientMode.VULNERABLE_BROTLI)
              .setOpenPingbackPostUrls(ImmutableSet.of(validPostUrl))
              .build();
      mockWebServer.setDispatcher(wpDispatcher);
      NetworkService service =
          createNetworkService().toBuilder()
              .setServiceContext(
                  ServiceContext.newBuilder()
                      .setWebServiceContext(
                          WebServiceContext.newBuilder()
                              .addCrawlResults(
                                  CrawlResult.newBuilder()
                                      .setResponseCode(HttpStatus.OK.code())
                                      .setCrawlTarget(
                                          CrawlTarget.newBuilder()
                                              .setUrl("http://other-host.invalid/unrelated-post")
                                              .setHttpMethod("GET")))))
              .build();
      TargetInfo target = createTargetInfo();

      DetectionReportList reports = createDetector().detect(target, ImmutableList.of(service));

      assertWithMessage("invalidRsdHomeLink=%s", invalidRsdHomeLink)
          .that(reports.getDetectionReportsList())
          .containsExactly(
              buildExpectedDetectionReport(
                  target,
                  service,
                  "Vulnerable endpoint: "
                      + baseServerUrl()
                      + "/xmlrpc.php (signal=tcs_pingback_differential, post="
                      + validPostUrl
                      + ", valid_fault=32, invalid_fault=16, probe_fault=32)"));
      assertThat(wpDispatcher.pingbackTargetUris())
          .doesNotContain("http://other-host.invalid/unrelated-post");
    }
  }

  @Test
  public void
      detect_whenCrawlResultsContainNonGetNon200FragmentsAndQueryRoutes_selectsValidQueryPost() {
    String queryRoutedDrupalPost = baseServerUrl() + "/?q=node/42";
    SimulatedWordPressDispatcher drupalDispatcher =
        SimulatedWordPressDispatcher.builder(baseServerUrl(), callbackHttpClient)
            .setXmlRpcRelativePath("/xmlrpc.php")
            .setRsdEnabled(false)
            .setIncludeWpGetUsersBlogs(false)
            .setRestApiEnabled(false)
            .setRetryWithNoneOnFailure(false)
            .setClientMode(ClientMode.VULNERABLE_BROTLI)
            .setOpenPingbackPostUrls(ImmutableSet.of(queryRoutedDrupalPost))
            .build();
    mockWebServer.setDispatcher(drupalDispatcher);
    TargetInfo target = createTargetInfo();
    NetworkService service =
        createNetworkService().toBuilder()
            .setServiceContext(
                ServiceContext.newBuilder()
                    .setWebServiceContext(
                        WebServiceContext.newBuilder()
                            .addCrawlResults(
                                CrawlResult.newBuilder()
                                    .setResponseCode(HttpStatus.OK.code())
                                    .setCrawlTarget(
                                        CrawlTarget.newBuilder()
                                            .setUrl(baseServerUrl() + "/contact")
                                            .setHttpMethod("POST")))
                            .addCrawlResults(
                                CrawlResult.newBuilder()
                                    .setResponseCode(HttpStatus.NOT_FOUND.code())
                                    .setCrawlTarget(
                                        CrawlTarget.newBuilder()
                                            .setUrl(baseServerUrl() + "/missing-article")
                                            .setHttpMethod("GET")))
                            .addCrawlResults(
                                CrawlResult.newBuilder()
                                    .setResponseCode(HttpStatus.FOUND.code())
                                    .setCrawlTarget(
                                        CrawlTarget.newBuilder()
                                            .setUrl(baseServerUrl() + "/redirect-article")
                                            .setHttpMethod("GET")))
                            .addCrawlResults(
                                CrawlResult.newBuilder()
                                    .setResponseCode(HttpStatus.OK.code())
                                    .setCrawlTarget(
                                        CrawlTarget.newBuilder()
                                            .setUrl(baseServerUrl() + "/#top")
                                            .setHttpMethod("GET")))
                            .addCrawlResults(
                                CrawlResult.newBuilder()
                                    .setResponseCode(HttpStatus.OK.code())
                                    .setCrawlTarget(
                                        CrawlTarget.newBuilder()
                                            .setUrl(baseServerUrl() + "/?q=user/login")
                                            .setHttpMethod("GET")))
                            .addCrawlResults(
                                CrawlResult.newBuilder()
                                    .setResponseCode(HttpStatus.OK.code())
                                    .setCrawlTarget(
                                        CrawlTarget.newBuilder()
                                            .setUrl(queryRoutedDrupalPost + "#comments")
                                            .setHttpMethod("GET")))
                            .addCrawlResults(
                                CrawlResult.newBuilder()
                                    .setResponseCode(HttpStatus.OK.code())
                                    .setCrawlTarget(
                                        CrawlTarget.newBuilder()
                                            .setUrl(queryRoutedDrupalPost + "#respond")
                                            .setHttpMethod("GET")))))
            .build();

    DetectionReportList reports = createDetector().detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                "Vulnerable endpoint: "
                    + baseServerUrl()
                    + "/xmlrpc.php (signal=tcs_pingback_differential, post="
                    + queryRoutedDrupalPost
                    + ", valid_fault=32, invalid_fault=16, probe_fault=32)"));
    assertThat(drupalDispatcher.pingbackTargetUris().get(0)).isEqualTo(queryRoutedDrupalPost);
  }

  @Test
  public void detect_whenXPingbackAdvertisesSplitHomeWordPress_resolvesRsdHomePageLink() {
    String customBlogHome = baseServerUrl() + "/blog";
    String customBlogPost = customBlogHome + "/?p=1";
    SimulatedWordPressDispatcher splitWpDispatcher =
        SimulatedWordPressDispatcher.builder(customBlogHome, callbackHttpClient)
            .setMountPathPrefix("/custom-wp")
            .setRestApiEnabled(false)
            .setClientMode(ClientMode.VULNERABLE_BROTLI)
            .setOpenPingbackPostUrls(ImmutableSet.of(customBlogPost))
            .build();
    mockWebServer.setDispatcher(splitWpDispatcher);
    TargetInfo target = createTargetInfo();
    NetworkService splitWpService =
        createNetworkService().toBuilder()
            .setServiceContext(
                ServiceContext.newBuilder()
                    .setWebServiceContext(
                        WebServiceContext.newBuilder()
                            .addCrawlResults(
                                CrawlResult.newBuilder()
                                    .setResponseCode(HttpStatus.OK.code())
                                    .setCrawlTarget(
                                        CrawlTarget.newBuilder()
                                            .setUrl(customBlogHome + "/")
                                            .setHttpMethod("GET"))
                                    .addResponseHeaders(
                                        HttpHeader.newBuilder()
                                            .setKey("X-Pingback")
                                            .setValue(baseServerUrl() + "/custom-wp/xmlrpc.php")))))
            .build();

    DetectionReportList splitWpReports =
        createDetector().detect(target, ImmutableList.of(splitWpService));

    assertThat(splitWpReports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                splitWpService,
                "Vulnerable endpoint: "
                    + baseServerUrl()
                    + "/custom-wp/xmlrpc.php (signal=tcs_pingback_differential, post="
                    + customBlogPost
                    + ", valid_fault=32, invalid_fault=16, probe_fault=32)"));
  }

  @Test
  public void detect_whenXPingbackAdvertisesB2evolutionPost_prioritizesCrawledPostAheadOfRss() {
    String b2evoRoot = baseServerUrl() + "/b2evo";
    String b2evoOpenPost = b2evoRoot + "/index.php/2026/10/open-post";
    SimulatedWordPressDispatcher b2evoDispatcher =
        SimulatedWordPressDispatcher.builder(b2evoRoot, callbackHttpClient)
            .setMountPathPrefix("/b2evo")
            .setXmlRpcRelativePath("/xmlsrv/xmlrpc.php")
            .setRsdEnabled(false)
            .setIncludeWpGetUsersBlogs(false)
            .setRestApiEnabled(false)
            .setRssFeedXml(
                "<?xml version=\"1.0\"?><rss version=\"2.0\"><channel>"
                    + "<item><link>"
                    + b2evoRoot
                    + "/closed-1</link></item>"
                    + "<item><link>"
                    + b2evoRoot
                    + "/closed-2</link></item>"
                    + "</channel></rss>")
            .setRetryWithNoneOnFailure(false)
            .setClientMode(ClientMode.VULNERABLE_BROTLI)
            .setOpenPingbackPostUrls(ImmutableSet.of(b2evoOpenPost))
            .build();
    mockWebServer.setDispatcher(b2evoDispatcher);
    TargetInfo target = createTargetInfo();
    NetworkService b2evoService =
        createNetworkService().toBuilder()
            .setServiceContext(
                ServiceContext.newBuilder()
                    .setWebServiceContext(
                        WebServiceContext.newBuilder()
                            .addCrawlResults(
                                CrawlResult.newBuilder()
                                    .setResponseCode(HttpStatus.OK.code())
                                    .setCrawlTarget(
                                        CrawlTarget.newBuilder()
                                            .setUrl(b2evoOpenPost)
                                            .setHttpMethod("GET"))
                                    .addResponseHeaders(
                                        HttpHeader.newBuilder()
                                            .setKey("X-Pingback")
                                            .setValue(b2evoRoot + "/xmlsrv/xmlrpc.php")))))
            .build();

    DetectionReportList b2evoReports =
        createDetector().detect(target, ImmutableList.of(b2evoService));

    assertThat(b2evoReports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                b2evoService,
                "Vulnerable endpoint: "
                    + b2evoRoot
                    + "/xmlsrv/xmlrpc.php (signal=tcs_pingback_differential, post="
                    + b2evoOpenPost
                    + ", valid_fault=32, invalid_fault=16, probe_fault=32)"));
  }

  @Test
  public void detect_whenSystemListMethodsReturns401AndRsdIsAvailable_fallsBackToRsdAndReportsVuln() {
    String baseUrl = baseServerUrl();
    String openPost = baseUrl + "/?p=1";
    SimulatedWordPressDispatcher dispatcher =
        SimulatedWordPressDispatcher.builder(baseUrl, callbackHttpClient)
            .setClientMode(ClientMode.VULNERABLE_BROTLI)
            .setSystemListMethodsResponseStatus(HttpStatus.UNAUTHORIZED.code())
            .setRsdEnabled(true)
            .setOpenPingbackPostUrls(ImmutableSet.of(openPost))
            .build();
    mockWebServer.setDispatcher(dispatcher);
    TargetInfo target = createTargetInfo();
    NetworkService service = createNetworkService();

    DetectionReportList reports = createDetector().detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                "Vulnerable endpoint: "
                    + baseUrl
                    + "/xmlrpc.php (signal=tcs_pingback_differential, post="
                    + openPost
                    + ", valid_fault=32, invalid_fault=16, probe_fault=32)"));
  }

  @Test
  public void detect_whenSystemListMethodsReturns500WithMethodResponseBody_doesNotReportVuln() {
    String baseUrl = baseServerUrl();
    String openPost = baseUrl + "/?p=1";
    SimulatedWordPressDispatcher dispatcher =
        SimulatedWordPressDispatcher.builder(baseUrl, callbackHttpClient)
            .setClientMode(ClientMode.VULNERABLE_BROTLI)
            .setSystemListMethodsResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.code())
            .setRsdEnabled(false)
            .setOpenPingbackPostUrls(ImmutableSet.of(openPost))
            .build();
    mockWebServer.setDispatcher(dispatcher);

    DetectionReportList reports =
        createDetector().detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(dispatcher.pingbackSourceUris()).isEmpty();
  }

  @Test
  public void
      detect_whenSystemListMethodsReturns403AndRsdReturns200WithoutRsdOrBanner_doesNotReportVuln() {
    String openPost = baseServerUrl() + "/?p=1";
    SimulatedWordPressDispatcher delegate =
        SimulatedWordPressDispatcher.builder(baseServerUrl(), callbackHttpClient)
            .setClientMode(ClientMode.VULNERABLE_BROTLI)
            .setSystemListMethodsResponseStatus(HttpStatus.FORBIDDEN.code())
            .setOpenPingbackPostUrls(ImmutableSet.of(openPost))
            .build();
    mockWebServer.setDispatcher(
        new Dispatcher() {
          @Override
          public MockResponse dispatch(RecordedRequest request) {
            if ("GET".equals(request.getMethod())
                && "/xmlrpc.php?rsd".equals(request.getPath())) {
              return new MockResponse()
                  .setResponseCode(HttpStatus.OK.code())
                  .setBody("<html><body>Welcome</body></html>");
            }
            return delegate.dispatch(request);
          }
        });

    DetectionReportList reports =
        createDetector().detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(delegate.pingbackSourceUris()).isEmpty();
  }

  @Test
  public void detect_whenSystemListMethodsReturns403AndRsdReturns200WithPostOnlyBanner_reportsVuln() {
    String openPost = baseServerUrl() + "/?p=1";
    SimulatedWordPressDispatcher delegate =
        SimulatedWordPressDispatcher.builder(baseServerUrl(), callbackHttpClient)
            .setClientMode(ClientMode.VULNERABLE_BROTLI)
            .setSystemListMethodsResponseStatus(HttpStatus.FORBIDDEN.code())
            .setOpenPingbackPostUrls(ImmutableSet.of(openPost))
            .build();
    mockWebServer.setDispatcher(
        new Dispatcher() {
          @Override
          public MockResponse dispatch(RecordedRequest request) {
            if ("GET".equals(request.getMethod())
                && "/xmlrpc.php?rsd".equals(request.getPath())) {
              return new MockResponse()
                  .setResponseCode(HttpStatus.OK.code())
                  .setBody("XML-RPC server accepts POST requests only.");
            }
            return delegate.dispatch(request);
          }
        });
    TargetInfo target = createTargetInfo();
    NetworkService service = createNetworkService();

    DetectionReportList reports = createDetector().detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                "Vulnerable endpoint: "
                    + baseServerUrl()
                    + "/xmlrpc.php (signal=tcs_pingback_differential, post="
                    + openPost
                    + ", valid_fault=32, invalid_fault=16, probe_fault=32)"));
  }

  private Cve2026111497OutboundDetector createDetector() {
    return createDetector(/* callbackServerEnabled= */ true);
  }

  private Cve2026111497OutboundDetector createDetector(boolean callbackServerEnabled) {
    FakePayloadGeneratorModule.Builder payloadBuilder = FakePayloadGeneratorModule.builder();
    if (callbackServerEnabled) {
      payloadBuilder.setCallbackServer(mockCallbackServer);
    }
    return Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            payloadBuilder.build(),
            new Cve2026111497OutboundDetectorBootstrapModule())
        .getInstance(Cve2026111497OutboundDetector.class);
  }

  private Cve2026111497OutboundDetector createDetectorWithTimeoutRule(
      Predicate<HttpRequest> shouldTimeout) {
    Injector injector =
        Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            FakePayloadGeneratorModule.builder().setCallbackServer(mockCallbackServer).build());
    HttpClient baseHttpClient = injector.getInstance(HttpClient.class);
    return new Cve2026111497OutboundDetector(
        fakeUtcClock,
        new TimeoutInjectingHttpClient(baseHttpClient, shouldTimeout),
        injector.getInstance(TcsClient.class),
        injector.getInstance(PayloadSecretGenerator.class));
  }

  private Cve2026111497OutboundDetector createDetectorWithoutCallbackServer() {
    return createDetector(/* callbackServerEnabled= */ false);
  }

  private TargetInfo createTargetInfo() {
    return TargetInfo.newBuilder().addNetworkEndpoints(forIp("127.0.0.1")).build();
  }

  private NetworkService createNetworkService() {
    return NetworkService.newBuilder()
        .setNetworkEndpoint(forIpAndPort("127.0.0.1", mockWebServer.getPort()))
        .setTransportProtocol(TransportProtocol.TCP)
        .setServiceName("http")
        .build();
  }

  private String baseServerUrl() {
    return "http://127.0.0.1:" + mockWebServer.getPort();
  }

  private DetectionReport buildExpectedDetectionReport(
      TargetInfo target, NetworkService service, String expectedEvidenceText) {
    return DetectionReport.newBuilder()
        .setTargetInfo(target)
        .setNetworkService(service)
        .setDetectionTimestamp(Timestamps.fromMillis(fakeUtcClock.instant().toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder()
                        .setPublisher(Cve2026111497OutboundDetector.VULNERABILITY_REPORT_PUBLISHER)
                        .setValue(Cve2026111497OutboundDetector.VULNERABILITY_REPORT_ID))
                .addRelatedId(
                    VulnerabilityId.newBuilder()
                        .setPublisher("CVE")
                        .setValue(Cve2026111497OutboundDetector.RELATED_CVE_ID))
                .setSeverity(Severity.CRITICAL)
                .setTitle(Cve2026111497OutboundDetector.VULNERABILITY_REPORT_TITLE)
                .setDescription(Cve2026111497OutboundDetector.VULN_DESCRIPTION)
                .setRecommendation(Cve2026111497OutboundDetector.RECOMMENDATION)
                .addAdditionalDetails(
                    AdditionalDetail.newBuilder()
                        .setDescription(
                            Cve2026111497OutboundDetector.DETECTION_EVIDENCE_DESCRIPTION)
                        .setTextData(TextData.newBuilder().setText(expectedEvidenceText))))
        .build();
  }

  private enum ClientMode {
    VULNERABLE_BROTLI,
    VULNERABLE_BROTLI_PRIVATE_CALLBACK_RETRY_BLOCKED,
    PATCHED_BROTLI,
    NO_BROTLI_SUPPORT,
    PROXY_IGNORING_CONTENT_ENCODING,
    INCONSISTENT_STEP4,
    TIMEOUT_ON_PROBE_WITHOUT_RETRY
  }

  private enum NextJsMode {
    VULNERABLE,
    PATCHED,
    DOMAIN_RESTRICTED_NO_FETCH,
    NO_DECOMPRESSION_ALWAYS_400,
    STEP2_NO_FETCH_500,
    INCONSISTENT_STEP4_VALID_500,
    INCONSISTENT_STEP4_INVALID_400,
    INCONSISTENT_STEP4_INVALID_STATUS_DRIFT
  }

  private static final class TimeoutInjectingHttpClient extends HttpClient {
    private final HttpClient delegate;
    private final Predicate<HttpRequest> shouldTimeout;

    TimeoutInjectingHttpClient(HttpClient delegate, Predicate<HttpRequest> shouldTimeout) {
      this.delegate = delegate;
      this.shouldTimeout = shouldTimeout;
    }

    @Override
    public String getLogId() {
      return delegate.getLogId();
    }

    @Override
    public HttpResponse sendAsIs(HttpRequest httpRequest) throws IOException {
      if (shouldTimeout.test(httpRequest)) {
        throw new SocketTimeoutException("Simulated socket timeout");
      }
      return delegate.sendAsIs(httpRequest);
    }

    @Override
    public HttpResponse send(HttpRequest httpRequest) throws IOException {
      return send(httpRequest, null);
    }

    @Override
    public HttpResponse send(HttpRequest httpRequest, NetworkService networkService)
        throws IOException {
      if (shouldTimeout.test(httpRequest)) {
        throw new SocketTimeoutException("Simulated socket timeout");
      }
      return delegate.send(httpRequest, networkService);
    }

    @Override
    public ListenableFuture<HttpResponse> sendAsync(HttpRequest httpRequest) {
      return delegate.sendAsync(httpRequest);
    }

    @Override
    public ListenableFuture<HttpResponse> sendAsync(
        HttpRequest httpRequest, NetworkService networkService) {
      return delegate.sendAsync(httpRequest, networkService);
    }

    @Override
    // Safe cast: HttpClient.modify() is parameterized on the caller's target HttpClient subtype.
    @SuppressWarnings("unchecked")
    public <T extends HttpClient> Builder<T> modify() {
      Builder<HttpClient> delegateBuilder = delegate.modify();
      return (Builder<T>)
          new Builder<TimeoutInjectingHttpClient>() {
            @Override
            public Builder<TimeoutInjectingHttpClient> setFollowRedirects(boolean followRedirects) {
              var unused = delegateBuilder.setFollowRedirects(followRedirects);
              return this;
            }

            @Override
            public Builder<TimeoutInjectingHttpClient> setLogId(String logId) {
              var unused = delegateBuilder.setLogId(logId);
              return this;
            }

            @Override
            public Builder<TimeoutInjectingHttpClient> setConnectTimeout(
                Duration connectionTimeout) {
              var unused = delegateBuilder.setConnectTimeout(connectionTimeout);
              return this;
            }

            @Override
            public TimeoutInjectingHttpClient build() {
              return new TimeoutInjectingHttpClient(delegateBuilder.build(), shouldTimeout);
            }
          };
    }
  }

  /**
   * Simulates Tsunami Callback Server (TCS) recording and polling endpoints, including {@code
   * ?response=brotli_*} presets and {@code &no_br_cbid=} attribution.
   */
  private static final class SimulatedTcsDispatcher extends Dispatcher {
    private final Sha3CbidGenerator cbidGenerator = new Sha3CbidGenerator();
    private final Set<String> recordedCbids = ConcurrentHashMap.newKeySet();

    @Override
    public MockResponse dispatch(RecordedRequest request) {
      String pathAndQuery = request.getPath();
      if (pathAndQuery == null) {
        return new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code());
      }

      Optional<String> secret = UrlParser.getQueryParameter(pathAndQuery, "secret");
      if (secret.isPresent()) {
        String cbid = cbidGenerator.generate(secret.get());
        if (recordedCbids.contains(cbid)) {
          try {
            return PayloadTestHelper.generateMockSuccessfulCallbackResponse();
          } catch (IOException e) {
            throw new AssertionError(e);
          }
        }
        return PayloadTestHelper.generateMockUnsuccessfulCallbackResponse();
      }

      Optional<String> responsePreset = UrlParser.getQueryParameter(pathAndQuery, "response");
      if (responsePreset.isPresent()) {
        String acceptEncoding = request.getHeader("Accept-Encoding");
        boolean acceptsBr =
            acceptEncoding != null
                && Ascii.toLowerCase(acceptEncoding).contains("br")
                && !Ascii.toLowerCase(acceptEncoding).contains("br;q=0");
        if (!acceptsBr) {
          UrlParser.getQueryParameter(pathAndQuery, "no_br_cbid")
              .ifPresent(noBrCbid -> recordedCbids.add(Ascii.toLowerCase(noBrCbid)));
          return new MockResponse()
              .setResponseCode(HttpStatus.OK.code())
              .setHeader("Content-Type", "text/plain; charset=utf-8")
              .setBody("");
        }

        int qIdx = pathAndQuery.indexOf('?');
        String pathOnly = qIdx >= 0 ? pathAndQuery.substring(0, qIdx) : pathAndQuery;
        CbidProcessor.extractCbidFromUrl(pathOnly).ifPresent(recordedCbids::add);

        ByteString body =
            switch (responsePreset.get()) {
              case Cve2026111497OutboundDetector.PRESET_BROTLI_VALID -> VALID_CONTROL_BYTES;
              case Cve2026111497OutboundDetector.PRESET_BROTLI_INVALID -> INVALID_CONTROL_BYTES;
              case Cve2026111497OutboundDetector.PRESET_BROTLI_CVE_2026_111497 -> PROBE_BYTES;
              default -> throw new AssertionError("Unexpected preset: " + responsePreset.get());
            };
        Buffer buf = new Buffer().write(body.toByteArray());
        return new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .setHeader("Content-Encoding", "br")
            .setHeader("Content-Type", "text/plain; charset=utf-8")
            .setBody(buf);
      }

      CbidProcessor.extractCbidFromUrl(pathAndQuery).ifPresent(recordedCbids::add);
      return new MockResponse()
          .setResponseCode(HttpStatus.OK.code())
          .setBody("{\"status\":\"OK\"}");
    }
  }

  private static final class SimulatedNextJsImageDispatcher extends Dispatcher {
    private final OkHttpClient httpClient;
    private final String mountPathPrefix;
    private final NextJsMode mode;
    private final int invalidStreamStatusCode;
    private final Optional<String> serverHeader;

    private final List<String> fetchedSourceUris = Collections.synchronizedList(new ArrayList<>());
    private final AtomicInteger callIndex = new AtomicInteger();
    private final AtomicInteger probeFetches = new AtomicInteger();

    private SimulatedNextJsImageDispatcher(Builder builder) {
      this.httpClient = builder.httpClient;
      this.mountPathPrefix = builder.mountPathPrefix;
      this.mode = builder.mode;
      this.invalidStreamStatusCode = builder.invalidStreamStatusCode;
      this.serverHeader = builder.serverHeader;
    }

    static Builder builder(OkHttpClient httpClient) {
      return new Builder(httpClient);
    }

    ImmutableList<String> fetchedSourceUris() {
      return ImmutableList.copyOf(fetchedSourceUris);
    }

    int probeFetches() {
      return probeFetches.get();
    }

    @Override
    public MockResponse dispatch(RecordedRequest request) {
      String path = request.getPath();
      if (path == null
          || !Objects.equals(request.getMethod(), "GET")
          || !path.startsWith(mountPathPrefix + "/_next/image?")) {
        return new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code());
      }

      if (mode == NextJsMode.DOMAIN_RESTRICTED_NO_FETCH) {
        return new MockResponse()
            .setResponseCode(HttpStatus.BAD_REQUEST.code())
            .setBody("\"url\" parameter is not allowed");
      }

      int currentCall = callIndex.incrementAndGet();
      if (mode == NextJsMode.STEP2_NO_FETCH_500 && currentCall == 2) {
        return new MockResponse()
            .setResponseCode(HttpStatus.INTERNAL_SERVER_ERROR.code())
            .setBody("Upstream blocked before fetch");
      }

      Optional<String> encodedUrl = UrlParser.getQueryParameter(path, "url");
      if (encodedUrl.isEmpty()) {
        return new MockResponse().setResponseCode(HttpStatus.BAD_REQUEST.code());
      }
      String sourceUri = URLDecoder.decode(encodedUrl.get(), StandardCharsets.UTF_8);
      fetchedSourceUris.add(sourceUri);

      try (Response resp =
              httpClient
                  .newCall(
                      new Request.Builder()
                          .url(sourceUri)
                          .header("Accept-Encoding", "gzip, deflate, br")
                          .get()
                          .build())
                  .execute();
          InputStream in = resp.body().byteStream()) {
        int firstByte = in.read();
        ByteStreams.exhaust(in);
        if (firstByte == PROBE_FIRST_BYTE) {
          probeFetches.incrementAndGet();
        }
        boolean decompressedCleanly =
            switch (mode) {
              case VULNERABLE, STEP2_NO_FETCH_500 ->
                  firstByte == VALID_FIRST_BYTE || firstByte == PROBE_FIRST_BYTE;
              case PATCHED -> firstByte == VALID_FIRST_BYTE;
              case NO_DECOMPRESSION_ALWAYS_400 -> true;
              case INCONSISTENT_STEP4_VALID_500 ->
                  (firstByte == VALID_FIRST_BYTE && currentCall < 4)
                      || firstByte == PROBE_FIRST_BYTE;
              case INCONSISTENT_STEP4_INVALID_400 ->
                  firstByte == VALID_FIRST_BYTE
                      || firstByte == PROBE_FIRST_BYTE
                      || (firstByte == INVALID_FIRST_BYTE && currentCall == 5);
              case INCONSISTENT_STEP4_INVALID_STATUS_DRIFT ->
                  firstByte == VALID_FIRST_BYTE || firstByte == PROBE_FIRST_BYTE;
              case DOMAIN_RESTRICTED_NO_FETCH -> false;
            };
        int failureCode =
            (mode == NextJsMode.INCONSISTENT_STEP4_INVALID_STATUS_DRIFT && currentCall == 5)
                ? HttpStatus.BAD_GATEWAY.code()
                : invalidStreamStatusCode;
        int statusCode = decompressedCleanly ? HttpStatus.BAD_REQUEST.code() : failureCode;
        MockResponse mockResp =
            new MockResponse()
                .setResponseCode(statusCode)
                .setBody(
                    decompressedCleanly
                        ? "\"url\" parameter is valid but upstream response is invalid"
                        : "Internal Server Error");
        serverHeader.ifPresent(server -> mockResp.setHeader("Server", server));
        return mockResp;
      } catch (IOException e) {
        throw new AssertionError("Failed simulated Next.js fetch to " + sourceUri, e);
      }
    }

    static final class Builder {
      private final OkHttpClient httpClient;
      private String mountPathPrefix = "";
      private NextJsMode mode = NextJsMode.VULNERABLE;
      private int invalidStreamStatusCode = HttpStatus.INTERNAL_SERVER_ERROR.code();
      private Optional<String> serverHeader = Optional.empty();

      private Builder(OkHttpClient httpClient) {
        this.httpClient = httpClient;
      }

      @CanIgnoreReturnValue
      Builder setMountPathPrefix(String mountPathPrefix) {
        this.mountPathPrefix = mountPathPrefix;
        return this;
      }

      @CanIgnoreReturnValue
      Builder setMode(NextJsMode mode) {
        this.mode = mode;
        return this;
      }

      @CanIgnoreReturnValue
      Builder setInvalidStreamStatusCode(int invalidStreamStatusCode) {
        this.invalidStreamStatusCode = invalidStreamStatusCode;
        return this;
      }

      @CanIgnoreReturnValue
      Builder setServerHeader(String serverHeader) {
        this.serverHeader = Optional.of(serverHeader);
        return this;
      }

      SimulatedNextJsImageDispatcher build() {
        return new SimulatedNextJsImageDispatcher(this);
      }
    }
  }

  private static final class SimulatedWordPressDispatcher extends Dispatcher {
    private final String homeUrl;
    private final String mountPathPrefix;
    private final String xmlRpcRelativePath;
    private final OkHttpClient httpClient;
    private final boolean rsdEnabled;
    private final boolean rsdReturns405Banner;
    private final boolean includeWpGetUsersBlogs;
    private final boolean pingbackMethodListed;
    private final int systemListMethodsResponseStatus;
    private final boolean systemListMethodsReturnsXmlFault;
    private final boolean restApiEnabled;
    private final boolean maskFaultCodes;
    private final boolean retryWithNoneOnFailure;
    private final int validSuccessFaultCode;
    private final Optional<String> serverHeader;
    private final String restPostsJson;
    private final String rssFeedPath;
    private final String rssFeedXml;
    private final ClientMode clientMode;
    private final ImmutableSet<String> openPingbackPostUrls;

    private final List<String> requestedPaths = Collections.synchronizedList(new ArrayList<>());
    private final List<String> pingbackSourceUris = Collections.synchronizedList(new ArrayList<>());
    private final List<String> pingbackTargetUris = Collections.synchronizedList(new ArrayList<>());
    private final AtomicInteger pingbackCallIndex = new AtomicInteger();
    private final AtomicInteger probeFetches = new AtomicInteger();

    private SimulatedWordPressDispatcher(Builder builder) {
      this.homeUrl = builder.homeUrl;
      this.mountPathPrefix = builder.mountPathPrefix;
      this.xmlRpcRelativePath = builder.xmlRpcRelativePath;
      this.httpClient = builder.httpClient;
      this.rsdEnabled = builder.rsdEnabled;
      this.rsdReturns405Banner = builder.rsdReturns405Banner;
      this.includeWpGetUsersBlogs = builder.includeWpGetUsersBlogs;
      this.pingbackMethodListed = builder.pingbackMethodListed;
      this.systemListMethodsResponseStatus = builder.systemListMethodsResponseStatus;
      this.systemListMethodsReturnsXmlFault = builder.systemListMethodsReturnsXmlFault;
      this.restApiEnabled = builder.restApiEnabled;
      this.maskFaultCodes = builder.maskFaultCodes;
      this.retryWithNoneOnFailure = builder.retryWithNoneOnFailure;
      this.validSuccessFaultCode = builder.validSuccessFaultCode;
      this.serverHeader = builder.serverHeader;
      this.restPostsJson = builder.restPostsJson;
      this.rssFeedPath = builder.rssFeedPath;
      this.rssFeedXml = builder.rssFeedXml;
      this.clientMode = builder.clientMode;
      this.openPingbackPostUrls = builder.openPingbackPostUrls;
    }

    static Builder builder(String homeUrl, OkHttpClient httpClient) {
      return new Builder(homeUrl, httpClient);
    }

    ImmutableList<String> requestedPaths() {
      return ImmutableList.copyOf(requestedPaths);
    }

    ImmutableList<String> pingbackSourceUris() {
      return ImmutableList.copyOf(pingbackSourceUris);
    }

    ImmutableList<String> pingbackTargetUris() {
      return ImmutableList.copyOf(pingbackTargetUris);
    }

    int probeFetches() {
      return probeFetches.get();
    }

    @Override
    public MockResponse dispatch(RecordedRequest request) {
      String path = request.getPath();
      if (path == null) {
        return new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code());
      }
      requestedPaths.add(path);

      String expectedRsdPath =
          mountPathPrefix
              + xmlRpcRelativePath
              + (xmlRpcRelativePath.contains("?") ? "&rsd" : "?rsd");
      if (path.equals(expectedRsdPath) && Objects.equals(request.getMethod(), "GET")) {
        if (!rsdEnabled) {
          return new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code());
        }
        if (rsdReturns405Banner) {
          return new MockResponse()
              .setResponseCode(HttpStatus.METHOD_NOT_ALLOWED.code())
              .setBody("XML-RPC server accepts POST requests only.");
        }
        return new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .setHeader("Content-Type", "text/xml; charset=UTF-8")
            .setBody(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><rsd version=\"1.0\">"
                    + "<service><engineName>WordPress</engineName>"
                    + "<homePageLink>"
                    + homeUrl
                    + "</homePageLink></service></rsd>");
      }

      if (path.equals(mountPathPrefix + xmlRpcRelativePath)
          && Objects.equals(request.getMethod(), "POST")) {
        String body = request.getBody().readUtf8();
        if (body.contains("<methodName>system.listMethods</methodName>")) {
          if (systemListMethodsResponseStatus == HttpStatus.FORBIDDEN.code()
              || systemListMethodsResponseStatus == HttpStatus.UNAUTHORIZED.code()) {
            return new MockResponse()
                .setResponseCode(systemListMethodsResponseStatus)
                .setBody("Forbidden");
          }
          if (systemListMethodsReturnsXmlFault) {
            return new MockResponse()
                .setResponseCode(systemListMethodsResponseStatus)
                .setHeader("Content-Type", "text/xml; charset=UTF-8")
                .setBody(buildFaultXml(-32601));
          }
          String methods =
              (includeWpGetUsersBlogs
                      ? "<value><string>wp.getUsersBlogs</string></value>"
                      : "<value><string>system.listMethods</string></value>")
                  + (pingbackMethodListed ? "<value><string>pingback.ping</string></value>" : "");
          return new MockResponse()
              .setResponseCode(systemListMethodsResponseStatus)
              .setHeader("Content-Type", "text/xml; charset=UTF-8")
              .setBody(
                  "<?xml version=\"1.0\"?><methodResponse><params><param><value><array><data>"
                      + methods
                      + "</data></array></value></param></params></methodResponse>");
        }
        if (body.contains("<methodName>pingback.ping</methodName>")) {
          int faultCode = handlePingbackCall(body);
          int reportedFault = maskFaultCodes ? 0 : faultCode;
          MockResponse response =
              new MockResponse()
                  .setResponseCode(HttpStatus.OK.code())
                  .setHeader("Content-Type", "text/xml; charset=UTF-8")
                  .setBody(buildFaultXml(reportedFault));
          serverHeader.ifPresent(server -> response.setHeader("Server", server));
          return response;
        }
      }

      if (path.startsWith(mountPathPrefix + "/wp-json/wp/v2/posts")
          && Objects.equals(request.getMethod(), "GET")) {
        if (!restApiEnabled) {
          return new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code());
        }
        return new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .setHeader("Content-Type", "application/json")
            .setBody(restPostsJson);
      }

      if (path.equals(mountPathPrefix + rssFeedPath)
          && Objects.equals(request.getMethod(), "GET")) {
        return new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .setHeader("Content-Type", "application/rss+xml")
            .setBody(rssFeedXml);
      }

      return new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code());
    }

    private int handlePingbackCall(String xmlBody) {
      Matcher matcher = XMLRPC_STRING_PARAM_PATTERN.matcher(xmlBody);
      if (!matcher.find()) {
        return 0;
      }
      String sourceUri = unescapeXml(matcher.group(1));
      if (!matcher.find()) {
        return 0;
      }
      String targetUri = unescapeXml(matcher.group(1));
      pingbackSourceUris.add(sourceUri);
      pingbackTargetUris.add(targetUri);
      int callNumber = pingbackCallIndex.incrementAndGet();

      if (!openPingbackPostUrls.contains(targetUri)) {
        return FAULT_PINGBACK_CLOSED;
      }

      try {
        return simulateWpSafeRemoteGet(sourceUri, callNumber);
      } catch (IOException e) {
        throw new AssertionError("Failed simulated wp_safe_remote_get to " + sourceUri, e);
      }
    }

    private int simulateWpSafeRemoteGet(String sourceUri, int callNumber) throws IOException {
      if (clientMode == ClientMode.NO_BROTLI_SUPPORT) {
        try (Response resp =
            httpClient
                .newCall(
                    new Request.Builder()
                        .url(sourceUri)
                        .header("Accept-Encoding", "deflate, gzip")
                        .get()
                        .build())
                .execute()) {
          byte[] bytes = resp.body().byteStream().readAllBytes();
          return bytes.length == 0 ? FAULT_PINGBACK_SOURCE_NOT_FOUND : validSuccessFaultCode;
        }
      }

      boolean shouldRetryWithNone = false;
      boolean succeededDecompressingNonEmptyBody = false;
      try (Response resp =
              httpClient
                  .newCall(
                      new Request.Builder()
                          .url(sourceUri)
                          .header("Accept-Encoding", "deflate, gzip, br, zstd")
                          .get()
                          .build())
                  .execute();
          InputStream in = resp.body().byteStream()) {
        int firstByte = in.read();
        if (firstByte == PROBE_FIRST_BYTE) {
          probeFetches.incrementAndGet();
        }
        switch (clientMode) {
          case VULNERABLE_BROTLI -> {
            ByteStreams.exhaust(in);
            shouldRetryWithNone = (firstByte == INVALID_FIRST_BYTE);
            succeededDecompressingNonEmptyBody = !shouldRetryWithNone;
          }
          case VULNERABLE_BROTLI_PRIVATE_CALLBACK_RETRY_BLOCKED -> {
            ByteStreams.exhaust(in);
            shouldRetryWithNone = (firstByte == INVALID_FIRST_BYTE);
            // Simulate WordPress wp_safe_remote_get() rejecting private-IP callback URLs on the
            // Accept-Encoding: none retry via curl.before_request hook so both valid and invalid
            // return fault 16 while still sending the 'none' retry only on invalid streams.
            succeededDecompressingNonEmptyBody = false;
          }
          case PATCHED_BROTLI -> {
            if (firstByte == VALID_FIRST_BYTE) {
              ByteStreams.exhaust(in);
              succeededDecompressingNonEmptyBody = true;
            } else {
              shouldRetryWithNone = true;
            }
          }
          case PROXY_IGNORING_CONTENT_ENCODING -> {
            ByteStreams.exhaust(in);
            shouldRetryWithNone = false;
            succeededDecompressingNonEmptyBody = true;
          }
          case INCONSISTENT_STEP4 -> {
            ByteStreams.exhaust(in);
            shouldRetryWithNone = (firstByte == INVALID_FIRST_BYTE && callNumber < 5);
            succeededDecompressingNonEmptyBody = !shouldRetryWithNone;
          }
          case TIMEOUT_ON_PROBE_WITHOUT_RETRY -> {
            ByteStreams.exhaust(in);
            if (firstByte == INVALID_FIRST_BYTE) {
              shouldRetryWithNone = true;
            } else if (firstByte == PROBE_FIRST_BYTE) {
              // Simulate CURLE_OPERATION_TIMEDOUT at end of stream: no 'none' retry, fault 16.
              shouldRetryWithNone = false;
              succeededDecompressingNonEmptyBody = false;
            } else {
              succeededDecompressingNonEmptyBody = true;
            }
          }
          case NO_BROTLI_SUPPORT ->
              throw new AssertionError("NO_BROTLI_SUPPORT is handled before sending 'br' request");
        }
      }

      if (shouldRetryWithNone && retryWithNoneOnFailure) {
        try (Response retryResp =
            httpClient
                .newCall(
                    new Request.Builder()
                        .url(sourceUri)
                        .header("Accept-Encoding", "none")
                        .get()
                        .build())
                .execute()) {
          byte[] bytes = retryResp.body().byteStream().readAllBytes();
          return bytes.length == 0
              ? FAULT_PINGBACK_SOURCE_NOT_FOUND
              : FAULT_PINGBACK_TARGET_LINK_MISSING;
        }
      }

      return succeededDecompressingNonEmptyBody
          ? validSuccessFaultCode
          : FAULT_PINGBACK_SOURCE_NOT_FOUND;
    }

    private static String unescapeXml(String input) {
      return input
          .replace("&quot;", "\"")
          .replace("&apos;", "'")
          .replace("&lt;", "<")
          .replace("&gt;", ">")
          .replace("&amp;", "&");
    }

    private static String buildFaultXml(int faultCode) {
      return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
          + "<methodResponse><fault><value><struct>"
          + "<member><name>faultCode</name><value><int>"
          + faultCode
          + "</int></value></member>"
          + "<member><name>faultString</name><value><string></string></value></member>"
          + "</struct></value></fault></methodResponse>";
    }

    static final class Builder {
      private final String homeUrl;
      private final OkHttpClient httpClient;
      private String mountPathPrefix = "";
      private String xmlRpcRelativePath = "/xmlrpc.php";
      private boolean rsdEnabled = true;
      private boolean rsdReturns405Banner = false;
      private boolean includeWpGetUsersBlogs = true;
      private boolean pingbackMethodListed = true;
      private int systemListMethodsResponseStatus = HttpStatus.OK.code();
      private boolean systemListMethodsReturnsXmlFault = false;
      private boolean restApiEnabled = true;
      private boolean maskFaultCodes = false;
      private boolean retryWithNoneOnFailure = true;
      private int validSuccessFaultCode = FAULT_PINGBACK_TITLE_MISSING;
      private Optional<String> serverHeader = Optional.empty();
      private String restPostsJson = "[]";
      private String rssFeedPath = "/?feed=rss2";
      private String rssFeedXml = "<rss version=\"2.0\"><channel></channel></rss>";
      private ClientMode clientMode = ClientMode.VULNERABLE_BROTLI;
      private ImmutableSet<String> openPingbackPostUrls = ImmutableSet.of();

      private Builder(String homeUrl, OkHttpClient httpClient) {
        this.homeUrl = homeUrl;
        this.httpClient = httpClient;
      }

      @CanIgnoreReturnValue
      Builder setMountPathPrefix(String mountPathPrefix) {
        this.mountPathPrefix = mountPathPrefix;
        return this;
      }

      @CanIgnoreReturnValue
      Builder setXmlRpcRelativePath(String xmlRpcRelativePath) {
        this.xmlRpcRelativePath = xmlRpcRelativePath;
        return this;
      }

      @CanIgnoreReturnValue
      Builder setRsdEnabled(boolean rsdEnabled) {
        this.rsdEnabled = rsdEnabled;
        return this;
      }

      @CanIgnoreReturnValue
      Builder setRsdReturns405Banner(boolean rsdReturns405Banner) {
        this.rsdReturns405Banner = rsdReturns405Banner;
        return this;
      }

      @CanIgnoreReturnValue
      Builder setIncludeWpGetUsersBlogs(boolean includeWpGetUsersBlogs) {
        this.includeWpGetUsersBlogs = includeWpGetUsersBlogs;
        return this;
      }

      @CanIgnoreReturnValue
      Builder setPingbackMethodListed(boolean pingbackMethodListed) {
        this.pingbackMethodListed = pingbackMethodListed;
        return this;
      }

      @CanIgnoreReturnValue
      Builder setSystemListMethodsResponseStatus(int systemListMethodsResponseStatus) {
        this.systemListMethodsResponseStatus = systemListMethodsResponseStatus;
        return this;
      }

      @CanIgnoreReturnValue
      Builder setSystemListMethodsReturnsXmlFault(boolean systemListMethodsReturnsXmlFault) {
        this.systemListMethodsReturnsXmlFault = systemListMethodsReturnsXmlFault;
        return this;
      }

      @CanIgnoreReturnValue
      Builder setRestApiEnabled(boolean restApiEnabled) {
        this.restApiEnabled = restApiEnabled;
        return this;
      }

      @CanIgnoreReturnValue
      Builder setMaskFaultCodes(boolean maskFaultCodes) {
        this.maskFaultCodes = maskFaultCodes;
        return this;
      }

      @CanIgnoreReturnValue
      Builder setRetryWithNoneOnFailure(boolean retryWithNoneOnFailure) {
        this.retryWithNoneOnFailure = retryWithNoneOnFailure;
        return this;
      }

      @CanIgnoreReturnValue
      Builder setValidSuccessFaultCode(int validSuccessFaultCode) {
        this.validSuccessFaultCode = validSuccessFaultCode;
        return this;
      }

      @CanIgnoreReturnValue
      Builder setServerHeader(String serverHeader) {
        this.serverHeader = Optional.of(serverHeader);
        return this;
      }

      @CanIgnoreReturnValue
      Builder setRestPostsJson(String restPostsJson) {
        this.restPostsJson = restPostsJson;
        return this;
      }

      @CanIgnoreReturnValue
      Builder setRssFeedPath(String rssFeedPath) {
        this.rssFeedPath = rssFeedPath;
        return this;
      }

      @CanIgnoreReturnValue
      Builder setRssFeedXml(String rssFeedXml) {
        this.rssFeedXml = rssFeedXml;
        return this;
      }

      @CanIgnoreReturnValue
      Builder setClientMode(ClientMode clientMode) {
        this.clientMode = clientMode;
        return this;
      }

      @CanIgnoreReturnValue
      Builder setOpenPingbackPostUrls(ImmutableSet<String> openPingbackPostUrls) {
        this.openPingbackPostUrls = openPingbackPostUrls;
        return this;
      }

      SimulatedWordPressDispatcher build() {
        return new SimulatedWordPressDispatcher(this);
      }
    }
  }
}
