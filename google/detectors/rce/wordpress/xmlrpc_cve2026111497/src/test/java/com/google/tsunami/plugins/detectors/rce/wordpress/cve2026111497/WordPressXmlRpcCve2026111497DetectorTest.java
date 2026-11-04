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

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forIp;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forIpAndPort;

import com.google.common.base.Ascii;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.io.ByteStreams;
import com.google.common.net.InetAddresses;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.inject.Guice;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.callbackserver.common.CbidProcessor;
import com.google.tsunami.callbackserver.common.Sha3CbidGenerator;
import com.google.tsunami.callbackserver.common.UrlParser;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.plugin.payload.testing.FakePayloadGeneratorModule;
import com.google.tsunami.plugin.payload.testing.PayloadTestHelper;
import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.CrawlResult;
import com.google.tsunami.proto.CrawlTarget;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
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
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
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

/** Unit tests for {@link WordPressXmlRpcCve2026111497Detector}. */
@RunWith(JUnit4.class)
public final class WordPressXmlRpcCve2026111497DetectorTest {
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
  public void getAdvisories_whenCalled_returnsWordPressSpecificMainIdAndRelatedCveId() {
    WordPressXmlRpcCve2026111497Detector detector = createDetector();

    ImmutableList<Vulnerability> advisories = detector.getAdvisories();

    assertThat(advisories)
        .containsExactly(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder()
                        .setPublisher("GOOGLE")
                        .setValue("CVE-2026-111497-WORDPRESS-XMLRPC"))
                .addRelatedId(
                    VulnerabilityId.newBuilder().setPublisher("CVE").setValue("CVE-2026-111497"))
                .setSeverity(Severity.CRITICAL)
                .setTitle(WordPressXmlRpcCve2026111497Detector.VULNERABILITY_REPORT_TITLE)
                .setDescription(WordPressXmlRpcCve2026111497Detector.VULN_DESCRIPTION)
                .setRecommendation(WordPressXmlRpcCve2026111497Detector.RECOMMENDATION)
                .build());
  }

  @Test
  public void detect_whenCallbackServerDisabled_skipsWithoutSendingRequests() {
    WordPressXmlRpcCve2026111497Detector detector = createDetectorWithoutCallbackServer();

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
    WordPressXmlRpcCve2026111497Detector detector = createDetector();
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
    WordPressXmlRpcCve2026111497Detector detector = createDetector();
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
    WordPressXmlRpcCve2026111497Detector detector = createDetector();
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
    WordPressXmlRpcCve2026111497Detector detector = createDetector();
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
    WordPressXmlRpcCve2026111497Detector detector = createDetector();

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    // Aborts after Step 2 when valid and invalid controls both return unmasked fault 16.
    assertThat(wpDispatcher.pingbackSourceUris()).hasSize(2);
    assertThat(wpDispatcher.probeFetches()).isEqualTo(0);
  }

  @Test
  public void isAllowedControlFaultPair_enforcesExpectedMaskedAndUnmaskedCombinations() {
    assertThat(WordPressXmlRpcCve2026111497Detector.isAllowedControlFaultPair(0, 0)).isTrue();
    assertThat(
            WordPressXmlRpcCve2026111497Detector.isAllowedControlFaultPair(
                FAULT_PINGBACK_TITLE_MISSING, FAULT_PINGBACK_SOURCE_NOT_FOUND))
        .isTrue();
    assertThat(
            WordPressXmlRpcCve2026111497Detector.isAllowedControlFaultPair(
                FAULT_PINGBACK_TARGET_LINK_MISSING, FAULT_PINGBACK_SOURCE_NOT_FOUND))
        .isTrue();
    assertThat(
            WordPressXmlRpcCve2026111497Detector.isAllowedControlFaultPair(
                0, FAULT_PINGBACK_SOURCE_NOT_FOUND))
        .isFalse();
    assertThat(
            WordPressXmlRpcCve2026111497Detector.isAllowedControlFaultPair(
                FAULT_PINGBACK_SOURCE_NOT_FOUND, 0))
        .isFalse();
    assertThat(
            WordPressXmlRpcCve2026111497Detector.isAllowedControlFaultPair(
                FAULT_PINGBACK_SOURCE_NOT_FOUND, FAULT_PINGBACK_SOURCE_NOT_FOUND))
        .isFalse();
    assertThat(
            WordPressXmlRpcCve2026111497Detector.isAllowedControlFaultPair(
                FAULT_PINGBACK_TITLE_MISSING, FAULT_PINGBACK_TITLE_MISSING))
        .isFalse();
    assertThat(
            WordPressXmlRpcCve2026111497Detector.isAllowedControlFaultPair(
                FAULT_PINGBACK_CLOSED, FAULT_PINGBACK_SOURCE_NOT_FOUND))
        .isFalse();
    assertThat(WordPressXmlRpcCve2026111497Detector.isAllowedControlFaultPair(48, 48)).isFalse();
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
    WordPressXmlRpcCve2026111497Detector detector = createDetector();

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
    WordPressXmlRpcCve2026111497Detector detector = createDetector();

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(wpDispatcher.pingbackSourceUris()).hasSize(3);
  }

  @Test
  public void detect_whenNonWordPressServerReturns404OnRsd_makesSingleGetAndNeverPollsTcs() {
    mockWebServer.setDispatcher(
        new Dispatcher() {
          @Override
          public MockResponse dispatch(RecordedRequest request) {
            return new MockResponse()
                .setResponseCode(HttpStatus.NOT_FOUND.code())
                .setBody("Not Found");
          }
        });
    WordPressXmlRpcCve2026111497Detector detector = createDetector();

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(mockWebServer.getRequestCount()).isEqualTo(1);
    assertThat(mockCallbackServer.getRequestCount()).isEqualTo(0);
  }

  @Test
  public void detect_whenPingbackDisabledInSystemListMethods_neverPollsTcs() {
    SimulatedWordPressDispatcher wpDispatcher =
        SimulatedWordPressDispatcher.builder(baseServerUrl(), callbackHttpClient)
            .setPingbackMethodListed(false)
            .build();
    mockWebServer.setDispatcher(wpDispatcher);
    WordPressXmlRpcCve2026111497Detector detector = createDetector();

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
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
    WordPressXmlRpcCve2026111497Detector detector = createDetector();

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
    WordPressXmlRpcCve2026111497Detector detector = createDetector();

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
    WordPressXmlRpcCve2026111497Detector detector = createDetector();
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
    WordPressXmlRpcCve2026111497Detector detector = createDetector();
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
    WordPressXmlRpcCve2026111497Detector detector = createDetector();
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
    WordPressXmlRpcCve2026111497Detector detector = createDetector();

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(wpDispatcher.pingbackSourceUris()).hasSize(5);
  }

  private WordPressXmlRpcCve2026111497Detector createDetector() {
    return createDetector(/* callbackServerEnabled= */ true);
  }

  private WordPressXmlRpcCve2026111497Detector createDetector(boolean callbackServerEnabled) {
    FakePayloadGeneratorModule.Builder payloadBuilder = FakePayloadGeneratorModule.builder();
    if (callbackServerEnabled) {
      payloadBuilder.setCallbackServer(mockCallbackServer);
    }
    return Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            payloadBuilder.build(),
            new WordPressXmlRpcCve2026111497DetectorBootstrapModule())
        .getInstance(WordPressXmlRpcCve2026111497Detector.class);
  }

  private WordPressXmlRpcCve2026111497Detector createDetectorWithoutCallbackServer() {
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
                        .setPublisher(
                            WordPressXmlRpcCve2026111497Detector.VULNERABILITY_REPORT_PUBLISHER)
                        .setValue(WordPressXmlRpcCve2026111497Detector.VULNERABILITY_REPORT_ID))
                .addRelatedId(
                    VulnerabilityId.newBuilder()
                        .setPublisher("CVE")
                        .setValue(WordPressXmlRpcCve2026111497Detector.RELATED_CVE_ID))
                .setSeverity(Severity.CRITICAL)
                .setTitle(WordPressXmlRpcCve2026111497Detector.VULNERABILITY_REPORT_TITLE)
                .setDescription(WordPressXmlRpcCve2026111497Detector.VULN_DESCRIPTION)
                .setRecommendation(WordPressXmlRpcCve2026111497Detector.RECOMMENDATION)
                .addAdditionalDetails(
                    AdditionalDetail.newBuilder()
                        .setDescription(
                            WordPressXmlRpcCve2026111497Detector.DETECTION_EVIDENCE_DESCRIPTION)
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
              case WordPressXmlRpcCve2026111497Detector.PRESET_BROTLI_VALID -> VALID_CONTROL_BYTES;
              case WordPressXmlRpcCve2026111497Detector.PRESET_BROTLI_INVALID ->
                  INVALID_CONTROL_BYTES;
              case WordPressXmlRpcCve2026111497Detector.PRESET_BROTLI_CVE_2026_111497 ->
                  PROBE_BYTES;
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

  private static final class SimulatedWordPressDispatcher extends Dispatcher {
    private final String homeUrl;
    private final String mountPathPrefix;
    private final OkHttpClient httpClient;
    private final boolean rsdReturns405Banner;
    private final boolean pingbackMethodListed;
    private final boolean restApiEnabled;
    private final boolean maskFaultCodes;
    private final Optional<String> serverHeader;
    private final String restPostsJson;
    private final String rssFeedXml;
    private final ClientMode clientMode;
    private final ImmutableSet<String> openPingbackPostUrls;

    private final List<String> pingbackSourceUris = Collections.synchronizedList(new ArrayList<>());
    private final List<String> pingbackTargetUris = Collections.synchronizedList(new ArrayList<>());
    private final AtomicInteger pingbackCallIndex = new AtomicInteger();
    private final AtomicInteger probeFetches = new AtomicInteger();

    private SimulatedWordPressDispatcher(Builder builder) {
      this.homeUrl = builder.homeUrl;
      this.mountPathPrefix = builder.mountPathPrefix;
      this.httpClient = builder.httpClient;
      this.rsdReturns405Banner = builder.rsdReturns405Banner;
      this.pingbackMethodListed = builder.pingbackMethodListed;
      this.restApiEnabled = builder.restApiEnabled;
      this.maskFaultCodes = builder.maskFaultCodes;
      this.serverHeader = builder.serverHeader;
      this.restPostsJson = builder.restPostsJson;
      this.rssFeedXml = builder.rssFeedXml;
      this.clientMode = builder.clientMode;
      this.openPingbackPostUrls = builder.openPingbackPostUrls;
    }

    static Builder builder(String homeUrl, OkHttpClient httpClient) {
      return new Builder(homeUrl, httpClient);
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

      if (path.equals(mountPathPrefix + "/xmlrpc.php?rsd")
          && Objects.equals(request.getMethod(), "GET")) {
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

      if (path.equals(mountPathPrefix + "/xmlrpc.php")
          && Objects.equals(request.getMethod(), "POST")) {
        String body = request.getBody().readUtf8();
        if (body.contains("<methodName>system.listMethods</methodName>")) {
          String methods =
              "<value><string>wp.getUsersBlogs</string></value>"
                  + (pingbackMethodListed ? "<value><string>pingback.ping</string></value>" : "");
          return new MockResponse()
              .setResponseCode(HttpStatus.OK.code())
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

      String rootSlash = mountPathPrefix.isEmpty() ? "/" : mountPathPrefix + "/";
      if (path.equals(rootSlash + "?feed=rss2") && Objects.equals(request.getMethod(), "GET")) {
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
          return bytes.length == 0 ? FAULT_PINGBACK_SOURCE_NOT_FOUND : FAULT_PINGBACK_TITLE_MISSING;
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

      if (shouldRetryWithNone) {
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
          ? FAULT_PINGBACK_TITLE_MISSING
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
      private boolean rsdReturns405Banner = false;
      private boolean pingbackMethodListed = true;
      private boolean restApiEnabled = true;
      private boolean maskFaultCodes = false;
      private Optional<String> serverHeader = Optional.empty();
      private String restPostsJson = "[]";
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
      Builder setRsdReturns405Banner(boolean rsdReturns405Banner) {
        this.rsdReturns405Banner = rsdReturns405Banner;
        return this;
      }

      @CanIgnoreReturnValue
      Builder setPingbackMethodListed(boolean pingbackMethodListed) {
        this.pingbackMethodListed = pingbackMethodListed;
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
