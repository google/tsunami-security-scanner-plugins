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
package com.google.tsunami.plugins.detectors.rce.cve2026123007;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static java.nio.charset.StandardCharsets.ISO_8859_1;
import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.google.common.base.Ticker;
import com.google.common.collect.ImmutableList;
import com.google.common.io.BaseEncoding;
import com.google.common.net.HostAndPort;
import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkEndpointUtils;
import com.google.tsunami.common.net.socket.TsunamiSocketFactory;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.plugins.detectors.rce.cve2026123007.HpackDecoder.HeaderField;
import com.google.tsunami.plugins.detectors.rce.cve2026123007.HpackDecoder.HpackException;
import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.CrawlResult;
import com.google.tsunami.proto.CrawlTarget;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.Hostname;
import com.google.tsunami.proto.IpAddress;
import com.google.tsunami.proto.NetworkEndpoint;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Port;
import com.google.tsunami.proto.ServiceContext;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TextData;
import com.google.tsunami.proto.TransportProtocol;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import com.google.tsunami.proto.WebServiceContext;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FilterInputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Unit tests for {@link Cve2026123007Detector}, {@link H2FlowControlProbe}, and {@link
 * HpackDecoder}.
 */
@RunWith(JUnit4.class)
public final class Cve2026123007DetectorTest {

  private static final Instant FIXED_INSTANT = Instant.parse("2026-11-19T12:00:00Z");
  private static final InetAddress LOOPBACK_ADDR = InetAddress.getLoopbackAddress();
  private static final String LOOPBACK_IP = LOOPBACK_ADDR.getHostAddress();
  private static final byte[] clientPreface = H2Frames.clientPrefaceCopy();
  // ASN.1 DER constants for X.509 v3 self-signed ECDSA-SHA256 certificate construction.
  private static final String DER_ECDSA_SHA256_ALG_ID_HEX = "300a06082a8648ce3d040302";
  private static final String DER_CN_TEST_RDN_HEX = "300f310d300b06035504030c0474657374";
  private static final byte[] derX509V3ExplicitVersion = {(byte) 0xa0, 0x03, 0x02, 0x01, 0x02};
  private static final byte[] derSerialNumberOne = {0x02, 0x01, 0x01};

  private final FakeUtcClock fakeUtcClock = FakeUtcClock.create().setNow(FIXED_INSTANT);
  private final List<ServerSocket> openServers = new ArrayList<>();
  private ExecutorService serverExecutor;

  @Before
  public void setUp() {
    serverExecutor = Executors.newCachedThreadPool();
  }

  @After
  public void tearDown() throws Exception {
    for (ServerSocket server : openServers) {
      try {
        server.close();
      } catch (IOException ignored) {
        // Closed during test teardown.
      }
    }
    serverExecutor.shutdownNow();
    serverExecutor.awaitTermination(3, SECONDS);
  }

  @Test
  public void getAdvisories_returnsCriticalCve2026123007Advisory() {
    Cve2026123007Detector detector = newFastDetector(new LoopbackSocketFactory());

    ImmutableList<Vulnerability> advisories = detector.getAdvisories();

    assertThat(advisories).hasSize(1);
    Vulnerability vuln = advisories.get(0);
    assertThat(vuln.getMainId())
        .isEqualTo(
            VulnerabilityId.newBuilder()
                .setPublisher("GOOGLE")
                .setValue("CVE-2026-123007")
                .build());
    assertThat(vuln.getRelatedIdList())
        .containsExactly(
            VulnerabilityId.newBuilder().setPublisher("CVE").setValue("CVE-2026-123007").build());
    assertThat(vuln.getSeverity()).isEqualTo(Severity.CRITICAL);
    assertThat(vuln.getTitle()).contains("CVE-2026-123007");
    assertThat(vuln.getDescription()).contains("ngx_http_v2_state_window_update");
    assertThat(vuln.getRecommendation()).contains("1.30.7");
    assertThat(vuln.getRecommendation()).contains("1.31.9");
  }

  @Test
  public void detect_vulnerableUnpatched18ByteSettingsOnNonDefaultWebService_verifiesWithoutRst()
      throws Exception {
    MockNginxConfig config = MockNginxConfig.unpatchedDefault().withSettings24Byte(false);
    MockNginxHarness harness = startMockNginxServer(config);
    Cve2026123007Detector detector =
        Guice.createInjector(
                new FakeUtcClockModule(fakeUtcClock),
                new Cve2026123007DetectorBootstrapModule(),
                new AbstractModule() {
                  @Override
                  protected void configure() {
                    bind(TsunamiSocketFactory.class)
                        .toInstance(new LoopbackSocketFactory(Duration.ofSeconds(3), true));
                  }
                })
            .getInstance(Cve2026123007Detector.class);

    NetworkEndpoint endpoint = NetworkEndpointUtils.forIpAndPort(LOOPBACK_IP, harness.port());
    NetworkService radanService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(endpoint)
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("radan-http")
            .build();
    TargetInfo targetInfo = TargetInfo.newBuilder().addNetworkEndpoints(endpoint).build();

    DetectionReportList reports = detector.detect(targetInfo, ImmutableList.of(radanService));

    String authority = HostAndPort.fromParts(LOOPBACK_IP, harness.port()).toString();
    long expectedWu = H2FlowControlProbe.NGINX_MAX_WINDOW - 8L * 12288L;
    String expectedDetail =
        String.format(
            "Verified unpatched NGINX ngx_http_v2 flow-control window validation over HTTP/2 (h2c)"
                + " at http://%s/ (settings_len=18, max_concurrent_streams=8,"
                + " static_body_bytes=12288, burst_streams=12, tail_refused_streams=2,"
                + " stream0_window_update=%d accepted with queued DATA frames in h2c->last_out and"
                + " verified by pre/post/liveness PING ACKs).",
            authority, expectedWu);

    assertThat(reports)
        .isEqualTo(
            DetectionReportList.newBuilder()
                .addDetectionReports(
                    expectedReport(detector, targetInfo, radanService, expectedDetail))
                .build());
    assertThat(harness.sawClientRstStream()).isFalse();
  }

  @Test
  public void detect_vulnerableUnpatched24ByteSettingsAndOpenResty_returnsVerifiedFinding()
      throws Exception {
    MockNginxConfig config =
        MockNginxConfig.unpatchedDefault()
            .withSettings24Byte(true)
            .withServerHeader("openresty/1.25.3.1");
    MockNginxHarness harness = startMockNginxServer(config);
    Cve2026123007Detector detector =
        new Cve2026123007Detector(
            fakeUtcClock, new LoopbackSocketFactory(Duration.ofSeconds(-1), false));

    NetworkEndpoint endpoint = NetworkEndpointUtils.forIpAndPort(LOOPBACK_IP, harness.port());
    NetworkService service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(endpoint)
            .setTransportProtocol(TransportProtocol.TRANSPORT_PROTOCOL_UNSPECIFIED)
            .setServiceName("http")
            .build();
    TargetInfo targetInfo = TargetInfo.newBuilder().addNetworkEndpoints(endpoint).build();

    DetectionReportList reports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList()).hasSize(1);
    DetectionReport report = reports.getDetectionReports(0);
    assertThat(report.getDetectionStatus()).isEqualTo(DetectionStatus.VULNERABILITY_VERIFIED);
    assertThat(report.getDetectionTimestamp())
        .isEqualTo(Timestamps.fromMillis(FIXED_INSTANT.toEpochMilli()));
    assertThat(report.getVulnerability().getAdditionalDetails(0).getTextData().getText())
        .contains("settings_len=24");
    assertThat(harness.sawClientRstStream()).isFalse();
  }

  @Test
  public void detect_patchedNginxSendsGoAwayFlowControlError_returnsEmptyAndNeverSendsRstStream()
      throws Exception {
    MockNginxConfig config = MockNginxConfig.patchedDefault();
    MockNginxHarness harness = startMockNginxServer(config);
    Cve2026123007Detector detector = newFastDetector(new LoopbackSocketFactory());

    NetworkService service = buildHttpService(harness.port(), "http");
    TargetInfo targetInfo =
        TargetInfo.newBuilder().addNetworkEndpoints(service.getNetworkEndpoint()).build();

    DetectionReportList reports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(harness.totalConnections()).isEqualTo(2);
    assertThat(harness.sawClientRstStream()).isFalse();
  }

  @Test
  public void detect_nonWebOrUnsupportedServicesAgainstLiveVulnerableServer_skipsAllWithoutDialing()
      throws Exception {
    MockNginxHarness harness = startMockNginxServer(MockNginxConfig.unpatchedDefault());
    LoopbackSocketFactory socketFactory = new LoopbackSocketFactory();
    Cve2026123007Detector detector = newFastDetector(socketFactory);

    NetworkEndpoint validEp = NetworkEndpointUtils.forIpAndPort(LOOPBACK_IP, harness.port());
    NetworkService sshService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(validEp)
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("ssh")
            .build();
    NetworkService udpHttpService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(validEp)
            .setTransportProtocol(TransportProtocol.UDP)
            .setServiceName("http")
            .build();
    NetworkService noPortService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(NetworkEndpointUtils.forIp(LOOPBACK_IP))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("http")
            .build();
    NetworkService zeroPortService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(NetworkEndpointUtils.forIpAndPort(LOOPBACK_IP, 0))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("http")
            .build();
    NetworkService overflowPortService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                NetworkEndpoint.newBuilder()
                    .setType(NetworkEndpoint.Type.IP_PORT)
                    .setPort(Port.newBuilder().setPortNumber(70000)))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("http")
            .build();

    TargetInfo targetInfo = TargetInfo.newBuilder().addNetworkEndpoints(validEp).build();
    DetectionReportList reports =
        detector.detect(
            targetInfo,
            ImmutableList.of(
                sshService, udpHttpService, noPortService, zeroPortService, overflowPortService));

    assertThat(Cve2026123007Detector.isSupportedService(buildHttpService(1, "http"))).isTrue();
    assertThat(Cve2026123007Detector.isSupportedService(buildHttpService(65535, "http"))).isTrue();
    assertThat(Cve2026123007Detector.isSupportedService(zeroPortService)).isFalse();
    assertThat(Cve2026123007Detector.isSupportedService(overflowPortService)).isFalse();
    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(socketFactory.dialedCount()).isEqualTo(0);
    assertThat(harness.totalConnections()).isEqualTo(0);
  }

  @Test
  public void detect_malformedOrInvalidEndpointHosts_skipsWithoutDialing() {
    LoopbackSocketFactory socketFactory = new LoopbackSocketFactory();
    Cve2026123007Detector detector = newFastDetector(socketFactory);

    NetworkService malformedHostAndPort =
        NetworkService.newBuilder()
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("http")
            .setNetworkEndpoint(
                NetworkEndpoint.newBuilder()
                    .setType(NetworkEndpoint.Type.HOSTNAME_PORT)
                    .setHostname(Hostname.newBuilder().setName("bad:9999"))
                    .setPort(Port.newBuilder().setPortNumber(8080)))
            .build();
    NetworkService controlCharHost =
        NetworkService.newBuilder()
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("http")
            .setNetworkEndpoint(
                NetworkEndpoint.newBuilder()
                    .setType(NetworkEndpoint.Type.HOSTNAME_PORT)
                    .setHostname(Hostname.newBuilder().setName("bad host"))
                    .setPort(Port.newBuilder().setPortNumber(8080)))
            .build();
    NetworkService invalidDialIp =
        NetworkService.newBuilder()
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("http")
            .setNetworkEndpoint(
                NetworkEndpoint.newBuilder()
                    .setType(NetworkEndpoint.Type.IP_HOSTNAME_PORT)
                    .setHostname(Hostname.newBuilder().setName("valid.example.com"))
                    .setIpAddress(IpAddress.newBuilder().setAddress("bad ip"))
                    .setPort(Port.newBuilder().setPortNumber(8080)))
            .build();

    DetectionReportList reports =
        detector.detect(
            TargetInfo.getDefaultInstance(),
            ImmutableList.of(malformedHostAndPort, controlCharHost, invalidDialIp));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(socketFactory.dialedCount()).isEqualTo(0);
  }

  @Test
  public void detect_invalidNginxGreetingOrStream0WindowUpdate_returnsEmpty() throws Exception {
    ImmutableList<MockNginxConfig> nonMatchingGreetings =
        ImmutableList.of(
            MockNginxConfig.unpatchedDefault().withRawSettingsPayload(new byte[12]),
            MockNginxConfig.unpatchedDefault().withMaxConcurrentStreams(0),
            MockNginxConfig.unpatchedDefault().withServerInitialWindowSize(0x80000000L),
            MockNginxConfig.unpatchedDefault().withMaxFrameSize(16384L),
            MockNginxConfig.unpatchedDefault().withSettings24Byte(true).withNoPrioritiesValue(0L),
            MockNginxConfig.unpatchedDefault().withStream0WindowUpdateDelta(983041L),
            MockNginxConfig.unpatchedDefault().withOmitStream0WindowUpdate(true));

    Cve2026123007Detector detector = newFastDetector(new LoopbackSocketFactory());
    for (MockNginxConfig cfg : nonMatchingGreetings) {
      MockNginxHarness harness = startMockNginxServer(cfg);
      NetworkService service = buildHttpService(harness.port(), "http");
      TargetInfo targetInfo =
          TargetInfo.newBuilder().addNetworkEndpoints(service.getNetworkEndpoint()).build();

      DetectionReportList reports = detector.detect(targetInfo, ImmutableList.of(service));

      assertThat(reports.getDetectionReportsList()).isEmpty();
      assertThat(harness.totalConnections()).isEqualTo(1);
    }
  }

  @Test
  public void detect_awsAlbViaAndNonNginxServerExclusions_returnsEmpty() throws Exception {
    ImmutableList<ImmutableList<HeaderField>> excludedHeaderSets =
        ImmutableList.of(
            ImmutableList.of(new HeaderField("server", "awselb/2.0")),
            ImmutableList.of(new HeaderField("server", "Apache/2.4.62")),
            ImmutableList.of(new HeaderField("server", "envoy")),
            ImmutableList.of(new HeaderField("server", "cloudflare")),
            ImmutableList.of(new HeaderField("server", "Caddy")),
            ImmutableList.of(
                new HeaderField("server", "nginx/1.24.0"),
                new HeaderField("via", "1.1 proxy.example.net")),
            ImmutableList.of(
                new HeaderField("server", "nginx/1.24.0"),
                new HeaderField("set-cookie", "AWSALB=abc123; Path=/")),
            ImmutableList.of(
                new HeaderField("server", "nginx/1.24.0"),
                new HeaderField("set-cookie", "AWSALBCORS=abc123; Path=/")),
            ImmutableList.of(
                new HeaderField("server", "nginx/1.24.0"),
                new HeaderField("set-cookie", "AWSALBTG=abc123; Path=/")),
            ImmutableList.of(
                new HeaderField("server", "nginx/1.24.0"),
                new HeaderField("set-cookie", "AWSALBTGCORS=abc123; Path=/")));

    Cve2026123007Detector detector = newFastDetector(new LoopbackSocketFactory());
    for (ImmutableList<HeaderField> extraHeaders : excludedHeaderSets) {
      MockNginxConfig cfg =
          MockNginxConfig.unpatchedDefault().withExtraResponseHeaders(extraHeaders);
      MockNginxHarness harness = startMockNginxServer(cfg);
      NetworkService service = buildHttpService(harness.port(), "http");
      TargetInfo targetInfo =
          TargetInfo.newBuilder().addNetworkEndpoints(service.getNetworkEndpoint()).build();

      DetectionReportList reports = detector.detect(targetInfo, ImmutableList.of(service));

      assertThat(reports.getDetectionReportsList()).isEmpty();
      assertThat(harness.totalConnections()).isEqualTo(1);
    }

    // Fallback candidate (/static/app.js) returning AWSALB cookie after clean '/' must also abort.
    MockNginxConfig fallbackAlbCfg =
        MockNginxConfig.unpatchedDefault()
            .withServerHeader(null)
            .withRouteBody("/", "<script src=\"/static/app.js\"></script>".getBytes(ISO_8859_1))
            .withRouteBody("/static/app.js", new byte[12_000])
            .withRouteHeaders(
                "/static/app.js",
                ImmutableList.of(new HeaderField("set-cookie", "AWSALB=sticky123; Path=/")));
    MockNginxHarness fallbackAlbHarness = startMockNginxServer(fallbackAlbCfg);
    NetworkService fallbackAlbSvc = buildHttpService(fallbackAlbHarness.port(), "http");
    DetectionReportList fallbackAlbReports =
        detector.detect(
            TargetInfo.newBuilder()
                .addNetworkEndpoints(fallbackAlbSvc.getNetworkEndpoint())
                .build(),
            ImmutableList.of(fallbackAlbSvc));
    assertThat(fallbackAlbReports.getDetectionReportsList()).isEmpty();
    assertThat(fallbackAlbHarness.totalConnections()).isEqualTo(1);
  }

  @Test
  public void detect_crawledStaticAssetPreferredAndOversizedSkipped_verifiesSelectedAsset()
      throws Exception {
    String hugePath = "/static/oversized.js";
    String goodCrawledPath = "/static/vendor-" + "a".repeat(130) + ".woff2";
    SSLContext serverSsl = createSelfSignedServerSslContext();
    MockNginxConfig cfg =
        MockNginxConfig.unpatchedDefault()
            .withTlsContext(serverSsl, new String[] {"h2"}, new AtomicReference<>())
            .withRouteBody(hugePath, new byte[200_000])
            .withRouteBody(goodCrawledPath, new byte[14_000])
            .withRouteBody("/", new byte[200]);
    MockNginxHarness harness = startMockNginxServer(cfg);
    Cve2026123007Detector detector = newFastDetector(new LoopbackSocketFactory());

    String longHostname = "sub." + "a".repeat(245) + ".com";
    NetworkEndpoint endpoint =
        NetworkEndpointUtils.forIpHostnameAndPort(LOOPBACK_IP, longHostname, harness.port());
    WebServiceContext webContext =
        WebServiceContext.newBuilder()
            .addCrawlResults(crawlResult("//evil.example.com/pwn.js"))
            .addCrawlResults(crawlResult("https://other.example.com/api/login"))
            .addCrawlResults(crawlResult("https://target.example.com/"))
            .addCrawlResults(crawlResult("https://target.example.com" + hugePath))
            .addCrawlResults(crawlResult("https://target.example.com" + goodCrawledPath))
            .addCrawlResults(crawlResult("https://target.example.com" + goodCrawledPath))
            .addCrawlResults(crawlResult("https://target.example.com/static/extra1.css"))
            .addCrawlResults(crawlResult("https://target.example.com/static/extra2.png"))
            .build();
    NetworkService service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(endpoint)
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("https")
            .setServiceContext(ServiceContext.newBuilder().setWebServiceContext(webContext))
            .build();
    TargetInfo targetInfo = TargetInfo.newBuilder().addNetworkEndpoints(endpoint).build();

    DetectionReportList reports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList()).hasSize(1);
    String detail =
        reports
            .getDetectionReports(0)
            .getVulnerability()
            .getAdditionalDetails(0)
            .getTextData()
            .getText();
    assertThat(detail).contains(goodCrawledPath);
    assertThat(detail).contains("static_body_bytes=14000");
    assertThat(harness.requestedPaths()).doesNotContain("/pwn.js");
  }

  @Test
  public void detect_htmlAssetExtractionRejectsSchemeRelativeAndUpgradesSmallRootToStaticJs()
      throws Exception {
    String html =
        "<html><head>"
            + "<script src=\"//evil.com/a.js\"></script>"
            + "<script src='javascript:alert(1)'></script>"
            + "<link href=\"https://fonts.googleapis.com/css2.css\" rel=\"stylesheet\">"
            + "<script src=\"https://cdn.jsdelivr.net/npm/vendor.js\"></script>"
            + "<link href=\"/assets/app.js\" rel=\"preload\">"
            + "</head><body>welcome</body></html>";
    MockNginxConfig cfg =
        MockNginxConfig.unpatchedDefault()
            .withRouteBody("/", html.getBytes(US_ASCII))
            .withRouteBody("/assets/app.js", new byte[10_240])
            .withPaddedDiscoveryHeadersAndData(true);
    MockNginxHarness harness = startMockNginxServer(cfg);
    Cve2026123007Detector detector = newFastDetector(new LoopbackSocketFactory());

    NetworkService service = buildHttpService(harness.port(), "http");
    TargetInfo targetInfo =
        TargetInfo.newBuilder().addNetworkEndpoints(service.getNetworkEndpoint()).build();

    DetectionReportList reports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList()).hasSize(1);
    String detail =
        reports
            .getDetectionReports(0)
            .getVulnerability()
            .getAdditionalDetails(0)
            .getTextData()
            .getText();
    assertThat(detail).contains("/assets/app.js");
    assertThat(detail).contains("static_body_bytes=10240");
    assertThat(harness.requestedPaths()).doesNotContain("//evil.com/a.js");
    assertThat(harness.requestedPaths()).doesNotContain("/css2.css");
    assertThat(harness.requestedPaths()).doesNotContain("/npm/vendor.js");
    assertThat(harness.sawClientRstStream()).isFalse();
    assertThat(
            H2FlowControlProbe.extractSafeLocalPathForAuthority(
                "https://EDGE.EXAMPLE.COM/assets/app.js", "edge.example.com:8443"))
        .hasValue("/assets/app.js");
    assertThat(
            H2FlowControlProbe.extractSafeLocalPathForAuthority(
                "https://[::1]/assets/app.js", "[::1]:8443"))
        .hasValue("/assets/app.js");
    assertThat(
            H2FlowControlProbe.extractSafeLocalPathForAuthority(
                "https://cdn.jsdelivr.net/npm/vendor.js", "edge.example.com:8443"))
        .isEmpty();
  }

  @Test
  public void detect_emptyRootAndOversizedAssetFallsBackToRandom404StaticPage_verifiesFinding()
      throws Exception {
    MockNginxConfig cfg =
        MockNginxConfig.unpatchedDefault()
            .withMaxConcurrentStreams(8)
            .withRouteBody("/", new byte[0])
            .withDefault404Body(new byte[9_000]);
    MockNginxHarness harness = startMockNginxServer(cfg);
    Cve2026123007Detector detector = newFastDetector(new LoopbackSocketFactory());

    NetworkService service = buildHttpService(harness.port(), "http");
    TargetInfo targetInfo =
        TargetInfo.newBuilder().addNetworkEndpoints(service.getNetworkEndpoint()).build();

    DetectionReportList reports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList()).hasSize(1);
    String detail =
        reports
            .getDetectionReports(0)
            .getVulnerability()
            .getAdditionalDetails(0)
            .getTextData()
            .getText();
    assertThat(detail).contains("static_body_bytes=9000");
    assertThat(harness.sawClientRstStream()).isFalse();
  }

  @Test
  public void detect_targetedRetryWhenRefusedCountExceedsMaxSafeRefused_recoversAndVerifies()
      throws Exception {
    // With max_concurrent_streams=200 (effM=200, maxSafeRefused=96, halfWin=48, step=80) and
    // 200-byte static page:
    // - Attempt 1 (startN=248): 50 flushed + 200 queued = 250 accepted (0 refused -> steps to 328).
    // - Attempt 2 (nStreams=328): 10 flushed + 200 queued = 210 accepted, 118 refused
    //   (96 < 118 <= max(200, 100)). Targeted retry at retryN = 210 + 48 = 258 (where
    //   258 * 200 = 51,600 < 65,535) must execute and succeed on unpatched NGINX while still
    //   rejecting patched NGINX.
    MockNginxConfig unpatchedOvershoot =
        MockNginxConfig.unpatchedDefault()
            .withMaxConcurrentStreams(200)
            .withFirstBurstFlushedBeforeBackpressure(50)
            .withFlushedBeforeBackpressure(10)
            .withRouteBody("/", new byte[200]);
    MockNginxHarness unpatchedHarness = startMockNginxServer(unpatchedOvershoot);
    Cve2026123007Detector detector = newFastDetector(new LoopbackSocketFactory());

    NetworkService unpatchedSvc = buildHttpService(unpatchedHarness.port(), "http");
    TargetInfo unpatchedTarget =
        TargetInfo.newBuilder().addNetworkEndpoints(unpatchedSvc.getNetworkEndpoint()).build();

    DetectionReportList unpatchedReports =
        detector.detect(unpatchedTarget, ImmutableList.of(unpatchedSvc));

    assertThat(unpatchedReports.getDetectionReportsList()).hasSize(1);
    String detail =
        unpatchedReports
            .getDetectionReports(0)
            .getVulnerability()
            .getAdditionalDetails(0)
            .getTextData()
            .getText();
    assertThat(detail).contains("burst_streams=258");
    assertThat(detail).contains("tail_refused_streams=48");
    assertThat(unpatchedHarness.totalConnections()).isEqualTo(4);
    assertThat(unpatchedHarness.sawClientRstStream()).isFalse();

    MockNginxConfig patchedOvershoot =
        MockNginxConfig.patchedDefault()
            .withMaxConcurrentStreams(200)
            .withFirstBurstFlushedBeforeBackpressure(50)
            .withFlushedBeforeBackpressure(10)
            .withRouteBody("/", new byte[200]);
    MockNginxHarness patchedHarness = startMockNginxServer(patchedOvershoot);
    NetworkService patchedSvc = buildHttpService(patchedHarness.port(), "http");
    TargetInfo patchedTarget =
        TargetInfo.newBuilder().addNetworkEndpoints(patchedSvc.getNetworkEndpoint()).build();

    DetectionReportList patchedReports =
        detector.detect(patchedTarget, ImmutableList.of(patchedSvc));

    assertThat(patchedReports.getDetectionReportsList()).isEmpty();
    assertThat(patchedHarness.sawClientRstStream()).isFalse();

    // Also verify overshoot at max_concurrent_streams=100 where excess streams (118 > max(100,100))
    // trigger GOAWAY(NO_ERROR) truncation after 101 RST_STREAM frames.
    MockNginxConfig truncatedOvershoot =
        MockNginxConfig.unpatchedDefault()
            .withMaxConcurrentStreams(100)
            .withFirstBurstFlushedBeforeBackpressure(50)
            .withFlushedBeforeBackpressure(10)
            .withRouteBody("/", new byte[200]);
    MockNginxHarness truncatedHarness = startMockNginxServer(truncatedOvershoot);
    NetworkService truncatedSvc = buildHttpService(truncatedHarness.port(), "http");
    DetectionReportList truncatedReports =
        detector.detect(
            TargetInfo.newBuilder().addNetworkEndpoints(truncatedSvc.getNetworkEndpoint()).build(),
            ImmutableList.of(truncatedSvc));
    assertThat(truncatedReports.getDetectionReportsList()).hasSize(1);
    assertThat(
            truncatedReports
                .getDetectionReports(0)
                .getVulnerability()
                .getAdditionalDetails(0)
                .getTextData()
                .getText())
        .contains("burst_streams=158, tail_refused_streams=48");
  }

  @Test
  public void detect_ladderStepsUpWhenFirstBurstHasZeroRefusedStreams_verifiesOnNextStep()
      throws Exception {
    // With max_concurrent_streams=8, startN=12. Setting flushed=6 accepts up to 6+8=14 streams,
    // so nStreams=12 has refusedCount=0 (pings A & B ACKed), stepping ladder to nStreams=20 where
    // 6 tail streams are refused and verified.
    MockNginxConfig cfg =
        MockNginxConfig.unpatchedDefault()
            .withMaxConcurrentStreams(8)
            .withFlushedBeforeBackpressure(6);
    MockNginxHarness harness = startMockNginxServer(cfg);
    Cve2026123007Detector detector = newFastDetector(new LoopbackSocketFactory());

    NetworkService service = buildHttpService(harness.port(), "http");
    TargetInfo targetInfo =
        TargetInfo.newBuilder().addNetworkEndpoints(service.getNetworkEndpoint()).build();

    DetectionReportList reports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList()).hasSize(1);
    assertThat(
            reports
                .getDetectionReports(0)
                .getVulnerability()
                .getAdditionalDetails(0)
                .getTextData()
                .getText())
        .contains("burst_streams=20, tail_refused_streams=6");
    assertThat(harness.totalConnections()).isEqualTo(3);
  }

  @Test
  public void detect_nonContiguousRefusedStreamsOrDroppedLivenessPingC_returnsEmpty()
      throws Exception {
    MockNginxConfig nonContiguousCfg =
        MockNginxConfig.unpatchedDefault().withNonContiguousRefusedStream(true);
    MockNginxHarness nonContiguousHarness = startMockNginxServer(nonContiguousCfg);
    Cve2026123007Detector detector = newFastDetector(new LoopbackSocketFactory());

    NetworkService svc1 = buildHttpService(nonContiguousHarness.port(), "http");
    DetectionReportList r1 =
        detector.detect(
            TargetInfo.newBuilder().addNetworkEndpoints(svc1.getNetworkEndpoint()).build(),
            ImmutableList.of(svc1));
    assertThat(r1.getDetectionReportsList()).isEmpty();

    MockNginxConfig dropPingCCfg = MockNginxConfig.unpatchedDefault().withDropPingCAck(true);
    MockNginxHarness dropPingCHarness = startMockNginxServer(dropPingCCfg);
    NetworkService svc2 = buildHttpService(dropPingCHarness.port(), "http");
    DetectionReportList r2 =
        detector.detect(
            TargetInfo.newBuilder().addNetworkEndpoints(svc2.getNetworkEndpoint()).build(),
            ImmutableList.of(svc2));
    assertThat(r2.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void detect_prePingBFlushedDataAndBurstUserAgentGuards_enforceInvariants()
      throws Exception {
    Cve2026123007Detector detector = newFastDetector(new LoopbackSocketFactory());

    // 1. Excessive pre-PING(B) flushed DATA across all steps rejects potential limit_req/partial
    // FP.
    MockNginxConfig excessivePrePingB =
        MockNginxConfig.unpatchedDefault()
            .withFlushedBeforeBackpressure(0)
            .withRouteBody("/", new byte[50])
            .withDefault404Body(new byte[50])
            .withPrePingBFlushBytes(48_000);
    MockNginxHarness fpHarness = startMockNginxServer(excessivePrePingB);
    NetworkService fpSvc = buildHttpService(fpHarness.port(), "http");
    DetectionReportList fpReports =
        detector.detect(
            TargetInfo.newBuilder().addNetworkEndpoints(fpSvc.getNetworkEndpoint()).build(),
            ImmutableList.of(fpSvc));
    assertThat(fpReports.getDetectionReportsList()).isEmpty();

    // 2. Boundary pre-PING(B) DATA equal to Attempt 1 differential ((168-120)*200 = 9600) steps up
    //    to Attempt 2 (nStreams=248, refused=88 <= 96, max=25600), ignores post-PING(B) DATA
    //    (20000), and enforces non-empty TsunamiSecurityScanner User-Agent across Streams 1..2N-1.
    MockNginxConfig stepUpAndUaCfg =
        MockNginxConfig.unpatchedDefault()
            .withMaxConcurrentStreams(120)
            .withFlushedBeforeBackpressure(40)
            .withRouteBody("/", new byte[200])
            .withDefault404Body(new byte[200])
            .withPrePingBFlushBytes(9_600)
            .withRequireScannerUserAgent(true);
    MockNginxHarness okHarness = startMockNginxServer(stepUpAndUaCfg);
    NetworkService okSvc = buildHttpService(okHarness.port(), "http");
    DetectionReportList okReports =
        detector.detect(
            TargetInfo.newBuilder().addNetworkEndpoints(okSvc.getNetworkEndpoint()).build(),
            ImmutableList.of(okSvc));
    assertThat(okReports.getDetectionReportsList()).hasSize(1);
    assertThat(
            okReports
                .getDetectionReports(0)
                .getVulnerability()
                .getAdditionalDetails(0)
                .getTextData()
                .getText())
        .contains("burst_streams=248, tail_refused_streams=88");
  }

  @Test
  public void detect_cleartextZeroByteEofFallsBackToTlsH2WithSni_returnsVerifiedFinding()
      throws Exception {
    SSLContext serverSsl = createSelfSignedServerSslContext();
    AtomicReference<List<SNIServerName>> capturedSni = new AtomicReference<>(ImmutableList.of());
    MockNginxConfig tlsCfg =
        MockNginxConfig.unpatchedDefault()
            .withTlsContext(serverSsl, new String[] {"h2"}, capturedSni)
            .withCleartextZeroByteEofBeforeTls(true);
    MockNginxHarness harness = startMockNginxServer(tlsCfg);
    Cve2026123007Detector detector = newFastDetector(new LoopbackSocketFactory());

    NetworkEndpoint endpoint =
        NetworkEndpointUtils.forIpHostnameAndPort(LOOPBACK_IP, "edge.example.com", harness.port());
    NetworkService plainHttpService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(endpoint)
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("http")
            .build();
    TargetInfo targetInfo = TargetInfo.newBuilder().addNetworkEndpoints(endpoint).build();

    DetectionReportList reports = detector.detect(targetInfo, ImmutableList.of(plainHttpService));

    assertThat(reports.getDetectionReportsList()).hasSize(1);
    String detail =
        reports
            .getDetectionReports(0)
            .getVulnerability()
            .getAdditionalDetails(0)
            .getTextData()
            .getText();
    assertThat(detail).contains("over HTTP/2 (h2) at https://edge.example.com:" + harness.port());
    assertThat(capturedSni.get()).isNotEmpty();
    assertThat(harness.totalConnections()).isEqualTo(3);
    assertThat(harness.sawClientRstStream()).isFalse();
  }

  @Test
  public void detect_httpsServiceNegotiatingHttp11Alpn_closesCleanlyAndReturnsEmpty()
      throws Exception {
    SSLContext serverSsl = createSelfSignedServerSslContext();
    MockNginxConfig tlsHttp11Cfg =
        MockNginxConfig.unpatchedDefault()
            .withTlsContext(serverSsl, new String[] {"http/1.1"}, new AtomicReference<>());
    MockNginxHarness harness = startMockNginxServer(tlsHttp11Cfg);
    Cve2026123007Detector detector = newFastDetector(new LoopbackSocketFactory());

    NetworkService httpsService = buildHttpService(harness.port(), "https");
    TargetInfo targetInfo =
        TargetInfo.newBuilder().addNetworkEndpoints(httpsService.getNetworkEndpoint()).build();

    DetectionReportList reports = detector.detect(targetInfo, ImmutableList.of(httpsService));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(harness.totalConnections()).isEqualTo(1);
  }

  @Test
  public void detect_ioExceptionFromSocketFactory_returnsEmptyCleanly() throws Exception {
    TsunamiSocketFactory failingFactory = mock(TsunamiSocketFactory.class);
    when(failingFactory.createSocket(anyString(), anyInt(), any(Duration.class)))
        .thenThrow(new IOException("connection refused"));
    Cve2026123007Detector detector = newFastDetector(failingFactory);

    NetworkService service = buildHttpService(18080, "http");
    TargetInfo targetInfo =
        TargetInfo.newBuilder().addNetworkEndpoints(service.getNetworkEndpoint()).build();

    DetectionReportList reports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void detect_hostnameOnlyEndpoint_pinsPhase1ValidatedInetAddressAgainstDnsRebinding()
      throws Exception {
    MockNginxHarness harness = startMockNginxServer(MockNginxConfig.unpatchedDefault());
    NetworkEndpoint hostnameOnlyEndpoint =
        NetworkEndpoint.newBuilder()
            .setType(NetworkEndpoint.Type.HOSTNAME_PORT)
            .setHostname(Hostname.newBuilder().setName("rebind-guard.invalid"))
            .setPort(Port.newBuilder().setPortNumber(harness.port()))
            .build();
    NetworkService service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(hostnameOnlyEndpoint)
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("http")
            .build();
    TargetInfo targetInfo =
        TargetInfo.newBuilder().addNetworkEndpoints(hostnameOnlyEndpoint).build();

    // 1. Unconnected socket path pins Phase 1's resolved InetAddress without re-resolving hostname.
    List<InetSocketAddress> unconnectedConnectTargets =
        Collections.synchronizedList(new ArrayList<>());
    AtomicInteger stringHostDials = new AtomicInteger(0);
    LoopbackSocketFactory baseFactory = new LoopbackSocketFactory();
    TsunamiSocketFactory pinningFactory =
        new ForwardingLoopbackFactory(baseFactory) {
          @Override
          public Socket createSocket(String host, int port, Duration timeout) throws IOException {
            stringHostDials.incrementAndGet();
            return baseFactory.createSocket(LOOPBACK_ADDR, port, timeout);
          }

          @Override
          public Socket createUnconnectedSocket() {
            return new Socket() {
              @Override
              public void connect(SocketAddress endpoint, int timeout) throws IOException {
                unconnectedConnectTargets.add((InetSocketAddress) endpoint);
                super.connect(endpoint, timeout);
              }
            };
          }
        };
    DetectionReportList pinnedReports =
        newFastDetector(pinningFactory).detect(targetInfo, ImmutableList.of(service));
    assertThat(pinnedReports.getDetectionReportsList()).hasSize(1);
    assertThat(stringHostDials.get()).isEqualTo(1);
    assertThat(unconnectedConnectTargets).isNotEmpty();
    for (InetSocketAddress addr : unconnectedConnectTargets) {
      assertThat(addr.getAddress()).isEqualTo(LOOPBACK_ADDR);
    }

    // 2. Null createUnconnectedSocket() path delegates to createSocket(InetAddress, port, timeout).
    AtomicInteger inetAddrDials = new AtomicInteger(0);
    TsunamiSocketFactory noUnconnectedPinningFactory =
        new ForwardingLoopbackFactory(baseFactory) {
          @Override
          public Socket createSocket(String host, int port, Duration timeout) throws IOException {
            return baseFactory.createSocket(LOOPBACK_ADDR, port, timeout);
          }

          @Override
          public Socket createSocket(InetAddress address, int port, Duration timeout)
              throws IOException {
            inetAddrDials.incrementAndGet();
            return baseFactory.createSocket(address, port, timeout);
          }

          @Override
          public Socket createUnconnectedSocket() {
            return null;
          }
        };
    DetectionReportList noUnconnectedReports =
        newFastDetector(noUnconnectedPinningFactory).detect(targetInfo, ImmutableList.of(service));
    assertThat(noUnconnectedReports.getDetectionReportsList()).hasSize(1);
    assertThat(inetAddrDials.get()).isGreaterThan(0);

    // 3. Null Socket.getInetAddress() falls back to createSocket(host, port, timeout) in Phase 2.
    AtomicInteger fallbackStringDials = new AtomicInteger(0);
    AtomicBoolean unconnectedCalled = new AtomicBoolean(false);
    TsunamiSocketFactory nullInetAddrFactory =
        new ForwardingLoopbackFactory(baseFactory) {
          @Override
          public Socket createSocket(String host, int port, Duration timeout) throws IOException {
            fallbackStringDials.incrementAndGet();
            Socket real = baseFactory.createSocket(LOOPBACK_ADDR, port, timeout);
            if (fallbackStringDials.get() > 1) {
              return real;
            }
            Socket phase1WithoutInetAddr = mock(Socket.class);
            when(phase1WithoutInetAddr.getInetAddress()).thenReturn(null);
            when(phase1WithoutInetAddr.getInputStream()).thenReturn(real.getInputStream());
            when(phase1WithoutInetAddr.getOutputStream()).thenReturn(real.getOutputStream());
            doAnswer(
                    inv -> {
                      real.close();
                      return null;
                    })
                .when(phase1WithoutInetAddr)
                .close();
            return phase1WithoutInetAddr;
          }

          @Override
          public Socket createUnconnectedSocket() {
            unconnectedCalled.set(true);
            return new Socket();
          }
        };
    DetectionReportList fallbackReports =
        newFastDetector(nullInetAddrFactory).detect(targetInfo, ImmutableList.of(service));
    assertThat(fallbackReports.getDetectionReportsList()).hasSize(1);
    assertThat(fallbackStringDials.get()).isGreaterThan(1);
    assertThat(unconnectedCalled.get()).isFalse();
  }

  @Test
  public void detect_smallStaticBody_verifiesWithoutInflatingBurst() throws Exception {
    // Small 50-byte static response body starts at effM + halfWin = 12 without over-inflating
    // startN past NGINX's refused_streams guard, verifying unpatched NGINX cleanly.
    MockNginxConfig tinyBodyCfg =
        MockNginxConfig.unpatchedDefault()
            .withRouteBody("/", new byte[50])
            .withDefault404Body(new byte[50]);
    MockNginxHarness tinyHarness = startMockNginxServer(tinyBodyCfg);
    Cve2026123007Detector detector = newFastDetector(new LoopbackSocketFactory());
    NetworkService tinySvc = buildHttpService(tinyHarness.port(), "http");
    assertThat(
            detector
                .detect(
                    TargetInfo.newBuilder()
                        .addNetworkEndpoints(tinySvc.getNetworkEndpoint())
                        .build(),
                    ImmutableList.of(tinySvc))
                .getDetectionReportsList())
        .hasSize(1);
  }

  @Test
  public void detect_malformedDiscoveryFrames_returnsEmptyCleanly() throws Exception {
    Cve2026123007Detector detector = newFastDetector(new LoopbackSocketFactory());
    List<byte[]> malformedServerStreams = new ArrayList<>();
    byte[] validGreeting = buildValidGreetingBytes();
    // 1. Stream 1 RST_STREAM during discovery.
    ByteArrayOutputStream rstDiscovery = new ByteArrayOutputStream();
    rstDiscovery.writeBytes(validGreeting);
    H2Frames.writeFrame(rstDiscovery, H2Frames.TYPE_RST_STREAM, 0, 1, new byte[] {0, 0, 0, 7});
    malformedServerStreams.add(rstDiscovery.toByteArray());

    // 2. Empty padded DATA frame on Stream 1.
    ByteArrayOutputStream emptyPaddedData = new ByteArrayOutputStream();
    emptyPaddedData.writeBytes(validGreeting);
    H2Frames.writeFrame(
        emptyPaddedData,
        H2Frames.TYPE_HEADERS,
        H2Frames.FLAG_END_HEADERS,
        1,
        new byte[] {(byte) 0x88});
    H2Frames.writeFrame(emptyPaddedData, H2Frames.TYPE_DATA, H2Frames.FLAG_PADDED, 1, new byte[0]);
    malformedServerStreams.add(emptyPaddedData.toByteArray());

    // 3. Padded DATA frame with padLen >= payload.length.
    ByteArrayOutputStream overPaddedData = new ByteArrayOutputStream();
    overPaddedData.writeBytes(validGreeting);
    H2Frames.writeFrame(
        overPaddedData,
        H2Frames.TYPE_HEADERS,
        H2Frames.FLAG_END_HEADERS,
        1,
        new byte[] {(byte) 0x88});
    H2Frames.writeFrame(
        overPaddedData, H2Frames.TYPE_DATA, H2Frames.FLAG_PADDED, 1, new byte[] {5, 1, 2});
    malformedServerStreams.add(overPaddedData.toByteArray());

    // 4. Empty padded HEADERS frame.
    ByteArrayOutputStream emptyPaddedHeaders = new ByteArrayOutputStream();
    emptyPaddedHeaders.writeBytes(validGreeting);
    H2Frames.writeFrame(
        emptyPaddedHeaders,
        H2Frames.TYPE_HEADERS,
        H2Frames.FLAG_PADDED | H2Frames.FLAG_END_HEADERS,
        1,
        new byte[0]);
    malformedServerStreams.add(emptyPaddedHeaders.toByteArray());

    // 5. HEADERS without END_HEADERS followed by non-CONTINUATION frame.
    ByteArrayOutputStream badCont = new ByteArrayOutputStream();
    badCont.writeBytes(validGreeting);
    H2Frames.writeFrame(badCont, H2Frames.TYPE_HEADERS, 0, 1, new byte[] {(byte) 0x88});
    H2Frames.writeFrame(badCont, H2Frames.TYPE_PING, 0, 0, new byte[8]);
    malformedServerStreams.add(badCont.toByteArray());

    for (byte[] rawResp : malformedServerStreams) {
      ServerSocket rawServer = new ServerSocket(0, 16, LOOPBACK_ADDR);
      openServers.add(rawServer);
      serverExecutor.execute(() -> {
        try (Socket client = rawServer.accept()) {
          byte[] ignoredPreface = client.getInputStream().readNBytes(clientPreface.length);
          if (ignoredPreface.length > 0) {
            client.getOutputStream().write(rawResp);
            client.getOutputStream().flush();
          }
        } catch (IOException ignored) {
          // Peer closed.
        }
      });
      NetworkService svc = buildHttpService(rawServer.getLocalPort(), "http");
      assertThat(
              detector
                  .detect(
                      TargetInfo.newBuilder().addNetworkEndpoints(svc.getNetworkEndpoint()).build(),
                      ImmutableList.of(svc))
                  .getDetectionReportsList())
          .isEmpty();
    }
  }

  @Test
  public void urlAndAuthorityHelpers_validateBoundariesAndRejectUnsafeInputs() {
    assertThat(H2FlowControlProbe.extractSafeLocalPath(null)).isEmpty();
    assertThat(H2FlowControlProbe.extractSafeLocalPath("")).isEmpty();
    assertThat(H2FlowControlProbe.extractSafeLocalPath("//evil.com/a.js")).isEmpty();
    assertThat(H2FlowControlProbe.extractSafeLocalPath("http://example.com//evil.com/a.js"))
        .isEmpty();
    assertThat(H2FlowControlProbe.extractSafeLocalPath("ftp://example.com/a.js")).isEmpty();
    assertThat(H2FlowControlProbe.extractSafeLocalPath("javascript:alert(1)")).isEmpty();
    assertThat(H2FlowControlProbe.extractSafeLocalPath("relative/a.js")).isEmpty();
    assertThat(H2FlowControlProbe.extractSafeLocalPath("http://example.com")).isEmpty();
    assertThat(H2FlowControlProbe.extractSafeLocalPath("/bad\u007f.js")).isEmpty();
    assertThat(H2FlowControlProbe.extractSafeLocalPath("/caf\u00e9.js")).isEmpty();
    assertThat(H2FlowControlProbe.extractSafeLocalPath("/bad space.js")).isEmpty();
    assertThat(H2FlowControlProbe.extractSafeLocalPath("/" + "a".repeat(200))).isEmpty();
    assertThat(H2FlowControlProbe.extractSafeLocalPath("/" + "a".repeat(196) + ".js"))
        .hasValue("/" + "a".repeat(196) + ".js");
    assertThat(
            H2FlowControlProbe.extractSafeLocalPath("HTTPS://example.com:8443/static/app.JS?v=1"))
        .hasValue("/static/app.JS");

    assertThat(H2FlowControlProbe.hasStaticExtension("/app.JS")).isTrue();
    assertThat(H2FlowControlProbe.hasStaticExtension("/font.woff2")).isTrue();
    assertThat(H2FlowControlProbe.hasStaticExtension("/api/v1/users")).isFalse();

    assertThat(H2FlowControlProbe.isValidAuthorityHost(null)).isFalse();
    assertThat(H2FlowControlProbe.isValidAuthorityHost("")).isFalse();
    assertThat(H2FlowControlProbe.isValidAuthorityHost("a".repeat(254))).isFalse();
    assertThat(H2FlowControlProbe.isValidAuthorityHost("a".repeat(253))).isTrue();
    assertThat(H2FlowControlProbe.isValidAuthorityHost("bad\r\nhost")).isFalse();

    assertThat(H2FlowControlProbe.formatAuthority("example.com", 80, false))
        .isEqualTo("example.com");
    assertThat(H2FlowControlProbe.formatAuthority("example.com", 443, true))
        .isEqualTo("example.com");
    assertThat(H2FlowControlProbe.formatAuthority("example.com", 8080, false))
        .isEqualTo("example.com:8080");
    assertThat(H2FlowControlProbe.formatAuthority("::1", 80, false)).isEqualTo("[::1]");
    assertThat(H2FlowControlProbe.formatAuthority("[::1]", 443, true)).isEqualTo("[::1]");
    assertThat(H2FlowControlProbe.formatAuthority("::1", 8443, true)).isEqualTo("[::1]:8443");
  }

  @Test
  public void detect_singleStreamServerWithoutBackpressure_capsLadderAttempts() throws Exception {
    MockNginxConfig cfg =
        MockNginxConfig.unpatchedDefault()
            .withMaxConcurrentStreams(1)
            .withFlushedBeforeBackpressure(100);
    MockNginxHarness harness = startMockNginxServer(cfg);
    Cve2026123007Detector detector = newFastDetector(new LoopbackSocketFactory());

    NetworkService service = buildHttpService(harness.port(), "http");
    TargetInfo targetInfo =
        TargetInfo.newBuilder().addNetworkEndpoints(service.getNetworkEndpoint()).build();

    DetectionReportList reports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    // 1 discovery connection + 16 capped Phase 2 ladder attempts.
    assertThat(harness.totalConnections()).isEqualTo(17);
  }

  @Test
  public void clampSocketTimeoutMillis_clampsSubMillisecondNegativeAndOverflowDurations() {
    assertThat(H2FlowControlProbe.clampSocketTimeoutMillis(Duration.ofSeconds(Long.MIN_VALUE)))
        .isEqualTo(1);
    assertThat(H2FlowControlProbe.clampSocketTimeoutMillis(Duration.ofMillis(-5))).isEqualTo(1);
    assertThat(H2FlowControlProbe.clampSocketTimeoutMillis(Duration.ZERO)).isEqualTo(1);
    assertThat(H2FlowControlProbe.clampSocketTimeoutMillis(Duration.ofNanos(500_000))).isEqualTo(1);
    assertThat(H2FlowControlProbe.clampSocketTimeoutMillis(Duration.ofMillis(1))).isEqualTo(1);
    assertThat(H2FlowControlProbe.clampSocketTimeoutMillis(Duration.ofSeconds(3))).isEqualTo(3000);
    assertThat(H2FlowControlProbe.clampSocketTimeoutMillis(Duration.ofMillis(Integer.MAX_VALUE)))
        .isEqualTo(Integer.MAX_VALUE);
    assertThat(H2FlowControlProbe.clampSocketTimeoutMillis(Duration.ofDays(30)))
        .isEqualTo(Integer.MAX_VALUE);
    assertThat(H2FlowControlProbe.clampSocketTimeoutMillis(Duration.ofSeconds(Long.MAX_VALUE)))
        .isEqualTo(Integer.MAX_VALUE);
  }

  @Test
  public void detect_oversizedTimeout_clampsConstrainedSocketConnectTimeoutToMaxInt()
      throws Exception {
    MockNginxHarness harness = startMockNginxServer(MockNginxConfig.unpatchedDefault());
    AtomicInteger observedConnectTimeout = new AtomicInteger(-1);
    LoopbackSocketFactory baseFactory = new LoopbackSocketFactory();
    TsunamiSocketFactory capturingFactory =
        new ForwardingLoopbackFactory(baseFactory) {
          @Override
          public Socket createSocket(String host, int port, Duration timeout) throws IOException {
            return baseFactory.createSocket(host, port, Duration.ofSeconds(3));
          }

          @Override
          public Socket createUnconnectedSocket() {
            return new Socket() {
              @Override
              public void connect(SocketAddress endpoint, int timeout) throws IOException {
                observedConnectTimeout.set(timeout);
                super.connect(endpoint, timeout);
              }
            };
          }
        };
    Cve2026123007Detector detector =
        new Cve2026123007Detector(
            fakeUtcClock,
            new H2FlowControlProbe(
                capturingFactory,
                Duration.ofDays(30),
                Duration.ZERO,
                Duration.ZERO,
                new SecureRandom()));
    NetworkService service = buildHttpService(harness.port(), "http");
    TargetInfo targetInfo =
        TargetInfo.newBuilder().addNetworkEndpoints(service.getNetworkEndpoint()).build();

    assertThat(detector.detect(targetInfo, ImmutableList.of(service)).getDetectionReportsList())
        .hasSize(1);
    assertThat(observedConnectTimeout.get()).isEqualTo(Integer.MAX_VALUE);
  }

  @Test
  public void detect_httpsOutOfRangeTimeouts_clampsTlsSocketReadTimeout() throws Exception {
    LoopbackSocketFactory baseFactory = new LoopbackSocketFactory();
    ServerSocket tcpServer = new ServerSocket(0, 16, LOOPBACK_ADDR);
    openServers.add(tcpServer);
    TsunamiSocketFactory safePhase1Factory =
        new ForwardingLoopbackFactory(baseFactory) {
          @Override
          public Socket createSocket(String host, int port, Duration timeout) throws IOException {
            return baseFactory.createSocket(host, port, Duration.ofSeconds(3));
          }
        };
    NetworkService httpsService = buildHttpService(tcpServer.getLocalPort(), "https");
    TargetInfo targetInfo =
        TargetInfo.newBuilder().addNetworkEndpoints(httpsService.getNetworkEndpoint()).build();

    SSLSocket oversizedSslSocket = mock(SSLSocket.class);
    when(oversizedSslSocket.getSSLParameters()).thenReturn(new SSLParameters());
    when(oversizedSslSocket.getApplicationProtocol()).thenReturn("http/1.1");
    SSLSocketFactory oversizedSslFactory = mock(SSLSocketFactory.class);
    when(oversizedSslFactory.createSocket(any(Socket.class), anyString(), anyInt(), anyBoolean()))
        .thenReturn(oversizedSslSocket);
    Cve2026123007Detector oversizedDetector =
        new Cve2026123007Detector(
            fakeUtcClock,
            new H2FlowControlProbe(
                safePhase1Factory,
                Duration.ofDays(30),
                Duration.ZERO,
                Duration.ZERO,
                new SecureRandom(),
                oversizedSslFactory));
    assertThat(
            oversizedDetector
                .detect(targetInfo, ImmutableList.of(httpsService))
                .getDetectionReportsList())
        .isEmpty();
    verify(oversizedSslSocket).setSoTimeout(Integer.MAX_VALUE);
    verify(oversizedSslSocket).close();

    SSLSocket subMsSslSocket = mock(SSLSocket.class);
    when(subMsSslSocket.getSSLParameters()).thenReturn(new SSLParameters());
    when(subMsSslSocket.getApplicationProtocol()).thenReturn("http/1.1");
    SSLSocketFactory subMsSslFactory = mock(SSLSocketFactory.class);
    when(subMsSslFactory.createSocket(any(Socket.class), anyString(), anyInt(), anyBoolean()))
        .thenReturn(subMsSslSocket);
    Cve2026123007Detector subMsDetector =
        new Cve2026123007Detector(
            fakeUtcClock,
            new H2FlowControlProbe(
                safePhase1Factory,
                Duration.ofNanos(500_000),
                Duration.ZERO,
                Duration.ZERO,
                new SecureRandom(),
                subMsSslFactory));
    assertThat(
            subMsDetector
                .detect(targetInfo, ImmutableList.of(httpsService))
                .getDetectionReportsList())
        .isEmpty();
    verify(subMsSslSocket).setSoTimeout(1);
    verify(subMsSslSocket).close();
  }

  @Test
  public void detect_singleHeadersFrameSizeCap_accepts32KiBAndRejectsOversized() throws Exception {
    Cve2026123007Detector detector = newFastDetector(new LoopbackSocketFactory());

    MockNginxHarness atLimitHarness =
        startMockNginxServer(
            MockNginxConfig.unpatchedDefault().withDiscoveryHeaderBlockMinBytes(32_768));
    NetworkService atLimitSvc = buildHttpService(atLimitHarness.port(), "http");
    assertThat(
            detector
                .detect(
                    TargetInfo.newBuilder()
                        .addNetworkEndpoints(atLimitSvc.getNetworkEndpoint())
                        .build(),
                    ImmutableList.of(atLimitSvc))
                .getDetectionReportsList())
        .hasSize(1);

    MockNginxHarness overLimitHarness =
        startMockNginxServer(
            MockNginxConfig.unpatchedDefault().withDiscoveryHeaderBlockMinBytes(32_769));
    NetworkService overLimitSvc = buildHttpService(overLimitHarness.port(), "http");
    assertThat(
            detector
                .detect(
                    TargetInfo.newBuilder()
                        .addNetworkEndpoints(overLimitSvc.getNetworkEndpoint())
                        .build(),
                    ImmutableList.of(overLimitSvc))
                .getDetectionReportsList())
        .isEmpty();
    assertThat(overLimitHarness.totalConnections()).isEqualTo(1);
  }

  @Test
  public void detect_httpsHandshakeFailureAgainstNonTlsPeer_closesSslSocketAndReturnsEmpty()
      throws Exception {
    ServerSocket nonTlsServer = new ServerSocket(0, 16, LOOPBACK_ADDR);
    openServers.add(nonTlsServer);
    serverExecutor.execute(() -> {
      try (Socket client = nonTlsServer.accept()) {
        client.getOutputStream().write("HTTP/1.1 400 Bad Request\r\n\r\n".getBytes(US_ASCII));
        client.getOutputStream().flush();
      } catch (IOException ignored) {
        // Peer closed after TLS handshake failure.
      }
    });

    RecordingSslSocketFactory recordingSslFactory =
        new RecordingSslSocketFactory(
            H2FlowControlProbe.createPermissiveSslSocketFactory(new SecureRandom()));
    Cve2026123007Detector detector =
        new Cve2026123007Detector(
            fakeUtcClock,
            new H2FlowControlProbe(
                new LoopbackSocketFactory(),
                Duration.ofSeconds(3),
                Duration.ZERO,
                Duration.ZERO,
                new SecureRandom(),
                recordingSslFactory));
    NetworkService httpsService = buildHttpService(nonTlsServer.getLocalPort(), "https");
    TargetInfo targetInfo =
        TargetInfo.newBuilder().addNetworkEndpoints(httpsService.getNetworkEndpoint()).build();

    assertThat(
            detector.detect(targetInfo, ImmutableList.of(httpsService)).getDetectionReportsList())
        .isEmpty();
    assertThat(recordingSslFactory.createdSockets()).hasSize(1);
    assertThat(recordingSslFactory.createdSockets().get(0).isClosed()).isTrue();
  }

  @Test
  public void detect_httpsSuccessfulProbe_closesAllPhase1AndPhase2SslSockets() throws Exception {
    SSLContext serverSsl = createSelfSignedServerSslContext();
    MockNginxConfig tlsCfg =
        MockNginxConfig.unpatchedDefault()
            .withTlsContext(serverSsl, new String[] {"h2"}, new AtomicReference<>());
    MockNginxHarness harness = startMockNginxServer(tlsCfg);
    RecordingSslSocketFactory recordingSslFactory =
        new RecordingSslSocketFactory(
            H2FlowControlProbe.createPermissiveSslSocketFactory(new SecureRandom()));
    Cve2026123007Detector detector =
        new Cve2026123007Detector(
            fakeUtcClock,
            new H2FlowControlProbe(
                new LoopbackSocketFactory(),
                Duration.ofSeconds(3),
                Duration.ZERO,
                Duration.ZERO,
                new SecureRandom(),
                recordingSslFactory));
    NetworkService httpsService = buildHttpService(harness.port(), "https");
    TargetInfo targetInfo =
        TargetInfo.newBuilder().addNetworkEndpoints(httpsService.getNetworkEndpoint()).build();

    assertThat(
            detector.detect(targetInfo, ImmutableList.of(httpsService)).getDetectionReportsList())
        .hasSize(1);
    assertThat(recordingSslFactory.createdSockets().size()).isAtLeast(2);
    for (SSLSocket sslSocket : recordingSslFactory.createdSockets()) {
      assertThat(sslSocket.isClosed()).isTrue();
    }
  }

  @Test
  public void detect_highConcurrencyZeroRefusedBurst_verifiesUnpatchedWithoutClientRst()
      throws Exception {
    MockNginxConfig config = MockNginxConfig.unpatchedDefault().withMaxConcurrentStreams(10_000);
    MockNginxHarness harness = startMockNginxServer(config);
    Cve2026123007Detector detector = newFastDetector(new LoopbackSocketFactory());

    NetworkService service = buildHttpService(harness.port(), "http");
    TargetInfo targetInfo =
        TargetInfo.newBuilder().addNetworkEndpoints(service.getNetworkEndpoint()).build();

    DetectionReportList reports = detector.detect(targetInfo, ImmutableList.of(service));

    // For max_concurrent_streams=10000 and bodyLen=12288:
    // firstBurst = max(256, ceil(131072 / 12288)) = 256, slack = 256 / 8 = 32,
    // wuIncrement = 0x7fffffff - 32 * 12288 = 2147090431.
    String authority = HostAndPort.fromParts(LOOPBACK_IP, harness.port()).toString();
    String expectedDetail =
        String.format(
            "Verified unpatched NGINX ngx_http_v2 flow-control window validation over HTTP/2 (h2c)"
                + " at http://%s/ (settings_len=18, max_concurrent_streams=10000,"
                + " static_body_bytes=12288, burst_streams=256, tail_refused_streams=0,"
                + " stream0_window_update=2147090431 accepted with queued DATA frames in"
                + " h2c->last_out and verified by pre/post/liveness PING ACKs).",
            authority);

    assertThat(reports)
        .isEqualTo(
            DetectionReportList.newBuilder()
                .addDetectionReports(expectedReport(detector, targetInfo, service, expectedDetail))
                .build());
    assertThat(harness.totalConnections()).isEqualTo(2);
    assertThat(harness.sawClientRstStream()).isFalse();
  }

  @Test
  public void detect_highConcurrencyPatchedNginx_sendsFlowControlGoAwayAndReturnsEmpty()
      throws Exception {
    MockNginxConfig config = MockNginxConfig.patchedDefault().withMaxConcurrentStreams(10_000);
    MockNginxHarness harness = startMockNginxServer(config);
    Cve2026123007Detector detector = newFastDetector(new LoopbackSocketFactory());

    NetworkService service = buildHttpService(harness.port(), "http");
    TargetInfo targetInfo =
        TargetInfo.newBuilder().addNetworkEndpoints(service.getNetworkEndpoint()).build();

    DetectionReportList reports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(harness.totalConnections()).isEqualTo(2);
    assertThat(harness.sawClientRstStream()).isFalse();
  }

  @Test
  public void detect_highConcurrencyFirstBurstDrainsCompletely_stepsUpToMaxBurst940AndVerifies()
      throws Exception {
    MockNginxConfig config =
        MockNginxConfig.unpatchedDefault()
            .withMaxConcurrentStreams(10_000)
            .withFirstBurstFlushAllDataBeforePingB(true);
    MockNginxHarness harness = startMockNginxServer(config);
    Cve2026123007Detector detector = newFastDetector(new LoopbackSocketFactory());

    NetworkService service = buildHttpService(harness.port(), "http");
    TargetInfo targetInfo =
        TargetInfo.newBuilder().addNetworkEndpoints(service.getNetworkEndpoint()).build();

    DetectionReportList reports = detector.detect(targetInfo, ImmutableList.of(service));

    // Attempt 1 (256 streams) flushes all DATA before PING(ACK, B); Attempt 2 steps to 940 streams
    // with slack = min(940 / 8, 96) = 96 -> wuIncrement = 0x7fffffff - 96 * 12288 = 2146303999.
    assertThat(reports.getDetectionReportsList()).hasSize(1);
    String detail =
        reports
            .getDetectionReports(0)
            .getVulnerability()
            .getAdditionalDetails(0)
            .getTextData()
            .getText();
    assertThat(detail).contains("max_concurrent_streams=10000");
    assertThat(detail).contains("burst_streams=940, tail_refused_streams=0");
    assertThat(detail).contains("stream0_window_update=2146303999");
    assertThat(harness.totalConnections()).isEqualTo(3);
    assertThat(harness.sawClientRstStream()).isFalse();
  }

  @Test
  public void detect_highConcurrencyContiguousRefusedWithinSlack_verifies() throws Exception {
    Cve2026123007Detector detector = newFastDetector(new LoopbackSocketFactory());

    // 256 burst streams with 244 active cap (flushed=2 + queued=244 = 246 accepted, 10 <= 32
    // contiguous tail refused).
    MockNginxHarness harness =
        startMockNginxServer(
            MockNginxConfig.unpatchedDefault()
                .withMaxConcurrentStreams(10_000)
                .withEffectiveActiveStreamLimit(244));
    NetworkService service = buildHttpService(harness.port(), "http");
    DetectionReportList reports =
        detector.detect(
            TargetInfo.newBuilder().addNetworkEndpoints(service.getNetworkEndpoint()).build(),
            ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList()).hasSize(1);
    assertThat(
            reports
                .getDetectionReports(0)
                .getVulnerability()
                .getAdditionalDetails(0)
                .getTextData()
                .getText())
        .contains("burst_streams=256, tail_refused_streams=10");
    assertThat(harness.sawClientRstStream()).isFalse();
  }

  @Test
  public void detect_highConcurrencyExcessRefusedBeyondSlack_returnsEmpty() throws Exception {
    Cve2026123007Detector detector = newFastDetector(new LoopbackSocketFactory());

    // 256 burst streams with 200 active cap (54 > 32 refused) exceeds slack -> aborts cleanly.
    MockNginxHarness harness =
        startMockNginxServer(
            MockNginxConfig.unpatchedDefault()
                .withMaxConcurrentStreams(10_000)
                .withEffectiveActiveStreamLimit(200));
    NetworkService service = buildHttpService(harness.port(), "http");
    DetectionReportList reports =
        detector.detect(
            TargetInfo.newBuilder().addNetworkEndpoints(service.getNetworkEndpoint()).build(),
            ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(harness.totalConnections()).isEqualTo(2);
    assertThat(harness.sawClientRstStream()).isFalse();
  }

  @Test
  public void detect_highConcurrencyAllDataFlushesOnBackportedNginx_returnsEmptyNoFalsePos()
      throws Exception {
    Cve2026123007Detector detector = newFastDetector(new LoopbackSocketFactory());

    // Distro-backported / patched NGINX where h2c->send_queued == 0 when WINDOW_UPDATE arrives
    // across both Stage 1 (256, 940) and Stage 2 parked release (accepts wuIncrement without
    // GOAWAY, so prePingBDataBytes < maxPrePingBData is the critical zero-FP invariant).
    MockNginxHarness harness =
        startMockNginxServer(
            MockNginxConfig.patchedDefault()
                .withServerHeader("nginx/1.24.0 (Ubuntu)")
                .withMaxConcurrentStreams(10_000)
                .withStage1FlushAllDataBeforePingB(true)
                .withStage2FlushAllDataBeforePingB(true));
    NetworkService service = buildHttpService(harness.port(), "http");
    DetectionReportList reports =
        detector.detect(
            TargetInfo.newBuilder().addNetworkEndpoints(service.getNetworkEndpoint()).build(),
            ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(harness.totalConnections()).isEqualTo(4);
    assertThat(harness.lastParkedPhaseADataBytes()).isEqualTo(65_535L);
    assertThat(harness.lastParkedReleaseBytes()).isEqualTo(60);
    assertThat(harness.sawClientRstStream()).isFalse();
  }

  @Test
  public void detect_highConcurrencyAllDataFlushesOnUnpatchedNginx_returnsEmptyNoFalsePos()
      throws Exception {
    Cve2026123007Detector detector = newFastDetector(new LoopbackSocketFactory());

    MockNginxHarness harness =
        startMockNginxServer(
            MockNginxConfig.unpatchedDefault()
                .withMaxConcurrentStreams(10_000)
                .withStage1FlushAllDataBeforePingB(true)
                .withStage2FlushAllDataBeforePingB(true));
    NetworkService service = buildHttpService(harness.port(), "http");
    DetectionReportList reports =
        detector.detect(
            TargetInfo.newBuilder().addNetworkEndpoints(service.getNetworkEndpoint()).build(),
            ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(harness.totalConnections()).isEqualTo(4);
    assertThat(harness.lastParkedPhaseADataBytes()).isEqualTo(65_535L);
    assertThat(harness.lastParkedReleaseBytes()).isEqualTo(60);
    assertThat(harness.sawClientRstStream()).isFalse();
  }

  @Test
  public void detect_highConcurrencyParkedAtomicFallback_verifiesUnpatchedWith60ByteAtomicRelease()
      throws Exception {
    MockNginxConfig config =
        MockNginxConfig.unpatchedDefault()
            .withMaxConcurrentStreams(10_000)
            .withStage1FlushAllDataBeforePingB(true);
    MockNginxHarness harness = startMockNginxServer(config);
    Cve2026123007Detector detector = newFastDetector(new LoopbackSocketFactory());

    NetworkService service = buildHttpService(harness.port(), "http");
    TargetInfo targetInfo =
        TargetInfo.newBuilder().addNetworkEndpoints(service.getNetworkEndpoint()).build();

    DetectionReportList reports = detector.detect(targetInfo, ImmutableList.of(service));

    // Stage 2 with bodyLen=12288: drainStreams = 65535 / 12288 + 1 = 6, parkStreams = 256,
    // totalStreams = 262, slack = 32 -> wuIncrement = 0x7fffffff - 32 * 12288 = 2147090431.
    assertThat(reports.getDetectionReportsList()).hasSize(1);
    String detail =
        reports
            .getDetectionReports(0)
            .getVulnerability()
            .getAdditionalDetails(0)
            .getTextData()
            .getText();
    assertThat(detail).contains("max_concurrent_streams=10000");
    assertThat(detail).contains("static_body_bytes=12288");
    assertThat(detail).contains("burst_streams=262, tail_refused_streams=0");
    assertThat(detail).contains("stream0_window_update=2147090431");
    assertThat(harness.totalConnections()).isEqualTo(4);
    assertThat(harness.lastParkedPhaseADataBytes()).isEqualTo(65_535L);
    assertThat(harness.lastParkedReleaseBytes()).isEqualTo(60);
    assertThat(harness.lastParkedReleaseFrameTypes())
        .containsExactly(
            H2Frames.TYPE_WINDOW_UPDATE,
            H2Frames.TYPE_PING,
            H2Frames.TYPE_WINDOW_UPDATE,
            H2Frames.TYPE_PING)
        .inOrder();
    assertThat(harness.sawClientRstStream()).isFalse();
  }

  @Test
  public void
      detect_highConcurrencyParkedAtomicFallbackOnPatchedNginx_rejectsWithFlowControlGoAway()
          throws Exception {
    MockNginxConfig config =
        MockNginxConfig.patchedDefault()
            .withMaxConcurrentStreams(10_000)
            .withStage1FlushAllDataBeforePingB(true);
    MockNginxHarness harness = startMockNginxServer(config);
    Cve2026123007Detector detector = newFastDetector(new LoopbackSocketFactory());

    NetworkService service = buildHttpService(harness.port(), "http");
    TargetInfo targetInfo =
        TargetInfo.newBuilder().addNetworkEndpoints(service.getNetworkEndpoint()).build();

    DetectionReportList reports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(harness.totalConnections()).isEqualTo(4);
    assertThat(harness.lastParkedPhaseADataBytes()).isEqualTo(65_535L);
    assertThat(harness.sawClientRstStream()).isFalse();
  }

  @Test
  public void
      detect_highConcurrencyParkedFallbackWithDefaultKeepalive1000_verifies615ByteIndexHtml()
          throws Exception {
    // NGINX default index.html is 615 bytes and default keepalive_requests is 1000
    // (ngx_http_core_module.c). Stage 2 must stay within 940 total streams (107 drain + 833
    // parked = 940 < 1000) so NGINX does not emit premature GOAWAY(NO_ERROR) at stream 1000.
    MockNginxConfig config =
        MockNginxConfig.unpatchedDefault()
            .withMaxConcurrentStreams(10_000)
            .withKeepaliveRequests(1_000)
            .withRouteBody("/", new byte[615])
            .withDefault404Body(new byte[153])
            .withStage1FlushAllDataBeforePingB(true);
    MockNginxHarness harness = startMockNginxServer(config);
    Cve2026123007Detector detector = newFastDetector(new LoopbackSocketFactory());

    NetworkService service = buildHttpService(harness.port(), "http");
    TargetInfo targetInfo =
        TargetInfo.newBuilder().addNetworkEndpoints(service.getNetworkEndpoint()).build();

    DetectionReportList reports = detector.detect(targetInfo, ImmutableList.of(service));

    // drainStreams = 65535 / 615 + 1 = 107, parkStreams = 940 - 107 = 833, slack = 96,
    // wuIncrement = 0x7fffffff - 96 * 615 = 2147424607.
    assertThat(reports.getDetectionReportsList()).hasSize(1);
    String detail =
        reports
            .getDetectionReports(0)
            .getVulnerability()
            .getAdditionalDetails(0)
            .getTextData()
            .getText();
    assertThat(detail).contains("burst_streams=940, tail_refused_streams=0");
    assertThat(detail).contains("stream0_window_update=2147424607");
    assertThat(harness.totalConnections()).isEqualTo(4);
    assertThat(harness.lastParkedPhaseADataBytes()).isEqualTo(65_535L);
    assertThat(harness.lastParkedReleaseBytes()).isEqualTo(60);
    assertThat(harness.sawClientRstStream()).isFalse();
  }

  @Test
  public void detect_highConcurrencyTiny16ByteBodyWhenStage1Drains_skipsUnboundedStage2Drain()
      throws Exception {
    // A 16-byte static body would require drainStreams = 65535 / 16 + 1 = 4096 (> 2048) just to
    // exhaust the initial 65,535-byte window; Stage 2 must short-circuit without dialing.
    MockNginxConfig config =
        MockNginxConfig.unpatchedDefault()
            .withMaxConcurrentStreams(10_000)
            .withRouteBody("/", new byte[16])
            .withDefault404Body(new byte[16])
            .withStage1FlushAllDataBeforePingB(true);
    MockNginxHarness harness = startMockNginxServer(config);
    Cve2026123007Detector detector = newFastDetector(new LoopbackSocketFactory());

    NetworkService service = buildHttpService(harness.port(), "http");
    TargetInfo targetInfo =
        TargetInfo.newBuilder().addNetworkEndpoints(service.getNetworkEndpoint()).build();

    DetectionReportList reports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    // 1 discovery connection + 1 Stage-1 burst (firstBurst == maxBurst == 940); 0 Stage-2 dials.
    assertThat(harness.totalConnections()).isEqualTo(2);
  }

  @Test
  public void detect_positivePreDrainDelayWithHighDiscoveryRtt_scalesSettleDelayInPhase2()
      throws Exception {
    ManualTicker ticker = new ManualTicker();
    MockNginxHarness harness =
        startMockNginxServer(
            MockNginxConfig.unpatchedDefault()
                .withMaxConcurrentStreams(10_000)
                .withOnDiscoveryResponseHook(() -> ticker.advance(Duration.ofMillis(120))));
    List<Duration> recordedSleeps = Collections.synchronizedList(new ArrayList<>());

    Cve2026123007Detector adaptiveDetector =
        new Cve2026123007Detector(
            fakeUtcClock,
            new H2FlowControlProbe(
                new LoopbackSocketFactory(),
                Duration.ofSeconds(3),
                Duration.ZERO,
                Duration.ofMillis(15),
                new SecureRandom(),
                H2FlowControlProbe.createPermissiveSslSocketFactory(new SecureRandom()),
                ticker,
                recordedSleeps::add));
    NetworkService service = buildHttpService(harness.port(), "http");
    TargetInfo targetInfo =
        TargetInfo.newBuilder().addNetworkEndpoints(service.getNetworkEndpoint()).build();

    DetectionReportList reports = adaptiveDetector.detect(targetInfo, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList()).hasSize(1);
    assertThat(recordedSleeps).containsExactly(Duration.ofMillis(120));
  }

  @Test
  public void computeEffectivePreDrainDelay_respectsZeroAndScalesPositiveDelayUpTo250MsCap() {
    LoopbackSocketFactory socketFactory = new LoopbackSocketFactory();
    H2FlowControlProbe zeroDelayProbe =
        new H2FlowControlProbe(
            socketFactory, Duration.ofSeconds(3), Duration.ZERO, Duration.ZERO, new SecureRandom());
    H2FlowControlProbe negativeDelayProbe =
        new H2FlowControlProbe(
            socketFactory,
            Duration.ofSeconds(3),
            Duration.ZERO,
            Duration.ofMillis(-5),
            new SecureRandom());
    H2FlowControlProbe defaultDelayProbe =
        new H2FlowControlProbe(
            socketFactory,
            Duration.ofSeconds(3),
            Duration.ofMillis(20),
            Duration.ofMillis(15),
            new SecureRandom());
    H2FlowControlProbe largeBaseDelayProbe =
        new H2FlowControlProbe(
            socketFactory,
            Duration.ofSeconds(3),
            Duration.ofMillis(20),
            Duration.ofMillis(300),
            new SecureRandom());

    assertThat(zeroDelayProbe.computeEffectivePreDrainDelay(Duration.ZERO))
        .isEqualTo(Duration.ZERO);
    assertThat(zeroDelayProbe.computeEffectivePreDrainDelay(Duration.ofMillis(180)))
        .isEqualTo(Duration.ZERO);
    assertThat(zeroDelayProbe.computeEffectivePreDrainDelay(Duration.ofSeconds(2)))
        .isEqualTo(Duration.ZERO);
    assertThat(negativeDelayProbe.computeEffectivePreDrainDelay(Duration.ofMillis(180)))
        .isEqualTo(Duration.ZERO);

    assertThat(defaultDelayProbe.computeEffectivePreDrainDelay(Duration.ZERO))
        .isEqualTo(Duration.ofMillis(15));
    assertThat(defaultDelayProbe.computeEffectivePreDrainDelay(Duration.ofMillis(8)))
        .isEqualTo(Duration.ofMillis(15));
    assertThat(defaultDelayProbe.computeEffectivePreDrainDelay(Duration.ofMillis(15)))
        .isEqualTo(Duration.ofMillis(15));
    assertThat(defaultDelayProbe.computeEffectivePreDrainDelay(Duration.ofMillis(120)))
        .isEqualTo(Duration.ofMillis(120));
    assertThat(defaultDelayProbe.computeEffectivePreDrainDelay(Duration.ofMillis(250)))
        .isEqualTo(Duration.ofMillis(250));
    assertThat(defaultDelayProbe.computeEffectivePreDrainDelay(Duration.ofMillis(251)))
        .isEqualTo(Duration.ofMillis(250));
    assertThat(defaultDelayProbe.computeEffectivePreDrainDelay(Duration.ofSeconds(3)))
        .isEqualTo(Duration.ofMillis(250));
    assertThat(largeBaseDelayProbe.computeEffectivePreDrainDelay(Duration.ofMillis(120)))
        .isEqualTo(Duration.ofMillis(300));
  }

  @Test
  public void detect_highConcurrencyTlsH2ParkedFallbackWithSni_verifiesAndClosesAllSslSockets()
      throws Exception {
    SSLContext serverSsl = createSelfSignedServerSslContext();
    AtomicReference<List<SNIServerName>> capturedSni = new AtomicReference<>(ImmutableList.of());
    MockNginxConfig tlsCfg =
        MockNginxConfig.unpatchedDefault()
            .withMaxConcurrentStreams(10_000)
            .withStage1FlushAllDataBeforePingB(true)
            .withTlsContext(serverSsl, new String[] {"h2"}, capturedSni);
    MockNginxHarness harness = startMockNginxServer(tlsCfg);
    RecordingSslSocketFactory recordingSslFactory =
        new RecordingSslSocketFactory(
            H2FlowControlProbe.createPermissiveSslSocketFactory(new SecureRandom()));
    Cve2026123007Detector detector =
        new Cve2026123007Detector(
            fakeUtcClock,
            new H2FlowControlProbe(
                new LoopbackSocketFactory(),
                Duration.ofSeconds(3),
                Duration.ZERO,
                Duration.ZERO,
                new SecureRandom(),
                recordingSslFactory));

    NetworkEndpoint endpoint =
        NetworkEndpointUtils.forIpHostnameAndPort(LOOPBACK_IP, "edge.example.com", harness.port());
    NetworkService httpsService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(endpoint)
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("https")
            .build();
    TargetInfo targetInfo = TargetInfo.newBuilder().addNetworkEndpoints(endpoint).build();

    DetectionReportList reports = detector.detect(targetInfo, ImmutableList.of(httpsService));

    assertThat(reports.getDetectionReportsList()).hasSize(1);
    String detail =
        reports
            .getDetectionReports(0)
            .getVulnerability()
            .getAdditionalDetails(0)
            .getTextData()
            .getText();
    assertThat(detail).contains("over HTTP/2 (h2) at https://edge.example.com:" + harness.port());
    assertThat(detail).contains("burst_streams=262, tail_refused_streams=0");
    assertThat(capturedSni.get()).isNotEmpty();
    assertThat(recordingSslFactory.createdSockets()).hasSize(4);
    for (SSLSocket sslSocket : recordingSslFactory.createdSockets()) {
      assertThat(sslSocket.isClosed()).isTrue();
    }
    assertThat(harness.lastParkedReleaseBytes()).isEqualTo(60);
    assertThat(harness.sawClientRstStream()).isFalse();
  }

  @Test
  public void detect_highConcurrencyParkedFallbackStepsUpTo2048WhenSafeCandidateDrains_verifies()
      throws Exception {
    // When keepalive_requests=5000 and an L4 proxy buffer absorbs the 940-stream keepalive-safe
    // candidate (107 + 833 = 940), Stage 2 steps up to desiredParkStreams=2048 (107 + 2048 = 2155).
    MockNginxConfig config =
        MockNginxConfig.unpatchedDefault()
            .withMaxConcurrentStreams(10_000)
            .withKeepaliveRequests(5_000)
            .withRouteBody("/", new byte[615])
            .withDefault404Body(new byte[153])
            .withStage1FlushAllDataBeforePingB(true)
            .withFirstStage2FlushAllDataBeforePingB(true);
    MockNginxHarness harness = startMockNginxServer(config);
    Cve2026123007Detector detector = newFastDetector(new LoopbackSocketFactory());

    NetworkService service = buildHttpService(harness.port(), "http");
    TargetInfo targetInfo =
        TargetInfo.newBuilder().addNetworkEndpoints(service.getNetworkEndpoint()).build();

    DetectionReportList reports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList()).hasSize(1);
    String detail =
        reports
            .getDetectionReports(0)
            .getVulnerability()
            .getAdditionalDetails(0)
            .getTextData()
            .getText();
    assertThat(detail).contains("burst_streams=2155, tail_refused_streams=0");
    assertThat(harness.totalConnections()).isEqualTo(5);
    assertThat(harness.sawClientRstStream()).isFalse();
  }

  @Test
  public void
      detect_highConcurrencyParkedPhaseAPingAckAheadOfBatchFrames_drainsBatchBeforeNextSend()
          throws Exception {
    // NGINX queues PING(ACK) ahead of unblocked stream HEADERS/DATA frames and defers
    // h2c->processing-- until queued DATA flushes. With max_concurrent_streams=300 and bodyLen=615
    // (drainStreams=107, parkStreams=284, totalStreams=391 > 300), Phase A must drain Batch 1's
    // 256 HEADERS and 65,535 DATA bytes before sending Batch 2 (streams #257..#391).
    MockNginxConfig config =
        MockNginxConfig.unpatchedDefault()
            .withMaxConcurrentStreams(300)
            .withRouteBody("/", new byte[615])
            .withDefault404Body(new byte[153])
            .withStage1FlushAllDataBeforePingB(true)
            .withPhaseAPingAckBeforeBatchFrames(true);
    MockNginxHarness harness = startMockNginxServer(config);

    AtomicLong stage2BytesRead = new AtomicLong(0L);
    AtomicLong stage2BytesReadAtBatch2Write = new AtomicLong(-1L);
    AtomicInteger stage2Sockets = new AtomicInteger(0);
    AtomicBoolean postConnectRecvBufShrunk = new AtomicBoolean(false);
    LoopbackSocketFactory baseFactory = new LoopbackSocketFactory();
    TsunamiSocketFactory recordingFactory =
        new ForwardingLoopbackFactory(baseFactory) {
          @Override
          public Socket createUnconnectedSocket() {
            return new Socket() {
              private volatile boolean stage2PhaseA = false;
              private int writesAfterPreface = 0;

              @Override
              public void setReceiveBufferSize(int size) throws SocketException {
                if (!isConnected() && size > 65_536) {
                  stage2PhaseA = true;
                  stage2Sockets.incrementAndGet();
                } else if (isConnected() && size <= 65_536) {
                  postConnectRecvBufShrunk.set(true);
                }
                super.setReceiveBufferSize(size);
              }

              @Override
              public InputStream getInputStream() throws IOException {
                InputStream rawIn = super.getInputStream();
                if (!stage2PhaseA) {
                  return rawIn;
                }
                return new FilterInputStream(rawIn) {
                  @Override
                  public int read() throws IOException {
                    int b = in.read();
                    if (b >= 0 && stage2PhaseA) {
                      stage2BytesRead.incrementAndGet();
                    }
                    return b;
                  }

                  @Override
                  public int read(byte[] b, int off, int len) throws IOException {
                    int n = in.read(b, off, len);
                    if (n > 0 && stage2PhaseA) {
                      stage2BytesRead.addAndGet(n);
                    }
                    return n;
                  }
                };
              }

              @Override
              public OutputStream getOutputStream() throws IOException {
                OutputStream rawOut = super.getOutputStream();
                if (!stage2PhaseA) {
                  return rawOut;
                }
                return new FilterOutputStream(rawOut) {
                  @Override
                  public void write(byte[] b, int off, int len) throws IOException {
                    out.write(b, off, len);
                  }

                  @Override
                  public void flush() throws IOException {
                    // Flush 1: preface; Flush 2: Batch 1 (256 streams); Flush 3: Batch 2 (135
                    // streams).
                    if (stage2PhaseA && ++writesAfterPreface == 3) {
                      stage2BytesReadAtBatch2Write.set(stage2BytesRead.get());
                    }
                    super.flush();
                  }
                };
              }
            };
          }
        };

    Cve2026123007Detector detector = newFastDetector(recordingFactory);
    NetworkService service = buildHttpService(harness.port(), "http");
    TargetInfo targetInfo =
        TargetInfo.newBuilder().addNetworkEndpoints(service.getNetworkEndpoint()).build();

    DetectionReportList reports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList()).hasSize(1);
    assertThat(
            reports
                .getDetectionReports(0)
                .getVulnerability()
                .getAdditionalDetails(0)
                .getTextData()
                .getText())
        .contains("burst_streams=391, tail_refused_streams=0");
    assertThat(stage2Sockets.get()).isEqualTo(1);
    assertThat(postConnectRecvBufShrunk.get()).isFalse();
    // Before Batch 2 is flushed on the Stage-2 Phase-A socket, the client must already have read
    // Batch 1's 256 HEADERS + 65,535 DATA bytes (> 68,000 wire bytes), not merely the leading
    // SETTINGS(ACK) + PING(ACK) (~26 wire bytes).
    assertThat(stage2BytesReadAtBatch2Write.get()).isGreaterThan(68_000L);
    assertThat(harness.sawClientRstStream()).isFalse();
  }

  @Test
  public void detect_highConcurrencyParkedPhaseAOversend_abortsCleanlyAndReturnsEmpty()
      throws Exception {
    Cve2026123007Detector detector = newFastDetector(new LoopbackSocketFactory());

    MockNginxHarness harness =
        startMockNginxServer(
            MockNginxConfig.unpatchedDefault()
                .withMaxConcurrentStreams(10_000)
                .withStage1FlushAllDataBeforePingB(true)
                .withPhaseAIgnoreConnWindow(true));
    NetworkService service = buildHttpService(harness.port(), "http");
    DetectionReportList reports =
        detector.detect(
            TargetInfo.newBuilder().addNetworkEndpoints(service.getNetworkEndpoint()).build(),
            ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(harness.sawClientRstStream()).isFalse();
  }

  @Test
  public void detect_highConcurrencyParkedPhaseARstStream_abortsCleanlyAndReturnsEmpty()
      throws Exception {
    Cve2026123007Detector detector = newFastDetector(new LoopbackSocketFactory());

    MockNginxHarness harness =
        startMockNginxServer(
            MockNginxConfig.unpatchedDefault()
                .withMaxConcurrentStreams(10_000)
                .withStage1FlushAllDataBeforePingB(true)
                .withPhaseARstOnStream(15));
    NetworkService service = buildHttpService(harness.port(), "http");
    DetectionReportList reports =
        detector.detect(
            TargetInfo.newBuilder().addNetworkEndpoints(service.getNetworkEndpoint()).build(),
            ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(harness.sawClientRstStream()).isFalse();
  }

  @Test
  public void detect_discoveryStreamExceedingDrainDeadline_abortsAndReturnsEmpty()
      throws Exception {
    ManualTicker ticker = new ManualTicker();
    ticker.setAutoIncrementStep(Duration.ofMillis(100));
    MockNginxHarness harness =
        startMockNginxServer(MockNginxConfig.unpatchedDefault().withMaxConcurrentStreams(10_000));
    Cve2026123007Detector detector =
        new Cve2026123007Detector(
            fakeUtcClock,
            new H2FlowControlProbe(
                new LoopbackSocketFactory(),
                Duration.ofMillis(80),
                Duration.ZERO,
                Duration.ZERO,
                new SecureRandom(),
                H2FlowControlProbe.createPermissiveSslSocketFactory(new SecureRandom()),
                ticker,
                d -> {}));
    NetworkService service = buildHttpService(harness.port(), "http");
    TargetInfo targetInfo =
        TargetInfo.newBuilder().addNetworkEndpoints(service.getNetworkEndpoint()).build();

    DetectionReportList reports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(harness.totalConnections()).isEqualTo(1);
  }

  @Test
  public void detect_parkedPhaseAExceedingDrainDeadline_abortsAndReturnsEmpty() throws Exception {
    ManualTicker ticker = new ManualTicker();
    MockNginxHarness harness =
        startMockNginxServer(
            MockNginxConfig.unpatchedDefault()
                .withMaxConcurrentStreams(10_000)
                .withStage1FlushAllDataBeforePingB(true)
                .withOnStage2PhaseAStartHook(() -> ticker.advance(Duration.ofMillis(200))));
    Cve2026123007Detector detector =
        new Cve2026123007Detector(
            fakeUtcClock,
            new H2FlowControlProbe(
                new LoopbackSocketFactory(),
                Duration.ofMillis(80),
                Duration.ZERO,
                Duration.ZERO,
                new SecureRandom(),
                H2FlowControlProbe.createPermissiveSslSocketFactory(new SecureRandom()),
                ticker,
                d -> {}));
    NetworkService service = buildHttpService(harness.port(), "http");
    TargetInfo targetInfo =
        TargetInfo.newBuilder().addNetworkEndpoints(service.getNetworkEndpoint()).build();

    DetectionReportList reports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(harness.totalConnections()).isEqualTo(4);
    assertThat(harness.lastParkedReleaseBytes()).isEqualTo(0);
  }

  @Test
  public void detect_verificationDrainExceedingDeadline_abortsAndReturnsEmpty() throws Exception {
    ManualTicker ticker = new ManualTicker();
    MockNginxHarness harness =
        startMockNginxServer(
            MockNginxConfig.unpatchedDefault()
                .withMaxConcurrentStreams(10_000)
                .withOnStage1PostBurstPingHook(
                    () -> ticker.setAutoIncrementStep(Duration.ofMillis(100))));
    Cve2026123007Detector detector =
        new Cve2026123007Detector(
            fakeUtcClock,
            new H2FlowControlProbe(
                new LoopbackSocketFactory(),
                Duration.ofMillis(80),
                Duration.ZERO,
                Duration.ZERO,
                new SecureRandom(),
                H2FlowControlProbe.createPermissiveSslSocketFactory(new SecureRandom()),
                ticker,
                d -> {}));
    NetworkService service = buildHttpService(harness.port(), "http");
    TargetInfo targetInfo =
        TargetInfo.newBuilder().addNetworkEndpoints(service.getNetworkEndpoint()).build();

    DetectionReportList reports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(harness.totalConnections()).isEqualTo(2);
  }

  @Test
  public void detect_highConcurrencyStage1OneByteBelowPrePingBLimit_verifies() throws Exception {
    Cve2026123007Detector detector = newFastDetector(new LoopbackSocketFactory());

    // max_concurrent_streams=260, bodyLen=200 -> maxBurst=260, slack=32, maxPrePingBData =
    // (260 - 32) * 200 = 45,600. At 45,599 flushed bytes (maxPrePingBData - 1), Stage 1 matches.
    MockNginxHarness harness =
        startMockNginxServer(
            MockNginxConfig.unpatchedDefault()
                .withMaxConcurrentStreams(260)
                .withFlushedBeforeBackpressure(0)
                .withRouteBody("/", new byte[200])
                .withDefault404Body(new byte[200])
                .withPrePingBFlushBytes(45_599));
    NetworkService service = buildHttpService(harness.port(), "http");
    DetectionReportList reports =
        detector.detect(
            TargetInfo.newBuilder().addNetworkEndpoints(service.getNetworkEndpoint()).build(),
            ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList()).hasSize(1);
    assertThat(harness.totalConnections()).isEqualTo(2);
  }

  @Test
  public void detect_highConcurrencyExactPrePingBLimitAcrossBothStages_returnsEmpty()
      throws Exception {
    Cve2026123007Detector detector = newFastDetector(new LoopbackSocketFactory());

    // Stage 1 maxPrePingBData = 45,600; Stage 2: drainStreams=328, desiredParkStreams=244,
    // slackStreams=30, remFirstBytes=65, triggerWin=48,865 -> maxPrePingBData = 42,865.
    // At the exact limit on both stages, detector must return empty.
    MockNginxHarness harness =
        startMockNginxServer(
            MockNginxConfig.unpatchedDefault()
                .withMaxConcurrentStreams(260)
                .withFlushedBeforeBackpressure(0)
                .withRouteBody("/", new byte[200])
                .withDefault404Body(new byte[200])
                .withPrePingBFlushBytes(45_600)
                .withStage2PrePingBFlushBytes(42_865));
    NetworkService service = buildHttpService(harness.port(), "http");
    DetectionReportList reports =
        detector.detect(
            TargetInfo.newBuilder().addNetworkEndpoints(service.getNetworkEndpoint()).build(),
            ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(harness.totalConnections()).isEqualTo(3);
  }

  @Test
  public void detect_highConcurrencyStage2OneByteBelowPrePingBLimit_verifies() throws Exception {
    Cve2026123007Detector detector = newFastDetector(new LoopbackSocketFactory());

    // At 42,864 flushed Stage-2 bytes (maxPrePingBData - 1), Stage 2 matches.
    MockNginxHarness harness =
        startMockNginxServer(
            MockNginxConfig.unpatchedDefault()
                .withMaxConcurrentStreams(260)
                .withFlushedBeforeBackpressure(0)
                .withRouteBody("/", new byte[200])
                .withDefault404Body(new byte[200])
                .withPrePingBFlushBytes(45_600)
                .withStage2PrePingBFlushBytes(42_864));
    NetworkService service = buildHttpService(harness.port(), "http");
    DetectionReportList reports =
        detector.detect(
            TargetInfo.newBuilder().addNetworkEndpoints(service.getNetworkEndpoint()).build(),
            ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList()).hasSize(1);
    assertThat(harness.totalConnections()).isEqualTo(3);
  }

  private static byte[] buildValidGreetingBytes() {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    byte[] settings = MockNginxConfig.unpatchedDefault().buildSettingsPayload();
    H2Frames.writeFrame(out, H2Frames.TYPE_SETTINGS, 0, 0, settings);
    H2Frames.writeWindowUpdateFrame(out, 0, H2FlowControlProbe.NGINX_CONN_WINDOW_DELTA);
    return out.toByteArray();
  }

  private Cve2026123007Detector newFastDetector(TsunamiSocketFactory socketFactory) {
    H2FlowControlProbe probe =
        new H2FlowControlProbe(
            socketFactory, Duration.ofSeconds(3), Duration.ZERO, Duration.ZERO, new SecureRandom());
    return new Cve2026123007Detector(fakeUtcClock, probe);
  }

  private static NetworkService buildHttpService(int port, String serviceName) {
    return NetworkService.newBuilder()
        .setNetworkEndpoint(NetworkEndpointUtils.forIpAndPort(LOOPBACK_IP, port))
        .setTransportProtocol(TransportProtocol.TCP)
        .setServiceName(serviceName)
        .build();
  }

  private static CrawlResult crawlResult(String url) {
    return CrawlResult.newBuilder()
        .setCrawlTarget(CrawlTarget.newBuilder().setUrl(url).setHttpMethod("GET"))
        .build();
  }

  private DetectionReport expectedReport(
      Cve2026123007Detector detector,
      TargetInfo targetInfo,
      NetworkService service,
      String detailText) {
    Vulnerability expectedVuln =
        detector.getAdvisories().get(0).toBuilder()
            .addAdditionalDetails(
                AdditionalDetail.newBuilder()
                    .setDescription(
                        "Non-destructive NGINX HTTP/2 queued-frame Stream 0 WINDOW_UPDATE"
                            + " verification evidence")
                    .setTextData(TextData.newBuilder().setText(detailText)))
            .build();
    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(service)
        .setDetectionTimestamp(Timestamps.fromMillis(FIXED_INSTANT.toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(expectedVuln)
        .build();
  }

  private static void writeRawString(ByteArrayOutputStream out, String s) {
    byte[] bytes = s.getBytes(ISO_8859_1);
    out.write(bytes.length);
    out.writeBytes(bytes);
  }

  private MockNginxHarness startMockNginxServer(MockNginxConfig config) throws IOException {
    ServerSocket serverSocket = new ServerSocket(0, 64, LOOPBACK_ADDR);
    openServers.add(serverSocket);
    MockNginxHarness harness = new MockNginxHarness(serverSocket.getLocalPort());
    serverExecutor.execute(() -> {
      while (!serverSocket.isClosed()) {
        Socket rawClient;
        try {
          rawClient = serverSocket.accept();
        } catch (IOException e) {
          break;
        }
        int connIndex = harness.connectionCounter.incrementAndGet();
        serverExecutor.execute(() -> {
          try (rawClient) {
            rawClient.setSoTimeout(3000);
            serveMockNginxConnection(rawClient, connIndex, config, harness);
          } catch (IOException ignored) {
            // Peer closed after probe completed.
          }
        });
      }
    });
    return harness;
  }

  private static void serveMockNginxConnection(
      Socket rawSocket, int connIndex, MockNginxConfig config, MockNginxHarness harness)
      throws IOException {
    if (config.cleartextZeroByteEofBeforeTls && connIndex == 1) {
      // Read initial cleartext preface byte and immediately close with 0 response bytes (EOF).
      InputStream rawIn = rawSocket.getInputStream();
      int ignoredByte = rawIn.read();
      if (ignoredByte >= 0) {
        rawSocket.close();
      }
      return;
    }

    Socket activeSocket = rawSocket;
    if (config.tlsContext != null) {
      SSLSocket sslServer =
          (SSLSocket)
              config
                  .tlsContext
                  .getSocketFactory()
                  .createSocket(rawSocket, LOOPBACK_IP, rawSocket.getLocalPort(), true);
      sslServer.setUseClientMode(false);
      SSLParameters params = sslServer.getSSLParameters();
      if (config.alpnProtocols != null && config.alpnProtocols.length > 0) {
        params.setApplicationProtocols(config.alpnProtocols);
      }
      sslServer.setSSLParameters(params);
      sslServer.startHandshake();
      if (config.capturedSni != null
          && sslServer.getSession() instanceof ExtendedSSLSession extSession) {
        config.capturedSni.set(extSession.getRequestedServerNames());
      }
      activeSocket = sslServer;
    }

    InputStream in = new BufferedInputStream(activeSocket.getInputStream(), 65_536);
    OutputStream out = activeSocket.getOutputStream();

    byte[] preface = in.readNBytes(clientPreface.length);
    if (!Arrays.equals(preface, clientPreface)) {
      return;
    }

    // Send NGINX server greeting: SETTINGS + optional Stream 0 WINDOW_UPDATE.
    ByteArrayOutputStream greeting = new ByteArrayOutputStream();
    byte[] settingsPayload = config.buildSettingsPayload();
    H2Frames.writeFrame(greeting, H2Frames.TYPE_SETTINGS, 0, 0, settingsPayload);
    if (!config.omitStream0WindowUpdate) {
      H2Frames.writeWindowUpdateFrame(greeting, 0, config.stream0WindowUpdateDelta);
    }
    greeting.writeTo(out);
    out.flush();

    HpackDecoder clientHpack = new HpackDecoder();
    MockConnectionState st = new MockConnectionState(config.flushedBeforeBackpressure);

    while (true) {
      byte[] hdr = in.readNBytes(H2Frames.FRAME_HEADER_LEN);
      if (hdr.length < H2Frames.FRAME_HEADER_LEN) {
        return;
      }
      H2Frames.FrameHeader fh = H2Frames.decodeFrameHeader(hdr);
      int length = fh.length();
      int type = fh.type();
      int flags = fh.flags();
      int streamId = fh.streamId();
      byte[] payload = in.readNBytes(length);
      if (payload.length < length) {
        return;
      }

      if (type == H2Frames.TYPE_RST_STREAM) {
        harness.clientRstObserved.set(true);
      }

      switch (type) {
        case H2Frames.TYPE_SETTINGS -> {
          if ((flags & H2Frames.FLAG_ACK) == 0) {
            for (int i = 0; i + 6 <= payload.length; i += 6) {
              int id = H2Frames.readUint16(payload, i);
              long val = H2Frames.readUint32(payload, i + 2);
              if (id == H2Frames.SETTING_INITIAL_WINDOW_SIZE) {
                st.peerInitialStreamWin = val;
              }
            }
            ByteArrayOutputStream ack = new ByteArrayOutputStream();
            H2Frames.writeFrame(ack, H2Frames.TYPE_SETTINGS, H2Frames.FLAG_ACK, 0, new byte[0]);
            ack.writeTo(out);
            out.flush();
          }
        }
        case H2Frames.TYPE_WINDOW_UPDATE -> {
          if (streamId == 0 && payload.length == 4) {
            long inc = H2Frames.readUint32(payload, 0) & 0x7fffffffL;
            if (st.acceptedRequestsOnConn == 0
                && st.undecidedStreams.isEmpty()
                && st.phase2Mode == Phase2Mode.UNDECIDED) {
              st.prefaceConnWindowUpdated = true;
              st.phase2Mode = Phase2Mode.STAGE1_BURST;
            }
            if (st.phase2Mode == Phase2Mode.STAGE2_PARKED) {
              if (!st.stage2PhaseBStarted) {
                st.stage2PhaseBStarted = true;
                st.stage2Idx = harness.stage2ConnectionCounter.incrementAndGet();
                harness.lastParkedPhaseADataBytes.set(st.phaseADataSent);
              }
              if (st.stage2ReleasePingCount < 2) {
                st.stage2ReleaseBytes += H2Frames.FRAME_HEADER_LEN + length;
                st.stage2ReleaseFrameTypes.add(type);
              }
            }
            long accountedWindow =
                config.patched ? (st.sendWindow + st.queuedBytes) : st.sendWindow;
            if (inc == 0 || inc > H2FlowControlProbe.NGINX_MAX_WINDOW - accountedWindow) {
              byte[] goaway = new byte[8];
              H2Frames.writeUint32(goaway, 0, st.lastProcessedStreamId);
              H2Frames.writeUint32(goaway, 4, H2Frames.ERR_FLOW_CONTROL);
              ByteArrayOutputStream buf = new ByteArrayOutputStream();
              H2Frames.writeFrame(buf, H2Frames.TYPE_GOAWAY, 0, 0, goaway);
              buf.writeTo(out);
              out.flush();
              closeWithLingeringDrain(config.tlsContext == null, rawSocket, in);
              return;
            }
            st.sendWindow += inc;
            if (st.phase2Mode == Phase2Mode.STAGE2_PARKED && !st.waitingStreams.isEmpty()) {
              boolean flushAllStage2 =
                  config.stage2FlushAllDataBeforePingB
                      || (st.stage2Idx == 1 && config.firstStage2FlushAllDataBeforePingB);
              ByteArrayOutputStream wakeOut = new ByteArrayOutputStream();
              while (!st.waitingStreams.isEmpty() && st.sendWindow > 0) {
                PendingStream ps = st.waitingStreams.pollFirst();
                int alloc = (int) Math.min(ps.bufferedLen(), st.sendWindow);
                st.sendWindow -= alloc;
                if (alloc < ps.bufferedLen()) {
                  st.waitingStreams.addFirst(
                      new PendingStream(ps.streamId(), ps.bufferedLen() - alloc));
                }
                if (flushAllStage2) {
                  st.pendingFastDrainBytes += alloc;
                } else {
                  long remainingFlushBudget =
                      Math.max(0L, config.stage2PrePingBFlushBytes - st.stage2FlushedDataBytes);
                  int flushNow = (int) Math.min(alloc, remainingFlushBudget);
                  if (flushNow > 0) {
                    writeChunkedDataFrames(
                        wakeOut,
                        ps.streamId(),
                        flushNow,
                        /* endStream= */ flushNow == ps.bufferedLen());
                    st.stage2FlushedDataBytes += flushNow;
                  }
                  st.queuedBytes += (alloc - flushNow);
                }
              }
              if (wakeOut.size() > 0) {
                wakeOut.writeTo(out);
                out.flush();
              }
            }
          }
        }
        case H2Frames.TYPE_PING -> {
          if ((flags & H2Frames.FLAG_ACK) == 0 && payload.length == 8) {
            if (st.phase2Mode == Phase2Mode.UNDECIDED && !st.undecidedStreams.isEmpty()) {
              st.phase2Mode = Phase2Mode.STAGE2_PARKED;
              config.onStage2PhaseAStartHook.run();
              while (!st.undecidedStreams.isEmpty()) {
                PendingStream pending = st.undecidedStreams.pollFirst();
                processParkedPhaseAStream(
                    out, pending.streamId(), pending.bufferedLen(), config, st);
              }
            }
            if (st.phase2Mode == Phase2Mode.STAGE2_PARKED && !st.stage2PhaseBStarted) {
              ByteArrayOutputStream syncAck = new ByteArrayOutputStream();
              H2Frames.writePingFrame(syncAck, /* ack= */ true, payload);
              if (st.deferredPhaseABatchFrames.size() > 0) {
                st.deferredPhaseABatchFrames.writeTo(syncAck);
                st.deferredPhaseABatchFrames.reset();
              }
              syncAck.writeTo(out);
              out.flush();
              break;
            }
            if (st.stage2PhaseBStarted && st.stage2ReleasePingCount < 2) {
              st.stage2ReleasePingCount++;
              st.stage2ReleaseBytes += H2Frames.FRAME_HEADER_LEN + length;
              st.stage2ReleaseFrameTypes.add(type);
              if (st.stage2ReleasePingCount == 2) {
                harness.lastParkedReleaseBytes.set(st.stage2ReleaseBytes);
                harness.lastParkedReleaseFrameTypes.set(
                    ImmutableList.copyOf(st.stage2ReleaseFrameTypes));
              }
            }
            st.pingAckCount++;
            if (st.countedBurst && st.pingAckCount == 1) {
              config.onStage1PostBurstPingHook.run();
            }
            if (config.dropPingCAck && st.pingAckCount >= 3) {
              return;
            }
            if (st.pingAckCount == 1 && st.pendingFastDrainBytes > 0) {
              long rem = st.pendingFastDrainBytes;
              st.pendingFastDrainBytes = 0L;
              while (rem > 0) {
                int chunk = (int) Math.min(65_536L, rem);
                rem -= chunk;
                ByteArrayOutputStream fastBuf = new ByteArrayOutputStream(chunk + 16);
                H2Frames.writeFrame(
                    fastBuf,
                    H2Frames.TYPE_DATA,
                    rem == 0 ? H2Frames.FLAG_END_STREAM : 0,
                    1,
                    new byte[chunk]);
                fastBuf.writeTo(out);
              }
              out.flush();
            }
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            if (st.countedBurst && config.prePingBFlushBytes > 0 && st.pingAckCount == 1) {
              H2Frames.writeFrame(
                  buf, H2Frames.TYPE_DATA, 0, 1, new byte[config.prePingBFlushBytes]);
            }
            H2Frames.writePingFrame(buf, /* ack= */ true, payload);
            if (st.countedBurst && config.prePingBFlushBytes > 0 && st.pingAckCount == 2) {
              H2Frames.writeFrame(
                  buf, H2Frames.TYPE_DATA, H2Frames.FLAG_END_STREAM, 1, new byte[20_000]);
            }
            buf.writeTo(out);
            out.flush();
            if (st.keepaliveGoAwaySent && st.pingAckCount >= 2) {
              closeWithLingeringDrain(config.tlsContext == null, rawSocket, in);
              return;
            }
          }
        }
        case H2Frames.TYPE_HEADERS -> {
          ImmutableList<HeaderField> reqHeaders;
          try {
            reqHeaders = clientHpack.decode(payload);
          } catch (HpackException e) {
            return;
          }
          String path = "/";
          String userAgent = "";
          String acceptEncoding = "";
          for (HeaderField hf : reqHeaders) {
            switch (hf.name()) {
              case ":path" -> path = hf.value();
              case "user-agent" -> userAgent = hf.value();
              case "accept-encoding" -> acceptEncoding = hf.value();
              default -> {}
            }
          }
          if (config.requireScannerUserAgent
              && (!userAgent.equals("TsunamiSecurityScanner")
                  || !acceptEncoding.equals("identity"))) {
            return;
          }
          harness.recordedPaths.add(path);
          byte[] body = config.resolveBody(path);
          boolean discoveryMode =
              (st.peerInitialStreamWin == H2FlowControlProbe.DISCOVERY_STREAM_WIN);

          if (discoveryMode) {
            st.lastProcessedStreamId = streamId;
            sendDiscoveryResponse(out, streamId, path, body, st.peerInitialStreamWin, config);
          } else {
            int bufferedLen =
                (config.tlsContext != null) ? Math.min(body.length, 65536) : body.length;
            if (st.phase2Mode == Phase2Mode.UNDECIDED) {
              if (config.maxConcurrentStreams <= 256 || st.prefaceConnWindowUpdated) {
                st.phase2Mode = Phase2Mode.STAGE1_BURST;
              } else if (st.undecidedStreams.size() >= H2FlowControlProbe.PARK_SYNC_BATCH_STREAMS) {
                // Stage 2 always emits a sync PING after at most PARK_SYNC_BATCH_STREAMS HEADERS.
                st.phase2Mode = Phase2Mode.STAGE1_BURST;
                while (!st.undecidedStreams.isEmpty()) {
                  PendingStream pending = st.undecidedStreams.pollFirst();
                  if (!processBurstStream(
                      rawSocket,
                      in,
                      out,
                      pending.streamId(),
                      pending.bufferedLen(),
                      config,
                      harness,
                      st)) {
                    return;
                  }
                }
              } else if (st.undecidedBodyBytes + bufferedLen > 65535L) {
                st.phase2Mode = Phase2Mode.STAGE2_PARKED;
                config.onStage2PhaseAStartHook.run();
                while (!st.undecidedStreams.isEmpty()) {
                  PendingStream pending = st.undecidedStreams.pollFirst();
                  processParkedPhaseAStream(
                      out, pending.streamId(), pending.bufferedLen(), config, st);
                }
              } else {
                st.undecidedStreams.addLast(new PendingStream(streamId, bufferedLen));
                st.undecidedBodyBytes += bufferedLen;
                break;
              }
            }
            if (st.phase2Mode == Phase2Mode.STAGE2_PARKED) {
              processParkedPhaseAStream(out, streamId, bufferedLen, config, st);
            } else if (!processBurstStream(
                rawSocket, in, out, streamId, bufferedLen, config, harness, st)) {
              return;
            }
          }
        }
        default -> {}
      }
    }
  }

  private enum Phase2Mode {
    UNDECIDED,
    STAGE1_BURST,
    STAGE2_PARKED
  }

  private record PendingStream(int streamId, int bufferedLen) {}

  private static final class MockConnectionState {
    long sendWindow = 65535L;
    long queuedBytes = 0L;
    long peerInitialStreamWin = 65535L;
    boolean prefaceConnWindowUpdated;
    long acceptedRequestsOnConn = 0L;
    boolean keepaliveGoAwaySent;
    int flushedInBurst = 0;
    int queuedStreams = 0;
    int refusedStreams = 0;
    int lastProcessedStreamId = 0;
    int pingAckCount = 0;
    boolean countedBurst;
    int burstIdx = 0;
    int stage2Idx = 0;
    int burstTargetFlushed;
    Phase2Mode phase2Mode = Phase2Mode.UNDECIDED;
    final Deque<PendingStream> undecidedStreams = new ArrayDeque<>();
    long undecidedBodyBytes = 0L;
    final Deque<PendingStream> waitingStreams = new ArrayDeque<>();
    final ByteArrayOutputStream deferredPhaseABatchFrames = new ByteArrayOutputStream();
    long phaseADataSent = 0L;
    long stage2FlushedDataBytes = 0L;
    long pendingFastDrainBytes = 0L;
    boolean stage2PhaseBStarted;
    int stage2ReleaseBytes = 0;
    final List<Integer> stage2ReleaseFrameTypes = new ArrayList<>();
    int stage2ReleasePingCount = 0;

    MockConnectionState(int burstTargetFlushed) {
      this.burstTargetFlushed = burstTargetFlushed;
    }
  }

  private static boolean processBurstStream(
      Socket rawSocket,
      InputStream in,
      OutputStream out,
      int streamId,
      int bufferedLen,
      MockNginxConfig config,
      MockNginxHarness harness,
      MockConnectionState st)
      throws IOException {
    if (!st.countedBurst) {
      st.countedBurst = true;
      st.burstIdx = harness.burstConnectionCounter.incrementAndGet();
      if (st.burstIdx == 1 && config.firstBurstFlushedBeforeBackpressure >= 0) {
        st.burstTargetFlushed = config.firstBurstFlushedBeforeBackpressure;
      }
    }
    if (st.keepaliveGoAwaySent) {
      return true;
    }
    long effectiveMaxStreams =
        config.effectiveActiveStreamLimit > 0
            ? config.effectiveActiveStreamLimit
            : config.maxConcurrentStreams;
    boolean flushFullBody =
        config.stage1FlushAllDataBeforePingB
            || (st.burstIdx == 1 && config.firstBurstFlushAllDataBeforePingB);
    if (flushFullBody && st.queuedStreams < effectiveMaxStreams) {
      st.acceptedRequestsOnConn++;
      st.lastProcessedStreamId = streamId;
      st.sendWindow -= bufferedLen;
      st.pendingFastDrainBytes += bufferedLen;
      if (st.acceptedRequestsOnConn >= config.keepaliveRequests && !st.keepaliveGoAwaySent) {
        ByteArrayOutputStream resp = new ByteArrayOutputStream();
        maybeWriteKeepaliveGoAway(resp, config, st);
        resp.writeTo(out);
        out.flush();
      }
      return true;
    }
    if (st.flushedInBurst < st.burstTargetFlushed) {
      st.flushedInBurst++;
      st.acceptedRequestsOnConn++;
      st.lastProcessedStreamId = streamId;
      st.sendWindow -= bufferedLen;
      ByteArrayOutputStream resp = new ByteArrayOutputStream();
      maybeWriteKeepaliveGoAway(resp, config, st);
      H2Frames.writeHeadersFrame(resp, streamId, new byte[] {(byte) 0x88}, true);
      resp.writeTo(out);
      out.flush();
      return true;
    }
    if (st.queuedStreams < effectiveMaxStreams) {
      st.queuedStreams++;
      st.acceptedRequestsOnConn++;
      st.lastProcessedStreamId = streamId;
      st.sendWindow -= bufferedLen;
      st.queuedBytes += bufferedLen;
      if (st.acceptedRequestsOnConn >= config.keepaliveRequests && !st.keepaliveGoAwaySent) {
        ByteArrayOutputStream resp = new ByteArrayOutputStream();
        maybeWriteKeepaliveGoAway(resp, config, st);
        resp.writeTo(out);
        out.flush();
      }
      return true;
    }
    if (st.refusedStreams > Math.max(config.maxConcurrentStreams, 100L)) {
      byte[] goaway = new byte[8];
      H2Frames.writeUint32(goaway, 0, st.lastProcessedStreamId);
      H2Frames.writeUint32(goaway, 4, 0L);
      ByteArrayOutputStream buf = new ByteArrayOutputStream();
      H2Frames.writeFrame(buf, H2Frames.TYPE_GOAWAY, 0, 0, goaway);
      buf.writeTo(out);
      out.flush();
      closeWithLingeringDrain(config.tlsContext == null, rawSocket, in);
      return false;
    }
    st.refusedStreams++;
    int refusedSid = (config.nonContiguousRefusedStream && streamId >= 3) ? 1 : streamId;
    byte[] rst = new byte[4];
    H2Frames.writeUint32(rst, 0, H2Frames.ERR_REFUSED_STREAM);
    ByteArrayOutputStream resp = new ByteArrayOutputStream();
    H2Frames.writeFrame(resp, H2Frames.TYPE_RST_STREAM, 0, refusedSid, rst);
    resp.writeTo(out);
    out.flush();
    return true;
  }

  private static void processParkedPhaseAStream(
      OutputStream out,
      int streamId,
      int bufferedLen,
      MockNginxConfig config,
      MockConnectionState st)
      throws IOException {
    if (st.keepaliveGoAwaySent) {
      return;
    }
    long effectiveMaxStreams =
        config.effectiveActiveStreamLimit > 0
            ? config.effectiveActiveStreamLimit
            : config.maxConcurrentStreams;
    if (st.waitingStreams.size() >= effectiveMaxStreams) {
      st.refusedStreams++;
      byte[] rst = new byte[4];
      H2Frames.writeUint32(rst, 0, H2Frames.ERR_REFUSED_STREAM);
      ByteArrayOutputStream resp = new ByteArrayOutputStream();
      H2Frames.writeFrame(resp, H2Frames.TYPE_RST_STREAM, 0, streamId, rst);
      resp.writeTo(out);
      out.flush();
      return;
    }
    if (config.phaseARstOnStream > 0 && streamId == config.phaseARstOnStream) {
      byte[] rst = new byte[4];
      H2Frames.writeUint32(rst, 0, 0x02L);
      ByteArrayOutputStream resp = new ByteArrayOutputStream();
      H2Frames.writeFrame(resp, H2Frames.TYPE_RST_STREAM, 0, streamId, rst);
      resp.writeTo(out);
      out.flush();
      return;
    }
    st.acceptedRequestsOnConn++;
    st.lastProcessedStreamId = streamId;
    ByteArrayOutputStream resp = new ByteArrayOutputStream();
    maybeWriteKeepaliveGoAway(resp, config, st);
    H2Frames.writeHeadersFrame(
        resp, streamId, new byte[] {(byte) 0x88}, /* endStream= */ bufferedLen == 0);
    if (bufferedLen > 0) {
      int grant =
          config.phaseAIgnoreConnWindow
              ? bufferedLen
              : (st.waitingStreams.isEmpty() ? (int) Math.min(bufferedLen, st.sendWindow) : 0);
      st.sendWindow = Math.max(0L, st.sendWindow - grant);
      if (grant > 0) {
        writeChunkedDataFrames(resp, streamId, grant, /* endStream= */ grant == bufferedLen);
        st.phaseADataSent += grant;
      }
      if (grant < bufferedLen) {
        st.waitingStreams.addLast(new PendingStream(streamId, bufferedLen - grant));
      }
    }
    if (config.phaseAPingAckBeforeBatchFrames) {
      resp.writeTo(st.deferredPhaseABatchFrames);
    } else {
      resp.writeTo(out);
      out.flush();
    }
  }

  private static void maybeWriteKeepaliveGoAway(
      ByteArrayOutputStream out, MockNginxConfig config, MockConnectionState st) {
    if (!st.keepaliveGoAwaySent && st.acceptedRequestsOnConn >= config.keepaliveRequests) {
      st.keepaliveGoAwaySent = true;
      byte[] goaway = new byte[8];
      H2Frames.writeUint32(goaway, 0, st.lastProcessedStreamId);
      H2Frames.writeUint32(goaway, 4, 0L);
      H2Frames.writeFrame(out, H2Frames.TYPE_GOAWAY, 0, 0, goaway);
    }
  }

  private static void writeChunkedDataFrames(
      ByteArrayOutputStream out, int streamId, int totalBytes, boolean endStream) {
    int remaining = totalBytes;
    while (remaining > 0) {
      int chunk = Math.min(16_384, remaining);
      remaining -= chunk;
      int flags = (remaining == 0 && endStream) ? H2Frames.FLAG_END_STREAM : 0;
      H2Frames.writeFrame(out, H2Frames.TYPE_DATA, flags, streamId, new byte[chunk]);
    }
  }

  private static void closeWithLingeringDrain(
      boolean halfClosePlaintext, Socket rawSocket, InputStream in) throws IOException {
    if (halfClosePlaintext && !rawSocket.isOutputShutdown()) {
      rawSocket.shutdownOutput();
    }
    byte[] sink = new byte[4096];
    while (in.read(sink) > 0) {}
  }

  private static void sendDiscoveryResponse(
      OutputStream out,
      int streamId,
      String path,
      byte[] body,
      long peerInitialStreamWin,
      MockNginxConfig config)
      throws IOException {
    if (streamId == 1) {
      config.onDiscoveryResponseHook.run();
    }
    ByteArrayOutputStream headerBlock = new ByteArrayOutputStream();
    String status = config.routes.containsKey(path) ? "200" : "404";
    headerBlock.write(status.equals("200") ? 0x88 : 0x8d);
    if (config.serverHeader != null) {
      headerBlock.write(0x0f);
      headerBlock.write(39); // index 54 = server
      writeRawString(headerBlock, config.serverHeader);
    }
    for (HeaderField hf : config.extraResponseHeaders) {
      headerBlock.write(0x00);
      writeRawString(headerBlock, hf.name());
      writeRawString(headerBlock, hf.value());
    }
    for (HeaderField hf : config.routeHeaders.getOrDefault(path, ImmutableList.of())) {
      headerBlock.write(0x00);
      writeRawString(headerBlock, hf.name());
      writeRawString(headerBlock, hf.value());
    }
    while (headerBlock.size() < config.discoveryHeaderBlockMinBytes) {
      headerBlock.write(0x88);
    }
    byte[] hpackBytes = headerBlock.toByteArray();

    ByteArrayOutputStream resp = new ByteArrayOutputStream();
    int endStreamOnHeaders = (body.length == 0) ? H2Frames.FLAG_END_STREAM : 0;
    if (config.paddedDiscoveryHeadersAndData && hpackBytes.length > 2) {
      // Split across PADDED+PRIORITY HEADERS + CONTINUATION to exercise RFC 9113 continuation path.
      int split = hpackBytes.length / 2;
      ByteArrayOutputStream firstPart = new ByteArrayOutputStream();
      firstPart.write(3); // pad length
      firstPart.writeBytes(new byte[] {0, 0, 0, 0, 15}); // 5-byte priority
      firstPart.write(hpackBytes, 0, split);
      firstPart.writeBytes(new byte[] {0, 0, 0}); // 3-byte padding
      H2Frames.writeFrame(
          resp,
          H2Frames.TYPE_HEADERS,
          H2Frames.FLAG_PADDED | H2Frames.FLAG_PRIORITY | endStreamOnHeaders,
          streamId,
          firstPart.toByteArray());
      byte[] secondPart = Arrays.copyOfRange(hpackBytes, split, hpackBytes.length);
      H2Frames.writeFrame(
          resp, H2Frames.TYPE_CONTINUATION, H2Frames.FLAG_END_HEADERS, streamId, secondPart);
    } else {
      H2Frames.writeFrame(
          resp,
          H2Frames.TYPE_HEADERS,
          H2Frames.FLAG_END_HEADERS | endStreamOnHeaders,
          streamId,
          hpackBytes);
    }

    int maxSendable = (int) Math.min(body.length, peerInitialStreamWin);
    int offset = 0;
    while (offset < maxSendable) {
      int chunk = Math.min(16384, maxSendable - offset);
      boolean isLastChunkOfFullBody = (offset + chunk == body.length);
      int dataFlags = isLastChunkOfFullBody ? H2Frames.FLAG_END_STREAM : 0;
      byte[] slice = Arrays.copyOfRange(body, offset, offset + chunk);
      if (config.paddedDiscoveryHeadersAndData && offset == 0 && chunk <= 16370) {
        ByteArrayOutputStream padded = new ByteArrayOutputStream();
        padded.write(4);
        padded.writeBytes(slice);
        padded.writeBytes(new byte[] {0, 0, 0, 0});
        H2Frames.writeFrame(
            resp,
            H2Frames.TYPE_DATA,
            dataFlags | H2Frames.FLAG_PADDED,
            streamId,
            padded.toByteArray());
      } else {
        H2Frames.writeFrame(resp, H2Frames.TYPE_DATA, dataFlags, streamId, slice);
      }
      offset += chunk;
    }
    resp.writeTo(out);
    out.flush();
  }

  private static SSLContext createSelfSignedServerSslContext()
      throws GeneralSecurityException, IOException {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
    kpg.initialize(new ECGenParameterSpec("secp256r1"));
    KeyPair kp = kpg.generateKeyPair();

    byte[] algId = BaseEncoding.base16().lowerCase().decode(DER_ECDSA_SHA256_ALG_ID_HEX);
    byte[] subjectRdn = BaseEncoding.base16().lowerCase().decode(DER_CN_TEST_RDN_HEX);
    byte[] validity =
        derSequence(
            derTag(0x17, "250101000000Z".getBytes(ISO_8859_1)),
            derTag(0x17, "350101000000Z".getBytes(ISO_8859_1)));
    byte[] tbs =
        derSequence(
            derX509V3ExplicitVersion,
            derSerialNumberOne,
            algId,
            subjectRdn,
            validity,
            subjectRdn,
            kp.getPublic().getEncoded());

    Signature signer = Signature.getInstance("SHA256withECDSA");
    signer.initSign(kp.getPrivate());
    signer.update(tbs);
    byte[] sigBytes = signer.sign();

    byte[] bitString = new byte[sigBytes.length + 1];
    System.arraycopy(sigBytes, 0, bitString, 1, sigBytes.length);
    byte[] certDer = derSequence(tbs, algId, derTag(0x03, bitString));

    X509Certificate cert =
        (X509Certificate)
            CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(certDer));

    KeyStore ks = KeyStore.getInstance("PKCS12");
    ks.load(null, null);
    char[] password = new char[0];
    ks.setKeyEntry("srv", kp.getPrivate(), password, new Certificate[] {cert});

    KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    kmf.init(ks, password);

    SSLContext ctx = SSLContext.getInstance("TLS");
    ctx.init(kmf.getKeyManagers(), null, new SecureRandom());
    return ctx;
  }

  private static byte[] derSequence(byte[]... elements) {
    ByteArrayOutputStream content = new ByteArrayOutputStream();
    for (byte[] el : elements) {
      content.writeBytes(el);
    }
    return derTag(0x30, content.toByteArray());
  }

  private static byte[] derTag(int tag, byte[] content) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.write(tag);
    int len = content.length;
    if (len < 128) {
      out.write(len);
    } else if (len < 256) {
      out.write(0x81);
      out.write(len);
    } else {
      out.write(0x82);
      out.write((len >>> 8) & 0xff);
      out.write(len & 0xff);
    }
    out.writeBytes(content);
    return out.toByteArray();
  }

  private static final class MockNginxHarness {
    private final int port;
    private final AtomicInteger connectionCounter = new AtomicInteger(0);
    private final AtomicInteger burstConnectionCounter = new AtomicInteger(0);
    private final AtomicInteger stage2ConnectionCounter = new AtomicInteger(0);
    private final AtomicBoolean clientRstObserved = new AtomicBoolean(false);
    private final AtomicLong lastParkedPhaseADataBytes = new AtomicLong(0L);
    private final AtomicInteger lastParkedReleaseBytes = new AtomicInteger(0);
    private final AtomicReference<ImmutableList<Integer>> lastParkedReleaseFrameTypes =
        new AtomicReference<>(ImmutableList.of());
    private final List<String> recordedPaths = Collections.synchronizedList(new ArrayList<>());

    MockNginxHarness(int port) {
      this.port = port;
    }

    int port() {
      return port;
    }

    int totalConnections() {
      return connectionCounter.get();
    }

    boolean sawClientRstStream() {
      return clientRstObserved.get();
    }

    long lastParkedPhaseADataBytes() {
      return lastParkedPhaseADataBytes.get();
    }

    int lastParkedReleaseBytes() {
      return lastParkedReleaseBytes.get();
    }

    ImmutableList<Integer> lastParkedReleaseFrameTypes() {
      return lastParkedReleaseFrameTypes.get();
    }

    ImmutableList<String> requestedPaths() {
      synchronized (recordedPaths) {
        return ImmutableList.copyOf(recordedPaths);
      }
    }
  }

  private static final class ManualTicker extends Ticker {
    private final AtomicLong nanos = new AtomicLong(1_000_000_000L);
    private final AtomicLong autoStepNanos = new AtomicLong(0L);

    void advance(Duration delta) {
      nanos.addAndGet(delta.toNanos());
    }

    void setAutoIncrementStep(Duration step) {
      autoStepNanos.set(step.toNanos());
    }

    @Override
    public long read() {
      return nanos.addAndGet(autoStepNanos.get());
    }
  }

  private static final class MockNginxConfig implements Cloneable {
    boolean patched;
    boolean settings24Byte;
    long maxConcurrentStreams = 8L;
    long effectiveActiveStreamLimit = 0L;
    long keepaliveRequests = 1_000L;
    long serverInitialWindowSize = 65535L;
    long maxFrameSize = H2FlowControlProbe.NGINX_MAX_FRAME_SIZE;
    long noPrioritiesValue = 1L;
    byte[] rawSettingsPayload;
    long stream0WindowUpdateDelta = H2FlowControlProbe.NGINX_CONN_WINDOW_DELTA;
    boolean omitStream0WindowUpdate;
    int flushedBeforeBackpressure = 2;
    int firstBurstFlushedBeforeBackpressure = -1;
    boolean firstBurstFlushAllDataBeforePingB;
    boolean stage1FlushAllDataBeforePingB;
    boolean stage2FlushAllDataBeforePingB;
    boolean firstStage2FlushAllDataBeforePingB;
    boolean phaseAIgnoreConnWindow;
    boolean phaseAPingAckBeforeBatchFrames;
    int phaseARstOnStream;
    long stage2PrePingBFlushBytes = 4_096L;
    Runnable onDiscoveryResponseHook = () -> {};
    Runnable onStage2PhaseAStartHook = () -> {};
    Runnable onStage1PostBurstPingHook = () -> {};
    String serverHeader = "nginx/1.31.8";
    ImmutableList<HeaderField> extraResponseHeaders = ImmutableList.of();
    Map<String, ImmutableList<HeaderField>> routeHeaders = new LinkedHashMap<>();
    Map<String, byte[]> routes = new LinkedHashMap<>();
    byte[] default404Body = new byte[153];
    boolean paddedDiscoveryHeadersAndData;
    boolean nonContiguousRefusedStream;
    boolean dropPingCAck;
    int prePingBFlushBytes;
    boolean requireScannerUserAgent;
    SSLContext tlsContext;
    String[] alpnProtocols;
    AtomicReference<List<SNIServerName>> capturedSni;
    boolean cleartextZeroByteEofBeforeTls;
    int discoveryHeaderBlockMinBytes;

    static MockNginxConfig unpatchedDefault() {
      MockNginxConfig c = new MockNginxConfig();
      c.patched = false;
      c.routes.put("/", new byte[12_288]);
      return c;
    }

    static MockNginxConfig patchedDefault() {
      MockNginxConfig c = unpatchedDefault();
      c.patched = true;
      c.serverHeader = "nginx/1.31.9";
      return c;
    }

    private MockNginxConfig copy() {
      try {
        MockNginxConfig c = (MockNginxConfig) super.clone();
        c.routeHeaders = new LinkedHashMap<>(this.routeHeaders);
        c.routes = new LinkedHashMap<>(this.routes);
        return c;
      } catch (CloneNotSupportedException e) {
        throw new AssertionError(e);
      }
    }

    MockNginxConfig withSettings24Byte(boolean v) {
      MockNginxConfig c = copy();
      c.settings24Byte = v;
      return c;
    }

    MockNginxConfig withMaxConcurrentStreams(long v) {
      MockNginxConfig c = copy();
      c.maxConcurrentStreams = v;
      return c;
    }

    MockNginxConfig withEffectiveActiveStreamLimit(long v) {
      MockNginxConfig c = copy();
      c.effectiveActiveStreamLimit = v;
      return c;
    }

    MockNginxConfig withKeepaliveRequests(long v) {
      MockNginxConfig c = copy();
      c.keepaliveRequests = v;
      return c;
    }

    MockNginxConfig withFirstBurstFlushAllDataBeforePingB(boolean v) {
      MockNginxConfig c = copy();
      c.firstBurstFlushAllDataBeforePingB = v;
      return c;
    }

    MockNginxConfig withStage1FlushAllDataBeforePingB(boolean v) {
      MockNginxConfig c = copy();
      c.stage1FlushAllDataBeforePingB = v;
      return c;
    }

    MockNginxConfig withStage2FlushAllDataBeforePingB(boolean v) {
      MockNginxConfig c = copy();
      c.stage2FlushAllDataBeforePingB = v;
      return c;
    }

    MockNginxConfig withFirstStage2FlushAllDataBeforePingB(boolean v) {
      MockNginxConfig c = copy();
      c.firstStage2FlushAllDataBeforePingB = v;
      return c;
    }

    MockNginxConfig withPhaseAIgnoreConnWindow(boolean v) {
      MockNginxConfig c = copy();
      c.phaseAIgnoreConnWindow = v;
      return c;
    }

    MockNginxConfig withPhaseAPingAckBeforeBatchFrames(boolean v) {
      MockNginxConfig c = copy();
      c.phaseAPingAckBeforeBatchFrames = v;
      return c;
    }

    MockNginxConfig withPhaseARstOnStream(int sid) {
      MockNginxConfig c = copy();
      c.phaseARstOnStream = sid;
      return c;
    }

    MockNginxConfig withStage2PrePingBFlushBytes(long bytes) {
      MockNginxConfig c = copy();
      c.stage2PrePingBFlushBytes = bytes;
      return c;
    }

    MockNginxConfig withOnDiscoveryResponseHook(Runnable hook) {
      MockNginxConfig c = copy();
      c.onDiscoveryResponseHook = hook;
      return c;
    }

    MockNginxConfig withOnStage2PhaseAStartHook(Runnable hook) {
      MockNginxConfig c = copy();
      c.onStage2PhaseAStartHook = hook;
      return c;
    }

    MockNginxConfig withOnStage1PostBurstPingHook(Runnable hook) {
      MockNginxConfig c = copy();
      c.onStage1PostBurstPingHook = hook;
      return c;
    }

    MockNginxConfig withServerInitialWindowSize(long v) {
      MockNginxConfig c = copy();
      c.serverInitialWindowSize = v;
      return c;
    }

    MockNginxConfig withMaxFrameSize(long v) {
      MockNginxConfig c = copy();
      c.maxFrameSize = v;
      return c;
    }

    MockNginxConfig withNoPrioritiesValue(long v) {
      MockNginxConfig c = copy();
      c.noPrioritiesValue = v;
      return c;
    }

    MockNginxConfig withRawSettingsPayload(byte[] raw) {
      MockNginxConfig c = copy();
      c.rawSettingsPayload = raw;
      return c;
    }

    MockNginxConfig withStream0WindowUpdateDelta(long v) {
      MockNginxConfig c = copy();
      c.stream0WindowUpdateDelta = v;
      return c;
    }

    MockNginxConfig withOmitStream0WindowUpdate(boolean v) {
      MockNginxConfig c = copy();
      c.omitStream0WindowUpdate = v;
      return c;
    }

    MockNginxConfig withFlushedBeforeBackpressure(int v) {
      MockNginxConfig c = copy();
      c.flushedBeforeBackpressure = v;
      return c;
    }

    MockNginxConfig withFirstBurstFlushedBeforeBackpressure(int v) {
      MockNginxConfig c = copy();
      c.firstBurstFlushedBeforeBackpressure = v;
      return c;
    }

    MockNginxConfig withRouteHeaders(String path, List<HeaderField> headers) {
      MockNginxConfig c = copy();
      c.routeHeaders.put(path, ImmutableList.copyOf(headers));
      return c;
    }

    MockNginxConfig withServerHeader(String v) {
      MockNginxConfig c = copy();
      c.serverHeader = v;
      return c;
    }

    MockNginxConfig withExtraResponseHeaders(List<HeaderField> headers) {
      MockNginxConfig c = copy();
      c.extraResponseHeaders = ImmutableList.copyOf(headers);
      return c;
    }

    MockNginxConfig withRouteBody(String path, byte[] body) {
      MockNginxConfig c = copy();
      c.routes.put(path, body);
      return c;
    }

    MockNginxConfig withDefault404Body(byte[] body) {
      MockNginxConfig c = copy();
      c.default404Body = body;
      return c;
    }

    MockNginxConfig withPaddedDiscoveryHeadersAndData(boolean v) {
      MockNginxConfig c = copy();
      c.paddedDiscoveryHeadersAndData = v;
      return c;
    }

    MockNginxConfig withNonContiguousRefusedStream(boolean v) {
      MockNginxConfig c = copy();
      c.nonContiguousRefusedStream = v;
      return c;
    }

    MockNginxConfig withDropPingCAck(boolean v) {
      MockNginxConfig c = copy();
      c.dropPingCAck = v;
      return c;
    }

    MockNginxConfig withPrePingBFlushBytes(int v) {
      MockNginxConfig c = copy();
      c.prePingBFlushBytes = v;
      return c;
    }

    MockNginxConfig withRequireScannerUserAgent(boolean v) {
      MockNginxConfig c = copy();
      c.requireScannerUserAgent = v;
      return c;
    }

    MockNginxConfig withTlsContext(
        SSLContext ctx, String[] alpn, AtomicReference<List<SNIServerName>> sniSink) {
      MockNginxConfig c = copy();
      c.tlsContext = ctx;
      c.alpnProtocols = alpn;
      c.capturedSni = sniSink;
      return c;
    }

    MockNginxConfig withCleartextZeroByteEofBeforeTls(boolean v) {
      MockNginxConfig c = copy();
      c.cleartextZeroByteEofBeforeTls = v;
      return c;
    }

    MockNginxConfig withDiscoveryHeaderBlockMinBytes(int v) {
      MockNginxConfig c = copy();
      c.discoveryHeaderBlockMinBytes = v;
      return c;
    }

    byte[] buildSettingsPayload() {
      if (rawSettingsPayload != null) {
        return rawSettingsPayload;
      }
      byte[] p = new byte[settings24Byte ? 24 : 18];
      H2Frames.writeUint16(p, 0, H2Frames.SETTING_MAX_CONCURRENT_STREAMS);
      H2Frames.writeUint32(p, 2, maxConcurrentStreams);
      H2Frames.writeUint16(p, 6, H2Frames.SETTING_INITIAL_WINDOW_SIZE);
      H2Frames.writeUint32(p, 8, serverInitialWindowSize);
      H2Frames.writeUint16(p, 12, H2Frames.SETTING_MAX_FRAME_SIZE);
      H2Frames.writeUint32(p, 14, maxFrameSize);
      if (settings24Byte) {
        H2Frames.writeUint16(p, 18, H2Frames.SETTING_NO_PRIORITIES);
        H2Frames.writeUint32(p, 20, noPrioritiesValue);
      }
      return p;
    }

    byte[] resolveBody(String path) {
      return Optional.ofNullable(routes.get(path)).orElse(default404Body);
    }
  }

  private static final class LoopbackSocketFactory implements TsunamiSocketFactory {
    private final Duration defaultReadTimeout;
    private final boolean supportUnconnected;
    private final AtomicInteger dials = new AtomicInteger(0);

    LoopbackSocketFactory() {
      this(Duration.ofSeconds(3), true);
    }

    LoopbackSocketFactory(Duration defaultReadTimeout, boolean supportUnconnected) {
      this.defaultReadTimeout = defaultReadTimeout;
      this.supportUnconnected = supportUnconnected;
    }

    int dialedCount() {
      return dials.get();
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException {
      return createSocket(host, port, Duration.ofSeconds(3));
    }

    @Override
    public Socket createSocket(String host, int port, Duration timeout) throws IOException {
      return createSocket(host, port, timeout, timeout);
    }

    @Override
    public Socket createSocket(String host, int port, Duration connectTimeout, Duration readTimeout)
        throws IOException {
      dials.incrementAndGet();
      Socket socket = new Socket();
      socket.setSoTimeout((int) readTimeout.toMillis());
      socket.connect(new InetSocketAddress(host, port), (int) connectTimeout.toMillis());
      return socket;
    }

    @Override
    public Socket createSocket(InetAddress address, int port) throws IOException {
      return createSocket(address.getHostAddress(), port);
    }

    @Override
    public Socket createSocket(InetAddress address, int port, Duration timeout) throws IOException {
      return createSocket(address.getHostAddress(), port, timeout);
    }

    @Override
    public Socket createSocket(
        InetAddress address, int port, Duration connectTimeout, Duration readTimeout)
        throws IOException {
      return createSocket(address.getHostAddress(), port, connectTimeout, readTimeout);
    }

    @Override
    public Socket createUnconnectedSocket() {
      if (!supportUnconnected) {
        return null;
      }
      dials.incrementAndGet();
      return new Socket();
    }

    @Override
    public SSLSocket createSslSocket(String host, int port) {
      throw new UnsupportedOperationException();
    }

    @Override
    public SSLSocket createSslSocket(String host, int port, Duration timeout) {
      throw new UnsupportedOperationException();
    }

    @Override
    public SSLSocket createSslSocket(
        String host, int port, Duration connectTimeout, Duration readTimeout) {
      throw new UnsupportedOperationException();
    }

    @Override
    public SSLSocket createSslSocket(InetAddress address, int port) {
      throw new UnsupportedOperationException();
    }

    @Override
    public SSLSocket createSslSocket(InetAddress address, int port, Duration timeout) {
      throw new UnsupportedOperationException();
    }

    @Override
    public SSLSocket createSslSocket(
        InetAddress address, int port, Duration connectTimeout, Duration readTimeout) {
      throw new UnsupportedOperationException();
    }

    @Override
    public SSLSocket wrapWithSsl(Socket socket, String host, int port, boolean autoClose) {
      throw new UnsupportedOperationException();
    }

    @Override
    public Duration getDefaultConnectTimeout() {
      return Duration.ofSeconds(3);
    }

    @Override
    public Duration getDefaultReadTimeout() {
      return defaultReadTimeout;
    }
  }

  private abstract static class ForwardingLoopbackFactory implements TsunamiSocketFactory {
    private final LoopbackSocketFactory delegate;

    ForwardingLoopbackFactory(LoopbackSocketFactory delegate) {
      this.delegate = delegate;
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException {
      return delegate.createSocket(host, port);
    }

    @Override
    public Socket createSocket(String host, int port, Duration timeout) throws IOException {
      return delegate.createSocket(host, port, timeout);
    }

    @Override
    public Socket createSocket(String host, int port, Duration connectTimeout, Duration readTimeout)
        throws IOException {
      return delegate.createSocket(host, port, connectTimeout, readTimeout);
    }

    @Override
    public Socket createSocket(InetAddress address, int port) throws IOException {
      return delegate.createSocket(address, port);
    }

    @Override
    public Socket createSocket(InetAddress address, int port, Duration timeout) throws IOException {
      return delegate.createSocket(address, port, timeout);
    }

    @Override
    public Socket createSocket(
        InetAddress address, int port, Duration connectTimeout, Duration readTimeout)
        throws IOException {
      return delegate.createSocket(address, port, connectTimeout, readTimeout);
    }

    @Override
    public Socket createUnconnectedSocket() {
      return delegate.createUnconnectedSocket();
    }

    @Override
    public SSLSocket createSslSocket(String host, int port) {
      return delegate.createSslSocket(host, port);
    }

    @Override
    public SSLSocket createSslSocket(String host, int port, Duration timeout) {
      return delegate.createSslSocket(host, port, timeout);
    }

    @Override
    public SSLSocket createSslSocket(
        String host, int port, Duration connectTimeout, Duration readTimeout) {
      return delegate.createSslSocket(host, port, connectTimeout, readTimeout);
    }

    @Override
    public SSLSocket createSslSocket(InetAddress address, int port) {
      return delegate.createSslSocket(address, port);
    }

    @Override
    public SSLSocket createSslSocket(InetAddress address, int port, Duration timeout) {
      return delegate.createSslSocket(address, port, timeout);
    }

    @Override
    public SSLSocket createSslSocket(
        InetAddress address, int port, Duration connectTimeout, Duration readTimeout) {
      return delegate.createSslSocket(address, port, connectTimeout, readTimeout);
    }

    @Override
    public SSLSocket wrapWithSsl(Socket socket, String host, int port, boolean autoClose) {
      return delegate.wrapWithSsl(socket, host, port, autoClose);
    }

    @Override
    public Duration getDefaultConnectTimeout() {
      return delegate.getDefaultConnectTimeout();
    }

    @Override
    public Duration getDefaultReadTimeout() {
      return delegate.getDefaultReadTimeout();
    }
  }

  private static final class RecordingSslSocketFactory extends SSLSocketFactory {
    private final SSLSocketFactory delegate;
    private final List<SSLSocket> created = Collections.synchronizedList(new ArrayList<>());

    RecordingSslSocketFactory(SSLSocketFactory delegate) {
      this.delegate = delegate;
    }

    ImmutableList<SSLSocket> createdSockets() {
      synchronized (created) {
        return ImmutableList.copyOf(created);
      }
    }

    @Override
    public String[] getDefaultCipherSuites() {
      return delegate.getDefaultCipherSuites();
    }

    @Override
    public String[] getSupportedCipherSuites() {
      return delegate.getSupportedCipherSuites();
    }

    @Override
    public Socket createSocket(Socket s, String host, int port, boolean autoClose)
        throws IOException {
      SSLSocket ssl = (SSLSocket) delegate.createSocket(s, host, port, autoClose);
      created.add(ssl);
      return ssl;
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException {
      return delegate.createSocket(host, port);
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort)
        throws IOException {
      return delegate.createSocket(host, port, localHost, localPort);
    }

    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
      return delegate.createSocket(host, port);
    }

    @Override
    public Socket createSocket(
        InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
      return delegate.createSocket(address, port, localAddress, localPort);
    }
  }
}
