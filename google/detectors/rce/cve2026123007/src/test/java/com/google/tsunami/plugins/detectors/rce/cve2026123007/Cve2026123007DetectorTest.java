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
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
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

    InputStream in = activeSocket.getInputStream();
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
    long sendWindow = 65535L;
    long queuedBytes = 0L;
    long peerInitialStreamWin = 65535L;
    int flushedInBurst = 0;
    int queuedStreams = 0;
    int refusedStreams = 0;
    int lastProcessedStreamId = 0;
    int pingAckCount = 0;
    boolean countedBurst = false;
    int burstTargetFlushed = config.flushedBeforeBackpressure;

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
                peerInitialStreamWin = val;
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
            long accountedWindow = config.patched ? (sendWindow + queuedBytes) : sendWindow;
            if (inc == 0 || inc > H2FlowControlProbe.NGINX_MAX_WINDOW - accountedWindow) {
              byte[] goaway = new byte[8];
              H2Frames.writeUint32(goaway, 0, lastProcessedStreamId);
              H2Frames.writeUint32(goaway, 4, H2Frames.ERR_FLOW_CONTROL);
              ByteArrayOutputStream buf = new ByteArrayOutputStream();
              H2Frames.writeFrame(buf, H2Frames.TYPE_GOAWAY, 0, 0, goaway);
              buf.writeTo(out);
              out.flush();
              closeWithLingeringDrain(config.tlsContext == null, rawSocket, in);
              return;
            }
            sendWindow += inc;
          }
        }
        case H2Frames.TYPE_PING -> {
          if ((flags & H2Frames.FLAG_ACK) == 0 && payload.length == 8) {
            pingAckCount++;
            if (config.dropPingCAck && pingAckCount >= 3) {
              return;
            }
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            if (countedBurst && config.prePingBFlushBytes > 0 && pingAckCount == 1) {
              H2Frames.writeFrame(
                  buf, H2Frames.TYPE_DATA, 0, 1, new byte[config.prePingBFlushBytes]);
            }
            H2Frames.writePingFrame(buf, /* ack= */ true, payload);
            if (countedBurst && config.prePingBFlushBytes > 0 && pingAckCount == 2) {
              H2Frames.writeFrame(
                  buf, H2Frames.TYPE_DATA, H2Frames.FLAG_END_STREAM, 1, new byte[20_000]);
            }
            buf.writeTo(out);
            out.flush();
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
          boolean discoveryMode = (peerInitialStreamWin == H2FlowControlProbe.DISCOVERY_STREAM_WIN);

          if (discoveryMode) {
            lastProcessedStreamId = streamId;
            sendDiscoveryResponse(out, streamId, path, body, peerInitialStreamWin, config);
          } else {
            if (!countedBurst) {
              countedBurst = true;
              int burstIdx = harness.burstConnectionCounter.incrementAndGet();
              if (burstIdx == 1 && config.firstBurstFlushedBeforeBackpressure >= 0) {
                burstTargetFlushed = config.firstBurstFlushedBeforeBackpressure;
              }
            }
            if (flushedInBurst < burstTargetFlushed) {
              flushedInBurst++;
              lastProcessedStreamId = streamId;
              sendWindow -= body.length;
              // Send compact response headers for flushed stream.
              ByteArrayOutputStream resp = new ByteArrayOutputStream();
              H2Frames.writeHeadersFrame(resp, streamId, new byte[] {(byte) 0x88}, true);
              resp.writeTo(out);
              out.flush();
            } else if (queuedStreams < config.maxConcurrentStreams) {
              queuedStreams++;
              lastProcessedStreamId = streamId;
              int bufferedLen =
                  (config.tlsContext != null) ? Math.min(body.length, 65536) : body.length;
              sendWindow -= bufferedLen;
              queuedBytes += bufferedLen;
            } else {
              if (refusedStreams > Math.max(config.maxConcurrentStreams, 100L)) {
                byte[] goaway = new byte[8];
                H2Frames.writeUint32(goaway, 0, lastProcessedStreamId);
                H2Frames.writeUint32(goaway, 4, 0L);
                ByteArrayOutputStream buf = new ByteArrayOutputStream();
                H2Frames.writeFrame(buf, H2Frames.TYPE_GOAWAY, 0, 0, goaway);
                buf.writeTo(out);
                out.flush();
                closeWithLingeringDrain(config.tlsContext == null, rawSocket, in);
                return;
              }
              refusedStreams++;
              int refusedSid = (config.nonContiguousRefusedStream && streamId >= 3) ? 1 : streamId;
              byte[] rst = new byte[4];
              H2Frames.writeUint32(rst, 0, H2Frames.ERR_REFUSED_STREAM);
              ByteArrayOutputStream resp = new ByteArrayOutputStream();
              H2Frames.writeFrame(resp, H2Frames.TYPE_RST_STREAM, 0, refusedSid, rst);
              resp.writeTo(out);
              out.flush();
            }
          }
        }
        default -> {}
      }
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
    private final AtomicBoolean clientRstObserved = new AtomicBoolean(false);
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

    ImmutableList<String> requestedPaths() {
      synchronized (recordedPaths) {
        return ImmutableList.copyOf(recordedPaths);
      }
    }
  }

  private static final class MockNginxConfig {
    boolean patched;
    boolean settings24Byte;
    long maxConcurrentStreams = 8L;
    long serverInitialWindowSize = 65535L;
    long maxFrameSize = H2FlowControlProbe.NGINX_MAX_FRAME_SIZE;
    long noPrioritiesValue = 1L;
    byte[] rawSettingsPayload;
    long stream0WindowUpdateDelta = H2FlowControlProbe.NGINX_CONN_WINDOW_DELTA;
    boolean omitStream0WindowUpdate;
    int flushedBeforeBackpressure = 2;
    int firstBurstFlushedBeforeBackpressure = -1;
    String serverHeader = "nginx/1.31.8";
    ImmutableList<HeaderField> extraResponseHeaders = ImmutableList.of();
    final Map<String, ImmutableList<HeaderField>> routeHeaders = new LinkedHashMap<>();
    final Map<String, byte[]> routes = new LinkedHashMap<>();
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
      MockNginxConfig c = new MockNginxConfig();
      c.patched = this.patched;
      c.settings24Byte = this.settings24Byte;
      c.maxConcurrentStreams = this.maxConcurrentStreams;
      c.serverInitialWindowSize = this.serverInitialWindowSize;
      c.maxFrameSize = this.maxFrameSize;
      c.noPrioritiesValue = this.noPrioritiesValue;
      c.rawSettingsPayload = this.rawSettingsPayload;
      c.stream0WindowUpdateDelta = this.stream0WindowUpdateDelta;
      c.omitStream0WindowUpdate = this.omitStream0WindowUpdate;
      c.flushedBeforeBackpressure = this.flushedBeforeBackpressure;
      c.firstBurstFlushedBeforeBackpressure = this.firstBurstFlushedBeforeBackpressure;
      c.serverHeader = this.serverHeader;
      c.extraResponseHeaders = this.extraResponseHeaders;
      c.routeHeaders.putAll(this.routeHeaders);
      c.routes.putAll(this.routes);
      c.default404Body = this.default404Body;
      c.paddedDiscoveryHeadersAndData = this.paddedDiscoveryHeadersAndData;
      c.nonContiguousRefusedStream = this.nonContiguousRefusedStream;
      c.dropPingCAck = this.dropPingCAck;
      c.prePingBFlushBytes = this.prePingBFlushBytes;
      c.requireScannerUserAgent = this.requireScannerUserAgent;
      c.tlsContext = this.tlsContext;
      c.alpnProtocols = this.alpnProtocols;
      c.capturedSni = this.capturedSni;
      c.cleartextZeroByteEofBeforeTls = this.cleartextZeroByteEofBeforeTls;
      c.discoveryHeaderBlockMinBytes = this.discoveryHeaderBlockMinBytes;
      return c;
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
