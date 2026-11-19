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
package com.google.tsunami.plugins.detectors.rce.dask;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.common.util.concurrent.Futures.immediateFuture;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forIp;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forIpAndPort;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forIpHostnameAndPort;
import static com.google.tsunami.plugins.detectors.rce.dask.DaskCommClient.writeMpStr;
import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.junit.Assert.assertThrows;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Range;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkEndpointUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpRequest;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.common.net.socket.DefaultTsunamiSocketFactory;
import com.google.tsunami.common.net.socket.TsunamiSocketFactory;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.proto.AdditionalDetail;
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
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.AbstractList;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.IntSupplier;
import javax.inject.Inject;
import javax.net.SocketFactory;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.SocketPolicy;
import org.checkerframework.checker.nullness.qual.Nullable;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link DaskUnauthenticatedRceDetector} and {@link DaskCommClient}. */
@RunWith(JUnit4.class)
public final class DaskUnauthenticatedRceDetectorTest {

  private static final String WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  private static final int FIXED_OPERAND_A = 12_345_678;
  private static final int FIXED_OPERAND_B = 23_456_789;
  private static final long FIXED_SUM = (long) FIXED_OPERAND_A + (long) FIXED_OPERAND_B;
  private static final byte[] expectedOperatorAddPickle =
      new byte[] {
        (byte) 0x80,
        0x02,
        'c',
        'o',
        'p',
        'e',
        'r',
        'a',
        't',
        'o',
        'r',
        '\n',
        'a',
        'd',
        'd',
        '\n',
        'q',
        0x00,
        '.'
      };
  private static final byte[] expectedEmptyKwargsPickle =
      new byte[] {(byte) 0x80, 0x02, '}', 'q', 0x00, '.'};

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2026-01-01T00:00:00.00Z"));
  private final InetAddress loopbackAddress = InetAddress.getLoopbackAddress();
  private final String loopbackIp = loopbackAddress.getHostAddress();
  private final List<MockDaskServer> activeServers = new ArrayList<>();

  private RecordingTsunamiSocketFactory socketFactory;
  private MockWebServer mockWebServer;
  private Optional<String> previousAllowInternalConnections = Optional.empty();

  @Inject private HttpClient httpClient;
  @Inject private DaskUnauthenticatedRceDetector injectedDetector;

  @Before
  public void setUp() throws IOException {
    previousAllowInternalConnections =
        Optional.ofNullable(System.setProperty("tsunami.allowInternalConnections", "true"));
    socketFactory = new RecordingTsunamiSocketFactory(loopbackIp);
    mockWebServer = new MockWebServer();
    mockWebServer.start(loopbackAddress, 0);

    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            new AbstractModule() {
              @Override
              protected void configure() {
                bind(TsunamiSocketFactory.class).toInstance(socketFactory);
              }
            },
            new DaskUnauthenticatedRceDetectorBootstrapModule())
        .injectMembers(this);
  }

  @After
  public void tearDown() throws IOException {
    if (previousAllowInternalConnections.isPresent()) {
      System.setProperty(
          "tsunami.allowInternalConnections", previousAllowInternalConnections.get());
    } else {
      System.clearProperty("tsunami.allowInternalConnections");
    }
    Throwable firstFailure = null;
    for (MockDaskServer server : activeServers) {
      try {
        server.close();
      } catch (Throwable t) {
        if (firstFailure == null) {
          firstFailure = t;
        } else {
          firstFailure.addSuppressed(t);
        }
      }
    }
    activeServers.clear();
    try {
      mockWebServer.shutdown();
    } catch (Throwable t) {
      if (firstFailure == null) {
        firstFailure = t;
      } else {
        firstFailure.addSuppressed(t);
      }
    }
    if (firstFailure instanceof IOException ioe) {
      throw ioe;
    }
    if (firstFailure instanceof Error error) {
      throw error;
    }
    if (firstFailure instanceof RuntimeException re) {
      throw re;
    }
    if (firstFailure != null) {
      throw new AssertionError("Unexpected tearDown failure", firstFailure);
    }
  }

  private DaskUnauthenticatedRceDetector createFixedOperandDetector() {
    AtomicInteger callIndex = new AtomicInteger();
    IntSupplier supplier =
        () -> (callIndex.getAndIncrement() % 2 == 0) ? FIXED_OPERAND_A : FIXED_OPERAND_B;
    return new DaskUnauthenticatedRceDetector(
        fakeUtcClock,
        httpClient,
        new DaskCommClient(socketFactory, Duration.ofSeconds(3)),
        supplier);
  }

  private MockDaskServer startCommServer(SocketHandler handler) throws IOException {
    MockDaskServer server = new MockDaskServer(loopbackAddress, handler);
    activeServers.add(server);
    return server;
  }

  private MockDaskServer startTcpRunFunctionReplyServer(String daemonId, List<byte[]> replyFrames)
      throws IOException {
    return startCommServer(socket -> {
      InputStream in = new BufferedInputStream(socket.getInputStream());
      OutputStream out = socket.getOutputStream();
      verifyClientHandshake(readTcpFrames(in));
      writeTcpFrames(out, ImmutableList.of(encodeHandshakeReply()));
      verifyIdentityRequest(readTcpFrames(in));
      writeTcpFrames(out, ImmutableList.of(encodeIdentityReply("Scheduler", daemonId)));
      assertThat(extractAndVerifyRunOperands(readTcpFrames(in).get(0), "run_function"))
          .isEqualTo(FIXED_SUM);
      writeTcpFrames(out, replyFrames);
    });
  }

  private MockDaskServer startWsRunFunctionReplyServer(String daemonId, List<byte[]> replyFrames)
      throws IOException {
    return startCommServer(socket -> {
      InputStream in = new BufferedInputStream(socket.getInputStream());
      OutputStream out = socket.getOutputStream();
      Optional<String> path = completeWsServerUpgrade(in, out);
      if (path.isEmpty()) {
        return;
      }
      verifyClientHandshake(readWsClientFrames(in));
      writeWsServerFrames(out, ImmutableList.of(encodeHandshakeReply()), false);
      verifyIdentityRequest(readWsClientFrames(in));
      writeWsServerFrames(out, ImmutableList.of(encodeIdentityReply("Scheduler", daemonId)), false);
      assertThat(extractAndVerifyRunOperands(readWsClientFrames(in).get(0), "run_function"))
          .isEqualTo(FIXED_SUM);
      writeWsServerFrames(out, replyFrames, false);
    });
  }

  private TargetInfo buildTargetInfo() {
    return TargetInfo.newBuilder().addNetworkEndpoints(forIp(loopbackIp)).build();
  }

  private NetworkService buildTcpService(int port, String serviceName) {
    return NetworkService.newBuilder()
        .setNetworkEndpoint(forIpAndPort(loopbackIp, port))
        .setTransportProtocol(TransportProtocol.TCP)
        .setServiceName(serviceName)
        .build();
  }

  private DetectionReport buildExpectedReport(
      TargetInfo targetInfo, NetworkService service, String evidenceText) {
    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(service)
        .setDetectionTimestamp(Timestamps.fromMillis(fakeUtcClock.instant().toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder()
                        .setPublisher(DaskUnauthenticatedRceDetector.VULNERABILITY_REPORT_PUBLISHER)
                        .setValue(DaskUnauthenticatedRceDetector.VULNERABILITY_REPORT_ID))
                .setSeverity(Severity.CRITICAL)
                .setTitle(DaskUnauthenticatedRceDetector.VULNERABILITY_REPORT_TITLE)
                .setDescription(DaskUnauthenticatedRceDetector.VULN_DESCRIPTION)
                .setRecommendation(DaskUnauthenticatedRceDetector.RECOMMENDATION)
                .addAdditionalDetails(
                    AdditionalDetail.newBuilder()
                        .setDescription(
                            "Verified unauthenticated Dask Distributed RPC code execution")
                        .setTextData(TextData.newBuilder().setText(evidenceText))))
        .build();
  }

  @Test
  public void getAdvisories_returnsCriticalDaskAdvisory() {
    assertThat(injectedDetector.getAdvisories())
        .containsExactly(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder()
                        .setPublisher("GOOGLE")
                        .setValue("DASK_DISTRIBUTED_UNAUTHENTICATED_RCE"))
                .setSeverity(Severity.CRITICAL)
                .setTitle(DaskUnauthenticatedRceDetector.VULNERABILITY_REPORT_TITLE)
                .setDescription(DaskUnauthenticatedRceDetector.VULN_DESCRIPTION)
                .setRecommendation(DaskUnauthenticatedRceDetector.RECOMMENDATION)
                .build());
  }

  @Test
  public void detect_whenTcpSchedulerAllowsRunFunction_reportsVulnerability() throws Exception {
    MockDaskServer commServer =
        startCommServer(socket ->
            serveTcpDaskSession(
                socket, "Scheduler", "Scheduler-1111", ResultMode.RUN_FUNCTION_PICKLED_MAP));
    NetworkService service = buildTcpService(commServer.port(), "dask-scheduler");
    TargetInfo target = buildTargetInfo();
    String commAddr = NetworkEndpointUtils.toHostAndPort(service.getNetworkEndpoint()).toString();

    DetectionReportList reports =
        createFixedOperandDetector().detect(target, ImmutableList.of(service));

    String expectedEvidence =
        String.format(
            "Verified unauthenticated Dask Scheduler (Scheduler-1111) code execution on %s via"
                + " run_function RPC handler: operator.add(%d, %d) returned %d.",
            commAddr, FIXED_OPERAND_A, FIXED_OPERAND_B, FIXED_SUM);
    assertThat(reports.getDetectionReportsList())
        .containsExactly(buildExpectedReport(target, service, expectedEvidence));
  }

  @Test
  public void detect_whenInjectedDetectorRunsWithRandomOperands_reportsVerifiedSum()
      throws Exception {
    MockDaskServer commServer =
        startCommServer(socket ->
            serveTcpDaskSession(
                socket,
                "Scheduler",
                "Scheduler-rand",
                ResultMode.RUN_FUNCTION_SERIALIZED_SUBFRAME));
    NetworkService service = buildTcpService(commServer.port(), "dask");

    DetectionReportList reports =
        injectedDetector.detect(buildTargetInfo(), ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList()).hasSize(1);
    DetectionReport report = reports.getDetectionReports(0);
    assertThat(report.getDetectionStatus()).isEqualTo(DetectionStatus.VULNERABILITY_VERIFIED);
    String detailText = report.getVulnerability().getAdditionalDetails(0).getTextData().getText();
    assertThat(detailText).contains("Scheduler (Scheduler-rand)");
    assertThat(detailText)
        .containsMatch("operator\\.add\\([1-4]\\d{7}, [1-4]\\d{7}\\) returned \\d+");
  }

  @Test
  public void createSecureOperandSupplier_generatesDiverseEightDigitOperandsWithinExpectedBounds() {
    IntSupplier supplier = DaskUnauthenticatedRceDetector.createSecureOperandSupplier();
    Set<Integer> distinctOperands = new HashSet<>();
    for (int i = 0; i < 256; i++) {
      int value = supplier.getAsInt();
      assertThat(value).isIn(Range.closedOpen(10_000_000, 50_000_000));
      distinctOperands.add(value);
    }
    assertThat(distinctOperands.size()).isGreaterThan(100);
  }

  @Test
  public void detect_whenSchedulerRunFunctionBlockedButBroadcastRunSucceeds_reportsVulnerability()
      throws Exception {
    MockDaskServer commServer =
        startCommServer(socket ->
            serveTcpDaskSession(
                socket, "Scheduler", "Scheduler-bcast", ResultMode.BROADCAST_FALLBACK));
    NetworkService service = buildTcpService(commServer.port(), "msgclnt");
    TargetInfo target = buildTargetInfo();
    String commAddr = NetworkEndpointUtils.toHostAndPort(service.getNetworkEndpoint()).toString();

    DetectionReportList reports =
        createFixedOperandDetector().detect(target, ImmutableList.of(service));

    String expectedEvidence =
        String.format(
            "Verified unauthenticated Dask Scheduler (Scheduler-bcast) code execution on %s via"
                + " broadcast(run) RPC handler: operator.add(%d, %d) returned %d.",
            commAddr, FIXED_OPERAND_A, FIXED_OPERAND_B, FIXED_SUM);
    assertThat(reports.getDetectionReportsList())
        .containsExactly(buildExpectedReport(target, service, expectedEvidence));
  }

  @Test
  public void detect_whenTcpWorkerAllowsRun_reportsVulnerability() throws Exception {
    MockDaskServer commServer =
        startCommServer(socket ->
            serveTcpDaskSession(socket, "Worker", "Worker-9999", ResultMode.WORKER_DIRECT_RUN));
    NetworkService service = buildTcpService(commServer.port(), "dask-worker");
    TargetInfo target = buildTargetInfo();
    String commAddr = NetworkEndpointUtils.toHostAndPort(service.getNetworkEndpoint()).toString();

    DetectionReportList reports =
        createFixedOperandDetector().detect(target, ImmutableList.of(service));

    String expectedEvidence =
        String.format(
            "Verified unauthenticated Dask Worker (Worker-9999) code execution on %s via run RPC"
                + " handler: operator.add(%d, %d) returned %d.",
            commAddr, FIXED_OPERAND_A, FIXED_OPERAND_B, FIXED_SUM);
    assertThat(reports.getDetectionReportsList())
        .containsExactly(buildExpectedReport(target, service, expectedEvidence));
  }

  @Test
  public void detect_whenSslTcpCommServiceAllowsRunFunction_usesSslSocketAndReportsVulnerability()
      throws Exception {
    MockDaskServer commServer =
        startCommServer(socket ->
            serveTcpDaskSession(
                socket, "Scheduler", "Scheduler-tls", ResultMode.RUN_FUNCTION_DIRECT_INT));
    NetworkService service = buildTcpService(commServer.port(), "ssl/dask");
    TargetInfo target = buildTargetInfo();

    DetectionReportList reports =
        createFixedOperandDetector().detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList()).hasSize(1);
    assertThat(socketFactory.dialAttempts())
        .containsExactly(new DialAttempt(loopbackIp, commServer.port(), true));
    assertThat(socketFactory.openedPlainSockets()).hasSize(1);
    assertThat(socketFactory.openedPlainSockets().get(0).isClosed()).isTrue();

    // Non-"ssl/" service name with populated supported_ssl_versions must also dial with TLS.
    socketFactory.clearDialAttempts();
    socketFactory.requireTlsOnPort(commServer.port());
    NetworkService sslVersionOnlyService =
        buildTcpService(commServer.port(), "dask").toBuilder()
            .addSupportedSslVersions("TLSv1.3")
            .build();
    DetectionReportList sslVersionReports =
        createFixedOperandDetector().detect(target, ImmutableList.of(sslVersionOnlyService));
    assertThat(sslVersionReports.getDetectionReportsList()).hasSize(1);
    assertThat(socketFactory.dialAttempts())
        .containsExactly(new DialAttempt(loopbackIp, commServer.port(), true));
  }

  @Test
  public void detect_whenWebSocketSchedulerAllowsRunFunction_reportsVulnerability()
      throws Exception {
    List<String> upgradePaths = new CopyOnWriteArrayList<>();
    MockDaskServer wsServer =
        startCommServer(socket ->
            serveWsDaskSession(
                socket,
                "Scheduler",
                "Scheduler-ws1",
                ResultMode.RUN_FUNCTION_DIRECT_BYTES,
                upgradePaths,
                /* fragmentAndPing= */ true));
    NetworkService service = buildTcpService(wsServer.port(), "http");
    TargetInfo target = buildTargetInfo();
    String commAddr = NetworkEndpointUtils.toHostAndPort(service.getNetworkEndpoint()).toString();

    DetectionReportList reports =
        createFixedOperandDetector().detect(target, ImmutableList.of(service));

    String expectedEvidence =
        String.format(
            "Verified unauthenticated Dask Scheduler (Scheduler-ws1) code execution on %s via"
                + " run_function RPC handler: operator.add(%d, %d) returned %d.",
            commAddr, FIXED_OPERAND_A, FIXED_OPERAND_B, FIXED_SUM);
    assertThat(reports.getDetectionReportsList())
        .containsExactly(buildExpectedReport(target, service, expectedEvidence));
    assertThat(upgradePaths).containsExactly("/");
    assertThat(socketFactory.dialAttempts())
        .containsExactly(new DialAttempt(loopbackIp, wsServer.port(), false));
  }

  @Test
  public void detect_whenSslHttpWebServiceExposesWssScheduler_usesSslSocketAndReportsVulnerability()
      throws Exception {
    List<String> upgradePaths = new CopyOnWriteArrayList<>();
    MockDaskServer wssServer =
        startCommServer(socket ->
            serveWsDaskSession(
                socket,
                "Scheduler",
                "Scheduler-wss",
                ResultMode.RUN_FUNCTION_DIRECT_INT,
                upgradePaths,
                /* fragmentAndPing= */ false));
    // Nmap labels HTTPS services on non-443 ports as "ssl/http" without populating SSL versions.
    NetworkService service = buildTcpService(wssServer.port(), "ssl/http");
    TargetInfo target = buildTargetInfo();

    // Configure recording socket factory to reject plaintext sockets on the TLS-only server port
    // so that probing without TLS fails just like a real wss:// listener.
    socketFactory.requireTlsOnPort(wssServer.port());

    DetectionReportList reports =
        createFixedOperandDetector().detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList()).hasSize(1);
    assertThat(socketFactory.dialAttempts())
        .containsExactly(new DialAttempt(loopbackIp, wssServer.port(), true));
    assertThat(socketFactory.openedPlainSockets()).hasSize(1);
    assertThat(socketFactory.openedPlainSockets().get(0).isClosed()).isTrue();
  }

  @Test
  public void
      detect_whenDashboardAdvertisesUntrustedExternalHostInJson_probesAuthorizedLoopbackHostOnly()
          throws Exception {
    MockDaskServer commServer =
        startCommServer(socket ->
            serveTcpDaskSession(
                socket, "Scheduler", "Scheduler-ssrf-safe", ResultMode.RUN_FUNCTION_PICKLED_MAP));
    String untrustedHost = "169.254.169.254";
    String identityJson =
        String.format(
            "{\"type\":\"Scheduler\",\"id\":\"Scheduler-ssrf-safe\",\"address\":\"tcp://%s:%d\"}",
            untrustedHost, commServer.port());
    // Request 1: WebSocket upgrade probe on dashboard port returns 404.
    // Request 2: GET /json/identity.json returns Scheduler JSON with untrusted host.
    mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code()));
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody(identityJson));

    NetworkService dashboardService = buildTcpService(mockWebServer.getPort(), "http");
    NetworkService inScopeCommPort = buildTcpService(commServer.port(), "tcpwrapped");
    TargetInfo target = buildTargetInfo();
    String commAddr =
        NetworkEndpointUtils.toHostAndPort(forIpAndPort(loopbackIp, commServer.port())).toString();
    String expectedIdentityUrl =
        String.format(
            "http://%s/json/identity.json",
            NetworkEndpointUtils.toUriAuthority(dashboardService.getNetworkEndpoint()));

    DetectionReportList reports =
        createFixedOperandDetector()
            .detect(target, ImmutableList.of(dashboardService, inScopeCommPort));

    String expectedEvidence =
        String.format(
            "Discovered via exposed Dask Dashboard %s. Verified unauthenticated Dask Scheduler"
                + " (Scheduler-ssrf-safe) code execution on %s via run_function RPC handler:"
                + " operator.add(%d, %d) returned %d.",
            expectedIdentityUrl, commAddr, FIXED_OPERAND_A, FIXED_OPERAND_B, FIXED_SUM);
    assertThat(reports.getDetectionReportsList())
        .containsExactly(buildExpectedReport(target, dashboardService, expectedEvidence));
    assertThat(socketFactory.dialAttempts())
        .containsExactly(
            new DialAttempt(loopbackIp, mockWebServer.getPort(), false),
            new DialAttempt(loopbackIp, commServer.port(), false))
        .inOrder();
    assertThat(socketFactory.dialedHosts()).doesNotContain(untrustedHost);
  }

  @Test
  public void detect_whenDashboardAdvertisesWsEndpointWithUnderscoreHostname_discoversAndVerifies()
      throws Exception {
    List<String> upgradePaths = new CopyOnWriteArrayList<>();
    MockDaskServer wsCommServer =
        startCommServer(socket ->
            serveWsDaskSession(
                socket,
                "Scheduler",
                "Scheduler-docker",
                ResultMode.RUN_FUNCTION_DIRECT_INT,
                upgradePaths,
                /* fragmentAndPing= */ false));
    String identityJson =
        String.format(
            "{\"type\":\"Scheduler\",\"id\":\"Scheduler-docker\","
                + "\"address\":\"ws://dask_scheduler:%d/ws\"}",
            wsCommServer.port());
    // Direct WS probes on /ws and / return 404; /ws/json/identity.json returns Scheduler JSON.
    mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code()));
    mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code()));
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody(identityJson));

    NetworkService dashboardService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forIpAndPort(loopbackIp, mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("http")
            .setServiceContext(
                ServiceContext.newBuilder()
                    .setWebServiceContext(WebServiceContext.newBuilder().setApplicationRoot("/ws")))
            .build();
    NetworkService inScopeWsPort = buildTcpService(wsCommServer.port(), "tcpwrapped");
    TargetInfo target = buildTargetInfo();

    DetectionReportList reports =
        createFixedOperandDetector()
            .detect(target, ImmutableList.of(dashboardService, inScopeWsPort));

    assertThat(reports.getDetectionReportsList()).hasSize(1);
    assertThat(upgradePaths).containsExactly("/ws");
    assertThat(socketFactory.dialAttempts())
        .containsExactly(
            new DialAttempt(loopbackIp, mockWebServer.getPort(), false),
            new DialAttempt(loopbackIp, mockWebServer.getPort(), false),
            new DialAttempt(loopbackIp, wsCommServer.port(), false))
        .inOrder();
    assertThat(socketFactory.dialedHosts()).doesNotContain("dask_scheduler");
  }

  @Test
  public void detect_whenDashboardAndTcpCommPointToSameScheduler_deduplicatesAndProbesCommOnce()
      throws Exception {
    AtomicInteger commConnections = new AtomicInteger();
    MockDaskServer commServer =
        startCommServer(socket -> {
          commConnections.incrementAndGet();
          serveTcpDaskSession(
              socket, "Scheduler", "Scheduler-dedup", ResultMode.RUN_FUNCTION_DIRECT_INT);
        });
    String identityJson =
        String.format(
            "{\"type\":\"Scheduler\",\"id\":\"Scheduler-dedup\",\"address\":\"tcp://10.0.0.8:%d\"}",
            commServer.port());
    mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code()));
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody(identityJson));

    NetworkService dashboardService = buildTcpService(mockWebServer.getPort(), "http");
    NetworkService commService = buildTcpService(commServer.port(), "dask-scheduler");
    NetworkService duplicateCommService = buildTcpService(commServer.port(), "unknown");
    TargetInfo target = buildTargetInfo();

    // Pass dashboardService BEFORE commService to verify orderedServices prioritizes raw Comm first
    // and deduplicates both the duplicate raw Comm service and the Dashboard-discovered endpoint.
    DetectionReportList reports =
        createFixedOperandDetector()
            .detect(target, ImmutableList.of(dashboardService, commService, duplicateCommService));

    assertThat(reports.getDetectionReportsList()).hasSize(1);
    assertThat(reports.getDetectionReports(0).getNetworkService()).isEqualTo(commService);
    assertThat(commConnections.get()).isEqualTo(1);
  }

  @Test
  public void
      detect_whenCudaWorkerAndNannyAllowRunAndPickledOffsetMsgpackSubframeUsed_reportsVulnerabilities()
          throws Exception {
    MockDaskServer cudaWorkerServer =
        startCommServer(socket ->
            serveTcpDaskSession(
                socket, "CUDAWorker", "k8s-gpu-pod-0", ResultMode.PICKLED_OFFSET_MSGPACK_SUBFRAME));
    MockDaskServer nannyServer =
        startCommServer(socket ->
            serveTcpDaskSession(socket, "Nanny", "nanny-node-0", ResultMode.WORKER_DIRECT_RUN));

    NetworkService cudaService = buildTcpService(cudaWorkerServer.port(), "dask-worker");
    NetworkService nannyService = buildTcpService(nannyServer.port(), "dask-nanny");

    DetectionReportList reports =
        createFixedOperandDetector()
            .detect(buildTargetInfo(), ImmutableList.of(cudaService, nannyService));

    assertThat(reports.getDetectionReportsList()).hasSize(2);
    assertThat(
            reports
                .getDetectionReports(0)
                .getVulnerability()
                .getAdditionalDetails(0)
                .getTextData()
                .getText())
        .contains("CUDAWorker (k8s-gpu-pod-0)");
    assertThat(
            reports
                .getDetectionReports(1)
                .getVulnerability()
                .getAdditionalDetails(0)
                .getTextData()
                .getText())
        .contains("Nanny (nanny-node-0)");
  }

  @Test
  public void
      detect_whenSchedulerBlocksWorkerBroadcastButAllowsNannyBroadcast_reportsVulnerability()
          throws Exception {
    MockDaskServer commServer =
        startCommServer(socket ->
            serveTcpDaskSession(
                socket, "Scheduler", "k8s-sched-0", ResultMode.NANNY_BROADCAST_FALLBACK));
    NetworkService service = buildTcpService(commServer.port(), "dask-scheduler");

    DetectionReportList reports =
        createFixedOperandDetector().detect(buildTargetInfo(), ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList()).hasSize(1);
    String evidence =
        reports
            .getDetectionReports(0)
            .getVulnerability()
            .getAdditionalDetails(0)
            .getTextData()
            .getText();
    assertThat(evidence).contains("Scheduler (k8s-sched-0)");
    assertThat(evidence).contains("via broadcast(nanny_run) RPC handler");
  }

  @Test
  public void detect_whenNonWebMsgsrvrAndMsgclntFallbackToWebAndWebSocket_reportsVulnerabilities()
      throws Exception {
    MockDaskServer tcpCommServer =
        startCommServer(socket ->
            serveTcpDaskSession(
                socket, "Scheduler", "Scheduler-msgsrvr", ResultMode.RUN_FUNCTION_DIRECT_INT));
    String identityJson =
        String.format(
            "{\"type\":\"Scheduler\",\"id\":\"Scheduler-msgsrvr\",\"address\":\"tcp://10.0.0.2:%d\"}",
            tcpCommServer.port());
    // msgsrvr probes: 1) raw TCP Comm (mockWebServer ignores/closes or returns 400), 2) WS upgrade
    // (404), 3) GET /json/identity.json (200 OK).
    mockWebServer.enqueue(new MockResponse().setSocketPolicy(SocketPolicy.DISCONNECT_AT_START));
    mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code()));
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody(identityJson));

    List<String> wsPaths = new CopyOnWriteArrayList<>();
    MockDaskServer wsCommServer =
        startCommServer(socket -> {
          BufferedInputStream in = new BufferedInputStream(socket.getInputStream());
          in.mark(16);
          byte[] peek = in.readNBytes(4);
          if (!Arrays.equals(peek, "GET ".getBytes(US_ASCII))) {
            socket.close();
            return;
          }
          in.reset();
          Optional<String> path = completeWsServerUpgrade(in, socket.getOutputStream());
          if (path.isEmpty()) {
            return;
          }
          wsPaths.add(path.get());
          List<byte[]> hs = readWsClientFrames(in);
          verifyClientHandshake(hs);
          writeWsServerFrames(
              socket.getOutputStream(), ImmutableList.of(encodeHandshakeReply()), false);
          List<byte[]> idReq = readWsClientFrames(in);
          verifyIdentityRequest(idReq);
          writeWsServerFrames(
              socket.getOutputStream(),
              ImmutableList.of(encodeIdentityReply("Scheduler", "Scheduler-msgclnt")),
              false);
          List<byte[]> rpcReq = readWsClientFrames(in);
          long sum = extractAndVerifyRunOperands(rpcReq.get(0), "run_function");
          writeWsServerFrames(
              socket.getOutputStream(),
              encodeRunResultFrames(sum, ResultMode.RUN_FUNCTION_DIRECT_INT),
              false);
        });

    NetworkService msgsrvrService = buildTcpService(mockWebServer.getPort(), "msgsrvr");
    NetworkService msgclntService = buildTcpService(wsCommServer.port(), "msgclnt");
    NetworkService inScopeTcpPort = buildTcpService(tcpCommServer.port(), "tcpwrapped");

    DetectionReportList reports =
        createFixedOperandDetector()
            .detect(
                buildTargetInfo(),
                ImmutableList.of(msgsrvrService, msgclntService, inScopeTcpPort));

    assertThat(reports.getDetectionReportsList()).hasSize(2);
    assertThat(wsPaths).containsExactly("/");
  }

  @Test
  public void
      detect_whenUnknownNonWebServiceOnCustomPortHostsWsServer_skipsWebSocketFallbackAndReturnsEmpty()
          throws Exception {
    List<String> wsPaths = new CopyOnWriteArrayList<>();
    MockDaskServer wsCommServer =
        startCommServer(socket -> {
          BufferedInputStream in = new BufferedInputStream(socket.getInputStream());
          in.mark(16);
          byte[] peek = in.readNBytes(4);
          if (!Arrays.equals(peek, "GET ".getBytes(US_ASCII))) {
            socket.close();
            return;
          }
          in.reset();
          completeWsServerUpgrade(in, socket.getOutputStream()).ifPresent(wsPaths::add);
        });

    socketFactory.clearDialAttempts();
    NetworkService unknownService = buildTcpService(wsCommServer.port(), "unknown");

    DetectionReportList reports =
        createFixedOperandDetector().detect(buildTargetInfo(), ImmutableList.of(unknownService));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(wsPaths).isEmpty();
    assertThat(socketFactory.dialAttempts()).hasSize(1);
  }

  @Test
  public void detect_whenWebServiceHasSubpathApplicationRoot_discoversSubpathDashboard()
      throws Exception {
    MockDaskServer tcpCommServer =
        startCommServer(socket ->
            serveTcpDaskSession(
                socket, "Scheduler", "k8s-sched-subpath", ResultMode.RUN_FUNCTION_DIRECT_INT));
    String identityJson =
        String.format(
            "{\"type\":\"Scheduler\",\"id\":\"k8s-sched-subpath\",\"address\":\"tcp://10.0.0.9:%d\"}",
            tcpCommServer.port());
    // Subpath WS probe (/dask) -> 404, root WS probe (/) -> 404, GET /dask/json/identity.json ->
    // 200.
    mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code()));
    mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code()));
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody(identityJson));

    NetworkService subpathDash =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forIpHostnameAndPort(loopbackIp, "localhost", mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("http")
            .setServiceContext(
                ServiceContext.newBuilder()
                    .setWebServiceContext(
                        WebServiceContext.newBuilder()
                            .setApplicationRoot("http://localhost/dask/")))
            .build();

    NetworkService inScopeTcpPort = buildTcpService(tcpCommServer.port(), "tcpwrapped");
    DetectionReportList reports =
        createFixedOperandDetector()
            .detect(buildTargetInfo(), ImmutableList.of(subpathDash, inScopeTcpPort));
    assertThat(reports.getDetectionReportsList()).hasSize(1);
    assertThat(
            reports
                .getDetectionReports(0)
                .getVulnerability()
                .getAdditionalDetails(0)
                .getTextData()
                .getText())
        .contains("/dask/json/identity.json");
  }

  @Test
  public void detect_whenDualHostnameAndIpEndpointsShareCanonicalIp_probesCommOnce()
      throws Exception {
    AtomicInteger wsConns = new AtomicInteger();
    List<String> paths = new CopyOnWriteArrayList<>();
    MockDaskServer wsServer =
        startCommServer(socket -> {
          wsConns.incrementAndGet();
          serveWsDaskSession(
              socket,
              "Scheduler",
              "Scheduler-dual-ep",
              ResultMode.RUN_FUNCTION_DIRECT_INT,
              paths,
              false);
        });
    NetworkService hostEpSvc =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forIpHostnameAndPort(loopbackIp, "untrusted-ptr.invalid", wsServer.port()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("http")
            .build();
    NetworkService ipEpSvc = buildTcpService(wsServer.port(), "http");

    DetectionReportList dedupReports =
        createFixedOperandDetector()
            .detect(buildTargetInfo(), ImmutableList.of(hostEpSvc, ipEpSvc));

    assertThat(dedupReports.getDetectionReportsList()).hasSize(1);
    assertThat(wsConns.get()).isEqualTo(1);
  }

  @Test
  public void detect_whenWebSocketServerFloodsPingFrames_abortsCleanlyWithinFrameCap()
      throws Exception {
    MockDaskServer pingFloodServer =
        startCommServer(socket -> {
          Optional<String> path =
              completeWsServerUpgrade(socket.getInputStream(), socket.getOutputStream());
          if (path.isEmpty()) {
            return;
          }
          assertThat(path.get()).isEqualTo("/");
          assertThat(readWsClientFrames(socket.getInputStream())).hasSize(1);
          byte[] pingFrame = new byte[] {(byte) 0x89, 0x00};
          for (int i = 0; i < 80; i++) {
            socket.getOutputStream().write(pingFrame);
          }
          socket.getOutputStream().flush();
        });
    // WS upgrade probes port -> aborted at 64 Ping frames; then /json/identity.json fails -> empty.
    NetworkService wsService = buildTcpService(pingFloodServer.port(), "http");

    DetectionReportList reports =
        createFixedOperandDetector().detect(buildTargetInfo(), ImmutableList.of(wsService));

    assertThat(reports.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void detect_whenServerIsEchoServer_returnsEmpty() throws Exception {
    AtomicInteger framesReadByServer = new AtomicInteger();
    MockDaskServer echoServer =
        startCommServer(socket -> {
          InputStream in = new BufferedInputStream(socket.getInputStream());
          OutputStream out = socket.getOutputStream();
          while (true) {
            List<byte[]> frames;
            try {
              frames = readTcpFrames(in);
            } catch (EOFException e) {
              return;
            }
            framesReadByServer.addAndGet(frames.size());
            writeTcpFrames(out, frames);
          }
        });
    NetworkService service = buildTcpService(echoServer.port(), "dask");

    DetectionReportList reports =
        createFixedOperandDetector().detect(buildTargetInfo(), ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    // Echo server receives handshake (1) and identity (1), then is rejected before any run probe.
    assertThat(framesReadByServer.get()).isEqualTo(2);
  }

  @Test
  public void detect_whenServerClosesImmediatelyOnEofOrMtlsRejection_returnsEmpty()
      throws Exception {
    MockDaskServer eofServer = startCommServer(Socket::close);
    socketFactory.failSslHandshakeWith(
        new SSLHandshakeException("Received fatal alert: bad_certificate"));

    NetworkService plainEofService = buildTcpService(eofServer.port(), "dask");
    NetworkService mtlsService = buildTcpService(eofServer.port(), "ssl/dask");

    DetectionReportList reports =
        createFixedOperandDetector()
            .detect(buildTargetInfo(), ImmutableList.of(plainEofService, mtlsService));

    assertThat(reports.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void detect_whenServerReturnsMalformedTcpFramesOrMsgPackOrWrongSum_returnsEmpty()
      throws Exception {
    MockDaskServer badHeaderServer =
        startCommServer(socket -> {
          assertThat(readTcpFrames(socket.getInputStream())).hasSize(1);
          // Write nosplitBytes = 24, nFrames = 99 (exceeds MAX_FRAMES_COUNT = 16).
          ByteBuffer hdr = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
          hdr.putLong(24L).putLong(99L);
          socket.getOutputStream().write(hdr.array());
          socket.getOutputStream().flush();
        });
    MockDaskServer badMsgPackServer =
        startCommServer(socket -> {
          assertThat(readTcpFrames(socket.getInputStream())).hasSize(1);
          // 0xc1 is the reserved never-used MsgPack tag.
          writeTcpFrames(socket.getOutputStream(), ImmutableList.of(new byte[] {(byte) 0xc1}));
        });
    MockDaskServer wrongSumServer =
        startCommServer(socket ->
            serveTcpDaskSession(socket, "Scheduler", "Scheduler-bad", ResultMode.WRONG_SUM));
    MockDaskServer blockedHandlersServer =
        startCommServer(socket ->
            serveTcpDaskSession(socket, "Scheduler", "Scheduler-blocked", ResultMode.ALL_BLOCKED));

    DetectionReportList reports =
        createFixedOperandDetector()
            .detect(
                buildTargetInfo(),
                ImmutableList.of(
                    buildTcpService(badHeaderServer.port(), "dask"),
                    buildTcpService(badMsgPackServer.port(), "dask"),
                    buildTcpService(wrongSumServer.port(), "dask"),
                    buildTcpService(blockedHandlersServer.port(), "dask")));

    assertThat(reports.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void detect_whenDashboardReturnsNon200OrTlsScheme_returnsEmptyWithoutDialingComm()
      throws Exception {
    socketFactory.failPortWithIoError(8786);
    // Service 1: WS upgrade 404, /json/identity.json returns 403 Forbidden even with valid JSON.
    String forbiddenIdentityJson =
        "{\"type\":\"Scheduler\",\"id\":\"Scheduler-403\",\"address\":\"tcp://10.0.0.5:8786\"}";
    mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code()));
    mockWebServer.enqueue(
        new MockResponse()
            .setResponseCode(HttpStatus.FORBIDDEN.code())
            .setBody(forbiddenIdentityJson));

    // Service 2: WS upgrade 404, /json/identity.json advertises mTLS "tls://" scheme on port 8786.
    String tlsIdentityJson =
        "{\"type\":\"Scheduler\",\"id\":\"Scheduler-mtls\",\"address\":\"tls://10.0.0.5:8786\"}";
    mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code()));
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody(tlsIdentityJson));

    // Service 3: WS upgrade 404, /json/identity.json returns 302 redirect to a valid identity JSON
    // endpoint; detector must NOT follow redirects.
    String validRedirectedJson =
        "{\"type\":\"Scheduler\",\"id\":\"Scheduler-redir\",\"address\":\"tcp://10.0.0.5:8786\"}";
    mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code()));
    mockWebServer.enqueue(
        new MockResponse()
            .setResponseCode(HttpStatus.FOUND.code())
            .setHeader("Location", mockWebServer.url("/redirected-identity.json").toString()));
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody(validRedirectedJson));

    NetworkService dashService = buildTcpService(mockWebServer.getPort(), "radan-http");

    DetectionReportList r1 =
        createFixedOperandDetector().detect(buildTargetInfo(), ImmutableList.of(dashService));
    assertThat(socketFactory.dialAttempts())
        .containsExactly(new DialAttempt(loopbackIp, mockWebServer.getPort(), false));
    socketFactory.clearDialAttempts();
    DetectionReportList r2 =
        createFixedOperandDetector().detect(buildTargetInfo(), ImmutableList.of(dashService));
    socketFactory.clearDialAttempts();
    DetectionReportList r3 =
        createFixedOperandDetector().detect(buildTargetInfo(), ImmutableList.of(dashService));

    assertThat(r1.getDetectionReportsList()).isEmpty();
    assertThat(r2.getDetectionReportsList()).isEmpty();
    assertThat(r3.getDetectionReportsList()).isEmpty();
    // Only the initial WS upgrade probe to mockWebServer.getPort() occurred; port 8786 was never
    // dialed because 302 redirect was not followed.
    assertThat(socketFactory.dialAttempts())
        .containsExactly(new DialAttempt(loopbackIp, mockWebServer.getPort(), false));
  }

  @Test
  public void
      detect_whenDashboardAdvertisesWssAndPortlessEndpointsAreProbed_usesExpectedTlsAndDefaultPorts()
          throws Exception {
    List<String> upgradePaths = new CopyOnWriteArrayList<>();
    MockDaskServer wssCommServer =
        startCommServer(socket ->
            serveWsDaskSession(
                socket,
                "Scheduler",
                "Scheduler-wss-dash",
                ResultMode.RUN_FUNCTION_DIRECT_INT,
                upgradePaths,
                /* fragmentAndPing= */ false));
    socketFactory.requireTlsOnPort(wssCommServer.port());
    String wssIdentityJson =
        String.format(
            "{\"type\":\"Scheduler\",\"id\":\"Scheduler-wss-dash\","
                + "\"address\":\"wss://user@dask_scheduler:%d\"}",
            wssCommServer.port());
    mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code()));
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody(wssIdentityJson));

    NetworkService dashboardService = buildTcpService(mockWebServer.getPort(), "http");
    NetworkService inScopeWssPort = buildTcpService(wssCommServer.port(), "tcpwrapped");
    DetectionReportList wssReports =
        createFixedOperandDetector()
            .detect(buildTargetInfo(), ImmutableList.of(dashboardService, inScopeWssPort));

    assertThat(wssReports.getDetectionReportsList()).hasSize(1);
    assertThat(upgradePaths).containsExactly("/");
    assertThat(socketFactory.dialAttempts())
        .containsExactly(
            new DialAttempt(loopbackIp, mockWebServer.getPort(), false),
            new DialAttempt(loopbackIp, wssCommServer.port(), true))
        .inOrder();

    // Verify default ports (8786 for raw Comm, 80 for plain http, 443 with TLS for https) when
    // NetworkEndpoint omits an explicit port. Reject port 443 during TLS upgrade rather than
    // plaintext connect so we still verify that portless HTTPS selects port 443 with TLS enabled
    // and closes the socket.
    socketFactory.clearDialAttempts();
    socketFactory.clearOpenedPlainSockets();
    socketFactory.failPortWithIoError(8786);
    socketFactory.failPortWithIoError(80);
    socketFactory.failSslUpgradeOnPort(443);
    NetworkService portlessComm =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forIp(loopbackIp))
            .setTransportProtocol(TransportProtocol.TRANSPORT_PROTOCOL_UNSPECIFIED)
            .setServiceName("dask")
            .build();
    NetworkService portlessHttp =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forIp(loopbackIp))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("http")
            .build();
    NetworkService portlessHttps =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forIp(loopbackIp))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("https")
            .build();
    assertThat(DaskUnauthenticatedRceDetector.isSupportedService(portlessComm)).isTrue();

    DetectionReportList portlessReports =
        createFixedOperandDetector()
            .detect(buildTargetInfo(), ImmutableList.of(portlessComm, portlessHttp, portlessHttps));
    assertThat(portlessReports.getDetectionReportsList()).isEmpty();
    assertThat(socketFactory.dialAttempts())
        .containsExactly(
            new DialAttempt(loopbackIp, 8786, false),
            new DialAttempt(loopbackIp, 8786, false),
            new DialAttempt(loopbackIp, 80, false),
            new DialAttempt(loopbackIp, 443, true))
        .inOrder();
    assertThat(socketFactory.openedPlainSockets()).hasSize(1);
    assertThat(socketFactory.openedPlainSockets().get(0).isClosed()).isTrue();
  }

  @Test
  public void isSupportedService_enforcesProtocolWebServiceTcpwrappedPortsAndCommNames() {
    assertThat(
            DaskUnauthenticatedRceDetector.isSupportedService(buildTcpService(8088, "radan-http")))
        .isTrue();
    assertThat(
            DaskUnauthenticatedRceDetector.isSupportedService(buildTcpService(8786, "tcpwrapped")))
        .isTrue();
    assertThat(
            DaskUnauthenticatedRceDetector.isSupportedService(
                buildTcpService(8786, "ssl/tcpwrapped")))
        .isTrue();
    assertThat(
            DaskUnauthenticatedRceDetector.isSupportedService(buildTcpService(8787, "tcpwrapped")))
        .isTrue();
    assertThat(
            DaskUnauthenticatedRceDetector.isSupportedService(buildTcpService(9999, "tcpwrapped")))
        .isFalse();
    assertThat(
            DaskUnauthenticatedRceDetector.isSupportedService(
                buildTcpService(9999, "dask-scheduler")))
        .isTrue();
    assertThat(
            DaskUnauthenticatedRceDetector.isSupportedService(
                buildTcpService(9999, "ssl/dask-worker")))
        .isTrue();
    assertThat(DaskUnauthenticatedRceDetector.isSupportedService(buildTcpService(9999, "unknown")))
        .isTrue();
    assertThat(DaskUnauthenticatedRceDetector.isSupportedService(buildTcpService(22, "ssh")))
        .isFalse();

    NetworkService udpScheduler =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forIpAndPort(loopbackIp, 8786))
            .setTransportProtocol(TransportProtocol.UDP)
            .setServiceName("dask-scheduler")
            .build();
    NetworkService udpWeb =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forIpAndPort(loopbackIp, 8787))
            .setTransportProtocol(TransportProtocol.UDP)
            .setServiceName("http")
            .build();
    assertThat(DaskUnauthenticatedRceDetector.isSupportedService(udpScheduler)).isFalse();
    assertThat(DaskUnauthenticatedRceDetector.isSupportedService(udpWeb)).isFalse();

    DetectionReportList skippedReports =
        createFixedOperandDetector()
            .detect(
                buildTargetInfo(),
                ImmutableList.of(buildTcpService(9999, "tcpwrapped"), udpScheduler, udpWeb));
    assertThat(skippedReports.getDetectionReportsList()).isEmpty();
    assertThat(socketFactory.dialAttempts()).isEmpty();
  }

  @Test
  public void parseDashboardIdentityJson_rejectsMalformedSchemasAndSchemes() {
    assertThat(DaskUnauthenticatedRceDetector.parseDashboardIdentityJson("", "http://x")).isEmpty();
    assertThat(DaskUnauthenticatedRceDetector.parseDashboardIdentityJson("not-json", "http://x"))
        .isEmpty();
    assertThat(DaskUnauthenticatedRceDetector.parseDashboardIdentityJson("[1,2]", "http://x"))
        .isEmpty();
    assertThat(
            DaskUnauthenticatedRceDetector.parseDashboardIdentityJson(
                "{\"type\":\"Worker\",\"id\":\"Worker-1\",\"address\":\"tcp://10.0.0.1:8786\"}",
                "http://x"))
        .isEmpty();
    assertThat(
            DaskUnauthenticatedRceDetector.parseDashboardIdentityJson(
                "{\"type\":\"Scheduler\",\"id\":\"k8s-sched-0\",\"address\":\"tcp://10.0.0.1:8786\"}",
                "http://x"))
        .isPresent();
    assertThat(
            DaskUnauthenticatedRceDetector.parseDashboardIdentityJson(
                "{\"type\":\"Scheduler\",\"id\":\"   \",\"address\":\"tcp://10.0.0.1:8786\"}",
                "http://x"))
        .isEmpty();
    assertThat(
            DaskUnauthenticatedRceDetector.parseDashboardIdentityJson(
                "{\"type\":\"Scheduler\",\"id\":\"Scheduler-1\",\"address\":\"tls://10.0.0.1:8786\"}",
                "http://x"))
        .isEmpty();
    assertThat(
            DaskUnauthenticatedRceDetector.parseDashboardIdentityJson(
                "{\"type\":\"Scheduler\",\"id\":\"Scheduler-1\",\"address\":\"tcp://10.0.0.1\"}",
                "http://x"))
        .isEmpty();
    assertThat(
            DaskUnauthenticatedRceDetector.parseDashboardIdentityJson(
                "{\"type\":\"Scheduler\",\"id\":\"Scheduler-1\",\"address\":\":::invalid\"}",
                "http://x"))
        .isEmpty();
    assertThat(
            DaskUnauthenticatedRceDetector.parseDashboardIdentityJson(
                "{\"type\":\"Scheduler\",\"id\":\"Scheduler-1\",\"address\":\"8786\"}", "http://x"))
        .isEmpty();
    assertThat(
            DaskUnauthenticatedRceDetector.parseDashboardIdentityJson(
                "{\"type\":\"Scheduler\",\"id\":\"Scheduler-1\",\"address\":\"tcp://:8786\"}",
                "http://x"))
        .isEmpty();
    assertThat(
            DaskUnauthenticatedRceDetector.parseDashboardIdentityJson(
                "{\"type\":\"Scheduler\",\"id\":\"Scheduler-1\","
                    + "\"address\":\"tcp://dask_scheduler:99999\"}",
                "http://x"))
        .isEmpty();
    assertThat(
            DaskUnauthenticatedRceDetector.parseDashboardIdentityJson(
                "{\"type\":\"Scheduler\",\"id\":\"Scheduler-1\","
                    + "\"address\":\"tcp://dask_scheduler\"}",
                "http://x"))
        .isEmpty();
    assertThat(
            DaskUnauthenticatedRceDetector.parseDashboardIdentityJson("{unterminated", "http://x"))
        .isEmpty();
    assertThat(
            DaskUnauthenticatedRceDetector.parseDashboardIdentityJson(
                "{\"type\":{},\"id\":\"Scheduler-1\",\"address\":\"tcp://10.0.0.1:8786\"}",
                "http://x"))
        .isEmpty();
    assertThat(
            DaskUnauthenticatedRceDetector.parseDashboardIdentityJson(
                "{\"type\":\"Scheduler\",\"id\":\"Scheduler-1\",\"address\":\"tcp:///path\"}",
                "http://x"))
        .isEmpty();
    assertThat(
            DaskUnauthenticatedRceDetector.parseDashboardIdentityJson(
                "{\"type\":\"Scheduler\",\"id\":\"Scheduler-1\",\"address\":\"tcp://10.0.0.1:0\"}",
                "http://x"))
        .isEmpty();
    assertThat(
            DaskUnauthenticatedRceDetector.parseDashboardIdentityJson(
                "{\"type\":\"Scheduler\",\"id\":\"Scheduler-1\",\"address\":\"tcp://10.0.0.1:1\"}",
                "http://x"))
        .isPresent();
    assertThat(
            DaskUnauthenticatedRceDetector.parseDashboardIdentityJson(
                "{\"type\":\"Scheduler\",\"id\":\"Scheduler-1\","
                    + "\"address\":\"wss://user:pass@dask_scheduler:8786\"}",
                "http://x"))
        .isPresent();
    assertThat(
            DaskUnauthenticatedRceDetector.parseDashboardIdentityJson(
                "{\"type\":\"Scheduler\",\"id\":\"Scheduler-1\","
                    + "\"address\":\"wss://user:pass@[::1]:8786\"}",
                "http://x"))
        .isPresent();
    assertThat(
            DaskUnauthenticatedRceDetector.parseDashboardIdentityJson(
                "{\"type\":\"Scheduler\",\"id\":\"Scheduler-1\",\"address\":\"tcp://[::1]:8786\"}",
                "http://x"))
        .isPresent();
    assertThat(
            DaskUnauthenticatedRceDetector.parseDashboardIdentityJson(
                "{\"type\":\"Scheduler\",\"id\":\"Scheduler-1\","
                    + "\"address\":\"wss://user@:8786\"}",
                "http://x"))
        .isEmpty();
  }

  @Test
  public void
      detect_whenDashboardHttpDisconnectsOrAdvertisedCommRejectsOrWorkerBlocked_returnsEmpty()
          throws Exception {
    MockDaskServer closedCommServer = startCommServer(Socket::close);
    MockDaskServer blockedWorkerServer =
        startCommServer(socket ->
            serveTcpDaskSession(socket, "Worker", "Worker-blocked", ResultMode.ALL_BLOCKED));

    // Case 1: Dashboard HTTP request disconnects abruptly.
    mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code()));
    mockWebServer.enqueue(new MockResponse().setSocketPolicy(SocketPolicy.DISCONNECT_AT_START));

    // Case 2: Dashboard advertises a TCP Comm port that immediately closes on probe.
    String deadCommJson =
        String.format(
            "{\"type\":\"Scheduler\",\"id\":\"Scheduler-dead\",\"address\":\"tcp://10.0.0.9:%d\"}",
            closedCommServer.port());
    mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code()));
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody(deadCommJson));

    NetworkService dashService = buildTcpService(mockWebServer.getPort(), "http");
    NetworkService blockedWorker = buildTcpService(blockedWorkerServer.port(), "dask-worker");

    DetectionReportList r1 =
        createFixedOperandDetector().detect(buildTargetInfo(), ImmutableList.of(dashService));
    socketFactory.clearDialAttempts();
    DetectionReportList r2 =
        createFixedOperandDetector()
            .detect(buildTargetInfo(), ImmutableList.of(dashService, blockedWorker));

    assertThat(r1.getDetectionReportsList()).isEmpty();
    assertThat(r2.getDetectionReportsList()).isEmpty();
    // Hardened Worker is confirmed raw TCP Dask so it must be dialed only once (no WS fallback),
    // and the dead TCP port advertised by the Dashboard is not in matchedServices.
    assertThat(socketFactory.dialAttempts())
        .containsExactly(
            new DialAttempt(loopbackIp, blockedWorkerServer.port(), false),
            new DialAttempt(loopbackIp, mockWebServer.getPort(), false))
        .inOrder();
  }

  @Test
  public void detect_whenFramesViolateTcpOrWebSocketWireInvariants_returnsEmpty() throws Exception {
    MockDaskServer mismatchedPrefixServer =
        startCommServer(socket -> {
          assertThat(readTcpFrames(socket.getInputStream())).hasSize(1);
          // Declare nosplitBytes = 999 for a 1-byte frame (expected 16 + 1 = 17).
          ByteBuffer hdr = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
          hdr.putLong(999L).putLong(1L).putLong(1L);
          socket.getOutputStream().write(hdr.array());
          socket.getOutputStream().flush();
        });
    MockDaskServer oversizedTcpFrameServer =
        startCommServer(socket -> {
          assertThat(readTcpFrames(socket.getInputStream())).hasSize(1);
          long hugeLen = 1024L * 1024L;
          ByteBuffer hdr = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
          hdr.putLong(16L + hugeLen).putLong(1L).putLong(hugeLen);
          socket.getOutputStream().write(hdr.array());
          socket.getOutputStream().flush();
        });
    MockDaskServer wsCloseFrameServer =
        startCommServer(socket -> {
          Optional<String> path =
              completeWsServerUpgrade(socket.getInputStream(), socket.getOutputStream());
          if (path.isEmpty()) {
            return;
          }
          assertThat(path.get()).isEqualTo("/");
          assertThat(readWsClientFrames(socket.getInputStream())).hasSize(1);
          // Send WebSocket Close control frame (FIN=1, opcode=0x08, len=0).
          socket.getOutputStream().write(new byte[] {(byte) 0x88, 0x00});
          socket.getOutputStream().flush();
        });
    MockDaskServer wsBadCountServer =
        startCommServer(socket -> {
          Optional<String> path =
              completeWsServerUpgrade(socket.getInputStream(), socket.getOutputStream());
          if (path.isEmpty()) {
            return;
          }
          assertThat(path.get()).isEqualTo("/");
          assertThat(readWsClientFrames(socket.getInputStream())).hasSize(1);
          // Send binary WS message of 3 bytes instead of 8-byte LE frame count.
          socket.getOutputStream().write(new byte[] {(byte) 0x82, 0x03, 1, 2, 3});
          socket.getOutputStream().flush();
        });
    MockDaskServer wsUnexpectedContinuationServer =
        startCommServer(socket -> {
          Optional<String> path =
              completeWsServerUpgrade(socket.getInputStream(), socket.getOutputStream());
          if (path.isEmpty()) {
            return;
          }
          assertThat(path.get()).isEqualTo("/");
          assertThat(readWsClientFrames(socket.getInputStream())).hasSize(1);
          // Uninitiated continuation frame (FIN=1, opcode=0x00, len=8).
          socket.getOutputStream().write(new byte[] {(byte) 0x80, 0x08, 1, 0, 0, 0, 0, 0, 0, 0});
          socket.getOutputStream().flush();
        });

    DetectionReportList reports =
        createFixedOperandDetector()
            .detect(
                buildTargetInfo(),
                ImmutableList.of(
                    buildTcpService(mismatchedPrefixServer.port(), "dask"),
                    buildTcpService(oversizedTcpFrameServer.port(), "dask"),
                    buildTcpService(wsCloseFrameServer.port(), "http"),
                    buildTcpService(wsBadCountServer.port(), "http"),
                    buildTcpService(wsUnexpectedContinuationServer.port(), "http")));

    assertThat(reports.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void parsePickleInt64AndDecodeMsgPack_handleProtocolVariantsAndRejectMalformedPayloads()
      throws IOException {
    // Pickle protocol 0 ASCII decimal ('I' ... '\n.') and 'L' suffix.
    assertThat(DaskCommClient.parsePickleInt64("I35802467\n.".getBytes(US_ASCII)))
        .isEqualTo(OptionalLong.of(35_802_467L));
    assertThat(DaskCommClient.parsePickleInt64("I35802467L\n.".getBytes(US_ASCII)))
        .isEqualTo(OptionalLong.of(35_802_467L));

    // Pickle protocol 4 PROTO + FRAME (0x95) + 'J' + MEMOIZE (0x94) + '.'.
    ByteBuffer proto4 = ByteBuffer.allocate(18).order(ByteOrder.LITTLE_ENDIAN);
    proto4.put((byte) 0x80).put((byte) 0x04).put((byte) 0x95).putLong(7L);
    proto4.put((byte) 'J').putInt(35_802_467).put((byte) 0x94).put((byte) '.');
    assertThat(DaskCommClient.parsePickleInt64(proto4.array()))
        .isEqualTo(OptionalLong.of(35_802_467L));

    // Pickle LONG1 (0x8a) positive 5-byte integer and negative 2-byte integer, plus BINPUT ('q')
    // and LONG_BINPUT ('r') memoize opcodes.
    byte[] long1Pos =
        new byte[] {
          (byte) 0x80, 0x02, (byte) 0x8a, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 'q', 0x01, '.'
        };
    assertThat(DaskCommClient.parsePickleInt64(long1Pos)).isEqualTo(OptionalLong.of(0x0504030201L));
    byte[] long1Neg =
        new byte[] {
          (byte) 0x80, 0x02, (byte) 0x8a, 0x02, (byte) 0xfe, (byte) 0xff, 'r', 1, 0, 0, 0, '.'
        };
    assertThat(DaskCommClient.parsePickleInt64(long1Neg)).isEqualTo(OptionalLong.of(-2L));

    // Malformed Pickle payloads.
    assertThat(DaskCommClient.parsePickleInt64(new byte[0])).isEqualTo(OptionalLong.empty());
    assertThat(DaskCommClient.parsePickleInt64(new byte[] {(byte) 0x80}))
        .isEqualTo(OptionalLong.empty());
    assertThat(DaskCommClient.parsePickleInt64(new byte[] {(byte) 0x80, 0x04, (byte) 0x95, 0x01}))
        .isEqualTo(OptionalLong.empty());
    assertThat(DaskCommClient.parsePickleInt64(new byte[] {'J', 0x01, 0x02}))
        .isEqualTo(OptionalLong.empty());
    assertThat(DaskCommClient.parsePickleInt64("I\n.".getBytes(US_ASCII)))
        .isEqualTo(OptionalLong.empty());
    assertThat(DaskCommClient.parsePickleInt64("I123".getBytes(US_ASCII)))
        .isEqualTo(OptionalLong.empty());
    assertThat(DaskCommClient.parsePickleInt64(new byte[] {(byte) 0x8a}))
        .isEqualTo(OptionalLong.empty());
    assertThat(DaskCommClient.parsePickleInt64(new byte[] {(byte) 0x8a, 0x09}))
        .isEqualTo(OptionalLong.empty());
    assertThat(DaskCommClient.parsePickleInt64(new byte[] {'J', 1, 0, 0, 0}))
        .isEqualTo(OptionalLong.empty());
    assertThat(DaskCommClient.parsePickleInt64("Inot_a_number\n.".getBytes(US_ASCII)))
        .isEqualTo(OptionalLong.empty());
    assertThat(DaskCommClient.parsePickleInt64("I123\n.trailing".getBytes(US_ASCII)))
        .isEqualTo(OptionalLong.empty());
    assertThat(DaskCommClient.parsePickleInt64(new byte[] {'S', '.'}))
        .isEqualTo(OptionalLong.empty());

    // Decode rich MsgPack map exercising scalar/string/binary/array/map/ext wire tags emitted by
    // real Dask Distributed Scheduler identity payloads.
    ByteArrayOutputStream richMp = new ByteArrayOutputStream();
    richMp.write(0xde); // map16 with 16 entries
    richMp.write(0x00);
    richMp.write(16);
    writeMpStr(richMp, "negfix");
    richMp.write(0xff); // -1
    writeMpStr(richMp, "false");
    richMp.write(0xc2);
    writeMpStr(richMp, "str8");
    richMp.writeBytes(new byte[] {(byte) 0xd9, 0x02, 'h', 'i'});
    writeMpStr(richMp, "str16");
    richMp.writeBytes(new byte[] {(byte) 0xda, 0x00, 0x02, 'o', 'k'});
    writeMpStr(richMp, "str32");
    richMp.writeBytes(new byte[] {(byte) 0xdb, 0x00, 0x00, 0x00, 0x01, 'z'});
    writeMpStr(richMp, "bin16");
    richMp.writeBytes(new byte[] {(byte) 0xc5, 0x00, 0x01, 0x2a});
    writeMpStr(richMp, "bin32");
    richMp.writeBytes(new byte[] {(byte) 0xc6, 0x00, 0x00, 0x00, 0x01, 0x2b});
    writeMpStr(richMp, "f32");
    richMp.writeBytes(new byte[] {(byte) 0xca, 0, 0, 0, 0});
    writeMpStr(richMp, "f64");
    richMp.writeBytes(new byte[] {(byte) 0xcb, 0, 0, 0, 0, 0, 0, 0, 0});
    writeMpStr(richMp, "uints");
    richMp.writeBytes(
        new byte[] {
          (byte) 0xdc,
          0x00,
          0x04, // array16(4)
          (byte) 0xcc,
          0x07,
          (byte) 0xcd,
          0x01,
          0x02,
          (byte) 0xce,
          0,
          0,
          0,
          9,
          (byte) 0xcf,
          0,
          0,
          0,
          0,
          0,
          0,
          0,
          11
        });
    writeMpStr(richMp, "ints");
    richMp.writeBytes(
        new byte[] {
          (byte) 0xdd,
          0,
          0,
          0,
          3, // array32(3)
          (byte) 0xd0,
          (byte) 0xfe,
          (byte) 0xd1,
          (byte) 0xff,
          (byte) 0xf0,
          (byte) 0xd2,
          0,
          0,
          0,
          5
        });
    writeMpStr(richMp, "map32");
    richMp.writeBytes(new byte[] {(byte) 0xdf, 0, 0, 0, 0});
    writeMpStr(richMp, "fixext1");
    richMp.writeBytes(new byte[] {(byte) 0xd4, 0x01, 0x55});
    writeMpStr(richMp, "ext8");
    richMp.writeBytes(new byte[] {(byte) 0xc7, 0x01, 0x02, 0x33});
    writeMpStr(richMp, "ext16");
    richMp.writeBytes(new byte[] {(byte) 0xc8, 0x00, 0x01, 0x02, 0x44});
    writeMpStr(richMp, "ext32");
    richMp.writeBytes(new byte[] {(byte) 0xc9, 0, 0, 0, 1, 0x02, 0x66});

    Optional<Object> richDecoded = DaskCommClient.decodeMsgPack(richMp.toByteArray());
    assertThat(richDecoded).isPresent();
    Map<?, ?> richMap = (Map<?, ?>) richDecoded.get();
    assertThat(richMap.get("negfix")).isEqualTo(-1L);
    assertThat(richMap.get("false")).isEqualTo(false);
    assertThat(richMap.get("str8")).isEqualTo("hi");
    assertThat(richMap.get("str16")).isEqualTo("ok");
    assertThat(richMap.get("str32")).isEqualTo("z");
    assertThat(richMap.get("uints")).isEqualTo(ImmutableList.of(7L, 258L, 9L, 11L));
    assertThat(richMap.get("ints")).isEqualTo(ImmutableList.of(-2L, -16L, 5L));

    // Oversized bin32 and array32 bounds checks.
    assertThat(
            DaskCommClient.decodeMsgPack(
                new byte[] {(byte) 0xc6, 0x01, 0x00, 0x00, 0x00})) // 16 MiB > MAX_FRAME_BYTES
        .isEmpty();
    assertThat(
            DaskCommClient.decodeMsgPack(
                new byte[] {(byte) 0xdd, 0x00, 0x01, 0x00, 0x00})) // 65536 > MAX_COLLECTION_SIZE
        .isEmpty();

    // MsgPack depth limit (> 16 nested arrays) and truncated input.
    byte[] tooDeep = new byte[20];
    Arrays.fill(tooDeep, (byte) 0x91);
    assertThat(DaskCommClient.decodeMsgPack(tooDeep)).isEmpty();
    assertThat(DaskCommClient.decodeMsgPack(new byte[0])).isEmpty();
    assertThat(DaskCommClient.decodeMsgPack(new byte[] {(byte) 0xc4, 0x10, 0x01})).isEmpty();

    // WebSocket upgrade rejections on non-101, missing headers, or EOF, plus path normalization
    // and non-zero randomized Sec-WebSocket-Key verification.
    DaskCommClient client = new DaskCommClient(socketFactory, Duration.ofSeconds(1));
    ByteArrayOutputStream emptyPathReq = new ByteArrayOutputStream();
    InputStream eofOnceStream =
        new InputStream() {
          private boolean returnedEof;

          @Override
          public int read() throws IOException {
            if (returnedEof) {
              throw new IOException("Must stop reading immediately after EOF");
            }
            returnedEof = true;
            return -1;
          }
        };
    assertThat(client.performWebSocketUpgrade(eofOnceStream, emptyPathReq, "localhost:8786", ""))
        .isFalse();
    String emptyPathReqStr = emptyPathReq.toString(US_ASCII);
    assertThat(emptyPathReqStr).startsWith("GET / HTTP/1.1\r\n");
    assertThat(emptyPathReqStr).doesNotContain("Sec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAA==\r\n");

    ByteArrayOutputStream slashPathReq = new ByteArrayOutputStream();
    String non101WithAllHeaders =
        String.join(
            "\r\n",
            "HTTP/1.1 200 OK",
            "Upgrade: websocket",
            "Connection: Upgrade",
            "Sec-WebSocket-Accept: dummy",
            "",
            "");
    assertThat(
            client.performWebSocketUpgrade(
                new ByteArrayInputStream(non101WithAllHeaders.getBytes(US_ASCII)),
                slashPathReq,
                "localhost:8786",
                "/ws"))
        .isFalse();
    assertThat(slashPathReq.toString(US_ASCII)).startsWith("GET /ws HTTP/1.1\r\n");

    ByteArrayOutputStream relativePathReq = new ByteArrayOutputStream();
    String missingAcceptHeader =
        String.join(
            "\r\n",
            "HTTP/1.1 101 Switching Protocols",
            "Upgrade: websocket",
            "Connection: Upgrade",
            "",
            "");
    assertThat(
            client.performWebSocketUpgrade(
                new ByteArrayInputStream(missingAcceptHeader.getBytes(US_ASCII)),
                relativePathReq,
                "localhost:8786",
                "ws"))
        .isFalse();
    assertThat(relativePathReq.toString(US_ASCII)).startsWith("GET /ws HTTP/1.1\r\n");

    String missingUpgradeHeader =
        String.join(
            "\r\n",
            "HTTP/1.1 101 Switching Protocols",
            "Connection: Upgrade",
            "Sec-WebSocket-Accept: dummy",
            "",
            "");
    assertThat(
            client.performWebSocketUpgrade(
                new ByteArrayInputStream(missingUpgradeHeader.getBytes(US_ASCII)),
                new ByteArrayOutputStream(),
                "localhost:8786",
                "/ws"))
        .isFalse();

    String missingConnectionHeader =
        String.join(
            "\r\n",
            "HTTP/1.1 101 Switching Protocols",
            "Upgrade: websocket",
            "Sec-WebSocket-Accept: dummy",
            "",
            "");
    assertThat(
            client.performWebSocketUpgrade(
                new ByteArrayInputStream(missingConnectionHeader.getBytes(US_ASCII)),
                new ByteArrayOutputStream(),
                "localhost:8786",
                "/ws"))
        .isFalse();

    // Valid 101 response with bare CR/LF bytes before CRLF (must not terminate headers early) and
    // no spaces after header colons (must not drop the first value character).
    String compactHeadersWithBareLf =
        String.join(
            "\r\n",
            "HTTP/1.1 101 Switching Protocols",
            "X-Cr: a\rb",
            "X-Lf: a\n",
            "X-Lf2: b\n\n",
            "\n\nX-Lf3: c",
            "Upgrade:websocket",
            "Connection:Upgrade",
            "Sec-WebSocket-Accept:dummy",
            "",
            "");
    assertThat(
            client.performWebSocketUpgrade(
                new ByteArrayInputStream(compactHeadersWithBareLf.getBytes(US_ASCII)),
                new ByteArrayOutputStream(),
                "localhost:8786",
                "/ws"))
        .isTrue();
  }

  @Test
  public void probeTcp_whenHandshakeReplyIsInvalidOrNonMap_returnsNotDask() throws IOException {
    MockDaskServer nonMapHandshakeServer =
        startCommServer(socket -> {
          InputStream in = new BufferedInputStream(socket.getInputStream());
          OutputStream out = socket.getOutputStream();
          verifyClientHandshake(readTcpFrames(in));
          writeTcpFrames(out, ImmutableList.of(new byte[] {0x01}));
        });
    MockDaskServer corruptHandshakeServer =
        startCommServer(socket -> {
          InputStream in = new BufferedInputStream(socket.getInputStream());
          OutputStream out = socket.getOutputStream();
          verifyClientHandshake(readTcpFrames(in));
          writeTcpFrames(out, ImmutableList.of(new byte[] {(byte) 0xc1}));
        });

    DaskCommClient client = new DaskCommClient(socketFactory, Duration.ofSeconds(5));
    assertThat(
            client.probeTcp(
                loopbackIp, nonMapHandshakeServer.port(), false, FIXED_OPERAND_A, FIXED_OPERAND_B))
        .isEqualTo(DaskCommClient.ProbeOutcome.NonVulnerable.NOT_DASK);
    assertThat(
            client.probeTcp(
                loopbackIp, corruptHandshakeServer.port(), false, FIXED_OPERAND_A, FIXED_OPERAND_B))
        .isEqualTo(DaskCommClient.ProbeOutcome.NonVulnerable.NOT_DASK);
  }

  @Test
  public void probeTcp_whenSessionDeadlineExpiredAndSingleByteReadCalled_abortsCleanly()
      throws IOException {
    MockDaskServer silentServer =
        startCommServer(socket -> {
          socket.getInputStream().read();
          try {
            Thread.sleep(Duration.ofMillis(200));
          } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
          }
        });

    DaskCommClient expiredClient = new DaskCommClient(socketFactory, Duration.ZERO);
    assertThat(
            expiredClient.probeTcp(
                loopbackIp, silentServer.port(), false, FIXED_OPERAND_A, FIXED_OPERAND_B))
        .isEqualTo(DaskCommClient.ProbeOutcome.NonVulnerable.NOT_DASK);

    try (Socket inMemorySocket =
        new Socket() {
          private final ByteArrayInputStream in =
              new ByteArrayInputStream(new byte[] {'D', 'K', 'Z', 'Q'});
          private int soTimeout = 5000;

          @Override
          public InputStream getInputStream() {
            return in;
          }

          @Override
          public synchronized void setSoTimeout(int timeout) {
            this.soTimeout = timeout;
          }

          @Override
          public synchronized int getSoTimeout() {
            return this.soTimeout;
          }
        }) {
      AtomicLong fakeNanos = new AtomicLong(1_000_000_000L);
      DaskCommClient.DeadlineInputStream validStream =
          new DaskCommClient.DeadlineInputStream(
              inMemorySocket, Duration.ofMillis(1), fakeNanos::get);
      // Exactly 1,000,000 ns remaining -> 1 ms socket timeout applied and byte read succeeds.
      assertThat(validStream.read()).isEqualTo('D');
      assertThat(inMemorySocket.getSoTimeout()).isEqualTo(1);
      byte[] chunk = new byte[1];
      assertThat(validStream.read(chunk, 0, 1)).isEqualTo(1);
      assertThat(chunk[0]).isEqualTo((byte) 'K');

      // Advancing clock by 1 ns leaves 999,999 ns -> 0 ms remaining -> throws immediately on both
      // single-byte and bulk read(byte[], int, int).
      fakeNanos.set(1_000_000_001L);
      assertThrows(SocketTimeoutException.class, validStream::read);
      assertThrows(SocketTimeoutException.class, () -> validStream.read(chunk, 0, 1));

      // Large duration above Integer.MAX_VALUE ms clamps cleanly to Integer.MAX_VALUE.
      DaskCommClient.DeadlineInputStream clampedStream =
          new DaskCommClient.DeadlineInputStream(
              inMemorySocket, Duration.ofDays(30), fakeNanos::get);
      assertThat(clampedStream.read()).isEqualTo('Z');
      assertThat(inMemorySocket.getSoTimeout()).isEqualTo(Integer.MAX_VALUE);
    }

    MockDaskServer singleByteServer =
        startCommServer(socket -> {
          socket.getOutputStream().write('D');
          socket.getOutputStream().flush();
        });
    try (Socket activeSocket = socketFactory.createSocket(loopbackIp, singleByteServer.port())) {
      DaskCommClient.DeadlineInputStream validStream =
          new DaskCommClient.DeadlineInputStream(activeSocket, Duration.ofSeconds(2));
      assertThat(validStream.read()).isEqualTo('D');

      DaskCommClient.DeadlineInputStream expiredStream =
          new DaskCommClient.DeadlineInputStream(activeSocket, Duration.ZERO);
      assertThrows(SocketTimeoutException.class, expiredStream::read);
    }

    MockDaskServer stalledServer =
        startCommServer(socket -> {
          try {
            Thread.sleep(Duration.ofSeconds(2));
          } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
          }
        });
    try (Socket stalledSocket = socketFactory.createSocket(loopbackIp, stalledServer.port())) {
      stalledSocket.setSoTimeout(5000);
      DaskCommClient.DeadlineInputStream shortTimeoutStream =
          new DaskCommClient.DeadlineInputStream(stalledSocket, Duration.ofMillis(150));
      assertThrows(SocketTimeoutException.class, shortTimeoutStream::read);
      assertThat(stalledSocket.getSoTimeout()).isAtMost(150);
    }
  }

  @Test
  public void webSocketFrameTransport_whenWritingPayloadOver126Bytes_encodes16BitExtendedLength()
      throws IOException {
    byte[] largePayload = new byte[300];
    for (int i = 0; i < largePayload.length; i++) {
      largePayload[i] = (byte) (i * 7 + 3);
    }
    ByteArrayOutputStream encoded = new ByteArrayOutputStream();
    DaskCommClient.WebSocketFrameTransport transport =
        new DaskCommClient.WebSocketFrameTransport(
            new ByteArrayInputStream(new byte[0]), encoded, new SecureRandom());
    transport.writeFrames(ImmutableList.of(largePayload));

    List<byte[]> decoded = readWsClientFrames(new ByteArrayInputStream(encoded.toByteArray()));
    assertThat(decoded).hasSize(1);
    assertThat(decoded.get(0)).isEqualTo(largePayload);
  }

  @Test
  public void
      detect_whenWebSocketSchedulerUsesExtended16BitAnd64BitMaskedFramesAndBroadcastFallback_reportsRce()
          throws IOException {
    String longDaemonId = "Scheduler-" + "a".repeat(140);
    MockDaskServer wsServer =
        startCommServer(socket -> {
          InputStream in = new BufferedInputStream(socket.getInputStream());
          OutputStream out = socket.getOutputStream();

          Optional<String> path = completeWsServerUpgrade(in, out);
          if (path.isEmpty()) {
            return;
          }
          assertThat(path.get()).isEqualTo("/");

          List<byte[]> hs = readWsClientFrames(in);
          verifyClientHandshake(hs);
          writeWsServerFrames(out, ImmutableList.of(encodeHandshakeReply()), false);

          List<byte[]> idReq = readWsClientFrames(in);
          verifyIdentityRequest(idReq);
          // Identity payload > 126 bytes exercises 16-bit extended WS length (payLen == 126).
          writeWsServerFrames(
              out, ImmutableList.of(encodeIdentityReply("Scheduler", longDaemonId)), false);

          List<byte[]> runFnReq = readWsClientFrames(in);
          assertThat(extractAndVerifyRunOperands(runFnReq.get(0), "run_function"))
              .isEqualTo(FIXED_SUM);
          writeWsServerFrames(out, ImmutableList.of(encodeErrorReply()), false);

          List<byte[]> bcastReq = readWsClientFrames(in);
          long bcastSum = extractAndVerifyBroadcastOperands(bcastReq.get(0), false);

          // Reply using a masked 64-bit extended-length (payLen == 127) WS binary frame.
          byte[] countBytes =
              ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(1L).array();
          writeMasked64BitWsBinary(out, countBytes);
          writeMasked64BitWsBinary(out, encodeBroadcastSuccessReply(bcastSum));
          out.flush();
        });

    NetworkService service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forIpAndPort(loopbackIp, wsServer.port()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("http")
            .build();

    DetectionReportList reports =
        createFixedOperandDetector().detect(buildTargetInfo(), ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList()).hasSize(1);
    DetectionReport report = reports.getDetectionReports(0);
    assertThat(report.getDetectionStatus()).isEqualTo(DetectionStatus.VULNERABILITY_VERIFIED);
    String detailText = report.getVulnerability().getAdditionalDetails(0).getTextData().getText();
    assertThat(detailText).contains("via broadcast(run) RPC handler");
    assertThat(detailText).contains(longDaemonId);
  }

  @Test
  public void detect_whenHttpDashboardUsesDefaultPort80_stripsPort80FromIdentityUrlAndVerifies()
      throws IOException {
    MockDaskServer commServer =
        startCommServer(socket ->
            serveTcpDaskSession(
                socket, "Scheduler", "Scheduler-http80", ResultMode.RUN_FUNCTION_DIRECT_INT));
    socketFactory.failPortWithIoError(80);

    String hostAuthority = NetworkEndpointUtils.toUriAuthority(forIp(loopbackIp));
    String expectedIdentityUrl = "http://" + hostAuthority + "/json/identity.json";
    String identityJson =
        "{\"type\":\"Scheduler\",\"id\":\"Scheduler-http80\",\"address\":\"tcp://10.0.0.5:"
            + commServer.port()
            + "\"}";
    RecordingStubHttpClient stubHttp = new RecordingStubHttpClient();
    stubHttp.registerJsonResponse(expectedIdentityUrl, identityJson);

    DaskUnauthenticatedRceDetector detector =
        new DaskUnauthenticatedRceDetector(
            fakeUtcClock,
            stubHttp,
            new DaskCommClient(socketFactory, Duration.ofSeconds(3)),
            () -> FIXED_OPERAND_A);

    NetworkService http80Service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forIpAndPort(loopbackIp, 80))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("http")
            .build();

    NetworkService inScopeCommPort = buildTcpService(commServer.port(), "tcpwrapped");
    DetectionReportList reports =
        detector.detect(buildTargetInfo(), ImmutableList.of(http80Service, inScopeCommPort));

    assertThat(stubHttp.requestedUrls()).containsExactly(expectedIdentityUrl);
    assertThat(reports.getDetectionReportsList()).hasSize(1);
    String detailText =
        reports
            .getDetectionReports(0)
            .getVulnerability()
            .getAdditionalDetails(0)
            .getTextData()
            .getText();
    assertThat(detailText).contains(expectedIdentityUrl);
  }

  @Test
  public void
      detect_whenHttpsDashboardUsesDefaultPort443AndMalformedAppRoot_stripsPort443AndVerifies()
          throws IOException {
    MockDaskServer commServer =
        startCommServer(socket ->
            serveTcpDaskSession(
                socket, "Scheduler", "Scheduler-https443", ResultMode.RUN_FUNCTION_DIRECT_INT));
    socketFactory.failPortWithIoError(443);

    String hostAuthority = NetworkEndpointUtils.toUriAuthority(forIp(loopbackIp));
    String expectedRootIdentityUrl = "https://" + hostAuthority + "/json/identity.json";
    String identityJson =
        "{\"type\":\"Scheduler\",\"id\":\"Scheduler-https443\",\"address\":\"tcp://10.0.0.6:"
            + commServer.port()
            + "\"}";
    RecordingStubHttpClient stubHttp = new RecordingStubHttpClient();
    stubHttp.registerJsonResponse(expectedRootIdentityUrl, identityJson);

    DaskUnauthenticatedRceDetector detector =
        new DaskUnauthenticatedRceDetector(
            fakeUtcClock,
            stubHttp,
            new DaskCommClient(socketFactory, Duration.ofSeconds(3)),
            () -> FIXED_OPERAND_B);

    NetworkService https443Service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forIpAndPort(loopbackIp, 443))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("https")
            .addSupportedSslVersions("TLSv1.3")
            .setServiceContext(
                ServiceContext.newBuilder()
                    .setWebServiceContext(
                        WebServiceContext.newBuilder().setApplicationRoot("https://[invalid")))
            .build();

    NetworkService inScopeCommPort = buildTcpService(commServer.port(), "tcpwrapped");
    DetectionReportList reports =
        detector.detect(buildTargetInfo(), ImmutableList.of(https443Service, inScopeCommPort));

    assertThat(stubHttp.requestedUrls()).hasSize(2);
    assertThat(stubHttp.requestedUrls().get(1)).isEqualTo(expectedRootIdentityUrl);
    assertThat(reports.getDetectionReportsList()).hasSize(1);
    String detailText =
        reports
            .getDetectionReports(0)
            .getVulnerability()
            .getAdditionalDetails(0)
            .getTextData()
            .getText();
    assertThat(detailText).contains(expectedRootIdentityUrl);
  }

  @Test
  public void detect_whenDashboardAdvertisesOutOfScopePortOrUntrustedWsPath_doesNotDialThem()
      throws Exception {
    MockDaskServer outOfScopeTcpServer =
        startCommServer(socket ->
            serveTcpDaskSession(
                socket, "Scheduler", "Scheduler-out-of-scope", ResultMode.RUN_FUNCTION_DIRECT_INT));
    MockDaskServer inScopeWsServer =
        startCommServer(socket ->
            serveWsDaskSession(
                socket,
                "Scheduler",
                "Scheduler-bad-path",
                ResultMode.RUN_FUNCTION_DIRECT_INT,
                new CopyOnWriteArrayList<>(),
                /* fragmentAndPing= */ false));

    // Case 1: Advertised port not in matchedServices (even if present as UDP) and != 8786 must
    // not be dialed.
    String outOfScopeJson =
        String.format(
            "{\"type\":\"Scheduler\",\"id\":\"Scheduler-out-of-scope\","
                + "\"address\":\"tcp://127.0.0.1:%d\"}",
            outOfScopeTcpServer.port());
    mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code()));
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody(outOfScopeJson));

    NetworkService dashboardService = buildTcpService(mockWebServer.getPort(), "http");
    NetworkService udpSamePort =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forIpAndPort(loopbackIp, outOfScopeTcpServer.port()))
            .setTransportProtocol(TransportProtocol.UDP)
            .setServiceName("unknown")
            .build();
    socketFactory.clearDialAttempts();
    DetectionReportList outOfScopeReports =
        createFixedOperandDetector()
            .detect(buildTargetInfo(), ImmutableList.of(dashboardService, udpSamePort));
    assertThat(outOfScopeReports.getDetectionReportsList()).isEmpty();
    assertThat(socketFactory.dialAttempts())
        .containsExactly(new DialAttempt(loopbackIp, mockWebServer.getPort(), false));

    // Case 2: Advertised WS path outside "/" and appPath must not be dialed even if port is in
    // matchedServices.
    String untrustedPathJson =
        String.format(
            "{\"type\":\"Scheduler\",\"id\":\"Scheduler-bad-path\","
                + "\"address\":\"ws://127.0.0.1:%d/admin/excluded\"}",
            inScopeWsServer.port());
    mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code()));
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody(untrustedPathJson));

    NetworkService inScopeWsPort = buildTcpService(inScopeWsServer.port(), "tcpwrapped");
    socketFactory.clearDialAttempts();
    DetectionReportList badPathReports =
        createFixedOperandDetector()
            .detect(buildTargetInfo(), ImmutableList.of(dashboardService, inScopeWsPort));
    assertThat(badPathReports.getDetectionReportsList()).isEmpty();
    assertThat(socketFactory.dialAttempts())
        .containsExactly(new DialAttempt(loopbackIp, mockWebServer.getPort(), false));
  }

  @Test
  public void detect_whenDashboardAdvertisesDefaultPort8786OutsideMatchedServices_probesPort8786()
      throws Exception {
    socketFactory.failPortWithIoError(8786);
    String defaultPortJson =
        "{\"type\":\"Scheduler\",\"id\":\"Scheduler-8786\",\"address\":\"tcp://10.0.0.1:8786\"}";
    mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code()));
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody(defaultPortJson));

    NetworkService dashboardService = buildTcpService(mockWebServer.getPort(), "http");
    socketFactory.clearDialAttempts();
    DetectionReportList reports =
        createFixedOperandDetector().detect(buildTargetInfo(), ImmutableList.of(dashboardService));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(socketFactory.dialAttempts())
        .containsExactly(
            new DialAttempt(loopbackIp, mockWebServer.getPort(), false),
            new DialAttempt(loopbackIp, 8786, false))
        .inOrder();
  }

  @Test
  public void detect_whenSubpathDashboardAdvertisesRootOrAppRootWsPath_probesWebSocket()
      throws Exception {
    List<String> upgradePaths = new CopyOnWriteArrayList<>();
    MockDaskServer wsServer =
        startCommServer(socket ->
            serveWsDaskSession(
                socket,
                "Scheduler",
                "Scheduler-subpath-ws",
                ResultMode.RUN_FUNCTION_DIRECT_INT,
                upgradePaths,
                /* fragmentAndPing= */ false));
    NetworkService subpathDashboard =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forIpAndPort(loopbackIp, mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("http")
            .setServiceContext(
                ServiceContext.newBuilder()
                    .setWebServiceContext(
                        WebServiceContext.newBuilder().setApplicationRoot("/dask")))
            .build();
    NetworkService inScopeWsPort = buildTcpService(wsServer.port(), "tcpwrapped");

    // Advertised root path "/" under non-root appPath "/dask".
    String rootWsJson =
        String.format(
            "{\"type\":\"Scheduler\",\"id\":\"Scheduler-subpath-ws\","
                + "\"address\":\"ws://127.0.0.1:%d/\"}",
            wsServer.port());
    mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code()));
    mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code()));
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody(rootWsJson));
    DetectionReportList rootWsReports =
        createFixedOperandDetector()
            .detect(buildTargetInfo(), ImmutableList.of(subpathDashboard, inScopeWsPort));
    assertThat(rootWsReports.getDetectionReportsList()).hasSize(1);

    // Advertised trailing-slash appPath "/dask/" normalized to "/dask".
    String appPathWsJson =
        String.format(
            "{\"type\":\"Scheduler\",\"id\":\"Scheduler-subpath-ws\","
                + "\"address\":\"ws://127.0.0.1:%d/dask/\"}",
            wsServer.port());
    mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code()));
    mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code()));
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody(appPathWsJson));
    DetectionReportList appPathWsReports =
        createFixedOperandDetector()
            .detect(buildTargetInfo(), ImmutableList.of(subpathDashboard, inScopeWsPort));
    assertThat(appPathWsReports.getDetectionReportsList()).hasSize(1);
    assertThat(upgradePaths).containsExactly("/", "/dask").inOrder();
  }

  @Test
  public void detect_whenHardenedRawTcpDaskRejectsIdentityOrExec_skipsHttpFallback()
      throws Exception {
    AtomicInteger connectionsOnErrorReply = new AtomicInteger();
    MockDaskServer hardenedErrorServer =
        startCommServer(socket -> {
          connectionsOnErrorReply.incrementAndGet();
          serveTcpDaskSession(
              socket, "Scheduler", "Scheduler-hardened-err", ResultMode.ALL_BLOCKED);
        });
    AtomicInteger connectionsOnExecDrop = new AtomicInteger();
    MockDaskServer hardenedExecDropServer =
        startCommServer(socket -> {
          connectionsOnExecDrop.incrementAndGet();
          InputStream in = new BufferedInputStream(socket.getInputStream());
          OutputStream out = socket.getOutputStream();
          verifyClientHandshake(readTcpFrames(in));
          writeTcpFrames(out, ImmutableList.of(encodeHandshakeReply()));
          verifyIdentityRequest(readTcpFrames(in));
          writeTcpFrames(out, ImmutableList.of(encodeIdentityReply("Scheduler", "Scheduler-drop")));
          assertThat(readTcpFrames(in))
              .hasSize(1); // read run_function then immediately drop connection
        });
    AtomicInteger connectionsOnIdentityDrop = new AtomicInteger();
    MockDaskServer hardenedIdentityDropServer =
        startCommServer(socket -> {
          connectionsOnIdentityDrop.incrementAndGet();
          InputStream in = new BufferedInputStream(socket.getInputStream());
          OutputStream out = socket.getOutputStream();
          verifyClientHandshake(readTcpFrames(in));
          writeTcpFrames(out, ImmutableList.of(encodeHandshakeReply()));
          verifyIdentityRequest(readTcpFrames(in));
          // Drop connection on Step 2 (identity) after confirming binary Dask TCP framing.
        });
    AtomicInteger connectionsOnIdentityError = new AtomicInteger();
    MockDaskServer hardenedIdentityErrorServer =
        startCommServer(socket -> {
          connectionsOnIdentityError.incrementAndGet();
          InputStream in = new BufferedInputStream(socket.getInputStream());
          OutputStream out = socket.getOutputStream();
          verifyClientHandshake(readTcpFrames(in));
          writeTcpFrames(out, ImmutableList.of(encodeHandshakeReply()));
          verifyIdentityRequest(readTcpFrames(in));
          // Return error map on Step 2 (parseIdentityReply returns empty).
          writeTcpFrames(out, ImmutableList.of(encodeErrorReply()));
        });

    // Dashboard advertising the already-confirmed hardened raw TCP Dask port must NOT re-probe it,
    // nor may a duplicate web-classified entry on the same port send HTTP/WS fallback bytes.
    String advHardenedJson =
        String.format(
            "{\"type\":\"Scheduler\",\"id\":\"Scheduler-hardened-err\","
                + "\"address\":\"tcp://127.0.0.1:%d\"}",
            hardenedErrorServer.port());
    mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code()));
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody(advHardenedJson));

    socketFactory.clearDialAttempts();
    DetectionReportList reports =
        createFixedOperandDetector()
            .detect(
                buildTargetInfo(),
                ImmutableList.of(
                    buildTcpService(hardenedErrorServer.port(), "msgclnt"),
                    buildTcpService(hardenedErrorServer.port(), "http"),
                    buildTcpService(hardenedExecDropServer.port(), "msgsrvr"),
                    buildTcpService(hardenedIdentityDropServer.port(), "msgclnt"),
                    buildTcpService(hardenedIdentityErrorServer.port(), "msgsrvr"),
                    buildTcpService(mockWebServer.getPort(), "http")));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    // Each confirmed raw TCP Dask port must be dialed exactly once (no HTTP/WS fallback or
    // redundant re-probing from duplicate web entries or Dashboard advertisements).
    assertThat(connectionsOnErrorReply.get()).isEqualTo(1);
    assertThat(connectionsOnExecDrop.get()).isEqualTo(1);
    assertThat(connectionsOnIdentityDrop.get()).isEqualTo(1);
    assertThat(connectionsOnIdentityError.get()).isEqualTo(1);
    assertThat(socketFactory.dialAttempts())
        .containsExactly(
            new DialAttempt(loopbackIp, hardenedErrorServer.port(), false),
            new DialAttempt(loopbackIp, hardenedExecDropServer.port(), false),
            new DialAttempt(loopbackIp, hardenedIdentityDropServer.port(), false),
            new DialAttempt(loopbackIp, hardenedIdentityErrorServer.port(), false),
            new DialAttempt(loopbackIp, mockWebServer.getPort(), false));
  }

  @Test
  public void detect_whenTwoDashboardsAdvertiseSameHardenedTcpPort_probesAdvertisedPortOnce()
      throws Exception {
    AtomicInteger advOnlyHardenedConns = new AtomicInteger();
    MockDaskServer advOnlyHardenedServer =
        startCommServer(socket -> {
          advOnlyHardenedConns.incrementAndGet();
          serveTcpDaskSession(
              socket, "Scheduler", "Scheduler-adv-hardened", ResultMode.ALL_BLOCKED);
        });
    try (MockWebServer secondDashboard = new MockWebServer()) {
      secondDashboard.start(loopbackAddress, 0);
      String advOnlyJson =
          String.format(
              "{\"type\":\"Scheduler\",\"id\":\"Scheduler-adv-hardened\","
                  + "\"address\":\"tcp://127.0.0.1:%d\"}",
              advOnlyHardenedServer.port());
      mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code()));
      mockWebServer.enqueue(
          new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody(advOnlyJson));
      secondDashboard.enqueue(new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code()));
      secondDashboard.enqueue(
          new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody(advOnlyJson));

      socketFactory.clearDialAttempts();
      DetectionReportList reports =
          createFixedOperandDetector()
              .detect(
                  buildTargetInfo(),
                  ImmutableList.of(
                      buildTcpService(mockWebServer.getPort(), "http"),
                      buildTcpService(secondDashboard.getPort(), "http"),
                      buildTcpService(advOnlyHardenedServer.port(), "tcpwrapped")));

      assertThat(reports.getDetectionReportsList()).isEmpty();
      assertThat(advOnlyHardenedConns.get()).isEqualTo(1);
      assertThat(socketFactory.dialAttempts())
          .containsExactly(
              new DialAttempt(loopbackIp, mockWebServer.getPort(), false),
              new DialAttempt(loopbackIp, advOnlyHardenedServer.port(), false),
              new DialAttempt(loopbackIp, secondDashboard.getPort(), false))
          .inOrder();
    }
  }

  @Test
  public void detect_whenSchedulerIdentityHasManyWorkers_targetsSingleWorkerAndNannyInBroadcast()
      throws Exception {
    String longWorkerNoNanny = "tls://dask-worker-0.dask-workers.default.svc.cluster.local:41234";
    String longWorkerWithNanny = "tls://dask-worker-1.dask-workers.default.svc.cluster.local:41234";
    String oversizedWorkerKey = "w".repeat(4097);
    String exactMaxLenWorkerKey =
        "tls://" + "a".repeat(4090); // 4096 bytes == MAX_WORKER_ADDR_BYTES
    List<Object> observedWorkerTargets = new CopyOnWriteArrayList<>();
    List<Object> observedNannyTargets = new CopyOnWriteArrayList<>();

    MockDaskServer multiWorkerScheduler =
        startCommServer(socket -> {
          InputStream in = new BufferedInputStream(socket.getInputStream());
          OutputStream out = socket.getOutputStream();
          verifyClientHandshake(readTcpFrames(in));
          writeTcpFrames(out, ImmutableList.of(encodeHandshakeReply()));
          verifyIdentityRequest(readTcpFrames(in));

          // Encode identity reply with empty key (skipped), >4096-byte key (skipped), worker 0
          // with empty nanny string (picked as workerTarget, skipped for nanny), worker 1 with a
          // real nanny (picked as nannyWorkerTarget), plus 6 additional workers.
          ByteArrayOutputStream idOut = new ByteArrayOutputStream();
          idOut.write(0x83); // fixmap(3): type, id, workers
          writeMpStr(idOut, "type");
          writeMpStr(idOut, "Scheduler");
          writeMpStr(idOut, "id");
          writeMpStr(idOut, "Scheduler-10w");
          writeMpStr(idOut, "workers");
          idOut.write(0x8a); // fixmap(10)
          writeMpStr(idOut, "");
          idOut.write(0x80);
          writeMpStr(idOut, oversizedWorkerKey);
          idOut.write(0x80);
          writeMpStr(idOut, longWorkerNoNanny);
          idOut.write(0x82);
          writeMpStr(idOut, "id");
          writeMpStr(idOut, "worker-0");
          writeMpStr(idOut, "nanny");
          writeMpStr(idOut, "");
          writeMpStr(idOut, longWorkerWithNanny);
          idOut.write(0x82);
          writeMpStr(idOut, "id");
          writeMpStr(idOut, "worker-1");
          writeMpStr(idOut, "nanny");
          writeMpStr(idOut, "tls://dask-worker-1:41235");
          for (int i = 4; i < 10; i++) {
            writeMpStr(idOut, "tcp://10.0.0." + (10 + i) + ":41234");
            idOut.write(0x80);
          }
          writeTcpFrames(out, ImmutableList.of(idOut.toByteArray()));

          // Reject run_function -> triggers worker broadcast(run).
          assertThat(extractAndVerifyRunOperands(readTcpFrames(in).get(0), "run_function"))
              .isEqualTo(FIXED_SUM);
          writeTcpFrames(out, ImmutableList.of(encodeErrorReply()));

          List<byte[]> bcastReq = readTcpFrames(in);
          Map<?, ?> bcastMap = (Map<?, ?>) DaskCommClient.decodeMsgPack(bcastReq.get(0)).get();
          observedWorkerTargets.add(bcastMap.get("workers"));
          assertThat(extractAndVerifyBroadcastOperands(bcastReq.get(0), false))
              .isEqualTo(FIXED_SUM);
          writeTcpFrames(out, ImmutableList.of(encodeBroadcastErrorReply()));

          // Reject worker broadcast -> triggers nanny broadcast(nanny_run).
          List<byte[]> nannyReq = readTcpFrames(in);
          Map<?, ?> nannyMap = (Map<?, ?>) DaskCommClient.decodeMsgPack(nannyReq.get(0)).get();
          observedNannyTargets.add(nannyMap.get("workers"));
          long nannySum = extractAndVerifyBroadcastOperands(nannyReq.get(0), true);
          writeTcpFrames(out, ImmutableList.of(encodeBroadcastSuccessReply(nannySum)));
        });

    // Second Scheduler whose only worker has exact 4096-byte address and no "nanny" metadata:
    // nanny broadcast must fall back to targeting that same workerTarget.
    List<Object> fallbackWorkerTargets = new CopyOnWriteArrayList<>();
    List<Object> fallbackNannyTargets = new CopyOnWriteArrayList<>();
    MockDaskServer noNannyMetadataScheduler =
        startCommServer(socket -> {
          InputStream in = new BufferedInputStream(socket.getInputStream());
          OutputStream out = socket.getOutputStream();
          verifyClientHandshake(readTcpFrames(in));
          writeTcpFrames(out, ImmutableList.of(encodeHandshakeReply()));
          verifyIdentityRequest(readTcpFrames(in));

          ByteArrayOutputStream idOut = new ByteArrayOutputStream();
          idOut.write(0x83);
          writeMpStr(idOut, "type");
          writeMpStr(idOut, "Scheduler");
          writeMpStr(idOut, "id");
          writeMpStr(idOut, "Scheduler-no-nanny-meta");
          writeMpStr(idOut, "workers");
          idOut.write(0x81);
          writeMpStr(idOut, exactMaxLenWorkerKey);
          idOut.write(0x80);
          writeTcpFrames(out, ImmutableList.of(idOut.toByteArray()));

          assertThat(extractAndVerifyRunOperands(readTcpFrames(in).get(0), "run_function"))
              .isEqualTo(FIXED_SUM);
          writeTcpFrames(out, ImmutableList.of(encodeErrorReply()));

          List<byte[]> bcastReq = readTcpFrames(in);
          Map<?, ?> bcastMap = (Map<?, ?>) DaskCommClient.decodeMsgPack(bcastReq.get(0)).get();
          fallbackWorkerTargets.add(bcastMap.get("workers"));
          assertThat(extractAndVerifyBroadcastOperands(bcastReq.get(0), false))
              .isEqualTo(FIXED_SUM);
          writeTcpFrames(out, ImmutableList.of(encodeBroadcastErrorReply()));

          List<byte[]> nannyReq = readTcpFrames(in);
          Map<?, ?> nannyMap = (Map<?, ?>) DaskCommClient.decodeMsgPack(nannyReq.get(0)).get();
          fallbackNannyTargets.add(nannyMap.get("workers"));
          long nannySum = extractAndVerifyBroadcastOperands(nannyReq.get(0), true);
          writeTcpFrames(out, ImmutableList.of(encodeBroadcastSuccessReply(nannySum)));
        });

    DetectionReportList reports =
        createFixedOperandDetector()
            .detect(
                buildTargetInfo(),
                ImmutableList.of(
                    buildTcpService(multiWorkerScheduler.port(), "dask-scheduler"),
                    buildTcpService(noNannyMetadataScheduler.port(), "dask-scheduler")));

    assertThat(reports.getDetectionReportsList()).hasSize(2);
    assertThat(observedWorkerTargets).containsExactly(ImmutableList.of(longWorkerNoNanny));
    assertThat(observedNannyTargets).containsExactly(ImmutableList.of(longWorkerWithNanny));
    assertThat(fallbackWorkerTargets).containsExactly(ImmutableList.of(exactMaxLenWorkerKey));
    assertThat(fallbackNannyTargets).containsExactly(ImmutableList.of(exactMaxLenWorkerKey));
  }

  @Test
  public void writeMpStr_encodesFixstrStr8Str16AndRejectsOversizedStrings() {
    String fixstr = "dask";
    ByteArrayOutputStream fixOut = new ByteArrayOutputStream();
    writeMpStr(fixOut, fixstr);
    assertThat(DaskCommClient.decodeMsgPack(fixOut.toByteArray())).hasValue(fixstr);

    String str8 = "s".repeat(100);
    ByteArrayOutputStream str8Out = new ByteArrayOutputStream();
    writeMpStr(str8Out, str8);
    assertThat(DaskCommClient.decodeMsgPack(str8Out.toByteArray())).hasValue(str8);

    String str16 = "w".repeat(300);
    ByteArrayOutputStream str16Out = new ByteArrayOutputStream();
    writeMpStr(str16Out, str16);
    assertThat(DaskCommClient.decodeMsgPack(str16Out.toByteArray())).hasValue(str16);

    ByteArrayOutputStream oversizedOut = new ByteArrayOutputStream();
    String oversizedStr = "x".repeat(65536);
    assertThrows(IllegalArgumentException.class, () -> writeMpStr(oversizedOut, oversizedStr));
  }

  @Test
  public void detect_whenReplyExceedsTotalReplyByteLimit_abortsCleanly() throws Exception {
    byte[] chunk512k = new byte[512 * 1024];
    byte[] okResultFrame =
        encodeRunResultFrames(FIXED_SUM, ResultMode.RUN_FUNCTION_DIRECT_INT).get(0);

    // TCP Case 1: sumLengths = 2 MiB + okResultFrame.length (> 2 MiB), while nosplitBytes =
    // 48 + sumLengths <= 2 MiB + 136 header cap; exercises the per-frame sumLengths cap directly.
    // Without the cap, verifyDirectRunReply would accept frame 0 and report VULNERABLE.
    MockDaskServer hugeTcpSumReplyServer =
        startTcpRunFunctionReplyServer(
            "Scheduler-big-tcp-sum",
            ImmutableList.of(okResultFrame, chunk512k, chunk512k, chunk512k, chunk512k));

    // TCP Case 2: nosplitBytes > 2 MiB + 136 header cap (6 frames totaling 2 MiB + 1 KiB + frame0).
    MockDaskServer hugeTcpHeaderReplyServer =
        startTcpRunFunctionReplyServer(
            "Scheduler-big-tcp-hdr",
            ImmutableList.of(
                okResultFrame, chunk512k, chunk512k, chunk512k, chunk512k, new byte[1024]));

    // WebSocket Case: 5 frames totaling > 2 MiB with valid FIXED_SUM in frame 0.
    // Without MAX_TOTAL_REPLY_BYTES, verifyDirectRunReply would match frame 0 and report
    // VULNERABLE.
    MockDaskServer hugeWsReplyServer =
        startWsRunFunctionReplyServer(
            "Scheduler-big-ws",
            ImmutableList.of(okResultFrame, chunk512k, chunk512k, chunk512k, chunk512k));

    socketFactory.clearDialAttempts();
    DetectionReportList reports =
        createFixedOperandDetector()
            .detect(
                buildTargetInfo(),
                ImmutableList.of(
                    buildTcpService(hugeTcpSumReplyServer.port(), "dask"),
                    buildTcpService(hugeTcpHeaderReplyServer.port(), "dask"),
                    buildTcpService(hugeWsReplyServer.port(), "http")));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    // Both oversized TCP replies occurred after Step 1 confirmation, so no WS fallback dials
    // happen.
    assertThat(socketFactory.dialAttempts())
        .containsExactly(
            new DialAttempt(loopbackIp, hugeTcpSumReplyServer.port(), false),
            new DialAttempt(loopbackIp, hugeTcpHeaderReplyServer.port(), false),
            new DialAttempt(loopbackIp, hugeWsReplyServer.port(), false));
  }

  @Test
  public void detect_whenReplyMatchesExactTotalReplyByteLimit_verifiesRce() throws Exception {
    byte[] okResultFrame =
        encodeRunResultFrames(FIXED_SUM, ResultMode.RUN_FUNCTION_DIRECT_INT).get(0);
    int maxTotalBytes = 2 * 1024 * 1024;

    // Exact TCP boundary: 16 frames (MAX_FRAMES_COUNT) totaling exact 2 MiB so nosplitBytes ==
    // 2 MiB + 8 * (1 + 16) = 2 MiB + 136. Kills > vs >= mutants on frame count, header cap, and
    // cumulative payload cap.
    ImmutableList.Builder<byte[]> exactTcpFramesBuilder = ImmutableList.builder();
    exactTcpFramesBuilder.add(okResultFrame);
    int tcpRemaining = maxTotalBytes - okResultFrame.length;
    byte[] chunk140k = new byte[140_000];
    for (int i = 0; i < 14; i++) {
      exactTcpFramesBuilder.add(chunk140k);
      tcpRemaining -= chunk140k.length;
    }
    exactTcpFramesBuilder.add(new byte[tcpRemaining]);
    MockDaskServer exactTcpServer =
        startTcpRunFunctionReplyServer("Scheduler-exact-tcp", exactTcpFramesBuilder.build());

    // Exact WebSocket boundary: 5 frames totaling exact 2 MiB (remainingReplyBytes hits 0).
    byte[] chunk512k = new byte[512 * 1024];
    byte[] finalWsChunk = new byte[512 * 1024 - okResultFrame.length];
    MockDaskServer exactWsServer =
        startWsRunFunctionReplyServer(
            "Scheduler-exact-ws",
            ImmutableList.of(okResultFrame, chunk512k, chunk512k, chunk512k, finalWsChunk));

    DetectionReportList reports =
        createFixedOperandDetector()
            .detect(
                buildTargetInfo(),
                ImmutableList.of(
                    buildTcpService(exactTcpServer.port(), "dask"),
                    buildTcpService(exactWsServer.port(), "http")));

    assertThat(reports.getDetectionReportsList()).hasSize(2);
  }

  @Test
  public void
      verifyBroadcastRunReply_withManyEntriesAndSerializedSubframes_scansOnceAndValidates() {
    // Build a broadcast map with 200 OK entries referencing __Serialized__ subframes and assert
    // the subframe list is scanned only once (not entryCount times).
    ByteArrayOutputStream outer = new ByteArrayOutputStream();
    int entryCount = 200;
    outer.write(0xde); // map16
    outer.write((entryCount >> 8) & 0xff);
    outer.write(entryCount & 0xff);
    for (int i = 0; i < entryCount; i++) {
      writeMpStr(outer, "worker-" + i);
      outer.write(0x82); // {"status": "OK", "result": {"__Serialized__": true}}
      writeMpStr(outer, "status");
      writeMpStr(outer, "OK");
      writeMpStr(outer, "result");
      outer.write(0x81);
      writeMpStr(outer, "__Serialized__");
      outer.write(0xc3);
    }
    byte[] headerFrame = outer.toByteArray();
    byte[] wrongSubframe = encodePickleInt32(999);
    byte[] matchSubframe = encodePickleInt32((int) FIXED_SUM);

    AtomicInteger subFrameReads = new AtomicInteger();
    List<byte[]> countedFrames =
        new AbstractList<>() {
          private final ImmutableList<byte[]> delegate =
              ImmutableList.of(headerFrame, wrongSubframe);

          @Override
          public byte[] get(int index) {
            if (index > 0) {
              subFrameReads.incrementAndGet();
            }
            return delegate.get(index);
          }

          @Override
          public int size() {
            return delegate.size();
          }
        };
    assertThat(DaskCommClient.verifyBroadcastRunReply(countedFrames, FIXED_SUM)).isFalse();
    assertThat(subFrameReads.get()).isEqualTo(1);

    assertThat(
            DaskCommClient.verifyBroadcastRunReply(
                ImmutableList.of(headerFrame, wrongSubframe, matchSubframe), FIXED_SUM))
        .isTrue();
  }

  @Test
  public void verifyBroadcastRunReply_whenInlineEntryFailsOrMismatches_ignoresUnrelatedSubframe() {
    byte[] matchSubframe = encodePickleInt32((int) FIXED_SUM);
    ByteArrayOutputStream wrongInlineIntOuter = new ByteArrayOutputStream();
    wrongInlineIntOuter.write(0x81);
    writeMpStr(wrongInlineIntOuter, "worker-0");
    wrongInlineIntOuter.writeBytes(
        encodeRunResultFrames(999L, ResultMode.RUN_FUNCTION_DIRECT_INT).get(0));

    assertThat(DaskCommClient.verifyBroadcastRunReply(ImmutableList.of(), FIXED_SUM)).isFalse();
    assertThat(
            DaskCommClient.verifyBroadcastRunReply(
                ImmutableList.of(encodeBroadcastErrorReply(), matchSubframe), FIXED_SUM))
        .isFalse();
    assertThat(
            DaskCommClient.verifyBroadcastRunReply(
                ImmutableList.of(encodeBroadcastSuccessReply(999L), matchSubframe), FIXED_SUM))
        .isFalse();
    assertThat(
            DaskCommClient.verifyBroadcastRunReply(
                ImmutableList.of(wrongInlineIntOuter.toByteArray(), matchSubframe), FIXED_SUM))
        .isFalse();
  }

  @Test
  public void verifyBroadcastRunReply_whenPickledOffsetMarkerPresent_resolvesViaSubframe() {
    ByteArrayOutputStream offsetOuter = new ByteArrayOutputStream();
    offsetOuter.write(0x81);
    writeMpStr(offsetOuter, "worker-0");
    ImmutableList<byte[]> offsetFrames =
        encodeRunResultFrames(FIXED_SUM, ResultMode.PICKLED_OFFSET_MSGPACK_SUBFRAME);
    offsetOuter.writeBytes(offsetFrames.get(0));

    assertThat(
            DaskCommClient.verifyBroadcastRunReply(
                ImmutableList.of(offsetOuter.toByteArray(), offsetFrames.get(1)), FIXED_SUM))
        .isTrue();
  }

  @Test
  public void openSocket_whenWrapWithSslFails_closesUnderlyingPlainSocketWithoutLeakingFd()
      throws Exception {
    MockDaskServer server =
        startCommServer(socket -> {
          socket.getInputStream().read();
        });
    socketFactory.failSslHandshakeWith(
        new SSLHandshakeException("simulated TLS handshake timeout"));
    socketFactory.clearOpenedPlainSockets();

    DaskCommClient client = new DaskCommClient(socketFactory, Duration.ofSeconds(1));
    assertThat(client.probeTcp(loopbackIp, server.port(), true, FIXED_OPERAND_A, FIXED_OPERAND_B))
        .isEqualTo(DaskCommClient.ProbeOutcome.NonVulnerable.NOT_DASK);
    assertThat(socketFactory.openedPlainSockets()).hasSize(1);
    assertThat(socketFactory.openedPlainSockets().get(0).isClosed()).isTrue();
  }

  @Test
  public void extractAppRootPath_normalizesUrlsLeadingAndTrailingSlashesAndInvalidUris() {
    assertThat(
            DaskUnauthenticatedRceDetector.extractAppRootPath(
                serviceWithAppRoot("http://localhost:8787/dask/")))
        .isEqualTo("/dask");
    assertThat(
            DaskUnauthenticatedRceDetector.extractAppRootPath(
                serviceWithAppRoot("https://example.com/proxy/dask/")))
        .isEqualTo("/proxy/dask");
    assertThat(
            DaskUnauthenticatedRceDetector.extractAppRootPath(
                serviceWithAppRoot("https://example.com")))
        .isEqualTo("/");
    assertThat(DaskUnauthenticatedRceDetector.extractAppRootPath(serviceWithAppRoot("dask")))
        .isEqualTo("/dask");
    assertThat(DaskUnauthenticatedRceDetector.extractAppRootPath(serviceWithAppRoot("/dask")))
        .isEqualTo("/dask");
    assertThat(DaskUnauthenticatedRceDetector.extractAppRootPath(serviceWithAppRoot("///dask///")))
        .isEqualTo("/dask");
    assertThat(DaskUnauthenticatedRceDetector.extractAppRootPath(serviceWithAppRoot("")))
        .isEqualTo("/");
    assertThat(DaskUnauthenticatedRceDetector.extractAppRootPath(serviceWithAppRoot("///")))
        .isEqualTo("/");
    assertThat(
            DaskUnauthenticatedRceDetector.extractAppRootPath(
                serviceWithAppRoot("http://[invalid")))
        .isEqualTo("/http://[invalid");
  }

  @Test
  public void mockDaskServer_whenHandlerThrowsAssertionError_rethrowsOnClose() throws Exception {
    MockDaskServer failingServer =
        new MockDaskServer(
            loopbackAddress,
            socket -> {
              socket.getInputStream().read();
              throw new AssertionError("expected handler failure");
            });
    try (Socket client = socketFactory.createSocket(loopbackIp, failingServer.port())) {
      client.getOutputStream().write('x');
      client.getOutputStream().flush();
      // Wait for handler to execute, throw AssertionError, and close the server-side socket.
      assertThat(client.getInputStream().read()).isEqualTo(-1);
    }
    AssertionError thrown = assertThrows(AssertionError.class, failingServer::close);
    assertThat(thrown).hasMessageThat().contains("expected handler failure");
  }

  private NetworkService serviceWithAppRoot(String appRoot) {
    return NetworkService.newBuilder()
        .setNetworkEndpoint(forIpAndPort(loopbackIp, 8787))
        .setTransportProtocol(TransportProtocol.TCP)
        .setServiceName("http")
        .setServiceContext(
            ServiceContext.newBuilder()
                .setWebServiceContext(WebServiceContext.newBuilder().setApplicationRoot(appRoot)))
        .build();
  }

  private enum ResultMode {
    RUN_FUNCTION_DIRECT_INT,
    RUN_FUNCTION_DIRECT_BYTES,
    RUN_FUNCTION_PICKLED_MAP,
    RUN_FUNCTION_SERIALIZED_SUBFRAME,
    PICKLED_OFFSET_MSGPACK_SUBFRAME,
    BROADCAST_FALLBACK,
    NANNY_BROADCAST_FALLBACK,
    WORKER_DIRECT_RUN,
    WRONG_SUM,
    ALL_BLOCKED
  }

  private static void serveTcpDaskSession(
      Socket socket, String daemonType, String daemonId, ResultMode mode) throws IOException {
    InputStream in = new BufferedInputStream(socket.getInputStream());
    OutputStream out = socket.getOutputStream();

    // Step 1: Read handshake and reply with {"pickle-protocol": 4, "compression": nil}.
    List<byte[]> hs = readTcpFrames(in);
    verifyClientHandshake(hs);
    writeTcpFrames(out, ImmutableList.of(encodeHandshakeReply()));

    // Step 2: Read identity request and reply with {"type": daemonType, "id": daemonId}.
    List<byte[]> idReq = readTcpFrames(in);
    verifyIdentityRequest(idReq);
    writeTcpFrames(out, ImmutableList.of(encodeIdentityReply(daemonType, daemonId)));

    // Step 3: Handle RPC execution request(s).
    List<byte[]> rpcReq = readTcpFrames(in);
    if (!Objects.equals(daemonType, "Scheduler")) {
      long sum = extractAndVerifyRunOperands(rpcReq.get(0), "run");
      if (mode == ResultMode.ALL_BLOCKED) {
        writeTcpFrames(out, ImmutableList.of(encodeErrorReply()));
      } else {
        writeTcpFrames(out, encodeRunResultFrames(sum, mode));
      }
      return;
    }

    long sum = extractAndVerifyRunOperands(rpcReq.get(0), "run_function");
    if (mode == ResultMode.BROADCAST_FALLBACK
        || mode == ResultMode.NANNY_BROADCAST_FALLBACK
        || mode == ResultMode.ALL_BLOCKED) {
      writeTcpFrames(out, ImmutableList.of(encodeErrorReply()));
      List<byte[]> bcastReq = readTcpFrames(in);
      long bcastSum = extractAndVerifyBroadcastOperands(bcastReq.get(0), false);
      if (mode == ResultMode.BROADCAST_FALLBACK) {
        writeTcpFrames(out, ImmutableList.of(encodeBroadcastSuccessReply(bcastSum)));
        return;
      }
      writeTcpFrames(out, ImmutableList.of(encodeBroadcastErrorReply()));
      List<byte[]> nannyReq = readTcpFrames(in);
      long nannySum = extractAndVerifyBroadcastOperands(nannyReq.get(0), true);
      if (mode == ResultMode.ALL_BLOCKED) {
        writeTcpFrames(out, ImmutableList.of(encodeBroadcastErrorReply()));
      } else {
        writeTcpFrames(out, ImmutableList.of(encodeBroadcastSuccessReply(nannySum)));
      }
      return;
    }

    long reported = (mode == ResultMode.WRONG_SUM) ? sum + 1 : sum;
    writeTcpFrames(out, encodeRunResultFrames(reported, mode));
  }

  private static void serveWsDaskSession(
      Socket socket,
      String daemonType,
      String daemonId,
      ResultMode mode,
      List<String> upgradePaths,
      boolean fragmentAndPing)
      throws IOException {
    InputStream in = new BufferedInputStream(socket.getInputStream());
    OutputStream out = socket.getOutputStream();

    Optional<String> path = completeWsServerUpgrade(in, out);
    if (path.isEmpty()) {
      return;
    }
    upgradePaths.add(path.get());

    List<byte[]> hs = readWsClientFrames(in);
    verifyClientHandshake(hs);
    writeWsServerFrames(out, ImmutableList.of(encodeHandshakeReply()), fragmentAndPing);

    List<byte[]> idReq = readWsClientFrames(in);
    verifyIdentityRequest(idReq);
    writeWsServerFrames(out, ImmutableList.of(encodeIdentityReply(daemonType, daemonId)), false);

    List<byte[]> rpcReq = readWsClientFrames(in);
    long sum = extractAndVerifyRunOperands(rpcReq.get(0), "run_function");
    writeWsServerFrames(out, encodeRunResultFrames(sum, mode), fragmentAndPing);
  }

  private static void verifyClientHandshake(List<byte[]> frames) {
    assertThat(frames).hasSize(1);
    Optional<Object> decoded = DaskCommClient.decodeMsgPack(frames.get(0));
    assertThat(decoded).isPresent();
    Map<?, ?> map = (Map<?, ?>) decoded.get();
    assertThat(map.get("pickle-protocol")).isEqualTo(4L);
  }

  private static void verifyIdentityRequest(List<byte[]> frames) {
    assertThat(frames).hasSize(1);
    Optional<Object> decoded = DaskCommClient.decodeMsgPack(frames.get(0));
    assertThat(decoded).isPresent();
    Map<?, ?> map = (Map<?, ?>) decoded.get();
    assertThat(map.get("op")).isEqualTo("identity");
    assertThat(map.get("reply")).isEqualTo(true);
  }

  private static long extractAndVerifyRunOperands(byte[] frame, String expectedOp) {
    Optional<Object> decoded = DaskCommClient.decodeMsgPack(frame);
    assertThat(decoded).isPresent();
    Map<?, ?> map = (Map<?, ?>) decoded.get();
    assertThat(map.get("op")).isEqualTo(expectedOp);
    assertThat(map.get("wait")).isEqualTo(true);
    assertThat(map.get("reply")).isEqualTo(true);
    return unpackAndVerifyPickleCall(map);
  }

  private static long extractAndVerifyBroadcastOperands(byte[] frame, boolean expectNanny) {
    Optional<Object> decoded = DaskCommClient.decodeMsgPack(frame);
    assertThat(decoded).isPresent();
    Map<?, ?> outer = (Map<?, ?>) decoded.get();
    assertThat(outer.get("op")).isEqualTo("broadcast");
    assertThat(outer.get("reply")).isEqualTo(true);
    if (expectNanny) {
      assertThat(outer.get("nanny")).isEqualTo(true);
    } else {
      assertThat(outer).doesNotContainKey("nanny");
    }
    Map<?, ?> inner = (Map<?, ?>) outer.get("msg");
    assertThat(inner.get("op")).isEqualTo("run");
    assertThat(inner.get("wait")).isEqualTo(true);
    return unpackAndVerifyPickleCall(inner);
  }

  private static long unpackAndVerifyPickleCall(Map<?, ?> callMap) {
    byte[] fnPkl = (byte[]) callMap.get("function");
    byte[] argsPkl = (byte[]) callMap.get("args");
    byte[] kwargsPkl = (byte[]) callMap.get("kwargs");
    assertThat(fnPkl).isEqualTo(expectedOperatorAddPickle);
    assertThat(kwargsPkl).isEqualTo(expectedEmptyKwargsPickle);
    assertThat(argsPkl).hasLength(16);
    ByteBuffer buf = ByteBuffer.wrap(argsPkl).order(ByteOrder.LITTLE_ENDIAN);
    assertThat(buf.get() & 0xff).isEqualTo(0x80);
    assertThat(buf.get() & 0xff).isEqualTo(0x02);
    assertThat((char) buf.get()).isEqualTo('J');
    int a = buf.getInt();
    assertThat((char) buf.get()).isEqualTo('J');
    int b = buf.getInt();
    assertThat(buf.get() & 0xff).isEqualTo(0x86); // TUPLE2
    assertThat((char) buf.get()).isEqualTo('q'); // BINPUT
    assertThat(buf.get() & 0xff).isEqualTo(0x00);
    assertThat((char) buf.get()).isEqualTo('.'); // STOP
    return (long) a + (long) b;
  }

  private static byte[] encodeHandshakeReply() {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.write(0x82); // fixmap(2)
    writeMpStr(out, "pickle-protocol");
    out.write(0x04);
    writeMpStr(out, "compression");
    out.write(0xc0); // nil
    return out.toByteArray();
  }

  private static byte[] encodeIdentityReply(String daemonType, String daemonId) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.write(0x82); // fixmap(2)
    writeMpStr(out, "type");
    writeMpStr(out, daemonType);
    writeMpStr(out, "id");
    writeMpStr(out, daemonId);
    return out.toByteArray();
  }

  private static byte[] encodeErrorReply() {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.write(0x82);
    writeMpStr(out, "status");
    writeMpStr(out, "error");
    writeMpStr(out, "text");
    writeMpStr(out, "handler blocked");
    return out.toByteArray();
  }

  private static byte[] encodeBroadcastErrorReply() {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.write(0x81);
    writeMpStr(out, "worker-1");
    out.writeBytes(encodeErrorReply());
    return out.toByteArray();
  }

  private static byte[] encodeBroadcastSuccessReply(long sum) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.write(0x81); // outer map {"worker-1": {"status": "OK", "result": {"__Pickled__": ...}}}
    writeMpStr(out, "worker-1");
    out.writeBytes(encodeRunResultFrames(sum, ResultMode.RUN_FUNCTION_PICKLED_MAP).get(0));
    return out.toByteArray();
  }

  private static ImmutableList<byte[]> encodeRunResultFrames(long sum, ResultMode mode) {
    byte[] pickleInt = encodePickleInt32((int) sum);
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.write(0x82); // fixmap(2): status, result
    writeMpStr(out, "status");
    writeMpStr(out, "OK");
    writeMpStr(out, "result");

    return switch (mode) {
      case RUN_FUNCTION_DIRECT_INT, WORKER_DIRECT_RUN, WRONG_SUM -> {
        out.write(0xd3); // int64 BE
        out.writeBytes(ByteBuffer.allocate(8).putLong(sum).array());
        yield ImmutableList.of(out.toByteArray());
      }
      case RUN_FUNCTION_DIRECT_BYTES -> {
        writeMpBin(out, pickleInt);
        yield ImmutableList.of(out.toByteArray());
      }
      case RUN_FUNCTION_PICKLED_MAP, BROADCAST_FALLBACK, NANNY_BROADCAST_FALLBACK, ALL_BLOCKED -> {
        out.write(0x81); // {"__Pickled__": <bytes>}
        writeMpStr(out, "__Pickled__");
        writeMpBin(out, pickleInt);
        yield ImmutableList.of(out.toByteArray());
      }
      case RUN_FUNCTION_SERIALIZED_SUBFRAME -> {
        out.write(0x81); // {"__Serialized__": true} + subframe[1] = pickleInt
        writeMpStr(out, "__Serialized__");
        out.write(0xc3);
        yield ImmutableList.of(out.toByteArray(), pickleInt);
      }
      case PICKLED_OFFSET_MSGPACK_SUBFRAME -> {
        out.write(0x81); // {"__Pickled__": 1} + subframe[1] = {"pickled-obj": pickleInt}
        writeMpStr(out, "__Pickled__");
        out.write(0x01);
        ByteArrayOutputStream sf = new ByteArrayOutputStream();
        sf.write(0x81);
        writeMpStr(sf, "pickled-obj");
        writeMpBin(sf, pickleInt);
        yield ImmutableList.of(out.toByteArray(), sf.toByteArray());
      }
    };
  }

  private static byte[] encodePickleInt32(int value) {
    ByteBuffer buf = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN);
    buf.put((byte) 0x80).put((byte) 0x02).put((byte) 'J').putInt(value).put((byte) '.');
    return buf.array();
  }

  private static void writeMpBin(ByteArrayOutputStream out, byte[] data) {
    out.write(0xc4);
    out.write(data.length);
    out.writeBytes(data);
  }

  private static List<byte[]> readTcpFrames(InputStream in) throws IOException {
    ByteBuffer hdr = ByteBuffer.wrap(readExactBytes(in, 16)).order(ByteOrder.LITTLE_ENDIAN);
    long nosplitBytes = hdr.getLong();
    long count = hdr.getLong();
    if (nosplitBytes <= 0 || count <= 0 || count > 16) {
      throw new IOException("Invalid test TCP frame header");
    }
    ByteBuffer lens =
        ByteBuffer.wrap(readExactBytes(in, (int) (count * 8))).order(ByteOrder.LITTLE_ENDIAN);
    int[] frameLens = new int[(int) count];
    long payloadSum = 0;
    for (int i = 0; i < count; i++) {
      frameLens[i] = (int) lens.getLong();
      payloadSum += frameLens[i];
    }
    if (nosplitBytes != 8L * (1L + count) + payloadSum) {
      throw new IOException("Mismatched test TCP frames_nosplit_nbytes prefix");
    }
    List<byte[]> frames = new ArrayList<>((int) count);
    for (int len : frameLens) {
      frames.add(readExactBytes(in, len));
    }
    return frames;
  }

  private static void writeTcpFrames(OutputStream out, List<byte[]> frames) throws IOException {
    long payloadSum = 0;
    for (byte[] f : frames) {
      payloadSum += f.length;
    }
    long n = frames.size();
    ByteBuffer hdr = ByteBuffer.allocate((int) (16 + 8 * n)).order(ByteOrder.LITTLE_ENDIAN);
    hdr.putLong(8L * (1L + n) + payloadSum);
    hdr.putLong(n);
    for (byte[] f : frames) {
      hdr.putLong(f.length);
    }
    out.write(hdr.array());
    for (byte[] f : frames) {
      out.write(f);
    }
    out.flush();
  }

  private static Optional<String> completeWsServerUpgrade(InputStream in, OutputStream out)
      throws IOException {
    ByteArrayOutputStream reqBuf = new ByteArrayOutputStream();
    int state = 0;
    while (state < 4) {
      int b = in.read();
      if (b < 0) {
        throw new EOFException("EOF reading WS upgrade");
      }
      reqBuf.write(b);
      if ((state == 0 && b == '\r')
          || (state == 1 && b == '\n')
          || (state == 2 && b == '\r')
          || (state == 3 && b == '\n')) {
        state++;
      } else {
        state = (b == '\r') ? 1 : 0;
      }
    }
    String[] lines = reqBuf.toString(US_ASCII).split("\r\n", -1);
    String[] reqParts = lines[0].split(" ", -1);
    String path = reqParts[1];
    String wsKey = "";
    boolean hasUpgradeWebsocket = false;
    for (int i = 1; i < lines.length; i++) {
      if (lines[i].regionMatches(true, 0, "Sec-WebSocket-Key:", 0, 18)) {
        wsKey = lines[i].substring(18).trim();
      } else if (lines[i].regionMatches(true, 0, "Upgrade:", 0, 8)
          && lines[i].substring(8).trim().equalsIgnoreCase("websocket")) {
        hasUpgradeWebsocket = true;
      }
    }
    if (!hasUpgradeWebsocket || wsKey.isEmpty()) {
      String notFound = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
      out.write(notFound.getBytes(US_ASCII));
      out.flush();
      return Optional.empty();
    }
    String accept;
    try {
      MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
      accept =
          Base64.getEncoder().encodeToString(sha1.digest((wsKey + WS_GUID).getBytes(US_ASCII)));
    } catch (NoSuchAlgorithmException e) {
      throw new AssertionError(e);
    }
    String resp =
        "HTTP/1.1 101 Switching Protocols\r\n"
            + "Upgrade: websocket\r\n"
            + "Connection: keep-alive, Upgrade\r\n"
            + "Sec-WebSocket-Accept: "
            + accept
            + "\r\n\r\n";
    out.write(resp.getBytes(US_ASCII));
    out.flush();
    return Optional.of(path);
  }

  private static List<byte[]> readWsClientFrames(InputStream in) throws IOException {
    boolean[] hasNonZeroMask = new boolean[] {false};
    byte[] countPayload = readSingleWsFrame(in, hasNonZeroMask);
    long n = ByteBuffer.wrap(countPayload).order(ByteOrder.LITTLE_ENDIAN).getLong();
    List<byte[]> frames = new ArrayList<>((int) n);
    for (int i = 0; i < n; i++) {
      frames.add(readSingleWsFrame(in, hasNonZeroMask));
    }
    assertThat(hasNonZeroMask[0]).isTrue();
    return frames;
  }

  private static byte[] readSingleWsFrame(InputStream in, boolean[] hasNonZeroMask)
      throws IOException {
    byte[] hdr = readExactBytes(in, 2);
    boolean masked = (hdr[1] & 0x80) != 0;
    assertThat(masked).isTrue();
    int len = hdr[1] & 0x7f;
    if (len == 126) {
      byte[] ext = readExactBytes(in, 2);
      len = ((ext[0] & 0xff) << 8) | (ext[1] & 0xff);
      // RFC 6455 §5.2 requires minimal-length encoding (16-bit extended length only for >= 126).
      assertThat(len).isAtLeast(126);
    }
    byte[] mask = readExactBytes(in, 4);
    for (byte b : mask) {
      if (b != 0) {
        hasNonZeroMask[0] = true;
      }
    }
    byte[] payload = readExactBytes(in, len);
    for (int i = 0; i < payload.length; i++) {
      payload[i] = (byte) (payload[i] ^ mask[i & 3]);
    }
    return payload;
  }

  private static void writeWsServerFrames(
      OutputStream out, List<byte[]> frames, boolean fragmentAndPing) throws IOException {
    if (fragmentAndPing) {
      // Emit a Ping control frame (FIN=1, opcode=0x09, len=2) before binary frames.
      out.write(new byte[] {(byte) 0x89, 0x02, 'h', 'i'});
    }
    byte[] countBytes =
        ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(frames.size()).array();
    writeUnmaskedWsBinary(out, countBytes, false);
    for (byte[] frame : frames) {
      writeUnmaskedWsBinary(out, frame, fragmentAndPing && frame.length > 4);
    }
    out.flush();
  }

  private static void writeUnmaskedWsBinary(OutputStream out, byte[] payload, boolean fragment)
      throws IOException {
    if (fragment) {
      int split = payload.length / 2;
      // First fragment: FIN=0, opcode=0x02
      out.write(0x02);
      out.write(split);
      out.write(payload, 0, split);
      // Final continuation fragment: FIN=1, opcode=0x00
      out.write(0x80);
      out.write(payload.length - split);
      out.write(payload, split, payload.length - split);
      return;
    }
    out.write(0x82);
    if (payload.length < 126) {
      out.write(payload.length);
    } else if (payload.length <= 65535) {
      out.write(126);
      out.write((payload.length >> 8) & 0xff);
      out.write(payload.length & 0xff);
    } else {
      out.write(127);
      out.write(ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN).putLong(payload.length).array());
    }
    out.write(payload);
  }

  private static byte[] readExactBytes(InputStream in, int len) throws IOException {
    byte[] buf = in.readNBytes(len);
    if (buf.length != len) {
      throw new EOFException("Unexpected EOF");
    }
    return buf;
  }

  @FunctionalInterface
  private interface SocketHandler {
    void handle(Socket socket) throws IOException;
  }

  private static final class MockDaskServer implements AutoCloseable {
    private final ServerSocket serverSocket;
    private final ExecutorService executor;
    private final AtomicReference<Throwable> handlerFailure = new AtomicReference<>();

    MockDaskServer(InetAddress bindAddr, SocketHandler handler) throws IOException {
      this.serverSocket = new ServerSocket(0, 50, bindAddr);
      this.executor =
          Executors.newCachedThreadPool(runnable -> {
            Thread t = new Thread(runnable, "mock-dask-server");
            t.setDaemon(true);
            return t;
          });
      executor.execute(() -> {
        while (!serverSocket.isClosed()) {
          try {
            Socket client = serverSocket.accept();
            executor.execute(() -> {
              try (client) {
                client.setSoTimeout(3000);
                handler.handle(client);
              } catch (IOException ignored) {
                // Expected on negative/EOF test cases.
              } catch (Throwable t) {
                handlerFailure.compareAndSet(null, t);
              }
            });
          } catch (IOException e) {
            return;
          }
        }
      });
    }

    int port() {
      return serverSocket.getLocalPort();
    }

    @Override
    public void close() throws IOException {
      serverSocket.close();
      executor.shutdownNow();
      try {
        executor.awaitTermination(2, SECONDS);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
      }
      Throwable err = handlerFailure.get();
      if (err instanceof Error error) {
        throw error;
      }
      if (err instanceof RuntimeException runtimeException) {
        throw runtimeException;
      }
      if (err != null) {
        throw new AssertionError("Unexpected handler failure in MockDaskServer", err);
      }
    }
  }

  private record DialAttempt(String host, int port, boolean tls) {}

  private record RecordedDial(String host, int port, boolean directTls, @Nullable Socket socket) {}

  private static final class RecordingTsunamiSocketFactory implements TsunamiSocketFactory {
    private final String allowedLoopbackHost;
    private final DefaultTsunamiSocketFactory delegate;
    private final List<RecordedDial> recordedDials = new CopyOnWriteArrayList<>();
    private final Set<Socket> tlsUpgradedSockets =
        Collections.synchronizedSet(Collections.newSetFromMap(new IdentityHashMap<>()));
    private final List<Socket> plainSockets = new CopyOnWriteArrayList<>();
    private final Set<Integer> forcedErrorPorts = ConcurrentHashMap.newKeySet();
    private final Set<Integer> forcedSslUpgradeErrorPorts = ConcurrentHashMap.newKeySet();
    private volatile IOException sslFailure;
    private volatile int tlsRequiredPort = -1;

    RecordingTsunamiSocketFactory(String allowedLoopbackHost) {
      this.allowedLoopbackHost = allowedLoopbackHost;
      this.delegate =
          new DefaultTsunamiSocketFactory(
              SocketFactory.getDefault(),
              (SSLSocketFactory) SSLSocketFactory.getDefault(),
              Duration.ofSeconds(3),
              Duration.ofSeconds(3));
    }

    void failSslHandshakeWith(IOException error) {
      this.sslFailure = error;
    }

    void requireTlsOnPort(int port) {
      this.tlsRequiredPort = port;
    }

    void failPortWithIoError(int port) {
      forcedErrorPorts.add(port);
    }

    void failSslUpgradeOnPort(int port) {
      forcedSslUpgradeErrorPorts.add(port);
    }

    void clearDialAttempts() {
      recordedDials.clear();
      tlsUpgradedSockets.clear();
    }

    void clearOpenedPlainSockets() {
      plainSockets.clear();
    }

    ImmutableList<Socket> openedPlainSockets() {
      return ImmutableList.copyOf(plainSockets);
    }

    ImmutableList<DialAttempt> dialAttempts() {
      ImmutableList.Builder<DialAttempt> result = ImmutableList.builder();
      for (RecordedDial dial : recordedDials) {
        boolean tls =
            dial.directTls()
                || (dial.socket() != null && tlsUpgradedSockets.contains(dial.socket()));
        result.add(new DialAttempt(dial.host(), dial.port(), tls));
      }
      return result.build();
    }

    List<String> dialedHosts() {
      List<String> hosts = new ArrayList<>();
      for (RecordedDial dial : recordedDials) {
        hosts.add(dial.host());
      }
      return hosts;
    }

    private void verifyAllowedHost(String host) throws IOException {
      if (!Objects.equals(host, allowedLoopbackHost)) {
        throw new IOException("Blocked connection to non-loopback host in test: " + host);
      }
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException {
      return createSocket(host, port, getDefaultConnectTimeout(), getDefaultReadTimeout());
    }

    @Override
    public Socket createSocket(String host, int port, Duration timeout) throws IOException {
      return createSocket(host, port, timeout, timeout);
    }

    @Override
    public Socket createSocket(String host, int port, Duration connectTimeout, Duration readTimeout)
        throws IOException {
      Socket tracked;
      try {
        verifyAllowedHost(host);
        if (forcedErrorPorts.contains(port)) {
          throw new IOException("Simulated connection refusal on port " + port);
        }
        if (forcedSslUpgradeErrorPorts.contains(port)) {
          tracked = new TlsGuardedPlainSocket(new Socket(), port);
        } else {
          Socket raw = delegate.createSocket(host, port, connectTimeout, readTimeout);
          tracked = (port == tlsRequiredPort) ? new TlsGuardedPlainSocket(raw, port) : raw;
        }
      } catch (IOException e) {
        recordedDials.add(new RecordedDial(host, port, /* directTls= */ false, /* socket= */ null));
        throw e;
      }
      recordedDials.add(new RecordedDial(host, port, /* directTls= */ false, tracked));
      plainSockets.add(tracked);
      return tracked;
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
    public Socket createUnconnectedSocket() throws IOException {
      return delegate.createUnconnectedSocket();
    }

    @Override
    public SSLSocket createSslSocket(String host, int port) throws IOException {
      return createSslSocket(host, port, getDefaultConnectTimeout(), getDefaultReadTimeout());
    }

    @Override
    public SSLSocket createSslSocket(String host, int port, Duration timeout) throws IOException {
      return createSslSocket(host, port, timeout, timeout);
    }

    @Override
    public SSLSocket createSslSocket(
        String host, int port, Duration connectTimeout, Duration readTimeout) throws IOException {
      recordedDials.add(new RecordedDial(host, port, true, null));
      verifyAllowedHost(host);
      if (forcedErrorPorts.contains(port)) {
        throw new IOException("Simulated SSL connection refusal on port " + port);
      }
      if (sslFailure != null) {
        throw sslFailure;
      }
      Socket raw = delegate.createSocket(host, port, connectTimeout, readTimeout);
      return new LoopbackSslSocket(raw, /* autoClose= */ true);
    }

    @Override
    public SSLSocket createSslSocket(InetAddress address, int port) throws IOException {
      return createSslSocket(address.getHostAddress(), port);
    }

    @Override
    public SSLSocket createSslSocket(InetAddress address, int port, Duration timeout)
        throws IOException {
      return createSslSocket(address.getHostAddress(), port, timeout);
    }

    @Override
    public SSLSocket createSslSocket(
        InetAddress address, int port, Duration connectTimeout, Duration readTimeout)
        throws IOException {
      return createSslSocket(address.getHostAddress(), port, connectTimeout, readTimeout);
    }

    @Override
    public SSLSocket wrapWithSsl(Socket socket, String host, int port, boolean autoClose)
        throws IOException {
      tlsUpgradedSockets.add(socket);
      if (forcedSslUpgradeErrorPorts.contains(port)) {
        throw new IOException("Simulated SSL upgrade failure on port " + port);
      }
      if (sslFailure != null) {
        throw sslFailure;
      }
      if (socket instanceof TlsGuardedPlainSocket guarded) {
        guarded.allowAfterTlsUpgrade();
      }
      return new LoopbackSslSocket(socket, autoClose);
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

  private static final class TlsGuardedPlainSocket extends Socket {
    private final Socket raw;
    private final int port;
    private volatile boolean tlsUpgraded;

    TlsGuardedPlainSocket(Socket raw, int port) {
      this.raw = raw;
      this.port = port;
    }

    void allowAfterTlsUpgrade() {
      this.tlsUpgraded = true;
    }

    @Override
    public InputStream getInputStream() throws IOException {
      return raw.getInputStream();
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
      return new FilterOutputStream(raw.getOutputStream()) {
        @Override
        public void write(int b) throws IOException {
          if (!tlsUpgraded) {
            throw new IOException("Plaintext connection rejected on TLS-only port " + port);
          }
          out.write(b);
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
          if (!tlsUpgraded) {
            throw new IOException("Plaintext connection rejected on TLS-only port " + port);
          }
          out.write(b, off, len);
        }
      };
    }

    @Override
    public void setSoTimeout(int timeout) throws SocketException {
      raw.setSoTimeout(timeout);
    }

    @Override
    public int getSoTimeout() throws SocketException {
      return raw.getSoTimeout();
    }

    @Override
    public boolean isClosed() {
      return raw.isClosed();
    }

    @Override
    public void close() throws IOException {
      raw.close();
    }
  }

  private static final class LoopbackSslSocket extends SSLSocket {
    private final Socket raw;
    private final boolean autoClose;

    LoopbackSslSocket(Socket raw, boolean autoClose) {
      this.raw = raw;
      this.autoClose = autoClose;
    }

    @Override
    public InputStream getInputStream() throws IOException {
      return raw.getInputStream();
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
      return raw.getOutputStream();
    }

    @Override
    public void close() throws IOException {
      if (autoClose) {
        raw.close();
      }
    }

    @Override
    public void setSoTimeout(int timeout) throws SocketException {
      raw.setSoTimeout(timeout);
    }

    @Override
    public String[] getSupportedCipherSuites() {
      return new String[0];
    }

    @Override
    public String[] getEnabledCipherSuites() {
      return new String[0];
    }

    @Override
    public void setEnabledCipherSuites(String[] suites) {}

    @Override
    public String[] getSupportedProtocols() {
      return new String[] {"TLSv1.3"};
    }

    @Override
    public String[] getEnabledProtocols() {
      return new String[] {"TLSv1.3"};
    }

    @Override
    public void setEnabledProtocols(String[] protocols) {}

    @Override
    public SSLSession getSession() {
      return null;
    }

    @Override
    public void addHandshakeCompletedListener(HandshakeCompletedListener listener) {}

    @Override
    public void removeHandshakeCompletedListener(HandshakeCompletedListener listener) {}

    @Override
    public void startHandshake() {}

    @Override
    public void setUseClientMode(boolean mode) {}

    @Override
    public boolean getUseClientMode() {
      return true;
    }

    @Override
    public void setNeedClientAuth(boolean need) {}

    @Override
    public boolean getNeedClientAuth() {
      return false;
    }

    @Override
    public void setWantClientAuth(boolean want) {}

    @Override
    public boolean getWantClientAuth() {
      return false;
    }

    @Override
    public void setEnableSessionCreation(boolean flag) {}

    @Override
    public boolean getEnableSessionCreation() {
      return true;
    }
  }

  private static void writeMasked64BitWsBinary(OutputStream out, byte[] payload)
      throws IOException {
    byte[] mask = new byte[] {0x12, 0x34, 0x56, 0x78};
    out.write(0x82); // FIN=1, binary opcode 0x02
    out.write(0x80 | 127); // MASK=1, 64-bit extended length
    out.write(ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN).putLong(payload.length).array());
    out.write(mask);
    for (int i = 0; i < payload.length; i++) {
      out.write(payload[i] ^ mask[i & 3]);
    }
  }

  private static final class RecordingStubHttpClient extends HttpClient {
    private final List<String> urls = new CopyOnWriteArrayList<>();
    private final Map<String, HttpResponse> responses = new HashMap<>();

    void registerJsonResponse(String url, String jsonBody) {
      responses.put(
          url,
          HttpResponse.builder()
              .setStatus(HttpStatus.OK)
              .setHeaders(
                  HttpHeaders.builder().addHeader("Content-Type", "application/json").build())
              .setBodyBytes(ByteString.copyFromUtf8(jsonBody))
              .build());
    }

    ImmutableList<String> requestedUrls() {
      return ImmutableList.copyOf(urls);
    }

    @Override
    public String getLogId() {
      return "stub";
    }

    @Override
    public HttpResponse sendAsIs(HttpRequest httpRequest) {
      return send(httpRequest, null);
    }

    @Override
    public HttpResponse send(HttpRequest httpRequest) {
      return send(httpRequest, null);
    }

    @Override
    public HttpResponse send(HttpRequest httpRequest, @Nullable NetworkService networkService) {
      urls.add(httpRequest.url());
      HttpResponse matched = responses.get(httpRequest.url());
      if (matched != null) {
        return matched;
      }
      return HttpResponse.builder()
          .setStatus(HttpStatus.NOT_FOUND)
          .setHeaders(HttpHeaders.builder().build())
          .build();
    }

    @Override
    public ListenableFuture<HttpResponse> sendAsync(HttpRequest httpRequest) {
      return immediateFuture(send(httpRequest, null));
    }

    @Override
    public ListenableFuture<HttpResponse> sendAsync(
        HttpRequest httpRequest, @Nullable NetworkService networkService) {
      return immediateFuture(send(httpRequest, networkService));
    }

    @Override
    @SuppressWarnings("unchecked") // Safe covariant builder return for HttpClient test stub.
    public <T extends HttpClient> Builder<T> modify() {
      return (Builder<T>)
          new Builder<RecordingStubHttpClient>() {
            @Override
            public Builder<RecordingStubHttpClient> setFollowRedirects(boolean followRedirects) {
              return this;
            }

            @Override
            public Builder<RecordingStubHttpClient> setLogId(String logId) {
              return this;
            }

            @Override
            public Builder<RecordingStubHttpClient> setConnectTimeout(Duration connectionTimeout) {
              return this;
            }

            @Override
            public RecordingStubHttpClient build() {
              return RecordingStubHttpClient.this;
            }
          };
    }
  }
}
