package com.google.tsunami.plugins.detectors.cves.cve202421181;

import static com.google.common.truth.Truth.assertThat;
import static com.google.tsunami.plugins.detectors.cves.cve202421181.Annotations.OobSleepDuration;
import static com.google.tsunami.plugins.detectors.cves.cve202421181.WeblogicUnsafeDeserializationDetector.VULNERABILITY_REPORT_DESCRIPTION_CALLBACK;
import static com.google.tsunami.plugins.detectors.cves.cve202421181.WeblogicUnsafeDeserializationDetector.VULNERABILITY_REPORT_ID;
import static com.google.tsunami.plugins.detectors.cves.cve202421181.WeblogicUnsafeDeserializationDetector.VULNERABILITY_REPORT_PUBLISHER;
import static com.google.tsunami.plugins.detectors.cves.cve202421181.WeblogicUnsafeDeserializationDetector.VULNERABILITY_REPORT_RECOMMENDATION;
import static com.google.tsunami.plugins.detectors.cves.cve202421181.WeblogicUnsafeDeserializationDetector.VULNERABILITY_REPORT_TITLE;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.google.common.collect.ImmutableList;
import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.inject.Inject;
import com.google.inject.multibindings.OptionalBinder;
import com.google.inject.testing.fieldbinder.Bind;
import com.google.inject.testing.fieldbinder.BoundFieldModule;
import com.google.inject.util.Modules;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkEndpointUtils;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.plugin.payload.testing.FakePayloadGeneratorModule;
import com.google.tsunami.plugin.payload.testing.PayloadTestHelper;
import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkEndpoint;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TextData;
import com.google.tsunami.proto.TransportProtocol;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.io.IOException;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.net.Socket;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import javax.net.SocketFactory;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link WeblogicUnsafeDeserializationDetector} */
@RunWith(JUnit4.class)
public final class WeblogicUnsafeDeserializationDetectorTest {
  @Inject private WeblogicUnsafeDeserializationDetector detector;
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2025-02-04T00:00:00.00Z"));
  private final MockWebServer mockCallbackServer = new MockWebServer();
  private final SocketFactory socketFactoryMock = mock(SocketFactory.class);
  private final NetworkEndpoint networkEndpoint =
      NetworkEndpointUtils.forHostnameAndPort("fake.local", 7001);
  private final NetworkService networkService =
      NetworkService.newBuilder()
          .setNetworkEndpoint(networkEndpoint)
          .setTransportProtocol(TransportProtocol.TCP)
          .setServiceName("http")
          .build();
  private final TargetInfo targetInfo =
      TargetInfo.newBuilder().addNetworkEndpoints(networkEndpoint).build();

  @Bind(lazy = true)
  @OobSleepDuration
  private final int oobSleepDuration = 0;

  @Before
  public void setUp() throws Exception {
    mockCallbackServer.start();
    this.createInjector(true);
  }

  @After
  public void tearDown() throws Exception {
    mockCallbackServer.shutdown();
  }

  private void createInjector(boolean tcsAvailable) {
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            FakePayloadGeneratorModule.builder()
                .setCallbackServer(tcsAvailable ? mockCallbackServer : null)
                .build(),
            new AbstractModule() {
              @Override
              protected void configure() {
                OptionalBinder.newOptionalBinder(binder(), SocketFactory.class)
                    .setBinding()
                    .toInstance(socketFactoryMock);
              }
            },
            Modules.override(new WeblogicUnsafeDeserializationDetectorBootstrapModule())
                .with(BoundFieldModule.of(this)))
        .injectMembers(this);
  }

  private MockTcpServer createMockServer() throws IOException {
    Socket socket = mock(Socket.class);
    when(socketFactoryMock.createSocket()).thenReturn(socket);

    // Pipe for client -> server communication
    PipedOutputStream clientOut = new PipedOutputStream();
    PipedInputStream serverIn = new PipedInputStream(clientOut, 8192);

    // Pipe for server -> client communication
    PipedOutputStream serverOut = new PipedOutputStream();
    PipedInputStream clientIn = new PipedInputStream(serverOut, 8192);

    when(socket.getOutputStream()).thenReturn(clientOut);
    when(socket.getInputStream()).thenReturn(clientIn);
    when(socket.isConnected()).thenReturn(true);

    return new MockTcpServer(serverIn, serverOut);
  }

  private DetectionReportList detect(List<String> expectedRequests, List<String> mockResponses)
      throws IOException {
    MockTcpServer mockTcpServer = createMockServer();

    // Enqueue fake responses
    for (String response : mockResponses) {
      mockTcpServer.enqueue(this.getClass().getResourceAsStream(response).readAllBytes());
    }

    // Start
    mockTcpServer.start();

    DetectionReportList detectionReports =
        detector.detect(targetInfo, ImmutableList.of(networkService));

    assertThat(mockTcpServer.getRequestCount()).isEqualTo(expectedRequests.size());
    for (int i = 0; i < expectedRequests.size(); i++) {
      String request = expectedRequests.get(i);
      byte[] expectedBytes = this.getClass().getResourceAsStream(request).readAllBytes();
      assertThat(Arrays.equals(expectedBytes, mockTcpServer.getRequestReceived(i)));
    }
    return detectionReports;
  }

  @Test
  public void detect_whenWeblogic14Vulnerable_reportsVulnerability() throws IOException {
    mockCallbackServer.enqueue(PayloadTestHelper.generateMockSuccessfulCallbackResponse());

    List<String> expectedRequests =
        ImmutableList.of(
            "/weblogic/T3VersionCheck.bin",
            "/weblogic/14/1_InitRequest.bin",
            "/weblogic/14/2_RebindRequest.bin",
            "/weblogic/14/3_RebindNewAddress.bin",
            "/weblogic/14/4_ResolveRequest.bin");

    List<String> mockResponses =
        ImmutableList.of(
            "/weblogic/14/0_T3VersionCheckResponse.bin",
            "/weblogic/14/1_InitResponse.bin",
            "/weblogic/14/2_RebindResponseLocationForward.bin",
            "/weblogic/14/3_RebindResponse.bin",
            "/weblogic/14/4_ResolveResponse.bin");

    DetectionReportList detectionReports = detect(expectedRequests, mockResponses);
    DetectionReport expectedDetection = generateDetectionReport("14.1.1.0");
    assertThat(detectionReports.getDetectionReportsList()).containsExactly(expectedDetection);

    assertThat(mockCallbackServer.getRequestCount()).isEqualTo(1);
  }

  @Test
  public void detect_whenWeblogic14NoCallback_reportsNoVulnerability() throws IOException {
    mockCallbackServer.enqueue(PayloadTestHelper.generateMockUnsuccessfulCallbackResponse());

    List<String> expectedRequests =
        ImmutableList.of(
            "/weblogic/T3VersionCheck.bin",
            "/weblogic/14/1_InitRequest.bin",
            "/weblogic/14/2_RebindRequest.bin",
            "/weblogic/14/3_RebindNewAddress.bin",
            "/weblogic/14/4_ResolveRequest.bin");

    List<String> mockResponses =
        ImmutableList.of(
            "/weblogic/14/0_T3VersionCheckResponse.bin",
            "/weblogic/14/1_InitResponse.bin",
            "/weblogic/14/2_RebindResponseLocationForward.bin",
            "/weblogic/14/3_RebindResponse.bin",
            "/weblogic/14/4_ResolveResponse.bin");

    DetectionReportList detectionReports = detect(expectedRequests, mockResponses);
    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
    assertThat(mockCallbackServer.getRequestCount()).isEqualTo(1);
  }

  @Test
  public void detect_whenWeblogic12Vulnerable_reportsVulnerability() throws IOException {
    mockCallbackServer.enqueue(PayloadTestHelper.generateMockSuccessfulCallbackResponse());

    List<String> expectedRequests =
        ImmutableList.of(
            "/weblogic/T3VersionCheck.bin",
            "/weblogic/12/1_InitRequest.bin",
            "/weblogic/12/2_RebindRequest.bin",
            "/weblogic/12/3_RebindNewAddress.bin",
            "/weblogic/12/4_ResolveRequest.bin");

    List<String> mockResponses =
        ImmutableList.of(
            "/weblogic/12/0_T3VersionCheckResponse.bin",
            "/weblogic/12/1_InitResponse.bin",
            "/weblogic/12/2_RebindResponseLocationForward.bin",
            "/weblogic/12/3_RebindResponse.bin",
            "/weblogic/12/4_ResolveResponse.bin");

    DetectionReportList detectionReports = detect(expectedRequests, mockResponses);
    DetectionReport expectedDetection = generateDetectionReport("12.2.1.3");
    assertThat(detectionReports.getDetectionReportsList()).containsExactly(expectedDetection);

    assertThat(mockCallbackServer.getRequestCount()).isEqualTo(1);
  }

  @Test
  public void detect_whenWeblogicPatched_reportsNoVulnerability() throws IOException {
    mockCallbackServer.enqueue(PayloadTestHelper.generateMockUnsuccessfulCallbackResponse());

    List<String> expectedRequests =
        ImmutableList.of(
            "/weblogic/T3VersionCheck.bin",
            "/weblogic/patched/1_InitRequest.bin",
            "/weblogic/patched/2_RebindRequest.bin",
            "/weblogic/patched/3_RebindNewAddress.bin");

    List<String> mockResponses =
        ImmutableList.of(
            "/weblogic/patched/0_T3VersionCheckResponse.bin",
            "/weblogic/patched/1_InitResponse.bin",
            "/weblogic/patched/2_RebindResponseLocationForward.bin",
            "/weblogic/patched/3_RebindResponse.bin");

    DetectionReportList detectionReports = detect(expectedRequests, mockResponses);
    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
    assertThat(mockCallbackServer.getRequestCount()).isEqualTo(0);
  }

  @Test
  public void detect_whenWeblogicUnsupported_reportsNoVulnerability() throws IOException {
    mockCallbackServer.enqueue(PayloadTestHelper.generateMockUnsuccessfulCallbackResponse());

    List<String> expectedRequests = ImmutableList.of("/weblogic/T3VersionCheck.bin");

    List<String> mockResponses = ImmutableList.of("/weblogic/misc/T3UnsupportedVersion.bin");

    DetectionReportList detectionReports = detect(expectedRequests, mockResponses);
    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
    assertThat(mockCallbackServer.getRequestCount()).isEqualTo(0);
  }

  @Test
  public void detect_noCallbackServer_reportsNoVulnerability() {
    this.createInjector(false);
    DetectionReportList detectionReports =
        detector.detect(targetInfo, ImmutableList.of(networkService));
    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void detect_whenResolveResponseExceptionWithCallback_reportsVulnerability()
      throws IOException {
    mockCallbackServer.enqueue(PayloadTestHelper.generateMockSuccessfulCallbackResponse());

    List<String> expectedRequests =
        ImmutableList.of(
            "/weblogic/T3VersionCheck.bin",
            "/weblogic/14/1_InitRequest.bin",
            "/weblogic/14/2_RebindRequest.bin",
            "/weblogic/14/3_RebindNewAddress.bin",
            "/weblogic/14/4_ResolveRequest.bin");

    List<String> mockResponses =
        ImmutableList.of(
            "/weblogic/14/0_T3VersionCheckResponse.bin",
            "/weblogic/14/1_InitResponse.bin",
            "/weblogic/14/2_RebindResponseLocationForward.bin",
            "/weblogic/14/3_RebindResponse.bin",
            "/weblogic/misc/ExceptionPacket.bin");

    DetectionReportList detectionReports = detect(expectedRequests, mockResponses);
    DetectionReport expectedDetection = generateDetectionReport("14.1.1.0");
    assertThat(detectionReports.getDetectionReportsList()).containsExactly(expectedDetection);

    assertThat(mockCallbackServer.getRequestCount()).isEqualTo(1);
  }

  @Test
  public void detect_whenResolveResponseInvalidWithCallback_reportsVulnerability()
      throws IOException {
    mockCallbackServer.enqueue(PayloadTestHelper.generateMockSuccessfulCallbackResponse());

    List<String> expectedRequests =
        ImmutableList.of(
            "/weblogic/T3VersionCheck.bin",
            "/weblogic/14/1_InitRequest.bin",
            "/weblogic/14/2_RebindRequest.bin",
            "/weblogic/14/3_RebindNewAddress.bin",
            "/weblogic/14/4_ResolveRequest.bin");

    List<String> mockResponses =
        ImmutableList.of(
            "/weblogic/14/0_T3VersionCheckResponse.bin",
            "/weblogic/14/1_InitResponse.bin",
            "/weblogic/14/2_RebindResponseLocationForward.bin",
            "/weblogic/14/3_RebindResponse.bin",
            "/weblogic/misc/InvalidResponse.bin");

    DetectionReportList detectionReports = detect(expectedRequests, mockResponses);
    DetectionReport expectedDetection = generateDetectionReport("14.1.1.0");
    assertThat(detectionReports.getDetectionReportsList()).containsExactly(expectedDetection);

    assertThat(mockCallbackServer.getRequestCount()).isEqualTo(1);
  }

  @Test
  public void detect_whenInvalidRebindResponse_reportsNoVulnerability() throws IOException {
    mockCallbackServer.enqueue(PayloadTestHelper.generateMockUnsuccessfulCallbackResponse());

    List<String> expectedRequests =
        ImmutableList.of(
            "/weblogic/T3VersionCheck.bin",
            "/weblogic/14/1_InitRequest.bin",
            "/weblogic/14/2_RebindRequest.bin");

    List<String> mockResponses =
        ImmutableList.of(
            "/weblogic/14/0_T3VersionCheckResponse.bin",
            "/weblogic/14/1_InitResponse.bin",
            "/weblogic/misc/InvalidResponse.bin");

    DetectionReportList detectionReports = detect(expectedRequests, mockResponses);
    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
    assertThat(mockCallbackServer.getRequestCount()).isEqualTo(0);
  }

  @Test
  public void detect_whenInvalidInitResponse_reportsNoVulnerability() throws IOException {
    mockCallbackServer.enqueue(PayloadTestHelper.generateMockUnsuccessfulCallbackResponse());

    List<String> expectedRequests =
        ImmutableList.of("/weblogic/T3VersionCheck.bin", "/weblogic/14/1_InitRequest.bin");

    List<String> mockResponses =
        ImmutableList.of(
            "/weblogic/14/0_T3VersionCheckResponse.bin", "/weblogic/misc/InvalidInitResponse.bin");

    DetectionReportList detectionReports = detect(expectedRequests, mockResponses);
    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
    assertThat(mockCallbackServer.getRequestCount()).isEqualTo(0);
  }

  private DetectionReport generateDetectionReport(String weblogicVersion) {
    String additionalDetails = "WebLogic version: " + weblogicVersion;

    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(networkService)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder()
                        .setPublisher(VULNERABILITY_REPORT_PUBLISHER)
                        .setValue(VULNERABILITY_REPORT_ID))
                .setSeverity(Severity.CRITICAL)
                .setTitle(VULNERABILITY_REPORT_TITLE)
                .setDescription(VULNERABILITY_REPORT_DESCRIPTION_CALLBACK)
                .setRecommendation(VULNERABILITY_REPORT_RECOMMENDATION)
                .addAdditionalDetails(
                    AdditionalDetail.newBuilder()
                        .setTextData(TextData.newBuilder().setText(additionalDetails))))
        .build();
  }
}
