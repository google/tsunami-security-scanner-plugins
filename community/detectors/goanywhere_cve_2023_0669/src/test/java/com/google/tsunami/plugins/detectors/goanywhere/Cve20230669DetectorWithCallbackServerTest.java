package com.google.tsunami.plugins.detectors.goanywhere;

import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;

import com.google.common.collect.ImmutableList;
import com.google.inject.Guice;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.plugin.payload.testing.FakePayloadGeneratorModule;
import com.google.tsunami.plugin.payload.testing.PayloadTestHelper;
import com.google.tsunami.proto.*;
import java.io.IOException;
import java.time.Instant;
import javax.inject.Inject;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class Cve20230669DetectorWithCallbackServerTest {

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2024-09-24T00:00:00.00Z"));

  @Inject private Cve20230669VulnDetector detector;
  private MockWebServer mockWebServer;
  private MockWebServer mockCallbackServer;
  private NetworkService service;

  // A version of secure random that gives predictable output for our unit tests

  @Before
  public void setUp() throws IOException {
    mockWebServer = new MockWebServer();
    mockWebServer.start();
    mockCallbackServer = new MockWebServer();
    mockCallbackServer.start();
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            FakePayloadGeneratorModule.builder().setCallbackServer(mockCallbackServer).build(),
            new Cve20230669DetectorBootstrapModule())
        .injectMembers(this);

    service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setSoftware(Software.newBuilder().setName("goanywhere"))
            .setServiceName("http")
            .build();
  }

  @After
  public void tearDown() throws IOException {
    mockWebServer.shutdown();
    mockCallbackServer.shutdown();
  }

  @Test
  public void detect_whenVulnerable_returnsVulnerability() throws IOException {
    mockWebServer.enqueue(
        new MockResponse()
            .setResponseCode(HttpStatus.FOUND.code())
            .setBody(
                "<title>GoAnywhere 6.8"
                    + ".6</title>"
                    + "<body class=\"loginBackground\"><div class=\"loginPanelOuter\"><div class=\"loginPanelInner\"><form id=\"stayAliveForm\" name=\"stayAliveForm\" method=\"post\" action=\"/goanywhere/auth/Login.xhtml\" enctype=\"application/x-www-form-urlencoded\""));
    mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.OK.code()));
    mockCallbackServer.enqueue(PayloadTestHelper.generateMockSuccessfulCallbackResponse());

    TargetInfo targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .build();

    DetectionReportList detectionReports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(detectionReports.getDetectionReportsList())
        .containsExactly(
            DetectionReport.newBuilder()
                .setTargetInfo(targetInfo)
                .setNetworkService(service)
                .setDetectionTimestamp(
                    Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
                .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
                .setVulnerability(
                    Vulnerability.newBuilder()
                        .setMainId(
                            VulnerabilityId.newBuilder()
                                .setPublisher("TSUNAMI_COMMUNITY")
                                .setValue("CVE-2023-0669"))
                        .addRelatedId(
                            VulnerabilityId.newBuilder()
                                .setPublisher("CVE")
                                .setValue("CVE-2023" + "-0669"))
                        .setSeverity(Severity.CRITICAL)
                        .setTitle("CVE-2023-0669: GoAnywhere MFT RCE vulnerability")
                        .setDescription(
                            "GoAnywhere MFT suffers from a pre-authentication command "
                                + "injection "
                                + "vulnerability in the License Response Servlet due "
                                + "to deserializing"
                                + " an arbitrary attacker-controlled object. All "
                                + "versions prior to 7.1.1 are affected.")
                        .setRecommendation("Update GoAnywhere MFT to version 7.1.2 or later."))
                .build());
  }

  @Test
  public void detect_whenNotVulnerable_returnsnoVulnerability() throws IOException {
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(HttpStatus.SERVICE_UNAVAILABLE.code()));

    mockCallbackServer.enqueue(PayloadTestHelper.generateMockUnsuccessfulCallbackResponse());

    TargetInfo targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .build();

    DetectionReportList detectionReports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }
}
