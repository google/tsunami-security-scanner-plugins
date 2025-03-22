package com.google.tsunami.plugins.detectors.exposedui.flowise;

import static com.google.common.truth.Truth.assertThat;

import com.google.common.collect.ImmutableList;
import com.google.inject.Guice;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkEndpointUtils;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;

import java.io.IOException;
import java.time.Instant;
import javax.inject.Inject;

import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TextData;
import com.google.tsunami.proto.TransportProtocol;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class FlowiseExposedUiDetectorTest {
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2025-03-22T00:00:00.00Z"));

  static final String FLOWISE_PRESENT_STR = "Flowise - Low-code LLM apps builder";

  private MockWebServer mockWebServer;

  @Inject private FlowiseExposedUiDetector detector;

  private NetworkService service;
  private TargetInfo targetInfo;

  @Before
  public void setUp() {
    mockWebServer = new MockWebServer();
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            new FlowiseExposedUiDetectorBootstrapModule())
        .injectMembers(this);

    targetInfo =
            TargetInfo.newBuilder()
                    .addNetworkEndpoints(NetworkEndpointUtils.forHostname(mockWebServer.getHostName()))
                    .build();
    service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                NetworkEndpointUtils.forHostnameAndPort(
                    mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("http")
            .build();
  }

  @After
  public void tearDown() throws IOException {
    mockWebServer.shutdown();
  }

  @Test
  public void detect_whenFlowiseUiExposed_returnsVulnerability() throws IOException {
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody(FLOWISE_PRESENT_STR));
    mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("[]"));

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
                                .setValue("FLOWISE_UI_EXPOSED"))
                        .setSeverity(Severity.HIGH)
                        .setTitle("Flowise UI Exposed")
                        .setDescription(
                            "Flowise UI instance is exposed without proper authentication.")
                        .setRecommendation(
                            "Secure the Flowise UI by implementing proper authentication.\n"
                                + "Consider restricting access to trusted networks only.")
                        .addAdditionalDetails(
                            AdditionalDetail.newBuilder()
                                .setTextData(
                                    TextData.newBuilder()
                                        .setText(
                                            String.format(
                                                "The Flowise UI instance at %s is exposed without"
                                                    + " proper authentication.",
                                                NetworkServiceUtils.buildWebApplicationRootUrl(
                                                    service))))))
                .build());
  }

  @Test
  public void detect_whenFlowiseUiNotPresent_returnsNoVulnerability() {
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("Some other content"));

    DetectionReportList detectionReports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void detect_whenFlowiseUiPresent_butApiProtected_returnsNoVulnerability() {
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody(FLOWISE_PRESENT_STR));
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(HttpStatus.UNAUTHORIZED.code()).setBody(""));

    DetectionReportList detectionReports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }
}
