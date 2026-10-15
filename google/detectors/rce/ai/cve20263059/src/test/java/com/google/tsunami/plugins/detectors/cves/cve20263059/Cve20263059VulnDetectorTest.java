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
package com.google.tsunami.plugins.detectors.cves.cve20263059;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostname;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;
import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.google.common.collect.ImmutableList;
import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.net.socket.TsunamiSocketFactory;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Software;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TextData;
import com.google.tsunami.proto.TransportProtocol;
import com.google.tsunami.proto.Vulnerability;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.time.Instant;
import javax.inject.Inject;
import mockwebserver3.MockResponse;
import mockwebserver3.MockWebServer;
import mockwebserver3.RecordedRequest;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link Cve20263059VulnDetector}. */
@RunWith(JUnit4.class)
public final class Cve20263059VulnDetectorTest {

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2026-03-12T00:00:00.00Z"));

  private final TsunamiSocketFactory socketFactoryMock = mock(TsunamiSocketFactory.class);

  @Inject private Cve20263059VulnDetector detector;

  private MockWebServer mockWebServer;

  @Before
  public void setUp() {
    mockWebServer = new MockWebServer();
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new Cve20263059DetectorBootstrapModule(),
            new HttpClientModule.Builder().build(),
            new AbstractModule() {
              @Override
              protected void configure() {
                bind(TsunamiSocketFactory.class).toInstance(socketFactoryMock);
              }
            })
        .injectMembers(this);
  }

  @After
  public void tearDown() throws IOException {
    mockWebServer.close();
  }

  @Test
  public void detect_whenVulnerableSglangAndZmqExposed_returnsDetectionReport()
      throws IOException, InterruptedException {
    mockWebServer.start();
    mockWebServer.enqueue(
        new MockResponse.Builder()
            .code(200)
            .setHeader("Content-Type", "application/json")
            .body(
                "{\"model_path\":\"Qwen/Qwen2-VL-7B-Instruct\","
                    + "\"tokenizer_path\":\"Qwen/Qwen2-VL-7B-Instruct\","
                    + "\"version\":\"0.5.9\"}")
            .build());

    int httpPort = mockWebServer.getPort();
    int expectedZmqPort = httpPort + 1;
    ByteArrayOutputStream socketOut =
        configureMockSocket(
            mockWebServer.getHostName(), expectedZmqPort, Cve20263059VulnDetector.ZMTP_GREETING);

    NetworkService service = createHttpService(mockWebServer);
    TargetInfo targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockWebServer.getHostName()))
            .build();

    DetectionReportList detectionReports = detector.detect(targetInfo, ImmutableList.of(service));

    Vulnerability expectedVulnerability =
        detector.getAdvisories().get(0).toBuilder()
            .addAdditionalDetails(
                AdditionalDetail.newBuilder()
                    .setDescription("Exposed ZeroMQ Broker Details")
                    .setTextData(
                        TextData.newBuilder()
                            .setText(
                                String.format(
                                    "Unauthenticated SGLang ZeroMQ broker confirmed via ZMTP"
                                        + " handshake on %s:%d (adjacent to HTTP service port %d).",
                                    mockWebServer.getHostName(), expectedZmqPort, httpPort))))
            .build();

    assertThat(detectionReports.getDetectionReportsList())
        .containsExactly(
            DetectionReport.newBuilder()
                .setTargetInfo(targetInfo)
                .setNetworkService(service)
                .setDetectionTimestamp(
                    Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
                .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
                .setVulnerability(expectedVulnerability)
                .build());

    RecordedRequest request = mockWebServer.takeRequest();
    assertThat(request.getMethod()).isEqualTo("GET");
    assertThat(request.getTarget()).isEqualTo("/get_server_info");
    assertThat(socketOut.toByteArray()).isEqualTo(Cve20263059VulnDetector.ZMTP_GREETING);
  }

  @Test
  public void detect_whenGetModelInfoFallbackAndZmqExposed_returnsDetectionReport()
      throws IOException, InterruptedException {
    mockWebServer.start();
    mockWebServer.enqueue(new MockResponse.Builder().code(404).build());
    mockWebServer.enqueue(
        new MockResponse.Builder()
            .code(200)
            .setHeader("Content-Type", "application/json")
            .body(
                "{\"model_path\":\"meta-llama/Llama-3.2-11B-Vision-Instruct\","
                    + "\"tokenizer_path\":\"meta-llama/Llama-3.2-11B-Vision-Instruct\","
                    + "\"is_generation\":true}")
            .build());

    int httpPort = mockWebServer.getPort();
    int expectedZmqPort = httpPort + 1;
    configureMockSocket(
        mockWebServer.getHostName(), expectedZmqPort, Cve20263059VulnDetector.ZMTP_GREETING);

    NetworkService service = createHttpService(mockWebServer);
    TargetInfo targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockWebServer.getHostName()))
            .build();

    DetectionReportList detectionReports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(detectionReports.getDetectionReportsList()).hasSize(1);
    RecordedRequest req1 = mockWebServer.takeRequest();
    assertThat(req1.getTarget()).isEqualTo("/get_server_info");
    RecordedRequest req2 = mockWebServer.takeRequest();
    assertThat(req2.getTarget()).isEqualTo("/get_model_info");
  }

  @Test
  public void detect_whenNonZmtpResponseOnAdjacentPort_returnsNoVulnerability() throws IOException {
    mockWebServer.start();
    mockWebServer.enqueue(
        new MockResponse.Builder()
            .code(200)
            .setHeader("Content-Type", "application/json")
            .body(
                "{\"model_path\":\"Qwen/Qwen2-VL-7B-Instruct\","
                    + "\"tokenizer_path\":\"Qwen/Qwen2-VL-7B-Instruct\"}")
            .build());

    int expectedZmqPort = mockWebServer.getPort() + 1;
    configureMockSocket(
        mockWebServer.getHostName(), expectedZmqPort, "HTTP/1.1 400 Bad Request\r\n\r\n".getBytes(US_ASCII));

    NetworkService service = createHttpService(mockWebServer);
    TargetInfo targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockWebServer.getHostName()))
            .build();

    DetectionReportList detectionReports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void detect_whenNotSglangService_returnsNoVulnerability() throws IOException {
    mockWebServer.start();
    mockWebServer.enqueue(new MockResponse.Builder().code(404).body("Not Found").build());
    mockWebServer.enqueue(new MockResponse.Builder().code(404).body("Not Found").build());

    NetworkService service = createHttpService(mockWebServer);
    TargetInfo targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockWebServer.getHostName()))
            .build();

    DetectionReportList detectionReports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
    verify(socketFactoryMock, never()).createSocket(anyString(), anyInt());
  }

  @Test
  public void detect_whenZmqPortClosed_returnsNoVulnerability() throws IOException {
    mockWebServer.start();
    mockWebServer.enqueue(
        new MockResponse.Builder()
            .code(200)
            .setHeader("Content-Type", "application/json")
            .body(
                "{\"model_path\":\"Qwen/Qwen2-VL-7B-Instruct\","
                    + "\"tokenizer_path\":\"Qwen/Qwen2-VL-7B-Instruct\","
                    + "\"version\":\"0.5.8\"}")
            .build());

    int expectedZmqPort = mockWebServer.getPort() + 1;
    when(socketFactoryMock.createSocket(eq(mockWebServer.getHostName()), eq(expectedZmqPort)))
        .thenThrow(new IOException("Connection refused"));

    NetworkService service = createHttpService(mockWebServer);
    TargetInfo targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockWebServer.getHostName()))
            .build();

    DetectionReportList detectionReports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void detect_whenZmqUsesCurveAuth_returnsNoVulnerability() throws IOException {
    mockWebServer.start();
    mockWebServer.enqueue(
        new MockResponse.Builder()
            .code(200)
            .setHeader("Content-Type", "application/json")
            .body(
                "{\"model_path\":\"Qwen/Qwen2-VL-7B-Instruct\","
                    + "\"tokenizer_path\":\"Qwen/Qwen2-VL-7B-Instruct\","
                    + "\"version\":\"0.5.9\"}")
            .build());

    byte[] curveGreeting = Cve20263059VulnDetector.ZMTP_GREETING.clone();
    byte[] curveMech = "CURVE".getBytes(US_ASCII);
    System.arraycopy(curveMech, 0, curveGreeting, 12, curveMech.length);

    int expectedZmqPort = mockWebServer.getPort() + 1;
    configureMockSocket(mockWebServer.getHostName(), expectedZmqPort, curveGreeting);

    NetworkService service = createHttpService(mockWebServer);
    TargetInfo targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockWebServer.getHostName()))
            .build();

    DetectionReportList detectionReports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }

  private ByteArrayOutputStream configureMockSocket(String host, int port, byte[] responseBytes)
      throws IOException {
    Socket socket = mock(Socket.class);
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    when(socketFactoryMock.createSocket(eq(host), eq(port))).thenReturn(socket);
    when(socket.getOutputStream()).thenReturn(outputStream);
    when(socket.getInputStream()).thenReturn(new ByteArrayInputStream(responseBytes));
    return outputStream;
  }

  private static NetworkService createHttpService(MockWebServer mockWebServer) {
    return NetworkService.newBuilder()
        .setNetworkEndpoint(
            forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
        .setTransportProtocol(TransportProtocol.TCP)
        .setSoftware(Software.newBuilder().setName("http"))
        .setServiceName("http")
        .build();
  }
}

