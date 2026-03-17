/*
 * Copyright 2024 Google LLC
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

package com.google.tsunami.plugins.detectors.rce.cve202333246;

import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;

import com.google.common.collect.ImmutableList;
import com.google.inject.Guice;
import com.google.inject.testing.fieldbinder.Bind;
import com.google.inject.testing.fieldbinder.BoundFieldModule;
import com.google.inject.util.Modules;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkEndpointUtils;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.net.socket.TsunamiSocketFactory;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.plugin.payload.testing.FakePayloadGeneratorModule;
import com.google.tsunami.plugin.payload.testing.PayloadTestHelper;
import com.google.tsunami.plugins.detectors.rce.cve202333246.Annotations.OobSleepDuration;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Software;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TransportProtocol;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import javax.inject.Inject;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.mockito.stubbing.Answer;

/** Unit tests for {@link RocketMqCve202333246Detector}. */
@RunWith(JUnit4.class)
public class RocketMqCve202333246DetectorTest {

  private static final String MOCK_ROCKETMQ_RESPONSE =
      "{\"code\":0,\"flag\":1,\"language\":\"JAVA\",\"opaque\":0,\"serializeTypeCurrentRPC\":\"JSON\",\"version\":401}";
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2024-12-03T00:00:00.00Z"));

  private final MockWebServer mockCallbackServer = new MockWebServer();

  @Inject private RocketMqCve202333246Detector detector;

  @Bind(lazy = true)
  @OobSleepDuration
  private final int sleepDuration = 1;

  @Bind(lazy = true)
  private final TsunamiSocketFactory socketFactoryMock = Mockito.mock(TsunamiSocketFactory.class);

  @Before
  public void setUp() throws IOException {
    mockCallbackServer.start();
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            FakePayloadGeneratorModule.builder().setCallbackServer(mockCallbackServer).build(),
            Modules.override(new RocketMqCve202333246DetectorBootstrapModule())
                .with(BoundFieldModule.of(this)),
            new HttpClientModule.Builder().build())
        .injectMembers(this);
  }

  @After
  public void tearDown() throws IOException {
    mockCallbackServer.shutdown();
  }

  @Test
  public void detect_whenVulnerable_returnsVulnerability() throws Exception {
    // Make target info
    NetworkService service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(NetworkEndpointUtils.forIpAndPort("127.0.0.1", 10911))
            .setTransportProtocol(TransportProtocol.TCP)
            .setSoftware(Software.newBuilder().setName("RocketMQ"))
            .build();
    TargetInfo targetInfo = TargetInfo.getDefaultInstance();

    // Prepare mock responses
    configureMockSocket(true);
    mockCallbackServer.enqueue(PayloadTestHelper.generateMockSuccessfulCallbackResponse());

    // Start detecting
    DetectionReportList detectionReports = detector.detect(targetInfo, ImmutableList.of(service));

    // Check results
    assertThat(detectionReports.getDetectionReportsList())
        .containsExactly(getVulnerableDetectionReport(detector, service, targetInfo));
  }

  @Test
  public void detect_whenNotVulnerable_returnsNoVulnerability() throws Exception {
    // Make target info
    NetworkService service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(NetworkEndpointUtils.forIpAndPort("127.0.0.1", 10911))
            .setTransportProtocol(TransportProtocol.TCP)
            .setSoftware(Software.newBuilder().setName("RocketMQ"))
            .build();
    TargetInfo targetInfo = TargetInfo.getDefaultInstance();

    // Prepare mock responses
    configureMockSocket(true);
    mockCallbackServer.enqueue(PayloadTestHelper.generateMockUnsuccessfulCallbackResponse());

    // Start detecting
    DetectionReportList detectionReports = detector.detect(targetInfo, ImmutableList.of(service));

    // Check results
    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void detect_whenTargetNotRocketMq_returnsNoVulnerability() throws Exception {
    // Make target info
    NetworkService service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(NetworkEndpointUtils.forIpAndPort("127.0.0.1", 10911))
            .setTransportProtocol(TransportProtocol.TCP)
            .setSoftware(Software.newBuilder().setName("RocketMQ"))
            .build();
    TargetInfo targetInfo = TargetInfo.getDefaultInstance();

    // Prepare mock responses
    configureMockSocket(false);

    // Start detecting
    DetectionReportList detectionReports = detector.detect(targetInfo, ImmutableList.of(service));

    // Check results
    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void detect_whenTcsNotAvailable_returnsNoVulnerability() throws Exception {
    // Simulate No TCS
    mockCallbackServer.shutdown();

    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            FakePayloadGeneratorModule.builder().setCallbackServer(null).build(),
            Modules.override(new RocketMqCve202333246DetectorBootstrapModule())
                .with(BoundFieldModule.of(this)),
            new HttpClientModule.Builder().build())
        .injectMembers(this);

    // Make target info
    NetworkService service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(NetworkEndpointUtils.forIpAndPort("127.0.0.1", 10911))
            .setTransportProtocol(TransportProtocol.TCP)
            .setSoftware(Software.newBuilder().setName("RocketMQ"))
            .build();
    TargetInfo targetInfo = TargetInfo.getDefaultInstance();

    // Prepare mock responses
    configureMockSocket(true);

    // Start detecting
    DetectionReportList detectionReports = detector.detect(targetInfo, ImmutableList.of(service));

    // Check results
    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }

  private DetectionReport getVulnerableDetectionReport(
      RocketMqCve202333246Detector detector, NetworkService service, TargetInfo targetInfo) {
    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(service)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(this.fakeUtcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(detector.getAdvisories().get(0))
        .build();
  }

  private void configureMockSocket(boolean isRocketMq) throws IOException {
    Socket socket = Mockito.mock(Socket.class);
    Mockito.when(socket.getOutputStream())
        .thenAnswer((Answer<ByteArrayOutputStream>) invocation -> new ByteArrayOutputStream());

    if (isRocketMq) {
      Mockito.when(socket.getInputStream())
          .thenAnswer(
              (Answer<ByteArrayInputStream>)
                  invocation ->
                      new ByteArrayInputStream(
                          MOCK_ROCKETMQ_RESPONSE.getBytes(StandardCharsets.UTF_8)));
    } else {
      Mockito.when(socket.getInputStream())
          .thenAnswer(
              (Answer<ByteArrayInputStream>)
                  invocation ->
                      new ByteArrayInputStream(
                          "someOtherService".getBytes(StandardCharsets.UTF_8)));
    }
    Mockito.when(
            socketFactoryMock.createSocket(ArgumentMatchers.anyString(), ArgumentMatchers.anyInt()))
        .thenReturn(socket);
  }
}
