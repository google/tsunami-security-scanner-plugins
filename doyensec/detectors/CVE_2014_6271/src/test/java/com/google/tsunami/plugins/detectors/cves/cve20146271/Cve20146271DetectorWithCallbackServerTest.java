/*
 * Copyright 2025 Google LLC
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

package com.google.tsunami.plugins.detectors.cves.cve20146271;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostname;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;

import com.google.common.collect.ImmutableList;
import com.google.inject.Guice;
import com.google.inject.testing.fieldbinder.Bind;
import com.google.inject.testing.fieldbinder.BoundFieldModule;
import com.google.inject.util.Modules;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.plugin.payload.testing.FakePayloadGeneratorModule;
import com.google.tsunami.plugin.payload.testing.PayloadTestHelper;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Software;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TransportProtocol;
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

/** Unit tests for {@link Cve20146271Detector}. */
@RunWith(JUnit4.class)
public final class Cve20146271DetectorWithCallbackServerTest {
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2000-01-01T00:00:00.00Z"));

  private final MockWebServer mockWebServer = new MockWebServer();
  private final MockWebServer mockCallbackServer = new MockWebServer();
  private TargetInfo targetInfo;

  @Bind(lazy = true)
  @Annotations.OobSleepDuration
  private final int sleepDuration = 0;

  @Inject private Cve20146271Detector detector;

  @Before
  public void setUp() throws IOException {
    mockWebServer.start();
    mockCallbackServer.start();
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            FakePayloadGeneratorModule.builder().setCallbackServer(mockCallbackServer).build(),
            Modules.override(new Cve20146271DetectorBootstrapModule())
                .with(BoundFieldModule.of(this)))
        .injectMembers(this);
    targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockWebServer.getHostName()))
            .build();
  }

  @After
  public void tearDown() throws Exception {
    mockCallbackServer.shutdown();
    mockWebServer.shutdown();
  }

  @Test
  public void detect_whenVulnerableAndTcsAvailable_reportsCriticalVulnerability()
      throws IOException {
    mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.OK.code()));
    mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code()));
    mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code()));
    mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.OK.code()));
    mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code()));
    mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code()));
    mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code()));
    mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code()));

    mockCallbackServer.enqueue(PayloadTestHelper.generateMockSuccessfulCallbackResponse());

    NetworkService targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setSoftware(Software.newBuilder().setName("http"))
            .setServiceName("http")
            .build();

    DetectionReportList detectionReports =
        detector.detect(targetInfo, ImmutableList.of(targetNetworkService));
    assertThat(mockWebServer.getRequestCount()).isEqualTo(8);
    assertThat(mockCallbackServer.getRequestCount()).isEqualTo(1);

    assertThat(detectionReports.getDetectionReportsList())
        .containsExactly(
            DetectionReport.newBuilder()
                .setTargetInfo(targetInfo)
                .setNetworkService(targetNetworkService)
                .setDetectionTimestamp(
                    Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
                .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
                .setVulnerability(detector.getAdvisories().get(0))
                .build());
  }

  @Test
  public void detect_whenNotVulnerableAndTcsAvailable_reportsNoVulnerability() {
    mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.OK.code()));
    mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code()));
    mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code()));
    mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.OK.code()));
    mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code()));
    mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code()));
    mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code()));
    mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code()));

    mockCallbackServer.enqueue(PayloadTestHelper.generateMockUnsuccessfulCallbackResponse());

    NetworkService targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setSoftware(Software.newBuilder().setName("http"))
            .setServiceName("http")
            .build();

    DetectionReportList detectionReports =
        detector.detect(targetInfo, ImmutableList.of(targetNetworkService));

    assertThat(mockWebServer.getRequestCount()).isEqualTo(8);
    assertThat(mockCallbackServer.getRequestCount()).isEqualTo(1);

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }
}
