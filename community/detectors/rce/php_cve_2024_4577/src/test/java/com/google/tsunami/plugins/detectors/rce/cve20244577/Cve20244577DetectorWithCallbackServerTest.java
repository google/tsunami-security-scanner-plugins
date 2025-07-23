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
package com.google.tsunami.plugins.detectors.rce.cve20244577;

import static com.google.common.truth.Truth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostname;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;
import com.google.tsunami.plugins.detectors.rce.cve20244577.Annotations.OobSleepDuration;

import com.google.common.collect.ImmutableList;
import com.google.inject.Guice;
import com.google.inject.testing.fieldbinder.Bind;
import com.google.inject.testing.fieldbinder.BoundFieldModule;
import com.google.inject.util.Modules;
import com.google.protobuf.util.JsonFormat;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.callbackserver.proto.PollingResult;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.plugin.payload.testing.FakePayloadGeneratorModule;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TransportProtocol;
import java.io.IOException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import javax.inject.Inject;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link Cve20244577Detector}. */
@RunWith(JUnit4.class)
public final class Cve20244577DetectorWithCallbackServerTest {
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  @Inject private Cve20244577Detector detector;

  private final SecureRandom testSecureRandom =
      new SecureRandom() {
        @Override
        public void nextBytes(byte[] bytes) {
          Arrays.fill(bytes, (byte) 0xFF);
        }
      };

  private MockWebServer mockPhpService;
  private MockWebServer mockCallbackServer;

  @Bind(lazy = true)
  @OobSleepDuration
  private int sleepDuration = 1;

  @Before
  public void setUp() throws IOException {

    mockPhpService = new MockWebServer();
    mockPhpService.start();
    mockCallbackServer = new MockWebServer();
    mockCallbackServer.start();

    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            FakePayloadGeneratorModule.builder()
                .setCallbackServer(mockCallbackServer)
                .setSecureRng(testSecureRandom)
                .build(),
            Modules.override(new Cve20244577DetectorBootstrapModule())
                .with(BoundFieldModule.of(this)))
        .injectMembers(this);
  }

  @After
  public void tearDown() throws Exception {
    mockPhpService.shutdown();
    mockCallbackServer.shutdown();
  }

  @Test
  public void detect_whenVulnerable_reportsVulnerability() throws IOException {
    mockPhpService.enqueue(
        new MockResponse().setResponseCode(HttpStatus.INTERNAL_SERVER_ERROR.code()));

    PollingResult log = PollingResult.newBuilder().setHasHttpInteraction(true).build();
    String body = JsonFormat.printer().preservingProtoFieldNames().print(log);
    mockCallbackServer.enqueue(
        new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody(body));

    NetworkService service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockPhpService.getHostName(), mockPhpService.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("http")
            .build();
    TargetInfo target =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockPhpService.getHostName()))
            .build();

    DetectionReportList detectionReports = detector.detect(target, ImmutableList.of(service));

    assertThat(detectionReports.getDetectionReportsList())
        .containsExactly(
            DetectionReport.newBuilder()
                .setTargetInfo(target)
                .setNetworkService(service)
                .setDetectionTimestamp(
                    Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
                .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
                .setVulnerability(detector.getAdvisories().get(0))
                .build());
  }

  @Test
  public void detect_whenNotVulnerable_doesNotReportVulnerability() {
    mockPhpService.enqueue(
        new MockResponse().setResponseCode(HttpStatus.INTERNAL_SERVER_ERROR.code()));
    // 404 NOT_FOUND means no valid oob logs for mockCallbackServer
    mockCallbackServer.enqueue(new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code()));

    NetworkService service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockPhpService.getHostName(), mockPhpService.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("http")
            .build();
    TargetInfo target =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockPhpService.getHostName()))
            .build();

    DetectionReportList detectionReports = detector.detect(target, ImmutableList.of(service));

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }
}
