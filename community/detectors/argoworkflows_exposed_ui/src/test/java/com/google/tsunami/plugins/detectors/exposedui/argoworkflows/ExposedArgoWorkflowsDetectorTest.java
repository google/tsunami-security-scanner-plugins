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

package com.google.tsunami.plugins.detectors.exposedui.argoworkflows;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;

import com.google.common.collect.ImmutableList;
import com.google.inject.Guice;
import com.google.inject.testing.fieldbinder.Bind;
import com.google.inject.testing.fieldbinder.BoundFieldModule;
import com.google.inject.util.Modules;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.plugin.payload.testing.FakePayloadGeneratorModule;
import com.google.tsunami.plugin.payload.testing.PayloadTestHelper;
import com.google.tsunami.plugins.detectors.exposedui.argoworkflows.Annotations.OobSleepDuration;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.TargetInfo;
import java.io.IOException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import javax.inject.Inject;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import okhttp3.tls.HandshakeCertificates;
import okhttp3.tls.HeldCertificate;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link ExposedArgoWorkflowsDetector}. */
@RunWith(JUnit4.class)
public final class ExposedArgoWorkflowsDetectorTest {
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2024-12-03T00:00:00.00Z"));

  private final MockWebServer mockTargetService = new MockWebServer();
  private final MockWebServer mockCallbackServer = new MockWebServer();

  @Inject private ExposedArgoWorkflowsDetector detector;

  TargetInfo targetInfo;
  NetworkService targetNetworkService;
  private final SecureRandom testSecureRandom =
      new SecureRandom() {
        @Override
        public void nextBytes(byte[] bytes) {
          Arrays.fill(bytes, (byte) 0xFF);
        }
      };

  @Bind(lazy = true)
  @OobSleepDuration
  private int sleepDuration = 1;

  private void createInjector() {
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            FakePayloadGeneratorModule.builder()
                .setCallbackServer(mockCallbackServer)
                .setSecureRng(testSecureRandom)
                .build(),
            Modules.override(new ExposedArgoWorkflowsDetectorBootstrapModule())
                .with(BoundFieldModule.of(this)))
        .injectMembers(this);
  }

  @Before
  public void setUp() throws IOException {
    mockCallbackServer.start();
  }

  @After
  public void tearDown() throws Exception {
    mockTargetService.shutdown();
    mockCallbackServer.shutdown();
  }

  @Test
  public void detect_whenVulnerable_returnsVulnerability_exposed_ui_oob() throws IOException {
    startMockWebServerForTestingWithOob();
    createInjector();
    mockCallbackServer.enqueue(PayloadTestHelper.generateMockSuccessfulCallbackResponse());

    DetectionReportList detectionReports =
        detector.detect(targetInfo, ImmutableList.of(targetNetworkService));

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
    assertThat(mockTargetService.getRequestCount()).isEqualTo(2);
    assertThat(mockCallbackServer.getRequestCount()).isEqualTo(1);
  }

  @Test
  public void detect_ifNotVulnerable_doesNotReportVuln_exposed_ui() throws IOException {
    startMockWebServerForTestingWithOob();
    createInjector();
    mockCallbackServer.enqueue(PayloadTestHelper.generateMockUnsuccessfulCallbackResponse());
    mockCallbackServer.enqueue(PayloadTestHelper.generateMockUnsuccessfulCallbackResponse());
    DetectionReportList detectionReports =
        detector.detect(targetInfo, ImmutableList.of(targetNetworkService));
    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
    assertThat(mockTargetService.getRequestCount()).isEqualTo(2);
  }

  private void startMockWebServerForTestingWithOob() throws IOException {
    final Dispatcher dispatcher =
        new Dispatcher() {
          @Override
          public MockResponse dispatch(RecordedRequest request) {
            if (request.getPath().equals("/api/v1/workflows/")
                && request.getMethod().equals("GET")) {
              return new MockResponse()
                  .setBody("{\"items\":[{\"metadata\":{\"name\":\"default\"}}]}")
                  .setResponseCode(200);
            }
            if (request.getPath().equals("/api/v1/workflows/default")
                && request.getMethod().equals("POST")) {
              return new MockResponse().setResponseCode(200);
            }
            return new MockResponse().setBody("[{}]").setResponseCode(200);
          }
        };
    mockTargetService.setDispatcher(dispatcher);
    mockTargetService.start();
    mockTargetService.url("/");
    // Generate a self-signed certificate
    HeldCertificate localhostCertificate =
        new HeldCertificate.Builder().addSubjectAlternativeName("localhost").build();
    HandshakeCertificates serverCertificates =
        new HandshakeCertificates.Builder().heldCertificate(localhostCertificate).build();
    mockTargetService.useHttps(serverCertificates.sslSocketFactory(), false);

    targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockTargetService.getHostName(), mockTargetService.getPort()))
            .addSupportedHttpMethods("POST")
            .addSupportedHttpMethods("GET")
            .build();
    targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(targetNetworkService.getNetworkEndpoint())
            .build();
  }
}
