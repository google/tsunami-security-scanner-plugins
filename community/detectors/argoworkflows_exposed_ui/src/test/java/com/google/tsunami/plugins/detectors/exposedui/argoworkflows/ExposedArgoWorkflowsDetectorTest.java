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

import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;

import com.google.common.collect.ImmutableList;
import com.google.common.truth.Truth;
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
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.io.IOException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import javax.inject.Inject;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
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
  public void detect_whenVulnerable_returnsVulnerability_Exposed_Ui_Oob() throws IOException {
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
                .setVulnerability(
                    Vulnerability.newBuilder()
                        .setMainId(
                            VulnerabilityId.newBuilder()
                                .setPublisher("TSUNAMI_COMMUNITY")
                                .setValue("ARGOWORKFLOWS_SERVER_EXPOSED"))
                        .setSeverity(Severity.CRITICAL)
                        .setTitle("Argo Workflows server Exposed")
                        .setDescription(
                            "Argo Workflows server is misconfigured. The server is not"
                                + " authenticated. All workflows can be accessed by the public and"
                                + " therefore can be modified resulting in all workflows instances"
                                + " being compromised. The Argo Workflows UI does not support"
                                + " executing OS commands in the hosting machine at this time. We"
                                + " detected this vulnerable Argo Workflows server by creating a"
                                + " test workflow and receiving out-of-band callback")
                        .setRecommendation(
                            "Please disable public access to your Argo Workflows server."))
                .build());
    Truth.assertThat(mockTargetService.getRequestCount()).isEqualTo(2);
    Truth.assertThat(mockCallbackServer.getRequestCount()).isEqualTo(1);
  }

  @Test
  public void detect_ifNotVulnerable_doesNotReportVuln_Exposed_Ui() throws IOException {
    startMockWebServerForTestingWithOob();
    createInjector();
    mockCallbackServer.enqueue(PayloadTestHelper.generateMockUnsuccessfulCallbackResponse());
    mockCallbackServer.enqueue(PayloadTestHelper.generateMockUnsuccessfulCallbackResponse());
    DetectionReportList detectionReports =
        detector.detect(targetInfo, ImmutableList.of(targetNetworkService));
    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
    Truth.assertThat(mockTargetService.getRequestCount()).isEqualTo(2);
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
