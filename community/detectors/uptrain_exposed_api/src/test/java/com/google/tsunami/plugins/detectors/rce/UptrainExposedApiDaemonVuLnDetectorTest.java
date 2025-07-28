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

package com.google.tsunami.plugins.detectors.rce;

import static com.google.common.truth.Truth.assertThat;
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
import com.google.tsunami.plugins.detectors.rce.UptrainExposedApiDetectorAnnotations.UptrainExposedApiOobSleepDuration;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.TargetInfo;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;
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

/** Unit tests for {@link UptrainExposedApiDetector}. */
@RunWith(JUnit4.class)
public final class UptrainExposedApiDaemonVuLnDetectorTest {
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2024-12-03T00:00:00.00Z"));

  private final MockWebServer mockTargetService = new MockWebServer();
  private final MockWebServer mockCallbackServer = new MockWebServer();

  @Inject private UptrainExposedApiDetector detector;

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
  @UptrainExposedApiOobSleepDuration
  private int sleepDuration = 1;

  @Before
  public void setUp() throws IOException {
    mockCallbackServer.start();
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            FakePayloadGeneratorModule.builder()
                .setCallbackServer(mockCallbackServer)
                .setSecureRng(testSecureRandom)
                .build(),
            Modules.override(new UptrainExposedApiDetectorBootstrapModule())
                .with(BoundFieldModule.of(this)))
        .injectMembers(this);
  }

  @After
  public void tearDown() throws Exception {
    mockTargetService.shutdown();
    mockCallbackServer.shutdown();
  }

  @Test
  public void detect_whenVulnerable_returnsVulnerability() throws IOException {
    startMockWebServer();
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
    assertThat(mockTargetService.getRequestCount()).isEqualTo(3);
    assertThat(mockCallbackServer.getRequestCount()).isEqualTo(1);
  }

  @Test
  public void detect_ifNotVulnerable_doesNotReportVuln() throws IOException {
    startMockWebServer();
    mockCallbackServer.enqueue(new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code()));
    DetectionReportList detectionReports =
        detector.detect(targetInfo, ImmutableList.of(targetNetworkService));
    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
    assertThat(mockTargetService.getRequestCount()).isEqualTo(3);
  }

  private void startMockWebServer() throws IOException {
    final Dispatcher dispatcher =
        new Dispatcher() {
          @Override
          public MockResponse dispatch(RecordedRequest request) {
            if (Objects.equals(request.getPath(), "/api/public/project_runs")
                && request.getMethod().equals("GET")
                && request.getBody().readString(StandardCharsets.UTF_8).isEmpty()) {
              if (request.getHeader("uptrain-access-token") != null
                  && request.getHeader("uptrain-access-token").equals("default_key")) {
                return new MockResponse()
                    .setBody(
                        "{\"detail\":[{\"type\":\"missing\",\"loc\":[\"query\",\"project_id\"],\"msg\":\"Field"
                            + " required\",\"input\":null}]}")
                    .setResponseCode(HttpStatus.UNPROCESSABLE_ENTITY.code());
              } else {
                return new MockResponse()
                    .setBody("{\"detail\":\"Unspecified API key\"}")
                    .setResponseCode(HttpStatus.FORBIDDEN.code());
              }
            }
            if (Objects.equals(request.getPath(), "/dashboard/evaluations")
                && request.getMethod().equals("GET")
                && request.getBody().readString(StandardCharsets.UTF_8).isEmpty()) {
              return new MockResponse()
                  .setResponseCode(200)
                  .setBody(
                      "0:[\"development\",[[\"children\",\"evaluations\",[\"evaluations\",{\"children\":[\"__PAGE__\",{}]}],\"$L1\",[null,\"$L2\"]]]]\n"
                          + "3:I[\"(app-pages-browser)");
            }
            if (Objects.equals(request.getPath(), "/api/public/create_project")
                && request.getMethod().equals("POST")) {
              String body = request.getBody().readString(StandardCharsets.UTF_8);
              if (body.contains("project_name")
                  && body.contains("project_description")
                  && body.contains(
                      "__import__(\\'os\\').system(\\'apt update && apt install curl -y &&")
                  && body.contains("project_type")) {
                return new MockResponse()
                    .setBody("{\"project_id\": \"test_project_id\"}")
                    .setResponseCode(200);
              }
              return new MockResponse().setResponseCode(500);
            }
            return new MockResponse().setResponseCode(403);
          }
        };
    mockTargetService.setDispatcher(dispatcher);
    mockTargetService.start();

    targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockTargetService.getHostName(), mockTargetService.getPort()))
            .addSupportedHttpMethods("POST")
            .build();
    targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(targetNetworkService.getNetworkEndpoint())
            .build();
  }
}
