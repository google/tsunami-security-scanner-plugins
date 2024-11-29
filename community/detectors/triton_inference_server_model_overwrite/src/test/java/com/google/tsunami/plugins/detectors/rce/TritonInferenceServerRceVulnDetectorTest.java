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

package com.google.tsunami.plugins.detectors.rce;

import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;
import static com.google.tsunami.plugins.detectors.rce.TritonInferenceServerRceVulnDetector.MODEL_CONFIG;
import static com.google.tsunami.plugins.detectors.rce.TritonInferenceServerRceVulnDetector.PYTHON_MODEL;
import static com.google.tsunami.plugins.detectors.rce.TritonInferenceServerRceVulnDetector.UPLOAD_CONFIG_PAYLOAD;
import static com.google.tsunami.plugins.detectors.rce.TritonInferenceServerRceVulnDetector.UPLOAD_MODEL_PAYLOAD;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.collect.ImmutableList;
import com.google.common.truth.Truth;
import com.google.inject.Guice;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.plugin.payload.testing.FakePayloadGeneratorModule;
import com.google.tsunami.plugin.payload.testing.PayloadTestHelper;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
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

/** Unit tests for {@link TritonInferenceServerRceVulnDetector}. */
@RunWith(JUnit4.class)
public final class TritonInferenceServerRceVulnDetectorTest {
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2024-12-03T00:00:00.00Z"));

  private final MockWebServer mockTargetService = new MockWebServer();
  private final MockWebServer mockCallbackServer = new MockWebServer();

  @Inject private TritonInferenceServerRceVulnDetector detector;

  TargetInfo targetInfo;
  NetworkService targetNetworkService;
  private final SecureRandom testSecureRandom =
      new SecureRandom() {
        @Override
        public void nextBytes(byte[] bytes) {
          Arrays.fill(bytes, (byte) 0xFF);
        }
      };

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
            new TritonInferenceServerRceDetectorBootstrapModule())
        .injectMembers(this);
  }

  @After
  public void tearDown() throws Exception {
    mockTargetService.shutdown();
    mockCallbackServer.shutdown();
  }

  @Test
  public void detect_whenVulnerable_returnsVulnerability() throws IOException {
    startMockWebServer(true);
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
                                .setValue("TritonInferenceServerRce"))
                        .setSeverity(Severity.CRITICAL)
                        .setTitle("Triton Inference Server RCE")
                        .setDescription(
                            "This detector checks triton inference server RCE with explicit"
                                + " model-control option enabled. \n"
                                + "All versions of triton inference server with the"
                                + " `--model-control explicit` option allows for loaded models to"
                                + " be overwritten by  malicious models and lead to RCE.")
                        .setRecommendation(
                            "don't use `--model-control explicit` option with public access")
                        .addRelatedId(
                            VulnerabilityId.newBuilder()
                                .setPublisher("CVE")
                                .setValue("CVE-2023-31036")))
                .build());
    Truth.assertThat(mockTargetService.getRequestCount()).isEqualTo(5);
    Truth.assertThat(mockCallbackServer.getRequestCount()).isEqualTo(1);
  }

  @Test
  public void detect_ifNotVulnerable_doesNotReportVuln() throws IOException {
    startMockWebServer(false);
    DetectionReportList detectionReports =
        detector.detect(targetInfo, ImmutableList.of(targetNetworkService));
    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
    Truth.assertThat(mockTargetService.getRequestCount()).isEqualTo(1);
  }

  private void startMockWebServer(boolean withAnExistingModel) throws IOException {
    final Dispatcher dispatcher =
        new Dispatcher() {
          @Override
          public MockResponse dispatch(RecordedRequest request) {
            // get an existing model name
            if (withAnExistingModel
                && Objects.equals(request.getPath(), "/v2/repository/index")
                && request.getMethod().equals("POST")) {
              return new MockResponse().setBody("[{\"name\":\"metasploit\"}]").setResponseCode(200);
            }
            // Attempting to unload model
            if (Objects.equals(request.getPath(), "/v2/repository/models/metasploit/unload")) {
              if (request.getMethod().equals("POST")) {
                return new MockResponse().setResponseCode(200);
              }
            }
            // Creating model repo layout: uploading the model
            // Or Creating model repo layout: uploading model config
            if (Objects.equals(request.getPath(), "/v2/repository/models/metasploit/load")) {
              if (request.getMethod().equals("POST")
                  && !request.getBody().readString(StandardCharsets.UTF_8).isEmpty()
                  && Objects.requireNonNull(request.getHeaders().get("Content-Type"))
                      .equals("application/json")
                  && (Objects.equals(
                          request.getBody().readString(StandardCharsets.UTF_8),
                          String.format(
                              UPLOAD_CONFIG_PAYLOAD,
                              Base64.getEncoder()
                                  .encodeToString(
                                      String.format(MODEL_CONFIG, "metasploit").getBytes(UTF_8))))
                      || request
                          .getBody()
                          .readString(StandardCharsets.UTF_8)
                          .startsWith(
                              String.format(
                                  UPLOAD_MODEL_PAYLOAD,
                                  Base64.getEncoder()
                                      .encodeToString(
                                          PYTHON_MODEL.substring(0, 20).getBytes(UTF_8)))))) {
                return new MockResponse().setResponseCode(200);
              }
            }
            // Loading model to trigger payload
            if (Objects.equals(request.getPath(), "/v2/repository/models/metasploit/load")) {
              if (request.getMethod().equals("POST")
                  && request.getBody().readString(StandardCharsets.UTF_8).isEmpty()) {
                return new MockResponse().setResponseCode(200);
              }
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
            .build();
    targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(targetNetworkService.getNetworkEndpoint())
            .build();
  }
}
