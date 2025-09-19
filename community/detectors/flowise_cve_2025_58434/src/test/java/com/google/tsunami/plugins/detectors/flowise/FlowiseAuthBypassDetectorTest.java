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

package com.google.tsunami.plugins.detectors.flowise;

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
import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TextData;
import com.google.tsunami.proto.TransportProtocol;
import java.io.IOException;
import java.time.Instant;
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

@RunWith(JUnit4.class)
public final class FlowiseAuthBypassDetectorTest {
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2025-03-22T00:00:00.00Z"));

  static final String FLOWISE_PRESENT_STR = "<title>Flowise - Build AI Agents, Visually</title>";

  private MockWebServer mockWebServer;

  @Inject private FlowiseAuthBypassDetector detector;

  private NetworkService service;
  private TargetInfo targetInfo;

  @Before
  public void setUp() {
    mockWebServer = new MockWebServer();
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            new FlowiseAuthBypassDetectorBootstrapModule())
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
  public void detect_whenFlowiseVulnerable_returnsVulnerability() throws IOException {
    mockWebServer.setDispatcher(
        new Dispatcher() {
          @Override
          public MockResponse dispatch(RecordedRequest request) throws InterruptedException {
            if ("GET".equals(request.getMethod()) && "/".equals(request.getPath())) {
              return new MockResponse()
                  .setResponseCode(HttpStatus.OK.code())
                  .setBody(FLOWISE_PRESENT_STR);
            } else if ("POST".equals(request.getMethod())
                && "/api/v1/account/forgot-password".equals(request.getPath())) {
              String body = request.getBody().readUtf8();
              assertThat(body).contains("\"email\":\"");
              return new MockResponse()
                  .setResponseCode(HttpStatus.CREATED.code())
                  .setBody(
                      "{\"user\":{\"credential\":\"hashedpassword\",\"tempToken\":\"token123\",\"tokenExpiry\":\"2025-09-18T10:04:26.131Z\"}}");
            } else {
              return new MockResponse().setResponseCode(404);
            }
          }
        });

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
                    detector.getAdvisories().getFirst().toBuilder()
                        .addAdditionalDetails(
                            AdditionalDetail.newBuilder()
                                .setTextData(
                                    TextData.newBuilder()
                                        .setText(
                                            String.format(
                                                "The Flowise instance at %s is"
                                                    + " vulnerable to authentication bypass"
                                                    + " (CVE-2025-58434). A password reset token"
                                                    + " was successfully obtained for the account"
                                                    + " admin@admin.com.",
                                                NetworkServiceUtils.buildWebApplicationRootUrl(
                                                    service))))))
                .build());
  }

  @Test
  public void detect_whenFlowiseNotPresent_returnsNoVulnerability() throws IOException {
    mockWebServer.setDispatcher(
        new Dispatcher() {
          @Override
          public MockResponse dispatch(RecordedRequest request) throws InterruptedException {
            if ("GET".equals(request.getMethod()) && "/".equals(request.getPath())) {
              return new MockResponse()
                  .setResponseCode(HttpStatus.OK.code())
                  .setBody("Some other content");
            } else {
              return new MockResponse().setResponseCode(404);
            }
          }
        });

    DetectionReportList detectionReports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void detect_whenNotVulnerableFlowise_returnsNothing() throws IOException {
    mockWebServer.setDispatcher(
        new Dispatcher() {
          @Override
          public MockResponse dispatch(RecordedRequest request) throws InterruptedException {
            if ("GET".equals(request.getMethod()) && "/".equals(request.getPath())) {
              return new MockResponse()
                  .setResponseCode(HttpStatus.OK.code())
                  .setBody(FLOWISE_PRESENT_STR);
            } else if ("POST".equals(request.getMethod())
                && "/api/v1/account/forgot-password".equals(request.getPath())) {
              return new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("{}");
            } else {
              return new MockResponse().setResponseCode(404);
            }
          }
        });

    DetectionReportList detectionReports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }
}
