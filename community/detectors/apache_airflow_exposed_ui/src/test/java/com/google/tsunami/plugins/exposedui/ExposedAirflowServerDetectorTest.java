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

package com.google.tsunami.plugins.exposedui;

import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;
import static com.google.tsunami.plugins.exposedui.ExposedAirflowServerDetector.RECOMMENDATION;

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

/** Unit tests for the {@link ExposedAirflowServerDetector}. */
@RunWith(JUnit4.class)
public final class ExposedAirflowServerDetectorTest {
  private final MockWebServer mockTargetService = new MockWebServer();
  private final MockWebServer mockCallbackServer = new MockWebServer();
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  @Inject private ExposedAirflowServerDetector detector;

  private void createInjector() {
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            FakePayloadGeneratorModule.builder().setCallbackServer(mockCallbackServer).build(),
            new ExposedAirflowServerDetectorModule())
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
  public void detect_withCallbackServer_onVulnerableTarget_returnsVulnerability()
      throws IOException {
    startMockWebServer();
    createInjector();
    mockCallbackServer.enqueue(PayloadTestHelper.generateMockSuccessfulCallbackResponse());
    NetworkService targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockTargetService.getHostName(), mockTargetService.getPort()))
            .addSupportedHttpMethods("POST")
            .build();
    TargetInfo targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(targetNetworkService.getNetworkEndpoint())
            .build();

    DetectionReportList detectionReports =
        detector.detect(targetInfo, ImmutableList.of(targetNetworkService));

    Truth.assertThat(mockCallbackServer.getRequestCount()).isEqualTo(1);
    Truth.assertThat(mockTargetService.getRequestCount()).isEqualTo(2);
    assertThat(detectionReports.getDetectionReportsList())
        .comparingExpectedFieldsOnly()
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
                                .setValue("APACHE_AIRFLOW_SERVER_EXPOSED"))
                        .setSeverity(Severity.CRITICAL)
                        .setTitle("Exposed Apache Airflow Server")
                        .setDescription(
                            "Apache Airflow Server is misconfigured and can be accessed publicly,"
                                + " Tsunami security scanner confirmed this by sending an HTTP"
                                + " request with test connection API and receiving the"
                                + " corresponding callback on tsunami callback server.")
                        .setRecommendation(RECOMMENDATION))
                .build());
  }

  @Test
  public void detect_withCallbackServer_butNoCallback_returnsEmpty() throws IOException {
    mockTargetService.enqueue(new MockResponse().setResponseCode(400));
    mockTargetService.enqueue(new MockResponse().setResponseCode(400));
    mockTargetService.enqueue(new MockResponse().setResponseCode(400));
    mockTargetService.start();
    createInjector();
    mockCallbackServer.enqueue(PayloadTestHelper.generateMockUnsuccessfulCallbackResponse());
    NetworkService targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockTargetService.getHostName(), mockTargetService.getPort()))
            .addSupportedHttpMethods("POST")
            .build();
    TargetInfo targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(targetNetworkService.getNetworkEndpoint())
            .build();

    DetectionReportList detectionReports =
        detector.detect(targetInfo, ImmutableList.of(targetNetworkService));

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void detect_no_airflow_webservice_returnsEmpty() throws IOException {
    mockTargetService.enqueue(new MockResponse().setResponseCode(400));
    mockTargetService.start();
    createInjector();
    mockCallbackServer.enqueue(PayloadTestHelper.generateMockUnsuccessfulCallbackResponse());
    NetworkService targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockTargetService.getHostName(), mockTargetService.getPort()))
            .addSupportedHttpMethods("POST")
            .addSupportedHttpMethods("GET")
            .build();
    TargetInfo targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(targetNetworkService.getNetworkEndpoint())
            .build();

    DetectionReportList detectionReports =
        detector.detect(targetInfo, ImmutableList.of(targetNetworkService));

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void detect_withResponseMatching_insteadof_withoutCallbackServer() throws IOException {
    startMockWebServer();
    createInjector();
    mockCallbackServer.enqueue(PayloadTestHelper.generateMockUnsuccessfulCallbackResponse());
    NetworkService targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockTargetService.getHostName(), mockTargetService.getPort()))
            .addSupportedHttpMethods("POST")
            .build();
    TargetInfo targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(targetNetworkService.getNetworkEndpoint())
            .build();

    DetectionReportList detectionReports =
        detector.detect(targetInfo, ImmutableList.of(targetNetworkService));

    Truth.assertThat(mockCallbackServer.getRequestCount()).isEqualTo(1);
    Truth.assertThat(mockTargetService.getRequestCount()).isEqualTo(3);
    assertThat(detectionReports.getDetectionReportsList())
        .comparingExpectedFieldsOnly()
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
                                .setValue("APACHE_AIRFLOW_SERVER_EXPOSED"))
                        .setSeverity(Severity.HIGH)
                        .setTitle("Exposed Apache Airflow Server")
                        .setDescription(
                            "Apache Airflow Server is misconfigured and can be accessed publicly,"
                                + " We confirmed this by checking API endpoint and matching the"
                                + " responses with our pattern.")
                        .setRecommendation(RECOMMENDATION))
                .build());
  }

  private void startMockWebServer() throws IOException {
    final Dispatcher dispatcher =
        new Dispatcher() {

          @Override
          public MockResponse dispatch(RecordedRequest request) {
            switch (request.getPath()) {
              case "/login":
                return new MockResponse()
                    .setResponseCode(200)
                    .setBody(
                        "<!DOCTYPE html>\n"
                            + "<html>\n"
                            + "  <head>\n"
                            + "    <title>Sign In - Airflow\n"
                            + "  \n"
                            + "</title>"
                            + " </head>"
                            + "<a href=\"https://airflow.apache.org\">Airflow Website</a>"
                            + "</html>");
              case "/api/v1/dags":
                return new MockResponse()
                    .setResponseCode(200)
                    .setBody(
                        "{\"dags\": [{\"next_dagrun_create_after\":"
                            + " \"2019-08-24T14:15:22Z\"}],\"total_entries\": 0}");
              case "/api/v1/connections/test":
                return new MockResponse().setResponseCode(200);
              default:
                return new MockResponse().setResponseCode(400);
            }
          }
        };
    mockTargetService.setDispatcher(dispatcher);
    mockTargetService.start();
    mockTargetService.url("/");
  }
}
