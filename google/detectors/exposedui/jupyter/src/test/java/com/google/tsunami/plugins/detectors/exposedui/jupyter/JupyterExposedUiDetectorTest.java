/*
 * Copyright 2020 Google LLC
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
package com.google.tsunami.plugins.detectors.exposedui.jupyter;

import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostname;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;
import static com.google.tsunami.plugins.detectors.exposedui.jupyter.JupyterExposedUiDetector.FINDING_RECOMMENDATION_TEXT;

import com.google.common.collect.ImmutableList;
import com.google.inject.Guice;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkEndpoint;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.Software;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TransportProtocol;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
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

/** Tests for {@link JupyterExposedUiDetector}. */
@RunWith(JUnit4.class)
public final class JupyterExposedUiDetectorTest {

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  private MockWebServer mockWebServer;

  @Inject private JupyterExposedUiDetector detector;

  @Before
  public void setUp() {
    mockWebServer = new MockWebServer();

    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            new JupyterExposedUiDetectorBootstrapModule())
        .injectMembers(this);
  }

  @After
  public void tearDown() throws IOException {
    mockWebServer.shutdown();
  }

  @Test
  public void detect_whenJupyterDoesNotRedirectToLogin_reportsVuln() throws IOException {
    startMockWebServer(
        "/terminals/1",
        HttpStatus.OK.code(),
        "Fake Jupyter Notebook terminal page that connect WebSocket to /terminals/websocket/1");
    ImmutableList<NetworkService> httpServices =
        ImmutableList.of(
            NetworkService.newBuilder()
                .setNetworkEndpoint(
                    forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
                .setTransportProtocol(TransportProtocol.TCP)
                .setSoftware(Software.newBuilder().setName("Jupyter Notebook"))
                .setServiceName("http")
                .build());

    assertThat(
            detector
                .detect(buildTargetInfo(forHostname(mockWebServer.getHostName())), httpServices)
                .getDetectionReportsList())
        .containsExactly(
            DetectionReport.newBuilder()
                .setTargetInfo(buildTargetInfo(forHostname(mockWebServer.getHostName())))
                .setNetworkService(httpServices.get(0))
                .setDetectionTimestamp(Timestamps.fromMillis(fakeUtcClock.millis()))
                .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
                .setVulnerability(
                    Vulnerability.newBuilder()
                        .setMainId(
                            VulnerabilityId.newBuilder()
                                .setPublisher("GOOGLE")
                                .setValue("JUPYTER_NOTEBOOK_EXPOSED_UI"))
                        .setSeverity(Severity.CRITICAL)
                        .setTitle("Jupyter Notebook Exposed Ui")
                        .setDescription("Jupyter Notebook is not password or token protected")
                        .setRecommendation(FINDING_RECOMMENDATION_TEXT))
                .build());
  }

  @Test
  public void detect_whenJupyterRedirectsToLoginPage_doesNotReportVuln() throws IOException {
    startMockWebServer(
        "/terminals/1", HttpStatus.FOUND.code(), "Fake Jupyter Notebook login page.");
    ImmutableList<NetworkService> httpServices =
        ImmutableList.of(
            NetworkService.newBuilder()
                .setNetworkEndpoint(
                    forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
                .setTransportProtocol(TransportProtocol.TCP)
                .setSoftware(Software.newBuilder().setName("Jupyter Notebook"))
                .setServiceName("http")
                .build());

    assertThat(
            detector
                .detect(buildTargetInfo(forHostname(mockWebServer.getHostName())), httpServices)
                .getDetectionReportsList())
        .isEmpty();
  }

  @Test
  public void detect_whenNonJupyterWebApp_ignoresServices() throws IOException {
    startMockWebServer("/terminals/1", HttpStatus.OK.code(), "This is WordPress.");
    ImmutableList<NetworkService> httpServices =
        ImmutableList.of(
            NetworkService.newBuilder()
                .setNetworkEndpoint(
                    forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
                .setTransportProtocol(TransportProtocol.TCP)
                .setSoftware(Software.newBuilder().setName("WordPress"))
                .setServiceName("http")
                .build());

    assertThat(
            detector
                .detect(buildTargetInfo(forHostname(mockWebServer.getHostName())), httpServices)
                .getDetectionReportsList())
        .isEmpty();
  }

  @Test
  public void detect_whenNonHttpNetworkService_ignoresServices() {
    ImmutableList<NetworkService> nonHttpServices =
        ImmutableList.of(
            NetworkService.newBuilder().setServiceName("ssh").build(),
            NetworkService.newBuilder().setServiceName("rdp").build());
    assertThat(
            detector
                .detect(buildTargetInfo(forHostname(mockWebServer.getHostName())), nonHttpServices)
                .getDetectionReportsList())
        .isEmpty();
  }

  @Test
  public void detect_whenEmptyNetworkService_generatesEmptyDetectionReports() {
    assertThat(
            detector
                .detect(
                    buildTargetInfo(forHostname(mockWebServer.getHostName())), ImmutableList.of())
                .getDetectionReportsList())
        .isEmpty();
  }

  private void startMockWebServer(String url, int responseCode, String response)
      throws IOException {
    mockWebServer.enqueue(new MockResponse().setResponseCode(responseCode).setBody(response));
    mockWebServer.start();
    mockWebServer.url(url);
  }

  private static TargetInfo buildTargetInfo(NetworkEndpoint networkEndpoint) {
    return TargetInfo.newBuilder().addNetworkEndpoints(networkEndpoint).build();
  }
}
