/*
 * Copyright 2022 Google LLC
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
package com.google.tsunami.plugins.detectors.exposedui.apachenifi.apivuln;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostname;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;

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
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link ApacheNiFiApiExposedUiDetector}. */
@RunWith(JUnit4.class)
public final class ApacheNiFiApiExposedUiDetectorTest {
  private static final String DEFAULT_BODY_SUPPORTS_LOGIN_FALSE =
      "\"config\":{\"supportsLogin\":false}}";
  private static final String DEFAULT_BODY_SUPPORTS_LOGIN_TRUE =
      "\"config\":{\"supportsLogin\":true}}";

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));
  private MockWebServer mockWebServer;

  @Inject private ApacheNiFiApiExposedUiDetector detector;

  /** Setting up the mock server before the tests. */
  @Before
  public void setUp() {
    mockWebServer = new MockWebServer();
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            new ApacheNiFiApiExposedUiDetectorBootstrapModule())
        .injectMembers(this);
  }

  /** Shutting down the server after the tests. */
  @After
  public void tearDown() throws IOException {
    mockWebServer.shutdown();
  }

  /** Testing the output when the mock server is vulnerable. */
  @Test
  public void detect_whenIsVulnerable_returnsVulnerability() throws Exception {
    mockWebServer.enqueue(buildDefaultResponse().setBody(DEFAULT_BODY_SUPPORTS_LOGIN_FALSE));
    mockWebServer.start();

    ImmutableList<NetworkService> httpServices = buildDefaultServices(mockWebServer);
    assertThat(
            detector
                .detect(buildTargetInfo(forHostname(mockWebServer.getHostName())), httpServices)
                .getDetectionReportsList())
        .containsExactly(
            DetectionReport.newBuilder()
                .setTargetInfo(buildTargetInfo(forHostname(mockWebServer.getHostName())))
                .setNetworkService(httpServices.get(0))
                .setDetectionTimestamp(
                    Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
                .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
                .setVulnerability(
                    Vulnerability.newBuilder()
                        .setMainId(
                            VulnerabilityId.newBuilder()
                                .setPublisher("GOOGLE")
                                .setValue("APACHE_NIFI_API_EXPOSED_UI"))
                        .setSeverity(Severity.CRITICAL)
                        .setTitle("Apache NiFi API Exposed UI")
                        .setDescription("Apache NiFi API is not password or token protected.")
                        .setRecommendation(
                            "Do not expose Apache NiFi API externally. Add authentication or bind"
                                + " it to local network."))
                .build());
    RecordedRequest recordedRequest = mockWebServer.takeRequest();
    assertThat(recordedRequest.getPath()).isEqualTo("/nifi-api/access/config");
  }

  /** Testing the output when the mock server is not vulnerable. */
  @Test
  public void detect_whenNotVulnerable_doesNotReportVulnerability() throws Exception {
    mockWebServer.enqueue(buildDefaultResponse().setBody(DEFAULT_BODY_SUPPORTS_LOGIN_TRUE));
    mockWebServer.start();

    ImmutableList<NetworkService> httpServices = buildDefaultServices(mockWebServer);

    assertThat(
            detector
                .detect(buildTargetInfo(forHostname(mockWebServer.getHostName())), httpServices)
                .getDetectionReportsList())
        .isEmpty();
    RecordedRequest recordedRequest = mockWebServer.takeRequest();
    assertThat(recordedRequest.getPath()).isEqualTo("/nifi-api/access/config");
  }

  /** Testing the output when the mock server returns a response with an empty body. */
  @Test
  public void detect_whenNoConfig_doesNotReportVulnerability() throws Exception {
    mockWebServer.enqueue(buildDefaultResponse());
    mockWebServer.start();

    ImmutableList<NetworkService> httpServices = buildDefaultServices(mockWebServer);

    assertThat(
            detector
                .detect(buildTargetInfo(forHostname(mockWebServer.getHostName())), httpServices)
                .getDetectionReportsList())
        .isEmpty();
    RecordedRequest recordedRequest = mockWebServer.takeRequest();
    assertThat(recordedRequest.getPath()).isEqualTo("/nifi-api/access/config");
  }

  /** Testing the output when non http services are scanned. */
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

  /** Testing the output when the server unexpectedly shuts down. */
  @Test
  public void detect_whenEmptyNetworkService_generatesEmptyDetectionReports() {
    assertThat(
            detector
                .detect(
                    buildTargetInfo(forHostname(mockWebServer.getHostName())), ImmutableList.of())
                .getDetectionReportsList())
        .isEmpty();
  }
  /** Testing the output when an empty NetworkService list is sent. */
  @Test
  public void detect_whenServerShutsDown_generatesEmptyDetectionReports() throws IOException {
    mockWebServer.enqueue(buildDefaultResponse());
    mockWebServer.start();
    ImmutableList<NetworkService> httpServices = buildDefaultServices(mockWebServer);
    mockWebServer.shutdown();

    assertThat(
            detector
                .detect(buildTargetInfo(forHostname(mockWebServer.getHostName())), httpServices)
                .getDetectionReportsList())
        .isEmpty();
  }
  /** Building the target info with the network endpoint. */
  private static TargetInfo buildTargetInfo(NetworkEndpoint networkEndpoint) {
    return TargetInfo.newBuilder().addNetworkEndpoints(networkEndpoint).build();
  }

  /** Building a default mock response. The default mock response is empty with status code 200. */
  private static MockResponse buildDefaultResponse() {
    return new MockResponse().setResponseCode(HttpStatus.OK.code());
  }

  /** Building default services for the mock server. */
  private static ImmutableList<NetworkService> buildDefaultServices(MockWebServer mockWebServer) {
    return ImmutableList.of(
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setSoftware(Software.newBuilder().setName("http"))
            .setServiceName("http")
            .build());
  }
}
