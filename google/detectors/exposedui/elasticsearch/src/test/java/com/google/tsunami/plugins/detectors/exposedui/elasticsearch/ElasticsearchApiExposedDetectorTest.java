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
package com.google.tsunami.plugins.detectors.exposedui.elasticsearch;

import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostname;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.collect.ImmutableList;
import com.google.common.io.Resources;
import com.google.inject.Guice;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkEndpoint;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.Software;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TextData;
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

/** Unit tests for {@link ElasticsearchApiExposedDetector}. */
@RunWith(JUnit4.class)
public final class ElasticsearchApiExposedDetectorTest {
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  private MockWebServer mockWebServer;

  @Inject private ElasticsearchApiExposedDetector detector;

  @Before
  public void setUp() {
    mockWebServer = new MockWebServer();

    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            new ElasticsearchApiExposedDetectorBootstrapModule())
        .injectMembers(this);
  }

  @After
  public void tearDown() throws IOException {
    mockWebServer.shutdown();
  }

  @Test
  public void detect_whenApiEndpointExposed_reportsVuln() throws IOException {
    startMockWebServer(
        "/",
        HttpStatus.OK.code(),
        Resources.toString(
            Resources.getResource(this.getClass(), "testdata/validApiResponse.json"), UTF_8));
    NetworkService httpService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setSoftware(Software.newBuilder().setName("Elasticsearch API"))
            .setServiceName("http")
            .build();
    ImmutableList<NetworkService> httpServices = ImmutableList.of(httpService);

    assertThat(
            detector
                .detect(buildTargetInfo(forHostname(mockWebServer.getHostName())), httpServices)
                .getDetectionReportsList())
        .containsExactly(
            DetectionReport.newBuilder()
                .setTargetInfo(buildTargetInfo(forHostname(mockWebServer.getHostName())))
                .setNetworkService(httpService)
                .setDetectionTimestamp(Timestamps.fromMillis(fakeUtcClock.millis()))
                .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
                .setVulnerability(
                    Vulnerability.newBuilder()
                        .setMainId(
                            VulnerabilityId.newBuilder()
                                .setPublisher("GOOGLE")
                                .setValue("ELASTICSEARCH_API_EXPOSED"))
                        .setSeverity(Severity.CRITICAL)
                        .setTitle("Elasticsearch API Exposed")
                        .setDescription("Elasticsearch API endpoint is exposed.")
                        .setRecommendation(
                            "Do not expose Elasticsearch externally.\n"
                                + "Bind it to localhost, or run it on a host that is not exposed to"
                                + " the Internet.")
                        .addAdditionalDetails(
                            AdditionalDetail.newBuilder()
                                .setTextData(
                                    TextData.newBuilder()
                                        .setText(
                                            String.format(
                                                "The Elasticsearch REST API endpoint at"
                                                    + " http://%s:%d/ is exposed.",
                                                mockWebServer.getHostName(),
                                                mockWebServer.getPort())))))
                .build());
  }

  @Test
  public void detect_whenApiEndpointNotFound_doesNotReportVuln() throws IOException {
    startMockWebServer("/", HttpStatus.NOT_FOUND.code(), "");
    ImmutableList<NetworkService> httpServices =
        ImmutableList.of(
            NetworkService.newBuilder()
                .setNetworkEndpoint(
                    forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
                .setTransportProtocol(TransportProtocol.TCP)
                .setSoftware(Software.newBuilder().setName("Elasticsearch API"))
                .setServiceName("http")
                .build());

    assertThat(
            detector
                .detect(buildTargetInfo(forHostname(mockWebServer.getHostName())), httpServices)
                .getDetectionReportsList())
        .isEmpty();
  }

  @Test
  public void detect_whenApiEndpointReturnsEmptyBody_doesNotReportVuln() throws IOException {
    startMockWebServer("/", HttpStatus.OK.code(), "");
    NetworkService httpService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setSoftware(Software.newBuilder().setName("Elasticsearch API"))
            .setServiceName("http")
            .build();
    ImmutableList<NetworkService> httpServices = ImmutableList.of(httpService);

    assertThat(
            detector
                .detect(buildTargetInfo(forHostname(mockWebServer.getHostName())), httpServices)
                .getDetectionReportsList())
        .isEmpty();
  }

  @Test
  public void detect_whenApiEndpointReturnsEmptyJson_doesNotReportVuln() throws IOException {
    startMockWebServer("/", HttpStatus.OK.code(), "{}");
    NetworkService httpService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setSoftware(Software.newBuilder().setName("Elasticsearch API"))
            .setServiceName("http")
            .build();
    ImmutableList<NetworkService> httpServices = ImmutableList.of(httpService);

    assertThat(
            detector
                .detect(buildTargetInfo(forHostname(mockWebServer.getHostName())), httpServices)
                .getDetectionReportsList())
        .isEmpty();
  }

  @Test
  public void detect_whenNonElasticsearchWebApp_ignoresServices() throws IOException {
    startMockWebServer("/", HttpStatus.OK.code(), "This is WordPress.");
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
