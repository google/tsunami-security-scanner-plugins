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
package com.google.tsunami.plugins.detectors.rce.cve20175638;

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
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Unit tests for {@link ApacheStrutsContentTypeRceDetector}.
 */
@RunWith(JUnit4.class)
public final class ApacheStrutsContentTypeRceDetectorTest {

  // Tsunami provides several testing utilities to make your lives easier with unit test.
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  @Inject
  private ApacheStrutsContentTypeRceDetector detector;

  private MockWebServer mockWebServer;

  private static TargetInfo buildTargetInfo(NetworkEndpoint networkEndpoint) {
    return TargetInfo.newBuilder().addNetworkEndpoints(networkEndpoint).build();
  }

  @Before
  public void setUp() {
    mockWebServer = new MockWebServer();

    Guice.createInjector(
        new FakeUtcClockModule(fakeUtcClock),
        new HttpClientModule.Builder().build(),
        new ApacheStrutsContentTypeRceDetectorBootstrapModule())
        .injectMembers(this);
  }

  @After
  public void tearDown() throws IOException {
    mockWebServer.shutdown();
  }

  @Test
  public void detect_whenWebAppIsVulnerable_reportsVuln() throws IOException {
    String header =
        ApacheStrutsContentTypeRceDetector.DETECTOR_HEADER_NAME + " : "
            + ApacheStrutsContentTypeRceDetector.RANDOM_VALUE;
    startMockWebServer("/", HttpStatus.OK.code(), header);
    ImmutableList<NetworkService> httpServices =
        ImmutableList.of(
            NetworkService.newBuilder()
                .setNetworkEndpoint(
                    forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
                .setTransportProtocol(TransportProtocol.TCP)
                .setSoftware(Software.newBuilder().setName("ApacheStruts"))
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
                                .setValue("CVE_2017_5638"))
                        .setSeverity(Severity.CRITICAL)
                        .setTitle(
                            "Apache Struts Command Injection via Content-Type header "
                                + "(CVE-2017-5638)")
                        .setDescription(
                            "Apache Struts server is vulnerable to CVE-2017-5638."))
                .build());
  }

  @Test
  public void detect_whenWebAppIsNotVulnerable_doesNotReportVuln() throws IOException {
    String header = "IrrelevantHeader: irrelevant";
    startMockWebServer("/", HttpStatus.OK.code(), header);
    ImmutableList<NetworkService> httpServices =
        ImmutableList.of(
            NetworkService.newBuilder()
                .setNetworkEndpoint(
                    forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
                .setTransportProtocol(TransportProtocol.TCP)
                .setSoftware(Software.newBuilder().setName("ApacheStruts"))
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

  private void startMockWebServer(String url, int responseCode, String header) throws IOException {
    mockWebServer.enqueue(new MockResponse().setResponseCode(responseCode).addHeader(header));
    mockWebServer.start();
    mockWebServer.url(url);
  }
}
