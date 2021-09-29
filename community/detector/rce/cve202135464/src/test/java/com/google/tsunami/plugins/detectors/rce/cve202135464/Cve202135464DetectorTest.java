/*
 * Copyright 2021 Google LLC
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
package com.google.tsunami.plugins.detectors.rce.cve202135464;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostname;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;

import com.google.common.collect.ImmutableList;
import com.google.inject.Guice;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
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

/** Unit tests for {@link Cve202135464Detector}. */
@RunWith(JUnit4.class)
public final class Cve202135464DetectorTest {
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  @Inject private Cve202135464Detector detector;

  private MockWebServer mockWebServer;

  @Before
  public void setUp() throws IOException {
    mockWebServer = new MockWebServer();
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new Cve202135464DetectorBootstrapModule(),
            new HttpClientModule.Builder().build())
        .injectMembers(this);
    mockWebServer.start();
  }

  @After
  public void tearDown() throws IOException {
    mockWebServer.shutdown();
  }

  @Test
  public void detect_whenFlinkVulnerable_returnsVulnerability()
      throws IOException, InterruptedException {
    enqueueMockVulnerabilityResponse();
    NetworkService service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("http")
            .build();
    TargetInfo targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockWebServer.getHostName()))
            .build();

    DetectionReportList detectionReports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(mockWebServer.getRequestCount()).isEqualTo(1);
    RecordedRequest detectionReportRequest = mockWebServer.takeRequest();
    assertThat(detectionReportRequest.getMethod()).isEqualTo("GET");
    assertThat(detectionReportRequest.getPath()).endsWith("..;/ccversion/Version");
    assertThat(detectionReportRequest.getHeader("Content-Length")).isEqualTo("970");
    assertThat(detectionReports.getDetectionReportsList())
        .containsExactly(
            DetectionReport.newBuilder()
                .setTargetInfo(targetInfo)
                .setNetworkService(service)
                .setDetectionTimestamp(
                    Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
                .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
                .setVulnerability(
                    Vulnerability.newBuilder()
                        .setMainId(
                            VulnerabilityId.newBuilder()
                                .setPublisher("0xtavi")
                                .setValue("CVE_2021_35464"))
                        .setSeverity(Severity.CRITICAL)
                        .setTitle("Pre-auth RCE in OpenAM 14.6.3/ForgeRock AM 7.0 (CVE-2021-35464)")
                        .setDescription("OpenAM server before 14.6.3 and ForgeRock AM server before 7.0 have "
                        + "a Java deserialization vulnerability in the jato.pageSession "
                        + "parameter on multiple pages. The exploitation does not require "
                        + "authentication, and remote code execution can be triggered by "
                        + "sending a single crafted /ccversion/* request to the server. "
                        + "The vulnerability exists due to the usage of Sun ONE Application "
                        + "Framework (JATO) found in versions of Java 8 or earlier. The issue "
                        + "was fixed in commit a267913b97002228c2df45f849151e9c373bc47f from "
                        + "OpenIdentityPlatform/OpenAM:master."))
                .build());
  }

  @Test
  public void detect_whenFlinkNotVulnerable_returnsNoVulnerability()
      throws IOException, InterruptedException {
    enqueueMockVulnerabilityResponse(mockResponse);
    NetworkService service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("http")
            .build();
    TargetInfo targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockWebServer.getHostName()))
            .build();

    DetectionReportList detectionReports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(mockWebServer.getRequestCount()).isEqualTo(1);
    RecordedRequest detectionReportRequest = mockWebServer.takeRequest();
    assertThat(detectionReportRequest.getMethod()).isEqualTo("GET");
    assertThat(detectionReportRequest.getPath()).endsWith("..;/ccversion/Version");
    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }

  private void enqueueMockVulnerabilityResponse() {
    MockResponse mockResponse =
        new MockResponse().setResponseCode(200).setPath("/..;/ccversion/Version");
    mockWebServer.enqueue(mockResponse);
  }

