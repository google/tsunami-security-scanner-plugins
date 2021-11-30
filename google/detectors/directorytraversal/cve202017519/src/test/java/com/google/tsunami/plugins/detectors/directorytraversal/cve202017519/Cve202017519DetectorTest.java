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
package com.google.tsunami.plugins.detectors.directorytraversal.cve202017519;

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

/** Unit tests for {@link Cve202017519Detector}. */
@RunWith(JUnit4.class)
public final class Cve202017519DetectorTest {
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  @Inject private Cve202017519Detector detector;

  private MockWebServer mockWebServer;

  @Before
  public void setUp() throws IOException {
    mockWebServer = new MockWebServer();
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new Cve202017519DetectorBootstrapModule(),
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
    enqueueMockIsFlinkResponse();
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

    assertThat(mockWebServer.getRequestCount()).isEqualTo(2);
    RecordedRequest flinkCheckRequest = mockWebServer.takeRequest();
    assertThat(flinkCheckRequest.getMethod()).isEqualTo("GET");
    RecordedRequest detectionReportRequest = mockWebServer.takeRequest();
    assertThat(detectionReportRequest.getMethod()).isEqualTo("GET");
    assertThat(detectionReportRequest.getPath()).endsWith("..%252fetc%252fpasswd");
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
                                .setPublisher("GOOGLE")
                                .setValue("CVE_2020_17519"))
                        .setSeverity(Severity.CRITICAL)
                        .setTitle("Apache Flink Unauthorized Directory Traversal (CVE-2020-17519)")
                        .setDescription(
                            "A change introduced in Apache Flink 1.11.0 (and released in 1.11.1 "
                                + "and 1.11.2 as well) allows attackers to read any file on the "
                                + "local filesystem of the JobManager through the REST interface "
                                + "of the JobManager process. Access is restricted to files "
                                + "accessible by the JobManager process. All users should upgrade "
                                + "to Flink 1.11.3 or 1.12.0 if their Flink instance(s) are "
                                + "exposed. The issue was fixed in commit "
                                + "b561010b0ee741543c3953306037f00d7a9f0801 from "
                                + "apache/flink:master."))
                .build());
  }

  @Test
  public void detect_whenFlinkNotVulnerable_returnsNoVulnerability()
      throws IOException, InterruptedException {
    enqueueMockIsFlinkResponse();
    MockResponse mockResponse =
        new MockResponse()
            .setResponseCode(404)
            .setBody("{\"errors\":[\"This file does not exist in JobManager log dir.\"]}");
    mockWebServer.enqueue(mockResponse);
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

    assertThat(mockWebServer.getRequestCount()).isEqualTo(2);
    RecordedRequest flinkCheckRequest = mockWebServer.takeRequest();
    assertThat(flinkCheckRequest.getMethod()).isEqualTo("GET");
    RecordedRequest detectionReportRequest = mockWebServer.takeRequest();
    assertThat(detectionReportRequest.getMethod()).isEqualTo("GET");
    assertThat(detectionReportRequest.getPath()).endsWith("..%252fetc%252fpasswd");
    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void detect_whenNotFlink_returnsNoVulnerability()
      throws IOException, InterruptedException {
    MockResponse mockIsNotFlinkResponse =
        new MockResponse()
            .setResponseCode(200)
            .setBody("<!DOCTYPE html><html><head></head><body>HELLO WORLD</body></html>");
    mockWebServer.enqueue(mockIsNotFlinkResponse);
    // Enqueue false positive.
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
    RecordedRequest flinkCheckRequest = mockWebServer.takeRequest();
    assertThat(flinkCheckRequest.getMethod()).isEqualTo("GET");
    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }

  private void enqueueMockVulnerabilityResponse() {
    MockResponse mockResponse =
        new MockResponse().setResponseCode(200).setBody("root:x:0:0:root:/root:/bin/bash");
    mockWebServer.enqueue(mockResponse);
  }

  private void enqueueMockIsFlinkResponse() {
    MockResponse mockIsFlinkResponse =
        new MockResponse()
            .setResponseCode(200)
            .setBody(
                "{\"logs\":[{\"name\":\"flink--standalonesession-0-7c54266a7265.log\","
                    + "\"size\":14258}]}");
    mockWebServer.enqueue(mockIsFlinkResponse);
  }
}
