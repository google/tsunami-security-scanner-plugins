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

package com.google.tsunami.plugins.detectors.cve.cve20248438;

import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostname;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;
import static com.google.tsunami.plugins.detectors.cve.cve20248438.Cve20248438Detector.VULN_DESCRIPTION;

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
import com.google.tsunami.proto.Software;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TransportProtocol;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import java.io.IOException;
import java.time.Instant;
import javax.inject.Inject;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link Cve20248438Detector}. */
@RunWith(JUnit4.class)
public final class Cve20248438DetectorTest {
  // Tsunami provides several testing utilities to make your lives easier with unit test.
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  @Inject private Cve20248438Detector detector;

  private MockWebServer mockWebServer;
  private NetworkService service;
  private TargetInfo targetInfo;

  @Before
  public void setUp() {
    mockWebServer = new MockWebServer();
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new Cve20248438DetectorBootstrapModule(),
            new HttpClientModule.Builder().build())
        .injectMembers(this);
    
    service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setSoftware(Software.newBuilder().setName("AgentScope Studio"))
            .setServiceName("http")
            .build();

    targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockWebServer.getHostName()))
            .build();
  }

  @After
  public void tearDown() throws IOException {
    mockWebServer.shutdown();
  }

  @Test
  public void detect_whenVulnerable_returnsVulnerability() throws IOException {
    mockWebServer.enqueue(new MockResponse()
        .setBody("<title>AgentScope Studio</title>")
        .setResponseCode(200));

    mockWebServer.enqueue(new MockResponse()
        .setBody("root:x:0:0:root:/root:/bin/bash")
        .setResponseCode(200));

    DetectionReport actual = 
        detector.detect(targetInfo, ImmutableList.of(service)).getDetectionReports(0);

    DetectionReport expected = 
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
                            .setPublisher("TSUNAMI_COMMUNITY")
                            .setValue("CVE_2024_8438"))
                    .setSeverity(Severity.HIGH)
                    .setTitle("CVE-2024-8438 Agentscope Studio API Arbitrary File Download")
                    .setDescription(VULN_DESCRIPTION)
                    .setRecommendation("Ensure this service is not exposed to the public internet. Restrict access using firewall rules, VPN, or an allowlist to limit exposure to only trusted users and networks."))
            .build();
    assertThat(actual).isEqualTo(expected);
  }

  @Test
  public void detect_whenNotVulnerable_returnsNoVulnerability() throws IOException {
    MockResponse response = 
        new MockResponse()
            .setBody("Hello World")
            .setResponseCode(200);
    mockWebServer.enqueue(response);

    ImmutableList<NetworkService> httpServices =
        ImmutableList.of(
            NetworkService.newBuilder()
                .setNetworkEndpoint(
                    forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
                .setTransportProtocol(TransportProtocol.TCP)
                .setServiceName("http")
                .build());
    TargetInfo targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockWebServer.getHostName()))
            .build();

    DetectionReportList detectionReports = detector.detect(targetInfo, httpServices);

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }

}
