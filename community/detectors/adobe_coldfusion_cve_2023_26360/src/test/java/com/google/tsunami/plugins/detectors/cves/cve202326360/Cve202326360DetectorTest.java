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
package com.google.tsunami.plugins.detectors.cves.cve202326360;

import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
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

/** Unit tests for {@link Cve202326360Detector}. */
@RunWith(JUnit4.class)
public final class Cve202326360DetectorTest {

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2024-01-01T00:00:00.00Z"));

  @Inject private Cve202326360Detector detector;

  private final MockWebServer mockWebServer = new MockWebServer();
  private NetworkService service;
  private TargetInfo targetInfo;

  @Before
  public void setUp() throws IOException {
    mockWebServer.start();
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            new Cve202326360DetectorBootstrapModule())
        .injectMembers(this);

    service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setSoftware(Software.newBuilder().setName("Adobe ColdFusion"))
            .setServiceName("http")
            .build();

    targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .build();
  }

  @After
  public void tearDown() throws IOException {
    mockWebServer.shutdown();
  }

  @Test
  public void detect_whenVulnerable_returnsDetection() {
    MockResponse response =
        new MockResponse()
            .setBody(
                "<wddxPacket version='1.0'><header/><data><struct><var name='variables'>"
                    + "<struct></struct></var></struct></data></wddxPacket>root:x:0:0:root:/root:/bin/bash"
                    + "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
                    + "bin:x:2:2:bin:/bin:/usr/sbin/nologinsys:x:3:3:sys:/dev:/usr/sbin/nologin"
                    + "sync:x:4:65534:sync:/bin:/bin/sync");
    mockWebServer.enqueue(response);

    DetectionReport actual =
        detector.detect(targetInfo, ImmutableList.of(service)).getDetectionReports(0);

    DetectionReport expected =
        DetectionReport.newBuilder()
            .setTargetInfo(targetInfo)
            .setNetworkService(service)
            .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
            .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
            .setVulnerability(
                Vulnerability.newBuilder()
                    .setMainId(
                        VulnerabilityId.newBuilder()
                            .setPublisher("TSUNAMI_COMMUNITY")
                            .setValue("CVE_2023_26360"))
                    .addRelatedId(
                        VulnerabilityId.newBuilder().setPublisher("CVE").setValue("CVE-2023-26360"))
                    .setSeverity(Severity.CRITICAL)
                    .setTitle(
                        "Adobe ColdFusion Unauthenticated Arbitrary Read and Remote Code Execution")
                    .setDescription(
                        "Adobe ColdFusion versions 2018 Update 15 (and earlier) and 2021 Update 5"
                            + " (and earlier) are affected by an Improper Access Control"
                            + " vulnerability that could result in unauthenticated file read and"
                            + " arbitrary code execution in the context of the current user."
                            + " Exploitation of this issue does not require user interaction.")
                    .setRecommendation(
                        "For Adobe ColdFusion 2018, ugrade to version Update 16 or higher"
                            + "For  Adobe ColdFusion 2021, upgrade to version Update 6 or higher"))
            .build();

    assertThat(actual).isEqualTo(expected);
  }

  @Test
  public void detect_whenNotVulnerable_returnsNoVulnerability() {
    MockResponse response = new MockResponse().setBody("x");
    mockWebServer.enqueue(response);
    DetectionReportList findings = detector.detect(targetInfo, ImmutableList.of(service));
    assertThat(findings.getDetectionReportsList()).isEmpty();
  }
}
