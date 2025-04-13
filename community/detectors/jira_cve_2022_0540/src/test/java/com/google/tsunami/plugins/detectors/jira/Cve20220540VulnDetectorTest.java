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
package com.google.tsunami.plugins.detectors.jira;

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

/** Unit tests for {@link Cve20220540VulnDetector}. */
@RunWith(JUnit4.class)
public final class Cve20220540VulnDetectorTest {

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  @Inject private Cve20220540VulnDetector detector;

  private MockWebServer mockWebServer;

  @Before
  public void setUp() {
    mockWebServer = new MockWebServer();
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new Cve20220540DetectorBootstrapModule(),
            new HttpClientModule.Builder().build())
        .injectMembers(this);
  }

  @After
  public void tearDown() throws IOException {
    mockWebServer.shutdown();
  }

  @Test
  public void detect_whenInsightsVulnerable_returnsVulnerability() throws IOException {
    mockWebServer.start();
    mockWebResponse(200, Cve20220540VulnDetector.INSIGHT_BODY);
    mockWebResponse(302, "test");
    NetworkService service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setSoftware(Software.newBuilder().setName("http"))
            .setServiceName("http")
            .build();
    TargetInfo targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockWebServer.getHostName()))
            .build();

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
                    Vulnerability.newBuilder()
                        .setMainId(
                            VulnerabilityId.newBuilder()
                                .setPublisher("TSUNAMI_COMMUNITY")
                                .setValue("CVE_2022_0540"))
                        .setSeverity(Severity.CRITICAL)
                        .setTitle(
                            "CVE-2022-0540: Authentication Bypass in Atlassian Jira Service"
                                + " Management Server and Data Center")
                        .setRecommendation("Upgrade Jira to the latest version")
                        .setDescription(
                            "A vulnerability in Jira Seraph allows a remote, unauthenticated"
                                + " attacker to bypass authentication by sending a specially"
                                + " crafted HTTP request. This affects Atlassian Jira Server and"
                                + " Data Center versions before 8.13.18, versions 8.14.0 and later"
                                + " before 8.20.6, and versions 8.21.0 and later before 8.22.0."
                                + " This also affects Atlassian Jira Service Management Server and"
                                + " Data Center versions before 4.13.18, versions 4.14.0 and later"
                                + " before 4.20.6, and versions 4.21.0 and later before"
                                + " 4.22.0, using insights prior to 8.10.0 and WBSGantt plugin"
                                + " versions prior to 9.14.4.1 can cause a remote code execution"
                                + " hazard."))
                .build());
  }

  @Test
  public void detect_whenWBSGanttVulnerable_returnsVulnerability() throws IOException {
    mockWebServer.start();
    mockWebResponse(301, "test");
    mockWebResponse(200, Cve20220540VulnDetector.WBSGANTT_DOBY);
    NetworkService service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setSoftware(Software.newBuilder().setName("http"))
            .setServiceName("http")
            .build();
    TargetInfo targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockWebServer.getHostName()))
            .build();

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
                    Vulnerability.newBuilder()
                        .setMainId(
                            VulnerabilityId.newBuilder()
                                .setPublisher("TSUNAMI_COMMUNITY")
                                .setValue("CVE_2022_0540"))
                        .setSeverity(Severity.CRITICAL)
                        .setTitle(
                            "CVE-2022-0540: Authentication Bypass in Atlassian Jira Service"
                                + " Management Server and Data Center")
                        .setRecommendation("Upgrade Jira to the latest version")
                        .setDescription(
                            "A vulnerability in Jira Seraph allows a remote, unauthenticated"
                                + " attacker to bypass authentication by sending a specially"
                                + " crafted HTTP request. This affects Atlassian Jira Server and"
                                + " Data Center versions before 8.13.18, versions 8.14.0 and later"
                                + " before 8.20.6, and versions 8.21.0 and later before 8.22.0."
                                + " This also affects Atlassian Jira Service Management Server and"
                                + " Data Center versions before 4.13.18, versions 4.14.0 and later"
                                + " before 4.20.6, and versions 4.21.0 and later before"
                                + " 4.22.0, using insights prior to 8.10.0 and WBSGantt plugin"
                                + " versions prior to 9.14.4.1 can cause a remote code execution"
                                + " hazard."))
                .build());
  }

  @Test
  public void detect_whenNotVulnerable_returnsNoVulnerability() throws IOException {
    mockWebServer.start();
    mockWebResponse(200, "Hello World");
    mockWebResponse(302, "Hello World");
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

  private void mockWebResponse(int responseCode, String body) {
    mockWebServer.enqueue(new MockResponse().setResponseCode(responseCode).setBody(body));
  }
}
