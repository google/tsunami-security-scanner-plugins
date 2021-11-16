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
package com.google.tsunami.plugins.detectors.confluence;

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
import com.google.tsunami.proto.NetworkEndpoint;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.Software;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TransportProtocol;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.time.Instant;
import javax.inject.Inject;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Unit tests for {@link AtlassianConfluencePreAuthOgnlInjectionDetector}.
 */
@RunWith(JUnit4.class)
public final class AtlassianConfluencePreAuthOgnlInjectionDetectorTest {

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  @Inject
  private AtlassianConfluencePreAuthOgnlInjectionDetector detector;

  private MockWebServer mockWebServer;
  private NetworkService confluenceService;

  @Before
  public void setUp() {
    mockWebServer = new MockWebServer();
    confluenceService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setSoftware(Software.newBuilder().setName("Atlassian Confluence"))
            .setServiceName("http")
            .build();

    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            new AtlassianConfluencePreAuthOgnlInjectionDetectorBootstrapModule())
        .injectMembers(this);
  }

  @Test
  public void detect_whenConfluenceIsVulnerable_reportsVuln() {
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(403).setBody("Google{101727396=null}Tsunami"));
    mockWebServer.url("/");

    DetectionReportList detectionReports =
        detector.detect(TargetInfo.getDefaultInstance(), ImmutableList.of(confluenceService));

    assertThat(detectionReports.getDetectionReportsList())
        .containsExactly(
            DetectionReport.newBuilder()
                .setTargetInfo(TargetInfo.getDefaultInstance())
                .setNetworkService(confluenceService)
                .setDetectionTimestamp(
                    Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
                .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
                .setVulnerability(
                    Vulnerability.newBuilder()
                        .setMainId(VulnerabilityId.newBuilder().setPublisher("TSUNAMI_COMMUNITY")
                            .setValue("CVE-2021-26084"))
                        .setSeverity(Severity.CRITICAL)
                        .setTitle("Atlassian Confluence Pre-Auth OGNL Injection")
                        .setDescription("An OGNL injection vulnerability exists that allows an "
                            + "unauthenticated attacker to execute arbitrary code on a Confluence "
                            + "Server or Data Center instance.")
                        .setRecommendation("enable authentication")
                ).build());
  }

  @Test
  public void detect_whenConfluenceIsNotVulnerable_doesNotReportVuln() {
    mockWebServer.enqueue(new MockResponse().setResponseCode(403).
        setBody("\\u0027+#{333*333}+\\u0027"));
    mockWebServer.url("/");

    assertThat(
        detector
            .detect(
                buildTargetInfo(forHostname(mockWebServer.getHostName())),
                ImmutableList.of(confluenceService))
            .getDetectionReportsList())
        .isEmpty();
  }

  private static TargetInfo buildTargetInfo(NetworkEndpoint networkEndpoint) {
    return TargetInfo.newBuilder().addNetworkEndpoints(networkEndpoint).build();
  }
}
