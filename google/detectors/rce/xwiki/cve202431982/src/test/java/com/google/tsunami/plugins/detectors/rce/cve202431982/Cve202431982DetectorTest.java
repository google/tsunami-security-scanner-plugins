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
package com.google.tsunami.plugins.detectors.rce.cve202431982;

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
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkEndpoint;
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
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link Cve202431982Detector}. */
@RunWith(JUnit4.class)
public final class Cve202431982DetectorTest {

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  private static final String VULN_CONTENT =
      "<title>RSS feed for search on tsunami-detection:3025</title>";

  private static final Vulnerability EXPECTED_VULN =
      Vulnerability.newBuilder()
          .setMainId(VulnerabilityId.newBuilder().setPublisher("GOOGLE").setValue("CVE-2024-31982"))
          .addRelatedId(VulnerabilityId.newBuilder().setPublisher("CVE").setValue("CVE-2024-31982"))
          .setSeverity(Severity.CRITICAL)
          .setTitle("xwiki instance vulnerable to CVE-2024-31982")
          .setRecommendation(
              "Update to one of the patched versions of xwiki: 14.10.20, 15.5.4, 15.10-rc-1")
          .setDescription(
              "The xwiki instance is vulnerable to CVE-2024-31982. This vulnerability allows"
                  + " an attacker to take control of the xwiki instance and does not require"
                  + " authentication.")
          .build();

  private MockWebServer mockWebServer;

  @Inject private Cve202431982Detector detector;

  @Before
  public void setUp() throws IOException {
    mockWebServer = new MockWebServer();
    mockWebServer.start();
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            new Cve202431982BootstrapModule())
        .injectMembers(this);
  }

  @After
  public void tearDown() throws IOException {
    mockWebServer.shutdown();
  }

  @Test
  public void detect_whenVulnerable_reportsVuln() {
    mockWebServer.enqueue(new MockResponse().setResponseCode(200).setBody(VULN_CONTENT));
    ImmutableList<NetworkService> httpServices =
        ImmutableList.of(
            NetworkService.newBuilder()
                .setNetworkEndpoint(
                    forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
                .setTransportProtocol(TransportProtocol.TCP)
                .setServiceName("http")
                .build());

    var report =
        detector
            .detect(buildTargetInfo(forHostname(mockWebServer.getHostName())), httpServices)
            .getDetectionReportsList();

    assertThat(report)
        .containsExactly(
            DetectionReport.newBuilder()
                .setTargetInfo(buildTargetInfo(forHostname(mockWebServer.getHostName())))
                .setNetworkService(httpServices.get(0))
                .setDetectionTimestamp(Timestamps.fromMillis(fakeUtcClock.millis()))
                .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
                .setVulnerability(EXPECTED_VULN)
                .build());
  }

  @Test
  public void detect_whenNotVulnerableStatus_reportsNothing() {
    mockWebServer.enqueue(new MockResponse().setResponseCode(404).setBody(VULN_CONTENT));
    ImmutableList<NetworkService> httpServices =
        ImmutableList.of(
            NetworkService.newBuilder()
                .setNetworkEndpoint(
                    forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
                .setTransportProtocol(TransportProtocol.TCP)
                .setServiceName("http")
                .build());

    var report =
        detector
            .detect(buildTargetInfo(forHostname(mockWebServer.getHostName())), httpServices)
            .getDetectionReportsList();

    assertThat(report).isEmpty();
  }

  @Test
  public void detect_whenNotVulnerableContent_reportsNothing() {
    mockWebServer.enqueue(new MockResponse().setResponseCode(200).setBody("Irrelevant"));
    mockWebServer.enqueue(new MockResponse().setResponseCode(200).setBody("Irrelevant"));
    ImmutableList<NetworkService> httpServices =
        ImmutableList.of(
            NetworkService.newBuilder()
                .setNetworkEndpoint(
                    forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
                .setTransportProtocol(TransportProtocol.TCP)
                .setServiceName("http")
                .build());

    var report =
        detector
            .detect(buildTargetInfo(forHostname(mockWebServer.getHostName())), httpServices)
            .getDetectionReportsList();

    assertThat(report).isEmpty();
  }

  private static TargetInfo buildTargetInfo(NetworkEndpoint networkEndpoint) {
    return TargetInfo.newBuilder().addNetworkEndpoints(networkEndpoint).build();
  }
}
