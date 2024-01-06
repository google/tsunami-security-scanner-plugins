/*
 * Copyright 2023 Google LLC
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
package com.google.tsunami.plugins.detectors.rce.cve202322518;

import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;
import static com.google.tsunami.common.data.NetworkEndpointUtils.toUriAuthority;
import static com.google.tsunami.plugins.detectors.rce.cve202322518.Cve202322518VulnDetector.FILE_UPLOAD_PATH;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

import com.google.common.collect.ImmutableList;
import com.google.common.truth.Truth;
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

/** Unit tests for {@link Cve202322518VulnDetector}. */
@RunWith(JUnit4.class)
public final class Cve202322518VuLnDetectorTest {
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2023-12-03T00:00:00.00Z"));

  private final MockWebServer mockWebServer = new MockWebServer();

  private NetworkService service;
  private TargetInfo targetInfo;
  @Inject private Cve202322518VulnDetector detector;

  @Before
  public void setUp() throws IOException {
    mockWebServer.start();
    mockWebServer.url("/" + FILE_UPLOAD_PATH);
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            new Cve202322518VulnDetectorBootstrapModule())
        .injectMembers(this);

    service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setSoftware(Software.newBuilder().setName("influxDB 1.6.6"))
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
  public void detect_whenVulnerable_returnsVulnerability() throws InterruptedException {
    mockWebServer.enqueue(
        new MockResponse()
            .setResponseCode(200)
            .setBody(
                "The zip file did not contain an entry" + "\n" + "exportDescriptor.properties"));

    DetectionReportList detectionReports = detector.detect(targetInfo, ImmutableList.of(service));

    Truth.assertThat(mockWebServer.getRequestCount()).isEqualTo(1);

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
                                .setValue("CVE-2023-22518"))
                        .setSeverity(Severity.CRITICAL)
                        .setTitle(
                            "Atlassian Confluence Data Center Improper Authorization"
                                + " CVE-2023-22515")
                        .setDescription(
                            "This Improper Authorization vulnerability allows an unauthenticated"
                                + " attacker to reset Confluence and create a Confluence instance"
                                + " administrator account.")
                        .setRecommendation(
                            "Patch the confluence version to one of the following versions: "
                                + "7.19.16, 8.3.4, 8.4.4, 8.5.3, 8.6.1"))
                .build());
  }

  @Test
  public void detect_whenNotVulnerable_returnsVulnerability() {
    Cve202322518VulnDetector mock = spy(detector);

    when(mock.buildRootUri(service))
        .thenReturn(String.format("http://%s/", toUriAuthority(service.getNetworkEndpoint())));

    mockWebServer.enqueue(new MockResponse().setResponseCode(200));

    DetectionReportList detectionReports = mock.detect(targetInfo, ImmutableList.of(service));
    Truth.assertThat(mockWebServer.getRequestCount()).isEqualTo(1);
    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }
}
