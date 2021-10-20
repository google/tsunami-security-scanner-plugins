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
package com.google.tsunami.plugins.detectors.rce.cve20213129;

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

/** Unit tests for {@link Cve20213129VulnDetector}. */
@RunWith(JUnit4.class)
public final class Cve20213129VulnDetectorTest {

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));
  private MockWebServer mockWebServer;

  @Inject private Cve20213129VulnDetector detector;

  @Before
  public void setUp() throws IOException {
    mockWebServer = new MockWebServer();
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new Cve20213129VulnDetectorBootstrapModule(),
            new HttpClientModule.Builder().build())
        .injectMembers(this);
    mockWebServer.start();
  }

  @After
  public void tearDown() throws IOException {
    mockWebServer.shutdown();
  }

  @Test
  public void detect_vulnerableToCve20213129_returnsVulnerability() throws InterruptedException {
    MockResponse mockResponse =
        new MockResponse()
            .setResponseCode(500)
            .setBody("file_get_contents(phar://Tsunami_iDontExist");
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

    RecordedRequest detectionReportRequest = mockWebServer.takeRequest();
    assertThat(detectionReportRequest.getMethod()).isEqualTo("POST");
    assertThat(detectionReportRequest.getPath()).endsWith("_ignition/execute-solution");
    assertThat(detectionReportRequest.getBody().readUtf8())
        .contains(
            "{\"solution\":"
                + " \"Facade\\\\Ignition\\\\Solutions\\\\MakeViewVariableOptionalSolution\",\"parameters\":"
                + " {\"variableName\": \"cve20213129_tsunami\", \"viewFile\":"
                + " \"phar://Tsunami_iDontExist\"}}");

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
                                .setValue("CVE_2021_3129"))
                        .setSeverity(Severity.CRITICAL)
                        .setTitle("CVE-2021-3129: Unauthenticated RCE in Laravel using Debug Mode")
                        .setDescription(
                            "Ignition before 2.5.2, as used in Laravel, allows unauthenticated"
                                + " remote attackers to execute arbitrary code because of insecure"
                                + " usage of file_get_contents() and file_put_contents(). This is"
                                + " exploitable on sites using debug mode with Laravel before"
                                + " 8.4.3")
                        .setRecommendation(
                            "Update Laravel to at least version 8.4.3, and facade/ignition to at"
                                + " least version 2.5.2.For production systems it is advised to"
                                + " disable debug mode within the Laravel configuration."))
                .build());
  }

  @Test
  public void detect_notVulnerable_returnsNoVulnerability()
      throws IOException, InterruptedException {
    MockResponse mockResponse = new MockResponse().setResponseCode(500).setBody("");
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

    RecordedRequest detectionReportRequest = mockWebServer.takeRequest();
    assertThat(detectionReportRequest.getMethod()).isEqualTo("POST");
    assertThat(detectionReportRequest.getPath()).endsWith("_ignition/execute-solution");

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }
}
