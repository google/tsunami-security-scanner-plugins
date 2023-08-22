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
package com.google.tsunami.plugins.papercut;

import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;

import com.google.common.collect.ImmutableList;
import com.google.common.io.Resources;
import com.google.inject.Guice;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.proto.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import javax.inject.Inject;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Unit tests for {@link PapercutNGMFVulnDetectorTest}, showing how to test a detector which
 * utilizes the payload generator framework.
 */
@RunWith(JUnit4.class)
public final class PapercutNGMFVulnDetectorTest {

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  private MockWebServer mockWebServer;
  private NetworkService papercutService;
  @Inject private PapercutNGMFVulnDetector detector;

  private DetectionReport detectorReport;

  @Before
  public void setUp() {
    mockWebServer = new MockWebServer();

    papercutService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setSoftware(Software.newBuilder().setName("Papercut MF"))
            .setServiceName("http")
            .build();

    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            new PapercutNGMFVulnDetectorBootstrapModule())
        .injectMembers(this);

    detectorReport =
        DetectionReport.newBuilder()
            .setTargetInfo(TargetInfo.getDefaultInstance())
            .setNetworkService(papercutService)
            .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
            .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
            .setVulnerability(
                Vulnerability.newBuilder()
                    .setMainId(
                        VulnerabilityId.newBuilder()
                            .setPublisher("TSUNAMI_COMMUNITY")
                            .setValue("CVE_2023_27350"))
                    .setSeverity(Severity.CRITICAL)
                    .setTitle("Papercut NG/MF Authentication Bypass and RCE")
                    .setDescription(
                        "This vulnerability allows remote attackers to bypass authentication"
                            + " on affected installations of PaperCut NG/MF."
                            + " Authentication is not required to exploit this vulnerability."
                            + " The specific flaw exists within the SetupCompleted class and the"
                            + " issue results from improper access control."
                            + " An attacker can leverage this vulnerability to bypass authentication"
                            + " and execute arbitrary code in the context of SYSTEM (Windows) "
                            + "or Root/Papercut User (Linux).")
                    .setRecommendation(
                        "Update to versions that are at least 20.1.7, 21.2.11, 22.0.9, or any later version."))
            .build();
  }

  @Test
  public void detect_whenVulnerable_returnsVulnerability() throws IOException {
    // Set up the mock webserver
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(200).setBody(loadResource("vulnerable_page.html")));
    mockWebServer.url("/app");

    DetectionReportList detectionReportList =
        detector.detect(TargetInfo.getDefaultInstance(), ImmutableList.of(papercutService));

    assertThat(detectionReportList.getDetectionReportsList()).containsExactly(detectorReport);
  }

  @Test
  public void detect_whenNotVulnerable_returnsNoFinding() throws IOException {

    // Set up the mock webserver
    //  - Redirects to a login page
    mockWebServer.enqueue(new MockResponse().setResponseCode(302));
    mockWebServer.url("/app");

    // Load the login page
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(200).setBody(loadResource("nonvulnerable_page.html")));
    mockWebServer.url("/app");

    assertThat(
        detector
            .detect(
                TargetInfo.newBuilder()
                    .addNetworkEndpoints(
                        forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
                    .build(),
                ImmutableList.of(papercutService))
            .getDetectionReportsList());
  }

  // Helper function load additional resources used in the tests
  private static String loadResource(String file) throws IOException {
    return Resources.toString(
            Resources.getResource(PapercutNGMFVulnDetectorTest.class, file), StandardCharsets.UTF_8)
        .strip();
  }
}
