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
package com.google.tsunami.plugins.detectors.cves.cve202229464;

import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostname;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;

import com.google.common.collect.ImmutableList;
import com.google.inject.Guice;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.proto.*;

import java.io.IOException;
import java.time.Instant;
import javax.inject.Inject;

import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.MockResponse;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link Cve202229464VulnDetector}. */
@RunWith(JUnit4.class)
public final class Cve202229464VuLnDetectorTest {
  // Tsunami provides several testing utilities to make your lives easier with unit test.
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  @Inject private Cve202229464VulnDetector detector;

  private MockWebServer mockWebServer;

  @Before
  public void setUp() {
    mockWebServer = new MockWebServer();
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new Cve202229464VulnDetectorBootstrapModule(),
            new HttpClientModule.Builder().build())
        .injectMembers(this);
  }

  @After
  public void tearDown() throws IOException {
    mockWebServer.shutdown();
  }

  // In Tsunami, unit test names should follow the following general convention:
  // functionUnderTest_condition_outcome.
  @Test
  public void detect_always_returnsVulnerability() throws IOException {
    mockWebResponse("1.651936903609122E12");
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
                                .setValue("CVE-2022-29464"))
                        .setSeverity(Severity.CRITICAL)
                        .setTitle("WSO2 Unrestricted Arbitrary File Upload CVE-2022-29464")
                        .setDescription("WSO2 API Manager 2.2.0, up to 4.0.0," +
                                "WSO2 Identity Server 5.2.0, up to 5.11.0," +
                                "WSO2 Identity Server Analytics 5.4.0, 5.4.1, 5.5.0, 5.6.0," +
                                "WSO2 Identity Server as Key Manager 5.3.0, up to 5.11.0," +
                                "WSO2 Enterprise Integrator 6.2.0, up to 6.6.0," +
                                "WSO2 Open Banking AM 1.4.0, up to 2.0.0," +
                                "WSO2 Open Banking KM 1.4.0, up to 2.0.0 contains a arbitrary file upload vulnerability." +
                                "Due to improper validation of user input, a malicious actor could upload an arbitrary file to a user controlled location of the server. By leveraging the arbitrary file upload vulnerability, it is further possible to gain remote code execution on the server.")
                        )
                .build());
  }

  @Test
  public void detect_whenNotVulnerable_returnsVulnerability() throws IOException {
    mockWebResponse("Hello Word");
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

  private void mockWebResponse(String body) throws IOException {
    mockWebServer.enqueue(new MockResponse().setResponseCode(200).setBody(body));
    mockWebServer.start();
  }
}
