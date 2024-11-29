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
package com.google.tsunami.plugins.detectors.rce.cve202229464;

import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;
import static com.google.tsunami.common.data.NetworkEndpointUtils.toUriAuthority;
import static com.google.tsunami.plugins.detectors.rce.cve202229464.Cve202229464VulnDetector.TEST_STR_RCE;
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

/** Unit tests for {@link Cve202229464VulnDetector}. */
@RunWith(JUnit4.class)
public final class Cve202229464VuLnDetectorTest {
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2022-12-03T00:00:00.00Z"));

  private MockWebServer mockWebServer;
  private NetworkService service;
  private TargetInfo targetInfo;
  @Inject private Cve202229464VulnDetector detector;

  @Before
  public void setUp() {
    mockWebServer = new MockWebServer();
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            new Cve202229464VulnDetectorBootstrapModule())
        .injectMembers(this);

    service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("ssl/tungsten-https")
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
  public void detect_whenVulnerable_returnsVulnerability() {
    Cve202229464VulnDetector mock = spy(detector);

    when(mock.buildRootUri(service))
        .thenReturn(String.format("http://%s/", toUriAuthority(service.getNetworkEndpoint())));

    mockWebServer.enqueue(new MockResponse().setResponseCode(200).setBody("1.651936903609122E12"));
    mockWebServer.enqueue(new MockResponse().setResponseCode(200).setBody(TEST_STR_RCE));

    DetectionReportList detectionReports = mock.detect(targetInfo, ImmutableList.of(service));

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
                        .setDescription(
                            "WSO2 API Manager 2.2.0, up to 4.0.0,WSO2 Identity Server 5.2.0, up"
                                + " to 5.11.0,WSO2 Identity Server Analytics 5.4.0, 5.4.1, 5.5.0,"
                                + " 5.6.0,WSO2 Identity Server as Key Manager 5.3.0, up to"
                                + " 5.11.0,WSO2 Enterprise Integrator 6.2.0, up to 6.6.0,WSO2 Open"
                                + " Banking AM 1.4.0, up to 2.0.0,WSO2 Open Banking KM 1.4.0, up"
                                + " to 2.0.0 contains a arbitrary file upload vulnerability. Due"
                                + " to improper validation of user input, a malicious actor could"
                                + " upload an arbitrary file to a user controlled location of the"
                                + " server. By leveraging the arbitrary file upload vulnerability,"
                                + " it is further possible to gain remote code execution on the"
                                + " server.")
                        .setRecommendation(
                            "Update WSO2 API Manager to 4.2.0, Identity Server to"
                                + " 6.1.0, Enterprise Integrator to 7.1.0, and"
                                + " Open Banking AM and KM to 3.0.0."))
                .build());

    Truth.assertThat(mockWebServer.getRequestCount()).isEqualTo(2);
  }

  @Test
  public void detect_whenNotVulnerable_returnsVulnerability() {
    Cve202229464VulnDetector mock = spy(detector);

    when(mock.buildRootUri(service))
        .thenReturn(String.format("http://%s/", toUriAuthority(service.getNetworkEndpoint())));

    mockWebServer.enqueue(new MockResponse().setResponseCode(200));

    DetectionReportList detectionReports = mock.detect(targetInfo, ImmutableList.of(service));
    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
    Truth.assertThat(mockWebServer.getRequestCount()).isEqualTo(1);
  }
}
