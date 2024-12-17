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
package com.google.tsunami.plugins.detectors.rce.cve202342793;

import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostname;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;
import static com.google.tsunami.plugins.detectors.rce.cve202342793.TeamCityAuthBypassDetector.RECOMMENDATION;
import static com.google.tsunami.plugins.detectors.rce.cve202342793.TeamCityAuthBypassDetector.VULNERABILITY_REPORT_TITLE;
import static com.google.tsunami.plugins.detectors.rce.cve202342793.TeamCityAuthBypassDetector.VULN_DESCRIPTION;

import com.google.common.collect.ImmutableList;
import com.google.inject.Guice;
import com.google.protobuf.util.JsonFormat;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.callbackserver.proto.PollingResult;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.plugin.payload.testing.FakePayloadGeneratorModule;
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
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import javax.inject.Inject;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link TeamCityAuthBypassDetector}. */
@RunWith(JUnit4.class)
public final class TeamCityAuthBypassDetectorTest {
  private static final String TOKEN_RESP =
      "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><token name=\"RPC2\""
          + " creationTime=\"2023-09-28T20:03:56.912Z\""
          + " value=\"eyJ0eXAiOiAiVENWMiJ9.VTd3NFpaWjBieE9hX1duQzNibWpKTGhzU1A4.MmI2ZjI4MzktYmQ1ZC00OTFkLTg3ZDUtZGJmZDNiN2ZhNzU3\"/>";
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  private MockWebServer mockWebServer;
  private MockWebServer mockCallbackServer;

  private final SecureRandom testSecureRandom =
      new SecureRandom() {
        @Override
        public void nextBytes(byte[] bytes) {
          Arrays.fill(bytes, (byte) 0xFF);
        }
      };

  @Inject private TeamCityAuthBypassDetector detector;

  @Before
  public void setUp() throws IOException {
    mockWebServer = new MockWebServer();
    mockCallbackServer = new MockWebServer();

    mockWebServer.start();
    mockCallbackServer.start();

    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            FakePayloadGeneratorModule.builder()
                .setCallbackServer(mockCallbackServer)
                .setSecureRng(testSecureRandom)
                .build(),
            new TeamCityAuthBypassDetectorBootstrapModule())
        .injectMembers(this);
  }

  @After
  public void tearDown() throws IOException {
    mockWebServer.shutdown();
  }

  @Test
  public void detect_whenApiEndpointReturns400_doesNotReportVuln() throws IOException {
    mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.BAD_REQUEST.code()));
    mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.BAD_REQUEST.code()));
    ImmutableList<NetworkService> httpServices =
        ImmutableList.of(
            NetworkService.newBuilder()
                .setNetworkEndpoint(
                    forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
                .setTransportProtocol(TransportProtocol.TCP)
                .setServiceName("http-alt")
                .build());

    assertThat(
            detector
                .detect(buildTargetInfo(forHostname(mockWebServer.getHostName())), httpServices)
                .getDetectionReportsList())
        .isEmpty();
  }

  @Test
  public void detect_whenVulnerable_reportsVuln() throws IOException {
    // Delete token
    mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.OK.code()));
    // Create token
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody(TOKEN_RESP));
    // Enable Debug Mode
    mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.OK.code()));
    // Refresh setting
    mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.OK.code()));
    // Execute payload
    mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.OK.code()));
    PollingResult log = PollingResult.newBuilder().setHasHttpInteraction(true).build();
    String body = JsonFormat.printer().preservingProtoFieldNames().print(log);
    mockCallbackServer.enqueue(
        new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody(body));
    ImmutableList<NetworkService> httpServices =
        ImmutableList.of(
            NetworkService.newBuilder()
                .setNetworkEndpoint(
                    forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
                .setTransportProtocol(TransportProtocol.TCP)
                .setServiceName("http-alt")
                .build());

    assertThat(
            detector
                .detect(buildTargetInfo(forHostname(mockWebServer.getHostName())), httpServices)
                .getDetectionReportsList())
        .containsExactly(
            DetectionReport.newBuilder()
                .setTargetInfo(buildTargetInfo(forHostname(mockWebServer.getHostName())))
                .setNetworkService(httpServices.get(0))
                .setDetectionTimestamp(Timestamps.fromMillis(fakeUtcClock.millis()))
                .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
                .setVulnerability(
                    Vulnerability.newBuilder()
                        .setMainId(
                            VulnerabilityId.newBuilder()
                                .setPublisher("GOOGLE")
                                .setValue("CVE_2023_42793"))
                        .setSeverity(Severity.CRITICAL)
                        .setTitle(VULNERABILITY_REPORT_TITLE)
                        .setDescription(VULN_DESCRIPTION)
                        .setRecommendation(RECOMMENDATION))
                .build());
  }

  private static TargetInfo buildTargetInfo(NetworkEndpoint networkEndpoint) {
    return TargetInfo.newBuilder().addNetworkEndpoints(networkEndpoint).build();
  }
}
