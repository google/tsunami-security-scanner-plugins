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
package com.google.tsunami.plugins.detectors.rce.joomla.rustyrce;

import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostname;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;

import com.google.common.collect.ImmutableList;
import com.google.common.net.HttpHeaders;
import com.google.inject.Guice;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkEndpoint;
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

/** Unit tests for {@link JoomlaRustyRCEDetector}. */
@RunWith(JUnit4.class)
public final class JoomlaRustyRCEDetectorTest {
  private static final String DEFAULT_COOKIE =
      "aa5220ed46db17514dfb70880a963560=2f2981b668f8809faf4b8af24d70906c";
  private static final String DEFAULT_CSRF = "CSRF_TOKEN01234567890123456789";
  private static final String DEFAULT_BODY =
      "Hello world!<input type=\"hidden\" name=\"" + DEFAULT_CSRF + "\" value=\"1\">";

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));
  private MockWebServer mockWebServer;

  @Inject private JoomlaRustyRCEDetector detector;

  @Before
  public void setUp() {
    mockWebServer = new MockWebServer();
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            new JoomlaRustyRCEDetectorBootstrapModule())
        .injectMembers(this);
  }

  @After
  public void tearDown() throws IOException {
    mockWebServer.shutdown();
  }

  @Test
  public void detect_whenIsVulnerableJoomla_returnsVulnerability() throws IOException {
    // Request 1: get root page with new cookie.
    mockWebServer.enqueue(
        buildDefaultResponse()
            .setBody(DEFAULT_BODY)
            .setHeader(HttpHeaders.SET_COOKIE, DEFAULT_COOKIE));
    mockWebServer.enqueue(
        buildDefaultResponse().setBody(DEFAULT_BODY + JoomlaRustyRCEDetector.TEST_STRING));
    mockWebServer.start();

    ImmutableList<NetworkService> httpServices = buildDefaultServices(mockWebServer);

    assertThat(
            detector
                .detect(buildTargetInfo(forHostname(mockWebServer.getHostName())), httpServices)
                .getDetectionReportsList())
        .containsExactly(
            DetectionReport.newBuilder()
                .setTargetInfo(buildTargetInfo(forHostname(mockWebServer.getHostName())))
                .setNetworkService(httpServices.get(0))
                .setDetectionTimestamp(
                    Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
                .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
                .setVulnerability(
                    Vulnerability.newBuilder()
                        .setMainId(
                            VulnerabilityId.newBuilder()
                                .setPublisher("GOOGLE")
                                .setValue("JOOMLA_RUSTY_RCE"))
                        .setSeverity(Severity.CRITICAL)
                        .setTitle(
                            "Joomla RCE via PHP object injection in HTTP POST (Rusty RCE, no CVE"
                                + " assigned)")
                        .setDescription(
                            "The Joomla application is vulnerable to Rusty RCE, which"
                                + " allows remote unprivileged attackers to execute arbitrary"
                                + " PHP code.")
                        .setRecommendation("Upgrade to Joomla 3.4.7 or greater."))
                .build());
  }

  @Test
  public void detect_whenNoCookies_doesNotReportVulnerability() throws IOException {
    // Request 1: we expect a cookie but none is set.
    mockWebServer.enqueue(buildDefaultResponse());
    mockWebServer.start();

    ImmutableList<NetworkService> httpServices = buildDefaultServices(mockWebServer);

    assertThat(
            detector
                .detect(buildTargetInfo(forHostname(mockWebServer.getHostName())), httpServices)
                .getDetectionReportsList())
        .isEmpty();
  }

  @Test
  public void detect_whenNotVulnerable_doesNotReportVulnerability() throws IOException {
    // Request 1: get root page with new cookie.
    mockWebServer.enqueue(buildDefaultResponse().setBody(DEFAULT_BODY).setHeader(HttpHeaders.SET_COOKIE, DEFAULT_COOKIE));
    // Request 2: send payload, the response is normal.
    mockWebServer.enqueue(buildDefaultResponse().setBody(DEFAULT_BODY));
    mockWebServer.start();

    ImmutableList<NetworkService> httpServices = buildDefaultServices(mockWebServer);

    assertThat(
            detector
                .detect(buildTargetInfo(forHostname(mockWebServer.getHostName())), httpServices)
                .getDetectionReportsList())
        .isEmpty();
  }

  @Test
  public void detect_whenNonHttpNetworkService_ignoresServices() {
    ImmutableList<NetworkService> nonHttpServices =
        ImmutableList.of(
            NetworkService.newBuilder().setServiceName("ssh").build(),
            NetworkService.newBuilder().setServiceName("rdp").build());
    assertThat(
            detector
                .detect(buildTargetInfo(forHostname(mockWebServer.getHostName())), nonHttpServices)
                .getDetectionReportsList())
        .isEmpty();
  }

  @Test
  public void detect_whenEmptyNetworkService_generatesEmptyDetectionReports() {
    assertThat(
            detector
                .detect(
                    buildTargetInfo(forHostname(mockWebServer.getHostName())), ImmutableList.of())
                .getDetectionReportsList())
        .isEmpty();
  }

  private static TargetInfo buildTargetInfo(NetworkEndpoint networkEndpoint) {
    return TargetInfo.newBuilder().addNetworkEndpoints(networkEndpoint).build();
  }

  private static MockResponse buildDefaultResponse() {
    return new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody(DEFAULT_BODY);
  }

  private static ImmutableList<NetworkService> buildDefaultServices(MockWebServer mockWebServer) {
    return ImmutableList.of(
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setSoftware(Software.newBuilder().setName("http"))
            .setServiceName("http")
            .build());
  }
}
