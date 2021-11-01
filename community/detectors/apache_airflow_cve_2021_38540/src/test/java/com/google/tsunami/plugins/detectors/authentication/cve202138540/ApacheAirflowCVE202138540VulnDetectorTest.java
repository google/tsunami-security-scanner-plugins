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
package com.google.tsunami.plugins.detectors.authentication.cve202138540;

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

/** Unit tests for {@link ApacheAirflowCVE202138540VulnDetector}. */
@RunWith(JUnit4.class)
public final class ApacheAirflowCVE202138540VulnDetectorTest {
  private static final String DEFAULT_BODY = "session=session_cookie";
  private static final String SESSION_COOKIE = "session=session_cookie";
  private static final String VULNERABLE_BODY = "<a href=\"/\">REDIRECTION TO HOME WITH 302</a>";
  private static final String CSRF_TOKEN = "csrf_token_value";
  private static final String CSRF_TOKEN_BODY =
      "<input id=\"csrf_token\" name=\"csrf_token\" type=\"hidden\" value=\"csrf_token_value\">";

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));
  private MockWebServer mockWebServer;

  @Inject private ApacheAirflowCVE202138540VulnDetector detector;

  @Before
  public void setUp() {
    mockWebServer = new MockWebServer();
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            new ApacheAirflowCVE202138540VulnDetectorBootstrapModule())
        .injectMembers(this);
  }

  @After
  public void tearDown() throws IOException {
    mockWebServer.shutdown();
  }

  @Test
  public void detect_whenNoCSRFNoSession_doesNotReportVulnerability() throws IOException {
    // Request 1: we expect a session and csrf but none is set.
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
    // Request 1: to fetch csrf and session cookie.
    mockWebServer.enqueue(
        buildDefaultResponse()
            .setBody(CSRF_TOKEN_BODY)
            .setHeader(HttpHeaders.SET_COOKIE, SESSION_COOKIE));
    // Request 2: send payload, the response is normal.
    mockWebServer.enqueue(buildTempMoveResponse().setBody(DEFAULT_BODY));
    mockWebServer.start();

    ImmutableList<NetworkService> httpServices = buildDefaultServices(mockWebServer);

    assertThat(
            detector
                .detect(buildTargetInfo(forHostname(mockWebServer.getHostName())), httpServices)
                .getDetectionReportsList())
        .isEmpty();
  }

  @Test
  public void detect_whenVulnerable_doesReportVulnerability() throws IOException {
    // Request 1: to fetch csrf and session cookie.
    mockWebServer.enqueue(
        buildDefaultResponse()
            .setBody(CSRF_TOKEN_BODY)
            .setHeader(HttpHeaders.SET_COOKIE, SESSION_COOKIE));
    // Request 2: send payload, the response is normal.
    mockWebServer.enqueue(buildTempMoveResponse().setBody(VULNERABLE_BODY));
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
                                .setPublisher("TSUNAMI_COMMUNITY")
                                .setValue("CVE_2021_38540"))
                        .setSeverity(Severity.CRITICAL)
                        .setTitle(
                            "CVE-2021-38540: Apache Airflow Variable Import endpoint missing auth"
                                + " check")
                        .setDescription(
                            "The variable import endpoint was not protected by authentication in"
                                + " Airflow >=2.0.0, <2.1.3.This allowed unauthenticated users to"
                                + " hit that endpoint to add/modify Airflow variables usedin DAGs,"
                                + " potentially resulting in a denial of service, information"
                                + " disclosure or remote codeexecution. This issue affects Apache"
                                + " Airflow >=2.0.0, <2.1.3."))
                .build());
  }

  private static TargetInfo buildTargetInfo(NetworkEndpoint networkEndpoint) {
    return TargetInfo.newBuilder().addNetworkEndpoints(networkEndpoint).build();
  }

  private static MockResponse buildDefaultResponse() {
    return new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody(DEFAULT_BODY);
  }

  private static MockResponse buildTempMoveResponse() {
    return new MockResponse().setResponseCode(302).setBody(DEFAULT_BODY);
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
