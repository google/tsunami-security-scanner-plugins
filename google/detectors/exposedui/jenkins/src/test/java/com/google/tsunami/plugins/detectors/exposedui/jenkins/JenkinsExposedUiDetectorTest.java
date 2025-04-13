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
package com.google.tsunami.plugins.detectors.exposedui.jenkins;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostname;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;
import static com.google.tsunami.plugins.detectors.exposedui.jenkins.JenkinsExposedUiDetector.FINDING_RECOMMENDATION_TEXT;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.collect.ImmutableList;
import com.google.common.io.Resources;
import com.google.common.net.HttpHeaders;
import com.google.common.net.MediaType;
import com.google.inject.Guice;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.net.http.HttpStatus;
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
import java.io.IOException;
import java.time.Instant;
import javax.inject.Inject;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link JenkinsExposedUiDetector}. */
@RunWith(JUnit4.class)
public final class JenkinsExposedUiDetectorTest {
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  private MockWebServer mockWebServer;

  @Inject private JenkinsExposedUiDetector detector;

  @Before
  public void setUp() {
    mockWebServer = new MockWebServer();

    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            new JenkinsExposedUiDetectorBootstrapModule())
        .injectMembers(this);
  }

  @After
  public void tearDown() throws IOException {
    mockWebServer.shutdown();
  }

  @Test
  public void detect_whenJenkinsDoesNotRequireAuthentication_reportsVuln() throws IOException {
    startMockWebServer(
        "/view/all/newJob",
        HttpStatus.OK.code(),
        Resources.toString(
            Resources.getResource(this.getClass(), "testdata/enUsNewJobPage.html"), UTF_8));
    assertVulnerabilityDetected();
  }

  @Test
  public void detect_whenJenkinsInForeignLanguageAndDoNotRequireAuthentication_reportsVuln()
      throws IOException {
    startMockWebServer(
        "/view/all/newJob",
        HttpStatus.OK.code(),
        Resources.toString(
            Resources.getResource(this.getClass(), "testdata/deChNewJobPage.html"), UTF_8));
    assertVulnerabilityDetected();
  }

  @Test
  public void detect_whenJenkinsRedirectsToLoginPage_doesNotReportVuln() throws IOException {
    String loginPageResponse =
        Resources.toString(
            Resources.getResource(this.getClass(), "testdata/loginPage.html"), UTF_8);
    mockWebServer.setDispatcher(new RedirectToLoginPageDispatcher(loginPageResponse));
    mockWebServer.start();

    ImmutableList<NetworkService> httpServices =
        ImmutableList.of(
            NetworkService.newBuilder()
                .setNetworkEndpoint(
                    forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
                .setTransportProtocol(TransportProtocol.TCP)
                .setSoftware(Software.newBuilder().setName("Jenkins"))
                .setServiceName("http")
                .build());

    assertThat(
            detector
                .detect(buildTargetInfo(forHostname(mockWebServer.getHostName())), httpServices)
                .getDetectionReportsList())
        .isEmpty();
  }

  @Test
  public void detect_whenNonJenkinsWebApp_ignoresServices() throws IOException {
    startMockWebServer("/view/all/newJob", HttpStatus.OK.code(), "This is WordPress.");
    ImmutableList<NetworkService> httpServices =
        ImmutableList.of(
            NetworkService.newBuilder()
                .setNetworkEndpoint(
                    forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
                .setTransportProtocol(TransportProtocol.TCP)
                .setSoftware(Software.newBuilder().setName("WordPress"))
                .setServiceName("http")
                .build());

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

  private void startMockWebServer(String url, int responseCode, String response)
      throws IOException {
    mockWebServer.enqueue(new MockResponse().setResponseCode(responseCode).setBody(response));
    mockWebServer.start();
    mockWebServer.url(url);
  }

  private static TargetInfo buildTargetInfo(NetworkEndpoint networkEndpoint) {
    return TargetInfo.newBuilder().addNetworkEndpoints(networkEndpoint).build();
  }

  private void assertVulnerabilityDetected() {
    ImmutableList<NetworkService> httpServices =
        ImmutableList.of(
            NetworkService.newBuilder()
                .setNetworkEndpoint(
                    forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
                .setTransportProtocol(TransportProtocol.TCP)
                .setSoftware(Software.newBuilder().setName("Jenkins"))
                .setServiceName("http")
                .build());
    DetectionReport expectedReport =
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
                            .setValue("UNAUTHENTICATED_JENKINS_NEW_ITEM_CONSOLE"))
                    .setSeverity(Severity.CRITICAL)
                    .setTitle("Unauthenticated Jenkins New Item Console")
                    .setDescription(
                        "Unauthenticated Jenkins instance allows anonymous users to create"
                            + " arbitrary projects, which usually leads to code downloading from"
                            + " the internet and remote code executions.")
                    .setRecommendation(FINDING_RECOMMENDATION_TEXT))
            .build();

    DetectionReportList report =
        detector.detect(buildTargetInfo(forHostname(mockWebServer.getHostName())), httpServices);

    assertThat(report.getDetectionReportsList()).containsExactly(expectedReport);
  }

  static final class RedirectToLoginPageDispatcher extends Dispatcher {
    private final String loginPageResponse;

    RedirectToLoginPageDispatcher(String loginPageResponse) {
      this.loginPageResponse = checkNotNull(loginPageResponse);
    }

    @Override
    public MockResponse dispatch(RecordedRequest recordedRequest) {
      if (recordedRequest.getPath().equals("/view/all/newJob")) {
        return new MockResponse()
            .setResponseCode(HttpStatus.FOUND.code())
            .setHeader(HttpHeaders.LOCATION, "/login?from=%2Fview%2Fall%2FnewJob");
      }

      if (recordedRequest.getPath().startsWith("/login")) {
        return new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .setHeader(HttpHeaders.CONTENT_TYPE, MediaType.HTML_UTF_8)
            .setBody(loginPageResponse);
      }
      return new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code());
    }
  }
}
