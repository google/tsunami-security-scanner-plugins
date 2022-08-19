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
package com.google.tsunami.plugins.detectors.exposedui.hadoop.yarn;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostname;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;
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
import com.google.tsunami.plugin.payload.testing.FakePayloadGeneratorModule;
import com.google.tsunami.plugin.payload.testing.PayloadTestHelper;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkEndpoint;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.ServiceContext;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.Software;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TransportProtocol;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import com.google.tsunami.proto.WebServiceContext;
import java.io.IOException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
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

/** Tests for {@link YarnExposedManagerApiDetector}. */
@RunWith(JUnit4.class)
public final class YarnExposedManagerApiDetectorTest {
  private static final Vulnerability DETECTED_VULNERABILITY =
      Vulnerability.newBuilder()
          .setMainId(
              VulnerabilityId.newBuilder()
                  .setPublisher("GOOGLE")
                  .setValue("HADOOP_YARN_UNAUTHENTICATED_RESOURCE_MANAGER_API"))
          .setSeverity(Severity.CRITICAL)
          .setTitle("Hadoop Yarn Unauthenticated ResourceManager API")
          .setDescription(
              "Hadoop Yarn ResourceManager controls the computation and storage"
                  + " resources of a Hadoop cluster. Unauthenticated ResourceManager"
                  + " API allows any remote users to create and execute arbitrary"
                  + " applications on the host.")
          .setRecommendation(
              "Set up authentication by following the instructions at"
                  + " https://hadoop.apache.org/docs/current/hadoop-project-dist/hadoop-common/HttpAuthentication.html.")
          .build();

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  private MockWebServer mockWebServer;

  private final MockWebServer mockCallbackServer = new MockWebServer();

  @Inject private YarnExposedManagerApiDetector detector;

  // A version of secure random that gives predictable output for our unit tests
  private final SecureRandom testSecureRandom =
      new SecureRandom() {
        @Override
        public void nextBytes(byte[] bytes) {
          Arrays.fill(bytes, (byte) 0xFF);
        }
      };

  @Before
  public void setUp() throws IOException {
    mockWebServer = new MockWebServer();
    mockCallbackServer.start();

    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            FakePayloadGeneratorModule.builder()
                .setCallbackServer(mockCallbackServer)
                .setSecureRng(testSecureRandom)
                .build(),
            new YarnExposedManagerApiDetectorBootstrapModule())
        .injectMembers(this);
  }

  @After
  public void tearDown() throws IOException {
    mockWebServer.shutdown();
    mockCallbackServer.shutdown();
  }

  @Test
  public void detect_whenUnauthenticatedYarnSuccessfullyCreatesNewApplication_reportsVuln()
      throws IOException {
    String unauthenticatedClusterPage =
        Resources.toString(
            Resources.getResource(this.getClass(), "testdata/unauthenticatedYarnClusterPage.html"),
            UTF_8);
    String validNewApplicationResponse =
        Resources.toString(
            Resources.getResource(this.getClass(), "testdata/validNewApplicationResponse.json"),
            UTF_8);
    mockWebServer.setDispatcher(
        new FakeYarnDispatcher("", unauthenticatedClusterPage, validNewApplicationResponse));
    mockWebServer.start();

    // Simulate that the callbackserver received a response i.e. detector exploited the
    // vulnerability
    mockCallbackServer.enqueue(PayloadTestHelper.generateMockSuccessfulCallbackResponse());

    ImmutableList<NetworkService> httpServices =
        ImmutableList.of(
            NetworkService.newBuilder()
                .setNetworkEndpoint(
                    forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
                .setTransportProtocol(TransportProtocol.TCP)
                .setSoftware(Software.newBuilder().setName("Hadoop Yarn"))
                .setServiceName("http")
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
                .setVulnerability(DETECTED_VULNERABILITY)
                .build());
  }

  @Test
  public void detect_whenUnauthenticatedYarnServesOnNonEmptyRoot_reportsVuln() throws IOException {
    String unauthenticatedClusterPage =
        Resources.toString(
            Resources.getResource(this.getClass(), "testdata/unauthenticatedYarnClusterPage.html"),
            UTF_8);
    String validNewApplicationResponse =
        Resources.toString(
            Resources.getResource(this.getClass(), "testdata/validNewApplicationResponse.json"),
            UTF_8);
    mockWebServer.setDispatcher(
        new FakeYarnDispatcher(
            "/yarn-root", unauthenticatedClusterPage, validNewApplicationResponse));
    mockWebServer.start();

    mockCallbackServer.enqueue(PayloadTestHelper.generateMockSuccessfulCallbackResponse());

    ImmutableList<NetworkService> httpServices =
        ImmutableList.of(
            NetworkService.newBuilder()
                .setNetworkEndpoint(
                    forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
                .setTransportProtocol(TransportProtocol.TCP)
                .setSoftware(Software.newBuilder().setName("Hadoop Yarn"))
                .setServiceName("http")
                .setServiceContext(
                    ServiceContext.newBuilder()
                        .setWebServiceContext(
                            WebServiceContext.newBuilder().setApplicationRoot("/yarn-root")))
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
                .setVulnerability(DETECTED_VULNERABILITY)
                .build());
  }

  @Test
  public void detect_whenUnauthenticatedYarnRespondUnexpectedNewApplicationFormat_ignoresServices()
      throws IOException {
    String unauthenticatedClusterPage =
        Resources.toString(
            Resources.getResource(this.getClass(), "testdata/unauthenticatedYarnClusterPage.html"),
            UTF_8);
    String unexpectedNewApplicationResponse = "[\"json\", \"array\", \"not\", \"expected\"]";
    mockWebServer.setDispatcher(
        new FakeYarnDispatcher("", unauthenticatedClusterPage, unexpectedNewApplicationResponse));
    mockWebServer.start();

    ImmutableList<NetworkService> httpServices =
        ImmutableList.of(
            NetworkService.newBuilder()
                .setNetworkEndpoint(
                    forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
                .setTransportProtocol(TransportProtocol.TCP)
                .setSoftware(Software.newBuilder().setName("Hadoop Yarn"))
                .setServiceName("http")
                .build());

    assertThat(
            detector
                .detect(buildTargetInfo(forHostname(mockWebServer.getHostName())), httpServices)
                .getDetectionReportsList())
        .isEmpty();
  }

  @Test
  public void detect_whenUnauthenticatedYarnRespondUnexpectedNewApplicationData_ignoresServices()
      throws IOException {
    String unauthenticatedClusterPage =
        Resources.toString(
            Resources.getResource(this.getClass(), "testdata/unauthenticatedYarnClusterPage.html"),
            UTF_8);
    String unexpectedNewApplicationResponse = "{ \"this\": \"is not expected\" }";
    mockWebServer.setDispatcher(
        new FakeYarnDispatcher("", unauthenticatedClusterPage, unexpectedNewApplicationResponse));
    mockWebServer.start();

    ImmutableList<NetworkService> httpServices =
        ImmutableList.of(
            NetworkService.newBuilder()
                .setNetworkEndpoint(
                    forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
                .setTransportProtocol(TransportProtocol.TCP)
                .setSoftware(Software.newBuilder().setName("Hadoop Yarn"))
                .setServiceName("http")
                .build());

    assertThat(
            detector
                .detect(buildTargetInfo(forHostname(mockWebServer.getHostName())), httpServices)
                .getDetectionReportsList())
        .isEmpty();
  }

  @Test
  public void detect_whenUnauthenticatedYarnRespondNonJsonData_ignoresServices()
      throws IOException {
    String unauthenticatedClusterPage =
        Resources.toString(
            Resources.getResource(this.getClass(), "testdata/unauthenticatedYarnClusterPage.html"),
            UTF_8);
    mockWebServer.setDispatcher(
        new FakeYarnDispatcher("", unauthenticatedClusterPage, "not a valid json"));
    mockWebServer.start();

    ImmutableList<NetworkService> httpServices =
        ImmutableList.of(
            NetworkService.newBuilder()
                .setNetworkEndpoint(
                    forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
                .setTransportProtocol(TransportProtocol.TCP)
                .setSoftware(Software.newBuilder().setName("Hadoop Yarn"))
                .setServiceName("http")
                .build());

    assertThat(
            detector
                .detect(buildTargetInfo(forHostname(mockWebServer.getHostName())), httpServices)
                .getDetectionReportsList())
        .isEmpty();
  }

  @Test
  public void detect_whenYarnResourceManagerIsAuthenticated_ignoresServices() throws IOException {
    String authenticatedClusterPage =
        Resources.toString(
            Resources.getResource(this.getClass(), "testdata/authenticatedYarnClusterPage.html"),
            UTF_8);
    String validNewApplicationResponse =
        Resources.toString(
            Resources.getResource(this.getClass(), "testdata/validNewApplicationResponse.json"),
            UTF_8);
    mockWebServer.setDispatcher(
        new FakeYarnDispatcher("", authenticatedClusterPage, validNewApplicationResponse));
    mockWebServer.start();

    ImmutableList<NetworkService> httpServices =
        ImmutableList.of(
            NetworkService.newBuilder()
                .setNetworkEndpoint(
                    forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
                .setTransportProtocol(TransportProtocol.TCP)
                .setSoftware(Software.newBuilder().setName("Hadoop Yarn"))
                .setServiceName("http")
                .build());

    assertThat(
            detector
                .detect(buildTargetInfo(forHostname(mockWebServer.getHostName())), httpServices)
                .getDetectionReportsList())
        .isEmpty();
  }

  @Test
  public void detect_whenAboutPageNotForYarn_ignoresServices() throws IOException {
    startMockWebServer("/cluster/cluster", HttpStatus.OK.code(), "not hadoop yarn page");
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
  public void detect_whenAboutPageNotExist_ignoresServices() throws IOException {
    startMockWebServer("/cluster/cluster", HttpStatus.NOT_FOUND.code(), "");
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

  static final class FakeYarnDispatcher extends Dispatcher {
    private final String applicationRoot;
    private final String clusterPageResponse;
    private final String newApplicationResponse;

    FakeYarnDispatcher(
        String applicationRoot, String clusterPageResponse, String newApplicationResponse) {
      this.applicationRoot = checkNotNull(applicationRoot);
      this.clusterPageResponse = checkNotNull(clusterPageResponse);
      this.newApplicationResponse = checkNotNull(newApplicationResponse);
    }

    @Override
    public MockResponse dispatch(RecordedRequest recordedRequest) {
      if (recordedRequest.getPath().equals(applicationRoot + "/cluster/cluster")) {
        return new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .setHeader(HttpHeaders.CONTENT_TYPE, MediaType.HTML_UTF_8)
            .setBody(clusterPageResponse);
      }

      if (recordedRequest.getMethod().equals("POST")
          && recordedRequest
              .getPath()
              .equals(applicationRoot + "/ws/v1/cluster/apps/new-application")) {
        return new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .setHeader(HttpHeaders.CONTENT_TYPE, MediaType.JSON_UTF_8)
            .setBody(newApplicationResponse);
      }

      if (recordedRequest.getMethod().equals("POST")
          && recordedRequest.getPath().equals(applicationRoot + "/ws/v1/cluster/apps")) {
        return new MockResponse()
            .setResponseCode(HttpStatus.ACCEPTED.code())
            .setHeader(HttpHeaders.CONTENT_TYPE, MediaType.JSON_UTF_8)
            .setHeader("Location", "http://10.132.0.2:8088/ws/v1/cluster/apps/foo");
      }

      return new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code());
    }
  }

  private static TargetInfo buildTargetInfo(NetworkEndpoint networkEndpoint) {
    return TargetInfo.newBuilder().addNetworkEndpoints(networkEndpoint).build();
  }
}
