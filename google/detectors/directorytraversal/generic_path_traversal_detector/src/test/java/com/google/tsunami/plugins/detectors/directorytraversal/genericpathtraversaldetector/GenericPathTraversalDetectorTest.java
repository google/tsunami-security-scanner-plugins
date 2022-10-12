/*
 * Copyright 2022 Google LLC
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
package com.google.tsunami.plugins.detectors.directorytraversal.genericpathtraversaldetector;

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
import com.google.tsunami.proto.CrawlResult;
import com.google.tsunami.proto.CrawlTarget;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.ServiceContext;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TransportProtocol;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import com.google.tsunami.proto.WebServiceContext;
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

/** Unit tests for {@link GenericPathTraversalDetector}. */
@RunWith(JUnit4.class)
public final class GenericPathTraversalDetectorTest {
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  private MockWebServer mockWebServer;

  @Inject private GenericPathTraversalDetector detector;

  @Before
  public void setUp() throws IOException {
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            new GenericPathTraversalDetectorBootstrapModule())
        .injectMembers(this);

    this.mockWebServer = new MockWebServer();
  }

  @After
  public void tearDown() throws IOException {
    this.mockWebServer.shutdown();
  }

  @Test
  public void detect_whenVulnerableNetworkService_reportContainsAllInformation()
      throws IOException {
    this.mockWebServer.setDispatcher(new VulnerableApplicationDispatcher());
    this.mockWebServer.start();

    ImmutableList<DetectionReport> detectionReports =
        ImmutableList.copyOf(
            detector
                .detect(buildMinimalTargetInfo(), ImmutableList.of(buildMinimalNetworkService()))
                .getDetectionReportsList());

    assertThat(detectionReports).isNotEmpty();
    assertThat(detectionReports)
        .comparingExpectedFieldsOnly()
        .contains(
            DetectionReport.newBuilder()
                .setTargetInfo(buildMinimalTargetInfo())
                .setNetworkService(buildMinimalNetworkService())
                .setDetectionTimestamp(Timestamps.fromMillis(fakeUtcClock.millis()))
                .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
                .build());
    assertThat(detectionReports.get(0).getVulnerability())
        .comparingExpectedFieldsOnly()
        .isEqualTo(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder().setPublisher("GOOGLE").setValue("GENERIC_PT"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Generic Path Traversal vulnerability")
                .setDescription(
                    "Generic Path Traversal vulnerability allowing to leak arbitrary files.")
                .build());
    assertThat(
            detectionReports.get(0).getVulnerability().getAdditionalDetailsList().stream()
                .anyMatch(detail -> detail.getTextData().getText().contains("..%2F")))
        .isTrue();
  }

  @Test
  public void detect_whenNotVulnerable_returnsNoFinding() throws IOException {
    this.mockWebServer.setDispatcher(new SecureApplicationDispatcher());
    this.mockWebServer.start();

    assertThat(
            detector
                .detect(buildMinimalTargetInfo(), ImmutableList.of(buildMinimalNetworkService()))
                .getDetectionReportsList())
        .isEmpty();
  }

  @Test
  public void detect_whenExploitResponseIsNotSuccess_doesNotDetectVulnerability()
      throws IOException {
    this.mockWebServer.setDispatcher(new ClientErrorDispatcher());
    this.mockWebServer.start();

    assertThat(
            detector
                .detect(buildMinimalTargetInfo(), ImmutableList.of(buildMinimalNetworkService()))
                .getDetectionReportsList())
        .isEmpty();
  }

  @Test
  public void detect_whenExploitResponseHasNoBody_doesNotDetectVulnerability() throws IOException {
    this.mockWebServer.setDispatcher(new BodylessApplicationDispatcher());
    this.mockWebServer.start();

    assertThat(
            detector
                .detect(buildMinimalTargetInfo(), ImmutableList.of(buildMinimalNetworkService()))
                .getDetectionReportsList())
        .isEmpty();
  }

  @Test
  public void detect_whenRedirect_doesNotDetectVulnerability() throws IOException {
    this.mockWebServer.setDispatcher(new VulnerableApplicationDispatcher());
    this.mockWebServer.start();

    assertThat(
            detector
                .detect(
                    buildMinimalTargetInfo(),
                    ImmutableList.of(buildMinimalNetworkService("GET", 300)))
                .getDetectionReportsList())
        .isEmpty();
  }

  @Test
  public void detect_whenClientError_doesDetectVulnerability() throws IOException {
    this.mockWebServer.setDispatcher(new VulnerableApplicationDispatcher());
    this.mockWebServer.start();

    assertThat(
            detector
                .detect(
                    buildMinimalTargetInfo(),
                    ImmutableList.of(buildMinimalNetworkService("GET", 400)))
                .getDetectionReportsList())
        .isNotEmpty();
  }

  @Test
  public void detect_whenNotGetRequest_doesNotDetectVulnerability() throws IOException {
    this.mockWebServer.setDispatcher(new VulnerableApplicationDispatcher());
    this.mockWebServer.start();

    assertThat(
            detector
                .detect(
                    buildMinimalTargetInfo(),
                    ImmutableList.of(buildMinimalNetworkService("POST", 200)))
                .getDetectionReportsList())
        .isEmpty();
  }

  @Test
  public void detect_whenNonHttpNetworkService_doesNotDetectVulnerability() throws IOException {
    this.mockWebServer.setDispatcher(new VulnerableApplicationDispatcher());
    this.mockWebServer.start();
    ImmutableList<NetworkService> nonHttpServices =
        ImmutableList.of(
            NetworkService.newBuilder().setServiceName("ssh").build(),
            NetworkService.newBuilder().setServiceName("rdp").build());

    assertThat(detector.detect(buildMinimalTargetInfo(), nonHttpServices).getDetectionReportsList())
        .isEmpty();
  }

  @Test
  public void detect_whenEmptyNetworkService_generatesEmptyDetectionReports() throws IOException {
    this.mockWebServer.setDispatcher(new VulnerableApplicationDispatcher());
    this.mockWebServer.start();

    assertThat(
            detector.detect(buildMinimalTargetInfo(), ImmutableList.of()).getDetectionReportsList())
        .isEmpty();
  }

  private NetworkService buildMinimalNetworkService(String httpMethod, int responseCode) {
    return NetworkService.newBuilder()
        .setNetworkEndpoint(
            forHostnameAndPort(this.mockWebServer.getHostName(), this.mockWebServer.getPort()))
        .setTransportProtocol(TransportProtocol.TCP)
        .setServiceName("http")
        .setServiceContext(
            ServiceContext.newBuilder()
                .setWebServiceContext(
                    WebServiceContext.newBuilder()
                        .addCrawlResults(
                            CrawlResult.newBuilder()
                                .setResponseCode(responseCode)
                                .setCrawlTarget(
                                    CrawlTarget.newBuilder()
                                        .setUrl(
                                            this.mockWebServer.url("/") + "test_get/?get_param=1")
                                        .setHttpMethod(httpMethod)))
                        .build()))
        .build();
  }

  private NetworkService buildMinimalNetworkService() {
    return buildMinimalNetworkService("GET", 200);
  }

  private TargetInfo buildMinimalTargetInfo() {
    return TargetInfo.newBuilder()
        .addNetworkEndpoints(forHostname(mockWebServer.getHostName()))
        .build();
  }

  private static final class VulnerableApplicationDispatcher extends Dispatcher {
    @Override
    public MockResponse dispatch(RecordedRequest recordedRequest) {
      if (recordedRequest.toString().contains("..%2Fetc%2Fpasswd")) {
        return new MockResponse().setResponseCode(200).setBody("root:x:0:0:root:/root:/bin/bash");
      } else {
        return new MockResponse().setResponseCode(200).setBody("Hello World");
      }
    }
  }

  private static final class SecureApplicationDispatcher extends Dispatcher {
    @Override
    public MockResponse dispatch(RecordedRequest recordedRequest) {
      return new MockResponse().setResponseCode(200).setBody("Hello World");
    }
  }

  private static final class BodylessApplicationDispatcher extends Dispatcher {
    @Override
    public MockResponse dispatch(RecordedRequest recordedRequest) {
      return new MockResponse().setResponseCode(200);
    }
  }

  private static final class ClientErrorDispatcher extends Dispatcher {
    @Override
    public MockResponse dispatch(RecordedRequest recordedRequest) {
      return new MockResponse().setResponseCode(400).setBody("root:x:0:0:root:/root:/bin/bash");
    }
  }
}
