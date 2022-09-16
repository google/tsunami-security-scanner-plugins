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
package com.google.tsunami.plugins.detectors.rce.cve20179805;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostname;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;

import com.google.common.collect.ImmutableList;
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
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link ApacheStrutsInsecureDeserializeDetector}. */
@RunWith(JUnit4.class)
public final class ApacheStrutsInsecureDeserializeDetectorTest {
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  private MockWebServer mockWebServer;

  @Inject private ApacheStrutsInsecureDeserializeDetector detector;

  @Before
  public void setUp() {
    mockWebServer = new MockWebServer();

    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            new ApacheStrutsInsecureDeserializeDetectorBootstrapModule())
        .injectMembers(this);
  }

  @After
  public void tearDown() throws IOException {
    mockWebServer.shutdown();
  }

  @Test
  public void detect_ifVulnerable_reportsVuln() throws IOException, InterruptedException {
    // The first and third request should run the RCE command while the second request should query
    // the created file.
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(HttpStatus.INTERNAL_SERVER_ERROR.code()));
    mockWebServer.enqueue(
        new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .setBody(ApacheStrutsInsecureDeserializeDetector.RANDOM_FILE_CONTENTS));
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(HttpStatus.INTERNAL_SERVER_ERROR.code()));
    mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code()));
    mockWebServer.start();
    mockWebServer.url("/");
    ImmutableList<NetworkService> httpServices =
        ImmutableList.of(
            NetworkService.newBuilder()
                .setNetworkEndpoint(
                    forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
                .setTransportProtocol(TransportProtocol.TCP)
                .setSoftware(Software.newBuilder().setName("ApacheStruts"))
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
                .setVulnerability(
                    Vulnerability.newBuilder()
                        .setMainId(
                            VulnerabilityId.newBuilder()
                                .setPublisher("GOOGLE")
                                .setValue("CVE_2017_9805"))
                        .setSeverity(Severity.CRITICAL)
                        .setTitle(
                            "Apache Struts Command Injection via Unsafe Deserialization"
                                + " (CVE-2017-9805)")
                        .setDescription(
                            "The REST Plugin in Apache Struts 2.1.1 through 2.3.x before 2.3.34"
                                + " and 2.5.x before 2.5.13 uses an XStreamHandler with an"
                                + " instance of XStream for deserialization without any type"
                                + " filtering, which can lead to Remote Code Execution when"
                                + " deserializing XML payloads.")
                        .setRecommendation("Upgrade to Struts 2.5.13 or Struts 2.3.34."))
                .build());

    // Check that the detector creates and erases the file.
    RecordedRequest recordedRequest = mockWebServer.takeRequest();
    String body = recordedRequest.getBody().readUtf8();
    assertThat(body).contains("echo ");
    assertThat(body).contains(ApacheStrutsInsecureDeserializeDetector.RANDOM_FILENAME);

    // Checks that the file got created.
    recordedRequest = mockWebServer.takeRequest();
    assertThat(recordedRequest.getPath())
        .isEqualTo("/" + ApacheStrutsInsecureDeserializeDetector.RANDOM_FILENAME);

    recordedRequest = mockWebServer.takeRequest();
    body = recordedRequest.getBody().readUtf8();
    assertThat(body).contains("rm ");
    assertThat(body).contains(ApacheStrutsInsecureDeserializeDetector.RANDOM_FILENAME);

    // Checks that the file got erased.
    recordedRequest = mockWebServer.takeRequest();
    assertThat(recordedRequest.getPath())
        .isEqualTo("/" + ApacheStrutsInsecureDeserializeDetector.RANDOM_FILENAME);
  }

  @Test
  public void detect_ifNotVulnerable_doesNotReportVuln() throws IOException {
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(HttpStatus.INTERNAL_SERVER_ERROR.code()));
    mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code()));
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(HttpStatus.INTERNAL_SERVER_ERROR.code()));
    mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code()));
    mockWebServer.start();
    mockWebServer.url("/");
    ImmutableList<NetworkService> httpServices =
        ImmutableList.of(
            NetworkService.newBuilder()
                .setNetworkEndpoint(
                    forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
                .setTransportProtocol(TransportProtocol.TCP)
                .setSoftware(Software.newBuilder().setName("ApacheStruts"))
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

  private static TargetInfo buildTargetInfo(NetworkEndpoint networkEndpoint) {
    return TargetInfo.newBuilder().addNetworkEndpoints(networkEndpoint).build();
  }
}
