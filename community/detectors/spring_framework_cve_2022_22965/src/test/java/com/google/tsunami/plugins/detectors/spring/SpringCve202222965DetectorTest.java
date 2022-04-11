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
package com.google.tsunami.plugins.detectors.spring;

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
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
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

/** Unit tests for {@link SpringCve202222965Detector}. */
@RunWith(JUnit4.class)
public final class SpringCve202222965DetectorTest {

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  @Inject private SpringCve202222965Detector detector;

  private MockWebServer mockWebServer;

  @Before
  public void setUp() {
    mockWebServer = new MockWebServer();
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new SpringCve202222965DetectorBootstrapModule(),
            new HttpClientModule.Builder().build())
        .injectMembers(this);
  }

  @After
  public void tearDown() throws IOException {
    mockWebServer.shutdown();
  }

  @Test
  public void detect_whenVulnerable_returnsVulnerability() throws IOException {
    mockWebServer.setDispatcher(new VulnerabilityEndpointDispatcher());
    mockWebServer.start();
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
                                .setValue("CVE_2022_22965"))
                        .setSeverity(Severity.CRITICAL)
                        .setTitle("Spring Framework RCE CVE-2022-22965")
                        .setDescription(
                            "A Spring MVC or Spring WebFlux application running on JDK"
                                + " 9+ may be vulnerable to remote code execution (RCE) via data "
                                + "binding. The specific exploit requires the application to run "
                                + "on Tomcat as a WAR deployment. If the application is deployed "
                                + "as a Spring Boot executable jar, i.e. the default, it is not "
                                + "vulnerable to the exploit. However, the nature of the "
                                + "vulnerability is more general, and there may be other ways to "
                                + "exploit it.")
                        .setRecommendation(
                            "Users of affected versions should apply the following mitigation: "
                                + "5.3.x users should upgrade to 5.3.18+, 5.2.x users should "
                                + "upgrade to 5.2.20+."))
                .build());
  }

  @Test
  public void detect_whenNotVulnerable_returnsNoVulnerability() throws IOException {
    mockWebServer.setDispatcher(new SafeEndpointDispatcher());
    mockWebServer.start();
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

  static final class SafeEndpointDispatcher extends Dispatcher {

    @Override
    public MockResponse dispatch(RecordedRequest recordedRequest) {
      return new MockResponse().setResponseCode(HttpStatus.OK.code());
    }
  }

  static final class VulnerabilityEndpointDispatcher extends Dispatcher {

    @Override
    public MockResponse dispatch(RecordedRequest recordedRequest) {
      if ("/?class.module.classLoader.DefaultAssertionStatus=1".equals(recordedRequest.getPath())) {
        return new MockResponse().setResponseCode(HttpStatus.OK.code());
      }
      if ("/?class.module.classLoader.DefaultAssertionStatus=2".equals(recordedRequest.getPath())) {
        return new MockResponse().setResponseCode(HttpStatus.BAD_REQUEST.code());
      }
      return new MockResponse()
          .setResponseCode(HttpStatus.OK.code())
          .setBody("<p><href=\"http://127.0.0.1:8889/\"></p>");
    }
  }
}
