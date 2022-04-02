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
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.Date;
import javax.inject.Inject;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Unit tests for {@link SpringCve202222965Detector}.
 */
@RunWith(JUnit4.class)
public final class SpringCve202222965DetectorTest {

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  @Inject
  private SpringCve202222965Detector detector;

  private MockWebServer mockWebServer;
  private NetworkService testService;

  private static final String VULNERABILITY_PAYLOAD_STRING_1 =
      "class.module.classLoader.DefaultAssertionStatus=1";
  private static final String VULNERABILITY_PAYLOAD_STRING_2 =
      "class.module.classLoader.DefaultAssertionStatus=2";

  @Before
  public void setUp() {
    mockWebServer = new MockWebServer();
    testService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setSoftware(Software.newBuilder().setName("Spring"))
            .setServiceName("http")
            .build();

    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            new SpringCve202222965DetectorBootstrapModule())
        .injectMembers(this);
  }

  @Test
  public void detect_whenIsVulnerable_reportsVuln() {
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(200).setBody("<p>Spring CVE-2022-22965 Test Page</p>\n"
            + "<a href=\"http://127.0.0.1:8081/\">vulnerable site</a>"));
    mockWebServer.url("index.html");
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(200).setBody(""));
    mockWebServer.url("?"+VULNERABILITY_PAYLOAD_STRING_1);
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(400).setBody(""));
    mockWebServer.url("?"+VULNERABILITY_PAYLOAD_STRING_2);

    DetectionReportList detectionReports =
        detector.detect(TargetInfo.getDefaultInstance(), ImmutableList.of(testService));

    assertThat(detectionReports.getDetectionReportsList())
        .containsExactly(
            DetectionReport.newBuilder()
                .setTargetInfo(TargetInfo.getDefaultInstance())
                .setNetworkService(testService)
                .setDetectionTimestamp(
                    Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
                .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
                .setVulnerability(
                    Vulnerability.newBuilder()
                        .setMainId(VulnerabilityId.newBuilder().setPublisher("TSUNAMI_COMMUNITY")
                            .setValue("CVE_2022_22965"))
                        .setSeverity(Severity.CRITICAL)
                        .setTitle("Spring Framework RCE CVE-2022-22965")
                        .setDescription("A Spring MVC or Spring WebFlux application running on JDK"
                            + " 9+ may be vulnerable to remote code execution (RCE) via data "
                            + "binding. The specific exploit requires the application to run on "
                            + "Tomcat as a WAR deployment. If the application is deployed as a "
                            + "Spring Boot executable jar, i.e. the default, it is not vulnerable "
                            + "to the exploit. However, the nature of the vulnerability is more "
                            + "general, and there may be other ways to exploit it.")
                ).build()
        );
  }

  @Test
  public void detect_whenIsNotVulnerable_doesNotReportVuln() {
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(200).setBody("<p>Spring CVE-2022-22965 Test Page</p>\n"
            + "<a href=\"http://127.0.0.1:8082/\">fixed site</a>"));
    mockWebServer.url("index.html");
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(200).setBody(""));
    mockWebServer.url("?"+VULNERABILITY_PAYLOAD_STRING_1);
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(200).setBody(""));
    mockWebServer.url("?"+VULNERABILITY_PAYLOAD_STRING_2);

    assertThat(
        detector
            .detect(
                buildTargetInfo(forHostname(mockWebServer.getHostName())),
                ImmutableList.of(testService))
            .getDetectionReportsList())
        .isEmpty();
  }

  private static TargetInfo buildTargetInfo(NetworkEndpoint networkEndpoint) {
    return TargetInfo.newBuilder().addNetworkEndpoints(networkEndpoint).build();
  }
}
