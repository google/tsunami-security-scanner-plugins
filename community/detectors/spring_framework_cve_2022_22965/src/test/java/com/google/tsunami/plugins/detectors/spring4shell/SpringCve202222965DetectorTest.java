/*
 * Copyright 2025 Google LLC
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
package com.google.tsunami.plugins.detectors.spring4shell;

import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostname;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;
import static com.google.tsunami.plugins.detectors.spring4shell.Annotations.DelayBetweenRequests;
import static com.google.tsunami.plugins.detectors.spring4shell.SpringCve202222965Detector.JSP_FILENAME_PREFIX;

import com.google.common.collect.ImmutableList;
import com.google.inject.Guice;
import com.google.inject.testing.fieldbinder.Bind;
import com.google.inject.testing.fieldbinder.BoundFieldModule;
import com.google.inject.util.Modules;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.plugin.payload.testing.FakePayloadGeneratorModule;
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

/** Unit tests for {@link SpringCve202222965Detector}. */
@RunWith(JUnit4.class)
public final class SpringCve202222965DetectorTest {

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  private final String fakeJspPath = "/" + JSP_FILENAME_PREFIX + fakeUtcClock.millis() + ".jsp";

  @Bind(lazy = true)
  @DelayBetweenRequests
  private final int delayBetweenRequests = 0;

  @Inject private SpringCve202222965Detector detector;

  private MockWebServer mockWebServer;
  private final SecureRandom testSecureRandom =
          new SecureRandom() {
            @Override
            public void nextBytes(byte[] bytes) {
              Arrays.fill(bytes, (byte) 0xFF);
            }
          };

  private final static String MOCK_PAYLOAD_EXECUTION = "TSUNAMI_PAYLOAD_STARTffffffffffffffffTSUNAMI_PAYLOAD_END";

  @Before
  public void setUp() {
    mockWebServer = new MockWebServer();
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            FakePayloadGeneratorModule.builder()
                    .setCallbackServer(null)
                    .setSecureRng(testSecureRandom)
                    .build(),
            new HttpClientModule.Builder().build(),
            Modules.override(new SpringCve202222965DetectorBootstrapModule())
                    .with(BoundFieldModule.of(this)))
        .injectMembers(this);
  }

  @After
  public void tearDown() throws IOException {
    mockWebServer.shutdown();
  }

  @Test
  public void detect_whenVulnerable_returnsVulnerability() throws IOException {
    mockWebServer.setDispatcher(new VulnerabilityEndpointDispatcher(this.fakeJspPath, MOCK_PAYLOAD_EXECUTION));
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

  @Test
  public void detect_whenFalsePositive_returnsNoVulnerability() throws IOException {
    /*
    We simulate a false positive by returning an incorrect response in the
    (supposedly) uploaded JSP page.
     */
    mockWebServer.setDispatcher(new VulnerabilityEndpointDispatcher(this.fakeJspPath, "This is not the page you're looking for."));
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

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }


  static final class SafeEndpointDispatcher extends Dispatcher {

    @Override
    public MockResponse dispatch(RecordedRequest recordedRequest) {
      return new MockResponse().setResponseCode(HttpStatus.OK.code());
    }
  }

  static final class VulnerabilityEndpointDispatcher extends Dispatcher {
    private final String jspPath;
    private final String jspResponse;
    VulnerabilityEndpointDispatcher(String jspPath, String jspResponse) {
      this.jspPath = jspPath;
      this.jspResponse = jspResponse;
    }

    @Override
    public MockResponse dispatch(RecordedRequest recordedRequest) {
      String path = recordedRequest.getPath();
      if (path.equals("/?class.module.classLoader.DefaultAssertionStatus=1")) {
        // Handle preliminary check 1
        return new MockResponse().setResponseCode(HttpStatus.OK.code());
      } else if (path.equals("/?class.module.classLoader.DefaultAssertionStatus=2")) {
        // Handle preliminary check 2
        return new MockResponse().setResponseCode(HttpStatus.BAD_REQUEST.code());
      } else if (path.startsWith(jspPath)) {
        // Handle requests to the uploaded
        return new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody(jspResponse);
      } else if (path.startsWith("/?")) {
        // Handle requests during JSP upload step
        return new MockResponse().setResponseCode(HttpStatus.OK.code());
      } else {
        return new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code());
      }
    }
  }
}
