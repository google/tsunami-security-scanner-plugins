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
package com.google.tsunami.plugins.detectors.exposedui.spring;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostname;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;

import com.google.common.collect.ImmutableList;
import com.google.common.net.HttpHeaders;
import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.plugins.detectors.exposedui.spring.SpringBootExposedEndpointDetector.Configs;
import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkEndpoint;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.ServiceContext;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TextData;
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

/** Tests for {@link SpringBootExposedEndpointDetector}. */
@RunWith(JUnit4.class)
public final class SpringBootExposedEndpointDetectorTest {
  private static final String VULNERABLE_HEADER_VALUE =
      "attachment; filename=\"heapdump2020-06-15-09-20-live3506123733943811331.hprof.gz\"";

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  private MockWebServer mockWebServer;
  private Configs configs;

  @Inject private SpringBootExposedEndpointDetector detector;

  @Before
  public void setUp() {
    mockWebServer = new MockWebServer();
    configs = new Configs();

    Guice.createInjector(
            new AbstractModule() {
              @Override
              protected void configure() {
                bind(Configs.class).toInstance(configs);
                install(new FakeUtcClockModule(fakeUtcClock));
                install(new HttpClientModule.Builder().build());
                install(new SpringBootExposedEndpointDetectorBootstrapModule());
              }
            })
        .injectMembers(this);
  }

  @After
  public void tearDown() throws IOException {
    mockWebServer.shutdown();
  }

  @Test
  public void detect_whenNoApplicationRootNoEndpointPrefix_checksDefaultEndpoints()
      throws IOException, InterruptedException {
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

    detector.detect(buildTargetInfo(forHostname(mockWebServer.getHostName())), httpServices);

    assertThat(mockWebServer.getRequestCount()).isEqualTo(2);
    assertThat(allRequestedPaths(mockWebServer, 2))
        .containsExactly("/heapdump", "/actuator/heapdump");
  }

  @Test
  public void detect_whenNonEmptyRootAndNoEndpointPrefix_checksDefaultEndpointsOnRootPath()
      throws IOException, InterruptedException {
    mockWebServer.setDispatcher(new SafeEndpointDispatcher());
    mockWebServer.start();
    ImmutableList<NetworkService> httpServices =
        ImmutableList.of(
            NetworkService.newBuilder()
                .setNetworkEndpoint(
                    forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
                .setTransportProtocol(TransportProtocol.TCP)
                .setServiceName("http")
                .setServiceContext(
                    ServiceContext.newBuilder()
                        .setWebServiceContext(
                            WebServiceContext.newBuilder().setApplicationRoot("/root/path")))
                .build());

    detector.detect(buildTargetInfo(forHostname(mockWebServer.getHostName())), httpServices);

    assertThat(mockWebServer.getRequestCount()).isEqualTo(2);
    assertThat(allRequestedPaths(mockWebServer, 2))
        .containsExactly("/root/path/heapdump", "/root/path/actuator/heapdump");
  }

  @Test
  public void
      detect_whenNonEmptyRootAndConfiguredEndpointPrefix_checksConfiguredEndpointsOnRootPath()
          throws IOException, InterruptedException {
    mockWebServer.setDispatcher(new SafeEndpointDispatcher());
    mockWebServer.start();
    ImmutableList<NetworkService> httpServices =
        ImmutableList.of(
            NetworkService.newBuilder()
                .setNetworkEndpoint(
                    forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
                .setTransportProtocol(TransportProtocol.TCP)
                .setServiceName("http")
                .setServiceContext(
                    ServiceContext.newBuilder()
                        .setWebServiceContext(
                            WebServiceContext.newBuilder().setApplicationRoot("/root/path")))
                .build());
    configs.endpointPrefixes = ImmutableList.of("", "/management");

    detector.detect(buildTargetInfo(forHostname(mockWebServer.getHostName())), httpServices);

    assertThat(mockWebServer.getRequestCount()).isEqualTo(2);
    assertThat(allRequestedPaths(mockWebServer, 2))
        .containsExactly("/root/path/heapdump", "/root/path/management/heapdump");
  }

  @Test
  public void detect_whenNetworkServiceVulnerable_returnsExpectedDetectionReport()
      throws IOException {
    mockWebServer.setDispatcher(new VulnerableEndpointDispatcher("/actuator/heapdump"));
    mockWebServer.start();
    ImmutableList<NetworkService> httpServices =
        ImmutableList.of(
            NetworkService.newBuilder()
                .setNetworkEndpoint(
                    forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
                .setTransportProtocol(TransportProtocol.TCP)
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
                                .setValue("EXPOSED_SPRING_BOOT_ACTUATOR_ENDPOINT"))
                        .setSeverity(Severity.CRITICAL)
                        .setTitle("Exposed Spring Boot Actuator Endpoint")
                        .setDescription(
                            "Spring Boot applications have several built-in Actuator endpoints"
                                + " enabled by default. For example, '/env' endpoint exposes all"
                                + " properties from Spring's ConfigurableEnvironment including"
                                + " system environment variables, and '/heapdump' will dump the"
                                + " entire memory of the server into a file. Exposing these"
                                + " endpoints could potentially leak sensitive information to any"
                                + " unauthenticated users.")
                        .setRecommendation("Disable public access to Actuator endpoints.")
                        .addAdditionalDetails(
                            AdditionalDetail.newBuilder()
                                .setTextData(
                                    TextData.newBuilder()
                                        .setText(
                                            String.format(
                                                "Vulnerable endpoint: '%s'",
                                                mockWebServer.url("/actuator/heapdump"))))))
                .build());
  }

  @Test
  public void detect_whenNetworkServiceNotVulnerable_returnsEmptyDetectionReport()
      throws IOException {
    mockWebServer.setDispatcher(new VulnerableEndpointDispatcher("/not/reachable/heapdump"));
    mockWebServer.start();
    ImmutableList<NetworkService> httpServices =
        ImmutableList.of(
            NetworkService.newBuilder()
                .setNetworkEndpoint(
                    forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
                .setTransportProtocol(TransportProtocol.TCP)
                .setServiceName("http")
                .build());

    assertThat(
            detector
                .detect(buildTargetInfo(forHostname(mockWebServer.getHostName())), httpServices)
                .getDetectionReportsList())
        .isEmpty();
  }

  private static TargetInfo buildTargetInfo(NetworkEndpoint networkEndpoint) {
    return TargetInfo.newBuilder().addNetworkEndpoints(networkEndpoint).build();
  }

  private static ImmutableList<String> allRequestedPaths(MockWebServer mockWebServer, int count)
      throws InterruptedException {
    ImmutableList.Builder<String> requestUrlsBuilder = ImmutableList.builder();
    for (int i = 0; i < count; i++) {
      requestUrlsBuilder.add(mockWebServer.takeRequest().getPath());
    }
    return requestUrlsBuilder.build();
  }

  static final class SafeEndpointDispatcher extends Dispatcher {
    @Override
    public MockResponse dispatch(RecordedRequest recordedRequest) {
      return new MockResponse().setResponseCode(HttpStatus.OK.code());
    }
  }

  static final class VulnerableEndpointDispatcher extends Dispatcher {
    private final String vulnerablePath;

    VulnerableEndpointDispatcher(String vulnerablePath) {
      this.vulnerablePath = vulnerablePath;
    }

    @Override
    public MockResponse dispatch(RecordedRequest recordedRequest) {
      if (recordedRequest.getPath().equals(vulnerablePath)) {
        return new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .setHeader(HttpHeaders.CONTENT_DISPOSITION, VULNERABLE_HEADER_VALUE);
      }

      return new MockResponse().setResponseCode(HttpStatus.OK.code());
    }
  }
}
