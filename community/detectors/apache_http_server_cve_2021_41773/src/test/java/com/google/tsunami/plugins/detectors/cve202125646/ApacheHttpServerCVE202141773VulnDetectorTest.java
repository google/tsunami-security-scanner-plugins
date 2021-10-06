package com.google.tsunami.plugins.detectors.cve202125646;

import static com.google.common.truth.Truth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostname;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;

import com.google.common.collect.ImmutableList;
import com.google.inject.Guice;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.plugin.PluginBootstrapModule;
import com.google.tsunami.plugins.detectors.rce.cve202125646
    .ApacheHttpServerCVE202141773VulnDetector;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.NetworkEndpoint;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TransportProtocol;
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

/**
 * Unit tests for {@link ApacheHttpServerCVE202141773VulnDetector}.
 */
public final class ApacheHttpServerCVE202141773VulnDetectorTest {

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  @Inject
  private ApacheHttpServerCVE202141773VulnDetector detector;

  private MockWebServer mockWebServer;

  @Before
  public void setUp() {
    mockWebServer = new MockWebServer();
  }

  @After
  public void tearDown() throws IOException {
    mockWebServer.shutdown();
  }

  private void createInjector() {
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build())
        .injectMembers(this);
  }

  @Test
  public void detect_whenVulnerable_returnsVulnerability()
      throws IOException {
    createInjector();
    mockWebServer.setDispatcher(new VulnerableEndpointDispatcher());
    mockWebServer.start();

    ImmutableList<NetworkService> httpServices = ImmutableList.of(
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("http")
            .build());

    TargetInfo targetInfo = buildTargetInfo(forHostname(mockWebServer.getHostName()));
    DetectionReportList detectionReports = detector.detect(targetInfo, httpServices);
    assertThat(detectionReports.getDetectionReportsList()).containsExactly(
        detector.buildDetectionReport(targetInfo, httpServices.get(0)));
    assertThat(mockWebServer.getRequestCount()).isEqualTo(1);
  }

  @Test
  public void detect_whenNoVulnerable_returnsVulnerability()
      throws IOException {
    createInjector();
    mockWebServer.setDispatcher(new SafeEndpointDispatcher());
    mockWebServer.start();

    ImmutableList<NetworkService> httpServices = ImmutableList.of(
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("http")
            .build());

    TargetInfo targetInfo = buildTargetInfo(forHostname(mockWebServer.getHostName()));
    DetectionReportList detectionReports = detector.detect(targetInfo, httpServices);
    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
    assertThat(mockWebServer.getRequestCount()).isEqualTo(1);
  }


  private static final class VulnerableEndpointDispatcher extends Dispatcher {

    @Override
    public MockResponse dispatch(RecordedRequest recordedRequest) {
      return new MockResponse().setResponseCode(HttpStatus.OK.code())
          .addHeader("Server", "Apache/2.4.49 (Unix)");
    }
  }

  private static final class SafeEndpointDispatcher extends Dispatcher {

    @Override
    public MockResponse dispatch(RecordedRequest recordedRequest) {
      if (recordedRequest.getPath().startsWith("/cgi-bin/.%2e")) {
        return new MockResponse().setResponseCode(HttpStatus.OK.code())
            .addHeader("Server", "Apache/2.4.49 (Unix)")
            .setBody("You don't have permission to access this resource.");
      }
      return new MockResponse().setResponseCode(HttpStatus.OK.code());
    }
  }

  private static TargetInfo buildTargetInfo(NetworkEndpoint networkEndpoint) {
    return TargetInfo.newBuilder().addNetworkEndpoints(networkEndpoint).build();
  }
}
