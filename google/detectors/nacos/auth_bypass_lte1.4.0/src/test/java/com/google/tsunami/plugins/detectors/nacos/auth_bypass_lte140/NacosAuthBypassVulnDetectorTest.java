package com.google.tsunami.plugins.detectors.nacos.auth_bypass_lte140;

import com.google.common.collect.ImmutableList;
import com.google.inject.Guice;
import com.google.inject.Inject;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.proto.*;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.time.Instant;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.google.common.truth.Truth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostname;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;

public class NacosAuthBypassVulnDetectorTest {

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  @Inject
  private NacosAuthBypassVulnDetector detector;

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
  public void testAuthBypass()
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
    assertThat(mockWebServer.getRequestCount()).isEqualTo(3);
  }


  static final class VulnerableEndpointDispatcher extends Dispatcher {

    private String username;

    private Pattern pattern = Pattern.compile("username=(.+?)&");

    @Override
    public MockResponse dispatch(RecordedRequest recordedRequest) {
      if (recordedRequest.getPath().startsWith("/nacos/v1/auth/users")) {
        if (recordedRequest.getMethod().equals("POST")) {
          Matcher matcher = pattern.matcher(recordedRequest.getPath());
          boolean match = matcher.find();
          if (!match) {
            matcher = pattern.matcher(recordedRequest.getUtf8Body());
            match = matcher.find();
          }
          if (match) {
            this.username = matcher.group(1);
          } else {
            return new MockResponse().setResponseCode(HttpStatus.OK.code());
          }
          return new MockResponse().setResponseCode(HttpStatus.OK.code())
              .setBody("create user ok!");
        } else if (recordedRequest.getMethod().equals("GET")) {
          return new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody(username);
        } else if (recordedRequest.getMethod().equals("DELETE")) {
          return new MockResponse().setResponseCode(HttpStatus.OK.code())
              .setBody("delete user ok!");
        }
      }
      return new MockResponse().setResponseCode(HttpStatus.OK.code());
    }
  }

  private static TargetInfo buildTargetInfo(NetworkEndpoint networkEndpoint) {
    return TargetInfo.newBuilder().addNetworkEndpoints(networkEndpoint).build();
  }
}
