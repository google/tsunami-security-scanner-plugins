package com.google.tsunami.plugins.detectors.cve202125646;

import static com.google.common.truth.Truth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostname;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;

import com.google.common.collect.ImmutableList;
import com.google.inject.Guice;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.plugins.detectors.rce.cve202125646.ApacheHttpServerCVE202141773VulnDetector;
import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkEndpoint;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TextData;
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

/**
 * Unit tests for {@link ApacheHttpServerCVE202141773VulnDetector}.
 */
@RunWith(JUnit4.class)
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
    assertThat(detectionReports.getDetectionReportsList())
        .containsExactly(
            DetectionReport.newBuilder()
                .setTargetInfo(targetInfo)
                .setNetworkService(httpServices.get(0))
                .setDetectionTimestamp(
                    Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
                .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
                .setVulnerability(
                    Vulnerability.newBuilder()
                        .setMainId(
                            VulnerabilityId.newBuilder()
                                .setPublisher("TSUNAMI_COMMUNITY")
                                .setValue("CVE_2021_41773"))
                        .setSeverity(Severity.HIGH)
                        .setTitle(
                            "Apache HTTP Server 2.4.49 Path traversal and disclosure vulnerability")
                        .setDescription(
                            "A flaw was found in a change made to path normalization in Apache HTTP"
                                + " Server 2.4.49. An attacker could use a path traversal attack to"
                                + " map URLs to files outside the expected document root. If files"
                                + " outside of the document root are not protected by \"require all"
                                + " denied\" these requests can succeed. Additionally this flaw"
                                + " could leak the source of interpreted files like CGI scripts."
                                + " This issue is known to be exploited in the wild. This issue"
                                + " affects Apache 2.4.49 and 2.4.50 but not earlier versions."
                                + " https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41773"
                                + " https://httpd.apache.org/security/vulnerabilities_24.html")
                        .setRecommendation("Update to 2.4.51 release.")
                        .addAdditionalDetails(
                            AdditionalDetail.newBuilder()
                                .setTextData(
                                    TextData.newBuilder()
                                        .setText(
                                            "Vulnerable target:\n"
                                                + mockWebServer.url("/")
                                                + "admin/%2e%2e/%2e%2e"
                                                + "/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e"
                                                + "/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd\n"
                                                + "\n"
                                                + "Response:\n"
                                                + "200 Ok\n"
                                                + "Content-Length: 104\n"
                                                + "\n"
                                                + "root:x:0:0:root:/root:/bin/bash\n"
                                                + "bin:x:1:1:bin:/bin:/sbin/nologin\n"
                                                + "daemon:x:2:2:daemon:/sbin:/sbin/nologin"))))
                .build());
    assertThat(mockWebServer.getRequestCount()).isEqualTo(1);
  }

  @Test
  public void detect_whenNoVulnerable_returnsNoFinding()
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
    assertThat(mockWebServer.getRequestCount()).isGreaterThan(1);
  }


  private static final class VulnerableEndpointDispatcher extends Dispatcher {

    @Override
    public MockResponse dispatch(RecordedRequest recordedRequest) {
      return new MockResponse().setResponseCode(HttpStatus.OK.code())
          .setBody("root:x:0:0:root:/root:/bin/bash\n"
              + "bin:x:1:1:bin:/bin:/sbin/nologin\n"
              + "daemon:x:2:2:daemon:/sbin:/sbin/nologin");
    }
  }

  private static final class SafeEndpointDispatcher extends Dispatcher {

    @Override
    public MockResponse dispatch(RecordedRequest recordedRequest) {
      if (recordedRequest.getPath().startsWith("/cgi-bin/")) {
        return new MockResponse().setResponseCode(HttpStatus.FORBIDDEN.code());
      }
      return new MockResponse().setResponseCode(HttpStatus.OK.code());
    }
  }

  private static TargetInfo buildTargetInfo(NetworkEndpoint networkEndpoint) {
    return TargetInfo.newBuilder().addNetworkEndpoints(networkEndpoint).build();
  }
}
