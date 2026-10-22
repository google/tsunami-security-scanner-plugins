/*
 * Copyright 2026 Google LLC
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
package com.google.tsunami.plugins.detectors.rce.php2shell;

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
import com.google.tsunami.proto.CrawlResult;
import com.google.tsunami.proto.CrawlTarget;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
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
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link Php2ShellDetector}. */
@RunWith(JUnit4.class)
public final class Php2ShellDetectorTest {
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2026-01-01T00:00:00.00Z"));

  @Inject private Php2ShellDetector detector;

  private MockWebServer mockPhpServer;

  @Before
  public void setUp() throws IOException {
    mockPhpServer = new MockWebServer();
    mockPhpServer.start();

    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            new Php2ShellDetectorBootstrapModule())
        .injectMembers(this);
  }

  @After
  public void tearDown() throws Exception {
    mockPhpServer.shutdown();
  }

  private NetworkService createNetworkService(MockWebServer mockService) {
    return NetworkService.newBuilder()
        .setNetworkEndpoint(forHostnameAndPort(mockService.getHostName(), mockService.getPort()))
        .setTransportProtocol(TransportProtocol.TCP)
        .setServiceName("http")
        .build();
  }

  private DetectionReport buildValidDetectionReport(
      TargetInfo target, NetworkService service, FakeUtcClock clock) {
    return DetectionReport.newBuilder()
        .setTargetInfo(target)
        .setNetworkService(service)
        .setDetectionTimestamp(Timestamps.fromMillis(clock.instant().toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder()
                        .setPublisher(Php2ShellDetector.VULNERABILITY_REPORT_PUBLISHER)
                        .setValue(Php2ShellDetector.VULNERABILITY_REPORT_ID))
                .addRelatedId(
                    VulnerabilityId.newBuilder().setPublisher("CVE").setValue("CVE-2026-109618"))
                .addRelatedId(
                    VulnerabilityId.newBuilder().setPublisher("CVE").setValue("CVE-2026-109619"))
                .setSeverity(Severity.CRITICAL)
                .setTitle(Php2ShellDetector.VULNERABILITY_REPORT_TITLE)
                .setDescription(Php2ShellDetector.VULN_DESCRIPTION)
                .setRecommendation(Php2ShellDetector.RECOMMENDATION))
        .build();
  }

  @Test
  public void detect_whenStage1InvalidSidFlushWarningPresent_reportsVulnerability()
      throws Exception {
    mockPhpServer.enqueue(
        new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .setBody(
                "<br />\n"
                    + "<b>Warning</b>:  PHP Request Startup: Session ID "
                    + Php2ShellDetector.STAGE1_INVALID_SID_WARNING
                    + " in <b>Unknown</b> on line <b>0</b><br />\n"
                    + "<b>Warning</b>:  PHP Request Startup: "
                    + Php2ShellDetector.STAGE1_FAILED_FLUSH_WARNING
                    + " (files). in <b>Unknown</b> on line <b>0</b><br />\n"
                    + "OK\n"));

    NetworkService service = createNetworkService(mockPhpServer);
    TargetInfo target =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockPhpServer.getHostName()))
            .build();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(buildValidDetectionReport(target, service, fakeUtcClock));
    assertThat(mockPhpServer.getRequestCount()).isEqualTo(1);
    assertThat(mockPhpServer.takeRequest().getHeader("Cookie"))
        .contains("PHPSESSID=tsunami/invalid_sid_");
  }

  @Test
  public void detect_whenLegacyPhp7InvalidSidFlushWarningPresent_reportsVulnerability() {
    mockPhpServer.enqueue(
        new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .setBody(
                "<b>Warning</b>:  Unknown: The session id "
                    + Php2ShellDetector.STAGE1_INVALID_SID_WARNING
                    + ", valid characters are a-z, A-Z, 0-9 and '-,' in <b>Unknown</b> on line"
                    + " <b>0</b><br />\n"
                    + "<b>Warning</b>:  Unknown: "
                    + Php2ShellDetector.STAGE1_FAILED_FLUSH_WARNING
                    + " (files). in <b>Unknown</b> on line <b>0</b><br />\n"));

    NetworkService service = createNetworkService(mockPhpServer);
    TargetInfo target =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockPhpServer.getHostName()))
            .build();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(buildValidDetectionReport(target, service, fakeUtcClock));
    assertThat(mockPhpServer.getRequestCount()).isEqualTo(1);
  }

  @Test
  public void detect_whenPatchedServerEmitsOnlyInvalidSidWarning_reportsEmpty() {
    for (int i = 0; i < Php2ShellDetector.CANDIDATE_PATHS.size(); i++) {
      // Patched PHP (8.5.12 / 8.4.27) emits only STAGE1_INVALID_SID_WARNING (no failed flush)
      mockPhpServer.enqueue(
          new MockResponse()
              .setResponseCode(HttpStatus.OK.code())
              .addHeader("Set-Cookie", "PHPSESSID=50332b68bd1c46bc8ce25ae1d11a54c5; path=/")
              .setBody(
                  "<b>Warning</b>:  PHP Request Startup: Session ID "
                      + Php2ShellDetector.STAGE1_INVALID_SID_WARNING
                      + " in <b>Unknown</b> on line <b>0</b><br />\n"));
    }

    NetworkService service = createNetworkService(mockPhpServer);
    TargetInfo target =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockPhpServer.getHostName()))
            .build();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void detect_whenRootFailsButIndexPhpVulnerable_reportsVulnerability() {
    // Root path (""): returns 405 Method Not Allowed
    mockPhpServer.enqueue(new MockResponse().setResponseCode(HttpStatus.METHOD_NOT_ALLOWED.code()));
    // Second candidate path ("index.php"): returns unpatched startup flush warnings
    mockPhpServer.enqueue(
        new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .setBody(
                Php2ShellDetector.STAGE1_INVALID_SID_WARNING
                    + "\n"
                    + Php2ShellDetector.STAGE1_FAILED_FLUSH_WARNING));

    NetworkService service = createNetworkService(mockPhpServer);
    TargetInfo target =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockPhpServer.getHostName()))
            .build();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(buildValidDetectionReport(target, service, fakeUtcClock));
    assertThat(mockPhpServer.getRequestCount()).isEqualTo(2);
  }

  @Test
  public void
      detect_whenCrawledPhpEndpointWithQueryAndFragmentVulnerable_checksOnlyFirstPhpEndpoint()
          throws Exception {
    mockPhpServer.enqueue(
        new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .setBody(
                Php2ShellDetector.STAGE1_INVALID_SID_WARNING
                    + "\n"
                    + Php2ShellDetector.STAGE1_FAILED_FLUSH_WARNING));

    String firstPhpUrl = mockPhpServer.url("/custom/upload.php?id=1#section").toString();
    String secondPhpUrl = mockPhpServer.url("/custom/other.php").toString();
    NetworkService service =
        createNetworkService(mockPhpServer).toBuilder()
            .setServiceContext(
                ServiceContext.newBuilder()
                    .setWebServiceContext(
                        WebServiceContext.newBuilder()
                            .addCrawlResults(
                                CrawlResult.newBuilder()
                                    .setCrawlTarget(
                                        CrawlTarget.newBuilder()
                                            .setUrl(firstPhpUrl)
                                            .setHttpMethod("GET")))
                            .addCrawlResults(
                                CrawlResult.newBuilder()
                                    .setCrawlTarget(
                                        CrawlTarget.newBuilder()
                                            .setUrl(secondPhpUrl)
                                            .setHttpMethod("GET")))))
            .build();
    TargetInfo target =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockPhpServer.getHostName()))
            .build();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(buildValidDetectionReport(target, service, fakeUtcClock));
    assertThat(mockPhpServer.getRequestCount()).isEqualTo(1);
    assertThat(mockPhpServer.takeRequest().getPath()).isEqualTo("/custom/upload.php?id=1");
  }

  @Test
  public void detect_whenNonWebService_reportsEmpty() {
    NetworkService sshService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockPhpServer.getHostName(), mockPhpServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("ssh")
            .build();
    TargetInfo target =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockPhpServer.getHostName()))
            .build();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(sshService));

    assertThat(reports.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void detect_whenServerReturnsError_reportsEmpty() {
    for (int i = 0; i < Php2ShellDetector.CANDIDATE_PATHS.size(); i++) {
      mockPhpServer.enqueue(new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code()));
    }

    NetworkService service = createNetworkService(mockPhpServer);
    TargetInfo target =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockPhpServer.getHostName()))
            .build();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void detect_whenServerReturns302Redirect_doesNotFollowRedirect() throws Exception {
    for (int i = 0; i < Php2ShellDetector.CANDIDATE_PATHS.size(); i++) {
      mockPhpServer.enqueue(
          new MockResponse()
              .setResponseCode(HttpStatus.FOUND.code())
              .setHeader("Location", "/redirected_location"));
    }

    NetworkService service = createNetworkService(mockPhpServer);
    TargetInfo target =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockPhpServer.getHostName()))
            .build();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(mockPhpServer.getRequestCount()).isEqualTo(Php2ShellDetector.CANDIDATE_PATHS.size());
    assertThat(mockPhpServer.takeRequest().getPath()).isEqualTo("/");
  }
}
