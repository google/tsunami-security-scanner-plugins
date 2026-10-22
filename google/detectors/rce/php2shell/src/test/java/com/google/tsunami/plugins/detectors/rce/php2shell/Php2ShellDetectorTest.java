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

import static com.google.common.net.HttpHeaders.CONTENT_TYPE;
import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostname;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;

import com.google.common.collect.ImmutableList;
import com.google.common.net.MediaType;
import com.google.inject.Guice;
import com.google.protobuf.util.JsonFormat;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.callbackserver.proto.PollingResult;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.plugin.payload.testing.FakePayloadGeneratorModule;
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
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
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

  private final SecureRandom testSecureRandom =
      new SecureRandom() {
        @Override
        public void nextBytes(byte[] bytes) {
          Arrays.fill(bytes, (byte) 0xFF);
        }
      };

  private MockWebServer mockPhpServer;
  private MockWebServer mockCallbackServer;

  @Before
  public void setUp() throws IOException {
    mockPhpServer = new MockWebServer();
    mockPhpServer.start();
    mockCallbackServer = new MockWebServer();
    mockCallbackServer.start();

    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            FakePayloadGeneratorModule.builder()
                .setCallbackServer(mockCallbackServer)
                .setSecureRng(testSecureRandom)
                .build(),
            new Php2ShellDetectorBootstrapModule())
        .injectMembers(this);
  }

  private void createDetectorWithoutCallbackServer() {
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            FakePayloadGeneratorModule.builder().setSecureRng(testSecureRandom).build(),
            new Php2ShellDetectorBootstrapModule())
        .injectMembers(this);
  }

  @After
  public void tearDown() throws Exception {
    mockCallbackServer.shutdown();
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
  public void detect_whenVulnerableWithCallback_reportsVulnerability() throws IOException {
    for (int i = 0; i < Php2ShellDetector.CANDIDATE_PATHS.size(); i++) {
      mockPhpServer.enqueue(new MockResponse().setResponseCode(HttpStatus.OK.code()));
    }

    PollingResult log = PollingResult.newBuilder().setHasHttpInteraction(true).build();
    String body = JsonFormat.printer().preservingProtoFieldNames().print(log);
    mockCallbackServer.enqueue(
        new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .setHeader(CONTENT_TYPE, MediaType.PLAIN_TEXT_UTF_8.toString())
            .setBody(body));

    NetworkService service = createNetworkService(mockPhpServer);
    TargetInfo target =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockPhpServer.getHostName()))
            .build();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(buildValidDetectionReport(target, service, fakeUtcClock));
  }

  @Test
  public void detect_whenVulnerableWithoutCallback_reportsVulnerability() {
    createDetectorWithoutCallbackServer();
    mockPhpServer.enqueue(
        new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .setBody("TSUNAMI_PAYLOAD_STARTffffffffffffffffTSUNAMI_PAYLOAD_END"));

    NetworkService service = createNetworkService(mockPhpServer);
    TargetInfo target =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockPhpServer.getHostName()))
            .build();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(buildValidDetectionReport(target, service, fakeUtcClock));
  }

  @Test
  public void detect_whenNotVulnerableWithCallback_reportsEmpty() throws IOException {
    for (int i = 0; i < Php2ShellDetector.CANDIDATE_PATHS.size(); i++) {
      mockPhpServer.enqueue(new MockResponse().setResponseCode(HttpStatus.OK.code()));
    }
    PollingResult log = PollingResult.newBuilder().setHasHttpInteraction(false).build();
    String body = JsonFormat.printer().preservingProtoFieldNames().print(log);
    mockCallbackServer.enqueue(
        new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .setHeader(CONTENT_TYPE, MediaType.PLAIN_TEXT_UTF_8.toString())
            .setBody(body));

    NetworkService service = createNetworkService(mockPhpServer);
    TargetInfo target =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockPhpServer.getHostName()))
            .build();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void detect_whenRootFailsButIndexPhpVulnerable_reportsVulnerability() throws IOException {
    mockPhpServer.enqueue(new MockResponse().setResponseCode(HttpStatus.METHOD_NOT_ALLOWED.code()));
    for (int i = 1; i < Php2ShellDetector.CANDIDATE_PATHS.size(); i++) {
      mockPhpServer.enqueue(new MockResponse().setResponseCode(HttpStatus.OK.code()));
    }

    PollingResult callback = PollingResult.newBuilder().setHasHttpInteraction(true).build();
    String callbackBody = JsonFormat.printer().preservingProtoFieldNames().print(callback);
    mockCallbackServer.enqueue(
        new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .setHeader(CONTENT_TYPE, MediaType.PLAIN_TEXT_UTF_8.toString())
            .setBody(callbackBody));

    NetworkService service = createNetworkService(mockPhpServer);
    TargetInfo target =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockPhpServer.getHostName()))
            .build();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(buildValidDetectionReport(target, service, fakeUtcClock));
  }

  @Test
  public void detect_whenCrawledPhpEndpointVulnerable_checksOnlyFirstPhpEndpoint()
      throws Exception {
    createDetectorWithoutCallbackServer();
    mockPhpServer.enqueue(
        new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .setBody("TSUNAMI_PAYLOAD_STARTffffffffffffffffTSUNAMI_PAYLOAD_END"));

    String firstPhpUrl = mockPhpServer.url("/custom/upload.php").toString();
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
    assertThat(mockPhpServer.takeRequest().getPath()).isEqualTo("/custom/upload.php");
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
  public void detect_whenServerReturnsErrorWithoutCallback_reportsEmpty() {
    createDetectorWithoutCallbackServer();
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
    mockPhpServer.enqueue(
        new MockResponse()
            .setResponseCode(HttpStatus.FOUND.code())
            .setHeader("Location", "/redirected_location"));
    for (int i = 1; i < Php2ShellDetector.CANDIDATE_PATHS.size(); i++) {
      mockPhpServer.enqueue(new MockResponse().setResponseCode(HttpStatus.OK.code()));
    }

    PollingResult log = PollingResult.newBuilder().setHasHttpInteraction(true).build();
    String body = JsonFormat.printer().preservingProtoFieldNames().print(log);
    mockCallbackServer.enqueue(
        new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .setHeader(CONTENT_TYPE, MediaType.PLAIN_TEXT_UTF_8.toString())
            .setBody(body));

    NetworkService service = createNetworkService(mockPhpServer);
    TargetInfo target =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockPhpServer.getHostName()))
            .build();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(buildValidDetectionReport(target, service, fakeUtcClock));
    assertThat(mockPhpServer.getRequestCount()).isEqualTo(Php2ShellDetector.CANDIDATE_PATHS.size());
    assertThat(mockPhpServer.takeRequest().getPath()).isEqualTo("/");
  }
}
