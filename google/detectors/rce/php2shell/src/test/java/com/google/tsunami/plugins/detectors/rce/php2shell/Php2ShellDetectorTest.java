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
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.CrawlResult;
import com.google.tsunami.proto.CrawlTarget;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.HttpHeader;
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
import java.util.Objects;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link Php2ShellDetector}. */
@RunWith(JUnit4.class)
public final class Php2ShellDetectorTest {
  private static final Instant TEST_INSTANT = Instant.parse("2026-01-01T00:00:00.00Z");

  private static final String PHP8_UNPATCHED_STARTUP_WARNINGS_HTML =
      "<br />\n"
          + "<b>Warning</b>:  PHP Request Startup: Session ID is too long or contains illegal"
          + " characters. Only the A-Z, a-z, 0-9, &quot;-&quot;, and &quot;,&quot; characters are"
          + " allowed in <b>Unknown</b> on line <b>0</b><br />\n"
          + "<br />\n"
          + "<b>Warning</b>:  PHP Request Startup: Failed to write session data (files). Please"
          + " verify that the current setting of session.save_path is correct (/tmp) in"
          + " <b>Unknown</b> on line <b>0</b><br />\n"
          + "OK\n";

  private static final String SANITIZED_PHP8_FLUSH_WARNING =
      "Warning:  PHP Request Startup: Failed to write session data (files). Please verify that the"
          + " current setting of session.save_path is correct (/tmp) in Unknown on line 0";

  private final FakeUtcClock fakeUtcClock = FakeUtcClock.create().setNow(TEST_INSTANT);

  private MockWebServer mockPhpServer;
  private Php2ShellDetector detector;

  @Before
  public void setUp() throws IOException {
    mockPhpServer = new MockWebServer();
    mockPhpServer.start();

    HttpClient httpClient =
        Guice.createInjector(
                new FakeUtcClockModule(fakeUtcClock), new HttpClientModule.Builder().build())
            .getInstance(HttpClient.class);
    detector = new Php2ShellDetector(fakeUtcClock, httpClient);
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

  private TargetInfo createTargetInfo(MockWebServer mockService) {
    return TargetInfo.newBuilder()
        .addNetworkEndpoints(forHostname(mockService.getHostName()))
        .build();
  }

  private DetectionReport buildExpectedDetectionReport(
      TargetInfo target,
      NetworkService service,
      String endpointUrl,
      String sessionName,
      String matchedWarning) {
    String detailText =
        String.format(
            "Vulnerable endpoint: %s\nSession parameter: %s\nMatched startup warning: %s",
            endpointUrl, sessionName, matchedWarning);
    return DetectionReport.newBuilder()
        .setTargetInfo(target)
        .setNetworkService(service)
        .setDetectionTimestamp(Timestamps.fromMillis(TEST_INSTANT.toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder().setPublisher("GOOGLE").setValue("CVE-2026-109618"))
                .addRelatedId(
                    VulnerabilityId.newBuilder().setPublisher("CVE").setValue("CVE-2026-109618"))
                .addRelatedId(
                    VulnerabilityId.newBuilder().setPublisher("CVE").setValue("CVE-2026-109619"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("PHP Core RCE (PHP2Shell)")
                .setDescription(Php2ShellDetector.VULN_DESCRIPTION)
                .setRecommendation(Php2ShellDetector.RECOMMENDATION)
                .addAdditionalDetails(
                    AdditionalDetail.newBuilder()
                        .setDescription(
                            "Verified unpatched PHP session.upload_progress startup session flush.")
                        .setTextData(TextData.newBuilder().setText(detailText))))
        .build();
  }

  private static Dispatcher constantResponseDispatcher(MockResponse response) {
    return new Dispatcher() {
      @Override
      public MockResponse dispatch(RecordedRequest request) {
        return response.clone();
      }
    };
  }

  @Test
  public void detect_whenPhp8UnpatchedStartupFlushDifferentialConfirmed_reportsVulnerability()
      throws Exception {
    mockPhpServer.enqueue(
        new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .setBody(PHP8_UNPATCHED_STARTUP_WARNINGS_HTML));
    mockPhpServer.enqueue(new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("OK\n"));
    NetworkService service = createNetworkService(mockPhpServer);
    TargetInfo target = createTargetInfo(mockPhpServer);

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                mockPhpServer.url("/").toString(),
                "PHPSESSID",
                SANITIZED_PHP8_FLUSH_WARNING));
    assertThat(mockPhpServer.getRequestCount()).isEqualTo(2);

    RecordedRequest probeRequest = mockPhpServer.takeRequest();
    String probeBody = probeRequest.getBody().readUtf8();
    assertThat(probeRequest.getHeader("Cookie"))
        .isEqualTo("PHPSESSID=tsunami/invalid_sid_1767225600000");
    assertThat(probeBody).contains("Content-Disposition: form-data; name=\"PHPSESSID\"");
    assertThat(probeBody).contains("tsunami/invalid_sid_1767225600000");
    assertThat(probeBody)
        .contains("Content-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"");

    RecordedRequest controlRequest = mockPhpServer.takeRequest();
    String controlBody = controlRequest.getBody().readUtf8();
    assertThat(controlRequest.getHeader("Cookie"))
        .isEqualTo("PHPSESSID=tsunami/invalid_sid_1767225600000");
    assertThat(controlBody).contains("Content-Disposition: form-data; name=\"PHPSESSID\"");
    assertThat(controlBody).doesNotContain("PHP_SESSION_UPLOAD_PROGRESS");
  }

  @Test
  public void detect_whenLegacyPhp7PlainTextStartupFlushConfirmed_reportsVulnerability() {
    String legacyPlainTextWarnings =
        "\nWarning: Unknown: The session id is too long or contains illegal characters, valid"
            + " characters are a-z, A-Z, 0-9 and '-,' in Unknown on line 0\n"
            + "\nWarning: Unknown: Failed to write session data (files). Please verify that the"
            + " current setting of session.save_path is correct (/var/lib/php/sessions) in Unknown"
            + " on line 0\n";
    mockPhpServer.enqueue(
        new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody(legacyPlainTextWarnings));
    mockPhpServer.enqueue(new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("OK"));
    NetworkService service = createNetworkService(mockPhpServer);
    TargetInfo target = createTargetInfo(mockPhpServer);

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                mockPhpServer.url("/").toString(),
                "PHPSESSID",
                "Warning: Unknown: Failed to write session data (files). Please verify that the"
                    + " current setting of session.save_path is correct (/var/lib/php/sessions) in"
                    + " Unknown on line 0"));
    assertThat(mockPhpServer.getRequestCount()).isEqualTo(2);
  }

  @Test
  public void detect_whenStaticPageReturnsWarningTextWithoutUploadProgress_reportsEmpty() {
    // A static blog post or mirror quoting the literal PHP startup warnings returns the same body
    // on both the probe and the causal-ablation control request.
    mockPhpServer.setDispatcher(
        constantResponseDispatcher(
            new MockResponse()
                .setResponseCode(HttpStatus.OK.code())
                .setBody(PHP8_UNPATCHED_STARTUP_WARNINGS_HTML)));
    NetworkService service = createNetworkService(mockPhpServer);
    TargetInfo target = createTargetInfo(mockPhpServer);

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(mockPhpServer.getRequestCount())
        .isEqualTo(Php2ShellDetector.CANDIDATE_PATHS.size() * 2);
  }

  @Test
  public void detect_whenPatchedPhp8427EmitsOnlyInvalidSidAndFailedReadWarnings_reportsEmpty() {
    mockPhpServer.setDispatcher(
        constantResponseDispatcher(
            new MockResponse()
                .setResponseCode(HttpStatus.OK.code())
                .addHeader("X-Powered-By", "PHP/8.4.27")
                .setBody(
                    "<b>Warning</b>:  PHP Request Startup: Session ID is too long or contains"
                        + " illegal characters. Only the A-Z, a-z, 0-9, &quot;-&quot;, and"
                        + " &quot;,&quot; characters are allowed in <b>Unknown</b> on line"
                        + " <b>0</b><br />\n"
                        + "<b>Warning</b>:  PHP Request Startup: Failed to read session data: files"
                        + " (path: /tmp) in <b>Unknown</b> on line <b>0</b><br />\n"
                        + "OK\n")));
    NetworkService service = createNetworkService(mockPhpServer);
    TargetInfo target = createTargetInfo(mockPhpServer);

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(mockPhpServer.getRequestCount()).isEqualTo(Php2ShellDetector.CANDIDATE_PATHS.size());
  }

  @Test
  public void detect_whenPatchedDistroBackportDisclosesOldPhpVersionAndSetCookie_reportsEmpty() {
    // Regression test: Patched Ubuntu 24.04 LTS (USN-8948-1, 8.3.6-0ubuntu0.24.04.13) discloses
    // X-Powered-By: PHP/8.3.6 with display_startup_errors = Off and session.upload_progress = 1.
    mockPhpServer.setDispatcher(
        constantResponseDispatcher(
            new MockResponse()
                .setResponseCode(HttpStatus.OK.code())
                .addHeader("X-Powered-By", "PHP/8.3.6")
                .addHeader("Server", "Apache/2.4.58 (Ubuntu) PHP/8.3.6")
                .addHeader("Set-Cookie", "PHPSESSID=c8d6d79a48f07ede6d274291da7c09f8; path=/")
                .setBody("OK")));
    NetworkService service = createNetworkService(mockPhpServer);
    TargetInfo target = createTargetInfo(mockPhpServer);

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(mockPhpServer.getRequestCount()).isEqualTo(Php2ShellDetector.CANDIDATE_PATHS.size());
  }

  @Test
  public void detect_whenUserlandRshutdownFailsSessionWriteClose_reportsEmpty() {
    // On patched PHP 8+, a broken userland SessionHandlerInterface::write() at shutdown emits
    // session_write_close(), NOT PHP Request Startup.
    mockPhpServer.setDispatcher(
        constantResponseDispatcher(
            new MockResponse()
                .setResponseCode(HttpStatus.OK.code())
                .setBody(
                    "<b>Warning</b>:  PHP Request Startup: Session ID is too long or contains"
                        + " illegal characters in <b>Unknown</b> on line <b>0</b><br />\n"
                        + "<b>Warning</b>:  session_write_close(): Failed to write session data"
                        + " using user defined save handler. (session.save_path: , handler:"
                        + " BadHandler::write) in <b>Unknown</b> on line <b>0</b><br />\n")));
    NetworkService service = createNetworkService(mockPhpServer);
    TargetInfo target = createTargetInfo(mockPhpServer);

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(mockPhpServer.getRequestCount()).isEqualTo(Php2ShellDetector.CANDIDATE_PATHS.size());
  }

  @Test
  public void
      detect_whenCustomSessionNameDisclosedInSetCookieHeader_retriesWithCustomSessionNameAndReportsVulnerability()
          throws Exception {
    // 1. Default PHPSESSID probe: target uses custom session.name=APPSESSID and calls
    // session_start().
    mockPhpServer.enqueue(
        new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .addHeader("Set-Cookie", "APPSESSID=e4ab7a82c5e9942c044b73ea880bb9d3; path=/")
            .setBody("LOGIN"));
    // 2. Retry probe with APPSESSID + PHP_SESSION_UPLOAD_PROGRESS: triggers unpatched flush.
    mockPhpServer.enqueue(
        new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .setBody(PHP8_UNPATCHED_STARTUP_WARNINGS_HTML));
    // 3. Control probe with APPSESSID without PHP_SESSION_UPLOAD_PROGRESS: only userland
    // session_start() warning in login.php, no startup flush warning.
    mockPhpServer.enqueue(
        new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .setBody(
                "<b>Warning</b>:  session_start(): Session ID is too long or contains illegal"
                    + " characters in <b>/var/www/html/login.php</b> on line <b>1</b><br />\n"
                    + "LOGIN"));
    NetworkService service = createNetworkService(mockPhpServer);
    TargetInfo target = createTargetInfo(mockPhpServer);

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                mockPhpServer.url("/").toString(),
                "APPSESSID",
                SANITIZED_PHP8_FLUSH_WARNING));
    assertThat(mockPhpServer.getRequestCount()).isEqualTo(3);
    assertThat(mockPhpServer.takeRequest().getHeader("Cookie")).startsWith("PHPSESSID=");
    RecordedRequest customProbe = mockPhpServer.takeRequest();
    assertThat(customProbe.getHeader("Cookie"))
        .isEqualTo("APPSESSID=tsunami/invalid_sid_1767225600000");
    assertThat(customProbe.getBody().readUtf8())
        .contains("Content-Disposition: form-data; name=\"APPSESSID\"");
    RecordedRequest customControl = mockPhpServer.takeRequest();
    assertThat(customControl.getHeader("Cookie"))
        .isEqualTo("APPSESSID=tsunami/invalid_sid_1767225600000");
    assertThat(customControl.getBody().readUtf8()).doesNotContain("PHP_SESSION_UPLOAD_PROGRESS");
  }

  @Test
  public void
      detect_whenCustomSessionNameRecordedInCrawlHeaders_probesCustomSessionNameOnStatelessEndpoint() {
    // 1. Default PHPSESSID probe on stateless index.php returns no Set-Cookie header.
    mockPhpServer.enqueue(new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("OK"));
    // 2. Fallback custom session name MYSESSID from CrawlResult response headers triggers flush.
    mockPhpServer.enqueue(
        new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .setBody(PHP8_UNPATCHED_STARTUP_WARNINGS_HTML));
    // 3. Control probe for MYSESSID returns clean OK.
    mockPhpServer.enqueue(new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("OK"));

    String crawledLoginUrl = mockPhpServer.url("/auth/login").toString();
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
                                            .setUrl(crawledLoginUrl)
                                            .setHttpMethod("GET"))
                                    .setResponseCode(200)
                                    .addResponseHeaders(
                                        HttpHeader.newBuilder()
                                            .setKey("Set-Cookie")
                                            .setValue(
                                                "MYSESSID=a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4;"
                                                    + " HttpOnly")))))
            .build();
    TargetInfo target = createTargetInfo(mockPhpServer);

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                mockPhpServer.url("/").toString(),
                "MYSESSID",
                SANITIZED_PHP8_FLUSH_WARNING));
    assertThat(mockPhpServer.getRequestCount()).isEqualTo(3);
  }

  @Test
  public void detect_whenCrawled404AndLivePhpEndpointsExist_skips404AndVerifiesLivePhpEndpoint()
      throws Exception {
    mockPhpServer.enqueue(
        new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .setBody(PHP8_UNPATCHED_STARTUP_WARNINGS_HTML));
    mockPhpServer.enqueue(new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("OK"));

    String deadPhpUrl = mockPhpServer.url("/legacy/removed.php").toString();
    String livePhpUrl = mockPhpServer.url("/custom/upload.php?id=1#section").toString();
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
                                            .setUrl(deadPhpUrl)
                                            .setHttpMethod("GET"))
                                    .setResponseCode(404))
                            .addCrawlResults(
                                CrawlResult.newBuilder()
                                    .setCrawlTarget(
                                        CrawlTarget.newBuilder()
                                            .setUrl(livePhpUrl)
                                            .setHttpMethod("GET"))
                                    .setResponseCode(200))))
            .build();
    TargetInfo target = createTargetInfo(mockPhpServer);

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target, service, livePhpUrl, "PHPSESSID", SANITIZED_PHP8_FLUSH_WARNING));
    assertThat(mockPhpServer.getRequestCount()).isEqualTo(2);
    assertThat(mockPhpServer.takeRequest().getPath()).isEqualTo("/custom/upload.php?id=1");
  }

  @Test
  public void detect_whenRootReturns405ButIndexPhpVulnerable_fallsBackAndReportsVulnerability() {
    mockPhpServer.enqueue(new MockResponse().setResponseCode(HttpStatus.METHOD_NOT_ALLOWED.code()));
    mockPhpServer.enqueue(
        new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .setBody(PHP8_UNPATCHED_STARTUP_WARNINGS_HTML));
    mockPhpServer.enqueue(new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("OK"));
    NetworkService service = createNetworkService(mockPhpServer);
    TargetInfo target = createTargetInfo(mockPhpServer);

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                mockPhpServer.url("/index.php").toString(),
                "PHPSESSID",
                SANITIZED_PHP8_FLUSH_WARNING));
    assertThat(mockPhpServer.getRequestCount()).isEqualTo(3);
  }

  @Test
  public void detect_whenServerReturns302Redirect_doesNotFollowRedirect() throws Exception {
    mockPhpServer.setDispatcher(
        constantResponseDispatcher(
            new MockResponse()
                .setResponseCode(HttpStatus.FOUND.code())
                .setHeader("Location", "/redirected_location")));
    NetworkService service = createNetworkService(mockPhpServer);
    TargetInfo target = createTargetInfo(mockPhpServer);

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(mockPhpServer.getRequestCount()).isEqualTo(Php2ShellDetector.CANDIDATE_PATHS.size());
    assertThat(mockPhpServer.takeRequest().getPath()).isEqualTo("/");
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
    TargetInfo target = createTargetInfo(mockPhpServer);

    DetectionReportList reports = detector.detect(target, ImmutableList.of(sshService));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(mockPhpServer.getRequestCount()).isEqualTo(0);
  }

  @Test
  public void
      detect_whenHyphenatedHostPrefixedSessionCookieDisclosedAlongsideIgnoredCookie_verifiesViaCausalAblation()
          throws Exception {
    mockPhpServer.enqueue(
        new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .addHeader("Set-Cookie", "XSRF-TOKEN=0123456789abcdef0123456789abcdef; Path=/")
            .addHeader(
                "Set-Cookie",
                "__Host-PHPSESSID=a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4; Path=/; Secure; HttpOnly")
            .setBody("LOGIN"));
    mockPhpServer.enqueue(
        new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .setBody(PHP8_UNPATCHED_STARTUP_WARNINGS_HTML));
    mockPhpServer.enqueue(new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("OK"));
    NetworkService service = createNetworkService(mockPhpServer);
    TargetInfo target = createTargetInfo(mockPhpServer);

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                mockPhpServer.url("/").toString(),
                "__Host-PHPSESSID",
                SANITIZED_PHP8_FLUSH_WARNING));
    assertThat(mockPhpServer.getRequestCount()).isEqualTo(3);

    assertThat(mockPhpServer.takeRequest().getHeader("Cookie")).startsWith("PHPSESSID=");
    RecordedRequest customProbe = mockPhpServer.takeRequest();
    assertThat(customProbe.getHeader("Cookie"))
        .isEqualTo("__Host-PHPSESSID=tsunami/invalid_sid_1767225600000");
    String customProbeBody = customProbe.getBody().readUtf8();
    assertThat(customProbeBody)
        .contains("Content-Disposition: form-data; name=\"__Host-PHPSESSID\"");
    assertThat(customProbeBody)
        .contains("Content-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"");

    RecordedRequest customControl = mockPhpServer.takeRequest();
    assertThat(customControl.getHeader("Cookie"))
        .isEqualTo("__Host-PHPSESSID=tsunami/invalid_sid_1767225600000");
    assertThat(customControl.getBody().readUtf8()).doesNotContain("PHP_SESSION_UPLOAD_PROGRESS");
  }

  @Test
  public void detect_whenHyphenatedAppSessIdRecordedInCrawlHeaders_verifiesViaCausalAblation()
      throws Exception {
    mockPhpServer.enqueue(new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("OK"));
    mockPhpServer.enqueue(
        new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .setBody(PHP8_UNPATCHED_STARTUP_WARNINGS_HTML));
    mockPhpServer.enqueue(new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("OK"));

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
                                            .setUrl(mockPhpServer.url("/account").toString())
                                            .setHttpMethod("GET"))
                                    .setResponseCode(HttpStatus.OK.code())
                                    .addResponseHeaders(
                                        HttpHeader.newBuilder()
                                            .setKey("Set-Cookie")
                                            .setValue(
                                                "APP-SESS-ID=0123456789abcdef0123456789; Path=/;"
                                                    + " HttpOnly")))))
            .build();
    TargetInfo target = createTargetInfo(mockPhpServer);

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                mockPhpServer.url("/").toString(),
                "APP-SESS-ID",
                SANITIZED_PHP8_FLUSH_WARNING));
    assertThat(mockPhpServer.getRequestCount()).isEqualTo(3);
    assertThat(mockPhpServer.takeRequest().getHeader("Cookie")).startsWith("PHPSESSID=");
    assertThat(mockPhpServer.takeRequest().getHeader("Cookie"))
        .isEqualTo("APP-SESS-ID=tsunami/invalid_sid_1767225600000");
    assertThat(mockPhpServer.takeRequest().getHeader("Cookie"))
        .isEqualTo("APP-SESS-ID=tsunami/invalid_sid_1767225600000");
  }

  @Test
  public void
      detect_whenHyphenatedIgnoredNonPhpCookiesReturnedInSetCookieAndCrawl_sendsNoRetryRequests() {
    mockPhpServer.setDispatcher(
        constantResponseDispatcher(
            new MockResponse()
                .setResponseCode(HttpStatus.OK.code())
                .addHeader("Set-Cookie", "XSRF-TOKEN=0123456789abcdef0123456789abcdef; Path=/")
                .addHeader("Set-Cookie", "CSRF-TOKEN=fedcba9876543210fedcba9876543210; Path=/")
                .addHeader(
                    "Set-Cookie", "__cf-bm=11223344556677889900aabbccddeeff; Path=/; HttpOnly")
                .addHeader(
                    "Set-Cookie",
                    "laravel-session=aabbccddeeff00112233445566778899; Path=/; HttpOnly")
                .setBody("OK")));

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
                                            .setUrl(mockPhpServer.url("/").toString())
                                            .setHttpMethod("GET"))
                                    .setResponseCode(HttpStatus.OK.code())
                                    .addResponseHeaders(
                                        HttpHeader.newBuilder()
                                            .setKey("Set-Cookie")
                                            .setValue(
                                                "XSRF-TOKEN=0123456789abcdef0123456789abcdef;"
                                                    + " Path=/"))
                                    .addResponseHeaders(
                                        HttpHeader.newBuilder()
                                            .setKey("Set-Cookie")
                                            .setValue(
                                                "CSRF-TOKEN=fedcba9876543210fedcba9876543210;"
                                                    + " Path=/"))
                                    .addResponseHeaders(
                                        HttpHeader.newBuilder()
                                            .setKey("Set-Cookie")
                                            .setValue(
                                                "__cf-bm=11223344556677889900aabbccddeeff;"
                                                    + " Path=/"))
                                    .addResponseHeaders(
                                        HttpHeader.newBuilder()
                                            .setKey("Set-Cookie")
                                            .setValue(
                                                "cf-clearance=99887766554433221100ffeeddccbbaa;"
                                                    + " Path=/")))))
            .build();
    TargetInfo target = createTargetInfo(mockPhpServer);

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(mockPhpServer.getRequestCount()).isEqualTo(Php2ShellDetector.CANDIDATE_PATHS.size());
  }

  @Test
  public void
      detect_whenZeroPhpUrlsCrawledAndCandidatePathsFail_verifiesExtensionlessHtmlRouteAfterCandidatePaths()
          throws Exception {
    for (int i = 0; i < Php2ShellDetector.CANDIDATE_PATHS.size(); i++) {
      mockPhpServer.enqueue(
          new MockResponse()
              .setResponseCode(HttpStatus.FOUND.code())
              .setHeader("Location", "/users/login"));
    }
    mockPhpServer.enqueue(
        new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .setBody(PHP8_UNPATCHED_STARTUP_WARNINGS_HTML));
    mockPhpServer.enqueue(
        new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("LOGIN"));

    String extensionlessRouteUrl = mockPhpServer.url("/users/login").toString();
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
                                            .setUrl(extensionlessRouteUrl)
                                            .setHttpMethod("GET"))
                                    .setResponseCode(HttpStatus.OK.code())
                                    .addResponseHeaders(
                                        HttpHeader.newBuilder()
                                            .setKey("Content-Type")
                                            .setValue("application/xhtml+xml; charset=UTF-8")))))
            .build();
    TargetInfo target = createTargetInfo(mockPhpServer);

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target, service, extensionlessRouteUrl, "PHPSESSID", SANITIZED_PHP8_FLUSH_WARNING));
    assertThat(mockPhpServer.getRequestCount())
        .isEqualTo(Php2ShellDetector.CANDIDATE_PATHS.size() + 2);
    assertThat(mockPhpServer.takeRequest().getPath()).isEqualTo("/");
    assertThat(mockPhpServer.takeRequest().getPath()).isEqualTo("/index.php");
    assertThat(mockPhpServer.takeRequest().getPath()).isEqualTo("/public/index.php");
    assertThat(mockPhpServer.takeRequest().getPath()).isEqualTo("/web/index.php");
    assertThat(mockPhpServer.takeRequest().getPath()).isEqualTo("/wp-login.php");
    assertThat(mockPhpServer.takeRequest().getPath()).isEqualTo("/users/login");
    assertThat(mockPhpServer.takeRequest().getPath()).isEqualTo("/users/login");
  }

  @Test
  public void
      detect_whenStaticCrossSchemeAndMultipleExtensionlessRoutesCrawled_probesAtMostOneExtensionlessHtmlRoute()
          throws Exception {
    mockPhpServer.setDispatcher(
        constantResponseDispatcher(
            new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code()).setBody("Not Found")));

    String httpsCrossSchemeUrl =
        String.format(
            "https://%s:%d/secure/login", mockPhpServer.getHostName(), mockPhpServer.getPort());
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
                                            .setUrl(mockPhpServer.url("/?page=home").toString())
                                            .setHttpMethod("GET"))
                                    .setResponseCode(HttpStatus.OK.code())
                                    .setContentType("text/html; charset=UTF-8"))
                            .addCrawlResults(
                                CrawlResult.newBuilder()
                                    .setCrawlTarget(
                                        CrawlTarget.newBuilder()
                                            .setUrl(mockPhpServer.url("/about.html").toString())
                                            .setHttpMethod("GET"))
                                    .setResponseCode(HttpStatus.OK.code())
                                    .setContentType("text/html; charset=UTF-8"))
                            .addCrawlResults(
                                CrawlResult.newBuilder()
                                    .setCrawlTarget(
                                        CrawlTarget.newBuilder()
                                            .setUrl(
                                                mockPhpServer.url("/assets/logo.png").toString())
                                            .setHttpMethod("GET"))
                                    .setResponseCode(HttpStatus.OK.code())
                                    .setContentType("image/png"))
                            .addCrawlResults(
                                CrawlResult.newBuilder()
                                    .setCrawlTarget(
                                        CrawlTarget.newBuilder()
                                            .setUrl(mockPhpServer.url("/api/status").toString())
                                            .setHttpMethod("GET"))
                                    .setResponseCode(HttpStatus.OK.code())
                                    .setContentType("application/json"))
                            .addCrawlResults(
                                CrawlResult.newBuilder()
                                    .setCrawlTarget(
                                        CrawlTarget.newBuilder()
                                            .setUrl(httpsCrossSchemeUrl)
                                            .setHttpMethod("GET"))
                                    .setResponseCode(HttpStatus.OK.code())
                                    .setContentType("text/html"))
                            .addCrawlResults(
                                CrawlResult.newBuilder()
                                    .setCrawlTarget(
                                        CrawlTarget.newBuilder()
                                            .setUrl("http://other.example/users/login")
                                            .setHttpMethod("GET"))
                                    .setResponseCode(HttpStatus.OK.code())
                                    .setContentType("text/html"))
                            .addCrawlResults(
                                CrawlResult.newBuilder()
                                    .setCrawlTarget(
                                        CrawlTarget.newBuilder()
                                            .setUrl(mockPhpServer.url("/legacy/route").toString())
                                            .setHttpMethod("GET"))
                                    .setResponseCode(HttpStatus.FOUND.code())
                                    .setContentType("text/html"))
                            .addCrawlResults(
                                CrawlResult.newBuilder()
                                    .setCrawlTarget(
                                        CrawlTarget.newBuilder()
                                            .setUrl(mockPhpServer.url("/users/login").toString())
                                            .setHttpMethod("GET"))
                                    .setResponseCode(HttpStatus.OK.code())
                                    .setContentType("text/html; charset=UTF-8"))
                            .addCrawlResults(
                                CrawlResult.newBuilder()
                                    .setCrawlTarget(
                                        CrawlTarget.newBuilder()
                                            .setUrl(mockPhpServer.url("/users/register").toString())
                                            .setHttpMethod("GET"))
                                    .setResponseCode(HttpStatus.OK.code())
                                    .setContentType("text/html; charset=UTF-8"))))
            .build();
    TargetInfo target = createTargetInfo(mockPhpServer);

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(mockPhpServer.getRequestCount())
        .isEqualTo(Php2ShellDetector.CANDIDATE_PATHS.size() + 1);
    assertThat(mockPhpServer.takeRequest().getPath()).isEqualTo("/");
    assertThat(mockPhpServer.takeRequest().getPath()).isEqualTo("/index.php");
    assertThat(mockPhpServer.takeRequest().getPath()).isEqualTo("/public/index.php");
    assertThat(mockPhpServer.takeRequest().getPath()).isEqualTo("/web/index.php");
    assertThat(mockPhpServer.takeRequest().getPath()).isEqualTo("/wp-login.php");
    assertThat(mockPhpServer.takeRequest().getPath()).isEqualTo("/users/login");
  }

  @Test
  public void detect_whenPhpUrlCrawled_doesNotAppendExtensionlessHtmlFallback() throws Exception {
    mockPhpServer.setDispatcher(
        constantResponseDispatcher(
            new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code()).setBody("Not Found")));

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
                                            .setUrl(mockPhpServer.url("/portal.php").toString())
                                            .setHttpMethod("GET"))
                                    .setResponseCode(HttpStatus.OK.code())
                                    .setContentType("text/html"))
                            .addCrawlResults(
                                CrawlResult.newBuilder()
                                    .setCrawlTarget(
                                        CrawlTarget.newBuilder()
                                            .setUrl(mockPhpServer.url("/users/login").toString())
                                            .setHttpMethod("GET"))
                                    .setResponseCode(HttpStatus.OK.code())
                                    .setContentType("text/html"))))
            .build();
    TargetInfo target = createTargetInfo(mockPhpServer);

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(mockPhpServer.getRequestCount())
        .isEqualTo(1 + Php2ShellDetector.CANDIDATE_PATHS.size());
    assertThat(mockPhpServer.takeRequest().getPath()).isEqualTo("/portal.php");
  }

  @Test
  public void detect_whenOnly404PhpUrlCrawled_probesFallbackPhpUrlWithoutExtensionlessRoute()
      throws Exception {
    mockPhpServer.setDispatcher(
        constantResponseDispatcher(
            new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code()).setBody("Not Found")));

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
                                            .setUrl(mockPhpServer.url("/legacy.php").toString())
                                            .setHttpMethod("GET"))
                                    .setResponseCode(HttpStatus.NOT_FOUND.code())
                                    .setContentType("text/html"))
                            .addCrawlResults(
                                CrawlResult.newBuilder()
                                    .setCrawlTarget(
                                        CrawlTarget.newBuilder()
                                            .setUrl(mockPhpServer.url("/users/login").toString())
                                            .setHttpMethod("GET"))
                                    .setResponseCode(HttpStatus.OK.code())
                                    .setContentType("text/html"))))
            .build();
    TargetInfo target = createTargetInfo(mockPhpServer);

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(mockPhpServer.getRequestCount())
        .isEqualTo(1 + Php2ShellDetector.CANDIDATE_PATHS.size());
    assertThat(mockPhpServer.takeRequest().getPath()).isEqualTo("/legacy.php");
  }

  @Test
  public void detect_whenCrawledCustomCookiePresent_skips404And405And3xxAndCapsLiveRetriesAtTwo()
      throws Exception {
    // Target URLs in order: /portal.php, /, /index.php, /public/index.php, /web/index.php,
    // /wp-login.php.
    // 1. /portal.php -> 302 redirect without Set-Cookie (skip retry).
    mockPhpServer.enqueue(
        new MockResponse().setResponseCode(HttpStatus.FOUND.code()).setHeader("Location", "/"));
    // 2. / -> 405 Method Not Allowed without Set-Cookie (skip retry).
    mockPhpServer.enqueue(new MockResponse().setResponseCode(HttpStatus.METHOD_NOT_ALLOWED.code()));
    // 3. /index.php -> 404 Not Found without Set-Cookie (skip retry).
    mockPhpServer.enqueue(new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code()));
    // 4. /public/index.php -> 200 OK (consumes retry #1 of 2).
    mockPhpServer.enqueue(new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("OK"));
    mockPhpServer.enqueue(new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("OK"));
    // 5. /web/index.php -> 200 OK (consumes retry #2 of 2).
    mockPhpServer.enqueue(new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("OK"));
    mockPhpServer.enqueue(new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("OK"));
    // 6. /wp-login.php -> 200 OK (retry cap exhausted, no retry sent).
    mockPhpServer.enqueue(new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("OK"));

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
                                            .setUrl(mockPhpServer.url("/portal.php").toString())
                                            .setHttpMethod("GET"))
                                    .setResponseCode(HttpStatus.OK.code())
                                    .addResponseHeaders(
                                        HttpHeader.newBuilder()
                                            .setKey("Set-Cookie")
                                            .setValue(
                                                "APP-SESS-ID=0123456789abcdef0123456789;"
                                                    + " Path=/")))))
            .build();
    TargetInfo target = createTargetInfo(mockPhpServer);

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(mockPhpServer.getRequestCount()).isEqualTo(8);

    RecordedRequest req1 = mockPhpServer.takeRequest();
    assertThat(req1.getPath()).isEqualTo("/portal.php");
    assertThat(req1.getHeader("Cookie")).startsWith("PHPSESSID=");

    RecordedRequest req2 = mockPhpServer.takeRequest();
    assertThat(req2.getPath()).isEqualTo("/");
    assertThat(req2.getHeader("Cookie")).startsWith("PHPSESSID=");

    RecordedRequest req3 = mockPhpServer.takeRequest();
    assertThat(req3.getPath()).isEqualTo("/index.php");
    assertThat(req3.getHeader("Cookie")).startsWith("PHPSESSID=");

    RecordedRequest req4 = mockPhpServer.takeRequest();
    assertThat(req4.getPath()).isEqualTo("/public/index.php");
    assertThat(req4.getHeader("Cookie")).startsWith("PHPSESSID=");
    RecordedRequest req5 = mockPhpServer.takeRequest();
    assertThat(req5.getPath()).isEqualTo("/public/index.php");
    assertThat(req5.getHeader("Cookie")).startsWith("APP-SESS-ID=");

    RecordedRequest req6 = mockPhpServer.takeRequest();
    assertThat(req6.getPath()).isEqualTo("/web/index.php");
    assertThat(req6.getHeader("Cookie")).startsWith("PHPSESSID=");
    RecordedRequest req7 = mockPhpServer.takeRequest();
    assertThat(req7.getPath()).isEqualTo("/web/index.php");
    assertThat(req7.getHeader("Cookie")).startsWith("APP-SESS-ID=");

    RecordedRequest req8 = mockPhpServer.takeRequest();
    assertThat(req8.getPath()).isEqualTo("/wp-login.php");
    assertThat(req8.getHeader("Cookie")).startsWith("PHPSESSID=");
  }

  @Test
  public void detect_when302RedirectResponseEmitsCustomSetCookie_retriesAndReportsVulnerability() {
    mockPhpServer.enqueue(
        new MockResponse()
            .setResponseCode(HttpStatus.FOUND.code())
            .setHeader("Location", "/login")
            .addHeader(
                "Set-Cookie",
                "__Host-PHPSESSID=a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4; Path=/; Secure; HttpOnly"));
    mockPhpServer.enqueue(
        new MockResponse()
            .setResponseCode(HttpStatus.FOUND.code())
            .setHeader("Location", "/login")
            .setBody(PHP8_UNPATCHED_STARTUP_WARNINGS_HTML));
    mockPhpServer.enqueue(
        new MockResponse()
            .setResponseCode(HttpStatus.FOUND.code())
            .setHeader("Location", "/login"));
    NetworkService service = createNetworkService(mockPhpServer);
    TargetInfo target = createTargetInfo(mockPhpServer);

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                mockPhpServer.url("/").toString(),
                "__Host-PHPSESSID",
                SANITIZED_PHP8_FLUSH_WARNING));
    assertThat(mockPhpServer.getRequestCount()).isEqualTo(3);
  }

  @Test
  public void detect_when405ResponseItselfEmitsCustomSetCookie_retriesAndReportsVulnerability() {
    mockPhpServer.setDispatcher(
        new Dispatcher() {
          @Override
          public MockResponse dispatch(RecordedRequest request) {
            if (!Objects.equals(request.getPath(), "/")) {
              return new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code());
            }
            String cookie = request.getHeader("Cookie");
            String body = request.getBody().readUtf8();
            if (cookie != null
                && cookie.startsWith("APP-SESS-ID=")
                && body.contains("PHP_SESSION_UPLOAD_PROGRESS")) {
              return new MockResponse()
                  .setResponseCode(HttpStatus.METHOD_NOT_ALLOWED.code())
                  .setBody(PHP8_UNPATCHED_STARTUP_WARNINGS_HTML);
            }
            return new MockResponse()
                .setResponseCode(HttpStatus.METHOD_NOT_ALLOWED.code())
                .addHeader(
                    "Set-Cookie", "APP-SESS-ID=a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4; Path=/; HttpOnly")
                .setBody("Method Not Allowed");
          }
        });
    NetworkService service = createNetworkService(mockPhpServer);
    TargetInfo target = createTargetInfo(mockPhpServer);

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                mockPhpServer.url("/").toString(),
                "APP-SESS-ID",
                SANITIZED_PHP8_FLUSH_WARNING));
    assertThat(mockPhpServer.getRequestCount()).isEqualTo(3);
  }

  @Test
  public void detect_when404ResponseItselfEmitsCustomSetCookie_retriesAndReportsVulnerability() {
    mockPhpServer.enqueue(
        new MockResponse()
            .setResponseCode(HttpStatus.NOT_FOUND.code())
            .addHeader(
                "Set-Cookie", "APP-SESS-ID=a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4; Path=/; HttpOnly")
            .setBody("Not Found"));
    mockPhpServer.enqueue(
        new MockResponse()
            .setResponseCode(HttpStatus.NOT_FOUND.code())
            .setBody(PHP8_UNPATCHED_STARTUP_WARNINGS_HTML));
    mockPhpServer.enqueue(
        new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code()).setBody("Not Found"));
    NetworkService service = createNetworkService(mockPhpServer);
    TargetInfo target = createTargetInfo(mockPhpServer);

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                mockPhpServer.url("/").toString(),
                "APP-SESS-ID",
                SANITIZED_PHP8_FLUSH_WARNING));
    assertThat(mockPhpServer.getRequestCount()).isEqualTo(3);
  }
}
