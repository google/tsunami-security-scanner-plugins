/*
 * Copyright 2023 Google LLC
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
package com.google.tsunami.plugins.detectors.rce.selenium;

// import static com.google.common.net.HttpHeaders.CONTENT_TYPE;
import static com.google.common.truth.Truth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostname;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.collect.ImmutableList;
import com.google.common.io.Resources;
import com.google.inject.Guice;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.plugin.payload.testing.FakePayloadGeneratorModule;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.TargetInfo;
import java.io.IOException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import javax.inject.Inject;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link RCEViaExposedSeleniumGridDetector}. */
@RunWith(JUnit4.class)
public final class RCEViaExposedSeleniumGridDetectorWithOutCallbackServerTest {

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  @Inject private RCEViaExposedSeleniumGridDetector detector;

  private MockWebServer mockSeleniumGridService;
  private final String validRCEResponse;
  private final String validStatusResponse;
  private final String validCreateSessionResponse;
  private final String validSourceFormatString;

  private final SecureRandom testSecureRandom =
      new SecureRandom() {
        @Override
        public void nextBytes(byte[] bytes) {
          Arrays.fill(bytes, (byte) 0xFF);
        }
      };

  public RCEViaExposedSeleniumGridDetectorWithOutCallbackServerTest() throws IOException {

    this.validRCEResponse =
        Resources.toString(Resources.getResource(this.getClass(), "validRCEResponse.json"), UTF_8);
    this.validStatusResponse =
        Resources.toString(
            Resources.getResource(this.getClass(), "validStatusResponse.json"), UTF_8);
    this.validCreateSessionResponse =
        Resources.toString(
            Resources.getResource(this.getClass(), "validCreateSessionResponse.json"), UTF_8);
    this.validSourceFormatString =
        Resources.toString(
            Resources.getResource(this.getClass(), "validSourceResponse.json"), UTF_8);
  }

  @Before
  public void setUp() throws IOException {

    mockSeleniumGridService = new MockWebServer();
    mockSeleniumGridService.start();

    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            FakePayloadGeneratorModule.builder().setSecureRng(testSecureRandom).build(),
            new RCEViaExposedSeleniumGridDetectorBootstrapModule())
        .injectMembers(this);
  }

  @After
  public void tearDown() throws Exception {
    mockSeleniumGridService.shutdown();
  }

  @Test
  public void detect_whenVulnerable_reportsVulnerability()
      throws IOException, InterruptedException {

    // Enqueue Selenium Grid /status endpoint response for exposure test
    mockSeleniumGridService.enqueue(
        new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody(validStatusResponse));

    // Enqueue Selenium Grid /status endpoint response for state
    mockSeleniumGridService.enqueue(
        new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody(validStatusResponse));

    // Enqueue Command Execution (create test RCE file) response
    mockSeleniumGridService.enqueue(
        new MockResponse()
            .setResponseCode(HttpStatus.INTERNAL_SERVER_ERROR.code())
            .setBody(validRCEResponse));

    // Enqueue Selenium Grid /session create response
    mockSeleniumGridService.enqueue(
        new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .setBody(validCreateSessionResponse));

    // Enqueue Selenium Grid file:// request response
    mockSeleniumGridService.enqueue(new MockResponse().setResponseCode(HttpStatus.OK.code()));

    // Enqueue Selenium Grid source-code handler file contents response. Must contain test string.
    String validSourceResponse =
        String.format(validSourceFormatString, RCEViaExposedSeleniumGridDetector.RCE_TEST_STRING);
    mockSeleniumGridService.enqueue(
        new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody(validSourceResponse));

    // Enqueue Close session response
    mockSeleniumGridService.enqueue(new MockResponse().setResponseCode(HttpStatus.OK.code()));

    // Enqueue Command Execution (Remove file / cleanup response)
    mockSeleniumGridService.enqueue(
        new MockResponse()
            .setResponseCode(HttpStatus.INTERNAL_SERVER_ERROR.code())
            .setBody(validRCEResponse));

    NetworkService service = TestHelper.createSeleniumGridService(mockSeleniumGridService);
    TargetInfo target =
        TestHelper.buildTargetInfo(forHostname(mockSeleniumGridService.getHostName()));

    DetectionReportList detectionReports = detector.detect(target, ImmutableList.of(service));
    assertThat(detectionReports.getDetectionReportsList())
        .contains(TestHelper.buildValidDetectionReport(target, service, fakeUtcClock));

    // Selenium exposure check
    RecordedRequest req = mockSeleniumGridService.takeRequest();
    assertThat(req.getPath()).contains("/status");

    // Selenium ready state check
    req = mockSeleniumGridService.takeRequest();
    assertThat(req.getPath()).contains("/status");

    // Command Execution - create file
    req = mockSeleniumGridService.takeRequest();
    assertThat(req.getPath()).contains("/session");

    // Create new session ID
    req = mockSeleniumGridService.takeRequest();
    assertThat(req.getPath()).contains("/session");

    // Request to file://
    req = mockSeleniumGridService.takeRequest();
    assertThat(req.getPath()).contains("/url");

    // Read file contents
    req = mockSeleniumGridService.takeRequest();
    assertThat(req.getPath()).contains("/source");

    // Close session
    req = mockSeleniumGridService.takeRequest();
    assertThat(req.getPath()).contains("/session");

    // Command Execution - Remove the RCE test file
    req = mockSeleniumGridService.takeRequest();
    assertThat(req.getPath()).contains("/session");
  }

  @Test
  public void detect_whenNotVulnerable_doesNotReportVulnerability()
      throws IOException, InterruptedException {

    // One failed response
    mockSeleniumGridService.enqueue(
        new MockResponse().setResponseCode(HttpStatus.FORBIDDEN.code()));

    NetworkService service = TestHelper.createSeleniumGridService(mockSeleniumGridService);

    DetectionReportList detectionReports =
        detector.detect(
            TestHelper.buildTargetInfo(forHostname(mockSeleniumGridService.getHostName())),
            ImmutableList.of(service));

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
    RecordedRequest req = mockSeleniumGridService.takeRequest();
    assertThat(req.getPath()).contains("/status");
  }

  @Test
  public void detect_whenSeleniumRequiresAuthentication_doesNotReportVulnerability()
      throws IOException, InterruptedException {
    NetworkService service = TestHelper.createSeleniumGridService(mockSeleniumGridService);
    // Auth required response
    // HTTP/1.1 401 Unauthorized
    // WWW-Authenticate: Basic realm="selenium-server"
    mockSeleniumGridService.enqueue(
        new MockResponse().setResponseCode(HttpStatus.UNAUTHORIZED.code()));

    DetectionReportList detectionReports =
        detector.detect(
            TestHelper.buildTargetInfo(forHostname(mockSeleniumGridService.getHostName())),
            ImmutableList.of(service));

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
    RecordedRequest req = mockSeleniumGridService.takeRequest();
    assertThat(req.getPath()).contains("/status");
  }

}
