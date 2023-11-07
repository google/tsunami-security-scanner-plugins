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
import com.google.tsunami.plugin.payload.testing.PayloadTestHelper;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.TargetInfo;
import java.io.IOException;
import java.time.Instant;
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
public final class RCEViaExposedSeleniumGridDetectorWithCallbackServerTest {

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  @Inject private RCEViaExposedSeleniumGridDetector detector;

  private MockWebServer mockSeleniumGridService;
  private MockWebServer mockCallbackServer;
  private final String validRCEResponse;
  private final String validStatusResponse;

  public RCEViaExposedSeleniumGridDetectorWithCallbackServerTest() throws IOException {
    this.validRCEResponse =
        Resources.toString(Resources.getResource(this.getClass(), "validRCEResponse.json"), UTF_8);
    this.validStatusResponse =
        Resources.toString(
            Resources.getResource(this.getClass(), "validStatusResponse.json"), UTF_8);
  }

  @Before
  public void setUp() throws IOException {

    mockSeleniumGridService = new MockWebServer();
    mockCallbackServer = new MockWebServer();
    mockSeleniumGridService.start();
    mockCallbackServer.start();

    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            FakePayloadGeneratorModule.builder().setCallbackServer(mockCallbackServer).build(),
            new RCEViaExposedSeleniumGridDetectorBootstrapModule())
        .injectMembers(this);
  }

  @After
  public void tearDown() throws Exception {
    mockCallbackServer.shutdown();
    mockSeleniumGridService.shutdown();
  }

  @Test
  public void detect_whenVulnerable_reportsVulnerability()
      throws IOException, InterruptedException {
    NetworkService service = TestHelper.createSeleniumGridService(mockSeleniumGridService);
    TargetInfo target =
        TestHelper.buildTargetInfo(forHostname(mockSeleniumGridService.getHostName()));

    // Enqueue Selenium Grid /status endpoint response for Selenium exposure test request
    mockSeleniumGridService.enqueue(
        new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody(validStatusResponse));

    // Enqueue Selenium Grid /status endpoint response for ready state check
    mockSeleniumGridService.enqueue(
        new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody(validStatusResponse));

    // Enqueue Selenium Grid response to RCE request (should contain "tab crashed")
    mockSeleniumGridService.enqueue(
        new MockResponse()
            .setResponseCode(HttpStatus.INTERNAL_SERVER_ERROR.code())
            .setBody(validRCEResponse));

    mockCallbackServer.enqueue(PayloadTestHelper.generateMockSuccessfulCallbackResponse());

    DetectionReportList detectionReports = detector.detect(target, ImmutableList.of(service));
    assertThat(detectionReports.getDetectionReportsList())
        .contains(TestHelper.buildValidDetectionReport(target, service, fakeUtcClock));

    // Exposure check
    RecordedRequest req = mockSeleniumGridService.takeRequest();
    assertThat(req.getPath()).contains("/status");

    // Ready state check
    req = mockSeleniumGridService.takeRequest();
    assertThat(req.getPath()).contains("/status");

    // RCE execution request
    req = mockSeleniumGridService.takeRequest();
    assertThat(req.getPath()).contains("/session");
  }

  @Test
  public void detect_whenNotVulnerable_doesNotReportVulnerability()
      throws IOException, InterruptedException {
    NetworkService service = TestHelper.createSeleniumGridService(mockSeleniumGridService);
    // One failed response
    mockSeleniumGridService.enqueue(
        new MockResponse().setResponseCode(HttpStatus.FORBIDDEN.code()));
    mockCallbackServer.enqueue(PayloadTestHelper.generateMockUnsuccessfulCallbackResponse());

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
    mockCallbackServer.enqueue(PayloadTestHelper.generateMockUnsuccessfulCallbackResponse());

    DetectionReportList detectionReports =
        detector.detect(
            TestHelper.buildTargetInfo(forHostname(mockSeleniumGridService.getHostName())),
            ImmutableList.of(service));

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
    RecordedRequest req = mockSeleniumGridService.takeRequest();
    assertThat(req.getPath()).contains("/status");
  }

}
