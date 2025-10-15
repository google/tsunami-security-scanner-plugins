/*
 * Copyright 2024 Google LLC
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

package com.google.tsunami.plugins.rce.flyteconsole;

import static com.google.common.truth.Truth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostname;

import com.google.common.collect.ImmutableList;
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
import java.net.URISyntaxException;
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

/** Unit tests for the {@link ExposedFlyteConsoleDetector}. */
@RunWith(JUnit4.class)
public final class ExposedFlyteConsoleDetectorTest {
  private final MockWebServer mockTargetService = new MockWebServer();
  private final MockWebServer mockCallbackServer = new MockWebServer();
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));
  private static final String MOCK_RESPONSE_BODY =
      "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta"
          + " name=\"description\" content=\"Dashboard values to monitor your FlyteConsole"
          + " instance\"><title>Flyte Dashboard</title>";

  @Inject private ExposedFlyteConsoleDetector detector;

  @Before
  public void setUp() throws IOException {

    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            FakePayloadGeneratorModule.builder().setCallbackServer(mockCallbackServer).build(),
            new ExposedFlyteConsoleDetectorModule())
        .injectMembers(this);
  }

  @After
  public void tearDown() throws Exception {
    mockTargetService.shutdown();
    mockCallbackServer.shutdown();
  }

  /*
   * /console path does not exist.
   */
  @Test
  public void detect_when_endpoint_is_not_console() throws IOException, InterruptedException {

    NetworkService service = TestHelper.createFlyteConsole(mockTargetService);

    TargetInfo target = TestHelper.buildTargetInfo(forHostname(mockTargetService.getHostName()));
    mockTargetService.enqueue(new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code()));
    DetectionReportList detectionReports = detector.detect(target, ImmutableList.of(service));

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
    RecordedRequest req = mockTargetService.takeRequest();
    assertThat(req.getPath()).contains("/console");
  }

  /*
   * console exists, but the callback URL is not called.
   */
  @Test
  public void detect_when_flyte_does_notReportVulnerability()
      throws IOException, InterruptedException, URISyntaxException {

    NetworkService service = TestHelper.createFlyteConsole(mockTargetService);
    mockCallbackServer.enqueue(PayloadTestHelper.generateMockUnsuccessfulCallbackResponse());

    TargetInfo target = TestHelper.buildTargetInfo(forHostname(mockTargetService.getHostName()));
    mockTargetService.enqueue(
        new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody(MOCK_RESPONSE_BODY));

    // Use the mock client
    detector.flyteClient = TestHelper.getMockFlyteProtoClient();

    DetectionReportList detectionReports = detector.detect(target, ImmutableList.of(service));
    assertThat(detectionReports.getDetectionReportsList()).isEmpty();

    RecordedRequest req = mockTargetService.takeRequest();
    assertThat(req.getPath()).contains("/console");
  }

  /*
   * /console exists, and the RCE executed.
   */

  @Test
  public void detect_when_flyte_reportVulnerability()
      throws IOException, InterruptedException, URISyntaxException {

    NetworkService service = TestHelper.createFlyteConsole(mockTargetService);
    mockCallbackServer.enqueue(PayloadTestHelper.generateMockSuccessfulCallbackResponse());

    TargetInfo target = TestHelper.buildTargetInfo(forHostname(mockTargetService.getHostName()));
    mockTargetService.enqueue(
        new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody(MOCK_RESPONSE_BODY));

    detector.flyteClient = TestHelper.getMockFlyteProtoClient();

    DetectionReportList detectionReports = detector.detect(target, ImmutableList.of(service));
    assertThat(detectionReports.getDetectionReportsList())
        .contains(TestHelper.buildValidDetectionReport(detector, target, service, fakeUtcClock));
  }
}
