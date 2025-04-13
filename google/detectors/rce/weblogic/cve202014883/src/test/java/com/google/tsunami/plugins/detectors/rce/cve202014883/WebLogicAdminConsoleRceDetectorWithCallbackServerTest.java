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
package com.google.tsunami.plugins.detectors.rce.cve202014883;

import static com.google.common.truth.Truth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostname;

import com.google.common.collect.ImmutableList;
import com.google.inject.Guice;
import com.google.protobuf.util.JsonFormat;
import com.google.tsunami.callbackserver.proto.PollingResult;
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
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link WebLogicAdminConsoleRceDetector}. */
@RunWith(JUnit4.class)
public final class WebLogicAdminConsoleRceDetectorWithCallbackServerTest {
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  @Inject private WebLogicAdminConsoleRceDetector detector;

  private final SecureRandom testSecureRandom =
      new SecureRandom() {
        @Override
        public void nextBytes(byte[] bytes) {
          Arrays.fill(bytes, (byte) 0xFF);
        }
      };

  private MockWebServer mockWebLogicService;
  private MockWebServer mockCallbackServer;

  @Before
  public void setUp() throws IOException {

    mockWebLogicService = new MockWebServer();
    mockCallbackServer = new MockWebServer();
    mockWebLogicService.start();
    mockCallbackServer.start();

    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            FakePayloadGeneratorModule.builder()
                .setCallbackServer(mockCallbackServer)
                .setSecureRng(testSecureRandom)
                .build(),
            new WebLogicAdminConsoleRceDetectorBootstrapModule())
        .injectMembers(this);
  }

  @After
  public void tearDown() throws Exception {
    mockCallbackServer.shutdown();
    mockWebLogicService.shutdown();
  }

  @Test
  public void detect_whenVulnerable_reportsVulnerability() throws IOException {
    mockWebLogicService.enqueue(new MockResponse().setResponseCode(HttpStatus.FORBIDDEN.code()));
    NetworkService service = TestHelper.createWebLogicService(mockWebLogicService);
    PollingResult log = PollingResult.newBuilder().setHasHttpInteraction(true).build();
    String body = JsonFormat.printer().preservingProtoFieldNames().print(log);
    mockCallbackServer.enqueue(
        new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody(body));
    TargetInfo target = TestHelper.buildTargetInfo(forHostname(mockWebLogicService.getHostName()));

    DetectionReportList detectionReports = detector.detect(target, ImmutableList.of(service));

    assertThat(detectionReports.getDetectionReportsList())
        .contains(TestHelper.buildValidDetectionReport(target, service, fakeUtcClock));
  }

  @Test
  public void detect_whenNotVulnerable_doesNotReportVulnerability() {
    mockWebLogicService.enqueue(new MockResponse().setResponseCode(HttpStatus.OK.code()));
    // 404 NOT_FOUND means no valid oob logs for mockCallbackServer
    mockCallbackServer.enqueue(new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code()));
    NetworkService service = TestHelper.createWebLogicService(mockWebLogicService);

    DetectionReportList detectionReports =
        detector.detect(
            TestHelper.buildTargetInfo(forHostname(mockWebLogicService.getHostName())),
            ImmutableList.of(service));

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }
}
