/*
 * Copyright 2022 Google LLC
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
package com.google.tsunami.plugins.detectors.rce.cve202224112;

import static com.google.common.truth.Truth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostname;

import com.google.common.collect.ImmutableList;
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
import java.time.Instant;
import javax.inject.Inject;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link Cve202224112Detector}. */
@RunWith(JUnit4.class)
public final class Cve202224112DetectorWithoutCallbackServerTest {
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2022-05-23T00:00:00.00Z"));

  private MockWebServer mockWebServer;
  private NetworkService service;
  private TargetInfo targetInfo;

  @Inject private Cve202224112Detector detector;

  @Before
  public void setUp() {
    mockWebServer = new MockWebServer();
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            FakePayloadGeneratorModule.builder().build(),
            new Cve202224112DetectorBootstrapModule())
        .injectMembers(this);

    service = TestHelper.createWebService(mockWebServer);

    targetInfo = TestHelper.buildTargetInfo(forHostname(mockWebServer.getHostName()));
  }

  @After
  public void tearDown() throws IOException {
    mockWebServer.shutdown();
  }

  @Test
  public void detect_whenVulnerable_returnsVulnerability() {
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("[{\"status\":200}]"));
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(HttpStatus.SERVICE_UNAVAILABLE.code()));
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("[{\"status\":200}]"));
    mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code()));

    DetectionReportList detectionReports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(detectionReports.getDetectionReportsList())
        .containsExactly(
            TestHelper.buildValidDetectionReport(detector, targetInfo, service, fakeUtcClock));
    assertThat(mockWebServer.getRequestCount()).isEqualTo(4);
  }

  @Test
  public void detect_ifNotVulnerableBatchRequest_doesNotReportVuln() {
    mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code()));

    DetectionReportList detectionReports = detector.detect(targetInfo, ImmutableList.of(service));
    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void detect_ifNotVulnerableHtmlResponse_doesNotReportVuln() {
    mockWebServer.enqueue(
        new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .setBody(
                "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta"
                    + " name=\"viewport\" content=\"width=device-width, initial-scale=1,"
                    + " shrink-to-fit=no\">\n"
                    + "Error\n"));

    DetectionReportList detectionReports = detector.detect(targetInfo, ImmutableList.of(service));
    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void detect_ifNotCreatedRoute_doesNotReportVuln() {
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("[{\"status\":200}]"));
    mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code()));

    DetectionReportList detectionReports = detector.detect(targetInfo, ImmutableList.of(service));
    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }
}
