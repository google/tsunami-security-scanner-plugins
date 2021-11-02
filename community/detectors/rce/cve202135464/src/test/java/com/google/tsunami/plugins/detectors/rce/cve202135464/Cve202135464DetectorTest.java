/*
 * Copyright 2021 Google LLC
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
package com.google.tsunami.plugins.detectors.rce.cve202135464;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.SECONDS;

import com.google.common.base.Ticker;
import com.google.common.collect.ImmutableList;
import com.google.common.net.HttpHeaders;
import com.google.common.testing.FakeTicker;
import com.google.inject.Guice;
import com.google.inject.testing.fieldbinder.Bind;
import com.google.inject.testing.fieldbinder.BoundFieldModule;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.plugins.detectors.rce.cve202135464.Cve202135464DetectorBootstrapModule.StopwatchTicker;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkEndpoint;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.Software;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TransportProtocol;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
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

/** Unit tests for {@link Cve202135464Detector}. */
@RunWith(JUnit4.class)
public final class Cve202135464DetectorTest {

  @Bind(to = Ticker.class)
  @StopwatchTicker
  FakeTicker fakeTicker = new FakeTicker();

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  @Inject private Cve202135464Detector detector;

  private MockWebServer mockWebServer;
  private TimedDispatcher timedDispatcher;
  private TargetInfo targetInfo;
  private ImmutableList<NetworkService> networkServices;

  private static class TimedDispatcher extends Dispatcher {
    private final Queue<MockResponse> responses = new ConcurrentLinkedQueue<>();
    private final FakeTicker fakeTicker;

    public TimedDispatcher(FakeTicker fakeTicker) {
      this.fakeTicker = fakeTicker;
    }

    public void enqueueResponse(MockResponse response) {
      responses.add(response);
    }

    @Override
    public MockResponse dispatch(RecordedRequest request) throws InterruptedException {
      if (responses.isEmpty()) {
        return new MockResponse().setResponseCode(404);
      }

      MockResponse response = responses.poll();
      if (response == null) {
        return new MockResponse().setResponseCode(404).setBody("no response provided");
      }
      long delayMillis = response.getBodyDelay(MILLISECONDS);
      if (delayMillis > 0) {
        fakeTicker.advance(Duration.ofMillis(delayMillis));
        // Avoid actually sleeping.
        response.setBodyDelay(0, MILLISECONDS);
      }
      return response;
    }
  }

  @Before
  public void setUp() throws IOException {
    timedDispatcher = new TimedDispatcher(fakeTicker);
    mockWebServer = new MockWebServer();
    mockWebServer.setDispatcher(timedDispatcher);
    mockWebServer.start();
    NetworkEndpoint endpoint =
        forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort());
    targetInfo = TargetInfo.newBuilder().addNetworkEndpoints(endpoint).build();
    networkServices =
        ImmutableList.of(
            NetworkService.newBuilder()
                .setNetworkEndpoint(endpoint)
                .setTransportProtocol(TransportProtocol.TCP)
                .setSoftware(Software.newBuilder().setName("http"))
                .setServiceName("http")
                .build());
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            BoundFieldModule.of(this),
            new HttpClientModule.Builder().build())
        .injectMembers(this);
  }

  @After
  public void tearDown() throws IOException {
    mockWebServer.shutdown();
  }

  @Test
  public void detect_withNonVulnerableSite_returnsEmpty() {
    timedDispatcher.enqueueResponse(new MockResponse().setResponseCode(404));

    DetectionReportList reports = detector.detect(targetInfo, networkServices);

    assertThat(reports).isEqualToDefaultInstance();
    assertThat(mockWebServer.getRequestCount()).isEqualTo(1);
    assertThat(reports.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void detect_withUnexpectedRedirectUrl_returnsEmpty() throws Exception {
    timedDispatcher.enqueueResponse(
        new MockResponse()
            .setHeader(HttpHeaders.LOCATION, mockWebServer.url("/openam/config/options.htm"))
            .setBodyDelay(5, SECONDS)
            .setResponseCode(302));
    DetectionReportList reports = detector.detect(targetInfo, networkServices);
    assertThat(reports).isEqualToDefaultInstance();
    assertThat(mockWebServer.getRequestCount()).isEqualTo(1);
    assertThat(reports.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void detect_withSleepRCE_returnsDetection() throws Exception {
    timedDispatcher.enqueueResponse(
        new MockResponse()
            .setHeader(HttpHeaders.LOCATION, mockWebServer.url("/openam/base/AMInvalidURL"))
            .setBodyDelay(5, SECONDS)
            .setResponseCode(302));
    String expectedPath = "/openam/oauth2/..;/ccversion/Version";
    DetectionReport expectedReport = getExpectedDetectionReport(networkServices.get(0), targetInfo);
    DetectionReportList reports = detector.detect(targetInfo, networkServices);
    assertThat(reports)
        .ignoringFieldDescriptors(
            DetectionReport.getDescriptor()
                .findFieldByNumber(DetectionReport.DETECTION_TIMESTAMP_FIELD_NUMBER))
        .isEqualTo(DetectionReportList.newBuilder().addDetectionReports(expectedReport).build());
    assertThat(mockWebServer.getRequestCount()).isEqualTo(1);
    RecordedRequest request = mockWebServer.takeRequest();
    assertThat(request.getMethod()).isEqualTo("GET");
    assertThat(request.getPath()).startsWith(expectedPath);
  }

  private DetectionReport getExpectedDetectionReport(
      NetworkService service, TargetInfo targetInfo) {
    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(service)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder()
                        .setPublisher("TSUNAMI_COMMUNITY")
                        .setValue("CVE_2021_35464"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Pre-auth RCE in OpenAM 14.6.3/ForgeRock AM 7.0 (CVE-2021-35464)")
                .setDescription(
                    "OpenAM server before 14.6.3 and ForgeRock AM server before 7.0 have"
                        + "a Java deserialization vulnerability in the jato.pageSession"
                        + "parameter on multiple pages. The exploitation does not require"
                        + "authentication, and remote code execution can be triggered by"
                        + "sending a single crafted /ccversion/* request to the server."
                        + "The vulnerability exists due to the usage of Sun ONE Application"
                        + "Framework (JATO) found in versions of Java 8 or earlier. The issue"
                        + "was fixed in commit a267913b97002228c2df45f849151e9c373bc47f from"
                        + "OpenIdentityPlatform/OpenAM:master.")
                .setRecommendation(
                    "Block access to the ccversion endpoint using a reverse proxy or"
                        + "other method like disabling VersionServlet mapping in web.xml."
                        + "Update OpenAM to version 14.6.4 and ForgeRockAM to version 7.1"))
        .build();
  }

}
