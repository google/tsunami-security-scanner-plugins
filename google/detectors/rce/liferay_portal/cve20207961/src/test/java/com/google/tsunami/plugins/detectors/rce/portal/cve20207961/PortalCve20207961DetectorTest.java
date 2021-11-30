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
package com.google.tsunami.plugins.detectors.rce.portal.cve20207961;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.SECONDS;

import com.google.common.base.Ticker;
import com.google.common.collect.ImmutableList;
import com.google.common.testing.FakeTicker;
import com.google.inject.Guice;
import com.google.inject.testing.fieldbinder.Bind;
import com.google.inject.testing.fieldbinder.BoundFieldModule;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.plugins.detectors.rce.portal.cve20207961.PortalCve20207961DetectorBootstrapModule.StopwatchTicker;
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

/** Tests for Liferay Portal pre-auth RCE vulnerability. */
@RunWith(JUnit4.class)
public final class PortalCve20207961DetectorTest {

  @Bind(to = Ticker.class)
  @StopwatchTicker
  FakeTicker fakeTicker = new FakeTicker();

  @Inject private PortalCve20207961Detector detector;

  private MockWebServer mockWebServer;
  private TimedDispatcher timedDispatcher;
  private TargetInfo targetInfo;
  private ImmutableList<NetworkService> networkServices;

  /**
   * Custom dispatcher that advances a FakeTicker instead of sleeping with a {@link
   * MockResponse#setBodyDelay}.
   */
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
  public void setUp() throws Exception {
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
            new FakeUtcClockModule(),
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
    timedDispatcher.enqueueResponse(
        new MockResponse().setResponseCode(404).setBody("What are you doing?"));

    DetectionReportList reports = detector.detect(targetInfo, networkServices);

    assertThat(reports).isEqualToDefaultInstance();
    assertThat(mockWebServer.getRequestCount()).isEqualTo(1);
  }

  @Test
  public void detect_withFailedTimeCheck_returnsEmpty() {
    timedDispatcher.enqueueResponse(
        new MockResponse()
            .setResponseCode(500)
            .setBody(
                "{\"exception\":\"<--- java.lang.IllegalArgumentException: unknown calendar type:"
                    + " TsunamiExceptionPayload\"}"));
    timedDispatcher.enqueueResponse(
        new MockResponse().setResponseCode(500).setBody("Another error!"));

    DetectionReportList reports = detector.detect(targetInfo, networkServices);

    assertThat(reports).isEqualToDefaultInstance();
    assertThat(mockWebServer.getRequestCount()).isEqualTo(2);
  }

  @Test
  public void detect_withUnexpected200Response_returnsEmpty() {
    timedDispatcher.enqueueResponse(
        new MockResponse()
            .setResponseCode(500)
            .setBody(
                "{\"exception\":\"<--- java.lang.IllegalArgumentException: unknown calendar type:"
                    + " TsunamiExceptionPayload\"}"));
    timedDispatcher.enqueueResponse(new MockResponse().setResponseCode(200).setBody("Success?!"));

    DetectionReportList reports = detector.detect(targetInfo, networkServices);

    assertThat(reports).isEqualToDefaultInstance();
    assertThat(mockWebServer.getRequestCount()).isEqualTo(2);
  }

  @Test
  public void detect_withSleepRCE_returnsDetection() throws Exception {
    timedDispatcher.enqueueResponse(
        new MockResponse()
            .setResponseCode(500)
            .setBody(
                "{\"exception\":\"<--- java.lang.IllegalArgumentException: unknown calendar type:"
                    + " TsunamiExceptionPayload\"}"));
    timedDispatcher.enqueueResponse(
        new MockResponse()
            .setBodyDelay(10, SECONDS)
            .setResponseCode(500)
            .setBody("Another error!"));
    String expectedPath = "/api/jsonws/expandocolumn/add-column";
    DetectionReport expectedReport =
        DetectionReport.newBuilder()
            .setTargetInfo(targetInfo)
            .setNetworkService(networkServices.get(0))
            .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
            .setVulnerability(
                Vulnerability.newBuilder()
                    .setMainId(
                        VulnerabilityId.newBuilder()
                            .setPublisher("GOOGLE")
                            .setValue("CVE_2020_7961"))
                    .setSeverity(Severity.CRITICAL)
                    .setTitle("Liferay Portal Pre-Auth RCE Vulnerability (CVE-2020-7961)")
                    .setDescription(
                        "Deserialization of Untrusted Data in Liferay Portal prior to 7.2.1 CE GA2"
                            + " allows remote attackers to execute arbitrary code via JSON web"
                            + " services (JSONWS)."))
            .build();

    DetectionReportList reports = detector.detect(targetInfo, networkServices);

    assertThat(reports)
        .ignoringFieldDescriptors(
            DetectionReport.getDescriptor()
                .findFieldByNumber(DetectionReport.DETECTION_TIMESTAMP_FIELD_NUMBER))
        .isEqualTo(DetectionReportList.newBuilder().addDetectionReports(expectedReport).build());
    assertThat(mockWebServer.getRequestCount()).isEqualTo(2);
    RecordedRequest request1 = mockWebServer.takeRequest();
    assertThat(request1.getMethod()).isEqualTo("POST");
    assertThat(request1.getPath()).isEqualTo(expectedPath);
    assertThat(request1.getBody().readUtf8()).contains("java.util.Calendar%24Builder");
    RecordedRequest request2 = mockWebServer.takeRequest();
    assertThat(request2.getMethod()).isEqualTo("POST");
    assertThat(request2.getPath()).isEqualTo(expectedPath);
    assertThat(request2.getBody().readUtf8())
        .contains("com.mchange.v2.c3p0.WrapperConnectionPoolDataSource");
  }
}
