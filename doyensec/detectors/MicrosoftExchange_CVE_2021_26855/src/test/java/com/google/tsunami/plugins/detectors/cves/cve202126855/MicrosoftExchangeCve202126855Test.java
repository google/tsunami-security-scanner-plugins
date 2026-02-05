/*
 * Copyright 2025 Google LLC
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

package com.google.tsunami.plugins.detectors.cves.cve202126855;

import static com.google.common.truth.Truth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostname;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;

import com.google.common.collect.ImmutableList;
import com.google.inject.Guice;
import com.google.inject.testing.fieldbinder.Bind;
import com.google.inject.testing.fieldbinder.BoundFieldModule;
import com.google.inject.util.Modules;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.plugin.payload.testing.FakePayloadGeneratorModule;
import com.google.tsunami.plugin.payload.testing.PayloadTestHelper;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TransportProtocol;
import java.io.IOException;
import java.time.Instant;
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

/** Unit tests for {@link MicrosoftExchangeCve202126855}. */
@RunWith(JUnit4.class)
public final class MicrosoftExchangeCve202126855Test {

  private final FakeUtcClock fakeUtcClock = FakeUtcClock.create().setNow(Instant.parse("2026-01-23T13:37:00.00Z"));

  @Bind(lazy = true)
  private final int oobSleepDuration = 0;

  @Inject
  private MicrosoftExchangeCve202126855 detector;
  private MockWebServer mockWebServer = new MockWebServer();
  private MockWebServer mockCallbackServer = new MockWebServer();

  private static final String SAFE_INSTANCE_RESPONSE = "<html><head><title>Object moved</title></head><body>\n" + //
      "<h2>Object moved to <a href=\"/owa/auth/errorFE.aspx?httpCode=500\">here</a>.</h2>\n" + //
      "</body></html>";

  @Before
  public void setUp() throws IOException {
    mockWebServer = new MockWebServer();
    mockCallbackServer.start();
  }

  @After
  public void tearDown() throws Exception {
    mockCallbackServer.shutdown();
    mockWebServer.shutdown();
  }

  private void createInjector(boolean tcsAvailable) {
    Guice.createInjector(
        new FakeUtcClockModule(fakeUtcClock),
        new HttpClientModule.Builder().build(),
        FakePayloadGeneratorModule.builder()
            .setCallbackServer(tcsAvailable ? mockCallbackServer : null)
            .build(),
        Modules.override(new MicrosoftExchangeCve202126855BootstrapModule())
            .with(BoundFieldModule.of(this)))
        .injectMembers(this);
  }

  @Test
  public void detect_whenVulnerableAndTcsAvailable_reportsCriticalVulnerability()
      throws IOException {
    ImmutableList<NetworkService> httpServices = mockWebServerSetup(true, true);
    TargetInfo targetInfo = TargetInfo.newBuilder()
        .addNetworkEndpoints(forHostname(mockWebServer.getHostName()))
        .build();

    createInjector(true);
    mockCallbackServer.enqueue(PayloadTestHelper.generateMockSuccessfulCallbackResponse());

    DetectionReportList detectionReports = detector.detect(targetInfo, httpServices);

    DetectionReport expectedDetection = generateDetectionReportWithCallback(detector, targetInfo, httpServices.get(0));
    assertThat(detectionReports.getDetectionReportsList()).containsExactly(expectedDetection);
    assertThat(mockWebServer.getRequestCount()).isEqualTo(2);
    assertThat(mockCallbackServer.getRequestCount()).isEqualTo(1);
  }

  @Test
  public void detect_whenNotVulnerableAndTcsAvailable_reportsNoVulnerability() throws IOException {
    ImmutableList<NetworkService> httpServices = mockWebServerSetup(false, true);
    TargetInfo targetInfo = TargetInfo.newBuilder()
        .addNetworkEndpoints(forHostname(mockWebServer.getHostName()))
        .build();

    createInjector(true);
    mockCallbackServer.enqueue(PayloadTestHelper.generateMockUnsuccessfulCallbackResponse());

    DetectionReportList detectionReports = detector.detect(targetInfo, httpServices);

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
    assertThat(mockWebServer.getRequestCount()).isEqualTo(2);
    assertThat(mockCallbackServer.getRequestCount()).isEqualTo(1);
  }

  @Test
  public void detect_whenNotExchangeAndTcsAvailable_reportsNoVulnerability() throws IOException {
    ImmutableList<NetworkService> httpServices = mockWebServerSetup(false, false);
    TargetInfo targetInfo = TargetInfo.newBuilder()
        .addNetworkEndpoints(forHostname(mockWebServer.getHostName()))
        .build();

    createInjector(true);
    mockCallbackServer.enqueue(PayloadTestHelper.generateMockUnsuccessfulCallbackResponse());

    DetectionReportList detectionReports = detector.detect(targetInfo, httpServices);

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
    assertThat(mockWebServer.getRequestCount()).isEqualTo(1);
    assertThat(mockCallbackServer.getRequestCount()).isEqualTo(0);
  }

  private DetectionReport generateDetectionReportWithCallback(
      MicrosoftExchangeCve202126855 detector, TargetInfo targetInfo, NetworkService networkService) {

    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(networkService)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(detector.getAdvisories().get(0))
        .build();
  }

  private ImmutableList<NetworkService> mockWebServerSetup(boolean isVulnerable, boolean isExchange)
      throws IOException {
    mockWebServer.setDispatcher(new EndpointDispatcher(isVulnerable, isExchange));
    mockWebServer.start();
    return ImmutableList.of(
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("http")
            .build());
  }

  static final class EndpointDispatcher extends Dispatcher {
    EndpointDispatcher(boolean isVulnerable, boolean isExchange) {
      this.isVulnerable = isVulnerable;
      this.isExchange = isExchange;
    }

    private final boolean isVulnerable;
    private final boolean isExchange;

    @Override
    public MockResponse dispatch(RecordedRequest recordedRequest) {
      if (recordedRequest.getMethod().equals("GET") && isExchange) {
        if (recordedRequest.getPath().startsWith("/owa/")) {
          // Not vulnerable case
          if (!isVulnerable) {
            return new MockResponse()
                .setResponseCode(HttpStatus.FOUND.code())
                .addHeader("location", "https://" + recordedRequest.getRequestUrl().host() + "/owa/")
                .setBody(SAFE_INSTANCE_RESPONSE);
          } else {
            return new MockResponse().setResponseCode(HttpStatus.OK.code()).addHeader("x-calculatedbetarget",
                "aaaaaaaaa.cb.tsunami");
          }
        } else {
          return new MockResponse().setResponseCode(HttpStatus.FOUND.code()).addHeader("location", "https://" + recordedRequest.getRequestUrl().host() + "/owa/");
        }
      } else {
        // Anything else, return a 404
        return new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code());
      }
    }
  }
}
