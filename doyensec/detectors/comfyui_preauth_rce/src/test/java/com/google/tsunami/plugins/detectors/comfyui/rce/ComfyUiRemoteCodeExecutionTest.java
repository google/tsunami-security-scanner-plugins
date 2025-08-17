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

package com.google.tsunami.plugins.detectors.comfyui.rce;

import static com.google.common.truth.Truth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostname;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;
import static com.google.tsunami.plugins.detectors.comfyui.rce.ComfyUiRemoteCodeExecution.CLEANUP_ENDPOINT;
import static com.google.tsunami.plugins.detectors.comfyui.rce.ComfyUiRemoteCodeExecution.EXPLOIT_ENDPOINT;
import static com.google.tsunami.plugins.detectors.comfyui.rce.ComfyUiRemoteCodeExecution.INSTALL_ENDPOINT;
import static com.google.tsunami.plugins.detectors.comfyui.rce.ComfyUiRemoteCodeExecution.QUEUE_START_ENDPOINT;
import static com.google.tsunami.plugins.detectors.comfyui.rce.ComfyUiRemoteCodeExecution.REBOOT_ENDPOINT;
import static com.google.tsunami.plugins.detectors.comfyui.rce.ComfyUiRemoteCodeExecution.VERSION_ENDPOINT;

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

/** Unit tests for {@link ComfyUiRemoteCodeExecution}. */
@RunWith(JUnit4.class)
public final class ComfyUiRemoteCodeExecutionTest {

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2025-03-03T11:30:00.00Z"));

  @Bind(lazy = true)
  private final int oobSleepDuration = 0;

  @Inject private ComfyUiRemoteCodeExecution detector;
  private MockWebServer mockWebServer = new MockWebServer();

  private static final String VERSION = "3.25.1";

  private static final String VULNERABLE_RESPONSE = "TSUNAMIYTIRUCESSCANNER";

  @Before
  public void setUp() throws IOException {
    mockWebServer = new MockWebServer();
  }

  @After
  public void tearDown() throws Exception {
    mockWebServer.shutdown();
  }

  private void createInjector() {
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            Modules.override(new ComfyUiRemoteCodeExecutionBootstrapModule())
                .with(BoundFieldModule.of(this)))
        .injectMembers(this);
  }

  @Test
  public void detect_whenVulnerable_reportsCriticalVulnerability() throws IOException {
    ImmutableList<NetworkService> httpServices = mockWebServerSetup(true);
    TargetInfo targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockWebServer.getHostName()))
            .build();

    createInjector();

    DetectionReportList detectionReports = detector.detect(targetInfo, httpServices);

    DetectionReport expectedDetection =
        DetectionReport.newBuilder()
            .setTargetInfo(targetInfo)
            .setNetworkService(httpServices.get(0))
            .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
            .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
            .setVulnerability(detector.getAdvisories().get(0))
            .build();
    assertThat(detectionReports.getDetectionReportsList()).containsExactly(expectedDetection);
    assertThat(mockWebServer.getRequestCount()).isEqualTo(8);
  }

  @Test
  public void detect_whenNotVulnerable_reportsNoVulnerability() throws IOException {
    ImmutableList<NetworkService> httpServices = mockWebServerSetup(false);
    TargetInfo targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockWebServer.getHostName()))
            .build();

    createInjector();

    DetectionReportList detectionReports = detector.detect(targetInfo, httpServices);

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
    assertThat(mockWebServer.getRequestCount()).isEqualTo(1);
  }

  private ImmutableList<NetworkService> mockWebServerSetup(boolean isVulnerable)
      throws IOException {
    mockWebServer.setDispatcher(new EndpointDispatcher(isVulnerable));
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

    public EndpointDispatcher(boolean isVulnerable) {
      this.isVulnerable = isVulnerable;
    }

    private final boolean isVulnerable;

    @Override
    public MockResponse dispatch(RecordedRequest recordedRequest) {
      if (recordedRequest.getMethod().equals("GET") && recordedRequest.getPath().equals("/")) {
        if (isVulnerable) {
          return new MockResponse()
              .setResponseCode(HttpStatus.OK.code())
              .setBody("<html><head><title>ComfyUI</title></head></html>");
        } else {
          return new MockResponse()
              .setResponseCode(HttpStatus.INTERNAL_SERVER_ERROR.code())
              .setBody("");
        }
      } else if (recordedRequest.getMethod().equals("GET")
          && recordedRequest.getPath().equals("/" + QUEUE_START_ENDPOINT)) {
        // Trigger request
        return new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("");
      } else if (recordedRequest.getMethod().equals("POST")
          && recordedRequest.getPath().equals("/" + INSTALL_ENDPOINT)) {
        // Exploit attempt
        return new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("");
      } else if (recordedRequest.getMethod().equals("GET")
          && recordedRequest.getPath().equals("" + REBOOT_ENDPOINT)) {
        // File leak
        return new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("");
      } else if (recordedRequest.getMethod().equals("GET")
          && recordedRequest.getPath().equals("/" + VERSION_ENDPOINT)) {
        return new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody(VERSION);
      } else if (recordedRequest.getMethod().equals("GET")
          && recordedRequest.getPath().equals("/" + CLEANUP_ENDPOINT)) {
        return new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("");
      } else if (recordedRequest.getMethod().equals("GET")
          && recordedRequest.getPath().contains("/" + EXPLOIT_ENDPOINT)) {
        return new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .setBody(VULNERABLE_RESPONSE);
      } else {
        // Anything else, return a 404
        return new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code());
      }
    }
  }
}
