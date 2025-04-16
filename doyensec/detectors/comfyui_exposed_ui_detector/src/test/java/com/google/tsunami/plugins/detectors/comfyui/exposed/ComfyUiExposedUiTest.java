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

package com.google.tsunami.plugins.detectors.comfyui.exposed;

import static com.google.common.truth.Truth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostname;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;
import static com.google.tsunami.plugins.detectors.comfyui.exposed.ComfyUiExposedUi.MANAGER_VERSION_ENDPOINT;
import static com.google.tsunami.plugins.detectors.comfyui.exposed.ComfyUiExposedUi.STATS_ENDPOINT;
import static com.google.tsunami.plugins.detectors.comfyui.exposed.ComfyUiExposedUi.VULNERABILITY_REPORT_DESCRIPTION;
import static com.google.tsunami.plugins.detectors.comfyui.exposed.ComfyUiExposedUi.VULNERABILITY_REPORT_PUBLISHER;
import static com.google.tsunami.plugins.detectors.comfyui.exposed.ComfyUiExposedUi.VULNERABILITY_REPORT_RECOMMENDATION;
import static com.google.tsunami.plugins.detectors.comfyui.exposed.ComfyUiExposedUi.VULNERABILITY_REPORT_TITLE;

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
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TransportProtocol;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
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

/** Unit tests for {@link ComfyUiExposedUi}. */
@RunWith(JUnit4.class)
public final class ComfyUiExposedUiTest {

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2025-03-03T11:30:00.00Z"));

  @Bind(lazy = true)
  private final int oobSleepDuration = 0;

  @Inject private ComfyUiExposedUi detector;
  private MockWebServer mockWebServer = new MockWebServer();

  private static final String VERSION = "V3.25.1";

  private static final String VULNERABLE_RESPONSE =
      "{\"system\": {\"os\": \"posix\", \"ram_total\": 8337022976, \"ram_free\":"
          + " 7153561600, \"comfyui_version\": \"0.3.15\", \"python_version\": \"3.10.14"
          + " (main, Mar 21 2024, 16:24:04) [GCC 11.2.0]\", \"pytorch_version\": \"2.3.0\","
          + " \"embedded_python\": false, \"argv\": [\"main.py\", \"--listen\", \"--port\","
          + " \"8188\", \"--cpu\"]}, \"devices\": [{\"name\": \"cpu\", \"type\": \"cpu\","
          + " \"index\": null, \"vram_total\": 8337022976, \"vram_free\": 7153561600,"
          + " \"torch_vram_total\": 8337022976, \"torch_vram_free\": 7153561600}]}";

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
            Modules.override(new ComfyUiExposedUiBootstrapModule()).with(BoundFieldModule.of(this)))
        .injectMembers(this);
  }

  @Test
  public void detect_whenVulnerable_reportsCriticalVulnerability() throws IOException {
    ImmutableList<NetworkService> httpServices = mockWebServerSetup(false);
    TargetInfo targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockWebServer.getHostName()))
            .build();

    createInjector();

    DetectionReportList detectionReports = detector.detect(targetInfo, httpServices);

    DetectionReport expectedDetection = generateDetectionReport(targetInfo, httpServices.get(0));
    assertThat(detectionReports.getDetectionReportsList()).containsExactly(expectedDetection);
    assertThat(mockWebServer.getRequestCount()).isEqualTo(3);
  }

  @Test
  public void detect_whenOutdatedAndVulnerable_reportsCriticalVulnerability() throws IOException {
    ImmutableList<NetworkService> httpServices = mockWebServerSetup(true);
    TargetInfo targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockWebServer.getHostName()))
            .build();

    createInjector();

    DetectionReportList detectionReports = detector.detect(targetInfo, httpServices);

    DetectionReport expectedDetection = generateDetectionReport(targetInfo, httpServices.get(0));
    assertThat(detectionReports.getDetectionReportsList()).containsExactly(expectedDetection);
    assertThat(mockWebServer.getRequestCount()).isEqualTo(3);
  }

  private DetectionReport generateDetectionReport(
      TargetInfo targetInfo, NetworkService vulnerableNetworkService) {

    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(vulnerableNetworkService)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder()
                        .setPublisher(VULNERABILITY_REPORT_PUBLISHER)
                        .setValue("COMFYUI_EXPOSED_UI"))
                .setSeverity(Severity.CRITICAL)
                .setTitle(VULNERABILITY_REPORT_TITLE)
                .setDescription(VULNERABILITY_REPORT_DESCRIPTION)
                .setRecommendation(VULNERABILITY_REPORT_RECOMMENDATION))
        .build();
  }

  private ImmutableList<NetworkService> mockWebServerSetup(boolean isOutdated) throws IOException {
    mockWebServer.setDispatcher(new EndpointDispatcher(isOutdated));
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

    public EndpointDispatcher(boolean isOutdated) {
      this.isOutdated = isOutdated;
    }

    private final boolean isOutdated;

    @Override
    public MockResponse dispatch(RecordedRequest recordedRequest) {
      if (recordedRequest.getMethod().equals("GET") && recordedRequest.getPath().equals("/")) {
        return new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .setBody("<html><head><title>ComfyUI</title></head></html>");
      } else if (recordedRequest.getMethod().equals("GET")
          && recordedRequest.getPath().equals("/" + MANAGER_VERSION_ENDPOINT)) {
        if (isOutdated) {
          return new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code()).setBody("");
        } else {
          return new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody(VERSION);
        }
      } else if (recordedRequest.getMethod().equals("GET")
          && recordedRequest.getPath().equals("/" + STATS_ENDPOINT)) {
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
