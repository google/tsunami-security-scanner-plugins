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

package com.google.tsunami.plugins.detectors.comfyui.filenameread;

import static com.google.common.truth.Truth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostname;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;
import static com.google.tsunami.plugins.detectors.comfyui.filenameread.ComfyUiFileReadViaFilename.INSTALL_MODEL_ENDPOINT;
import static com.google.tsunami.plugins.detectors.comfyui.filenameread.ComfyUiFileReadViaFilename.LOGS_ENDPOINT;
import static com.google.tsunami.plugins.detectors.comfyui.filenameread.ComfyUiFileReadViaFilename.OS_ENDPOINT;
import static com.google.tsunami.plugins.detectors.comfyui.filenameread.ComfyUiFileReadViaFilename.QUEUE_START_ENDPOINT;
import static com.google.tsunami.plugins.detectors.comfyui.filenameread.ComfyUiFileReadViaFilename.VERSION_ENDPOINT;
import static com.google.tsunami.plugins.detectors.comfyui.filenameread.ComfyUiFileReadViaFilename.VULNERABILITY_REPORT_DESCRIPTION;
import static com.google.tsunami.plugins.detectors.comfyui.filenameread.ComfyUiFileReadViaFilename.VULNERABILITY_REPORT_PUBLISHER;
import static com.google.tsunami.plugins.detectors.comfyui.filenameread.ComfyUiFileReadViaFilename.VULNERABILITY_REPORT_RECOMMENDATION;
import static com.google.tsunami.plugins.detectors.comfyui.filenameread.ComfyUiFileReadViaFilename.VULNERABILITY_REPORT_TITLE;

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

/** Unit tests for {@link ComfyUiFileReadViaFilename}. */
@RunWith(JUnit4.class)
public final class ComfyUiFileReadViaFilenameTest {

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2025-03-03T11:30:00.00Z"));

  @Bind(lazy = true)
  private final int oobSleepDuration = 0;

  @Inject private ComfyUiFileReadViaFilename detector;
  private MockWebServer mockWebServer = new MockWebServer();

  private static final String VERSION = "3.25.1";

  private static final String VULNERABLE_RESPONSE = "127.0.0.1";

  private static final String OS = "{\"system\":{\"os\":\"posix\"}}";

  private static final String WEBROOT_BODY =
      "{\n"
          + "    \"entries\":\n"
          + "    [\n"
          + "        {\n"
          + "            \"t\": \"2025-03-04T15:29:00.595153\",\n"
          + "            \"m\": \"[Prompt Server] web root:"
          + " /Users/savio/ComfyUI.app/Contents/Resources/ComfyUI/web_custom_versions/desktop_app\\n"
          + "\"\n"
          + "        }\n"
          + "    ]\n"
          + "}";

  @Before
  public void setUp() {
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
            Modules.override(new ComfyUiFileReadViaFilenameBootStrapModule())
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

    DetectionReport expectedDetection = generateDetectionReport(targetInfo, httpServices.get(0));
    assertThat(detectionReports.getDetectionReportsList()).containsExactly(expectedDetection);
    assertThat(mockWebServer.getRequestCount()).isEqualTo(7);
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
                        .setValue("COMFYUI_2025_FILE_READ_FILENAME"))
                .setSeverity(Severity.CRITICAL)
                .setTitle(VULNERABILITY_REPORT_TITLE)
                .setDescription(VULNERABILITY_REPORT_DESCRIPTION)
                .setRecommendation(VULNERABILITY_REPORT_RECOMMENDATION))
        .build();
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
          && recordedRequest.getPath().equals("/" + INSTALL_MODEL_ENDPOINT)) {
        // Exploit attempt
        return new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("");
      } else if (recordedRequest.getMethod().equals("GET")
          && recordedRequest.getPath().contains(".safetensors")) {
        // File leak
        return new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .setBody(VULNERABLE_RESPONSE);
      } else if (recordedRequest.getMethod().equals("GET")
          && recordedRequest.getPath().equals("/" + VERSION_ENDPOINT)) {
        return new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody(VERSION);
      } else if (recordedRequest.getMethod().equals("GET")
          && recordedRequest.getPath().equals("/" + LOGS_ENDPOINT)) {
        return new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody(WEBROOT_BODY);
      } else if (recordedRequest.getMethod().equals("GET")
          && recordedRequest.getPath().equals("/" + OS_ENDPOINT)) {
        return new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody(OS);
      } else {
        // Anything else, return a 404
        return new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code());
      }
    }
  }
}
