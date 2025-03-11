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

package com.google.tsunami.plugins.detectors.cves.cve20250655;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.collect.ImmutableList;
import com.google.common.io.Resources;
import com.google.inject.Guice;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.plugin.payload.testing.FakePayloadGeneratorModule;
import com.google.tsunami.plugin.payload.testing.PayloadTestHelper;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
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

/** Unit tests for {@link Cve20250655VulnDetector}. */
@RunWith(JUnit4.class)
public class Cve20250655VulnDetectorTest {
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2022-05-23T00:00:00.00Z"));
  private MockWebServer mockWebServer;
  private MockWebServer mockCallbackServer;
  private NetworkService targetNetworkService;
  private TargetInfo targetInfo;
  private String notFoundPageResponse;

  @Inject private Cve20250655VulnDetector detector;

  @Before
  public void setUp() throws IOException {
    mockWebServer = new MockWebServer();
    mockCallbackServer = new MockWebServer();
    mockCallbackServer.start();
    notFoundPageResponse = Resources.toString(Resources.getResource("404.html"), UTF_8);
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            FakePayloadGeneratorModule.builder().setCallbackServer(mockCallbackServer).build(),
            new Cve20250655DetectorBootstrapModule())
        .injectMembers(this);
  }

  @After
  public void tearDown() throws IOException {
    mockWebServer.shutdown();
    mockCallbackServer.shutdown();
  }

  @Test
  public void detect_whenVulnerable_returnsVulnerability() throws IOException {
    startMockWebServer(true);
    mockCallbackServer.enqueue(PayloadTestHelper.generateMockSuccessfulCallbackResponse());
    DetectionReportList detectionReports =
        detector.detect(targetInfo, ImmutableList.of(targetNetworkService));
    assertThat(detectionReports.getDetectionReportsList())
        .containsExactly(
            DetectionReport.newBuilder()
                .setTargetInfo(targetInfo)
                .setNetworkService(targetNetworkService)
                .setDetectionTimestamp(
                    Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
                .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
                .setVulnerability(
                    Vulnerability.newBuilder()
                        .setMainId(
                            VulnerabilityId.newBuilder()
                                .setPublisher("TSUNAMI_COMMUNITY")
                                .setValue("CVE_2025_0655"))
                        .setSeverity(Severity.CRITICAL)
                        .setTitle("CVE-2025-0655 D-Tale Remote Code Execution")
                        .setDescription(
                            "D-Tale is vulnerable to a Remote Code Execution vulnerability, which"
                                + " was fixed in version 3.16.1, due to Global State Override"
                                + " mechanism. Specifically, this vulnerability leverages the"
                                + " ability to manipulate global  application settings to activate"
                                + " the enable_custom_filters feature, typically restricted to"
                                + " trusted environments. Once enabled, the /test-filter endpoint"
                                + " of the Custom Filters functionality can be exploited to execute"
                                + " arbitrary system commands.")
                        .setRecommendation(
                            "You can upgrade your D-Tale instances to 3.16.1 or later."))
                .build());
    assertThat(mockWebServer.getRequestCount()).isEqualTo(4);
    assertThat(mockCallbackServer.getRequestCount()).isEqualTo(1);
  }

  @Test
  public void detect_ifNotVulnerable_doesNotReportVuln() throws IOException {
    startMockWebServer(false);

    DetectionReportList detectionReports =
        detector.detect(targetInfo, ImmutableList.of(targetNetworkService));
    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
    assertThat(mockWebServer.getRequestCount()).isEqualTo(2);
  }

  private void startMockWebServer(boolean isVulnerableServer) throws IOException {
    final Dispatcher dispatcher =
        new Dispatcher() {

          @Override
          public MockResponse dispatch(RecordedRequest request) {
            switch (request.getPath()) {
              case "/":
                return new MockResponse()
                    .setResponseCode(200)
                    .setBody(
                        "<!doctype html>\n"
                            + "<html lang=en>\n"
                            + "<title>Redirecting...</title>\n"
                            + "<h1>Redirecting...</h1>\n"
                            + "<p>You should be redirected automatically to the target URL: <a"
                            + " href=\"/dtale/popup/upload\">/dtale/popup/upload</a>. If not, click"
                            + " the link.");

              case "/dtale/upload":
                if (isVulnerableServer) {
                  return new MockResponse()
                      .setResponseCode(200)
                      .setBody("{\"data_id\":\"7\",\"success\":true}\n");
                } else {
                  return new MockResponse()
                      .setResponseCode(200)
                      .setBody(
                          "{\"error\":\"Cannot alter the property 'enable_custom_filters' from this"
                              + " endpoint\",\"success\":false,\"traceback\":\"Traceback (most"
                              + " recent call last):\\n"
                              + "  File"
                              + " \\\"/usr/local/lib/python3.9/site-packages/dtale/views.py\\\","
                              + " line 120, in _handle_exceptions\\n"
                              + "    return func(*args, **kwargs)\\n"
                              + "  File"
                              + " \\\"/usr/local/lib/python3.9/site-packages/dtale/views.py\\\","
                              + " line 1631, in update_settings\\n"
                              + "    raise ValueError(\\n"
                              + "ValueError: Cannot alter the property 'enable_custom_filters' from"
                              + " this endpoint\\n"
                              + "\"}\n");
                }
              case "/dtale/update-settings/7?settings=%7B%22enable_custom_filters%22%3Atrue%7D":
                return new MockResponse().setResponseCode(200).setBody("{\"success\":true}\n");

              default:
                if (request
                    .getPath()
                    .contains(
                        "/dtale/test-filter/7?query=%40pd.core.frame.com.builtins.__import__")) {
                  return new MockResponse().setResponseCode(200).setBody("{\"success\":true}\n");
                } else {
                  return new MockResponse().setResponseCode(404).setBody(notFoundPageResponse);
                }
            }
          }
        };
    mockWebServer.setDispatcher(dispatcher);
    mockWebServer.start();
    mockWebServer.url("/");
    targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .addSupportedHttpMethods("POST")
            .addSupportedHttpMethods("GET")
            .build();
    targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(targetNetworkService.getNetworkEndpoint())
            .build();
  }
}
