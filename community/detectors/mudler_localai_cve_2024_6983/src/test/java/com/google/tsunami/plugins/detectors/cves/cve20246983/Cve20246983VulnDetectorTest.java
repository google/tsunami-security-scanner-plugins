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

package com.google.tsunami.plugins.detectors.cves.cve20246983;

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

/** Unit tests for {@link Cve20246983VulnDetector}. */
@RunWith(JUnit4.class)
public class Cve20246983VulnDetectorTest {
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2022-05-23T00:00:00.00Z"));
  private MockWebServer mockWebServer;
  private MockWebServer mockCallbackServer;
  private NetworkService targetNetworkService;
  private TargetInfo targetInfo;
  private String mainPageResponse;
  private String notFoundPageResponse;

  @Inject private Cve20246983VulnDetector detector;

  @Before
  public void setUp() throws IOException {
    mockWebServer = new MockWebServer();
    mockCallbackServer = new MockWebServer();
    mockCallbackServer.start();
    mainPageResponse = Resources.toString(Resources.getResource("mainpage.html"), UTF_8);
    notFoundPageResponse = Resources.toString(Resources.getResource("404.html"), UTF_8);
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            FakePayloadGeneratorModule.builder().setCallbackServer(mockCallbackServer).build(),
            new Cve20246983DetectorBootstrapModule())
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
                                .setValue("CVE_2024_6983"))
                        .setSeverity(Severity.CRITICAL)
                        .setTitle("CVE-2024-6983 Mudler LocalAI RCE")
                        .setRecommendation(
                            "You can upgrade your Mudler LocalAI instances to 2.19.4 or later.")
                        .setDescription(
                            "The Mudler LocalAI has API endpoints that allow its users to interact"
                                + " with model functionalities. The vulnerability here allows an"
                                + " attacker to upload a configuration file that includes a URI"
                                + " pointing to a malicious binary file through '/models/apply'"
                                + " endpoint. When the software processes this configuration file,"
                                + " it downloads the binary without conditional checking. By"
                                + " triggering the new model, created by this malicious"
                                + " configuration file, over the '/embeddings' endpoint, an"
                                + " attacker could trigger it by passing the malicious file"
                                + " location through the 'backend' parameter of this request."))
                .build());
    assertThat(mockWebServer.getRequestCount()).isEqualTo(5);
    assertThat(mockCallbackServer.getRequestCount()).isEqualTo(1);
  }

  @Test
  public void detect_ifNotVulnerable_doesNotReportVuln() throws IOException {
    startMockWebServer(false);

    DetectionReportList detectionReports =
        detector.detect(targetInfo, ImmutableList.of(targetNetworkService));
    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
    assertThat(mockWebServer.getRequestCount()).isEqualTo(5);
  }

  private void startMockWebServer(boolean isVulnerableServer) throws IOException {
    final Dispatcher dispatcher =
        new Dispatcher() {

          @Override
          public MockResponse dispatch(RecordedRequest request) {
            switch (request.getPath()) {
              case "/":
                return new MockResponse().setResponseCode(200).setBody(mainPageResponse);
              case "/v1/files":
                return new MockResponse()
                    .setResponseCode(200)
                    .setBody(
                        "{\"id\":\"file-1\",\"object\":\"file\",\"bytes\":153,\"created_at\":\"2025-02-17T19:55:26.098173971Z\",\"filename\":\"tsunamiPayload.txt\",\"purpose\":\"fine-tune\"}");
              case "/v1/files/file-1":
                return new MockResponse()
                    .setResponseCode(200)
                    .setBody("{\"Id\":\"file-1\",\"Object\":\"file\",\"Deleted\":true}");
              case "/models/apply":
                return new MockResponse()
                    .setResponseCode(200)
                    .setBody(
                        "{\"uuid\":\"cb998134-ed77-11ef-85b8-000c297ee14d\",\"status\":\"http://localhost:8080/models/jobs/cb998134-ed77-11ef-85b8-000c297ee14d\"}");

              case "/embeddings":
                if (isVulnerableServer) {
                  return new MockResponse()
                      .setResponseCode(500)
                      .setBody(
                          "{\"error\":{\"code\":500,\"message\":\"grpc service not"
                              + " ready\",\"type\":\"\"}}");
                } else {
                  return new MockResponse()
                      .setResponseCode(500)
                      .setBody(
                          "{\"error\":{\"code\":500,\"message\":\"failed reading parameters from"
                              + " request:failed to validate config\",\"type\":\"\"}}");
                }
              default:
                return new MockResponse().setResponseCode(404).setBody(notFoundPageResponse);
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
            .addSupportedHttpMethods("DELETE")
            .build();
    targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(targetNetworkService.getNetworkEndpoint())
            .build();
  }
}
