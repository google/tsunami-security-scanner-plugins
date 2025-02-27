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

package com.google.tsunami.plugins.detectors.cves.cve20241728;

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

/** Unit tests for {@link Cve20241728VulnDetector}. */
@RunWith(JUnit4.class)
public class Cve20241728VulnDetectorTest {
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2022-05-23T00:00:00.00Z"));
  private MockWebServer mockWebServer;
  private NetworkService targetNetworkService;
  private TargetInfo targetInfo;
  private String mainPage;
  private String passwdFile;

  @Inject private Cve20241728VulnDetector detector;

  @Before
  public void setUp() throws IOException {
    mockWebServer = new MockWebServer();
    mainPage = Resources.toString(Resources.getResource("main.html"), UTF_8);
    passwdFile = Resources.toString(Resources.getResource("passwd.txt"), UTF_8);
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new Cve20241728DetectorBootstrapModule(),
            new HttpClientModule.Builder().build())
        .injectMembers(this);
  }

  @After
  public void tearDown() throws IOException {
    mockWebServer.shutdown();
  }

  @Test
  public void detect_whenVulnerable_returnsVulnerability() throws IOException {
    startMockWebServer(true);
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
                                .setValue("CVE_2024_1728"))
                        .setSeverity(Severity.HIGH)
                        .setTitle("CVE-2024-1728 Gradio Local File Inclusion")
                        .setDescription(
                            "Gradio is vulnerable to a Local File Inclusion vulnerability, which"
                                + " was fixed in version 4.19.2, due to improper validation of"
                                + " user-supplied input in the UploadButton component. While the"
                                + " component handles file upload paths, it unintentionally allows"
                                + " attackers to redirect file uploads to arbitrary locations on"
                                + " the server. After this path change, attackers can exploit this"
                                + " vulnerability to read arbitrary files on the filesystem, such"
                                + " as private SSH keys, by manipulating the file path in the"
                                + " request to the /queue/join endpoint.")
                        .setRecommendation(
                            "You can upgrade your Gradio instances to 4.19.2 or later."))
                .build());
    assertThat(mockWebServer.getRequestCount()).isEqualTo(4);
  }

  @Test
  public void detect_ifNotVulnerable_doesNotReportVuln() throws IOException {
    startMockWebServer(false);

    DetectionReportList detectionReports =
        detector.detect(targetInfo, ImmutableList.of(targetNetworkService));
    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
    assertThat(mockWebServer.getRequestCount()).isEqualTo(3);
  }

  private void startMockWebServer(boolean isVulnerableServer) throws IOException {
    final Dispatcher dispatcher =
        new Dispatcher() {

          @Override
          public MockResponse dispatch(RecordedRequest request) {
            switch (request.getPath()) {
              case "/":
                return new MockResponse().setResponseCode(200).setBody(mainPage);
              case "/queue/join?":
                return new MockResponse()
                    .setResponseCode(200)
                    .setBody("{\"event_id\":\"ceffeac5f90743d4a6a021bcfea3ec01\"}");
              case "/queue/data?session_hash=hu6na4f3d08":
                if (isVulnerableServer) {
                  return new MockResponse()
                      .setResponseCode(200)
                      .setBody(
                          "data: {\"msg\": \"estimation\", \"event_id\":"
                              + " \"ceffeac5f90743d4a6a021bcfea3ec01\", \"rank\": 0,"
                              + " \"queue_size\": 1, \"avg_event_process_time\": 0.0,"
                              + " \"avg_event_concurrent_process_time\": null, \"rank_eta\": null,"
                              + " \"queue_eta\": 1.0}\n"
                              + "\n"
                              + "data: {\"msg\": \"process_starts\", \"event_id\":"
                              + " \"ceffeac5f90743d4a6a021bcfea3ec01\"}\n"
                              + "\n"
                              + "data: {\"msg\": \"process_completed\", \"event_id\":"
                              + " \"ceffeac5f90743d4a6a021bcfea3ec01\", \"output\": {\"data\":"
                              + " [[{\"path\":"
                              + " \"/tmp/gradio/916eb712d668cf14a35adf8179617549780c4070/passwd\","
                              + " \"url\": null, \"size\": 839, \"orig_name\": \"passwd\","
                              + " \"mime_type\": null}]], \"is_generating\": false, \"duration\":"
                              + " 0.00046896934509277344, \"average_duration\":"
                              + " 0.00046896934509277344}, \"success\": true}\n"
                              + "\n");
                } else {
                  return new MockResponse()
                      .setResponseCode(200)
                      .setBody(
                          "data: {\"msg\": \"estimation\", \"event_id\":"
                              + " \"658cf26c56bf485287e83f0928b77c46\", \"rank\": 0,"
                              + " \"queue_size\": 1, \"rank_eta\": null}\n"
                              + "\n"
                              + "data: {\"msg\": \"process_starts\", \"event_id\":"
                              + " \"658cf26c56bf485287e83f0928b77c46\", \"eta\": null}\n"
                              + "\n"
                              + "data: {\"msg\": \"process_completed\", \"event_id\":"
                              + " \"658cf26c56bf485287e83f0928b77c46\", \"output\": {\"error\":"
                              + " null}, \"success\": false}");
                }
              case "/file=/tmp/gradio/916eb712d668cf14a35adf8179617549780c4070/passwd":
                return new MockResponse().setResponseCode(200).setBody(passwdFile);
              default:
                return new MockResponse()
                    .setResponseCode(404)
                    .setBody("{\"detail\":\"Not Found\"}");
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
