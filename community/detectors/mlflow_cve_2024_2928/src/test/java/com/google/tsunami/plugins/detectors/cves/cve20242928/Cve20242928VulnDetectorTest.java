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

package com.google.tsunami.plugins.detectors.cves.cve20242928;

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

/** Unit tests for {@link Cve20242928VulnDetector}. */
@RunWith(JUnit4.class)
public class Cve20242928VulnDetectorTest {
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2022-05-23T00:00:00.00Z"));
  private MockWebServer mockWebServer;
  private NetworkService targetNetworkService;
  private TargetInfo targetInfo;
  private String mainPage;
  private String passwdFile;

  @Inject private Cve20242928VulnDetector detector;

  @Before
  public void setUp() throws IOException {
    mockWebServer = new MockWebServer();
    mainPage = Resources.toString(Resources.getResource(this.getClass(), "main.html"), UTF_8);
    passwdFile = Resources.toString(Resources.getResource(this.getClass(), "passwd"), UTF_8);
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new Cve20242928DetectorBootstrapModule(),
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
                                .setValue("CVE_2024_2928"))
                        .setSeverity(Severity.HIGH)
                        .setTitle("CVE-2024-2928 MLflow Local File Inclusion")
                        .setDescription(
                            "A Local File Inclusion (LFI) vulnerability was identified in"
                                + " mlflow, which was fixed in version 2.11.2. This"
                                + " vulnerability arises from the application's failure to properly"
                                + " validate URI fragments for directory traversal sequences such"
                                + " as '../'. An attacker can exploit this flaw by manipulating the"
                                + " fragment part of the URI to read arbitrary files on the local"
                                + " file system, including sensitive files like '/etc/passwd'. The"
                                + " vulnerability is a bypass to a previous patched vulnerability"
                                + " (namely for CVE-2023-6909) that only addressed similar"
                                + " manipulation within the URI's query string.")
                        .setRecommendation(
                            "You can upgrade your MLflow instances to 2.11.2 or later."))
                .build());
    assertThat(mockWebServer.getRequestCount()).isEqualTo(8);
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
                return new MockResponse().setResponseCode(200).setBody(mainPage);
              case "/ajax-api/2.0/mlflow/experiments/create":
                if (isVulnerableServer) {
                  return new MockResponse()
                      .setResponseCode(200)
                      .setBody("{\"experiment_id\": \"771333603874438576\" }");
                } else {
                  return new MockResponse()
                      .setResponseCode(400)
                      .setBody(
                          "{\"error_code\": \"INVALID_PARAMETER_VALUE\", \"message\":"
                              + " \"'artifact_location' URL can't include fragments or params.\"}");
                }
              case "/api/2.0/mlflow/runs/create":
                return new MockResponse()
                    .setResponseCode(200)
                    .setBody(
                        "{\"run\":{\"info\":{\"run_uuid\":\"3a422702c6564a71873bcf7945aff74c\",\"experiment_id\":\"771333603874438576\",\"run_name\":\"salty-dove-144\",\"user_id\":\"\",\"status\":\"RUNNING\",\"start_time\":0,\"artifact_uri\":\"http:///3a422702c6564a71873bcf7945aff74c/artifacts#/../../../../../../../../../../../../../../etc/\",\"lifecycle_stage\":\"active\",\"run_id\":\"3a422702c6564a71873bcf7945aff74c\"},\"data\":{\"tags\":[{\"key\":\"mlflow.runName\",\"value\":\"salty-dove-144\"}]},\"inputs\":{}}}");
              case "/ajax-api/2.0/mlflow/registered-models/create":
                return new MockResponse()
                    .setResponseCode(200)
                    .setBody(
                        "{\"registered_model\":{\"name\":\"poc\",\"creation_timestamp\":1725611425002,\"last_updated_timestamp\":1725611425002}}");
              case "/ajax-api/2.0/mlflow/model-versions/create":
                return new MockResponse()
                    .setResponseCode(200)
                    .setBody(
                        "{\"model_version\":{\"name\":\"poc\",\"version\":\"1\",\"creation_timestamp\":1725611889193,\"last_updated_timestamp\":1725611889193,\"current_stage\":\"None\",\"description\":\"\",\"source\":\"file:///etc/\",\"run_id\":\"3a422702c6564a71873bcf7945aff74c\",\"status\":\"READY\",\"run_link\":\"\"}}");
              case "/ajax-api/2.0/mlflow/experiments/delete":
                return new MockResponse().setResponseCode(200).setBody("{}");
              case "/ajax-api/2.0/mlflow/registered-models/delete":
                return new MockResponse().setResponseCode(200).setBody("{}");
              case "/model-versions/get-artifact?path=passwd&name=poc&version=1":
                return new MockResponse().setResponseCode(200).setBody(passwdFile);
              default:
                return new MockResponse()
                    .setResponseCode(404)
                    .setBody(
                        "<!doctype html>\n"
                            + "<html lang=en>\n"
                            + "<title>404 Not Found</title>\n"
                            + "<h1>Not Found</h1>\n"
                            + "<p>The requested URL was not found on the server. If you entered the"
                            + " URL manually please check your spelling and try again.</p>\n");
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
