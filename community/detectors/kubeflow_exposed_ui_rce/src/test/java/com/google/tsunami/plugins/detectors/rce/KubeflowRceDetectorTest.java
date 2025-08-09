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
package com.google.tsunami.plugins.detectors.rce;

import static com.google.common.truth.Truth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;
import static com.google.tsunami.plugins.detectors.rce.KubeflowRceDetector.PAYLOAD;

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
import com.google.tsunami.plugins.detectors.rce.Annotations.OobSleepDuration;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;
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

/** Unit tests for {@link KubeflowRceDetector}. */
@RunWith(JUnit4.class)
public final class KubeflowRceDetectorTest {
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2025-05-23T00:00:00.00Z"));
  private final MockWebServer mockTargetService = new MockWebServer();
  private final MockWebServer mockCallbackServer = new MockWebServer();
  @Inject private KubeflowRceDetector detector;

  @Bind(lazy = true)
  @OobSleepDuration
  private int sleepDuration = 1;

  TargetInfo targetInfo;
  NetworkService targetNetworkService;
  private final SecureRandom testSecureRandom =
      new SecureRandom() {
        @Override
        public void nextBytes(byte[] bytes) {
          Arrays.fill(bytes, (byte) 0xFF);
        }
      };

  @Before
  public void setUp() throws IOException {
    mockCallbackServer.start();
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            FakePayloadGeneratorModule.builder()
                .setCallbackServer(mockCallbackServer)
                .setSecureRng(testSecureRandom)
                .build(),
            Modules.override(new KubeflowRceDetectorBootstrapModule())
                .with(BoundFieldModule.of(this)))
        .injectMembers(this);
  }

  @After
  public void tearDown() throws Exception {
    mockTargetService.shutdown();
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
                                .setValue("KUBEFLOW_EXPOSED_API_RCE"))
                        .setSeverity(Severity.CRITICAL)
                        .setTitle("Exposed kubeflow API")
                        .setDescription(
                            "This vulnerability check exposed Kubeflow "
                                + "API by executing a OS command in a kubeflow pipeline."))
                .build());
    assertThat(mockTargetService.getRequestCount()).isEqualTo(8);
    assertThat(mockCallbackServer.getRequestCount()).isEqualTo(1);
  }

  @Test
  public void detect_ifNotVulnerable_doesNotReportVuln() throws IOException {
    startMockWebServer();
    mockCallbackServer.enqueue(new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code()));
    DetectionReportList detectionReports =
        detector.detect(targetInfo, ImmutableList.of(targetNetworkService));
    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
    assertThat(mockTargetService.getRequestCount()).isEqualTo(10);
  }

  private void startMockWebServer() throws IOException {
    final Dispatcher dispatcher =
        new Dispatcher() {
          @Override
          public MockResponse dispatch(RecordedRequest request) {
            if (Objects.equals(request.getPath(), "/")
                && request.getMethod().equals("GET")
                && request.getBody().readString(StandardCharsets.UTF_8).isEmpty()) {
              return new MockResponse()
                  .setBody("<title>Kubeflow Central Dashboard</title>")
                  .setResponseCode(HttpStatus.FORBIDDEN.code());
            }
            if (Objects.equals(request.getPath(), "/api/workgroup/env-info")
                && request.getMethod().equals("GET")
                && request.getHeader("Accept").equals("application/json")) {
              return new MockResponse()
                  .setResponseCode(200)
                  .setBody(
                      "{\"user\":\"user@example.com\",\"platform\""
                          + ":{\"kubeflowVersion\":\"unknown\",\"provider\""
                          + ":\"other://\",\"providerName\":\"other\",\"logoutUrl\""
                          + ":\"/oauth2/sign_out\"},\"namespaces\":[{\"user\""
                          + ":\"user@example.com\",\"namespace\":\"kubeflow-user-example-com\""
                          + ",\"role\":\"owner\"}],\"isClusterAdmin\":false}");
            }
            if (Objects.equals(request.getPath(), "/pipeline/apis/v2beta1/experiments")
                && request.getMethod().equals("POST")
                && request
                    .getBody()
                    .readString(StandardCharsets.UTF_8)
                    .startsWith(
                        "{\"description\":\"\",\"display_name\""
                            + ":\"TsunamiExperiment\",\"namespace\":\"")) {
              return new MockResponse()
                  .setResponseCode(200)
                  .setBody(
                      "{\"experiment_id\":\"2aae0438-bc6b-48af-bdcd-78f333028426\","
                          + "\"display_name\":\"TsunamiExperiment\",\"created_at\""
                          + ":\"2025-02-23T15:18:07Z\",\"namespace\":"
                          + "\"kubeflow-user-example-com\",\"storage_state\":\"AVAILABLE\"}");
            }
            if (request
                    .getPath()
                    .equals(
                        "/pipeline/apis/v2beta1/experiments"
                            + "?page_token=&page_size=100&sort_by=created_at%20desc&filter"
                            + "=%257B%2522predicates%2522%253A%255B%257B%2522key%2522%253A%2522"
                            + "storage_state%2522%252C%2522operation%2522%253A%2522"
                            + "NOT_EQUALS%2522%252C%2522string_value%2522%253A%2522"
                            + "ARCHIVED%2522%257D%255D%257D&namespace=kubeflow-user-example-com")
                && request.getMethod().equals("GET")
                && request.getHeader("Accept").equals("application/json")) {
              return new MockResponse()
                  .setResponseCode(200)
                  .setBody(
                      "{\"experiments\":[{\"experiment_id\":"
                          + "\"2aae0438-bc6b-48af-bdcd-78f333028426\",\"display_name\":"
                          + "\"TsunamiExperiment\",\"created_at\":\"2025-02-23T15:18:07Z\","
                          + "\"namespace\":\"kubeflow-user-example-com\",\"storage_state\":"
                          + "\"AVAILABLE\"}],\"total_size\":1}");
            }
            if (request
                    .getPath()
                    .startsWith("/pipeline/apis/v2beta1/pipelines/upload?name=TsunamiPipeline-")
                && request.getPath().endsWith("&description=&namespace=kubeflow-user-example-com")
                && request.getMethod().equals("POST")
                && request.getHeader("Content-Type").startsWith("multipart/form-data; boundary=")
                && request
                    .getBody()
                    .readString(StandardCharsets.UTF_8)
                    .contains(PAYLOAD.substring(0, 60))) {
              return new MockResponse()
                  .setResponseCode(200)
                  .setBody(
                      "{\"pipeline_id\":\"c71bf706-24a9-410a-9aec-d5c1264d205f\""
                          + ",\"display_name\":\"TsunamiPipeline-111111\",\"created_at\""
                          + ":\"2025-02-23T15:47:52Z\",\"namespace\":\"kubeflow-user-example-com\"}");
            }
            if (request
                    .getPath()
                    .equals(
                        "/pipeline/apis/v2beta1/pipelines/c71bf706-24a9-410a-9aec-d5c1264d205f/versions?page_size=1&sort_by=created_at%20desc")
                && request.getMethod().equals("GET")) {
              return new MockResponse()
                  .setResponseCode(200)
                  .setBody(
                      "{\n"
                          + "  \"pipeline_versions\": [\n"
                          + "    {\n"
                          + "      \"pipeline_id\": \"c71bf706-24a9-410a-9aec-d5c1264d205f\",\n"
                          + "      \"pipeline_version_id\":"
                          + " \"8373284f-596b-42b7-af6e-d8fc72e14300\"\n"
                          + "    }\n"
                          + "  ]\n"
                          + "}");
            }
            if (request.getPath().equals("/pipeline/apis/v2beta1/runs")
                && request.getMethod().equals("POST")
                && request
                    .getBody()
                    .readString(StandardCharsets.UTF_8)
                    .equals(
                        "{\"description\":\"\",\"display_name\":\"Run of TsunamiPipeline2"
                            + " (f510b)\",\"experiment_id\":\"2aae0438-bc6b-48af-bdcd-78f333028426\",\"pipeline_version_reference\":{\"pipeline_id\":\"c71bf706-24a9-410a-9aec-d5c1264d205f\",\"pipeline_version_id\":\"8373284f-596b-42b7-af6e-d8fc72e14300\"},\"runtime_config\":{\"parameters\":{}},\"service_account\":\"\"}")) {
              return new MockResponse().setResponseCode(200);
            }
            return new MockResponse().setResponseCode(500);
          }
        };
    mockTargetService.setDispatcher(dispatcher);
    mockTargetService.start();

    targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockTargetService.getHostName(), mockTargetService.getPort()))
            .addSupportedHttpMethods("POST")
            .build();
    targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(targetNetworkService.getNetworkEndpoint())
            .build();
  }
}
