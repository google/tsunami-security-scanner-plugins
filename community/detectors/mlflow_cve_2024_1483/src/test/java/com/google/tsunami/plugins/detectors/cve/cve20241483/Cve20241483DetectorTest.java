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

package com.google.tsunami.plugins.detectors.cve.cve20241483;

import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostname;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;

import com.google.common.collect.ImmutableList;
import com.google.inject.Guice;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Software;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TransportProtocol;
import java.io.IOException;
import java.time.Instant;
import javax.inject.Inject;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link Cve20241483Detector}. */
@RunWith(JUnit4.class)
public final class Cve20241483DetectorTest {
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  @Inject private Cve20241483Detector detector;

  private MockWebServer mockWebServer;
  private NetworkService service;
  private TargetInfo targetInfo;

  @Before
  public void setUp() {
    mockWebServer = new MockWebServer();
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new Cve20241483DetectorBootstrapModule(),
            new HttpClientModule.Builder().build())
        .injectMembers(this);

    service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setSoftware(Software.newBuilder().setName("MLFlow"))
            .setServiceName("http")
            .build();

    targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockWebServer.getHostName()))
            .build();
  }

  @After
  public void tearDown() throws IOException {
    mockWebServer.shutdown();
  }

  @Test
  public void detect_whenVulnerable_returnsVulnerability() throws IOException {
    mockWebServer.enqueue(new MockResponse().setBody("<title>MLflow</title>").setResponseCode(200));
    mockWebServer.enqueue(
        new MockResponse()
            .setBody("{\"experiment_id\": \"827049542911897353\"}")
            .setResponseCode(200));
    mockWebServer.enqueue(
        new MockResponse()
            .setBody(
                "{\"run\": {\"info\": {\"run_uuid\": \"cd867f09c62b4bf69dc6c76193355709\","
                    + " \"experiment_id\": \"827049542911897353\", \"run_name\":"
                    + " \"hilarious-moth-534\", \"user_id\": \"\", \"status\": \"RUNNING\","
                    + " \"start_time\": 0, \"artifact_uri\":"
                    + " \"http:///cd867f09c62b4bf69dc6c76193355709/artifacts#/../../../../../../../../../../../../../../etc/\","
                    + " \"lifecycle_stage\": \"active\", \"run_id\":"
                    + " \"cd867f09c62b4bf69dc6c76193355709\"}, \"data\": {\"tags\": [{\"key\":"
                    + " \"mlflow.runName\", \"value\": \"hilarious-moth-534\"}]}, \"inputs\":"
                    + " {}}}\n")
            .setResponseCode(200));
    mockWebServer.enqueue(
        new MockResponse()
            .setBody(
                "{\"registered_model\": {\"name\": \"tsunami_scanner_TJGa\","
                    + " \"creation_timestamp\": 1742128371105, \"last_updated_timestamp\":"
                    + " 1742128371105}}\n")
            .setResponseCode(200));
    mockWebServer.enqueue(
        new MockResponse()
            .setBody(
                "{\"model_version\": {\"name\": \"tsunami_scanner_TJGa\", \"version\": \"1\","
                    + " \"creation_timestamp\": 1742128371109, \"last_updated_timestamp\":"
                    + " 1742128371109, \"current_stage\": \"None\", \"description\": \"\","
                    + " \"source\": \"file:///etc/\", \"run_id\":"
                    + " \"cd867f09c62b4bf69dc6c76193355709\", \"status\": \"READY\", \"run_link\":"
                    + " \"\"}}")
            .setResponseCode(200));
    mockWebServer.enqueue(
        new MockResponse().setBody("root:x:0:0:root:/root:/bin/bash").setResponseCode(200));

    DetectionReport actual =
        detector.detect(targetInfo, ImmutableList.of(service)).getDetectionReports(0);

    DetectionReport expected =
        DetectionReport.newBuilder()
            .setTargetInfo(targetInfo)
            .setNetworkService(service)
            .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
            .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
            .setVulnerability(detector.getAdvisories().getFirst())
            .build();
    assertThat(actual).isEqualTo(expected);
  }

  @Test
  public void detect_whenNotVulnerable_returnsNoVulnerability() throws IOException {
    MockResponse response = new MockResponse().setBody("Hello World").setResponseCode(200);
    mockWebServer.enqueue(response);

    ImmutableList<NetworkService> httpServices =
        ImmutableList.of(
            NetworkService.newBuilder()
                .setNetworkEndpoint(
                    forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
                .setTransportProtocol(TransportProtocol.TCP)
                .setServiceName("http")
                .build());
    TargetInfo targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockWebServer.getHostName()))
            .build();

    DetectionReportList detectionReports = detector.detect(targetInfo, httpServices);

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }
}
