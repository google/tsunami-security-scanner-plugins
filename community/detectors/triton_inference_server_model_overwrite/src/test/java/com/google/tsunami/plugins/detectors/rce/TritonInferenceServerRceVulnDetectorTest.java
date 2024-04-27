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

package com.google.tsunami.plugins.detectors.rce;

import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.*;

import com.google.common.collect.ImmutableList;
import com.google.common.truth.Truth;
import com.google.inject.Guice;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.plugin.payload.testing.FakePayloadGeneratorModule;
import com.google.tsunami.plugin.payload.testing.PayloadTestHelper;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.Software;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TransportProtocol;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
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

/** Unit tests for {@link TritonInferenceServerRceVulnDetector}. */
@RunWith(JUnit4.class)
public final class TritonInferenceServerRceVulnDetectorTest {
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2024-12-03T00:00:00.00Z"));

  private MockWebServer mockWebServer;
  private MockWebServer mockCallbackServer;

  private NetworkService service;
  private TargetInfo targetInfo;
  @Inject private TritonInferenceServerRceVulnDetector detector;

  @Before
  public void setUp() throws IOException {

    mockWebServer = new MockWebServer();
    mockCallbackServer = new MockWebServer();
    mockCallbackServer.start();

    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            FakePayloadGeneratorModule.builder().setCallbackServer(mockCallbackServer).build(),
            new TritonInferenceServerRceDetectorBootstrapModule())
        .injectMembers(this);

    service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setSoftware(Software.newBuilder().setName("http"))
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
    mockCallbackServer.shutdown();
  }

  @Test
  public void detect_whenVulnerable_returnsVulnerability() throws IOException {
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(200).setBody("[{\"name\":\"metasploit\"}]"));
    mockWebServer.enqueue(new MockResponse().setResponseCode(200));
    mockWebServer.enqueue(new MockResponse().setResponseCode(200));
    mockWebServer.enqueue(new MockResponse().setResponseCode(200));
    mockWebServer.enqueue(new MockResponse().setResponseCode(200));
    mockCallbackServer.enqueue(PayloadTestHelper.generateMockSuccessfulCallbackResponse());

    DetectionReportList detectionReports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(detectionReports.getDetectionReportsList())
        .containsExactly(
            DetectionReport.newBuilder()
                .setTargetInfo(targetInfo)
                .setNetworkService(service)
                .setDetectionTimestamp(
                    Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
                .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
                .setVulnerability(
                    Vulnerability.newBuilder()
                        .setMainId(
                            VulnerabilityId.newBuilder()
                                .setPublisher("TSUNAMI_COMMUNITY")
                                .setValue("TritonInferenceServerRce"))
                        .setSeverity(Severity.CRITICAL)
                        .setTitle(
                            "This detector checks triton inference server RCE with explicit model-control option enabled")
                        .setDescription(
                            "All versions of triton inference server with the `--model-control explicit` option"
                                + " and at least one loaded model can be overwritten by a malicious model and lead to RCE.")
                        .setRecommendation(
                            "don't use `--model-control explicit` option with public access"))
                .build());
    Truth.assertThat(mockWebServer.getRequestCount()).isEqualTo(5);
    Truth.assertThat(mockCallbackServer.getRequestCount()).isEqualTo(1);
  }

  @Test
  public void detect_ifNotVulnerable_doesNotReportVuln() throws IOException {
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("Hello world!"));

    DetectionReportList detectionReports = detector.detect(targetInfo, ImmutableList.of(service));
    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
    Truth.assertThat(mockWebServer.getRequestCount()).isEqualTo(1);
  }
}
