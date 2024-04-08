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
package com.google.tsunami.plugins.detectors.apachesparksexposedwebui;

import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostname;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;

import com.google.common.collect.ImmutableList;
import com.google.inject.Guice;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.plugin.payload.testing.FakePayloadGeneratorModule;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkEndpoint;
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

/** tests for {@link ApacheSparksExposedWebuiVulnDetector}. */
@RunWith(JUnit4.class)
public final class ApacheSparksExposedWebuiVulnDetectorTest {
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  @Inject private ApacheSparksExposedWebuiVulnDetector detector;
  private MockWebServer mockWebServer;
  private MockWebServer mockCallbackServer;

  @Before
  public void setUp() throws IOException {
    mockWebServer = new MockWebServer();
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            FakePayloadGeneratorModule.builder().build(),
            new ApacheSparksExposedWebuiVulnDetectorBootstrapModule())
        .injectMembers(this);
  }

  @After
  public void tearDown() throws Exception {
    mockWebServer.shutdown();
  }

  @Test
  public void detect_ifVulnerable_reportsVuln() throws IOException {
    mockWebServer.setDispatcher(new VulnerableEndpointDispatcher());
    mockWebServer.start();

    NetworkService service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("http")
            .build();

    TargetInfo targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockWebServer.getHostName()))
            .build();

    DetectionReportList detectionReports =
        detector.detect(
            buildTargetInfo(forHostname(mockWebServer.getHostName())), ImmutableList.of(service));

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
                                .setPublisher("Community")
                                .setValue("Apache_Spark_Exposed_WebUI"))
                        .setSeverity(Severity.MEDIUM)
                        .setTitle(
                            "Exposed Apache Spark UI which discloses information about the Apache"
                                + " Spark environment and its' tasks.")
                        .setDescription(
                            "An exposed Apache Spark Web UI provides attackers information about"
                                + " the Apache Spark UI and its' tasks. The disclosed information"
                                + " might leak other configured Apache Spark nodes and the output"
                                + " of previously run tasks. Depending on the task, the output"
                                + " might contain sensitive information which was logged during the"
                                + " task execution.")
                        .setRecommendation(
                            "Don't expose the Apache Spark Web UI to unauthenticated attackers."))
                .build());
  }

  @Test
  public void detect_ifNotVulnerable_doNotReportsVuln() throws IOException {
    mockWebServer.setDispatcher(new SafeEndpointDispatcher());
    mockWebServer.start();

    NetworkService service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("http")
            .build();

    DetectionReportList detectionReports =
        detector.detect(
            buildTargetInfo(forHostname(mockWebServer.getHostName())), ImmutableList.of(service));

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }

  private static final class VulnerableEndpointDispatcher extends Dispatcher {

    @Override
    public MockResponse dispatch(RecordedRequest recordedRequest) {
      return new MockResponse()
          .setResponseCode(HttpStatus.OK.code())
          .setBody(
              "<title>Spark Worker at 192.168.48.3:36075</title><body><span"
                  + " class=\"collapse-aggregated-runningExecutors collapse-table\""
                  + " onClick=\"collapseTable('collapse-aggregated-runningExecutors',\n"
                  + "'aggregated-runningExecutors')\"></body>");
    }
  }

  private static final class SafeEndpointDispatcher extends Dispatcher {

    @Override
    public MockResponse dispatch(RecordedRequest recordedRequest) {
      return new MockResponse().setResponseCode(HttpStatus.FORBIDDEN.code()).setBody("");
    }
  }

  private static TargetInfo buildTargetInfo(NetworkEndpoint networkEndpoint) {
    return TargetInfo.newBuilder().addNetworkEndpoints(networkEndpoint).build();
  }
}
