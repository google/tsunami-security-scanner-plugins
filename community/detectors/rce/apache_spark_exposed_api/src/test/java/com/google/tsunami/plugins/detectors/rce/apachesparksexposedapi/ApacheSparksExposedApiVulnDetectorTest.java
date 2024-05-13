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
package com.google.tsunami.plugins.detectors.rce.apachesparksexposedapi;

import static com.google.common.net.HttpHeaders.CONTENT_TYPE;
import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostname;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;

import com.google.common.collect.ImmutableList;
import com.google.common.net.MediaType;
import com.google.inject.Guice;
import com.google.protobuf.util.JsonFormat;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.callbackserver.proto.PollingResult;
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
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** tests for {@link ApacheSparksExposedApiVulnDetector}. */
@RunWith(JUnit4.class)
public final class ApacheSparksExposedApiVulnDetectorTest {
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  @Inject private ApacheSparksExposedApiVulnDetector detector;
  private MockWebServer mockWebServer;
  private MockWebServer mockCallbackServer;

  @Before
  public void setUp() throws IOException {
    mockWebServer = new MockWebServer();
    mockCallbackServer = new MockWebServer();
    mockCallbackServer.start();

    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            FakePayloadGeneratorModule.builder().setCallbackServer(mockCallbackServer).build(),
            new ApacheSparksExposedApiVulnDetectorBootstrapModule())
        .injectMembers(this);
  }

  @After
  public void tearDown() throws Exception {
    mockCallbackServer.shutdown();
    mockWebServer.shutdown();
  }

  @Test
  public void detect_ifVulnerable_reportsVuln() throws IOException {
    // returning a 200 OK from vulnerable server is enough
    mockWebServer.enqueue(
        new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .setBody(" \"message\" : \"Driver successfully submitted as"));
    mockWebServer.start();
    mockWebServer.url(ApacheSparksExposedApiVulnDetector.VULNERABLE_PATH);
    // prepare a callbackserver response
    PollingResult log = PollingResult.newBuilder().setHasHttpInteraction(true).build();
    String body = JsonFormat.printer().preservingProtoFieldNames().print(log);
    mockCallbackServer.enqueue(
        new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .setHeader(CONTENT_TYPE, MediaType.PLAIN_TEXT_UTF_8.toString())
            .setBody(body));

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
                                .setValue("Apache_Spark_Exposed_Api"))
                        .setSeverity(Severity.CRITICAL)
                        .setTitle(
                            "Exposed Apache Spark API which allows unauthenticated RCE detected.")
                        .setDescription(
                            "An exposed Apache Spark API allows an unauthenticated attacker to"
                                + " submit a malicious task. If an Apache Spark worker processes"
                                + " such a task, it loads and executes attacker-controlled content"
                                + " from an external resource. This allows an attacker to execute"
                                + " arbitrary Java Code within the context of the worker node.")
                        .setRecommendation(
                            "Don't expose the Apache Spark API to unauthenticated attackers."))
                .build());
  }

  @Test
  public void detect_ifNotVulnerable_doNotReportsVuln() throws IOException {
    mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.OK.code()));
    mockWebServer.start();
    mockWebServer.url(ApacheSparksExposedApiVulnDetector.VULNERABLE_PATH);
    // 404 NOT_FOUND means no valid oob logs for mockCallbackServer
    mockCallbackServer.enqueue(
        new MockResponse()
            .setResponseCode(HttpStatus.NOT_FOUND.code())
            .setHeader(CONTENT_TYPE, MediaType.PLAIN_TEXT_UTF_8.toString()));
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

  private static TargetInfo buildTargetInfo(NetworkEndpoint networkEndpoint) {
    return TargetInfo.newBuilder().addNetworkEndpoints(networkEndpoint).build();
  }
}
