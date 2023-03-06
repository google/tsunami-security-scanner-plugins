/*
 * Copyright 2022 Google LLC
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
package com.google.tsunami.plugins.detectors.cves.cve201920933;

import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.*;
import static com.google.tsunami.plugins.detectors.cves.cve201920933.Cve201920933VulnDetector.DETECTION_STRING_1;
import static com.google.tsunami.plugins.detectors.cves.cve201920933.Cve201920933VulnDetector.DETECTION_STRING_BY_STATUS;
import static com.google.tsunami.plugins.detectors.cves.cve201920933.Cve201920933VulnDetector.VULNERABLE_PATH;
import static com.google.tsunami.plugins.detectors.cves.cve201920933.Cve201920933VulnDetector.DETECTION_STRING_BY_HEADER_Name_1;
import static com.google.tsunami.plugins.detectors.cves.cve201920933.Cve201920933VulnDetector.DETECTION_STRING_BY_HEADER_Name_2;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.google.common.collect.ImmutableList;
import com.google.inject.Guice;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.proto.*;
import java.io.*;
import java.time.Instant;
import java.util.Objects;
import javax.inject.Inject;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Unit tests for {@link Cve201920933VulnDetector}.
 */
@RunWith(JUnit4.class)
public final class Cve201920933VulnDetectorTest {

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  @Inject
  private Cve201920933VulnDetector detector;

  private final MockWebServer mockWebServer = new MockWebServer();
  ;

  private NetworkService influxDBservice;
  private TargetInfo targetInfo;

  @Before
  public void setUp() throws IOException {
    mockWebServer.start();
    mockWebServer.url("/" + VULNERABLE_PATH);
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            new Cve201920933DetectorBootstrapModule())
        .injectMembers(this);

    influxDBservice =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setSoftware(Software.newBuilder().setName("influxDB 1.6.6"))
            .setServiceName("http")
            .build();

    targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .build();
  }

  @After
  public void tearDown() throws IOException {
    mockWebServer.shutdown();
  }

  @Test
  public void detect_CVE201920933() throws InterruptedException {
    MockResponse response =
        new MockResponse()
            .setResponseCode(401);
    // the first response return 401 as we check for missing Authentication in first request
    mockWebServer.enqueue(response);
    response =
        new MockResponse()
            .addHeader(DETECTION_STRING_BY_HEADER_Name_1, "1.6.6")
            .addHeader(DETECTION_STRING_BY_HEADER_Name_2, "1")
            .setBody(
                "{\"results\":[{\"statement_id\":0,\"series\":[{\"columns\":[\"user\",\"admin\"],\"values\":[[\"admin\",true]]}]}]}")
            .setResponseCode(DETECTION_STRING_BY_STATUS);
    mockWebServer.enqueue(response);

    DetectionReport mockWebServer_detectionReport =
        detector.detect(targetInfo, ImmutableList.of(influxDBservice)).getDetectionReports(0);

    DetectionReport expected_detectionReport =
        DetectionReport.newBuilder()
            .setTargetInfo(targetInfo)
            .setNetworkService(influxDBservice)
            .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
            .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
            .setVulnerability(
                Vulnerability.newBuilder()
                    .setMainId(
                        VulnerabilityId.newBuilder()
                            .setPublisher("TSUNAMI_COMMUNITY")
                            .setValue("CVE_2019_20933"))
                    .setSeverity(Severity.CRITICAL)
                    .setTitle("InfluxDB Empty JWT Secret Key Authentication Bypass")
                    .setDescription(
                        "InfluxDB before 1.7.6 has an authentication bypass vulnerability because a JWT token may have an empty SharedSecret (aka shared secret).")
                    .setRecommendation("Upgrade to higher versions")
                    .addAdditionalDetails(
                        AdditionalDetail.newBuilder()
                            .setTextData(
                                TextData.newBuilder()
                                    .setText(
                                        "attacker can run arbitrary queries and see database data"))))
            .build();

    mockWebServer.takeRequest(); // pass first request that is for checking the missing authentication scenario
    RecordedRequest request1 = mockWebServer.takeRequest();
    // second request must have the Authorization header to pass a successful test
    if (Objects.equals(request1.getHeader("Authorization"),
        "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjoxNzk1MjMzMjY3fQ.u8VkK_D8ERfgYAKoo8E0Llri1HdrEU0ml6Q0_YEx9fI")) {
      assertThat(mockWebServer_detectionReport)
          .isEqualTo(expected_detectionReport);
    }

  }

  @Test
  public void detect_MissingAuth() throws InterruptedException {
    MockResponse response =
        new MockResponse()
            .addHeader(DETECTION_STRING_BY_HEADER_Name_1, "1.6.6")
            .addHeader(DETECTION_STRING_BY_HEADER_Name_2, "1")
            .setBody(
                "{\"results\":[{\"statement_id\":0,\"series\":[{\"columns\":[\"user\",\"admin\"],\"values\":[[\"admin\",true]]}]}]}")
            .setResponseCode(DETECTION_STRING_BY_STATUS);
    mockWebServer.enqueue(response);
    DetectionReport mockWebServer_detectionReport_Missing_auth =
        detector.detect(targetInfo, ImmutableList.of(influxDBservice)).getDetectionReports(0);

    DetectionReport expected_detectionReport_missing_auth =
        DetectionReport.newBuilder()
            .setTargetInfo(targetInfo)
            .setNetworkService(influxDBservice)
            .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
            .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
            .setVulnerability(
                Vulnerability.newBuilder()
                    .setMainId(
                        VulnerabilityId.newBuilder()
                            .setPublisher("TSUNAMI_COMMUNITY")
                            .setValue("MISSING_AUTHENTICATION_FOR_INFLUX_DB"))
                    .setSeverity(Severity.CRITICAL)
                    .setTitle("influxDB instance without any authentication")
                    .setDescription(
                        "attacker can access any DB information for this influxDB instance because there are no authentication methods")
                    .setRecommendation(
                        "set authentication value to true in influxDB setup config file before running a instance of influxDB")
                    .addAdditionalDetails(
                        AdditionalDetail.newBuilder()
                            .setTextData(
                                TextData.newBuilder()
                                    .setText(
                                        "attacker can run arbitrary queries and see database data"))))
            .build();
    assertThat(mockWebServer_detectionReport_Missing_auth)
        .isEqualTo(expected_detectionReport_missing_auth);
  }

  @Test
  public void detect_whenNotVulnerable_returnsNoVulnerability() throws IOException {
    mockWebServer.url("/notexistpath123321");
    MockResponse response =
        new MockResponse()
            .addHeader("Content-Type", "application/json; charset=utf-8")
            .setBody("NotExistDetectionString")
            .setResponseCode(200);
    mockWebServer.enqueue(response);
    DetectionReportList mockWebServer_detectionReport =
        detector.detect(targetInfo, ImmutableList.of(influxDBservice));
    assert (mockWebServer_detectionReport.getDetectionReportsList().isEmpty());
  }

}