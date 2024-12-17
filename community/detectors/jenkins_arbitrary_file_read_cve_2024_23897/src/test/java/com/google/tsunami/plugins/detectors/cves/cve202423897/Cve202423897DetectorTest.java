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
package com.google.tsunami.plugins.detectors.cves.cve202423897;

import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
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

/** Unit tests for {@link Cve202423897Detector}. */
@RunWith(JUnit4.class)
public final class Cve202423897DetectorTest {

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2024-01-01T00:00:00.00Z"));

  @Inject private Cve202423897Detector detector;

  private final MockWebServer mockWebServer = new MockWebServer();
  private NetworkService service;
  private TargetInfo targetInfo;

  @Before
  public void setUp() throws IOException {
    mockWebServer.start();
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            new Cve202423897DetectorBootstrapModule())
        .injectMembers(this);

    service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setSoftware(Software.newBuilder().setName("jenkins"))
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
  public void detect_whenVulnerable_returnsDetection() {
    MockResponse response =
        new MockResponse()
            .setBody("COMMAND : Name of the command (default: root:x:0:0:root:/root:/bin/bash)")
            .setResponseCode(200);
    mockWebServer.enqueue(response);

    DetectionReport actual =
        detector.detect(targetInfo, ImmutableList.of(service)).getDetectionReports(0);

    DetectionReport expected =
        DetectionReport.newBuilder()
            .setTargetInfo(targetInfo)
            .setNetworkService(service)
            .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
            .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
            .setVulnerability(
                Vulnerability.newBuilder()
                    .setMainId(
                        VulnerabilityId.newBuilder()
                            .setPublisher("TSUNAMI_COMMUNITY")
                            .setValue("CVE_2024_23897"))
                    .addRelatedId(
                        VulnerabilityId.newBuilder().setPublisher("CVE").setValue("CVE-2024-23897"))
                    .setSeverity(Severity.CRITICAL)
                    .setTitle("Jenkins Arbitrary File Read")
                    .setDescription(
                        "Jenkins uses the args4j library to parse command arguments and options on"
                            + " the Jenkins controller when processing CLI commands. This command"
                            + " parser has a feature that replaces an @ character followed by a"
                            + " file path in an argument with the file's contents (expandAtFiles)."
                            + " This feature is enabled by default and Jenkins 2.441 and earlier,"
                            + " LTS 2.426.2 and earlier does not disable it. This allows attackers"
                            + " to read arbitrary files on the Jenkins controller file system using"
                            + " the default character encoding of the Jenkins controller process.")
                    .setRecommendation("Upgrade to version 2.426.3 or higher"))
            .build();
    assertThat(actual).isEqualTo(expected);
  }

  @Test
  public void detect_whenNotVulnerable_returnsNoVulnerability() {
    MockResponse response = new MockResponse().setBody("x").setResponseCode(200);
    mockWebServer.enqueue(response);
    DetectionReportList findings = detector.detect(targetInfo, ImmutableList.of(service));
    assertThat(findings.getDetectionReportsList()).isEmpty();
  }
}
