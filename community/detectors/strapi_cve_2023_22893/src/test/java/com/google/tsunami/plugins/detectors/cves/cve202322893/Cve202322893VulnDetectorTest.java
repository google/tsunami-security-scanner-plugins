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
package com.google.tsunami.plugins.detectors.cves.cve202322893;

import static com.google.common.net.HttpHeaders.CONTENT_TYPE;
import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;

import com.google.common.collect.ImmutableList;
import com.google.common.net.MediaType;
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

/** Unit tests for {@link Cve202322893VulnDetector}. */
@RunWith(JUnit4.class)
public final class Cve202322893VulnDetectorTest {

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2023-01-01T00:00:00.00Z"));

  @Inject private Cve202322893VulnDetector detector;

  private final MockWebServer mockWebServer = new MockWebServer();
  private NetworkService strapiService;
  private TargetInfo targetInfo;

  @Before
  public void setUp() throws IOException {
    mockWebServer.start();
    mockWebServer.url("/");
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            new Cve202322893DetectorBootstrapModule())
        .injectMembers(this);

    strapiService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setSoftware(Software.newBuilder().setName("strapi"))
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
            .setBody(
                "{\"jwt\":\"a jwt\n"
                    + "token\",\"user\":{\"id\":2,\"username\":\"auth-bypass-example\",\"email\":\"notexists@notexist.com\",\"provider\":\"cognito\",\"confirmed\":true,\"blocked\":false,\"createdAt\":\"2023-04-28T06:56:20.344Z\",\"updatedAt\":\"2023-04-28T06:56:20.344Z\"}}")
            .setResponseCode(200)
            .setHeader(CONTENT_TYPE, MediaType.JSON_UTF_8.toString());
    mockWebServer.enqueue(response);

    DetectionReport actual =
        detector.detect(targetInfo, ImmutableList.of(strapiService)).getDetectionReports(0);

    DetectionReport expected =
        DetectionReport.newBuilder()
            .setTargetInfo(targetInfo)
            .setNetworkService(strapiService)
            .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
            .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
            .setVulnerability(
                Vulnerability.newBuilder()
                    .setMainId(
                        VulnerabilityId.newBuilder()
                            .setPublisher("TSUNAMI_COMMUNITY")
                            .setValue("CVE_2023_22893"))
                    .setSeverity(Severity.CRITICAL)
                    .setTitle("Authentication Bypass For Strapi AWS Cognito Login Provider")
                    .setDescription(
                        "Strapi before 4.5.5 does not verify the access or ID tokens issued during"
                            + " the OAuth flow when the AWS Cognito login provider is used for"
                            + " authentication. A remote attacker could forge an ID token that is"
                            + " signed using the 'None' type algorithm to bypass authentication and"
                            + " impersonate any user that use AWS Cognito for authentication. with"
                            + " the help of CVE-2023-22621 and CVE-2023-22894 attackers can gain"
                            + " Unauthenticated Remote Code Execution on this version of Strapi")
                    .setRecommendation("Upgrade to version 4.5.6 and higher"))
            .build();
    assertThat(actual).isEqualTo(expected);
  }

  @Test
  public void detect_whenNotVulnerable_returnsNoVulnerability() {
    mockWebServer.url("/notexistpath123321");
    MockResponse response =
        new MockResponse().setBody("NotExistDetectionString").setResponseCode(400);
    mockWebServer.enqueue(response);

    DetectionReportList findings = detector.detect(targetInfo, ImmutableList.of(strapiService));

    assertThat(findings.getDetectionReportsList()).isEmpty();
  }
}
