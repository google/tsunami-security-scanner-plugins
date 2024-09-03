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
package com.google.tsunami.plugins.detectors.rce.cve202421650;

import static com.google.common.truth.Truth.assertThat;

import com.google.common.collect.ImmutableList;
import com.google.inject.Guice;
import com.google.inject.testing.fieldbinder.Bind;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkEndpointUtils;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.plugin.payload.testing.FakePayloadGeneratorModule;
import com.google.tsunami.plugin.payload.testing.PayloadTestHelper;
import com.google.tsunami.plugins.detectors.rce.cve202421650.Annotations.OobSleepDuration;
import com.google.tsunami.proto.*;
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

/** Unit tests for {@link Cve202421650Detector}. */
@RunWith(JUnit4.class)
public final class Cve202421650DetectorTest {
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2024-01-27T00:00:00.00Z"));

  static final String CSRF_TEMPLATE =
      "<input type=\"hidden\" name=\"form_token\" value=\"XJJ8bxI3PjfwK9FxAUPFCg\" />";

  static String PSEUDO_RANDOM_STR = "18d48374c00";

  private MockWebServer mockWebServer;
  private MockWebServer mockCallbackServer;

  @Inject private Cve202421650Detector detector;

  private NetworkService service;
  private TargetInfo targetInfo;

  @Bind(lazy = true)
  @OobSleepDuration
  private int sleepDuration = 1;

  @Before
  public void setUp() {
    mockWebServer = new MockWebServer();
    mockCallbackServer = new MockWebServer();
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            FakePayloadGeneratorModule.builder().setCallbackServer(mockCallbackServer).build(),
            new Cve202421650DetectorBootstrapModule())
        .injectMembers(this);

    targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(NetworkEndpointUtils.forHostname(mockWebServer.getHostName()))
            .build();
    service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                NetworkEndpointUtils.forHostnameAndPort(
                    mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("http")
            .build();
  }

  @After
  public void tearDown() throws IOException {
    mockWebServer.shutdown();
  }

  @Test
  public void detect_whenVulnerable_returnsVulnerability() throws IOException {
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody(CSRF_TEMPLATE));
    mockWebServer.enqueue(
        new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .setBody("XWiki.test" + PSEUDO_RANDOM_STR + "]] (test" + PSEUDO_RANDOM_STR + ")"));
    mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.ACCEPTED.code()));
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
                                .setValue("CVE-2024-21650"))
                        .setSeverity(Severity.CRITICAL)
                        .setTitle("XWiki RCE (CVE-2024-21650)")
                        .setDescription(
                            "XWiki is vulnerable to a remote code execution (RCE) attack through"
                                + " its user registration feature. This issue allows an attacker to"
                                + " execute arbitrary code by crafting malicious payloads in the"
                                + " \"first name\" or \"last name\" fields during user"
                                + " registration. This impacts all installations that have user"
                                + " registration enabled for guests. This vulnerability has been"
                                + " patched in XWiki 14.10.17, 15.5.3 and 15.8 RC1."))
                .build());
  }

  @Test
  public void detect_whenVulnerable_noCallbackServer_returnsVulnerability() {
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            FakePayloadGeneratorModule.builder().build(),
            new Cve202421650DetectorBootstrapModule())
        .injectMembers(this);

    mockWebServer.enqueue(
        new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody(CSRF_TEMPLATE));
    mockWebServer.enqueue(
        new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .setBody("XWiki.test" + PSEUDO_RANDOM_STR + "]] (test" + PSEUDO_RANDOM_STR + ")"));
    mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.ACCEPTED.code()));

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
                                .setValue("CVE-2024-21650"))
                        .setSeverity(Severity.CRITICAL)
                        .setTitle("XWiki RCE (CVE-2024-21650)")
                        .setDescription(
                            "XWiki is vulnerable to a remote code execution (RCE) attack through"
                                + " its user registration feature. This issue allows an attacker to"
                                + " execute arbitrary code by crafting malicious payloads in the"
                                + " \"first name\" or \"last name\" fields during user"
                                + " registration. This impacts all installations that have user"
                                + " registration enabled for guests. This vulnerability has been"
                                + " patched in XWiki 14.10.17, 15.5.3 and 15.8 RC1."))
                .build());
  }

  @Test
  public void detect_ifNotVulnerable_doesNotReportVuln() {
    mockWebServer.enqueue(new MockResponse().setResponseCode(200).setBody(CSRF_TEMPLATE));
    mockWebServer.enqueue(
        new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .setBody("<!DOCTYPE html><html><head></head><body>...</body></html>"));
    mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.ACCEPTED.code()));
    mockCallbackServer.enqueue(PayloadTestHelper.generateMockUnsuccessfulCallbackResponse());

    DetectionReportList detectionReports = detector.detect(targetInfo, ImmutableList.of(service));
    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void detect_ifNotVulnerable_noCallbackServer_doesNotReportVuln() {
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            FakePayloadGeneratorModule.builder().build(),
            new Cve202421650DetectorBootstrapModule())
        .injectMembers(this);

    mockWebServer.enqueue(new MockResponse().setResponseCode(200).setBody(CSRF_TEMPLATE));
    mockWebServer.enqueue(
        new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .setBody("<!DOCTYPE html><html><head></head><body>...</body></html>"));
    mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.ACCEPTED.code()));

    DetectionReportList detectionReports = detector.detect(targetInfo, ImmutableList.of(service));
    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }
}
