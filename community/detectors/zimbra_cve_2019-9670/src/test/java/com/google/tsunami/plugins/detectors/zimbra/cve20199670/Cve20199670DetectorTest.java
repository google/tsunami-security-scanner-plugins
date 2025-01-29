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
package com.google.tsunami.plugins.detectors.zimbra.cve20199670;

import static com.google.common.truth.Truth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostname;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;
import static com.google.tsunami.plugins.detectors.zimbra.cve20199670.Cve20199670Detector.ERROR_MSG;
import static com.google.tsunami.plugins.detectors.zimbra.cve20199670.Cve20199670Detector.RECOMMENDATION;
import static com.google.tsunami.plugins.detectors.zimbra.cve20199670.Cve20199670Detector.TEST_STRING;
import static com.google.tsunami.plugins.detectors.zimbra.cve20199670.Cve20199670Detector.VULNERABILITY_REPORT_ID;
import static com.google.tsunami.plugins.detectors.zimbra.cve20199670.Cve20199670Detector.VULNERABILITY_REPORT_PUBLISHER;
import static com.google.tsunami.plugins.detectors.zimbra.cve20199670.Cve20199670Detector.VULNERABILITY_REPORT_TITLE;
import static com.google.tsunami.plugins.detectors.zimbra.cve20199670.Cve20199670Detector.VULN_DESCRIPTION;
import static com.google.tsunami.plugins.detectors.zimbra.cve20199670.Cve20199670Detector.ZIMBRA_FINGERPRING;

import com.google.common.collect.ImmutableList;
import com.google.inject.Guice;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TransportProtocol;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.io.IOException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import javax.inject.Inject;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link Cve20199670DetectorTest}. */
@RunWith(JUnit4.class)
public final class Cve20199670DetectorTest {
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  @Inject private Cve20199670Detector detector;

  private final SecureRandom testSecureRandom =
      new SecureRandom() {
        @Override
        public void nextBytes(byte[] bytes) {
          Arrays.fill(bytes, (byte) 0xFF);
        }
      };

  private MockWebServer mockZimbraService;

  @Before
  public void setUp() throws IOException {

    mockZimbraService = new MockWebServer();
    mockZimbraService.start();

    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            new Cve20199670DetectorBootstrapModule())
        .injectMembers(this);
  }

  @After
  public void tearDown() throws Exception {
    mockZimbraService.shutdown();
  }

  @Test
  public void detect_whenVulnerable_reportsVulnerability() throws IOException {
    // Zimbra is detected
    mockZimbraService.enqueue(
        new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody(ZIMBRA_FINGERPRING));
    mockZimbraService.enqueue(new MockResponse().setResponseCode(HttpStatus.OK.code()));

    // Detects XXE
    mockZimbraService.enqueue(
        new MockResponse()
            .setResponseCode(HttpStatus.SERVICE_UNAVAILABLE.code())
            .setBody(ERROR_MSG + TEST_STRING));

    NetworkService service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockZimbraService.getHostName(), mockZimbraService.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("http")
            .build();

    TargetInfo target =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockZimbraService.getHostName()))
            .build();

    DetectionReportList detectionReports = detector.detect(target, ImmutableList.of(service));

    assertThat(detectionReports.getDetectionReportsList())
        .containsExactly(
            DetectionReport.newBuilder()
                .setTargetInfo(target)
                .setNetworkService(service)
                .setDetectionTimestamp(
                    Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
                .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
                .setVulnerability(
                    Vulnerability.newBuilder()
                        .setMainId(
                            VulnerabilityId.newBuilder()
                                .setPublisher(VULNERABILITY_REPORT_PUBLISHER)
                                .setValue(VULNERABILITY_REPORT_ID))
                        .setSeverity(Severity.CRITICAL)
                        .setTitle(VULNERABILITY_REPORT_TITLE)
                        .setDescription(VULN_DESCRIPTION)
                        .setRecommendation(RECOMMENDATION))
                .build());
  }

  @Test
  public void detect_whenNotVulnerable_doesNotReportVulnerability() throws IOException {
    // Zimbra is detected
    mockZimbraService.enqueue(
        new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody(ZIMBRA_FINGERPRING));
    mockZimbraService.enqueue(new MockResponse().setResponseCode(HttpStatus.OK.code()));

    // Does not detect XXE
    mockZimbraService.enqueue(new MockResponse().setResponseCode(HttpStatus.BAD_REQUEST.code()));

    NetworkService service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockZimbraService.getHostName(), mockZimbraService.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("http")
            .build();

    TargetInfo target =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockZimbraService.getHostName()))
            .build();

    DetectionReportList detectionReports = detector.detect(target, ImmutableList.of(service));

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void detect_whenNonZimbraService_doesNotReportVulnerability() throws IOException {
    // Zimbra is not detected
    mockZimbraService.enqueue(new MockResponse().setResponseCode(HttpStatus.OK.code()));

    NetworkService service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockZimbraService.getHostName(), mockZimbraService.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("http")
            .build();

    TargetInfo target =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockZimbraService.getHostName()))
            .build();

    DetectionReportList detectionReports = detector.detect(target, ImmutableList.of(service));

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }
}
