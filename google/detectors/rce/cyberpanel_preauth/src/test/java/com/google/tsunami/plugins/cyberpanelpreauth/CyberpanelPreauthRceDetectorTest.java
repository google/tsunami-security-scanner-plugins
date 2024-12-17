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
package com.google.tsunami.plugins.cyberpanelpreauth;

import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostname;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;

import com.google.common.collect.ImmutableList;
import com.google.inject.Guice;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.plugin.payload.testing.FakePayloadGeneratorModule;
import com.google.tsunami.proto.DetectionReport;
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

/** Unit tests for {@link CyberpanelPreauthRceDetector}. */
@RunWith(JUnit4.class)
public final class CyberpanelPreauthRceDetectorTest {
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));
  private static final String VULN_RESPONSE =
      "{'requestStatus': 'TSUNAMI_PAYLOAD_STARTffffffffffffffffTSUNAMI_PAYLOAD_END'}";
  private static final Vulnerability EXPECTED_VULN =
      Vulnerability.newBuilder()
          .setMainId(
              VulnerabilityId.newBuilder()
                  .setPublisher("GOOGLE")
                  .setValue("CYBERPANEL_PREAUTH_RCE"))
          .setSeverity(Severity.CRITICAL)
          .setTitle("Cyberpanel is vulnerable to pre-authentication remote code execution")
          .setRecommendation(
              "This is an unpatched vulnerability, we recommend temporarily firewalling the"
                  + " instance and apply a patch as soon as it is available.")
          .setDescription(
              "The instance of Cyberpanel is vulnerable to pre-authentication remote code"
                  + " execution.")
          .build();

  private MockWebServer mockWebServer;

  @Inject private CyberpanelPreauthRceDetector detector;

  private final SecureRandom testSecureRandom =
      new SecureRandom() {
        @Override
        public void nextBytes(byte[] bytes) {
          Arrays.fill(bytes, (byte) 0xFF);
        }
      };

  @Before
  public void setUp() {
    mockWebServer = new MockWebServer();

    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            FakePayloadGeneratorModule.builder().setSecureRng(testSecureRandom).build(),
            new CyberpanelPreauthRceDetectorBootstrapModule())
        .injectMembers(this);
  }

  @After
  public void tearDown() throws IOException {
    mockWebServer.shutdown();
  }

  @Test
  public void detect_whenVulnerable_reportsVuln() throws IOException {
    mockWebServer.enqueue(
        new MockResponse()
            .setResponseCode(200)
            .setHeader("Set-Cookie", "csrftoken=1234567890")
            .setBody("Login to your CyberPanel Account"));
    mockWebServer.enqueue(new MockResponse().setResponseCode(200).setBody(VULN_RESPONSE));
    mockWebServer.start();

    ImmutableList<NetworkService> httpServices =
        ImmutableList.of(
            NetworkService.newBuilder()
                .setNetworkEndpoint(
                    forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
                .setTransportProtocol(TransportProtocol.TCP)
                .setServiceName("http")
                .build());
    var targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockWebServer.getHostName()))
            .build();

    assertThat(detector.detect(targetInfo, httpServices).getDetectionReportsList())
        .containsExactly(
            DetectionReport.newBuilder()
                .setTargetInfo(targetInfo)
                .setNetworkService(httpServices.get(0))
                .setDetectionTimestamp(Timestamps.fromMillis(fakeUtcClock.instant().toEpochMilli()))
                .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
                .setVulnerability(EXPECTED_VULN)
                .build());
  }

  @Test
  public void detect_whenNotCyberpanel_reportsNothing() throws IOException {
    mockWebServer.enqueue(new MockResponse().setResponseCode(200).setBody("Welcome to confluence"));
    mockWebServer.start();

    ImmutableList<NetworkService> httpServices =
        ImmutableList.of(
            NetworkService.newBuilder()
                .setNetworkEndpoint(
                    forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
                .setTransportProtocol(TransportProtocol.TCP)
                .setServiceName("http")
                .build());
    var targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockWebServer.getHostName()))
            .build();

    assertThat(detector.detect(targetInfo, httpServices).getDetectionReportsList()).isEmpty();
  }

  @Test
  public void detect_whenNoCookie_reportsNothing() throws IOException {
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(200).setBody("Login to your CyberPanel Account"));
    mockWebServer.start();

    ImmutableList<NetworkService> httpServices =
        ImmutableList.of(
            NetworkService.newBuilder()
                .setNetworkEndpoint(
                    forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
                .setTransportProtocol(TransportProtocol.TCP)
                .setServiceName("http")
                .build());
    var targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockWebServer.getHostName()))
            .build();

    assertThat(detector.detect(targetInfo, httpServices).getDetectionReportsList()).isEmpty();
  }
}
