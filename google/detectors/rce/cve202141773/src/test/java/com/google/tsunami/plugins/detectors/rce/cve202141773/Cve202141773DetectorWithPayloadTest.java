/*
 * Copyright 2020 Google LLC
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
package com.google.tsunami.plugins.detectors.rce.cve202141773;

import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;

import com.google.common.collect.ImmutableList;
import com.google.inject.Guice;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.plugin.payload.testing.FakePayloadGeneratorModule;
import com.google.tsunami.plugin.payload.testing.PayloadTestHelper;
import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TextData;
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

/**
 * Unit tests for {@link Cve202141773DetectorWithPayload}
 */
@RunWith(JUnit4.class)
public final class Cve202141773DetectorWithPayloadTest {

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  @Inject private Cve202141773DetectorWithPayload detector;

  private final SecureRandom testSecureRandom =
      new SecureRandom() {
        @Override
        public void nextBytes(byte[] bytes) {
          Arrays.fill(bytes, (byte) 0xFF);
        }
      };

  private final MockWebServer mockTargetService = new MockWebServer();

  private final MockWebServer mockCallbackServer = new MockWebServer();

  @Before
  public void setUp() throws IOException {
    mockTargetService.start();
    mockCallbackServer.start();

    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            FakePayloadGeneratorModule.builder()
                .setCallbackServer(mockCallbackServer)
                .setSecureRng(testSecureRandom)
                .build(),
            new Cve202141773DetectorWithPayloadBootstrapModule())
        .injectMembers(this);
  }

  @After
  public void tearDown() throws Exception {
    mockTargetService.shutdown();
    mockCallbackServer.shutdown();
  }

  @Test
  public void detect_withCallbackServer_onVulnerableTarget_returnsVulnerability()
      throws IOException {
    mockTargetService.enqueue(new MockResponse().setResponseCode(HttpStatus.OK.code()));
    mockCallbackServer.enqueue(PayloadTestHelper.generateMockSuccessfulCallbackResponse());
    NetworkService targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockTargetService.getHostName(), mockTargetService.getPort()))
            .build();
    TargetInfo targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(targetNetworkService.getNetworkEndpoint())
            .build();

    DetectionReportList detectionReports =
        detector.detect(targetInfo, ImmutableList.of(targetNetworkService));

     assertThat(detectionReports.getDetectionReportsList())
        .containsExactly(
            DetectionReport.newBuilder()
                .setTargetInfo(targetInfo)
                .setNetworkService(targetNetworkService)
                .setDetectionTimestamp(
                    Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
                .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
                .setVulnerability(
                  Vulnerability.newBuilder()
                    .setMainId(
                        VulnerabilityId.newBuilder()
                            .setPublisher("GOOGLE")
                            .setValue("CVE_2021_41773"))
                    .setSeverity(Severity.CRITICAL)
                    .setTitle("Apache RCE Vulnerability CVE-2021-41773")
                    .setDescription("This version of Apache is vulnerable to a Remote Code "
                      + "Execution vulnerability described in CVE-2021-41773. The attacker has the "
                      + "user permissions of the Apache process. For more information see "
                      + "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41773")
                    .setRecommendation("Update to 2.4.51 release.")
                    .addAdditionalDetails(
                        AdditionalDetail.newBuilder()
                            .setTextData(
                                TextData.newBuilder().setText("This detector checks only for the "
                                + "RCE vulnerability described in the CVE-2021-41773 and not for "
                                + "the path traversal described in the same CVE. If CGI is enabled "
                                + "on Apache in a vulnerable version the path traversal is not "
                                + "detected anymore by common detectors. In this case this "
                                + "detector finds the RCE. The detector can be tested with the "
                                + "following docker containers "
                                + "https://github.com/BlueTeamSteve/CVE-2021-41773"))))
                .build());
  }

  @Test
  public void detect_withCallbackServer_onNotVulnerableTarget_returnsEmpty() throws IOException {
    mockTargetService.enqueue(new MockResponse().setResponseCode(HttpStatus.OK.code()));
    mockCallbackServer.enqueue(PayloadTestHelper.generateMockUnsuccessfulCallbackResponse());
    NetworkService targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockTargetService.getHostName(), mockTargetService.getPort()))
            .build();
    TargetInfo targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(targetNetworkService.getNetworkEndpoint())
            .build();

    DetectionReportList detectionReports =
        detector.detect(targetInfo, ImmutableList.of(targetNetworkService));

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void detect_withoutCallbackServer_onVulnerableTarget_returnsVulnerability()
      throws IOException {
    mockTargetService.enqueue(
      new MockResponse()
        .setResponseCode(HttpStatus.OK.code())
        .setBody("TSUNAMI_PAYLOAD_STARTffffffffffffffffTSUNAMI_PAYLOAD_END"));

    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            FakePayloadGeneratorModule.builder().setSecureRng(testSecureRandom).build(),
            new Cve202141773DetectorWithPayloadBootstrapModule())
        .injectMembers(this);

    NetworkService targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockTargetService.getHostName(), mockTargetService.getPort()))
            .build();
     TargetInfo targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(targetNetworkService.getNetworkEndpoint())
            .build();
    DetectionReportList detectionReports =
        detector.detect(targetInfo, ImmutableList.of(targetNetworkService));

    assertThat(detectionReports.getDetectionReportsList())
        .containsExactly(
            DetectionReport.newBuilder()
                .setTargetInfo(targetInfo)
                .setNetworkService(targetNetworkService)
                .setDetectionTimestamp(
                    Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
                .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
                .setVulnerability(
                  Vulnerability.newBuilder()
                    .setMainId(
                        VulnerabilityId.newBuilder()
                            .setPublisher("GOOGLE")
                            .setValue("CVE_2021_41773"))
                    .setSeverity(Severity.CRITICAL)
                    .setTitle("Apache RCE Vulnerability CVE-2021-41773")
                    .setDescription("This version of Apache is vulnerable to a Remote Code "
                      + "Execution vulnerability described in CVE-2021-41773. The attacker has the "
                      + "user permissions of the Apache process. For more information see "
                      + "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41773")
                    .setRecommendation("Update to 2.4.51 release.")
                    .addAdditionalDetails(
                        AdditionalDetail.newBuilder()
                            .setTextData(
                                TextData.newBuilder().setText("This detector checks only for the "
                                + "RCE vulnerability described in the CVE-2021-41773 and not for "
                                + "the path traversal described in the same CVE. If CGI is enabled "
                                + "on Apache in a vulnerable version the path traversal is not "
                                + "detected anymore by common detectors. In this case this "
                                + "detector finds the RCE. The detector can be tested with the "
                                + "following docker containers "
                                + "https://github.com/BlueTeamSteve/CVE-2021-41773"))))
                .build());
  }

  @Test
  public void detect_withoutCallbackServer_onNotVulnerableTarget_returnsVulnerability()
      throws IOException {
    mockTargetService.enqueue(
      new MockResponse()
        .setResponseCode(HttpStatus.OK.code())
        .setBody("not vulnerable"));

    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            FakePayloadGeneratorModule.builder().setSecureRng(testSecureRandom).build(),
            new Cve202141773DetectorWithPayloadBootstrapModule())
        .injectMembers(this);

    NetworkService targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockTargetService.getHostName(), mockTargetService.getPort()))
            .build();
     TargetInfo targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(targetNetworkService.getNetworkEndpoint())
            .build();
    DetectionReportList detectionReports =
        detector.detect(targetInfo, ImmutableList.of(targetNetworkService));

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }
}
