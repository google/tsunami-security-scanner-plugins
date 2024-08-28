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
package com.google.tsunami.plugins.detectors.cves.cve202434102;

import static com.google.common.truth.Truth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostname;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;
import static com.google.tsunami.plugins.detectors.cves.cve202434102.MagentoCosmicStingXxe.*;

import com.google.common.collect.ImmutableList;
import com.google.inject.Guice;
import com.google.inject.testing.fieldbinder.Bind;
import com.google.inject.testing.fieldbinder.BoundFieldModule;
import com.google.inject.util.Modules;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.plugin.payload.testing.FakePayloadGeneratorModule;
import com.google.tsunami.plugin.payload.testing.PayloadTestHelper;
import com.google.tsunami.plugins.detectors.cves.cve202434102.Annotations.OobSleepDuration;
import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TextData;
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

/** Unit tests for {@link MagentoCosmicStingXxe}. */
@RunWith(JUnit4.class)
public final class MagentoCosmicStingXxeTest {

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2024-08-28T13:37:00.00Z"));

  @Bind(lazy = true)
  @OobSleepDuration
  private final int oobSleepDuration = 0;

  @Inject private MagentoCosmicStingXxe detector;
  private MockWebServer mockWebServer = new MockWebServer();
  private MockWebServer mockCallbackServer = new MockWebServer();

  private static final String MOCK_MAGENTO_VERSION = "Magento/2.4 (Mock)";
  private static final String PATCHED_INSTANCE_RESPONSE = "{\"message\":\"Invalid data type\"}";
  private static final String VULNERABLE_INSTANCE_RESPONSE =
      "{\"message\":\"Internal Error. Details are available in Magento log file. Report ID:"
          + " webapi-deadbeef1337\"}";

  @Before
  public void setUp() throws IOException {
    mockWebServer = new MockWebServer();
    mockCallbackServer.start();
  }

  @After
  public void tearDown() throws Exception {
    mockCallbackServer.shutdown();
    mockWebServer.shutdown();
  }

  private void createInjector(boolean tcsAvailable) {
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            FakePayloadGeneratorModule.builder()
                .setCallbackServer(tcsAvailable ? mockCallbackServer : null)
                .build(),
            Modules.override(new MagentoCosmicStingXxeBootstrapModule())
                .with(BoundFieldModule.of(this)))
        .injectMembers(this);
  }

  @Test
  public void detect_whenVulnerableAndTcsAvailable_reportsCriticalVulnerability()
      throws IOException {
    ImmutableList<NetworkService> httpServices = mockWebServerSetup(true);
    TargetInfo targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockWebServer.getHostName()))
            .build();

    createInjector(true);
    mockCallbackServer.enqueue(PayloadTestHelper.generateMockSuccessfulCallbackResponse());

    DetectionReportList detectionReports = detector.detect(targetInfo, httpServices);

    DetectionReport expectedDetection =
        generateDetectionReportWithCallback(targetInfo, httpServices.get(0));
    assertThat(detectionReports.getDetectionReportsList()).containsExactly(expectedDetection);
    assertThat(mockWebServer.getRequestCount()).isEqualTo(2);
    assertThat(mockCallbackServer.getRequestCount()).isEqualTo(1);
  }

  @Test
  public void detect_whenVulnerableAndTcsNotAvailable_reportsHighVulnerability()
      throws IOException {
    ImmutableList<NetworkService> httpServices = mockWebServerSetup(true);
    TargetInfo targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockWebServer.getHostName()))
            .build();

    createInjector(false);

    DetectionReportList detectionReports = detector.detect(targetInfo, httpServices);

    DetectionReport expectedDetection =
        generateDetectionReportWithResponseMatching(targetInfo, httpServices.get(0));
    assertThat(detectionReports.getDetectionReportsList()).containsExactly(expectedDetection);
    assertThat(mockWebServer.getRequestCount()).isEqualTo(2);
    assertThat(mockCallbackServer.getRequestCount()).isEqualTo(0);
  }

  @Test
  public void detect_whenNotVulnerableAndTcsAvailable_reportsNoVulnerability() throws IOException {
    ImmutableList<NetworkService> httpServices = mockWebServerSetup(false);
    TargetInfo targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockWebServer.getHostName()))
            .build();

    createInjector(true);
    mockCallbackServer.enqueue(PayloadTestHelper.generateMockUnsuccessfulCallbackResponse());

    DetectionReportList detectionReports = detector.detect(targetInfo, httpServices);

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
    assertThat(mockWebServer.getRequestCount()).isEqualTo(2);
    assertThat(mockCallbackServer.getRequestCount()).isEqualTo(1);
  }

  @Test
  public void detect_whenNotVulnerableAndTcsNotAvailable_reportsNoVulnerability()
      throws IOException {
    ImmutableList<NetworkService> httpServices = mockWebServerSetup(false);
    TargetInfo targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockWebServer.getHostName()))
            .build();

    createInjector(false);

    DetectionReportList detectionReports = detector.detect(targetInfo, httpServices);

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
    assertThat(mockWebServer.getRequestCount()).isEqualTo(2);
    assertThat(mockCallbackServer.getRequestCount()).isEqualTo(0);
  }

  private DetectionReport generateDetectionReportWithCallback(
      TargetInfo targetInfo, NetworkService networkService) {
    String additionalDetails = "Magento version: " + MOCK_MAGENTO_VERSION;

    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(networkService)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder()
                        .setPublisher(VULNERABILITY_REPORT_PUBLISHER)
                        .setValue(VULNERABILITY_REPORT_ID))
                .setSeverity(Severity.CRITICAL)
                .setTitle(VULNERABILITY_REPORT_TITLE)
                .setDescription(VULNERABILITY_REPORT_DESCRIPTION_CALLBACK)
                .setRecommendation(VULNERABILITY_REPORT_RECOMMENDATION)
                .addAdditionalDetails(
                    AdditionalDetail.newBuilder()
                        .setTextData(TextData.newBuilder().setText(additionalDetails))))
        .build();
  }

  private DetectionReport generateDetectionReportWithResponseMatching(
      TargetInfo targetInfo, NetworkService networkService) {
    String additionalDetails = "Magento version: " + MOCK_MAGENTO_VERSION;

    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(networkService)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder()
                        .setPublisher(VULNERABILITY_REPORT_PUBLISHER)
                        .setValue(VULNERABILITY_REPORT_ID))
                .setSeverity(Severity.HIGH)
                .setTitle(VULNERABILITY_REPORT_TITLE)
                .setDescription(VULNERABILITY_REPORT_DESCRIPTION_RESPONSE_MATCHING)
                .setRecommendation(VULNERABILITY_REPORT_RECOMMENDATION)
                .addAdditionalDetails(
                    AdditionalDetail.newBuilder()
                        .setTextData(TextData.newBuilder().setText(additionalDetails))))
        .build();
  }

  private ImmutableList<NetworkService> mockWebServerSetup(boolean isVulnerable)
      throws IOException {
    mockWebServer.setDispatcher(new EndpointDispatcher(isVulnerable));
    mockWebServer.start();
    return ImmutableList.of(
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("http")
            .build());
  }

  static final class EndpointDispatcher extends Dispatcher {
    EndpointDispatcher(boolean isVulnerable) {
      this.isVulnerable = isVulnerable;
    }

    private final boolean isVulnerable;

    @Override
    public MockResponse dispatch(RecordedRequest recordedRequest) {

      if (recordedRequest.getMethod().equals("GET")
          && recordedRequest.getPath().equals("/magento_version")) {
        // Version detection request
        return new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .setBody(MOCK_MAGENTO_VERSION);
      } else if (recordedRequest.getMethod().equals("POST")
          && recordedRequest.getPath().equals("/" + VULNERABLE_ENDPOINT_PATH)) {
        // Exploit attempt
        if (isVulnerable) {
          return new MockResponse()
              .setResponseCode(HttpStatus.INTERNAL_SERVER_ERROR.code())
              .setBody(VULNERABLE_INSTANCE_RESPONSE);
        } else {
          return new MockResponse()
              .setResponseCode(HttpStatus.BAD_REQUEST.code())
              .setBody(PATCHED_INSTANCE_RESPONSE);
        }
      } else {
        // Anything else, return a 404
        return new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code());
      }
    }
  }
}
