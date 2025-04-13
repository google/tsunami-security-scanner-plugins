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
package com.google.tsunami.plugins.detectors.rce.cve20187600;

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
import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkEndpoint;
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

/** Unit tests for {@link DrupalCve20187600Detector}. */
@RunWith(JUnit4.class)
public final class DrupalCve20187600DetectorTest {

  private static final String PATH =
      "user/register?element_parents=account/mail/%23value&"
          + "ajax_form=1&_wrapper_format=drupal_ajax";

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2021-01-01T00:00:00.00Z"));

  private MockWebServer mockWebServer;

  @Inject private DrupalCve20187600Detector detector;

  @Before
  public void setUp() {
    mockWebServer = new MockWebServer();
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            new DrupalCve20187600DetectorBootstrapModule())
        .injectMembers(this);
  }

  @After
  public void tearDown() throws IOException {
    mockWebServer.shutdown();
  }

  @Test
  public void detect_whenDrupalCve20187600DetectorTriggered_returnsVulnerability()
      throws IOException {
    ImmutableList<NetworkService> httpServices = testSetupWithVulnerableEndpoint();

    DetectionReportList detectionReports =
        detector.detect(buildTargetInfo(forHostname(mockWebServer.getHostName())), httpServices);

    verifyVulnerabilityReport(detectionReports, httpServices.get(0));
  }

  @Test
  public void detect_whenDrupalCve20187600DetectorNotTriggered_returnsEmptyDetectionReport()
      throws IOException {
    mockWebServer.setDispatcher(new SafeEndpointDispatcher());
    mockWebServer.start();
    ImmutableList<NetworkService> httpServices =
        ImmutableList.of(
            NetworkService.newBuilder()
                .setNetworkEndpoint(
                    forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
                .setTransportProtocol(TransportProtocol.TCP)
                .setServiceName("http")
                .build());

    assertThat(
            detector
                .detect(buildTargetInfo(forHostname(mockWebServer.getHostName())), httpServices)
                .getDetectionReportsList())
        .isEmpty();
  }

  private ImmutableList<NetworkService> testSetupWithVulnerableEndpoint() throws IOException {
    mockWebServer.setDispatcher(new VulnerableEndpointDispatcher(PATH));
    mockWebServer.start();
    return ImmutableList.of(
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("http")
            .build());
  }

  private void verifyVulnerabilityReport(
      DetectionReportList detectionReports, NetworkService service) {
    assertThat(detectionReports.getDetectionReportsList())
        .containsExactly(
            DetectionReport.newBuilder()
                .setTargetInfo(buildTargetInfo(forHostname(mockWebServer.getHostName())))
                .setNetworkService(service)
                .setDetectionTimestamp(
                    Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
                .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
                .setVulnerability(
                    Vulnerability.newBuilder()
                        .setMainId(
                            VulnerabilityId.newBuilder()
                                .setPublisher("GOOGLE")
                                .setValue("CVE_2018_7600"))
                        .setSeverity(Severity.CRITICAL)
                        .setTitle("Drupalgeddon 2 Detected")
                        .setDescription(
                            "This version of Drupal is vulnerable to CVE-2018-7600. Drupal versions"
                                + " before 7.58, 8.x before 8.3.9, 8.4.x before 8.4.6, and 8.5.x"
                                + " before 8.5.1 are vulnerable to this vulnerability. Drupal has"
                                + " insufficient input sanitation on Form API AJAX requests. This"
                                + " enables an attacker to inject a malicious payload into the"
                                + " internal form structure which would then be executed without"
                                + " any authentication")
                        .setRecommendation("Upgrade to Drupal 8.3.9 or Drupal 8.5.1.")
                        .addAdditionalDetails(
                            AdditionalDetail.newBuilder()
                                .setTextData(
                                    TextData.newBuilder()
                                        .setText(
                                            "The Drupal platform is vulnerable to "
                                                + "CVE-2018-7600."))))
                .build());
  }

  static final class SafeEndpointDispatcher extends Dispatcher {

    @Override
    public MockResponse dispatch(RecordedRequest recordedRequest) {
      return new MockResponse().setResponseCode(HttpStatus.OK.code());
    }
  }

  private static TargetInfo buildTargetInfo(NetworkEndpoint networkEndpoint) {
    return TargetInfo.newBuilder().addNetworkEndpoints(networkEndpoint).build();
  }

  static final class VulnerableEndpointDispatcher extends Dispatcher {

    private final String vulnerablePath;

    VulnerableEndpointDispatcher(String vulnerablePath) {
      this.vulnerablePath = vulnerablePath;
    }

    @Override
    public MockResponse dispatch(RecordedRequest recordedRequest) {
      if (recordedRequest.getPath().equals("/" + vulnerablePath)) {
        return new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .setBody(DrupalCve20187600Detector.RESPONSE_STRING);
      }

      return new MockResponse().setResponseCode(HttpStatus.OK.code());
    }
  }
}
