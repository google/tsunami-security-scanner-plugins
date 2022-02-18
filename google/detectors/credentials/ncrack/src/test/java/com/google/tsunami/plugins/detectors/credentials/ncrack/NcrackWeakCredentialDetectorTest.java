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
package com.google.tsunami.plugins.detectors.credentials.ncrack;

import static com.google.common.truth.Truth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forIp;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forIpAndPort;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.google.common.collect.ImmutableList;
import com.google.inject.Guice;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.plugins.detectors.credentials.ncrack.provider.CredentialProvider;
import com.google.tsunami.plugins.detectors.credentials.ncrack.provider.TestCredential;
import com.google.tsunami.plugins.detectors.credentials.ncrack.tester.CredentialTester;
import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.Credential;
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
import java.util.Optional;
import javax.inject.Inject;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.ArgumentCaptor;

/** Tests for {@link NcrackWeakCredentialDetector}. */
@RunWith(JUnit4.class)
public final class NcrackWeakCredentialDetectorTest {

  private static final Instant FAKE_NOW = Instant.parse("2020-01-01T00:00:00.00Z");
  private static final ImmutableList<TestCredential> TEST_CREDENTIALS =
      ImmutableList.of(
          TestCredential.create("username1", Optional.of("password1")),
          TestCredential.create("username2", Optional.of("password2")),
          TestCredential.create("username3", Optional.of("password3")));

  private CredentialTester tester1;
  private CredentialTester tester2;
  private CredentialTester tester3;
  private NcrackWeakCredentialDetector plugin;
  private FakeUtcClock fakeUtcClock;
  @Inject private HttpClient httpClient;

  @Before
  public void setupPlugin() {
    CredentialProvider provider = mock(CredentialProvider.class);
    tester1 = mock(CredentialTester.class);
    tester2 = mock(CredentialTester.class);
    tester3 = mock(CredentialTester.class);

    // thenReturn method will always return the same instance of iterator, which will be exhausted
    // by previous testers, hence we are using thenAnswer method.
    when(provider.generateTestCredentials()).thenAnswer(invocation -> TEST_CREDENTIALS.iterator());
    when(tester1.canAccept(any())).thenReturn(true);
    when(tester2.canAccept(any())).thenReturn(true);
    when(tester3.canAccept(any())).thenReturn(true);

    fakeUtcClock = FakeUtcClock.create().setNow(FAKE_NOW);

    Guice.createInjector(new HttpClientModule.Builder().build()).injectMembers(this);

    plugin =
        new NcrackWeakCredentialDetector(
            provider, ImmutableList.of(tester1, tester2, tester3), fakeUtcClock, httpClient);
  }

  @Test
  public void run_whenNoTesterReportsValidCredential_returnsEmptyList() {
    when(tester1.testValidCredentials(any(), any())).thenReturn(ImmutableList.of());
    when(tester2.testValidCredentials(any(), any())).thenReturn(ImmutableList.of());
    when(tester3.testValidCredentials(any(), any())).thenReturn(ImmutableList.of());

    DetectionReportList detectionReports =
        plugin.detect(
            TargetInfo.newBuilder().addNetworkEndpoints(forIp("1.1.1.1")).build(),
            ImmutableList.of(
                NetworkService.newBuilder()
                    .setNetworkEndpoint(forIpAndPort("1.1.1.1", 80))
                    .setTransportProtocol(TransportProtocol.TCP)
                    .setServiceName("http")
                    .build()));

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void run_whenATestersReportsValidCredential_returnsFinding() {
    when(tester1.testValidCredentials(any(), any()))
        .thenReturn(ImmutableList.of(TestCredential.create("username1", Optional.of("password1"))))
        .thenReturn(ImmutableList.of());
    when(tester2.testValidCredentials(any(), any())).thenReturn(ImmutableList.of());
    when(tester3.testValidCredentials(any(), any())).thenReturn(ImmutableList.of());

    DetectionReportList detectionReports =
        plugin.detect(
            TargetInfo.newBuilder().addNetworkEndpoints(forIp("1.1.1.1")).build(),
            ImmutableList.of(
                NetworkService.newBuilder()
                    .setNetworkEndpoint(forIpAndPort("1.1.1.1", 80))
                    .setTransportProtocol(TransportProtocol.TCP)
                    .setServiceName("http")
                    .build()));

    assertThat(detectionReports.getDetectionReportsList())
        .containsExactly(
            DetectionReport.newBuilder()
                .setTargetInfo(TargetInfo.newBuilder().addNetworkEndpoints(forIp("1.1.1.1")))
                .setNetworkService(
                    NetworkService.newBuilder()
                        .setNetworkEndpoint(forIpAndPort("1.1.1.1", 80))
                        .setTransportProtocol(TransportProtocol.TCP)
                        .setServiceName("http")
                        .build())
                .setDetectionTimestamp(Timestamps.fromMillis(FAKE_NOW.toEpochMilli()))
                .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
                .setVulnerability(
                    Vulnerability.newBuilder()
                        .setMainId(
                            VulnerabilityId.newBuilder()
                                .setPublisher("GOOGLE")
                                .setValue("WEAK_CREDENTIALS_FOR_HTTP"))
                        .setSeverity(Severity.CRITICAL)
                        .setTitle("Weak 'http' service credential")
                        .setDescription(
                            "Well known or weak credentials are detected for 'http' service on"
                                + " port '80'.")
                        .setCvssV3("7.5")
                        .addAdditionalDetails(
                            AdditionalDetail.newBuilder()
                                .setDescription("Identified credential")
                                .setCredential(
                                    Credential.newBuilder()
                                        .setUsername("username1")
                                        .setPassword("password1"))))
                .build());
  }

  @Test
  public void run_whenMultipleTestersReportValidCredential_returnsMultipleFindings() {
    when(tester1.testValidCredentials(any(), any()))
        .thenReturn(ImmutableList.of(TestCredential.create("username1", Optional.of("password1"))))
        .thenReturn(ImmutableList.of());
    when(tester2.testValidCredentials(any(), any()))
        .thenReturn(ImmutableList.of(TestCredential.create("username2", Optional.of("password2"))))
        .thenReturn(ImmutableList.of());
    when(tester3.testValidCredentials(any(), any())).thenReturn(ImmutableList.of());

    DetectionReportList detectionReports =
        plugin.detect(
            TargetInfo.newBuilder().addNetworkEndpoints(forIp("1.1.1.1")).build(),
            ImmutableList.of(
                NetworkService.newBuilder()
                    .setNetworkEndpoint(forIpAndPort("1.1.1.1", 80))
                    .setTransportProtocol(TransportProtocol.TCP)
                    .setServiceName("http")
                    .build()));

    assertThat(detectionReports.getDetectionReportsList())
        .containsExactly(
            DetectionReport.newBuilder()
                .setTargetInfo(TargetInfo.newBuilder().addNetworkEndpoints(forIp("1.1.1.1")))
                .setNetworkService(
                    NetworkService.newBuilder()
                        .setNetworkEndpoint(forIpAndPort("1.1.1.1", 80))
                        .setTransportProtocol(TransportProtocol.TCP)
                        .setServiceName("http")
                        .build())
                .setDetectionTimestamp(Timestamps.fromMillis(FAKE_NOW.toEpochMilli()))
                .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
                .setVulnerability(
                    Vulnerability.newBuilder()
                        .setMainId(
                            VulnerabilityId.newBuilder()
                                .setPublisher("GOOGLE")
                                .setValue("WEAK_CREDENTIALS_FOR_HTTP"))
                        .setSeverity(Severity.CRITICAL)
                        .setTitle("Weak 'http' service credential")
                        .setDescription(
                            "Well known or weak credentials are detected for 'http' service on"
                                + " port '80'.")
                        .setCvssV3("7.5")
                        .addAdditionalDetails(
                            AdditionalDetail.newBuilder()
                                .setDescription("Identified credential")
                                .setCredential(
                                    Credential.newBuilder()
                                        .setUsername("username1")
                                        .setPassword("password1"))))
                .build(),
            DetectionReport.newBuilder()
                .setTargetInfo(TargetInfo.newBuilder().addNetworkEndpoints(forIp("1.1.1.1")))
                .setNetworkService(
                    NetworkService.newBuilder()
                        .setNetworkEndpoint(forIpAndPort("1.1.1.1", 80))
                        .setTransportProtocol(TransportProtocol.TCP)
                        .setServiceName("http")
                        .build())
                .setDetectionTimestamp(Timestamps.fromMillis(FAKE_NOW.toEpochMilli()))
                .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
                .setVulnerability(
                    Vulnerability.newBuilder()
                        .setMainId(
                            VulnerabilityId.newBuilder()
                                .setPublisher("GOOGLE")
                                .setValue("WEAK_CREDENTIALS_FOR_HTTP"))
                        .setSeverity(Severity.CRITICAL)
                        .setTitle("Weak 'http' service credential")
                        .setDescription(
                            "Well known or weak credentials are detected for 'http' service on"
                                + " port '80'.")
                        .setCvssV3("7.5")
                        .addAdditionalDetails(
                            AdditionalDetail.newBuilder()
                                .setDescription("Identified credential")
                                .setCredential(
                                    Credential.newBuilder()
                                        .setUsername("username2")
                                        .setPassword("password2"))))
                .build());
  }

  @Test
  public void run_whenNetworkServiceIsWordPress_performsFingerprintingAndTestWordPress()
      throws IOException {
    MockWebServer mockWebServer = new MockWebServer();
    mockWebServer.enqueue(
        new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .setBody(
                "<a href=\"https://wordpress.org/\">Powered by WordPress</a><form"
                    + " name=\"loginform\" id=\"loginform\""
                    + " action=\"http://fakehost/wp-login.php\" method=\"post\"></form>"));
    mockWebServer.start();
    mockWebServer.url("/wp-login.php");

    ArgumentCaptor<NetworkService> networkServiceCaptor =
        ArgumentCaptor.forClass(NetworkService.class);
    when(tester1.testValidCredentials(networkServiceCaptor.capture(), any()))
        .thenReturn(ImmutableList.of());
    when(tester2.testValidCredentials(networkServiceCaptor.capture(), any()))
        .thenReturn(ImmutableList.of());
    when(tester3.testValidCredentials(networkServiceCaptor.capture(), any()))
        .thenReturn(ImmutableList.of());

    NetworkService inputService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("http")
            .build();
    plugin.detect(
        TargetInfo.newBuilder()
            .addNetworkEndpoints(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .build(),
        ImmutableList.of(inputService));

    assertThat(networkServiceCaptor.getAllValues())
        .containsExactly(
            NetworkService.newBuilder(inputService)
                .setSoftware(Software.newBuilder().setName("WordPress"))
                .build(),
            NetworkService.newBuilder(inputService)
                .setSoftware(Software.newBuilder().setName("WordPress"))
                .build(),
            NetworkService.newBuilder(inputService)
                .setSoftware(Software.newBuilder().setName("WordPress"))
                .build());
  }
}
