/*
 * Copyright 2023 Google LLC
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
package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector;

import static com.google.common.truth.Truth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.inject.Guice;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.provider.CredentialProvider;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.provider.TestCredential;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.tester.CredentialTester;
import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.Credential;
import com.google.tsunami.proto.Credentials;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.ServiceContext;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.Software;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TransportProtocol;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import com.google.tsunami.proto.WebServiceContext;
import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import javax.inject.Inject;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

/** Tests for {@link GenericWeakCredentialDetector}. */
@RunWith(JUnit4.class)
public final class GenericWeakCredentialDetectorTest {
  @Rule public final MockitoRule mockito = MockitoJUnit.rule();

  private static final TestCredential HIGH_PRIORITY_CRED =
      TestCredential.create("admin", Optional.of("admin"));
  private static final Instant FAKE_NOW = Instant.parse("2020-01-01T00:00:00.00Z");
  private static final ImmutableList<TestCredential> TEST_CREDENTIALS1 =
      ImmutableList.of(
          TestCredential.create("username1", Optional.of("password1")),
          TestCredential.create("username2", Optional.of("password2")));
  private static final ImmutableList<TestCredential> TEST_CREDENTIALS2 =
      ImmutableList.of(
          TestCredential.create("username1", Optional.of("password1")),
          TestCredential.create("username2", Optional.of("password2")),
          TestCredential.create("username3", Optional.of("password3")));

  private static final ImmutableList<TestCredential> TEST_CREDENTIALS_HIGH_PRIORITY =
      ImmutableList.of(HIGH_PRIORITY_CRED);
  @Mock private CredentialProvider provider1;
  @Mock private CredentialProvider provider2;
  @Mock private CredentialProvider provider3;
  @Mock private CredentialTester tester1;
  @Mock private CredentialTester tester2;
  @Mock private CredentialTester tester3;
  private GenericWeakCredentialDetector plugin;
  private FakeUtcClock fakeUtcClock;
  private final MockWebServer mockWebServer = new MockWebServer();

  private NetworkService wpNetworkService;
  private NetworkService wpWebService;
  @Inject private HttpClient httpClient;

  @Captor private ArgumentCaptor<List<TestCredential>> listCaptor1;
  @Captor private ArgumentCaptor<List<TestCredential>> listCaptor2;
  @Captor private ArgumentCaptor<List<TestCredential>> listCaptor3;

  @Before
  public void setupPlugin() throws IOException {
    // thenReturn method will always return the same instance of iterator, which will be exhausted
    // by previous testers, hence we are using thenAnswer method.
    when(provider1.generateTestCredentials(any()))
        .thenAnswer(invocation -> TEST_CREDENTIALS1.iterator());
    when(provider2.generateTestCredentials(any()))
        .thenAnswer(invocation -> TEST_CREDENTIALS2.iterator());
    when(provider3.generateTestCredentials(any()))
        .thenAnswer(invocation -> TEST_CREDENTIALS_HIGH_PRIORITY.iterator());
    when(provider1.priority()).thenReturn(2);
    when(provider2.priority()).thenReturn(2);
    when(provider3.priority()).thenReturn(1);
    when(tester1.canAccept(any())).thenReturn(true);
    when(tester2.canAccept(any())).thenReturn(true);
    when(tester3.canAccept(any())).thenReturn(true);

    fakeUtcClock = FakeUtcClock.create().setNow(FAKE_NOW);

    Dispatcher dispatcher =
        new Dispatcher() {
          @Override
          public MockResponse dispatch(RecordedRequest request) throws InterruptedException {

            if (request.getPath().equals("/wp-login.php")) {
              return new MockResponse()
                  .setResponseCode(HttpStatus.OK.code())
                  .setBody(
                      "<a href=\"https://wordpress.org/\">Powered by WordPress</a><form"
                          + " name=\"loginform\" id=\"loginform\""
                          + " action=\"http://fakehost/wp-login.php\" method=\"post\"></form>");
            }

            return new MockResponse().setResponseCode(404);
          }
        };
    mockWebServer.setDispatcher(dispatcher);
    mockWebServer.start();

    wpNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("wordpress")
            .build();
    wpWebService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("http")
            .setServiceContext(
                ServiceContext.newBuilder()
                    .setWebServiceContext(
                        WebServiceContext.newBuilder()
                            .setSoftware(Software.newBuilder().setName("wordpress").build())
                            .build())
                    .build())
            .build();

    Guice.createInjector(new HttpClientModule.Builder().build()).injectMembers(this);

    plugin =
        new GenericWeakCredentialDetector(
            ImmutableSet.of(provider1, provider2, provider3),
            ImmutableSet.of(tester1, tester2, tester3),
            fakeUtcClock,
            httpClient);
  }

  @After
  public void tearDown() throws IOException {
    mockWebServer.shutdown();
  }

  @CanIgnoreReturnValue
  private DetectionReportList runDetectOnMockWebServer() {
    return plugin.detect(
        TargetInfo.newBuilder()
            .addNetworkEndpoints(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .build(),
        ImmutableList.of(
            NetworkService.newBuilder()
                .setNetworkEndpoint(
                    forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
                .setTransportProtocol(TransportProtocol.TCP)
                .setServiceName("wordpress")
                .build()));
  }

  @CanIgnoreReturnValue
  private DetectionReportList runDetectOnMockWebServerAgainstWebService() {
    return plugin.detect(
        TargetInfo.newBuilder()
            .addNetworkEndpoints(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .build(),
        ImmutableList.of(wpWebService));
  }

  private DetectionReport.Builder generateDetectionReport(
      NetworkService networkService, AdditionalDetail.Builder additionalDetailBuilder) {
    return DetectionReport.newBuilder()
        .setTargetInfo(
            TargetInfo.newBuilder()
                .addNetworkEndpoints(
                    forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort())))
        .setNetworkService(networkService)
        .setDetectionTimestamp(Timestamps.fromMillis(FAKE_NOW.toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder()
                        .setPublisher("GOOGLE")
                        .setValue("WEAK_CREDENTIALS_FOR_WORDPRESS"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Weak 'wordpress' service credential")
                .setCvssV3("7.5")
                .setDescription(
                    String.format(
                        "Well known or weak credentials are detected for 'wordpress' service on"
                            + " port '%s'.",
                        mockWebServer.getPort()))
                .setRecommendation("Change the password of all affected users to a strong one.")
                .addAdditionalDetails(additionalDetailBuilder));
  }

  @Test
  public void detect_utilizesAllCredentialProviders() {
    when(tester1.testValidCredentials(any(), any())).thenReturn(ImmutableList.of());
    when(tester2.testValidCredentials(any(), any())).thenReturn(ImmutableList.of());
    when(tester3.testValidCredentials(any(), any())).thenReturn(ImmutableList.of());

    runDetectOnMockWebServer();

    // 3 testers so generate credentials 3 times
    verify(provider1, times(3)).generateTestCredentials(any());
    verify(provider2, times(3)).generateTestCredentials(any());
  }

  @Test
  public void detect_onlyTestsUniqueCredentials() {
    when(tester1.testValidCredentials(any(), any())).thenReturn(ImmutableList.of());
    when(tester2.testValidCredentials(any(), any())).thenReturn(ImmutableList.of());
    when(tester3.testValidCredentials(any(), any())).thenReturn(ImmutableList.of());

    runDetectOnMockWebServer();

    verify(tester1).testValidCredentials(any(), listCaptor1.capture());
    assertThat(listCaptor1.getValue()).hasSize(4);
    assertThat(listCaptor1.getValue().get(0)).isEqualTo(HIGH_PRIORITY_CRED);
    verify(tester2).testValidCredentials(any(), listCaptor2.capture());
    assertThat(listCaptor2.getValue()).hasSize(4);
    assertThat(listCaptor2.getValue().get(0)).isEqualTo(HIGH_PRIORITY_CRED);
    verify(tester3).testValidCredentials(any(), listCaptor3.capture());
    assertThat(listCaptor3.getValue()).hasSize(4);
    assertThat(listCaptor3.getValue().get(0)).isEqualTo(HIGH_PRIORITY_CRED);
  }

  @Test
  public void run_whenNoTesterReportsValidCredential_returnsEmptyList() {
    when(tester1.testValidCredentials(any(), any())).thenReturn(ImmutableList.of());
    when(tester2.testValidCredentials(any(), any())).thenReturn(ImmutableList.of());
    when(tester3.testValidCredentials(any(), any())).thenReturn(ImmutableList.of());

    DetectionReportList detectionReports = runDetectOnMockWebServer();

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void run_whenATesterReportsValidCredential_returnsFinding() {
    when(tester1.testValidCredentials(any(), any()))
        .thenReturn(ImmutableList.of(TestCredential.create("username1", Optional.of("password1"))))
        .thenReturn(ImmutableList.of());
    when(tester2.testValidCredentials(any(), any())).thenReturn(ImmutableList.of());
    when(tester3.testValidCredentials(any(), any())).thenReturn(ImmutableList.of());

    DetectionReportList detectionReports = runDetectOnMockWebServer();

    assertThat(detectionReports.getDetectionReportsList())
        .containsExactly(
            generateDetectionReport(
                    wpNetworkService,
                    AdditionalDetail.newBuilder()
                        .setDescription("Identified credential(s)")
                        .setCredentials(
                            Credentials.newBuilder()
                                .addCredential(
                                    Credential.newBuilder()
                                        .setUsername("username1")
                                        .setPassword("password1"))
                                .build()))
                .build());
  }

  @Test
  public void run_whenMultipleTestersReportValidCredential_returnsSingleFinding() {
    when(tester1.testValidCredentials(any(), any()))
        .thenReturn(ImmutableList.of(TestCredential.create("username1", Optional.of("password1"))))
        .thenReturn(ImmutableList.of());
    when(tester2.testValidCredentials(any(), any()))
        .thenReturn(ImmutableList.of(TestCredential.create("username2", Optional.of("password2"))))
        .thenReturn(ImmutableList.of());
    when(tester3.testValidCredentials(any(), any())).thenReturn(ImmutableList.of());

    DetectionReportList detectionReports = runDetectOnMockWebServer();

    assertThat(detectionReports.getDetectionReportsList())
        .containsExactly(
            generateDetectionReport(
                    wpNetworkService,
                    AdditionalDetail.newBuilder()
                        .setDescription("Identified credential(s)")
                        .setCredentials(
                            Credentials.newBuilder()
                                .addCredential(
                                    Credential.newBuilder()
                                        .setUsername("username1")
                                        .setPassword("password1"))
                                .addCredential(
                                    Credential.newBuilder()
                                        .setUsername("username2")
                                        .setPassword("password2"))
                                .build()))
                .build());
  }

  @Test
  public void run_whenTestersReportsValidCredentialForWebService_returnsFinding() {
    when(tester1.testValidCredentials(any(), any()))
        .thenReturn(ImmutableList.of(TestCredential.create("username1", Optional.of("password1"))))
        .thenReturn(ImmutableList.of());
    when(tester2.testValidCredentials(any(), any())).thenReturn(ImmutableList.of());
    when(tester3.testValidCredentials(any(), any())).thenReturn(ImmutableList.of());

    DetectionReportList detectionReports = runDetectOnMockWebServerAgainstWebService();

    assertThat(detectionReports.getDetectionReportsList())
        .containsExactly(
            generateDetectionReport(
                    wpWebService,
                    AdditionalDetail.newBuilder()
                        .setDescription("Identified credential(s)")
                        .setCredentials(
                            Credentials.newBuilder()
                                .addCredential(
                                    Credential.newBuilder()
                                        .setUsername("username1")
                                        .setPassword("password1"))
                                .build()))
                .build());
  }
}
