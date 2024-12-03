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
package com.google.tsunami.plugins.cve20232843;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;
import static com.google.tsunami.plugins.cves.cve202328432.Cve202328432VulnDetector.DESCRIPTION;
import static com.google.tsunami.plugins.cves.cve202328432.Cve202328432VulnDetector.RECOMMENDATION;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertEquals;

import com.google.common.collect.ImmutableList;
import com.google.common.io.Resources;
import com.google.common.truth.Truth8;
import com.google.inject.Guice;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.net.http.HttpRequest;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.plugins.cves.cve202328432.Cve202328432VulnDetector;
import com.google.tsunami.plugins.cves.cve202328432.Cve202328432VulnDetectorBootstrapModule;
import com.google.tsunami.plugins.cves.cve202328432.minio.Digest;
import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.Software;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TextData;
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

/** Unit tests for {@link Cve202328432VulnDetector}. */
@RunWith(JUnit4.class)
public final class Cve202328432VulnDetectorTest {
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  @Inject private Cve202328432VulnDetector detector;

  private MockWebServer mockMinIOWebService;
  private NetworkService minIONetworkService;

  @Before
  public void setUp() throws IOException {

    mockMinIOWebService = new MockWebServer();
    minIONetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(
                    mockMinIOWebService.getHostName(), mockMinIOWebService.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setSoftware(Software.newBuilder().setName("MinIO"))
            .setServiceName("http")
            .build();
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            new Cve202328432VulnDetectorBootstrapModule())
        .injectMembers(this);
  }

  @Test
  public void buildSignedHttpRequest_whenValidKey_signedHttpRequest() {

    String uri = "http://foo.bar:9000/";
    String requestDate = "20230405T175634Z";
    String accessKey = "this_is_the_access_key";
    String accessSecret = "this_is_the_password";

    HttpRequest signedRequest =
        detector.buildSignedHttpRequest(uri, requestDate, accessKey, accessSecret);

    assertEquals(signedRequest.url().toString(), uri);
    assertEquals("GET", signedRequest.method().toString());
    assertThat(signedRequest.headers().names()).hasSize(5);
    Truth8.assertThat(signedRequest.headers().get("Host")).hasValue("foo.bar:9000");
    Truth8.assertThat(signedRequest.headers().get("x-amz-content-sha256"))
        .hasValue(Digest.ZERO_SHA256_HASH);
    assertEquals(signedRequest.headers().get("x-amz-date").get(), requestDate);
    Truth8.assertThat(signedRequest.headers().get("Authorization"))
        .hasValue(
            "AWS4-HMAC-SHA256 Credential=this_is_the_access_key/20230405/us-east-1/s3/aws4_request,"
                + " SignedHeaders=host;x-amz-content-sha256;x-amz-date,"
                + " Signature=7c8a3b72959c706663af9b6fe03c42e56410b63931a971e9d2e5ce8e422333b5");
    assertEquals(signedRequest.requestBody(), Optional.empty());
  }

  @Test
  public void detect_whenMinIOIsVulnerableKey_reportsVuln() throws IOException {
    String failedAuthResponse =
        Resources.toString(Resources.getResource(this.getClass(), "failedAuthResponse.xml"), UTF_8);
    String vulnerableResponseKey =
        Resources.toString(
            Resources.getResource(this.getClass(), "vulnerableResponseKey.json"), UTF_8);
    String successfulAuthResponse =
        Resources.toString(
            Resources.getResource(this.getClass(), "successfulAuthResponse.xml"), UTF_8);

    mockMinIOWebService.enqueue(
        new MockResponse().setResponseCode(200).setBody(failedAuthResponse));
    mockMinIOWebService.enqueue(
        new MockResponse().setResponseCode(200).setBody(vulnerableResponseKey));
    mockMinIOWebService.enqueue(
        new MockResponse().setResponseCode(200).setBody(successfulAuthResponse));

    DetectionReportList detectionReports =
        detector.detect(TargetInfo.getDefaultInstance(), ImmutableList.of(minIONetworkService));

    assertThat(detectionReports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(minIONetworkService, false, true, vulnerableResponseKey));
  }

  @Test
  public void detect_whenMinIOIsVulnerablePassword_reportsVuln() throws IOException {
    String failedAuthResponse =
        Resources.toString(Resources.getResource(this.getClass(), "failedAuthResponse.xml"), UTF_8);
    String vulnerableResponsePassword =
        Resources.toString(
            Resources.getResource(this.getClass(), "vulnerableResponsePassword.json"), UTF_8);
    String successfulAuthResponse =
        Resources.toString(
            Resources.getResource(this.getClass(), "successfulAuthResponse.xml"), UTF_8);

    mockMinIOWebService.enqueue(
        new MockResponse().setResponseCode(200).setBody(failedAuthResponse));
    mockMinIOWebService.enqueue(
        new MockResponse().setResponseCode(200).setBody(vulnerableResponsePassword));
    mockMinIOWebService.enqueue(
        new MockResponse().setResponseCode(200).setBody(successfulAuthResponse));

    DetectionReportList detectionReports =
        detector.detect(TargetInfo.getDefaultInstance(), ImmutableList.of(minIONetworkService));

    assertThat(detectionReports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                minIONetworkService, false, true, vulnerableResponsePassword));
  }

  @Test
  public void detect_whenMinIOUsesDefaultPassword_reportsVuln() throws IOException {
    String successfulAuthResponse =
        Resources.toString(
            Resources.getResource(this.getClass(), "successfulAuthResponse.xml"), UTF_8);
    String saveResponse =
        Resources.toString(Resources.getResource(this.getClass(), "secureResponse.json"), UTF_8);

    mockMinIOWebService.enqueue(
        new MockResponse().setResponseCode(200).setBody(successfulAuthResponse));
    mockMinIOWebService.enqueue(new MockResponse().setResponseCode(200).setBody(saveResponse));
    mockMinIOWebService.enqueue(
        new MockResponse().setResponseCode(200).setBody(successfulAuthResponse));

    DetectionReportList detectionReports =
        detector.detect(TargetInfo.getDefaultInstance(), ImmutableList.of(minIONetworkService));

    assertThat(detectionReports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(minIONetworkService, true, true, saveResponse));
  }

  @Test
  public void detect_whenMinIOIsNotVulnerable_doesNotReportVuln() throws IOException {
    String failedAuthResponse =
        Resources.toString(Resources.getResource(this.getClass(), "failedAuthResponse.xml"), UTF_8);
    String saveResponse =
        Resources.toString(Resources.getResource(this.getClass(), "secureResponse.json"), UTF_8);

    mockMinIOWebService.enqueue(
        new MockResponse().setResponseCode(403).setBody(failedAuthResponse));
    mockMinIOWebService.enqueue(new MockResponse().setResponseCode(200).setBody(saveResponse));
    mockMinIOWebService.enqueue(
        new MockResponse().setResponseCode(403).setBody(failedAuthResponse));

    DetectionReportList detectionReports =
        detector.detect(TargetInfo.getDefaultInstance(), ImmutableList.of(minIONetworkService));

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void detect_whenFixedMinIOUsesDefaultPassword_doesReportVuln() throws IOException {
    String successfulAuthResponse =
        Resources.toString(
            Resources.getResource(this.getClass(), "successfulAuthResponse.xml"), UTF_8);
    String blockedNotifyResponse =
        Resources.toString(Resources.getResource(this.getClass(), "blockedNotify.xml"), UTF_8);

    mockMinIOWebService.enqueue(
        new MockResponse().setResponseCode(200).setBody(successfulAuthResponse));
    mockMinIOWebService.enqueue(
        new MockResponse().setResponseCode(403).setBody(blockedNotifyResponse));

    DetectionReportList detectionReports =
        detector.detect(TargetInfo.getDefaultInstance(), ImmutableList.of(minIONetworkService));

    assertThat(detectionReports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(minIONetworkService, true, true, blockedNotifyResponse));
  }

  @Test
  public void detect_whenNoMinIOEnvironment_doesNotReportVuln() throws IOException {
    mockMinIOWebService.enqueue(
        new MockResponse().setResponseCode(200).setBody("{\"random\": {}}"));
    mockMinIOWebService.enqueue(
        new MockResponse().setResponseCode(200).setBody("more-random-stuff"));
    DetectionReportList detectionReports =
        detector.detect(TargetInfo.getDefaultInstance(), ImmutableList.of(minIONetworkService));

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }

  private DetectionReport buildExpectedDetectionReport(
      NetworkService minIOService,
      Boolean usesDefaultPassword,
      Boolean authenticationSuccessful,
      String content) {
    String vulnerabilityDetail = "MinIO instances are vulnerable for the following reason(s):";
    if (usesDefaultPassword) {
      vulnerabilityDetail =
          vulnerabilityDetail.concat(" Default credentials (minioadmin:minioadmin) are used.");
    }
    if (authenticationSuccessful) {
      vulnerabilityDetail =
          vulnerabilityDetail.concat(" Leaked credentials enabled authentication bypass.");
    }
    vulnerabilityDetail = vulnerabilityDetail.concat(" Endpoint Response: " + content);

    return DetectionReport.newBuilder()
        .setTargetInfo(TargetInfo.getDefaultInstance())
        .setNetworkService(minIOService)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder()
                        .setPublisher("TSUNAMI_COMMUNITY")
                        .setValue("MINIO_INFORMATION_DISCLOSURE_CLUSTER_ENVIRONMENT"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("MinIO Information Disclosure in Cluster Environment")
                .setDescription(DESCRIPTION)
                .setRecommendation(RECOMMENDATION)
                .addAdditionalDetails(
                    AdditionalDetail.newBuilder()
                        .setTextData(TextData.newBuilder().setText(vulnerabilityDetail))))
        .build();
  }
}
