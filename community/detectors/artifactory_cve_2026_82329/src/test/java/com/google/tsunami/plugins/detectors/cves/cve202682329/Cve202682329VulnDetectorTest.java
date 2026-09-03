/*
 * Copyright 2026 Google LLC
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
package com.google.tsunami.plugins.detectors.cves.cve202682329;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostname;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.collect.ImmutableList;
import com.google.inject.Guice;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Software;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TransportProtocol;
import java.io.IOException;
import java.time.Instant;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.inject.Inject;
import mockwebserver3.MockResponse;
import mockwebserver3.MockWebServer;
import mockwebserver3.RecordedRequest;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link Cve202682329VulnDetector}. */
@RunWith(JUnit4.class)
public final class Cve202682329VulnDetectorTest {

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2026-09-03T00:00:00.00Z"));

  @Inject private Cve202682329VulnDetector detector;

  private MockWebServer mockWebServer;

  @Before
  public void setUp() {
    mockWebServer = new MockWebServer();
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new Cve202682329DetectorBootstrapModule(),
            new HttpClientModule.Builder().build())
        .injectMembers(this);
  }

  @After
  public void tearDown() throws IOException {
    mockWebServer.close();
  }

  @Test
  public void detect_whenTargetVulnerable_returnsDetectionReport()
      throws IOException, InterruptedException {
    mockWebServer.start();
    mockWebServer.enqueue(
        new MockResponse.Builder()
            .code(201)
            .setHeader("Content-Type", "application/json")
            .body("{\"token\":\"eyJh...fake-admin-token\"}")
            .build());

    NetworkService service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setSoftware(Software.newBuilder().setName("http"))
            .setServiceName("http")
            .build();
    TargetInfo targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockWebServer.getHostName()))
            .build();

    DetectionReportList detectionReports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(detectionReports.getDetectionReportsList())
        .containsExactly(
            DetectionReport.newBuilder()
                .setTargetInfo(targetInfo)
                .setNetworkService(service)
                .setDetectionTimestamp(
                    Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
                .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
                .setVulnerability(detector.getAdvisories().get(0))
                .build());

    RecordedRequest request = mockWebServer.takeRequest();
    assertThat(request.getMethod()).isEqualTo("POST");
    assertThat(request.getTarget()).isEqualTo("/access/api/v1/registry/join");
    assertThat(request.getHeaders().get("Content-Type")).isEqualTo("text/plain");
    String requestBody = request.getBody().utf8();
    String[] parts = requestBody.split("\\.", -1);
    assertThat(parts).hasLength(3);
    String decodedPayload = new String(Base64.getUrlDecoder().decode(parts[1]), UTF_8);
    assertThat(decodedPayload)
        .isEqualTo(
            String.format(
                "{\"iat\":%d,\"service_id\":\"tsunami@scanner\",\"kid\":\"%s\","
                    + "\"skip_node_registration\":true}",
                Instant.now(fakeUtcClock).getEpochSecond(), Cve202682329VulnDetector.BLANK_KID));
  }

  @Test
  public void detect_whenArtifactorySubpathVulnerable_returnsDetectionReport()
      throws IOException, InterruptedException {
    mockWebServer.start();
    mockWebServer.enqueue(new MockResponse.Builder().code(404).build());
    mockWebServer.enqueue(
        new MockResponse.Builder()
            .code(201)
            .setHeader("Content-Type", "application/json")
            .body("{\"token\":\"eyJh...fake-admin-token\"}")
            .build());

    NetworkService service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setSoftware(Software.newBuilder().setName("http"))
            .setServiceName("http")
            .build();
    TargetInfo targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockWebServer.getHostName()))
            .build();

    DetectionReportList detectionReports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(detectionReports.getDetectionReportsList())
        .containsExactly(
            DetectionReport.newBuilder()
                .setTargetInfo(targetInfo)
                .setNetworkService(service)
                .setDetectionTimestamp(
                    Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
                .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
                .setVulnerability(detector.getAdvisories().get(0))
                .build());

    RecordedRequest req1 = mockWebServer.takeRequest();
    assertThat(req1.getTarget()).isEqualTo("/access/api/v1/registry/join");
    RecordedRequest req2 = mockWebServer.takeRequest();
    assertThat(req2.getTarget()).isEqualTo("/artifactory/access/api/v1/registry/join");
    String requestBody = req2.getBody().utf8();
    String[] parts = requestBody.split("\\.", -1);
    assertThat(parts).hasLength(3);
    String decodedPayload = new String(Base64.getUrlDecoder().decode(parts[1]), UTF_8);
    assertThat(decodedPayload)
        .isEqualTo(
            String.format(
                "{\"iat\":%d,\"service_id\":\"tsunami@scanner\",\"kid\":\"%s\","
                    + "\"skip_node_registration\":true}",
                Instant.now(fakeUtcClock).getEpochSecond(), Cve202682329VulnDetector.BLANK_KID));
  }

  @Test
  public void detect_whenTargetPatched_returnsNoVulnerability() throws IOException {
    mockWebServer.start();
    // Patched versions return 400 Bad Request
    mockWebServer.enqueue(
        new MockResponse.Builder()
            .code(400)
            .body("{\"errors\":[{\"status\":400,\"message\":\"Bad request\"}]}")
            .build());
    mockWebServer.enqueue(
        new MockResponse.Builder()
            .code(400)
            .body("{\"errors\":[{\"status\":400,\"message\":\"Bad request\"}]}")
            .build());

    NetworkService service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setSoftware(Software.newBuilder().setName("http"))
            .setServiceName("http")
            .build();
    TargetInfo targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockWebServer.getHostName()))
            .build();

    DetectionReportList detectionReports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void detect_whenNonWebService_returnsNoVulnerability() {
    NetworkService service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forHostnameAndPort("localhost", 1234))
            .setTransportProtocol(TransportProtocol.UDP)
            .setServiceName("dns")
            .build();
    TargetInfo targetInfo =
        TargetInfo.newBuilder().addNetworkEndpoints(forHostname("localhost")).build();

    DetectionReportList detectionReports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void forgeJoinJwt_generatesValidTokenStructure() throws Exception {
    long epochSeconds = 1700000000L;
    String serviceId = "jfrt@01";
    String jwt = Cve202682329VulnDetector.forgeJoinJwt(epochSeconds, serviceId);
    assertThat(jwt).isNotNull();

    String[] parts = jwt.split("\\.", -1);
    assertThat(parts).hasLength(3);

    // Verify header
    assertThat(parts[0]).isEqualTo("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");
    String decodedHeader = new String(Base64.getUrlDecoder().decode(parts[0]), UTF_8);
    assertThat(decodedHeader).isEqualTo("{\"alg\":\"HS256\",\"typ\":\"JWT\"}");

    // Verify payload
    String expectedPayload =
        String.format(
            "{\"iat\":%d,\"service_id\":\"%s\",\"kid\":\"%s\",\"skip_node_registration\":true}",
            epochSeconds, serviceId, Cve202682329VulnDetector.BLANK_KID);
    String expectedPayloadB64 =
        Base64.getUrlEncoder().withoutPadding().encodeToString(expectedPayload.getBytes(UTF_8));
    assertThat(parts[1]).isEqualTo(expectedPayloadB64);
    String decodedPayload = new String(Base64.getUrlDecoder().decode(parts[1]), UTF_8);
    assertThat(decodedPayload).isEqualTo(expectedPayload);

    // Verify signature
    String expectedSigningInput = parts[0] + "." + expectedPayloadB64;
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(Cve202682329VulnDetector.blankSecret, "HmacSHA256"));
    byte[] expectedSig = mac.doFinal(expectedSigningInput.getBytes(UTF_8));
    String expectedSignatureB64 =
        Base64.getUrlEncoder().withoutPadding().encodeToString(expectedSig);
    assertThat(parts[2]).isEqualTo(expectedSignatureB64);
  }
}
