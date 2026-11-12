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

import com.google.common.base.Splitter;
import com.google.common.collect.ImmutableList;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.inject.Guice;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.ServiceContext;
import com.google.tsunami.proto.Software;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TransportProtocol;
import com.google.tsunami.proto.WebServiceContext;
import java.io.IOException;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.inject.Inject;
import mockwebserver3.MockResponse;
import mockwebserver3.MockWebServer;
import mockwebserver3.QueueDispatcher;
import mockwebserver3.RecordedRequest;
import mockwebserver3.SocketEffect;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link Cve202682329VulnDetector}. */
@RunWith(JUnit4.class)
public final class Cve202682329VulnDetectorTest {

  private static final String TEST_SUBJECT_PLACEHOLDER = "tsunami@scanner";

  private static final byte[] expectedBlankSecret = {
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20
  };

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2026-09-03T00:00:00.00Z"));

  @Inject private Cve202682329VulnDetector detector;

  private MockWebServer mockWebServer;

  @Before
  public void setUp() {
    mockWebServer = new MockWebServer();
    mockWebServer.setDispatcher(
        new QueueDispatcher() {
          @Override
          public MockResponse dispatch(RecordedRequest request) throws InterruptedException {
            MockResponse queued = super.dispatch(request);
            if (!Objects.equals(request.getMethod(), "POST")
                || queued.getBody() == null
                || queued.getBody().getContentLength() != validJoinResponseBody().length()) {
              return queued;
            }
            String requestServiceId = extractServiceIdFromRequest(request);
            if (requestServiceId.isEmpty()) {
              return queued;
            }
            return queued
                .newBuilder()
                .body(
                    String.format(
                        "{\"token\":\"%s\"}", validJoinTokenForSubject(requestServiceId)))
                .build();
          }
        });
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

  private static String extractServiceIdFromRequest(RecordedRequest request) {
    List<String> parts = Splitter.on('.').splitToList(request.getBody().utf8());
    if (parts.size() != 3) {
      return "";
    }
    try {
      String payloadJson = new String(Base64.getUrlDecoder().decode(parts.get(1)), UTF_8);
      JsonObject obj = JsonParser.parseString(payloadJson).getAsJsonObject();
      return obj.has("service_id") ? obj.get("service_id").getAsString() : "";
    } catch (RuntimeException e) {
      return "";
    }
  }

  private static String b64Url(String raw) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(raw.getBytes(UTF_8));
  }

  private static String rawJwt(String headerJson, String claimsJson, String signature) {
    return b64Url(headerJson) + "." + b64Url(claimsJson) + "." + b64Url(signature);
  }

  private static String mintAdminJwt(String alg, String subject, String scope) {
    return rawJwt(
        String.format("{\"alg\":\"%s\",\"typ\":\"JWT\"}", alg),
        String.format("{\"sub\":\"%s\",\"scp\":\"%s\",\"aud\":\"*@*\"}", subject, scope),
        "mock-rs256-signature");
  }

  private static String validJoinTokenForSubject(String subject) {
    return mintAdminJwt("RS256", subject, "applied-permissions/admin");
  }

  private static String validJoinResponseBody() {
    return String.format("{\"token\":\"%s\"}", validJoinTokenForSubject(TEST_SUBJECT_PLACEHOLDER));
  }

  @Test
  public void detect_whenTargetVulnerable_returnsDetectionReport()
      throws IOException, InterruptedException {
    mockWebServer.start();
    // 1. Negative control probe is rejected with 400 Bad Request
    mockWebServer.enqueue(
        new MockResponse.Builder()
            .code(400)
            .setHeader("Content-Type", "application/json")
            .body("{\"errors\":[{\"status\":400,\"message\":\"Failed to parse token\"}]}")
            .build());
    // 2. Positive probe succeeds with 200 OK and signed admin JWT
    mockWebServer.enqueue(
        new MockResponse.Builder()
            .code(200)
            .setHeader("Content-Type", "application/json")
            .body(validJoinResponseBody())
            .build());
    // 3. Minted admin JWT is immediately self-revoked via DELETE /access/api/v1/tokens/me
    mockWebServer.enqueue(new MockResponse.Builder().code(204).build());

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
                .setDetectionTimestamp(Timestamps.fromMillis(fakeUtcClock.instant().toEpochMilli()))
                .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
                .setVulnerability(detector.getAdvisories().get(0))
                .build());

    assertThat(mockWebServer.getRequestCount()).isEqualTo(3);

    RecordedRequest negativeRequest = mockWebServer.takeRequest();
    assertThat(negativeRequest.getMethod()).isEqualTo("POST");
    assertThat(negativeRequest.getTarget()).isEqualTo("/access/api/v1/registry/join");
    List<String> negParts = Splitter.on('.').splitToList(negativeRequest.getBody().utf8());
    String negDecodedPayload = new String(Base64.getUrlDecoder().decode(negParts.get(1)), UTF_8);
    assertThat(negDecodedPayload).contains(Cve202682329VulnDetector.INVALID_KID);

    RecordedRequest positiveRequest = mockWebServer.takeRequest();
    assertThat(positiveRequest.getMethod()).isEqualTo("POST");
    assertThat(positiveRequest.getTarget()).isEqualTo("/access/api/v1/registry/join");
    assertThat(positiveRequest.getHeaders().get("Content-Type")).isEqualTo("text/plain");
    assertThat(positiveRequest.getHeaders().get("Accept")).isEqualTo("application/json");
    String positiveBody = positiveRequest.getBody().utf8();
    List<String> parts = Splitter.on('.').splitToList(positiveBody);
    assertThat(parts).hasSize(3);
    String decodedPayload = new String(Base64.getUrlDecoder().decode(parts.get(1)), UTF_8);
    String sentServiceId = extractServiceIdFromRequest(positiveRequest);
    assertThat(sentServiceId).matches("jfrt@01tsunami-[0-9a-f-]{36}");
    long expectedIssuedAt = fakeUtcClock.instant().getEpochSecond();
    assertThat(decodedPayload)
        .isEqualTo(
            String.format(
                "{\"iat\":%d,\"service_id\":\"%s\",\"kid\":\"%s\","
                    + "\"skip_node_registration\":true}",
                expectedIssuedAt, sentServiceId, Cve202682329VulnDetector.BLANK_KID));

    RecordedRequest revokeRequest = mockWebServer.takeRequest();
    assertThat(revokeRequest.getMethod()).isEqualTo("DELETE");
    assertThat(revokeRequest.getTarget()).isEqualTo("/access/api/v1/tokens/me");
    assertThat(revokeRequest.getHeaders().get("Authorization"))
        .isEqualTo("Bearer " + validJoinTokenForSubject(sentServiceId));
  }

  @Test
  public void detect_whenArtifactorySubpathVulnerable_returnsDetectionReport()
      throws IOException, InterruptedException {
    mockWebServer.start();
    mockWebServer.enqueue(new MockResponse.Builder().code(404).build());
    mockWebServer.enqueue(new MockResponse.Builder().code(404).build());
    mockWebServer.enqueue(
        new MockResponse.Builder()
            .code(200)
            .setHeader("Content-Type", "application/json")
            .body("{\"errors\":[{\"status\":400,\"message\":\"Invalid join token\"}]}")
            .build());
    mockWebServer.enqueue(
        new MockResponse.Builder()
            .code(201)
            .setHeader("Content-Type", "application/json")
            .body(validJoinResponseBody())
            .build());
    mockWebServer.enqueue(new MockResponse.Builder().code(204).build());

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

    assertThat(detectionReports.getDetectionReportsList()).hasSize(1);
    assertThat(mockWebServer.getRequestCount()).isEqualTo(5);
    RecordedRequest req1 = mockWebServer.takeRequest();
    assertThat(req1.getTarget()).isEqualTo("/access/api/v1/registry/join");
    RecordedRequest req2 = mockWebServer.takeRequest();
    assertThat(req2.getTarget()).isEqualTo("/access/api/v1/registry/join");
    RecordedRequest req3 = mockWebServer.takeRequest();
    assertThat(req3.getTarget()).isEqualTo("/artifactory/access/api/v1/registry/join");
    RecordedRequest req4 = mockWebServer.takeRequest();
    assertThat(req4.getTarget()).isEqualTo("/artifactory/access/api/v1/registry/join");
    RecordedRequest revokeReq = mockWebServer.takeRequest();
    assertThat(revokeReq.getMethod()).isEqualTo("DELETE");
    assertThat(revokeReq.getTarget()).isEqualTo("/artifactory/access/api/v1/tokens/me");
  }

  @Test
  public void detect_whenWebServiceHasCustomApplicationRoot_probesOriginRootFirst()
      throws IOException, InterruptedException {
    mockWebServer.start();
    mockWebServer.enqueue(
        new MockResponse.Builder()
            .code(200)
            .setHeader("Content-Type", "application/json")
            .body("{\"errors\":[{\"status\":400,\"message\":\"Invalid join token\"}]}")
            .build());
    mockWebServer.enqueue(
        new MockResponse.Builder()
            .code(201)
            .setHeader("Content-Type", "application/json")
            .body(validJoinResponseBody())
            .build());
    mockWebServer.enqueue(new MockResponse.Builder().code(204).build());

    NetworkService service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("http")
            .setServiceContext(
                ServiceContext.newBuilder()
                    .setWebServiceContext(WebServiceContext.newBuilder().setApplicationRoot("/ui")))
            .build();
    TargetInfo targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockWebServer.getHostName()))
            .build();

    DetectionReportList detectionReports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(detectionReports.getDetectionReportsList()).hasSize(1);
    RecordedRequest firstReq = mockWebServer.takeRequest();
    assertThat(firstReq.getTarget()).isEqualTo("/access/api/v1/registry/join");
  }

  @Test
  public void detect_whenBlackiceIcecapServiceVulnerable_returnsDetectionReport()
      throws IOException {
    mockWebServer.start();
    mockWebServer.enqueue(
        new MockResponse.Builder()
            .code(200)
            .setHeader("Content-Type", "application/json")
            .body("{\"errors\":[{\"status\":400,\"message\":\"Invalid join token\"}]}")
            .build());
    mockWebServer.enqueue(
        new MockResponse.Builder()
            .code(201)
            .setHeader("Content-Type", "application/json")
            .body(validJoinResponseBody())
            .build());
    mockWebServer.enqueue(new MockResponse.Builder().code(204).build());

    NetworkService service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("blackice-icecap")
            .build();
    TargetInfo targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockWebServer.getHostName()))
            .build();

    DetectionReportList detectionReports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(detectionReports.getDetectionReportsList()).hasSize(1);
  }

  @Test
  public void detect_whenSameHostRedirectPreservesJoinEndpoint_rePostsAndDetects()
      throws IOException, InterruptedException {
    mockWebServer.start();
    String redirectLocation =
        String.format(
            "http://%s:%d/v2-proxy/access/api/v1/registry/join",
            mockWebServer.getHostName(), mockWebServer.getPort());
    NetworkService service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("http")
            .build();
    TargetInfo targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockWebServer.getHostName()))
            .build();

    for (int redirectCode : ImmutableList.of(301, 302, 307, 308)) {
      mockWebServer.enqueue(
          new MockResponse.Builder()
              .code(redirectCode)
              .setHeader("Location", redirectLocation)
              .build());
      mockWebServer.enqueue(
          new MockResponse.Builder().code(400).body(validJoinResponseBody()).build());
      mockWebServer.enqueue(
          new MockResponse.Builder()
              .code(redirectCode)
              .setHeader("Location", redirectLocation)
              .build());
      mockWebServer.enqueue(
          new MockResponse.Builder()
              .code(201)
              .setHeader("Content-Type", "application/json")
              .body(validJoinResponseBody())
              .build());
      mockWebServer.enqueue(new MockResponse.Builder().code(204).build());

      DetectionReportList detectionReports =
          detector.detect(targetInfo, ImmutableList.of(service));

      assertThat(detectionReports.getDetectionReportsList()).hasSize(1);
      RecordedRequest negInitialReq = mockWebServer.takeRequest();
      assertThat(negInitialReq.getTarget()).isEqualTo("/access/api/v1/registry/join");
      RecordedRequest negRedirectedReq = mockWebServer.takeRequest();
      assertThat(negRedirectedReq.getTarget()).isEqualTo("/v2-proxy/access/api/v1/registry/join");
      RecordedRequest initialReq = mockWebServer.takeRequest();
      assertThat(initialReq.getMethod()).isEqualTo("POST");
      assertThat(initialReq.getTarget()).isEqualTo("/access/api/v1/registry/join");
      RecordedRequest redirectedReq = mockWebServer.takeRequest();
      assertThat(redirectedReq.getMethod()).isEqualTo("POST");
      assertThat(redirectedReq.getTarget()).isEqualTo("/v2-proxy/access/api/v1/registry/join");
      assertThat(redirectedReq.getBody().utf8()).isEqualTo(initialReq.getBody().utf8());
      RecordedRequest revokeReq = mockWebServer.takeRequest();
      assertThat(revokeReq.getMethod()).isEqualTo("DELETE");
      assertThat(revokeReq.getTarget()).isEqualTo("/access/api/v1/tokens/me");
    }
  }

  @Test
  public void detect_whenRedirectMissingOrDisallowedOrNonRedirectHasLocation_doesNotRePost()
      throws IOException {
    mockWebServer.start();
    String redirectLocation =
        String.format(
            "http://%s:%d/v2-proxy/access/api/v1/registry/join",
            mockWebServer.getHostName(), mockWebServer.getPort());
    // Path 1: 302 without Location header; Path 2: 302 to non-join login page
    mockWebServer.enqueue(new MockResponse.Builder().code(302).build());
    mockWebServer.enqueue(new MockResponse.Builder().code(302).build());
    mockWebServer.enqueue(
        new MockResponse.Builder().code(302).setHeader("Location", "/ui/login").build());
    mockWebServer.enqueue(
        new MockResponse.Builder().code(302).setHeader("Location", "/ui/login").build());

    NetworkService service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("http")
            .build();
    TargetInfo targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockWebServer.getHostName()))
            .build();

    assertThat(detector.detect(targetInfo, ImmutableList.of(service)).getDetectionReportsList())
        .isEmpty();
    assertThat(mockWebServer.getRequestCount()).isEqualTo(4);

    // Non-redirect 400 with Location header and valid token body must not redirect or report vuln
    mockWebServer.enqueue(
        new MockResponse.Builder()
            .code(400)
            .setHeader("Location", redirectLocation)
            .body(validJoinResponseBody())
            .build());
    mockWebServer.enqueue(
        new MockResponse.Builder()
            .code(200)
            .setHeader("Content-Type", "application/json")
            .body("{\"token\":\"not-a-jwt\"}")
            .build());
    // Extra fallback responses so surviving mutants fail assertions rapidly without hanging
    mockWebServer.enqueue(new MockResponse.Builder().code(400).build());
    mockWebServer.enqueue(new MockResponse.Builder().code(400).build());

    assertThat(detector.detect(targetInfo, ImmutableList.of(service)).getDetectionReportsList())
        .isEmpty();
    assertThat(mockWebServer.getRequestCount()).isEqualTo(8);
  }

  @Test
  public void detect_whenTargetAcceptsNegativeControlKey_returnsNoVulnerability()
      throws IOException {
    mockWebServer.start();
    // Accept-all server returns 201 with admin JWT on negative control probes, short-circuiting
    // before any positive probe is sent (1 request per candidate path = 2 requests total).
    for (int i = 0; i < 6; i++) {
      mockWebServer.enqueue(
          new MockResponse.Builder()
              .code(201)
              .setHeader("Content-Type", "application/json")
              .body(validJoinResponseBody())
              .build());
    }

    NetworkService service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("http")
            .build();
    TargetInfo targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockWebServer.getHostName()))
            .build();

    DetectionReportList detectionReports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
    assertThat(mockWebServer.getRequestCount()).isEqualTo(2);
  }

  @Test
  public void detect_whenConnectionFailsOnFirstPath_shortCircuitsSameSchemeBaseUrls()
      throws IOException {
    mockWebServer.start();
    // First request drops socket after receiving request; subsequent enqueued 400+201 would cause a
    // false detection if the detector failed to break out of paths or skip same-scheme base URLs.
    mockWebServer.enqueue(
        new MockResponse.Builder().onResponseStart(new SocketEffect.CloseSocket()).build());
    mockWebServer.enqueue(new MockResponse.Builder().code(400).build());
    mockWebServer.enqueue(
        new MockResponse.Builder()
            .code(201)
            .setHeader("Content-Type", "application/json")
            .body(validJoinResponseBody())
            .build());
    mockWebServer.enqueue(new MockResponse.Builder().code(204).build());

    NetworkService service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("http")
            .setServiceContext(
                ServiceContext.newBuilder()
                    .setWebServiceContext(WebServiceContext.newBuilder().setApplicationRoot("/ui")))
            .build();
    TargetInfo targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockWebServer.getHostName()))
            .build();

    DetectionReportList detectionReports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
    assertThat(mockWebServer.getRequestCount()).isEqualTo(1);
  }

  @Test
  public void detect_whenSslUnknownMultiplexerFailsTlsHandshake_fallsBackToHttpAndDetects()
      throws IOException {
    mockWebServer.start();
    // 1. HTTPS attempt closes immediately during TLS ClientHello (simulating JFrog Router cmux SNI
    // alert on port 8082 / NodePorts).
    mockWebServer.enqueue(
        new MockResponse.Builder().onRequestStart(new SocketEffect.CloseSocket()).build());
    // 2. Detector falls back to plain HTTP on the same port and verifies CVE-2026-82329.
    mockWebServer.enqueue(new MockResponse.Builder().code(400).build());
    mockWebServer.enqueue(
        new MockResponse.Builder()
            .code(201)
            .setHeader("Content-Type", "application/json")
            .body(validJoinResponseBody())
            .build());
    mockWebServer.enqueue(new MockResponse.Builder().code(204).build());

    NetworkService service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("ssl/unknown")
            .addSupportedSslVersions("TLSV1.3")
            .build();
    TargetInfo targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockWebServer.getHostName()))
            .build();

    DetectionReportList detectionReports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(detectionReports.getDetectionReportsList()).hasSize(1);
  }

  @Test
  public void detect_whenRevokeTokenThrowsIoException_stillReturnsDetectionReport()
      throws IOException {
    mockWebServer.start();
    mockWebServer.enqueue(new MockResponse.Builder().code(400).build());
    mockWebServer.enqueue(
        new MockResponse.Builder()
            .code(200)
            .setHeader("Content-Type", "application/json")
            .body(validJoinResponseBody())
            .build());
    // Revocation DELETE drops socket, which must be ignored as best-effort cleanup
    mockWebServer.enqueue(
        new MockResponse.Builder().onResponseStart(new SocketEffect.CloseSocket()).build());

    NetworkService service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("http")
            .build();
    TargetInfo targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockWebServer.getHostName()))
            .build();

    DetectionReportList detectionReports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(detectionReports.getDetectionReportsList()).hasSize(1);
  }

  @Test
  public void detect_whenTargetPatched_returnsNoVulnerability() throws IOException {
    mockWebServer.start();
    for (int i = 0; i < 4; i++) {
      mockWebServer.enqueue(
          new MockResponse.Builder()
              .code(400)
              .body("{\"errors\":[{\"status\":400,\"message\":\"Bad request\"}]}")
              .build());
    }

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
  public void isCandidateService_handlesWebAndArtifactoryPortsAndRejectsOthers() {
    NetworkService radanHttp =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forHostnameAndPort("localhost", 9000))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("radan-http")
            .build();
    NetworkService unspecifiedProtoHttp =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forHostnameAndPort("localhost", 9000))
            .setTransportProtocol(TransportProtocol.TRANSPORT_PROTOCOL_UNSPECIFIED)
            .setServiceName("http")
            .build();
    for (String directName :
        ImmutableList.of(
            "blackice-alerts",
            "blackice-icecap",
            "https-alt",
            "ssl/blackice-alerts",
            "ssl/blackice-icecap",
            "ssl/https-alt",
            "  SSL/UNKNOWN  ")) {
      NetworkService directService =
          NetworkService.newBuilder()
              .setNetworkEndpoint(forHostnameAndPort("localhost", 18082))
              .setTransportProtocol(TransportProtocol.TCP)
              .setServiceName(directName)
              .build();
      assertThat(Cve202682329VulnDetector.isCandidateService(directService)).isTrue();
    }
    for (int artifactoryPort : ImmutableList.of(8081, 8082, 8443)) {
      NetworkService portMatched =
          NetworkService.newBuilder()
              .setNetworkEndpoint(forHostnameAndPort("localhost", artifactoryPort))
              .setTransportProtocol(TransportProtocol.TCP)
              .setServiceName("tcpwrapped")
              .build();
      assertThat(Cve202682329VulnDetector.isCandidateService(portMatched)).isTrue();
    }
    NetworkService tcpwrapped22 =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forHostnameAndPort("localhost", 22))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("tcpwrapped")
            .build();
    NetworkService unknownHighPort =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forHostnameAndPort("localhost", 18082))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("unknown")
            .build();
    NetworkService udpHttp =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forHostnameAndPort("localhost", 8082))
            .setTransportProtocol(TransportProtocol.UDP)
            .setServiceName("http")
            .build();

    assertThat(Cve202682329VulnDetector.isCandidateService(radanHttp)).isTrue();
    assertThat(Cve202682329VulnDetector.isCandidateService(unspecifiedProtoHttp)).isTrue();
    assertThat(Cve202682329VulnDetector.isCandidateService(tcpwrapped22)).isFalse();
    assertThat(Cve202682329VulnDetector.isCandidateService(unknownHighPort)).isFalse();
    assertThat(Cve202682329VulnDetector.isCandidateService(udpHttp)).isFalse();
  }

  @Test
  public void buildCandidateBaseUrls_handlesNonWebTlsAndCustomAppRoot() {
    NetworkService tlsMultiplexed =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forHostnameAndPort("example.com", 18082))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("ssl/unknown")
            .addSupportedSslVersions("TLSv1.3")
            .build();
    assertThat(Cve202682329VulnDetector.buildCandidateBaseUrls(tlsMultiplexed))
        .containsExactly("https://example.com:18082/", "http://example.com:18082/")
        .inOrder();

    NetworkService plainBlackice =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forHostnameAndPort("example.com", 8082))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("blackice-alerts")
            .build();
    assertThat(Cve202682329VulnDetector.buildCandidateBaseUrls(plainBlackice))
        .containsExactly("http://example.com:8082/");

    NetworkService webWithCustomRoot =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forHostnameAndPort("example.com", 8082))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("http")
            .setServiceContext(
                ServiceContext.newBuilder()
                    .setWebServiceContext(
                        WebServiceContext.newBuilder().setApplicationRoot("/artifactory")))
            .build();
    assertThat(Cve202682329VulnDetector.buildCandidateBaseUrls(webWithCustomRoot))
        .containsExactly("http://example.com:8082/", "http://example.com:8082/artifactory/")
        .inOrder();
  }

  @Test
  public void resolveSameHostRedirectUrl_validatesHostSchemeAndJoinPath() {
    String base = "http://artifactory.local:8082/access/api/v1/registry/join";
    assertThat(
            Cve202682329VulnDetector.resolveSameHostRedirectUrl(
                base, "https://artifactory.local:8443/access/api/v1/registry/join"))
        .hasValue("https://artifactory.local:8443/access/api/v1/registry/join");
    assertThat(
            Cve202682329VulnDetector.resolveSameHostRedirectUrl(
                base, "/artifactory/access/api/v1/registry/join"))
        .hasValue("http://artifactory.local:8082/artifactory/access/api/v1/registry/join");

    // Reject self-redirect, login redirect, external/missing host, opaque URI, and non-HTTP scheme
    assertThat(Cve202682329VulnDetector.resolveSameHostRedirectUrl(base, base)).isEmpty();
    assertThat(Cve202682329VulnDetector.resolveSameHostRedirectUrl(base, "/ui/login")).isEmpty();
    assertThat(
            Cve202682329VulnDetector.resolveSameHostRedirectUrl(
                base, "https://evil.example.com/access/api/v1/registry/join"))
        .isEmpty();
    assertThat(
            Cve202682329VulnDetector.resolveSameHostRedirectUrl(
                base, "http:///access/api/v1/registry/join"))
        .isEmpty();
    assertThat(Cve202682329VulnDetector.resolveSameHostRedirectUrl("mailto:user@host", "/join"))
        .isEmpty();
    assertThat(
            Cve202682329VulnDetector.resolveSameHostRedirectUrl(
                base, "ftp://artifactory.local/access/api/v1/registry/join"))
        .isEmpty();
    assertThat(Cve202682329VulnDetector.resolveSameHostRedirectUrl(base, "http://[::1")).isEmpty();
  }

  @Test
  public void isSuccessfulJoinResponse_validatesJwtFormatAndAdminClaims() {
    String sub = TEST_SUBJECT_PLACEHOLDER;
    String validAdminJwt = mintAdminJwt("RS256", sub, "admin");
    String validExactPermJwt = mintAdminJwt("RS256", sub, "applied-permissions/admin");
    String validScopedAdminJwt = mintAdminJwt("RS256", sub, "reader applied-permissions/admin:all");
    String validFederationAdminJwt = mintAdminJwt("RS256", sub, "system:federation:admin");
    assertThat(validAdminJwt).startsWith(Cve202682329VulnDetector.RS256_HEADER_PREFIX);

    assertThat(
            Cve202682329VulnDetector.isSuccessfulJoinResponse(
                String.format("{\"token\":\"%s\"}", validAdminJwt), "sent-jwt", sub))
        .isTrue();
    assertThat(
            Cve202682329VulnDetector.isSuccessfulJoinResponse(
                String.format("{\"token\":\"%s\"}", validExactPermJwt), "sent-jwt", sub))
        .isTrue();
    assertThat(
            Cve202682329VulnDetector.isSuccessfulJoinResponse(
                String.format("{\"token\":\"%s\"}", validScopedAdminJwt), "sent-jwt", sub))
        .isTrue();
    assertThat(
            Cve202682329VulnDetector.isSuccessfulJoinResponse(
                String.format("{\"token\":\"%s\"}", validFederationAdminJwt), "sent-jwt", sub))
        .isTrue();

    // Reject malformed JSON, non-object JSON, missing/non-primitive/empty/echoed token
    assertThat(Cve202682329VulnDetector.isSuccessfulJoinResponse("{invalid", "sent", sub))
        .isFalse();
    assertThat(Cve202682329VulnDetector.isSuccessfulJoinResponse("not-json", "sent", sub))
        .isFalse();
    assertThat(Cve202682329VulnDetector.isSuccessfulJoinResponse("[]", "sent", sub)).isFalse();
    assertThat(Cve202682329VulnDetector.isSuccessfulJoinResponse("{}", "sent", sub)).isFalse();
    assertThat(Cve202682329VulnDetector.isSuccessfulJoinResponse("{\"token\":{}}", "sent", sub))
        .isFalse();
    assertThat(Cve202682329VulnDetector.isSuccessfulJoinResponse("{\"token\":\"\"}", "sent", sub))
        .isFalse();
    assertThat(
            Cve202682329VulnDetector.isSuccessfulJoinResponse(
                String.format("{\"token\":\"%s\"}", validAdminJwt), validAdminJwt, sub))
        .isFalse();

    // Reject malformed JWT structure (2-part, 4-part, empty signature), invalid Base64/JSON,
    // non-object header/claims, non-RS256 alg, and bad claims
    String validHeaderB64 = b64Url("{\"alg\":\"RS256\"}");
    String validClaimsB64 = b64Url(String.format("{\"sub\":\"%s\",\"scp\":\"admin\"}", sub));
    assertThat(
            Cve202682329VulnDetector.isSuccessfulJoinResponse(
                String.format("{\"token\":\"%s.%s\"}", validHeaderB64, validClaimsB64),
                "sent",
                sub))
        .isFalse();
    assertThat(
            Cve202682329VulnDetector.isSuccessfulJoinResponse(
                String.format("{\"token\":\"%s.extra\"}", validAdminJwt), "sent", sub))
        .isFalse();
    assertThat(
            Cve202682329VulnDetector.isSuccessfulJoinResponse(
                String.format("{\"token\":\"%s.%s.\"}", validHeaderB64, validClaimsB64),
                "sent",
                sub))
        .isFalse();
    assertThat(
            Cve202682329VulnDetector.isSuccessfulJoinResponse(
                "{\"token\":\"!!!.b.c\"}", "sent", sub))
        .isFalse();
    assertThat(
            Cve202682329VulnDetector.isSuccessfulJoinResponse(
                String.format("{\"token\":\"%s\"}", rawJwt("{bad", "{}", "sig")), "sent", sub))
        .isFalse();
    assertThat(
            Cve202682329VulnDetector.isSuccessfulJoinResponse(
                String.format(
                    "{\"token\":\"%s\"}",
                    rawJwt("[]", String.format("{\"sub\":\"%s\",\"scp\":\"admin\"}", sub), "sig")),
                "sent",
                sub))
        .isFalse();
    assertThat(
            Cve202682329VulnDetector.isSuccessfulJoinResponse(
                String.format("{\"token\":\"%s\"}", rawJwt("{\"alg\":\"RS256\"}", "[]", "sig")),
                "sent",
                sub))
        .isFalse();
    assertThat(
            Cve202682329VulnDetector.isSuccessfulJoinResponse(
                String.format(
                    "{\"token\":\"%s\"}",
                    rawJwt("{}", String.format("{\"sub\":\"%s\",\"scp\":\"admin\"}", sub), "sig")),
                "sent",
                sub))
        .isFalse();
    assertThat(
            Cve202682329VulnDetector.isSuccessfulJoinResponse(
                String.format(
                    "{\"token\":\"%s\"}",
                    rawJwt(
                        "{\"alg\":{}}",
                        String.format("{\"sub\":\"%s\",\"scp\":\"admin\"}", sub),
                        "sig")),
                "sent",
                sub))
        .isFalse();
    assertThat(
            Cve202682329VulnDetector.isSuccessfulJoinResponse(
                String.format("{\"token\":\"%s\"}", mintAdminJwt("   ", sub, "admin")),
                "sent",
                sub))
        .isFalse();
    assertThat(
            Cve202682329VulnDetector.isSuccessfulJoinResponse(
                String.format("{\"token\":\"%s\"}", mintAdminJwt("none", sub, "admin")),
                "sent",
                sub))
        .isFalse();
    assertThat(
            Cve202682329VulnDetector.isSuccessfulJoinResponse(
                String.format("{\"token\":\"%s\"}", mintAdminJwt("HS256", sub, "admin")),
                "sent",
                sub))
        .isFalse();
    assertThat(
            Cve202682329VulnDetector.isSuccessfulJoinResponse(
                String.format(
                    "{\"token\":\"%s\"}", rawJwt("{\"alg\":\"RS256\"}", "{\"scp\":\"admin\"}", "s")),
                "sent",
                sub))
        .isFalse();
    assertThat(
            Cve202682329VulnDetector.isSuccessfulJoinResponse(
                String.format(
                    "{\"token\":\"%s\"}",
                    rawJwt("{\"alg\":\"RS256\"}", "{\"sub\":{},\"scp\":\"admin\"}", "s")),
                "sent",
                sub))
        .isFalse();
    assertThat(
            Cve202682329VulnDetector.isSuccessfulJoinResponse(
                String.format(
                    "{\"token\":\"%s\"}", mintAdminJwt("RS256", "other@scanner", "admin")),
                "sent",
                sub))
        .isFalse();
    assertThat(
            Cve202682329VulnDetector.isSuccessfulJoinResponse(
                String.format(
                    "{\"token\":\"%s\"}",
                    rawJwt("{\"alg\":\"RS256\"}", String.format("{\"sub\":\"%s\"}", sub), "s")),
                "sent",
                sub))
        .isFalse();
    assertThat(
            Cve202682329VulnDetector.isSuccessfulJoinResponse(
                String.format(
                    "{\"token\":\"%s\"}",
                    rawJwt(
                        "{\"alg\":\"RS256\"}",
                        String.format("{\"sub\":\"%s\",\"scp\":[]}", sub),
                        "s")),
                "sent",
                sub))
        .isFalse();
    assertThat(
            Cve202682329VulnDetector.isSuccessfulJoinResponse(
                String.format(
                    "{\"token\":\"%s\"}",
                    mintAdminJwt("RS256", sub, "applied-permissions/admin-fake")),
                "sent",
                sub))
        .isFalse();
    assertThat(
            Cve202682329VulnDetector.isSuccessfulJoinResponse(
                String.format(
                    "{\"token\":\"%s\"}", mintAdminJwt("RS256", sub, "applied-permissions/user")),
                "sent",
                sub))
        .isFalse();
  }

  @Test
  public void forgeJoinJwt_generatesValidTokenStructure() throws Exception {
    long epochSeconds = 1700000000L;
    String serviceId = "jfrt@01";
    String jwt = Cve202682329VulnDetector.forgeJoinJwt(epochSeconds, serviceId);
    assertThat(jwt).isNotNull();

    List<String> parts = Splitter.on('.').splitToList(jwt);
    assertThat(parts).hasSize(3);

    // Verify header
    assertThat(parts.get(0)).isEqualTo("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");
    String decodedHeader = new String(Base64.getUrlDecoder().decode(parts.get(0)), UTF_8);
    assertThat(decodedHeader).isEqualTo("{\"alg\":\"HS256\",\"typ\":\"JWT\"}");

    // Verify payload
    String expectedPayload =
        String.format(
            "{\"iat\":%d,\"service_id\":\"%s\",\"kid\":\"%s\",\"skip_node_registration\":true}",
            epochSeconds, serviceId, Cve202682329VulnDetector.BLANK_KID);
    String expectedPayloadB64 =
        Base64.getUrlEncoder().withoutPadding().encodeToString(expectedPayload.getBytes(UTF_8));
    assertThat(parts.get(1)).isEqualTo(expectedPayloadB64);
    String decodedPayload = new String(Base64.getUrlDecoder().decode(parts.get(1)), UTF_8);
    assertThat(decodedPayload).isEqualTo(expectedPayload);

    // Verify signature
    String expectedSigningInput = parts.get(0) + "." + expectedPayloadB64;
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(expectedBlankSecret, "HmacSHA256"));
    byte[] expectedSig = mac.doFinal(expectedSigningInput.getBytes(UTF_8));
    String expectedSignatureB64 =
        Base64.getUrlEncoder().withoutPadding().encodeToString(expectedSig);
    assertThat(parts.get(2)).isEqualTo(expectedSignatureB64);
  }
}
