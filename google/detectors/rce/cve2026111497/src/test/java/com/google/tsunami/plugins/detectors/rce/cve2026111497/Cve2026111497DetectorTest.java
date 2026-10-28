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
package com.google.tsunami.plugins.detectors.rce.cve2026111497;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostname;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;
import static java.nio.charset.StandardCharsets.ISO_8859_1;

import com.google.common.collect.ImmutableList;
import com.google.inject.Guice;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.proto.CrawlResult;
import com.google.tsunami.proto.CrawlTarget;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.ServiceContext;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TransportProtocol;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import com.google.tsunami.proto.WebServiceContext;
import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import java.util.function.Supplier;
import javax.inject.Inject;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import okhttp3.mockwebserver.SocketPolicy;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link Cve2026111497Detector}. */
@RunWith(JUnit4.class)
public final class Cve2026111497DetectorTest {
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2026-01-01T00:00:00.00Z"));

  @Inject private Cve2026111497Detector detector;

  private MockWebServer mockWebServer;

  @Before
  public void setUp() throws IOException {
    mockWebServer = new MockWebServer();
    mockWebServer.start();

    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            new Cve2026111497DetectorBootstrapModule())
        .injectMembers(this);
  }

  @After
  public void tearDown() throws IOException {
    mockWebServer.shutdown();
  }

  private TargetInfo createTargetInfo() {
    return TargetInfo.newBuilder()
        .addNetworkEndpoints(forHostname(mockWebServer.getHostName()))
        .build();
  }

  private NetworkService createNetworkService() {
    return NetworkService.newBuilder()
        .setNetworkEndpoint(
            forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
        .setTransportProtocol(TransportProtocol.TCP)
        .setServiceName("http")
        .build();
  }

  private NetworkService createServiceWithCrawledUrls(String... urls) {
    WebServiceContext.Builder webContext = WebServiceContext.newBuilder();
    for (String url : urls) {
      webContext.addCrawlResults(
          CrawlResult.newBuilder()
              .setCrawlTarget(CrawlTarget.newBuilder().setUrl(url).setHttpMethod("POST")));
    }
    return createNetworkService().toBuilder()
        .setServiceContext(ServiceContext.newBuilder().setWebServiceContext(webContext))
        .build();
  }

  private void enqueueVulnerableCycle(
      Supplier<MockResponse> validResponse, Supplier<MockResponse> invalidResponse) {
    mockWebServer.enqueue(validResponse.get());
    mockWebServer.enqueue(invalidResponse.get());
    mockWebServer.enqueue(validResponse.get());
    mockWebServer.enqueue(validResponse.get());
    mockWebServer.enqueue(invalidResponse.get());
  }

  private static boolean isValidControl(RecordedRequest request) {
    return request.getBodySize() == Cve2026111497Detector.VALID_BROTLI_CONTROL.size()
        && Arrays.equals(
            request.getBody().clone().readByteArray(),
            Cve2026111497Detector.VALID_BROTLI_CONTROL.toByteArray());
  }

  private static boolean isProbe(RecordedRequest request) {
    return request.getBodySize() == Cve2026111497Detector.Holder.CVE_2026_111497_PROBE.size();
  }

  private DetectionReport buildExpectedDetectionReport(TargetInfo target, NetworkService service) {
    return DetectionReport.newBuilder()
        .setTargetInfo(target)
        .setNetworkService(service)
        .setDetectionTimestamp(Timestamps.fromMillis(fakeUtcClock.instant().toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder()
                        .setPublisher(Cve2026111497Detector.VULNERABILITY_REPORT_PUBLISHER)
                        .setValue(Cve2026111497Detector.VULNERABILITY_REPORT_ID))
                .addRelatedId(
                    VulnerabilityId.newBuilder()
                        .setPublisher("CVE")
                        .setValue(Cve2026111497Detector.VULNERABILITY_REPORT_ID))
                .setSeverity(Severity.CRITICAL)
                .setTitle(Cve2026111497Detector.VULNERABILITY_REPORT_TITLE)
                .setDescription(Cve2026111497Detector.VULN_DESCRIPTION)
                .setRecommendation(Cve2026111497Detector.RECOMMENDATION))
        .build();
  }

  @Test
  public void payloadInvariants_rawBytesDoNotContainContiguousCanaryAndLengthsMatch() {
    assertThat(Cve2026111497Detector.VALID_BROTLI_CONTROL.toStringUtf8())
        .doesNotContain(Cve2026111497Detector.DECOMPRESSED_CANARY);
    assertThat(Cve2026111497Detector.INVALID_BROTLI_CONTROL.toStringUtf8())
        .doesNotContain(Cve2026111497Detector.DECOMPRESSED_CANARY);
    assertThat(Cve2026111497Detector.PROBE_TAIL.toStringUtf8())
        .doesNotContain(Cve2026111497Detector.DECOMPRESSED_CANARY);
    assertThat(Cve2026111497Detector.INVALID_BROTLI_CONTROL.toStringUtf8())
        .startsWith("{tsunami_brotli_invalid_control_");
    assertThat(Cve2026111497Detector.INVALID_BROTLI_CONTROL.toStringUtf8()).endsWith("}");
    assertThat(Cve2026111497Detector.INVALID_BROTLI_CONTROL.toStringUtf8()).doesNotContain("\"");
    assertThat(Cve2026111497Detector.VALID_BROTLI_CONTROL.toStringUtf8()).startsWith("P");
    assertThat(Cve2026111497Detector.VALID_BROTLI_CONTROL.size()).isEqualTo(191);
    assertThat(Cve2026111497Detector.INVALID_BROTLI_CONTROL.size()).isEqualTo(191);
    byte[] probeTailUncompressedBlocks =
        Cve2026111497Detector.PROBE_TAIL.substring(39).toByteArray();
    assertThat(probeTailUncompressedBlocks)
        .isEqualTo(Cve2026111497Detector.VALID_BROTLI_CONTROL.substring(9).toByteArray());
    assertThat(Cve2026111497Detector.VALID_BROTLI_CONTROL.toString(ISO_8859_1))
        .matches("(?s)[\\x00-\\x7F]+");
    assertThat(Cve2026111497Detector.INVALID_BROTLI_CONTROL.toString(ISO_8859_1))
        .matches("(?s)[\\x00-\\x7F]+");
    assertThat(Cve2026111497Detector.PROBE_TAIL.substring(3).toString(ISO_8859_1))
        .matches("(?s)[\\x00-\\x7F]+");
    assertThat(Cve2026111497Detector.Holder.CVE_2026_111497_PROBE.size()).isEqualTo(23_068_910);
  }

  @Test
  public void detect_whenVulnerableServerAcceptsProbeWithStatusDifferential_reportsVulnerability()
      throws InterruptedException {
    enqueueVulnerableCycle(
        () -> new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("OK"),
        () ->
            new MockResponse()
                .setResponseCode(HttpStatus.BAD_REQUEST.code())
                .setBody("BadRequestError: decompression failed"));
    NetworkService service = createNetworkService();
    TargetInfo target = createTargetInfo();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(buildExpectedDetectionReport(target, service));
    assertThat(mockWebServer.getRequestCount()).isEqualTo(5);

    RecordedRequest req1 = mockWebServer.takeRequest();
    assertThat(req1.getHeader("Content-Encoding")).isEqualTo("br");
    assertThat(req1.getHeader("Content-Type")).startsWith("application/json");
    assertThat(req1.getBodySize()).isEqualTo(Cve2026111497Detector.VALID_BROTLI_CONTROL.size());

    RecordedRequest req2 = mockWebServer.takeRequest();
    assertThat(req2.getBodySize()).isEqualTo(Cve2026111497Detector.INVALID_BROTLI_CONTROL.size());

    RecordedRequest req3 = mockWebServer.takeRequest();
    assertThat(req3.getHeader("Content-Encoding")).isEqualTo("br");
    assertThat(req3.getBodySize())
        .isEqualTo(Cve2026111497Detector.Holder.CVE_2026_111497_PROBE.size());
  }

  @Test
  public void
      detect_whenVulnerableMiddlewareReturns404OnValidAnd400OnInvalid_reportsVulnerability() {
    // Express app.use(express.json()) on an unrouted POST / returns 404 after successful
    // decompression, but 400 Bad Request when Brotli decompression fails.
    enqueueVulnerableCycle(
        () ->
            new MockResponse()
                .setResponseCode(HttpStatus.NOT_FOUND.code())
                .setBody("Cannot POST /"),
        () ->
            new MockResponse()
                .setResponseCode(HttpStatus.BAD_REQUEST.code())
                .setBody("BadRequestError: decompression failed"));
    NetworkService service = createNetworkService();
    TargetInfo target = createTargetInfo();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(buildExpectedDetectionReport(target, service));
    assertThat(mockWebServer.getRequestCount()).isEqualTo(5);
  }

  @Test
  public void detect_whenVulnerableServerReflectsDecompressedCanary_reportsVulnerability() {
    String reflectedJson = "{\"echo\":\"" + Cve2026111497Detector.DECOMPRESSED_CANARY + "\"}";
    enqueueVulnerableCycle(
        () -> new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody(reflectedJson),
        () -> new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("{\"echo\":null}"));
    NetworkService service = createNetworkService();
    TargetInfo target = createTargetInfo();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(buildExpectedDetectionReport(target, service));
    assertThat(mockWebServer.getRequestCount()).isEqualTo(5);
  }

  @Test
  public void
      detect_whenApplianceFilterReturns401OnValidAnd400OnInvalid_reportsVulnerability() {
    // Envoy HTTP decompressor filter / Apache mod_brotli in front of an authenticated appliance
    // API returns 401 Unauthorized after successful Brotli decompression, and 400 Bad Request when
    // Brotli decompression fails.
    enqueueVulnerableCycle(
        () ->
            new MockResponse()
                .setResponseCode(HttpStatus.UNAUTHORIZED.code())
                .setBody("Unauthorized"),
        () ->
            new MockResponse()
                .setResponseCode(HttpStatus.BAD_REQUEST.code())
                .setBody("Bad Request"));
    NetworkService service = createNetworkService();
    TargetInfo target = createTargetInfo();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(buildExpectedDetectionReport(target, service));
    assertThat(mockWebServer.getRequestCount()).isEqualTo(5);
  }

  @Test
  public void detect_whenApplianceAclReturns403OnValidAnd422OnInvalid_reportsVulnerability() {
    enqueueVulnerableCycle(
        () -> new MockResponse().setResponseCode(HttpStatus.FORBIDDEN.code()).setBody("Forbidden"),
        () ->
            new MockResponse()
                .setResponseCode(HttpStatus.UNPROCESSABLE_ENTITY.code())
                .setBody("Unprocessable Entity"));
    NetworkService service = createNetworkService();
    TargetInfo target = createTargetInfo();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(buildExpectedDetectionReport(target, service));
    assertThat(mockWebServer.getRequestCount()).isEqualTo(5);
  }

  @Test
  public void detect_whenInputFilterReturns405OnValidAnd500OnInvalid_reportsVulnerability() {
    // Apache SetInputFilter BROTLI_COMPRESS on a GET-only resource returns 405 Method Not Allowed
    // when Brotli decompression succeeds, and 400/500 when Brotli decompression fails.
    enqueueVulnerableCycle(
        () -> new MockResponse().setResponseCode(HttpStatus.METHOD_NOT_ALLOWED.code()),
        () -> new MockResponse().setResponseCode(HttpStatus.INTERNAL_SERVER_ERROR.code()));
    NetworkService service = createNetworkService();
    TargetInfo target = createTargetInfo();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(buildExpectedDetectionReport(target, service));
    assertThat(mockWebServer.getRequestCount()).isEqualTo(5);
  }

  @Test
  public void
      detect_whenApplianceLoginRedirectReturns302OnValidAnd400OnInvalid_reportsVulnerability() {
    enqueueVulnerableCycle(
        () ->
            new MockResponse()
                .setResponseCode(HttpStatus.FOUND.code())
                .setHeader("Location", "/auth"),
        () -> new MockResponse().setResponseCode(HttpStatus.BAD_REQUEST.code()));
    NetworkService service = createNetworkService();
    TargetInfo target = createTargetInfo();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(buildExpectedDetectionReport(target, service));
    assertThat(mockWebServer.getRequestCount()).isEqualTo(5);
  }

  @Test
  public void
      detect_whenApplianceLoginRedirectReturns303OnValidAnd400OnInvalid_reportsVulnerability() {
    enqueueVulnerableCycle(
        () ->
            new MockResponse()
                .setResponseCode(HttpStatus.SEE_OTHER.code())
                .setHeader("Location", "/auth"),
        () -> new MockResponse().setResponseCode(HttpStatus.BAD_REQUEST.code()));
    NetworkService service = createNetworkService();
    TargetInfo target = createTargetInfo();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(buildExpectedDetectionReport(target, service));
    assertThat(mockWebServer.getRequestCount()).isEqualTo(5);
  }

  @Test
  public void
      detect_whenVulnerableGraphQlReturns400WithCanaryOnValidAnd400WithoutCanaryOnInvalid_reportsVulnerability() {
    // Strict GraphQL / Jackson / Go / Rust schema validators return 400 Bad Request on both valid
    // Brotli (schema/field error containing the decompressed canary) and invalid Brotli
    // (decompression error without the canary).
    String graphQlError =
        "{\"errors\":[{\"message\":\"Cannot query field '"
            + Cve2026111497Detector.DECOMPRESSED_CANARY
            + "' on type 'Query'.\"}]}";
    String decompError = "{\"errors\":[{\"message\":\"Invalid Brotli stream\"}]}";
    enqueueVulnerableCycle(
        () ->
            new MockResponse()
                .setResponseCode(HttpStatus.BAD_REQUEST.code())
                .setBody(graphQlError),
        () ->
            new MockResponse()
                .setResponseCode(HttpStatus.BAD_REQUEST.code())
                .setBody(decompError));
    NetworkService service = createNetworkService();
    TargetInfo target = createTargetInfo();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(buildExpectedDetectionReport(target, service));
    assertThat(mockWebServer.getRequestCount()).isEqualTo(5);
  }

  @Test
  public void
      detect_whenVulnerableFastApiReturns422WithCanaryOnValidAnd400OnInvalid_reportsVulnerability() {
    String pydanticError =
        "{\"detail\":[{\"type\":\"extra_forbidden\",\"loc\":[\"body\",\""
            + Cve2026111497Detector.DECOMPRESSED_CANARY
            + "\"]}]}";
    enqueueVulnerableCycle(
        () ->
            new MockResponse()
                .setResponseCode(HttpStatus.UNPROCESSABLE_ENTITY.code())
                .setBody(pydanticError),
        () ->
            new MockResponse()
                .setResponseCode(HttpStatus.BAD_REQUEST.code())
                .setBody("Invalid Brotli body"));
    NetworkService service = createNetworkService();
    TargetInfo target = createTargetInfo();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(buildExpectedDetectionReport(target, service));
    assertThat(mockWebServer.getRequestCount()).isEqualTo(5);
  }

  @Test
  public void
      detect_whenPatchedGraphQlReflectsCanaryOnControlButRejectsProbeWithoutCanary_reportsEmpty() {
    String graphQlError =
        "{\"errors\":[{\"message\":\"Cannot query field '"
            + Cve2026111497Detector.DECOMPRESSED_CANARY
            + "' on type 'Query'.\"}]}";
    String decompError = "{\"errors\":[{\"message\":\"BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH\"}]}";
    ProbeTrackingDispatcher dispatcher =
        new ProbeTrackingDispatcher(
            request -> {
              if (!request.getPath().equals("/graphql")) {
                return new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code());
              }
              return isValidControl(request)
                  ? new MockResponse()
                      .setResponseCode(HttpStatus.BAD_REQUEST.code())
                      .setBody(graphQlError)
                  : new MockResponse()
                      .setResponseCode(HttpStatus.BAD_REQUEST.code())
                      .setBody(decompError);
            });
    mockWebServer.setDispatcher(dispatcher);

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(dispatcher.probeCount()).isEqualTo(1);
  }

  @Test
  public void detect_whenBothControlsReflectCanaryString_abortsBeforeSending23MbProbe() {
    String staticBannerWithCanary = "Error trace: " + Cve2026111497Detector.DECOMPRESSED_CANARY;
    ProbeTrackingDispatcher dispatcher =
        new ProbeTrackingDispatcher(
            request ->
                new MockResponse()
                    .setResponseCode(HttpStatus.BAD_REQUEST.code())
                    .setBody(staticBannerWithCanary));
    mockWebServer.setDispatcher(dispatcher);

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(dispatcher.receivedProbe()).isFalse();
  }

  @Test
  public void detect_whenProbeReflectsCanaryWithMismatchedStatusCode_reportsEmpty() {
    String canaryError = "Field error: " + Cve2026111497Detector.DECOMPRESSED_CANARY;
    ProbeTrackingDispatcher dispatcher =
        new ProbeTrackingDispatcher(
            request -> {
              if (!request.getPath().equals("/graphql")) {
                return new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code());
              }
              if (isProbe(request)) {
                return new MockResponse()
                    .setResponseCode(HttpStatus.INTERNAL_SERVER_ERROR.code())
                    .setBody(canaryError);
              }
              return isValidControl(request)
                  ? new MockResponse()
                      .setResponseCode(HttpStatus.BAD_REQUEST.code())
                      .setBody(canaryError)
                  : new MockResponse()
                      .setResponseCode(HttpStatus.BAD_REQUEST.code())
                      .setBody("Invalid Brotli");
            });
    mockWebServer.setDispatcher(dispatcher);

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(dispatcher.probeCount()).isEqualTo(1);
  }

  @Test
  public void detect_whenCanaryReflectedPostProbeInvalidControlReturns503_reportsEmpty() {
    String canaryError = "Field error: " + Cve2026111497Detector.DECOMPRESSED_CANARY;
    AtomicInteger graphQlStep = new AtomicInteger();
    ProbeTrackingDispatcher dispatcher =
        new ProbeTrackingDispatcher(
            request -> {
              if (!request.getPath().equals("/graphql")) {
                return new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code());
              }
              int step = graphQlStep.incrementAndGet();
              if (step == 5) {
                return new MockResponse()
                    .setResponseCode(HttpStatus.SERVICE_UNAVAILABLE.code())
                    .setBody("Service Unavailable");
              }
              return isValidControl(request) || isProbe(request)
                  ? new MockResponse()
                      .setResponseCode(HttpStatus.BAD_REQUEST.code())
                      .setBody(canaryError)
                  : new MockResponse()
                      .setResponseCode(HttpStatus.BAD_REQUEST.code())
                      .setBody("Invalid Brotli");
            });
    mockWebServer.setDispatcher(dispatcher);

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(dispatcher.probeCount()).isEqualTo(1);
  }

  @Test
  public void detect_whenCanaryReflectedPostProbeValidControlOmitsCanary_reportsEmpty() {
    String canaryError = "Field error: " + Cve2026111497Detector.DECOMPRESSED_CANARY;
    AtomicInteger graphQlStep = new AtomicInteger();
    ProbeTrackingDispatcher dispatcher =
        new ProbeTrackingDispatcher(
            request -> {
              if (!request.getPath().equals("/graphql")) {
                return new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code());
              }
              int step = graphQlStep.incrementAndGet();
              if (step == 4) {
                return new MockResponse()
                    .setResponseCode(HttpStatus.BAD_REQUEST.code())
                    .setBody("Generic Bad Request");
              }
              return isValidControl(request) || isProbe(request)
                  ? new MockResponse()
                      .setResponseCode(HttpStatus.BAD_REQUEST.code())
                      .setBody(canaryError)
                  : new MockResponse()
                      .setResponseCode(HttpStatus.BAD_REQUEST.code())
                      .setBody("Invalid Brotli");
            });
    mockWebServer.setDispatcher(dispatcher);

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(dispatcher.probeCount()).isEqualTo(1);
  }

  @Test
  public void detect_whenServerDisconnectsDuringControlRequest_reportsEmpty() {
    ProbeTrackingDispatcher dispatcher =
        new ProbeTrackingDispatcher(
            request -> new MockResponse().setSocketPolicy(SocketPolicy.DISCONNECT_AT_START));
    mockWebServer.setDispatcher(dispatcher);

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(dispatcher.receivedProbe()).isFalse();
  }

  @Test
  public void
      detect_whenMultiPodServerAlternates200OkBodiesWithoutCanary_abortsBeforeSending23MbProbe() {
    // Multi-pod load-balanced services (e.g., GKE hello-app returning pod hostnames in 200 OK
    // responses while ignoring Content-Encoding: br) must abort after the two control requests and
    // never trigger a false positive or send the 23 MB probe.
    AtomicInteger requestIndex = new AtomicInteger();
    ProbeTrackingDispatcher dispatcher =
        new ProbeTrackingDispatcher(
            request -> {
              String podName =
                  requestIndex.getAndIncrement() % 2 == 0
                      ? "deployment-pod-a"
                      : "deployment-pod-b";
              return new MockResponse()
                  .setResponseCode(HttpStatus.OK.code())
                  .setBody("Hello, world!\nVersion: 2.0.0\nHostname: " + podName + "\n");
            });
    mockWebServer.setDispatcher(dispatcher);

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(dispatcher.receivedProbe()).isFalse();
  }

  @Test
  public void detect_whenPatchedServerRejectsProbeWith400_reportsEmpty() {
    ProbeTrackingDispatcher dispatcher =
        new ProbeTrackingDispatcher(
            request -> {
              if (!request.getPath().equals("/")) {
                return new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code());
              }
              if (isValidControl(request)) {
                return new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("OK");
              }
              return new MockResponse()
                  .setResponseCode(HttpStatus.BAD_REQUEST.code())
                  .setBody("BadRequestError: decompression failed");
            });
    mockWebServer.setDispatcher(dispatcher);

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(dispatcher.probeCount()).isEqualTo(1);
  }

  @Test
  public void detect_whenServerIgnoresContentEncodingBr_abortsBeforeSending23MbProbe() {
    ProbeTrackingDispatcher dispatcher =
        new ProbeTrackingDispatcher(
            request ->
                new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("Static Page"));
    mockWebServer.setDispatcher(dispatcher);

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(dispatcher.receivedProbe()).isFalse();
  }

  @Test
  public void detect_whenServerReturnsDynamicBodyWithNonce_abortsBeforeSending23MbProbe() {
    AtomicInteger counter = new AtomicInteger();
    ProbeTrackingDispatcher dispatcher =
        new ProbeTrackingDispatcher(
            request ->
                new MockResponse()
                    .setResponseCode(HttpStatus.OK.code())
                    .setBody("{\"requestId\":\"req-" + counter.incrementAndGet() + "\"}"));
    mockWebServer.setDispatcher(dispatcher);

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(dispatcher.receivedProbe()).isFalse();
  }

  @Test
  public void detect_whenRawEchoServerEchoesCompressedBytesWithoutDecompressing_reportsEmpty() {
    ProbeTrackingDispatcher dispatcher =
        new ProbeTrackingDispatcher(
            request ->
                new MockResponse()
                    .setResponseCode(HttpStatus.OK.code())
                    .setBody(request.getBody().clone()));
    mockWebServer.setDispatcher(dispatcher);

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(dispatcher.receivedProbe()).isFalse();
  }

  @Test
  public void detect_whenAuthWallReturns401ToBothControls_abortsBeforeSending23MbProbe() {
    ProbeTrackingDispatcher dispatcher =
        new ProbeTrackingDispatcher(
            request ->
                new MockResponse()
                    .setResponseCode(HttpStatus.UNAUTHORIZED.code())
                    .setBody("Unauthorized"));
    mockWebServer.setDispatcher(dispatcher);

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(dispatcher.receivedProbe()).isFalse();
  }

  @Test
  public void
      detect_whenServerReturnsNonDecompressionStatusPair401And403_abortsBeforeSending23MbProbe() {
    ProbeTrackingDispatcher dispatcher =
        new ProbeTrackingDispatcher(
            request ->
                new MockResponse()
                    .setResponseCode(
                        isValidControl(request)
                            ? HttpStatus.UNAUTHORIZED.code()
                            : HttpStatus.FORBIDDEN.code()));
    mockWebServer.setDispatcher(dispatcher);

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(dispatcher.receivedProbe()).isFalse();
  }

  @Test
  public void
      detect_whenServerReturns200OnValidAnd503UnavailableOnInvalid_abortsBeforeSending23MbProbe() {
    ProbeTrackingDispatcher dispatcher =
        new ProbeTrackingDispatcher(
            request ->
                new MockResponse()
                    .setResponseCode(
                        isValidControl(request)
                            ? HttpStatus.OK.code()
                            : HttpStatus.SERVICE_UNAVAILABLE.code()));
    mockWebServer.setDispatcher(dispatcher);

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(dispatcher.receivedProbe()).isFalse();
  }

  @Test
  public void detect_whenNonBrotliServerReturns422OnValidControl_abortsAtStep1() {
    // Non-Brotli FastAPI/Pydantic endpoints return 422 Unprocessable Entity when raw compressed
    // bytes fail json.loads(); 422 must never be treated as post-decompression status success.
    ProbeTrackingDispatcher dispatcher =
        new ProbeTrackingDispatcher(
            request ->
                new MockResponse()
                    .setResponseCode(HttpStatus.UNPROCESSABLE_ENTITY.code())
                    .setBody("{\"detail\":[{\"type\":\"json_invalid\"}]}"));
    mockWebServer.setDispatcher(dispatcher);

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(Collections.frequency(dispatcher.requestedPaths(), "/")).isEqualTo(1);
    assertThat(dispatcher.receivedProbe()).isFalse();
  }

  @Test
  public void detect_whenRootFailsButSecondCandidatePathVulnerable_reportsVulnerability() {
    ProbeTrackingDispatcher dispatcher =
        new ProbeTrackingDispatcher(
            request -> {
              if (!request.getPath().equals("/graphql")) {
                return new MockResponse().setResponseCode(HttpStatus.METHOD_NOT_ALLOWED.code());
              }
              return isValidControl(request) || isProbe(request)
                  ? new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("OK")
                  : new MockResponse()
                      .setResponseCode(HttpStatus.BAD_REQUEST.code())
                      .setBody("Error");
            });
    mockWebServer.setDispatcher(dispatcher);
    NetworkService service = createNetworkService();
    TargetInfo target = createTargetInfo();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(buildExpectedDetectionReport(target, service));
    assertThat(dispatcher.probeCount()).isEqualTo(1);
  }

  @Test
  public void detect_whenPostProbeVerificationFails_reportsEmpty() {
    // Root path ("/"): Steps 1-3 pass, but Step 4 invalid control returns 200 OK (inconsistent).
    AtomicInteger rootRequestCount = new AtomicInteger();
    ProbeTrackingDispatcher dispatcher =
        new ProbeTrackingDispatcher(
            request -> {
              if (!request.getPath().equals("/")) {
                return new MockResponse().setResponseCode(HttpStatus.METHOD_NOT_ALLOWED.code());
              }
              int stepRequest = rootRequestCount.incrementAndGet();
              if (stepRequest == 2) {
                return new MockResponse()
                    .setResponseCode(HttpStatus.BAD_REQUEST.code())
                    .setBody("Error");
              }
              return new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("OK");
            });
    mockWebServer.setDispatcher(dispatcher);

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(dispatcher.probeCount()).isEqualTo(1);
  }

  @Test
  public void detect_whenNonWebService_reportsEmpty() {
    NetworkService sshService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("ssh")
            .build();

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(sshService));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(mockWebServer.getRequestCount()).isEqualTo(0);
  }

  @Test
  public void
      detect_whenServerReturns302RedirectToBothControls_doesNotFollowRedirectAndReportsEmpty() {
    ProbeTrackingDispatcher dispatcher =
        new ProbeTrackingDispatcher(
            request ->
                new MockResponse()
                    .setResponseCode(HttpStatus.FOUND.code())
                    .setHeader("Location", "/login-target"));
    mockWebServer.setDispatcher(dispatcher);

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(dispatcher.requestedPaths()).doesNotContain("/login-target");
    assertThat(dispatcher.receivedProbe()).isFalse();
  }

  @Test
  public void
      detect_whenCrawledEndpointsIncludeMalformedAndOffOriginUrls_filtersAndReportsSameOriginVuln()
          throws InterruptedException {
    enqueueVulnerableCycle(
        () -> new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("OK"),
        () -> new MockResponse().setResponseCode(HttpStatus.BAD_REQUEST.code()).setBody("Error"));
    NetworkService service =
        createServiceWithCrawledUrls(
            "://malformed_uri",
            "http://external.example.com/ingest",
            mockWebServer.url("/v1/ingest?source=test#section").toString());
    TargetInfo target = createTargetInfo();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(buildExpectedDetectionReport(target, service));
    assertThat(mockWebServer.getRequestCount()).isEqualTo(5);
    assertThat(mockWebServer.takeRequest().getPath()).isEqualTo("/v1/ingest?source=test");
  }

  private static final class ProbeTrackingDispatcher extends Dispatcher {
    private final Function<RecordedRequest, MockResponse> handler;
    private final AtomicInteger probeCount = new AtomicInteger();
    private final List<String> requestedPaths = Collections.synchronizedList(new ArrayList<>());

    ProbeTrackingDispatcher(Function<RecordedRequest, MockResponse> handler) {
      this.handler = handler;
    }

    @Override
    public MockResponse dispatch(RecordedRequest request) {
      requestedPaths.add(request.getPath());
      if (isProbe(request)) {
        probeCount.incrementAndGet();
      }
      return handler.apply(request);
    }

    boolean receivedProbe() {
      return probeCount.get() > 0;
    }

    int probeCount() {
      return probeCount.get();
    }

    ImmutableList<String> requestedPaths() {
      return ImmutableList.copyOf(requestedPaths);
    }
  }
}
