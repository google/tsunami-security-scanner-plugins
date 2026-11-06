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
import com.google.tsunami.plugins.detectors.rce.cve2026111497.Cve2026111497Detector.ControlPairOrder;
import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.CrawlResult;
import com.google.tsunami.proto.CrawlTarget;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.ServiceContext;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TextData;
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
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
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

  private void enqueueVulnerableCanaryCycle(
      Supplier<MockResponse> validResponse, Supplier<MockResponse> invalidResponse) {
    mockWebServer.enqueue(validResponse.get());
    mockWebServer.enqueue(invalidResponse.get());
    mockWebServer.enqueue(validResponse.get());
    mockWebServer.enqueue(validResponse.get());
    mockWebServer.enqueue(invalidResponse.get());
    mockWebServer.enqueue(invalidResponse.get());
  }

  private void enqueueVulnerableStatusCycle(
      Supplier<MockResponse> validResponse, Supplier<MockResponse> invalidResponse) {
    enqueueVulnerableStatusCycle(validResponse, invalidResponse, invalidResponse, invalidResponse);
  }

  private void enqueueVulnerableStatusCycle(
      Supplier<MockResponse> validResponse,
      Supplier<MockResponse> invalidResponse,
      Supplier<MockResponse> unencodedValidResponse,
      Supplier<MockResponse> unencodedInvalidResponse) {
    enqueueControlPair(ControlPairOrder.VALID_FIRST, validResponse, invalidResponse);
    for (ControlPairOrder pairOrder : Cve2026111497Detector.PRE_PROBE_STATUS_PAIR_POLARITIES) {
      enqueueControlPair(pairOrder, validResponse, invalidResponse);
    }
    mockWebServer.enqueue(validResponse.get());
    for (ControlPairOrder pairOrder : Cve2026111497Detector.POST_PROBE_STATUS_PAIR_POLARITIES) {
      enqueueControlPair(pairOrder, validResponse, invalidResponse);
    }
    mockWebServer.enqueue(unencodedValidResponse.get());
    mockWebServer.enqueue(unencodedInvalidResponse.get());
  }

  private void enqueueControlPair(
      ControlPairOrder pairOrder,
      Supplier<MockResponse> validResponse,
      Supplier<MockResponse> invalidResponse) {
    if (pairOrder == ControlPairOrder.VALID_FIRST) {
      mockWebServer.enqueue(validResponse.get());
      mockWebServer.enqueue(invalidResponse.get());
    } else {
      mockWebServer.enqueue(invalidResponse.get());
      mockWebServer.enqueue(validResponse.get());
    }
  }

  private void assertRecordedBrotliRequests(int count) throws InterruptedException {
    for (int i = 0; i < count; i++) {
      assertThat(mockWebServer.takeRequest().getHeader("Content-Encoding")).isEqualTo("br");
    }
  }

  private static void assertRecordedBrotliControl(RecordedRequest request, byte[] expectedBody) {
    assertThat(request.getHeader("Content-Encoding")).isEqualTo("br");
    assertThat(request.getHeader("Content-Type")).startsWith("application/json");
    assertThat(request.getHeader("Accept"))
        .isEqualTo("application/json, text/event-stream, text/plain, */*");
    assertThat(request.getBody().readByteArray()).isEqualTo(expectedBody);
  }

  private static void assertRecordedUnencodedControl(RecordedRequest request, byte[] expectedBody) {
    assertThat(request.getHeader("Content-Encoding")).isNull();
    assertThat(request.getHeader("Content-Type")).startsWith("application/json");
    assertThat(request.getHeader("Accept"))
        .isEqualTo("application/json, text/event-stream, text/plain, */*");
    assertThat(request.getBody().readByteArray()).isEqualTo(expectedBody);
  }

  private static boolean hasValidControlBody(RecordedRequest request) {
    return request.getBodySize() == Cve2026111497Detector.VALID_BROTLI_CONTROL.size()
        && Arrays.equals(
            request.getBody().clone().readByteArray(),
            Cve2026111497Detector.VALID_BROTLI_CONTROL.toByteArray());
  }

  private static boolean isValidControl(RecordedRequest request) {
    return Objects.equals(request.getHeader("Content-Encoding"), "br")
        && hasValidControlBody(request);
  }

  private static boolean isProbe(RecordedRequest request) {
    return Objects.equals(request.getHeader("Content-Encoding"), "br")
        && request.getBodySize() == Cve2026111497Detector.Holder.CVE_2026_111497_PROBE.size();
  }

  private DetectionReport buildExpectedDetectionReport(
      TargetInfo target, NetworkService service, String expectedEvidenceText) {
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
                .setRecommendation(Cve2026111497Detector.RECOMMENDATION)
                .addAdditionalDetails(
                    AdditionalDetail.newBuilder()
                        .setDescription(Cve2026111497Detector.DETECTION_EVIDENCE_DESCRIPTION)
                        .setTextData(TextData.newBuilder().setText(expectedEvidenceText))))
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
        .startsWith("Vtsunami_brotli_invalid_control_");
    assertThat(Cve2026111497Detector.INVALID_BROTLI_CONTROL.toStringUtf8()).endsWith("_");
    assertThat(Cve2026111497Detector.INVALID_BROTLI_CONTROL.toStringUtf8()).doesNotContain("\"");
    assertThat(Cve2026111497Detector.INVALID_BROTLI_CONTROL.toStringUtf8()).doesNotContain("{");
    assertThat(Cve2026111497Detector.INVALID_BROTLI_CONTROL.toStringUtf8()).doesNotContain("}");
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
  public void statusPairPolarities_matchAperiodicPreAndPostProbeSchedule() {
    assertThat(Cve2026111497Detector.PRE_PROBE_STATUS_PAIR_POLARITIES)
        .containsExactly(ControlPairOrder.INVALID_FIRST, ControlPairOrder.VALID_FIRST)
        .inOrder();
    assertThat(Cve2026111497Detector.POST_PROBE_STATUS_PAIR_POLARITIES)
        .containsExactly(
            ControlPairOrder.INVALID_FIRST,
            ControlPairOrder.VALID_FIRST,
            ControlPairOrder.INVALID_FIRST,
            ControlPairOrder.INVALID_FIRST,
            ControlPairOrder.VALID_FIRST)
        .inOrder();
  }

  @Test
  public void detect_whenVulnerableServerAcceptsProbeWithStatusDifferential_reportsVulnerability()
      throws InterruptedException {
    enqueueVulnerableStatusCycle(
        () -> new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("OK"),
        () ->
            new MockResponse()
                .setResponseCode(HttpStatus.BAD_REQUEST.code())
                .setBody("BadRequestError: decompression failed"));
    NetworkService service = createNetworkService();
    TargetInfo target = createTargetInfo();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                "Vulnerable endpoint: "
                    + mockWebServer.url("/")
                    + " (signal=status_differential, valid_br=200, invalid_br=400, probe_br=200,"
                    + " unencoded_valid=400, unencoded_invalid=400)"));
    assertThat(mockWebServer.getRequestCount()).isEqualTo(19);

    byte[] validControlBytes = Cve2026111497Detector.VALID_BROTLI_CONTROL.toByteArray();
    byte[] invalidControlBytes = Cve2026111497Detector.INVALID_BROTLI_CONTROL.toByteArray();

    // Steps 1-2 initial pair: (valid, invalid)
    assertRecordedBrotliControl(mockWebServer.takeRequest(), validControlBytes);
    assertRecordedBrotliControl(mockWebServer.takeRequest(), invalidControlBytes);
    // Step 2 pre-probe polarities [false, true]: (invalid, valid), (valid, invalid)
    assertRecordedBrotliControl(mockWebServer.takeRequest(), invalidControlBytes);
    assertRecordedBrotliControl(mockWebServer.takeRequest(), validControlBytes);
    assertRecordedBrotliControl(mockWebServer.takeRequest(), validControlBytes);
    assertRecordedBrotliControl(mockWebServer.takeRequest(), invalidControlBytes);

    // Step 3 probe
    RecordedRequest probeReq = mockWebServer.takeRequest();
    assertThat(probeReq.getHeader("Content-Encoding")).isEqualTo("br");
    assertThat(probeReq.getHeader("Content-Type")).startsWith("application/json");
    assertThat(probeReq.getBodySize())
        .isEqualTo(Cve2026111497Detector.Holder.CVE_2026_111497_PROBE.size());

    // Step 4 post-probe polarities [false, true, false, false, true]
    assertRecordedBrotliControl(mockWebServer.takeRequest(), invalidControlBytes);
    assertRecordedBrotliControl(mockWebServer.takeRequest(), validControlBytes);
    assertRecordedBrotliControl(mockWebServer.takeRequest(), validControlBytes);
    assertRecordedBrotliControl(mockWebServer.takeRequest(), invalidControlBytes);
    assertRecordedBrotliControl(mockWebServer.takeRequest(), invalidControlBytes);
    assertRecordedBrotliControl(mockWebServer.takeRequest(), validControlBytes);
    assertRecordedBrotliControl(mockWebServer.takeRequest(), invalidControlBytes);
    assertRecordedBrotliControl(mockWebServer.takeRequest(), validControlBytes);
    assertRecordedBrotliControl(mockWebServer.takeRequest(), validControlBytes);
    assertRecordedBrotliControl(mockWebServer.takeRequest(), invalidControlBytes);

    // Step 5 dual unencoded baseline: (valid unencoded, invalid unencoded)
    assertRecordedUnencodedControl(mockWebServer.takeRequest(), validControlBytes);
    assertRecordedUnencodedControl(mockWebServer.takeRequest(), invalidControlBytes);
  }

  @Test
  public void
      detect_whenVulnerableMiddlewareReturns404OnValidAnd400OnInvalid_reportsVulnerability() {
    // Express app.use(express.json()) on an unrouted POST / returns 404 after successful
    // decompression, but 400 Bad Request when Brotli decompression fails.
    enqueueVulnerableStatusCycle(
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
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                "Vulnerable endpoint: "
                    + mockWebServer.url("/")
                    + " (signal=status_differential, valid_br=404, invalid_br=400, probe_br=404,"
                    + " unencoded_valid=400, unencoded_invalid=400)"));
    assertThat(mockWebServer.getRequestCount()).isEqualTo(19);
  }

  @Test
  public void detect_whenVulnerableServerReflectsDecompressedCanary_reportsVulnerability() {
    String reflectedJson = "{\"echo\":\"" + Cve2026111497Detector.DECOMPRESSED_CANARY + "\"}";
    enqueueVulnerableCanaryCycle(
        () -> new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody(reflectedJson),
        () -> new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("{\"echo\":null}"));
    NetworkService service = createNetworkService();
    TargetInfo target = createTargetInfo();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                "Vulnerable endpoint: "
                    + mockWebServer.url("/")
                    + " (signal=canary_reflection, valid_br=200, invalid_br=200, probe_br=200,"
                    + " unencoded_valid=200)"));
    assertThat(mockWebServer.getRequestCount()).isEqualTo(6);
  }

  @Test
  public void detect_whenApplianceFilterReturns401OnValidAnd400OnInvalid_reportsVulnerability() {
    // Envoy HTTP decompressor filter / Apache mod_brotli in front of an authenticated appliance
    // API returns 401 Unauthorized after successful Brotli decompression, and 400 Bad Request when
    // Brotli decompression fails.
    enqueueVulnerableStatusCycle(
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
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                "Vulnerable endpoint: "
                    + mockWebServer.url("/")
                    + " (signal=status_differential, valid_br=401, invalid_br=400, probe_br=401,"
                    + " unencoded_valid=400, unencoded_invalid=400)"));
    assertThat(mockWebServer.getRequestCount()).isEqualTo(19);
  }

  @Test
  public void detect_whenApplianceAclReturns403OnValidAnd422OnInvalid_reportsVulnerability() {
    enqueueVulnerableStatusCycle(
        () -> new MockResponse().setResponseCode(HttpStatus.FORBIDDEN.code()).setBody("Forbidden"),
        () ->
            new MockResponse()
                .setResponseCode(HttpStatus.UNPROCESSABLE_ENTITY.code())
                .setBody("Unprocessable Entity"));
    NetworkService service = createNetworkService();
    TargetInfo target = createTargetInfo();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                "Vulnerable endpoint: "
                    + mockWebServer.url("/")
                    + " (signal=status_differential, valid_br=403, invalid_br=422, probe_br=403,"
                    + " unencoded_valid=422, unencoded_invalid=422)"));
    assertThat(mockWebServer.getRequestCount()).isEqualTo(19);
  }

  @Test
  public void detect_whenInputFilterReturns405OnValidAnd500OnInvalid_reportsVulnerability() {
    // Apache SetInputFilter BROTLI_COMPRESS on a GET-only resource returns 405 Method Not Allowed
    // when Brotli decompression succeeds, and 400/500 when Brotli decompression fails.
    enqueueVulnerableStatusCycle(
        () -> new MockResponse().setResponseCode(HttpStatus.METHOD_NOT_ALLOWED.code()),
        () -> new MockResponse().setResponseCode(HttpStatus.INTERNAL_SERVER_ERROR.code()));
    NetworkService service = createNetworkService();
    TargetInfo target = createTargetInfo();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                "Vulnerable endpoint: "
                    + mockWebServer.url("/")
                    + " (signal=status_differential, valid_br=405, invalid_br=500, probe_br=405,"
                    + " unencoded_valid=500, unencoded_invalid=500)"));
    assertThat(mockWebServer.getRequestCount()).isEqualTo(19);
  }

  @Test
  public void
      detect_whenApplianceLoginRedirectReturns302OnValidAnd400OnInvalid_reportsVulnerability() {
    enqueueVulnerableStatusCycle(
        () ->
            new MockResponse()
                .setResponseCode(HttpStatus.FOUND.code())
                .setHeader("Location", "/auth"),
        () -> new MockResponse().setResponseCode(HttpStatus.BAD_REQUEST.code()));
    NetworkService service = createNetworkService();
    TargetInfo target = createTargetInfo();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                "Vulnerable endpoint: "
                    + mockWebServer.url("/")
                    + " (signal=status_differential, valid_br=302, invalid_br=400, probe_br=302,"
                    + " unencoded_valid=400, unencoded_invalid=400)"));
    assertThat(mockWebServer.getRequestCount()).isEqualTo(19);
  }

  @Test
  public void
      detect_whenApplianceLoginRedirectReturns303OnValidAnd400OnInvalid_reportsVulnerability() {
    enqueueVulnerableStatusCycle(
        () ->
            new MockResponse()
                .setResponseCode(HttpStatus.SEE_OTHER.code())
                .setHeader("Location", "/auth"),
        () -> new MockResponse().setResponseCode(HttpStatus.BAD_REQUEST.code()));
    NetworkService service = createNetworkService();
    TargetInfo target = createTargetInfo();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                "Vulnerable endpoint: "
                    + mockWebServer.url("/")
                    + " (signal=status_differential, valid_br=303, invalid_br=400, probe_br=303,"
                    + " unencoded_valid=400, unencoded_invalid=400)"));
    assertThat(mockWebServer.getRequestCount()).isEqualTo(19);
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
    enqueueVulnerableCanaryCycle(
        () ->
            new MockResponse().setResponseCode(HttpStatus.BAD_REQUEST.code()).setBody(graphQlError),
        () ->
            new MockResponse().setResponseCode(HttpStatus.BAD_REQUEST.code()).setBody(decompError));
    NetworkService service = createNetworkService();
    TargetInfo target = createTargetInfo();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                "Vulnerable endpoint: "
                    + mockWebServer.url("/")
                    + " (signal=canary_reflection, valid_br=400, invalid_br=400, probe_br=400,"
                    + " unencoded_valid=400)"));
    assertThat(mockWebServer.getRequestCount()).isEqualTo(6);
  }

  @Test
  public void
      detect_whenVulnerableFastApiReturns422WithCanaryOnValidAnd400OnInvalid_reportsVulnerability() {
    String pydanticError =
        "{\"detail\":[{\"type\":\"extra_forbidden\",\"loc\":[\"body\",\""
            + Cve2026111497Detector.DECOMPRESSED_CANARY
            + "\"]}]}";
    enqueueVulnerableCanaryCycle(
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
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                "Vulnerable endpoint: "
                    + mockWebServer.url("/")
                    + " (signal=canary_reflection, valid_br=422, invalid_br=400, probe_br=422,"
                    + " unencoded_valid=400)"));
    assertThat(mockWebServer.getRequestCount()).isEqualTo(6);
  }

  @Test
  public void
      detect_whenPatchedGraphQlReflectsCanaryOnControlButRejectsProbeWithoutCanary_reportsEmpty() {
    String graphQlError =
        "{\"errors\":[{\"message\":\"Cannot query field '"
            + Cve2026111497Detector.DECOMPRESSED_CANARY
            + "' on type 'Query'.\"}]}";
    String decompError =
        "{\"errors\":[{\"message\":\"BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH\"}]}";
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
            request -> new MockResponse().setSocketPolicy(SocketPolicy.DISCONNECT_AFTER_REQUEST));
    mockWebServer.setDispatcher(dispatcher);

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(dispatcher.receivedProbe()).isFalse();
    assertThat(dispatcher.requestedPaths())
        .hasSize(Cve2026111497Detector.MAX_CONSECUTIVE_STEP1_IO_ERRORS);
  }

  @Test
  public void
      detect_whenIntermittentStep1IoErrorsResetByHttpResponse_continuesProbingUntilVulnerablePath() {
    ProbeTrackingDispatcher dispatcher =
        new ProbeTrackingDispatcher(
            request -> {
              String path = request.getPath();
              if (path.equals("/")
                  || path.equals("/graphql")
                  || path.equals("/api/v1")
                  || path.equals("/api/graphql")) {
                return new MockResponse().setSocketPolicy(SocketPolicy.DISCONNECT_AFTER_REQUEST);
              }
              if (!path.equals("/rpc")) {
                return new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code());
              }
              return isValidControl(request) || isProbe(request)
                  ? new MockResponse().setResponseCode(HttpStatus.UNAUTHORIZED.code())
                  : new MockResponse().setResponseCode(HttpStatus.BAD_REQUEST.code());
            });
    mockWebServer.setDispatcher(dispatcher);
    NetworkService service = createNetworkService();
    TargetInfo target = createTargetInfo();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                "Vulnerable endpoint: "
                    + mockWebServer.url("/rpc")
                    + " (signal=status_differential, valid_br=401, invalid_br=400, probe_br=401,"
                    + " unencoded_valid=400, unencoded_invalid=400)"));
    assertThat(dispatcher.probeCount()).isEqualTo(1);
  }

  @Test
  public void
      detect_whenPatchedGlobalBrotliFilterAcceptsControlsOnAllPaths_stopsAfterSingleRootProbe() {
    ProbeTrackingDispatcher dispatcher =
        new ProbeTrackingDispatcher(
            request ->
                isValidControl(request)
                    ? new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code())
                    : new MockResponse().setResponseCode(HttpStatus.BAD_REQUEST.code()));
    mockWebServer.setDispatcher(dispatcher);

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(dispatcher.probeCount()).isEqualTo(1);
    assertThat(dispatcher.requestedPaths()).containsExactly("/", "/", "/", "/", "/", "/", "/");
  }

  @Test
  public void
      detect_whenMultipleRouteSpecificPatchedEndpointsRejectStep3Probe_capsProbesAtMaxPerService() {
    ProbeTrackingDispatcher dispatcher =
        new ProbeTrackingDispatcher(
            request -> {
              if (request.getPath().equals("/")) {
                return new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code());
              }
              return isValidControl(request)
                  ? new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("OK")
                  : new MockResponse().setResponseCode(HttpStatus.BAD_REQUEST.code());
            });
    mockWebServer.setDispatcher(dispatcher);

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(dispatcher.probeCount()).isEqualTo(Cve2026111497Detector.MAX_PROBES_PER_SERVICE);
    assertThat(dispatcher.requestedPaths()).doesNotContain("/api/v1");
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
                  requestIndex.getAndIncrement() % 2 == 0 ? "deployment-pod-a" : "deployment-pod-b";
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
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                "Vulnerable endpoint: "
                    + mockWebServer.url("/graphql")
                    + " (signal=status_differential, valid_br=200, invalid_br=400, probe_br=200,"
                    + " unencoded_valid=400, unencoded_invalid=400)"));
    assertThat(dispatcher.probeCount()).isEqualTo(1);
    assertThat(Collections.frequency(dispatcher.requestedPaths(), "/graphql")).isEqualTo(19);
  }

  @Test
  public void detect_whenPostProbeVerificationFails_reportsEmpty() {
    // Root path ("/"): Steps 1-3 pass, but Step 4's first post-probe invalid control returns 200 OK
    // instead of 400 Bad Request.
    AtomicBoolean probeSeen = new AtomicBoolean();
    ProbeTrackingDispatcher dispatcher =
        new ProbeTrackingDispatcher(
            request -> {
              if (!request.getPath().equals("/")) {
                return new MockResponse().setResponseCode(HttpStatus.METHOD_NOT_ALLOWED.code());
              }
              if (isProbe(request)) {
                probeSeen.set(true);
                return new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("OK");
              }
              if (probeSeen.get()) {
                return new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("OK");
              }
              return isValidControl(request)
                  ? new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("OK")
                  : new MockResponse()
                      .setResponseCode(HttpStatus.BAD_REQUEST.code())
                      .setBody("Error");
            });
    mockWebServer.setDispatcher(dispatcher);

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(dispatcher.probeCount()).isEqualTo(1);
    assertThat(Collections.frequency(dispatcher.requestedPaths(), "/")).isEqualTo(8);
  }

  @Test
  public void detect_whenCanaryReflectedOnUnencodedControl_reportsEmpty() {
    String canaryError = "Field error: " + Cve2026111497Detector.DECOMPRESSED_CANARY;
    ProbeTrackingDispatcher dispatcher =
        new ProbeTrackingDispatcher(
            request -> {
              if (!request.getPath().equals("/graphql")) {
                return new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code());
              }
              boolean isRawValidPayload =
                  request.getBodySize() == Cve2026111497Detector.VALID_BROTLI_CONTROL.size()
                      && Arrays.equals(
                          request.getBody().clone().readByteArray(),
                          Cve2026111497Detector.VALID_BROTLI_CONTROL.toByteArray());
              return isRawValidPayload || isProbe(request)
                  ? new MockResponse()
                      .setResponseCode(HttpStatus.BAD_REQUEST.code())
                      .setBody(canaryError)
                  : new MockResponse()
                      .setResponseCode(HttpStatus.BAD_REQUEST.code())
                      .setBody("Invalid payload");
            });
    mockWebServer.setDispatcher(dispatcher);

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(dispatcher.probeCount()).isEqualTo(1);
  }

  @Test
  public void
      detect_whenStep5UnencodedControlReturns415UnsupportedMediaType_reportsVulnerability() {
    ProbeTrackingDispatcher dispatcher =
        new ProbeTrackingDispatcher(
            request -> {
              if (!request.getPath().equals("/")) {
                return new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code());
              }
              if (request.getHeader("Content-Encoding") == null) {
                return new MockResponse()
                    .setResponseCode(HttpStatus.UNSUPPORTED_MEDIA_TYPE.code())
                    .setBody("Content-Encoding: br required");
              }
              return isValidControl(request) || isProbe(request)
                  ? new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("OK")
                  : new MockResponse()
                      .setResponseCode(HttpStatus.BAD_REQUEST.code())
                      .setBody("Bad Brotli");
            });
    mockWebServer.setDispatcher(dispatcher);
    NetworkService service = createNetworkService();
    TargetInfo target = createTargetInfo();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                "Vulnerable endpoint: "
                    + mockWebServer.url("/")
                    + " (signal=status_differential, valid_br=200, invalid_br=400, probe_br=200,"
                    + " unencoded_valid=415, unencoded_invalid=415)"));
    assertThat(mockWebServer.getRequestCount()).isEqualTo(19);
  }

  @Test
  public void
      detect_whenFilterBypassesUnencodedControlsWithMatchingStatus_reportsVulnerabilityWithBothUnencodedStatuses()
          throws InterruptedException {
    Supplier<MockResponse> unauthorized =
        () ->
            new MockResponse()
                .setResponseCode(HttpStatus.UNAUTHORIZED.code())
                .setBody("Unauthorized");
    Supplier<MockResponse> badBrotli =
        () ->
            new MockResponse().setResponseCode(HttpStatus.BAD_REQUEST.code()).setBody("Bad Brotli");
    enqueueVulnerableStatusCycle(unauthorized, badBrotli, unauthorized, unauthorized);
    NetworkService service = createNetworkService();
    TargetInfo target = createTargetInfo();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                "Vulnerable endpoint: "
                    + mockWebServer.url("/")
                    + " (signal=status_differential, valid_br=401, invalid_br=400, probe_br=401,"
                    + " unencoded_valid=401, unencoded_invalid=401)"));
    assertThat(mockWebServer.getRequestCount()).isEqualTo(19);
    assertRecordedBrotliRequests(17);
    assertRecordedUnencodedControl(
        mockWebServer.takeRequest(), Cve2026111497Detector.VALID_BROTLI_CONTROL.toByteArray());
    assertRecordedUnencodedControl(
        mockWebServer.takeRequest(), Cve2026111497Detector.INVALID_BROTLI_CONTROL.toByteArray());
  }

  @Test
  public void detect_whenServerDiscriminatesRawPayloadsWithoutContentEncodingBr_reportsEmpty() {
    ProbeTrackingDispatcher dispatcher =
        new ProbeTrackingDispatcher(
            request -> {
              if (!request.getPath().equals("/")) {
                return new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code());
              }
              boolean isRawValidOrProbe =
                  (request.getBodySize() == Cve2026111497Detector.VALID_BROTLI_CONTROL.size()
                          && Arrays.equals(
                              request.getBody().clone().readByteArray(),
                              Cve2026111497Detector.VALID_BROTLI_CONTROL.toByteArray()))
                      || request.getBodySize()
                          == Cve2026111497Detector.Holder.CVE_2026_111497_PROBE.size();
              return isRawValidOrProbe
                  ? new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("OK")
                  : new MockResponse()
                      .setResponseCode(HttpStatus.BAD_REQUEST.code())
                      .setBody("WAF blocked payload");
            });
    mockWebServer.setDispatcher(dispatcher);

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(dispatcher.probeCount()).isEqualTo(1);
    assertThat(Collections.frequency(dispatcher.requestedPaths(), "/")).isEqualTo(19);
  }

  @Test
  public void
      detect_whenStatusDifferentialStep5UnencodedValidReturnsNonRejectionStatus_reportsEmpty() {
    ProbeTrackingDispatcher dispatcher =
        new ProbeTrackingDispatcher(
            request -> {
              if (!request.getPath().equals("/")) {
                return new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code());
              }
              if (request.getHeader("Content-Encoding") == null) {
                return new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code());
              }
              return isValidControl(request) || isProbe(request)
                  ? new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("OK")
                  : new MockResponse().setResponseCode(HttpStatus.BAD_REQUEST.code());
            });
    mockWebServer.setDispatcher(dispatcher);

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(dispatcher.probeCount()).isEqualTo(1);
    assertThat(Collections.frequency(dispatcher.requestedPaths(), "/")).isEqualTo(18);
  }

  @Test
  public void detect_whenStep5UnencodedValidReturnsUnspecifiedStatus_reportsEmpty() {
    String canaryError = "Field error: " + Cve2026111497Detector.DECOMPRESSED_CANARY;
    ProbeTrackingDispatcher dispatcher =
        new ProbeTrackingDispatcher(
            request -> {
              if (!request.getPath().equals("/graphql")) {
                return new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code());
              }
              if (request.getHeader("Content-Encoding") == null) {
                return new MockResponse().setResponseCode(599).setBody("Unknown proxy status");
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
  public void detect_whenStep5UnencodedValidRequestDisconnects_reportsEmpty() {
    ProbeTrackingDispatcher dispatcher =
        new ProbeTrackingDispatcher(
            request -> {
              if (!request.getPath().equals("/")) {
                return new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code());
              }
              if (request.getHeader("Content-Encoding") == null) {
                return new MockResponse().setSocketPolicy(SocketPolicy.DISCONNECT_AFTER_REQUEST);
              }
              return isValidControl(request) || isProbe(request)
                  ? new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("OK")
                  : new MockResponse().setResponseCode(HttpStatus.BAD_REQUEST.code());
            });
    mockWebServer.setDispatcher(dispatcher);

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(dispatcher.probeCount()).isEqualTo(1);
  }

  @Test
  public void detect_whenStep5UnencodedInvalidRequestDisconnects_reportsEmpty() {
    ProbeTrackingDispatcher dispatcher =
        new ProbeTrackingDispatcher(
            request -> {
              if (!request.getPath().equals("/")) {
                return new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code());
              }
              if (request.getHeader("Content-Encoding") == null) {
                return hasValidControlBody(request)
                    ? new MockResponse().setResponseCode(HttpStatus.UNAUTHORIZED.code())
                    : new MockResponse().setSocketPolicy(SocketPolicy.DISCONNECT_AFTER_REQUEST);
              }
              return isValidControl(request) || isProbe(request)
                  ? new MockResponse().setResponseCode(HttpStatus.UNAUTHORIZED.code())
                  : new MockResponse().setResponseCode(HttpStatus.BAD_REQUEST.code());
            });
    mockWebServer.setDispatcher(dispatcher);

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(dispatcher.probeCount()).isEqualTo(1);
  }

  @Test
  public void detect_whenVulnerableServerIncludesServerHeader_recordsSanitizedServerInEvidence() {
    enqueueVulnerableStatusCycle(
        () ->
            new MockResponse()
                .setResponseCode(HttpStatus.OK.code())
                .setHeader("Server", "Apache/2.4.58 (Ubuntu)")
                .setBody("OK"),
        () -> new MockResponse().setResponseCode(HttpStatus.BAD_REQUEST.code()).setBody("Error"));
    NetworkService service = createNetworkService();
    TargetInfo target = createTargetInfo();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                "Vulnerable endpoint: "
                    + mockWebServer.url("/")
                    + " (signal=status_differential, valid_br=200, invalid_br=400, probe_br=200,"
                    + " unencoded_valid=400, unencoded_invalid=400, server=Apache/2.4.58"
                    + " (Ubuntu))"));
  }

  @Test
  public void
      detect_whenServerHeaderContainsControlCharsAndExceedsMaxLength_sanitizesAndTruncatesInEvidence() {
    String rawServerHeader =
        "  envoy/1.30.0\t\t\t(custom-build-identifier-0123456789-abcdefghijklmnopqrstuvwxyz)  ";
    String expectedSanitizedServer =
        "envoy/1.30.0   (custom-build-identifier-0123456789-abcdefghij...";
    enqueueVulnerableStatusCycle(
        () ->
            new MockResponse()
                .setResponseCode(HttpStatus.OK.code())
                .setHeader("Server", rawServerHeader)
                .setBody("OK"),
        () -> new MockResponse().setResponseCode(HttpStatus.BAD_REQUEST.code()).setBody("Error"));
    NetworkService service = createNetworkService();
    TargetInfo target = createTargetInfo();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                "Vulnerable endpoint: "
                    + mockWebServer.url("/")
                    + " (signal=status_differential, valid_br=200, invalid_br=400, probe_br=200,"
                    + " unencoded_valid=400, unencoded_invalid=400, server="
                    + expectedSanitizedServer
                    + ")"));
  }

  @Test
  public void detect_whenServerHeaderIsOnlyControlCharsOrWhitespace_omitsServerFieldFromEvidence() {
    enqueueVulnerableStatusCycle(
        () ->
            new MockResponse()
                .setResponseCode(HttpStatus.OK.code())
                .setHeader("Server", "\t\t\t   ")
                .setBody("OK"),
        () -> new MockResponse().setResponseCode(HttpStatus.BAD_REQUEST.code()).setBody("Error"));
    NetworkService service = createNetworkService();
    TargetInfo target = createTargetInfo();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                "Vulnerable endpoint: "
                    + mockWebServer.url("/")
                    + " (signal=status_differential, valid_br=200, invalid_br=400, probe_br=200,"
                    + " unencoded_valid=400, unencoded_invalid=400)"));
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

    DetectionReportList reports = detector.detect(createTargetInfo(), ImmutableList.of(sshService));

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
    enqueueVulnerableStatusCycle(
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
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                "Vulnerable endpoint: "
                    + mockWebServer.url("/v1/ingest?source=test")
                    + " (signal=status_differential, valid_br=200, invalid_br=400, probe_br=200,"
                    + " unencoded_valid=400, unencoded_invalid=400)"));
    assertThat(mockWebServer.getRequestCount()).isEqualTo(19);
    assertThat(mockWebServer.takeRequest().getPath()).isEqualTo("/v1/ingest?source=test");
  }

  @Test
  public void
      detect_whenCrawledEndpointsBeginWithStaticAssets_skipsStaticAssetsAndDetectsDynamicEndpoint()
          throws InterruptedException {
    enqueueVulnerableStatusCycle(
        () -> new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("OK"),
        () -> new MockResponse().setResponseCode(HttpStatus.BAD_REQUEST.code()).setBody("Error"));
    NetworkService service =
        createServiceWithCrawledUrls(
            "mailto:admin@example.com",
            mockWebServer.url("/assets/styles.css?v=1").toString(),
            mockWebServer.url("/assets/app.js;jsessionid=ABCD1234").toString(),
            mockWebServer.url("/static/BUNDLE.JS").toString(),
            mockWebServer.url("/favicon.ico").toString(),
            mockWebServer.url("/cgi-bin/api.cgi").toString());
    TargetInfo target = createTargetInfo();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                "Vulnerable endpoint: "
                    + mockWebServer.url("/cgi-bin/api.cgi")
                    + " (signal=status_differential, valid_br=200, invalid_br=400, probe_br=200,"
                    + " unencoded_valid=400, unencoded_invalid=400)"));
    assertThat(mockWebServer.getRequestCount()).isEqualTo(19);
    assertThat(mockWebServer.takeRequest().getPath()).isEqualTo("/cgi-bin/api.cgi");
  }

  @Test
  public void detect_whenCrawledEndpointsRepeatFragmentsAndCandidatePaths_deduplicatesBeforeCap() {
    ProbeTrackingDispatcher dispatcher =
        new ProbeTrackingDispatcher(
            request -> {
              if (!request.getPath().equals("/cgi-bin/api.cgi")) {
                return new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code());
              }
              return isValidControl(request) || isProbe(request)
                  ? new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("OK")
                  : new MockResponse()
                      .setResponseCode(HttpStatus.BAD_REQUEST.code())
                      .setBody("Error");
            });
    mockWebServer.setDispatcher(dispatcher);
    NetworkService service =
        createServiceWithCrawledUrls(
            mockWebServer.url("/#skip").toString(),
            mockWebServer.url("/#nav").toString(),
            mockWebServer.url("/#footer").toString(),
            mockWebServer.url("/").toString(),
            mockWebServer.url("/login#form").toString(),
            mockWebServer.url("/cgi-bin/api.cgi").toString());
    TargetInfo target = createTargetInfo();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                "Vulnerable endpoint: "
                    + mockWebServer.url("/cgi-bin/api.cgi")
                    + " (signal=status_differential, valid_br=200, invalid_br=400, probe_br=200,"
                    + " unencoded_valid=400, unencoded_invalid=400)"));
    assertThat(dispatcher.requestedPaths().get(0)).isEqualTo("/cgi-bin/api.cgi");
    assertThat(dispatcher.probeCount()).isEqualTo(1);
  }

  @Test
  public void detect_whenMoreThanThreeDistinctDynamicCrawledUrls_probesAtMostThreeCrawledUrls() {
    ProbeTrackingDispatcher dispatcher =
        new ProbeTrackingDispatcher(
            request -> new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code()));
    mockWebServer.setDispatcher(dispatcher);
    NetworkService service =
        createServiceWithCrawledUrls(
            mockWebServer.url("/dyn-1").toString(),
            mockWebServer.url("/dyn-2").toString(),
            mockWebServer.url("/dyn-3").toString(),
            mockWebServer.url("/dyn-4").toString());

    DetectionReportList reports = detector.detect(createTargetInfo(), ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(dispatcher.requestedPaths()).containsAtLeast("/dyn-1", "/dyn-2", "/dyn-3");
    assertThat(dispatcher.requestedPaths()).doesNotContain("/dyn-4");
    assertThat(dispatcher.receivedProbe()).isFalse();
  }

  @Test
  public void detect_whenApplianceExposesVulnerableRedfishPath_reportsVulnerability() {
    assertVulnerableApplianceCandidatePathDetected("/redfish/v1");
  }

  @Test
  public void detect_whenApplianceExposesVulnerableRpcPath_reportsVulnerability() {
    assertVulnerableApplianceCandidatePathDetected("/rpc");
  }

  @Test
  public void detect_whenApplianceExposesVulnerableJsonRpcPath_reportsVulnerability() {
    assertVulnerableApplianceCandidatePathDetected("/jsonrpc");
  }

  @Test
  public void detect_whenApplianceExposesVulnerableRestPath_reportsVulnerability() {
    assertVulnerableApplianceCandidatePathDetected("/rest");
  }

  @Test
  public void detect_whenServiceExposesVulnerableMcpPath_reportsVulnerability() {
    assertVulnerableApplianceCandidatePathDetected("/mcp");
  }

  @Test
  public void detect_whenMcpStreamableHttpRequiresEventStreamAcceptHeader_reportsVulnerability() {
    ProbeTrackingDispatcher dispatcher =
        new ProbeTrackingDispatcher(
            request -> {
              if (!request.getPath().equals("/mcp")) {
                return new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code());
              }
              String accept = request.getHeader("Accept");
              if (accept == null
                  || !accept.contains("application/json")
                  || !accept.contains("text/event-stream")) {
                return new MockResponse().setResponseCode(HttpStatus.NOT_ACCEPTABLE.code());
              }
              return isValidControl(request) || isProbe(request)
                  ? new MockResponse().setResponseCode(HttpStatus.ACCEPTED.code())
                  : new MockResponse().setResponseCode(HttpStatus.BAD_REQUEST.code());
            });
    mockWebServer.setDispatcher(dispatcher);
    NetworkService service = createNetworkService();
    TargetInfo target = createTargetInfo();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                "Vulnerable endpoint: "
                    + mockWebServer.url("/mcp")
                    + " (signal=status_differential, valid_br=202, invalid_br=400, probe_br=202,"
                    + " unencoded_valid=400, unencoded_invalid=400)"));
    assertThat(dispatcher.probeCount()).isEqualTo(1);
  }

  @Test
  public void
      detect_whenProxyDecompressesBeforeHandlerReturns406OnValidAnd400OnInvalid_reportsVulnerability() {
    enqueueVulnerableStatusCycle(
        () -> new MockResponse().setResponseCode(HttpStatus.NOT_ACCEPTABLE.code()),
        () -> new MockResponse().setResponseCode(HttpStatus.BAD_REQUEST.code()));
    NetworkService service = createNetworkService();
    TargetInfo target = createTargetInfo();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                "Vulnerable endpoint: "
                    + mockWebServer.url("/")
                    + " (signal=status_differential, valid_br=406, invalid_br=400, probe_br=406,"
                    + " unencoded_valid=400, unencoded_invalid=400)"));
    assertThat(mockWebServer.getRequestCount()).isEqualTo(19);
  }

  @Test
  public void detect_whenServiceExposesVulnerableMessagesPath_reportsVulnerability() {
    assertVulnerableApplianceCandidatePathDetected(
        "/messages?session_id=00000000-0000-0000-0000-000000000000"
            + "&sessionId=00000000-0000-0000-0000-000000000000");
  }

  @Test
  public void
      detect_whenFastMcpSlashRedirectReturns307OnValidAnd400OnInvalid_reportsVulnerability() {
    enqueueVulnerableStatusCycle(
        () ->
            new MockResponse()
                .setResponseCode(HttpStatus.TEMPORARY_REDIRECT.code())
                .setHeader("Location", "/messages/"),
        () -> new MockResponse().setResponseCode(HttpStatus.BAD_REQUEST.code()));
    NetworkService service = createNetworkService();
    TargetInfo target = createTargetInfo();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                "Vulnerable endpoint: "
                    + mockWebServer.url("/")
                    + " (signal=status_differential, valid_br=307, invalid_br=400, probe_br=307,"
                    + " unencoded_valid=400, unencoded_invalid=400)"));
    assertThat(mockWebServer.getRequestCount()).isEqualTo(19);
  }

  @Test
  public void detect_whenFlaskSlashRedirectReturns308OnValidAnd400OnInvalid_reportsVulnerability() {
    enqueueVulnerableStatusCycle(
        () ->
            new MockResponse()
                .setResponseCode(HttpStatus.PERMANENT_REDIRECT.code())
                .setHeader("Location", "/messages/"),
        () -> new MockResponse().setResponseCode(HttpStatus.BAD_REQUEST.code()));
    NetworkService service = createNetworkService();
    TargetInfo target = createTargetInfo();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                "Vulnerable endpoint: "
                    + mockWebServer.url("/")
                    + " (signal=status_differential, valid_br=308, invalid_br=400, probe_br=308,"
                    + " unencoded_valid=400, unencoded_invalid=400)"));
    assertThat(mockWebServer.getRequestCount()).isEqualTo(19);
  }

  @Test
  public void detect_whenServiceExposesVulnerableV1Path_reportsVulnerability() {
    assertVulnerableApplianceCandidatePathDetected("/v1");
  }

  @Test
  public void detect_whenServiceExposesVulnerableApiV2Path_reportsVulnerability() {
    assertVulnerableApplianceCandidatePathDetected("/api/v2");
  }

  @Test
  public void detect_whenServiceExposesVulnerableInvocationsPath_reportsVulnerability() {
    assertVulnerableApplianceCandidatePathDetected("/invocations");
  }

  @Test
  public void detect_whenServiceExposesVulnerablePredictPath_reportsVulnerability() {
    assertVulnerableApplianceCandidatePathDetected("/predict");
  }

  @Test
  public void detect_whenServiceExposesVulnerableIndexPhpPath_reportsVulnerability() {
    assertVulnerableApplianceCandidatePathDetected("/index.php");
  }

  @Test
  public void
      detect_whenTwoPodRoundRobinAlternates200And400AcrossCandidatePaths_abortsBeforeSending23MbProbe() {
    int[] statusCycle = {HttpStatus.OK.code(), HttpStatus.BAD_REQUEST.code()};
    AtomicInteger requestIndex = new AtomicInteger();
    ProbeTrackingDispatcher dispatcher =
        new ProbeTrackingDispatcher(
            request ->
                new MockResponse()
                    .setResponseCode(
                        statusCycle[requestIndex.getAndIncrement() % statusCycle.length]));
    mockWebServer.setDispatcher(dispatcher);

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(dispatcher.receivedProbe()).isFalse();
    assertThat(Collections.frequency(dispatcher.requestedPaths(), "/")).isEqualTo(3);
  }

  @Test
  public void
      detect_whenTwoPodRoundRobinAlternates404And500AcrossCandidatePaths_abortsBeforeSending23MbProbe() {
    int[] statusCycle = {HttpStatus.NOT_FOUND.code(), HttpStatus.INTERNAL_SERVER_ERROR.code()};
    AtomicInteger requestIndex = new AtomicInteger();
    ProbeTrackingDispatcher dispatcher =
        new ProbeTrackingDispatcher(
            request ->
                new MockResponse()
                    .setResponseCode(
                        statusCycle[requestIndex.getAndIncrement() % statusCycle.length]));
    mockWebServer.setDispatcher(dispatcher);

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(dispatcher.receivedProbe()).isFalse();
    assertThat(Collections.frequency(dispatcher.requestedPaths(), "/")).isEqualTo(3);
  }

  @Test
  public void
      detect_whenThreePodRoundRobinCycles404And500And500AcrossCandidatePaths_abortsBeforeSending23MbProbe() {
    int[] statusCycle = {
      HttpStatus.NOT_FOUND.code(),
      HttpStatus.INTERNAL_SERVER_ERROR.code(),
      HttpStatus.INTERNAL_SERVER_ERROR.code()
    };
    AtomicInteger requestIndex = new AtomicInteger();
    ProbeTrackingDispatcher dispatcher =
        new ProbeTrackingDispatcher(
            request ->
                new MockResponse()
                    .setResponseCode(
                        statusCycle[requestIndex.getAndIncrement() % statusCycle.length]));
    mockWebServer.setDispatcher(dispatcher);

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(dispatcher.receivedProbe()).isFalse();
    assertThat(Collections.frequency(dispatcher.requestedPaths(), "/")).isEqualTo(5);
  }

  @Test
  public void
      detect_whenFivePodRoundRobinMatchesFirstFiveControlsAcrossCandidatePaths_abortsBeforeSending23MbProbe() {
    int[] statusCycle = {
      HttpStatus.OK.code(),
      HttpStatus.BAD_REQUEST.code(),
      HttpStatus.BAD_REQUEST.code(),
      HttpStatus.OK.code(),
      HttpStatus.OK.code()
    };
    AtomicInteger requestIndex = new AtomicInteger();
    ProbeTrackingDispatcher dispatcher =
        new ProbeTrackingDispatcher(
            request ->
                new MockResponse()
                    .setResponseCode(
                        statusCycle[requestIndex.getAndIncrement() % statusCycle.length]));
    mockWebServer.setDispatcher(dispatcher);

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(dispatcher.receivedProbe()).isFalse();
    assertThat(Collections.frequency(dispatcher.requestedPaths(), "/")).isEqualTo(6);
  }

  @Test
  public void detect_whenFourPodRoundRobinPassesPreProbeGate_rejectedAtProbeStep3() {
    int[] statusCycle = {
      HttpStatus.OK.code(),
      HttpStatus.BAD_REQUEST.code(),
      HttpStatus.BAD_REQUEST.code(),
      HttpStatus.OK.code()
    };
    AtomicInteger requestIndex = new AtomicInteger();
    ProbeTrackingDispatcher dispatcher =
        new ProbeTrackingDispatcher(
            request ->
                new MockResponse()
                    .setResponseCode(
                        statusCycle[requestIndex.getAndIncrement() % statusCycle.length]));
    mockWebServer.setDispatcher(dispatcher);

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(dispatcher.receivedProbe()).isTrue();
    assertThat(Collections.frequency(dispatcher.requestedPaths(), "/")).isEqualTo(7);
  }

  @Test
  public void detect_whenSevenPodRoundRobinPassesPreProbeAndProbe_rejectedInPostProbeStep4() {
    int[] statusCycle = {
      HttpStatus.OK.code(),
      HttpStatus.BAD_REQUEST.code(),
      HttpStatus.BAD_REQUEST.code(),
      HttpStatus.OK.code(),
      HttpStatus.OK.code(),
      HttpStatus.BAD_REQUEST.code(),
      HttpStatus.OK.code()
    };
    AtomicInteger requestIndex = new AtomicInteger();
    ProbeTrackingDispatcher dispatcher =
        new ProbeTrackingDispatcher(
            request ->
                new MockResponse()
                    .setResponseCode(
                        statusCycle[requestIndex.getAndIncrement() % statusCycle.length]));
    mockWebServer.setDispatcher(dispatcher);

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(dispatcher.receivedProbe()).isTrue();
    assertThat(Collections.frequency(dispatcher.requestedPaths(), "/")).isEqualTo(8);
  }

  @Test
  public void
      detect_whenStochasticSocketRaceProducesSixRequest200And400Sequence_abortsBeforeSending23MbProbe() {
    // Non-blocking TCP socket reader race on a crawled query endpoint (e.g., /login?from=/) that
    // previously satisfied a 6-request [200, 400, 200, 200, 400, 400] status sequence while
    // returning 200 OK on non-query candidate paths; reversed pre-probe pair 1 now aborts at
    // request 3 before sending the 23 MB probe.
    assertCrawledQueryRaceSequenceAbortsAtRequestThree(200, 400, 200, 200, 400, 400);
  }

  @Test
  public void
      detect_whenStochasticSocketRaceProducesSevenRequestUnencoded200Sequence_abortsBeforeSending23MbProbe() {
    // Legacy 7-request dual-unencoded bypass vector [200, 400, 200, 200, 400, 200, 200] is
    // likewise preempted at request 3 by the reversed first pre-probe control pair.
    assertCrawledQueryRaceSequenceAbortsAtRequestThree(200, 400, 200, 200, 400, 200, 200);
  }

  private void assertCrawledQueryRaceSequenceAbortsAtRequestThree(int... raceSequence) {
    AtomicInteger loginStep = new AtomicInteger();
    ProbeTrackingDispatcher dispatcher =
        new ProbeTrackingDispatcher(
            request -> {
              if (!request.getPath().equals("/login?from=/")) {
                return new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("OK");
              }
              int index = loginStep.getAndIncrement();
              int code = index < raceSequence.length ? raceSequence[index] : HttpStatus.OK.code();
              return new MockResponse().setResponseCode(code);
            });
    mockWebServer.setDispatcher(dispatcher);
    NetworkService service =
        createServiceWithCrawledUrls(mockWebServer.url("/login?from=%2F").toString());

    DetectionReportList reports = detector.detect(createTargetInfo(), ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(dispatcher.receivedProbe()).isFalse();
    assertThat(Collections.frequency(dispatcher.requestedPaths(), "/login?from=/")).isEqualTo(3);
  }

  @Test
  public void detect_whenPreProbeFirstPairSecondControlFails_abortsBeforeSending23MbProbe() {
    AtomicInteger rootStep = new AtomicInteger();
    ProbeTrackingDispatcher dispatcher =
        new ProbeTrackingDispatcher(
            request -> {
              if (!request.getPath().equals("/")) {
                return new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code());
              }
              if (rootStep.incrementAndGet() == 4) {
                return new MockResponse().setResponseCode(HttpStatus.BAD_REQUEST.code());
              }
              return isValidControl(request)
                  ? new MockResponse().setResponseCode(HttpStatus.OK.code())
                  : new MockResponse().setResponseCode(HttpStatus.BAD_REQUEST.code());
            });
    mockWebServer.setDispatcher(dispatcher);

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(dispatcher.receivedProbe()).isFalse();
    assertThat(Collections.frequency(dispatcher.requestedPaths(), "/")).isEqualTo(4);
  }

  @Test
  public void detect_whenControlPairFirstRequestDisconnects_abortsBeforeSending23MbProbe() {
    AtomicInteger rootStep = new AtomicInteger();
    ProbeTrackingDispatcher dispatcher =
        new ProbeTrackingDispatcher(
            request -> {
              if (!request.getPath().equals("/")) {
                return new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code());
              }
              if (rootStep.incrementAndGet() == 3) {
                return new MockResponse().setSocketPolicy(SocketPolicy.DISCONNECT_AFTER_REQUEST);
              }
              return isValidControl(request)
                  ? new MockResponse().setResponseCode(HttpStatus.OK.code())
                  : new MockResponse().setResponseCode(HttpStatus.BAD_REQUEST.code());
            });
    mockWebServer.setDispatcher(dispatcher);

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(dispatcher.receivedProbe()).isFalse();
    assertThat(Collections.frequency(dispatcher.requestedPaths(), "/")).isEqualTo(3);
  }

  @Test
  public void detect_whenControlPairSecondRequestDisconnects_abortsBeforeSending23MbProbe() {
    AtomicInteger rootStep = new AtomicInteger();
    ProbeTrackingDispatcher dispatcher =
        new ProbeTrackingDispatcher(
            request -> {
              if (!request.getPath().equals("/")) {
                return new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code());
              }
              if (rootStep.incrementAndGet() == 4) {
                return new MockResponse().setSocketPolicy(SocketPolicy.DISCONNECT_AFTER_REQUEST);
              }
              return isValidControl(request)
                  ? new MockResponse().setResponseCode(HttpStatus.OK.code())
                  : new MockResponse().setResponseCode(HttpStatus.BAD_REQUEST.code());
            });
    mockWebServer.setDispatcher(dispatcher);

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(dispatcher.receivedProbe()).isFalse();
    assertThat(Collections.frequency(dispatcher.requestedPaths(), "/")).isEqualTo(4);
  }

  @Test
  public void detect_whenCanaryReflectedPostProbeInvalidControlContainsCanary_reportsEmpty() {
    String canaryError = "Field error: " + Cve2026111497Detector.DECOMPRESSED_CANARY;
    AtomicInteger graphQlStep = new AtomicInteger();
    ProbeTrackingDispatcher dispatcher =
        new ProbeTrackingDispatcher(
            request -> {
              if (!request.getPath().equals("/graphql")) {
                return new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code());
              }
              if (graphQlStep.incrementAndGet() == 5) {
                return new MockResponse()
                    .setResponseCode(HttpStatus.BAD_REQUEST.code())
                    .setBody(canaryError);
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
    assertThat(Collections.frequency(dispatcher.requestedPaths(), "/graphql")).isEqualTo(5);
  }

  @Test
  public void detect_whenFinalPostProbeConfirmationRoundFirstControlFails_reportsEmpty() {
    AtomicInteger brStep = new AtomicInteger();
    ProbeTrackingDispatcher dispatcher =
        new ProbeTrackingDispatcher(
            request -> {
              if (!request.getPath().equals("/")) {
                return new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code());
              }
              if (request.getHeader("Content-Encoding") == null) {
                return new MockResponse().setResponseCode(HttpStatus.BAD_REQUEST.code());
              }
              if (brStep.incrementAndGet() == 16) {
                return new MockResponse().setResponseCode(HttpStatus.BAD_REQUEST.code());
              }
              return isValidControl(request) || isProbe(request)
                  ? new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("OK")
                  : new MockResponse().setResponseCode(HttpStatus.BAD_REQUEST.code());
            });
    mockWebServer.setDispatcher(dispatcher);

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(dispatcher.probeCount()).isEqualTo(1);
    assertThat(Collections.frequency(dispatcher.requestedPaths(), "/")).isEqualTo(16);
  }

  @Test
  public void detect_whenFinalPostProbeConfirmationRoundSecondControlFails_reportsEmpty() {
    AtomicInteger brStep = new AtomicInteger();
    ProbeTrackingDispatcher dispatcher =
        new ProbeTrackingDispatcher(
            request -> {
              if (!request.getPath().equals("/")) {
                return new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code());
              }
              if (request.getHeader("Content-Encoding") == null) {
                return new MockResponse().setResponseCode(HttpStatus.BAD_REQUEST.code());
              }
              if (brStep.incrementAndGet() == 17) {
                return new MockResponse().setResponseCode(HttpStatus.OK.code());
              }
              return isValidControl(request) || isProbe(request)
                  ? new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("OK")
                  : new MockResponse().setResponseCode(HttpStatus.BAD_REQUEST.code());
            });
    mockWebServer.setDispatcher(dispatcher);

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(dispatcher.probeCount()).isEqualTo(1);
    assertThat(Collections.frequency(dispatcher.requestedPaths(), "/")).isEqualTo(17);
  }

  @Test
  public void detect_whenStep5UnencodedInvalidMismatchesBypassedValidStatus_reportsEmpty() {
    ProbeTrackingDispatcher dispatcher =
        new ProbeTrackingDispatcher(
            request -> {
              if (!request.getPath().equals("/")) {
                return new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code());
              }
              if (request.getHeader("Content-Encoding") == null) {
                return hasValidControlBody(request)
                    ? new MockResponse().setResponseCode(HttpStatus.UNAUTHORIZED.code())
                    : new MockResponse().setResponseCode(HttpStatus.FORBIDDEN.code());
              }
              return isValidControl(request) || isProbe(request)
                  ? new MockResponse().setResponseCode(HttpStatus.UNAUTHORIZED.code())
                  : new MockResponse().setResponseCode(HttpStatus.BAD_REQUEST.code());
            });
    mockWebServer.setDispatcher(dispatcher);

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(dispatcher.probeCount()).isEqualTo(1);
    assertThat(Collections.frequency(dispatcher.requestedPaths(), "/")).isEqualTo(19);
  }

  @Test
  public void
      detect_whenStep5UnencodedValidRejectedWith400ButUnencodedInvalidReturns200_reportsEmpty() {
    ProbeTrackingDispatcher dispatcher =
        new ProbeTrackingDispatcher(
            request -> {
              if (!request.getPath().equals("/")) {
                return new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code());
              }
              if (request.getHeader("Content-Encoding") == null) {
                return hasValidControlBody(request)
                    ? new MockResponse().setResponseCode(HttpStatus.BAD_REQUEST.code())
                    : new MockResponse().setResponseCode(HttpStatus.OK.code());
              }
              return isValidControl(request) || isProbe(request)
                  ? new MockResponse().setResponseCode(HttpStatus.OK.code())
                  : new MockResponse().setResponseCode(HttpStatus.BAD_REQUEST.code());
            });
    mockWebServer.setDispatcher(dispatcher);

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(dispatcher.probeCount()).isEqualTo(1);
    assertThat(Collections.frequency(dispatcher.requestedPaths(), "/")).isEqualTo(19);
  }

  @Test
  public void
      detect_whenStep5UnencodedValidRejectedWith400ButUnencodedInvalidReturnsNonRejection404_reportsEmpty() {
    ProbeTrackingDispatcher dispatcher =
        new ProbeTrackingDispatcher(
            request -> {
              if (!request.getPath().equals("/")) {
                return new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code());
              }
              if (request.getHeader("Content-Encoding") == null) {
                return hasValidControlBody(request)
                    ? new MockResponse().setResponseCode(HttpStatus.BAD_REQUEST.code())
                    : new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code());
              }
              return isValidControl(request) || isProbe(request)
                  ? new MockResponse().setResponseCode(HttpStatus.OK.code())
                  : new MockResponse().setResponseCode(HttpStatus.BAD_REQUEST.code());
            });
    mockWebServer.setDispatcher(dispatcher);

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(dispatcher.probeCount()).isEqualTo(1);
    assertThat(Collections.frequency(dispatcher.requestedPaths(), "/")).isEqualTo(19);
  }

  @Test
  public void detect_whenStep5UnencodedInvalidReturnsUnspecifiedStatus_reportsEmpty() {
    ProbeTrackingDispatcher dispatcher =
        new ProbeTrackingDispatcher(
            request -> {
              if (!request.getPath().equals("/")) {
                return new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code());
              }
              if (request.getHeader("Content-Encoding") == null) {
                return hasValidControlBody(request)
                    ? new MockResponse().setResponseCode(HttpStatus.BAD_REQUEST.code())
                    : new MockResponse().setResponseCode(599).setBody("Unknown proxy status");
              }
              return isValidControl(request) || isProbe(request)
                  ? new MockResponse().setResponseCode(HttpStatus.OK.code())
                  : new MockResponse().setResponseCode(HttpStatus.BAD_REQUEST.code());
            });
    mockWebServer.setDispatcher(dispatcher);

    DetectionReportList reports =
        detector.detect(createTargetInfo(), ImmutableList.of(createNetworkService()));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(dispatcher.probeCount()).isEqualTo(1);
    assertThat(Collections.frequency(dispatcher.requestedPaths(), "/")).isEqualTo(19);
  }

  @Test
  public void
      detect_whenStep5UnencodedControlsReturnDistinctRejectionStatuses_recordsBothInEvidence() {
    enqueueVulnerableStatusCycle(
        () -> new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("OK"),
        () -> new MockResponse().setResponseCode(HttpStatus.BAD_REQUEST.code()).setBody("Bad br"),
        () -> new MockResponse().setResponseCode(HttpStatus.BAD_REQUEST.code()).setBody("Bad JSON"),
        () ->
            new MockResponse()
                .setResponseCode(HttpStatus.UNPROCESSABLE_ENTITY.code())
                .setBody("Unprocessable"));
    NetworkService service = createNetworkService();
    TargetInfo target = createTargetInfo();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                "Vulnerable endpoint: "
                    + mockWebServer.url("/")
                    + " (signal=status_differential, valid_br=200, invalid_br=400, probe_br=200,"
                    + " unencoded_valid=400, unencoded_invalid=422)"));
    assertThat(mockWebServer.getRequestCount()).isEqualTo(19);
  }

  private void assertVulnerableApplianceCandidatePathDetected(String expectedPath) {
    ProbeTrackingDispatcher dispatcher =
        new ProbeTrackingDispatcher(
            request -> {
              if (!request.getPath().equals(expectedPath)) {
                return new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code());
              }
              return isValidControl(request) || isProbe(request)
                  ? new MockResponse().setResponseCode(HttpStatus.UNAUTHORIZED.code())
                  : new MockResponse().setResponseCode(HttpStatus.BAD_REQUEST.code());
            });
    mockWebServer.setDispatcher(dispatcher);
    NetworkService service = createNetworkService();
    TargetInfo target = createTargetInfo();

    DetectionReportList reports = detector.detect(target, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                target,
                service,
                "Vulnerable endpoint: "
                    + mockWebServer.url(expectedPath)
                    + " (signal=status_differential, valid_br=401, invalid_br=400, probe_br=401,"
                    + " unencoded_valid=400, unencoded_invalid=400)"));
    assertThat(dispatcher.probeCount()).isEqualTo(1);
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
