/*
 * Copyright 2021 Google LLC
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
package com.google.tsunami.plugins.detectors.solr;

import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostname;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;
import static com.google.tsunami.plugins.detectors.solr.ApacheSolrArbitraryFileReadingDetector.DESCRIPTION;
import static com.google.tsunami.plugins.detectors.solr.ApacheSolrArbitraryFileReadingDetector.RECOMMENDATION;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.collect.ImmutableList;
import com.google.common.io.Resources;
import com.google.inject.Guice;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkEndpoint;
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
import javax.inject.Inject;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Unit tests for {@link ApacheSolrArbitraryFileReadingDetector}.
 */
@RunWith(JUnit4.class)
public final class ApacheSolrArbitraryFileReadingDetectorTest {

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  @Inject
  private ApacheSolrArbitraryFileReadingDetector detector;

  private MockWebServer mockWebServer;
  private NetworkService solrService;

  @Before
  public void setUp() {
    mockWebServer = new MockWebServer();
    solrService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setSoftware(Software.newBuilder().setName("Apache Solr"))
            .setServiceName("http")
            .build();

    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            new ApacheSolrArbitraryFileReadingDetectorBootstrapModule())
        .injectMembers(this);
  }

  @Test
  public void detect_whenSolrIsVulnerable_reportsVuln() throws IOException {
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(200).setBody("{\"status\": {\"test\": {}}}"));
    mockWebServer.enqueue(new MockResponse().setResponseCode(200));
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(200).setBody(loadResource("vulnerable_response.json")));
    mockWebServer.enqueue(new MockResponse().setResponseCode(200));
    mockWebServer.url("/");

    DetectionReportList detectionReports =
        detector.detect(TargetInfo.getDefaultInstance(), ImmutableList.of(solrService));

    assertThat(detectionReports.getDetectionReportsList())
        .containsExactly(
            DetectionReport.newBuilder()
                .setTargetInfo(TargetInfo.getDefaultInstance())
                .setNetworkService(solrService)
                .setDetectionTimestamp(
                    Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
                .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
                .setVulnerability(
                    Vulnerability.newBuilder()
                        .setMainId(
                            VulnerabilityId.newBuilder()
                                .setPublisher("TSUNAMI_COMMUNITY")
                                .setValue("APACHE_SOLR_REMOTE_STREAMING_FILE_READING"))
                        .setSeverity(Severity.HIGH)
                        .setTitle("Apache Solr RemoteStreaming Arbitrary File Reading")
                        .setDescription(DESCRIPTION)
                        .setRecommendation(RECOMMENDATION)
                        .addAdditionalDetails(buildAdditionalDetail("vulnerable_check_trace.txt")))
                .build());
  }

  @Test
  public void detect_whenSolrIsVulnerableWithPermissionDenied_reportsVuln() throws IOException {
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(200).setBody("{\"status\": {\"test\": {}}}"));
    mockWebServer.enqueue(new MockResponse().setResponseCode(200));
    mockWebServer.enqueue(
        new MockResponse()
            .setResponseCode(200)
            .setBody(loadResource("vulnerable_with_permission_denied_response.json")));
    mockWebServer.enqueue(new MockResponse().setResponseCode(200));
    mockWebServer.url("/");

    DetectionReportList detectionReports =
        detector.detect(TargetInfo.getDefaultInstance(), ImmutableList.of(solrService));

    assertThat(detectionReports.getDetectionReportsList())
        .containsExactly(
            DetectionReport.newBuilder()
                .setTargetInfo(TargetInfo.getDefaultInstance())
                .setNetworkService(solrService)
                .setDetectionTimestamp(
                    Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
                .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
                .setVulnerability(
                    Vulnerability.newBuilder()
                        .setMainId(
                            VulnerabilityId.newBuilder()
                                .setPublisher("TSUNAMI_COMMUNITY")
                                .setValue("APACHE_SOLR_REMOTE_STREAMING_FILE_READING"))
                        .setSeverity(Severity.HIGH)
                        .setTitle("Apache Solr RemoteStreaming Arbitrary File Reading")
                        .setDescription(DESCRIPTION)
                        .setRecommendation(RECOMMENDATION)
                        .addAdditionalDetails(
                            buildAdditionalDetail("vulnerable_with_permission_denied_trace.txt")))
                .build());
  }

  @Test
  public void detect_whenSolrIsVulnerableWithFileNotFound_reportsVuln() throws IOException {
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(200).setBody("{\"status\": {\"test\": {}}}"));
    mockWebServer.enqueue(new MockResponse().setResponseCode(200));
    mockWebServer.enqueue(
        new MockResponse()
            .setResponseCode(200)
            .setBody(loadResource("vulnerable_with_file_not_found_response.json")));
    mockWebServer.enqueue(new MockResponse().setResponseCode(200));
    mockWebServer.url("/");

    DetectionReportList detectionReports =
        detector.detect(TargetInfo.getDefaultInstance(), ImmutableList.of(solrService));

    assertThat(detectionReports.getDetectionReportsList())
        .containsExactly(
            DetectionReport.newBuilder()
                .setTargetInfo(TargetInfo.getDefaultInstance())
                .setNetworkService(solrService)
                .setDetectionTimestamp(
                    Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
                .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
                .setVulnerability(
                    Vulnerability.newBuilder()
                        .setMainId(
                            VulnerabilityId.newBuilder()
                                .setPublisher("TSUNAMI_COMMUNITY")
                                .setValue("APACHE_SOLR_REMOTE_STREAMING_FILE_READING"))
                        .setSeverity(Severity.HIGH)
                        .setTitle("Apache Solr RemoteStreaming Arbitrary File Reading")
                        .setDescription(DESCRIPTION)
                        .setRecommendation(RECOMMENDATION)
                        .addAdditionalDetails(
                            buildAdditionalDetail("vulnerable_with_file_not_found_trace.txt")))
                .build());
  }

  @Test
  public void detect_whenSolrIsNotVulnerable_doesNotReportVuln() {
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(200).setBody("{\"status\": {\"test\": {}}}"));
    mockWebServer.enqueue(new MockResponse().setResponseCode(200));
    mockWebServer.enqueue(new MockResponse().setResponseCode(200).setBody(""));
    mockWebServer.enqueue(new MockResponse().setResponseCode(200));
    mockWebServer.url("/");

    assertThat(
        detector
            .detect(
                buildTargetInfo(forHostname(mockWebServer.getHostName())),
                ImmutableList.of(solrService))
            .getDetectionReportsList())
        .isEmpty();
  }

  @Test
  public void detect_whenSolrHasNoCores_doesNotReportVuln() {
    mockWebServer.enqueue(new MockResponse().setResponseCode(200).setBody("{\"status\": {}}"));
    mockWebServer.enqueue(new MockResponse().setResponseCode(200));
    mockWebServer.enqueue(new MockResponse().setResponseCode(200).setBody(""));
    mockWebServer.enqueue(new MockResponse().setResponseCode(200));
    mockWebServer.url("/");

    assertThat(
            detector
                .detect(
                    buildTargetInfo(forHostname(mockWebServer.getHostName())),
                    ImmutableList.of(solrService))
                .getDetectionReportsList())
        .isEmpty();
  }

  private static TargetInfo buildTargetInfo(NetworkEndpoint networkEndpoint) {
    return TargetInfo.newBuilder().addNetworkEndpoints(networkEndpoint).build();
  }

  private static AdditionalDetail buildAdditionalDetail(String traceFile) throws IOException {
    return AdditionalDetail.newBuilder()
        .setTextData(TextData.newBuilder().setText(loadResource(traceFile)))
        .build();
  }

  private static String loadResource(String file) throws IOException {
    return Resources.toString(
            Resources.getResource(ApacheSolrArbitraryFileReadingDetectorTest.class, file), UTF_8)
        .strip();
  }
}
