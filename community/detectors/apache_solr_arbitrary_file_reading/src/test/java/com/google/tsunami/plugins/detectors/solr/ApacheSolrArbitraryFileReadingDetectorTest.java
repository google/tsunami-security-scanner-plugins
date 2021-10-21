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
package com.google.tsunami.plugins.detectors.solr;

import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostname;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;

import com.google.common.collect.ImmutableList;
import com.google.inject.Guice;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkEndpoint;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.Software;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TransportProtocol;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
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
  public void detect_whenSolrIsVulnerable_reportsVuln() {
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(200).setBody("{\"status\": {\"test\": {}}}"));
    mockWebServer.enqueue(new MockResponse().setResponseCode(200));
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(200).setBody("{\n"
            + "  \"responseHeader\":{\n"
            + "    \"status\":0,\n"
            + "    \"QTime\":6,\n"
            + "    \"handler\":\"org.apache.solr.handler.DumpRequestHandler\",\n"
            + "    \"params\":{\n"
            + "      \"param\":\"ContentStreams\",\n"
            + "      \"stream.url\":\"file:///etc/passwd\"}},\n"
            + "  \"params\":{\n"
            + "    \"stream.url\":\"file:///etc/passwd\",\n"
            + "    \"echoHandler\":\"true\",\n"
            + "    \"param\":\"ContentStreams\",\n"
            + "    \"echoParams\":\"explicit\"},\n"
            + "  \"streams\":[{\n"
            + "      \"name\":null,\n"
            + "      \"sourceInfo\":\"url\",\n"
            + "      \"size\":null,\n"
            + "      \"contentType\":null,\n"
            + "      \"stream\":\"root:x:0:0:root:/root:/bin/bash\"}],\n"
            + "  \"context\":{\n"
            + "    \"webapp\":\"/solr\",\n"
            + "    \"path\":\"/debug/dump\",\n"
            + "    \"httpMethod\":\"GET\"}}"));
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
                        .setMainId(VulnerabilityId.newBuilder().setPublisher("TSUNAMI_COMMUNITY")
                            .setValue("APACHE_SOLR_UNPROTECTED_SERVER"))
                        .setSeverity(Severity.HIGH)
                        .setTitle("Apache Solr RemoteStreaming Arbitrary File Reading")
                        .setDescription("Apache Solr is an open source search server. When Apache "
                            + "Solr does not enable authentication, an attacker can directly craft"
                            + " a request to enable a specific configuration, and eventually cause"
                            + " SSRF or arbitrary file reading.")
                        .setRecommendation("enable authentication")
                ).build());
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
}
