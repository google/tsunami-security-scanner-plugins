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
package com.google.tsunami.plugins.detectors.rce;

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
import java.io.IOException;
import java.time.Instant;
import javax.inject.Inject;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link SolrVelocityTemplateRceDetector}. */
@RunWith(JUnit4.class)
public final class SolrVelocityTemplateRceDetectorTest {
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  @Inject private SolrVelocityTemplateRceDetector detector;

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
            new SolrVelocityTemplateRceDetectorBootstrapModule())
        .injectMembers(this);
  }

  @Test
  public void detect_whenSolrIsVulnerable_reportsVuln() throws IOException {
    // 3 HTTP responses are queued including the expected command result in the last response.
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(200).setBody("{\"status\": {\"test\": {}}}"));
    mockWebServer.enqueue(new MockResponse().setResponseCode(200));
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(200).setBody("   amiTSUN 536870912 amiTSUN"));
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
                                .setPublisher("GOOGLE")
                                .setValue("CVE_2019_17558"))
                        .setSeverity(Severity.CRITICAL)
                        .setTitle("Apache Solr Velocity Template RCE (CVE-2019-17558)")
                        .setDescription(
                            "Apache Solr 5.0.0 to Apache Solr 8.3.1 are vulnerable to a Remote"
                                + " Code Execution through the VelocityResponseWriter. A Velocity"
                                + " template can be provided through Velocity templates in a"
                                + " configset `velocity/` directory or as a parameter. A user"
                                + " defined configset could contain renderable, potentially"
                                + " malicious, templates. Parameter provided templates are"
                                + " disabled by default, but can be enabled by setting"
                                + " `params.resource.loader.enabled` by defining a response writer"
                                + " with that setting set to `true`. Defining a response writer"
                                + " requires configuration API access. Solr 8.4 removed the params"
                                + " resource loader entirely, and only enables the"
                                + " configset-provided template rendering when the configset is"
                                + " `trusted` (has been uploaded by an authenticated user).")
                        .setRecommendation("Upgrade to Solr 8.4.0 or greater."))
                .build());
  }

  @Test
  public void detect_whenSolrIsNotVulnerable_doesNotReportVuln() throws IOException {
    // Last response lacks the expected command result indicating that the exploit failed.
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(200).setBody("{\"status\": {\"test\": {}}}"));
    mockWebServer.enqueue(new MockResponse().setResponseCode(200));
    mockWebServer.enqueue(new MockResponse().setResponseCode(200).setBody("      0  "));
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
  public void detect_whenSolrFailsTemplateUpdate_doesNotReportVuln() throws IOException {
    // Second response has status code 400 indicating that the update failed.
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(200).setBody("{\"status\": {\"test\": {}}}"));
    mockWebServer.enqueue(new MockResponse().setResponseCode(400));
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(200).setBody("   amiTSUN 536870912 amiTSUN"));
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
  public void detect_whenSolrHasNoCores_doesNotReportVuln() throws IOException {
    // First response has no cores meaning no targets are available in Solr for testing.
    mockWebServer.enqueue(new MockResponse().setResponseCode(200).setBody("{\"status\": {}}"));
    mockWebServer.enqueue(new MockResponse().setResponseCode(200));
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(200).setBody("   amiTSUN 536870912 amiTSUN"));
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
  public void detect_whenNonHttpNetworkService_ignoresServices() {
    ImmutableList<NetworkService> nonHttpServices =
        ImmutableList.of(
            NetworkService.newBuilder().setServiceName("ssh").build(),
            NetworkService.newBuilder().setServiceName("rdp").build());
    assertThat(
            detector
                .detect(buildTargetInfo(forHostname(mockWebServer.getHostName())), nonHttpServices)
                .getDetectionReportsList())
        .isEmpty();
  }

  private static TargetInfo buildTargetInfo(NetworkEndpoint networkEndpoint) {
    return TargetInfo.newBuilder().addNetworkEndpoints(networkEndpoint).build();
  }
}
