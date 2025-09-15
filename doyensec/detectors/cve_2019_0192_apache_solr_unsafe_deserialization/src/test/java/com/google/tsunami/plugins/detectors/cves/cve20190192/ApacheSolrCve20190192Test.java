/*
 * Copyright 2025 Google LLC
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

package com.google.tsunami.plugins.detectors.cves.cve20190192;

import static com.google.common.truth.Truth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostname;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;
import static com.google.tsunami.plugins.detectors.cves.cve20190192.ApacheSolrCve20190192.CORE_ENDPOINT;
import static com.google.tsunami.plugins.detectors.cves.cve20190192.ApacheSolrCve20190192.EXPLOIT_ENDPOINT;
import static com.google.tsunami.plugins.detectors.cves.cve20190192.ApacheSolrCve20190192.HOME_ENDPOINT;

import com.google.common.collect.ImmutableList;
import com.google.inject.Guice;
import com.google.inject.testing.fieldbinder.Bind;
import com.google.inject.testing.fieldbinder.BoundFieldModule;
import com.google.inject.util.Modules;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.plugin.payload.testing.FakePayloadGeneratorModule;
import com.google.tsunami.plugin.payload.testing.PayloadTestHelper;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TransportProtocol;
import java.io.IOException;
import java.time.Instant;
import javax.inject.Inject;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link ApacheSolrCve20190192}. */
@RunWith(JUnit4.class)
public final class ApacheSolrCve20190192Test {

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2024-08-28T13:37:00.00Z"));

  @Bind(lazy = true)
  private final int oobSleepDuration = 0;

  @Inject private ApacheSolrCve20190192 detector;
  private MockWebServer mockWebServer = new MockWebServer();
  private MockWebServer mockCallbackServer = new MockWebServer();

  private static final String VULNERABLE_VERSION =
      "<link rel=\"icon\" type=\"image/x-icon\" href=\"img/favicon.ico?_=6.6.4\">";

  private static final String SAFE_VERSION =
      "<link rel=\"icon\" type=\"image/x-icon\" href=\"img/favicon.ico?_=9.0.0\">";

  private static final String MOCK_CORE_ENDPOINT_RESPONSE =
      "{\"responseHeader\":{\"status\":0,\"QTime\":0},\"initFailures\":{\"doyensec\":\"java.lang.RuntimeException:java.lang.RuntimeException:"
          + " Could not start JMX monitoring"
          + " \"},\"status\":{\"doyensec\":{\"name\":\"doyensec\",\"instanceDir\":\"/opt/solr/server/solr/doyensec\",\"dataDir\":\"/opt/solr/server/solr/doyensec/data/\",\"config\":\"solrconfig.xml\",\"schema\":\"managed-schema\",\"startTime\":\"2025-02-26T10:23:13.070Z\",\"uptime\":88837602,\"index\":{\"numDocs\":0,\"maxDoc\":0,\"deletedDocs\":0,\"indexHeapUsageBytes\":0,\"version\":2,\"segmentCount\":0,\"current\":true,\"hasDeletions\":false,\"directory\":\"org.apache.lucene.store.NRTCachingDirectory:NRTCachingDirectory(MMapDirectory@/opt/solr/server/solr/doyensec/data/index"
          + " lockFactory=org.apache.lucene.store.NativeFSLockFactory@22152f77; maxCacheMB=48.0"
          + " maxMergeSizeMB=4.0)\",\"segmentsFile\":\"segments_1\",\"segmentsFileSizeInBytes\":71,\"userData\":{},\"sizeInBytes\":71,\"size\":\"71"
          + " bytes\"}}}}";
  private static final String VULNERABLE_INSTANCE_RESPONSE =
      "{\n"
          + //
          "  \"responseHeader\":{\n"
          + //
          "    \"status\":500,\n"
          + //
          "    \"QTime\":174},\n"
          + //
          "  \"errorMessages\":[\"Unable to reload core [doyensec]\\n"
          + //
          "Could not start JMX monitoring \\n"
          + //
          "Cannot bind to URL"
        + " [rmi://38c41c3d5f356f2728d28d20dce09e255796f97bc157d00ce755439d.cb.tsunami.doyentesting.com:53/obj]:"
        + " javax.naming.ServiceUnavailableException [Root exception is java.rmi.ConnectException:"
        + " Connection refused to host:"
        + " 38c41c3d5f356f2728d28d20dce09e255796f97bc157d00ce755439d.cb.tsunami.doyentesting.com;"
        + " nested exception is: \\n"
          + //
          "\\tjava.net.ConnectException: Connection refused (Connection refused)]\\n"
          + //
          "null\\n"
          + //
          "Connection refused to host:"
          + " 38c41c3d5f356f2728d28d20dce09e255796f97bc157d00ce755439d.cb.tsunami.doyentesting.com;"
          + " nested exception is: \\n"
          + //
          "\\tjava.net.ConnectException: Connection refused (Connection refused)\\n"
          + //
          "\"]};";

  @Before
  public void setUp() throws IOException {
    mockWebServer = new MockWebServer();
    mockCallbackServer.start();
  }

  @After
  public void tearDown() throws Exception {
    mockCallbackServer.shutdown();
    mockWebServer.shutdown();
  }

  private void createInjector(boolean tcsAvailable) {
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            FakePayloadGeneratorModule.builder()
                .setCallbackServer(tcsAvailable ? mockCallbackServer : null)
                .build(),
            Modules.override(new ApacheSolrCve20190192BootstrapModule())
                .with(BoundFieldModule.of(this)))
        .injectMembers(this);
  }

  @Test
  public void detect_whenVulnerableAndTcsAvailable_reportsCriticalVulnerability()
      throws IOException {
    ImmutableList<NetworkService> httpServices = mockWebServerSetup(true);
    TargetInfo targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockWebServer.getHostName()))
            .build();

    createInjector(true);
    mockCallbackServer.enqueue(PayloadTestHelper.generateMockSuccessfulCallbackResponse());

    DetectionReportList detectionReports = detector.detect(targetInfo, httpServices);

    DetectionReport expectedDetection =
        generateDetectionReportWithCallback(detector, targetInfo, httpServices.get(0));
    assertThat(detectionReports.getDetectionReportsList()).containsExactly(expectedDetection);
    assertThat(mockWebServer.getRequestCount()).isEqualTo(3);
    assertThat(mockCallbackServer.getRequestCount()).isEqualTo(1);
  }

  @Test
  public void detect_whenNotVulnerableAndTcsAvailable_reportsNoVulnerability() throws IOException {
    ImmutableList<NetworkService> httpServices = mockWebServerSetup(false);
    TargetInfo targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockWebServer.getHostName()))
            .build();

    createInjector(true);
    mockCallbackServer.enqueue(PayloadTestHelper.generateMockUnsuccessfulCallbackResponse());

    DetectionReportList detectionReports = detector.detect(targetInfo, httpServices);

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
    assertThat(mockWebServer.getRequestCount()).isEqualTo(1);
    assertThat(mockCallbackServer.getRequestCount()).isEqualTo(0);
  }

  private DetectionReport generateDetectionReportWithCallback(
      ApacheSolrCve20190192 detector, TargetInfo targetInfo, NetworkService networkService) {

    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(networkService)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(detector.getAdvisories().get(0))
        .build();
  }

  private ImmutableList<NetworkService> mockWebServerSetup(boolean isVulnerable)
      throws IOException {
    mockWebServer.setDispatcher(new EndpointDispatcher(isVulnerable));
    mockWebServer.start();
    return ImmutableList.of(
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("http")
            .build());
  }

  static final class EndpointDispatcher extends Dispatcher {
    EndpointDispatcher(boolean isVulnerable) {
      this.isVulnerable = isVulnerable;
    }

    private final boolean isVulnerable;

    @Override
    public MockResponse dispatch(RecordedRequest recordedRequest) {
      if (recordedRequest.getMethod().equals("GET")
          && recordedRequest.getPath().equals("/" + HOME_ENDPOINT)) {
        if (isVulnerable) {
          return new MockResponse()
              .setResponseCode(HttpStatus.OK.code())
              .setBody(VULNERABLE_VERSION);
        } else {
          return new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody(SAFE_VERSION);
        }
      } else if (recordedRequest.getMethod().equals("GET")
          && recordedRequest.getPath().equals("/" + CORE_ENDPOINT)) {
        // Version detection request
        return new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .setBody(MOCK_CORE_ENDPOINT_RESPONSE);
      } else if (recordedRequest.getMethod().equals("POST")
          && recordedRequest
              .getPath()
              .equals("/" + EXPLOIT_ENDPOINT.replace("REPLACE", "doyensec"))) {
        // Exploit attempt
        if (isVulnerable) {
          return new MockResponse()
              .setResponseCode(HttpStatus.INTERNAL_SERVER_ERROR.code())
              .setBody(VULNERABLE_INSTANCE_RESPONSE);
        } else {
          return new MockResponse().setResponseCode(HttpStatus.BAD_REQUEST.code());
        }
      } else {
        // Anything else, return a 404
        return new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code());
      }
    }
  }
}
