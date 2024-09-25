/*
 * Copyright 2024 Google LLC
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
package com.google.tsunami.plugins.detectors.exposedui.nodered;

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
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkEndpoint;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TransportProtocol;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.io.IOException;
import java.time.Instant;
import javax.inject.Inject;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link NodeRedExposedUiDetector}. */
@RunWith(JUnit4.class)
public final class NodeRedExposedUiDetectorTest {

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  private static final String VULN_SETTINGS_PAGE =
      "{\"httpNodeRoot\":\"/\",\"version\":\"3.1.5\",\"context\":{\"default\":\"memory\",\"stores\":[\"memory\"]},\"codeEditor\":{\"lib\":\"monaco\",\"options\":{}},\"markdownEditor\":{\"mermaid\":{\"enabled\":true}},\"libraries\":[{\"id\":\"local\",\"label\":\"editor:library.types.local\",\"user\":false,\"icon\":\"font-awesome/fa-hdd-o\"},{\"id\":\"examples\",\"label\":\"editor:library.types.examples\",\"user\":false,\"icon\":\"font-awesome/fa-life-ring\",\"types\":[\"flows\"],\"readOnly\":true}],\"flowFilePretty\":true,\"externalModules\":{},\"flowEncryptionType\":\"system\",\"diagnostics\":{\"enabled\":true,\"ui\":true},\"runtimeState\":{\"enabled\":false,\"ui\":false},\"functionExternalModules\":true,\"functionTimeout\":0,\"tlsConfigDisableLocalFiles\":false,\"editorTheme\":{\"palette\":{},\"projects\":{\"enabled\":false,\"workflow\":{\"mode\":\"manual\"}},\"languages\":[\"de\",\"en-US\",\"es-ES\",\"fr\",\"ja\",\"ko\",\"pt-BR\",\"ru\",\"zh-CN\",\"zh-TW\"]}}";
  private static final String VULN_TOUR_PAGE = "\"en-US\": \"Welcome to Node-RED 3.1!\",";
  private static final Vulnerability EXPECTED_VULN =
      Vulnerability.newBuilder()
          .setMainId(
              VulnerabilityId.newBuilder()
                  .setPublisher("GOOGLE")
                  .setValue("NODERED_EXPOSED_UI"))
          .setSeverity(Severity.CRITICAL)
          .setTitle("Exposed NodeRED instance")
          .setRecommendation(
              "Configure authentication or ensure the NodeRED instance is not exposed to the"
                  + " network. See"
                  + " https://nodered.org/docs/user-guide/runtime/securing-node-red for"
                  + " details")
          .setDescription("NodeRED instance is exposed and can be used to compromise the system.")
          .build();

  private MockWebServer mockWebServer;

  @Inject private NodeRedExposedUiDetector detector;

  @Before
  public void setUp() {
    mockWebServer = new MockWebServer();

    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            new NodeRedExposedUiDetectorBootstrapModule())
        .injectMembers(this);
  }

  @After
  public void tearDown() throws IOException {
    mockWebServer.shutdown();
  }

  @Test
  public void detect_whenVulnerable_reportsVuln() throws IOException {
    mockWebServer.enqueue(new MockResponse().setResponseCode(200).setBody(VULN_TOUR_PAGE));
    mockWebServer.enqueue(new MockResponse().setResponseCode(200).setBody(VULN_SETTINGS_PAGE));
    mockWebServer.start();

    ImmutableList<NetworkService> httpServices =
        ImmutableList.of(
            NetworkService.newBuilder()
                .setNetworkEndpoint(
                    forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
                .setTransportProtocol(TransportProtocol.TCP)
                .setServiceName("http")
                .build());

    assertThat(
            detector
                .detect(buildTargetInfo(forHostname(mockWebServer.getHostName())), httpServices)
                .getDetectionReportsList())
        .containsExactly(
            DetectionReport.newBuilder()
                .setTargetInfo(buildTargetInfo(forHostname(mockWebServer.getHostName())))
                .setNetworkService(httpServices.get(0))
                .setDetectionTimestamp(Timestamps.fromMillis(fakeUtcClock.millis()))
                .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
                .setVulnerability(EXPECTED_VULN)
                .build());
  }

  @Test
  public void detect_whenSettingsDenied_reportsNothing() throws IOException {
    mockWebServer.enqueue(new MockResponse().setResponseCode(200).setBody(VULN_TOUR_PAGE));
    mockWebServer.enqueue(new MockResponse().setResponseCode(401).setBody("Unauthorized"));
    mockWebServer.start();

    ImmutableList<NetworkService> httpServices =
        ImmutableList.of(
            NetworkService.newBuilder()
                .setNetworkEndpoint(
                    forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
                .setTransportProtocol(TransportProtocol.TCP)
                .setServiceName("http")
                .build());
    assertThat(
            detector
                .detect(buildTargetInfo(forHostname(mockWebServer.getHostName())), httpServices)
                .getDetectionReportsList())
        .isEmpty();
  }
  
  @Test
  public void detect_whenIsNotNodeRed_reportsNothing() throws IOException {
    mockWebServer.enqueue(new MockResponse().setResponseCode(200).setBody("Apache server"));
    mockWebServer.start();

    ImmutableList<NetworkService> httpServices =
        ImmutableList.of(
            NetworkService.newBuilder()
                .setNetworkEndpoint(
                    forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
                .setTransportProtocol(TransportProtocol.TCP)
                .setServiceName("http")
                .build());
    assertThat(
            detector
                .detect(buildTargetInfo(forHostname(mockWebServer.getHostName())), httpServices)
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

  @Test
  public void detect_whenEmptyNetworkService_generatesEmptyDetectionReports() {
    assertThat(
            detector
                .detect(
                    buildTargetInfo(forHostname(mockWebServer.getHostName())), ImmutableList.of())
                .getDetectionReportsList())
        .isEmpty();
  }

  private static TargetInfo buildTargetInfo(NetworkEndpoint networkEndpoint) {
    return TargetInfo.newBuilder().addNetworkEndpoints(networkEndpoint).build();
  }
}
