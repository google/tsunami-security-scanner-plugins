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
package com.google.tsunami.plugins.detectors.rce.cve201811776;

import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostname;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.inject.Guice;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
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
import java.util.Map;
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

/** Unit tests for {@link ApacheStrutsNamespaceRceDetector} */
@RunWith(JUnit4.class)
public final class ApacheStrutsNamespaceRceDetectorTest {
  private enum VulnerabilityType {
    NONE,
    REDIRECT,
    NAMESPACE_ERROR
  }

  private static final String NAMESPACE_ERROR_BODY =
      "<html><head><meta http-equiv=\"Content-Type\""
          + " content=\"text/html;charset=utf-8\"/><title>Error 404 There is no Action mapped for"
          + " namespace [//tsunami-detected-cve20181776-eipnop]and action name [some.action]"
          + " associated with context path [].</title></head><body><h2>HTTP ERROR"
          + " 404</h2><p>Problem accessing"
          + " //%24%7B%27tsunami-%27+%2B+%27detected-%27+%2B+%27cve20181776-eipnop%27%7D/<some>."
          + " Reason:<pre>    There is no Action mapped for namespace"
          + " [//tsunami-detected-cve20181776-eipnop] and action name [some.action] associated"
          + " with context path [].</pre></p></body></html>";

  private static final class VulnerableTypeDispatcher extends Dispatcher {
    private final Map<Integer, VulnerabilityType> indexErrorMap;
    private int index;

    VulnerableTypeDispatcher(Map<Integer, VulnerabilityType> indexErrorMap) {
      this.indexErrorMap = indexErrorMap;
      this.index = 0;
    }

    @Override
    public MockResponse dispatch(RecordedRequest recordedRequest) {
      int currentIndex = index;
      index++;
      switch (indexErrorMap.getOrDefault(currentIndex, VulnerabilityType.NONE)) {
        case NONE:
          return new MockResponse()
              .setResponseCode(HttpStatus.NOT_FOUND.code())
              .setBody("irrelevant-body");
        case REDIRECT:
          return new MockResponse()
              .setResponseCode(HttpStatus.FOUND.code())
              .setHeader(
                  "Location",
                  "http://irrelevant.com/tsunami-detected-cve20181776-eipnop/irrelevant.action");
        case NAMESPACE_ERROR:
          return new MockResponse()
              .setResponseCode(HttpStatus.NOT_FOUND.code())
              .setBody(NAMESPACE_ERROR_BODY);
      }
      return new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("nothing");
    }
  }

  private final FakeUtcClock utcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  @Inject private ApacheStrutsNamespaceRceDetector detector;
  private MockWebServer mockWebServer;

  @Before
  public void setUp() {
    mockWebServer = new MockWebServer();
    Guice.createInjector(
            new FakeUtcClockModule(utcClock),
            new HttpClientModule.Builder().build(),
            new ApacheStrutsNamespaceRceDetectorBootstrapModule())
        .injectMembers(this);
  }

  @After
  public void tearDown() throws IOException {
    mockWebServer.shutdown();
  }

  @Test
  public void report_whenAppHasVulnerableRedirect_reportsVulnerable() throws Exception {
    ImmutableList<NetworkService> networkServices =
        setupActionWithVulnerableNamespace(ImmutableMap.of(0, VulnerabilityType.REDIRECT));
    TargetInfo targetInfo = buildTargetInfo(forHostname(mockWebServer.getHostName()));
    DetectionReport expectedDetectionReport = getExpectedDetectionReport(networkServices.get(0));

    DetectionReportList detectionReportList = detector.detect(targetInfo, networkServices);

    assertThat(detectionReportList.getDetectionReportsList())
        .containsExactly(expectedDetectionReport);
  }

  @Test
  public void report_whenAppHasVulnerableErrorPage_reportVulnerable() throws Exception {
    ImmutableList<NetworkService> networkServices =
        setupActionWithVulnerableNamespace(ImmutableMap.of(0, VulnerabilityType.NAMESPACE_ERROR));
    TargetInfo targetInfo = buildTargetInfo(forHostname(mockWebServer.getHostName()));
    DetectionReport expectedDetectionReport = getExpectedDetectionReport(networkServices.get(0));

    DetectionReportList detectionReportList = detector.detect(targetInfo, networkServices);

    assertThat(detectionReportList.getDetectionReportsList())
        .containsExactly(expectedDetectionReport);
  }

  @Test
  public void report_whenAppFindVulnerableRedirectInLaterAttempts_reportsVulnerable()
      throws Exception {
    ImmutableList<NetworkService> networkServices =
        setupActionWithVulnerableNamespace(ImmutableMap.of(5, VulnerabilityType.REDIRECT));
    TargetInfo targetInfo = buildTargetInfo(forHostname(mockWebServer.getHostName()));
    DetectionReport expectedDetectionReport = getExpectedDetectionReport(networkServices.get(0));

    DetectionReportList detectionReportList = detector.detect(targetInfo, networkServices);

    assertThat(detectionReportList.getDetectionReportsList())
        .containsExactly(expectedDetectionReport);
  }

  @Test
  public void report_whenAppHasVulnerableErrorPageInLaterAttempts_reportVulnerable()
      throws Exception {
    ImmutableList<NetworkService> networkServices =
        setupActionWithVulnerableNamespace(ImmutableMap.of(5, VulnerabilityType.NAMESPACE_ERROR));
    TargetInfo targetInfo = buildTargetInfo(forHostname(mockWebServer.getHostName()));
    DetectionReport expectedDetectionReport = getExpectedDetectionReport(networkServices.get(0));

    DetectionReportList detectionReportList = detector.detect(targetInfo, networkServices);

    assertThat(detectionReportList.getDetectionReportsList())
        .containsExactly(expectedDetectionReport);
  }

  @Test
  public void report_whenAppDoesNotHaveVulnerability_reportNotVulnerable() throws Exception {
    ImmutableList<NetworkService> networkServices =
        setupActionWithVulnerableNamespace(ImmutableMap.of());
    TargetInfo targetInfo = buildTargetInfo(forHostname(mockWebServer.getHostName()));

    DetectionReportList detectionReportList = detector.detect(targetInfo, networkServices);

    assertThat(detectionReportList.getDetectionReportsList()).isEmpty();
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

  private ImmutableList<NetworkService> setupActionWithVulnerableNamespace(
      ImmutableMap<Integer, VulnerabilityType> vulnerableActions) throws IOException {
    mockWebServer.setDispatcher(new VulnerableTypeDispatcher(vulnerableActions));
    mockWebServer.start();
    return ImmutableList.of(
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("http")
            .build());
  }

  private DetectionReport getExpectedDetectionReport(NetworkService service) {
    return DetectionReport.newBuilder()
        .setTargetInfo(buildTargetInfo(forHostname(mockWebServer.getHostName())))
        .setNetworkService(service)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder().setPublisher("GOOGLE").setValue("CVE_2018_11776"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Apache Struts Command Injection via Namespace (CVE-2018-11776)")
                .setDescription(
                    "Apache Struts versions 2.3 to 2.3.34 and 2.5 to 2.5.16 suffer from possible"
                        + " Remote Code Execution when alwaysSelectFullNamespace is true (either"
                        + " by user or a plugin like Convention Plugin) and then: results are used"
                        + " with no namespace and in same time, its upper package have no or"
                        + " wildcard namespace and similar to results, same possibility when using"
                        + " url tag which doesn't have value and action set and in same time, its"
                        + " upper package have no or wildcard namespace."))
        .build();
  }

  private static TargetInfo buildTargetInfo(NetworkEndpoint networkEndpoint) {
    return TargetInfo.newBuilder().addNetworkEndpoints(networkEndpoint).build();
  }
}
