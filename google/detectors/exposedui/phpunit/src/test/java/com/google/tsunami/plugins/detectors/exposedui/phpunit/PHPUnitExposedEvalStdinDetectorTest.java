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
package com.google.tsunami.plugins.detectors.exposedui.phpunit;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostname;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;

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
import com.google.tsunami.plugins.detectors.exposedui.phpunit.Annotations.RunMode;
import com.google.tsunami.plugins.detectors.exposedui.phpunit.Annotations.ScriptPaths;
import com.google.tsunami.plugins.detectors.exposedui.phpunit.PHPUnitExposedEvalStdinDetectorBootstrapModule.Mode;
import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkEndpoint;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TextData;
import com.google.tsunami.proto.TransportProtocol;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.io.IOException;
import java.time.Instant;
import javax.inject.Inject;
import javax.inject.Provider;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link PHPUnitExposedEvalStdinDetector}. */
@RunWith(JUnit4.class)
public final class PHPUnitExposedEvalStdinDetectorTest {

  private static final String EVAL_STDIN_SCRIPT_PATH =
      "vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php";

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  @Bind(lazy = true)
  @RunMode
  private Provider<Mode> runModeProvider = () -> Mode.DEFAULT;

  @Bind(lazy = true)
  @ScriptPaths
  private Provider<ImmutableList<String>> scriptPathsProvider = ImmutableList::of;

  private MockWebServer mockWebServer;

  @Inject private PHPUnitExposedEvalStdinDetector detector;

  @Before
  public void setUp() {
    mockWebServer = new MockWebServer();
  }

  @After
  public void tearDown() throws IOException {
    mockWebServer.shutdown();
  }

  @Test
  public void detect_whenPHPEvalStdinScriptTriggeredInDefaultMode_returnsVulnerability()
      throws IOException {
    ImmutableList<NetworkService> httpServices = testSetupWithVulnerableEndpoint();

    DetectionReportList detectionReports =
        detector.detect(buildTargetInfo(forHostname(mockWebServer.getHostName())), httpServices);

    verifyVulnerabilityReport(detectionReports, httpServices.get(0));
  }

  @Test
  public void detect_whenPHPEvalStdinScriptNotTriggered_returnsEmptyDetectionReport()
      throws IOException {
    createInjector();
    mockWebServer.setDispatcher(new SafeEndpointDispatcher());
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
  public void detect_whenPHPEvalStdinScriptTriggeredInCustomScanMode_returnsVulnerability()
      throws IOException {
    runModeProvider = () -> Mode.CUSTOM;
    scriptPathsProvider = () -> ImmutableList.of("foo/eval-stdin.php", EVAL_STDIN_SCRIPT_PATH);
    ImmutableList<NetworkService> httpServices = testSetupWithVulnerableEndpoint();

    DetectionReportList detectionReports =
        detector.detect(buildTargetInfo(forHostname(mockWebServer.getHostName())), httpServices);

    verifyVulnerabilityReport(detectionReports, httpServices.get(0));
    assertThat(mockWebServer.getRequestCount()).isEqualTo(2);
  }

  private void createInjector() {
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            Modules.override(new PHPUnitExposedEvalStdinDetectorBootstrapModule())
                .with(BoundFieldModule.of(this)))
        .injectMembers(this);
  }

  private ImmutableList<NetworkService> testSetupWithVulnerableEndpoint() throws IOException {
    createInjector();
    mockWebServer.setDispatcher(new VulnerableEndpointDispatcher(EVAL_STDIN_SCRIPT_PATH));
    mockWebServer.start();
    return ImmutableList.of(
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("http")
            .build());
  }

  private void verifyVulnerabilityReport(
      DetectionReportList detectionReports, NetworkService service) {
    assertThat(detectionReports.getDetectionReportsList())
        .containsExactly(
            DetectionReport.newBuilder()
                .setTargetInfo(buildTargetInfo(forHostname(mockWebServer.getHostName())))
                .setNetworkService(service)
                .setDetectionTimestamp(
                    Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
                .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
                .setVulnerability(
                    Vulnerability.newBuilder()
                        .setMainId(
                            VulnerabilityId.newBuilder()
                                .setPublisher("GOOGLE")
                                .setValue("EXPOSED_PHPUNIT_EVAL_STDIN"))
                        .setSeverity(Severity.CRITICAL)
                        .setTitle("CVE-2017-9841: Exposed Vulnerable eval-stdin.php in PHPUnit")
                        .setDescription(
                            "CVE-2017-9841: For vulnerable versions of PHPUnit, its eval-stdin.php"
                                + " script allows RCE via a POST request payload.")
                        .setRecommendation(
                            "Remove the PHPUnit module or upgrade to the latest version.")
                        .addAdditionalDetails(
                            AdditionalDetail.newBuilder()
                                .setTextData(
                                    TextData.newBuilder()
                                        .setText(
                                            "Vulnerable endpoint: " + EVAL_STDIN_SCRIPT_PATH))))
                .build());
  }

  static final class SafeEndpointDispatcher extends Dispatcher {

    @Override
    public MockResponse dispatch(RecordedRequest recordedRequest) {
      return new MockResponse().setResponseCode(HttpStatus.OK.code());
    }
  }

  private static TargetInfo buildTargetInfo(NetworkEndpoint networkEndpoint) {
    return TargetInfo.newBuilder().addNetworkEndpoints(networkEndpoint).build();
  }

  static final class VulnerableEndpointDispatcher extends Dispatcher {

    private final String vulnerablePath;

    VulnerableEndpointDispatcher(String vulnerablePath) {
      this.vulnerablePath = vulnerablePath;
    }

    @Override
    public MockResponse dispatch(RecordedRequest recordedRequest) {
      if (recordedRequest.getPath().equals("/" + vulnerablePath)) {
        return new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("tsunami-phpunit");
      }

      return new MockResponse().setResponseCode(HttpStatus.OK.code());
    }
  }
}
