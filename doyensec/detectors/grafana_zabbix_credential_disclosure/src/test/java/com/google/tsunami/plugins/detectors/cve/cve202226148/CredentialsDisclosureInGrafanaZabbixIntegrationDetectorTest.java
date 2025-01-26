/*
 * Copyright 2023 Google LLC
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

package com.google.tsunami.plugins.detectors.cve.cve202226148;

import static com.google.common.truth.Truth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostname;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.collect.ImmutableList;
import com.google.common.io.Resources;
import com.google.inject.Guice;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.TargetInfo;
import java.io.IOException;
import java.time.Instant;
import java.util.List;
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

/** Unit tests for {@link CredentialsDisclosureInGrafanaZabbixIntegrationDetector}. */
@RunWith(JUnit4.class)
public final class CredentialsDisclosureInGrafanaZabbixIntegrationDetectorTest {

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  @Inject private CredentialsDisclosureInGrafanaZabbixIntegrationDetector detector;

  private MockWebServer mockGrafanaService;

  private final String disclosedCredentialGrafanaResponse;
  private final String secureGrafanaResponse;

  public CredentialsDisclosureInGrafanaZabbixIntegrationDetectorTest() throws IOException {
    disclosedCredentialGrafanaResponse =
        Resources.toString(
            Resources.getResource(this.getClass(), "disclosedCredentialGrafanaResponse.html"),
            UTF_8);
    secureGrafanaResponse =
        Resources.toString(
            Resources.getResource(this.getClass(), "secureGrafanaResponse.html"), UTF_8);
  }

  @Before
  public void setUp() throws IOException {
    mockGrafanaService = new MockWebServer();
    mockGrafanaService.start();

    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            new CredentialsDisclosureInGrafanaZabbixIntegrationDetectorBootstrapModule())
        .injectMembers(this);
  }

  @After
  public void tearDown() throws Exception {
    mockGrafanaService.shutdown();
  }

  @Test
  public void detect_whenVulnerable_reportsVulnerability()
      throws IOException, InterruptedException {

    List<String> vulnerablePaths =
        CredentialsDisclosureInGrafanaZabbixIntegrationDetector.VULNERABLE_PATHS;

    mockGrafanaService.setDispatcher(
        new EndpointDispatcher(disclosedCredentialGrafanaResponse, vulnerablePaths));

    NetworkService service = TestHelper.createGrafanaService(mockGrafanaService);

    TargetInfo target = TestHelper.buildTargetInfo(forHostname(mockGrafanaService.getHostName()));

    DetectionReportList detectionReports = detector.detect(target, ImmutableList.of(service));

    assertThat(mockGrafanaService.getRequestCount()).isEqualTo(1);

    // The plugin should report the vuln
    assertThat(detectionReports.getDetectionReportsList())
        .contains(TestHelper.buildValidDetectionReport(target, service, fakeUtcClock));
  }

  @Test
  public void detect_whenNotVulnerable_doesNotReportVulnerability()
      throws IOException, InterruptedException {
    // response without password disclosed
    List<String> vulnerablePaths =
        CredentialsDisclosureInGrafanaZabbixIntegrationDetector.VULNERABLE_PATHS;

    mockGrafanaService.setDispatcher(
        new EndpointDispatcher(secureGrafanaResponse, vulnerablePaths));

    NetworkService service = TestHelper.createGrafanaService(mockGrafanaService);

    DetectionReportList detectionReports =
        detector.detect(
            TestHelper.buildTargetInfo(forHostname(mockGrafanaService.getHostName())),
            ImmutableList.of(service));

    // since the vulnerability is not present all the VULNEREABLE_PATHS should be tried
    assertThat(mockGrafanaService.getRequestCount()).isEqualTo(vulnerablePaths.size());

    // the plugin should not report the vuln
    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }

  private final class EndpointDispatcher extends Dispatcher {
    private final String response;
    private final List<String> registeredPaths;

    EndpointDispatcher(final String response, final List<String> registeredPaths) {
      this.response = response;
      this.registeredPaths = registeredPaths;
    }

    @Override
    public MockResponse dispatch(RecordedRequest recordedRequest) {
      // remove the first "/"
      String path = recordedRequest.getPath().substring(1);

      // Return BAD_REQUEST if path is not in the registered list
      if (!registeredPaths.contains(path)) {
        return new MockResponse().setResponseCode(HttpStatus.BAD_REQUEST.code());
      }

      return new MockResponse().setBody(response).setResponseCode(HttpStatus.OK.code());
    }
  }
}
