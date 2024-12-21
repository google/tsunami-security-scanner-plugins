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
import javax.inject.Inject;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
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

  private final String disclosedCredentialGrafanaLoginResponse;
  private final String secureGrafanaLoginResponse;
  private final String disclosedCredentialGrafanaWelcomeResponse;
  private final String secureGrafanaWelcomeResponse;

  public CredentialsDisclosureInGrafanaZabbixIntegrationDetectorTest() throws IOException {
    this.disclosedCredentialGrafanaLoginResponse =
        Resources.toString(
            Resources.getResource(this.getClass(), "disclosedCredentialGrafanaLoginResponse.html"),
            UTF_8);
    this.secureGrafanaLoginResponse =
        Resources.toString(
            Resources.getResource(this.getClass(), "secureGrafanaLoginResponse.html"), UTF_8);
    this.disclosedCredentialGrafanaWelcomeResponse =
        Resources.toString(
            Resources.getResource(
                this.getClass(), "disclosedCredentialGrafanaWelcomeResponse.html"),
            UTF_8);
    this.secureGrafanaWelcomeResponse =
        Resources.toString(
            Resources.getResource(this.getClass(), "secureGrafanaWelcomeResponse.html"), UTF_8);
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
    // response with password disclosed
    mockGrafanaService.enqueue(
        new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .setBody(disclosedCredentialGrafanaLoginResponse));
    mockGrafanaService.enqueue(
        new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .setBody(disclosedCredentialGrafanaLoginResponse));
    mockGrafanaService.enqueue(
        new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .setBody(disclosedCredentialGrafanaWelcomeResponse));
    mockGrafanaService.enqueue(
        new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .setBody(disclosedCredentialGrafanaWelcomeResponse));

    NetworkService service = TestHelper.createGrafanaService(mockGrafanaService);

    TargetInfo target = TestHelper.buildTargetInfo(forHostname(mockGrafanaService.getHostName()));

    DetectionReportList detectionReports = detector.detect(target, ImmutableList.of(service));

    // The plugin should report the vuln
    assertThat(detectionReports.getDetectionReportsList())
        .contains(TestHelper.buildValidDetectionReport(target, service, fakeUtcClock));
  }

  @Test
  public void detect_whenNotVulnerable_doesNotReportVulnerability()
      throws IOException, InterruptedException {
    // response without password disclosed
    mockGrafanaService.enqueue(
        new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .setBody(secureGrafanaLoginResponse));
    mockGrafanaService.enqueue(
        new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .setBody(secureGrafanaLoginResponse));
    mockGrafanaService.enqueue(
        new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .setBody(secureGrafanaWelcomeResponse));
    mockGrafanaService.enqueue(
        new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .setBody(secureGrafanaWelcomeResponse));

    NetworkService service = TestHelper.createGrafanaService(mockGrafanaService);

    DetectionReportList detectionReports =
        detector.detect(
            TestHelper.buildTargetInfo(forHostname(mockGrafanaService.getHostName())),
            ImmutableList.of(service));
    // the plugin should not report the vuln
    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }
}
