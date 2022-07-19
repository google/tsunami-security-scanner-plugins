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
package com.google.tsunami.plugins.detectors.rce.consul;

// import static com.google.common.net.HttpHeaders.CONTENT_TYPE;
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
import com.google.tsunami.plugin.payload.testing.FakePayloadGeneratorModule;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.TargetInfo;
import java.io.IOException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import javax.inject.Inject;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link ConsulEnableScriptChecksCommandExecutionDetector}. */
@RunWith(JUnit4.class)
public final class ConsulEnableScriptChecksCommandExecutionDetectorWithOutCallbackServerTest {

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  @Inject private ConsulEnableScriptChecksCommandExecutionDetector detector;

  private MockWebServer mockConsulService;
  private final String validRceResponse;

  private final SecureRandom testSecureRandom =
      new SecureRandom() {
        @Override
        public void nextBytes(byte[] bytes) {
          Arrays.fill(bytes, (byte) 0xFF);
        }
      };

  public ConsulEnableScriptChecksCommandExecutionDetectorWithOutCallbackServerTest()
      throws IOException {
    this.validRceResponse =
        Resources.toString(Resources.getResource(this.getClass(), "validRCEResponse.json"), UTF_8);
  }

  @Before
  public void setUp() throws IOException {

    mockConsulService = new MockWebServer();
    mockConsulService.start();

    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            FakePayloadGeneratorModule.builder().setSecureRng(testSecureRandom).build(),
            new ConsulEnableScriptChecksCommandExecutionDetectorBootstrapModule())
        .injectMembers(this);
  }

  @After
  public void tearDown() throws Exception {
    mockConsulService.shutdown();
  }

  @Test
  public void detect_whenVulnerable_reportsVulnerability()
      throws IOException, InterruptedException {
    // For the service registration request
    mockConsulService.enqueue(new MockResponse().setResponseCode(HttpStatus.OK.code()));
    // For the RCE check
    mockConsulService.enqueue(
        new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody(validRceResponse));
    // For the service deregistration
    mockConsulService.enqueue(new MockResponse().setResponseCode(HttpStatus.OK.code()));

    NetworkService service = TestHelper.createConsulService(mockConsulService);
    TargetInfo target = TestHelper.buildTargetInfo(forHostname(mockConsulService.getHostName()));

    DetectionReportList detectionReports = detector.detect(target, ImmutableList.of(service));

    assertThat(detectionReports.getDetectionReportsList())
        .contains(TestHelper.buildValidDetectionReport(target, service, fakeUtcClock));
    RecordedRequest req = mockConsulService.takeRequest();
    assertThat(req.getPath()).contains("/v1/agent/service/register");
    req = mockConsulService.takeRequest();
    assertThat(req.getPath()).contains("/v1/health/service/TSUNAMI_RCE_TEST");
    req = mockConsulService.takeRequest();
    assertThat(req.getPath()).contains("/v1/agent/service/deregister");
  }

  @Test
  public void detect_whenNotVulnerable_doesNotReportVulnerability()
      throws IOException, InterruptedException {
    // For the service registration request
    mockConsulService.enqueue(new MockResponse().setResponseCode(HttpStatus.OK.code()));
    // For the RCE check
    mockConsulService.enqueue(
        new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("NO RCE"));
    // For the service deregistration
    mockConsulService.enqueue(new MockResponse().setResponseCode(HttpStatus.OK.code()));

    NetworkService service = TestHelper.createConsulService(mockConsulService);

    DetectionReportList detectionReports =
        detector.detect(
            TestHelper.buildTargetInfo(forHostname(mockConsulService.getHostName())),
            ImmutableList.of(service));

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
    RecordedRequest req = mockConsulService.takeRequest();
    assertThat(req.getPath()).contains("/v1/agent/service/register");
    req = mockConsulService.takeRequest();
    assertThat(req.getPath()).contains("/v1/health/service/TSUNAMI_RCE_TEST");
    req = mockConsulService.takeRequest();
    assertThat(req.getPath()).contains("/v1/agent/service/deregister");
  }
}
