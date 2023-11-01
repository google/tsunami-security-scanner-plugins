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
package com.google.tsunami.plugins.detectors.rce.kubernetes;

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

/** Unit tests for {@link RCEInKubernetesClusterWithOpenAccessDetector}. */
@RunWith(JUnit4.class)
public final class RCEInKubernetesClusterWithOpenAccessDetectorWithOutCallbackServerTest {

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  @Inject private RCEInKubernetesClusterWithOpenAccessDetector detector;

  private MockWebServer mockKubernetesService;
  private final String validRceResponse;

  private final SecureRandom testSecureRandom =
      new SecureRandom() {
        @Override
        public void nextBytes(byte[] bytes) {
          Arrays.fill(bytes, (byte) 0xFF);
        }
      };

  public RCEInKubernetesClusterWithOpenAccessDetectorWithOutCallbackServerTest()
      throws IOException {
    this.validRceResponse =
        Resources.toString(Resources.getResource(this.getClass(), "validRCEResponse.json"), UTF_8);
  }

  @Before
  public void setUp() throws IOException {

    mockKubernetesService = new MockWebServer();
    mockKubernetesService.start();

    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            FakePayloadGeneratorModule.builder().setSecureRng(testSecureRandom).build(),
            new RCEInKubernetesClusterWithOpenAccessDetectorBootstrapModule())
        .injectMembers(this);
  }

  @After
  public void tearDown() throws Exception {
    mockKubernetesService.shutdown();
  }

  @Test
  public void detect_whenVulnerable_reportsVulnerability()
      throws IOException, InterruptedException {
    // Enqueue create pod response
    mockKubernetesService.enqueue(
        new MockResponse().setResponseCode(HttpStatus.CREATED.code()).setBody(validRceResponse));
    // Enqueue delete pod response
    mockKubernetesService.enqueue(new MockResponse().setResponseCode(HttpStatus.OK.code()));

    NetworkService service = TestHelper.createKubernetesService(mockKubernetesService);
    TargetInfo target =
        TestHelper.buildTargetInfo(forHostname(mockKubernetesService.getHostName()));

    DetectionReportList detectionReports = detector.detect(target, ImmutableList.of(service));

    assertThat(detectionReports.getDetectionReportsList())
        .contains(TestHelper.buildValidDetectionReport(target, service, fakeUtcClock));
    RecordedRequest req = mockKubernetesService.takeRequest();
    assertThat(req.getPath()).contains("/api/v1/namespaces/default/pods");
    req = mockKubernetesService.takeRequest();
    assertThat(req.getPath()).contains("/api/v1/namespaces/default/pods/tsunami-rce-pod");
  }

  @Test
  public void detect_whenNotVulnerable_doesNotReportVulnerability()
      throws IOException, InterruptedException {

    // One failed response, for creating RCE pod.
    mockKubernetesService.enqueue(new MockResponse().setResponseCode(HttpStatus.FORBIDDEN.code()));

    NetworkService service = TestHelper.createKubernetesService(mockKubernetesService);

    DetectionReportList detectionReports =
        detector.detect(
            TestHelper.buildTargetInfo(forHostname(mockKubernetesService.getHostName())),
            ImmutableList.of(service));

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
    RecordedRequest req = mockKubernetesService.takeRequest();
    assertThat(req.getPath()).contains("/api/v1/namespaces/default/pods");
  }
}
