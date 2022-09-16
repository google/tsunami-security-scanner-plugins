/*
 * Copyright 2022 Google LLC
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
package com.google.tsunami.plugins.kubereadonly;

import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;

import com.google.common.collect.ImmutableList;
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

/** Unit tests for {@link KubeReadOnlyPortDetector}. */
@RunWith(JUnit4.class)
public final class KubeReadOnlyPortDetectorTest {
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  @Inject private KubeReadOnlyPortDetector detector;

  private final MockWebServer mockTargetService = new MockWebServer();

  @Before
  public void setUp() throws IOException {
    mockTargetService.start();

    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            new KubeReadOnlyPortDetectorBootstrapModule())
        .injectMembers(this);
  }

  @After
  public void tearDown() throws Exception {
    mockTargetService.shutdown();
  }

  private DetectionReportList doDetect() {
    NetworkService targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockTargetService.getHostName(), mockTargetService.getPort()))
            .setServiceName("http")
            .build();

    TargetInfo targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(targetNetworkService.getNetworkEndpoint())
            .build();

    return detector.detect(targetInfo, ImmutableList.of(targetNetworkService));
  }

  @Test
  public void detect_podlist_returnsVulnerability() {
    mockTargetService.enqueue(
        new MockResponse().setBody("{\"kind\":\"PodList\"}").setResponseCode(HttpStatus.OK.code()));

    DetectionReportList detectionReports = doDetect();

    assertThat(detectionReports.getDetectionReportsList()).hasSize(1);
  }

  private void shouldHaveNoFingings() {
    DetectionReportList detectionReports = doDetect();

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void detect_no_podlist_returnsEmpty() {

    mockTargetService.enqueue(
        new MockResponse().setBody("{\"foobar\":1}").setResponseCode(HttpStatus.OK.code()));

    shouldHaveNoFingings();
  }

  @Test
  public void detect_array_returnsEmpty() {

    mockTargetService.enqueue(
        new MockResponse().setBody("[]").setResponseCode(HttpStatus.OK.code()));

    shouldHaveNoFingings();
  }

  @Test
  public void detect_nojson_returnsEmpty() {
    mockTargetService.enqueue(
        new MockResponse().setBody("foobar").setResponseCode(HttpStatus.OK.code()));

    shouldHaveNoFingings();
  }

  @Test
  public void detect_404_returnsEmpty() {
    mockTargetService.enqueue(
        new MockResponse()
            .setBody("{\"kind\":\"PodList\"}") // the body should be ignored
            .setResponseCode(HttpStatus.NOT_FOUND.code()));

    shouldHaveNoFingings();
  }

  @Test
  public void detect_serverIsGone_returnsEmpty() throws IOException {

    // shutting down the target purposefully
    mockTargetService.shutdown();

    shouldHaveNoFingings();
  }
}
