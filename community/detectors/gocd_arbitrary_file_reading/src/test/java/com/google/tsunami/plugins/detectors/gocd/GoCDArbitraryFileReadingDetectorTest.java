/*
 * Copyright 2021 Google LLC
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
package com.google.tsunami.plugins.detectors.gocd;

import static com.google.common.truth.Truth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;

import com.google.common.collect.ImmutableList;
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
import com.google.tsunami.proto.Software;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TransportProtocol;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
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

/**
 * Unit tests for {@link GoCDArbitraryFileReadingDetector}.
 */
@RunWith(JUnit4.class)
public final class GoCDArbitraryFileReadingDetectorTest {

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  @Inject
  private GoCDArbitraryFileReadingDetector detector;

  private MockWebServer mockWebServer;
  private NetworkService goCDService;

  @Before
  public void setUp() {
    mockWebServer = new MockWebServer();
    goCDService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setSoftware(Software.newBuilder().setName("GoCD"))
            .setServiceName("http")
            .build();

    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            new GoCDArbitraryFileReadingDetectorBootstrapModule())
        .injectMembers(this);
  }

  @After
  public void tearDown() throws IOException {
    mockWebServer.shutdown();
  }

  @Test
  public void detect_whenVulnerable_returnsVulnerability() {
    mockWebServer.setDispatcher(new VulnerableEndpointDispatcher());

    DetectionReportList detectionReports = detector.detect(TargetInfo.getDefaultInstance(),
        ImmutableList.of(goCDService));
    assertThat(detectionReports.getDetectionReportsList())
        .containsExactly(
            DetectionReport.newBuilder()
                .setTargetInfo(TargetInfo.getDefaultInstance())
                .setNetworkService(goCDService)
                .setDetectionTimestamp(
                    Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
                .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
                .setVulnerability(
                    Vulnerability.newBuilder()
                        .setMainId(
                            VulnerabilityId.newBuilder().setPublisher("TSUNAMI_COMMUNITY")
                                .setValue("GoCD_ARBITRARY_FILE_READING"))
                        .setSeverity(Severity.CRITICAL)
                        .setTitle("GoCD Pre-Auth Arbitrary File Reading vulnerability")
                        .setDescription(
                            "In GoCD 21.2.0 and earlier, there is an endpoint that can be accessed "
                                + "without authentication. This endpoint has a directory traversal "
                                + "vulnerability, and any user can read any file on the server "
                                + "without authentication, causing information leakage."
                                + "https://www.gocd.org/releases/#21-3-0")
                        .setRecommendation("Update 21.3.0 released, or later released.")
                )
                .build());
    assertThat(mockWebServer.getRequestCount()).isEqualTo(1);
  }

  @Test
  public void detect_whenNoVulnerable_returnsNoFinding() {
    mockWebServer.setDispatcher(new SafeEndpointDispatcher());

    DetectionReportList detectionReports = detector.detect(TargetInfo.getDefaultInstance(),
        ImmutableList.of(goCDService));
    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
    assertThat(mockWebServer.getRequestCount()).isEqualTo(1);
  }

  private static final class VulnerableEndpointDispatcher extends Dispatcher {

    @Override
    public MockResponse dispatch(RecordedRequest recordedRequest) {
      return new MockResponse().setResponseCode(HttpStatus.OK.code())
          .setBody("root:x:0:0:root:/root:/bin/ash\n"
              + "bin:x:1:1:bin:/bin:/sbin/nologin\n"
              + "daemon:x:2:2:daemon:/sbin:/sbin/nologin\n"
              + "adm:x:3:4:adm:/var/adm:/sbin/nologin\n"
              + "lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin\n"
              + "sync:x:5:0:sync:/sbin:/bin/sync\n"
              + "shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown\n");
    }
  }

  private static final class SafeEndpointDispatcher extends Dispatcher {

    @Override
    public MockResponse dispatch(RecordedRequest recordedRequest) {
      return new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code());
    }
  }

  private static TargetInfo buildTargetInfo(NetworkEndpoint networkEndpoint) {
    return TargetInfo.newBuilder().addNetworkEndpoints(networkEndpoint).build();
  }
}
